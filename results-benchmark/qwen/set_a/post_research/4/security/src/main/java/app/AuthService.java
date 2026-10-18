package app;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;

/**
 * Sign-in: validates a credential against server-side state and issues a session.
 *
 * <h2>Uniform failure</h2>
 * The four ways a sign-in can fail - malformed input, unknown account, wrong password, account
 * in its lockout window - all answer with {@link #INVALID_MESSAGE} and all perform
 * <em>exactly one</em> Argon2id derivation. The unknown-account and locked-account paths derive
 * against {@link #dummyHash()}: the same memory-hard work against a constant credential that can
 * never match, so neither wall-clock time nor peak memory reveals which branch ran. There is no
 * sleep-based pad, so the padding cannot drift out of step with the configured cost. A successful
 * sign-in on an account whose stored parameters are below policy does one extra derivation to
 * upgrade it - a path that already required the correct password.
 *
 * <h2>Atomicity</h2>
 * One transaction per attempt, in a fixed order: consume the source budget, read the account, take
 * the {@code auth_guard} row lock, verify, then either clear or charge the account counter and
 * insert the session. Any failure rolls the whole attempt back, so a session cannot exist without
 * its account, and a failure cannot be charged to an account without the source budget also being
 * spent.
 *
 * <h2>Lockout is not a denial-of-access lever</h2>
 * The per-account counter is temporary ({@link Throttle#ACCOUNT_LOCK_SECONDS}) and self-clearing,
 * and a successful sign-in clears it, so knowing a colleague's email does not let an attacker keep
 * them out beyond one window. Total attempt rate is bounded by the per-source budget, which is
 * independent of the account: burning an account's five strikes costs the attacker five of their
 * own ten.
 */
public final class AuthService {

    /** Single sign-in refusal for every failure mode, including a locked account. */
    public static final String INVALID_MESSAGE = "The email or password is not correct.";

    /** Shown when the audit trail or the store cannot be honoured: access is refused. */
    public static final String INTERNAL_MESSAGE = "Sign-in is unavailable right now. Try again later.";

    private final AccountStore accounts;
    private final Throttle throttle;
    private final SessionStore sessions;
    private final PasswordHasher hasher;
    private final Gate gate;
    private final Clock clock;
    private final String dummyHash;

    /**
     * Fixed internal buffer used to buy an equal-cost refusal. Argon2id's cost is set by its
     * parameters, not by the length of the input, so a refusal can match the price of a real
     * comparison without ever feeding an attacker-sized candidate into the KDF.
     */
    private static final char[] WORK_FILLER = "equalising-derivation".toCharArray();

    public AuthService(AccountStore accounts, Throttle throttle, SessionStore sessions,
        PasswordHasher hasher, Gate gate, Clock clock) {
        this.accounts = accounts;
        this.throttle = throttle;
        this.sessions = sessions;
        this.hasher = hasher;
        this.gate = gate;
        this.clock = clock;
        // Derived once at construction: a genuine Argon2id string with a random salt whose
        // password is random and kept nowhere, so nobody - including an operator with the
        // database - can present it.
        java.security.SecureRandom filler = new java.security.SecureRandom();
        char[] throwaway = new char[24];
        try {
            for (int i = 0; i < throwaway.length; i++) {
                throwaway[i] = (char) ('a' + filler.nextInt(26));
            }
            this.dummyHash = hasher.encode(throwaway);
        } finally {
            java.util.Arrays.fill(throwaway, '\0');
        }
    }

    public enum Status {
        /** Credential accepted; a session was issued. */
        AUTHENTICATED,
        /** Generic refusal: malformed input, unknown account, or wrong password. */
        INVALID_CREDENTIALS,
        /** Refused by a rate limit; the client-visible message is identical to a bad password. */
        THROTTLED,
        /** Refused because a security control (audit trail or store) could not be honoured. */
        UNAVAILABLE
    }

    public record Result(Status status, String message, SessionStore.Session session) {
        public boolean authenticated() {
            return status == Status.AUTHENTICATED;
        }
    }

    /**
     * @param identifierChars email or username exactly as typed; never trimmed here
     * @param passwordChars   candidate password; the caller erases it, this class never stores it
     * @param sourceId        opaque caller-supplied source key (a digest in the CLI)
     */
    public Result login(char[] identifierChars, char[] passwordChars, String sourceId) {
        InputPolicy.Identity identity;
        try {
            identity = InputPolicy.identifier(identifierChars);
        } catch (InputPolicy.ValidationException invalidInput) {
            return refuseWithoutStore(sourceId, "identifier rejected");
        }
        if (passwordChars == null || passwordChars.length == 0
            || passwordChars.length > InputPolicy.PASSWORD_MAX) {
            // Never enter the KDF with an attacker-sized buffer: the work factor would be theirs.
            // The equalising derivation below uses this class's own fixed buffer instead.
            return refuseWithoutStore(sourceId, "password length rejected");
        }
        try {
            return attempt(identity, passwordChars, sourceId);
        } catch (SQLException | AuditLog.AuditException storeOrAuditFault) {
            // Fail closed: an unreadable store or an unwritable trail is a denial, not a bypass.
            refuseQuietly(AuditLog.Event.LOGIN_STORE_ERROR, sourceId, "store or audit fault");
            return new Result(Status.UNAVAILABLE, INTERNAL_MESSAGE, null);
        }
    }

    /**
     * Refuses a sign-in whose input was rejected before any credential could be compared. The source
     * budget is still charged, and a spent budget still returns the same generic line: otherwise
     * sending malformed input would be free - an attacker could force a full key-derivation and an
     * audit record on every attempt, forever, without ever touching the limit that is meant to bound
     * online work. Charging here is what makes the per-source limit bound the expensive path, not only
     * the well-formed one.
     */
    private Result refuseWithoutStore(String sourceId, String reason) {
        try {
            boolean allowed = Boolean.TRUE.equals(accounts.db().inTransaction(
                connection -> throttle.tryConsumeSource(connection, Throttle.LOGIN_SOURCE_SCOPE, sourceId)));
            if (!allowed) {
                gate.record(AuditLog.Event.LOGIN_THROTTLED_SOURCE, "source", gate.sourceTag(sourceId));
                equaliseWork();
                return throttled();
            }
            refuseQuietly(AuditLog.Event.LOGIN_REFUSED_INVALID_INPUT, sourceId, reason);
        } catch (SQLException | AuditLog.AuditException storeOrAuditFault) {
            // The budget could not be consulted, so the attempt cannot be counted. Fail closed with
            // the generic unavailable answer rather than serve a free derivation that escapes the limit.
            refuseQuietly(AuditLog.Event.LOGIN_STORE_ERROR, sourceId, "store or audit fault on refusal");
            return new Result(Status.UNAVAILABLE, INTERNAL_MESSAGE, null);
        }
        equaliseWork();
        return new Result(Status.INVALID_CREDENTIALS, INVALID_MESSAGE, null);
    }

    /**
     * Buys one derivation so a refusal that never compared against the stored credential still
     * costs what one that did. Without this, response time alone separates "no such account" and
     * "you are being rate limited" from a wrong password, which is exactly the disclosure the
     * uniform message was written to prevent.
     */
    private void equaliseWork() {
        hasher.verify(WORK_FILLER.clone(), dummyHash);
    }

    private Result attempt(InputPolicy.Identity identity, char[] password, String sourceId)
        throws SQLException, AuditLog.AuditException {
        final Result[] outcome = new Result[1];
        // Set by whichever branch performs a real comparison, so the caller can tell a refusal that
        // already cost a derivation from one that cost none. The equalising derivation then runs
        // <em>after</em> the transaction closes - never inside it - because the store monitor is
        // held for the whole transaction and a padded derivation there would serialise every
        // concurrent request behind it.
        final boolean[] paidForWork = new boolean[1];
        accounts.db().inTransaction(connection -> {
            if (!throttle.tryConsumeSource(connection, Throttle.LOGIN_SOURCE_SCOPE, sourceId)) {
                gate.record(AuditLog.Event.LOGIN_THROTTLED_SOURCE, "source", gate.sourceTag(sourceId));
                outcome[0] = throttled();
                return Boolean.FALSE;
            }

            AccountStore.Account account = identity.byEmail()
                ? accountBy(connection, "email = ?", identity.value())
                : accountBy(connection, "username = ?", identity.value());

            if (account == null) {
                paidForWork[0] = true;
                hasher.verify(password, dummyHash);
                gate.record(AuditLog.Event.LOGIN_FAILURE, "reason", "no such account",
                    "source", gate.sourceTag(sourceId),
                    "identity", identity.byEmail() ? gate.emailTag(identity.value())
                        : gate.usernameTag(identity.value()));
                outcome[0] = invalid();
                return Boolean.FALSE;
            }

            Throttle.AccountGuard guard = throttle.lockAccountGuard(connection, account.id());
            if (guard.isBlocked(clock.instant().getEpochSecond())) {
                paidForWork[0] = true;
                hasher.verify(password, dummyHash);
                gate.record(AuditLog.Event.LOGIN_THROTTLED_ACCOUNT, "account", gate.accountTag(account.id()),
                    "source", gate.sourceTag(sourceId));
                outcome[0] = throttled();
                return Boolean.FALSE;
            }

            paidForWork[0] = true;
            if (!hasher.verify(password, account.passwordHash())) {
                long blockedUntil = throttle.chargeFailure(connection, account.id(), guard);
                gate.record(AuditLog.Event.LOGIN_FAILURE, "reason", "credential mismatch",
                    "account", gate.accountTag(account.id()), "source", gate.sourceTag(sourceId),
                    "locked", blockedUntil > 0 ? "yes" : "no");
                if (blockedUntil > 0) {
                    gate.record(AuditLog.Event.ACCOUNT_LOCKED, "account", gate.accountTag(account.id()),
                        "seconds", Integer.toString(Throttle.ACCOUNT_LOCK_SECONDS));
                }
                outcome[0] = invalid();
                return Boolean.FALSE;
            }

            throttle.clearFailures(connection, account.id());
            if (guard.failures() > 0) {
                // The counter was non-zero, so this sign-in ended a strike window: recording that
                // lets an operator see a lockout was cleared by the real owner.
                gate.record(AuditLog.Event.ACCOUNT_UNLOCKED, "account", gate.accountTag(account.id()),
                    "failures", Integer.toString(guard.failures()));
            }
            if (hasher.weakerThanPolicy(account.passwordHash())) {
                accounts.upgradePasswordHash(account.id(), password, account.passwordUpdatedAt());
            }
            SessionStore.Session session = sessions.issue(account.id());
            gate.record(AuditLog.Event.LOGIN_SUCCESS, "account", gate.accountTag(account.id()),
                "source", gate.sourceTag(sourceId), "session", gate.sessionTag(session.token()));
            outcome[0] = new Result(Status.AUTHENTICATED, "Sign-in complete.", session);
            return Boolean.TRUE;
        });
        if (outcome[0] == null) {
            throw new SQLException("the sign-in transaction produced no outcome");
        }
        if (!paidForWork[0]) {
            // Reached by the rate-limited branch, which never read a credential. Pay the same
            // price now, outside the store lock, so a throttle cannot be spotted by timing.
            equaliseWork();
        }
        return outcome[0];
    }

    private static Result invalid() {
        return new Result(Status.INVALID_CREDENTIALS, INVALID_MESSAGE, null);
    }

    private static Result throttled() {
        // Deliberately the same wording as a wrong password: a locked account must not be
        // distinguishable by the message either. The distinction is recorded in the audit trail.
        return new Result(Status.THROTTLED, INVALID_MESSAGE, null);
    }

    private void refuseQuietly(AuditLog.Event event, String sourceId, String reason) {
        try {
            gate.record(event, "reason", reason, "source", gate.sourceTag(sourceId));
        } catch (AuditLog.AuditException auditUnavailable) {
            // The refusal has already happened and is the safe direction; this path never touched
            // a credential, so there is nothing further to protect and no second channel to hide.
            System.err.println("NOTE an audit record for a refused request could not be written");
        }
    }

    private static AccountStore.Account accountBy(Connection connection, String predicate, String value)
        throws SQLException {
        String sql = "SELECT id, email, username, password_hash, kdf_memory_kib, kdf_iterations,"
            + " kdf_parallelism, password_updated_at FROM accounts WHERE " + predicate;
        try (PreparedStatement query = connection.prepareStatement(sql)) {
            query.setString(1, value);
            try (ResultSet found = query.executeQuery()) {
                if (!found.next()) {
                    return null;
                }
                return new AccountStore.Account(found.getLong(1), found.getString(2), found.getString(3),
                    found.getString(4), found.getInt(5), found.getInt(6), found.getInt(7), found.getLong(8));
            }
        }
    }

    /** Validates a session token and resolves it to an account id, or {@code null}. */
    public Long resolveSession(String token) {
        try {
            Long accountId = sessions.resolve(token);
            if (accountId == null) {
                gate.record(AuditLog.Event.SESSION_REJECTED, "session", gate.sessionTag(token));
            }
            return accountId;
        } catch (SQLException | AuditLog.AuditException fault) {
            return null;
        }
    }

    /**
     * Revokes the presented session. The result distinguishes "a store/audit fault happened" from
     * the two client-indistinguishable outcomes, so the caller can fail closed on a fault while
     * keeping a revoked session and a never-existing one worded identically.
     */
    public enum LogoutStatus {
        /** A live session was ended by this call. */
        REVOKED,
        /** The token was well-formed but matched no live session; never disclosed as distinct. */
        NO_LIVE_SESSION,
        /** The store or trail could not be consulted: revocation is <em>not</em> confirmed. */
        UNAVAILABLE
    }

    /**
     * Revokes the presented session. The client-visible outcome is kept uniform between
     * {@link LogoutStatus#REVOKED} and {@link LogoutStatus#NO_LIVE_SESSION} by the caller, so this
     * cannot probe session identifiers - but {@link LogoutStatus#UNAVAILABLE} is reported honestly:
     * a bearer credential whose revocation the store could not confirm must not be reported as
     * revoked, because that is the one case where a captured token would silently stay live.
     * The record is written by {@link SessionStore#revoke}, the layer that actually ends the
     * session, so no caller can end one without it appearing in the trail.
     */
    public LogoutStatus logout(String token) {
        try {
            return sessions.revoke(token) ? LogoutStatus.REVOKED : LogoutStatus.NO_LIVE_SESSION;
        } catch (SQLException | AuditLog.AuditException fault) {
            return LogoutStatus.UNAVAILABLE;
        }
    }

    /** The constant credential used to equalise work across failure branches. */
    public String dummyHash() {
        return dummyHash;
    }
}
