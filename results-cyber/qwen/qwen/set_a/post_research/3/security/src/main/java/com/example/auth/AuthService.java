package com.example.auth;

import java.util.Arrays;
import java.util.List;

/**
 * The authentication decision.
 *
 * <p>Equal-work design (rule 6). Every call performs exactly one PBKDF2 derivation. On every path
 * except a successful credential match that derivation uses a fixed-length internal password sample
 * rather than the caller's, so:
 * <ul>
 *   <li>unknown address costs the same as a known address - response time does not answer "does this
 *       account exist?";</li>
 *   <li>throttled, malformed-email, malformed-password, storage-failure and wrong-password attempts
 *       each cost the same as those;</li>
 *   <li>cost never depends on the caller's input length, so an attacker cannot make one class of
 *       attempt cheaper than another or use request cost as a denial-of-service dial.</li>
 * </ul>
 * On top of that the wall-clock duration of every call is floored at {@link Config#minLoginMs()}
 * (see {@link #padToFloor}) so the derivation's own cost is not a usable signal either.
 *
 * <p>Order of operations: validate -&gt; reserve budget -&gt; read credential -&gt; derive -&gt;
 * compare -&gt; grant. The reservation happens before the credential is read, so the decision to
 * throttle depends only on the account hash and the source label, never on whether a row exists. A
 * budget row is written on failed attempts against unknown addresses too, so the write pattern does
 * not reveal existence either.
 *
 * <p>Fail closed: any storage error, rejected row, or unexpected state produces
 * {@link Outcome#DENIED}. There is no path from an exception to {@link Outcome#GRANTED}.
 */
final class AuthService {

    /** Exactly two user-visible outcomes. Nothing else may be rendered from a decision. */
    enum Outcome {
        GRANTED,
        DENIED
    }

    /** Internal reason. Logged as a code; never rendered to the user. */
    enum Reason {
        CREDENTIAL_MATCH("credential_match"),
        BAD_CREDENTIAL("bad_credential"),
        NO_SUCH_IDENTITY("no_such_identity"),
        ROW_REJECTED("row_rejected"),
        BUDGET_SPENT("budget_spent"),
        INVALID_EMAIL("invalid_email"),
        INVALID_PASSWORD("invalid_password"),
        STORAGE("storage"),
        INTERNAL("internal");

        private final String code;

        Reason(String code) {
            this.code = code;
        }

        String code() {
            return code;
        }
    }

    /**
     * Fixed password sample for the equal-work derivation. Not a secret and not a default
     * credential: it is never compared against anything and never stored.
     */
    private static final char[] WORK_SAMPLE = "work-sample-not-a-credential".toCharArray();

    /** Base for the salt used when there is no address to key the work to. Copied before use. */
    private static final byte[] WORK_SALT_BASE = Arrays.copyOf(
            CryptoUtils.sha256("auth-work-salt-v1"), PasswordHasher.SALT_BYTES);

    private final Config config;
    private final Database database;
    private final SessionStore sessions;
    private final ThrottleStore throttles;
    private final PasswordHasher hasher;
    private final LogWriter log;
    private final ThrottleStore.TimeSource clock;

    AuthService(Config config, Database database, LogWriter log) {
        this(config, database, log, ThrottleStore.SYSTEM_CLOCK);
    }

    AuthService(Config config, Database database, LogWriter log, ThrottleStore.TimeSource clock) {
        this.config = config;
        this.database = database;
        this.log = log;
        this.clock = clock;
        this.hasher = new PasswordHasher(config.iterations());
        this.sessions = new SessionStore(database);
        this.throttles = new ThrottleStore(database);
    }

    /** Result carries the outcome, an optional session token, and the measured duration. */
    static final class Result {
        final Outcome outcome;
        final Reason reason;
        final String sessionToken;
        final long micros;

        Result(Outcome outcome, Reason reason, String sessionToken, long micros) {
            this.outcome = outcome;
            this.reason = reason;
            this.sessionToken = sessionToken;
            this.micros = micros;
        }

        boolean granted() {
            return outcome == Outcome.GRANTED;
        }
    }

    /**
     * Authenticates. {@code password} stays a {@code char[]} throughout and is never wiped here - it
     * is caller-owned, and the same array is deliberately reused by the derivation. The caller wipes
     * it in a {@code finally} block.
     */
    Result authenticate(String email, char[] password) {
        long start = System.nanoTime();
        Outcome outcome = Outcome.DENIED;
        Reason reason;
        String token = null;
        String masked = "*";
        try {
            String normalised = InputValidator.requireEmail(email);
            masked = LogWriter.maskEmail(normalised);
            String identityHash = identityHash(normalised);

            List<ThrottleStore.BudgetKey> budgets =
                    ThrottleStore.attemptBudgets(identityHash, config.sourceId(), config);
            boolean slot;
            boolean budgetKnown = true;
            try {
                slot = throttles.reserve(budgets, clock.epochMillis());
            } catch (Database.StorageException e) {
                // Fail closed on the counter itself: if the throttle store cannot be trusted, an
                // attacker who corrupted or filled it would otherwise get unlimited attempts.
                logDbFailure(e);
                slot = false;
                budgetKnown = false;
            }
            if (!budgetKnown) {
                reason = Reason.STORAGE;
                log.log(LogWriter.Event.LOGIN_THROTTLED, masked, reason.code());
                workEqualDerivation(normalised);
            } else if (!slot) {
                reason = Reason.BUDGET_SPENT;
                log.log(LogWriter.Event.LOGIN_THROTTLED, masked, reason.code());
                workEqualDerivation(normalised);
            } else {
                PasswordCheck check = checkCredential(normalised, identityHash, password);
                reason = check.reason;
                if (check.granted) {
                    token = grant(check.identityId, identityHash, masked);
                    if (token != null) {
                        outcome = Outcome.GRANTED;
                        reason = Reason.CREDENTIAL_MATCH;
                        log.log(LogWriter.Event.LOGIN_SUCCESS, masked, reason.code());
                    } else {
                        // Right password, but the session could not be recorded server-side.
                        reason = Reason.STORAGE;
                    }
                } else {
                    log.log(LogWriter.Event.LOGIN_DENIED, masked, reason.code());
                }
            }
        } catch (InputValidator.ValidationException e) {
            reason = e.getMessage() != null && e.getMessage().startsWith("password")
                    ? Reason.INVALID_PASSWORD : Reason.INVALID_EMAIL;
            log.log(LogWriter.Event.LOGIN_INVALID_INPUT, masked, reason.code());
            workEqualDerivation(null);
        } catch (RuntimeException e) {
            reason = Reason.INTERNAL;
            log.log(LogWriter.Event.LOGIN_INTERNAL, masked, reason.code());
            workEqualDerivation(null);
        }
        long elapsedNanos = padToFloor(start);
        return new Result(outcome, reason, token, elapsedNanos / 1000L);
    }

    /** SHA-256 of the normalised address; the only form of the address ever sent to the database. */
    static String identityHash(String normalisedEmail) {
        return CryptoUtils.toHex(CryptoUtils.sha256(PasswordHasher.utf8(normalisedEmail)));
    }

    private static final class PasswordCheck {
        boolean granted;
        Reason reason = Reason.BAD_CREDENTIAL;
        long identityId;
    }

    /**
     * Reads the credential row and performs the one derivation this attempt is allowed. When no
     * usable row exists the derivation still happens, against a salt keyed to the address, so an
     * unknown address costs exactly what a known one costs.
     */
    private PasswordCheck checkCredential(String normalisedEmail, String identityHash,
            char[] password) {
        PasswordCheck out = new PasswordCheck();
        Database.AccountRow row = null;
        boolean storageAnswered = false;
        try {
            row = database.findAccount(identityHash, PasswordHasher.MIN_ITERATIONS,
                    PasswordHasher.MAX_ITERATIONS);
        } catch (Database.RowRejectedException e) {
            // Storage holds a value this code refuses to act on: log the code, deny, keep working.
            log.log(LogWriter.Event.DB_ROW_REJECTED, LogWriter.maskEmail(normalisedEmail),
                    e.getMessage());
            out.reason = Reason.ROW_REJECTED;
            storageAnswered = true;
        } catch (Database.StorageException e) {
            logDbFailure(e);
            out.reason = Reason.STORAGE;
            storageAnswered = true;
        }
        if (row == null) {
            // A rejected or unreadable row already carries its own reason; only a genuine "no such
            // account" is labelled as such. Both are operator-facing: the rendered message is the
            // same single string used for BAD_CREDENTIAL, and the derivation below makes the
            // attempt cost exactly what a real comparison costs, so nothing here is observable.
            if (!storageAnswered) {
                out.reason = Reason.NO_SUCH_IDENTITY;
            }
            workEqualDerivation(normalisedEmail);
            return out;
        }
        try {
            InputValidator.requirePassword(password, config.passwordMinLength());
        } catch (InputValidator.ValidationException e) {
            out.reason = Reason.INVALID_PASSWORD;
            log.log(LogWriter.Event.LOGIN_INVALID_INPUT, LogWriter.maskEmail(normalisedEmail),
                    out.reason.code());
            // The caller's password is deliberately not hashed here, so pay the same cost with the
            // sample instead of answering faster than a real comparison would.
            workEqualDerivation(normalisedEmail);
            return out;
        }
        boolean equal = hasher.matches(password, row.salt, row.iterations, row.digest);
        CryptoUtils.wipe(row.salt);
        CryptoUtils.wipe(row.digest);
        if (!equal) {
            out.reason = Reason.BAD_CREDENTIAL;
            return out;
        }
        out.granted = true;
        out.identityId = row.identityId;
        return out;
    }

    /** One derivation at the configured cost, on the fixed sample, keyed to the address if known. */
    private void workEqualDerivation(String normalisedEmail) {
        // A fresh copy every time: derive() must never be handed the shared base array, and the
        // salt must be exactly SALT_BYTES long or the derivation would be refused (paying no cost).
        byte[] salt = normalisedEmail == null
                ? Arrays.copyOf(WORK_SALT_BASE, PasswordHasher.SALT_BYTES)
                : hasher.blindSalt(normalisedEmail);
        try {
            byte[] digest = hasher.derive(WORK_SAMPLE, salt, config.iterations());
            CryptoUtils.wipe(digest);
        } catch (PasswordHasher.AuthFailure e) {
            log.log(LogWriter.Event.LOGIN_INTERNAL, "*", 0);
        } finally {
            CryptoUtils.wipe(salt);
        }
    }

    /**
     * Records the session and refunds the account budget. Returns null when the session could not be
     * written, which the caller turns into a denial.
     */
    private String grant(long identityId, String identityHash, String masked) {
        String token;
        try {
            token = sessions.issue(identityId, config.sessionTtlSec(), config.sourceId());
        } catch (Database.StorageException e) {
            logDbFailure(e);
            return null;
        }
        try {
            throttles.refund(ThrottleStore.identityBudget(identityHash,
                    config.identityMaxFailures(), config.identityWindowSec()), clock.epochMillis());
            log.log(LogWriter.Event.COUNTER_REFUNDED, masked, 0);
        } catch (Database.StorageException e) {
            // The refund is a courtesy to the legitimate owner. Failing to refund must not revoke an
            // otherwise valid session, and must not be silent.
            logDbFailure(e);
        }
        log.log(LogWriter.Event.SESSION_ISSUED, masked, 0);
        return token;
    }

    private void logDbFailure(Database.StorageException e) {
        log.log(LogWriter.Event.DB_UNAVAILABLE, "*", e.getMessage());
    }

    /**
     * Sleeps, then spins briefly, until at least {@link Config#minLoginMs()} has elapsed since
     * {@code startNano}, and returns the total elapsed nanos. An attempt that already overran the
     * floor is left alone.
     */
    private long padToFloor(long startNano) {
        long floor = config.minLoginMs() * 1_000_000L;
        long elapsed = System.nanoTime() - startNano;
        long remain = floor - elapsed;
        if (remain <= 0) {
            return elapsed;
        }
        long sleepMs = remain / 1_000_000L;
        if (sleepMs > 0) {
            try {
                Thread.sleep(sleepMs);
            } catch (InterruptedException e) {
                // Interrupted during padding only; keep the outcome, restore the flag.
                Thread.currentThread().interrupt();
                return System.nanoTime() - startNano;
            }
        }
        long deadline = System.nanoTime() + (remain - sleepMs * 1_000_000L);
        while (System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        return System.nanoTime() - startNano;
    }

    /**
     * Revokes a presented session. The answer is generic: it never says anything about which tokens
     * exist beyond whether this exact one was live, which the holder already knows.
     */
    Result logout(String presentedToken) {
        long start = System.nanoTime();
        boolean revoked;
        try {
            revoked = sessions.revoke(presentedToken);
        } catch (Database.StorageException e) {
            logDbFailure(e);
            revoked = false;
        }
        log.log(revoked ? LogWriter.Event.SESSION_REVOKED : LogWriter.Event.SESSION_NOT_FOUND,
                "*", 0);
        return new Result(revoked ? Outcome.GRANTED : Outcome.DENIED,
                revoked ? Reason.CREDENTIAL_MATCH : Reason.BAD_CREDENTIAL, null,
                (System.nanoTime() - start) / 1000L);
    }

    /** Resolves a session against server-side state. Null means "not authenticated", nothing more. */
    Long resolveSession(String presentedToken) throws Database.StorageException {
        return sessions.verify(presentedToken);
    }

    int purgeExpiredSessions() throws Database.StorageException {
        return sessions.purgeExpired();
    }

    PasswordHasher hasher() {
        return hasher;
    }

    SessionStore sessions() {
        return sessions;
    }

    ThrottleStore throttles() {
        return throttles;
    }

    /** Drops budget rows for an identity so a re-seeded account cannot inherit a stale counter. */
    void clearIdentityBudgetsFor(String normalisedEmail) throws Database.StorageException {
        throttles.clearIdentityBudgets(identityHash(normalisedEmail));
    }
}
