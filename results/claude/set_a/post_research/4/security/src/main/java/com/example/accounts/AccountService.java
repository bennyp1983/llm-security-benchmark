package com.example.accounts;

import java.sql.SQLException;
import java.time.Clock;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import java.util.logging.Logger;
import java.text.Normalizer;

/**
 * Registration and authentication.
 *
 * <p>This is where the enumeration-resistance rules are enforced, so the ordering of operations
 * matters as much as the operations themselves:
 *
 * <ul>
 *   <li>Rule 6 (failure behaviour): {@link #register} returns the same {@link RegistrationStatus}
 *       whether the account was created or the email/username was already taken, and it hashes the
 *       password <em>before</em> attempting the insert in both cases, so neither the message nor
 *       the elapsed time distinguishes them. {@link #authenticate} returns one
 *       {@code INVALID_CREDENTIALS} for an unknown identifier, a wrong password and a disabled
 *       account, and runs a full Argon2 verification against a decoy hash when there is no account
 *       so that the work done is comparable.</li>
 *   <li>Rule 3: the password check is against the stored hash in the database and nothing else, and
 *       every path that is not a positive verification returns failure.</li>
 *   <li>Rule 7: the throttle check and its increment are one atomic step
 *       ({@link ThrottleService#tryAcquire}), and account uniqueness is decided by the database's
 *       UNIQUE constraints rather than by a read followed by a write.</li>
 * </ul>
 */
public final class AccountService {

    /** Result of a registration request. Carries no information about existing accounts. */
    public enum RegistrationStatus {
        /**
         * The request was accepted. Returned both when a new account was created and when the
         * email or username was already in use -- the caller cannot tell which, by design.
         */
        ACCEPTED,
        /** Too many recent registration attempts from this source. */
        THROTTLED
    }

    /** Result of an authentication attempt. */
    public enum AuthStatus {
        AUTHENTICATED,
        /** Unknown identifier, wrong password, or disabled account -- indistinguishable. */
        INVALID_CREDENTIALS,
        /** Too many recent failures for this source or this identifier. */
        THROTTLED
    }

    /** Authentication outcome; {@code session} is present only when {@code AUTHENTICATED}. */
    public record AuthResult(AuthStatus status, SessionService.IssuedSession session,
                             String usernameDisplay) {

        static AuthResult failure(AuthStatus status) {
            return new AuthResult(status, null, null);
        }
    }

    private final Database database;
    private final PasswordHasher hasher;
    private final AccountRepository accounts;
    private final ThrottleService throttle;
    private final SessionService sessions;
    private final Logger log;
    private final Clock clock;

    /** Hash of a value nobody knows, used to equalise work when no account matches. */
    private final String decoyHash;

    public AccountService(Config config, Database database, Logger log) {
        this(config, database, log, Clock.systemUTC());
    }

    AccountService(Config config, Database database, Logger log, Clock clock) {
        this.database = database;
        this.log = log;
        this.clock = clock;
        this.hasher = new PasswordHasher(config.argon2(), config.pepper());
        this.accounts = new AccountRepository();
        this.throttle = new ThrottleService(config);
        this.sessions = new SessionService(config);
        this.decoyHash = hasher.newDecoyHash();
    }

    /**
     * Registers an account.
     *
     * @param email       client-supplied email address
     * @param username    client-supplied username
     * @param password    client-supplied password; the caller owns and must wipe this array
     * @param sourceId    server-observed request origin, used for rate limiting
     * @throws ValidationException if an input breaks a documented format rule; the message is
     *                             format-only and safe to show the user
     */
    public RegistrationStatus register(String email, String username, char[] password,
                                       String sourceId) throws ValidationException, SQLException {
        String source = normalizeSourceId(sourceId);
        String canonicalEmail = InputValidator.canonicalEmail(email);
        String canonicalUsername = InputValidator.canonicalUsername(username);
        String displayUsername = displayForm(username, canonicalUsername);

        char[] prepared = InputValidator.preparePassword(password);
        try {
            InputValidator.checkPasswordPolicy(prepared, canonicalUsername, canonicalEmail);

            Instant now = clock.instant();
            // Gate first, and in its own transaction: hashing is deliberately expensive, so a
            // throttled source must not be able to make us spend 64 MiB and three Argon2 passes
            // per request. The gate is still one atomic check-and-count (rule 7).
            boolean allowed = database.inTransaction(connection ->
                    // Source-only limiting: an attacker must not be able to burn a victim's
                    // *account* counter by repeatedly "registering" their address.
                    throttle.tryAcquire(connection, source, null, now).allowed());
            if (!allowed) {
                log.info(() -> "registration throttled for source");
                return RegistrationStatus.THROTTLED;
            }

            // Hashed before the insert, and on every path, so a taken address costs the same as a
            // free one (rule 6: comparable work for every outcome).
            final String hashToStore = hasher.hash(prepared);
            boolean created = database.inTransaction(connection -> accounts.insert(connection,
                    canonicalEmail, canonicalUsername, displayUsername, hashToStore, now));

            if (created) {
                log.info(() -> "account created email=" + Mask.email(canonicalEmail)
                        + " username=" + Mask.username(canonicalUsername));
            } else {
                // The *only* place this distinction is recorded, and it goes to the private log.
                log.info(() -> "registration rejected as duplicate email="
                        + Mask.email(canonicalEmail) + " username=" + Mask.username(canonicalUsername));
            }
            return RegistrationStatus.ACCEPTED;
        } finally {
            Wipe.chars(prepared);
        }
    }

    /**
     * Authenticates an identifier (email or username) and password.
     *
     * @param identifier client-supplied email or username
     * @param password   client-supplied password; the caller owns and must wipe this array
     * @param sourceId   server-observed request origin, used for rate limiting
     */
    public AuthResult authenticate(String identifier, char[] password, String sourceId)
            throws SQLException {
        String source = normalizeSourceId(sourceId);
        String lookupKey = canonicalLookupKey(identifier);
        Instant now = clock.instant();

        // Step 1 (atomic): is this attempt allowed, and count it.
        Decisionable gate = database.inTransaction(connection -> {
            ThrottleService.Decision decision =
                    throttle.tryAcquire(connection, source, lookupKey, now);
            if (!decision.allowed()) {
                return new Decisionable(decision, null);
            }
            Optional<AccountRepository.Account> account =
                    lookupKey == null ? Optional.empty() : accounts.findByLogin(connection, lookupKey);
            return new Decisionable(decision, account.orElse(null));
        });

        if (!gate.decision().allowed()) {
            // One message for both scopes: which limit was hit is not the caller's business.
            log.info(() -> "authentication throttled (" + gate.decision() + ")");
            return AuthResult.failure(AuthStatus.THROTTLED);
        }

        AccountRepository.Account account = gate.account();
        // A disabled account verifies against the decoy too, so "disabled" is not observable.
        boolean usable = account != null && !account.disabled();
        char[] prepared;
        try {
            prepared = InputValidator.preparePassword(password);
        } catch (ValidationException e) {
            // A password that cannot even be prepared cannot match. Spend comparable work anyway.
            burnComparableWork();
            log.info(() -> "authentication failed: unusable password input");
            return AuthResult.failure(AuthStatus.INVALID_CREDENTIALS);
        }

        boolean verified;
        try {
            String candidateHash = usable ? account.passwordHash() : decoyHash;
            verified = hasher.verify(prepared, candidateHash) && usable;
            if (!verified) {
                log.info(() -> "authentication failed for identifier="
                        + Mask.username(lookupKey == null ? "" : lookupKey));
                return AuthResult.failure(AuthStatus.INVALID_CREDENTIALS);
            }

            final long accountId = account.id();
            final boolean rehash = hasher.needsRehash(account.passwordHash());
            final String upgraded = rehash ? hasher.hash(prepared) : null;

            // Step 2 (atomic): clear the account counter and mint the session together.
            SessionService.IssuedSession issued = database.inTransaction(connection -> {
                throttle.clearAccount(connection, lookupKey, now);
                if (upgraded != null) {
                    accounts.updatePasswordHash(connection, accountId, upgraded, now);
                }
                return sessions.issue(connection, accountId, now);
            });
            log.info(() -> "authentication succeeded username="
                    + Mask.username(account.usernameCanonical())
                    + " session=" + issued.reference()
                    + (rehash ? " (password hash upgraded)" : ""));
            return new AuthResult(AuthStatus.AUTHENTICATED, issued, account.usernameDisplay());
        } finally {
            Wipe.chars(prepared);
        }
    }

    /** Carries the throttle decision and the account row out of the first transaction. */
    private record Decisionable(ThrottleService.Decision decision,
                                AccountRepository.Account account) {
    }

    /**
     * Resolves a session token to the account it belongs to. This is the only supported way to act
     * on behalf of a logged-in user (rule 3: verified against server-side state, fails closed).
     */
    public Optional<SessionService.ValidSession> resolveSession(char[] token) throws SQLException {
        Instant now = clock.instant();
        return database.inTransaction(connection -> sessions.validate(connection, token, now));
    }

    /** Revokes a session server-side. Pair with {@link SessionCookie#clearCookieHeader()}. */
    public void logout(char[] token) throws SQLException {
        database.inTransaction(connection -> {
            sessions.revoke(connection, token);
            return null;
        });
    }

    /** Burns roughly one Argon2 verification so an early rejection is not visibly cheap. */
    private void burnComparableWork() {
        char[] filler = "decoy-work-only".toCharArray();
        try {
            hasher.verify(filler, decoyHash);
        } finally {
            Wipe.chars(filler);
        }
    }

    /**
     * Canonicalises a login identifier the same way registration did.
     *
     * @return the canonical email or username, or {@code null} if the input cannot be a valid
     *         identifier at all (treated as "no such account", never as a different error)
     */
    private static String canonicalLookupKey(String identifier) {
        if (identifier == null) {
            return null;
        }
        String stripped = identifier.strip();
        if (stripped.isEmpty() || stripped.length() > InputValidator.EMAIL_MAX_LENGTH) {
            return null;
        }
        try {
            return stripped.indexOf('@') >= 0
                    ? InputValidator.canonicalEmail(stripped)
                    : InputValidator.canonicalUsername(stripped);
        } catch (ValidationException e) {
            return null;
        }
    }

    /** The username as typed, NFKC-normalised, kept only for display. */
    private static String displayForm(String raw, String canonical) {
        String normalized = Normalizer.normalize(raw.strip(), Normalizer.Form.NFKC);
        // Must differ from the canonical form only by case; otherwise store the canonical form.
        return normalized.toLowerCase(Locale.ROOT).equals(canonical) ? normalized : canonical;
    }

    /**
     * Normalises the server-observed source identifier.
     *
     * <p>Rule 1: this value must be supplied by the server (a socket peer address, or the local
     * actor for the CLI) and never read from a client-controlled header such as
     * {@code X-Forwarded-For} unless a trusted proxy is the only possible writer of it. It is
     * bounded and stripped of surprises here because it ends up in a digest and a log line.
     */
    private static String normalizeSourceId(String sourceId) {
        if (sourceId == null || sourceId.isBlank()) {
            // Fail closed: an unattributable request is counted against one shared bucket rather
            // than escaping rate limiting entirely.
            return "unknown-source";
        }
        String value = sourceId.strip();
        if (value.length() > 128) {
            value = value.substring(0, 128);
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            sb.append(c >= 0x21 && c <= 0x7e ? c : '?');
        }
        return sb.toString();
    }

}
