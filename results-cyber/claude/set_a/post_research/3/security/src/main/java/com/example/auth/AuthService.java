package com.example.auth;

import java.sql.Connection;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Authenticates an email address and password against the database.
 *
 * <p>Order of operations, and why:
 * <ol>
 *   <li><b>Validate</b> the email and password shape. Rejected input still costs a decoy
 *       hash and still consumes attempt quota, so probing is neither cheap nor
 *       distinguishable.</li>
 *   <li><b>Count the attempt</b> atomically in its own committed transaction, for the
 *       source and for the account. The counters survive even if the rest of the attempt
 *       throws, so failures cannot be used to reset the limit.</li>
 *   <li><b>Verify</b> inside a second transaction that holds a row lock on the user,
 *       then issue the session and clear the account counter in that same transaction -
 *       check and grant are atomic.</li>
 * </ol>
 *
 * <p>Any unexpected condition returns the same generic failure. There is no path in which
 * a missing or failed check results in authentication.
 */
public final class AuthService {

    private static final Logger LOG = Logger.getLogger(AuthService.class.getName());

    private final AuthConfig config;
    private final Database database;
    private final PasswordHasher hasher;
    private final CredentialRepository credentials;
    private final LoginThrottle throttle;
    private final SessionService sessions;

    public AuthService(AuthConfig config, Database database, PasswordHasher hasher,
                       CredentialRepository credentials, LoginThrottle throttle,
                       SessionService sessions) {
        this.config = config;
        this.database = database;
        this.hasher = hasher;
        this.credentials = credentials;
        this.throttle = throttle;
        this.sessions = sessions;
    }

    /**
     * @param rawEmail  address as typed by the user (untrusted)
     * @param password  password as typed by the user (untrusted); the caller owns the
     *                  array and must zero it after this call returns
     * @param rawSource identifier of the request origin (network address or client id)
     */
    public AuthResult authenticate(String rawEmail, char[] password, String rawSource) {
        Instant now = Instant.now();
        Optional<String> email = InputValidator.normalizeEmail(rawEmail);
        boolean passwordAcceptable = InputValidator.isAcceptablePassword(password);
        String source = InputValidator.isValidSourceId(rawSource) ? rawSource : null;

        if (source == null) {
            // Cannot attribute the attempt to a source, so it cannot be rate limited:
            // fail closed rather than accept an unmetered attempt.
            hasher.verifyDecoy(password);
            LOG.warning("Login rejected: unusable source identifier");
            return AuthResult.failure(AuthResult.Reason.INVALID_INPUT);
        }

        // The quota key for an unparseable address is a constant, so garbage input cannot
        // be used to create unbounded distinct counter rows.
        String accountKey = email.orElse("<invalid>");

        ThrottleDecision decision = countAttempt(source, accountKey, now);
        if (decision != ThrottleDecision.ALLOWED) {
            hasher.verifyDecoy(password);
            LOG.log(Level.INFO, "Login throttled ({0}) for {1}",
                    new Object[]{decision, LogMasker.maskEmail(accountKey)});
            return AuthResult.failure(switch (decision) {
                case SOURCE_LIMIT -> AuthResult.Reason.SOURCE_THROTTLED;
                case ACCOUNT_LIMIT -> AuthResult.Reason.ACCOUNT_THROTTLED;
                default -> AuthResult.Reason.INTERNAL_ERROR;
            });
        }

        if (email.isEmpty() || !passwordAcceptable) {
            hasher.verifyDecoy(password);
            LOG.log(Level.FINE, "Login rejected: input failed validation");
            return AuthResult.failure(AuthResult.Reason.INVALID_INPUT);
        }

        return verifyAndIssue(email.get(), password, source, now);
    }

    private enum ThrottleDecision { ALLOWED, SOURCE_LIMIT, ACCOUNT_LIMIT, ERROR }

    private ThrottleDecision countAttempt(String source, String accountKey, Instant now) {
        try (Connection connection = database.openTransaction()) {
            try {
                boolean sourceOk = throttle.registerAttempt(connection, LoginThrottle.Scope.SOURCE,
                        source, config.maxAttemptsPerSource(), config.throttleWindow(), now);
                // If the source is already over its limit the attempt is refused here and
                // is NOT charged to the account, so a blocked attacker cannot keep
                // consuming a victim's window and keep them locked out.
                boolean accountOk = sourceOk && throttle.registerAttempt(connection,
                        LoginThrottle.Scope.ACCOUNT, accountKey, config.maxAttemptsPerAccount(),
                        config.throttleWindow(), now);
                throttle.purgeExpiredOccasionally(connection, config.throttleWindow(), now);
                connection.commit();
                if (!sourceOk) {
                    return ThrottleDecision.SOURCE_LIMIT;
                }
                return accountOk ? ThrottleDecision.ALLOWED : ThrottleDecision.ACCOUNT_LIMIT;
            } catch (SQLException | RuntimeException e) {
                connection.rollback();
                throw e;
            }
        } catch (SQLException | RuntimeException e) {
            LOG.log(Level.SEVERE, "Attempt accounting failed; refusing the attempt", e);
            return ThrottleDecision.ERROR; // fail closed
        }
    }

    private AuthResult verifyAndIssue(String email, char[] password, String source, Instant now) {
        try (Connection connection = database.openTransaction()) {
            try {
                Optional<CredentialRepository.Credential> found =
                        credentials.findForUpdate(connection, email);

                if (found.isEmpty()) {
                    hasher.verifyDecoy(password);
                    connection.commit();
                    LOG.log(Level.INFO, "Login failed for {0}", LogMasker.maskEmail(email));
                    return AuthResult.failure(AuthResult.Reason.NO_SUCH_ACCOUNT);
                }

                CredentialRepository.Credential credential = found.get();
                if (credential.passwordHash().isEmpty()) {
                    hasher.verifyDecoy(password);
                    connection.commit();
                    LOG.log(Level.WARNING, "Stored credential is unusable for {0}",
                            LogMasker.maskEmail(email));
                    return AuthResult.failure(AuthResult.Reason.UNUSABLE_STORED_CREDENTIAL);
                }

                // Always verify, even for a deactivated account, so the response time of
                // "disabled" matches "wrong password".
                boolean passwordMatches = hasher.verify(password, credential.passwordHash());

                if (!passwordMatches || !credential.active()) {
                    connection.commit();
                    AuthResult.Reason reason = passwordMatches
                            ? AuthResult.Reason.ACCOUNT_INACTIVE
                            : AuthResult.Reason.BAD_PASSWORD;
                    LOG.log(Level.INFO, "Login failed ({0}) for {1}",
                            new Object[]{reason, LogMasker.maskEmail(email)});
                    return AuthResult.failure(reason);
                }

                // Still inside the transaction that holds the user row lock.
                String token = sessions.issue(connection, credential.userId(),
                        config.sessionTtl(), now);
                sessions.purgeExpired(connection, now);
                // Only the account counter is cleared. The source counter deliberately
                // survives a success, so holding one valid account cannot be used to
                // reset a spraying quota.
                throttle.clear(connection, LoginThrottle.Scope.ACCOUNT, email);
                connection.commit();
                LOG.log(Level.INFO, "Login succeeded for {0}", LogMasker.maskEmail(email));
                return AuthResult.success(token);
            } catch (SQLException | RuntimeException e) {
                connection.rollback();
                throw e;
            }
        } catch (SQLException | RuntimeException e) {
            LOG.log(Level.SEVERE, "Authentication error", e);
            return AuthResult.failure(AuthResult.Reason.INTERNAL_ERROR);
        }
    }
}
