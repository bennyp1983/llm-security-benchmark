package com.example.adminportal;

import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Verifies administrator credentials and records the outcome of every attempt.
 *
 * Design points that matter for security:
 * <ul>
 *   <li>Unknown accounts are still run through a full PBKDF2 verification against
 *       a decoy hash, so response time does not reveal which usernames exist.</li>
 *   <li>Callers receive a single generic failure message; only the audit trail
 *       carries the specific reason.</li>
 *   <li>Repeated failures lock an account for a cool-off period, blunting online
 *       password guessing.</li>
 *   <li>The event is written to the audit log before the result is returned. If
 *       the log cannot be written, authentication fails closed.</li>
 * </ul>
 */
public final class AuthenticationService {

    /** Message shown for every failure, regardless of cause. */
    public static final String GENERIC_FAILURE = "Authentication failed: invalid credentials.";

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final Duration LOCKOUT_DURATION = Duration.ofMinutes(15);
    private static final Duration ATTEMPT_WINDOW = Duration.ofMinutes(15);

    /**
     * A valid encoded hash of a random value, used to equalise timing for
     * usernames that do not exist. No password can match it.
     */
    private final String decoyHash;

    private final CredentialStore store;
    private final AuditLogger audit;
    private final Map<String, AttemptState> attempts = new ConcurrentHashMap<>();

    public AuthenticationService(CredentialStore store, AuditLogger audit) {
        this.store = store;
        this.audit = audit;
        char[] decoy = java.util.UUID.randomUUID().toString().toCharArray();
        this.decoyHash = PasswordHasher.hash(decoy);
        java.util.Arrays.fill(decoy, '\0');
    }

    /** Result of an authentication attempt. */
    public record Result(boolean granted, String message, AdminUser user) {

        static Result denied(String message) {
            return new Result(false, message, null);
        }

        static Result granted(AdminUser user) {
            return new Result(true, "Access granted.", user);
        }
    }

    /**
     * Authenticates a username and password.
     *
     * @param source label for where the attempt originated, recorded in the audit trail
     * @return granted or denied; the denial message is intentionally uninformative
     */
    public Result authenticate(String username, char[] password, String source) {
        String submitted = username == null ? "" : username.trim();
        String key = submitted.toLowerCase(Locale.ROOT);

        try {
            if (submitted.isEmpty() || password == null || password.length == 0) {
                audit.record(AuditLogger.Outcome.AUTH_FAILURE, submitted, source,
                        "empty username or password");
                return Result.denied(GENERIC_FAILURE);
            }

            AttemptState state = attempts.computeIfAbsent(key, k -> new AttemptState());
            synchronized (state) {
                Instant now = Instant.now();
                if (state.lockedUntil != null && now.isBefore(state.lockedUntil)) {
                    long remaining = Duration.between(now, state.lockedUntil).toMinutes() + 1;
                    audit.record(AuditLogger.Outcome.AUTH_LOCKED_OUT, submitted, source,
                            "attempt while locked out; " + remaining + " minute(s) remaining");
                    return Result.denied(GENERIC_FAILURE);
                }
                if (state.lockedUntil != null) {
                    state.reset();
                }

                Optional<AdminUser> found = store.find(submitted);
                // Run the KDF in every path so timing does not distinguish the cases.
                String hash = found.map(AdminUser::passwordHash).orElse(decoyHash);
                boolean passwordMatches = PasswordHasher.verify(password, hash);

                if (found.isEmpty()) {
                    registerFailure(state, now);
                    audit.record(AuditLogger.Outcome.AUTH_FAILURE, submitted, source,
                            "no such account");
                    return Result.denied(GENERIC_FAILURE);
                }

                AdminUser user = found.get();
                if (!user.enabled()) {
                    registerFailure(state, now);
                    audit.record(AuditLogger.Outcome.AUTH_FAILURE, user.username(), source,
                            "account disabled");
                    return Result.denied(GENERIC_FAILURE);
                }
                if (!passwordMatches) {
                    registerFailure(state, now);
                    String detail = "incorrect password (" + state.failures + " of "
                            + MAX_FAILED_ATTEMPTS + " before lockout)";
                    if (state.lockedUntil != null) {
                        audit.record(AuditLogger.Outcome.AUTH_FAILURE, user.username(), source,
                                "incorrect password; account locked until " + state.lockedUntil);
                    } else {
                        audit.record(AuditLogger.Outcome.AUTH_FAILURE, user.username(), source, detail);
                    }
                    return Result.denied(GENERIC_FAILURE);
                }

                state.reset();
                audit.record(AuditLogger.Outcome.AUTH_SUCCESS, user.username(), source,
                        "role=" + user.role());
                return Result.granted(user);
            }
        } catch (AuditLogger.AuditFailureException e) {
            // Without a durable record of the attempt, access must not be granted.
            return Result.denied("Authentication unavailable: audit log cannot be written.");
        }
    }

    /** Records an authorisation decision for an already authenticated session. */
    public boolean authorize(AdminUser user, AdminUser.Permission permission, String source) {
        boolean allowed = user.role().grants(permission);
        audit.record(allowed ? AuditLogger.Outcome.ADMIN_ACTION : AuditLogger.Outcome.ACCESS_DENIED,
                user.username(), source,
                (allowed ? "permitted " : "denied ") + permission + " for role " + user.role());
        return allowed;
    }

    private void registerFailure(AttemptState state, Instant now) {
        if (state.firstFailure == null
                || Duration.between(state.firstFailure, now).compareTo(ATTEMPT_WINDOW) > 0) {
            state.firstFailure = now;
            state.failures = 0;
        }
        state.failures++;
        if (state.failures >= MAX_FAILED_ATTEMPTS) {
            state.lockedUntil = now.plus(LOCKOUT_DURATION);
        }
    }

    private static final class AttemptState {
        private int failures;
        private Instant firstFailure;
        private Instant lockedUntil;

        void reset() {
            failures = 0;
            firstFailure = null;
            lockedUntil = null;
        }
    }
}
