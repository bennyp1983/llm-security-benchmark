package com.example.adminportal;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Verifies administrator credentials and throttles repeated failures.
 *
 * <p>Failures are rate-limited per username with a temporary lockout, every failure mode reports
 * the same message, and an unknown username still pays the full hashing cost so response time does
 * not reveal which accounts exist.
 */
final class AuthenticationService {

    /** Hash of a value no user can supply, used to equalise timing for unknown usernames. */
    private static final String DUMMY_HASH = PasswordHasher.hash("::no-such-user::".toCharArray());

    private final CredentialStore store;
    private final AuditLog auditLog;
    private final Clock clock;
    private final int maxAttempts;
    private final Duration lockoutDuration;
    private final Map<String, FailureState> failures = new HashMap<>();

    AuthenticationService(
            CredentialStore store,
            AuditLog auditLog,
            Clock clock,
            int maxAttempts,
            Duration lockoutDuration) {
        this.store = store;
        this.auditLog = auditLog;
        this.clock = clock;
        this.maxAttempts = maxAttempts;
        this.lockoutDuration = lockoutDuration;
    }

    /**
     * Authenticates a username/password pair. The caller keeps ownership of {@code password} and
     * should zero it once done; this method does not retain a reference.
     */
    AuthenticationResult authenticate(String username, char[] password) {
        String key = normalise(username);

        Optional<Long> lockRemaining = lockoutSecondsRemaining(key);
        if (lockRemaining.isPresent()) {
            auditLog.record(key, "LOCKED_OUT");
            return AuthenticationResult.lockedOut(lockRemaining.get());
        }

        Optional<AdminUser> found = store.find(key);
        // Always run the KDF, even for an unknown user, so both paths take comparable time.
        String hash = found.map(AdminUser::passwordHash).orElse(DUMMY_HASH);
        boolean passwordMatches = password != null && PasswordHasher.verify(password, hash);
        boolean granted = found.isPresent() && found.get().enabled() && passwordMatches;

        if (!granted) {
            registerFailure(key);
            auditLog.record(key, "DENIED");
            return AuthenticationResult.denied();
        }

        failures.remove(key);
        auditLog.record(key, "GRANTED");
        return AuthenticationResult.granted(found.get());
    }

    /** Remaining lockout in seconds, or empty if the account is not currently locked. */
    private Optional<Long> lockoutSecondsRemaining(String key) {
        FailureState state = failures.get(key);
        if (state == null || state.count < maxAttempts) {
            return Optional.empty();
        }
        Instant expiry = state.lastFailure.plus(lockoutDuration);
        Instant now = clock.instant();
        if (now.isBefore(expiry)) {
            return Optional.of(Math.max(1, Duration.between(now, expiry).toSeconds()));
        }
        // Lockout elapsed: reset the counter so the user gets a fresh set of attempts.
        failures.remove(key);
        return Optional.empty();
    }

    private void registerFailure(String key) {
        FailureState state = failures.computeIfAbsent(key, k -> new FailureState());
        state.count++;
        state.lastFailure = clock.instant();
    }

    /** Attempts left before {@code username} is locked out. */
    int remainingAttempts(String username) {
        FailureState state = failures.get(normalise(username));
        return state == null ? maxAttempts : Math.max(0, maxAttempts - state.count);
    }

    private static String normalise(String username) {
        return username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
    }

    private static final class FailureState {
        private int count;
        private Instant lastFailure = Instant.EPOCH;
    }
}
