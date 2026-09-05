package com.example.portal.auth;

import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;

/**
 * Checks employee credentials against the records store, under a per-account lockout.
 *
 * <p>Order of checks matters. The lockout is evaluated <em>before</em> the password, so a
 * locked account costs an attacker a rejection rather than a guess. A correct password
 * supplied during a lockout is still refused; that is the point of the lock.
 */
public final class AuthenticationService {

    /** Default policy: five consecutive misses, then a fifteen-minute cool-off. */
    public static final int DEFAULT_MAX_ATTEMPTS = 5;
    public static final Duration DEFAULT_LOCKOUT = Duration.ofMinutes(15);

    /**
     * Hash of a value no one will type. Verifying against it when the account does not
     * exist makes the unknown-user path cost roughly the same as the known-user path, so
     * response time does not reveal which usernames are real.
     */
    private static final String DUMMY_HASH =
            PasswordHasher.hash("$2-not-a-real-password-placeholder".toCharArray());

    private final CredentialStore store;
    private final LockoutPolicy lockoutPolicy;

    public AuthenticationService(CredentialStore store) {
        this(store, new LockoutPolicy(DEFAULT_MAX_ATTEMPTS, DEFAULT_LOCKOUT));
    }

    public AuthenticationService(CredentialStore store, LockoutPolicy lockoutPolicy) {
        this.store = store;
        this.lockoutPolicy = lockoutPolicy;
    }

    public LockoutPolicy lockoutPolicy() {
        return lockoutPolicy;
    }

    /**
     * Authenticates one attempt.
     *
     * <p>The password array is wiped before returning, so the cleartext does not linger on
     * the heap waiting for a crash dump. Pass a copy if the caller still needs it.
     */
    public AuthResult authenticate(String username, char[] password) {
        String account = InMemoryCredentialStore.canonical(username);
        try {
            if (account.isEmpty() || password == null || password.length == 0) {
                return AuthResult.invalid(lockoutPolicy.remainingAttempts(account));
            }

            LockoutPolicy.Status status = lockoutPolicy.check(account);
            if (status.lockedOut()) {
                return AuthResult.lockedOut(status.remaining());
            }

            Optional<UserRecord> record = store.find(account);

            // Always run a verification, even for unknown accounts, to keep timing uniform.
            String hash = record.map(UserRecord::passwordHash).orElse(DUMMY_HASH);
            boolean passwordMatches = PasswordHasher.verify(password, hash);
            boolean granted = passwordMatches && record.isPresent() && record.get().enabled();

            if (granted) {
                lockoutPolicy.recordSuccess(account);
                return AuthResult.success(record.get().username());
            }

            // Failures on unknown and disabled accounts are counted too, so the lockout
            // behaviour itself does not disclose whether an account exists.
            LockoutPolicy.Status after = lockoutPolicy.recordFailure(account);
            if (after.lockedOut()) {
                return AuthResult.lockedOut(after.remaining());
            }
            if (record.isPresent() && !record.get().enabled() && passwordMatches) {
                return AuthResult.disabled();
            }
            return AuthResult.invalid(Math.max(0, lockoutPolicy.maxAttempts() - after.consecutiveFailures()));
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }
}
