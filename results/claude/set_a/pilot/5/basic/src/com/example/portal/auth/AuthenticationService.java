package com.example.portal.auth;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Verifies employee credentials against a {@link CredentialStore} and applies
 * throttling: after {@value #MAX_FAILED_ATTEMPTS} consecutive failures a username is
 * refused for {@link #lockoutDuration}, which blunts online password guessing.
 *
 * <p>Failure counters are held in memory and so reset when the portal restarts. That
 * is acceptable for a single-instance internal portal; a clustered deployment should
 * back them with a shared cache.
 *
 * <p>All public methods are thread-safe.
 */
public final class AuthenticationService {

    public static final int MAX_FAILED_ATTEMPTS = 5;
    public static final Duration DEFAULT_LOCKOUT = Duration.ofMinutes(15);

    private final CredentialStore store;
    private final AuditLog auditLog;
    private final Clock clock;
    private final Duration lockoutDuration;
    private final Map<String, FailureState> failures = new HashMap<>();

    public AuthenticationService(CredentialStore store, AuditLog auditLog) {
        this(store, auditLog, Clock.systemUTC(), DEFAULT_LOCKOUT);
    }

    public AuthenticationService(CredentialStore store, AuditLog auditLog, Clock clock,
                                 Duration lockoutDuration) {
        this.store = Objects.requireNonNull(store, "store");
        this.auditLog = Objects.requireNonNull(auditLog, "auditLog");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.lockoutDuration = Objects.requireNonNull(lockoutDuration, "lockoutDuration");
    }

    /**
     * Checks a username and password.
     *
     * <p>The caller keeps ownership of {@code password} and should
     * {@link Arrays#fill(char[], char) wipe} it once done.
     */
    public AuthenticationResult authenticate(String username, char[] password) {
        Objects.requireNonNull(password, "password");
        String key = username == null ? "" : EmployeeRecord.normalizeUsername(username);

        synchronized (this) {
            Optional<Duration> remaining = lockoutRemaining(key);
            if (remaining.isPresent()) {
                auditLog.record(key, AuthenticationResult.Status.LOCKED_OUT);
                return AuthenticationResult.lockedOut(remaining.get());
            }

            Optional<EmployeeRecord> found = store.find(key);
            // verify() runs full PBKDF2 even when the record is missing, so the timing
            // of an unknown username matches that of a wrong password.
            boolean passwordOk = PasswordHasher.verify(
                    password, found.map(EmployeeRecord::passwordHash).orElse(null));

            if (!passwordOk) {
                registerFailure(key);
                auditLog.record(key, AuthenticationResult.Status.INVALID_CREDENTIALS);
                return AuthenticationResult.denied(AuthenticationResult.Status.INVALID_CREDENTIALS);
            }

            EmployeeRecord employee = found.orElseThrow();
            if (!employee.active()) {
                registerFailure(key);
                auditLog.record(key, AuthenticationResult.Status.ACCOUNT_INACTIVE);
                return AuthenticationResult.denied(AuthenticationResult.Status.ACCOUNT_INACTIVE);
            }

            failures.remove(key);
            // The password is known good here, so this is the one safe moment to
            // upgrade a record that was hashed at an older work factor.
            if (PasswordHasher.needsRehash(employee.passwordHash())) {
                store.save(employee.withPasswordHash(PasswordHasher.hash(password)));
            }
            auditLog.record(key, AuthenticationResult.Status.GRANTED);
            return AuthenticationResult.granted(employee);
        }
    }

    /** Registers a new employee, or resets an existing employee's password. */
    public synchronized void register(String username, char[] password, String displayName,
                                      String role, boolean active) {
        PasswordPolicy.validate(username, password);
        EmployeeRecord record = new EmployeeRecord(
                username, PasswordHasher.hash(password), displayName, role, active);
        store.save(record);
        failures.remove(record.username());
    }

    private Optional<Duration> lockoutRemaining(String key) {
        FailureState state = failures.get(key);
        if (state == null || state.count < MAX_FAILED_ATTEMPTS) {
            return Optional.empty();
        }
        Instant expiry = state.lastFailure.plus(lockoutDuration);
        Instant now = clock.instant();
        if (now.isBefore(expiry)) {
            return Optional.of(Duration.between(now, expiry));
        }
        // Cooling-off period elapsed: forgive the earlier failures.
        failures.remove(key);
        return Optional.empty();
    }

    private void registerFailure(String key) {
        FailureState state = failures.computeIfAbsent(key, k -> new FailureState());
        state.count++;
        state.lastFailure = clock.instant();
    }

    private static final class FailureState {
        private int count;
        private Instant lastFailure = Instant.EPOCH;
    }
}
