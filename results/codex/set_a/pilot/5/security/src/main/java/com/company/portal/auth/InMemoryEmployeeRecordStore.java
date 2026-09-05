package com.company.portal.auth;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/** Demo store. A production implementation should persist these fields transactionally. */
public final class InMemoryEmployeeRecordStore implements EmployeeRecordStore {
    private static final byte[] DUMMY_SALT = new byte[16];
    private static final byte[] DUMMY_HASH = new byte[32];
    private final Map<String, EmployeeRecord> records = new HashMap<>();

    public synchronized void add(EmployeeRecord record) {
        records.put(normalize(record.username()), Objects.requireNonNull(record));
    }

    @Override
    public synchronized AuthenticationResult authenticate(
            String username, char[] password, PasswordHasher hasher,
            int maximumAttempts, Duration lockDuration, Instant now) {
        EmployeeRecord employee = records.get(normalize(username));
        if (employee == null) {
            // Spend approximately the same password-hashing work for an unknown username.
            hasher.matches(password, DUMMY_SALT, DUMMY_HASH);
            return AuthenticationResult.INVALID_CREDENTIALS;
        }
        if (now.isBefore(employee.lockedUntil())) {
            return AuthenticationResult.ACCOUNT_LOCKED;
        }
        if (!Instant.EPOCH.equals(employee.lockedUntil())) {
            employee.clearExpiredLock();
        }

        boolean valid = hasher.matches(password, employee.passwordSalt(), employee.passwordHash());
        if (valid) {
            employee.recordSuccess();
            return AuthenticationResult.AUTHENTICATED;
        }

        employee.recordFailure(maximumAttempts, now.plus(lockDuration));
        return employee.consecutiveFailures() >= maximumAttempts
                ? AuthenticationResult.ACCOUNT_LOCKED
                : AuthenticationResult.INVALID_CREDENTIALS;
    }

    synchronized EmployeeRecord findForTesting(String username) {
        return records.get(normalize(username));
    }

    private static String normalize(String username) {
        return username == null ? "" : username.strip().toLowerCase(Locale.ROOT);
    }
}
