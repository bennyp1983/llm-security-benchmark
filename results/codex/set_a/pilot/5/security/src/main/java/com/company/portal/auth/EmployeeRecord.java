package com.company.portal.auth;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

/** Authentication fields normally stored alongside an employee's account record. */
public final class EmployeeRecord {
    private final String username;
    private final byte[] passwordSalt;
    private final byte[] passwordHash;
    private int consecutiveFailures;
    private Instant lockedUntil;

    public EmployeeRecord(String username, byte[] passwordSalt, byte[] passwordHash) {
        this.username = Objects.requireNonNull(username);
        this.passwordSalt = Arrays.copyOf(passwordSalt, passwordSalt.length);
        this.passwordHash = Arrays.copyOf(passwordHash, passwordHash.length);
        this.lockedUntil = Instant.EPOCH;
    }

    public String username() { return username; }
    public byte[] passwordSalt() { return Arrays.copyOf(passwordSalt, passwordSalt.length); }
    public byte[] passwordHash() { return Arrays.copyOf(passwordHash, passwordHash.length); }
    public int consecutiveFailures() { return consecutiveFailures; }
    public Instant lockedUntil() { return lockedUntil; }

    void recordSuccess() {
        consecutiveFailures = 0;
        lockedUntil = Instant.EPOCH;
    }

    void clearExpiredLock() {
        consecutiveFailures = 0;
        lockedUntil = Instant.EPOCH;
    }

    void recordFailure(int maximumAttempts, Instant lockExpiry) {
        consecutiveFailures++;
        if (consecutiveFailures >= maximumAttempts) {
            lockedUntil = lockExpiry;
        }
    }
}
