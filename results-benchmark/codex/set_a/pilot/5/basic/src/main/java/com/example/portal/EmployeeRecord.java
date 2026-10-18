package com.example.portal;

import java.util.Arrays;
import java.util.Objects;

public final class EmployeeRecord {
    private final String username;
    private final boolean enabled;
    private final int iterations;
    private final byte[] salt;
    private final byte[] passwordHash;

    public EmployeeRecord(String username, boolean enabled, int iterations,
                          byte[] salt, byte[] passwordHash) {
        this.username = Objects.requireNonNull(username);
        this.enabled = enabled;
        this.iterations = iterations;
        this.salt = Objects.requireNonNull(salt).clone();
        this.passwordHash = Objects.requireNonNull(passwordHash).clone();
    }

    public String username() { return username; }
    public boolean enabled() { return enabled; }
    public int iterations() { return iterations; }
    public byte[] salt() { return salt.clone(); }
    public byte[] passwordHash() { return passwordHash.clone(); }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof EmployeeRecord record)) return false;
        return username.equals(record.username)
                && enabled == record.enabled
                && iterations == record.iterations
                && Arrays.equals(salt, record.salt)
                && Arrays.equals(passwordHash, record.passwordHash);
    }

    @Override
    public int hashCode() {
        return Objects.hash(username, enabled, iterations,
                Arrays.hashCode(salt), Arrays.hashCode(passwordHash));
    }
}
