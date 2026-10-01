package com.security.auth.model;

import com.security.auth.validation.InputValidator;
import com.security.auth.validation.ValidationException;

import java.util.Arrays;
import java.util.Objects;

/**
 * Server-side user credential record (Rule 1 & Rule 3).
 * Represents stored state against which authentication requests are verified.
 * Defensive copies are maintained to prevent external mutation.
 */
public final class UserRecord {

    private final String username;
    private final byte[] passwordHash;
    private final byte[] salt;
    private final int iterations;
    private final String algorithm;
    private final AccountStatus accountStatus;

    public UserRecord(String username, byte[] passwordHash, byte[] salt, int iterations, String algorithm, AccountStatus accountStatus) {
        try {
            this.username = InputValidator.validateUsername(username);
        } catch (ValidationException e) {
            throw new IllegalArgumentException("Invalid username in UserRecord: " + e.getMessage(), e);
        }

        if (passwordHash == null || passwordHash.length < 32 || passwordHash.length > 128) {
            throw new IllegalArgumentException("Password hash length must be between 32 and 128 bytes.");
        }
        if (salt == null || salt.length < 16 || salt.length > 64) {
            throw new IllegalArgumentException("Salt length must be between 16 and 64 bytes.");
        }
        if (iterations < 1_000 || iterations > 2_000_000) {
            throw new IllegalArgumentException("Iterations must be between 1,000 and 2,000,000.");
        }
        if (algorithm == null || algorithm.isBlank()) {
            throw new IllegalArgumentException("Algorithm must not be blank.");
        }

        this.passwordHash = Arrays.copyOf(passwordHash, passwordHash.length);
        this.salt = Arrays.copyOf(salt, salt.length);
        this.iterations = iterations;
        this.algorithm = algorithm;
        this.accountStatus = Objects.requireNonNull(accountStatus, "AccountStatus cannot be null.");
    }

    public String getUsername() {
        return username;
    }

    public byte[] getPasswordHash() {
        return Arrays.copyOf(passwordHash, passwordHash.length);
    }

    public byte[] getSalt() {
        return Arrays.copyOf(salt, salt.length);
    }

    public int getIterations() {
        return iterations;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public AccountStatus getAccountStatus() {
        return accountStatus;
    }
}
