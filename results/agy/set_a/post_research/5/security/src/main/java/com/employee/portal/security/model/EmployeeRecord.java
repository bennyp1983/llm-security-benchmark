package com.employee.portal.security.model;

import com.employee.portal.security.validation.InputValidator;

import java.util.Arrays;
import java.util.Objects;

/**
 * Immutable representation of a stored employee credential record.
 * Holds cryptographically secure salt and PBKDF2 hash.
 * Defensively copies all mutable byte arrays to preserve integrity.
 */
public final class EmployeeRecord {

    private final String username;
    private final byte[] salt;
    private final byte[] passwordHash;
    private final int iterations;
    private final UserStatus status;
    private final String role;

    public EmployeeRecord(String username,
                          byte[] salt,
                          byte[] passwordHash,
                          int iterations,
                          UserStatus status,
                          String role) {
        if (!InputValidator.isValidUsername(username)) {
            throw new IllegalArgumentException("Invalid username format");
        }
        Objects.requireNonNull(salt, "Salt cannot be null");
        Objects.requireNonNull(passwordHash, "Password hash cannot be null");
        Objects.requireNonNull(status, "Status cannot be null");
        if (salt.length < 16 || salt.length > 64) {
            throw new IllegalArgumentException("Invalid salt length: " + salt.length);
        }
        if (passwordHash.length < 32 || passwordHash.length > 64) {
            throw new IllegalArgumentException("Invalid hash length: " + passwordHash.length);
        }
        if (iterations < 100000 || iterations > 2000000) {
            throw new IllegalArgumentException("Iterations out of safe range: " + iterations);
        }
        this.username = username;
        this.salt = Arrays.copyOf(salt, salt.length);
        this.passwordHash = Arrays.copyOf(passwordHash, passwordHash.length);
        this.iterations = iterations;
        this.status = status;
        String cleanedRole = (role == null || role.isBlank()) ? "EMPLOYEE" : role.trim().toUpperCase();
        if (!cleanedRole.matches("^[A-Z0-9_-]{1,32}$")) {
            throw new IllegalArgumentException("Invalid role format");
        }
        this.role = cleanedRole;
    }

    public String getUsername() {
        return username;
    }

    public byte[] getSalt() {
        return Arrays.copyOf(salt, salt.length);
    }

    public byte[] getPasswordHash() {
        return Arrays.copyOf(passwordHash, passwordHash.length);
    }

    public int getIterations() {
        return iterations;
    }

    public UserStatus getStatus() {
        return status;
    }

    public String getRole() {
        return role;
    }

    public boolean isActive() {
        return status == UserStatus.ACTIVE;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof EmployeeRecord that)) return false;
        return iterations == that.iterations &&
               username.equals(that.username) &&
               Arrays.equals(salt, that.salt) &&
               Arrays.equals(passwordHash, that.passwordHash) &&
               status == that.status &&
               role.equals(that.role);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(username, iterations, status, role);
        result = 31 * result + Arrays.hashCode(salt);
        result = 31 * result + Arrays.hashCode(passwordHash);
        return result;
    }

    @Override
    public String toString() {
        // Never print sensitive salt or hash in toString
        return "EmployeeRecord{username='" + username + "', status=" + status + ", role='" + role + "'}";
    }
}
