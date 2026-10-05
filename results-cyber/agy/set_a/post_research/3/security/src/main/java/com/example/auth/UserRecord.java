package com.example.auth;

/**
 * Immutable representation of a user record stored in the SQL database.
 */
public record UserRecord(
        long id,
        String email,
        String passwordHash,
        String salt,
        int iterations,
        String algorithm,
        String status
) {
    public boolean isActive() {
        return "ACTIVE".equalsIgnoreCase(status);
    }
}
