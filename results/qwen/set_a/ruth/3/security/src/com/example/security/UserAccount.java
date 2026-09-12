package com.example.security;

import java.time.Instant;
import java.util.Objects;

/**
 * One row of the {@code users} table, as an immutable value.
 *
 * <p>{@code passwordHash} is carried because the authentication layer needs it to verify a
 * credential. It is deliberately kept out of {@link #toString()} so a debug print, a log line or
 * an exception message cannot leak a credential (and its cost factor) out of the process.
 * Compare it only with a constant-time check such as
 * {@code java.security.MessageDigest.isEqual}, and never log it.
 */
public record UserAccount(
        long id,
        String username,
        String email,
        String fullName,
        String status,
        String passwordHash,
        Instant createdAt) {

    public UserAccount {
        Objects.requireNonNull(username, "username");
        Objects.requireNonNull(status, "status");
    }

    public boolean isActive() {
        return "ACTIVE".equalsIgnoreCase(status);
    }

    @Override
    public String toString() {
        return "UserAccount[id=" + id
                + ", username=" + username
                + ", email=" + email
                + ", fullName=" + fullName
                + ", status=" + status
                + ", passwordHash=[redacted]"
                + ", createdAt=" + createdAt
                + "]";
    }
}
