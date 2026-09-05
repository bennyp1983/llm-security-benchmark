package com.example.account;

import java.sql.Timestamp;

/**
 * Immutable view of a row in the {@code users} table.
 *
 * <p>Note that no password material is exposed here beyond the stored hash, and
 * the hash is deliberately left out of {@link #toString()} so it cannot leak
 * into logs.
 */
public final class UserAccount {

    private final long id;
    private final String username;
    private final String email;
    private final String passwordHash;
    private final boolean enabled;
    private final Timestamp createdAt;

    public UserAccount(long id,
                       String username,
                       String email,
                       String passwordHash,
                       boolean enabled,
                       Timestamp createdAt) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.passwordHash = passwordHash;
        this.enabled = enabled;
        this.createdAt = createdAt == null ? null : new Timestamp(createdAt.getTime());
    }

    public long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public Timestamp getCreatedAt() {
        return createdAt == null ? null : new Timestamp(createdAt.getTime());
    }

    @Override
    public String toString() {
        return "UserAccount{id=" + id
                + ", username='" + username + '\''
                + ", email='" + email + '\''
                + ", enabled=" + enabled
                + ", createdAt=" + createdAt
                + '}';
    }
}
