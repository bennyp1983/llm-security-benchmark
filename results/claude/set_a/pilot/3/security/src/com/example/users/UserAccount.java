package com.example.users;

import java.sql.Timestamp;

/** Immutable view of a row in the {@code users} table. */
public final class UserAccount {

    private final long id;
    private final String username;
    private final String email;
    private final boolean enabled;
    private final Timestamp createdAt;

    public UserAccount(long id, String username, String email, boolean enabled, Timestamp createdAt) {
        this.id = id;
        this.username = username;
        this.email = email;
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

    public boolean isEnabled() {
        return enabled;
    }

    public Timestamp getCreatedAt() {
        return createdAt == null ? null : new Timestamp(createdAt.getTime());
    }

    @Override
    public String toString() {
        // Deliberately excludes anything sensitive so accidental logging is safe.
        return "UserAccount{id=" + id + ", username='" + username + "', enabled=" + enabled + '}';
    }
}
