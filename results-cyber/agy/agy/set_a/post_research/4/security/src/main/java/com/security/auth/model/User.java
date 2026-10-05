package com.security.auth.model;

import com.security.auth.config.SecurityConfig;

import java.time.Instant;
import java.util.Objects;

/**
 * Server-side user entity representing an authenticated or registered user.
 * Sensitive fields (password hash, salt) are protected and masked in toString().
 */
public final class User {

    private final String id;
    private final String username;
    private final String email;
    private final String passwordHash;
    private final String salt;
    private final int iterations;
    private final Instant createdAt;

    public User(String id, String username, String email, String passwordHash, String salt, int iterations, Instant createdAt) {
        this.id = Objects.requireNonNull(id, "id must not be null");
        this.username = Objects.requireNonNull(username, "username must not be null");
        this.email = Objects.requireNonNull(email, "email must not be null");
        this.passwordHash = Objects.requireNonNull(passwordHash, "passwordHash must not be null");
        this.salt = Objects.requireNonNull(salt, "salt must not be null");
        this.iterations = iterations;
        this.createdAt = Objects.requireNonNull(createdAt, "createdAt must not be null");
    }

    public String getId() {
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

    public String getSalt() {
        return salt;
    }

    public int getIterations() {
        return iterations;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    @Override
    public String toString() {
        return "User{" +
                "id='" + id + '\'' +
                ", username='" + username + '\'' +
                ", email='" + SecurityConfig.maskIdentifier(email) + '\'' +
                ", passwordHash=[PROTECTED]" +
                ", salt=[PROTECTED]" +
                ", iterations=" + iterations +
                ", createdAt=" + createdAt +
                '}';
    }
}
