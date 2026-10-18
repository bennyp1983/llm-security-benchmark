package com.security.auth.model;

import java.time.Instant;
import java.util.Objects;

/**
 * Server-side session record.
 * Tracks session lifetime, inactivity, and issuing client source IP.
 */
public final class Session {

    private final String id;
    private final String userId;
    private final String tokenHash;
    private final Instant createdAt;
    private final Instant expiresAt;
    private final Instant lastActiveAt;
    private final String sourceIp;

    public Session(String id, String userId, String tokenHash, Instant createdAt, Instant expiresAt, Instant lastActiveAt, String sourceIp) {
        this.id = Objects.requireNonNull(id, "id must not be null");
        this.userId = Objects.requireNonNull(userId, "userId must not be null");
        this.tokenHash = Objects.requireNonNull(tokenHash, "tokenHash must not be null");
        this.createdAt = Objects.requireNonNull(createdAt, "createdAt must not be null");
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt must not be null");
        this.lastActiveAt = Objects.requireNonNull(lastActiveAt, "lastActiveAt must not be null");
        this.sourceIp = Objects.requireNonNull(sourceIp, "sourceIp must not be null");
    }

    public String getId() {
        return id;
    }

    public String getUserId() {
        return userId;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getLastActiveAt() {
        return lastActiveAt;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public boolean isExpired(Instant now) {
        return now.isAfter(expiresAt);
    }

    @Override
    public String toString() {
        return "Session{" +
                "id='" + id + '\'' +
                ", userId='" + userId + '\'' +
                ", tokenHash=[PROTECTED]" +
                ", createdAt=" + createdAt +
                ", expiresAt=" + expiresAt +
                ", lastActiveAt=" + lastActiveAt +
                ", sourceIp='" + sourceIp + '\'' +
                '}';
    }
}
