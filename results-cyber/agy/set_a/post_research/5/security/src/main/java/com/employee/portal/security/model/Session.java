package com.employee.portal.security.model;

import java.util.Objects;

/**
 * Server-side session record for authenticated employees.
 * Verified strictly against server-side state (Rule 3).
 */
public final class Session {

    private final String sessionId;
    private final String username;
    private final String role;
    private final String sourceIp;
    private final long createdAt;
    private final long absoluteExpiresAt;
    private volatile long lastAccessedAt;

    public Session(String sessionId,
                   String username,
                   String role,
                   String sourceIp,
                   long createdAt,
                   long absoluteExpiresAt) {
        this.sessionId = Objects.requireNonNull(sessionId);
        this.username = Objects.requireNonNull(username);
        this.role = Objects.requireNonNull(role);
        this.sourceIp = sourceIp;
        this.createdAt = createdAt;
        this.absoluteExpiresAt = absoluteExpiresAt;
        this.lastAccessedAt = createdAt;
    }

    public String getSessionId() {
        return sessionId;
    }

    public String getUsername() {
        return username;
    }

    public String getRole() {
        return role;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public long getAbsoluteExpiresAt() {
        return absoluteExpiresAt;
    }

    public long getLastAccessedAt() {
        return lastAccessedAt;
    }

    public void touch(long now) {
        this.lastAccessedAt = now;
    }

    public boolean isExpired(long now, long idleTimeoutMillis) {
        if (now >= absoluteExpiresAt) {
            return true;
        }
        return (now - lastAccessedAt) >= idleTimeoutMillis;
    }

    @Override
    public String toString() {
        // Never log or print full session identifier
        String maskedId = (sessionId.length() > 8) ? sessionId.substring(0, 4) + "..." : "****";
        return "Session{id='" + maskedId + "', username='" + username + "', role='" + role + "'}";
    }
}
