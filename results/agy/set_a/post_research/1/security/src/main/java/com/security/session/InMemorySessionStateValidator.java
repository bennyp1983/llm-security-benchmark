package com.security.session;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Thread-safe reference implementation of SessionStateValidator.
 * Guarantees atomic verification and claim operations to prevent session fixation and race conditions.
 */
public class InMemorySessionStateValidator implements SessionStateValidator {

    private static final int MAX_ACTIVE_SESSIONS = 50_000;

    public static final class ServerSessionRecord {
        private final String sessionId;
        private final String userId;
        private final Instant createdAt;
        private final Instant expiresAt;
        private final AtomicBoolean claimed = new AtomicBoolean(false);
        private final AtomicBoolean revoked = new AtomicBoolean(false);

        public ServerSessionRecord(String sessionId, String userId, Instant createdAt, Instant expiresAt) {
            this.sessionId = Objects.requireNonNull(sessionId);
            this.userId = Objects.requireNonNull(userId);
            this.createdAt = Objects.requireNonNull(createdAt);
            this.expiresAt = Objects.requireNonNull(expiresAt);
        }

        public String getSessionId() {
            return sessionId;
        }

        public String getUserId() {
            return userId;
        }

        public Instant getExpiresAt() {
            return expiresAt;
        }

        public boolean isClaimed() {
            return claimed.get();
        }

        public boolean isRevoked() {
            return revoked.get();
        }

        public void revoke() {
            revoked.set(true);
        }
    }

    private final ConcurrentHashMap<String, ServerSessionRecord> sessions = new ConcurrentHashMap<>();

    /**
     * Registers a new server-side session created by the upstream trusted authentication component.
     */
    public void registerSession(String sessionId, String userId, Instant expiresAt) {
        if (sessionId == null || userId == null || expiresAt == null) {
            throw new IllegalArgumentException("Session registration arguments cannot be null");
        }
        if (sessions.size() >= MAX_ACTIVE_SESSIONS) {
            // Evict expired entries to bound memory usage
            cleanupExpired();
            if (sessions.size() >= MAX_ACTIVE_SESSIONS) {
                throw new IllegalStateException("Session registry capacity exceeded");
            }
        }
        sessions.put(sessionId, new ServerSessionRecord(sessionId, userId, Instant.now(), expiresAt));
    }

    @Override
    public SessionValidationResult validateAndClaimSession(String sessionId, String userId) {
        if (sessionId == null || userId == null) {
            return SessionValidationResult.failure("NULL_INPUT", "SessionId or UserId was null");
        }

        ServerSessionRecord record = sessions.get(sessionId);
        if (record == null) {
            return SessionValidationResult.failure("SESSION_NOT_FOUND", "Session identifier not found in server state");
        }

        // Check revocation
        if (record.isRevoked()) {
            return SessionValidationResult.failure("SESSION_REVOKED", "Session identifier has been revoked");
        }

        // Check expiration
        if (Instant.now().isAfter(record.getExpiresAt())) {
            sessions.remove(sessionId);
            return SessionValidationResult.failure("SESSION_EXPIRED", "Session identifier has expired");
        }

        // Constant-time comparison of userId to prevent timing attacks
        byte[] expectedUser = record.getUserId().getBytes(StandardCharsets.UTF_8);
        byte[] actualUser = userId.getBytes(StandardCharsets.UTF_8);
        if (!MessageDigest.isEqual(expectedUser, actualUser)) {
            return SessionValidationResult.failure("USER_MISMATCH", "Session does not belong to the claiming user");
        }

        // Atomic check-and-act: claim the session once
        if (!record.claimed.compareAndSet(false, true)) {
            return SessionValidationResult.failure("ALREADY_CLAIMED", "Session has already been claimed / issued");
        }

        return SessionValidationResult.success();
    }

    public void cleanupExpired() {
        Instant now = Instant.now();
        sessions.entrySet().removeIf(entry -> now.isAfter(entry.getValue().getExpiresAt()));
    }

    public int getActiveSessionCount() {
        return sessions.size();
    }
}
