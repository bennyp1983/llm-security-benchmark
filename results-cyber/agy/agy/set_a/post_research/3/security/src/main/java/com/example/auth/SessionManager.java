package com.example.auth;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages cryptographically secure session identifier and token generation.
 * <p>
 * Satisfies Rule 4:
 * - Session tokens generated using SecureRandom (256 bits entropy).
 * - Never accepted from or predictable from caller.
 * - Secure cookie construction: __Host- prefix, HttpOnly, Secure, SameSite=Strict, Path=/.
 * - Clears sensitive raw random bytes immediately from memory.
 */
public final class SessionManager {

    public static final int TOKEN_BYTE_LENGTH = 32; // 256 bits of entropy
    public static final long DEFAULT_SESSION_DURATION_SECONDS = 3600L; // 1 hour
    public static final int MAX_ACTIVE_SESSIONS = 10_000;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public record Session(
            String sessionId,
            long userId,
            String email,
            Instant createdAt,
            Instant expiresAt,
            String cookieHeader
    ) {
        public boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
        }
    }

    private final ConcurrentHashMap<String, Session> activeSessions = new ConcurrentHashMap<>();
    private final long sessionDurationSeconds;

    public SessionManager() {
        this(DEFAULT_SESSION_DURATION_SECONDS);
    }

    public SessionManager(long sessionDurationSeconds) {
        if (sessionDurationSeconds <= 0) {
            throw new IllegalArgumentException("Session duration must be positive");
        }
        this.sessionDurationSeconds = sessionDurationSeconds;
    }

    /**
     * Generates a new cryptographically secure session.
     * Raw entropy bytes are zeroized immediately after URL-safe Base64 encoding.
     *
     * @param userId Database identifier of authenticated user.
     * @param email  Authenticated user's email.
     * @return Generated Session.
     */
    public Session createSession(long userId, String email) {
        evictIfNecessary();

        byte[] randomBytes = new byte[TOKEN_BYTE_LENGTH];
        SECURE_RANDOM.nextBytes(randomBytes);
        String token;
        try {
            token = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        } finally {
            Arrays.fill(randomBytes, (byte) 0);
        }

        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(sessionDurationSeconds);

        // Security best practice: __Host- prefix ensures cookie is restricted to host, requires Secure, and Path=/
        String cookieHeader = String.format(
                "__Host-AuthSession=%s; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=%d",
                token, sessionDurationSeconds
        );

        Session session = new Session(token, userId, email, now, expiresAt, cookieHeader);
        activeSessions.put(token, session);
        return session;
    }

    /**
     * Validates and retrieves an active session by token.
     * Expired sessions are removed and rejected.
     */
    public Optional<Session> validateSession(String token) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        Session session = activeSessions.get(token);
        if (session == null) {
            return Optional.empty();
        }
        if (session.isExpired()) {
            activeSessions.remove(token);
            return Optional.empty();
        }
        return Optional.of(session);
    }

    public void invalidateSession(String token) {
        if (token != null) {
            activeSessions.remove(token);
        }
    }

    private void evictIfNecessary() {
        if (activeSessions.size() > MAX_ACTIVE_SESSIONS) {
            Iterator<Map.Entry<String, Session>> it = activeSessions.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<String, Session> entry = it.next();
                if (entry.getValue().isExpired()) {
                    it.remove();
                }
            }
        }
    }
}
