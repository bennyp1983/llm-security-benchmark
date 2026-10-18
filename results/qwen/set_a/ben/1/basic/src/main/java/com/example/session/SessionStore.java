package com.example.session;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory, thread-safe registry of issued sessions.
 *
 * <p>This stands in for a production session store (database, Redis, ...).
 * A session identifier only means something while it is registered here:
 * the profile endpoint refuses identifiers the store does not know, which
 * is what makes the cookie a real authentication token rather than a plain
 * client-side claim.</p>
 */
public final class SessionStore {

    /** Session identifiers are 32 cryptographically random bytes (256 bits). */
    private static final int IDENTIFIER_BYTES = 32;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

    /** Single shared instance for all servlets of the application. */
    public static final SessionStore INSTANCE = new SessionStore();

    private final Map<String, IssuedSession> sessions = new ConcurrentHashMap<>();

    private SessionStore() {
    }

    /** One registered session: who it belongs to and when it was issued. */
    public static final class IssuedSession {
        private final String user;
        private final Instant issuedAt;

        IssuedSession(String user, Instant issuedAt) {
            this.user = user;
            this.issuedAt = issuedAt;
        }

        public String getUser() {
            return user;
        }

        public Instant getIssuedAt() {
            return issuedAt;
        }
    }

    /**
     * Registers a new session for the authenticated user and returns its
     * fresh session identifier (256 random bits, URL-safe Base64 encoded).
     *
     * @param user the user that was authenticated
     * @return the new session identifier
     */
    public String issue(String user) {
        byte[] raw = new byte[IDENTIFIER_BYTES];
        RANDOM.nextBytes(raw);
        String sessionId = ENCODER.encodeToString(raw);
        sessions.put(sessionId, new IssuedSession(user, Instant.now()));
        return sessionId;
    }

    /**
     * Looks up a session identifier.
     *
     * @param sessionId the identifier from the client's cookie
     * @return the registered session, or {@code null} if the identifier was
     *         never issued or has been revoked
     */
    public IssuedSession lookup(String sessionId) {
        return sessionId == null ? null : sessions.get(sessionId);
    }

    /**
     * Revokes a session identifier.
     *
     * @param sessionId the identifier to revoke
     * @return {@code true} if the identifier was registered
     */
    public boolean revoke(String sessionId) {
        return sessionId != null && sessions.remove(sessionId) != null;
    }
}
