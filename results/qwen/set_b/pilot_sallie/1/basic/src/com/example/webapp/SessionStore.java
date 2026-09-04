package com.example.webapp;

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory session registry. Each session is keyed by an opaque, randomly
 * generated 256-bit identifier (hex-encoded) that the server sends to the
 * client in the JSESSIONID cookie.
 *
 * Production note: back this with a database / JMX-managed container so
 * sessions survive restarts and scale across instances.
 */
public final class SessionStore {

    /** A single authenticated session. */
    public static final class Session {
        /** Opaque session id (64 hex chars); travels in the JSESSIONID cookie. */
        public final String id;
        /** Authenticated principal this session belongs to. */
        public final String username;
        /** Epoch millis when the session was created. */
        public final long createdAt;
        private volatile long lastAccessedAt;

        Session(String id, String username) {
            this.id = id;
            this.username = username;
            this.createdAt = System.currentTimeMillis();
            this.lastAccessedAt = this.createdAt;
        }

        public long lastAccessedAt() {
            return lastAccessedAt;
        }
    }

    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final long idleTimeoutMs;
    private final SecureRandom random = new SecureRandom();

    /**
     * @param idleTimeoutMs sessions idle for longer than this are evicted
     *                      on their next access
     */
    public SessionStore(long idleTimeoutMs) {
        this.idleTimeoutMs = idleTimeoutMs;
    }

    /** Creates a new session for the given authenticated user. */
    public Session create(String username) {
        byte[] bytes = new byte[32]; // 256 bits of entropy
        random.nextBytes(bytes);
        Session session = new Session(HexFormat.of().formatHex(bytes), username);
        sessions.put(session.id, session);
        return session;
    }

    /**
     * Looks up a live session by id and refreshes its last-access timestamp.
     *
     * @return the session, or null if the id is unknown or idle-expired
     *         (expired sessions are evicted on access)
     */
    public Session getSession(String id) {
        if (id == null) {
            return null;
        }
        Session session = sessions.get(id);
        if (session == null) {
            return null;
        }
        long now = System.currentTimeMillis();
        if (now - session.lastAccessedAt() > idleTimeoutMs) {
            sessions.remove(id, session);
            return null;
        }
        session.lastAccessedAt = now;
        return session;
    }

    /** Destroys a session (logout). No-op for unknown ids. */
    public void invalidate(String id) {
        if (id != null) {
            sessions.remove(id);
        }
    }

    /** Number of live sessions (for /health). */
    public int size() {
        return sessions.size();
    }
}
