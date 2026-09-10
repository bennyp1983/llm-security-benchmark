package com.example.auth;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Minimal server-side session registry.
 *
 * <p>The cookie carries only a lookup key; every piece of trusted state
 * (the user identity, the expiry) is held here, where the client cannot
 * tamper with it. Swap the map for Redis or a database in a clustered
 * deployment.
 */
public final class SessionStore {

    /** Absolute lifetime: the session dies at this point regardless of activity. */
    private static final Duration ABSOLUTE_TIMEOUT = Duration.ofHours(8);

    /** Idle timeout: the session dies after this long without a request. */
    private static final Duration IDLE_TIMEOUT = Duration.ofMinutes(30);

    private static final Map<String, Session> SESSIONS = new ConcurrentHashMap<>();

    private SessionStore() {
    }

    public record Session(String userId, Instant createdAt, Instant lastSeenAt) {
    }

    public static void create(String sessionId, String userId) {
        Instant now = Instant.now();
        SESSIONS.put(sessionId, new Session(userId, now, now));
    }

    /**
     * Validates the identifier and refreshes its idle timer.
     *
     * @return the live session, or {@code null} if unknown or expired
     */
    public static Session validate(String sessionId) {
        if (sessionId == null) {
            return null;
        }
        Session session = SESSIONS.get(sessionId);
        if (session == null) {
            return null;
        }
        Instant now = Instant.now();
        boolean expired = session.createdAt().plus(ABSOLUTE_TIMEOUT).isBefore(now)
                || session.lastSeenAt().plus(IDLE_TIMEOUT).isBefore(now);
        if (expired) {
            SESSIONS.remove(sessionId);
            return null;
        }
        Session refreshed = new Session(session.userId(), session.createdAt(), now);
        SESSIONS.put(sessionId, refreshed);
        return refreshed;
    }

    public static void invalidate(String sessionId) {
        if (sessionId != null) {
            SESSIONS.remove(sessionId);
        }
    }
}
