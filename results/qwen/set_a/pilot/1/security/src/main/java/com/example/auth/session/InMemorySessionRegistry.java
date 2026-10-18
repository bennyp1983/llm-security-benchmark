package com.example.auth.session;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Single-node {@link SessionRegistry}. A clustered deployment has to replace this with a shared
 * store, otherwise a session issued by one node is unknown to the next one that receives the cookie.
 */
public final class InMemorySessionRegistry implements SessionRegistry {

    private static final Duration PURGE_INTERVAL = Duration.ofMinutes(1);

    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final AtomicLong nextPurgeEpochMilli = new AtomicLong();

    @Override
    public void register(String sessionId, String subjectId, Duration ttl) {
        Instant now = Instant.now();
        purgeExpired(now);
        Instant expiresAt = now.plus(ttl);
        if (sessions.putIfAbsent(sessionId, new Session(sessionId, subjectId, expiresAt)) != null) {
            throw new IllegalStateException("session identifier already in use");
        }
    }

    @Override
    public Session find(String sessionId) {
        if (sessionId == null) {
            return null;
        }
        Session session = sessions.get(sessionId);
        if (session == null) {
            return null;
        }
        if (session.isExpiredAt(Instant.now())) {
            sessions.remove(sessionId, session);
            return null;
        }
        return session;
    }

    @Override
    public void remove(String sessionId) {
        if (sessionId != null) {
            sessions.remove(sessionId);
        }
    }

    /**
     * Expired sessions are rejected on read; this only stops a long-running node from accumulating
     * entries for clients that never come back.
     */
    private void purgeExpired(Instant now) {
        long nowMilli = now.toEpochMilli();
        long scheduled = nextPurgeEpochMilli.get();
        if (nowMilli < scheduled || !nextPurgeEpochMilli.compareAndSet(scheduled, nowMilli + PURGE_INTERVAL.toMillis())) {
            return;
        }
        sessions.entrySet().removeIf(entry -> entry.getValue().isExpiredAt(now));
    }
}
