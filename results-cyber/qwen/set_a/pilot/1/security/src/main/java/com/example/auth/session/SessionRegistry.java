package com.example.auth.session;

import java.time.Duration;
import java.time.Instant;

/**
 * Server-side bookkeeping behind the cookie. The identifier in the browser is only a lookup key:
 * who a request belongs to and when the session dies are decided here, so stealing the cookie is the
 * most an attacker can do and never grants more than the legitimate holder had.
 */
public interface SessionRegistry {

    /**
     * Binds a freshly issued identifier to the authenticated subject.
     *
     * @param ttl absolute lifetime; the cookie is told the same value so client and server agree on
     *            when the session ends
     */
    void register(String sessionId, String subjectId, Duration ttl);

    /** @return the live binding for {@code sessionId}, or {@code null} if unknown or expired */
    Session find(String sessionId);

    void remove(String sessionId);

    record Session(String sessionId, String subjectId, Instant expiresAt) {

        boolean isExpiredAt(Instant now) {
            return !expiresAt.isAfter(now);
        }
    }
}
