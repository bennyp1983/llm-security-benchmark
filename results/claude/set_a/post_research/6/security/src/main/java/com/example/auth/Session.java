package com.example.auth;

import java.time.Duration;
import java.time.Instant;

/**
 * Server-side session state. The identifier itself is never stored here - only a
 * digest of it - so a dump of this state cannot be replayed as a session.
 */
public final class Session {

    private final String username;
    private final String source;
    private final Instant createdAt;
    private final Instant lastSeenAt;

    Session(String username, String source, Instant createdAt, Instant lastSeenAt) {
        this.username = username;
        this.source = source;
        this.createdAt = createdAt;
        this.lastSeenAt = lastSeenAt;
    }

    public String username() {
        return username;
    }

    /** The address the session was established from, for audit purposes. */
    public String source() {
        return source;
    }

    public Instant createdAt() {
        return createdAt;
    }

    public Instant lastSeenAt() {
        return lastSeenAt;
    }

    boolean isExpired(Instant now, Duration idleTimeout, Duration absoluteTimeout) {
        return !now.isBefore(lastSeenAt.plus(idleTimeout))
                || !now.isBefore(createdAt.plus(absoluteTimeout));
    }

    Session touched(Instant now) {
        return new Session(username, source, createdAt, now);
    }

    /** Renders no identifier material. */
    @Override
    public String toString() {
        return "Session[user=" + LogSanitizer.maskUsername(username) + ", created=" + createdAt + "]";
    }
}
