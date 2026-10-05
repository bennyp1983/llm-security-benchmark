package com.example.adminportal;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

/**
 * An authenticated administrator session.
 *
 * <p>Bounded by both an idle timeout and an absolute lifetime, so an unattended terminal stops
 * being an open door to admin functionality.
 */
final class AdminSession {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final String id;
    private final AdminUser user;
    private final Clock clock;
    private final Duration idleTimeout;
    private final Instant absoluteExpiry;

    private Instant lastActivity;
    private boolean terminated;

    AdminSession(AdminUser user, Clock clock, Duration idleTimeout, Duration maxLifetime) {
        this.id = newSessionId();
        this.user = user;
        this.clock = clock;
        this.idleTimeout = idleTimeout;
        this.lastActivity = clock.instant();
        this.absoluteExpiry = lastActivity.plus(maxLifetime);
    }

    private static String newSessionId() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    String id() {
        return id;
    }

    AdminUser user() {
        return user;
    }

    boolean isActive() {
        if (terminated) {
            return false;
        }
        Instant now = clock.instant();
        return now.isBefore(absoluteExpiry) && now.isBefore(lastActivity.plus(idleTimeout));
    }

    void touch() {
        lastActivity = clock.instant();
    }

    void terminate() {
        terminated = true;
    }

    /** Authorisation check for a single privileged operation. */
    boolean isAuthorised(String requiredRole) {
        return isActive() && user.hasRole(requiredRole);
    }
}
