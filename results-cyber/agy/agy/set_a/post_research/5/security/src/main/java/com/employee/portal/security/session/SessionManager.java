package com.employee.portal.security.session;

import com.employee.portal.security.config.SecurityConfig;
import com.employee.portal.security.crypto.SecureTokenGenerator;
import com.employee.portal.security.model.Session;
import com.employee.portal.security.ratelimit.BoundedLruCache;
import com.employee.portal.security.validation.InputValidator;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongSupplier;

/**
 * Manages active employee portal sessions.
 * Complies with Rule 3 (verify against server-side state, fail closed),
 * Rule 4 (cryptographically secure tokens, strict token validation),
 * Rule 5 (bounded storage size), and Rule 7 (atomic operations).
 */
public final class SessionManager {

    private final BoundedLruCache<String, Session> sessionCache;
    private final SecureTokenGenerator tokenGenerator;
    private final long idleTimeoutMillis;
    private final long absoluteTimeoutMillis;
    private final int maxSessionsPerUser;
    private final LongSupplier clock;
    private final ReentrantLock userSessionLock;

    public SessionManager(SecurityConfig config) {
        this(config, new SecureTokenGenerator(), System::currentTimeMillis);
    }

    public SessionManager(SecurityConfig config, SecureTokenGenerator tokenGenerator, LongSupplier clock) {
        this.sessionCache = new BoundedLruCache<>(config.getMaxActiveSessions());
        this.tokenGenerator = Objects.requireNonNull(tokenGenerator);
        this.idleTimeoutMillis = config.getSessionIdleTimeoutMillis();
        this.absoluteTimeoutMillis = config.getSessionAbsoluteTimeoutMillis();
        this.maxSessionsPerUser = config.getMaxSessionsPerUser();
        this.clock = Objects.requireNonNull(clock);
        this.userSessionLock = new ReentrantLock();
    }

    /**
     * Creates a new authenticated session for the employee.
     * Generates a 256-bit unguessable random token and bounds active sessions per user.
     */
    public Session createSession(String username, String role, String sourceIp) {
        Objects.requireNonNull(username, "Username cannot be null");
        Objects.requireNonNull(role, "Role cannot be null");

        long now = clock.getAsLong();
        long absoluteExpiresAt = now + absoluteTimeoutMillis;
        String token = tokenGenerator.generateToken();

        Session session = new Session(token, username, role, sourceIp, now, absoluteExpiresAt);

        userSessionLock.lock();
        try {
            // Evict oldest session for this user if max sessions exceeded
            List<Session> userSessions = new ArrayList<>();
            sessionCache.forEach((k, s) -> {
                if (s.getUsername().equalsIgnoreCase(username)) {
                    userSessions.add(s);
                }
            });

            if (userSessions.size() >= maxSessionsPerUser) {
                userSessions.sort((a, b) -> Long.compare(a.getLastAccessedAt(), b.getLastAccessedAt()));
                int toRemove = userSessions.size() - maxSessionsPerUser + 1;
                for (int i = 0; i < toRemove; i++) {
                    sessionCache.remove(userSessions.get(i).getSessionId());
                }
            }

            sessionCache.put(token, session);
        } finally {
            userSessionLock.unlock();
        }

        return session;
    }

    /**
     * Validates a session token against server-side state.
     * Fails closed: returns empty if token is missing, malformed, expired, or source IP mismatch.
     */
    public Optional<Session> validateSession(String token, String currentSourceIp) {
        if (!InputValidator.isValidSessionToken(token)) {
            return Optional.empty();
        }

        Session session = sessionCache.get(token);
        if (session == null) {
            return Optional.empty();
        }

        long now = clock.getAsLong();
        if (session.isExpired(now, idleTimeoutMillis)) {
            sessionCache.remove(token);
            return Optional.empty();
        }

        // Validate client IP binding if source IP is available (prevents session hijacking)
        if (currentSourceIp != null && session.getSourceIp() != null) {
            if (!session.getSourceIp().equals(currentSourceIp)) {
                // Suspicious IP change for active session: invalidate
                sessionCache.remove(token);
                return Optional.empty();
            }
        }

        // Session valid, touch last access time
        session.touch(now);
        return Optional.of(session);
    }

    /**
     * Revokes an existing session.
     */
    public void revokeSession(String token) {
        if (token != null) {
            sessionCache.remove(token);
        }
    }

    /**
     * Revokes all active sessions for a user (e.g. on password change or account suspension).
     */
    public void revokeAllForUser(String username) {
        if (username == null) return;
        userSessionLock.lock();
        try {
            List<String> toRemove = new ArrayList<>();
            sessionCache.forEach((token, session) -> {
                if (session.getUsername().equalsIgnoreCase(username)) {
                    toRemove.add(token);
                }
            });
            for (String token : toRemove) {
                sessionCache.remove(token);
            }
        } finally {
            userSessionLock.unlock();
        }
    }

    public int getActiveSessionCount() {
        return sessionCache.size();
    }

    public void clear() {
        sessionCache.clear();
    }
}
