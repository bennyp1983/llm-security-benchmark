package com.example.auth;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory map from session identifier to authenticated state.
 *
 * <p>This is deliberately not the container's {@code HttpSession}. Nothing here ever calls
 * {@code request.getSession()}, so no second cookie ({@code JSESSIONID}) is ever minted and a request
 * never carries two identities that can disagree - verified in both {@code TestHarness} and
 * {@code smoke-test.sh}. {@code web.xml} additionally marks the container session cookie HttpOnly and
 * Secure and sets {@code tracking-mode="COOKIE"}, so if some library does ask for a container session
 * it cannot leak its identifier into a URL.
 *
 * <p>Single-JVM and non-durable: restarting the application logs everyone out, and it does not scale
 * horizontally. A real deployment swaps it for a shared store (Redis, a database table) behind this
 * same interface. Identifiers are the map key, so a lookup is a hash probe, not a scan;
 * {@link SessionIdentifier#matches(String)} is what an attacker-facing comparison uses.
 */
public final class InMemorySessionStore {

    private final Map<String, AuthenticatedSession> sessions = new ConcurrentHashMap<>();

    /**
     * Mints a fresh identifier for {@code user} and records the session. Callers must call this on
     * every successful login, including for a user who already had a session, so an identifier fixed
     * before authentication never names an authenticated session.
     */
    public AuthenticatedSession create(SessionUser user, Duration ttl) {
        Instant now = Instant.now();
        AuthenticatedSession session =
                new AuthenticatedSession(SessionIdentifier.generate(), user, now, now.plus(ttl));
        sweep(now);
        sessions.put(session.identifier().value(), session);
        return session;
    }

    /**
     * Resolves a cookie value to live session state. An unknown, expired, or malformed value yields
     * empty, which callers must translate into "anonymous" - never into a session for anybody.
     */
    public Optional<AuthenticatedSession> findLive(String rawIdentifier) {
        if (rawIdentifier == null || rawIdentifier.isEmpty()) {
            return Optional.empty();
        }
        SessionIdentifier identifier;
        try {
            identifier = SessionIdentifier.of(rawIdentifier);
        } catch (IllegalArgumentException craftedValue) {
            return Optional.empty();
        }
        AuthenticatedSession session = sessions.get(identifier.value());
        if (session == null || !session.isLive(Instant.now())) {
            return Optional.empty();
        }
        // Constant-time check that the presented value really is this session's identifier. The map
        // already guarantees it, but the comparison is the place an implementation could otherwise
        // drift into early-exit equality on a secret.
        if (!identifier.matches(session.identifier().value())) {
            return Optional.empty();
        }
        return Optional.of(session);
    }

    /** Drops a session so its identifier stops resolving, even if the cookie survives client side. */
    public void remove(String rawIdentifier) {
        if (rawIdentifier != null) {
            sessions.remove(rawIdentifier);
        }
    }

    public int activeCount() {
        sweep(Instant.now());
        return sessions.size();
    }

    private void sweep(Instant now) {
        sessions.values().removeIf(session -> !session.isLive(now));
    }
}
