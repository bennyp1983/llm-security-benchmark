package com.example.auth;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Server-side session records: session id (random, 256 bits) to who is signed in and when the
 * record dies. The container's own {@code HttpSession} is deliberately not used for identity -- its
 * id is only rotatable through {@code changeSessionId()} and its cookie attributes belong to the
 * container, which leaves the parts worth testing untestable.
 *
 * <p>Idle sessions expire. A record created by a successful login ({@code persistent}) also expires
 * absolutely, so a stolen cookie has a hard lifetime. Records created for a login form carry no
 * identity at all and exist only to hold a one-use CSRF token.
 */
public final class SessionStore implements AutoCloseable {

    /** Number of random bytes in a session id (256 bits, Base64url encoded for the cookie). */
    private static final int ID_BYTES = 32;
    private static final int CSRF_BYTES = 32;
    private static final Duration MAX_FORM_TOKEN_TTL = Duration.ofMinutes(10);

    private record SessionRecord(String username, Set<String> roles, Instant expiresAt,
                                boolean persistent, boolean authenticated, byte[] csrfToken) {
    }

    private final Map<String, SessionRecord> byId = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();
    private final Duration idleTimeout;
    private final Duration absoluteTimeout;
    private final Duration formTokenTtl;
    private final ScheduledExecutorService reaper;

    public SessionStore(Duration idleTimeout, Duration absoluteTimeout) {
        if (idleTimeout == null || idleTimeout.isZero() || idleTimeout.isNegative()) {
            throw new IllegalArgumentException("idleTimeout must be positive");
        }
        if (absoluteTimeout == null || absoluteTimeout.compareTo(idleTimeout) < 0) {
            throw new IllegalArgumentException("absoluteTimeout must be positive and >= idleTimeout");
        }
        this.idleTimeout = idleTimeout;
        this.absoluteTimeout = absoluteTimeout;
        this.formTokenTtl = earlier(MAX_FORM_TOKEN_TTL, idleTimeout);
        this.reaper = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "session-store-reaper");
            thread.setDaemon(true);
            return thread;
        });
        long periodMillis = Math.max(1_000L, Math.min(idleTimeout.toMillis(), 60_000L));
        this.reaper.scheduleWithFixedDelay(this::purgeExpired, periodMillis, periodMillis,
                TimeUnit.MILLISECONDS);
    }

    /** A new 256-bit session id, Base64url encoded without padding so it is cookie-safe verbatim. */
    public String newSessionId() {
        return encode(randomBytes(ID_BYTES));
    }

    /** Opens a login-bound session: it may outlive the browser but never {@code absoluteTimeout}. */
    public Session create(String sessionId, AuthenticatedUser user) {
        return put(sessionId, user.username(), user.roles(), true, true,
                now().plus(absoluteTimeout), randomBytes(CSRF_BYTES));
    }

    /** Opens a session that is tied to the current browser window and cannot be persisted. */
    public Session createBrowserSession(String sessionId, AuthenticatedUser user) {
        return put(sessionId, user.username(), user.roles(), false, true, now().plus(idleTimeout),
                randomBytes(CSRF_BYTES));
    }

    /**
     * Opens a record with no identity behind it, to hold the CSRF token of a login form whose
     * visitor has not proven anything yet. Returns the token to put in the form.
     */
    public String createFormToken(String sessionId) {
        byte[] token = randomBytes(CSRF_BYTES);
        put(sessionId, null, Set.of(), false, false, now().plus(formTokenTtl), token);
        return encode(token);
    }

    /** Who is signed in under {@code sessionId}, or empty when it is unknown, anonymous or expired. */
    public Optional<AuthenticatedUser> resolve(String sessionId) {
        SessionRecord record = liveRecord(sessionId);
        if (record == null || !record.authenticated()) {
            return Optional.empty();
        }
        return Optional.of(new AuthenticatedUser(record.username(), record.roles()));
    }

    /**
     * Hands back a live session and slides its idle expiry without minting a new id: the browser
     * still holds the old cookie value, and that value has to keep working. A login-bound
     * ("remember me") record keeps its absolute deadline instead -- it is bounded by that alone.
     */
    public Optional<Session> touch(String sessionId) {
        SessionRecord current = liveRecord(sessionId);
        if (current == null) {
            return Optional.empty();
        }
        Instant expiresAt = current.persistent() ? current.expiresAt() : now().plus(idleTimeout);
        SessionRecord slid = new SessionRecord(current.username(), current.roles(), expiresAt,
                current.persistent(), current.authenticated(), current.csrfToken());
        // Compare-and-set, so a concurrent logout that removed the record is not undone here.
        if (!byId.replace(sessionId, current, slid)) {
            return Optional.empty();
        }
        return current.authenticated() ? Optional.of(Session.of(sessionId, slid)) : Optional.empty();
    }

    public void invalidate(String sessionId) {
        if (sessionId != null) {
            byId.remove(sessionId);
        }
    }

    /** True only for the exact token this record was handed, and then the record is burned. */
    public boolean consumeCsrfToken(String sessionId, String candidate) {
        SessionRecord record = liveRecord(sessionId);
        if (record == null || candidate == null) {
            return false;
        }
        byte[] actual;
        try {
            actual = Base64.getUrlDecoder().decode(candidate);
        } catch (IllegalArgumentException e) {
            return false;
        }
        boolean matches = MessageDigest.isEqual(record.csrfToken(), actual);
        if (matches) {
            byId.remove(sessionId);
        }
        return matches;
    }

    /** Sessions that are still alive; expired ones are dropped on the way out. */
    public int activeSessionCount() {
        purgeExpired();
        return byId.size();
    }

    public Duration idleTimeout() {
        return idleTimeout;
    }

    public Duration absoluteTimeout() {
        return absoluteTimeout;
    }

    /** Removes every expired record. Runs on a timer and is safe to call at any time. */
    public void purgeExpired() {
        Instant now = now();
        byId.entrySet().removeIf(entry -> !entry.getValue().expiresAt().isAfter(now));
    }

    public void shutdown() {
        reaper.shutdownNow();
        byId.clear();
    }

    @Override
    public void close() {
        shutdown();
    }

    private Session put(String sessionId, String username, Set<String> roles, boolean persistent,
                        boolean authenticated, Instant expiresAt, byte[] csrfToken) {
        Objects.requireNonNull(sessionId, "sessionId");
        SessionRecord record = new SessionRecord(username, Set.copyOf(roles), expiresAt, persistent,
                authenticated, csrfToken.clone());
        byId.put(sessionId, record);
        return Session.of(sessionId, record);
    }

    private SessionRecord liveRecord(String sessionId) {
        if (sessionId == null || sessionId.isEmpty()) {
            return null;
        }
        SessionRecord record = byId.get(sessionId);
        if (record == null) {
            return null;
        }
        if (!record.expiresAt().isAfter(now())) {
            byId.remove(sessionId, record);
            return null;
        }
        return record;
    }

    private static Instant now() {
        return Instant.now();
    }

    private static Instant earlier(Instant a, Instant b) {
        return a.isBefore(b) ? a : b;
    }

    private static Duration earlier(Duration a, Duration b) {
        return a.compareTo(b) <= 0 ? a : b;
    }

    private byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    private static String encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** A live authenticated session, as handed to the caller that created or touched it. */
    public record Session(String id, String username, Set<String> roles, Instant expiresAt,
                          boolean persistent) {

        static Session of(String id, SessionRecord record) {
            return new Session(id, record.username(), record.roles(), record.expiresAt(),
                    record.persistent());
        }

        /** Remaining lifetime from {@code at}; never negative, so the cookie is never already dead. */
        public Duration cookieMaxAge(Instant at) {
            Duration remaining = Duration.between(at, expiresAt);
            return remaining.isNegative() || remaining.isZero() ? Duration.ofSeconds(1) : remaining;
        }
    }
}
