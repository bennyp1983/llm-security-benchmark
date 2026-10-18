package com.portal.auth;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Server-side session and CSRF-token state.
 *
 * <p>A session id is <b>generated here</b> from {@link SecureRandom} (256 bits); it is
 * never accepted from a caller as proof of anything. What the cookie carries is only a
 * lookup key: {@link #find} validates the wire shape, hashes the value, and requires a
 * live server-side entry that has not expired. No entry, expired entry, wrong shape
 * =&gt; anonymous. A forged or guessed cookie therefore grants exactly nothing, and a
 * dumped map does not yield usable ids because only SHA-256(id) is stored.
 *
 * <p>Both maps are bounded and evict oldest-first, so a client that mints requests
 * cannot grow the heap without limit.
 *
 * <h2>Remaining risk, stated plainly</h2>
 * A session id stolen from a browser (XSS, malware, a shared workstation) is usable by
 * the thief until it expires. Mitigations: {@code HttpOnly} (no script reads it),
 * {@code Secure} + HTTPS-only listener (no network sniffing), {@code SameSite=Strict}
 * (not sent on cross-site requests), 20-minute idle / 8-hour absolute lifetime, and a
 * logout that deletes the server-side entry. Full defence needs per-device key
 * confirmation, which is outside this feature.
 */
public final class SessionManager {

    public static final Duration IDLE_TIMEOUT = Duration.ofMinutes(20);
    public static final Duration ABSOLUTE_TIMEOUT = Duration.ofHours(8);
    public static final Duration CSRF_TIMEOUT = Duration.ofMinutes(15);
    public static final int MAX_SESSIONS = 10_000;
    public static final int MAX_PENDING_CSRF = 50_000;

    public static final class Session {
        public final String username;
        final long issuedAtEpochSecond;
        long lastUsedEpochSecond;

        Session(String username, long now) {
            this.username = username;
            this.issuedAtEpochSecond = now;
            this.lastUsedEpochSecond = now;
        }
    }

    private final Object monitor = new Object();

    /** Bounded, insertion-ordered so eviction is deterministic. Keyed by SHA-256(id). */
    private final LinkedHashMap<String, Session> sessions =
            new LinkedHashMap<>(64, 0.75f, false) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Session> eldest) {
                    boolean evict = size() > MAX_SESSIONS;
                    if (evict) {
                        // Counted here rather than by comparing the size before and after
                        // the put: under concurrent issue() calls two threads can each
                        // evict an entry while each observes a size that makes it look as
                        // though no eviction happened, so the operator-facing counter
                        // would silently under-report exactly the pressure it exists to
                        // reveal.
                        evictedSessions++;
                    }
                    return evict;
                }
            };

    private final LinkedHashMap<String, Long> pendingCsrf = new LinkedHashMap<>() {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Long> eldest) {
            // Self-evicting for the same reason the session map is, and because one
            // unauthenticated visitor may request the login page (and therefore a CSRF
            // pair) as often as they like: an eviction that only ran when the writer
            // happened to notice the ceiling had been reached could be skipped entirely by
            // a caller that removed entries as it went, letting the map grow past the
            // documented bound. The bound is what keeps that heap cost finite.
            return size() > MAX_PENDING_CSRF;
        }
    };
    private long evictedSessions;
    private long expiredLookups;

    /** Mint a new session. Only ever called after a verified password match. */
    public String issue(String username) {
        String id = Crypto.randomUrlToken(InputPolicy.SESSION_TOKEN_BYTES);
        long now = AuditClock.epochSecond();
        synchronized (monitor) {
            sessions.put(Crypto.sha256Hex(id), new Session(username, now));
        }
        return id;
    }

    /**
     * Resolve a cookie value to a live session. Any deviation is a silent
     * "not authenticated" -- there is nothing to leak, because a caller who holds a
     * valid id is authenticated and one who does not must learn nothing about why.
     */
    public Optional<Session> find(String presentedId) {
        if (!InputPolicy.isSessionToken(presentedId)) {
            return Optional.empty();
        }
        String key = Crypto.sha256Hex(presentedId);
        long now = AuditClock.epochSecond();
        synchronized (monitor) {
            Session s = sessions.get(key);
            if (s == null) {
                return Optional.empty();
            }
            if (now - s.issuedAtEpochSecond > ABSOLUTE_TIMEOUT.getSeconds()) {
                sessions.remove(key);
                expiredLookups++;
                return Optional.empty();
            }
            if (now - s.lastUsedEpochSecond > IDLE_TIMEOUT.getSeconds()) {
                sessions.remove(key);
                expiredLookups++;
                return Optional.empty();
            }
            s.lastUsedEpochSecond = now;
            return Optional.of(s);
        }
    }

    public void logout(String presentedId) {
        if (!InputPolicy.isSessionToken(presentedId)) {
            return;
        }
        synchronized (monitor) {
            sessions.remove(Crypto.sha256Hex(presentedId));
        }
    }

    /** Bind an identity to every live session of that user (used after a password change). */
    public void revokeAllFor(String username) {
        synchronized (monitor) {
            Iterator<Map.Entry<String, Session>> it = sessions.entrySet().iterator();
            while (it.hasNext()) {
                if (it.next().getValue().username.equals(username)) {
                    it.remove();
                }
            }
        }
    }

    public int issueCsrfToken(String cookieValue, String hiddenValue) {
        long now = AuditClock.epochSecond();
        synchronized (monitor) {
            pruneCsrfLocked(now);
            pendingCsrf.put(Crypto.sha256Hex(cookieValue + "\n" + hiddenValue),
                    now + CSRF_TIMEOUT.getSeconds());
        }
        return pendingCsrf.size();
    }

    /**
     * Consume a CSRF token. Both halves must be present, well-formed and equal to each
     * other, and the pair must be one we issued; a matching pair is removed whether or not
     * it is still in time, so a token cannot be replayed.
     *
     * <p>An attempt whose two halves do not match is refused <em>before</em> the store is
     * consulted, so it does not consume the pending entry. Worth stating because the first
     * note here claimed the entry went away "either way", which is not what the code does
     * and is not what the test asserts. The difference is deliberate and costs nothing: a
     * mismatched attempt proves the caller does not hold the pair, and refusing it without
     * burning the entry means a bystander who can post junk to the endpoint cannot push a
     * legitimate user's in-flight form past its single use. Guessing the pair itself is
     * still a 192-bit task, and expiry bounds the window regardless.
     */
    public boolean consumeCsrfToken(String cookieValue, String hiddenValue) {
        if (!InputPolicy.isCsrfToken(cookieValue) || !InputPolicy.isCsrfToken(hiddenValue)) {
            return false;
        }
        if (!Crypto.equalConstantTime(cookieValue, hiddenValue)) {
            return false;
        }
        String key = Crypto.sha256Hex(cookieValue + "\n" + hiddenValue);
        long now = AuditClock.epochSecond();
        synchronized (monitor) {
            Long until = pendingCsrf.remove(key);
            return until != null && until > now;
        }
    }

    public int purgeExpired() {
        long now = AuditClock.epochSecond();
        int removed = 0;
        synchronized (monitor) {
            Iterator<Map.Entry<String, Session>> it = sessions.entrySet().iterator();
            while (it.hasNext()) {
                Session s = it.next().getValue();
                if (now - s.issuedAtEpochSecond > ABSOLUTE_TIMEOUT.getSeconds()
                        || now - s.lastUsedEpochSecond > IDLE_TIMEOUT.getSeconds()) {
                    it.remove();
                    removed++;
                }
            }
            pruneCsrfLocked(now);
        }
        return removed;
    }

    private void pruneCsrfLocked(long now) {
        Iterator<Map.Entry<String, Long>> it = pendingCsrf.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getValue() <= now) {
                it.remove();
            }
        }
    }

    public int liveSessionCount() {
        synchronized (monitor) {
            return sessions.size();
        }
    }

    public int pendingCsrfCount() {
        synchronized (monitor) {
            return pendingCsrf.size();
        }
    }

    public long evictedSessionCount() {
        synchronized (monitor) {
            return evictedSessions;
        }
    }

    public long expiredLookupCount() {
        synchronized (monitor) {
            return expiredLookups;
        }
    }

    /** Snapshot of live usernames, for the operator status command. */
    public List<String> liveSubjects() {
        synchronized (monitor) {
            List<String> out = new ArrayList<>();
            for (Session s : sessions.values()) {
                out.add(s.username);
            }
            return out;
        }
    }
}
