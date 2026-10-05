package com.example.portal.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Issues and validates session tokens.
 *
 * <p>Tokens are generated here and only here. Each is 32 bytes drawn from {@link SecureRandom} --
 * the platform's CSPRNG -- and rendered as unpadded Base64url. 256 bits leaves nothing to guess and
 * nothing to predict from a previously issued token. No part of a token derives from the username,
 * the time, a counter, or anything the caller supplied; a token presented by a caller is never
 * trusted as an identity on its own, only as a lookup key into this server-side table.
 *
 * <p>The table is keyed by SHA-256 of the token rather than by the token itself. A token is a bearer
 * credential, so storing it verbatim would mean a heap dump or an accidental dump of the table
 * handed over working sessions. The digest is a one-way function of a 256-bit random value, so
 * precomputation against it is not a concern.
 *
 * <p>Two expiries apply: an idle timeout that advances on use, and an absolute lifetime that does
 * not. Validation, expiry checks and the idle-timeout refresh all happen inside a single
 * {@link ConcurrentHashMap#compute} call, so a session cannot be validated and expired concurrently
 * with an inconsistent result. Lookup failure and expiry are indistinguishable to the caller.
 */
public final class SessionManager {

    private static final int TOKEN_BYTES = 32;
    /** Length of an unpadded Base64url encoding of {@value #TOKEN_BYTES} bytes. */
    private static final int TOKEN_LENGTH = 43;

    /** Upper bound on live sessions, so session creation cannot be used to exhaust memory. */
    public static final int MAX_SESSIONS = 20_000;

    private final ConcurrentHashMap<String, Entry> sessions = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();
    private final Duration idleTimeout;
    private final Duration absoluteLifetime;

    private static final class Entry {
        private final String username;
        private final Instant createdAt;
        private final Instant absoluteExpiry;
        private Instant idleExpiry;

        Entry(String username, Instant createdAt, Instant absoluteExpiry, Instant idleExpiry) {
            this.username = username;
            this.createdAt = createdAt;
            this.absoluteExpiry = absoluteExpiry;
            this.idleExpiry = idleExpiry;
        }
    }

    public SessionManager() {
        this(Duration.ofMinutes(15), Duration.ofHours(8));
    }

    public SessionManager(Duration idleTimeout, Duration absoluteLifetime) {
        if (idleTimeout.isZero() || idleTimeout.isNegative()
                || absoluteLifetime.isZero() || absoluteLifetime.isNegative()) {
            throw new IllegalArgumentException("session timeouts must be positive durations");
        }
        this.idleTimeout = idleTimeout;
        this.absoluteLifetime = absoluteLifetime;
    }

    /** The idle timeout applied to issued sessions; used when building a cookie's {@code Max-Age}. */
    public Duration idleTimeout() {
        return idleTimeout;
    }

    /**
     * Establishes a session for an account that has just authenticated successfully.
     *
     * <p>Must only be called after verification against the credential store has passed. The
     * returned value holds the one and only copy of the token this class will ever produce; the
     * caller is responsible for getting it to the client over a confidential channel and not
     * writing it anywhere else.
     *
     * @throws IllegalStateException if the session table is full after pruning expired entries; a
     *                               refused session is preferable to an untracked one
     */
    public Issued create(String username) {
        if (sessions.size() >= MAX_SESSIONS) {
            pruneExpired();
            if (sessions.size() >= MAX_SESSIONS) {
                throw new IllegalStateException("session capacity exhausted");
            }
        }
        byte[] raw = new byte[TOKEN_BYTES];
        random.nextBytes(raw);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        java.util.Arrays.fill(raw, (byte) 0);

        String digest = digestOf(token);
        Instant now = Instant.now();
        Entry entry = new Entry(username, now, now.plus(absoluteLifetime), now.plus(idleTimeout));
        if (sessions.putIfAbsent(digest, entry) != null) {
            // A 256-bit collision does not happen by chance; treat it as a broken RNG and stop.
            throw new IllegalStateException("session identifier collision");
        }
        return new Issued(token, new Session(username, referenceOf(digest), now, entry.absoluteExpiry));
    }

    /**
     * Resolves a token presented by a caller to its server-side session, if it is still valid.
     *
     * <p>The token's shape is checked before it is used as a map key, and the result is empty for
     * every failure mode -- wrong shape, unknown token, idle-timed-out, past its absolute lifetime --
     * so a caller cannot tell a never-issued token from an expired one.
     */
    public Optional<Session> validate(String presentedToken) {
        if (!hasTokenShape(presentedToken)) {
            return Optional.empty();
        }
        String digest = digestOf(presentedToken);
        Instant now = Instant.now();
        Session[] result = new Session[1];
        sessions.compute(digest, (key, entry) -> {
            if (entry == null) {
                return null;
            }
            if (!now.isBefore(entry.absoluteExpiry) || !now.isBefore(entry.idleExpiry)) {
                return null; // Expired sessions are removed on contact rather than left to linger.
            }
            entry.idleExpiry = now.plus(idleTimeout);
            result[0] = new Session(entry.username, referenceOf(key), entry.createdAt, entry.absoluteExpiry);
            return entry;
        });
        return Optional.ofNullable(result[0]);
    }

    /** Invalidates a session. Silent when the token is unknown; there is nothing to report. */
    public void invalidate(String presentedToken) {
        if (hasTokenShape(presentedToken)) {
            sessions.remove(digestOf(presentedToken));
        }
    }

    /** Number of live entries, including any not yet pruned. Operational logging only. */
    public int size() {
        return sessions.size();
    }

    /**
     * Rejects anything that is not exactly the encoding this class emits.
     *
     * <p>A caller-supplied token is attacker-controlled input. Validating its shape first keeps
     * oversized or odd values out of the digest and the map, and means a probe learns nothing from
     * how long a rejection takes.
     */
    public static boolean hasTokenShape(String token) {
        if (token == null || token.length() != TOKEN_LENGTH) {
            return false;
        }
        for (int i = 0; i < token.length(); i++) {
            char c = token.charAt(i);
            boolean permitted = (c >= 'a' && c <= 'z')
                    || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9')
                    || c == '-' || c == '_';
            if (!permitted) {
                return false;
            }
        }
        return true;
    }

    private void pruneExpired() {
        Instant now = Instant.now();
        for (Iterator<Map.Entry<String, Entry>> it = sessions.entrySet().iterator(); it.hasNext(); ) {
            Map.Entry<String, Entry> e = it.next();
            Entry entry = e.getValue();
            if (!now.isBefore(entry.absoluteExpiry) || !now.isBefore(entry.idleExpiry)) {
                sessions.remove(e.getKey(), entry);
            }
        }
    }

    private static String digestOf(String token) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    /** A short, non-secret handle: the leading 12 hex characters of the token digest. */
    private static String referenceOf(String digest) {
        return digest.substring(0, 12);
    }

    /**
     * A freshly issued session and its token.
     *
     * @param token   the bearer token, to be transmitted to the client and then discarded by the
     *                caller; never logged, never persisted
     * @param session the server-side view, safe to log via {@link Session#reference()}
     */
    public record Issued(String token, Session session) {

        /** Never renders the token. */
        @Override
        public String toString() {
            return "Issued[token=<redacted>, session=" + session + "]";
        }
    }
}
