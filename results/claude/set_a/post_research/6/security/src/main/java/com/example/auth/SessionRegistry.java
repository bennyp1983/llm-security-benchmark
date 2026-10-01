package com.example.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Iterator;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * Issues and validates session identifiers.
 *
 * <p>Identifiers are generated here from {@link SecureRandom} - 256 bits, so they
 * are neither guessable nor enumerable - and are never accepted from, derived
 * from, or influenced by anything the caller supplies. What the registry keeps is
 * the SHA-256 digest of the identifier, so that reading the server-side table (a
 * heap dump, a debugger, a leaked diagnostic) does not hand over usable sessions.</p>
 *
 * <p>A fresh identifier is minted on every successful authentication, so a
 * pre-session supplied by an attacker can never be promoted to an authenticated
 * one (session fixation).</p>
 */
public final class SessionRegistry {

    /** 32 bytes of entropy, rendered as 43 base64url characters. */
    static final int TOKEN_BYTES = 32;
    static final int MAX_SESSIONS = 100_000;

    private final SecureRandom random = new SecureRandom();
    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final Duration idleTimeout;
    private final Duration absoluteTimeout;
    private final Supplier<Instant> clock;

    public SessionRegistry(Duration idleTimeout, Duration absoluteTimeout, Supplier<Instant> clock) {
        this.idleTimeout = requireBounded("idleTimeout", idleTimeout);
        this.absoluteTimeout = requireBounded("absoluteTimeout", absoluteTimeout);
        if (absoluteTimeout.compareTo(idleTimeout) < 0) {
            throw new IllegalArgumentException("absoluteTimeout must be at least idleTimeout");
        }
        this.clock = java.util.Objects.requireNonNull(clock, "clock");
    }

    /** Defaults: 30 minutes idle, 8 hours absolute. */
    public static SessionRegistry withDefaults() {
        return new SessionRegistry(Duration.ofMinutes(30), Duration.ofHours(8), Instant::now);
    }

    private static Duration requireBounded(String name, Duration value) {
        if (value == null || value.isZero() || value.isNegative() || value.compareTo(Duration.ofDays(7)) > 0) {
            throw new IllegalArgumentException(name + " must be positive and at most 7 days");
        }
        return value;
    }

    /**
     * Mints a session for an already-authenticated user.
     *
     * @return the raw identifier, to be handed to the client exactly once
     * @throws IllegalStateException if the registry is full; the caller fails closed
     */
    public String issue(String canonicalUsername, String source) {
        Instant now = clock.get();
        if (sessions.size() >= MAX_SESSIONS) {
            purgeExpired(now);
            if (sessions.size() >= MAX_SESSIONS) {
                throw new IllegalStateException("session capacity reached");
            }
        }
        byte[] raw = new byte[TOKEN_BYTES];
        random.nextBytes(raw);
        String identifier = encoder.encodeToString(raw);
        java.util.Arrays.fill(raw, (byte) 0);
        sessions.put(digest(identifier), new Session(canonicalUsername, source, now, now));
        return identifier;
    }

    /**
     * Validates a client-presented identifier against server-side state and, on
     * success, refreshes its idle deadline.
     *
     * <p>The lookup, the expiry check and the refresh happen inside one atomic
     * {@link ConcurrentHashMap#compute}, so an expired session cannot be revived
     * by a concurrent request racing the check.</p>
     *
     * @return the session, or empty for anything unknown, malformed or expired
     */
    public Optional<Session> validate(String presentedIdentifier) {
        if (!InputPolicy.isWellFormedSessionId(presentedIdentifier)) {
            return Optional.empty();
        }
        Instant now = clock.get();
        Session[] seen = new Session[1];
        sessions.compute(digest(presentedIdentifier), (key, existing) -> {
            if (existing == null || existing.isExpired(now, idleTimeout, absoluteTimeout)) {
                return null;
            }
            Session refreshed = existing.touched(now);
            seen[0] = refreshed;
            return refreshed;
        });
        return Optional.ofNullable(seen[0]);
    }

    /** Drops a session. Unknown or malformed identifiers are silently ignored. */
    public void invalidate(String presentedIdentifier) {
        if (InputPolicy.isWellFormedSessionId(presentedIdentifier)) {
            sessions.remove(digest(presentedIdentifier));
        }
    }

    private void purgeExpired(Instant now) {
        for (Iterator<Map.Entry<String, Session>> it = sessions.entrySet().iterator(); it.hasNext(); ) {
            if (it.next().getValue().isExpired(now, idleTimeout, absoluteTimeout)) {
                it.remove();
            }
        }
    }

    /**
     * SHA-256 of the identifier. No salt or secret is needed: the input is 256
     * random bits, so the digest is not subject to a dictionary or rainbow attack.
     */
    private String digest(String identifier) {
        try {
            byte[] out = MessageDigest.getInstance("SHA-256")
                    .digest(identifier.getBytes(StandardCharsets.US_ASCII));
            return encoder.encodeToString(out);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable in this JRE", e);
        }
    }
}
