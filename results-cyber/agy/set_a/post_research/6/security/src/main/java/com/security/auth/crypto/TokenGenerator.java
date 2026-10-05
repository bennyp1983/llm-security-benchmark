package com.security.auth.crypto;

import com.security.auth.model.SessionToken;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * Generates cryptographically secure session identifiers and tokens (Rule 4).
 * Uses java.security.SecureRandom with at least 256 bits of entropy.
 */
public final class TokenGenerator {

    private static final int DEFAULT_ENTROPY_BYTES = 32; // 256 bits
    private static final Duration DEFAULT_SESSION_DURATION = Duration.ofHours(1);

    private final SecureRandom secureRandom;
    private final Duration sessionDuration;

    public TokenGenerator() {
        this(DEFAULT_SESSION_DURATION);
    }

    public TokenGenerator(Duration sessionDuration) {
        this.secureRandom = new SecureRandom();
        this.sessionDuration = Objects.requireNonNull(sessionDuration, "Session duration cannot be null.");
        if (sessionDuration.isNegative() || sessionDuration.isZero()) {
            throw new IllegalArgumentException("Session duration must be positive.");
        }
    }

    /**
     * Generates a new cryptographically random session token for an authenticated user.
     *
     * @param username the authenticated username
     * @return cryptographically secure SessionToken
     */
    public SessionToken generateToken(String username) {
        Objects.requireNonNull(username, "Username cannot be null.");

        byte[] randomBytes = new byte[DEFAULT_ENTROPY_BYTES];
        try {
            secureRandom.nextBytes(randomBytes);
            String tokenValue = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
            Instant now = Instant.now();
            Instant expiry = now.plus(sessionDuration);
            return new SessionToken(tokenValue, username, now, expiry);
        } finally {
            // Clear temporary random bytes from memory (Rule 5)
            Arrays.fill(randomBytes, (byte) 0);
        }
    }
}
