package com.example.auth;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * A validated, opaque session identifier.
 *
 * <p>The value is treated as untrusted input wherever it comes from (a login routine, a header, a
 * cookie that a client may have crafted). Construction therefore goes through {@link #of(String)},
 * which rejects anything that is not a plain URL-safe token, and {@link #toCookieValue()} is the
 * only accessor used when the value is placed into a {@code Set-Cookie} header.
 */
public final class SessionIdentifier {

    /** 256 bits of entropy, base64url encoded without padding: 43 characters. */
    public static final int RANDOM_BYTES = 32;

    /** Longest identifier we are willing to echo into a header. */
    public static final int MAX_LENGTH = 128;

    private static final SecureRandom RANDOM = new SecureRandom();

    private final String value;

    private SessionIdentifier(String value) {
        this.value = value;
    }

    /**
     * Creates an identifier from an externally supplied value.
     *
     * @throws IllegalArgumentException if {@code value} is null, blank, oversized, or contains any
     *     character outside {@code [A-Za-z0-9._~-]}. That character class excludes CR, LF, {@code ;},
     *     {@code ,}, quotes, spaces and every other cookie-attribute separator, so a rejected value
     *     can never split the {@code Set-Cookie} header or inject extra attributes.
     */
    public static SessionIdentifier of(String value) {
        if (value == null) {
            throw new IllegalArgumentException("session identifier is null");
        }
        if (value.isEmpty()) {
            throw new IllegalArgumentException("session identifier is empty");
        }
        if (value.length() > MAX_LENGTH) {
            throw new IllegalArgumentException("session identifier exceeds " + MAX_LENGTH + " characters");
        }
        for (int i = 0; i < value.length(); i++) {
            if (!isTokenCharacter(value.charAt(i))) {
                throw new IllegalArgumentException(
                        "session identifier contains illegal character at index " + i);
            }
        }
        return new SessionIdentifier(value);
    }

    /**
     * mints a fresh identifier from {@link SecureRandom}. Used to replace the pre-authentication
     * identifier on login so a value an attacker fixed earlier cannot name the authenticated
     * session (session fixation).
     */
    public static SessionIdentifier generate() {
        byte[] bytes = new byte[RANDOM_BYTES];
        RANDOM.nextBytes(bytes);
        return new SessionIdentifier(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes));
    }

    /**
     * Timing-safe comparison against another identifier. Used when a supplied session token has to
     * be matched to a stored one, so a remote attacker cannot win by racing response times.
     */
    public boolean matches(String other) {
        if (other == null) {
            return false;
        }
        return MessageDigest.isEqual(
                this.value.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                other.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    /** The raw value, for lookups and for the constant-time comparison above. */
    public String value() {
        return value;
    }

    /** The value as it appears in the cookie. Identical to {@link #value()}: no encoding, no masking. */
    public String toCookieValue() {
        return value;
    }

    @Override
    public String toString() {
        return "SessionIdentifier[" + describe() + "]";
    }

    /** Redacted rendering, safe to log: never emits the full identifier. */
    public String describe() {
        if (value.length() <= 8) {
            return "***";
        }
        return value.substring(0, 4) + "..." + value.substring(value.length() - 4)
                + " (len=" + value.length() + ")";
    }

    /**
     * One-way fingerprint, safe to return in a response body. Shows which identifier was minted
     * without exposing any part of it: a prefix of the real value would be 48 bits of the secret
     * given away for free.
     */
    public String fingerprint() {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(java.util.Arrays.copyOf(digest, 8));
        } catch (java.security.NoSuchAlgorithmException absent) {
            // SHA-256 is required of every JVM implementation; the JRE would have failed to start.
            throw new IllegalStateException("SHA-256 unavailable", absent);
        }
    }

    private static boolean isTokenCharacter(char c) {
        return (c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9')
                || c == '.' || c == '_' || c == '~' || c == '-';
    }
}
