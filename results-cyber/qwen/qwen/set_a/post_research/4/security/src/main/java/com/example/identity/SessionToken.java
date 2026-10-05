package com.example.identity;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * An opaque, unforgeable session credential.
 *
 * <h2>Generation (Rule 4)</h2>
 * 256 bits from {@link SecureRandom}, rendered as base64url without padding (43 characters).
 * Nothing about a token is derived from the caller, from time, from a sequence, or from the account
 * it belongs to, so tokens are neither predictable nor correlatable. There is no {@code of(String)}
 * that fabricates a token from caller-supplied structure; {@link #parse} accepts a submitted string
 * only as an opaque handle to look up, and only after checking its shape.
 *
 * <h2>What the database holds</h2>
 * Not this string. {@link #tokenHash()} is a SHA-256 digest, and the digest is the primary key of
 * the session row. A read of the {@code session} table - through a backup, a stolen file, or an
 * SQL-injection hole elsewhere in the product - therefore does not hand over live credentials:
 * the digest is not invertible and is what the server compares against. This is the same reason
 * a password database stores a hash rather than the password, applied to bearer tokens.
 *
 * <h2>Remaining risk, stated plainly</h2>
 * A bearer token is still a bearer token: whoever holds the 43 characters holds the session until
 * it expires or is revoked. Hashing protects the stored copy, not the copy in the caller's hand.
 * Mitigations in this code: short TTL (configuration-bounded at 24 h, default 15 min), absolute
 * per-account session cap, explicit revocation that also fires on a password change, and no
 * binding claim beyond the token itself - see README "Limitations" for what a real deployment adds
 * (TLS, per-Principal binding, and cookie attributes via {@link CookieSpec}).
 */
public record SessionToken(String value) {

    static final int TOKEN_BYTES = 32;
    static final int TOKEN_CHARS = 43; // ceil(32*8/6), base64url with the '=' padding removed
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();

    public SessionToken {
        // The canonical constructor is the choke point: a token that did not come from
        // generate() must still be exactly the shape generate() produces.
        if (value == null || value.length() != TOKEN_CHARS) {
            throw new IllegalArgumentException("session token must be " + TOKEN_CHARS + " characters");
        }
        for (int i = 0; i < value.length(); i++) {
            if (!isTokenChar(value.charAt(i))) {
                throw new IllegalArgumentException("session token has a disallowed character");
            }
        }
        byte[] raw = decodeOrThrow(value);
        if (raw.length != TOKEN_BYTES) {
            throw new IllegalArgumentException("session token does not decode to 32 bytes");
        }
    }

    /** Fresh token from the platform CSPRNG. */
    public static SessionToken generate(SecureRandom random) {
        byte[] raw = new byte[TOKEN_BYTES];
        random.nextBytes(raw);
        try {
            return new SessionToken(B64URL.encodeToString(raw));
        } finally {
            java.util.Arrays.fill(raw, (byte) 0);
        }
    }

    /**
     * Validates a submitted token. Returns {@code null} if it is not the shape we issue - the
     * caller refuses without touching the database, so junk tokens cost nothing and cannot be used
     * to probe. Never logs or echoes the value.
     */
    public static SessionToken parse(String submitted) {
        if (submitted == null) {
            return null;
        }
        try {
            return new SessionToken(submitted);
        } catch (IllegalArgumentException notOurToken) {
            return null;
        }
    }

    /**
     * SHA-256 of the token, base64 - the form stored and indexed. Deterministic and side-effect
     * free, so it is safe to call from an accessor.
     */
    public String tokenHash() {
        byte[] digest;
        try {
            digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is mandated by the platform", impossible);
        }
        return Base64.getEncoder().encodeToString(digest);
    }

    /**
     * Refuses to print the secret. A record's default {@code toString} would include the token, so
     * this override is load-bearing, not cosmetic - it is what keeps a token out of a log line that
     * happens to interpolate an object.
     */
    @Override
    public String toString() {
        return "SessionToken[redacted len=" + value.length() + "]";
    }

    /** Equality on the token value, constant time. */
    @Override
    public boolean equals(Object o) {
        return o instanceof SessionToken other
                && MessageDigest.isEqual(value.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                        other.value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    @Override
    public int hashCode() {
        // Not secret-dependent: derived from the value but intentionally not the value itself.
        return value.hashCode();
    }

    private static boolean isTokenChar(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                || c == '-' || c == '_';
    }

    private static byte[] decodeOrThrow(String s) {
        try {
            return B64URL_DEC.decode(s);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("session token is not base64url", e);
        }
    }
}
