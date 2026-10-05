package com.employee.portal.security.crypto;

import com.employee.portal.security.config.SecurityConfig;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Generates cryptographically strong random session identifiers and tokens.
 * Complies with Rule 4 (cryptographically secure random source, unguessable, high entropy).
 */
public final class SecureTokenGenerator {

    private final SecureRandom secureRandom;
    private final int tokenLengthBytes;
    private final Base64.Encoder urlEncoder;

    public SecureTokenGenerator() {
        this(SecurityConfig.SESSION_TOKEN_LENGTH_BYTES);
    }

    public SecureTokenGenerator(int tokenLengthBytes) {
        SecureRandom rng;
        try {
            rng = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            rng = new SecureRandom();
        }
        this.secureRandom = rng;
        this.tokenLengthBytes = tokenLengthBytes;
        this.urlEncoder = Base64.getUrlEncoder().withoutPadding();
    }

    /**
     * Generates a 256-bit cryptographically secure session token string.
     */
    public String generateToken() {
        byte[] bytes = new byte[tokenLengthBytes];
        secureRandom.nextBytes(bytes);
        return urlEncoder.encodeToString(bytes);
    }

    /**
     * Generates a Set-Cookie header value adhering to Rule 4:
     * - Uses __Host- cookie prefix for HTTPS defense-in-depth
     * - HttpOnly flag to prevent XSS exfiltration
     * - Secure flag to mandate TLS transmission
     * - SameSite=Strict flag to prevent CSRF
     * - Path=/
     * - Explicit Max-Age
     */
    public static String buildSessionCookieHeader(String token, long maxAgeSeconds, boolean requireSecure) {
        String cookieName = requireSecure ? "__Host-session" : "portal_session";
        StringBuilder sb = new StringBuilder();
        sb.append(cookieName).append("=").append(token).append("; ");
        sb.append("Path=/; ");
        if (requireSecure) {
            sb.append("Secure; ");
        }
        sb.append("HttpOnly; ");
        sb.append("SameSite=Strict; ");
        sb.append("Max-Age=").append(maxAgeSeconds);
        return sb.toString();
    }

    /**
     * Cookie invalidation header (Max-Age=0).
     */
    public static String buildLogoutCookieHeader(boolean requireSecure) {
        String cookieName = requireSecure ? "__Host-session" : "portal_session";
        StringBuilder sb = new StringBuilder();
        sb.append(cookieName).append("=; ");
        sb.append("Path=/; ");
        if (requireSecure) {
            sb.append("Secure; ");
        }
        sb.append("HttpOnly; ");
        sb.append("SameSite=Strict; ");
        sb.append("Max-Age=0");
        return sb.toString();
    }
}
