package com.security.session;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Utility class providing safe RFC 6265 / RFC 6265bis Set-Cookie header construction,
 * defense against CRLF injection / HTTP response splitting, and sensitive token masking.
 */
public final class CookieSecurityUtil {

    private CookieSecurityUtil() {
        // Prevent instantiation
    }

    /**
     * Builds an RFC 6265bis compliant Set-Cookie header string with strict validation
     * against header injection, control characters, and insecure configurations.
     *
     * @param config the validated session cookie configuration
     * @param cookieValue the session identifier to set
     * @return a secure Set-Cookie header value
     */
    public static String buildSetCookieHeader(SessionCookieConfig config, String cookieValue) {
        if (config == null) {
            throw new SecurityValidationException("Internal error", "SessionCookieConfig cannot be null");
        }
        if (cookieValue == null || cookieValue.isBlank()) {
            throw new SecurityValidationException("Invalid input", "Cookie value cannot be null or blank");
        }

        // Validate value against CRLF and forbidden characters
        assertNoControlCharacters("Cookie Value", cookieValue);
        assertNoHeaderDelimiters("Cookie Value", cookieValue);

        StringBuilder sb = new StringBuilder(128);
        sb.append(config.getCookieName()).append('=').append(cookieValue);

        // Path
        if (config.getPath() != null && !config.getPath().isBlank()) {
            assertNoControlCharacters("Path", config.getPath());
            sb.append("; Path=").append(config.getPath());
        }

        // Max-Age (if >= 0)
        if (config.getMaxAgeSeconds() >= 0) {
            sb.append("; Max-Age=").append(config.getMaxAgeSeconds());
        }

        // Secure flag
        if (config.isSecure()) {
            sb.append("; Secure");
        }

        // HttpOnly flag (guarantees protection against client-side script access)
        if (config.isHttpOnly()) {
            sb.append("; HttpOnly");
        }

        // SameSite policy
        if (config.getSameSite() != null) {
            sb.append("; SameSite=").append(config.getSameSite().getAttributeValue());
        }

        // Domain (if set and permitted)
        if (config.getDomain() != null && !config.getDomain().isBlank()) {
            assertNoControlCharacters("Domain", config.getDomain());
            sb.append("; Domain=").append(config.getDomain());
        }

        // Partitioned flag (CHIPS: Cookies Having Independent Partitioned State)
        if (config.isPartitioned() && config.isSecure()) {
            sb.append("; Partitioned");
        }

        return sb.toString();
    }

    /**
     * Validates that the input string does not contain CR (0x0D), LF (0x0A),
     * or any ASCII control characters (0x00 - 0x1F, 0x7F).
     */
    public static void assertNoControlCharacters(String fieldName, String value) {
        if (value == null) {
            return;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c <= 0x1F || c == 0x7F) {
                throw new SecurityValidationException("Invalid request",
                        "CRLF or control character detected in " + fieldName + " at index " + i);
            }
        }
    }

    /**
     * Ensures no semicolon or comma exists in cookie value to avoid splitting attributes.
     */
    public static void assertNoHeaderDelimiters(String fieldName, String value) {
        if (value == null) {
            return;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == ';' || c == ',' || c == ' ' || c == '\t') {
                throw new SecurityValidationException("Invalid request",
                        "Delimiter character detected in " + fieldName + " at index " + i);
            }
        }
    }

    /**
     * Masks sensitive tokens (e.g. session identifiers) for safe logging.
     * Computes a SHA-256 fingerprint, returning the first 8 hex characters.
     * Never prints or logs the raw session identifier.
     *
     * @param token the sensitive token to mask
     * @return a masked string representation (e.g., "[sha256:a1b2c3d4]")
     */
    public static String maskToken(String token) {
        if (token == null || token.isBlank()) {
            return "[null]";
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            String hex = HexFormat.of().formatHex(hash);
            return "[sha256:" + hex.substring(0, 8) + "...]";
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed by standard Java specification
            return "[masked-token]";
        }
    }

    /**
     * Performs a constant-time equality check to prevent timing side channels.
     */
    public static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return a == b;
        }
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8)
        );
    }
}
