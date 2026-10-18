package com.security.auth.model;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Represents a cryptographically secure session token issued upon successful authentication (Rule 4).
 * Enforces secure cookie attributes: HttpOnly, Secure, SameSite=Strict, Path=/.
 */
public final class SessionToken {

    private final String value;
    private final String username;
    private final Instant issuedAt;
    private final Instant expiresAt;

    public SessionToken(String value, String username, Instant issuedAt, Instant expiresAt) {
        if (value == null || value.length() < 32) {
            throw new IllegalArgumentException("Session token value must be non-null and at least 32 characters.");
        }
        this.value = value;
        this.username = Objects.requireNonNull(username, "Username cannot be null.");
        this.issuedAt = Objects.requireNonNull(issuedAt, "IssuedAt cannot be null.");
        this.expiresAt = Objects.requireNonNull(expiresAt, "ExpiresAt cannot be null.");
        if (expiresAt.isBefore(issuedAt)) {
            throw new IllegalArgumentException("Expiry must be after issuance.");
        }
    }

    public String getValue() {
        return value;
    }

    public String getUsername() {
        return username;
    }

    public Instant getIssuedAt() {
        return issuedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    /**
     * Formats this session token as a compliant, hardened HTTP Set-Cookie header value (Rule 4).
     *
     * @param cookieName name of the cookie (e.g., "AUTH_SESSION")
     * @return hardened Set-Cookie header string
     */
    public String toSetCookieHeader(String cookieName) {
        if (cookieName == null || !cookieName.matches("^[a-zA-Z0-9_-]+$")) {
            throw new IllegalArgumentException("Invalid cookie name format.");
        }
        long maxAgeSeconds = Math.max(0, Duration.between(Instant.now(), expiresAt).getSeconds());
        return String.format("%s=%s; Path=/; Max-Age=%d; HttpOnly; Secure; SameSite=Strict",
                cookieName, value, maxAgeSeconds);
    }

    /**
     * Computes a non-reversible SHA-256 fingerprint of the token for audit logging (Rule 2 & Rule 5).
     * Prevents recording the plaintext secret token in application logs.
     *
     * @return SHA-256 hex digest prefix of the token
     */
    public String getAuditFingerprint() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash).substring(0, 16);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
