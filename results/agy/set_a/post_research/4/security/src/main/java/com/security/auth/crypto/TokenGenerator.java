package com.security.auth.crypto;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * Generates and validates cryptographically secure identifiers and session tokens.
 * Employs SecureRandom with 256 bits of entropy.
 * Complies with Rule 4: Session tokens must never be caller-specified or predictable.
 */
public final class TokenGenerator {

    public static final int TOKEN_BYTE_LENGTH = 32; // 256 bits of entropy
    private static final Pattern TOKEN_FORMAT = Pattern.compile("^[A-Za-z0-9_-]{43}$");

    private final SecureRandom secureRandom;

    public TokenGenerator() {
        this.secureRandom = new SecureRandom();
    }

    /**
     * Generates a high-entropy, cryptographically secure random session token.
     *
     * @return 43-character URL-safe Base64 encoded string containing 256 bits of entropy
     */
    public String generateSecureToken() {
        byte[] randomBytes = new byte[TOKEN_BYTE_LENGTH];
        secureRandom.nextBytes(randomBytes);
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        } finally {
            CryptoUtils.wipe(randomBytes);
        }
    }

    /**
     * Hashes a raw session token using SHA-256 for secure database storage.
     * Storing token hashes prevents session hijacking in the event of database exfiltration.
     *
     * @param rawToken raw session token presented by client
     * @return 64-character hex SHA-256 hash
     */
    public String hashToken(String rawToken) {
        if (!isValidTokenFormat(rawToken)) {
            throw new IllegalArgumentException("Invalid session token format");
        }
        return CryptoUtils.sha256Hex(rawToken);
    }

    /**
     * Strictly verifies whether an input string conforms to expected session token format.
     *
     * @param token candidate token
     * @return true if valid format, false otherwise
     */
    public boolean isValidTokenFormat(String token) {
        if (token == null || token.length() != 43) {
            return false;
        }
        return TOKEN_FORMAT.matcher(token).matches();
    }
}
