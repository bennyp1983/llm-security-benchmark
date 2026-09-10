package com.example.adminportal;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Salted, iterated password hashing built on PBKDF2-HMAC-SHA256.
 *
 * <p>Encoded form: {@code pbkdf2_sha256$<iterations>$<base64 salt>$<base64 hash>}. The parameters
 * travel with the hash so stored credentials stay verifiable after the work factor is raised.
 */
final class PasswordHasher {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String IDENTIFIER = "pbkdf2_sha256";
    private static final int DEFAULT_ITERATIONS = 210_000;
    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;

    private static final SecureRandom RANDOM = new SecureRandom();

    private PasswordHasher() {
    }

    /** Hashes {@code password} with a fresh random salt and returns the encoded form. */
    static String hash(char[] password) {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] key = deriveKey(password, salt, DEFAULT_ITERATIONS);
        Base64.Encoder encoder = Base64.getEncoder();
        try {
            return IDENTIFIER
                    + "$" + DEFAULT_ITERATIONS
                    + "$" + encoder.encodeToString(salt)
                    + "$" + encoder.encodeToString(key);
        } finally {
            java.util.Arrays.fill(key, (byte) 0);
        }
    }

    /**
     * Verifies {@code password} against an encoded hash. Returns {@code false} rather than throwing
     * when the stored value is malformed, so a corrupt record cannot be used to bypass a check.
     */
    static boolean verify(char[] password, String encoded) {
        if (encoded == null) {
            return false;
        }
        String[] parts = encoded.split("\\$");
        if (parts.length != 4 || !IDENTIFIER.equals(parts[0])) {
            return false;
        }
        byte[] salt;
        byte[] expected;
        int iterations;
        try {
            iterations = Integer.parseInt(parts[1]);
            salt = Base64.getDecoder().decode(parts[2]);
            expected = Base64.getDecoder().decode(parts[3]);
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (iterations <= 0 || salt.length == 0 || expected.length == 0) {
            return false;
        }
        byte[] actual = deriveKey(password, salt, iterations);
        try {
            // Constant-time comparison: never short-circuit on the first differing byte.
            return MessageDigest.isEqual(expected, actual);
        } finally {
            java.util.Arrays.fill(actual, (byte) 0);
        }
    }

    private static byte[] deriveKey(char[] password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } catch (java.security.GeneralSecurityException e) {
            // A missing PBKDF2 provider is an environment fault, not a failed login.
            throw new IllegalStateException("Password hashing is unavailable", e);
        } finally {
            spec.clearPassword();
        }
    }
}
