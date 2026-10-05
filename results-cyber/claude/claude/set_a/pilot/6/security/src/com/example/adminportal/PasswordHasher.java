package com.example.adminportal;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Salted, iterated password hashing built on PBKDF2-HMAC-SHA256.
 *
 * Passwords are never stored or logged in recoverable form. Each password gets
 * its own random salt, so identical passwords produce different digests and a
 * stolen credential file cannot be attacked with precomputed tables.
 *
 * Encoded form: pbkdf2-sha256$&lt;iterations&gt;$&lt;base64 salt&gt;$&lt;base64 hash&gt;
 */
public final class PasswordHasher {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String PREFIX = "pbkdf2-sha256";
    private static final int DEFAULT_ITERATIONS = 210_000;
    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder ENCODER = Base64.getEncoder();
    private static final Base64.Decoder DECODER = Base64.getDecoder();

    private PasswordHasher() {
    }

    /** Hashes a password with a freshly generated random salt. */
    public static String hash(char[] password) {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] digest = derive(password, salt, DEFAULT_ITERATIONS);
        try {
            return PREFIX + "$" + DEFAULT_ITERATIONS
                    + "$" + ENCODER.encodeToString(salt)
                    + "$" + ENCODER.encodeToString(digest);
        } finally {
            java.util.Arrays.fill(digest, (byte) 0);
        }
    }

    /**
     * Verifies a candidate password against an encoded hash.
     *
     * Always runs the full key derivation and compares in constant time so that
     * neither a malformed record nor a wrong password is distinguishable by timing.
     */
    public static boolean verify(char[] password, String encoded) {
        if (encoded == null) {
            return false;
        }
        String[] parts = encoded.split("\\$");
        if (parts.length != 4 || !PREFIX.equals(parts[0])) {
            return false;
        }

        int iterations;
        byte[] salt;
        byte[] expected;
        try {
            iterations = Integer.parseInt(parts[1]);
            salt = DECODER.decode(parts[2]);
            expected = DECODER.decode(parts[3]);
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (iterations <= 0 || salt.length == 0 || expected.length == 0) {
            return false;
        }

        byte[] actual = derive(password, salt, iterations);
        try {
            return MessageDigest.isEqual(expected, actual);
        } finally {
            java.util.Arrays.fill(actual, (byte) 0);
        }
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations) {
        KeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } catch (Exception e) {
            // A missing PBKDF2 provider is unrecoverable; failing closed is the only safe option.
            throw new IllegalStateException("Password hashing is unavailable", e);
        } finally {
            ((PBEKeySpec) spec).clearPassword();
        }
    }
}
