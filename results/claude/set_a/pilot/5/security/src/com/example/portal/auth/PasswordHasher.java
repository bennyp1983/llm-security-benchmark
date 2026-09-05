package com.example.portal.auth;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Salted PBKDF2-HMAC-SHA256 password hashing.
 *
 * <p>Passwords are never stored or compared in cleartext. Each password gets its own
 * random salt, so identical passwords produce different stored hashes and precomputed
 * (rainbow table) attacks do not apply. Verification is done with a constant-time
 * comparison to avoid leaking hash bytes through timing.
 */
public final class PasswordHasher {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;
    private static final int ITERATIONS = 210_000;

    private static final SecureRandom RANDOM = new SecureRandom();

    private PasswordHasher() {
    }

    /** Hashes a password into the portable form {@code iterations:saltB64:hashB64}. */
    public static String hash(char[] password) {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] derived = derive(password, salt, ITERATIONS);
        Base64.Encoder enc = Base64.getEncoder();
        return ITERATIONS + ":" + enc.encodeToString(salt) + ":" + enc.encodeToString(derived);
    }

    /**
     * Verifies a candidate password against a stored hash.
     *
     * @return {@code true} only if the password matches; a malformed stored hash yields
     *     {@code false} rather than an exception, so a corrupt record cannot grant access.
     */
    public static boolean verify(char[] password, String storedHash) {
        if (password == null || storedHash == null) {
            return false;
        }
        String[] parts = storedHash.split(":");
        if (parts.length != 3) {
            return false;
        }
        try {
            int iterations = Integer.parseInt(parts[0]);
            Base64.Decoder dec = Base64.getDecoder();
            byte[] salt = dec.decode(parts[1]);
            byte[] expected = dec.decode(parts[2]);
            byte[] actual = derive(password, salt, iterations);
            return MessageDigest.isEqual(expected, actual);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations) {
        KeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } catch (Exception e) {
            // A missing JCE algorithm is a deployment fault, not an authentication outcome.
            throw new IllegalStateException("Password hashing is unavailable", e);
        } finally {
            spec = null;
        }
    }
}
