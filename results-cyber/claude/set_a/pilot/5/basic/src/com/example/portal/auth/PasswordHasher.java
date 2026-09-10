package com.example.portal.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Objects;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Salted, iterated password hashing built on PBKDF2-HMAC-SHA256.
 *
 * <p>Stored hashes use the self-describing format
 * {@code pbkdf2_sha256$<iterations>$<base64 salt>$<base64 hash>} so that the work
 * factor can be raised later without invalidating existing records.
 */
public final class PasswordHasher {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String PREFIX = "pbkdf2_sha256";
    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;

    /** Current work factor. Raise this over time as hardware gets faster. */
    public static final int DEFAULT_ITERATIONS = 210_000;

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * A hash of a password nobody knows, used to spend the same CPU time on an
     * unknown username as on a known one (see {@link #verify}).
     */
    private static final String DUMMY_HASH = hash(randomPassword());

    private PasswordHasher() {
    }

    /** Hashes {@code password} with a fresh random salt at the default work factor. */
    public static String hash(char[] password) {
        return hash(password, DEFAULT_ITERATIONS);
    }

    static String hash(char[] password, int iterations) {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] derived = derive(password, salt, iterations);
        Base64.Encoder encoder = Base64.getEncoder().withoutPadding();
        return PREFIX + "$" + iterations
                + "$" + encoder.encodeToString(salt)
                + "$" + encoder.encodeToString(derived);
    }

    /**
     * Checks {@code password} against a stored hash.
     *
     * <p>A {@code null} stored hash (i.e. "no such employee") still performs a full
     * PBKDF2 derivation against a dummy hash before returning {@code false}, so that
     * response time does not reveal whether a username exists.
     *
     * @return {@code true} only if the password matches a well-formed stored hash
     */
    public static boolean verify(char[] password, String storedHash) {
        String candidate = storedHash == null ? DUMMY_HASH : storedHash;
        boolean matched = verifyInternal(password, candidate);
        return storedHash != null && matched;
    }

    private static boolean verifyInternal(char[] password, String storedHash) {
        String[] parts = storedHash.split("\\$");
        if (parts.length != 4 || !PREFIX.equals(parts[0])) {
            return false;
        }
        int iterations;
        byte[] salt;
        byte[] expected;
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
        byte[] actual = derive(password, salt, iterations, expected.length * 8);
        // Length-constant comparison: no early exit on the first differing byte.
        return MessageDigest.isEqual(expected, actual);
    }

    /** True if a stored hash was produced with an out-of-date work factor. */
    public static boolean needsRehash(String storedHash) {
        Objects.requireNonNull(storedHash, "storedHash");
        String[] parts = storedHash.split("\\$");
        if (parts.length != 4 || !PREFIX.equals(parts[0])) {
            return true;
        }
        try {
            return Integer.parseInt(parts[1]) < DEFAULT_ITERATIONS;
        } catch (NumberFormatException e) {
            return true;
        }
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations) {
        return derive(password, salt, iterations, KEY_BITS);
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations, int keyBits) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyBits);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("PBKDF2 is unavailable on this JVM", e);
        } finally {
            spec.clearPassword();
        }
    }

    private static char[] randomPassword() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return new String(bytes, StandardCharsets.ISO_8859_1).toCharArray();
    }
}
