package com.example.auth;

import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Password hashing with the JDK's own PBKDF2-HMAC-SHA512 - a proven, platform-provided
 * KDF, so no password hashing is hand-rolled here.
 *
 * <p>Encoded form stored in the database:
 * {@code pbkdf2-sha512$<iterations>$<base64 salt>$<base64 hash>}.
 *
 * <p>If a stronger KDF is available in the deployment (Argon2id via
 * org.bouncycastle:bcprov-jdk18on:1.78.1, or a container-provided
 * {@code PasswordEncoder}), prefer it; the encoded prefix above is the version marker
 * that makes such a migration possible.
 */
public final class PasswordHasher {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA512";
    private static final String SCHEME_ID = "pbkdf2-sha512";
    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;
    private static final int ITERATIONS = 210_000;
    private static final int MIN_ACCEPTED_ITERATIONS = 100_000;
    private static final int MAX_ACCEPTED_ITERATIONS = 5_000_000;
    private static final int MAX_ENCODED_LENGTH = 256;

    private final SecureRandom random = new SecureRandom();

    /**
     * Encoded hash of a fixed random password, generated once per process. Used to spend
     * the same CPU time when an account does not exist or its stored hash is unusable,
     * so response time does not disclose which accounts are real.
     */
    private final String decoyHash;

    public PasswordHasher() {
        char[] decoy = new char[32];
        for (int i = 0; i < decoy.length; i++) {
            decoy[i] = (char) ('!' + random.nextInt(0x5E));
        }
        try {
            this.decoyHash = hash(decoy);
        } finally {
            Arrays.fill(decoy, '\0');
        }
    }

    /** Hashes a password with a fresh random salt. The input array is not modified. */
    public String hash(char[] password) {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] derived = derive(password, salt, ITERATIONS, KEY_BITS);
        try {
            Base64.Encoder enc = Base64.getEncoder().withoutPadding();
            return SCHEME_ID + "$" + ITERATIONS + "$" + enc.encodeToString(salt) + "$"
                    + enc.encodeToString(derived);
        } finally {
            Arrays.fill(derived, (byte) 0);
        }
    }

    /**
     * Verifies a password against a stored encoded hash.
     *
     * <p>The stored value comes out of the database and is therefore treated as
     * attacker-controlled: it is parsed strictly, with bounds on every field. A value
     * that fails to parse causes a decoy verification of equivalent cost and returns
     * {@code false} - it never short-circuits to success.
     */
    public boolean verify(char[] password, String storedEncoded) {
        if (password == null || storedEncoded == null
                || storedEncoded.length() > MAX_ENCODED_LENGTH) {
            verifyDecoy(password);
            return false;
        }
        String[] parts = storedEncoded.split("\\$", -1);
        if (parts.length != 4 || !SCHEME_ID.equals(parts[0].toLowerCase(Locale.ROOT))) {
            verifyDecoy(password);
            return false;
        }
        int iterations;
        try {
            iterations = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            verifyDecoy(password);
            return false;
        }
        if (iterations < MIN_ACCEPTED_ITERATIONS || iterations > MAX_ACCEPTED_ITERATIONS) {
            verifyDecoy(password);
            return false;
        }
        byte[] salt;
        byte[] expected;
        try {
            Base64.Decoder dec = Base64.getDecoder();
            salt = dec.decode(parts[2]);
            expected = dec.decode(parts[3]);
        } catch (IllegalArgumentException e) {
            verifyDecoy(password);
            return false;
        }
        if (salt.length < 8 || salt.length > 64 || expected.length < 16 || expected.length > 64) {
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(expected, (byte) 0);
            verifyDecoy(password);
            return false;
        }
        byte[] actual = derive(password, salt, iterations, expected.length * 8);
        try {
            // Length-independent, constant-time comparison from the platform.
            return java.security.MessageDigest.isEqual(expected, actual);
        } finally {
            Arrays.fill(actual, (byte) 0);
            Arrays.fill(expected, (byte) 0);
            Arrays.fill(salt, (byte) 0);
        }
    }

    /**
     * Performs a full hash computation and discards the result. Called on the
     * "no such account" and "unusable stored hash" paths so that every failure costs
     * the same work as a real verification.
     */
    public void verifyDecoy(char[] password) {
        char[] input = (password == null || password.length == 0)
                ? new char[]{'\0'} : password;
        String[] parts = decoyHash.split("\\$", -1);
        byte[] salt = Base64.getDecoder().decode(parts[2]);
        byte[] derived = derive(input, salt, Integer.parseInt(parts[1]), KEY_BITS);
        Arrays.fill(derived, (byte) 0);
        Arrays.fill(salt, (byte) 0);
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations, int keyBits) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyBits);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } catch (InvalidKeySpecException | java.security.NoSuchAlgorithmException e) {
            // Fail closed: a KDF that will not run must never be read as a pass.
            throw new IllegalStateException("Password hashing is unavailable", e);
        } finally {
            spec.clearPassword();
        }
    }
}
