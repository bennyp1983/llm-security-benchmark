package com.security.auth.crypto;

import com.security.auth.model.UserRecord;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * Platform-standard password hashing implementation using PBKDF2WithHmacSHA512 (Rule 8).
 * Features:
 * - Constant-time hash verification via MessageDigest.isEqual (Rule 6).
 * - Dummy verification execution to prevent user enumeration via timing attacks (Rule 6).
 * - Sensitive byte and char array zeroization in memory (Rule 5).
 * - Cryptographically secure random salts via SecureRandom (Rule 4).
 */
public final class Pbkdf2PasswordHasher implements PasswordHasher {

    public static final String ALGORITHM = "PBKDF2WithHmacSHA512";
    public static final int DEFAULT_ITERATIONS = 210_000;
    public static final int KEY_LENGTH_BITS = 512;
    public static final int DEFAULT_SALT_BYTES = 16;

    private static final char[] DUMMY_FALLBACK_PASSWORD = "DummyFallbackPasswordToProtectTiming!".toCharArray();

    private final SecureRandom secureRandom;
    private final int defaultIterations;
    private final byte[] dummySalt;
    private final byte[] dummyExpectedHash;

    public Pbkdf2PasswordHasher() {
        this(DEFAULT_ITERATIONS);
    }

    public Pbkdf2PasswordHasher(int iterations) {
        if (iterations < 1000) {
            throw new IllegalArgumentException("Iteration count must be at least 1,000.");
        }
        this.secureRandom = new SecureRandom();
        this.defaultIterations = iterations;

        // Initialize dummy salt and hash once at startup to keep dummy verification constant-time
        this.dummySalt = new byte[DEFAULT_SALT_BYTES];
        this.secureRandom.nextBytes(this.dummySalt);
        this.dummyExpectedHash = hashPassword(DUMMY_FALLBACK_PASSWORD, this.dummySalt, this.defaultIterations);
    }

    @Override
    public byte[] generateSalt(int byteLength) {
        if (byteLength < 16 || byteLength > 64) {
            throw new IllegalArgumentException("Salt length must be between 16 and 64 bytes.");
        }
        byte[] salt = new byte[byteLength];
        secureRandom.nextBytes(salt);
        return salt;
    }

    @Override
    public byte[] hashPassword(char[] password, byte[] salt, int iterations) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password cannot be null or empty.");
        }
        if (salt == null || salt.length < 16) {
            throw new IllegalArgumentException("Salt must be at least 16 bytes.");
        }
        if (iterations < 1000) {
            throw new IllegalArgumentException("Iterations must be at least 1,000.");
        }

        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_LENGTH_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            return factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Failed to compute PBKDF2 hash using algorithm " + ALGORITHM, e);
        } finally {
            // Clear internal password array in PBEKeySpec (Rule 5)
            spec.clearPassword();
        }
    }

    @Override
    public boolean verifyPassword(char[] password, UserRecord record) {
        if (password == null || record == null) {
            return false;
        }

        byte[] computedHash = null;
        try {
            computedHash = hashPassword(password, record.getSalt(), record.getIterations());
            // Constant-time byte array equality comparison (Rule 6)
            return MessageDigest.isEqual(computedHash, record.getPasswordHash());
        } finally {
            if (computedHash != null) {
                // Clear derived hash buffer from memory (Rule 5)
                Arrays.fill(computedHash, (byte) 0);
            }
        }
    }

    @Override
    public void performDummyVerification(char[] password) {
        char[] pwdToUse = (password != null && password.length > 0) ? password : DUMMY_FALLBACK_PASSWORD;
        byte[] computedHash = null;
        try {
            computedHash = hashPassword(pwdToUse, this.dummySalt, this.defaultIterations);
            // Execute constant-time comparison to match real verification execution profile
            MessageDigest.isEqual(computedHash, this.dummyExpectedHash);
        } finally {
            if (computedHash != null) {
                Arrays.fill(computedHash, (byte) 0);
            }
        }
    }

    public int getDefaultIterations() {
        return defaultIterations;
    }
}
