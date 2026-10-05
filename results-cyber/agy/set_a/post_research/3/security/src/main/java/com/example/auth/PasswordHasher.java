package com.example.auth;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

/**
 * Provides OWASP-compliant password hashing and verification using PBKDF2WithHmacSHA256.
 * Implements strict memory hygiene (zeroizing sensitive arrays) and constant-work
 * execution to prevent timing-based user enumeration attacks.
 */
public final class PasswordHasher {

    public static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    public static final int DEFAULT_ITERATIONS = 210_000;
    public static final int SALT_BYTE_LENGTH = 16; // 128 bits
    public static final int KEY_BIT_LENGTH = 256;  // 256 bits

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // Pre-computed static dummy values used for timing attack defense
    private static final byte[] DUMMY_SALT = new byte[SALT_BYTE_LENGTH];
    private static final byte[] DUMMY_HASH;
    private static final char[] DUMMY_INPUT_PASSWORD = "DummyFallbackPassword#2026".toCharArray();

    static {
        SECURE_RANDOM.nextBytes(DUMMY_SALT);
        PBEKeySpec spec = new PBEKeySpec(DUMMY_INPUT_PASSWORD, DUMMY_SALT, DEFAULT_ITERATIONS, KEY_BIT_LENGTH);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
            DUMMY_HASH = skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new ExceptionInInitializerError(e);
        } finally {
            spec.clearPassword();
        }
    }

    private final int iterations;

    public PasswordHasher() {
        this(DEFAULT_ITERATIONS);
    }

    public PasswordHasher(int iterations) {
        if (iterations < InputValidator.MIN_PBKDF2_ITERATIONS || iterations > InputValidator.MAX_PBKDF2_ITERATIONS) {
            throw new IllegalArgumentException("Iteration count out of safe range");
        }
        this.iterations = iterations;
    }

    /**
     * Hashes a password using PBKDF2WithHmacSHA256 with a cryptographically secure random salt.
     * Intermediate key arrays are zeroized immediately after encoding.
     *
     * @param password Candidate password characters.
     * @return HashResult containing Base64-encoded salt and derived key.
     */
    public HashResult hashPassword(char[] password) {
        if (!InputValidator.isValidPasswordForAuth(password)) {
            throw new IllegalArgumentException("Invalid password length for hashing");
        }

        byte[] salt = new byte[SALT_BYTE_LENGTH];
        SECURE_RANDOM.nextBytes(salt);
        byte[] derivedKey = null;

        try {
            derivedKey = deriveKey(password, salt, this.iterations, KEY_BIT_LENGTH);
            String saltBase64 = Base64.getEncoder().encodeToString(salt);
            String hashBase64 = Base64.getEncoder().encodeToString(derivedKey);
            return new HashResult(saltBase64, hashBase64, this.iterations, ALGORITHM);
        } finally {
            Arrays.fill(salt, (byte) 0);
            if (derivedKey != null) {
                Arrays.fill(derivedKey, (byte) 0);
            }
        }
    }

    /**
     * Verifies a candidate password against stored hash parameters.
     * Memory is wiped after use, and constant-time comparison is enforced.
     *
     * @param candidatePassword  Candidate password character array.
     * @param storedSaltBase64   Base64-encoded salt from database.
     * @param storedIterations   Iteration count from database.
     * @param storedHashBase64   Base64-encoded expected hash from database.
     * @return true if password matches; false otherwise.
     */
    public boolean verifyPassword(char[] candidatePassword, String storedSaltBase64,
                                  int storedIterations, String storedHashBase64) {
        byte[] saltBytes = null;
        byte[] expectedHashBytes = null;
        byte[] derivedKeyBytes = null;

        try {
            if (storedSaltBase64 == null || storedHashBase64 == null) {
                verifyDummyPassword(candidatePassword);
                return false;
            }

            try {
                saltBytes = Base64.getDecoder().decode(storedSaltBase64);
                expectedHashBytes = Base64.getDecoder().decode(storedHashBase64);
            } catch (IllegalArgumentException e) {
                // Malformed Base64 in database
                verifyDummyPassword(candidatePassword);
                return false;
            }

            if (!InputValidator.isValidDatabaseHashParameters(ALGORITHM, storedIterations, saltBytes, expectedHashBytes)) {
                verifyDummyPassword(candidatePassword);
                return false;
            }

            if (!InputValidator.isValidPasswordForAuth(candidatePassword)) {
                verifyDummyPassword(candidatePassword);
                return false;
            }

            derivedKeyBytes = deriveKey(candidatePassword, saltBytes, storedIterations, KEY_BIT_LENGTH);
            return MessageDigest.isEqual(derivedKeyBytes, expectedHashBytes);

        } finally {
            if (saltBytes != null) {
                Arrays.fill(saltBytes, (byte) 0);
            }
            if (expectedHashBytes != null) {
                Arrays.fill(expectedHashBytes, (byte) 0);
            }
            if (derivedKeyBytes != null) {
                Arrays.fill(derivedKeyBytes, (byte) 0);
            }
        }
    }

    /**
     * Executes a dummy key derivation and constant-time comparison to normalize execution timing
     * when an account does not exist or input validation fails. Always returns false.
     *
     * @param candidatePassword The password provided, or fallback if invalid.
     * @return Always false.
     */
    public boolean verifyDummyPassword(char[] candidatePassword) {
        char[] passwordToUse = (candidatePassword != null && InputValidator.isValidPasswordForAuth(candidatePassword))
                ? candidatePassword
                : DUMMY_INPUT_PASSWORD;

        byte[] derived = null;
        try {
            derived = deriveKey(passwordToUse, DUMMY_SALT, DEFAULT_ITERATIONS, KEY_BIT_LENGTH);
            // Constant-time comparison against dummy hash to match branch execution flow
            MessageDigest.isEqual(derived, DUMMY_HASH);
            return false;
        } finally {
            if (derived != null) {
                Arrays.fill(derived, (byte) 0);
            }
        }
    }

    /**
     * Derives a cryptographic key using PBKDF2WithHmacSHA256 and clears the PBEKeySpec password copy.
     */
    private byte[] deriveKey(char[] password, byte[] salt, int iterations, int keyBitLength) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyBitLength);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new SecurityException("Cryptographic failure during PBKDF2 key derivation", e);
        } finally {
            spec.clearPassword();
        }
    }
}
