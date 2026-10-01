package com.security.auth.crypto;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Objects;

/**
 * Robust, platform-based password hashing implementation using PBKDF2 with HMAC-SHA512.
 * Adheres to OWASP Password Storage Guidelines (minimum 210,000 iterations, 256-bit salt, 512-bit key).
 * Integrates dummy password hashing to prevent timing-based user enumeration.
 */
public final class PasswordHasher {

    public static final String ALGORITHM = "PBKDF2WithHmacSHA512";
    public static final int DEFAULT_ITERATIONS = 210_000;
    public static final int SALT_BYTE_LENGTH = 32; // 256 bits
    public static final int KEY_BIT_LENGTH = 512;  // 512 bits (64 bytes)

    private final SecureRandom secureRandom;
    private final int iterations;

    // Pre-generated dummy salt and hash used to ensure constant work when a user does not exist.
    private final String dummySaltBase64;
    private final String dummyHashBase64;

    public PasswordHasher() {
        this(DEFAULT_ITERATIONS);
    }

    public PasswordHasher(int iterations) {
        if (iterations < 100_000) {
            throw new IllegalArgumentException("Iteration count must be at least 100,000 for PBKDF2-HMAC-SHA512");
        }
        this.iterations = iterations;
        this.secureRandom = new SecureRandom();

        // Initialize dummy salt and hash for timing resistance
        byte[] dummySalt = new byte[SALT_BYTE_LENGTH];
        this.secureRandom.nextBytes(dummySalt);
        this.dummySaltBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(dummySalt);
        CryptoUtils.wipe(dummySalt);

        // Precompute a dummy hash with a dummy password once during startup
        char[] dummyPwd = "DUMMY_INITIALIZATION_SECRET_987#%*".toCharArray();
        try {
            HashedPassword precomputed = hash(dummyPwd, Base64.getUrlDecoder().decode(this.dummySaltBase64), this.iterations);
            this.dummyHashBase64 = precomputed.hashBase64();
        } finally {
            CryptoUtils.wipe(dummyPwd);
        }
    }

    /**
     * Represents a securely hashed password and its cryptographic parameters.
     */
    public record HashedPassword(
            String algorithm,
            int iterations,
            String saltBase64,
            String hashBase64
    ) {
        public HashedPassword {
            Objects.requireNonNull(algorithm, "algorithm must not be null");
            Objects.requireNonNull(saltBase64, "saltBase64 must not be null");
            Objects.requireNonNull(hashBase64, "hashBase64 must not be null");
            if (iterations < 1) {
                throw new IllegalArgumentException("iterations must be positive");
            }
        }

        /**
         * Formats into Modular Crypt Format (MCF) string:
         * $pbkdf2-sha512$i=210000$salt$hash
         */
        public String toMcfString() {
            return String.format("$pbkdf2-sha512$i=%d$%s$%s", iterations, saltBase64, hashBase64);
        }
    }

    /**
     * Hashes a user password using a newly generated cryptographically secure random salt.
     *
     * @param password the sensitive password as a character array
     * @return the HashedPassword record
     */
    public HashedPassword hash(char[] password) {
        Objects.requireNonNull(password, "password must not be null");
        byte[] salt = new byte[SALT_BYTE_LENGTH];
        secureRandom.nextBytes(salt);
        try {
            return hash(password, salt, this.iterations);
        } finally {
            CryptoUtils.wipe(salt);
        }
    }

    /**
     * Hashes a password with an explicit salt and iteration count.
     */
    public HashedPassword hash(char[] password, byte[] salt, int iterationCount) {
        Objects.requireNonNull(password, "password must not be null");
        Objects.requireNonNull(salt, "salt must not be null");

        PBEKeySpec spec = new PBEKeySpec(password, salt, iterationCount, KEY_BIT_LENGTH);
        byte[] rawHash = null;
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
            rawHash = skf.generateSecret(spec).getEncoded();
            String saltBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(salt);
            String hashBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(rawHash);
            return new HashedPassword(ALGORITHM, iterationCount, saltBase64, hashBase64);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Required platform algorithm " + ALGORITHM + " is not available", e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException("Invalid key specification", e);
        } finally {
            spec.clearPassword();
            CryptoUtils.wipe(rawHash);
        }
    }

    /**
     * Verifies a password against expected salt, hash, and iteration count in constant time.
     *
     * @param password candidate password
     * @param expectedSaltBase64 stored salt (Base64 URL)
     * @param expectedHashBase64 stored hash (Base64 URL)
     * @param iterationCount stored iteration count
     * @return true if password matches, false otherwise
     */
    public boolean verify(char[] password, String expectedSaltBase64, String expectedHashBase64, int iterationCount) {
        if (password == null || expectedSaltBase64 == null || expectedHashBase64 == null || iterationCount < 1) {
            return false;
        }

        byte[] salt;
        try {
            salt = Base64.getUrlDecoder().decode(expectedSaltBase64);
        } catch (IllegalArgumentException e) {
            return false;
        }

        byte[] expectedHash;
        try {
            expectedHash = Base64.getUrlDecoder().decode(expectedHashBase64);
        } catch (IllegalArgumentException e) {
            CryptoUtils.wipe(salt);
            return false;
        }

        PBEKeySpec spec = new PBEKeySpec(password, salt, iterationCount, KEY_BIT_LENGTH);
        byte[] computedHash = null;
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
            computedHash = skf.generateSecret(spec).getEncoded();
            return CryptoUtils.constantTimeEquals(computedHash, expectedHash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            return false;
        } finally {
            spec.clearPassword();
            CryptoUtils.wipe(salt);
            CryptoUtils.wipe(expectedHash);
            CryptoUtils.wipe(computedHash);
        }
    }

    /**
     * Executes identical cryptographic work against a dummy hash when an account does not exist.
     * Always returns false. This guarantees response times are indistinguishable whether an
     * account exists or not, preventing timing-based enumeration attacks.
     *
     * @param password candidate password
     * @return always false
     */
    public boolean verifyDummy(char[] password) {
        verify(password, dummySaltBase64, dummyHashBase64, this.iterations);
        return false;
    }

    public int getIterations() {
        return iterations;
    }
}
