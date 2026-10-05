package com.employee.portal.security.crypto;

import com.employee.portal.security.config.SecurityConfig;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * Handles PBKDF2WithHmacSHA512 password hashing and verification.
 * Implements constant-time comparisons and dummy verification to mitigate timing attacks.
 * Wipes sensitive password characters and byte arrays from memory when done.
 */
public final class PasswordHasher {

    private final SecureRandom secureRandom;
    private final int defaultIterations;
    private final int saltLengthBytes;
    private final int keyLengthBits;

    // Dummy values for timing-neutral dummy verification
    private final byte[] dummySalt;
    private final byte[] dummyHash;

    public PasswordHasher() {
        this(SecurityConfig.DEFAULT_PBKDF2_ITERATIONS,
             SecurityConfig.SALT_LENGTH_BYTES,
             SecurityConfig.DERIVED_KEY_LENGTH_BYTES * 8);
    }

    public PasswordHasher(int iterations, int saltLengthBytes, int keyLengthBits) {
        SecureRandom rng;
        try {
            rng = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            rng = new SecureRandom();
        }
        this.secureRandom = rng;
        this.defaultIterations = iterations;
        this.saltLengthBytes = saltLengthBytes;
        this.keyLengthBits = keyLengthBits;

        // Initialize dummy salt and dummy hash for constant-time dummy verification
        this.dummySalt = new byte[saltLengthBytes];
        this.secureRandom.nextBytes(this.dummySalt);
        char[] dummyPwd = "DUMMY_TIMING_PASSWORD_9x$q".toCharArray();
        byte[] dHash;
        try {
            dHash = hashPasswordInternal(dummyPwd, this.dummySalt, this.defaultIterations, this.keyLengthBits);
        } catch (Exception e) {
            // Fallback safe dummy hash
            dHash = new byte[keyLengthBits / 8];
            this.secureRandom.nextBytes(dHash);
        } finally {
            Arrays.fill(dummyPwd, '\0');
        }
        this.dummyHash = dHash;
    }

    /**
     * Generates a cryptographically secure random salt.
     */
    public byte[] generateSalt() {
        byte[] salt = new byte[saltLengthBytes];
        secureRandom.nextBytes(salt);
        return salt;
    }

    /**
     * Computes PBKDF2 hash of password using provided salt and iterations.
     * Memory of sensitive data is cleared before returning.
     */
    public byte[] hashPassword(char[] password, byte[] salt, int iterations) {
        return hashPasswordInternal(password, salt, iterations, keyLengthBits);
    }

    public byte[] hashPassword(char[] password, byte[] salt) {
        return hashPassword(password, salt, defaultIterations);
    }

    private byte[] hashPasswordInternal(char[] password, byte[] salt, int iterations, int keyBits) {
        if (password == null || salt == null) {
            throw new IllegalArgumentException("Password and salt cannot be null");
        }
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyBits);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(SecurityConfig.HASH_ALGORITHM);
            byte[] hash = skf.generateSecret(spec).getEncoded();
            return hash;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Cryptographic algorithm unavailable: " + SecurityConfig.HASH_ALGORITHM, e);
        } finally {
            spec.clearPassword();
        }
    }

    /**
     * Verifies password against expected salt and hash using constant-time comparison.
     */
    public boolean verifyPassword(char[] password, byte[] salt, byte[] expectedHash, int iterations) {
        if (password == null || salt == null || expectedHash == null) {
            return false;
        }
        byte[] computedHash = null;
        try {
            computedHash = hashPasswordInternal(password, salt, iterations, expectedHash.length * 8);
            return MessageDigest.isEqual(computedHash, expectedHash);
        } catch (Exception e) {
            return false;
        } finally {
            if (computedHash != null) {
                Arrays.fill(computedHash, (byte) 0);
            }
        }
    }

    /**
     * Executes dummy verification using the same PBKDF2 algorithm and iteration count.
     * Used when an account does not exist, is suspended, or input is malformed.
     * Ensures equal execution time to prevent user enumeration via timing analysis.
     */
    public void dummyVerify(char[] password) {
        char[] pwdToUse = (password != null && password.length > 0) ? password : "dummy_timing_check_chars".toCharArray();
        byte[] computed = null;
        try {
            computed = hashPasswordInternal(pwdToUse, dummySalt, defaultIterations, keyLengthBits);
            // Always compare in constant time even though result will be false
            MessageDigest.isEqual(computed, dummyHash);
        } catch (Exception ignored) {
            // Timing-neutral catch
        } finally {
            if (computed != null) {
                Arrays.fill(computed, (byte) 0);
            }
        }
    }

    public int getDefaultIterations() {
        return defaultIterations;
    }
}
