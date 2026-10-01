package com.security.crypto;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

/**
 * Key derivation function using platform standard PBKDF2WithHmacSHA512.
 * <p>
 * Satisfies:
 * <ul>
 *   <li>Rule 1 (Trust Boundaries): Enforces strict minimum bounds on iteration count and salt length.</li>
 *   <li>Rule 2 & 5 (Secrets & Sensitive Data): Zeroes passphrase char arrays and derived byte buffers from memory.</li>
 *   <li>Rule 8 (Prefer the Platform): Utilizes standard JCA PBKDF2WithHmacSHA512.</li>
 * </ul>
 */
public final class KeyDerivation {

    /**
     * Standard platform PBKDF2 algorithm using HMAC-SHA512.
     */
    public static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA512";

    /**
     * OWASP-recommended iteration count for PBKDF2.
     */
    public static final int DEFAULT_ITERATIONS = 600_000;

    /**
     * Hard lower bound for iterations to prevent weak key derivation.
     */
    public static final int MIN_ITERATIONS = 210_000;

    /**
     * Required salt size in bytes (128 bits).
     */
    public static final int MIN_SALT_BYTES = 16;

    /**
     * Derived key length in bits for AES-256.
     */
    public static final int DERIVED_KEY_BITS = 256;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private KeyDerivation() {
        // Utility class
    }

    /**
     * Generates a cryptographically secure random salt of the specified length.
     *
     * @param length Number of salt bytes (must be &gt;= 16).
     * @return Generated salt byte array.
     */
    public static byte[] generateSalt(int length) {
        if (length < MIN_SALT_BYTES) {
            throw new CryptoException("Salt length must be at least " + MIN_SALT_BYTES + " bytes");
        }
        byte[] salt = new byte[length];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    /**
     * Generates a default 16-byte cryptographically secure salt.
     *
     * @return 16-byte random salt.
     */
    public static byte[] generateSalt() {
        return generateSalt(MIN_SALT_BYTES);
    }

    /**
     * Derives an AES-256 SecretKey from a passphrase and salt using default iteration count.
     *
     * @param passphrase Passphrase characters (will be zeroed upon completion).
     * @param salt       Cryptographic salt (must be &gt;= 16 bytes).
     * @return 256-bit AES SecretKey.
     */
    public static SecretKey deriveKey(char[] passphrase, byte[] salt) {
        return deriveKey(passphrase, salt, DEFAULT_ITERATIONS);
    }

    /**
     * Derives an AES-256 SecretKey from a passphrase, salt, and specified iteration count.
     *
     * @param passphrase Passphrase characters (will be zeroed upon completion).
     * @param salt       Cryptographic salt (must be &gt;= 16 bytes).
     * @param iterations Iteration count (must be &gt;= 210,000).
     * @return 256-bit AES SecretKey.
     */
    public static SecretKey deriveKey(char[] passphrase, byte[] salt, int iterations) {
        Objects.requireNonNull(passphrase, "Passphrase must not be null");
        Objects.requireNonNull(salt, "Salt must not be null");

        if (salt.length < MIN_SALT_BYTES) {
            throw new CryptoException("Salt must be at least " + MIN_SALT_BYTES + " bytes");
        }
        if (iterations < MIN_ITERATIONS) {
            throw new CryptoException("Iteration count must be at least " + MIN_ITERATIONS);
        }

        PBEKeySpec spec = null;
        byte[] encodedKey = null;
        try {
            spec = new PBEKeySpec(passphrase, salt, iterations, DERIVED_KEY_BITS);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALGORITHM);
            SecretKey pbeKey = factory.generateSecret(spec);
            encodedKey = pbeKey.getEncoded();
            return new SecretKeySpec(encodedKey, "AES");
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CryptoException("Key derivation failed", e);
        } finally {
            if (spec != null) {
                spec.clearPassword();
            }
            CryptoUtils.wipe(passphrase);
            CryptoUtils.wipe(encodedKey);
        }
    }
}
