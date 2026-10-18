package com.security.crypto;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;

/**
 * Utility for generating cryptographically secure symmetric keys, random IVs, and key identifiers.
 * <p>
 * Satisfies:
 * <ul>
 *   <li>Rule 4 (Identifiers and tokens): Generates key identifiers using cryptographically secure random source.</li>
 *   <li>Rule 8 (Prefer the Platform): Uses platform JCA KeyGenerator and SecureRandom.</li>
 * </ul>
 */
public final class KeyGeneratorUtil {

    private static final String ALGORITHM = "AES";
    private static final int KEY_SIZE_BITS = 256;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private KeyGeneratorUtil() {
        // Utility class
    }

    /**
     * Generates a new 256-bit AES symmetric key using standard platform cryptography.
     *
     * @return Generated SecretKey.
     */
    public static SecretKey generateAes256Key() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
            keyGen.init(KEY_SIZE_BITS, SECURE_RANDOM);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Failed to generate AES key: algorithm unavailable", e);
        }
    }

    /**
     * Generates a cryptographically strong, random key identifier.
     * Prefixed with "k_" followed by 16 random bytes in lowercase hexadecimal (34 chars total).
     *
     * @return A random, valid key identifier complying with KEY_ID_PATTERN.
     */
    public static String generateKeyId() {
        byte[] randomBytes = new byte[16];
        SECURE_RANDOM.nextBytes(randomBytes);
        return "k_" + HexFormat.of().formatHex(randomBytes);
    }

    /**
     * Generates a cryptographically secure 12-byte initialization vector (IV) for AES-GCM.
     *
     * @return 12-byte random IV array.
     */
    public static byte[] generateGcmIv() {
        byte[] iv = new byte[EncryptedPayload.GCM_IV_LENGTH];
        SECURE_RANDOM.nextBytes(iv);
        return iv;
    }
}
