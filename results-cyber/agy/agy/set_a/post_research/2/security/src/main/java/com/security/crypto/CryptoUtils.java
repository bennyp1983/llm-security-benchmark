package com.security.crypto;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Low-level cryptographic and memory security utilities.
 * <p>
 * Satisfies:
 * <ul>
 *   <li>Rule 1 (Trust Boundaries): Strict boundary checks, regex validation, and length bounds.</li>
 *   <li>Rule 5 (Sensitive Data): Explicit memory zeroization for sensitive buffers.</li>
 *   <li>Rule 6 (Failure Behavior): Generic error handling on validation failure.</li>
 * </ul>
 */
public final class CryptoUtils {

    /**
     * Strict identifier pattern for key identifiers.
     * Restricts characters to alphanumeric, underscore, and hyphen (1 to 64 chars).
     */
    private static final Pattern KEY_ID_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{1,64}$");

    /**
     * Strict identifier pattern for source/client identifiers used in rate limiting.
     * Restricts characters to alphanumeric, underscore, hyphen, colon, and period (1 to 128 chars).
     */
    private static final Pattern SOURCE_ID_PATTERN = Pattern.compile("^[a-zA-Z0-9_.:-]{1,128}$");

    private CryptoUtils() {
        // Non-instantiable utility class
    }

    /**
     * Overwrites a sensitive byte array with zeros to clear sensitive data from memory.
     *
     * @param data The sensitive buffer to wipe (if null, operation is a no-op).
     */
    public static void wipe(byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }

    /**
     * Overwrites a sensitive char array with null characters to clear sensitive data from memory.
     *
     * @param chars The sensitive char array to wipe (if null, operation is a no-op).
     */
    public static void wipe(char[] chars) {
        if (chars != null) {
            Arrays.fill(chars, '\0');
        }
    }

    /**
     * Attempts to destroy a SecretKey if it implements {@link Destroyable}.
     *
     * @param key The key to destroy.
     */
    public static void wipe(SecretKey key) {
        if (key != null) {
            try {
                if (!key.isDestroyed()) {
                    key.destroy();
                }
            } catch (DestroyFailedException | UnsupportedOperationException ignored) {
                // SecretKey implementations (e.g. SecretKeySpec) may not support destruction
            }
        }
    }

    /**
     * Performs a constant-time comparison of two byte arrays to protect against timing attacks.
     *
     * @param a First array.
     * @param b Second array.
     * @return true if both arrays are non-null and identical in content; false otherwise.
     */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(a, b);
    }

    /**
     * Validates that a key identifier complies with strict format rules.
     *
     * @param keyId The key identifier to validate.
     * @return The validated keyId.
     * @throws CryptoException If keyId is null, empty, exceeds 64 chars, or contains illegal characters.
     */
    public static String validateKeyId(String keyId) {
        if (keyId == null || !KEY_ID_PATTERN.matcher(keyId).matches()) {
            throw new CryptoException("Invalid cryptographic request: invalid key identifier format");
        }
        return keyId;
    }

    /**
     * Validates that a source/client identifier complies with strict format rules.
     *
     * @param sourceId The source identifier to validate.
     * @return The validated sourceId.
     * @throws CryptoException If sourceId is null, empty, exceeds 128 chars, or contains illegal characters.
     */
    public static String validateSourceId(String sourceId) {
        if (sourceId == null || !SOURCE_ID_PATTERN.matcher(sourceId).matches()) {
            throw new CryptoException("Invalid cryptographic request: invalid source identifier format");
        }
        return sourceId;
    }

    /**
     * Validates that plaintext input is non-null and within allowed size bounds.
     *
     * @param plaintext      The plaintext buffer.
     * @param maxAllowedSize Maximum permitted bytes.
     * @throws CryptoException If validation fails.
     */
    public static void validatePlaintext(byte[] plaintext, int maxAllowedSize) {
        Objects.requireNonNull(plaintext, "Plaintext input must not be null");
        if (plaintext.length > maxAllowedSize) {
            throw new CryptoException("Invalid cryptographic request: input exceeds maximum permitted size");
        }
    }

    /**
     * Validates that associated authenticated data (AAD) is within allowed size bounds.
     *
     * @param aad            The AAD buffer (can be null).
     * @param maxAllowedSize Maximum permitted bytes.
     * @throws CryptoException If validation fails.
     */
    public static void validateAad(byte[] aad, int maxAllowedSize) {
        if (aad != null && aad.length > maxAllowedSize) {
            throw new CryptoException("Invalid cryptographic request: AAD exceeds maximum permitted size");
        }
    }

    /**
     * Creates a defensive copy of a byte array, or returns an empty array if input is null.
     *
     * @param source The source array.
     * @return A copy of the source array.
     */
    public static byte[] copyDefensive(byte[] source) {
        if (source == null) {
            return new byte[0];
        }
        return Arrays.copyOf(source, source.length);
    }
}
