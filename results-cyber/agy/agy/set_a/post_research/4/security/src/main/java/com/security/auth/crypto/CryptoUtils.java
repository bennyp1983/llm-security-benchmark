package com.security.auth.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Low-level cryptographic and memory security utilities.
 * Ensures credentials can be reliably wiped from memory and comparisons
 * are performed in constant time to prevent side-channel timing attacks.
 */
public final class CryptoUtils {

    private CryptoUtils() {
        // Utility class
    }

    /**
     * Overwrites a sensitive character array in memory with null characters.
     *
     * @param chars the sensitive character array to clear
     */
    public static void wipe(char[] chars) {
        if (chars != null) {
            Arrays.fill(chars, '\0');
        }
    }

    /**
     * Overwrites a sensitive byte array in memory with zeroes.
     *
     * @param bytes the sensitive byte array to clear
     */
    public static void wipe(byte[] bytes) {
        if (bytes != null) {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    /**
     * Performs a constant-time comparison of two byte arrays to prevent timing attacks.
     *
     * @param a first byte array
     * @param b second byte array
     * @return true if both arrays are non-null and contain identical bytes; false otherwise
     */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(a, b);
    }

    /**
     * Performs a constant-time comparison of two strings using UTF-8 byte representations.
     *
     * @param a first string
     * @param b second string
     * @return true if both strings are non-null and equal; false otherwise
     */
    public static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return constantTimeEquals(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8)
        );
    }

    /**
     * Computes the SHA-256 digest of an input string and returns it as a hex string.
     * Used for hashing session tokens prior to database storage.
     *
     * @param input string to hash
     * @return lowercase 64-character hex digest
     */
    public static String sha256Hex(String input) {
        Objects.requireNonNull(input, "Input must not be null");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available in platform", e);
        }
    }

    /**
     * Computes the SHA-256 digest of a byte array and returns the resulting 32 bytes.
     *
     * @param input bytes to hash
     * @return 32-byte digest
     */
    public static byte[] sha256(byte[] input) {
        Objects.requireNonNull(input, "Input must not be null");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available in platform", e);
        }
    }
}
