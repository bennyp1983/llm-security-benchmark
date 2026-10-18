package com.example.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Cryptographic helpers. Every method here is either a hash, a constant-time compare, or a
 * CSPRNG draw. Nothing in this class accepts a security decision as an argument.
 */
final class CryptoUtils {

    static final SecureRandom RANDOM = new SecureRandom();

    private CryptoUtils() {
    }

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandated by the JCE spec; absence means an unusable platform.
            throw new IllegalStateException("sha256_unavailable", e);
        }
    }

    static byte[] sha256(String text) {
        return sha256(text.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Length-independent constant-time comparison. MessageDigest.isEqual is already
     * constant-time with respect to content but its behaviour on differing lengths is
     * implementation-defined, so the length is folded into the timing-independent result.
     */
    static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return false;
        }
        int diff = a.length ^ b.length;
        int n = Math.min(a.length, b.length);
        for (int i = 0; i < n; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }

    /**
     * Compares a candidate secret held as UTF-8 text against a stored hex digest without ever
     * exposing either. Returns false for a malformed stored value.
     */
    static boolean matchesHexDigest(String candidate, String storedHex) {
        if (candidate == null || storedHex == null) {
            return false;
        }
        byte[] cand = sha256(candidate);
        byte[] stored = tryHex(storedHex);
        if (stored == null) {
            Arrays.fill(cand, (byte) 0);
            return false;
        }
        boolean eq = constantTimeEquals(cand, stored);
        Arrays.fill(cand, (byte) 0);
        Arrays.fill(stored, (byte) 0);
        return eq;
    }

    static String toHex(byte[] data) {
        char[] out = new char[data.length * 2];
        final char[] digits = "0123456789abcdef".toCharArray();
        for (int i = 0; i < data.length; i++) {
            int v = data[i] & 0xFF;
            out[i * 2] = digits[v >>> 4];
            out[i * 2 + 1] = digits[v & 0x0F];
        }
        return new String(out);
    }

    static byte[] fromHex(String hex) {
        // An odd length can never be a hex encoding; null and odd are the only shape failures.
        if (hex == null || (hex.length() & 1) == 1) {
            throw new IllegalArgumentException("bad_hex_length");
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("bad_hex_char");
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    private static byte[] tryHex(String s) {
        try {
            return fromHex(s);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** Fills the buffer with CSPRNG bytes. */
    static byte[] randomBytes(int n) {
        if (n <= 0 || n > 4096) {
            throw new IllegalArgumentException("bad_random_length");
        }
        byte[] out = new byte[n];
        RANDOM.nextBytes(out);
        return out;
    }

    static void wipe(char[] buffer) {
        if (buffer != null) {
            Arrays.fill(buffer, (char) 0);
        }
    }

    static void wipe(byte[] buffer) {
        if (buffer != null) {
            Arrays.fill(buffer, (byte) 0);
        }
    }
}
