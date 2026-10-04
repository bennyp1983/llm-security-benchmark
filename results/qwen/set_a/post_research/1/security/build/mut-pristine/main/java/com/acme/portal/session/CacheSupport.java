package com.acme.portal.session;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** SHA-256 helper shared by the fingerprint and the cache validator. Not a MAC, not a KDF. */
final class CacheSupport {

    private static final ThreadLocal<MessageDigest> SHA256 = new ThreadLocal<MessageDigest>() {
        @Override
        protected MessageDigest initialValue() {
            try {
                return MessageDigest.getInstance("SHA-256");
            } catch (java.security.NoSuchAlgorithmException impossible) {
                // Mandated by the Java platform specification; without it there is no JVM.
                throw new IllegalStateException("SHA-256 unavailable", impossible);
            }
        }
    };

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    /** Hex characters in a full SHA-256 digest. */
    private static final int FULL_HEX = 64;

    static String sha256Hex(String text) {
        return digestHexPrefix(new String[]{text}, FULL_HEX);
    }

    /**
     * First {@code hexChars} hex characters of SHA-256(text), for log-safe identifiers.
     *
     * <p>The input here can be a bearer credential, so the digest is fed in chunks and every
     * intermediate array is zeroed on the way out. The obvious {@code digest(prefix + secret)}
     * would allocate a second full copy of the secret, and formatting a whole 64-character hex
     * string before cutting it down leaves 52 characters of digest material alive for no reason.
     * Nothing here is truly erasable in a JVM (see the note in {@code SessionId} about immutable
     * strings); the aim is the fewest copies with the shortest lifetime.
     */
    static String sha256HexPrefix(String text, int hexChars) {
        return digestHexPrefix(new String[]{text}, hexChars);
    }

    /** Digest of the concatenation of {@code parts}, without materialising that concatenation. */
    static String digestHexPrefix(String[] parts, int hexChars) {
        MessageDigest digest = SHA256.get();
        digest.reset();
        try {
            for (String part : parts) {
                byte[] bytes = part.getBytes(StandardCharsets.UTF_8);
                try {
                    digest.update(bytes);
                } finally {
                    java.util.Arrays.fill(bytes, (byte) 0);
                }
            }
            int chars = Math.max(0, Math.min(hexChars, FULL_HEX));
            byte[] out = digest.digest();
            char[] hex = new char[chars];
            try {
                for (int i = 0; i < chars; i++) {
                    byte b = out[i / 2];
                    hex[i] = HEX[(i % 2 == 0) ? ((b >> 4) & 0xF) : (b & 0xF)];
                }
            } finally {
                java.util.Arrays.fill(out, (byte) 0);
            }
            String result = new String(hex);
            java.util.Arrays.fill(hex, '\u0000');
            return result;
        } finally {
            digest.reset();
        }
    }

    private CacheSupport() {
    }
}
