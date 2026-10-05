package com.example.accounts;

/** Lowercase hex encoding for digests and random identifiers. */
final class Hex {

    private static final char[] DIGITS = "0123456789abcdef".toCharArray();

    private Hex() {
    }

    static String encode(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xff;
            out[i * 2] = DIGITS[v >>> 4];
            out[i * 2 + 1] = DIGITS[v & 0x0f];
        }
        return new String(out);
    }
}
