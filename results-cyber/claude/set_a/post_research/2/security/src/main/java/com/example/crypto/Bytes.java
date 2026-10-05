package com.example.crypto;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/** Small helpers for handling byte arrays that may hold secret material. */
final class Bytes {

    private Bytes() {
    }

    /** Overwrites the array with zeroes. Null-safe so it is usable in finally blocks. */
    static void wipe(byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }

    /** Overwrites the array with zeroes. Null-safe so it is usable in finally blocks. */
    static void wipe(char[] data) {
        if (data != null) {
            Arrays.fill(data, '\0');
        }
    }

    /**
     * Constant-time equality. Used wherever the comparison operands could be
     * secret or attacker-supplied, so that the number of matching leading bytes
     * cannot be recovered from timing.
     */
    static boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    /**
     * Encodes characters to UTF-8 without leaving an intermediate copy of the
     * text in a {@link String} (which cannot be wiped). Malformed or
     * unmappable input is rejected rather than silently replaced, so no
     * permissive default is substituted for invalid input.
     */
    static byte[] toUtf8(char[] chars) {
        CharsetEncoder encoder = StandardCharsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        CharBuffer in = CharBuffer.wrap(chars);
        ByteBuffer out;
        try {
            out = encoder.encode(in);
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("text is not encodable as UTF-8");
        }
        byte[] exact = new byte[out.remaining()];
        out.get(exact);
        // Zero the encoder's backing buffer if it over-allocated.
        if (out.hasArray()) {
            Arrays.fill(out.array(), (byte) 0);
        }
        return exact;
    }
}
