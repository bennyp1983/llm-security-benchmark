package com.portal.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Crypto helpers. Everything here is a thin, checked wrapper over a JDK primitive:
 * SHA-256, {@link MessageDigest#isEqual} (constant time) and {@link SecureRandom}.
 * No hand-rolled primitives, no third-party code.
 */
public final class Crypto {

    private Crypto() {
    }

    /**
     * The single entropy source for every token, salt and key in this program.
     * The default provider's StrongShadowed/NativePRNG instance is seeded from the OS.
     */
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();
    private static final Base64.Decoder B64STD_DEC = Base64.getDecoder();
    private static final Base64.Encoder B64STD = Base64.getEncoder();

    public static byte[] randomBytes(int count) {
        if (count < 16 || count > 4096) {
            throw new IllegalArgumentException("randomBytes count out of range");
        }
        byte[] out = new byte[count];
        RANDOM.nextBytes(out);
        return out;
    }

    /** URL-safe, unpadded base64 of {@code byteCount} random bytes (never caller-supplied). */
    public static String randomUrlToken(int byteCount) {
        return B64URL.encodeToString(randomBytes(byteCount));
    }

    /**
     * Short random suffix for temp/probe filenames. Kept separate from
     * {@link #randomUrlToken} on purpose: the 16-byte floor of {@link #randomBytes} is a
     * guard against accidentally minting a weak *security* token, and this is not one --
     * it only has to defeat a same-instant collision by another process.
     */
    public static String randomNameSuffix(int byteCount) {
        if (byteCount < 6 || byteCount > 15) {
            throw new IllegalArgumentException("name-suffix size out of range");
        }
        byte[] out = new byte[byteCount];
        RANDOM.nextBytes(out);
        try {
            return B64URL.encodeToString(out);
        } finally {
            Crypto.wipe(out);
        }
    }

    public static byte[] sha256(byte[] in) {
        return digest("SHA-256").digest(in);
    }

    public static byte[] sha256(char[] ascii) {
        return digest("SHA-256").digest(asciiBytes(ascii));
    }

    public static String sha256Hex(byte[] in) {
        return toHex(sha256(in));
    }

    public static String sha256Hex(String in) {
        return sha256Hex(in.getBytes(StandardCharsets.UTF_8));
    }

    /** Constant-time comparison; the platform implementation, not ours. */
    public static boolean equal(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    /**
     * Length-safe, never-throwing comparison of two {@code char[]} secrets, used for the
     * "repeat your new password" confirmation. Not a security decision (both values came
     * from the same terminal), but written so it cannot leak a difference through an
     * exception or an early exit either.
     */
    public static boolean equalChars(char[] a, char[] b) {
        if (a == null || b == null) {
            return a == b;
        }
        int diff = a.length ^ b.length;
        int n = Math.min(a.length, b.length);
        for (int i = 0; i < n; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }

    /**
     * Constant-time comparison of two ASCII tokens, on the platform's {@code MessageDigest}
     * comparison rather than a hand-written loop. Anything non-ASCII is reported as unequal
     * without being encoded: a charset that cannot represent a character replaces it with
     * {@code '?'}, which is the one way this comparison could report two different values as
     * equal. The single production caller validates both operands first
     * ({@code InputPolicy.isCsrfToken}), so the guard never fires on a live request -- it
     * exists so that a later caller cannot inherit that failure mode by accident.
     */
    public static boolean equalConstantTime(String a, String b) {
        if (a == null || b == null) {
            return a == b;
        }
        if (!isAscii(a) || !isAscii(b)) {
            return false;
        }
        byte[] x = a.getBytes(StandardCharsets.US_ASCII);
        byte[] y = b.getBytes(StandardCharsets.US_ASCII);
        try {
            return MessageDigest.isEqual(x, y);
        } finally {
            wipe(x);
            wipe(y);
        }
    }

    private static boolean isAscii(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) > 0x7F) {
                return false;
            }
        }
        return true;
    }

    /**
     * Strict base64 decode: rejects the empty field, an over-long field, unknown alphabet
     * characters, stray padding and trailing bits. The empty case matters because
     * {@code "pbkdf2$sha256$100000$$<key>"} has a structurally present but valueless salt
     * field; decoding it to a zero-length array and letting a length check downstream do
     * the work would spread the decision across two places.
     */
    public static byte[] base64Strict(String s) {
        if (s == null || s.isEmpty() || s.length() > 512) {
            throw new IllegalArgumentException("base64:length");
        }
        byte[] raw;
        try {
            raw = B64STD_DEC.decode(s);
        } catch (IllegalArgumentException bad) {
            throw new IllegalArgumentException("base64:illegal");
        }
        // Canonical form check: non-canonical encodings decode "fine" but are malleable.
        if (!B64STD.encodeToString(raw).equals(s)) {
            throw new IllegalArgumentException("base64:non-canonical");
        }
        return raw;
    }

    public static String base64(byte[] in) {
        return B64STD.encodeToString(in);
    }

    /**
     * Strict url-safe base64 decode with the same canonical-form requirement, plus an
     * exact expected byte length. Used for session ids and CSRF tokens, i.e. attacker-
     * supplied strings that are about to be compared against server-side state.
     */
    public static byte[] base64UrlStrictExpectedLen(String s, int expectedBytes) {
        if (s == null || s.isEmpty() || s.length() > 256) {
            throw new IllegalArgumentException("b64url:length");
        }
        byte[] raw;
        try {
            raw = B64URL_DEC.decode(s);
        } catch (IllegalArgumentException bad) {
            throw new IllegalArgumentException("b64url:illegal");
        }
        if (raw.length != expectedBytes) {
            throw new IllegalArgumentException("b64url:wrong-length");
        }
        if (!B64URL.encodeToString(raw).equals(s)) {
            throw new IllegalArgumentException("b64url:non-canonical");
        }
        return raw;
    }

    /** Bytes of an already-validated ASCII char array. Refuses anything non-ASCII. */
    public static byte[] asciiBytes(char[] ascii) {
        byte[] out = new byte[ascii.length];
        for (int i = 0; i < ascii.length; i++) {
            char c = ascii[i];
            if (c > 0x7F) {
                Arrays.fill(out, (byte) 0);
                throw new IllegalArgumentException("ascii:non-ascii");
            }
            out[i] = (byte) c;
        }
        return out;
    }

    public static String toHex(byte[] in) {
        StringBuilder sb = new StringBuilder(in.length * 2);
        for (byte b : in) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    /**
     * Short, non-reversible reference to an identity or address: the first 16 hex characters
     * of the digest, i.e. 64 bits. Truncated so the audit line stays short and the value
     * cannot be offline-brute-forced back to a name, yet wide enough to double as a
     * throttle-bucket key -- a collision there would mean two accounts sharing one failure
     * counter, which is a security outcome. The subject population for a bucket is the set of
     * names and source addresses seen inside one retention window, so even a six-figure
     * directory leaves the collision chance near {@code n^2/2^65} (~3e-8 at n = 1e6), far
     * below anything operationally relevant. The width is pinned on both sides of the ledger
     * rather than inferred: {@code Ledger.key} refuses a subject that is not exactly
     * {@code Ledger.SUBJECT_HEX} wide and {@code Ledger.validKey} refuses it again on load.
     */
    public static String idRef(char[] ascii) {
        return sha256Hex(asciiBytes(ascii)).substring(0, 16);
    }

    /**
     * Same reference as {@link #idRef(char[])} and deliberately routed through it: a lossy
     * charset conversion here would fold two different names onto one throttle bucket, so
     * non-ASCII is refused the same way the {@code char[]} overload refuses it instead of
     * being mapped to {@code '?'}.
     */
    public static String idRef(String ascii) {
        return idRef(ascii.toCharArray());
    }

    public static void wipe(char[] a) {
        if (a != null) {
            Arrays.fill(a, '\0');
        }
    }

    public static void wipe(byte[] a) {
        if (a != null) {
            Arrays.fill(a, (byte) 0);
        }
    }

    private static MessageDigest digest(String alg) {
        try {
            return MessageDigest.getInstance(alg);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("digest-missing:" + alg, impossible);
        }
    }
}
