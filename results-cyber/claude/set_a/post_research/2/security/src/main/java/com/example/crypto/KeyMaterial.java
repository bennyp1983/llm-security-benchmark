package com.example.crypto;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Generation and strict parsing of raw AES-256 key material.
 *
 * <p>No key is ever hard-coded here or anywhere else in the component: keys are
 * either generated at runtime by the caller (for tests, for a key-rotation
 * tool, for ephemeral data) or supplied by configuration through a
 * {@link SecretKeyProvider}.
 */
public final class KeyMaterial {

    /**
     * One shared, thread-safe CSPRNG. {@code SecureRandom}'s default
     * ("NativePRNG"/"DRBG" depending on platform) is seeded by the OS and is the
     * platform's proven mechanism; no hand-rolled randomness is used anywhere in
     * this component.
     */
    private static final SecureRandom RANDOM = new SecureRandom();

    private KeyMaterial() {
    }

    /** @return {@code count} cryptographically secure random bytes. */
    static byte[] randomBytes(int count) {
        if (count <= 0) {
            throw new IllegalArgumentException("count must be positive");
        }
        byte[] out = new byte[count];
        RANDOM.nextBytes(out);
        return out;
    }

    /**
     * Generates a fresh AES-256 key from the platform CSPRNG.
     *
     * <p>Intended for provisioning and for tests. Production deployments
     * generate the key once, store it in a secret manager, and feed it to a
     * {@link SecretKeyProvider}.
     */
    public static ZeroizableSecretKey generateKey() {
        byte[] raw = randomBytes(ZeroizableSecretKey.KEY_LENGTH_BYTES);
        try {
            return new ZeroizableSecretKey(raw);
        } finally {
            Bytes.wipe(raw);
        }
    }

    /**
     * Parses a Base64-encoded AES-256 key coming from configuration.
     *
     * <p>Configuration is treated as attacker-controlled: the text is
     * length-bounded before decoding, decoded with the strict (non-lenient)
     * Base64 decoder, and the result must be exactly 32 non-zero bytes. Every
     * rejection path produces the same generic message and never includes the
     * value.
     *
     * @param base64 the encoded key; the caller should wipe its own copy
     * @throws IllegalArgumentException if the value is not a well-formed 256-bit key
     */
    public static ZeroizableSecretKey fromBase64(char[] base64) {
        if (base64 == null) {
            throw new IllegalArgumentException("key material is not configured");
        }
        // 32 bytes encodes to 44 chars with padding, 43 without. Anything far
        // larger is rejected before we allocate a decode buffer, which bounds
        // the work an oversized configuration value can cause.
        if (base64.length < 43 || base64.length > 48) {
            CryptoLog.detail("rejected configured key: encoded length=" + base64.length);
            throw new IllegalArgumentException("configured key material is malformed");
        }
        byte[] ascii = null;
        byte[] raw = null;
        try {
            ascii = asciiOf(base64);
            raw = Base64.getDecoder().decode(ascii); // strict: rejects stray characters
            return new ZeroizableSecretKey(raw);
        } catch (IllegalArgumentException e) {
            CryptoLog.detail("rejected configured key: " + CryptoLog.masked(raw));
            throw new IllegalArgumentException("configured key material is malformed");
        } finally {
            Bytes.wipe(ascii);
            Bytes.wipe(raw);
        }
    }

    /** Base64 is ASCII by definition; any non-ASCII character is a rejection. */
    private static byte[] asciiOf(char[] chars) {
        byte[] out = new byte[chars.length];
        for (int i = 0; i < chars.length; i++) {
            char c = chars[i];
            if (c > 0x7F) {
                Bytes.wipe(out);
                throw new IllegalArgumentException("configured key material is malformed");
            }
            out[i] = (byte) c;
        }
        return out;
    }
}
