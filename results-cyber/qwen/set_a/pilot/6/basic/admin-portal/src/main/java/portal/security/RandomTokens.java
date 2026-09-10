package portal.security;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Cryptographically strong random values. All bounds-safe (no modulo bias) and
 * never seeded from time or {@link java.util.Random}.
 */
public final class RandomTokens {

    /** Ambiguity-free alphabet, used for human-readable one-time passwords. */
    private static final char[] ALPHABET =
            "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789".toCharArray();

    private final SecureRandom random;

    public RandomTokens() {
        this.random = new SecureRandom();
    }

    public byte[] bytes(int length) {
        if (length <= 0 || length > 4096) {
            throw new IllegalArgumentException("invalid length");
        }
        byte[] out = new byte[length];
        random.nextBytes(out);
        return out;
    }

    /** URL-safe, unpadded Base64 of {@code byteLength} random bytes. */
    public String base64Url(int byteLength) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes(byteLength));
    }

    /** {@code length} characters drawn uniformly from {@link #ALPHABET}. */
    public String alphabetString(int length) {
        if (length < 8 || length > 128) {
            throw new IllegalArgumentException("invalid length");
        }
        char[] out = new char[length];
        for (int i = 0; i < length; i++) {
            out[i] = ALPHABET[random.nextInt(ALPHABET.length)];
        }
        return new String(out);
    }
}
