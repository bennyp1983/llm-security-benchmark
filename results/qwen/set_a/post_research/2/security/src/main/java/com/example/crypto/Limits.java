package com.example.crypto;

/**
 * Hard bounds applied to every externally supplied value this component accepts.
 *
 * <p>All of these are lower bounds on what an attacker can make the component do: an unbounded
 * plaintext turns encryption into a memory-exhaustion primitive, an unbounded blob turns a
 * malformed-base64 string into one, and an unbounded iteration count turns a wrong password into a
 * denial of service. Nothing here is tunable at runtime on purpose.
 */
public final class Limits {

    /** Largest plaintext accepted by {@link SymmetricCrypto#encrypt}. */
    public static final int MAX_PLAINTEXT_BYTES = 1 << 20; // 1 MiB

    /** GCM nonce length. Fixed, never read from the record header beyond a consistency check. */
    public static final int IV_BYTES = 12;

    /** Ciphertext is plaintext plus the 16 byte GCM tag. */
    public static final int MAX_CIPHERTEXT_BYTES = MAX_PLAINTEXT_BYTES + 16;

    /** Largest encoded record string accepted by {@link EncryptedBlob#fromEncoded}. */
    public static final int MAX_ENCODED_BLOB_CHARS = 4 * ((3 + IV_BYTES + MAX_CIPHERTEXT_BYTES) / 3) + 8;

    /** GCM tag length in bits. Fixed at the maximum; shorter tags are rejected. */
    public static final int TAG_BITS = 128;

    /** Largest plaintext accepted through the String convenience overloads. */
    public static final int MAX_PLAINTEXT_CHARS = MAX_PLAINTEXT_BYTES;

    /** Allowed characters in a context string (which is authenticated as AES-GCM AAD). */
    public static final int MAX_CONTEXT_CHARS = 200;

    /** Lower bound for PBKDF2. Values below this are rejected rather than honoured. */
    public static final int MIN_KDF_ITERATIONS = 310_000;

    /** Upper bound for PBKDF2: above this a wrong-password attempt becomes a cheap DoS. */
    public static final int MAX_KDF_ITERATIONS = 2_000_000;

    private Limits() {
    }

    /**
     * Validates a caller supplied byte array payload.
     *
     * @throws CryptoException {@code MISSING_INPUT} if null, {@code TOO_LARGE} if over {@code maxBytes}
     */
    public static byte[] requirePayload(byte[] value, int maxBytes, String what) throws CryptoException {
        if (value == null) {
            throw new CryptoException(CryptoException.CryptoFailureCode.MISSING_INPUT, what + " is missing");
        }
        if (value.length > maxBytes) {
            throw new CryptoException(CryptoException.CryptoFailureCode.TOO_LARGE,
                    what + " exceeds the permitted size of " + maxBytes + " bytes");
        }
        return value;
    }

    /**
     * Validates a text field that must stay inside printable US-ASCII: no NULs, no newlines
     * (log injection), no control characters, no bidi overrides.
     *
     * @throws CryptoException if the value is null, empty, too long or holds a disallowed code point
     */
    public static String requireAsciiText(String value, int maxChars, String what) throws CryptoException {
        if (value == null || value.isEmpty()) {
            throw new CryptoException(what + " is missing");
        }
        if (value.length() > maxChars) {
            throw new CryptoException(what + " exceeds the permitted length");
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x21 || c > 0x7E) {
                throw new CryptoException(what + " contains an unsupported character");
            }
        }
        return value;
    }
}
