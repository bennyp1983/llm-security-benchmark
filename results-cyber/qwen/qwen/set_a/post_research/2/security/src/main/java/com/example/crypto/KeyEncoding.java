package com.example.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Parses key material out of a byte buffer that came from configuration or a file.
 *
 * <p>Two shapes are accepted, and only these two:
 * <ol>
 *   <li>exactly {@value KeyMaterial#KEY_BYTES} raw bytes;</li>
 *   <li>canonical base64url text without padding, decoding to exactly
 *       {@value KeyMaterial#KEY_BYTES} bytes, with no whitespace anywhere.</li>
 * </ol>
 *
 * <p>Why the encoding rules are strict:
 * <ul>
 *   <li>{@code Base64.getMimeDecoder()} silently discards every character outside the alphabet, so
 *       {@code "not-a-key!"} decodes to five bytes with no error and would become a truncated,
 *       weak key. The strict decoder is used and the result is re-encoded and compared, so a
 *       non-canonical spelling is refused rather than silently accepted;</li>
 *   <li>no whitespace is accepted <em>anywhere</em>, in either form. A trailing newline is refused in
 *       the text form as well as the raw one: byte {@code 0x0A} is not printable, so it is rejected
 *       before the decoder is consulted. Trimming first is not an option - a value whose leading or
 *       trailing characters are removable is a value whose length somebody else decides, and the length
 *       is what distinguishes the raw form from the text form. The two forms are distinguishable by
 *       length alone, so there is no ambiguity to resolve and no "try both and hope" path;</li>
 *   <li>a buffer that is neither is rejected outright. There is no fallback that pads, truncates, or
 *       hashes the input down to 32 bytes - silently deriving a key from a malformed one is how a key
 *       rotation ends up with two different keys called the same thing.</li>
 * </ul>
 *
 * <p>There is deliberately no counterpart that renders key material as a {@code String}: a
 * {@code String} cannot be zeroed, so it would leave the key in the heap past the end of the
 * operation. {@link KeyMaterial#copyForWrite()} is the only export path and it hands back a byte array
 * the caller is expected to wipe.
 */
public final class KeyEncoding {

    /** Maximum size of a buffer this will look at: more than any accepted key form needs. */
    public static final int MAX_INPUT_BYTES = 4096;

    private static final Base64.Encoder CANON = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private KeyEncoding() {
    }

    /**
     * @param raw bytes read from a key file or a configuration value; never null
     * @return a new array of exactly {@value KeyMaterial#KEY_BYTES} bytes
     * @throws CryptoException if the buffer is not one of the two accepted forms
     */
    public static byte[] decodeKeyBytes(byte[] raw) throws CryptoException {
        byte[] in = Limits.requirePayload(raw, MAX_INPUT_BYTES, "key material");
        if (in.length == KeyMaterial.KEY_BYTES) {
            return in.clone();
        }
        if (in.length == 0) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY, "key material is empty");
        }
        for (byte b : in) {
            int v = b & 0xFF;
            /* Control characters, including NUL and newline, are not part of the text form. */
            if (v <= 0x20 || v > 0x7E) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                        "key material is neither " + KeyMaterial.KEY_BYTES + " raw bytes nor printable base64url text");
            }
        }
        String text = new String(in, StandardCharsets.US_ASCII);
        byte[] decoded;
        try {
            decoded = DECODER.decode(text);
        } catch (IllegalArgumentException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                    "key material is not valid base64url text", e);
        }
        if (!CANON.encodeToString(decoded).equals(text)) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                    "key material is not canonically encoded base64url text");
        }
        if (decoded.length != KeyMaterial.KEY_BYTES) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                    "key material decodes to " + decoded.length + " bytes, expected " + KeyMaterial.KEY_BYTES);
        }
        return decoded;
    }

    /**
     * Renders a key as canonical base64url text. For the one legitimate case: an operator-facing
     * export used to place a key into a secret manager.
     *
     * <p>The result is a {@code String} and therefore <em>not</em> erasable; it exists so the caller
     * can hand a key to a system that only accepts text. Callers must not log it, must not put it in a
     * command line, and must not write it to a file they have not created with {@code 0600}
     * permissions. Prefer {@code PrivateFiles.writeOwnerOnlyFile} with raw bytes.
     *
     * <p>{@link KeyMaterial} is required rather than a bare array so the caller has already had to
     * hold the key in a managed object.
     */
    public static String toBase64Url(KeyMaterial key) throws CryptoException {
        byte[] raw = key.copyForWrite();
        try {
            return CANON.encodeToString(raw);
        } finally {
            java.util.Arrays.fill(raw, (byte) 0);
        }
    }
}
