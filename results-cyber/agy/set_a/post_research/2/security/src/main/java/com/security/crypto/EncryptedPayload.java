package com.security.crypto;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * Encapsulates authenticated ciphertext, initialization vector (IV), version,
 * and key metadata in a tamper-evident binary or URL-safe Base64 envelope.
 * <p>
 * Wire Format (Version 1):
 * <pre>
 * +---------------+--------------+----------------+---------------+---------------+----------+--------------------+---------------------+
 * | Magic (4B)    | Version (1B) | KeyIdLen (1B)  | KeyId (NB)    | IvLen (1B)    | IV (12B) | CipherLen (4B)     | Ciphertext+Tag (MB) |
 * | 'S','E','C','1'| 0x01         | 1..64          | UTF-8 bytes   | 0x0C (12)     | 12 bytes | Big-endian integer | >= 16 bytes         |
 * +---------------+--------------+----------------+---------------+---------------+----------+--------------------+---------------------+
 * </pre>
 * <p>
 * Security Design:
 * <ul>
 *   <li>Rule 1 (Trust Boundaries): Strictly validates magic bytes, version, lengths,
 *       and character boundaries. Bounded buffer allocations eliminate DoS/OOM vectors.</li>
 *   <li>Rule 2 & 5 (Secrets & Sensitive Data): Overrides {@link #toString()} to mask
 *       all cryptographic data, preventing leakage in logs, monitoring, or debug traces.</li>
 *   <li>Rule 6 (Failure Behavior): Malformed payloads trigger uniform {@link CryptoException}
 *       rejections with generic error messages.</li>
 * </ul>
 */
public final class EncryptedPayload {

    /**
     * Magic identifier bytes: ASCII "SEC1".
     */
    public static final byte[] MAGIC = new byte[]{'S', 'E', 'C', '1'};

    /**
     * Payload wire format version.
     */
    public static final byte CURRENT_VERSION = 0x01;

    /**
     * Standard GCM nonce / IV length in bytes (96 bits).
     */
    public static final int GCM_IV_LENGTH = 12;

    /**
     * Standard GCM authentication tag length in bytes (128 bits).
     */
    public static final int GCM_TAG_LENGTH = 16;

    /**
     * Minimum valid binary wire size (Magic + Version + KeyIdLen + MinKeyId + IvLen + IV + CipherLen + MinCiphertextTag).
     */
    private static final int MIN_WIRE_LENGTH = 4 + 1 + 1 + 1 + 1 + GCM_IV_LENGTH + 4 + GCM_TAG_LENGTH;

    private final byte version;
    private final String keyId;
    private final byte[] iv;
    private final byte[] ciphertextWithTag;

    /**
     * Constructs an EncryptedPayload.
     *
     * @param version           The wire protocol version.
     * @param keyId             The key identifier used to encrypt the payload.
     * @param iv                The 12-byte initialization vector.
     * @param ciphertextWithTag The ciphertext including the 16-byte GCM authentication tag.
     */
    public EncryptedPayload(byte version, String keyId, byte[] iv, byte[] ciphertextWithTag) {
        if (version != CURRENT_VERSION) {
            throw new CryptoException("Invalid cryptographic request: unsupported payload version");
        }
        this.version = version;
        this.keyId = CryptoUtils.validateKeyId(keyId);

        Objects.requireNonNull(iv, "IV must not be null");
        if (iv.length != GCM_IV_LENGTH) {
            throw new CryptoException("Invalid cryptographic request: invalid IV length");
        }
        this.iv = CryptoUtils.copyDefensive(iv);

        Objects.requireNonNull(ciphertextWithTag, "Ciphertext must not be null");
        if (ciphertextWithTag.length < GCM_TAG_LENGTH) {
            throw new CryptoException("Invalid cryptographic request: ciphertext shorter than authentication tag");
        }
        this.ciphertextWithTag = CryptoUtils.copyDefensive(ciphertextWithTag);
    }

    public byte getVersion() {
        return version;
    }

    public String getKeyId() {
        return keyId;
    }

    public byte[] getIv() {
        return CryptoUtils.copyDefensive(iv);
    }

    public byte[] getCiphertextWithTag() {
        return CryptoUtils.copyDefensive(ciphertextWithTag);
    }

    /**
     * Serializes this payload to standard binary wire format.
     *
     * @return Serialized byte array.
     */
    public byte[] toBytes() {
        byte[] keyIdBytes = keyId.getBytes(StandardCharsets.UTF_8);
        int totalLength = 4 + 1 + 1 + keyIdBytes.length + 1 + iv.length + 4 + ciphertextWithTag.length;
        ByteBuffer buffer = ByteBuffer.allocate(totalLength);
        buffer.put(MAGIC);
        buffer.put(version);
        buffer.put((byte) keyIdBytes.length);
        buffer.put(keyIdBytes);
        buffer.put((byte) iv.length);
        buffer.put(iv);
        buffer.putInt(ciphertextWithTag.length);
        buffer.put(ciphertextWithTag);
        return buffer.array();
    }

    /**
     * Serializes this payload to a URL-safe Base64 string without padding.
     *
     * @return URL-safe Base64 encoded string.
     */
    public String toBase64Url() {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(toBytes());
    }

    /**
     * Parses and strictly validates an EncryptedPayload from binary wire format.
     *
     * @param data              Raw byte array from untrusted input.
     * @param maxCiphertextSize Maximum permissible ciphertext size to prevent OOM DoS attacks.
     * @return Validated EncryptedPayload instance.
     * @throws CryptoException If the input fails validation or integrity checks.
     */
    public static EncryptedPayload fromBytes(byte[] data, int maxCiphertextSize) {
        if (data == null || data.length < MIN_WIRE_LENGTH) {
            throw new CryptoException("Invalid cryptographic payload: payload too short or malformed");
        }
        if (data.length > maxCiphertextSize + 1024) {
            throw new CryptoException("Invalid cryptographic payload: payload exceeds maximum allowable size");
        }

        try {
            ByteBuffer buffer = ByteBuffer.wrap(data);

            // 1. Verify Magic Header
            byte[] magicHeader = new byte[4];
            buffer.get(magicHeader);
            if (!Arrays.equals(magicHeader, MAGIC)) {
                throw new CryptoException("Invalid cryptographic payload: unrecognized format header");
            }

            // 2. Verify Version
            byte ver = buffer.get();
            if (ver != CURRENT_VERSION) {
                throw new CryptoException("Invalid cryptographic payload: unsupported version");
            }

            // 3. Verify KeyId
            int keyIdLen = buffer.get() & 0xFF;
            if (keyIdLen < 1 || keyIdLen > 64 || buffer.remaining() < keyIdLen) {
                throw new CryptoException("Invalid cryptographic payload: invalid key identifier length");
            }
            byte[] keyIdBytes = new byte[keyIdLen];
            buffer.get(keyIdBytes);
            String parsedKeyId = new String(keyIdBytes, StandardCharsets.UTF_8);
            CryptoUtils.validateKeyId(parsedKeyId);

            // 4. Verify IV
            if (buffer.remaining() < 1) {
                throw new CryptoException("Invalid cryptographic payload: truncated payload header");
            }
            int ivLen = buffer.get() & 0xFF;
            if (ivLen != GCM_IV_LENGTH || buffer.remaining() < ivLen) {
                throw new CryptoException("Invalid cryptographic payload: invalid IV length");
            }
            byte[] parsedIv = new byte[ivLen];
            buffer.get(parsedIv);

            // 5. Verify Ciphertext & Tag
            if (buffer.remaining() < 4) {
                throw new CryptoException("Invalid cryptographic payload: truncated payload header");
            }
            int cipherLen = buffer.getInt();
            if (cipherLen < GCM_TAG_LENGTH || cipherLen > maxCiphertextSize) {
                throw new CryptoException("Invalid cryptographic payload: invalid ciphertext length");
            }
            if (buffer.remaining() != cipherLen) {
                // Must match exactly: reject extra trailing bytes or truncation
                throw new CryptoException("Invalid cryptographic payload: payload length mismatch");
            }
            byte[] parsedCiphertext = new byte[cipherLen];
            buffer.get(parsedCiphertext);

            return new EncryptedPayload(ver, parsedKeyId, parsedIv, parsedCiphertext);
        } catch (java.nio.BufferUnderflowException e) {
            throw new CryptoException("Invalid cryptographic payload: truncated payload", e);
        }
    }

    /**
     * Parses and strictly validates an EncryptedPayload from a URL-safe Base64 string.
     *
     * @param base64Url         Untrusted Base64 string.
     * @param maxCiphertextSize Maximum permissible ciphertext size.
     * @return Validated EncryptedPayload instance.
     * @throws CryptoException If Base64 decoding or structure validation fails.
     */
    public static EncryptedPayload fromBase64Url(String base64Url, int maxCiphertextSize) {
        if (base64Url == null || base64Url.isBlank()) {
            throw new CryptoException("Invalid cryptographic payload: empty input");
        }
        // Basic pre-check on base64 string length to avoid allocating oversized arrays
        int maxBase64Len = ((maxCiphertextSize + 1024) * 4) / 3 + 4;
        if (base64Url.length() > maxBase64Len) {
            throw new CryptoException("Invalid cryptographic payload: input exceeds maximum allowable size");
        }

        byte[] raw;
        try {
            raw = Base64.getUrlDecoder().decode(base64Url);
        } catch (IllegalArgumentException e) {
            throw new CryptoException("Invalid cryptographic payload: invalid Base64 encoding", e);
        }

        return fromBytes(raw, maxCiphertextSize);
    }

    /**
     * Masks sensitive payload contents to prevent accidental disclosure in logs,
     * exceptions, or debug inspection (Rules 2 &amp; 5).
     */
    @Override
    public String toString() {
        return "EncryptedPayload[version=" + version
                + ", keyId='" + keyId + '\''
                + ", ivLength=" + iv.length
                + ", ciphertextLength=" + ciphertextWithTag.length
                + ", content=[PROTECTED]]";
    }
}
