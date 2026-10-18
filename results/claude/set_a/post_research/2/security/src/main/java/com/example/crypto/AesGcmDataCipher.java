package com.example.crypto;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * AES-256-GCM authenticated encryption for application data.
 *
 * <h2>Algorithm choices</h2>
 * <ul>
 *   <li><b>AES-256/GCM with a 128-bit tag</b>, via the JDK's own SunJCE
 *       provider. GCM is an AEAD mode, so confidentiality and integrity come
 *       from one primitive and there is no way for a caller to forget the
 *       MAC. No ECB, no unauthenticated CBC, no custom construction.</li>
 *   <li><b>96-bit nonce from {@link java.security.SecureRandom}</b>, fresh for
 *       every single encryption. The nonce is stored in the envelope, never
 *       reused, never derived from the data, and never supplied by the caller -
 *       nonce reuse is the one catastrophic failure mode of GCM, so the API
 *       gives nobody the opportunity to cause it.</li>
 *   <li>A <b>per-key encryption counter</b> enforces a hard ceiling of
 *       {@value #MAX_ENCRYPTIONS_PER_KEY} (2^32) messages per key per process,
 *       keeping the probability of a random 96-bit nonce collision negligible.
 *       The increment-and-test is a single atomic operation, so concurrent
 *       callers cannot slip past the limit.</li>
 *   <li>The envelope <b>header is authenticated</b>: version, key id and length
 *       bytes all go into the GCM associated data together with the caller's
 *       AAD, so an attacker cannot re-label a ciphertext as belonging to a
 *       different key or a different format version.</li>
 * </ul>
 *
 * <h2>Untrusted input</h2>
 * {@link #decrypt} treats its argument as wholly attacker-controlled. It
 * bounds the length before allocating, validates magic, version, key-id length
 * and key-id characters, and requires a minimum ciphertext length. Unknown key
 * ids are not distinguishable from a wrong key or a forged tag: the lookup miss
 * runs a decoy decryption so that the work done and the exception thrown are the
 * same, and the only error ever surfaced is the generic
 * {@link CryptoException}.
 *
 * <h2>Envelope format (version 1)</h2>
 * <pre>
 *   offset  size  field
 *   0       4     magic "EDC1"
 *   4       1     format version (1)
 *   5       1     key id length L (1..64)
 *   6       L     key id, ASCII [A-Za-z0-9._-]
 *   6+L     12    GCM nonce
 *   18+L    ...   ciphertext || 16-byte GCM tag
 * </pre>
 * The format is not secret; it carries no plaintext and no key material.
 *
 * <p>Instances are immutable apart from the per-key counters and are safe for
 * concurrent use; a fresh {@link Cipher} is obtained for each operation because
 * {@code Cipher} objects are not thread-safe.
 */
public final class AesGcmDataCipher implements DataCipher {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    /** Magic bytes identifying this envelope format. */
    private static final byte[] MAGIC = {'E', 'D', 'C', '1'};

    private static final byte FORMAT_VERSION = 1;

    /** 96 bits: the size NIST SP 800-38D recommends for GCM. */
    private static final int NONCE_BYTES = 12;

    /** 128 bits: the full GCM tag length; no truncation. */
    private static final int TAG_BITS = 128;
    private static final int TAG_BYTES = TAG_BITS / 8;

    private static final int HEADER_FIXED_BYTES = MAGIC.length + 1 + 1;

    /** Hard ceiling on encryptions per key per process (2^32). */
    public static final long MAX_ENCRYPTIONS_PER_KEY = 4_294_967_296L;

    /** Default maximum plaintext size accepted or produced: 1 MiB. */
    public static final int DEFAULT_MAX_PLAINTEXT_BYTES = 1024 * 1024;

    /** Hard upper bound a caller may configure: 64 MiB. */
    public static final int MAX_CONFIGURABLE_PLAINTEXT_BYTES = 64 * 1024 * 1024;

    /** Maximum accepted associated-data size: 64 KiB. */
    public static final int MAX_AAD_BYTES = 64 * 1024;

    private static final byte[] NO_AAD = new byte[0];

    private final SecretKeyProvider keyProvider;
    private final int maxPlaintextBytes;
    private final Map<String, AtomicLong> encryptionCounters = new ConcurrentHashMap<>();

    /**
     * A key that decrypts nothing, used to equalise the work done when a key id
     * is unknown. Generated per instance from the CSPRNG and never exported.
     */
    private final ZeroizableSecretKey decoyKey = KeyMaterial.generateKey();

    /** Uses {@link #DEFAULT_MAX_PLAINTEXT_BYTES}. */
    public AesGcmDataCipher(SecretKeyProvider keyProvider) {
        this(keyProvider, DEFAULT_MAX_PLAINTEXT_BYTES);
    }

    /**
     * @param keyProvider       source of key material; must already be loaded
     * @param maxPlaintextBytes size limit for plaintext, 1..{@value #MAX_CONFIGURABLE_PLAINTEXT_BYTES}
     */
    public AesGcmDataCipher(SecretKeyProvider keyProvider, int maxPlaintextBytes) {
        this.keyProvider = Objects.requireNonNull(keyProvider, "keyProvider");
        if (maxPlaintextBytes < 1 || maxPlaintextBytes > MAX_CONFIGURABLE_PLAINTEXT_BYTES) {
            throw new IllegalArgumentException("maxPlaintextBytes must be 1-"
                    + MAX_CONFIGURABLE_PLAINTEXT_BYTES);
        }
        this.maxPlaintextBytes = maxPlaintextBytes;
        // Fail fast if the configured active key is unusable, rather than on
        // the first request that needs it.
        requireUsableKey(keyProvider.activeKeyId());
    }

    @Override
    public String activeKeyId() {
        return keyProvider.activeKeyId();
    }

    // ---------------------------------------------------------------- encrypt

    /** Equivalent to {@code encrypt(plaintext, null)}. */
    public byte[] encrypt(byte[] plaintext) throws CryptoException {
        return encrypt(plaintext, null);
    }

    @Override
    public byte[] encrypt(byte[] plaintext, byte[] aad) throws CryptoException {
        if (plaintext == null) {
            throw new IllegalArgumentException("plaintext must not be null");
        }
        if (plaintext.length > maxPlaintextBytes) {
            // Reject oversized input instead of truncating it.
            throw new IllegalArgumentException("plaintext exceeds " + maxPlaintextBytes + " bytes");
        }
        byte[] effectiveAad = checkedAad(aad);

        String keyId = keyProvider.activeKeyId();
        SecretKey key = requireUsableKey(keyId);
        byte[] keyIdBytes = asciiKeyId(keyId);

        reserveNonceBudget(keyId);

        byte[] nonce = KeyMaterial.randomBytes(NONCE_BYTES);
        byte[] header = header(keyIdBytes);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(header);
            cipher.updateAAD(effectiveAad);
            byte[] sealed = cipher.doFinal(plaintext);

            ByteBuffer out = ByteBuffer.allocate(header.length + NONCE_BYTES + sealed.length);
            out.put(header).put(nonce).put(sealed);
            return out.array();
        } catch (GeneralSecurityException e) {
            CryptoLog.detail("encryption failed: keyId=" + keyId
                    + " plaintext=" + CryptoLog.masked(plaintext)
                    + " reason=" + e.getClass().getSimpleName());
            throw new CryptoException("unable to encrypt data");
        } finally {
            Bytes.wipe(nonce);
        }
    }

    // ---------------------------------------------------------------- decrypt

    /** Equivalent to {@code decrypt(envelope, null)}. */
    public byte[] decrypt(byte[] envelope) throws CryptoException {
        return decrypt(envelope, null);
    }

    @Override
    public byte[] decrypt(byte[] envelope, byte[] aad) throws CryptoException {
        byte[] effectiveAad = checkedAad(aad);
        if (envelope == null) {
            throw new IllegalArgumentException("ciphertext must not be null");
        }
        // Bound the input before any parsing or allocation.
        int maxEnvelope = maxEnvelopeBytes();
        if (envelope.length < minEnvelopeBytes() || envelope.length > maxEnvelope) {
            throw fail("envelope length out of range: " + envelope.length);
        }

        byte[] magic = new byte[MAGIC.length];
        System.arraycopy(envelope, 0, magic, 0, MAGIC.length);
        if (!Bytes.constantTimeEquals(MAGIC, magic)) {
            throw fail("envelope magic mismatch");
        }
        if (envelope[MAGIC.length] != FORMAT_VERSION) {
            // Unknown versions are rejected; we never guess a layout.
            throw fail("unsupported envelope version");
        }

        int keyIdLength = envelope[MAGIC.length + 1] & 0xFF;
        if (keyIdLength < 1 || keyIdLength > KeyId.MAX_LENGTH) {
            throw fail("envelope key id length out of range: " + keyIdLength);
        }
        int headerLength = HEADER_FIXED_BYTES + keyIdLength;
        if (envelope.length < headerLength + NONCE_BYTES + TAG_BYTES) {
            throw fail("envelope too short for its declared key id");
        }

        String keyId = decodeKeyId(envelope, HEADER_FIXED_BYTES, keyIdLength);

        byte[] header = new byte[headerLength];
        System.arraycopy(envelope, 0, header, 0, headerLength);
        byte[] nonce = new byte[NONCE_BYTES];
        System.arraycopy(envelope, headerLength, nonce, 0, NONCE_BYTES);
        int sealedOffset = headerLength + NONCE_BYTES;
        int sealedLength = envelope.length - sealedOffset;

        SecretKey key = keyProvider.keyFor(keyId);
        boolean knownKey = key != null && isUsable(key);
        if (!knownKey) {
            // Unknown or unusable key id: carry on with a decoy key so that the
            // amount of work and the resulting error are indistinguishable from
            // a forged or tampered ciphertext. No oracle for "which key ids
            // exist" is exposed.
            key = decoyKey;
        }

        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(header);
            cipher.updateAAD(effectiveAad);
            byte[] plaintext = cipher.doFinal(envelope, sealedOffset, sealedLength);
            if (!knownKey) {
                // Unreachable in practice (the decoy key cannot produce a valid
                // tag), but belt-and-braces: never return data decrypted under
                // a key the provider did not vouch for.
                Bytes.wipe(plaintext);
                throw fail("unknown key id");
            }
            if (plaintext.length > maxPlaintextBytes) {
                Bytes.wipe(plaintext);
                throw fail("decrypted payload exceeds the configured limit");
            }
            return plaintext;
        } catch (AEADBadTagException e) {
            throw fail("authentication tag mismatch for keyId=" + keyId);
        } catch (GeneralSecurityException e) {
            throw fail("decryption failed: " + e.getClass().getSimpleName());
        } finally {
            Bytes.wipe(nonce);
        }
    }

    /**
     * Re-encrypts an existing envelope under the current active key, for
     * migrating stored data after a key rotation.
     *
     * <p>The intermediate plaintext never leaves this method and is wiped
     * before it returns, on both the success and the failure path. The
     * associated data must be the same on both sides, so a record cannot be
     * silently re-bound to a different context during migration.
     *
     * @throws CryptoException if the input does not authenticate under a known key
     */
    public byte[] reencryptUnderActiveKey(byte[] envelope, byte[] aad) throws CryptoException {
        byte[] plaintext = decrypt(envelope, aad);
        try {
            return encrypt(plaintext, aad);
        } finally {
            Bytes.wipe(plaintext);
        }
    }

    // ------------------------------------------------------- text/Base64 API

    /**
     * Encrypts text and returns the envelope as Base64, convenient for storing
     * in a text column or a JSON field.
     *
     * @param text characters to protect; wiped by this method on every path so
     *             the secret does not linger in an unwipeable {@code String}
     */
    public String encryptText(char[] text, byte[] aad) throws CryptoException {
        if (text == null) {
            throw new IllegalArgumentException("text must not be null");
        }
        byte[] utf8 = null;
        try {
            utf8 = Bytes.toUtf8(text);
            return Base64.getEncoder().encodeToString(encrypt(utf8, aad));
        } finally {
            Bytes.wipe(utf8);
            Bytes.wipe(text);
        }
    }

    /**
     * Decrypts a Base64 envelope produced by {@link #encryptText}.
     *
     * @param base64Envelope untrusted text; strictly decoded and length-bounded
     * @return the characters; the caller should wipe them when done
     */
    public char[] decryptText(String base64Envelope, byte[] aad) throws CryptoException {
        byte[] plaintext = decrypt(decodeBase64(base64Envelope), aad);
        try {
            CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            CharBuffer decoded = decoder.decode(ByteBuffer.wrap(plaintext));
            char[] chars = new char[decoded.remaining()];
            decoded.get(chars);
            if (decoded.hasArray()) {
                Bytes.wipe(decoded.array());
            }
            return chars;
        } catch (CharacterCodingException e) {
            // Authentic ciphertext that is not valid UTF-8: still a failure, and
            // still reported identically.
            throw fail("decrypted payload is not valid UTF-8");
        } finally {
            Bytes.wipe(plaintext);
        }
    }

    /** Encrypts and returns the envelope as Base64. */
    public String encryptToBase64(byte[] plaintext, byte[] aad) throws CryptoException {
        return Base64.getEncoder().encodeToString(encrypt(plaintext, aad));
    }

    /** Decrypts a Base64 envelope. */
    public byte[] decryptFromBase64(String base64Envelope, byte[] aad) throws CryptoException {
        return decrypt(decodeBase64(base64Envelope), aad);
    }

    // ----------------------------------------------------------- internals

    private byte[] decodeBase64(String base64Envelope) throws CryptoException {
        if (base64Envelope == null) {
            throw new IllegalArgumentException("ciphertext must not be null");
        }
        // Base64 inflates by 4/3; bound the text before decoding so a huge
        // string cannot be used to exhaust memory.
        long maxChars = 4L * ((maxEnvelopeBytes() + 2) / 3) + 4;
        if (base64Envelope.length() > maxChars) {
            throw fail("base64 ciphertext too long: " + base64Envelope.length());
        }
        try {
            return Base64.getDecoder().decode(base64Envelope); // strict decoder
        } catch (IllegalArgumentException e) {
            throw fail("ciphertext is not valid base64");
        }
    }

    private int minEnvelopeBytes() {
        return HEADER_FIXED_BYTES + 1 + NONCE_BYTES + TAG_BYTES;
    }

    private int maxEnvelopeBytes() {
        return HEADER_FIXED_BYTES + KeyId.MAX_LENGTH + NONCE_BYTES + maxPlaintextBytes + TAG_BYTES;
    }

    private byte[] header(byte[] keyIdBytes) {
        ByteBuffer header = ByteBuffer.allocate(HEADER_FIXED_BYTES + keyIdBytes.length);
        header.put(MAGIC).put(FORMAT_VERSION).put((byte) keyIdBytes.length).put(keyIdBytes);
        return header.array();
    }

    private byte[] checkedAad(byte[] aad) {
        if (aad == null) {
            return NO_AAD;
        }
        if (aad.length > MAX_AAD_BYTES) {
            throw new IllegalArgumentException(
                    "associated data exceeds " + MAX_AAD_BYTES + " bytes");
        }
        return aad;
    }

    /**
     * Reads the key id out of the envelope and validates it against the
     * allow-list. Bytes outside {@code [A-Za-z0-9._-]} are rejected, so the id
     * can never carry control characters into logs or path separators anywhere.
     */
    private String decodeKeyId(byte[] envelope, int offset, int length) throws CryptoException {
        char[] chars = new char[length];
        for (int i = 0; i < length; i++) {
            chars[i] = (char) (envelope[offset + i] & 0xFF);
        }
        String keyId = new String(chars);
        if (!KeyId.isValid(keyId)) {
            throw fail("envelope key id is not well formed");
        }
        return keyId;
    }

    private static byte[] asciiKeyId(String keyId) {
        KeyId.require(keyId);
        byte[] out = new byte[keyId.length()];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) keyId.charAt(i);
        }
        return out;
    }

    /**
     * Atomically claims one nonce from this key's budget.
     *
     * <p>Check and act are a single {@code incrementAndGet}, so no two threads
     * can both observe "one slot left" and both use it.
     */
    private void reserveNonceBudget(String keyId) throws CryptoException {
        AtomicLong counter = encryptionCounters.computeIfAbsent(keyId, id -> new AtomicLong());
        long used = counter.incrementAndGet();
        if (used > MAX_ENCRYPTIONS_PER_KEY) {
            counter.decrementAndGet(); // keep the counter from running away
            CryptoLog.configProblem("encryption limit reached for key id " + keyId
                    + "; rotate the key");
            throw new CryptoException("unable to encrypt data");
        }
    }

    /** Validates a key from the provider: present, AES, exactly 256 bits, not destroyed. */
    private SecretKey requireUsableKey(String keyId) {
        SecretKey key = keyProvider.keyFor(KeyId.require(keyId));
        if (key == null || !isUsable(key)) {
            CryptoLog.configProblem("no usable key material for key id " + keyId);
            throw new IllegalStateException("encryption key configuration is incomplete");
        }
        return key;
    }

    private static boolean isUsable(SecretKey key) {
        if (!"AES".equalsIgnoreCase(key.getAlgorithm())) {
            return false;
        }
        byte[] encoded = key.getEncoded();
        try {
            return encoded != null && encoded.length == ZeroizableSecretKey.KEY_LENGTH_BYTES;
        } finally {
            Bytes.wipe(encoded);
        }
    }

    /**
     * Logs the real reason (non-secret metadata only) and returns the single
     * generic exception every failure path shares.
     */
    private static CryptoException fail(String internalDetail) {
        CryptoLog.detail("decryption rejected: " + internalDetail);
        return new CryptoException("unable to decrypt data");
    }
}
