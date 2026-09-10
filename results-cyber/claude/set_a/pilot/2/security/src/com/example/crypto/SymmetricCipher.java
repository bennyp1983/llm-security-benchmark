package com.example.crypto;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Authenticated symmetric encryption of application data with AES-256-GCM.
 *
 * <p>GCM gives confidentiality and integrity in one pass: a modified ciphertext fails to
 * decrypt rather than yielding attacker-influenced plaintext. Every message gets a fresh
 * random 96-bit IV, which is the size GCM is specified for and the only size that lets the
 * birthday bound be reasoned about simply. Reusing an IV under one key destroys GCM's
 * security completely, so the IV is never derived from the plaintext or a counter held in
 * application state.
 *
 * <p>Wire format, all big-endian, IV and parameters in the clear:
 *
 * <pre>
 *   magic "SDC1" (4) | version (1) | paramsLen (2) | params | ivLen (1) | iv | ciphertext||tag
 * </pre>
 *
 * The whole header is fed to GCM as additional authenticated data, so an attacker cannot
 * swap the version, the KDF salt, or the IV length without the tag check failing.
 */
public final class SymmetricCipher {

    public static final int KEY_BITS = 256;

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final byte[] MAGIC = {'S', 'D', 'C', '1'};
    private static final byte VERSION = 1;
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final int MAX_PARAMS = 4096;

    private final KeyProvider keyProvider;
    private final SecureRandom random;

    public SymmetricCipher(KeyProvider keyProvider) {
        this.keyProvider = keyProvider;
        this.random = new SecureRandom();
    }

    public KeyProvider keyProvider() {
        return keyProvider;
    }

    /**
     * Encrypts {@code plaintext} and returns a self-describing envelope.
     *
     * @param associatedData context bound to the ciphertext but not encrypted, such as a
     *     record id or tenant name. Decryption must supply the identical value. May be null.
     */
    public byte[] encrypt(byte[] plaintext, byte[] associatedData) throws GeneralSecurityException {
        byte[] params = keyProvider.newParameters();
        if (params.length > MAX_PARAMS) {
            throw new GeneralSecurityException("key parameters too large: " + params.length);
        }
        byte[] iv = new byte[IV_BYTES];
        random.nextBytes(iv);
        byte[] header = header(params, iv);

        SecretKey key = keyProvider.resolve(params);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(header);
            if (associatedData != null) {
                cipher.updateAAD(associatedData);
            }
            byte[] sealed = cipher.doFinal(plaintext);

            return ByteBuffer.allocate(header.length + sealed.length)
                    .put(header)
                    .put(sealed)
                    .array();
        } finally {
            destroy(key);
        }
    }

    /**
     * Decrypts an envelope produced by {@link #encrypt}.
     *
     * @throws javax.crypto.AEADBadTagException if the message was altered, was produced under a
     *     different key, or {@code associatedData} does not match what was used at encryption.
     */
    public byte[] decrypt(byte[] envelope, byte[] associatedData) throws GeneralSecurityException {
        ByteBuffer in = ByteBuffer.wrap(envelope);
        byte[] params;
        byte[] iv;
        try {
            byte[] magic = new byte[MAGIC.length];
            in.get(magic);
            if (!Arrays.equals(magic, MAGIC)) {
                throw new GeneralSecurityException("not an SDC envelope");
            }
            byte version = in.get();
            if (version != VERSION) {
                throw new GeneralSecurityException("unsupported envelope version: " + version);
            }
            int paramsLen = Short.toUnsignedInt(in.getShort());
            if (paramsLen > MAX_PARAMS) {
                throw new GeneralSecurityException("key parameters too large: " + paramsLen);
            }
            params = new byte[paramsLen];
            in.get(params);
            int ivLen = Byte.toUnsignedInt(in.get());
            if (ivLen != IV_BYTES) {
                throw new GeneralSecurityException("unexpected IV length: " + ivLen);
            }
            iv = new byte[ivLen];
            in.get(iv);
        } catch (BufferUnderflowException e) {
            throw new GeneralSecurityException("truncated envelope", e);
        }
        if (in.remaining() < TAG_BITS / 8) {
            throw new GeneralSecurityException("truncated envelope");
        }
        byte[] header = header(params, iv);

        SecretKey key = keyProvider.resolve(params);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(header);
            if (associatedData != null) {
                cipher.updateAAD(associatedData);
            }
            byte[] sealed = new byte[in.remaining()];
            in.get(sealed);
            return cipher.doFinal(sealed);
        } finally {
            destroy(key);
        }
    }

    private static byte[] header(byte[] params, byte[] iv) {
        return ByteBuffer.allocate(MAGIC.length + 1 + 2 + params.length + 1 + iv.length)
                .put(MAGIC)
                .put(VERSION)
                .putShort((short) params.length)
                .put(params)
                .put((byte) iv.length)
                .put(iv)
                .array();
    }

    /** Clears the key's bytes where the provider allows it, shortening its life in the heap. */
    private static void destroy(SecretKey key) {
        try {
            key.destroy();
        } catch (Exception ignored) {
            // Most JCE key implementations do not support destruction; nothing else to do.
        }
    }
}
