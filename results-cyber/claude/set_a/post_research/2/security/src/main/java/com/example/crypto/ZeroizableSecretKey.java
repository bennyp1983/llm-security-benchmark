package com.example.crypto;

import javax.crypto.SecretKey;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.MessageDigest;
import java.util.Objects;

/**
 * An AES {@link SecretKey} whose material can actually be erased.
 *
 * <p>The JDK's {@code SecretKeySpec} keeps a private copy of the key bytes that
 * {@code destroy()} does not clear (it throws
 * {@code DestroyFailedException}). This implementation owns its only copy, so
 * {@link #destroy()} genuinely zeroes it and every subsequent use fails closed.
 *
 * <p>Instances are safe to share across threads: the byte array is only mutated
 * by {@link #destroy()}, which is synchronized together with every read.
 */
public final class ZeroizableSecretKey implements SecretKey {

    private static final long serialVersionUID = 1L;

    /** Only AES-256 is accepted; see {@link AesGcmDataCipher} for the rationale. */
    static final int KEY_LENGTH_BYTES = 32;

    private final byte[] key;
    private boolean destroyed;

    /**
     * Takes a defensive copy of {@code keyBytes}. The caller remains responsible
     * for wiping its own array.
     *
     * @throws IllegalArgumentException if the length is not exactly 32 bytes
     */
    ZeroizableSecretKey(byte[] keyBytes) {
        Objects.requireNonNull(keyBytes, "keyBytes");
        if (keyBytes.length != KEY_LENGTH_BYTES) {
            // Length is checked before anything else so that short/empty
            // material from a misconfigured deployment can never be used.
            // The length itself is not secret and is useful for operators.
            throw new IllegalArgumentException(
                    "AES key must be exactly " + KEY_LENGTH_BYTES + " bytes (256 bits)");
        }
        if (isAllZero(keyBytes)) {
            // An all-zero key is the classic symptom of an unset or
            // truncated configuration value. Reject rather than "work".
            throw new IllegalArgumentException("AES key material is unset (all zero bytes)");
        }
        this.key = keyBytes.clone();
    }

    @Override
    public String getAlgorithm() {
        return "AES";
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public synchronized byte[] getEncoded() {
        if (destroyed) {
            return null; // Contract of SecretKey after destruction.
        }
        return key.clone();
    }

    @Override
    public synchronized void destroy() {
        Bytes.wipe(key);
        destroyed = true;
    }

    @Override
    public synchronized boolean isDestroyed() {
        return destroyed;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof ZeroizableSecretKey)) {
            return false;
        }
        byte[] mine = getEncoded();
        byte[] theirs = ((ZeroizableSecretKey) other).getEncoded();
        try {
            if (mine == null || theirs == null) {
                // A destroyed key equals nothing, including another destroyed
                // key: there is no material left to compare.
                return false;
            }
            // Constant-time: a key comparison must not leak a prefix match.
            return MessageDigest.isEqual(mine, theirs);
        } finally {
            Bytes.wipe(mine);
            Bytes.wipe(theirs);
        }
    }

    @Override
    public int hashCode() {
        // Deliberately coarse: a hash derived from key material could leak it
        // through collections or logs.
        return getAlgorithm().hashCode();
    }

    /** Never renders key material. */
    @Override
    public String toString() {
        return "ZeroizableSecretKey[AES-256, destroyed=" + isDestroyed() + "]";
    }

    /**
     * {@link SecretKey} extends {@link java.io.Serializable}, which would
     * otherwise let any code write this key's bytes to a stream, a session
     * store or a cache. Both directions are refused so key material can never
     * leave the process this way.
     */
    private void writeObject(ObjectOutputStream out) throws NotSerializableException {
        throw new NotSerializableException("secret key material must not be serialized");
    }

    private void readObject(ObjectInputStream in) throws NotSerializableException {
        throw new NotSerializableException("secret key material must not be deserialized");
    }

    private static boolean isAllZero(byte[] data) {
        int acc = 0;
        for (byte b : data) {
            acc |= b;
        }
        return acc == 0;
    }
}
