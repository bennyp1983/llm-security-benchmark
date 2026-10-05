package com.example.crypto;

import java.util.Arrays;

/**
 * An AES key held as a private, copy-owned {@code byte[]} that this class wipes as soon as it is
 * finished with.
 *
 * <p>Why not hold a {@code SecretKey}? Because {@code SecretKeySpec} keeps a live copy of the key
 * for the lifetime of the object, and its {@code destroy()} does not erase anything - on this JDK it
 * throws {@code DestroyFailedException} and leaves {@code isDestroyed()} false - so the only way to
 * actually remove the bytes from the heap is to own the array and zero it. {@code KeyMaterial} owns
 * the array.
 *
 * <p>Instances are short-lived by construction: {@link #use(java.util.function.Function)} derives a
 * {@code SecretKey} from the bytes, hands it to the callback and zeroes its own working array in a
 * {@code finally} block, and {@link #destroy()} erases the master copy. Nothing else in this component
 * is handed the key, and {@code SymmetricCrypto} never retains a {@code KeyMaterial}.
 *
 * <p>What {@code use} does <em>not</em> erase is stated rather than glossed over: {@code SecretKeySpec}
 * clones the array it is given, so the {@code Cipher} inside the callback runs on the JDK's copy, which
 * no public API reaches. Zeroing {@code working} removes this class's copy only. That JDK copy becomes
 * unreachable when the callback returns and is collected on the ordinary schedule; erasing key material
 * held inside another library is not achievable from this class, and saying otherwise would make the
 * {@code finally} block look like a control stronger than it is. It is on the residual-risk list.
 *
 * <p>Security notes that are easy to get wrong and are enforced here:
 * <ul>
 *   <li>the constructor copies the caller's array, so wiping the caller's buffer cannot corrupt
 *       this object, and this object cannot corrupt the caller's buffer;</li>
 *   <li>{@link #equals}, {@link #hashCode} and {@link #toString} never expose the bytes;</li>
 *   <li>only 256-bit AES keys are accepted. {@code SecretKeySpec} would happily construct from a
 *       20-byte array and fail later, so the length is checked here, at the boundary.</li>
 * </ul>
 */
public final class KeyMaterial implements AutoCloseable {

    static final int KEY_BYTES = 32;

    private final int version;
    private byte[] key;
    private boolean destroyed;

    /**
     * Imports key bytes supplied by the caller - from a key store, an environment variable or a
     * secret manager. The bytes are copied, so the caller may (and should) zero its own buffer
     * immediately; exactly {@value #KEY_BYTES} bytes are accepted and anything else is refused rather
     * than padded, truncated or hashed down. The key is version 1.
     */
    public static KeyMaterial fromBytes(byte[] rawKey) throws CryptoException {
        return new KeyMaterial(rawKey, EncryptedBlob.MIN_KEY_VERSION);
    }

    /**
     * Imports key bytes tagged with a key version, for use with {@link KeyVault}. The version is not
     * bookkeeping metadata: it is written into every record this key encrypts and included in the
     * AES-GCM AAD, so a record is cryptographically bound to the key version that produced it and
     * cannot be re-stamped to claim another one.
     *
     * @throws CryptoException if the version is outside {@code 1..255}
     */
    public static KeyMaterial fromBytes(byte[] rawKey, int keyVersion) throws CryptoException {
        if (keyVersion < EncryptedBlob.MIN_KEY_VERSION || keyVersion > EncryptedBlob.MAX_KEY_VERSION) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                    "key version must be between " + EncryptedBlob.MIN_KEY_VERSION + " and "
                            + EncryptedBlob.MAX_KEY_VERSION);
        }
        return new KeyMaterial(rawKey, keyVersion);
    }

    /** The key version this material is tagged with. */
    public int version() {
        return version;
    }

    KeyMaterial(byte[] rawKey, int version) throws CryptoException {
        this.version = version;
        if (rawKey == null) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY, "key material is missing");
        }
        if (rawKey.length != KEY_BYTES) {
            /* Security: only AES-256. A shorter key is a downgrade, not a configuration option. */
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                    "expected a " + KEY_BYTES + "-byte key, got " + rawKey.length);
        }
        this.key = rawKey.clone();
    }

    /**
     * Runs {@code action} with a {@code SecretKey} derived from this key material, then erases both
     * copies. The action's return value is passed through.
     *
     * @throws CryptoException if the key has already been destroyed
     */
    public synchronized <T> T use(java.util.function.Function<javax.crypto.SecretKey, T> action)
            throws CryptoException {
        if (destroyed || key == null) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_NOT_ACTIVE,
                    "key material has already been destroyed");
        }
        byte[] working = key.clone();
        try {
            return action.apply(new javax.crypto.spec.SecretKeySpec(working, "AES"));
        } finally {
            Arrays.fill(working, (byte) 0);
        }
    }

    /**
     * Package-internal raw export, used by {@link #writeTo} and {@link KeyEncoding#toBase64Url}.
     * Deliberately not public: there is no safe generic answer to "give me the key bytes", so the two
     * supported destinations - a file created private, and a canonical base64url string the caller is
     * told not to log - are the only exits, each with its own documented handling requirements.
     */
    synchronized byte[] copyForWrite() throws CryptoException {
        if (destroyed || key == null) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_NOT_ACTIVE,
                    "key material has already been destroyed");
        }
        return key.clone();
    }

    /**
     * Writes the key to a new file that is private from its first byte, for a deployment that keeps
     * keys as files. The file is created {@code 0600} by {@link PrivateFiles} - never created readable
     * and chmod-ed afterwards - its directory must already be private, and an existing file is refused
     * rather than overwritten.
     *
     * <p>The key stays usable afterwards: this does not destroy it. Nothing about this call lets the
     * key be recovered from the file's name, so {@link KeyFileKeySource} needs the same path to read it
     * back.
     *
     * @throws CryptoException if the file exists, the directory is not private, the filesystem has no
     *     POSIX permissions, or this material has been destroyed
     */
    public void writeTo(java.nio.file.Path file) throws CryptoException {
        byte[] raw = copyForWrite();
        try {
            PrivateFiles.writeOwnerOnlyFile(file, raw);
        } finally {
            java.util.Arrays.fill(raw, (byte) 0);
        }
    }

    /** True once the bytes have been erased. */
    public synchronized boolean isDestroyed() {
        return destroyed;
    }

    /** Erases the key bytes. Idempotent. */
    @Override
    public synchronized void close() {
        destroy();
    }

    /** Erases the key bytes. Idempotent. */
    public synchronized void destroy() {
        if (key != null) {
            Arrays.fill(key, (byte) 0);
            key = null;
        }
        destroyed = true;
    }

    /**
     * Compares by identity only. A constant-time content comparison is deliberately not offered:
     * nothing in this component needs to compare key material, and a method that returns "is this
     * the same key" is a way for a caller to mount a byte-at-a-time oracle by accident.
     */
    @Override
    public boolean equals(Object o) {
        return this == o;
    }

    @Override
    public int hashCode() {
        return System.identityHashCode(this);
    }

    /** Never contains key material. */
    @Override
    public String toString() {
        return "KeyMaterial[destroyed=" + destroyed + "]";
    }
}
