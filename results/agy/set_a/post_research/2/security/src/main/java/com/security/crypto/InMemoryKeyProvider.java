package com.security.crypto;

import javax.crypto.SecretKey;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Thread-safe in-memory key provider supporting key registration, key rotation,
 * key revocation, and memory zeroization.
 * <p>
 * Satisfies:
 * <ul>
 *   <li>Rule 1 (Trust Boundaries): Strictly validates key format, algorithm, and length (must be AES-256).</li>
 *   <li>Rule 2 (Secrets): Holds keys in memory without logging or exposing them in toString().</li>
 *   <li>Rule 5 (Sensitive Data): Implements memory destruction on revocation and on close.</li>
 *   <li>Rule 7 (Concurrency): Fully thread-safe operations backed by ConcurrentHashMap and AtomicReference.</li>
 * </ul>
 */
public final class InMemoryKeyProvider implements KeyProvider {

    private static final String REQUIRED_ALGORITHM = "AES";
    private static final int REQUIRED_KEY_LENGTH_BYTES = 32; // 256-bit AES

    private final ConcurrentHashMap<String, SecretKey> keys = new ConcurrentHashMap<>();
    private final AtomicReference<String> activeKeyId = new AtomicReference<>(null);
    private final AtomicBoolean closed = new AtomicBoolean(false);

    /**
     * Constructs an empty InMemoryKeyProvider.
     */
    public InMemoryKeyProvider() {
    }

    /**
     * Constructs an InMemoryKeyProvider pre-seeded with an initial active key.
     *
     * @param initialKeyId The identifier of the initial key.
     * @param initialKey   The initial 256-bit AES key.
     */
    public InMemoryKeyProvider(String initialKeyId, SecretKey initialKey) {
        registerKey(initialKeyId, initialKey);
        setActiveKeyId(initialKeyId);
    }

    private void ensureOpen() {
        if (closed.get()) {
            throw new CryptoException("Key provider has been closed and destroyed");
        }
    }

    private static void validateKey(SecretKey key) {
        Objects.requireNonNull(key, "Key must not be null");
        if (!REQUIRED_ALGORITHM.equalsIgnoreCase(key.getAlgorithm())) {
            throw new CryptoException("Invalid cryptographic key: algorithm must be " + REQUIRED_ALGORITHM);
        }
        byte[] encoded = key.getEncoded();
        if (encoded != null) {
            try {
                if (encoded.length != REQUIRED_KEY_LENGTH_BYTES) {
                    throw new CryptoException("Invalid cryptographic key: key size must be 256 bits (32 bytes)");
                }
            } finally {
                CryptoUtils.wipe(encoded);
            }
        }
    }

    /**
     * Registers a key under the given keyId.
     *
     * @param keyId The unique identifier for this key.
     * @param key   The 256-bit AES SecretKey.
     */
    public void registerKey(String keyId, SecretKey key) {
        ensureOpen();
        CryptoUtils.validateKeyId(keyId);
        validateKey(key);
        keys.put(keyId, key);
    }

    /**
     * Sets the active key ID used for new encryptions. The key must already be registered.
     *
     * @param keyId The registered key identifier.
     */
    public void setActiveKeyId(String keyId) {
        ensureOpen();
        CryptoUtils.validateKeyId(keyId);
        if (!keys.containsKey(keyId)) {
            throw new CryptoException("Invalid cryptographic request: active key ID is not registered");
        }
        activeKeyId.set(keyId);
    }

    /**
     * Rotates the active encryption key by registering a new key and making it active atomically.
     *
     * @param newKeyId The new key identifier.
     * @param newKey   The new 256-bit AES key.
     */
    public void rotateKey(String newKeyId, SecretKey newKey) {
        ensureOpen();
        CryptoUtils.validateKeyId(newKeyId);
        validateKey(newKey);
        keys.put(newKeyId, newKey);
        activeKeyId.set(newKeyId);
    }

    /**
     * Revokes and destroys an existing key. If the key was the active key, the active key is cleared.
     *
     * @param keyId The identifier of the key to revoke.
     */
    public void revokeKey(String keyId) {
        ensureOpen();
        CryptoUtils.validateKeyId(keyId);
        SecretKey removedKey = keys.remove(keyId);
        activeKeyId.compareAndSet(keyId, null);
        if (removedKey != null) {
            CryptoUtils.wipe(removedKey);
        }
    }

    @Override
    public SecretKey getActiveKey() {
        ensureOpen();
        String currentActiveId = activeKeyId.get();
        if (currentActiveId == null) {
            throw new CryptoException("Invalid cryptographic request: no active key configured");
        }
        SecretKey key = keys.get(currentActiveId);
        if (key == null) {
            throw new CryptoException("Invalid cryptographic request: active key not found in key provider");
        }
        return key;
    }

    @Override
    public String getActiveKeyId() {
        ensureOpen();
        String currentActiveId = activeKeyId.get();
        if (currentActiveId == null) {
            throw new CryptoException("Invalid cryptographic request: no active key configured");
        }
        return currentActiveId;
    }

    @Override
    public Optional<SecretKey> getKey(String keyId) {
        ensureOpen();
        if (keyId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(keys.get(keyId));
    }

    @Override
    public boolean hasKey(String keyId) {
        ensureOpen();
        if (keyId == null) {
            return false;
        }
        return keys.containsKey(keyId);
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            activeKeyId.set(null);
            for (SecretKey key : keys.values()) {
                CryptoUtils.wipe(key);
            }
            keys.clear();
        }
    }

    @Override
    public String toString() {
        return "InMemoryKeyProvider[closed=" + closed.get()
                + ", registeredKeyCount=" + keys.size()
                + ", activeKeyId='" + activeKeyId.get() + "']";
    }
}
