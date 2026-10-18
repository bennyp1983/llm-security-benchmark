package com.security.crypto;

import javax.crypto.SecretKey;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Enumeration;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * KeyProvider implementation that securely loads symmetric AES-256 keys
 * from a standard Java KeyStore (PKCS12 format).
 * <p>
 * Satisfies:
 * <ul>
 *   <li>Rule 1 (Trust Boundaries): Validates file paths, permissions, and key aliases.</li>
 *   <li>Rule 2 (Secrets): Clears char array passwords from memory immediately after loading.
 *       Rejects files accessible by other users.</li>
 *   <li>Rule 5 (Sensitive Data): Destroys secret keys upon close; masks toString().</li>
 *   <li>Rule 8 (Prefer the Platform): Utilizes standard Java PKCS12 KeyStore platform mechanisms.</li>
 * </ul>
 */
public final class KeyStoreKeyProvider implements KeyProvider {

    private static final String DEFAULT_KEYSTORE_TYPE = "PKCS12";
    private static final String REQUIRED_ALGORITHM = "AES";
    private static final int REQUIRED_KEY_LENGTH_BYTES = 32;

    private final ConcurrentHashMap<String, SecretKey> keys = new ConcurrentHashMap<>();
    private final AtomicReference<String> activeKeyId = new AtomicReference<>(null);
    private final AtomicBoolean closed = new AtomicBoolean(false);

    /**
     * Loads a KeyStore from a secure filesystem path.
     *
     * @param keyStorePath     The path to the KeyStore file.
     * @param password         The KeyStore password as a char array (will be zeroed upon return).
     * @param activeKeyAlias   The alias of the key to use as the active encryption key.
     * @return Initialized KeyStoreKeyProvider.
     */
    public static KeyStoreKeyProvider fromFile(Path keyStorePath, char[] password, String activeKeyAlias) {
        Path validatedPath = FileSecurityUtil.validatePrivateFile(keyStorePath);
        try (InputStream in = Files.newInputStream(validatedPath)) {
            return fromInputStream(in, password, activeKeyAlias);
        } catch (Exception e) {
            if (e instanceof CryptoException ce) {
                throw ce;
            }
            throw new CryptoException("Failed to load KeyStore from file", e);
        }
    }

    /**
     * Loads a KeyStore from an input stream.
     *
     * @param inputStream      Stream containing the KeyStore data.
     * @param password         KeyStore password (zeroed immediately upon completion).
     * @param activeKeyAlias   The alias of the key to use as the active encryption key.
     * @return Initialized KeyStoreKeyProvider.
     */
    public static KeyStoreKeyProvider fromInputStream(InputStream inputStream, char[] password, String activeKeyAlias) {
        Objects.requireNonNull(inputStream, "InputStream must not be null");
        Objects.requireNonNull(password, "Password must not be null");
        Objects.requireNonNull(activeKeyAlias, "Active key alias must not be null");

        KeyStoreKeyProvider provider = new KeyStoreKeyProvider();
        try {
            KeyStore keyStore = KeyStore.getInstance(DEFAULT_KEYSTORE_TYPE);
            keyStore.load(inputStream, password);

            KeyStore.PasswordProtection protParam = new KeyStore.PasswordProtection(password);
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (keyStore.isKeyEntry(alias)) {
                    KeyStore.Entry entry = keyStore.getEntry(alias, protParam);
                    if (entry instanceof KeyStore.SecretKeyEntry secretEntry) {
                        SecretKey key = secretEntry.getSecretKey();
                        if (REQUIRED_ALGORITHM.equalsIgnoreCase(key.getAlgorithm())) {
                            byte[] encoded = key.getEncoded();
                            if (encoded != null) {
                                try {
                                    if (encoded.length == REQUIRED_KEY_LENGTH_BYTES) {
                                        provider.keys.put(alias, key);
                                    }
                                } finally {
                                    CryptoUtils.wipe(encoded);
                                }
                            }
                        }
                    }
                }
            }

            // Verify active key alias exists
            CryptoUtils.validateKeyId(activeKeyAlias);
            if (!provider.keys.containsKey(activeKeyAlias)) {
                provider.close();
                throw new CryptoException("Active key alias '" + activeKeyAlias + "' not found in KeyStore");
            }
            provider.activeKeyId.set(activeKeyAlias);

            return provider;
        } catch (CryptoException ce) {
            provider.close();
            throw ce;
        } catch (Exception e) {
            provider.close();
            throw new CryptoException("Failed to initialize KeyStore: invalid format or credentials", e);
        } finally {
            CryptoUtils.wipe(password);
        }
    }

    private void ensureOpen() {
        if (closed.get()) {
            throw new CryptoException("Key provider has been closed and destroyed");
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
        return "KeyStoreKeyProvider[closed=" + closed.get()
                + ", loadedKeysCount=" + keys.size()
                + ", activeKeyId='" + activeKeyId.get() + "']";
    }
}
