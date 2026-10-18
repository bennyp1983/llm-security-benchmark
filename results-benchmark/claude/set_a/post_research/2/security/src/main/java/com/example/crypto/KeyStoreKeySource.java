package com.example.crypto;

import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.UnrecoverableKeyException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Loads the key set from a PKCS#12 keystore - the platform's own mechanism for
 * storing secret keys at rest, used here in preference to any hand-rolled key
 * file format.
 *
 * <p>Each {@code SecretKeyEntry} alias becomes a key id; the alias named by
 * {@code activeAlias} becomes the active key. The keystore file must be a
 * regular, owner-only-readable file in a non-world-writable directory
 * ({@link SecureFiles}), and every entry must hold exactly a 256-bit AES key.
 *
 * <p>Create one with, for example:
 * <pre>
 *   umask 077
 *   keytool -genseckey -alias v1 -keyalg AES -keysize 256 \
 *           -storetype PKCS12 -keystore keys.p12
 * </pre>
 * The store password comes from the runtime environment or a secret manager -
 * never from a command-line argument of this process, and never from a constant
 * in this source tree.
 */
public final class KeyStoreKeySource {

    private KeyStoreKeySource() {
    }

    /**
     * @param keystorePath  path to a PKCS#12 keystore
     * @param storePassword store/entry password; wiped by this method on every path
     * @param activeAlias   alias of the key new data is encrypted under
     */
    public static KeySetSecretKeyProvider load(Path keystorePath, char[] storePassword, String activeAlias) {
        Objects.requireNonNull(keystorePath, "keystorePath");
        Objects.requireNonNull(storePassword, "storePassword");
        KeyId.require(activeAlias);

        Map<String, ZeroizableSecretKey> keys = new LinkedHashMap<>();
        byte[] contents = null;
        boolean loaded = false;
        try {
            contents = SecureFiles.readPrivateFile(keystorePath);
            KeyStore store = KeyStore.getInstance("PKCS12");
            try (InputStream in = new ByteArrayInputStream(contents)) {
                // Passing the password also verifies the store's integrity MAC.
                store.load(in, storePassword);
            }
            List<String> aliases = Collections.list(store.aliases());
            if (aliases.size() > KeySetSecretKeyProvider.MAX_KEYS) {
                throw new IllegalStateException(
                        "keystore holds more than " + KeySetSecretKeyProvider.MAX_KEYS + " entries");
            }
            for (String alias : aliases) {
                if (!store.entryInstanceOf(alias, KeyStore.SecretKeyEntry.class)) {
                    continue; // certificates and key pairs are not our business
                }
                if (!KeyId.isValid(alias)) {
                    CryptoLog.configProblem("skipping keystore alias with an unusable name");
                    continue;
                }
                SecretKey entry = (SecretKey) store.getKey(alias, storePassword);
                byte[] raw = entry == null ? null : entry.getEncoded();
                try {
                    if (raw == null || raw.length != ZeroizableSecretKey.KEY_LENGTH_BYTES) {
                        throw new IllegalStateException(
                                "keystore entry is not a 256-bit AES key: " + alias);
                    }
                    keys.put(alias, new ZeroizableSecretKey(raw));
                } finally {
                    Bytes.wipe(raw);
                }
            }
            if (!keys.containsKey(activeAlias)) {
                CryptoLog.configProblem("keystore does not contain the configured active alias");
                throw new IllegalStateException("encryption key configuration is incomplete");
            }
            KeySetSecretKeyProvider provider = new KeySetSecretKeyProvider(keys, activeAlias);
            loaded = true;
            return provider;
        } catch (UnrecoverableKeyException e) {
            // Wrong password: generic message, no detail about which alias.
            CryptoLog.configProblem("keystore password was rejected");
            throw new IllegalStateException("encryption key configuration is incomplete");
        } catch (GeneralSecurityException | java.io.IOException e) {
            CryptoLog.configProblem("keystore could not be loaded: " + e.getClass().getSimpleName());
            throw new IllegalStateException("encryption key configuration is incomplete");
        } finally {
            if (!loaded) {
                // Never leave half-loaded key material in memory after a
                // failed start-up.
                keys.values().forEach(ZeroizableSecretKey::destroy);
            }
            Bytes.wipe(contents);
            Bytes.wipe(storePassword);
        }
    }
}
