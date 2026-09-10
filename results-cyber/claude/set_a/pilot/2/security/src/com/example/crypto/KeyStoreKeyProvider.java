package com.example.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.UnrecoverableKeyException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * Loads the AES key from a PKCS#12 keystore file.
 *
 * <p>This is the provider to use for a service. The key is generated once by
 * {@code Main genkey}, lives in a file the application does not otherwise touch, and is
 * protected at rest by a keystore password supplied through the environment
 * ({@code SDC_KEYSTORE_PASSWORD}) or an interactive prompt. Rotation means generating a new key
 * under a new alias and re-encrypting; the alias travels in configuration, not in the code.
 *
 * <p>The keystore file is deliberately not created implicitly during encryption. Silent
 * creation makes a misconfigured path look like success and produces data no one can decrypt
 * later, since the "real" key was never involved.
 */
public final class KeyStoreKeyProvider implements KeyProvider {

    public static final String PASSWORD_ENV = "SDC_KEYSTORE_PASSWORD";
    private static final String STORE_TYPE = "PKCS12";
    private static final byte[] NO_PARAMETERS = new byte[0];

    private final Path storePath;
    private final String alias;

    public KeyStoreKeyProvider(Path storePath, String alias) {
        this.storePath = storePath;
        this.alias = alias;
    }

    @Override
    public String id() {
        return "keystore:" + storePath + "#" + alias;
    }

    @Override
    public byte[] newParameters() {
        return NO_PARAMETERS;
    }

    @Override
    public SecretKey resolve(byte[] parameters) throws GeneralSecurityException {
        char[] password = Secrets.read(PASSWORD_ENV, "Keystore password");
        try {
            if (!Files.exists(storePath)) {
                throw new GeneralSecurityException(
                        "keystore not found: " + storePath + " (run: genkey --keystore " + storePath + ")");
            }
            if (Secrets.isWorldOrGroupReadable(storePath)) {
                // Refusing is safer than warning: a readable keystore plus a password that is
                // often a deployment constant is close to no protection at all.
                throw new GeneralSecurityException(
                        "keystore " + storePath + " is readable beyond its owner; run: chmod 600 " + storePath);
            }
            KeyStore store = KeyStore.getInstance(STORE_TYPE);
            try (InputStream in = Files.newInputStream(storePath)) {
                store.load(in, password);
            }
            if (!store.containsAlias(alias)) {
                throw new GeneralSecurityException("no key with alias '" + alias + "' in " + storePath);
            }
            java.security.Key key = store.getKey(alias, password);
            if (!(key instanceof SecretKey secret)) {
                throw new GeneralSecurityException("alias '" + alias + "' does not hold a secret key");
            }
            return secret;
        } catch (UnrecoverableKeyException e) {
            throw new GeneralSecurityException("wrong keystore password for alias '" + alias + "'", e);
        } catch (IOException e) {
            // An IOException from KeyStore.load usually means the password was wrong.
            throw new GeneralSecurityException("cannot read keystore " + storePath, e);
        } finally {
            Secrets.wipe(password);
        }
    }

    /**
     * Generates a fresh AES-256 key and stores it under {@code alias}, creating the keystore
     * if needed. Refuses to overwrite an existing alias, since doing so would strand every
     * ciphertext already produced under the old key.
     */
    public void generateKey() throws GeneralSecurityException, IOException {
        char[] password = Secrets.read(PASSWORD_ENV, "Keystore password");
        try {
            KeyStore store = KeyStore.getInstance(STORE_TYPE);
            if (Files.exists(storePath)) {
                try (InputStream in = Files.newInputStream(storePath)) {
                    store.load(in, password);
                }
                if (store.containsAlias(alias)) {
                    throw new GeneralSecurityException(
                            "alias '" + alias + "' already exists in " + storePath
                                    + "; choose a new alias to rotate keys");
                }
            } else {
                store.load(null, password);
            }

            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(SymmetricCipher.KEY_BITS);
            SecretKey key = generator.generateKey();
            store.setKeyEntry(alias, key, password, null);

            // Create with owner-only permissions before any bytes are written, so the key is
            // never briefly world-readable on disk.
            Path tmp = storePath.resolveSibling(storePath.getFileName() + ".tmp");
            try (OutputStream out = Files.newOutputStream(
                    tmp, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE)) {
                Secrets.restrictToOwner(tmp);
                store.store(out, password);
            }
            Files.move(tmp, storePath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            Secrets.restrictToOwner(storePath);
        } finally {
            Secrets.wipe(password);
        }
    }
}
