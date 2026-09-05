package vault;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Custody of the symmetric keys: where they live, how they are created, how they are read
 * back, and how they are removed.
 *
 * <h2>Where keys live</h2>
 * Keys are stored in a PKCS#12 keystore file. The keystore password is the single secret an
 * operator or secret manager has to supply; the file itself is created {@code 0600} so no
 * other local account can read it, and it is rewritten through a staging file so a crash
 * cannot leave a truncated keystore behind. Loading verifies the PKCS#12 MAC, so a edited or
 * swapped keystore is rejected instead of being used quietly.
 *
 * <h2>Deliberately avoided</h2>
 * <ul>
 *   <li>No key is derived from a hard-coded constant, a word list, or the data it protects.</li>
 *   <li>No key material appears in a log line, {@code toString()}, or exception message.</li>
 *   <li>{@link #key(String)} hands back a key for a single operation and validates that it is
 *       AES-256; {@link #zero(javax.crypto.SecretKey)} exists so callers can wipe it after use.</li>
 * </ul>
 *
 * <h2>Passphrase-derived keys</h2>
 * Where an operator only has a passphrase, {@link #deriveFromPassphrase} stretches it with
 * PBKDF2-HMAC-SHA256 at {@value #PBKDF2_ITERATIONS} iterations over a random 128-bit salt. The
 * salt and iteration count are recorded in the authenticated envelope header, so the key can be
 * rebuilt later without ever being stored, and neither cost parameter can be silently downgraded
 * to make an old payload readable.
 */
public final class KeyVault implements AutoCloseable {

    /** 256-bit AES key, paired with a 128-bit GCM tag by {@link AesGcmCipher}. */
    public static final int KEY_LENGTH_BITS = 256;

    public static final int PBKDF2_ITERATIONS = 310_000;
    public static final int MIN_PBKDF2_ITERATIONS = 100_000;
    public static final int SALT_LENGTH = Envelope.MAX_SALT_LENGTH;
    public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";

    static final String STORE_TYPE = "PKCS12";
    private static final Pattern ALIAS_PATTERN = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,63}");
    private static final int MAX_PASSPHRASE_CHARS = 1024;
    private static final int KEY_BYTES = KEY_LENGTH_BITS / 8;

    private final Path storePath;
    private final char[] storePassword;
    private final KeyStore store;
    private final SecureRandom random;

    private KeyVault(Path storePath, char[] storePassword, KeyStore store, SecureRandom random) {
        this.storePath = storePath;
        this.storePassword = storePassword.clone();
        this.store = store;
        this.random = random;
    }

    /**
     * Opens {@code storePath}, creating an owner-readable-only store when none exists. The
     * parent directory is created if missing.
     */
    public static KeyVault open(Path storePath, char[] storePassword, SecureRandom random) {
        return open(storePath, storePassword, random, true);
    }

    /**
     * Opens an existing store and refuses to create one. Read paths (decrypt, list) should use
     * this: silently producing an empty keystore turns a mistyped {@code --keystore} into a
     * confusing "no such key" error and leaves a stray file behind.
     */
    public static KeyVault openExisting(Path storePath, char[] storePassword) {
        return open(storePath, storePassword, new SecureRandom(), false);
    }

    private static KeyVault open(Path storePath, char[] storePassword, SecureRandom random,
            boolean createIfMissing) {
        if (storePassword == null || storePassword.length == 0) {
            throw new VaultException("keystore password must not be empty");
        }
        try {
            KeyStore store = KeyStore.getInstance(STORE_TYPE);
            boolean exists = Files.isRegularFile(storePath);
            if (!exists && !createIfMissing) {
                throw new VaultException("no keystore at " + storePath
                        + "; run the init command to create one");
            }
            Path parent = storePath.toAbsolutePath().getParent();
            Files.createDirectories(parent);
            if (!exists) {
                store.load(null, null);
                KeyVault vault = new KeyVault(storePath, storePassword, store, random);
                vault.persist();
                return vault;
            }
            FilePermissions.restrictToOwner(storePath);
            try (InputStream in = Files.newInputStream(storePath)) {
                store.load(in, storePassword);
            } catch (IOException e) {
                // PKCS#12 verifies its integrity MAC during load and surfaces a bad password
                // or an edited file as IOException from here.
                throw new VaultException("unable to load keystore " + storePath
                        + ": wrong password, or the file was altered", e);
            }
            return new KeyVault(storePath, storePassword, store, random);
        } catch (VaultException e) {
            throw e;
        } catch (GeneralSecurityException | IOException e) {
            throw new VaultException("unable to open keystore " + storePath, e);
        }
    }

    public static KeyVault open(Path storePath, char[] storePassword) {
        return open(storePath, storePassword, new SecureRandom());
    }

    public Path storePath() {
        return storePath;
    }

    public Set<String> aliases() {
        try {
            Set<String> names = new TreeSet<>();
            names.addAll(Collections.list(store.aliases()));
            return names;
        } catch (KeyStoreException e) {
            throw new VaultException("unable to list keystore aliases", e);
        }
    }

    public boolean contains(String alias) {
        requireAlias(alias);
        try {
            return store.containsAlias(alias);
        } catch (KeyStoreException e) {
            throw new VaultException("unable to inspect alias " + alias, e);
        }
    }

    /**
     * Creates a fresh random AES-256 key. Refuses to overwrite an existing alias: replacing a
     * key in place would strand every payload sealed under it. Rotate through the facade
     * instead, which re-seals what the old key protected.
     */
    public SecretKey generate(String alias) {
        requireAlias(alias);
        if (contains(alias)) {
            throw new VaultException("alias " + alias + " already exists; pick an unused alias, or "
                    + "re-seal existing payloads before replacing this key");
        }
        try {
            KeyGenerator generator = KeyGenerator.getInstance(AesGcmCipher.KEY_ALGORITHM);
            generator.init(KEY_LENGTH_BITS, random);
            SecretKey key = generator.generateKey();
            putEntry(alias, key);
            return key;
        } catch (GeneralSecurityException e) {
            throw new VaultException("unable to generate key for alias " + alias, e);
        }
    }

    /**
     * Stores an AES-256 key that came from elsewhere, such as a secret manager or a key
     * ceremony. Only the length is validated here; the bytes are never echoed back.
     */
    public void importKey(String alias, byte[] rawKey) {
        requireAlias(alias);
        if (rawKey == null || rawKey.length != KEY_BYTES) {
            throw new VaultException("raw key must be exactly " + KEY_BYTES + " bytes, got "
                    + (rawKey == null ? "nothing" : rawKey.length));
        }
        putEntry(alias, new SecretKeySpec(rawKey, AesGcmCipher.KEY_ALGORITHM));
    }

    /**
     * Reads a key for one operation. Wipe it with {@link #zero(SecretKey)} when the operation
     * ends rather than caching it for the life of the process.
     */
    public SecretKey key(String alias) {
        requireAlias(alias);
        if (!contains(alias)) {
            throw new VaultException("no key stored under alias " + alias + "; available: " + aliases());
        }
        try {
            if (!(store.getKey(alias, storePassword) instanceof SecretKey key)) {
                throw new VaultException("entry " + alias + " is not a secret key");
            }
            byte[] encoded = key.getEncoded();
            if (encoded == null || encoded.length != KEY_BYTES) {
                throw new VaultException("entry " + alias + " is not a " + KEY_LENGTH_BITS + "-bit AES key");
            }
            java.util.Arrays.fill(encoded, (byte) 0);
            return key;
        } catch (ClassCastException notASecret) {
            throw new VaultException("entry " + alias + " is a certificate or private key, not a secret key");
        } catch (UnrecoverableKeyException e) {
            throw new VaultException("entry " + alias + " could not be recovered; wrong keystore password?", e);
        } catch (GeneralSecurityException e) {
            throw new VaultException("unable to read key " + alias, e);
        }
    }

    /** Removes a key. Any payload still sealed under it becomes unreadable. */
    public void delete(String alias) {
        requireAlias(alias);
        try {
            if (!store.containsAlias(alias)) {
                return;
            }
            store.deleteEntry(alias);
            persist();
        } catch (KeyStoreException e) {
            throw new VaultException("unable to delete alias " + alias, e);
        }
    }

    /**
     * Stretches a passphrase into an AES-256 key. Returns the cost parameters alongside the
     * key because the envelope needs them to rebuild it later.
     */
    public static DerivedKey deriveFromPassphrase(char[] passphrase, byte[] salt, int iterations,
            SecureRandom random) {
        if (passphrase == null || passphrase.length == 0) {
            throw new VaultException("passphrase must not be empty");
        }
        if (passphrase.length > MAX_PASSPHRASE_CHARS) {
            throw new VaultException("passphrase longer than " + MAX_PASSPHRASE_CHARS + " characters");
        }
        byte[] effectiveSalt = salt;
        if (effectiveSalt == null) {
            effectiveSalt = newSalt(random);
        } else if (effectiveSalt.length != SALT_LENGTH) {
            throw new VaultException("salt must be " + SALT_LENGTH + " bytes, got " + effectiveSalt.length);
        }
        int effectiveIterations = iterations <= 0 ? PBKDF2_ITERATIONS : iterations;
        if (effectiveIterations < MIN_PBKDF2_ITERATIONS) {
            throw new VaultException("refusing to derive a key from " + effectiveIterations
                    + " iterations; minimum is " + MIN_PBKDF2_ITERATIONS);
        }
        char[] copy = passphrase.clone();
        try {
            PBEKeySpec spec = new PBEKeySpec(copy, effectiveSalt, effectiveIterations, KEY_LENGTH_BITS);
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
                byte[] raw = factory.generateSecret(spec).getEncoded();
                try {
                    return new DerivedKey(new SecretKeySpec(raw, AesGcmCipher.KEY_ALGORITHM), effectiveSalt,
                            effectiveIterations);
                } finally {
                    java.util.Arrays.fill(raw, (byte) 0);
                }
            } catch (GeneralSecurityException e) {
                throw new VaultException("unable to derive key from passphrase", e);
            } finally {
                spec.clearPassword();
            }
        } finally {
            java.util.Arrays.fill(copy, '\0');
        }
    }

    public static byte[] newSalt(SecureRandom random) {
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        return salt;
    }

    public static byte[] newSalt() {
        return newSalt(new SecureRandom());
    }

    /**
     * Clears the byte array handed back by {@code key.getEncoded()}. This is weaker than it
     * looks: {@code SecretKeySpec} keeps its own private copy and returns a fresh clone each
     * time, so the key itself survives - and no Java API can scrub copies the JVM has already
     * duplicated or pinned on the heap.
     *
     * <p>The real mitigation is scoping, which is what {@link DataVault} does: a key is
     * resolved for one operation and dropped immediately, rather than cached for the life of
     * the process. Call this on arrays you own; do not rely on it to erase a key from memory.
     */
    public static void zero(SecretKey key) {
        if (key == null) {
            return;
        }
        try {
            byte[] encoded = key.getEncoded();
            if (encoded != null) {
                java.util.Arrays.fill(encoded, (byte) 0);
            }
        } catch (RuntimeException ignored) {
            // Implementations that refuse getEncoded after destruction have nothing left to wipe.
        }
    }

    /** Key inventory safe to print: aliases only, never key material. */
    public String describe() {
        return "keystore " + storePath + " [" + STORE_TYPE + "] aliases=" + aliases();
    }

    @Override
    public void close() {
        java.util.Arrays.fill(storePassword, '\0');
    }

    private void putEntry(String alias, SecretKey key) {
        try {
            byte[] encoded = key.getEncoded();
            if (encoded == null || encoded.length != KEY_BYTES) {
                throw new VaultException("only " + KEY_LENGTH_BITS + "-bit AES keys may be stored");
            }
            java.util.Arrays.fill(encoded, (byte) 0);
            store.setKeyEntry(alias, key, storePassword, null);
            persist();
        } catch (KeyStoreException e) {
            throw new VaultException("unable to store key under alias " + alias, e);
        }
    }

    private void persist() {
        Path absolute = storePath.toAbsolutePath();
        Path parent = absolute.getParent();
        Path partial = null;
        try {
            Files.createDirectories(parent);
            partial = Files.createTempFile(parent, absolute.getFileName() + "-", ".part");
            FilePermissions.restrictToOwner(partial);
            try (OutputStream out = Files.newOutputStream(partial)) {
                store.store(out, storePassword);
            }
            FilePermissions.restrictToOwner(partial);
            Files.move(partial, absolute, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            FilePermissions.restrictToOwner(absolute);
        } catch (GeneralSecurityException | IOException e) {
            throw new VaultException("unable to persist keystore " + absolute, e);
        } finally {
            if (partial != null) {
                try {
                    Files.deleteIfExists(partial);
                } catch (IOException ignored) {
                    // The staging file was usually consumed by the move.
                }
            }
        }
    }

    private static void requireAlias(String alias) {
        if (alias == null || !ALIAS_PATTERN.matcher(alias).matches()) {
            throw new VaultException("key alias must match " + ALIAS_PATTERN.pattern() + ", got " + alias);
        }
    }

    /** Key material plus the KDF parameters required to rebuild it. */
    public static final class DerivedKey implements AutoCloseable {

        private final SecretKey key;
        private final byte[] salt;
        private final int iterations;

        DerivedKey(SecretKey key, byte[] salt, int iterations) {
            this.key = key;
            this.salt = salt.clone();
            this.iterations = iterations;
        }

        public SecretKey key() {
            return key;
        }

        public byte[] salt() {
            return salt.clone();
        }

        public int iterations() {
            return iterations;
        }

        @Override
        public void close() {
            zero(key);
            java.util.Arrays.fill(salt, (byte) 0);
        }
    }
}
