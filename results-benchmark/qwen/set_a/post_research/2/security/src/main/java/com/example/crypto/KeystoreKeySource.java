package com.example.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * A passphrase-protected PKCS#12 key store, using the platform {@link KeyStore} implementation.
 *
 * <p>Layout: a {@code SecretKeyEntry} holding a <em>random</em> AES-256 key, protected by the key
 * password, inside a store whose integrity MAC is computed from the store password. Nothing is derived
 * from the passphrase, so the key's entropy does not depend on passphrase wording, and no verification
 * pattern is needed: the MAC fails on a wrong store password and {@code getKey} fails on a wrong key
 * password.
 *
 * <p><strong>What this does not buy you.</strong> PKCS#12 protects both with a password-based KDF
 * whose iteration count this build does not control, and measurement on OpenJDK&nbsp;17.0.20.1 puts it
 * at roughly {@code 10^4} iterations - about 20&nbsp;ms per guess, five orders of magnitude cheaper
 * than a 600&nbsp;000-iteration PBKDF2. That gap is the entire offline-brute-force defence, so this
 * class is only safe when the "passphrase" is a high-entropy machine secret. It refuses anything
 * shorter than {@value #MIN_PASSPHRASE_CHARS} characters, and
 * {@link RandomPasswords#generate()} exists so nobody has to invent one by hand.
 *
 * <p>For a human-memorable passphrase, do not use this class. Generate a random key with
 * {@link SymmetricCrypto#generateKey(int)} and keep it in a KMS or HSM, or protect it with a
 * deliberately expensive KDF that you configure yourself.
 *
 * <p><strong>It is also a container, not a lock.</strong> A file-based key store protects a key only
 * from a reader who lacks the password. It does not hide the key from this process, so it adds nothing
 * against an attacker who can already read process memory, and it does not stop whoever supplies both
 * the file and the password from reading every record ever written.
 *
 * <p>File handling: the store must satisfy {@link PrivateFiles} - owner-only regular file, no symlink,
 * private ancestry - and that is re-checked on every {@link #load()}, not just at construction.
 * {@link #create} writes it private from the first byte, because {@code KeyStore.store()} would
 * otherwise leave the new file at {@code 0644} until a later chmod.
 *
 * <p>Passwords are {@code char[]}, copied on construction and erased by {@link #destroy()}. There is
 * deliberately no {@code String} overload: a {@code String} password cannot be erased and would remain
 * in the heap for the life of the process.
 */
public final class KeystoreKeySource implements KeySource, AutoCloseable {

    /** Minimum accepted password length. See the class notes: length is the whole defence here. */
    public static final int MIN_PASSPHRASE_CHARS = 32;

    /** Default alias inside stores created by {@link #create}. */
    public static final String DEFAULT_ALIAS = "data-key";

    private static final int MAX_PASSPHRASE_CHARS = 4096;
    private static final String STORE_TYPE = "PKCS12";
    private static final String ALIAS_PATTERN = "[A-Za-z0-9_.:\\-]{1,64}";
    private static final int MAX_STORE_BYTES = 1 << 20;
    private static final int MAX_ENTRIES = 64;

    private final Path file;
    private final String alias;
    private final int keyVersion;
    private final char[] storePassword;
    private final char[] keyPassword;
    private volatile boolean destroyed;

    /**
     * @param file existing store file
     * @param alias key entry name, matching {@code [A-Za-z0-9_.:\-]{1,64}}, from deployment
     *     configuration
     * @param keyVersion the version to tag loaded keys with, {@code 1..255}; in a {@link KeyVault}
     *     this is what the alias is registered under, and it goes into the AAD of every record
     * @param storePassword PKCS#12 integrity password, random, at least {@value #MIN_PASSPHRASE_CHARS}
     *     characters
     * @param keyPassword password protecting the key entry, same floor. May equal
     *     {@code storePassword}; two different values means two independent secrets to manage.
     * @throws CryptoException if any parameter is invalid
     */
    public KeystoreKeySource(Path file, String alias, int keyVersion, char[] storePassword, char[] keyPassword)
            throws CryptoException {
        if (file == null) {
            throw new CryptoException(CryptoException.CryptoFailureCode.MISSING_INPUT, "key store path is missing");
        }
        String abs = file.toAbsolutePath().toString();
        if (abs.length() > 4096 || abs.indexOf('\0') >= 0) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT, "key store path is invalid");
        }
        if (alias == null || !alias.matches(ALIAS_PATTERN)) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                    "key alias must match " + ALIAS_PATTERN);
        }
        if (keyVersion < EncryptedBlob.MIN_KEY_VERSION || keyVersion > EncryptedBlob.MAX_KEY_VERSION) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT, "key version is out of range");
        }
        char[] sp = requirePassphrase(storePassword, "store password");
        char[] kp;
        try {
            kp = requirePassphrase(keyPassword, "key password");
        } catch (CryptoException e) {
            Arrays.fill(sp, (char) 0);
            throw e;
        }
        this.file = file;
        this.alias = alias;
        this.keyVersion = keyVersion;
        this.storePassword = sp;
        this.keyPassword = kp;
    }

    /** Creates a store holding a freshly generated random AES-256 key under {@link #DEFAULT_ALIAS}. */
    public static void create(Path file, char[] storePassword, char[] keyPassword) throws CryptoException {
        create(file, DEFAULT_ALIAS, EncryptedBlob.MIN_KEY_VERSION, storePassword, keyPassword);
    }

    /**
     * Creates a store holding a freshly generated random AES-256 key.
     *
     * @param file destination; must not exist, and its directory must satisfy {@link PrivateFiles}
     * @param alias entry name to create
     * @param keyVersion version to tag the key with, {@code 1..255}
     * @param storePassword integrity password, random, at least {@value #MIN_PASSPHRASE_CHARS} chars
     * @param keyPassword key-entry password, same floor
     * @throws CryptoException if the file exists, its directory is not private, a password is too
     *     short, or the platform cannot generate the key
     */
    public static void create(Path file, String alias, int keyVersion, char[] storePassword, char[] keyPassword)
            throws CryptoException {
        if (file == null) {
            throw new CryptoException(CryptoException.CryptoFailureCode.MISSING_INPUT, "key store path is missing");
        }
        if (alias == null || !alias.matches(ALIAS_PATTERN)) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                    "key alias must match " + ALIAS_PATTERN);
        }
        if (keyVersion < EncryptedBlob.MIN_KEY_VERSION || keyVersion > EncryptedBlob.MAX_KEY_VERSION) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT, "key version is out of range");
        }
        char[] sp = requirePassphrase(storePassword, "store password");
        char[] kp = null;
        byte[] raw = new byte[KeyMaterial.KEY_BYTES];
        try {
            kp = requirePassphrase(keyPassword, "key password");
            Path parent = file.toAbsolutePath().getParent();
            if (parent == null || !Files.exists(parent)) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                        "key store directory does not exist; create it privately first");
            }
            PrivateFiles.requireSecureDirectory(parent);
            if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                        "key store already exists; refusing to overwrite it");
            }

            new SecureRandom().nextBytes(raw);
            KeyStore ks = KeyStore.getInstance(STORE_TYPE);
            ks.load(null, null);
            ks.setKeyEntry(alias, new SecretKeySpec(raw, "AES"), kp, null);

            /* Created 0600 rather than chmod-ed afterwards: it must never exist world-readable. */
            try (OutputStream out = PrivateFiles.newOwnerOnlyOutputStream(file)) {
                ks.store(out, sp);
            }
            PrivateFiles.requirePrivateKeyFile(file);
        } catch (CryptoException e) {
            throw e;
        } catch (GeneralSecurityException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.PROVIDER_FAILURE,
                    "key store could not be created: " + e.getClass().getSimpleName(), e);
        } catch (IOException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                    "key store could not be written", e);
        } finally {
            Arrays.fill(raw, (byte) 0);
            Arrays.fill(sp, (char) 0);
            if (kp != null) {
                Arrays.fill(kp, (char) 0);
            }
        }
    }

    /**
     * Loads the key. The store is re-read from disk each time - no key material is cached - and its
     * file permissions are re-checked first.
     *
     * <p>Every failure is {@code KEY_SOURCE_UNAVAILABLE}, {@code INVALID_KEY} or {@code KEY_UNAVAILABLE}
     * behind the same generic user message, so a wrong store password, a wrong key password, a
     * tampered file and a missing alias cannot be told apart through {@code getMessage()}.
     */
    @Override
    public KeyMaterial load() throws CryptoException {
        if (destroyed) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_NOT_ACTIVE, "key source is closed");
        }
        PrivateFiles.requirePrivateKeyFile(file);
        KeyStore ks;
        try {
            ks = KeyStore.getInstance(STORE_TYPE);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.PROVIDER_FAILURE,
                    "the PKCS12 keystore type is unavailable on this JVM", e);
        }
        try {
            if (Files.size(file) > MAX_STORE_BYTES) {
                throw new CryptoException(CryptoException.CryptoFailureCode.TOO_LARGE, "key store is too large");
            }
        } catch (IOException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE,
                    "key store could not be inspected", e);
        }
        try (InputStream in = Files.newInputStream(file)) {
            /*
             * Both types together: on PKCS#12 a wrong store password surfaces as an IOException
             * wrapping an integrity failure, not as a GeneralSecurityException, and a handler that
             * catches only the latter would let it escape unclassified.
             */
            ks.load(in, storePassword);
        } catch (GeneralSecurityException | IOException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE,
                    "key store could not be opened: wrong store password, tampered file, or unreadable ("
                            + e.getClass().getSimpleName() + ")", e);
        }
        try {
            if (ks.size() > MAX_ENTRIES) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                        "key store has too many entries");
            }
            if (!ks.containsAlias(alias)) {
                throw new CryptoException(CryptoException.CryptoFailureCode.KEY_UNAVAILABLE,
                        "key store has no entry named " + alias);
            }
            if (!ks.entryInstanceOf(alias, KeyStore.SecretKeyEntry.class)) {
                /* Guards against a secret stored under a PrivateKeyEntry, which getKey would reject. */
                throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                        "key store entry " + alias + " is not a symmetric key entry");
            }
            Key entry = ks.getKey(alias, keyPassword);
            if (!(entry instanceof SecretKey sk)) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                        "key store entry " + alias + " is not a symmetric key");
            }
            byte[] raw = sk.getEncoded();
            if (raw == null) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_KEY,
                        "key store entry " + alias + " cannot be exported");
            }
            try {
                return KeyMaterial.fromBytes(raw, keyVersion);
            } finally {
                Arrays.fill(raw, (byte) 0);
            }
        } catch (CryptoException e) {
            throw e;
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            /* UnrecoverableKeyException: wrong key password. */
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE,
                    "key could not be recovered: wrong key password or unreadable entry ("
                            + e.getClass().getSimpleName() + ")", e);
        }
    }

    /** Erases this object's copies of both passwords. Further {@link #load()} calls fail closed. */
    /** Same as {@link #destroy()}; lets callers use try-with-resources, which is the easy path. */
    @Override
    public void close() {
        destroy();
    }

    public synchronized void destroy() {
        Arrays.fill(storePassword, (char) 0);
        Arrays.fill(keyPassword, (char) 0);
        destroyed = true;
    }

    public boolean isDestroyed() {
        return destroyed;
    }

    /**
     * Validates a password and returns a private copy.
     *
     * <p>Two JDK behaviours drive the checks, both verified on OpenJDK&nbsp;17.0.20.1: a trailing
     * {@code NUL} is dropped and every unpaired surrogate is mapped to {@code '?'} when the JCE
     * converts a {@code char[]} to the KDF input, so passphrases in those classes derive the
     * <em>same</em> key material as different ones; and the store's MAC is the only thing standing
     * between an attacker and the key, so two passphrases that collapse to one are one lock with two
     * keys. Both are refused rather than trimmed - trimming would silently change the secret and make
     * an existing store unreadable.
     *
     * @throws CryptoException if null, empty, shorter than {@value #MIN_PASSPHRASE_CHARS}, longer than
     *     {@value #MAX_PASSPHRASE_CHARS}, ending in {@code NUL}, or containing an unpaired surrogate
     */
    static char[] requirePassphrase(char[] password, String what) throws CryptoException {
        if (password == null || password.length == 0) {
            throw new CryptoException(CryptoException.CryptoFailureCode.MISSING_INPUT, what + " is missing");
        }
        if (password.length < MIN_PASSPHRASE_CHARS || password.length > MAX_PASSPHRASE_CHARS) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                    what + " must be between " + MIN_PASSPHRASE_CHARS + " and " + MAX_PASSPHRASE_CHARS
                            + " characters. Generate it randomly; do not compose it by hand.");
        }
        if (password[password.length - 1] == 0) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                    what + " ends with a NUL character, which the JCE silently discards");
        }
        for (int i = 0; i < password.length; i++) {
            char c = password[i];
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= password.length || !Character.isLowSurrogate(password[i + 1])) {
                    throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                            what + " contains an unpaired surrogate, which the JCE maps to '?'");
                }
                i++;
            } else if (Character.isLowSurrogate(c)) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                        what + " contains an unpaired surrogate, which the JCE maps to '?'");
            }
        }
        return password.clone();
    }

    /** The store path and alias. A path is not a secret; the contents are. */
    @Override
    public String describe() {
        return "pkcs12:" + file.toAbsolutePath() + "#" + alias + "@" + keyVersion;
    }

    /**
     * Identity for {@link KeyVault}'s cache key. Deliberately excludes the passwords: a source's
     * identity is where it reads from, and deriving a hash over secret material to compare sources
     * would be a oracle-shaped footgun for no benefit.
     */
    @Override
    public boolean equals(Object o) {
        return o instanceof KeystoreKeySource other
                && keyVersion == other.keyVersion
                && file.equals(other.file)
                && alias.equals(other.alias);
    }

    @Override
    public int hashCode() {
        return Objects.hash(file, alias, keyVersion);
    }

    @Override
    public String toString() {
        return describe();
    }
}
