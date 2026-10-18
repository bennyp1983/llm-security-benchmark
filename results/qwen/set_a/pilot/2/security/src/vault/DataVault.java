package vault;

import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.SecretKey;

/**
 * The entry point most callers want: seal bytes or files with a key the vault resolves itself,
 * and open them again.
 *
 * <p>The key is chosen from the envelope header rather than from an argument, which matters
 * because the header is authenticated. A payload cannot be re-interpreted under a different
 * key after the fact, and a sealed file always says which alias produced it.
 *
 * <pre>{@code
 * try (KeyVault keys = KeyVault.open(Path.of("app.p12"), password);
 *      DataVault vault = new DataVault(keys, "app-data")) {
 *     byte[] sealed = vault.seal(secret.getBytes(UTF_8)).toBytes();
 *     byte[] clear = vault.open(Envelope.fromBytes(sealed)).data();
 * }
 * }</pre>
 */
public final class DataVault implements AutoCloseable {

    /**
     * Supplies the passphrase for {@link KeySource#PASSPHRASE} payloads. Typically reads from a
     * console prompt or a secret manager at the moment it is needed; the vault holds on to the
     * characters only long enough to run PBKDF2.
     */
    public interface PassphraseProvider {

        char[] passphrase();
    }

    private final KeyVault keyVault;
    private final AesGcmCipher cipher;
    private final String defaultAlias;
    private final PassphraseProvider passphraseProvider;
    private final SecureRandom random;

    public DataVault(KeyVault keyVault, String defaultAlias, PassphraseProvider passphraseProvider,
            AesGcmCipher cipher) {
        this.keyVault = keyVault;
        this.defaultAlias = defaultAlias;
        this.passphraseProvider = passphraseProvider;
        this.cipher = cipher;
        this.random = new SecureRandom();
    }

    /** Keystore-backed vault: keys are looked up under {@code defaultAlias}. */
    public DataVault(KeyVault keyVault, String defaultAlias) {
        this(keyVault, defaultAlias, null, AesGcmCipher.withSystemRandom());
    }

    /** Passphrase-backed vault: every payload carries its own salt and iteration count. */
    public DataVault(KeyVault keyVault, PassphraseProvider passphraseProvider) {
        this(keyVault, null, passphraseProvider, AesGcmCipher.withSystemRandom());
    }

    public KeyVault keyVault() {
        return keyVault;
    }

    public String defaultAlias() {
        return defaultAlias;
    }

    /** Sealed plaintext wrapper: {@link #data()} for bytes, {@link #envelope()} for metadata. */
    public static final class Opened implements AutoCloseable {

        private final Envelope envelope;
        private byte[] data;

        Opened(Envelope envelope, byte[] data) {
            this.envelope = envelope;
            this.data = data;
        }

        public byte[] data() {
            if (data == null) {
                throw new VaultException("plaintext has already been wiped");
            }
            return data.clone();
        }

        public Envelope envelope() {
            return envelope;
        }

        @Override
        public void close() {
            if (data != null) {
                Arrays.fill(data, (byte) 0);
                data = null;
            }
        }
    }

    public Envelope seal(byte[] plaintext) {
        if (defaultAlias == null) {
            throw new VaultException("this vault has no default key alias; sealWithPassphrase instead");
        }
        return sealWithKeystoreKey(plaintext, defaultAlias);
    }

    public Envelope sealWithKeystoreKey(byte[] plaintext, String alias) {
        SecretKey key = keyVault.key(alias);
        try {
            return cipher.seal(key, KeySource.KEYSTORE, alias, new byte[0], 0, plaintext);
        } finally {
            KeyVault.zero(key);
        }
    }

    public Envelope sealWithPassphrase(byte[] plaintext) {
        try (KeyVault.DerivedKey derived = deriveDefault()) {
            return cipher.seal(derived.key(), KeySource.PASSPHRASE, aliasForPassphrase(), derived.salt(),
                    derived.iterations(), plaintext);
        }
    }

    /** Opens with whichever key the authenticated header names. */
    public Opened open(Envelope envelope) {
        SecretKey key = resolveKey(envelope);
        try {
            return new Opened(envelope, cipher.open(key, envelope));
        } finally {
            KeyVault.zero(key);
        }
    }

    /** Convenience for bytes produced by {@code Envelope#toBytes()}. */
    public byte[] open(byte[] sealed) {
        try (Opened opened = open(Envelope.fromBytes(sealed))) {
            return opened.data();
        }
    }

    public Envelope sealFile(Path plaintextFile) {
        return sealFileTo(plaintextFile, siblingWithSuffix(plaintextFile, ".sealed"));
    }

    public Envelope sealFileTo(Path plaintextFile, Path sealedFile) {
        if (defaultAlias == null) {
            throw new VaultException("this vault has no default key alias");
        }
        SecretKey key = keyVault.key(defaultAlias);
        try {
            cipher.sealToFile(key, KeySource.KEYSTORE, defaultAlias, new byte[0], 0, plaintextFile, sealedFile);
            return cipher.readEnvelopeHeader(sealedFile);
        } finally {
            KeyVault.zero(key);
        }
    }

    public void sealFileWithPassphraseTo(Path plaintextFile, Path sealedFile) {
        try (KeyVault.DerivedKey derived = deriveDefault()) {
            cipher.sealToFile(derived.key(), KeySource.PASSPHRASE, aliasForPassphrase(), derived.salt(),
                    derived.iterations(), plaintextFile, sealedFile);
        }
    }

    public void openFile(Path sealedFile, Path plaintextFile) {
        Envelope envelope = cipher.readEnvelopeHeader(sealedFile);
        SecretKey key = resolveKey(envelope);
        try {
            cipher.openToFile(key, envelope, sealedFile, plaintextFile);
        } finally {
            KeyVault.zero(key);
        }
    }

    /**
     * Re-seals an in-memory payload under {@code newAlias}. Call this before deleting the old
     * key, otherwise the payload is unrecoverable.
     */
    public Envelope rekey(Envelope envelope, String newAlias) {
        try (Opened opened = open(envelope)) {
            return sealWithKeystoreKey(opened.data(), newAlias);
        }
    }

    /**
     * Re-seals a sealed file under {@code newAlias}, writing to {@code targetFile}. The source
     * is left untouched so an interrupted rotation loses nothing.
     */
    public void rekeyFile(Path sealedFile, Path targetFile, String newAlias) {
        Path staging = siblingWithSuffix(sealedFile, ".rekey.tmp");
        try {
            openFile(sealedFile, staging);
            SecretKey key = keyVault.key(newAlias);
            try {
                cipher.sealToFile(key, KeySource.KEYSTORE, newAlias, new byte[0], 0, staging, targetFile);
            } finally {
                KeyVault.zero(key);
            }
        } finally {
            try {
                java.nio.file.Files.deleteIfExists(staging);
            } catch (java.io.IOException ignored) {
                // best effort: the staging file holds authenticated plaintext only
            }
        }
    }

    /** Human-readable provenance for a payload, safe to log. */
    public String keyDescription(Envelope envelope) {
        if (envelope.keySource() == KeySource.PASSPHRASE) {
            return "passphrase-derived (" + KeyVault.PBKDF2_ALGORITHM + ", " + envelope.iterations()
                    + " iterations, salt " + envelope.salt().length + " bytes)";
        }
        return "keystore alias " + envelope.alias() + " in " + keyVault.storePath();
    }

    /** Creates the default alias if it is absent; returns true when it had to be created. */
    public boolean ensureDefaultKey() {
        if (defaultAlias == null || keyVault.contains(defaultAlias)) {
            return false;
        }
        keyVault.generate(defaultAlias);
        return true;
    }

    @Override
    public void close() {
        // Keys are resolved per operation and wiped immediately; nothing long-lived to clear.
    }

    private SecretKey resolveKey(Envelope envelope) {
        if (envelope.keySource() == KeySource.PASSPHRASE) {
            try (KeyVault.DerivedKey derived = derive(envelope)) {
                byte[] raw = derived.key().getEncoded();
                return new javax.crypto.spec.SecretKeySpec(raw, AesGcmCipher.KEY_ALGORITHM);
            }
        }
        return keyVault.key(envelope.alias());
    }

    private KeyVault.DerivedKey derive(Envelope envelope) {
        char[] passphrase = requirePassphrase();
        try {
            return KeyVault.deriveFromPassphrase(passphrase, envelope.salt(), envelope.iterations(), random);
        } finally {
            Arrays.fill(passphrase, '\0');
        }
    }

    private KeyVault.DerivedKey deriveDefault() {
        char[] passphrase = requirePassphrase();
        try {
            return KeyVault.deriveFromPassphrase(passphrase, null, 0, random);
        } finally {
            Arrays.fill(passphrase, '\0');
        }
    }

    private char[] requirePassphrase() {
        if (passphraseProvider == null) {
            throw new VaultException("payload was sealed with a passphrase-derived key but this vault has "
                    + "no passphrase provider");
        }
        char[] passphrase = passphraseProvider.passphrase();
        if (passphrase == null || passphrase.length == 0) {
            throw new VaultException("passphrase provider returned nothing");
        }
        return passphrase;
    }

    private String aliasForPassphrase() {
        return defaultAlias != null ? defaultAlias : "passphrase";
    }

    private static Path siblingWithSuffix(Path source, String suffix) {
        Path absolute = source.toAbsolutePath();
        return absolute.resolveSibling(absolute.getFileName() + suffix);
    }
}
