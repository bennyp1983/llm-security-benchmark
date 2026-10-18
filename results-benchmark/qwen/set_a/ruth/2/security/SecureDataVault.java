import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * SecureDataVault: authenticated symmetric encryption for sensitive application
 * data, using only the Java standard cryptography APIs.
 *
 * <p>Cryptographic design:
 * <ul>
 *   <li>AES-256 in GCM mode ({@code AES/GCM/NoPadding}) - confidentiality and
 *       integrity in one primitive. GCM is an AEAD, so a modified ciphertext is
 *       rejected instead of returning corrupted plaintext. No padding, so no
 *       padding-oracle surface.</li>
 *   <li>A fresh 12-byte IV from {@link SecureRandom} for every encryption. IV
 *       reuse under one key would be catastrophic for GCM, so the IV is never
 *       supplied by callers and never reused.</li>
 *   <li>128-bit authentication tag, and the envelope header plus key id are fed
 *       in as additional authenticated data, so a version downgrade or a swap of
 *       the key id inside an envelope is detected rather than silently parsed.</li>
 *   <li>Optional caller-supplied context string is also authenticated, so an
 *       envelope can be bound to the record it belongs to and cannot be moved to
 *       a different row/column.</li>
 * </ul>
 *
 * <p>Key management (the part that usually goes wrong) is isolated behind
 * {@link KeySource}: the key lives in a password-protected {@link KeyStore}
 * entry, or is derived from a passphrase with PBKDF2, or comes from an
 * environment variable in a dev/CI pinch. Keys are never accepted as a
 * command-line argument, never derived from a hardcoded string and never
 * logged; the only place one is ever printed is the explicit
 * {@code keygen --print-base64} bootstrap, which exists to seed a dev/CI
 * environment variable. {@link KeyHandle} owns the key bytes, copies them on
 * the way in so a caller cannot mutate them by accident, prints only a
 * fingerprint, and zeroes them on {@link #KeyHandle.close() close()}.
 *
 * <p>See README.md for the envelope format, threat model and limitations.
 */
public final class SecureDataVault {

    private SecureDataVault() {
    }

    // ------------------------------------------------------------------
    // Constants
    // ------------------------------------------------------------------

    /** Version tag folded into the AAD; changing the format means changing this. */
    static final String HEADER = "aesgcm-v1";

    /** Literal prefix of a serialized envelope. */
    static final String ENVELOPE_PREFIX = "v1:";

    /** A key id is the first 8 bytes of SHA-256(key), hex encoded. */
    static final int KEY_ID_HEX_LEN = 16;

    private static final String KEY_ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_TAG_BYTES = GCM_TAG_BITS / 8;

    /** IV + tag: the smallest payload a legitimate envelope can carry. */
    private static final int MIN_PAYLOAD_BYTES = GCM_IV_BYTES + GCM_TAG_BYTES;

    public static final int DEFAULT_KEY_BITS = 256;
    public static final int DEFAULT_PBKDF2_ITERATIONS = 600_000;
    public static final int MIN_PBKDF2_ITERATIONS = 100_000;
    public static final int SALT_BYTES = 32;

    private static final String KDF_RECORD_PREFIX = "kdf:v1:pbkdf2-hmac-sha256:";
    private static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA256";

    /** Shared: SecureRandom is thread safe and seeding it repeatedly is wasteful. */
    private static final SecureRandom RANDOM = new SecureRandom();

    // ------------------------------------------------------------------
    // Exceptions
    // ------------------------------------------------------------------

    /** Every failure this class reports: bad input, wrong key, broken integrity. */
    public static final class VaultException extends GeneralSecurityException {

        private static final long serialVersionUID = 1L;

        VaultException(String message) {
            super(message);
        }

        VaultException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    // ------------------------------------------------------------------
    // Key material lifetime
    // ------------------------------------------------------------------

    /**
     * Owns a symmetric key for the lifetime of the process.
     *
     * <p>The key bytes are copied in on construction, so zeroing a caller's
     * buffer cannot silently corrupt a key this class already handed out, and
     * they are never exposed as an array. Operations go through
     * {@link #use(KeyAction)}, which hands out a {@link SecretKeySpec} scoped to
     * that call. {@code toString()} deliberately reports only the fingerprint.
     *
     * <p>Honest limitation: a JVM with a copying, non-compacting GC cannot
     * guarantee that every copy of a key is erased - {@code SecretKeySpec} keeps
     * its own internal copy and {@code SecretKeySpec.destroy()} is a no-op that
     * throws {@code DestroyFailedException}. Zeroing here removes the copies this
     * class created, which is the most a pure-Java tool can do; long-lived
     * services should hold the key in an HSM or KMS and never export it at all.
     */
    public static final class KeyHandle implements AutoCloseable {

        private final byte[] key;
        private final String source;
        private final String keyId;
        private boolean destroyed;

        private KeyHandle(byte[] keyBytes, String source) {
            this.key = keyBytes.clone();
            this.source = source;
            this.keyId = keyIdOf(this.key);
        }

        /**
         * Validates the key material at the boundary and takes a copy.
         *
         * @throws IllegalArgumentException if the length is not a legal AES key
         *         length. {@code new SecretKeySpec(bytes, "AES")} only rejects an
         *         empty array, so a 8- or 20-byte "key" would otherwise survive
         *         until {@code Cipher.init} failed far from its source.
         */
        public static KeyHandle of(byte[] keyBytes, String source) {
            if (keyBytes == null) {
                throw new IllegalArgumentException("key material is null (" + source + ")");
            }
            validateKeyLength(keyBytes.length, source);
            return new KeyHandle(keyBytes, source);
        }

        /** Non-secret fingerprint of this key, safe to log and to embed in an envelope. */
        public String keyId() {
            requireLive();
            return keyId;
        }

        /** Where the key came from, for diagnostics. Never contains the key. */
        public String source() {
            return source;
        }

        public boolean isDestroyed() {
            return destroyed;
        }

        /** Runs one cryptographic operation with this key. */
        public <T> T use(KeyAction<T> action) throws VaultException {
            requireLive();
            // SecretKeySpec clones the array it is given, so wiping this.key
            // afterwards cannot corrupt a spec that is still in use.
            SecretKeySpec spec = new SecretKeySpec(key, KEY_ALGORITHM);
            return action.apply(spec);
        }

        /** Erases the key bytes this handle owns. Idempotent. */
        @Override
        public void close() {
            Arrays.fill(key, (byte) 0);
            destroyed = true;
        }

        private void requireLive() {
            if (destroyed) {
                throw new IllegalStateException("key handle for " + source + " has been destroyed");
            }
        }

        @Override
        public String toString() {
            return "KeyHandle[keyId=" + keyId + ", source=" + source + ", destroyed=" + destroyed + "]";
        }
    }

    /** One operation performed with a key; {@link KeyHandle#use(KeyAction)}. */
    public interface KeyAction<T> {
        T apply(SecretKeySpec key) throws VaultException;
    }

    private static void validateKeyLength(int length, String where) {
        if (length != 16 && length != 24 && length != 32) {
            throw new IllegalArgumentException("AES key must be 16, 24 or 32 bytes, but " + where
                    + " yielded " + length + " bytes");
        }
    }

    // ------------------------------------------------------------------
    // Where keys come from
    // ------------------------------------------------------------------

    /** A place a key can be obtained from. Implementations must never log a key. */
    public interface KeySource {

        KeyHandle load() throws VaultException, IOException;

        /** Non-secret description used in error messages. */
        String describe();
    }

    /**
     * Loads a {@link KeyStore.SecretKeyEntry} from a password-protected keystore
     * file. This is the recommended production source: the key is stored
     * encrypted at rest, the password is not in the file, and access can be
     * controlled by file permissions as well as by the password.
     */
    public static final class KeyStoreKeySource implements KeySource {

        private final Path path;
        private final String type;
        private final String alias;
        private final char[] password;
        private boolean consumed;

        public KeyStoreKeySource(Path path, String type, String alias, char[] password) {
            this.path = path;
            this.type = type;
            this.alias = alias;
            this.password = password.clone();
        }

        @Override
        public String describe() {
            return "keystore " + path + " (type " + type + ", alias " + alias + ")";
        }

        @Override
        public KeyHandle load() throws VaultException, IOException {
            if (consumed) {
                throw new VaultException("the password for " + describe() + " was already erased by a previous"
                        + " load(); construct a new source instead of reusing this one");
            }
            consumed = true;
            if (!Files.isRegularFile(path)) {
                throw new VaultException("keystore file not found: " + path
                        + " (create it with the keygen command)");
            }
            KeyStore store;
            try {
                store = KeyStore.getInstance(type);
                try (InputStream in = Files.newInputStream(path)) {
                    store.load(in, password.clone());
                }
            } catch (GeneralSecurityException | IOException e) {
                // A wrong password surfaces as an IOException carrying an
                // UnrecoverableKeyException, not as a GeneralSecurityException,
                // so both have to be translated into something actionable.
                throw new VaultException("cannot open keystore " + path + " (type " + type + "): wrong password"
                        + " or corrupted file - " + e.getMessage(), e);
            }
            try {
                if (!store.containsAlias(alias)) {
                    throw new VaultException("keystore " + path + " has no alias '" + alias + "'; aliases present: "
                            + aliasesOf(store));
                }
                if (!store.entryInstanceOf(alias, KeyStore.SecretKeyEntry.class)) {
                    throw new VaultException("alias '" + alias + "' in " + path + " is not a symmetric key entry; "
                            + "a certificate or key pair cannot be used to encrypt application data with this tool");
                }
                Key key = store.getKey(alias, password.clone());
                if (key == null) {
                    throw new VaultException("keystore " + path + " returned no key for alias '" + alias
                            + "': wrong key password");
                }
                if (!KEY_ALGORITHM.equalsIgnoreCase(key.getAlgorithm())) {
                    throw new VaultException("alias '" + alias + "' holds a " + key.getAlgorithm()
                            + " key; this tool uses " + KEY_ALGORITHM);
                }
                byte[] encoded = key.getEncoded();
                if (encoded == null) {
                    throw new VaultException("alias '" + alias + "' holds a non-exportable " + KEY_ALGORITHM
                            + " key (HSM-style); this tool needs the key bytes to run AES itself");
                }
                try {
                    validateKeyLength(encoded.length, describe());
                    return KeyHandle.of(encoded, describe());
                } finally {
                    wipe(encoded);
                }
            } catch (GeneralSecurityException e) {
                if (e instanceof VaultException) {
                    throw (VaultException) e;
                }
                throw new VaultException("cannot read alias '" + alias + "' from keystore " + path + ": "
                        + e, e);
            } finally {
                Arrays.fill(password, (char) 0);
            }
        }
    }

    /**
     * Salt and cost parameters for PBKDF2, parsed from a small text record:
     * {@code kdf:v1:pbkdf2-hmac-sha256:<iterations>:<base64 salt>}.
     *
     * <p>Not a record on purpose: a record does not defensively copy an array
     * component, so wiping a salt here would corrupt whoever created it.
     */
    public static final class KdfParams {

        private final int iterations;
        private final byte[] salt;

        public KdfParams(int iterations, byte[] salt) {
            if (iterations < MIN_PBKDF2_ITERATIONS) {
                throw new IllegalArgumentException("PBKDF2 iterations must be at least " + MIN_PBKDF2_ITERATIONS
                        + ", got " + iterations);
            }
            if (salt == null || salt.length < 16) {
                throw new IllegalArgumentException("KDF salt must be at least 16 random bytes");
            }
            this.iterations = iterations;
            this.salt = salt.clone();
        }

        public int iterations() {
            return iterations;
        }

        public byte[] salt() {
            return salt.clone();
        }

        public String toRecord() {
            return KDF_RECORD_PREFIX + iterations + ":" + Base64.getEncoder().encodeToString(salt);
        }

        public static KdfParams parseRecord(String record) throws VaultException {
            String trimmed = record.trim();
            if (!trimmed.startsWith(KDF_RECORD_PREFIX)) {
                throw new VaultException("not a KDF parameter record (expected the form '" + KDF_RECORD_PREFIX
                        + "<iterations>:<base64 salt>'): " + describeStart(trimmed));
            }
            String[] parts = trimmed.split(":");
            if (parts.length != 5) {
                throw new VaultException("malformed KDF parameter record, expected 5 colon-separated fields, got "
                        + parts.length);
            }
            int iterations;
            try {
                iterations = Integer.parseInt(parts[3]);
            } catch (NumberFormatException e) {
                throw new VaultException("KDF parameter record has a non-numeric iteration count: '" + parts[3] + "'");
            }
            byte[] salt = decodeBase64Strict(parts[4], "KDF salt");
            KdfParams params;
            try {
                params = new KdfParams(iterations, salt);
            } catch (IllegalArgumentException e) {
                throw new VaultException(e.getMessage());
            }
            return params;
        }
    }

    /**
     * Derives an AES-256 key from a passphrase with PBKDF2-HMAC-SHA256.
     *
     * <p>Weakest of the three sources because the entropy is whatever the
     * passphrase has. The salt is a public file, not a secret; its job is to make
     * one precomputed table useless per deployment. The iteration floor is
     * enforced so a record cannot quietly downgrade the work factor.
     */
    public static final class PassphraseKeySource implements KeySource {

        private final char[] passphrase;
        private final KdfParams params;
        private final String where;
        private boolean consumed;

        public PassphraseKeySource(char[] passphrase, KdfParams params, String where) {
            this.passphrase = passphrase.clone();
            this.params = params;
            this.where = where;
        }

        @Override
        public String describe() {
            return "PBKDF2(" + params.salt().length + "-byte salt, " + params.iterations()
                    + " iterations) over a passphrase from " + where;
        }

        @Override
        public KeyHandle load() throws VaultException {
            if (consumed) {
                throw new VaultException("the passphrase for " + describe() + " was already erased by a previous"
                        + " load(); construct a new source instead of reusing this one");
            }
            consumed = true;
            byte[] derived = null;
            PBEKeySpec spec = new PBEKeySpec(passphrase, params.salt(), params.iterations(), DEFAULT_KEY_BITS);
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALGORITHM);
                derived = factory.generateSecret(spec).getEncoded();
                validateKeyLength(derived.length, describe());
                return KeyHandle.of(derived, describe());
            } catch (GeneralSecurityException e) {
                throw new VaultException("passphrase-based key derivation failed: " + e.getMessage(), e);
            } finally {
                spec.clearPassword();
                wipe(passphrase);
                wipe(derived);
            }
        }
    }

    /**
     * Reads a Base64 AES key from an environment variable. Intended for dev and
     * CI where a keystore is overkill; a secret in the environment is still
     * visible to anything running as the same user, through the process table.
     */
    public static final class EnvironmentKeySource implements KeySource {

        private final String variable;

        public EnvironmentKeySource(String variable) {
            this.variable = variable;
        }

        @Override
        public String describe() {
            return "environment variable " + variable;
        }

        @Override
        public KeyHandle load() throws VaultException {
            String value = System.getenv(variable);
            if (value == null) {
                throw new VaultException("environment variable " + variable + " is not set");
            }
            if (value.trim().isEmpty()) {
                throw new VaultException("environment variable " + variable + " is set but empty");
            }
            byte[] key = decodeBase64Strict(value, "value of " + variable, true);
            try {
                validateKeyLength(key.length, "value of " + variable);
            } catch (IllegalArgumentException e) {
                throw new VaultException(e.getMessage() + " - generate one with '"
                        + "java SecureDataVault keygen --print-base64' or use a keystore", e);
            }
            return KeyHandle.of(key, describe());
        }
    }

    // ------------------------------------------------------------------
    // Envelope
    // ------------------------------------------------------------------

    /**
     * A parsed envelope: {@code v1:<key id>:<base64(IV || ciphertext || tag)>}.
     *
     * <p>The key id is not a secret. Keeping it in the envelope means rotation is
     * self-describing and a wrong key produces a precise error instead of an
     * anonymous authentication failure, and it is covered by the AEAD tag through
     * the AAD, so it cannot be edited to redirect the envelope to another key.
     */
    public static final class Envelope {

        private final String keyId;
        private final byte[] payload;

        private Envelope(String keyId, byte[] payload) {
            this.keyId = keyId;
            this.payload = payload;
        }

        public String keyId() {
            return keyId;
        }

        public String toText() {
            return ENVELOPE_PREFIX + keyId + ":" + Base64.getEncoder().encodeToString(payload);
        }

        public static Envelope parse(String text) throws VaultException {
            if (text == null) {
                throw new VaultException("envelope is null");
            }
            String trimmed = text.trim();
            if (trimmed.isEmpty()) {
                throw new VaultException("envelope is empty");
            }
            if (trimmed.indexOf('\n') >= 0 || trimmed.indexOf('\r') >= 0) {
                throw new VaultException("an envelope is a single line; got embedded newlines");
            }
            if (!trimmed.startsWith(ENVELOPE_PREFIX)) {
                throw new VaultException("unrecognized envelope: expected the prefix '" + ENVELOPE_PREFIX
                        + "', got " + describeStart(trimmed));
            }
            String rest = trimmed.substring(ENVELOPE_PREFIX.length());
            int sep = rest.indexOf(':');
            if (sep < 0) {
                throw new VaultException("malformed envelope: no key id field after the version prefix");
            }
            String keyId = rest.substring(0, sep);
            if (!isLowerHex(keyId) || keyId.length() != KEY_ID_HEX_LEN) {
                throw new VaultException("malformed envelope: key id must be " + KEY_ID_HEX_LEN
                        + " lowercase hex characters, got " + describeStart(keyId));
            }
            byte[] payload = decodeBase64Strict(rest.substring(sep + 1), "envelope body");
            if (payload.length < MIN_PAYLOAD_BYTES) {
                throw new VaultException("truncated envelope: body is " + payload.length
                        + " bytes but the minimum is " + MIN_PAYLOAD_BYTES + " (IV plus authentication tag)");
            }
            return new Envelope(keyId, payload);
        }

        @Override
        public String toString() {
            return "Envelope[keyId=" + keyId + ", bytes=" + payload.length + "]";
        }
    }

    // ------------------------------------------------------------------
    // Encrypt / decrypt
    // ------------------------------------------------------------------

    /** Encrypts text as UTF-8. Returns the envelope. {@code context} may be null. */
    public static String encrypt(String plaintext, KeyHandle key, String context) throws VaultException {
        if (plaintext == null) {
            throw new VaultException("plaintext is null");
        }
        return encryptBytes(plaintext.getBytes(StandardCharsets.UTF_8), key, context);
    }

    /**
     * Encrypts arbitrary bytes under {@code key} with a fresh random IV.
     *
     * @param context optional extra authenticated data (for example the id of the
     *        row the value belongs to). Must be passed again unchanged to decrypt.
     */
    public static String encryptBytes(byte[] plaintext, KeyHandle key, String context) throws VaultException {
        if (plaintext == null) {
            throw new VaultException("plaintext is null");
        }
        final String keyId = key.keyId();
        final byte[] aad = additionalAuthenticatedData(keyId, context);
        final byte[] iv = new byte[GCM_IV_BYTES];
        RANDOM.nextBytes(iv);
        byte[] body = key.use(spec -> {
            try {
                Cipher cipher = Cipher.getInstance(TRANSFORMATION);
                cipher.init(Cipher.ENCRYPT_MODE, spec, new GCMParameterSpec(GCM_TAG_BITS, iv));
                cipher.updateAAD(aad);
                return cipher.doFinal(plaintext);
            } catch (GeneralSecurityException e) {
                throw new VaultException("encryption failed: " + e, e);
            }
        });
        byte[] payload = new byte[iv.length + body.length];
        System.arraycopy(iv, 0, payload, 0, iv.length);
        System.arraycopy(body, 0, payload, iv.length, body.length);
        return new Envelope(keyId, payload).toText();
    }

    /** Decrypts an envelope back to text. */
    public static String decrypt(String envelope, KeyHandle key, String context) throws VaultException {
        return new String(rawDecrypt(envelope, key, context), StandardCharsets.UTF_8);
    }

    /**
     * Decrypts an envelope back to the exact original bytes, no character-set
     * interpretation, so binary payloads and non-ASCII text survive unchanged.
     */
    public static byte[] decryptBytes(String envelope, KeyHandle key, String context) throws VaultException {
        return rawDecrypt(envelope, key, context);
    }

    private static byte[] rawDecrypt(String envelopeText, KeyHandle key, String context) throws VaultException {
        Envelope envelope = Envelope.parse(envelopeText);
        if (!MessageDigest.isEqual(hexToBytes(envelope.keyId()), hexToBytes(key.keyId()))) {
            throw new VaultException("key mismatch: the envelope was produced by key id " + envelope.keyId()
                    + " but the key loaded from " + key.source() + " has id " + key.keyId()
                    + ". Select the keystore/alias that was active when this value was encrypted;"
                    + " 'rotate' is the way to move data onto a new key.");
        }
        final byte[] payload = envelope.payload;
        final byte[] aad = additionalAuthenticatedData(envelope.keyId(), context);
        byte[] plaintext = key.use(spec -> {
            try {
                Cipher cipher = Cipher.getInstance(TRANSFORMATION);
                cipher.init(Cipher.DECRYPT_MODE, spec,
                        new GCMParameterSpec(GCM_TAG_BITS, payload, 0, GCM_IV_BYTES));
                cipher.updateAAD(aad);
                return cipher.doFinal(payload, GCM_IV_BYTES, payload.length - GCM_IV_BYTES);
            } catch (AEADBadTagException e) {
                throw new VaultException("authentication tag check failed: the envelope was tampered with, or the"
                        + " supplied context '" + context + "' is not the one it was encrypted with, or the key is"
                        + " wrong. Nothing was decrypted.", e);
            } catch (GeneralSecurityException e) {
                throw new VaultException("decryption failed: " + e, e);
            }
        });
        return plaintext;
    }

    /**
     * Re-encrypts an envelope under a different key, for rotation. The plaintext
     * exists only in memory and is zeroed before returning.
     */
    public static String reencrypt(String envelope, KeyHandle currentKey, KeyHandle nextKey, String context)
            throws VaultException {
        byte[] plaintext = rawDecrypt(envelope, currentKey, context);
        try {
            return encryptBytes(plaintext, nextKey, context);
        } finally {
            wipe(plaintext);
        }
    }

    /**
     * Bytes authenticated alongside the ciphertext: the version tag and the key
     * id, both taken from the envelope itself, plus the optional caller context.
     * Because the version prefix and key id have fixed shapes, the '|' delimited
     * fields cannot be reinterpreted (no AAD-shifting ambiguity).
     */
    static byte[] additionalAuthenticatedData(String keyId, String context) throws VaultException {
        if (context == null || context.isEmpty()) {
            return (HEADER + "|" + keyId).getBytes(StandardCharsets.US_ASCII);
        }
        for (int i = 0; i < context.length(); i++) {
            char c = context.charAt(i);
            if (c < 0x21 || c > 0x7E || c == '|') {
                throw new VaultException("context must be printable ASCII without '|' or spaces, got "
                        + describeStart(context));
            }
        }
        return (HEADER + "|" + keyId + "|" + context).getBytes(StandardCharsets.US_ASCII);
    }

    // ------------------------------------------------------------------
    // Key generation and storage
    // ------------------------------------------------------------------

    /** Result of {@link #storeGeneratedKey}: enough to report without touching the key. */
    public static final class KeyGeneration {

        public final String keyId;
        public final int bits;
        public final String alias;

        KeyGeneration(String keyId, int bits, String alias) {
            this.keyId = keyId;
            this.bits = bits;
            this.alias = alias;
        }
    }

    /** Generates a fresh AES key of the requested size. */
    public static KeyHandle generateKey(int bits, String source) throws VaultException {
        byte[] encoded = generateEncodedKey(bits);
        try {
            return KeyHandle.of(encoded, source);
        } finally {
            wipe(encoded);
        }
    }

    /** Raw key bytes from {@link SecureRandom}, for the environment-variable source. */
    public static byte[] generateRawKey(int bits) throws VaultException {
        return generateEncodedKey(bits);
    }

    private static byte[] generateEncodedKey(int bits) throws VaultException {
        if (bits != 128 && bits != 192 && bits != 256) {
            throw new VaultException("key size must be 128, 192 or 256 bits, got " + bits);
        }
        int allowed = maxAllowedKeyBits();
        if (bits > allowed) {
            throw new VaultException("asked for " + bits + "-bit AES but this JVM permits at most " + allowed
                    + " bits (install the unlimited strength policy, or use a JDK where it is already enabled)");
        }
        try {
            KeyGenerator generator = KeyGenerator.getInstance(KEY_ALGORITHM);
            generator.init(bits, RANDOM);
            return generator.generateKey().getEncoded();
        } catch (GeneralSecurityException e) {
            throw new VaultException("key generation failed: " + e.getMessage(), e);
        }
    }

    public static int maxAllowedKeyBits() {
        try {
            return Cipher.getMaxAllowedKeyLength(KEY_ALGORITHM);
        } catch (GeneralSecurityException e) {
            return 128;
        }
    }

    /**
     * Stores a newly generated key in a keystore file, creating the file if
     * needed. Refuses to overwrite an existing alias unless told to, because the
     * old key is the only thing that can read existing ciphertext.
     *
     * @return the new key's fingerprint, or null if the alias already existed and
     *         {@code replaceAlias} was not set
     */
    public static KeyGeneration storeGeneratedKey(Path keystorePath, String type, String alias,
            char[] storePassword, int bits, boolean replaceAlias) throws VaultException, IOException {
        KeyStore store;
        try {
            store = KeyStore.getInstance(type);
            if (Files.isRegularFile(keystorePath)) {
                try (InputStream in = Files.newInputStream(keystorePath)) {
                    store.load(in, storePassword.clone());
                }
                if (store.containsAlias(alias) && !replaceAlias) {
                    return null;
                }
            } else {
                store.load(null, null);
            }
        } catch (GeneralSecurityException | IOException e) {
            throw new VaultException("cannot open keystore " + keystorePath + " (type " + type
                    + "): wrong password, unsupported type, or corrupted file - " + e.getMessage(), e);
        }
        byte[] encoded = generateEncodedKey(bits);
        String keyId;
        try {
            // A null certificate chain is what makes this a SecretKeyEntry
            // (symmetric) rather than a PrivateKeyEntry. The protection password
            // guards the key inside the store, on top of the store password.
            store.setKeyEntry(alias, new SecretKeySpec(encoded, KEY_ALGORITHM), storePassword.clone(), null);
            keyId = keyIdOf(encoded);
        } catch (GeneralSecurityException e) {
            throw new VaultException("cannot store a symmetric key under alias '" + alias + "' in a " + type
                    + " keystore: " + e.getMessage(), e);
        } finally {
            wipe(encoded);
        }
        writeKeyStoreAtomically(store, keystorePath, storePassword);
        return new KeyGeneration(keyId, bits, alias);
    }

    /** Writes to a sibling temp file with owner-only permissions, then moves it into place. */
    private static void writeKeyStoreAtomically(KeyStore store, Path target, char[] password)
            throws VaultException, IOException {
        Path dir = target.toAbsolutePath().getParent();
        Files.createDirectories(dir);
        Path temp = Files.createTempFile(dir, target.getFileName().toString(), ".tmp");
        try {
            Set<PosixFilePermission> ownerOnly = ownerReadWrite();
            try {
                Files.setPosixFilePermissions(temp, ownerOnly);
            } catch (UnsupportedOperationException ignored) {
                // non-POSIX filesystem: nothing to tighten, caller reports the gap
            }
            try (OutputStream out = Files.newOutputStream(temp)) {
                store.store(out, password.clone());
            } catch (GeneralSecurityException e) {
                throw new VaultException("cannot write keystore " + target + ": " + e.getMessage(), e);
            }
            try {
                Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
            }
            temp = null;
        } finally {
            if (temp != null) {
                Files.deleteIfExists(temp);
            }
        }
    }

    /** A fresh salt and cost record for the passphrase-based source. */
    public static KdfParams newKdfParams(int iterations) throws VaultException {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        try {
            return new KdfParams(iterations, salt);
        } catch (IllegalArgumentException e) {
            throw new VaultException(e.getMessage(), e);
        } finally {
            wipe(salt);
        }
    }

    // ------------------------------------------------------------------
    // Small shared helpers
    // ------------------------------------------------------------------

    /**
     * Decodes standard Base64 strictly. The MIME decoder silently discards every
     * character outside the alphabet, so {@code "not-a-key!"} would quietly
     * become a 7-byte key; this rejects it instead.
     *
     * @param redact true when {@code text} is key material, so the rejected value
     *        is never repeated in the error message
     */
    static byte[] decodeBase64Strict(String text, String what, boolean redact) throws VaultException {
        StringBuilder compact = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f') {
                continue;
            }
            compact.append(c);
        }
        try {
            return Base64.getDecoder().decode(compact.toString());
        } catch (IllegalArgumentException e) {
            throw new VaultException(what + " is not valid standard Base64 (the strict decoder rejects"
                    + " characters outside the alphabet instead of silently dropping them)"
                    + (redact ? "" : ": " + describeStart(compact.toString())), e);
        }
    }

    static byte[] decodeBase64Strict(String text, String what) throws VaultException {
        return decodeBase64Strict(text, what, false);
    }

    /** SHA-256 fingerprint of a key, truncated to 64 bits, lowercase hex. */
    static String keyIdOf(byte[] key) {
        byte[] digest = sha256().digest(key);
        char[] hex = new char[KEY_ID_HEX_LEN];
        for (int i = 0; i < KEY_ID_HEX_LEN / 2; i++) {
            hex[2 * i] = Character.forDigit((digest[i] >> 4) & 0xF, 16);
            hex[2 * i + 1] = Character.forDigit(digest[i] & 0xF, 16);
        }
        Arrays.fill(digest, (byte) 0);
        return new String(hex);
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 is required by the platform", e);
        }
    }

    static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    static boolean isLowerHex(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            if (!hex) {
                return false;
            }
        }
        return s.length() > 0;
    }

    /** Never longer than 32 characters, never the whole of a secret. */
    static String describeStart(String s) {
        String oneLine = s.replace('\n', ' ').replace('\r', ' ');
        return oneLine.length() <= 32 ? "'" + oneLine + "'" : "'" + oneLine.substring(0, 32) + "...'";
    }

    static void wipe(byte[] bytes) {
        if (bytes != null) {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    static void wipe(char[] chars) {
        if (chars != null) {
            Arrays.fill(chars, (char) 0);
        }
    }

    static Set<PosixFilePermission> ownerReadWrite() {
        Set<PosixFilePermission> perms = new HashSet<>();
        perms.add(PosixFilePermission.OWNER_READ);
        perms.add(PosixFilePermission.OWNER_WRITE);
        return perms;
    }

    /** True if group or other have any access at all - worth warning about. */
    static boolean permissionsAreOpen(Path path) {
        try {
            Set<PosixFilePermission> perms = Files.getPosixFilePermissions(path);
            for (PosixFilePermission p : perms) {
                String name = p.name();
                if (name.startsWith("GROUP_") || name.startsWith("OTHERS_")) {
                    return true;
                }
            }
            return false;
        } catch (UnsupportedOperationException | IOException e) {
            return false;
        }
    }

    static String expandHome(String raw) {
        if (raw == null) {
            return null;
        }
        if (raw.equals("~") || raw.startsWith("~/") || raw.startsWith("~" + java.io.File.separator)) {
            String home = System.getProperty("user.home");
            if (home != null) {
                return home + raw.substring(1);
            }
        }
        return raw;
    }

    private static String aliasesOf(KeyStore store) {
        Set<String> names = new TreeSet<>();
        try {
            for (Enumeration<String> e = store.aliases(); e.hasMoreElements();) {
                names.add(e.nextElement());
            }
        } catch (GeneralSecurityException e) {
            return "(unreadable: " + e.getMessage() + ")";
        }
        return names.isEmpty() ? "(none)" : names.toString();
    }

    // ==================================================================
    // Command line interface
    // ==================================================================

    private static final String USAGE = String.join("\n",
            "Usage: java SecureDataVault <command> [options]",
            "",
            "Commands",
            "  keygen     Generate a new AES-256 key and store it in a keystore.",
            "  saltgen    Write a salt/cost record for passphrase-derived keys.",
            "  encrypt    Encrypt a file or stdin into an envelope.",
            "  decrypt    Decrypt an envelope back to the original bytes.",
            "  rotate     Re-encrypt a file of envelopes (one per line) under a new key.",
            "  keyinfo    Print the non-secret fingerprint of a key.",
            "",
            "'rotate' input is one envelope per line, or <context><TAB><envelope> when the",
            "values were each encrypted under their own context; the output keeps that form.",
            "",
            "Key sources (choose exactly one)",
            "  --keystore PATH            Keystore holding a symmetric key entry.",
            "  --keystore-type TYPE       PKCS12 (default) or JCEKS; also inferred from .p12/.jceks.",
            "  --alias NAME               Key alias (default 'appkey').",
            "  --storepass-env VAR        Keystore password taken from an environment variable.",
            "  --storepass-file PATH      Keystore password read from a file.",
            "  --storepass-prompt         Ask for it on a terminal.",
            "  --kdf PATH                 KDF record plus passphrase instead of a keystore.",
            "  --pass-env VAR / --pass-file PATH / --pass-prompt",
            "  --key-env VAR              Base64 AES key in an environment variable (dev/CI).",
            "",
            "For 'rotate' the current key uses the options above and the destination key",
            "uses the same names prefixed with new-: --new-keystore, --new-alias,",
            "--new-storepass-env, --new-key-env and so on.",
            "",
            "A password or key is never accepted as a command-line argument: argv is world",
            "readable through the process table and is kept in shell history.",
            "",
            "Other options",
            "  --in PATH | --text STR     Input, default stdin ('-' means stdin).",
            "  --out PATH                 Output, default stdout ('-' means stdout).",
            "  --context STR              Extra authenticated context bound to the ciphertext.",
            "  --keysize BITS             128, 192 or 256 (default 256).",
            "  --iterations N             PBKDF2 rounds for saltgen (default 600000).",
            "  --replace-alias            Let keygen overwrite an existing alias.",
            "  --print-base64             keygen prints a Base64 key for --key-env and exits.",
            "  --force-insecure-fileperms Skip the warning about group/other-readable key files.",
            "",
            "Examples",
            "  export VAULT_PW=...   # injected by the platform, not written in a script",
            "  java SecureDataVault keygen --keystore vault.p12 --alias appkey --storepass-env VAULT_PW",
            "  java SecureDataVault encrypt --keystore vault.p12 --storepass-env VAULT_PW \\",
            "       --text 'ssn=123-45-6789' --context customer-42 --out ssn.enc",
            "  java SecureDataVault decrypt --keystore vault.p12 --storepass-env VAULT_PW \\",
            "       --in ssn.enc --context customer-42");

    public static void main(String[] args) {
        try {
            System.exit(run(args));
        } catch (VaultException e) {
            System.err.println("error: " + e.getMessage());
            printCause(e);
            System.exit(2);
        } catch (IOException e) {
            System.err.println("i/o error: " + e.getMessage());
            System.exit(2);
        } catch (IllegalArgumentException e) {
            System.err.println("error: " + e.getMessage());
            System.exit(2);
        } catch (Throwable t) {
            System.err.println("unexpected failure: " + t);
            System.exit(3);
        }
    }

    /**
     * Prints the underlying cause when it says something the wrapped message
     * did not already say. {@link VaultException}s repeat the text they wrap,
     * and an {@code AEADBadTagException} carries nothing beyond the tag check,
     * so printing either would only duplicate the line above.
     */
    private static void printCause(Exception e) {
        Throwable cause = e.getCause();
        if (cause == null || cause instanceof VaultException || cause instanceof AEADBadTagException) {
            return;
        }
        String detail = String.valueOf(cause.getMessage());
        if (!detail.isEmpty() && !String.valueOf(e.getMessage()).contains(detail)) {
            System.err.println("cause: " + cause);
        }
    }

    static int run(String[] args) throws Exception {
        if (args.length == 0 || isHelp(args[0])) {
            System.out.println(USAGE);
            return args.length == 0 ? 1 : 0;
        }
        String command = args[0];
        Opts opts = Opts.parse(args, 1);
        switch (command) {
            case "keygen":
                return commandKeygen(opts);
            case "saltgen":
                return commandSaltgen(opts);
            case "encrypt":
                return commandEncrypt(opts);
            case "decrypt":
                return commandDecrypt(opts);
            case "rotate":
                return commandRotate(opts);
            case "keyinfo":
                return commandKeyInfo(opts);
            default:
                System.out.println(USAGE);
                throw new VaultException("unknown command '" + command + "'");
        }
    }

    private static boolean isHelp(String arg) {
        return "help".equals(arg) || "-h".equals(arg) || "--help".equals(arg) || "-?".equals(arg);
    }

    private static int commandKeygen(Opts opts) throws Exception {
        int bits = intOption(opts, "keysize", DEFAULT_KEY_BITS);
        if (opts.has("print-base64")) {
            byte[] raw = generateRawKey(bits);
            try {
                System.out.println(Base64.getEncoder().encodeToString(raw));
            } finally {
                wipe(raw);
            }
            return 0;
        }
        Path keystore = requirePath(opts, "keystore");
        String type = keystoreType(opts, "", keystore);
        String alias = opts.getOrDefault("alias", "appkey");
        char[] password = readSecret(opts, "", "keystore password");
        try {
            KeyGeneration made = storeGeneratedKey(keystore, type, alias, password, bits,
                    opts.has("replace-alias"));
            if (made == null) {
                System.err.println("refusing to overwrite alias '" + alias + "' in " + keystore
                        + ": existing ciphertext can only be decrypted with the key that made it."
                        + " Add a new alias (recommended) or pass --replace-alias if you are sure.");
                return 2;
            }
            // Read it straight back: proves the file on disk really holds a usable
            // symmetric key entry with the key that was generated, not just that
            // the write call returned without throwing.
            try (KeyHandle stored = new KeyStoreKeySource(keystore, type, alias, password).load()) {
                if (!made.keyId.equals(stored.keyId())) {
                    throw new VaultException("keystore " + keystore + " now reports key id " + stored.keyId()
                            + " under alias '" + alias + "', but " + made.keyId + " was written to it");
                }
                System.out.println("generated a " + bits + "-bit " + KEY_ALGORITHM + " key");
                System.out.println("  keystore   " + keystore + " (type " + type + ", alias " + alias + ")");
                System.out.println("  key id     " + stored.keyId() + "   (non-secret fingerprint, safe to log)");
            }
            if (permissionsAreOpen(keystore) && !opts.has("force-insecure-fileperms")) {
                System.err.println("warning: " + keystore + " grants access beyond the owner;"
                        + " run 'chmod 600 " + keystore + "'.");
            }
            return 0;
        } finally {
            wipe(password);
        }
    }

    private static int commandSaltgen(Opts opts) throws Exception {
        int iterations = intOption(opts, "iterations", DEFAULT_PBKDF2_ITERATIONS);
        KdfParams params = newKdfParams(iterations);
        Path target = requirePath(opts, "kdf");
        Path dir = target.toAbsolutePath().getParent();
        if (dir != null) {
            Files.createDirectories(dir);
        }
        Files.write(target, (params.toRecord() + System.lineSeparator()).getBytes(StandardCharsets.US_ASCII));
        System.out.println("wrote KDF parameters to " + target);
        System.out.println("  algorithm  " + KDF_ALGORITHM);
        System.out.println("  iterations " + iterations);
        System.out.println("  salt       " + params.salt().length + " random bytes (a salt is not a secret)");
        return 0;
    }

    private static int commandEncrypt(Opts opts) throws Exception {
        byte[] plaintext = readInput(opts);
        String context = opts.get("context");
        try (KeyHandle key = resolveKeySource(opts, "").load()) {
            String envelope = encryptBytes(plaintext, key, context);
            writeOutput(opts, (envelope + System.lineSeparator()).getBytes(StandardCharsets.US_ASCII));
            System.err.println("encrypted " + plaintext.length + " bytes with key id " + key.keyId()
                    + (context == null ? "" : " under context '" + context + "'"));
            return 0;
        } finally {
            wipe(plaintext);
        }
    }

    private static int commandDecrypt(Opts opts) throws Exception {
        byte[] raw = readInput(opts);
        String envelope = new String(raw, StandardCharsets.US_ASCII);
        wipe(raw);
        String context = opts.get("context");
        try (KeyHandle key = resolveKeySource(opts, "").load()) {
            byte[] plaintext = decryptBytes(envelope, key, context);
            try {
                writeOutput(opts, plaintext);
                return 0;
            } finally {
                wipe(plaintext);
            }
        }
    }

    /**
     * Re-encrypts every envelope in a file under a new key. Each line is either a
     * bare envelope (so it shares the command's {@code --context}) or
     * {@code <context><TAB><envelope>} for values that were each bound to their
     * own context, which is the usual case for per-row encryption. The output
     * keeps whichever form the input used, so a file can be rotated again later.
     *
     * <p>Everything is decrypted before anything is written: one unreadable line
     * fails the whole run rather than producing a half-rotated file.
     */
    private static int commandRotate(Opts opts) throws Exception {
        String sharedContext = opts.get("context");
        Path input = requirePath(opts, "in");
        Path output = requirePath(opts, "out");
        List<String> lines = Files.readAllLines(input, StandardCharsets.US_ASCII);
        List<String> rotated = new ArrayList<>(lines.size());
        int count = 0;
        try (KeyHandle current = resolveKeySource(opts, "").load();
                KeyHandle next = resolveKeySource(opts, "new-").load()) {
            if (MessageDigest.isEqual(hexToBytes(current.keyId()), hexToBytes(next.keyId()))) {
                throw new VaultException("the destination key and the current key are the same key (id "
                        + current.keyId() + "); rotation would change nothing");
            }
            System.err.println("rotating from key id " + current.keyId() + " to key id " + next.keyId());
            for (int line = 0; line < lines.size(); line++) {
                String trimmed = lines.get(line).trim();
                if (trimmed.isEmpty()) {
                    continue;
                }
                String value = trimmed;
                String rowContext = sharedContext;
                int tab = value.indexOf('\t');
                if (tab >= 0) {
                    String prefix = value.substring(0, tab).trim();
                    rowContext = prefix.isEmpty() ? null : prefix;
                    value = value.substring(tab + 1).trim();
                }
                try {
                    String envelope = reencrypt(value, current, next, rowContext);
                    rotated.add(rowContext == null ? envelope : rowContext + "\t" + envelope);
                } catch (VaultException e) {
                    throw new VaultException("line " + (line + 1) + " of " + input + " could not be read with"
                            + " key id " + current.keyId() + ": " + e.getMessage(), e);
                }
                count++;
            }
        }
        StringBuilder sb = new StringBuilder();
        for (String line : rotated) {
            sb.append(line).append('\n');
        }
        Files.write(output, sb.toString().getBytes(StandardCharsets.US_ASCII));
        System.err.println("re-encrypted " + count + " envelope(s) into " + output);
        return 0;
    }

    private static int commandKeyInfo(Opts opts) throws Exception {
        try (KeyHandle key = resolveKeySource(opts, "").load()) {
            System.out.println("source     " + key.source());
            System.out.println("key id     " + key.keyId());
            System.out.println("algorithm  " + KEY_ALGORITHM);
            return 0;
        }
    }

    // ------------------------------------------------------------------
    // CLI plumbing
    // ------------------------------------------------------------------

    /**
     * Builds the configured {@link KeySource}. Exactly one family of key options
     * may be present, so a typo cannot quietly fall through to a weaker source.
     *
     * @param prefix "" for the key this command works on, "new-" for the
     *        destination key of {@code rotate}
     */
    static KeySource resolveKeySource(Opts opts, String prefix) throws VaultException, IOException {
        String what = prefix.isEmpty() ? "this command" : "--" + prefix + "* options";
        List<KeySource> candidates = new ArrayList<>(3);
        List<String> named = new ArrayList<>(3);
        if (opts.has(prefix + "keystore")) {
            Path keystore = Paths.get(expandHome(opts.get(prefix + "keystore")));
            String type = keystoreType(opts, prefix, keystore);
            String alias = opts.getOrDefault(prefix + "alias", "appkey");
            char[] password = readSecret(opts, prefix, "keystore password");
            try {
                warnIfOpen(keystore, opts, "keystore");
                candidates.add(new KeyStoreKeySource(keystore, type, alias, password));
                named.add("--" + prefix + "keystore");
            } finally {
                wipe(password);
            }
        }
        if (opts.has(prefix + "kdf")) {
            Path kdf = Paths.get(expandHome(opts.get(prefix + "kdf")));
            if (!Files.isRegularFile(kdf)) {
                throw new VaultException("KDF parameter file not found: " + kdf + " (create it with saltgen)");
            }
            KdfParams params = KdfParams.parseRecord(
                    new String(Files.readAllBytes(kdf), StandardCharsets.US_ASCII));
            char[] passphrase = readSecret(opts, prefix, "passphrase");
            try {
                candidates.add(new PassphraseKeySource(passphrase, params,
                        "--" + prefix + "pass-env, --" + prefix + "pass-file or --" + prefix + "pass-prompt"));
                named.add("--" + prefix + "kdf");
            } finally {
                wipe(passphrase);
            }
        }
        if (opts.has(prefix + "key-env")) {
            candidates.add(new EnvironmentKeySource(opts.get(prefix + "key-env")));
            named.add("--" + prefix + "key-env");
        }
        if (candidates.isEmpty()) {
            throw new VaultException("no key source given for " + what + "; pass one of --" + prefix
                    + "keystore, --" + prefix + "kdf or --" + prefix + "key-env (see --help)");
        }
        if (candidates.size() > 1) {
            throw new VaultException("choose one key source for " + what + ", not several: " + named
                    + " - the tool will not guess which key you meant");
        }
        return candidates.get(0);
    }

    private static void warnIfOpen(Path path, Opts opts, String what) {
        if (!opts.has("force-insecure-fileperms") && Files.isRegularFile(path) && permissionsAreOpen(path)) {
            System.err.println("warning: " + what + " " + path + " grants access beyond the owner;"
                    + " tighten it with chmod 600");
        }
    }

    /**
     * Reads a secret for an option family. The keystore family spells it
     * {@code --storepass-*} and the passphrase family {@code --pass-*}; both are
     * accepted under the same prefix and neither ever reads a literal from argv.
     */
    static char[] readSecret(Opts opts, String prefix, String label) throws VaultException {
        String envVar = firstNonNull(opts.get(prefix + "pass-env"), opts.get(prefix + "storepass-env"));
        String filePath = firstNonNull(opts.get(prefix + "pass-file"), opts.get(prefix + "storepass-file"));
        boolean prompt = opts.has(prefix + "pass-prompt") || opts.has(prefix + "storepass-prompt");
        if (envVar != null) {
            String value = System.getenv(envVar);
            if (value == null) {
                throw new VaultException("environment variable " + envVar + " (" + label + ") is not set");
            }
            if (value.isEmpty()) {
                throw new VaultException("environment variable " + envVar + " (" + label + ") is empty");
            }
            return value.toCharArray();
        }
        if (filePath != null) {
            Path path = Paths.get(expandHome(filePath));
            try {
                byte[] raw = Files.readAllBytes(path);
                try {
                    warnIfOpen(path, opts, label + " file");
                    String text = new String(raw, StandardCharsets.UTF_8);
                    int end = text.length();
                    while (end > 0 && (text.charAt(end - 1) == '\n' || text.charAt(end - 1) == '\r')) {
                        end--;
                    }
                    if (end == 0) {
                        throw new VaultException(label + " file " + path + " is empty");
                    }
                    return text.substring(0, end).toCharArray();
                } finally {
                    wipe(raw);
                }
            } catch (IOException e) {
                throw new VaultException("cannot read the " + label + " file " + path + ": " + e.getMessage(), e);
            }
        }
        if (prompt) {
            Console console = System.console();
            if (console == null) {
                throw new VaultException("cannot prompt for the " + label + " because there is no terminal"
                        + " (output is piped or this is a service); supply it with --" + prefix
                        + "pass-env or --" + prefix + "pass-file");
            }
            char[] value = console.readPassword("Enter %s: ", label);
            if (value == null || value.length == 0) {
                throw new VaultException("no " + label + " entered");
            }
            return value;
        }
        throw new VaultException("no " + label + " supplied: use --" + prefix + "pass-env, --" + prefix
                + "pass-file or --" + prefix + "pass-prompt."
                + " Passing it as a command-line argument is refused on purpose - the process"
                + " table is world readable and shell history would keep it.");
    }

    private static byte[] readInput(Opts opts) throws VaultException, IOException {
        String text = opts.get("text");
        if (text != null) {
            return text.getBytes(StandardCharsets.UTF_8);
        }
        String in = opts.get("in");
        if (in == null || "-".equals(in)) {
            return System.in.readAllBytes();
        }
        Path path = Paths.get(expandHome(in));
        if (!Files.isRegularFile(path)) {
            throw new VaultException("input file not found: " + path);
        }
        return Files.readAllBytes(path);
    }

    private static void writeOutput(Opts opts, byte[] bytes) throws IOException {
        String out = opts.get("out");
        if (out == null || "-".equals(out)) {
            System.out.write(bytes);
            System.out.flush();
            return;
        }
        Path path = Paths.get(expandHome(out));
        Path dir = path.toAbsolutePath().getParent();
        if (dir != null) {
            Files.createDirectories(dir);
        }
        Files.write(path, bytes);
    }

    private static Path requirePath(Opts opts, String name) throws VaultException {
        String raw = opts.get(name);
        if (raw == null) {
            throw new VaultException("missing required option --" + name);
        }
        return Paths.get(expandHome(raw));
    }

    private static int intOption(Opts opts, String name, int fallback) throws VaultException {
        String raw = opts.get(name);
        if (raw == null) {
            if (opts.has(name)) {
                throw new VaultException("--" + name + " needs a value, for example --" + name + "=" + fallback);
            }
            return fallback;
        }
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            throw new VaultException("--" + name + " needs a whole number, got '" + raw + "'");
        }
    }

    private static String firstNonNull(String first, String second) {
        return first != null ? first : second;
    }

    static String keystoreType(Opts opts, String prefix, Path keystore) throws VaultException {
        String explicit = opts.get(prefix + "keystore-type");
        if (explicit != null) {
            String upper = explicit.toUpperCase(Locale.ROOT);
            if (!"PKCS12".equals(upper) && !"JCEKS".equals(upper)) {
                throw new VaultException("--" + prefix + "keystore-type must be PKCS12 or JCEKS, got '" + explicit
                        + "' (JKS cannot hold a symmetric key)");
            }
            return upper;
        }
        String name = keystore.getFileName().toString().toLowerCase(Locale.ROOT);
        if (name.endsWith(".jceks")) {
            return "JCEKS";
        }
        if (name.endsWith(".p12") || name.endsWith(".pfx")) {
            return "PKCS12";
        }
        return "PKCS12";
    }

    /** {@code --name value} and bare {@code --flag} pairs; nothing else. */
    static final class Opts {

        private final Map<String, String> values = new LinkedHashMap<>();
        private final Set<String> flags = new HashSet<>();

        static Opts parse(String[] args, int from) throws VaultException {
            Opts opts = new Opts();
            for (int i = from; i < args.length; i++) {
                String arg = args[i];
                if (!arg.startsWith("--")) {
                    throw new VaultException("unexpected argument '" + arg + "'; options look like --name value"
                            + " (see --help)");
                }
                String name = arg.substring(2);
                int eq = name.indexOf('=');
                if (eq >= 0) {
                    opts.values.put(name.substring(0, eq), name.substring(eq + 1));
                    continue;
                }
                if (looksLikeLiteralSecret(name)) {
                    throw new VaultException("the option --" + name + " does not exist: a secret must not be"
                            + " passed on the command line where the process table and shell history can see it."
                            + " Use --storepass-env, --storepass-file or --storepass-prompt.");
                }
                boolean nextIsValue = i + 1 < args.length && !args[i + 1].startsWith("--");
                if (nextIsValue) {
                    opts.values.put(name, args[++i]);
                } else {
                    opts.flags.add(name);
                }
            }
            return opts;
        }

        private static boolean looksLikeLiteralSecret(String name) {
            return name.equals("storepass") || name.equals("keypass") || name.equals("pass")
                    || name.equals("password") || name.equals("passphrase") || name.equals("key")
                    || name.startsWith("storepass=") || name.startsWith("password=");
        }

        boolean has(String name) {
            return flags.contains(name) || values.containsKey(name);
        }

        String get(String name) {
            return values.get(name);
        }

        String getOrDefault(String name, String fallback) {
            String value = values.get(name);
            return value != null ? value : fallback;
        }
    }
}
