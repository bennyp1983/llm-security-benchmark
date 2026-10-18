import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Enterprise-grade Symmetric Encryption and Cryptographic Key Management System.
 *
 * Cryptographic Design:
 * - Cipher Algorithm: AES (Advanced Encryption Standard)
 * - Mode of Operation: GCM (Galois/Counter Mode) - Authenticated Encryption with Associated Data (AEAD)
 * - Padding: NoPadding (GCM is a stream/counter mode; no padding oracle vulnerabilities)
 * - Key Length: 256 bits (AES-256)
 * - Initialization Vector (IV / Nonce): 96 bits (12 bytes) uniquely generated via SecureRandom (NIST SP 800-38D)
 * - Authentication Tag Length: 128 bits (16 bytes)
 * - Key Derivation Function: PBKDF2WithHmacSHA256 (310,000 iterations, 128-bit random salt per OWASP)
 * - Key Storage: Standard PKCS#12 KeyStore with password-based encryption and strict POSIX 0600 file permissions
 * - Key Lifecycle Management: Versioned aliases, seamless key rotation, metadata packaging, memory zeroization
 */
public class SymmetricEncryption {

    // Cryptographic Configuration Constants
    public static final String CIPHER_ALGORITHM = "AES";
    public static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    public static final String KEYSTORE_TYPE = "PKCS12";
    public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";

    public static final int AES_KEY_SIZE_BITS = 256;         // 256-bit AES
    public static final int GCM_IV_LENGTH_BYTES = 12;        // 96-bit IV (12 bytes) recommended for AES-GCM
    public static final int GCM_TAG_LENGTH_BITS = 128;       // 128-bit authentication tag
    public static final int PBKDF2_ITERATIONS = 310_000;     // NIST/OWASP compliant PBKDF2 iterations
    public static final int SALT_LENGTH_BYTES = 16;          // 128-bit salt
    public static final byte PAYLOAD_VERSION_1 = 0x01;       // Version identifier for serialized payload

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // =========================================================================
    // 1. KEY GENERATION & DERIVATION (Obtaining Cryptographic Keys)
    // =========================================================================

    /**
     * Generates a cryptographically secure random AES key of the specified bit size.
     *
     * @param keyBitSize Key size in bits (128, 192, or 256)
     * @return Generated SecretKey
     * @throws NoSuchAlgorithmException if AES is not supported by the security provider
     */
    public static SecretKey generateKey(int keyBitSize) throws NoSuchAlgorithmException {
        if (keyBitSize != 128 && keyBitSize != 192 && keyBitSize != 256) {
            throw new IllegalArgumentException("Invalid AES key size: " + keyBitSize + ". Must be 128, 192, or 256.");
        }
        KeyGenerator keyGenerator = KeyGenerator.getInstance(CIPHER_ALGORITHM);
        keyGenerator.init(keyBitSize, SECURE_RANDOM);
        return keyGenerator.generateKey();
    }

    /**
     * Generates a standard 256-bit AES symmetric key using SecureRandom.
     *
     * @return 256-bit SecretKey
     * @throws NoSuchAlgorithmException if AES is not supported
     */
    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        return generateKey(AES_KEY_SIZE_BITS);
    }

    /**
     * Derives a 256-bit AES key from a passphrase and salt using PBKDF2-HMAC-SHA256.
     * Wipes intermediate key byte arrays immediately after constructing SecretKey.
     *
     * @param passphrase Passphrase character array (caller is responsible for wiping)
     * @param salt       Cryptographically secure random salt (minimum 16 bytes)
     * @param iterations PBKDF2 iteration count (minimum 100,000; recommended >= 310,000)
     * @param keyBitSize Output key size in bits (typically 256)
     * @return Derived SecretKey
     * @throws GeneralSecurityException if key derivation fails
     */
    public static SecretKey deriveKeyFromPassphrase(char[] passphrase, byte[] salt, int iterations, int keyBitSize)
            throws GeneralSecurityException {
        if (passphrase == null || passphrase.length == 0) {
            throw new IllegalArgumentException("Passphrase cannot be null or empty.");
        }
        if (salt == null || salt.length < 16) {
            throw new IllegalArgumentException("Salt must be at least 16 bytes.");
        }
        if (iterations < 100_000) {
            throw new IllegalArgumentException("PBKDF2 iteration count must be at least 100,000 for security.");
        }

        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        KeySpec spec = new PBEKeySpec(passphrase, salt, iterations, keyBitSize);
        byte[] encodedKey = null;
        try {
            encodedKey = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(encodedKey, CIPHER_ALGORITHM);
        } finally {
            if (encodedKey != null) {
                Arrays.fill(encodedKey, (byte) 0);
            }
        }
    }

    /**
     * Derives a 256-bit AES key using default PBKDF2 parameters (310,000 iterations).
     *
     * @param passphrase Passphrase character array
     * @param salt       16-byte cryptographically secure salt
     * @return Derived SecretKey
     * @throws GeneralSecurityException if key derivation fails
     */
    public static SecretKey deriveKeyFromPassphrase(char[] passphrase, byte[] salt) throws GeneralSecurityException {
        return deriveKeyFromPassphrase(passphrase, salt, PBKDF2_ITERATIONS, AES_KEY_SIZE_BITS);
    }

    /**
     * Generates cryptographically secure random bytes.
     *
     * @param length Number of random bytes
     * @return Fresh random byte array
     */
    public static byte[] generateRandomBytes(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("Length must be positive.");
        }
        byte[] bytes = new byte[length];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }

    // =========================================================================
    // 2. CORE SYMMETRIC ENCRYPTION & DECRYPTION (AES-GCM Authenticated Cipher)
    // =========================================================================

    /**
     * Encrypts plaintext bytes using AES-GCM with optional Associated Authenticated Data (AAD).
     *
     * Output format: [12-byte IV] + [Ciphertext with 16-byte GCM Authentication Tag]
     *
     * @param plaintext      Plaintext byte array to encrypt
     * @param key            AES SecretKey
     * @param associatedData Optional Associated Authenticated Data (can be null or empty)
     * @return Combined byte array containing IV followed by Ciphertext and Tag
     * @throws GeneralSecurityException on encryption failure
     */
    public static byte[] encrypt(byte[] plaintext, SecretKey key, byte[] associatedData) throws GeneralSecurityException {
        Objects.requireNonNull(plaintext, "Plaintext cannot be null.");
        Objects.requireNonNull(key, "Encryption key cannot be null.");

        // Generate a fresh, cryptographically secure 96-bit (12-byte) IV for EVERY encryption
        byte[] iv = generateRandomBytes(GCM_IV_LENGTH_BYTES);

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }

        byte[] ciphertextWithTag = cipher.doFinal(plaintext);

        // Prepend IV to ciphertext
        ByteBuffer buffer = ByteBuffer.allocate(iv.length + ciphertextWithTag.length);
        buffer.put(iv);
        buffer.put(ciphertextWithTag);
        return buffer.array();
    }

    /**
     * Encrypts plaintext bytes using AES-GCM without associated authenticated data.
     *
     * @param plaintext Plaintext bytes
     * @param key       AES SecretKey
     * @return Combined byte array of [IV + Ciphertext + Tag]
     * @throws GeneralSecurityException on encryption failure
     */
    public static byte[] encrypt(byte[] plaintext, SecretKey key) throws GeneralSecurityException {
        return encrypt(plaintext, key, null);
    }

    /**
     * Encrypts a UTF-8 plaintext string and returns a Base64-encoded representation.
     *
     * @param plaintext Plaintext string
     * @param key       AES SecretKey
     * @return Base64 encoded string of [IV + Ciphertext + Tag]
     * @throws GeneralSecurityException on encryption failure
     */
    public static String encrypt(String plaintext, SecretKey key) throws GeneralSecurityException {
        Objects.requireNonNull(plaintext, "Plaintext cannot be null.");
        byte[] encrypted = encrypt(plaintext.getBytes(StandardCharsets.UTF_8), key, null);
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * Encrypts a UTF-8 plaintext string with Associated Authenticated Data (AAD) and returns Base64.
     *
     * @param plaintext      Plaintext string
     * @param key            AES SecretKey
     * @param associatedData Associated Authenticated Data
     * @return Base64 encoded string of [IV + Ciphertext + Tag]
     * @throws GeneralSecurityException on encryption failure
     */
    public static String encrypt(String plaintext, SecretKey key, byte[] associatedData) throws GeneralSecurityException {
        Objects.requireNonNull(plaintext, "Plaintext cannot be null.");
        byte[] encrypted = encrypt(plaintext.getBytes(StandardCharsets.UTF_8), key, associatedData);
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * Decrypts an encrypted byte array containing [12-byte IV + Ciphertext + Tag] using AES-GCM.
     *
     * @param encryptedData  Combined byte array containing IV and Ciphertext with Tag
     * @param key            AES SecretKey used for decryption
     * @param associatedData Optional Associated Authenticated Data (must match encryption AAD)
     * @return Decrypted plaintext bytes
     * @throws AEADBadTagException      if authentication tag verification fails (tampering/wrong key/wrong AAD)
     * @throws GeneralSecurityException on decryption failure
     */
    public static byte[] decrypt(byte[] encryptedData, SecretKey key, byte[] associatedData) throws GeneralSecurityException {
        Objects.requireNonNull(encryptedData, "Encrypted data cannot be null.");
        Objects.requireNonNull(key, "Decryption key cannot be null.");

        int minLength = GCM_IV_LENGTH_BYTES + (GCM_TAG_LENGTH_BITS / Byte.SIZE);
        if (encryptedData.length < minLength) {
            throw new IllegalArgumentException(
                    "Encrypted data is too short: " + encryptedData.length + " bytes (minimum: " + minLength + " bytes)."
            );
        }

        ByteBuffer buffer = ByteBuffer.wrap(encryptedData);
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        buffer.get(iv);

        byte[] ciphertextWithTag = new byte[buffer.remaining()];
        buffer.get(ciphertextWithTag);

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }

        return cipher.doFinal(ciphertextWithTag);
    }

    /**
     * Decrypts an encrypted byte array containing [12-byte IV + Ciphertext + Tag] without associated data.
     *
     * @param encryptedData Combined byte array
     * @param key           AES SecretKey
     * @return Decrypted plaintext bytes
     * @throws GeneralSecurityException on decryption failure
     */
    public static byte[] decrypt(byte[] encryptedData, SecretKey key) throws GeneralSecurityException {
        return decrypt(encryptedData, key, null);
    }

    /**
     * Decrypts a Base64-encoded ciphertext string back to UTF-8 plaintext string.
     *
     * @param base64Ciphertext Base64 encoded ciphertext string
     * @param key              AES SecretKey
     * @return Original plaintext string
     * @throws GeneralSecurityException on decryption failure
     */
    public static String decrypt(String base64Ciphertext, SecretKey key) throws GeneralSecurityException {
        return decrypt(base64Ciphertext, key, null);
    }

    /**
     * Decrypts a Base64-encoded ciphertext string with Associated Authenticated Data.
     *
     * @param base64Ciphertext Base64 encoded ciphertext string
     * @param key              AES SecretKey
     * @param associatedData   Associated Authenticated Data
     * @return Original plaintext string
     * @throws GeneralSecurityException on decryption failure
     */
    public static String decrypt(String base64Ciphertext, SecretKey key, byte[] associatedData) throws GeneralSecurityException {
        Objects.requireNonNull(base64Ciphertext, "Base64 ciphertext cannot be null.");
        byte[] decoded = Base64.getDecoder().decode(base64Ciphertext);
        byte[] plaintextBytes = decrypt(decoded, key, associatedData);
        return new String(plaintextBytes, StandardCharsets.UTF_8);
    }

    // =========================================================================
    // 3. KEY MANAGEMENT & KEYSTORE (Storing and Managing Cryptographic Keys)
    // =========================================================================

    /**
     * Encapsulates self-describing encrypted payload containing key metadata.
     * Enables zero-downtime key rotation: the decryptor reads the key alias from the payload,
     * fetches the appropriate key from KeyStore, and decrypts seamlessly.
     *
     * Wire Format:
     * [1 byte: Version (0x01)]
     * [1 byte: Key Alias Length (N)]
     * [N bytes: Key Alias UTF-8 bytes]
     * [1 byte: IV Length (12)]
     * [12 bytes: IV]
     * [Remaining bytes: Ciphertext + 16-byte GCM Tag]
     */
    public static class EncryptedEnvelope {
        private final byte version;
        private final String keyAlias;
        private final byte[] iv;
        private final byte[] ciphertextWithTag;

        public EncryptedEnvelope(String keyAlias, byte[] iv, byte[] ciphertextWithTag) {
            this(PAYLOAD_VERSION_1, keyAlias, iv, ciphertextWithTag);
        }

        public EncryptedEnvelope(byte version, String keyAlias, byte[] iv, byte[] ciphertextWithTag) {
            this.version = version;
            this.keyAlias = Objects.requireNonNull(keyAlias, "Key alias cannot be null.");
            this.iv = Objects.requireNonNull(iv, "IV cannot be null.");
            this.ciphertextWithTag = Objects.requireNonNull(ciphertextWithTag, "Ciphertext cannot be null.");
        }

        public byte getVersion() {
            return version;
        }

        public String getKeyAlias() {
            return keyAlias;
        }

        public byte[] getIv() {
            return iv.clone();
        }

        public byte[] getCiphertextWithTag() {
            return ciphertextWithTag.clone();
        }

        public byte[] toByteArray() {
            byte[] aliasBytes = keyAlias.getBytes(StandardCharsets.UTF_8);
            if (aliasBytes.length > 255) {
                throw new IllegalArgumentException("Key alias length exceeds 255 bytes limit.");
            }
            if (iv.length > 255) {
                throw new IllegalArgumentException("IV length exceeds 255 bytes limit.");
            }

            ByteBuffer buffer = ByteBuffer.allocate(1 + 1 + aliasBytes.length + 1 + iv.length + ciphertextWithTag.length);
            buffer.put(version);
            buffer.put((byte) aliasBytes.length);
            buffer.put(aliasBytes);
            buffer.put((byte) iv.length);
            buffer.put(iv);
            buffer.put(ciphertextWithTag);
            return buffer.array();
        }

        public static EncryptedEnvelope fromByteArray(byte[] bytes) {
            Objects.requireNonNull(bytes, "Bytes cannot be null.");
            int minSize = 1 + 1 + 1 + 1 + GCM_IV_LENGTH_BYTES + (GCM_TAG_LENGTH_BITS / Byte.SIZE);
            if (bytes.length < minSize) {
                throw new IllegalArgumentException("Envelope payload is too small: " + bytes.length + " bytes.");
            }

            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            byte ver = buffer.get();
            if (ver != PAYLOAD_VERSION_1) {
                throw new IllegalArgumentException("Unsupported envelope version: " + ver);
            }

            int aliasLen = Byte.toUnsignedInt(buffer.get());
            if (buffer.remaining() < aliasLen) {
                throw new IllegalArgumentException("Malformed payload: truncated key alias.");
            }
            byte[] aliasBytes = new byte[aliasLen];
            buffer.get(aliasBytes);
            String alias = new String(aliasBytes, StandardCharsets.UTF_8);

            int ivLen = Byte.toUnsignedInt(buffer.get());
            if (buffer.remaining() < ivLen) {
                throw new IllegalArgumentException("Malformed payload: truncated IV.");
            }
            byte[] iv = new byte[ivLen];
            buffer.get(iv);

            byte[] cipherBytes = new byte[buffer.remaining()];
            buffer.get(cipherBytes);

            return new EncryptedEnvelope(ver, alias, iv, cipherBytes);
        }

        public String toBase64() {
            return Base64.getEncoder().encodeToString(toByteArray());
        }

        public static EncryptedEnvelope fromBase64(String base64) {
            Objects.requireNonNull(base64, "Base64 string cannot be null.");
            return fromByteArray(Base64.getDecoder().decode(base64));
        }
    }

    /**
     * Production-ready KeyStore Manager using PKCS#12 format.
     * Provides key generation, secure storage, access control, rotation, and file permission enforcement.
     */
    public static class KeyManager implements AutoCloseable {
        private final KeyStore keyStore;
        private final Path keyStorePath;
        private char[] masterPassword;

        private KeyManager(KeyStore keyStore, Path keyStorePath, char[] masterPassword) {
            this.keyStore = keyStore;
            this.keyStorePath = keyStorePath;
            this.masterPassword = masterPassword != null ? masterPassword.clone() : null;
        }

        /**
         * Creates a new PKCS#12 KeyStore file protected with the given master password.
         * Enforces strict POSIX file permissions (0600: read/write owner only).
         *
         * @param keyStorePath   File path for the new KeyStore
         * @param masterPassword Master password for keystore encryption
         * @return Initialized KeyManager instance
         * @throws GeneralSecurityException if KeyStore initialization fails
         * @throws IOException              if file operations fail
         */
        public static KeyManager createKeyStore(Path keyStorePath, char[] masterPassword)
                throws GeneralSecurityException, IOException {
            Objects.requireNonNull(keyStorePath, "KeyStore path cannot be null.");
            Objects.requireNonNull(masterPassword, "Master password cannot be null.");

            KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
            ks.load(null, null); // Initialize empty keystore

            // Create parent directory if needed
            Path parent = keyStorePath.getParent();
            if (parent != null && !Files.exists(parent)) {
                Files.createDirectories(parent);
            }

            // Write keystore to disk
            try (OutputStream fos = Files.newOutputStream(keyStorePath)) {
                ks.store(fos, masterPassword);
            }

            // Apply strict POSIX file permissions (0600: owner read/write only)
            setStrictFilePermissions(keyStorePath);

            return new KeyManager(ks, keyStorePath, masterPassword);
        }

        /**
         * Loads an existing PKCS#12 KeyStore file.
         *
         * @param keyStorePath   Path to existing KeyStore file
         * @param masterPassword Master password
         * @return KeyManager instance
         * @throws GeneralSecurityException if loading fails (e.g. wrong password)
         * @throws IOException              if file reading fails
         */
        public static KeyManager loadKeyStore(Path keyStorePath, char[] masterPassword)
                throws GeneralSecurityException, IOException {
            Objects.requireNonNull(keyStorePath, "KeyStore path cannot be null.");
            Objects.requireNonNull(masterPassword, "Master password cannot be null.");

            if (!Files.exists(keyStorePath)) {
                throw new IOException("KeyStore file does not exist at: " + keyStorePath.toAbsolutePath());
            }

            KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
            try (InputStream fis = Files.newInputStream(keyStorePath)) {
                ks.load(fis, masterPassword);
            }

            return new KeyManager(ks, keyStorePath, masterPassword);
        }

        /**
         * Opens an existing KeyStore or creates a new one if it does not yet exist.
         */
        public static KeyManager openOrCreate(Path keyStorePath, char[] masterPassword)
                throws GeneralSecurityException, IOException {
            if (Files.exists(keyStorePath)) {
                return loadKeyStore(keyStorePath, masterPassword);
            } else {
                return createKeyStore(keyStorePath, masterPassword);
            }
        }

        /**
         * Generates a new 256-bit AES symmetric key and stores it in the KeyStore under the specified alias.
         * Persists the updated KeyStore to disk.
         *
         * @param alias       Key alias identifier
         * @param keyPassword Password protecting the key entry
         * @return The newly generated and stored SecretKey
         * @throws GeneralSecurityException on cryptographic error
         * @throws IOException              on persistence error
         */
        public synchronized SecretKey generateAndStoreKey(String alias, char[] keyPassword)
                throws GeneralSecurityException, IOException {
            Objects.requireNonNull(alias, "Alias cannot be null.");
            Objects.requireNonNull(keyPassword, "Key password cannot be null.");

            SecretKey newKey = SymmetricEncryption.generateKey(AES_KEY_SIZE_BITS);
            storeKey(alias, newKey, keyPassword);
            return newKey;
        }

        /**
         * Generates and stores a new AES key using the KeyStore's master password.
         */
        public synchronized SecretKey generateAndStoreKey(String alias)
                throws GeneralSecurityException, IOException {
            return generateAndStoreKey(alias, masterPassword);
        }

        /**
         * Stores an existing SecretKey in the KeyStore under the specified alias.
         */
        public synchronized void storeKey(String alias, SecretKey key, char[] keyPassword)
                throws GeneralSecurityException, IOException {
            Objects.requireNonNull(alias, "Alias cannot be null.");
            Objects.requireNonNull(key, "Key cannot be null.");
            Objects.requireNonNull(keyPassword, "Key password cannot be null.");

            KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(key);
            KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(keyPassword);
            keyStore.setEntry(alias, entry, protection);
            saveKeyStore();
        }

        /**
         * Retrieves a SecretKey from the KeyStore by alias.
         *
         * @param alias       Key alias identifier
         * @param keyPassword Password protecting the key entry
         * @return SecretKey instance
         * @throws KeyStoreException         if alias does not exist or entry is invalid
         * @throws UnrecoverableKeyException if key password is incorrect
         */
        public synchronized SecretKey getKey(String alias, char[] keyPassword) throws GeneralSecurityException {
            Objects.requireNonNull(alias, "Alias cannot be null.");
            Objects.requireNonNull(keyPassword, "Key password cannot be null.");

            if (!keyStore.containsAlias(alias)) {
                throw new KeyStoreException("Key alias not found in KeyStore: " + alias);
            }

            KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(keyPassword);
            KeyStore.Entry entry = keyStore.getEntry(alias, protection);

            if (!(entry instanceof KeyStore.SecretKeyEntry secretEntry)) {
                throw new KeyStoreException("Entry under alias '" + alias + "' is not a SecretKeyEntry.");
            }

            return secretEntry.getSecretKey();
        }

        /**
         * Retrieves a SecretKey using the master password.
         */
        public synchronized SecretKey getKey(String alias) throws GeneralSecurityException {
            return getKey(alias, masterPassword);
        }

        /**
         * Performs key rotation: generates a new key under newAlias, keeping oldAlias intact
         * so historical data can still be decrypted.
         *
         * @param newAlias    Alias for the newly generated active key
         * @param keyPassword Password for the new key
         * @return The newly generated SecretKey
         */
        public synchronized SecretKey rotateKey(String newAlias, char[] keyPassword)
                throws GeneralSecurityException, IOException {
            Objects.requireNonNull(newAlias, "New alias cannot be null.");
            if (keyStore.containsAlias(newAlias)) {
                throw new IllegalArgumentException("Alias already exists: " + newAlias);
            }
            return generateAndStoreKey(newAlias, keyPassword);
        }

        /**
         * Checks if an alias exists in the KeyStore.
         */
        public synchronized boolean containsAlias(String alias) throws KeyStoreException {
            return keyStore.containsAlias(alias);
        }

        /**
         * Lists all aliases currently registered in the KeyStore.
         */
        public synchronized List<String> listAliases() throws KeyStoreException {
            Enumeration<String> aliases = keyStore.aliases();
            List<String> list = new ArrayList<>();
            while (aliases.hasMoreElements()) {
                list.add(aliases.nextElement());
            }
            Collections.sort(list);
            return list;
        }

        /**
         * Deletes a key from the KeyStore and persists changes to disk.
         */
        public synchronized void deleteKey(String alias) throws GeneralSecurityException, IOException {
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias);
                saveKeyStore();
            }
        }

        /**
         * Persists the KeyStore to disk and enforces file permissions.
         */
        private synchronized void saveKeyStore() throws GeneralSecurityException, IOException {
            try (OutputStream fos = Files.newOutputStream(keyStorePath)) {
                keyStore.store(fos, masterPassword);
            }
            setStrictFilePermissions(keyStorePath);
        }

        /**
         * Enforces strict file permissions (POSIX 0600: rw-------) on the keystore file.
         */
        private static void setStrictFilePermissions(Path path) {
            try {
                Set<PosixFilePermission> permissions = PosixFilePermissions.fromString("rw-------");
                Files.setPosixFilePermissions(path, permissions);
            } catch (UnsupportedOperationException e) {
                // Fallback for non-POSIX environments (e.g. Windows)
                File file = path.toFile();
                file.setReadable(false, false);
                file.setReadable(true, true);
                file.setWritable(false, false);
                file.setWritable(true, true);
                file.setExecutable(false, false);
            } catch (IOException ignored) {
                // Best effort if underlying filesystem attributes restrict modifications
            }
        }

        /**
         * Securely cleanses in-memory master password when KeyManager is closed.
         */
        @Override
        public synchronized void close() {
            if (masterPassword != null) {
                Arrays.fill(masterPassword, '\0');
                masterPassword = null;
            }
        }
    }

    // =========================================================================
    // 4. KEYSTORE-INTEGRATED ENCRYPTION / DECRYPTION (Managed Symmetric Crypto)
    // =========================================================================

    /**
     * Encrypts plaintext bytes using a key stored in the KeyManager and returns a self-describing
     * EncryptedEnvelope containing key alias metadata.
     *
     * @param plaintext      Plaintext bytes
     * @param keyManager     KeyManager instance
     * @param keyAlias       Key alias to use for encryption
     * @param associatedData Optional Associated Authenticated Data
     * @return EncryptedEnvelope containing metadata, IV, and ciphertext+tag
     */
    public static EncryptedEnvelope encryptWithKeyManager(
            byte[] plaintext,
            KeyManager keyManager,
            String keyAlias,
            byte[] associatedData) throws GeneralSecurityException {
        Objects.requireNonNull(plaintext, "Plaintext cannot be null.");
        Objects.requireNonNull(keyManager, "KeyManager cannot be null.");
        Objects.requireNonNull(keyAlias, "Key alias cannot be null.");

        SecretKey key = keyManager.getKey(keyAlias);
        byte[] iv = generateRandomBytes(GCM_IV_LENGTH_BYTES);

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }

        byte[] ciphertextWithTag = cipher.doFinal(plaintext);
        return new EncryptedEnvelope(keyAlias, iv, ciphertextWithTag);
    }

    /**
     * Encrypts a plaintext string using a key from KeyManager and returns a Base64 self-describing string.
     */
    public static String encryptWithKeyManager(
            String plaintext,
            KeyManager keyManager,
            String keyAlias,
            byte[] associatedData) throws GeneralSecurityException {
        Objects.requireNonNull(plaintext, "Plaintext cannot be null.");
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        EncryptedEnvelope envelope = encryptWithKeyManager(plaintextBytes, keyManager, keyAlias, associatedData);
        return envelope.toBase64();
    }

    /**
     * Encrypts a plaintext string using KeyManager without associated data.
     */
    public static String encryptWithKeyManager(
            String plaintext,
            KeyManager keyManager,
            String keyAlias) throws GeneralSecurityException {
        return encryptWithKeyManager(plaintext, keyManager, keyAlias, null);
    }

    /**
     * Decrypts an EncryptedEnvelope by reading its key alias, dynamically fetching the corresponding key
     * from KeyManager, and deciphering the ciphertext.
     *
     * @param envelope       Self-describing encrypted envelope
     * @param keyManager     KeyManager containing the required key
     * @param associatedData Optional Associated Authenticated Data (must match encryption AAD)
     * @return Decrypted plaintext bytes
     * @throws GeneralSecurityException if decryption or authentication tag verification fails
     */
    public static byte[] decryptWithKeyManager(
            EncryptedEnvelope envelope,
            KeyManager keyManager,
            byte[] associatedData) throws GeneralSecurityException {
        Objects.requireNonNull(envelope, "Envelope cannot be null.");
        Objects.requireNonNull(keyManager, "KeyManager cannot be null.");

        SecretKey key = keyManager.getKey(envelope.getKeyAlias());

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, envelope.getIv());
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }

        return cipher.doFinal(envelope.getCiphertextWithTag());
    }

    /**
     * Decrypts a Base64-encoded self-describing ciphertext string using KeyManager.
     */
    public static String decryptWithKeyManager(
            String base64Envelope,
            KeyManager keyManager,
            byte[] associatedData) throws GeneralSecurityException {
        Objects.requireNonNull(base64Envelope, "Base64 envelope cannot be null.");
        EncryptedEnvelope envelope = EncryptedEnvelope.fromBase64(base64Envelope);
        byte[] plaintextBytes = decryptWithKeyManager(envelope, keyManager, associatedData);
        return new String(plaintextBytes, StandardCharsets.UTF_8);
    }

    /**
     * Decrypts a Base64-encoded self-describing ciphertext string using KeyManager without associated data.
     */
    public static String decryptWithKeyManager(
            String base64Envelope,
            KeyManager keyManager) throws GeneralSecurityException {
        return decryptWithKeyManager(base64Envelope, keyManager, null);
    }

    // =========================================================================
    // 5. SECURE MEMORY SANITATION
    // =========================================================================

    /**
     * Overwrites a character array (e.g. password) with null characters to eliminate
     * sensitive data from memory.
     *
     * @param chars Character array to wipe
     */
    public static void wipe(char[] chars) {
        if (chars != null) {
            Arrays.fill(chars, '\0');
        }
    }

    /**
     * Overwrites a byte array (e.g. raw key bytes or salt) with zeros.
     *
     * @param bytes Byte array to wipe
     */
    public static void wipe(byte[] bytes) {
        if (bytes != null) {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    // =========================================================================
    // 6. DEMONSTRATION & COMMAND-LINE INTERFACE
    // =========================================================================

    /**
     * Runs an in-depth security and cryptographic demonstration covering:
     * 1. Cryptographic Key Generation & Inspection
     * 2. KeyStore Lifecycle & Strict Permission Enforcement (PKCS#12, 0600)
     * 3. AES-256-GCM Sensitive Data Encryption & Decryption
     * 4. Context Binding via Associated Authenticated Data (AAD)
     * 5. Tamper Resistance & AEAD Authentication Tag Verification
     * 6. Zero-Downtime Cryptographic Key Rotation
     * 7. Password-Based Key Derivation (PBKDF2-HMAC-SHA256)
     * 8. Secure In-Memory Secret Zeroization
     */
    public static void runDemonstration() {
        Path tempKeystorePath = null;
        try {
            System.out.println("===============================================================================");
            System.out.println("    JAVA SECURE SYMMETRIC ENCRYPTION & KEY MANAGEMENT DEMONSTRATION (AES-GCM)   ");
            System.out.println("===============================================================================\n");

            // Define Master Password
            char[] masterPassword = "MasterApplicationVaultKey!2026".toCharArray();

            // -----------------------------------------------------------------
            // STEP 1: KEY ACQUISITION & GENERATION
            // -----------------------------------------------------------------
            System.out.println("[Step 1] Key Acquisition: Generating AES-256 Symmetric Key...");
            SecretKey ephemeralKey = generateKey(AES_KEY_SIZE_BITS);
            System.out.println(" -> Algorithm: " + ephemeralKey.getAlgorithm());
            System.out.println(" -> Format: " + ephemeralKey.getFormat());
            System.out.println(" -> Key Size: " + (ephemeralKey.getEncoded().length * 8) + " bits");
            System.out.println(" -> Generated using: SecureRandom (Cryptographically Secure PRNG)\n");

            // -----------------------------------------------------------------
            // STEP 2: KEY STORAGE (PKCS#12 KeyStore with POSIX 0600 permissions)
            // -----------------------------------------------------------------
            tempKeystorePath = Files.createTempFile("app_vault_", ".p12");
            Files.deleteIfExists(tempKeystorePath); // createKeyStore will write fresh
            System.out.println("[Step 2] Key Storage: Initializing Encrypted PKCS#12 KeyStore...");
            System.out.println(" -> KeyStore File: " + tempKeystorePath.toAbsolutePath());

            KeyManager keyManager = KeyManager.createKeyStore(tempKeystorePath, masterPassword);
            System.out.println(" -> Initialized empty PKCS#12 KeyStore.");

            // Store initial key (version 1)
            String aliasV1 = "data-encryption-key-v1";
            System.out.println(" -> Generating and storing AES-256 key under alias '" + aliasV1 + "'...");
            keyManager.generateAndStoreKey(aliasV1);
            System.out.println(" -> Key saved and encrypted in KeyStore with master password protection.");
            System.out.println(" -> Enforced POSIX file permissions: rw------- (0600 owner-only)\n");

            // -----------------------------------------------------------------
            // STEP 3: PERSISTENCE & KEY RETRIEVAL
            // -----------------------------------------------------------------
            System.out.println("[Step 3] Key Retrieval: Loading KeyStore from Disk...");
            // Close old manager and reload from disk to simulate application restart
            keyManager.close();
            keyManager = KeyManager.loadKeyStore(tempKeystorePath, masterPassword);
            SecretKey retrievedV1Key = keyManager.getKey(aliasV1);
            System.out.println(" -> Successfully reloaded KeyStore and retrieved key: " + aliasV1);
            System.out.println(" -> Registered aliases in store: " + keyManager.listAliases() + "\n");

            // -----------------------------------------------------------------
            // STEP 4: ENCRYPTING SENSITIVE APPLICATION DATA
            // -----------------------------------------------------------------
            String sensitivePayload = "{\"customerId\": 98765, \"ssn\": \"000-12-3456\", \"accountBalance\": 152500.50, \"card\": \"4111-2222-3333-4444\"}";
            System.out.println("[Step 4] Plaintext Sensitive Data to Encrypt:");
            System.out.println("-------------------------------------------------------------------------------");
            System.out.println(sensitivePayload);
            System.out.println("-------------------------------------------------------------------------------");

            // Encrypt using KeyStore-managed key
            System.out.println("\nEncrypting with AES-256-GCM using alias '" + aliasV1 + "'...");
            String base64Encrypted = encryptWithKeyManager(sensitivePayload, keyManager, aliasV1);
            System.out.println("Ciphertext Envelope (Base64):");
            System.out.println(base64Encrypted);

            // Inspect envelope contents
            EncryptedEnvelope envelope = EncryptedEnvelope.fromBase64(base64Encrypted);
            System.out.println(" -> Envelope Metadata:");
            System.out.println("    - Format Version: " + envelope.getVersion());
            System.out.println("    - Target Key Alias: " + envelope.getKeyAlias());
            System.out.println("    - IV Length: " + envelope.getIv().length + " bytes (96-bit nonce)");
            System.out.println("    - Ciphertext + Tag Length: " + envelope.getCiphertextWithTag().length + " bytes\n");

            // -----------------------------------------------------------------
            // STEP 5: DECRYPTING CIPHERTEXT BACK TO ORIGINAL DATA
            // -----------------------------------------------------------------
            System.out.println("[Step 5] Decrypting Ciphertext back to Plaintext...");
            String decryptedData = decryptWithKeyManager(base64Encrypted, keyManager);
            System.out.println("Decrypted Data Output:");
            System.out.println("-------------------------------------------------------------------------------");
            System.out.println(decryptedData);
            System.out.println("-------------------------------------------------------------------------------");
            boolean matches = sensitivePayload.equals(decryptedData);
            System.out.println("Data Authenticity & Integrity Verified: " + matches + "\n");

            // -----------------------------------------------------------------
            // STEP 6: ASSOCIATED AUTHENTICATED DATA (AAD) CONTEXT BINDING
            // -----------------------------------------------------------------
            System.out.println("[Step 6] Associated Authenticated Data (AAD) Context Binding...");
            byte[] recordContext = "tenantId:enterprise-corp-01;entity:customer-record".getBytes(StandardCharsets.UTF_8);
            System.out.println(" -> Binding context AAD: \"" + new String(recordContext, StandardCharsets.UTF_8) + "\"");

            String encryptedWithAad = encryptWithKeyManager(sensitivePayload, keyManager, aliasV1, recordContext);
            String decryptedWithAad = decryptWithKeyManager(encryptedWithAad, keyManager, recordContext);
            System.out.println(" -> Decrypted with valid AAD: " + sensitivePayload.equals(decryptedWithAad));

            // Attempt decryption with mismatched AAD
            byte[] forgedContext = "tenantId:malicious-tenant;entity:customer-record".getBytes(StandardCharsets.UTF_8);
            try {
                System.out.println(" -> Attempting decryption with forged AAD context...");
                decryptWithKeyManager(encryptedWithAad, keyManager, forgedContext);
                System.err.println(" -> ERROR: Decryption succeeded with forged AAD! (Insecure)");
            } catch (AEADBadTagException e) {
                System.out.println(" -> SUCCESS: Tampering detected! Decryption rejected with AEADBadTagException.");
                System.out.println("    Details: " + e.getMessage() + "\n");
            }

            // -----------------------------------------------------------------
            // STEP 7: TAMPER RESISTANCE & BIT-FLIP INTEGRITY TEST
            // -----------------------------------------------------------------
            System.out.println("[Step 7] Tamper Resistance Test (Corrupting Ciphertext)...");
            byte[] tamperedBytes = Base64.getDecoder().decode(base64Encrypted);
            // Flip one bit in the ciphertext / tag region
            tamperedBytes[tamperedBytes.length - 1] ^= 0x01;
            String tamperedBase64 = Base64.getEncoder().encodeToString(tamperedBytes);

            try {
                System.out.println(" -> Attempting to decrypt tampered ciphertext...");
                decryptWithKeyManager(tamperedBase64, keyManager);
                System.err.println(" -> ERROR: Corrupted ciphertext was accepted! (Insecure)");
            } catch (AEADBadTagException e) {
                System.out.println(" -> SUCCESS: AEAD authentication tag failed verification!");
                System.out.println("    Caught expected: " + e.getClass().getName() + "\n");
            }

            // -----------------------------------------------------------------
            // STEP 8: CRYPTOGRAPHIC KEY ROTATION
            // -----------------------------------------------------------------
            System.out.println("[Step 8] Key Management: Zero-Downtime Key Rotation...");
            String aliasV2 = "data-encryption-key-v2";
            System.out.println(" -> Rotating key: generating new active key alias '" + aliasV2 + "'...");
            keyManager.rotateKey(aliasV2, masterPassword);
            System.out.println(" -> KeyStore now contains keys: " + keyManager.listAliases());

            // Encrypt new data using v2 key
            String newRecord = "{\"customerId\": 98766, \"status\": \"ACTIVE\", \"action\": \"CREDIT_ISSUANCE\"}";
            String ciphertextV2 = encryptWithKeyManager(newRecord, keyManager, aliasV2);
            System.out.println(" -> Encrypted new record with active key '" + aliasV2 + "'.");

            // Decrypt BOTH records using the same KeyManager
            System.out.println(" -> Decrypting historical record (encrypted with " + aliasV1 + "):");
            String historicalDecrypted = decryptWithKeyManager(base64Encrypted, keyManager);
            System.out.println("    Historical Decryption: " + historicalDecrypted);

            System.out.println(" -> Decrypting modern record (encrypted with " + aliasV2 + "):");
            String modernDecrypted = decryptWithKeyManager(ciphertextV2, keyManager);
            System.out.println("    Modern Decryption:     " + modernDecrypted);
            System.out.println(" -> Key Rotation Verification: Both generations decrypted successfully without downtime.\n");

            // -----------------------------------------------------------------
            // STEP 9: PASSWORD-DERIVED KEY GENERATION (PBKDF2)
            // -----------------------------------------------------------------
            System.out.println("[Step 9] Key Derivation: PBKDF2-HMAC-SHA256 (Password-Based Encryption)...");
            char[] userPassphrase = "UserSuperStrongMasterPassphrase!2026#".toCharArray();
            byte[] salt = generateRandomBytes(SALT_LENGTH_BYTES);

            System.out.println(" -> Deriving 256-bit AES key using " + PBKDF2_ITERATIONS + " iterations and 128-bit salt...");
            SecretKey pbeKey = deriveKeyFromPassphrase(userPassphrase, salt);
            System.out.println(" -> Derived SecretKey successfully.");

            String pbePlaintext = "Confidential User Vault Item: API_KEY_abcdef123456";
            String pbeCiphertext = encrypt(pbePlaintext, pbeKey);
            System.out.println(" -> Encrypted with PBE key: " + pbeCiphertext);
            String pbeDecrypted = decrypt(pbeCiphertext, pbeKey);
            System.out.println(" -> Decrypted with PBE key: " + pbeDecrypted);
            System.out.println(" -> PBE Match: " + pbePlaintext.equals(pbeDecrypted) + "\n");

            // -----------------------------------------------------------------
            // STEP 10: MEMORY HYGIENE & ZEROIZATION
            // -----------------------------------------------------------------
            System.out.println("[Step 10] Memory Hygiene: Zeroizing Sensitive Secrets in Memory...");
            wipe(masterPassword);
            wipe(userPassphrase);
            wipe(salt);
            keyManager.close();
            System.out.println(" -> Overwritten sensitive char[] and byte[] arrays with null/zero bytes.\n");

            System.out.println("===============================================================================");
            System.out.println("                        ALL DEMONSTRATION TESTS PASSED                         ");
            System.out.println("===============================================================================");

        } catch (Exception e) {
            System.err.println("Demonstration failed with exception: " + e.getMessage());
            e.printStackTrace();
        } finally {
            if (tempKeystorePath != null) {
                try {
                    Files.deleteIfExists(tempKeystorePath);
                } catch (IOException ignored) {
                }
            }
        }
    }

    /**
     * Prints command-line usage instructions.
     */
    private static void printUsage() {
        System.out.println("Usage: java SymmetricEncryption [options]");
        System.out.println();
        System.out.println("Modes:");
        System.out.println("  (no args)                                           Run self-contained cryptographic demonstration");
        System.out.println("  --init-keystore <keystore-path> <password>          Create a new PKCS#12 KeyStore with 0600 permissions");
        System.out.println("  --gen-key <keystore-path> <password> <alias>        Generate a 256-bit AES key and store in KeyStore");
        System.out.println("  --list-keys <keystore-path> <password>              List all key aliases in the KeyStore");
        System.out.println("  --encrypt <keystore-path> <password> <alias> <text> Encrypt plaintext data using key from KeyStore");
        System.out.println("  --decrypt <keystore-path> <password> <ciphertext>   Decrypt self-describing ciphertext using KeyStore");
        System.out.println("  --help, -h                                          Display this help message");
    }

    /**
     * Application entry point supporting both automated demonstration and CLI commands.
     */
    public static void main(String[] args) {
        if (args.length == 0) {
            runDemonstration();
            return;
        }

        String command = args[0];
        try {
            switch (command) {
                case "--help":
                case "-h":
                    printUsage();
                    break;

                case "--demo":
                    runDemonstration();
                    break;

                case "--init-keystore": {
                    if (args.length < 3) {
                        System.err.println("Error: Missing arguments for --init-keystore.");
                        printUsage();
                        System.exit(1);
                    }
                    Path ksPath = Paths.get(args[1]);
                    char[] pass = args[2].toCharArray();
                    try (KeyManager km = KeyManager.createKeyStore(ksPath, pass)) {
                        System.out.println("Created KeyStore at: " + ksPath.toAbsolutePath());
                    } finally {
                        wipe(pass);
                    }
                    break;
                }

                case "--gen-key": {
                    if (args.length < 4) {
                        System.err.println("Error: Missing arguments for --gen-key.");
                        printUsage();
                        System.exit(1);
                    }
                    Path ksPath = Paths.get(args[1]);
                    char[] pass = args[2].toCharArray();
                    String alias = args[3];
                    try (KeyManager km = KeyManager.loadKeyStore(ksPath, pass)) {
                        km.generateAndStoreKey(alias);
                        System.out.println("Generated and stored 256-bit AES key under alias: " + alias);
                    } finally {
                        wipe(pass);
                    }
                    break;
                }

                case "--list-keys": {
                    if (args.length < 3) {
                        System.err.println("Error: Missing arguments for --list-keys.");
                        printUsage();
                        System.exit(1);
                    }
                    Path ksPath = Paths.get(args[1]);
                    char[] pass = args[2].toCharArray();
                    try (KeyManager km = KeyManager.loadKeyStore(ksPath, pass)) {
                        List<String> aliases = km.listAliases();
                        System.out.println("Keys in KeyStore (" + aliases.size() + "):");
                        for (String alias : aliases) {
                            System.out.println(" - " + alias);
                        }
                    } finally {
                        wipe(pass);
                    }
                    break;
                }

                case "--encrypt": {
                    if (args.length < 5) {
                        System.err.println("Error: Missing arguments for --encrypt.");
                        printUsage();
                        System.exit(1);
                    }
                    Path ksPath = Paths.get(args[1]);
                    char[] pass = args[2].toCharArray();
                    String alias = args[3];
                    String plaintext = args[4];
                    try (KeyManager km = KeyManager.loadKeyStore(ksPath, pass)) {
                        String ciphertext = encryptWithKeyManager(plaintext, km, alias);
                        System.out.println("Ciphertext:");
                        System.out.println(ciphertext);
                    } finally {
                        wipe(pass);
                    }
                    break;
                }

                case "--decrypt": {
                    if (args.length < 4) {
                        System.err.println("Error: Missing arguments for --decrypt.");
                        printUsage();
                        System.exit(1);
                    }
                    Path ksPath = Paths.get(args[1]);
                    char[] pass = args[2].toCharArray();
                    String ciphertext = args[3];
                    try (KeyManager km = KeyManager.loadKeyStore(ksPath, pass)) {
                        String plaintext = decryptWithKeyManager(ciphertext, km);
                        System.out.println("Plaintext:");
                        System.out.println(plaintext);
                    } finally {
                        wipe(pass);
                    }
                    break;
                }

                default:
                    System.err.println("Unknown command: " + command);
                    printUsage();
                    System.exit(1);
            }
        } catch (Exception e) {
            System.err.println("Operation failed: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
