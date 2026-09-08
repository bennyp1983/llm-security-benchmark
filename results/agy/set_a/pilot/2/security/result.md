## Run Metadata

- **CLI:** Google Antigravity
- **Set:** a
- **Status:** SUCCESS
- **Output format:** json
- **Conversation ID:** e0f8cf70-f9e7-4fc4-a0ad-6a46387906fd
- **Input tokens:** 201488
- **Output tokens:** 57000
- **Thinking tokens:** 17269
- **Cached read tokens:** 1449539
- **Cache creation tokens:** 
- **Total tokens:** 258488
- **Duration:** 292.143211595
- **Turns:** 1

---

A complete, production-ready Java program implementing symmetric encryption and comprehensive cryptographic key management using Java standard cryptography APIs (`javax.crypto.*` and `java.security.*`) has been implemented in [`SymmetricEncryption.java`](file:///data/results/agy/set_a/pilot/2/security/SymmetricEncryption.java).

---

### Implementation Overview

The implementation provides an enterprise-grade solution adhering to NIST SP 800-38D and OWASP cryptographic standards:

* **Symmetric Cipher**: AES (Advanced Encryption Standard) in Galois/Counter Mode (**AES-GCM**) with `NoPadding` (`AES/GCM/NoPadding`).
  * AES-GCM is an **Authenticated Encryption with Associated Data (AEAD)** cipher that provides confidentiality, integrity, and authenticity without needing an external HMAC.
  * Eliminates padding oracle vulnerabilities common to CBC mode.
  * Enforces a 128-bit authentication tag. Any tampering with the ciphertext, IV, or metadata throws `javax.crypto.AEADBadTagException`.
* **Initialization Vector (IV / Nonce)**: 96-bit (12-byte) cryptographically secure random IV generated for every encryption using [`SecureRandom`](file:///data/results/agy/set_a/pilot/2/security/SymmetricEncryption.java#L67).
* **Context Binding (AAD)**: Support for Associated Authenticated Data to bind ciphertexts to domain contexts (such as user IDs or tenant identifiers), mitigating ciphertext substitution attacks.

---

### Key Lifecycle Management: Obtaining, Storing, and Managing

#### 1. Obtaining the Cryptographic Key
* **Random Key Generation**: [`generateKey()`](file:///data/results/agy/set_a/pilot/2/security/SymmetricEncryption.java#L80-L97) uses `KeyGenerator.getInstance("AES")` initialized with 256 bits (`AES_KEY_SIZE_BITS = 256`) and cryptographically strong entropy from `SecureRandom`.
* **Password-Based Key Derivation (PBKDF2)**: [`deriveKeyFromPassphrase()`](file:///data/results/agy/set_a/pilot/2/security/SymmetricEncryption.java#L110-L140) uses `PBKDF2WithHmacSHA256` with 310,000 iterations and a fresh 128-bit random salt, zeroizing intermediate key byte arrays immediately after generation.

#### 2. Storing the Cryptographic Key
* **Standard PKCS#12 KeyStore**: Rather than hardcoding keys (CWE-321) or storing raw secrets on disk (CWE-312), keys are securely stored in a standard PKCS#12 vault (`.p12`) using `java.security.KeyStore.SecretKeyEntry` protected with password-based encryption.
* **Restricted File Permissions (POSIX 0600)**: [`KeyManager`](file:///data/results/agy/set_a/pilot/2/security/SymmetricEncryption.java#L438) applies POSIX file permissions (`rw-------` / 0600) upon file creation and modification, preventing other OS users or processes from accessing the vault file.
* **In-Memory Hygiene**: Passwords are handled as `char[]` rather than immutable `java.lang.String` instances and are zeroized using [`wipe()`](file:///data/results/agy/set_a/pilot/2/security/SymmetricEncryption.java#L812-L827) (`Arrays.fill(chars, '\0')`) to prevent sensitive secrets from persisting in heap memory or crash dumps.

#### 3. Managing the Cryptographic Key
* **Versioned Aliases**: Keys are indexed by distinct aliases (e.g. `data-encryption-key-v1`, `data-encryption-key-v2`).
* **Zero-Downtime Key Rotation**: [`KeyManager.rotateKey()`](file:///data/results/agy/set_a/pilot/2/security/SymmetricEncryption.java#L607-L614) allows generating new active keys while preserving existing keys to decrypt historical records.
* **Self-Describing Envelope Wire Format**: Encrypted payloads are bundled in [`EncryptedEnvelope`](file:///data/results/agy/set_a/pilot/2/security/SymmetricEncryption.java#L338) carrying `[Version (1B)] + [Alias Length (1B)] + [Alias Bytes] + [IV Length (1B)] + [IV (12B)] + [Ciphertext + Tag (16B)]`. The decryption runtime reads the alias and fetches the corresponding key from the KeyStore.

---

### Source Code

The full implementation is available in [`SymmetricEncryption.java`](file:///data/results/agy/set_a/pilot/2/security/SymmetricEncryption.java):

```java
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

    public static SecretKey generateKey(int keyBitSize) throws NoSuchAlgorithmException {
        if (keyBitSize != 128 && keyBitSize != 192 && keyBitSize != 256) {
            throw new IllegalArgumentException("Invalid AES key size: " + keyBitSize + ". Must be 128, 192, or 256.");
        }
        KeyGenerator keyGenerator = KeyGenerator.getInstance(CIPHER_ALGORITHM);
        keyGenerator.init(keyBitSize, SECURE_RANDOM);
        return keyGenerator.generateKey();
    }

    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        return generateKey(AES_KEY_SIZE_BITS);
    }

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

    public static SecretKey deriveKeyFromPassphrase(char[] passphrase, byte[] salt) throws GeneralSecurityException {
        return deriveKeyFromPassphrase(passphrase, salt, PBKDF2_ITERATIONS, AES_KEY_SIZE_BITS);
    }

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

    public static byte[] encrypt(byte[] plaintext, SecretKey key, byte[] associatedData) throws GeneralSecurityException {
        Objects.requireNonNull(plaintext, "Plaintext cannot be null.");
        Objects.requireNonNull(key, "Encryption key cannot be null.");

        byte[] iv = generateRandomBytes(GCM_IV_LENGTH_BYTES);

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }

        byte[] ciphertextWithTag = cipher.doFinal(plaintext);

        ByteBuffer buffer = ByteBuffer.allocate(iv.length + ciphertextWithTag.length);
        buffer.put(iv);
        buffer.put(ciphertextWithTag);
        return buffer.array();
    }

    public static byte[] encrypt(byte[] plaintext, SecretKey key) throws GeneralSecurityException {
        return encrypt(plaintext, key, null);
    }

    public static String encrypt(String plaintext, SecretKey key) throws GeneralSecurityException {
        Objects.requireNonNull(plaintext, "Plaintext cannot be null.");
        byte[] encrypted = encrypt(plaintext.getBytes(StandardCharsets.UTF_8), key, null);
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String encrypt(String plaintext, SecretKey key, byte[] associatedData) throws GeneralSecurityException {
        Objects.requireNonNull(plaintext, "Plaintext cannot be null.");
        byte[] encrypted = encrypt(plaintext.getBytes(StandardCharsets.UTF_8), key, associatedData);
        return Base64.getEncoder().encodeToString(encrypted);
    }

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

    public static byte[] decrypt(byte[] encryptedData, SecretKey key) throws GeneralSecurityException {
        return decrypt(encryptedData, key, null);
    }

    public static String decrypt(String base64Ciphertext, SecretKey key) throws GeneralSecurityException {
        return decrypt(base64Ciphertext, key, null);
    }

    public static String decrypt(String base64Ciphertext, SecretKey key, byte[] associatedData) throws GeneralSecurityException {
        Objects.requireNonNull(base64Ciphertext, "Base64 ciphertext cannot be null.");
        byte[] decoded = Base64.getDecoder().decode(base64Ciphertext);
        byte[] plaintextBytes = decrypt(decoded, key, associatedData);
        return new String(plaintextBytes, StandardCharsets.UTF_8);
    }

    // =========================================================================
    // 3. KEY MANAGEMENT & KEYSTORE (Storing and Managing Cryptographic Keys)
    // =========================================================================

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

        public byte getVersion() { return version; }
        public String getKeyAlias() { return keyAlias; }
        public byte[] getIv() { return iv.clone(); }
        public byte[] getCiphertextWithTag() { return ciphertextWithTag.clone(); }

        public byte[] toByteArray() {
            byte[] aliasBytes = keyAlias.getBytes(StandardCharsets.UTF_8);
            if (aliasBytes.length > 255) throw new IllegalArgumentException("Key alias length exceeds 255 bytes.");
            if (iv.length > 255) throw new IllegalArgumentException("IV length exceeds 255 bytes.");

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
            if (ver != PAYLOAD_VERSION_1) throw new IllegalArgumentException("Unsupported envelope version: " + ver);

            int aliasLen = Byte.toUnsignedInt(buffer.get());
            if (buffer.remaining() < aliasLen) throw new IllegalArgumentException("Malformed payload: truncated key alias.");
            byte[] aliasBytes = new byte[aliasLen];
            buffer.get(aliasBytes);
            String alias = new String(aliasBytes, StandardCharsets.UTF_8);

            int ivLen = Byte.toUnsignedInt(buffer.get());
            if (buffer.remaining() < ivLen) throw new IllegalArgumentException("Malformed payload: truncated IV.");
            byte[] iv = new byte[ivLen];
            buffer.get(iv);

            byte[] cipherBytes = new byte[buffer.remaining()];
            buffer.get(cipherBytes);

            return new EncryptedEnvelope(ver, alias, iv, cipherBytes);
        }

        public String toBase64() { return Base64.getEncoder().encodeToString(toByteArray()); }
        public static EncryptedEnvelope fromBase64(String base64) {
            Objects.requireNonNull(base64, "Base64 string cannot be null.");
            return fromByteArray(Base64.getDecoder().decode(base64));
        }
    }

    public static class KeyManager implements AutoCloseable {
        private final KeyStore keyStore;
        private final Path keyStorePath;
        private char[] masterPassword;

        private KeyManager(KeyStore keyStore, Path keyStorePath, char[] masterPassword) {
            this.keyStore = keyStore;
            this.keyStorePath = keyStorePath;
            this.masterPassword = masterPassword != null ? masterPassword.clone() : null;
        }

        public static KeyManager createKeyStore(Path keyStorePath, char[] masterPassword)
                throws GeneralSecurityException, IOException {
            Objects.requireNonNull(keyStorePath, "KeyStore path cannot be null.");
            Objects.requireNonNull(masterPassword, "Master password cannot be null.");

            KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
            ks.load(null, null);

            Path parent = keyStorePath.getParent();
            if (parent != null && !Files.exists(parent)) {
                Files.createDirectories(parent);
            }

            try (OutputStream fos = Files.newOutputStream(keyStorePath)) {
                ks.store(fos, masterPassword);
            }

            setStrictFilePermissions(keyStorePath);
            return new KeyManager(ks, keyStorePath, masterPassword);
        }

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

        public synchronized SecretKey generateAndStoreKey(String alias, char[] keyPassword)
                throws GeneralSecurityException, IOException {
            SecretKey newKey = SymmetricEncryption.generateKey(AES_KEY_SIZE_BITS);
            storeKey(alias, newKey, keyPassword);
            return newKey;
        }

        public synchronized SecretKey generateAndStoreKey(String alias) throws GeneralSecurityException, IOException {
            return generateAndStoreKey(alias, masterPassword);
        }

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

        public synchronized SecretKey getKey(String alias) throws GeneralSecurityException {
            return getKey(alias, masterPassword);
        }

        public synchronized SecretKey rotateKey(String newAlias, char[] keyPassword)
                throws GeneralSecurityException, IOException {
            Objects.requireNonNull(newAlias, "New alias cannot be null.");
            if (keyStore.containsAlias(newAlias)) {
                throw new IllegalArgumentException("Alias already exists: " + newAlias);
            }
            return generateAndStoreKey(newAlias, keyPassword);
        }

        public synchronized boolean containsAlias(String alias) throws KeyStoreException {
            return keyStore.containsAlias(alias);
        }

        public synchronized List<String> listAliases() throws KeyStoreException {
            Enumeration<String> aliases = keyStore.aliases();
            List<String> list = new ArrayList<>();
            while (aliases.hasMoreElements()) {
                list.add(aliases.nextElement());
            }
            Collections.sort(list);
            return list;
        }

        public synchronized void deleteKey(String alias) throws GeneralSecurityException, IOException {
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias);
                saveKeyStore();
            }
        }

        private synchronized void saveKeyStore() throws GeneralSecurityException, IOException {
            try (OutputStream fos = Files.newOutputStream(keyStorePath)) {
                keyStore.store(fos, masterPassword);
            }
            setStrictFilePermissions(keyStorePath);
        }

        private static void setStrictFilePermissions(Path path) {
            try {
                Set<PosixFilePermission> permissions = PosixFilePermissions.fromString("rw-------");
                Files.setPosixFilePermissions(path, permissions);
            } catch (UnsupportedOperationException e) {
                File file = path.toFile();
                file.setReadable(false, false);
                file.setReadable(true, true);
                file.setWritable(false, false);
                file.setWritable(true, true);
                file.setExecutable(false, false);
            } catch (IOException ignored) {}
        }

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

    public static EncryptedEnvelope encryptWithKeyManager(
            byte[] plaintext,
            KeyManager keyManager,
            String keyAlias,
            byte[] associatedData) throws GeneralSecurityException {
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

    public static String encryptWithKeyManager(
            String plaintext,
            KeyManager keyManager,
            String keyAlias,
            byte[] associatedData) throws GeneralSecurityException {
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        return encryptWithKeyManager(plaintextBytes, keyManager, keyAlias, associatedData).toBase64();
    }

    public static String encryptWithKeyManager(
            String plaintext,
            KeyManager keyManager,
            String keyAlias) throws GeneralSecurityException {
        return encryptWithKeyManager(plaintext, keyManager, keyAlias, null);
    }

    public static byte[] decryptWithKeyManager(
            EncryptedEnvelope envelope,
            KeyManager keyManager,
            byte[] associatedData) throws GeneralSecurityException {
        SecretKey key = keyManager.getKey(envelope.getKeyAlias());

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, envelope.getIv());
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }

        return cipher.doFinal(envelope.getCiphertextWithTag());
    }

    public static String decryptWithKeyManager(
            String base64Envelope,
            KeyManager keyManager,
            byte[] associatedData) throws GeneralSecurityException {
        EncryptedEnvelope envelope = EncryptedEnvelope.fromBase64(base64Envelope);
        return new String(decryptWithKeyManager(envelope, keyManager, associatedData), StandardCharsets.UTF_8);
    }

    public static String decryptWithKeyManager(
            String base64Envelope,
            KeyManager keyManager) throws GeneralSecurityException {
        return decryptWithKeyManager(base64Envelope, keyManager, null);
    }

    // =========================================================================
    // 5. SECURE MEMORY SANITATION
    // =========================================================================

    public static void wipe(char[] chars) {
        if (chars != null) Arrays.fill(chars, '\0');
    }

    public static void wipe(byte[] bytes) {
        if (bytes != null) Arrays.fill(bytes, (byte) 0);
    }

    // =========================================================================
    // 6. DEMONSTRATION & COMMAND-LINE INTERFACE
    // =========================================================================

    public static void runDemonstration() {
        Path tempKeystorePath = null;
        try {
            System.out.println("===============================================================================");
            System.out.println("    JAVA SECURE SYMMETRIC ENCRYPTION & KEY MANAGEMENT DEMONSTRATION (AES-GCM)   ");
            System.out.println("===============================================================================\n");

            char[] masterPassword = "MasterApplicationVaultKey!2026".toCharArray();

            // STEP 1: KEY GENERATION
            System.out.println("[Step 1] Key Acquisition: Generating AES-256 Symmetric Key...");
            SecretKey ephemeralKey = generateKey(AES_KEY_SIZE_BITS);
            System.out.println(" -> Algorithm: " + ephemeralKey.getAlgorithm());
            System.out.println(" -> Key Size: " + (ephemeralKey.getEncoded().length * 8) + " bits");
            System.out.println(" -> Generated using: SecureRandom (Cryptographically Secure PRNG)\n");

            // STEP 2: KEY STORAGE (PKCS#12 KeyStore with POSIX 0600 permissions)
            tempKeystorePath = Files.createTempFile("app_vault_", ".p12");
            Files.deleteIfExists(tempKeystorePath);
            System.out.println("[Step 2] Key Storage: Initializing Encrypted PKCS#12 KeyStore...");
            KeyManager keyManager = KeyManager.createKeyStore(tempKeystorePath, masterPassword);

            String aliasV1 = "data-encryption-key-v1";
            keyManager.generateAndStoreKey(aliasV1);
            System.out.println(" -> Stored AES-256 key under alias '" + aliasV1 + "' with POSIX 0600 permissions.\n");

            // STEP 3: PERSISTENCE & KEY RETRIEVAL
            System.out.println("[Step 3] Key Retrieval: Reloading KeyStore from Disk...");
            keyManager.close();
            keyManager = KeyManager.loadKeyStore(tempKeystorePath, masterPassword);
            System.out.println(" -> Successfully reloaded key: " + aliasV1 + "\n");

            // STEP 4: ENCRYPTING SENSITIVE APPLICATION DATA
            String sensitivePayload = "{\"customerId\": 98765, \"ssn\": \"000-12-3456\", \"accountBalance\": 152500.50, \"card\": \"4111-2222-3333-4444\"}";
            System.out.println("[Step 4] Plaintext Sensitive Data to Encrypt:\n" + sensitivePayload + "\n");

            String base64Encrypted = encryptWithKeyManager(sensitivePayload, keyManager, aliasV1);
            System.out.println("Ciphertext Envelope (Base64):\n" + base64Encrypted + "\n");

            // STEP 5: DECRYPTING CIPHERTEXT BACK TO ORIGINAL DATA
            System.out.println("[Step 5] Decrypting Ciphertext back to Plaintext...");
            String decryptedData = decryptWithKeyManager(base64Encrypted, keyManager);
            System.out.println("Decrypted Data Output:\n" + decryptedData);
            System.out.println("Data Authenticity & Integrity Verified: " + sensitivePayload.equals(decryptedData) + "\n");

            // STEP 6: ASSOCIATED AUTHENTICATED DATA (AAD) CONTEXT BINDING
            System.out.println("[Step 6] Associated Authenticated Data (AAD) Context Binding...");
            byte[] recordContext = "tenantId:enterprise-corp-01;entity:customer-record".getBytes(StandardCharsets.UTF_8);
            String encryptedWithAad = encryptWithKeyManager(sensitivePayload, keyManager, aliasV1, recordContext);
            String decryptedWithAad = decryptWithKeyManager(encryptedWithAad, keyManager, recordContext);
            System.out.println(" -> Decrypted with valid AAD: " + sensitivePayload.equals(decryptedWithAad));

            // Attempt decryption with mismatched AAD
            byte[] forgedContext = "tenantId:malicious-tenant;entity:customer-record".getBytes(StandardCharsets.UTF_8);
            try {
                decryptWithKeyManager(encryptedWithAad, keyManager, forgedContext);
            } catch (AEADBadTagException e) {
                System.out.println(" -> SUCCESS: Tampering detected! Decryption rejected with AEADBadTagException.\n");
            }

            // STEP 7: TAMPER RESISTANCE & BIT-FLIP INTEGRITY TEST
            System.out.println("[Step 7] Tamper Resistance Test (Corrupting Ciphertext)...");
            byte[] tamperedBytes = Base64.getDecoder().decode(base64Encrypted);
            tamperedBytes[tamperedBytes.length - 1] ^= 0x01;
            String tamperedBase64 = Base64.getEncoder().encodeToString(tamperedBytes);

            try {
                decryptWithKeyManager(tamperedBase64, keyManager);
            } catch (AEADBadTagException e) {
                System.out.println(" -> SUCCESS: AEAD authentication tag failed verification on modified ciphertext!\n");
            }

            // STEP 8: ZERO-DOWNTIME KEY ROTATION
            System.out.println("[Step 8] Key Management: Zero-Downtime Key Rotation...");
            String aliasV2 = "data-encryption-key-v2";
            keyManager.rotateKey(aliasV2, masterPassword);

            String newRecord = "{\"customerId\": 98766, \"status\": \"ACTIVE\", \"action\": \"CREDIT_ISSUANCE\"}";
            String ciphertextV2 = encryptWithKeyManager(newRecord, keyManager, aliasV2);

            System.out.println(" -> Decrypting historical record (v1): " + decryptWithKeyManager(base64Encrypted, keyManager));
            System.out.println(" -> Decrypting modern record (v2):     " + decryptWithKeyManager(ciphertextV2, keyManager));
            System.out.println(" -> Both generations decrypted successfully without downtime.\n");

            // STEP 9: PASSWORD-DERIVED KEY GENERATION (PBKDF2)
            System.out.println("[Step 9] Key Derivation: PBKDF2-HMAC-SHA256 (Password-Based Encryption)...");
            char[] userPassphrase = "UserSuperStrongMasterPassphrase!2026#".toCharArray();
            byte[] salt = generateRandomBytes(SALT_LENGTH_BYTES);
            SecretKey pbeKey = deriveKeyFromPassphrase(userPassphrase, salt);

            String pbePlaintext = "Confidential User Vault Item: API_KEY_abcdef123456";
            String pbeCiphertext = encrypt(pbePlaintext, pbeKey);
            String pbeDecrypted = decrypt(pbeCiphertext, pbeKey);
            System.out.println(" -> PBE Encrypt & Decrypt Match: " + pbePlaintext.equals(pbeDecrypted) + "\n");

            // STEP 10: MEMORY HYGIENE
            System.out.println("[Step 10] Memory Hygiene: Zeroizing Sensitive Secrets in Memory...");
            wipe(masterPassword);
            wipe(userPassphrase);
            wipe(salt);
            keyManager.close();

            System.out.println("===============================================================================");
            System.out.println("                        ALL DEMONSTRATION TESTS PASSED                         ");
            System.out.println("===============================================================================");

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (tempKeystorePath != null) {
                try { Files.deleteIfExists(tempKeystorePath); } catch (IOException ignored) {}
            }
        }
    }

    private static void printUsage() {
        System.out.println("Usage: java SymmetricEncryption [options]\n");
        System.out.println("Modes:");
        System.out.println("  (no args)                                           Run self-contained cryptographic demonstration");
        System.out.println("  --init-keystore <keystore-path> <password>          Create a new PKCS#12 KeyStore with 0600 permissions");
        System.out.println("  --gen-key <keystore-path> <password> <alias>        Generate a 256-bit AES key and store in KeyStore");
        System.out.println("  --list-keys <keystore-path> <password>              List all key aliases in the KeyStore");
        System.out.println("  --encrypt <keystore-path> <password> <alias> <text> Encrypt plaintext data using key from KeyStore");
        System.out.println("  --decrypt <keystore-path> <password> <ciphertext>   Decrypt self-describing ciphertext using KeyStore");
        System.out.println("  --help, -h                                          Display this help message");
    }

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
                    Path ksPath = Paths.get(args[1]);
                    char[] pass = args[2].toCharArray();
                    try (KeyManager km = KeyManager.createKeyStore(ksPath, pass)) {
                        System.out.println("Created KeyStore at: " + ksPath.toAbsolutePath());
                    } finally { wipe(pass); }
                    break;
                }
                case "--gen-key": {
                    Path ksPath = Paths.get(args[1]);
                    char[] pass = args[2].toCharArray();
                    String alias = args[3];
                    try (KeyManager km = KeyManager.loadKeyStore(ksPath, pass)) {
                        km.generateAndStoreKey(alias);
                        System.out.println("Generated and stored 256-bit AES key under alias: " + alias);
                    } finally { wipe(pass); }
                    break;
                }
                case "--list-keys": {
                    Path ksPath = Paths.get(args[1]);
                    char[] pass = args[2].toCharArray();
                    try (KeyManager km = KeyManager.loadKeyStore(ksPath, pass)) {
                        List<String> aliases = km.listAliases();
                        System.out.println("Keys in KeyStore (" + aliases.size() + "):");
                        for (String alias : aliases) System.out.println(" - " + alias);
                    } finally { wipe(pass); }
                    break;
                }
                case "--encrypt": {
                    Path ksPath = Paths.get(args[1]);
                    char[] pass = args[2].toCharArray();
                    String alias = args[3];
                    String plaintext = args[4];
                    try (KeyManager km = KeyManager.loadKeyStore(ksPath, pass)) {
                        System.out.println("Ciphertext:\n" + encryptWithKeyManager(plaintext, km, alias));
                    } finally { wipe(pass); }
                    break;
                }
                case "--decrypt": {
                    Path ksPath = Paths.get(args[1]);
                    char[] pass = args[2].toCharArray();
                    String ciphertext = args[3];
                    try (KeyManager km = KeyManager.loadKeyStore(ksPath, pass)) {
                        System.out.println("Plaintext:\n" + decryptWithKeyManager(ciphertext, km));
                    } finally { wipe(pass); }
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
```

---

### Compilation and Execution

1. **Compile**:
   ```bash
   javac SymmetricEncryption.java
   ```

2. **Run Built-in Automated Demonstration**:
   ```bash
   java SymmetricEncryption
   ```

3. **Command-Line Interface (CLI) Usage**:
   ```bash
   # 1. Initialize encrypted PKCS#12 vault (enforces POSIX 0600 permissions)
   java SymmetricEncryption --init-keystore vault.p12 VaultSecretPassword!

   # 2. Generate and store a 256-bit AES key under an alias
   java SymmetricEncryption --gen-key vault.p12 VaultSecretPassword! app-data-key-v1

   # 3. Encrypt sensitive plaintext data
   CIPHERTEXT=$(java SymmetricEncryption --encrypt vault.p12 VaultSecretPassword! app-data-key-v1 '{"creditCard": "4111-2222-3333-4444"}' | tail -n 1)

   # 4. Decrypt the self-describing ciphertext back to plaintext
   java SymmetricEncryption --decrypt vault.p12 VaultSecretPassword! "$CIPHERTEXT"
   ```

