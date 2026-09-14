import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.EnumSet;
import java.util.List;
import java.util.Scanner;
import java.util.Set;

/**
 * SymmetricCryptoApp
 *
 * A production-grade, complete Java application demonstrating symmetric encryption
 * and decryption of sensitive application data using standard Java Cryptography Architecture (JCA).
 *
 * Cryptographic Highlights:
 * 1. Algorithm: AES (Advanced Encryption Standard) in Galois/Counter Mode (GCM) with NoPadding (AES/GCM/NoPadding).
 *    - AEAD (Authenticated Encryption with Associated Data) provides both confidentiality and integrity/authenticity.
 *    - Automatic protection against padding oracle attacks and ciphertext tampering (bit-flipping).
 * 2. Key Management:
 *    - Secure Random Generation: 256-bit AES keys generated via SecureRandom.
 *    - KeyStore Storage: Industry-standard PKCS#12 (.p12) password-protected keystore for key storage and lifecycle management.
 *    - Key Derivation: PBKDF2 with HMAC-SHA256 (310,000 iterations conforming to OWASP recommendations)
 *      with a 128-bit cryptographically random salt for password-based encryption.
 *    - Memory Hygiene: Passwords and sensitive key material stored in char[] and byte[] arrays with explicit zeroing.
 * 3. IV / Nonce Management:
 *    - Unique 96-bit (12-byte) initialization vector generated per encryption operation using SecureRandom.
 *    - Standard 128-bit GCM authentication tag.
 * 4. Additional Authenticated Data (AAD):
 *    - Support for cryptographically binding metadata (e.g., account ID, timestamp) to the ciphertext.
 */
public class SymmetricCryptoApp {

    // =========================================================================
    // Cryptographic Constants
    // =========================================================================
    public static final String KEY_ALGORITHM = "AES";
    public static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    public static final String KEYSTORE_TYPE = "PKCS12";
    public static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA256";

    public static final int AES_KEY_SIZE_BITS = 256;          // 32 bytes
    public static final int GCM_IV_LENGTH_BYTES = 12;         // 96 bits (NIST SP 800-38D recommendation)
    public static final int GCM_TAG_LENGTH_BITS = 128;        // 16 bytes authentication tag
    public static final int PBKDF2_SALT_LENGTH_BYTES = 16;    // 128 bits
    public static final int PBKDF2_ITERATIONS = 310_000;      // OWASP recommended iteration count

    // Self-describing payload format markers
    public static final byte PAYLOAD_VERSION_KEYSTORE = 0x01;
    public static final byte PAYLOAD_VERSION_PBKDF2 = 0x02;

    // SecureRandom instance for all cryptographic operations
    private static final SecureRandom SECURE_RANDOM = createSecureRandom();

    private static SecureRandom createSecureRandom() {
        try {
            return SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            return new SecureRandom();
        }
    }

    // =========================================================================
    // Custom Exception
    // =========================================================================
    public static class CryptoException extends Exception {
        private static final long serialVersionUID = 1L;

        public CryptoException(String message) {
            super(message);
        }

        public CryptoException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    // =========================================================================
    // Encrypted Payload Container
    // =========================================================================
    /**
     * Encapsulates the encrypted ciphertext along with necessary cryptographic metadata
     * (version, IV, authentication tag, and optional PBKDF2 salt/iterations).
     *
     * Wire formats:
     * - Version 0x01 (KeyStore / Pre-shared Key):
     *   [1 byte Version: 0x01] [12 bytes IV] [Ciphertext + 16 bytes GCM Auth Tag]
     *
     * - Version 0x02 (Password-Derived Key via PBKDF2):
     *   [1 byte Version: 0x02] [16 bytes Salt] [4 bytes Iterations (BE int)] [12 bytes IV] [Ciphertext + 16 bytes GCM Auth Tag]
     */
    public static class EncryptedPayload {
        private final byte version;
        private final byte[] salt;          // Only used for version 0x02
        private final int iterations;       // Only used for version 0x02
        private final byte[] iv;            // 12 bytes
        private final byte[] ciphertextAndTag; // Ciphertext concatenated with 16-byte GCM authentication tag

        public EncryptedPayload(byte version, byte[] salt, int iterations, byte[] iv, byte[] ciphertextAndTag) {
            this.version = version;
            this.salt = salt != null ? salt.clone() : null;
            this.iterations = iterations;
            this.iv = iv.clone();
            this.ciphertextAndTag = ciphertextAndTag.clone();
        }

        public byte getVersion() { return version; }
        public byte[] getSalt() { return salt != null ? salt.clone() : null; }
        public int getIterations() { return iterations; }
        public byte[] getIv() { return iv.clone(); }
        public byte[] getCiphertextAndTag() { return ciphertextAndTag.clone(); }

        /**
         * Serializes this payload to a unified binary format.
         */
        public byte[] toByteArray() {
            if (version == PAYLOAD_VERSION_KEYSTORE) {
                ByteBuffer buffer = ByteBuffer.allocate(1 + GCM_IV_LENGTH_BYTES + ciphertextAndTag.length);
                buffer.put(PAYLOAD_VERSION_KEYSTORE);
                buffer.put(iv);
                buffer.put(ciphertextAndTag);
                return buffer.array();
            } else if (version == PAYLOAD_VERSION_PBKDF2) {
                ByteBuffer buffer = ByteBuffer.allocate(1 + PBKDF2_SALT_LENGTH_BYTES + 4 + GCM_IV_LENGTH_BYTES + ciphertextAndTag.length);
                buffer.put(PAYLOAD_VERSION_PBKDF2);
                buffer.put(salt);
                buffer.putInt(iterations);
                buffer.put(iv);
                buffer.put(ciphertextAndTag);
                return buffer.array();
            } else {
                throw new IllegalStateException("Unsupported payload version: " + version);
            }
        }

        /**
         * Deserializes a binary payload.
         */
        public static EncryptedPayload fromByteArray(byte[] data) throws CryptoException {
            if (data == null || data.length < 1) {
                throw new CryptoException("Invalid payload: empty or null data.");
            }

            ByteBuffer buffer = ByteBuffer.wrap(data);
            byte ver = buffer.get();

            if (ver == PAYLOAD_VERSION_KEYSTORE) {
                // Minimum size: 1 byte ver + 12 bytes IV + 16 bytes tag = 29 bytes
                if (data.length < 1 + GCM_IV_LENGTH_BYTES + (GCM_TAG_LENGTH_BITS / 8)) {
                    throw new CryptoException("Corrupted payload: data too short for KeyStore AES-GCM payload.");
                }
                byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
                buffer.get(iv);
                byte[] cipherBytes = new byte[buffer.remaining()];
                buffer.get(cipherBytes);
                return new EncryptedPayload(ver, null, 0, iv, cipherBytes);
            } else if (ver == PAYLOAD_VERSION_PBKDF2) {
                // Minimum size: 1 byte ver + 16 bytes salt + 4 bytes iter + 12 bytes IV + 16 bytes tag = 49 bytes
                if (data.length < 1 + PBKDF2_SALT_LENGTH_BYTES + 4 + GCM_IV_LENGTH_BYTES + (GCM_TAG_LENGTH_BITS / 8)) {
                    throw new CryptoException("Corrupted payload: data too short for PBKDF2 AES-GCM payload.");
                }
                byte[] salt = new byte[PBKDF2_SALT_LENGTH_BYTES];
                buffer.get(salt);
                int iters = buffer.getInt();
                if (iters <= 0 || iters > 10_000_000) {
                    throw new CryptoException("Invalid PBKDF2 iteration count in payload: " + iters);
                }
                byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
                buffer.get(iv);
                byte[] cipherBytes = new byte[buffer.remaining()];
                buffer.get(cipherBytes);
                return new EncryptedPayload(ver, salt, iters, iv, cipherBytes);
            } else {
                throw new CryptoException(String.format("Unrecognized payload header version: 0x%02X", ver));
            }
        }

        /**
         * Serializes the payload into a Base64 string for safe text transmission.
         */
        public String toBase64() {
            return Base64.getEncoder().encodeToString(toByteArray());
        }

        /**
         * Deserializes a Base64-encoded payload.
         */
        public static EncryptedPayload fromBase64(String base64String) throws CryptoException {
            if (base64String == null || base64String.trim().isEmpty()) {
                throw new CryptoException("Ciphertext string cannot be null or empty.");
            }
            try {
                byte[] decoded = Base64.getDecoder().decode(base64String.trim());
                return fromByteArray(decoded);
            } catch (IllegalArgumentException e) {
                throw new CryptoException("Invalid Base64 encoding in ciphertext payload.", e);
            }
        }
    }

    // =========================================================================
    // Key Management Service (PKCS#12 KeyStore)
    // =========================================================================
    /**
     * Manages the lifecycle of symmetric cryptographic keys:
     * - Secure Generation using Java KeyGenerator & SecureRandom
     * - Storage in standard PKCS#12 KeyStore (.p12) with POSIX file protection
     * - Key retrieval and alias management
     */
    public static class KeyStoreManager {

        /**
         * Generates a new 256-bit AES symmetric key.
         */
        public static SecretKey generateKey() throws CryptoException {
            try {
                KeyGenerator keyGen = KeyGenerator.getInstance(KEY_ALGORITHM);
                keyGen.init(AES_KEY_SIZE_BITS, SECURE_RANDOM);
                return keyGen.generateKey();
            } catch (NoSuchAlgorithmException e) {
                throw new CryptoException("AES key generation algorithm not supported.", e);
            }
        }

        /**
         * Initializes a new, empty PKCS#12 keystore file with strict file permissions.
         */
        public static void createKeyStore(Path keystorePath, char[] keystorePassword) throws CryptoException {
            try {
                KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
                keyStore.load(null, null); // Initialize new empty keystore

                saveKeyStoreToFile(keyStore, keystorePath, keystorePassword);
            } catch (GeneralSecurityException | IOException e) {
                throw new CryptoException("Failed to initialize keystore at " + keystorePath + ": " + e.getMessage(), e);
            }
        }

        /**
         * Generates a new AES-256 key and stores it inside the specified KeyStore.
         */
        public static SecretKey generateAndStoreKey(Path keystorePath,
                                                    char[] keystorePassword,
                                                    String alias,
                                                    char[] keyPassword) throws CryptoException {
            SecretKey secretKey = generateKey();
            storeKey(keystorePath, keystorePassword, alias, secretKey, keyPassword);
            return secretKey;
        }

        /**
         * Stores an existing SecretKey into the PKCS#12 keystore under the given alias.
         */
        public static void storeKey(Path keystorePath,
                                    char[] keystorePassword,
                                    String alias,
                                    SecretKey secretKey,
                                    char[] keyPassword) throws CryptoException {
            try {
                KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);

                if (Files.exists(keystorePath)) {
                    try (InputStream is = Files.newInputStream(keystorePath)) {
                        keyStore.load(is, keystorePassword);
                    }
                } else {
                    keyStore.load(null, null);
                }

                KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(keyPassword);
                KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(secretKey);
                keyStore.setEntry(alias, entry, protParam);

                saveKeyStoreToFile(keyStore, keystorePath, keystorePassword);
            } catch (GeneralSecurityException | IOException e) {
                throw new CryptoException("Failed to store key in keystore: " + e.getMessage(), e);
            }
        }

        /**
         * Loads a SecretKey from the PKCS#12 keystore by alias.
         */
        public static SecretKey loadKey(Path keystorePath,
                                        char[] keystorePassword,
                                        String alias,
                                        char[] keyPassword) throws CryptoException {
            if (!Files.exists(keystorePath)) {
                throw new CryptoException("KeyStore file not found: " + keystorePath);
            }

            try {
                KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
                try (InputStream is = Files.newInputStream(keystorePath)) {
                    keyStore.load(is, keystorePassword);
                }

                if (!keyStore.containsAlias(alias)) {
                    throw new CryptoException("Key alias '" + alias + "' not found in keystore.");
                }

                KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(keyPassword);
                KeyStore.Entry entry = keyStore.getEntry(alias, protParam);

                if (entry == null) {
                    throw new CryptoException("Unable to retrieve entry for alias '" + alias + "'. Incorrect key password?");
                }

                if (!(entry instanceof KeyStore.SecretKeyEntry)) {
                    throw new CryptoException("KeyStore entry for alias '" + alias + "' is not a SecretKeyEntry.");
                }

                return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
            } catch (GeneralSecurityException | IOException e) {
                throw new CryptoException("Failed to load key from keystore: " + e.getMessage(), e);
            }
        }

        /**
         * Lists all aliases currently present in the keystore.
         */
        public static List<String> listAliases(Path keystorePath, char[] keystorePassword) throws CryptoException {
            if (!Files.exists(keystorePath)) {
                throw new CryptoException("KeyStore file not found: " + keystorePath);
            }

            try {
                KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
                try (InputStream is = Files.newInputStream(keystorePath)) {
                    keyStore.load(is, keystorePassword);
                }

                List<String> aliases = new ArrayList<>();
                Enumeration<String> enumeration = keyStore.aliases();
                while (enumeration.hasMoreElements()) {
                    aliases.add(enumeration.nextElement());
                }
                Collections.sort(aliases);
                return aliases;
            } catch (GeneralSecurityException | IOException e) {
                throw new CryptoException("Failed to list keystore aliases: " + e.getMessage(), e);
            }
        }

        private static void saveKeyStoreToFile(KeyStore keyStore, Path path, char[] password) throws IOException, GeneralSecurityException {
            if (path.getParent() != null) {
                Files.createDirectories(path.getParent());
            }

            try (OutputStream os = Files.newOutputStream(path)) {
                keyStore.store(os, password);
            }

            // Enforce restrictive POSIX file permissions (owner read/write only: 0600)
            setOwnerOnlyPermissions(path);
        }

        private static void setOwnerOnlyPermissions(Path path) {
            try {
                if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                    Set<PosixFilePermission> permissions = EnumSet.of(
                            PosixFilePermission.OWNER_READ,
                            PosixFilePermission.OWNER_WRITE
                    );
                    Files.setPosixFilePermissions(path, permissions);
                }
            } catch (Exception ignored) {
                // Ignore gracefully on non-POSIX filesystems (Windows, etc.)
            }
        }
    }

    // =========================================================================
    // Key Derivation Service (PBKDF2)
    // =========================================================================
    /**
     * Handles deriving cryptographically strong symmetric keys from passwords/passphrases
     * using PBKDF2WithHmacSHA256, adhering to OWASP key derivation guidelines.
     */
    public static class KeyDerivationService {

        /**
         * Generates a cryptographically random salt.
         */
        public static byte[] generateSalt(int lengthBytes) {
            byte[] salt = new byte[lengthBytes];
            SECURE_RANDOM.nextBytes(salt);
            return salt;
        }

        /**
         * Derives an AES SecretKey from a password and salt using PBKDF2WithHmacSHA256.
         */
        public static SecretKey deriveKey(char[] password, byte[] salt, int iterations, int keyLengthBits) throws CryptoException {
            if (password == null || password.length == 0) {
                throw new CryptoException("Password cannot be null or empty.");
            }
            if (salt == null || salt.length < 16) {
                throw new CryptoException("Salt must be at least 16 bytes (128 bits).");
            }

            KeySpec spec = new PBEKeySpec(password, salt, iterations, keyLengthBits);
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALGORITHM);
                SecretKey tmp = factory.generateSecret(spec);
                byte[] rawKeyBytes = tmp.getEncoded();
                try {
                    return new SecretKeySpec(rawKeyBytes, KEY_ALGORITHM);
                } finally {
                    wipe(rawKeyBytes);
                }
            } catch (GeneralSecurityException e) {
                throw new CryptoException("Key derivation failed: " + e.getMessage(), e);
            } finally {
                ((PBEKeySpec) spec).clearPassword();
            }
        }
    }

    // =========================================================================
    // Symmetric Encryption Service (AES-GCM Core)
    // =========================================================================
    /**
     * Core cryptographic service for AES-256-GCM authenticated encryption and decryption.
     */
    public static class SymmetricEncryptionService {

        /**
         * Generates a unique 12-byte (96-bit) Initialization Vector (IV/Nonce).
         */
        public static byte[] generateIv() {
            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            SECURE_RANDOM.nextBytes(iv);
            return iv;
        }

        /**
         * Encrypts plaintext bytes using a pre-shared SecretKey (e.g., loaded from KeyStore).
         *
         * @param plaintext      Sensitive data to encrypt.
         * @param key            256-bit AES SecretKey.
         * @param associatedData Optional authenticated associated data (AAD). May be null.
         * @return EncryptedPayload containing version, IV, and ciphertext+tag.
         */
        public EncryptedPayload encrypt(byte[] plaintext, SecretKey key, byte[] associatedData) throws CryptoException {
            if (plaintext == null) {
                throw new CryptoException("Plaintext cannot be null.");
            }
            if (key == null) {
                throw new CryptoException("SecretKey cannot be null.");
            }

            byte[] iv = generateIv();
            try {
                Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
                GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
                cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

                if (associatedData != null && associatedData.length > 0) {
                    cipher.updateAAD(associatedData);
                }

                byte[] cipherBytes = cipher.doFinal(plaintext);
                return new EncryptedPayload(PAYLOAD_VERSION_KEYSTORE, null, 0, iv, cipherBytes);
            } catch (GeneralSecurityException e) {
                throw new CryptoException("Encryption failed: " + e.getMessage(), e);
            }
        }

        /**
         * Decrypts ciphertext bytes using a pre-shared SecretKey.
         *
         * @param payload        Encrypted payload containing IV and ciphertext+tag.
         * @param key            256-bit AES SecretKey.
         * @param associatedData Optional authenticated associated data (must match what was supplied at encryption).
         * @return Decrypted plaintext bytes.
         * @throws CryptoException If authentication fails, data was tampered with, or wrong key/AAD was used.
         */
        public byte[] decrypt(EncryptedPayload payload, SecretKey key, byte[] associatedData) throws CryptoException {
            if (payload == null) {
                throw new CryptoException("Encrypted payload cannot be null.");
            }
            if (key == null) {
                throw new CryptoException("SecretKey cannot be null.");
            }

            try {
                Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
                GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, payload.getIv());
                cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

                if (associatedData != null && associatedData.length > 0) {
                    cipher.updateAAD(associatedData);
                }

                return cipher.doFinal(payload.getCiphertextAndTag());
            } catch (AEADBadTagException e) {
                throw new CryptoException("Decryption failed: Authentication tag mismatch. " +
                        "The ciphertext has been tampered with, corrupted, or decrypted with an incorrect key/associated data.", e);
            } catch (GeneralSecurityException e) {
                throw new CryptoException("Decryption failed: " + e.getMessage(), e);
            }
        }

        /**
         * Encrypts plaintext bytes using a password by deriving an ephemeral AES key via PBKDF2.
         * The random salt and iteration count are included in the self-describing payload.
         */
        public EncryptedPayload encryptWithPassword(byte[] plaintext, char[] password, byte[] associatedData) throws CryptoException {
            byte[] salt = KeyDerivationService.generateSalt(PBKDF2_SALT_LENGTH_BYTES);
            SecretKey derivedKey = KeyDerivationService.deriveKey(password, salt, PBKDF2_ITERATIONS, AES_KEY_SIZE_BITS);

            byte[] iv = generateIv();
            try {
                Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
                GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
                cipher.init(Cipher.ENCRYPT_MODE, derivedKey, parameterSpec);

                if (associatedData != null && associatedData.length > 0) {
                    cipher.updateAAD(associatedData);
                }

                byte[] cipherBytes = cipher.doFinal(plaintext);
                return new EncryptedPayload(PAYLOAD_VERSION_PBKDF2, salt, PBKDF2_ITERATIONS, iv, cipherBytes);
            } catch (GeneralSecurityException e) {
                throw new CryptoException("Password-based encryption failed: " + e.getMessage(), e);
            }
        }

        /**
         * Decrypts ciphertext bytes using a password by reconstructing the key from the payload's salt and iterations.
         */
        public byte[] decryptWithPassword(EncryptedPayload payload, char[] password, byte[] associatedData) throws CryptoException {
            if (payload.getVersion() != PAYLOAD_VERSION_PBKDF2) {
                throw new CryptoException("Payload is not formatted as a password-derived (PBKDF2) encryption container.");
            }

            SecretKey derivedKey = KeyDerivationService.deriveKey(password, payload.getSalt(), payload.getIterations(), AES_KEY_SIZE_BITS);
            try {
                Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
                GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, payload.getIv());
                cipher.init(Cipher.DECRYPT_MODE, derivedKey, parameterSpec);

                if (associatedData != null && associatedData.length > 0) {
                    cipher.updateAAD(associatedData);
                }

                return cipher.doFinal(payload.getCiphertextAndTag());
            } catch (AEADBadTagException e) {
                throw new CryptoException("Decryption failed: Authentication tag mismatch. " +
                        "The password may be incorrect, or the ciphertext/associated data has been tampered with.", e);
            } catch (GeneralSecurityException e) {
                throw new CryptoException("Password-based decryption failed: " + e.getMessage(), e);
            }
        }

        // ---------------------------------------------------------------------
        // High-level String Convenience Methods
        // ---------------------------------------------------------------------

        public String encryptString(String plaintext, SecretKey key) throws CryptoException {
            return encryptString(plaintext, key, null);
        }

        public String encryptString(String plaintext, SecretKey key, byte[] associatedData) throws CryptoException {
            if (plaintext == null) throw new CryptoException("Plaintext cannot be null.");
            byte[] plainBytes = plaintext.getBytes(StandardCharsets.UTF_8);
            EncryptedPayload payload = encrypt(plainBytes, key, associatedData);
            return payload.toBase64();
        }

        public String decryptString(String base64Ciphertext, SecretKey key) throws CryptoException {
            return decryptString(base64Ciphertext, key, null);
        }

        public String decryptString(String base64Ciphertext, SecretKey key, byte[] associatedData) throws CryptoException {
            EncryptedPayload payload = EncryptedPayload.fromBase64(base64Ciphertext);
            byte[] decrypted = decrypt(payload, key, associatedData);
            return new String(decrypted, StandardCharsets.UTF_8);
        }

        public String encryptStringWithPassword(String plaintext, char[] password) throws CryptoException {
            return encryptStringWithPassword(plaintext, password, null);
        }

        public String encryptStringWithPassword(String plaintext, char[] password, byte[] associatedData) throws CryptoException {
            if (plaintext == null) throw new CryptoException("Plaintext cannot be null.");
            byte[] plainBytes = plaintext.getBytes(StandardCharsets.UTF_8);
            EncryptedPayload payload = encryptWithPassword(plainBytes, password, associatedData);
            return payload.toBase64();
        }

        public String decryptStringWithPassword(String base64Ciphertext, char[] password) throws CryptoException {
            return decryptStringWithPassword(base64Ciphertext, password, null);
        }

        public String decryptStringWithPassword(String base64Ciphertext, char[] password, byte[] associatedData) throws CryptoException {
            EncryptedPayload payload = EncryptedPayload.fromBase64(base64Ciphertext);
            byte[] decrypted = decryptWithPassword(payload, password, associatedData);
            return new String(decrypted, StandardCharsets.UTF_8);
        }
    }

    // =========================================================================
    // Memory Hygiene Utilities
    // =========================================================================
    /**
     * Overwrites sensitive character arrays in memory with null bytes.
     */
    public static void wipe(char[] chars) {
        if (chars != null) {
            Arrays.fill(chars, '\0');
        }
    }

    /**
     * Overwrites sensitive byte arrays in memory with zeros.
     */
    public static void wipe(byte[] bytes) {
        if (bytes != null) {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    // =========================================================================
    // Command Line Interface & Demonstration
    // =========================================================================

    public static void main(String[] args) {
        if (args.length == 0 || args[0].equalsIgnoreCase("help") || args[0].equals("-h") || args[0].equals("--help")) {
            printUsage();
            return;
        }

        String command = args[0].toLowerCase();
        try {
            switch (command) {
                case "demo":
                    runComprehensiveDemo();
                    break;
                case "init-keystore":
                    handleInitKeystore(args);
                    break;
                case "generate-key":
                    handleGenerateKey(args);
                    break;
                case "list-keys":
                    handleListKeys(args);
                    break;
                case "encrypt":
                    handleEncrypt(args);
                    break;
                case "decrypt":
                    handleDecrypt(args);
                    break;
                default:
                    System.err.println("Error: Unknown command '" + command + "'.");
                    printUsage();
                    System.exit(1);
            }
        } catch (CryptoException e) {
            System.err.println("\n[CRYPTO ERROR] " + e.getMessage());
            if (e.getCause() != null && !(e.getCause() instanceof AEADBadTagException)) {
                System.err.println("Caused by: " + e.getCause().getMessage());
            }
            System.exit(2);
        } catch (Exception e) {
            System.err.println("\n[SYSTEM ERROR] " + e.getMessage());
            e.printStackTrace();
            System.exit(3);
        }
    }

    private static void handleInitKeystore(String[] args) throws Exception {
        String keystorePathStr = getRequiredArg(args, "-k", "--keystore");
        char[] password = getOptionalPassword(args, "-p", "--password", "Enter master password for new KeyStore: ");
        try {
            Path path = Paths.get(keystorePathStr);
            if (Files.exists(path)) {
                System.err.println("Error: File already exists at " + path);
                System.exit(1);
            }
            KeyStoreManager.createKeyStore(path, password);
            System.out.println("Initialized empty PKCS#12 KeyStore at: " + path.toAbsolutePath());
        } finally {
            wipe(password);
        }
    }

    private static void handleGenerateKey(String[] args) throws Exception {
        String keystorePathStr = getRequiredArg(args, "-k", "--keystore");
        String alias = getRequiredArg(args, "-a", "--alias");

        char[] keystorePassword = getOptionalPassword(args, "-kp", "--keystore-pass", "Enter KeyStore master password: ");
        char[] keyPassword = getOptionalPassword(args, "-p", "--key-pass", "Enter protection password for key alias '" + alias + "' (press Enter to use keystore password): ");
        if (keyPassword.length == 0) {
            keyPassword = keystorePassword.clone();
        }

        try {
            Path path = Paths.get(keystorePathStr);
            KeyStoreManager.generateAndStoreKey(path, keystorePassword, alias, keyPassword);
            System.out.println("Successfully generated 256-bit AES key and stored under alias '" + alias + "' in " + path.toAbsolutePath());
        } finally {
            wipe(keystorePassword);
            wipe(keyPassword);
        }
    }

    private static void handleListKeys(String[] args) throws Exception {
        String keystorePathStr = getRequiredArg(args, "-k", "--keystore");
        char[] keystorePassword = getOptionalPassword(args, "-p", "--password", "Enter KeyStore master password: ");
        try {
            Path path = Paths.get(keystorePathStr);
            List<String> aliases = KeyStoreManager.listAliases(path, keystorePassword);
            System.out.println("KeyStore: " + path.toAbsolutePath());
            System.out.println("Stored key aliases (" + aliases.size() + "):");
            for (String alias : aliases) {
                System.out.println("  - " + alias);
            }
        } finally {
            wipe(keystorePassword);
        }
    }

    private static void handleEncrypt(String[] args) throws Exception {
        byte[] inputData = getInputBytes(args);
        String aadStr = getOptionalArg(args, "--aad");
        byte[] aad = aadStr != null ? aadStr.getBytes(StandardCharsets.UTF_8) : null;
        String outputFile = getOptionalArg(args, "-o", "--out");

        SymmetricEncryptionService service = new SymmetricEncryptionService();
        EncryptedPayload payload;

        String keystorePath = getOptionalArg(args, "-k", "--keystore");
        if (keystorePath != null) {
            String alias = getRequiredArg(args, "-a", "--alias");
            char[] ksPassword = getOptionalPassword(args, "-kp", "--keystore-pass", "Enter KeyStore master password: ");
            char[] keyPassword = getOptionalPassword(args, "-p", "--key-pass", "Enter protection password for key '" + alias + "': ");
            if (keyPassword.length == 0) keyPassword = ksPassword.clone();

            try {
                SecretKey key = KeyStoreManager.loadKey(Paths.get(keystorePath), ksPassword, alias, keyPassword);
                payload = service.encrypt(inputData, key, aad);
            } finally {
                wipe(ksPassword);
                wipe(keyPassword);
            }
        } else {
            // Password-based encryption mode
            char[] password = getOptionalPassword(args, "-p", "--password", "Enter encryption password: ");
            try {
                payload = service.encryptWithPassword(inputData, password, aad);
            } finally {
                wipe(password);
            }
        }

        outputResult(payload.toBase64(), outputFile);
    }

    private static void handleDecrypt(String[] args) throws Exception {
        String ciphertextBase64 = getInputString(args);
        EncryptedPayload payload = EncryptedPayload.fromBase64(ciphertextBase64);

        String aadStr = getOptionalArg(args, "--aad");
        byte[] aad = aadStr != null ? aadStr.getBytes(StandardCharsets.UTF_8) : null;
        String outputFile = getOptionalArg(args, "-o", "--out");

        SymmetricEncryptionService service = new SymmetricEncryptionService();
        byte[] decryptedBytes;

        if (payload.getVersion() == PAYLOAD_VERSION_KEYSTORE) {
            String keystorePath = getRequiredArg(args, "-k", "--keystore");
            String alias = getRequiredArg(args, "-a", "--alias");
            char[] ksPassword = getOptionalPassword(args, "-kp", "--keystore-pass", "Enter KeyStore master password: ");
            char[] keyPassword = getOptionalPassword(args, "-p", "--key-pass", "Enter protection password for key '" + alias + "': ");
            if (keyPassword.length == 0) keyPassword = ksPassword.clone();

            try {
                SecretKey key = KeyStoreManager.loadKey(Paths.get(keystorePath), ksPassword, alias, keyPassword);
                decryptedBytes = service.decrypt(payload, key, aad);
            } finally {
                wipe(ksPassword);
                wipe(keyPassword);
            }
        } else if (payload.getVersion() == PAYLOAD_VERSION_PBKDF2) {
            char[] password = getOptionalPassword(args, "-p", "--password", "Enter decryption password: ");
            try {
                decryptedBytes = service.decryptWithPassword(payload, password, aad);
            } finally {
                wipe(password);
            }
        } else {
            throw new CryptoException("Unknown payload format version.");
        }

        if (outputFile != null) {
            Files.write(Paths.get(outputFile), decryptedBytes);
            System.out.println("Decrypted data written to: " + outputFile);
        } else {
            String text = new String(decryptedBytes, StandardCharsets.UTF_8);
            System.out.println(text);
        }
    }

    // =========================================================================
    // Automated Comprehensive Demonstration
    // =========================================================================
    /**
     * Executes a complete, automated demonstration of all cryptographic capabilities:
     * 1. Secure AES-256 key generation
     * 2. Storage in a PKCS#12 KeyStore with POSIX permissions
     * 3. Retrieval from KeyStore
     * 4. AES-GCM encryption with 12-byte IV and 128-bit authentication tag
     * 5. Successful decryption and roundtrip validation
     * 6. Tamper detection (AEADBadTagException verification)
     * 7. Authenticated Associated Data (AAD) binding and mismatch detection
     * 8. Password-Based Encryption via PBKDF2WithHmacSHA256
     * 9. Memory wiping demonstration
     */
    public static void runComprehensiveDemo() {
        System.out.println("===============================================================================");
        System.out.println("           COMPREHENSIVE SYMMETRIC CRYPTOGRAPHY DEMONSTRATION                  ");
        System.out.println("===============================================================================");
        System.out.println("Features: AES-256-GCM | PKCS#12 KeyStore | PBKDF2-HMAC-SHA256 | AAD | Tamper Check\n");

        Path demoKeystore = Paths.get("demo_keystore.p12");
        char[] keystorePass = "MasterKeystorePassword#2026".toCharArray();
        char[] keyPass = "KeySpecificPassword$9876".toCharArray();
        String keyAlias = "app-sensitive-data-key";

        try {
            // Step 1: KeyStore Creation and Key Generation
            System.out.println("[Step 1] Initializing PKCS#12 KeyStore and Generating AES-256 Symmetric Key...");
            Files.deleteIfExists(demoKeystore);
            SecretKey generatedKey = KeyStoreManager.generateAndStoreKey(demoKeystore, keystorePass, keyAlias, keyPass);
            System.out.println("  -> Created KeyStore: " + demoKeystore.toAbsolutePath());
            System.out.println("  -> Generated Key Algorithm: " + generatedKey.getAlgorithm());
            System.out.println("  -> Key Size: " + (generatedKey.getEncoded().length * 8) + " bits (AES-256)");
            System.out.println("  -> Stored under alias: '" + keyAlias + "' with dual-password protection.");

            // Step 2: Key Retrieval from KeyStore
            System.out.println("\n[Step 2] Retrieving Key from KeyStore...");
            SecretKey loadedKey = KeyStoreManager.loadKey(demoKeystore, keystorePass, keyAlias, keyPass);
            boolean keysMatch = Arrays.equals(generatedKey.getEncoded(), loadedKey.getEncoded());
            System.out.println("  -> Successfully loaded key from keystore.");
            System.out.println("  -> Key equality verified: " + keysMatch);

            // Step 3: Encrypting Sensitive Application Data with AES-GCM
            System.out.println("\n[Step 3] Encrypting Sensitive Application Data...");
            String sensitivePlaintext = "{\"userId\":\"usr_998811\",\"ssn\":\"***-**-8421\",\"creditCard\":\"4111-2222-3333-4444\",\"balance\":28540.75}";
            System.out.println("  -> Sensitive Plaintext Data: " + sensitivePlaintext);

            SymmetricEncryptionService cryptoService = new SymmetricEncryptionService();
            EncryptedPayload encryptedPayload = cryptoService.encrypt(
                    sensitivePlaintext.getBytes(StandardCharsets.UTF_8),
                    loadedKey,
                    null
            );

            System.out.println("  -> Generated 12-byte IV (Hex): " + bytesToHex(encryptedPayload.getIv()));
            System.out.println("  -> Ciphertext + Tag length: " + encryptedPayload.getCiphertextAndTag().length + " bytes (includes 16-byte GCM tag)");
            String base64Payload = encryptedPayload.toBase64();
            System.out.println("  -> Base64 Encrypted Container: " + base64Payload);

            // Step 4: Decrypting and Validating Roundtrip
            System.out.println("\n[Step 4] Decrypting Ciphertext Container...");
            EncryptedPayload parsedPayload = EncryptedPayload.fromBase64(base64Payload);
            byte[] decryptedBytes = cryptoService.decrypt(parsedPayload, loadedKey, null);
            String recoveredText = new String(decryptedBytes, StandardCharsets.UTF_8);
            System.out.println("  -> Decrypted Text: " + recoveredText);
            boolean roundtripSuccess = sensitivePlaintext.equals(recoveredText);
            System.out.println("  -> Integrity & Confidentiality verified: " + (roundtripSuccess ? "SUCCESS" : "FAILED"));

            // Step 5: Tamper Detection (AEAD Integrity Check)
            System.out.println("\n[Step 5] Demonstrating Tamper Detection (AEAD Integrity Check)...");
            byte[] tamperedBytes = encryptedPayload.toByteArray();
            // Flip a single bit in the ciphertext / tag region
            tamperedBytes[tamperedBytes.length - 1] ^= 0x01;
            System.out.println("  -> Intentionally corrupted 1 bit in the ciphertext/auth-tag.");
            try {
                EncryptedPayload tamperedPayload = EncryptedPayload.fromByteArray(tamperedBytes);
                cryptoService.decrypt(tamperedPayload, loadedKey, null);
                System.err.println("  -> [FAIL] Tampered data was unexpectedly accepted!");
            } catch (CryptoException e) {
                System.out.println("  -> [SUCCESS] Tampering was detected and blocked by GCM authentication tag:");
                System.out.println("     \"" + e.getMessage() + "\"");
            }

            // Step 6: Authenticated Associated Data (AAD) Demonstration
            System.out.println("\n[Step 6] Demonstrating Authenticated Associated Data (AAD)...");
            String tenantContextAAD = "tenant-id:enterprise-alpha;record-id:rec-10029";
            byte[] aadBytes = tenantContextAAD.getBytes(StandardCharsets.UTF_8);
            System.out.println("  -> Binding Ciphertext to Context Metadata (AAD): " + tenantContextAAD);

            EncryptedPayload aadPayload = cryptoService.encrypt(
                    sensitivePlaintext.getBytes(StandardCharsets.UTF_8),
                    loadedKey,
                    aadBytes
            );

            // Decrypt with correct AAD
            byte[] aadDecrypted = cryptoService.decrypt(aadPayload, loadedKey, aadBytes);
            System.out.println("  -> Decryption with matching AAD: SUCCESS (" + new String(aadDecrypted, StandardCharsets.UTF_8) + ")");

            // Decrypt with forged/altered AAD
            byte[] forgedAAD = "tenant-id:rogue-tenant;record-id:rec-10029".getBytes(StandardCharsets.UTF_8);
            try {
                cryptoService.decrypt(aadPayload, loadedKey, forgedAAD);
                System.err.println("  -> [FAIL] Forged AAD was unexpectedly accepted!");
            } catch (CryptoException e) {
                System.out.println("  -> [SUCCESS] Context swapping blocked! Decryption with altered AAD failed as expected:");
                System.out.println("     \"" + e.getMessage() + "\"");
            }

            // Step 7: Password-Based Encryption via PBKDF2 Key Derivation
            System.out.println("\n[Step 7] Demonstrating Password-Based Encryption (PBKDF2-HMAC-SHA256 + AES-GCM)...");
            char[] userPassword = "SuperStrongUserPassword@2026!".toCharArray();
            String recordData = "Confidential Employee Compensation: $195,000/yr + Equity";

            String pwBase64 = cryptoService.encryptStringWithPassword(recordData, userPassword);
            System.out.println("  -> Encrypted with Password (Base64): " + pwBase64);

            String pwDecrypted = cryptoService.decryptStringWithPassword(pwBase64, userPassword);
            System.out.println("  -> Decrypted with Password: " + pwDecrypted);

            // Try with incorrect password
            char[] wrongPassword = "WrongPassword#1234".toCharArray();
            try {
                cryptoService.decryptStringWithPassword(pwBase64, wrongPassword);
                System.err.println("  -> [FAIL] Wrong password was unexpectedly accepted!");
            } catch (CryptoException e) {
                System.out.println("  -> [SUCCESS] Decryption with incorrect password correctly rejected:");
                System.out.println("     \"" + e.getMessage() + "\"");
            } finally {
                wipe(wrongPassword);
            }

            // Step 8: Memory Hygiene
            System.out.println("\n[Step 8] Demonstrating In-Memory Cryptographic Hygiene...");
            wipe(keystorePass);
            wipe(keyPass);
            wipe(userPassword);
            System.out.println("  -> Sensitive char[] and byte[] arrays securely wiped with null bytes.");

            System.out.println("\n===============================================================================");
            System.out.println("               DEMONSTRATION COMPLETED SUCCESSFULLY!                           ");
            System.out.println("===============================================================================");
        } catch (Exception e) {
            System.err.println("\n[DEMO FAILED] " + e.getMessage());
            e.printStackTrace();
        } finally {
            // Clean up demonstration file
            try {
                Files.deleteIfExists(demoKeystore);
            } catch (IOException ignored) {}
            wipe(keystorePass);
            wipe(keyPass);
        }
    }

    // =========================================================================
    // CLI Helper Utilities
    // =========================================================================

    private static String getRequiredArg(String[] args, String... flags) {
        String val = getOptionalArg(args, flags);
        if (val == null) {
            System.err.println("Error: Missing required option: " + Arrays.toString(flags));
            printUsage();
            System.exit(1);
        }
        return val;
    }

    private static String getOptionalArg(String[] args, String... flags) {
        for (int i = 0; i < args.length; i++) {
            for (String flag : flags) {
                if (args[i].equalsIgnoreCase(flag)) {
                    if (i + 1 < args.length && !args[i + 1].startsWith("-")) {
                        return args[i + 1];
                    }
                }
            }
        }
        return null;
    }

    private static char[] getOptionalPassword(String[] args, String flagShort, String flagLong, String prompt) {
        String pwd = getOptionalArg(args, flagShort, flagLong);
        if (pwd != null) {
            return pwd.toCharArray();
        }

        // Prompt interactively if console is available
        Console console = System.console();
        if (console != null) {
            char[] read = console.readPassword(prompt);
            return read != null ? read : new char[0];
        }

        // Fallback for non-interactive / piped environments
        Scanner scanner = new Scanner(System.in);
        if (System.in != null && scanner.hasNextLine()) {
            System.out.print(prompt);
            String line = scanner.nextLine();
            return line.toCharArray();
        }

        return new char[0];
    }

    private static byte[] getInputBytes(String[] args) throws IOException {
        String text = getOptionalArg(args, "-t", "--text");
        if (text != null) {
            return text.getBytes(StandardCharsets.UTF_8);
        }

        String file = getOptionalArg(args, "-i", "--in");
        if (file != null) {
            return Files.readAllBytes(Paths.get(file));
        }

        // Read from standard input
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[4096];
            int n;
            while ((n = System.in.read(buf)) != -1) {
                baos.write(buf, 0, n);
            }
            if (baos.size() == 0) {
                System.err.println("Error: No input provided via --text, --in, or stdin.");
                System.exit(1);
            }
            return baos.toByteArray();
        }
    }

    private static String getInputString(String[] args) throws IOException {
        String text = getOptionalArg(args, "-t", "--text");
        if (text != null) {
            return text.trim();
        }

        String file = getOptionalArg(args, "-i", "--in");
        if (file != null) {
            return Files.readString(Paths.get(file)).trim();
        }

        // Read from stdin
        Scanner scanner = new Scanner(System.in);
        StringBuilder sb = new StringBuilder();
        while (scanner.hasNextLine()) {
            sb.append(scanner.nextLine().trim());
        }
        if (sb.length() == 0) {
            System.err.println("Error: No ciphertext provided via --text, --in, or stdin.");
            System.exit(1);
        }
        return sb.toString();
    }

    private static void outputResult(String text, String outputFile) throws IOException {
        if (outputFile != null) {
            Files.writeString(Paths.get(outputFile), text, StandardCharsets.UTF_8);
            System.out.println("Result written to: " + outputFile);
        } else {
            System.out.println(text);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static void printUsage() {
        System.out.println("===============================================================================");
        System.out.println("                    SymmetricCryptoApp - CLI Usage Guide                      ");
        System.out.println("===============================================================================");
        System.out.println("A complete Java symmetric encryption & key management utility using AES-256-GCM.");
        System.out.println("\nCOMMANDS:");
        System.out.println("  demo");
        System.out.println("      Runs an automated end-to-end demonstration of key generation, PKCS12 storage,");
        System.out.println("      encryption, decryption, tampering detection, AAD, and PBKDF2 derivation.\n");

        System.out.println("  init-keystore -k <keystore-path> [-p <password>]");
        System.out.println("      Initializes a new, empty PKCS#12 (.p12) keystore file.\n");

        System.out.println("  generate-key -k <keystore-path> -a <alias> [-kp <keystore-pass>] [-p <key-pass>]");
        System.out.println("      Generates a secure 256-bit AES key and saves it into the KeyStore.\n");

        System.out.println("  list-keys -k <keystore-path> [-p <password>]");
        System.out.println("      Lists all stored key aliases within the KeyStore.\n");

        System.out.println("  encrypt [options]");
        System.out.println("      Encrypts data using either a KeyStore key or a password.");
        System.out.println("      KeyStore mode options:  -k <keystore> -a <alias> [-kp <ks-pass>] [-p <key-pass>]");
        System.out.println("      Password mode options:  -p <password>");
        System.out.println("      Input options:          -t <plaintext> OR -i <input-file> OR stdin");
        System.out.println("      Output options:         -o <output-file> (defaults to stdout in Base64)");
        System.out.println("      Metadata option:        --aad <associated-data-string>\n");

        System.out.println("  decrypt [options]");
        System.out.println("      Decrypts Base64 ciphertext using either a KeyStore key or a password.");
        System.out.println("      KeyStore mode options:  -k <keystore> -a <alias> [-kp <ks-pass>] [-p <key-pass>]");
        System.out.println("      Password mode options:  -p <password>");
        System.out.println("      Input options:          -t <base64-ciphertext> OR -i <input-file> OR stdin");
        System.out.println("      Output options:         -o <output-file> (defaults to stdout)");
        System.out.println("      Metadata option:        --aad <associated-data-string>\n");

        System.out.println("EXAMPLES:");
        System.out.println("  # 1. Run comprehensive self-test and demonstration:");
        System.out.println("      java SymmetricCryptoApp demo\n");

        System.out.println("  # 2. Generate an AES-256 key in a PKCS#12 keystore:");
        System.out.println("      java SymmetricCryptoApp generate-key -k mykeys.p12 -a customer-dek -kp MyPass123! -p KeySecret456!\n");

        System.out.println("  # 3. Encrypt sensitive text using the keystore key:");
        System.out.println("      java SymmetricCryptoApp encrypt -k mykeys.p12 -a customer-dek -kp MyPass123! -p KeySecret456! -t \"Secret Data\"\n");

        System.out.println("  # 4. Decrypt ciphertext:");
        System.out.println("      java SymmetricCryptoApp decrypt -k mykeys.p12 -a customer-dek -kp MyPass123! -p KeySecret456! -t \"<base64-payload>\"\n");

        System.out.println("  # 5. Encrypt sensitive text using direct password derivation (PBKDF2):");
        System.out.println("      java SymmetricCryptoApp encrypt -p \"StrongPassword123!\" -t \"Confidential Message\"\n");

        System.out.println("  # 6. Decrypt password-derived ciphertext:");
        System.out.println("      java SymmetricCryptoApp decrypt -p \"StrongPassword123!\" -t \"<base64-payload>\"\n");
        System.out.println("===============================================================================");
    }
}
