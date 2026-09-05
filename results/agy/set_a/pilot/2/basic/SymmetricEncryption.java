import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * Robust symmetric encryption utility utilizing AES in GCM (Galois/Counter Mode) mode.
 * 
 * AES-GCM is an Authenticated Encryption with Associated Data (AEAD) cipher mode that provides
 * both confidentiality and cryptographic integrity/authenticity without requiring a separate HMAC.
 */
public class SymmetricEncryption {

    // Standard cryptographic configuration
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA256";

    // Recommended parameters according to NIST SP 800-38D & OWASP guidelines
    public static final int AES_KEY_SIZE_BITS = 256;      // 256-bit AES key
    public static final int GCM_IV_LENGTH_BYTES = 12;     // 96-bit IV (12 bytes) recommended for GCM
    public static final int GCM_TAG_LENGTH_BITS = 128;    // 128-bit authentication tag
    public static final int PBKDF2_ITERATIONS = 100_000;  // PBKDF2 iteration count
    public static final int SALT_LENGTH_BYTES = 16;       // 128-bit salt

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Generates a cryptographically strong random AES symmetric key.
     *
     * @param keyBitSize Key size in bits (128, 192, or 256)
     * @return A newly generated SecretKey
     * @throws NoSuchAlgorithmException if AES is not supported by the security provider
     */
    public static SecretKey generateKey(int keyBitSize) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM);
        keyGenerator.init(keyBitSize, SECURE_RANDOM);
        return keyGenerator.generateKey();
    }

    /**
     * Generates a standard 256-bit AES symmetric key.
     *
     * @return 256-bit SecretKey
     * @throws NoSuchAlgorithmException if AES is not supported
     */
    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        return generateKey(AES_KEY_SIZE_BITS);
    }

    /**
     * Derives a 256-bit AES SecretKey from a user password and salt using PBKDF2.
     *
     * @param password Password character array
     * @param salt     Cryptographically secure random salt
     * @return Derived SecretKey
     * @throws GeneralSecurityException if key derivation fails
     */
    public static SecretKey deriveKeyFromPassword(char[] password, byte[] salt) throws GeneralSecurityException {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password cannot be null or empty.");
        }
        if (salt == null || salt.length < 16) {
            throw new IllegalArgumentException("Salt must be at least 16 bytes.");
        }

        SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALGORITHM);
        KeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, AES_KEY_SIZE_BITS);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, ENCRYPTION_ALGORITHM);
    }

    /**
     * Generates cryptographically secure random bytes (e.g., for salt or IV).
     *
     * @param length Number of bytes
     * @return Random byte array
     */
    public static byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }

    /**
     * Encrypts plaintext bytes using AES-GCM.
     * 
     * Output format: [12-byte IV] + [Ciphertext with 16-byte GCM authentication tag]
     *
     * @param plaintext Raw bytes to encrypt
     * @param key       SecretKey for encryption
     * @return Byte array containing IV followed by encrypted data + auth tag
     * @throws GeneralSecurityException on encryption failure
     */
    public static byte[] encrypt(byte[] plaintext, SecretKey key) throws GeneralSecurityException {
        if (plaintext == null) {
            throw new IllegalArgumentException("Plaintext cannot be null.");
        }
        if (key == null) {
            throw new IllegalArgumentException("Encryption key cannot be null.");
        }

        // Generate a fresh random Initialization Vector (IV) for every encryption
        byte[] iv = generateRandomBytes(GCM_IV_LENGTH_BYTES);

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

        byte[] ciphertext = cipher.doFinal(plaintext);

        // Prepend IV to ciphertext for storage/transmission
        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + ciphertext.length);
        byteBuffer.put(iv);
        byteBuffer.put(ciphertext);
        return byteBuffer.array();
    }

    /**
     * Encrypts a plaintext string and returns a Base64-encoded representation.
     *
     * @param plaintext Plaintext string to encrypt
     * @param key       SecretKey for encryption
     * @return Base64-encoded encrypted payload containing IV and ciphertext+tag
     * @throws GeneralSecurityException on encryption failure
     */
    public static String encrypt(String plaintext, SecretKey key) throws GeneralSecurityException {
        if (plaintext == null) {
            throw new IllegalArgumentException("Plaintext string cannot be null.");
        }
        byte[] encryptedBytes = encrypt(plaintext.getBytes(StandardCharsets.UTF_8), key);
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * Decrypts combined [IV + Ciphertext + Tag] byte array back to plaintext bytes.
     *
     * @param encryptedData Combined byte array of IV and ciphertext with auth tag
     * @param key           SecretKey used for decryption
     * @return Decrypted plaintext bytes
     * @throws GeneralSecurityException if decryption or authentication fails (e.g. tampering)
     */
    public static byte[] decrypt(byte[] encryptedData, SecretKey key) throws GeneralSecurityException {
        if (encryptedData == null) {
            throw new IllegalArgumentException("Encrypted data cannot be null.");
        }
        if (key == null) {
            throw new IllegalArgumentException("Decryption key cannot be null.");
        }

        int minLength = GCM_IV_LENGTH_BYTES + (GCM_TAG_LENGTH_BITS / Byte.SIZE);
        if (encryptedData.length < minLength) {
            throw new IllegalArgumentException(
                    "Invalid ciphertext length: must be at least " + minLength + " bytes."
            );
        }

        // Extract IV and Ciphertext
        ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedData);
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        byteBuffer.get(iv);

        byte[] ciphertext = new byte[byteBuffer.remaining()];
        byteBuffer.get(ciphertext);

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

        return cipher.doFinal(ciphertext);
    }

    /**
     * Decrypts a Base64-encoded ciphertext string back to the original plaintext string.
     *
     * @param base64EncryptedData Base64 string containing IV and ciphertext+tag
     * @param key                 SecretKey used for decryption
     * @return Original plaintext string
     * @throws GeneralSecurityException if decryption fails or authentication tag is invalid
     */
    public static String decrypt(String base64EncryptedData, SecretKey key) throws GeneralSecurityException {
        if (base64EncryptedData == null) {
            throw new IllegalArgumentException("Ciphertext cannot be null.");
        }
        byte[] decodedBytes = Base64.getDecoder().decode(base64EncryptedData);
        byte[] decryptedBytes = decrypt(decodedBytes, key);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    /**
     * Encodes a SecretKey to its Base64 string representation.
     *
     * @param key SecretKey
     * @return Base64-encoded key string
     */
    public static String encodeKeyToBase64(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Reconstructs a SecretKey from its Base64 string representation.
     *
     * @param base64Key Base64 encoded key
     * @return Reconstituted SecretKey
     */
    public static SecretKey decodeKeyFromBase64(String base64Key) {
        byte[] decodedKey = Base64.getDecoder().decode(base64Key);
        return new SecretKeySpec(decodedKey, ENCRYPTION_ALGORITHM);
    }

    /**
     * Demonstrates complete encryption and decryption workflow including:
     * 1. Random AES-256 key generation
     * 2. Encrypting sensitive data
     * 3. Decrypting ciphertext back to original data
     * 4. Authenticated data tampering detection
     * 5. Password-based key derivation (PBKDF2) encryption and decryption
     */
    public static void main(String[] args) {
        try {
            System.out.println("===============================================================");
            System.out.println("       Java Symmetric Encryption Demonstration (AES-GCM)       ");
            System.out.println("===============================================================\n");

            // 1. Generate a random AES 256-bit symmetric key
            System.out.println("[Step 1] Generating 256-bit AES Symmetric Key...");
            SecretKey secretKey = generateKey();
            String base64Key = encodeKeyToBase64(secretKey);
            System.out.println("Generated Secret Key (Base64): " + base64Key);
            System.out.println("Key Algorithm: " + secretKey.getAlgorithm());
            System.out.println("Key Length: " + (secretKey.getEncoded().length * 8) + " bits\n");

            // 2. Sensitive application data to encrypt
            String originalSensitiveData = "{\"userId\": 42, \"ssn\": \"123-45-6789\", \"creditCard\": \"4111-2222-3333-4444\"}";
            System.out.println("[Step 2] Original Plaintext Data:");
            System.out.println("---------------------------------------------------------------");
            System.out.println(originalSensitiveData);
            System.out.println("---------------------------------------------------------------\n");

            // 3. Encrypt data
            System.out.println("[Step 3] Encrypting Data with AES/GCM/NoPadding...");
            String ciphertext = encrypt(originalSensitiveData, secretKey);
            System.out.println("Ciphertext Payload (Base64):");
            System.out.println(ciphertext);
            System.out.println("(Payload structure: [12-byte IV] + [Encrypted Data] + [16-byte Auth Tag])\n");

            // 4. Decrypt data
            System.out.println("[Step 4] Decrypting Ciphertext back to Plaintext...");
            String decryptedData = decrypt(ciphertext, secretKey);
            System.out.println("Decrypted Data:");
            System.out.println("---------------------------------------------------------------");
            System.out.println(decryptedData);
            System.out.println("---------------------------------------------------------------");
            boolean matches = originalSensitiveData.equals(decryptedData);
            System.out.println("Integrity Check Passed: " + matches + "\n");

            // 5. Demonstrate Tamper Detection (Authentication Tag Validation)
            System.out.println("[Step 5] Demonstrating Integrity Protection (Tamper Detection)...");
            byte[] tamperedBytes = Base64.getDecoder().decode(ciphertext);
            // Flip the last bit of the payload (corrupting the ciphertext/tag)
            tamperedBytes[tamperedBytes.length - 1] ^= 0x01;
            String tamperedCiphertext = Base64.getEncoder().encodeToString(tamperedBytes);

            try {
                System.out.println("Attempting to decrypt tampered ciphertext...");
                decrypt(tamperedCiphertext, secretKey);
                System.err.println("WARNING: Tampered ciphertext was accepted! (Unexpected)");
            } catch (AEADBadTagException e) {
                System.out.println("SUCCESS: AEAD detected tampering! Decryption failed with: " + e.getClass().getSimpleName());
                System.out.println("Details: " + e.getMessage() + "\n");
            }

            // 6. Demonstrate Password-Derived Key (PBKDF2)
            System.out.println("[Step 6] Demonstrating Password-Based Symmetric Encryption (PBKDF2)...");
            char[] userPassword = "MySuperSecretApplicationMasterPassword!".toCharArray();
            byte[] salt = generateRandomBytes(SALT_LENGTH_BYTES);
            System.out.println("Deriving AES key from user password using PBKDF2WithHmacSHA256 (100,000 iterations)...");
            SecretKey passwordDerivedKey = deriveKeyFromPassword(userPassword, salt);

            String secretMessage = "Sensitive API Secret: sk_live_51M0abcdef1234567890";
            String encryptedWithPassword = encrypt(secretMessage, passwordDerivedKey);
            System.out.println("Encrypted with password-derived key: " + encryptedWithPassword);

            String decryptedWithPassword = decrypt(encryptedWithPassword, passwordDerivedKey);
            System.out.println("Decrypted with password-derived key: " + decryptedWithPassword);
            System.out.println("Password decryption successful: " + secretMessage.equals(decryptedWithPassword) + "\n");

            // Clear sensitive password array from memory
            Arrays.fill(userPassword, '\0');

            System.out.println("===============================================================");
            System.out.println("                  Demonstration Completed                      ");
            System.out.println("===============================================================");

        } catch (Exception e) {
            System.err.println("Cryptographic operation failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
