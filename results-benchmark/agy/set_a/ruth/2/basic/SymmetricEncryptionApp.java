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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

/**
 * SymmetricEncryptionApp
 *
 * A comprehensive, production-grade Java application demonstrating symmetric encryption
 * and decryption of sensitive application data using standard Java Cryptography Architecture (JCA) APIs.
 *
 * Key Cryptographic Properties:
 * - Cipher Algorithm: AES (Advanced Encryption Standard)
 * - Mode of Operation: GCM (Galois/Counter Mode) - provides Authenticated Encryption with Associated Data (AEAD)
 * - Padding: NoPadding (GCM is a stream-cipher mode and does not require block padding)
 * - Key Length: 256 bits (AES-256)
 * - Initialization Vector (IV): 96 bits (12 bytes) uniquely generated per encryption via SecureRandom
 * - Authentication Tag Length: 128 bits (16 bytes) to protect confidentiality and integrity
 * - Key Derivation (Password-based): PBKDF2 with HMAC-SHA256 and 310,000 iterations (OWASP recommended)
 */
public class SymmetricEncryptionApp {

    // Cryptographic configuration constants
    public static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    public static final String KEY_ALGORITHM = "AES";
    public static final int AES_KEY_SIZE_BITS = 256;
    public static final int GCM_IV_LENGTH_BYTES = 12;      // 96 bits recommended for AES-GCM
    public static final int GCM_TAG_LENGTH_BITS = 128;     // 128-bit authentication tag
    public static final int PBKDF2_SALT_LENGTH_BYTES = 16; // 128-bit salt
    public static final int PBKDF2_ITERATIONS = 310_000;    // Current OWASP recommendation for PBKDF2-HMAC-SHA256
    public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // =========================================================================
    // Key Management APIs
    // =========================================================================

    /**
     * Generates a cryptographically strong 256-bit AES secret key.
     *
     * @return SecretKey suitable for AES-256 encryption/decryption
     * @throws NoSuchAlgorithmException if AES key generation is unavailable
     */
    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
        keyGenerator.init(AES_KEY_SIZE_BITS, SECURE_RANDOM);
        return keyGenerator.generateKey();
    }

    /**
     * Encodes a SecretKey into a Base64-encoded string representation.
     *
     * @param secretKey the key to encode
     * @return Base64-encoded string
     */
    public static String encodeKeyToBase64(SecretKey secretKey) {
        if (secretKey == null) {
            throw new IllegalArgumentException("Secret key cannot be null.");
        }
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    /**
     * Decodes a Base64-encoded string back into an AES SecretKey.
     *
     * @param base64Key Base64-encoded key string
     * @return reconstituted SecretKey
     * @throws IllegalArgumentException if the key string is invalid or incorrect size
     */
    public static SecretKey decodeKeyFromBase64(String base64Key) {
        if (base64Key == null || base64Key.trim().isEmpty()) {
            throw new IllegalArgumentException("Base64 key cannot be null or empty.");
        }
        byte[] keyBytes = Base64.getDecoder().decode(base64Key.trim());
        if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
            throw new IllegalArgumentException(
                "Invalid AES key length: " + (keyBytes.length * 8) + " bits. Expected 128, 192, or 256 bits."
            );
        }
        return new SecretKeySpec(keyBytes, KEY_ALGORITHM);
    }

    /**
     * Derives an AES-256 SecretKey from a password and salt using PBKDF2WithHmacSHA256.
     *
     * @param password user password
     * @param salt     random cryptographic salt
     * @return derived SecretKey
     * @throws GeneralSecurityException if key derivation fails
     */
    public static SecretKey deriveKeyFromPassword(char[] password, byte[] salt) throws GeneralSecurityException {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password cannot be null or empty.");
        }
        if (salt == null || salt.length < 16) {
            throw new IllegalArgumentException("Salt must be at least 16 bytes.");
        }

        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            KeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, AES_KEY_SIZE_BITS);
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(keyBytes, KEY_ALGORITHM);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new GeneralSecurityException("Failed to derive key from password: " + e.getMessage(), e);
        }
    }

    // =========================================================================
    // Core Symmetric Encryption and Decryption (Raw Bytes)
    // =========================================================================

    /**
     * Encrypts raw plaintext bytes using AES-GCM with a freshly generated random IV.
     *
     * The returned byte array packages the IV together with the ciphertext:
     * [ IV (12 bytes) ][ Ciphertext + GCM Tag (variable length) ]
     *
     * @param plaintextBytes data to encrypt
     * @param key            symmetric secret key
     * @return combined payload [IV + Ciphertext + Tag]
     * @throws GeneralSecurityException if encryption fails
     */
    public static byte[] encrypt(byte[] plaintextBytes, SecretKey key) throws GeneralSecurityException {
        if (plaintextBytes == null) {
            throw new IllegalArgumentException("Plaintext bytes cannot be null.");
        }
        if (key == null) {
            throw new IllegalArgumentException("Secret key cannot be null.");
        }

        // Generate a cryptographically secure, unique 12-byte IV for every encryption operation
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

        byte[] cipherTextWithTag = cipher.doFinal(plaintextBytes);

        // Prepend IV to ciphertext: [IV (12 bytes)][Ciphertext + Tag]
        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherTextWithTag.length);
        byteBuffer.put(iv);
        byteBuffer.put(cipherTextWithTag);
        return byteBuffer.array();
    }

    /**
     * Decrypts combined payload [IV + Ciphertext + Tag] back to raw plaintext bytes.
     *
     * @param encryptedPayload combined byte array [IV (12 bytes) + Ciphertext + Tag]
     * @param key              symmetric secret key used during encryption
     * @return decrypted plaintext bytes
     * @throws AEADBadTagException     if authentication tag verification fails (ciphertext was tampered or key is wrong)
     * @throws GeneralSecurityException if decryption fails
     */
    public static byte[] decrypt(byte[] encryptedPayload, SecretKey key) throws GeneralSecurityException {
        if (encryptedPayload == null) {
            throw new IllegalArgumentException("Encrypted payload cannot be null.");
        }
        if (key == null) {
            throw new IllegalArgumentException("Secret key cannot be null.");
        }
        if (encryptedPayload.length < GCM_IV_LENGTH_BYTES + (GCM_TAG_LENGTH_BITS / 8)) {
            throw new IllegalArgumentException(
                "Encrypted payload is too short to contain a valid IV and authentication tag."
            );
        }

        ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedPayload);

        // Extract IV
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        byteBuffer.get(iv);

        // Extract Ciphertext + Tag
        byte[] cipherTextWithTag = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherTextWithTag);

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

        return cipher.doFinal(cipherTextWithTag);
    }

    // =========================================================================
    // String Convenience APIs (Base64 Encoded)
    // =========================================================================

    /**
     * Encrypts a plaintext string using an AES SecretKey and returns a Base64-encoded string.
     *
     * @param plaintext UTF-8 string to encrypt
     * @param key       AES secret key
     * @return Base64-encoded string containing [IV + Ciphertext + Tag]
     * @throws GeneralSecurityException if encryption fails
     */
    public static String encryptString(String plaintext, SecretKey key) throws GeneralSecurityException {
        if (plaintext == null) {
            throw new IllegalArgumentException("Plaintext string cannot be null.");
        }
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedBytes = encrypt(plaintextBytes, key);
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * Decrypts a Base64-encoded string produced by encryptString using the corresponding AES SecretKey.
     *
     * @param base64Ciphertext Base64-encoded [IV + Ciphertext + Tag]
     * @param key              AES secret key
     * @return decrypted plaintext string (UTF-8)
     * @throws GeneralSecurityException if decryption or authentication fails
     */
    public static String decryptString(String base64Ciphertext, SecretKey key) throws GeneralSecurityException {
        if (base64Ciphertext == null || base64Ciphertext.trim().isEmpty()) {
            throw new IllegalArgumentException("Ciphertext cannot be null or empty.");
        }
        byte[] encryptedBytes = Base64.getDecoder().decode(base64Ciphertext.trim());
        byte[] decryptedBytes = decrypt(encryptedBytes, key);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    // =========================================================================
    // Password-based Encryption APIs (PBKDF2 + AES-GCM)
    // =========================================================================

    /**
     * Encrypts plaintext using a user-supplied password.
     * Generates a random salt, derives a 256-bit AES key, encrypts with AES-GCM,
     * and packages the payload as: [ Salt (16B) ][ IV (12B) ][ Ciphertext + Tag ].
     *
     * @param plaintext string to encrypt
     * @param password  passphrase
     * @return Base64-encoded payload
     * @throws GeneralSecurityException if derivation or encryption fails
     */
    public static String encryptWithPassword(String plaintext, char[] password) throws GeneralSecurityException {
        if (plaintext == null) {
            throw new IllegalArgumentException("Plaintext cannot be null.");
        }

        byte[] salt = new byte[PBKDF2_SALT_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(salt);

        SecretKey derivedKey = deriveKeyFromPassword(password, salt);
        byte[] ivAndCiphertext = encrypt(plaintext.getBytes(StandardCharsets.UTF_8), derivedKey);

        ByteBuffer byteBuffer = ByteBuffer.allocate(salt.length + ivAndCiphertext.length);
        byteBuffer.put(salt);
        byteBuffer.put(ivAndCiphertext);

        return Base64.getEncoder().encodeToString(byteBuffer.array());
    }

    /**
     * Decrypts a Base64-encoded payload created with encryptWithPassword.
     *
     * @param base64Payload Base64 string containing [ Salt (16B) ][ IV (12B) ][ Ciphertext + Tag ]
     * @param password      passphrase
     * @return decrypted plaintext string
     * @throws GeneralSecurityException if password is wrong or ciphertext is corrupted
     */
    public static String decryptWithPassword(String base64Payload, char[] password) throws GeneralSecurityException {
        if (base64Payload == null || base64Payload.trim().isEmpty()) {
            throw new IllegalArgumentException("Payload cannot be null or empty.");
        }

        byte[] payload = Base64.getDecoder().decode(base64Payload.trim());
        int minLength = PBKDF2_SALT_LENGTH_BYTES + GCM_IV_LENGTH_BYTES + (GCM_TAG_LENGTH_BITS / 8);
        if (payload.length < minLength) {
            throw new IllegalArgumentException("Payload too short for password-based encrypted data.");
        }

        ByteBuffer byteBuffer = ByteBuffer.wrap(payload);

        byte[] salt = new byte[PBKDF2_SALT_LENGTH_BYTES];
        byteBuffer.get(salt);

        byte[] ivAndCiphertext = new byte[byteBuffer.remaining()];
        byteBuffer.get(ivAndCiphertext);

        SecretKey derivedKey = deriveKeyFromPassword(password, salt);
        byte[] decryptedBytes = decrypt(ivAndCiphertext, derivedKey);

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    // =========================================================================
    // Automated Demonstration
    // =========================================================================

    /**
     * Runs an end-to-end demonstration illustrating key generation, encryption,
     * decryption, tamper detection, and password-based encryption.
     */
    public static void runDemonstration() {
        System.out.println("================================================================================");
        System.out.println("          Symmetric Encryption Demo (AES-256-GCM with Authenticated Tag)        ");
        System.out.println("================================================================================");

        try {
            // Step 1: Key Generation
            System.out.println("\n[1] Generating 256-bit AES Cryptographic Key...");
            SecretKey secretKey = generateKey();
            String base64Key = encodeKeyToBase64(secretKey);
            System.out.println("    Algorithm    : " + secretKey.getAlgorithm());
            System.out.println("    Key Size     : " + (secretKey.getEncoded().length * 8) + " bits");
            System.out.println("    Key (Base64) : " + base64Key);

            // Step 2: Sample Sensitive Application Data
            String sensitiveData = "{\"userId\":\"usr_99182\",\"ssn\":\"123-45-6789\",\"creditCard\":\"4111-2222-3333-4444\",\"balance\":12500.75}";
            System.out.println("\n[2] Original Sensitive Application Data (Plaintext):");
            System.out.println("    " + sensitiveData);

            // Step 3: Encryption
            System.out.println("\n[3] Encrypting with AES/GCM/NoPadding (12-byte random IV + 128-bit tag)...");
            String ciphertext = encryptString(sensitiveData, secretKey);
            System.out.println("    Encrypted Ciphertext (Base64 payload containing IV + Ciphertext + Tag):");
            System.out.println("    " + ciphertext);

            // Step 4: Decryption
            System.out.println("\n[4] Decrypting back to original plaintext...");
            String decryptedData = decryptString(ciphertext, secretKey);
            System.out.println("    Decrypted Plaintext:");
            System.out.println("    " + decryptedData);

            boolean matches = sensitiveData.equals(decryptedData);
            System.out.println("    Integrity Check: " + (matches ? "SUCCESS (Data matches perfectly!)" : "FAILED"));

            // Step 5: Tamper-resistance verification (AEAD protection)
            System.out.println("\n[5] Demonstrating Tamper Detection (Integrity & Authenticity Protection):");
            byte[] rawPayload = Base64.getDecoder().decode(ciphertext);
            // Flip the last byte of the payload (which is part of the GCM authentication tag)
            rawPayload[rawPayload.length - 1] ^= 0x01;
            String tamperedCiphertext = Base64.getEncoder().encodeToString(rawPayload);
            System.out.println("    Simulating bit flip in ciphertext: " + tamperedCiphertext);

            try {
                decryptString(tamperedCiphertext, secretKey);
                System.out.println("    ERROR: Tampered data was accepted unexpectedly!");
            } catch (AEADBadTagException e) {
                System.out.println("    SUCCESS: Tampering correctly detected!");
                System.out.println("    Security Exception Caught: AEADBadTagException (Tag mismatch)");
                System.out.println("    AES-GCM prevents any altered ciphertext from being accepted or decrypted.");
            }

            // Step 6: Password-based Encryption demonstration
            System.out.println("\n[6] Demonstrating Password-Based Encryption (PBKDF2 + AES-256-GCM):");
            String password = "CorrectHorseBatteryStaple#2026";
            String secretMessage = "Confidential: Database credentials [host=prod-db.internal, user=admin, pass=secret]";
            System.out.println("    Password        : " + password);
            System.out.println("    Plaintext       : " + secretMessage);

            String pwCiphertext = encryptWithPassword(secretMessage, password.toCharArray());
            System.out.println("    PBE Ciphertext  : " + pwCiphertext);

            String pwDecrypted = decryptWithPassword(pwCiphertext, password.toCharArray());
            System.out.println("    Decrypted with correct password : " + pwDecrypted);

            // Test with wrong password
            try {
                System.out.println("    Attempting decryption with incorrect password...");
                decryptWithPassword(pwCiphertext, "WrongPassword123!".toCharArray());
                System.out.println("    ERROR: Decryption succeeded with wrong password!");
            } catch (AEADBadTagException e) {
                System.out.println("    SUCCESS: Decryption failed as expected with wrong password (AEADBadTagException).");
            }

            System.out.println("\n================================================================================");
            System.out.println("                        Demonstration Completed Successfully                    ");
            System.out.println("================================================================================");

        } catch (Exception e) {
            System.err.println("Demonstration failed with exception: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // =========================================================================
    // Interactive Console Menu
    // =========================================================================

    /**
     * Provides an interactive CLI for users to encrypt, decrypt, and manage keys.
     */
    public static void runInteractiveConsole() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("\n--- Symmetric Encryption Interactive Mode ---");

        while (true) {
            System.out.println("\nPlease choose an option:");
            System.out.println("  1. Generate a new AES-256 Key");
            System.out.println("  2. Encrypt plaintext with AES Key");
            System.out.println("  3. Decrypt ciphertext with AES Key");
            System.out.println("  4. Encrypt plaintext with Password (PBKDF2)");
            System.out.println("  5. Decrypt ciphertext with Password (PBKDF2)");
            System.out.println("  6. Run Full Demonstration");
            System.out.println("  0. Exit");
            System.out.print("Enter choice [0-6]: ");

            if (!scanner.hasNextLine()) {
                break;
            }
            String choice = scanner.nextLine().trim();

            try {
                switch (choice) {
                    case "1": {
                        SecretKey key = generateKey();
                        System.out.println("\nGenerated AES-256 Key (Base64):");
                        System.out.println(encodeKeyToBase64(key));
                        break;
                    }
                    case "2": {
                        System.out.print("\nEnter AES Key (Base64): ");
                        String keyInput = scanner.nextLine().trim();
                        SecretKey key = decodeKeyFromBase64(keyInput);

                        System.out.print("Enter plaintext to encrypt: ");
                        String plaintext = scanner.nextLine();

                        String encrypted = encryptString(plaintext, key);
                        System.out.println("\nCiphertext (Base64):");
                        System.out.println(encrypted);
                        break;
                    }
                    case "3": {
                        System.out.print("\nEnter AES Key (Base64): ");
                        String keyInput = scanner.nextLine().trim();
                        SecretKey key = decodeKeyFromBase64(keyInput);

                        System.out.print("Enter ciphertext to decrypt (Base64): ");
                        String ciphertext = scanner.nextLine().trim();

                        String decrypted = decryptString(ciphertext, key);
                        System.out.println("\nDecrypted Plaintext:");
                        System.out.println(decrypted);
                        break;
                    }
                    case "4": {
                        System.out.print("\nEnter password: ");
                        String password = scanner.nextLine();

                        System.out.print("Enter plaintext to encrypt: ");
                        String plaintext = scanner.nextLine();

                        char[] pwdChars = password.toCharArray();
                        String encrypted = encryptWithPassword(plaintext, pwdChars);
                        Arrays.fill(pwdChars, '0'); // clear password from memory

                        System.out.println("\nCiphertext (Base64):");
                        System.out.println(encrypted);
                        break;
                    }
                    case "5": {
                        System.out.print("\nEnter password: ");
                        String password = scanner.nextLine();

                        System.out.print("Enter ciphertext to decrypt (Base64): ");
                        String ciphertext = scanner.nextLine().trim();

                        char[] pwdChars = password.toCharArray();
                        String decrypted = decryptWithPassword(ciphertext, pwdChars);
                        Arrays.fill(pwdChars, '0'); // clear password from memory

                        System.out.println("\nDecrypted Plaintext:");
                        System.out.println(decrypted);
                        break;
                    }
                    case "6": {
                        runDemonstration();
                        break;
                    }
                    case "0":
                    case "exit":
                    case "quit": {
                        System.out.println("Exiting. Goodbye!");
                        return;
                    }
                    default: {
                        System.out.println("Invalid option. Please enter a number between 0 and 6.");
                        break;
                    }
                }
            } catch (AEADBadTagException e) {
                System.err.println("\n[ERROR] Decryption failed: Data authentication tag mismatch.");
                System.err.println("The key/password is incorrect, or the ciphertext was altered/tampered.");
            } catch (IllegalArgumentException e) {
                System.err.println("\n[INPUT ERROR] " + e.getMessage());
            } catch (Exception e) {
                System.err.println("\n[ERROR] Operation failed: " + e.getMessage());
            }
        }
    }

    // =========================================================================
    // CLI Arguments Handler and Entry Point
    // =========================================================================

    private static void printUsage() {
        System.out.println("Usage:");
        System.out.println("  java SymmetricEncryptionApp [command] [options]");
        System.out.println();
        System.out.println("Commands:");
        System.out.println("  (no arguments)                         Run automated demo, then interactive prompt");
        System.out.println("  --demo                                 Run automated demonstration and exit");
        System.out.println("  --interactive                          Launch interactive CLI menu");
        System.out.println("  keygen                                 Generate a new random 256-bit AES key (Base64)");
        System.out.println("  encrypt <plaintext> <base64Key>        Encrypt plaintext using AES key");
        System.out.println("  decrypt <base64Ciphertext> <base64Key> Decrypt ciphertext using AES key");
        System.out.println("  encrypt-pw <plaintext> <password>      Encrypt plaintext using password (PBKDF2)");
        System.out.println("  decrypt-pw <ciphertext> <password>     Decrypt ciphertext using password (PBKDF2)");
        System.out.println("  --help, -h                             Display this help message");
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            runDemonstration();
            if (System.console() != null) {
                runInteractiveConsole();
            }
            return;
        }

        String command = args[0].toLowerCase();
        try {
            switch (command) {
                case "--demo":
                    runDemonstration();
                    break;

                case "--interactive":
                case "-i":
                    runInteractiveConsole();
                    break;

                case "keygen":
                case "generate-key":
                    SecretKey key = generateKey();
                    System.out.println(encodeKeyToBase64(key));
                    break;

                case "encrypt":
                    if (args.length < 3) {
                        System.err.println("Error: Missing arguments for encrypt.");
                        System.err.println("Usage: java SymmetricEncryptionApp encrypt <plaintext> <base64Key>");
                        System.exit(1);
                    }
                    String plaintext = args[1];
                    String base64Key = args[2];
                    SecretKey secretKey = decodeKeyFromBase64(base64Key);
                    System.out.println(encryptString(plaintext, secretKey));
                    break;

                case "decrypt":
                    if (args.length < 3) {
                        System.err.println("Error: Missing arguments for decrypt.");
                        System.err.println("Usage: java SymmetricEncryptionApp decrypt <base64Ciphertext> <base64Key>");
                        System.exit(1);
                    }
                    String ciphertext = args[1];
                    String decryptKeyBase64 = args[2];
                    SecretKey decKey = decodeKeyFromBase64(decryptKeyBase64);
                    System.out.println(decryptString(ciphertext, decKey));
                    break;

                case "encrypt-pw":
                    if (args.length < 3) {
                        System.err.println("Error: Missing arguments for encrypt-pw.");
                        System.err.println("Usage: java SymmetricEncryptionApp encrypt-pw <plaintext> <password>");
                        System.exit(1);
                    }
                    char[] encPw = args[2].toCharArray();
                    String encResult = encryptWithPassword(args[1], encPw);
                    Arrays.fill(encPw, '0');
                    System.out.println(encResult);
                    break;

                case "decrypt-pw":
                    if (args.length < 3) {
                        System.err.println("Error: Missing arguments for decrypt-pw.");
                        System.err.println("Usage: java SymmetricEncryptionApp decrypt-pw <ciphertext> <password>");
                        System.exit(1);
                    }
                    char[] decPw = args[2].toCharArray();
                    String decResult = decryptWithPassword(args[1], decPw);
                    Arrays.fill(decPw, '0');
                    System.out.println(decResult);
                    break;

                case "--help":
                case "-h":
                case "help":
                    printUsage();
                    break;

                default:
                    System.err.println("Unknown command: " + command);
                    printUsage();
                    System.exit(1);
            }
        } catch (AEADBadTagException e) {
            System.err.println("Decryption failed: AEADBadTagException - data authentication failed.");
            System.err.println("The key/password is incorrect or ciphertext has been modified.");
            System.exit(2);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }
}
