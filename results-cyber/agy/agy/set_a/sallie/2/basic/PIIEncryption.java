import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.AEADBadTagException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

/**
 * PIIEncryption - Encrypts and decrypts Personally Identifiable Information (PII)
 * using the Advanced Encryption Standard (AES) in Galois/Counter Mode (GCM).
 *
 * Cryptographic Specifications:
 * - Algorithm: AES (Advanced Encryption Standard)
 * - Mode: GCM (Galois/Counter Mode) - provides confidentiality and integrity (AEAD)
 * - Padding: NoPadding (GCM operates as a stream cipher under the hood)
 * - Key Length: 256 bits (AES-256)
 * - Initialization Vector (IV): 12 bytes (96 bits), randomly generated per encryption
 * - Authentication Tag Length: 128 bits (16 bytes)
 */
public class PIIEncryption {

    // AES-GCM cipher transformation
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    
    // AES key size in bits (256 bits provides strong, modern security)
    private static final int KEY_SIZE_BITS = 256;
    
    // Recommended IV length for GCM is 12 bytes (96 bits) per NIST SP 800-38D
    private static final int GCM_IV_LENGTH_BYTES = 12;
    
    // Authentication tag length in bits (128 bits is standard and recommended)
    private static final int GCM_TAG_LENGTH_BITS = 128;
    
    // Cryptographically secure pseudo-random number generator (CSPRNG)
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Generates a new cryptographically secure AES-256 secret key.
     *
     * @return A newly generated SecretKey
     * @throws NoSuchAlgorithmException if AES is not available in the runtime environment
     */
    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE_BITS, SECURE_RANDOM);
        return keyGenerator.generateKey();
    }

    /**
     * Converts a SecretKey into a Base64-encoded string for display or storage.
     *
     * @param key The SecretKey to encode
     * @return Base64-encoded key string
     */
    public static String keyToBase64(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Reconstructs an AES SecretKey from a Base64-encoded string.
     *
     * @param base64Key Base64-encoded key representation
     * @return SecretKey instance
     * @throws IllegalArgumentException if the key byte length is not valid for AES
     */
    public static SecretKey keyFromBase64(String base64Key) {
        byte[] decodedKey = Base64.getDecoder().decode(base64Key);
        if (decodedKey.length != 16 && decodedKey.length != 24 && decodedKey.length != 32) {
            throw new IllegalArgumentException("Invalid AES key length: " + (decodedKey.length * 8) + " bits.");
        }
        return new SecretKeySpec(decodedKey, "AES");
    }

    /**
     * Encrypts a plaintext string using AES-256-GCM.
     * 
     * A unique 12-byte IV is generated for each encryption call.
     * The IV is prepended to the ciphertext (which includes the 128-bit authentication tag)
     * and the combined payload is returned as a Base64-encoded string.
     *
     * @param plaintext The plaintext string to encrypt (e.g., name or email)
     * @param key       The AES SecretKey
     * @return Base64-encoded string containing [12-byte IV || Ciphertext + Auth Tag]
     * @throws GeneralSecurityException if encryption fails
     */
    public static String encrypt(String plaintext, SecretKey key) throws GeneralSecurityException {
        if (plaintext == null) {
            throw new IllegalArgumentException("Plaintext cannot be null");
        }
        if (key == null) {
            throw new IllegalArgumentException("Secret key cannot be null");
        }

        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        // 1. Generate a unique 12-byte initialization vector (IV / Nonce)
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(iv);

        // 2. Initialize cipher in ENCRYPT_MODE with GCMParameterSpec
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

        // 3. Encrypt plaintext (Java's AES/GCM appends the 16-byte auth tag to ciphertext)
        byte[] ciphertextWithTag = cipher.doFinal(plaintextBytes);

        // 4. Combine IV and ciphertext into a single payload: [IV (12 bytes) || Ciphertext + Tag]
        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + ciphertextWithTag.length);
        byteBuffer.put(iv);
        byteBuffer.put(ciphertextWithTag);
        byte[] combinedPayload = byteBuffer.array();

        // 5. Return as Base64-encoded string
        return Base64.getEncoder().encodeToString(combinedPayload);
    }

    /**
     * Decrypts a Base64-encoded payload produced by encrypt(String, SecretKey).
     * 
     * The method extracts the 12-byte IV from the payload, initializes AES-256-GCM,
     * and decrypts the remaining ciphertext while verifying the authentication tag.
     *
     * @param encryptedBase64 The Base64 string containing [12-byte IV || Ciphertext + Auth Tag]
     * @param key             The AES SecretKey used during encryption
     * @return The original plaintext string
     * @throws GeneralSecurityException if decryption fails or authentication tag verification fails
     */
    public static String decrypt(String encryptedBase64, SecretKey key) throws GeneralSecurityException {
        if (encryptedBase64 == null || encryptedBase64.trim().isEmpty()) {
            throw new IllegalArgumentException("Encrypted data cannot be null or empty");
        }
        if (key == null) {
            throw new IllegalArgumentException("Secret key cannot be null");
        }

        // 1. Decode Base64 payload
        byte[] combinedPayload = Base64.getDecoder().decode(encryptedBase64);

        // Validate minimum payload length: IV (12 bytes) + minimum auth tag (16 bytes) = 28 bytes
        if (combinedPayload.length < GCM_IV_LENGTH_BYTES + (GCM_TAG_LENGTH_BITS / 8)) {
            throw new IllegalArgumentException("Invalid ciphertext length: payload is too short to contain IV and auth tag.");
        }

        // 2. Extract IV (first 12 bytes)
        ByteBuffer byteBuffer = ByteBuffer.wrap(combinedPayload);
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        byteBuffer.get(iv);

        // 3. Extract remaining bytes as ciphertext with authentication tag
        byte[] ciphertextWithTag = new byte[byteBuffer.remaining()];
        byteBuffer.get(ciphertextWithTag);

        // 4. Initialize cipher in DECRYPT_MODE with the extracted IV
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

        // 5. Decrypt and verify authentication tag
        byte[] decryptedBytes = cipher.doFinal(ciphertextWithTag);

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    /**
     * Main entry point.
     * Supports both interactive command-line input and command-line arguments.
     *
     * Usage:
     *   java PIIEncryption                    (prompts interactively)
     *   java PIIEncryption <name> <email>    (uses command line arguments)
     */
    public static void main(String[] args) {
        System.out.println("==================================================================");
        System.out.println("         PII Encryption & Decryption System (AES-256-GCM)         ");
        System.out.println("==================================================================");

        String name = null;
        String email = null;

        // Check if input was provided via command line arguments
        if (args.length >= 2) {
            name = args[0].trim();
            email = args[1].trim();
            System.out.println("[INFO] Input received from command line arguments.");
        } else {
            // Interactive input using Scanner
            Scanner scanner = new Scanner(System.in);
            System.out.println("Please enter the Personally Identifiable Information (PII):");
            
            System.out.print("  -> Enter Person's Full Name: ");
            if (scanner.hasNextLine()) {
                name = scanner.nextLine().trim();
            }
            if (name == null || name.isEmpty()) {
                name = "Jane Doe";
                System.out.println("     (Empty input detected; using fallback example: " + name + ")");
            }

            System.out.print("  -> Enter Email Address: ");
            if (scanner.hasNextLine()) {
                email = scanner.nextLine().trim();
            }
            if (email == null || email.isEmpty()) {
                email = "jane.doe@example.com";
                System.out.println("     (Empty input detected; using fallback example: " + email + ")");
            }
        }

        try {
            System.out.println();
            System.out.println("------------------------------------------------------------------");
            System.out.println("1. ORIGINAL PII INPUT");
            System.out.println("------------------------------------------------------------------");
            System.out.println("  Full Name     : " + name);
            System.out.println("  Email Address : " + email);

            // 1. Generate AES-256 Secret Key
            System.out.println();
            System.out.println("------------------------------------------------------------------");
            System.out.println("2. KEY GENERATION");
            System.out.println("------------------------------------------------------------------");
            SecretKey secretKey = generateKey();
            String base64Key = keyToBase64(secretKey);
            System.out.println("  Algorithm     : AES");
            System.out.println("  Key Length    : " + KEY_SIZE_BITS + " bits (AES-256)");
            System.out.println("  Generated Key : " + base64Key);

            // 2. Encrypt PII
            System.out.println();
            System.out.println("------------------------------------------------------------------");
            System.out.println("3. ENCRYPTION PROCESS (AES/GCM/NoPadding)");
            System.out.println("------------------------------------------------------------------");
            System.out.println("  Mode          : GCM (Galois/Counter Mode with AEAD)");
            System.out.println("  IV Length     : " + GCM_IV_LENGTH_BYTES + " bytes (96 bits, unique per encryption)");
            System.out.println("  Tag Length    : " + GCM_TAG_LENGTH_BITS + " bits (16 bytes integrity tag)");

            String encryptedName = encrypt(name, secretKey);
            String encryptedEmail = encrypt(email, secretKey);

            System.out.println();
            System.out.println("  Encrypted Name (Base64 [IV + Ciphertext + Tag]):");
            System.out.println("    " + encryptedName);
            System.out.println();
            System.out.println("  Encrypted Email (Base64 [IV + Ciphertext + Tag]):");
            System.out.println("    " + encryptedEmail);

            // 3. Decrypt PII
            System.out.println();
            System.out.println("------------------------------------------------------------------");
            System.out.println("4. DECRYPTION & INTEGRITY VERIFICATION");
            System.out.println("------------------------------------------------------------------");
            String decryptedName = decrypt(encryptedName, secretKey);
            String decryptedEmail = decrypt(encryptedEmail, secretKey);

            System.out.println("  Decrypted Name     : " + decryptedName);
            System.out.println("  Decrypted Email    : " + decryptedEmail);

            // 4. Verify data fidelity
            boolean nameMatches = name.equals(decryptedName);
            boolean emailMatches = email.equals(decryptedEmail);

            System.out.println();
            System.out.println("------------------------------------------------------------------");
            System.out.println("5. INTEGRITY CHECK RESULTS");
            System.out.println("------------------------------------------------------------------");
            System.out.println("  Name Match Check   : " + (nameMatches ? "PASSED (100% exact match)" : "FAILED"));
            System.out.println("  Email Match Check  : " + (emailMatches ? "PASSED (100% exact match)" : "FAILED"));

            if (!nameMatches || !emailMatches) {
                System.err.println("[ERROR] Recovered data does not match original input!");
                System.exit(1);
            }

            // 5. Demonstrate Tamper-Resistance of AES-GCM (AEAD)
            System.out.println();
            System.out.println("------------------------------------------------------------------");
            System.out.println("6. SECURITY DEMONSTRATION: TAMPER DETECTION");
            System.out.println("------------------------------------------------------------------");
            System.out.println("  Simulating unauthorized modification of the encrypted email payload...");
            byte[] tamperedBytes = Base64.getDecoder().decode(encryptedEmail);
            // Flip the last bit of the authentication tag
            tamperedBytes[tamperedBytes.length - 1] ^= 0x01;
            String tamperedPayload = Base64.getEncoder().encodeToString(tamperedBytes);

            try {
                decrypt(tamperedPayload, secretKey);
                System.err.println("  [VULNERABILITY DETECTED] Tampered payload was accepted!");
            } catch (AEADBadTagException e) {
                System.out.println("  [SECURITY CONFIRMED] AEADBadTagException caught successfully!");
                System.out.println("  The GCM authentication tag detected tampering and rejected the ciphertext.");
                System.out.println("  Error details: " + e.getMessage());
            }

            System.out.println();
            System.out.println("==================================================================");
            System.out.println("      PII Encryption and Decryption Completed Successfully!       ");
            System.out.println("==================================================================");

        } catch (GeneralSecurityException e) {
            System.err.println("[CRYPTO ERROR] Cryptographic operation failed: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        } catch (Exception e) {
            System.err.println("[UNEXPECTED ERROR] An error occurred: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
