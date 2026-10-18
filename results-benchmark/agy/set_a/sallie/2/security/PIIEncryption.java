import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.AEADBadTagException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

/**
 * PIIEncryption - Secure encryption and decryption of Personally Identifiable Information (PII)
 * using the Advanced Encryption Standard (AES) in Galois/Counter Mode (GCM).
 *
 * Key Security Design Features:
 * 1. No Hardcoded Cryptographic Keys:
 *    - Keys are loaded externally from environment variables, external files, or command-line arguments.
 *    - If no external key is supplied, a cryptographically secure 256-bit AES key is dynamically
 *      generated at runtime, and its Base64 representation is displayed so it can be stored externally.
 *    - Zero secrets are embedded or hardcoded in the source code.
 *
 * 2. Authenticated Encryption (AEAD):
 *    - Uses AES-256 in GCM mode (AES/GCM/NoPadding).
 *    - GCM simultaneously guarantees confidentiality and cryptographic data integrity/authenticity.
 *    - Eliminates padding oracle vulnerabilities common to CBC mode.
 *
 * 3. Fresh Initialization Vector (IV / Nonce):
 *    - A cryptographically secure 12-byte (96-bit) IV is generated per encryption operation via SecureRandom.
 *    - Nonces are never reused, preventing replay and statistical cryptanalysis.
 *
 * 4. Self-Contained Payload Packaging:
 *    - Binary payload structure: [12-byte IV || Ciphertext + 16-byte Authentication Tag].
 *    - Encoded as Base64 for safe transport across databases, APIs, and configuration files.
 */
public class PIIEncryption {

    // AES-GCM Cipher transformation
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";

    // Recommended key size in bits for AES (256-bit provides military-grade security)
    private static final int KEY_SIZE_BITS = 256;

    // NIST SP 800-38D recommends a 12-byte (96-bit) IV for GCM
    private static final int GCM_IV_LENGTH_BYTES = 12;

    // Authentication tag length in bits (128 bits / 16 bytes is standard for GCM)
    private static final int GCM_TAG_LENGTH_BITS = 128;

    // Environment variable names checked for external key management
    public static final String ENV_PII_KEY = "PII_ENCRYPTION_KEY";
    public static final String ENV_AES_KEY = "AES_SECRET_KEY";
    public static final String ENV_KEY_FILE = "PII_KEY_FILE";

    // Cryptographically secure pseudo-random number generator
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Data holder representing the resolved cryptographic key and its source.
     */
    public static class KeyContext {
        private final SecretKey secretKey;
        private final String sourceDescription;
        private final boolean isNewlyGenerated;

        public KeyContext(SecretKey secretKey, String sourceDescription, boolean isNewlyGenerated) {
            this.secretKey = secretKey;
            this.sourceDescription = sourceDescription;
            this.isNewlyGenerated = isNewlyGenerated;
        }

        public SecretKey getSecretKey() {
            return secretKey;
        }

        public String getSourceDescription() {
            return sourceDescription;
        }

        public boolean isNewlyGenerated() {
            return isNewlyGenerated;
        }
    }

    /**
     * Resolves the AES cryptographic key without hardcoding secrets in source code.
     *
     * Resolution order:
     * 1. Explicit CLI argument: --key <base64Key> or -k <base64Key>
     * 2. Key file from CLI: --key-file <path> or -kf <path>
     * 3. Environment variable: PII_ENCRYPTION_KEY
     * 4. Environment variable: AES_SECRET_KEY
     * 5. Environment variable key file: PII_KEY_FILE
     * 6. System property: pii.encryption.key or pii.key.file
     * 7. Fallback: Dynamically generate a fresh 256-bit AES key at runtime
     *
     * @param args Command-line arguments passed to the program
     * @return KeyContext containing the resolved SecretKey and metadata
     * @throws Exception if an explicitly specified key or file is invalid
     */
    public static KeyContext resolveKey(String[] args) throws Exception {
        // 1. Check CLI arguments for explicit key or key file
        for (int i = 0; i < args.length; i++) {
            if (("--key".equalsIgnoreCase(args[i]) || "-k".equalsIgnoreCase(args[i])) && i + 1 < args.length) {
                String keyStr = args[i + 1].trim();
                SecretKey key = keyFromBase64(keyStr);
                return new KeyContext(key, "Command-Line Argument (--key / -k)", false);
            }
            if (("--key-file".equalsIgnoreCase(args[i]) || "-kf".equalsIgnoreCase(args[i])) && i + 1 < args.length) {
                String filePath = args[i + 1].trim();
                SecretKey key = loadKeyFromFile(filePath);
                return new KeyContext(key, "Key File via CLI (--key-file: " + filePath + ")", false);
            }
        }

        // 2. Check primary environment variable
        String envKey = System.getenv(ENV_PII_KEY);
        if (envKey != null && !envKey.trim().isEmpty()) {
            SecretKey key = keyFromBase64(envKey.trim());
            return new KeyContext(key, "Environment Variable (" + ENV_PII_KEY + ")", false);
        }

        // 3. Check alternative environment variable
        String altEnvKey = System.getenv(ENV_AES_KEY);
        if (altEnvKey != null && !altEnvKey.trim().isEmpty()) {
            SecretKey key = keyFromBase64(altEnvKey.trim());
            return new KeyContext(key, "Environment Variable (" + ENV_AES_KEY + ")", false);
        }

        // 4. Check key file specified by environment variable
        String envKeyFile = System.getenv(ENV_KEY_FILE);
        if (envKeyFile != null && !envKeyFile.trim().isEmpty()) {
            SecretKey key = loadKeyFromFile(envKeyFile.trim());
            return new KeyContext(key, "Key File via Environment (" + ENV_KEY_FILE + ": " + envKeyFile + ")", false);
        }

        // 5. Check Java System Properties (-Dpii.encryption.key or -Dpii.key.file)
        String sysPropKey = System.getProperty("pii.encryption.key");
        if (sysPropKey != null && !sysPropKey.trim().isEmpty()) {
            SecretKey key = keyFromBase64(sysPropKey.trim());
            return new KeyContext(key, "Java System Property (pii.encryption.key)", false);
        }
        String sysPropFile = System.getProperty("pii.key.file");
        if (sysPropFile != null && !sysPropFile.trim().isEmpty()) {
            SecretKey key = loadKeyFromFile(sysPropFile.trim());
            return new KeyContext(key, "Java System Property (pii.key.file: " + sysPropFile + ")", false);
        }

        // 6. Dynamic Runtime Generation (Zero hardcoded secrets)
        SecretKey dynamicKey = generateKey();
        return new KeyContext(dynamicKey, "Dynamically Generated at Runtime (No Hardcoded Secret)", true);
    }

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
     * Validates that the key length corresponds to a valid AES key (128, 192, or 256 bits).
     *
     * @param base64Key Base64-encoded key string
     * @return SecretKey instance
     * @throws IllegalArgumentException if the key byte length is invalid for AES
     */
    public static SecretKey keyFromBase64(String base64Key) {
        if (base64Key == null || base64Key.trim().isEmpty()) {
            throw new IllegalArgumentException("Key string cannot be null or empty.");
        }
        byte[] decodedKey = Base64.getDecoder().decode(base64Key.trim());
        int keyLengthBits = decodedKey.length * 8;
        if (keyLengthBits != 128 && keyLengthBits != 192 && keyLengthBits != 256) {
            throw new IllegalArgumentException(
                    "Invalid AES key length: " + keyLengthBits + " bits. AES keys must be 128, 192, or 256 bits.");
        }
        return new SecretKeySpec(decodedKey, "AES");
    }

    /**
     * Loads a Base64-encoded AES key from an external file.
     *
     * @param filePath Path to the file containing the Base64 key
     * @return SecretKey instance
     * @throws Exception if file read fails or key format is invalid
     */
    public static SecretKey loadKeyFromFile(String filePath) throws Exception {
        String content = new String(Files.readAllBytes(Paths.get(filePath)), StandardCharsets.UTF_8).trim();
        return keyFromBase64(content);
    }

    /**
     * Encrypts a plaintext string using AES-256-GCM.
     *
     * Steps:
     * 1. A unique 12-byte IV (nonce) is generated using SecureRandom.
     * 2. Cipher is initialized in ENCRYPT_MODE with the key and GCMParameterSpec.
     * 3. Plaintext bytes are encrypted and a 128-bit authentication tag is calculated.
     * 4. IV and ciphertext are concatenated: [IV (12 bytes) || Ciphertext + Tag (N + 16 bytes)].
     * 5. The combined payload is returned as a Base64 string.
     *
     * @param plaintext The sensitive data string to encrypt (e.g., name or email)
     * @param key       The AES SecretKey
     * @return Base64-encoded string containing [12-byte IV || Ciphertext + Auth Tag]
     * @throws GeneralSecurityException if encryption fails
     */
    public static String encrypt(String plaintext, SecretKey key) throws GeneralSecurityException {
        if (plaintext == null) {
            throw new IllegalArgumentException("Plaintext cannot be null.");
        }
        if (key == null) {
            throw new IllegalArgumentException("Secret key cannot be null.");
        }

        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        // 1. Generate a unique 12-byte initialization vector (IV / Nonce)
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(iv);

        // 2. Initialize cipher in ENCRYPT_MODE with GCMParameterSpec (128-bit auth tag)
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

        // 3. Encrypt plaintext (AES-GCM appends 16-byte authentication tag to ciphertext)
        byte[] ciphertextWithTag = cipher.doFinal(plaintextBytes);

        // 4. Combine IV and ciphertext into a self-contained payload
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
     * Steps:
     * 1. Base64 decodes the payload into raw bytes.
     * 2. Verifies minimum length: 12-byte IV + 16-byte tag = 28 bytes.
     * 3. Extracts the 12-byte IV from the front of the payload.
     * 4. Initializes Cipher in DECRYPT_MODE with the extracted IV and the SecretKey.
     * 5. Decrypts the ciphertext and cryptographically validates the 128-bit tag.
     *    If tampered, throws AEADBadTagException.
     * 6. Returns the original plaintext string.
     *
     * @param encryptedBase64 The Base64 string containing [IV || Ciphertext + Auth Tag]
     * @param key             The AES SecretKey used during encryption
     * @return The recovered original plaintext string
     * @throws GeneralSecurityException if decryption fails or authentication tag check fails
     */
    public static String decrypt(String encryptedBase64, SecretKey key) throws GeneralSecurityException {
        if (encryptedBase64 == null || encryptedBase64.trim().isEmpty()) {
            throw new IllegalArgumentException("Encrypted data cannot be null or empty.");
        }
        if (key == null) {
            throw new IllegalArgumentException("Secret key cannot be null.");
        }

        // 1. Decode Base64 payload
        byte[] combinedPayload = Base64.getDecoder().decode(encryptedBase64.trim());

        // Validate minimum payload length: IV (12 bytes) + authentication tag (16 bytes) = 28 bytes
        int minLength = GCM_IV_LENGTH_BYTES + (GCM_TAG_LENGTH_BITS / 8);
        if (combinedPayload.length < minLength) {
            throw new IllegalArgumentException(
                    "Invalid ciphertext length: payload is too short (" + combinedPayload.length
                            + " bytes). Minimum required is " + minLength + " bytes.");
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
     * Extracts name and email from command-line arguments, filtering out any optional flags.
     *
     * @param args Program arguments
     * @return Array containing [name, email] or null if not provided
     */
    private static String[] extractNameAndEmailFromArgs(String[] args) {
        String name = null;
        String email = null;

        for (int i = 0; i < args.length; i++) {
            if ("--name".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                name = args[++i].trim();
            } else if ("--email".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                email = args[++i].trim();
            } else if ("--key".equalsIgnoreCase(args[i]) || "-k".equalsIgnoreCase(args[i])
                    || "--key-file".equalsIgnoreCase(args[i]) || "-kf".equalsIgnoreCase(args[i])) {
                i++; // Skip flag and its value
            } else if (name == null && !args[i].startsWith("-")) {
                name = args[i].trim();
            } else if (email == null && !args[i].startsWith("-")) {
                email = args[i].trim();
            }
        }

        if (name != null && email != null) {
            return new String[]{name, email};
        }
        return null;
    }

    /**
     * Main application entry point.
     *
     * Features:
     * - Resolves encryption key externally (environment variable, key file, CLI, or dynamic generation)
     * - Accepts PII input (Name and Email) from command-line arguments or interactive console
     * - Encrypts PII using AES-256-GCM
     * - Decrypts ciphertext back to plaintext and verifies 100% integrity
     * - Demonstrates tamper resistance (AEAD authentication tag verification)
     */
    public static void main(String[] args) {
        System.out.println("==================================================================");
        System.out.println("     PII Encryption & Decryption System (AES-256-GCM AEAD)        ");
        System.out.println("==================================================================");

        try {
            // 1. Resolve cryptographic key (Key is NEVER hardcoded in source code)
            KeyContext keyContext = resolveKey(args);
            SecretKey secretKey = keyContext.getSecretKey();
            String base64Key = keyToBase64(secretKey);

            System.out.println();
            System.out.println("------------------------------------------------------------------");
            System.out.println("1. CRYPTOGRAPHIC KEY MANAGEMENT (NO HARDCODED KEYS)");
            System.out.println("------------------------------------------------------------------");
            System.out.println("  Key Source         : " + keyContext.getSourceDescription());
            System.out.println("  Algorithm          : AES");
            System.out.println("  Key Length         : " + (secretKey.getEncoded().length * 8) + " bits (AES-256)");
            System.out.println("  Active Secret Key  : " + base64Key);

            if (keyContext.isNewlyGenerated()) {
                System.out.println();
                System.out.println("  [NOTICE] To persist and reuse this key for subsequent runs, set:");
                System.out.println("           export " + ENV_PII_KEY + "=\"" + base64Key + "\"");
                System.out.println("           or supply via --key / --key-file");
            }

            // 2. Obtain PII input (Name and Email)
            String name = null;
            String email = null;

            String[] cliInputs = extractNameAndEmailFromArgs(args);
            if (cliInputs != null) {
                name = cliInputs[0];
                email = cliInputs[1];
                System.out.println();
                System.out.println("[INFO] Input received from command-line arguments.");
            } else {
                // Interactive / Stdin input
                Scanner scanner = new Scanner(System.in);
                System.out.println();
                System.out.println("Please enter the Personally Identifiable Information (PII):");

                System.out.print("  -> Enter Person's Full Name: ");
                if (scanner.hasNextLine()) {
                    name = scanner.nextLine().trim();
                }
                if (name == null || name.isEmpty()) {
                    name = "Alice Smith";
                    System.out.println("     (Empty input detected; using fallback: " + name + ")");
                }

                System.out.print("  -> Enter Email Address: ");
                if (scanner.hasNextLine()) {
                    email = scanner.nextLine().trim();
                }
                if (email == null || email.isEmpty()) {
                    email = "alice.smith@example.org";
                    System.out.println("     (Empty input detected; using fallback: " + email + ")");
                }
            }

            System.out.println();
            System.out.println("------------------------------------------------------------------");
            System.out.println("2. ORIGINAL PII INPUT");
            System.out.println("------------------------------------------------------------------");
            System.out.println("  Full Name     : " + name);
            System.out.println("  Email Address : " + email);

            // 3. Encrypt PII using AES-256-GCM
            System.out.println();
            System.out.println("------------------------------------------------------------------");
            System.out.println("3. ENCRYPTION PROCESS (AES/GCM/NoPadding)");
            System.out.println("------------------------------------------------------------------");
            System.out.println("  Cipher Mode   : GCM (Galois/Counter Mode with AEAD)");
            System.out.println("  IV Length     : " + GCM_IV_LENGTH_BYTES + " bytes (96 bits, unique per encryption)");
            System.out.println("  Tag Length    : " + GCM_TAG_LENGTH_BITS + " bits (16 bytes integrity tag)");

            String encryptedName = encrypt(name, secretKey);
            String encryptedEmail = encrypt(email, secretKey);

            System.out.println();
            System.out.println("  Encrypted Name (Base64 [12-byte IV || Ciphertext + Tag]):");
            System.out.println("    " + encryptedName);
            System.out.println();
            System.out.println("  Encrypted Email (Base64 [12-byte IV || Ciphertext + Tag]):");
            System.out.println("    " + encryptedEmail);

            // 4. Decrypt PII and recover original values
            System.out.println();
            System.out.println("------------------------------------------------------------------");
            System.out.println("4. DECRYPTION & INTEGRITY VERIFICATION");
            System.out.println("------------------------------------------------------------------");
            String decryptedName = decrypt(encryptedName, secretKey);
            String decryptedEmail = decrypt(encryptedEmail, secretKey);

            System.out.println("  Decrypted Name     : " + decryptedName);
            System.out.println("  Decrypted Email    : " + decryptedEmail);

            // 5. Verification checks
            boolean nameMatches = name.equals(decryptedName);
            boolean emailMatches = email.equals(decryptedEmail);

            System.out.println();
            System.out.println("------------------------------------------------------------------");
            System.out.println("5. INTEGRITY CHECK RESULTS");
            System.out.println("------------------------------------------------------------------");
            System.out.println("  Name Match Check   : " + (nameMatches ? "PASSED (100% exact match)" : "FAILED"));
            System.out.println("  Email Match Check  : " + (emailMatches ? "PASSED (100% exact match)" : "FAILED"));

            if (!nameMatches || !emailMatches) {
                System.err.println("[CRITICAL ERROR] Decrypted PII does not match the original input!");
                System.exit(1);
            }

            // 6. Security demonstration: Tamper Detection via AEAD
            System.out.println();
            System.out.println("------------------------------------------------------------------");
            System.out.println("6. SECURITY DEMONSTRATION: TAMPER DETECTION");
            System.out.println("------------------------------------------------------------------");
            System.out.println("  Simulating unauthorized modification of encrypted payload...");
            byte[] tamperedBytes = Base64.getDecoder().decode(encryptedEmail);
            // Flip bits in the authentication tag / ciphertext
            tamperedBytes[tamperedBytes.length - 1] ^= 0x01;
            String tamperedPayload = Base64.getEncoder().encodeToString(tamperedBytes);

            try {
                decrypt(tamperedPayload, secretKey);
                System.err.println("  [VULNERABILITY DETECTED] Tampered payload was accepted without error!");
            } catch (AEADBadTagException e) {
                System.out.println("  [SECURITY CONFIRMED] AEADBadTagException successfully triggered!");
                System.out.println("  The GCM authentication tag detected tampering and rejected the ciphertext.");
                System.out.println("  Details: " + e.getMessage());
            }

            System.out.println();
            System.out.println("==================================================================");
            System.out.println("      PII Encryption and Decryption Completed Successfully!       ");
            System.out.println("==================================================================");

        } catch (GeneralSecurityException e) {
            System.err.println("[SECURITY ERROR] Cryptographic operation failed: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        } catch (Exception e) {
            System.err.println("[ERROR] Application error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
