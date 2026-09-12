import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Pattern;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encrypts and decrypts personally identifiable information (a person's name
 * and email address) using AES-256 in GCM mode.
 *
 * <p>The key is never stored in this source code. It is loaded at runtime from
 * one of the following, in order of preference:
 * <ol>
 *   <li>The file named by the {@code PII_ENCRYPTION_KEY_FILE} environment variable</li>
 *   <li>The {@code PII_ENCRYPTION_KEY} environment variable</li>
 * </ol>
 * In both cases the key must be a Base64-encoded 256-bit (32-byte) value. Run
 * the program with {@code --generate-key} to create one.
 */
public final class PiiEncryptor {

    static final String KEY_ENV_VAR = "PII_ENCRYPTION_KEY";
    static final String KEY_FILE_ENV_VAR = "PII_ENCRYPTION_KEY_FILE";

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_LENGTH_BYTES = 32;   // AES-256
    private static final int IV_LENGTH_BYTES = 12;    // recommended size for GCM
    private static final int TAG_LENGTH_BITS = 128;   // full-length authentication tag
    private static final int MAX_INPUT_LENGTH = 320;  // generous upper bound for names/emails

    // Deliberately simple: rejects obvious garbage without trying to implement RFC 5322.
    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");

    private static final SecureRandom RANDOM = new SecureRandom();

    private final SecretKey key;

    public PiiEncryptor(SecretKey key) {
        if (key == null || !"AES".equals(key.getAlgorithm())) {
            throw new IllegalArgumentException("An AES key is required.");
        }
        this.key = key;
    }

    /**
     * Encrypts a value. The {@code fieldLabel} is bound to the ciphertext as
     * associated data, so a ciphertext produced for one field (e.g. "email")
     * cannot be silently substituted for another (e.g. "name").
     *
     * @return Base64 text of: IV || ciphertext || authentication tag
     */
    public String encrypt(String plaintext, String fieldLabel) throws GeneralSecurityException {
        byte[] iv = new byte[IV_LENGTH_BYTES];
        RANDOM.nextBytes(iv); // a fresh, unique IV for every encryption is mandatory with GCM

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
        cipher.updateAAD(fieldLabel.getBytes(StandardCharsets.UTF_8));

        byte[] plainBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        try {
            byte[] cipherBytes = cipher.doFinal(plainBytes);
            byte[] output = new byte[iv.length + cipherBytes.length];
            System.arraycopy(iv, 0, output, 0, iv.length);
            System.arraycopy(cipherBytes, 0, output, iv.length, cipherBytes.length);
            return Base64.getEncoder().encodeToString(output);
        } finally {
            Arrays.fill(plainBytes, (byte) 0);
        }
    }

    /**
     * Decrypts a value produced by {@link #encrypt}. Throws if the data was
     * tampered with, was encrypted under a different key, or belongs to a
     * different field.
     */
    public String decrypt(String encoded, String fieldLabel) throws GeneralSecurityException {
        byte[] input;
        try {
            input = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("Encrypted value is not valid Base64.", e);
        }
        if (input.length < IV_LENGTH_BYTES + TAG_LENGTH_BITS / 8) {
            throw new GeneralSecurityException("Encrypted value is too short.");
        }

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key,
                new GCMParameterSpec(TAG_LENGTH_BITS, input, 0, IV_LENGTH_BYTES));
        cipher.updateAAD(fieldLabel.getBytes(StandardCharsets.UTF_8));

        byte[] plainBytes = cipher.doFinal(input, IV_LENGTH_BYTES, input.length - IV_LENGTH_BYTES);
        try {
            return new String(plainBytes, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(plainBytes, (byte) 0);
        }
    }

    // ---------------------------------------------------------------------
    // Key handling
    // ---------------------------------------------------------------------

    /** Creates a new random AES-256 key and returns it Base64-encoded. */
    static String generateEncodedKey() throws GeneralSecurityException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(KEY_LENGTH_BYTES * 8, RANDOM);
        return Base64.getEncoder().encodeToString(generator.generateKey().getEncoded());
    }

    /** Loads the key from the environment. Never falls back to a built-in default. */
    static SecretKey loadKeyFromEnvironment() throws IOException {
        String encoded;
        String source;

        String keyFile = System.getenv(KEY_FILE_ENV_VAR);
        if (keyFile != null && !keyFile.isBlank()) {
            encoded = Files.readString(Path.of(keyFile), StandardCharsets.US_ASCII);
            source = "the file named in " + KEY_FILE_ENV_VAR;
        } else {
            encoded = System.getenv(KEY_ENV_VAR);
            source = KEY_ENV_VAR;
        }

        if (encoded == null || encoded.isBlank()) {
            throw new IllegalStateException("No encryption key found. Set " + KEY_ENV_VAR
                    + " or " + KEY_FILE_ENV_VAR + ". Run with --generate-key to create a key.");
        }

        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(encoded.strip());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("The key in " + source + " is not valid Base64.");
        }
        try {
            if (keyBytes.length != KEY_LENGTH_BYTES) {
                throw new IllegalStateException("The key in " + source + " must decode to "
                        + KEY_LENGTH_BYTES + " bytes (AES-256), but it is " + keyBytes.length + " bytes.");
            }
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            Arrays.fill(keyBytes, (byte) 0); // SecretKeySpec keeps its own copy
        }
    }

    // ---------------------------------------------------------------------
    // Input handling
    // ---------------------------------------------------------------------

    private static String prompt(BufferedReader reader, String label) throws IOException {
        Console console = System.console();
        String value;
        if (console != null) {
            value = console.readLine("%s: ", label);
        } else {
            System.out.print(label + ": ");
            System.out.flush();
            value = reader.readLine();
            System.out.println();
        }
        if (value == null) {
            throw new IllegalArgumentException("No input received for " + label.toLowerCase() + ".");
        }
        return value.strip();
    }

    private static String validateName(String name) {
        if (name.isEmpty()) {
            throw new IllegalArgumentException("Name must not be empty.");
        }
        if (name.length() > MAX_INPUT_LENGTH) {
            throw new IllegalArgumentException("Name is too long.");
        }
        return name;
    }

    private static String validateEmail(String email) {
        if (email.length() > MAX_INPUT_LENGTH || !EMAIL_PATTERN.matcher(email).matches()) {
            throw new IllegalArgumentException("Email address is not valid.");
        }
        return email;
    }

    // ---------------------------------------------------------------------
    // Entry point
    // ---------------------------------------------------------------------

    public static void main(String[] args) {
        try {
            if (args.length == 1 && "--generate-key".equals(args[0])) {
                System.out.println(generateEncodedKey());
                return;
            }
            if (args.length != 0) {
                // PII is intentionally NOT accepted as command-line arguments, because
                // arguments are visible in process listings and shell history.
                System.err.println("Usage: java PiiEncryptor [--generate-key]");
                System.err.println("The name and email address are requested interactively.");
                System.exit(2);
            }

            PiiEncryptor encryptor = new PiiEncryptor(loadKeyFromEnvironment());

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(System.in, StandardCharsets.UTF_8));
            String name = validateName(prompt(reader, "Name"));
            String email = validateEmail(prompt(reader, "Email address"));

            String encryptedName = encryptor.encrypt(name, "name");
            String encryptedEmail = encryptor.encrypt(email, "email");

            System.out.println("Encrypted data");
            System.out.println("  Name : " + encryptedName);
            System.out.println("  Email: " + encryptedEmail);

            String decryptedName = encryptor.decrypt(encryptedName, "name");
            String decryptedEmail = encryptor.decrypt(encryptedEmail, "email");

            System.out.println("Decrypted data");
            System.out.println("  Name : " + decryptedName);
            System.out.println("  Email: " + decryptedEmail);

            boolean matches = name.equals(decryptedName) && email.equals(decryptedEmail);
            System.out.println("Round trip " + (matches ? "succeeded: the original data was recovered."
                                                         : "FAILED: decrypted data does not match."));
            if (!matches) {
                System.exit(1);
            }
        } catch (AEADBadTagException e) {
            // Deliberately vague: don't reveal details that could help an attacker.
            System.err.println("Error: decryption failed (wrong key or data was altered).");
            System.exit(1);
        } catch (IllegalArgumentException | IllegalStateException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Error: could not read input or key file: " + e.getMessage());
            System.exit(1);
        } catch (GeneralSecurityException e) {
            System.err.println("Error: a cryptographic operation failed.");
            System.exit(1);
        }
    }
}
