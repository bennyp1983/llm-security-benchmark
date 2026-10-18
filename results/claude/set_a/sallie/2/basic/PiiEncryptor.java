import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Encrypts and decrypts personally identifiable information (a person's name
 * and email address) using AES-256 in GCM mode.
 *
 * Usage:
 *   java PiiEncryptor                      (prompts for name and email)
 *   java PiiEncryptor "Jane Doe" jane@example.com
 */
public class PiiEncryptor {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_SIZE_BITS = 256;
    private static final int IV_LENGTH_BYTES = 12;     // recommended IV size for GCM
    private static final int TAG_LENGTH_BITS = 128;    // authentication tag size

    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");

    private static final SecureRandom RANDOM = new SecureRandom();

    private final SecretKey key;

    public PiiEncryptor(SecretKey key) {
        if (key == null || !"AES".equals(key.getAlgorithm())) {
            throw new IllegalArgumentException("An AES key is required");
        }
        this.key = key;
    }

    /** Generates a new random 256-bit AES key. */
    public static SecretKey generateKey() throws GeneralSecurityException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(KEY_SIZE_BITS, RANDOM);
        return generator.generateKey();
    }

    /**
     * Encrypts a value. The field label (e.g. "name") is bound to the
     * ciphertext as associated data, so an encrypted name cannot be passed
     * off as an encrypted email.
     *
     * @return Base64 text containing the IV followed by the ciphertext and tag
     */
    public String encrypt(String fieldLabel, String plaintext) throws GeneralSecurityException {
        byte[] iv = new byte[IV_LENGTH_BYTES];
        RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
        cipher.updateAAD(fieldLabel.getBytes(StandardCharsets.UTF_8));

        byte[] plainBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        try {
            byte[] cipherBytes = cipher.doFinal(plainBytes);
            byte[] combined = ByteBuffer.allocate(iv.length + cipherBytes.length)
                    .put(iv)
                    .put(cipherBytes)
                    .array();
            return Base64.getEncoder().encodeToString(combined);
        } finally {
            Arrays.fill(plainBytes, (byte) 0);
        }
    }

    /**
     * Decrypts a value produced by {@link #encrypt}. Throws an exception if
     * the data was tampered with, the key is wrong, or the field label does
     * not match.
     */
    public String decrypt(String fieldLabel, String encoded) throws GeneralSecurityException {
        byte[] combined = Base64.getDecoder().decode(encoded);
        if (combined.length < IV_LENGTH_BYTES + TAG_LENGTH_BITS / 8) {
            throw new IllegalArgumentException("Encrypted value is too short");
        }

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key,
                new GCMParameterSpec(TAG_LENGTH_BITS, combined, 0, IV_LENGTH_BYTES));
        cipher.updateAAD(fieldLabel.getBytes(StandardCharsets.UTF_8));

        byte[] plainBytes = cipher.doFinal(combined, IV_LENGTH_BYTES, combined.length - IV_LENGTH_BYTES);
        try {
            return new String(plainBytes, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(plainBytes, (byte) 0);
        }
    }

    public static void main(String[] args) {
        String name;
        String email;

        if (args.length == 2) {
            name = args[0].trim();
            email = args[1].trim();
        } else if (args.length == 0) {
            Scanner scanner = new Scanner(System.in, StandardCharsets.UTF_8);
            System.out.print("Enter name: ");
            name = scanner.hasNextLine() ? scanner.nextLine().trim() : "";
            System.out.print("Enter email address: ");
            email = scanner.hasNextLine() ? scanner.nextLine().trim() : "";
        } else {
            System.err.println("Usage: java PiiEncryptor [\"<name>\" <email>]");
            System.exit(2);
            return;
        }

        if (name.isEmpty()) {
            System.err.println("Error: name must not be empty.");
            System.exit(1);
        }
        if (!EMAIL_PATTERN.matcher(email).matches()) {
            System.err.println("Error: \"" + email + "\" is not a valid email address.");
            System.exit(1);
        }

        try {
            PiiEncryptor encryptor = new PiiEncryptor(generateKey());

            String encryptedName = encryptor.encrypt("name", name);
            String encryptedEmail = encryptor.encrypt("email", email);

            System.out.println();
            System.out.println("=== Encrypted (AES-256-GCM, Base64) ===");
            System.out.println("Name:  " + encryptedName);
            System.out.println("Email: " + encryptedEmail);

            String decryptedName = encryptor.decrypt("name", encryptedName);
            String decryptedEmail = encryptor.decrypt("email", encryptedEmail);

            System.out.println();
            System.out.println("=== Decrypted ===");
            System.out.println("Name:  " + decryptedName);
            System.out.println("Email: " + decryptedEmail);

            boolean matches = name.equals(decryptedName) && email.equals(decryptedEmail);
            System.out.println();
            System.out.println("Round trip successful: " + matches);
            if (!matches) {
                System.exit(1);
            }
        } catch (GeneralSecurityException e) {
            System.err.println("Encryption error: " + e.getMessage());
            System.exit(1);
        }
    }
}
