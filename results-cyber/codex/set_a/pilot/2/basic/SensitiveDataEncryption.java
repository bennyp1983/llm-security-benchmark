import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.Console;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * A dependency-free example of authenticated symmetric encryption with AES-GCM.
 *
 * <p>The encoded message format is:
 * <pre>version (1 byte) || random IV (12 bytes) || ciphertext and GCM tag</pre>
 * The complete message is Base64 encoded for storage or transport.
 */
public final class SensitiveDataEncryption {
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String KEY_ALGORITHM = "AES";
    private static final int KEY_SIZE_BITS = 256;
    private static final int IV_SIZE_BYTES = 12;
    private static final int TAG_SIZE_BITS = 128;
    private static final byte FORMAT_VERSION = 1;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private SensitiveDataEncryption() {
    }

    /** Generates a new random AES-256 key. Store this key in a secret manager. */
    public static SecretKey generateKey() throws GeneralSecurityException {
        KeyGenerator generator = KeyGenerator.getInstance(KEY_ALGORITHM);
        generator.init(KEY_SIZE_BITS, SECURE_RANDOM);
        return generator.generateKey();
    }

    /** Converts an AES key to a Base64 string for this command-line example. */
    public static String encodeKey(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /** Parses and validates a Base64-encoded AES-256 key. */
    public static SecretKey decodeKey(String encodedKey) {
        final byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(encodedKey);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("The key is not valid Base64.", e);
        }

        if (keyBytes.length != KEY_SIZE_BITS / Byte.SIZE) {
            Arrays.fill(keyBytes, (byte) 0);
            throw new IllegalArgumentException("The key must be a 256-bit AES key.");
        }

        SecretKey key = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
        Arrays.fill(keyBytes, (byte) 0);
        return key;
    }

    /** Encrypts UTF-8 text and returns a portable Base64-encoded message. */
    public static String encrypt(String plaintext, SecretKey key)
            throws GeneralSecurityException {
        if (plaintext == null) {
            throw new IllegalArgumentException("Plaintext must not be null.");
        }
        validateKey(key);

        byte[] iv = new byte[IV_SIZE_BYTES];
        SECURE_RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_SIZE_BITS, iv));
        cipher.updateAAD(new byte[]{FORMAT_VERSION});
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        ByteBuffer message = ByteBuffer.allocate(1 + iv.length + encrypted.length);
        message.put(FORMAT_VERSION).put(iv).put(encrypted);
        return Base64.getEncoder().encodeToString(message.array());
    }

    /** Decrypts a message produced by {@link #encrypt(String, SecretKey)}. */
    public static String decrypt(String encodedMessage, SecretKey key)
            throws GeneralSecurityException {
        if (encodedMessage == null) {
            throw new IllegalArgumentException("Ciphertext must not be null.");
        }
        validateKey(key);

        final byte[] message;
        try {
            message = Base64.getDecoder().decode(encodedMessage);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("The ciphertext is not valid Base64.", e);
        }

        // GCM appends a 16-byte tag, so even an empty plaintext needs this much data.
        int minimumLength = 1 + IV_SIZE_BYTES + TAG_SIZE_BITS / Byte.SIZE;
        if (message.length < minimumLength) {
            throw new IllegalArgumentException("The ciphertext is too short.");
        }

        ByteBuffer buffer = ByteBuffer.wrap(message);
        byte version = buffer.get();
        if (version != FORMAT_VERSION) {
            throw new IllegalArgumentException("Unsupported ciphertext version: " + version);
        }

        byte[] iv = new byte[IV_SIZE_BYTES];
        buffer.get(iv);
        byte[] encrypted = new byte[buffer.remaining()];
        buffer.get(encrypted);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_SIZE_BITS, iv));
        cipher.updateAAD(new byte[]{version});
        byte[] plaintext = cipher.doFinal(encrypted);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    private static void validateKey(SecretKey key) {
        if (key == null || key.getEncoded() == null
                || key.getEncoded().length != KEY_SIZE_BITS / Byte.SIZE
                || !KEY_ALGORITHM.equalsIgnoreCase(key.getAlgorithm())) {
            throw new IllegalArgumentException("A 256-bit AES key is required.");
        }
    }

    public static void main(String[] args) {
        try {
            if (args.length == 0) {
                runInteractiveDemo();
                return;
            }

            switch (args[0].toLowerCase()) {
                case "generate-key":
                    requireArgumentCount(args, 1);
                    System.out.println(encodeKey(generateKey()));
                    break;
                case "encrypt":
                    requireArgumentCount(args, 3);
                    System.out.println(encrypt(args[2], decodeKey(args[1])));
                    break;
                case "decrypt":
                    requireArgumentCount(args, 3);
                    System.out.println(decrypt(args[2], decodeKey(args[1])));
                    break;
                default:
                    printUsage();
                    System.exit(2);
            }
        } catch (AEADBadTagException e) {
            System.err.println("Decryption failed: wrong key or modified ciphertext.");
            System.exit(1);
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void runInteractiveDemo() throws GeneralSecurityException {
        Console console = System.console();
        if (console == null) {
            throw new IllegalArgumentException(
                    "No interactive console is available. Use one of the command-line modes.");
        }

        char[] input = console.readPassword("Plaintext: ");
        if (input == null) {
            throw new IllegalArgumentException("No plaintext was supplied.");
        }

        try {
            String plaintext = new String(input);
            SecretKey key = generateKey();
            String ciphertext = encrypt(plaintext, key);

            console.printf("Key (Base64):        %s%n", encodeKey(key));
            console.printf("Ciphertext (Base64): %s%n", ciphertext);
            console.printf("Decrypted text:      %s%n", decrypt(ciphertext, key));
        } finally {
            Arrays.fill(input, '\0');
        }
    }

    private static void requireArgumentCount(String[] args, int expected) {
        if (args.length != expected) {
            printUsage();
            throw new IllegalArgumentException("Incorrect number of arguments.");
        }
    }

    private static void printUsage() {
        System.err.println("Usage:");
        System.err.println("  java SensitiveDataEncryption generate-key");
        System.err.println("  java SensitiveDataEncryption encrypt <base64-key> <plaintext>");
        System.err.println("  java SensitiveDataEncryption decrypt <base64-key> <base64-ciphertext>");
        System.err.println("  java SensitiveDataEncryption   # interactive round-trip demo");
    }
}
