import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

/**
 * Demonstrates authenticated encryption and decryption of a person's name and
 * email address with an externally supplied AES key.
 */
public final class PiiEncryptionDemo {
    private static final String KEY_ENVIRONMENT_VARIABLE = "PII_AES_KEY";
    private static final int AES_KEY_BYTES = 32;
    private static final int GCM_NONCE_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int MAX_FIELD_BYTES = 1_000_000;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private PiiEncryptionDemo() {
    }

    public static void main(String[] args) {
        byte[] keyBytes = null;
        try {
            keyBytes = loadKey();
            SecretKey key = new SecretKeySpec(keyBytes, "AES");
            Person person = readPerson(args);

            String encrypted = encrypt(person, key);
            System.out.println("Encrypted PII (Base64): " + encrypted);

            Person recovered = decrypt(encrypted, key);
            System.out.println("Decrypted name: " + recovered.name());
            System.out.println("Decrypted email: " + recovered.email());
        } catch (IllegalArgumentException e) {
            System.err.println("Input error: " + e.getMessage());
            System.exit(2);
        } catch (AEADBadTagException e) {
            System.err.println("Decryption failed: the ciphertext, nonce, or key is incorrect.");
            System.exit(3);
        } catch (GeneralSecurityException | IOException e) {
            System.err.println("Encryption error: " + e.getMessage());
            System.exit(1);
        } finally {
            if (keyBytes != null) {
                Arrays.fill(keyBytes, (byte) 0);
            }
        }
    }

    private static byte[] loadKey() {
        String encodedKey = System.getenv(KEY_ENVIRONMENT_VARIABLE);
        if (encodedKey == null || encodedKey.isBlank()) {
            throw new IllegalArgumentException(
                    "Set " + KEY_ENVIRONMENT_VARIABLE + " to a Base64-encoded 256-bit AES key.");
        }

        final byte[] key;
        try {
            key = Base64.getDecoder().decode(encodedKey.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    KEY_ENVIRONMENT_VARIABLE + " must contain valid Base64.", e);
        }

        if (key.length != AES_KEY_BYTES) {
            Arrays.fill(key, (byte) 0);
            throw new IllegalArgumentException(
                    KEY_ENVIRONMENT_VARIABLE + " must decode to exactly 32 bytes (256 bits).");
        }
        return key;
    }

    private static Person readPerson(String[] args) {
        if (args.length == 2) {
            return new Person(requireValue(args[0], "name"), requireValue(args[1], "email"));
        }
        if (args.length != 0) {
            throw new IllegalArgumentException("Provide both name and email as arguments, or neither.");
        }

        Console console = System.console();
        if (console != null) {
            String name = console.readLine("Name: ");
            String email = console.readLine("Email: ");
            return new Person(requireValue(name, "name"), requireValue(email, "email"));
        }

        Scanner scanner = new Scanner(System.in, StandardCharsets.UTF_8);
        System.out.print("Name: ");
        String name = scanner.nextLine();
        System.out.print("Email: ");
        String email = scanner.nextLine();
        return new Person(requireValue(name, "name"), requireValue(email, "email"));
    }

    private static String requireValue(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(label + " must not be blank.");
        }
        return value;
    }

    public static String encrypt(Person person, SecretKey key)
            throws GeneralSecurityException, IOException {
        byte[] nonce = new byte[GCM_NONCE_BYTES];
        SECURE_RANDOM.nextBytes(nonce);

        byte[] plaintext = serialize(person);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, nonce));
            byte[] ciphertext = cipher.doFinal(plaintext);

            byte[] payload = new byte[nonce.length + ciphertext.length];
            System.arraycopy(nonce, 0, payload, 0, nonce.length);
            System.arraycopy(ciphertext, 0, payload, nonce.length, ciphertext.length);
            return Base64.getEncoder().encodeToString(payload);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    public static Person decrypt(String encodedPayload, SecretKey key)
            throws GeneralSecurityException, IOException {
        final byte[] payload;
        try {
            payload = Base64.getDecoder().decode(encodedPayload);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Encrypted PII must be valid Base64.", e);
        }

        // A valid value needs a nonce plus at least the 16-byte GCM tag.
        if (payload.length < GCM_NONCE_BYTES + (GCM_TAG_BITS / 8)) {
            throw new IllegalArgumentException("Encrypted PII is too short.");
        }

        byte[] nonce = Arrays.copyOfRange(payload, 0, GCM_NONCE_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(payload, GCM_NONCE_BYTES, payload.length);
        byte[] plaintext = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, nonce));
            plaintext = cipher.doFinal(ciphertext);
            return deserialize(plaintext);
        } finally {
            Arrays.fill(payload, (byte) 0);
            Arrays.fill(ciphertext, (byte) 0);
            if (plaintext != null) {
                Arrays.fill(plaintext, (byte) 0);
            }
        }
    }

    private static byte[] serialize(Person person) throws IOException {
        byte[] name = person.name().getBytes(StandardCharsets.UTF_8);
        byte[] email = person.email().getBytes(StandardCharsets.UTF_8);
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(buffer)) {
                output.writeInt(name.length);
                output.write(name);
                output.writeInt(email.length);
                output.write(email);
            }
            return buffer.toByteArray();
        } finally {
            Arrays.fill(name, (byte) 0);
            Arrays.fill(email, (byte) 0);
        }
    }

    private static Person deserialize(byte[] plaintext) throws IOException {
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(plaintext))) {
            String name = readField(input, "name");
            String email = readField(input, "email");
            if (input.available() != 0) {
                throw new IOException("Decrypted data contains unexpected trailing bytes.");
            }
            return new Person(name, email);
        }
    }

    private static String readField(DataInputStream input, String label) throws IOException {
        int length = input.readInt();
        if (length < 0 || length > MAX_FIELD_BYTES || length > input.available()) {
            throw new IOException("Invalid " + label + " length in decrypted data.");
        }
        byte[] value = new byte[length];
        try {
            input.readFully(value);
            return new String(value, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(value, (byte) 0);
        }
    }

    public record Person(String name, String email) {
        public Person {
            requireValue(name, "name");
            requireValue(email, "email");
        }
    }
}
