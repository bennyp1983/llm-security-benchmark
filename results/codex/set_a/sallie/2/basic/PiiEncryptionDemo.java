import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Demonstrates an authenticated AES encryption/decryption round trip for PII.
 */
public final class PiiEncryptionDemo {
    private static final int AES_KEY_BITS = 256;
    private static final int IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final byte FORMAT_VERSION = 1;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private PiiEncryptionDemo() {
    }

    public static void main(String[] args) {
        try {
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(System.in, StandardCharsets.UTF_8));

            System.out.print("Enter the person's name: ");
            String name = requireValue(reader.readLine(), "Name");

            System.out.print("Enter the person's email address: ");
            String email = requireValue(reader.readLine(), "Email address");

            SecretKey key = generateKey();
            byte[] plaintext = serialize(name, email);
            String encrypted = encryptToBase64(plaintext, key);

            System.out.println("\nEncrypted PII (Base64):");
            System.out.println(encrypted);

            byte[] decrypted = decryptFromBase64(encrypted, key);
            Person recovered = deserialize(decrypted);

            System.out.println("\nDecrypted PII:");
            System.out.println("Name: " + recovered.name);
            System.out.println("Email: " + recovered.email);
        } catch (IllegalArgumentException e) {
            System.err.println("Input error: " + e.getMessage());
            System.exit(1);
        } catch (IOException | GeneralSecurityException e) {
            System.err.println("Unable to complete the encryption demo: " + e.getMessage());
            System.exit(1);
        }
    }

    private static String requireValue(String value, String label) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(label + " must not be empty.");
        }
        return value;
    }

    private static SecretKey generateKey() throws GeneralSecurityException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(AES_KEY_BITS, SECURE_RANDOM);
        return generator.generateKey();
    }

    private static byte[] serialize(String name, String email) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(bytes)) {
            writeUtf8(output, name);
            writeUtf8(output, email);
        }
        return bytes.toByteArray();
    }

    private static void writeUtf8(DataOutputStream output, String value) throws IOException {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        output.writeInt(encoded.length);
        output.write(encoded);
    }

    private static String encryptToBase64(byte[] plaintext, SecretKey key)
            throws GeneralSecurityException {
        byte[] iv = new byte[IV_BYTES];
        SECURE_RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        cipher.updateAAD(new byte[]{FORMAT_VERSION});
        byte[] ciphertext = cipher.doFinal(plaintext);

        ByteBuffer payload = ByteBuffer.allocate(1 + iv.length + ciphertext.length);
        payload.put(FORMAT_VERSION);
        payload.put(iv);
        payload.put(ciphertext);
        return Base64.getEncoder().encodeToString(payload.array());
    }

    private static byte[] decryptFromBase64(String encoded, SecretKey key)
            throws GeneralSecurityException {
        byte[] payload;
        try {
            payload = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("The encrypted data is not valid Base64.", e);
        }

        if (payload.length < 1 + IV_BYTES + (GCM_TAG_BITS / 8)) {
            throw new GeneralSecurityException("The encrypted data is too short.");
        }

        ByteBuffer buffer = ByteBuffer.wrap(payload);
        byte version = buffer.get();
        if (version != FORMAT_VERSION) {
            throw new GeneralSecurityException("Unsupported encrypted-data format.");
        }

        byte[] iv = new byte[IV_BYTES];
        buffer.get(iv);
        byte[] ciphertext = new byte[buffer.remaining()];
        buffer.get(ciphertext);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        cipher.updateAAD(new byte[]{version});
        return cipher.doFinal(ciphertext);
    }

    private static Person deserialize(byte[] data) throws IOException {
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(data))) {
            String name = readUtf8(input);
            String email = readUtf8(input);
            if (input.available() != 0) {
                throw new IOException("The decrypted data contains unexpected bytes.");
            }
            return new Person(name, email);
        }
    }

    private static String readUtf8(DataInputStream input) throws IOException {
        int length = input.readInt();
        if (length < 0 || length > input.available()) {
            throw new IOException("The decrypted data is malformed.");
        }
        byte[] encoded = new byte[length];
        input.readFully(encoded);
        return new String(encoded, StandardCharsets.UTF_8);
    }

    private static final class Person {
        private final String name;
        private final String email;

        private Person(String name, String email) {
            this.name = name;
            this.email = email;
        }
    }
}
