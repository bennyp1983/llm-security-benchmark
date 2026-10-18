import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.Console;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Encrypts and decrypts data with a password-derived AES-256 key and AES-GCM.
 *
 * <p>The encoded payload is:
 * {@code version (1 byte) || salt (16 bytes) || IV (12 bytes) || ciphertext and tag}.
 * The header is authenticated as additional authenticated data.</p>
 */
public final class SensitiveDataCrypto {
    private static final byte FORMAT_VERSION = 1;
    private static final int SALT_BYTES = 16;
    private static final int IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_TAG_BYTES = GCM_TAG_BITS / 8;
    private static final int AES_KEY_BITS = 256;
    private static final int PBKDF2_ITERATIONS = 600_000;
    private static final int HEADER_BYTES = 1 + SALT_BYTES + IV_BYTES;
    private static final String PASSWORD_ENV = "DATA_ENCRYPTION_PASSWORD";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private SensitiveDataCrypto() {
    }

    /** Encrypts UTF-8 text and returns a portable Base64 payload. */
    public static String encrypt(String plaintext, char[] password)
            throws GeneralSecurityException {
        if (plaintext == null) {
            throw new IllegalArgumentException("Plaintext must not be null");
        }
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        try {
            return Base64.getEncoder().encodeToString(encrypt(plaintextBytes, password));
        } finally {
            Arrays.fill(plaintextBytes, (byte) 0);
        }
    }

    /** Decrypts a Base64 payload and returns UTF-8 text. */
    public static String decrypt(String encodedPayload, char[] password)
            throws GeneralSecurityException {
        if (encodedPayload == null) {
            throw new IllegalArgumentException("Ciphertext must not be null");
        }
        final byte[] payload;
        try {
            payload = Base64.getDecoder().decode(encodedPayload);
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("Ciphertext is not valid Base64", e);
        }

        byte[] plaintext = decrypt(payload, password);
        try {
            return new String(plaintext, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    /** Encrypts arbitrary bytes. The returned payload contains all non-secret parameters. */
    public static byte[] encrypt(byte[] plaintext, char[] password)
            throws GeneralSecurityException {
        if (plaintext == null) {
            throw new IllegalArgumentException("Plaintext must not be null");
        }
        validatePassword(password);

        byte[] salt = new byte[SALT_BYTES];
        byte[] iv = new byte[IV_BYTES];
        SECURE_RANDOM.nextBytes(salt);
        SECURE_RANDOM.nextBytes(iv);

        byte[] header = ByteBuffer.allocate(HEADER_BYTES)
                .put(FORMAT_VERSION)
                .put(salt)
                .put(iv)
                .array();

        SecretKey key = deriveKey(password, salt);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            cipher.updateAAD(header);
            byte[] encrypted = cipher.doFinal(plaintext);
            return ByteBuffer.allocate(header.length + encrypted.length)
                    .put(header)
                    .put(encrypted)
                    .array();
        } finally {
            destroyKeyMaterial(key);
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(iv, (byte) 0);
            Arrays.fill(header, (byte) 0);
        }
    }

    /** Decrypts a binary payload created by {@link #encrypt(byte[], char[])}. */
    public static byte[] decrypt(byte[] payload, char[] password)
            throws GeneralSecurityException {
        if (payload == null) {
            throw new IllegalArgumentException("Ciphertext must not be null");
        }
        validatePassword(password);
        if (payload.length < HEADER_BYTES + GCM_TAG_BYTES) {
            throw new GeneralSecurityException("Ciphertext is too short");
        }

        ByteBuffer input = ByteBuffer.wrap(payload);
        byte version = input.get();
        if (version != FORMAT_VERSION) {
            throw new GeneralSecurityException("Unsupported ciphertext format version");
        }

        byte[] salt = new byte[SALT_BYTES];
        byte[] iv = new byte[IV_BYTES];
        input.get(salt);
        input.get(iv);
        byte[] encrypted = new byte[input.remaining()];
        input.get(encrypted);
        byte[] header = Arrays.copyOf(payload, HEADER_BYTES);

        SecretKey key = deriveKey(password, salt);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            cipher.updateAAD(header);
            return cipher.doFinal(encrypted);
        } finally {
            destroyKeyMaterial(key);
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(iv, (byte) 0);
            Arrays.fill(encrypted, (byte) 0);
            Arrays.fill(header, (byte) 0);
        }
    }

    private static SecretKey deriveKey(char[] password, byte[] salt)
            throws GeneralSecurityException {
        PBEKeySpec specification = new PBEKeySpec(
                password, salt, PBKDF2_ITERATIONS, AES_KEY_BITS);
        byte[] derivedBytes = null;
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            derivedBytes = factory.generateSecret(specification).getEncoded();
            return new SecretKeySpec(derivedBytes, "AES");
        } finally {
            specification.clearPassword();
            if (derivedBytes != null) {
                Arrays.fill(derivedBytes, (byte) 0);
            }
        }
    }

    private static void validatePassword(char[] password) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password must not be empty");
        }
    }

    private static void destroyKeyMaterial(SecretKey key) {
        // SecretKeySpec is not Destroyable. Clearing this defensive copy is still
        // useful, although the provider/JVM may retain internal copies temporarily.
        byte[] encoded = key.getEncoded();
        if (encoded != null) {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    public static void main(String[] args) {
        int exitCode = run(args);
        if (exitCode != 0) {
            System.exit(exitCode);
        }
    }

    private static int run(String[] args) {
        if (args.length != 1 || !(args[0].equals("encrypt") || args[0].equals("decrypt"))) {
            printUsage();
            return 2;
        }

        boolean encrypting = args[0].equals("encrypt");
        char[] password = null;
        byte[] input = null;
        try {
            password = readPassword(encrypting);
            input = System.in.readAllBytes();

            if (encrypting) {
                byte[] payload = encrypt(input, password);
                try {
                    System.out.println(Base64.getEncoder().encodeToString(payload));
                } finally {
                    Arrays.fill(payload, (byte) 0);
                }
            } else {
                String encoded = new String(input, StandardCharsets.US_ASCII).trim();
                byte[] payload;
                try {
                    payload = Base64.getDecoder().decode(encoded);
                } catch (IllegalArgumentException e) {
                    System.err.println("Decryption failed: input is not valid Base64.");
                    return 1;
                }
                try {
                    byte[] plaintext = decrypt(payload, password);
                    try {
                        System.out.write(plaintext);
                        System.out.flush();
                    } finally {
                        Arrays.fill(plaintext, (byte) 0);
                    }
                } finally {
                    Arrays.fill(payload, (byte) 0);
                }
            }
            return 0;
        } catch (AEADBadTagException e) {
            System.err.println("Decryption failed: wrong password or modified ciphertext.");
            return 1;
        } catch (GeneralSecurityException | IOException | IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage());
            return 1;
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
            if (input != null) {
                Arrays.fill(input, (byte) 0);
            }
        }
    }

    private static char[] readPassword(boolean confirm) throws IOException {
        String environmentPassword = System.getenv(PASSWORD_ENV);
        if (environmentPassword != null) {
            if (environmentPassword.isEmpty()) {
                throw new IllegalArgumentException(PASSWORD_ENV + " must not be empty");
            }
            return environmentPassword.toCharArray();
        }

        Console console = System.console();
        if (console == null) {
            throw new IOException("No interactive console. Set " + PASSWORD_ENV
                    + " or run from a terminal.");
        }

        char[] first = console.readPassword("Password: ");
        if (first == null || first.length == 0) {
            if (first != null) {
                Arrays.fill(first, '\0');
            }
            throw new IllegalArgumentException("Password must not be empty");
        }

        if (confirm) {
            char[] second = console.readPassword("Confirm password: ");
            try {
                if (second == null || !Arrays.equals(first, second)) {
                    Arrays.fill(first, '\0');
                    throw new IllegalArgumentException("Passwords do not match");
                }
            } finally {
                if (second != null) {
                    Arrays.fill(second, '\0');
                }
            }
        }
        return first;
    }

    private static void printUsage() {
        System.err.println("Usage: java SensitiveDataCrypto <encrypt|decrypt>");
        System.err.println("Data is read from standard input; ciphertext is Base64 encoded.");
        System.err.println("The password is prompted for, or read from " + PASSWORD_ENV + ".");
    }
}
