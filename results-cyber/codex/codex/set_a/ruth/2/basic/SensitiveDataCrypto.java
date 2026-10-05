import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Set;

/**
 * Command-line authenticated encryption for UTF-8 application data.
 *
 * <p>The ciphertext format is Base64(MAGIC || IV || AES-GCM ciphertext/tag).
 * The magic/version bytes are also authenticated as additional data.</p>
 */
public final class SensitiveDataCrypto {
    private static final byte[] MAGIC = {'S', 'D', 'C', 1};
    private static final int KEY_BITS = 256;
    private static final int KEY_BYTES = KEY_BITS / 8;
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final int TAG_BYTES = TAG_BITS / 8;
    private static final SecureRandom RANDOM = new SecureRandom();

    private SensitiveDataCrypto() {
    }

    public static void main(String[] args) {
        try {
            run(args);
        } catch (AEADBadTagException e) {
            fail("Decryption failed: the key is wrong or the ciphertext was modified.");
        } catch (FileAlreadyExistsException e) {
            fail("Refusing to overwrite existing key file: " + e.getFile());
        } catch (IllegalArgumentException | GeneralSecurityException | IOException e) {
            fail("Error: " + e.getMessage());
        }
    }

    private static void run(String[] args) throws GeneralSecurityException, IOException {
        if (args.length < 2 || args.length > 3) {
            usage();
            System.exit(2);
        }

        String command = args[0];
        Path keyFile = Path.of(args[1]);

        switch (command) {
            case "generate-key":
                if (args.length != 2) {
                    throw new IllegalArgumentException("generate-key takes only a key-file argument");
                }
                generateAndSaveKey(keyFile);
                System.out.println("Created a new AES-256 key in " + keyFile);
                break;
            case "encrypt": {
                byte[] plaintext = inputBytes(args);
                try {
                    String token = encrypt(plaintext, loadKey(keyFile));
                    System.out.println(token);
                } finally {
                    Arrays.fill(plaintext, (byte) 0);
                }
                break;
            }
            case "decrypt": {
                String token = inputString(args).trim();
                byte[] plaintext = decrypt(token, loadKey(keyFile));
                try {
                    System.out.write(plaintext);
                    System.out.flush();
                } finally {
                    Arrays.fill(plaintext, (byte) 0);
                }
                break;
            }
            default:
                throw new IllegalArgumentException("Unknown command: " + command);
        }
    }

    private static void generateAndSaveKey(Path keyFile)
            throws GeneralSecurityException, IOException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(KEY_BITS, RANDOM);
        byte[] encodedKey = generator.generateKey().getEncoded();
        byte[] fileContents = (Base64.getEncoder().encodeToString(encodedKey) + System.lineSeparator())
                .getBytes(StandardCharsets.US_ASCII);

        try {
            createPrivateFile(keyFile, fileContents);
        } finally {
            Arrays.fill(encodedKey, (byte) 0);
            Arrays.fill(fileContents, (byte) 0);
        }
    }

    private static void createPrivateFile(Path path, byte[] contents) throws IOException {
        try {
            Set<PosixFilePermission> permissions = PosixFilePermissions.fromString("rw-------");
            FileAttribute<Set<PosixFilePermission>> attribute =
                    PosixFilePermissions.asFileAttribute(permissions);
            Files.createFile(path, attribute);
        } catch (UnsupportedOperationException e) {
            Files.createFile(path);
        }

        try (OutputStream output = Files.newOutputStream(path)) {
            output.write(contents);
        } catch (IOException e) {
            Files.deleteIfExists(path);
            throw e;
        }
    }

    private static SecretKey loadKey(Path keyFile) throws IOException {
        String encoded = Files.readString(keyFile, StandardCharsets.US_ASCII).trim();
        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Key file is not valid Base64", e);
        }

        if (keyBytes.length != KEY_BYTES) {
            Arrays.fill(keyBytes, (byte) 0);
            throw new IllegalArgumentException("Key file must contain exactly a 256-bit AES key");
        }
        try {
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }

    /** Encrypts bytes and returns a portable, URL-safe Base64 ciphertext token. */
    public static String encrypt(byte[] plaintext, SecretKey key)
            throws GeneralSecurityException {
        requireAes256Key(key);
        byte[] iv = new byte[IV_BYTES];
        RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
        cipher.updateAAD(MAGIC);
        byte[] encrypted = cipher.doFinal(plaintext);

        byte[] envelope = new byte[MAGIC.length + iv.length + encrypted.length];
        System.arraycopy(MAGIC, 0, envelope, 0, MAGIC.length);
        System.arraycopy(iv, 0, envelope, MAGIC.length, iv.length);
        System.arraycopy(encrypted, 0, envelope, MAGIC.length + iv.length, encrypted.length);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(envelope);
    }

    /** Decrypts a token produced by {@link #encrypt(byte[], SecretKey)}. */
    public static byte[] decrypt(String token, SecretKey key)
            throws GeneralSecurityException {
        requireAes256Key(key);
        byte[] envelope;
        try {
            envelope = Base64.getUrlDecoder().decode(token);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Ciphertext is not valid URL-safe Base64", e);
        }

        if (envelope.length < MAGIC.length + IV_BYTES + TAG_BYTES) {
            throw new IllegalArgumentException("Ciphertext is too short");
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (envelope[i] != MAGIC[i]) {
                throw new IllegalArgumentException("Unsupported ciphertext format or version");
            }
        }

        byte[] iv = Arrays.copyOfRange(envelope, MAGIC.length, MAGIC.length + IV_BYTES);
        byte[] encrypted = Arrays.copyOfRange(envelope, MAGIC.length + IV_BYTES, envelope.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
        cipher.updateAAD(MAGIC);
        return cipher.doFinal(encrypted);
    }

    private static void requireAes256Key(SecretKey key) {
        if (key == null || !"AES".equalsIgnoreCase(key.getAlgorithm())) {
            throw new IllegalArgumentException("A 256-bit AES key is required");
        }
        byte[] encoded = key.getEncoded();
        try {
            if (encoded == null || encoded.length != KEY_BYTES) {
                throw new IllegalArgumentException("A 256-bit AES key is required");
            }
        } finally {
            if (encoded != null) {
                Arrays.fill(encoded, (byte) 0);
            }
        }
    }

    private static byte[] inputBytes(String[] args) throws IOException {
        return args.length == 3
                ? args[2].getBytes(StandardCharsets.UTF_8)
                : System.in.readAllBytes();
    }

    private static String inputString(String[] args) throws IOException {
        return args.length == 3
                ? args[2]
                : new String(System.in.readAllBytes(), StandardCharsets.US_ASCII);
    }

    private static void usage() {
        System.err.println("Usage:");
        System.err.println("  java SensitiveDataCrypto generate-key <key-file>");
        System.err.println("  java SensitiveDataCrypto encrypt <key-file> [plaintext]");
        System.err.println("  java SensitiveDataCrypto decrypt <key-file> [ciphertext]");
        System.err.println("If data is omitted, encrypt/decrypt reads it from standard input.");
    }

    private static void fail(String message) {
        System.err.println(message);
        System.exit(1);
    }
}
