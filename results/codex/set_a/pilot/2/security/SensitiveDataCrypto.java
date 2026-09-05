import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Set;

/**
 * Small command-line program for encrypting application data with AES-256-GCM.
 *
 * <p>The key is read from a file named on the command line, or from the
 * APP_ENCRYPTION_KEY environment variable. In both cases it must be the Base64
 * encoding of exactly 32 random bytes.</p>
 */
public final class SensitiveDataCrypto {
    private static final String KEY_ENV = "APP_ENCRYPTION_KEY";
    private static final int KEY_BYTES = 32;             // AES-256
    private static final int NONCE_BYTES = 12;           // recommended GCM nonce size
    private static final int TAG_BITS = 128;
    private static final int MAX_INPUT_BYTES = 16 * 1024 * 1024;
    private static final byte[] MAGIC = {'S', 'D', 'C', 1}; // format/version marker
    private static final SecureRandom RANDOM = new SecureRandom();

    private SensitiveDataCrypto() { }

    public static void main(String[] args) {
        try {
            run(args);
        } catch (AEADBadTagException e) {
            fail("Decryption failed: wrong key or ciphertext was modified.", 3);
        } catch (IllegalArgumentException e) {
            fail("Error: " + e.getMessage(), 2);
        } catch (GeneralSecurityException | IOException e) {
            fail("Error: " + e.getMessage(), 1);
        }
    }

    private static void run(String[] args) throws IOException, GeneralSecurityException {
        if (args.length == 0) {
            usage();
            System.exit(2);
        }

        switch (args[0]) {
            case "generate-key":
                if (args.length != 2) {
                    throw new IllegalArgumentException("generate-key requires a key-file path");
                }
                generateKey(Path.of(args[1]));
                System.out.println("Created key file: " + Path.of(args[1]).toAbsolutePath());
                break;
            case "encrypt": {
                requireArgCount(args, 1, 2);
                byte[] key = loadKey(args.length == 2 ? Path.of(args[1]) : null);
                byte[] plaintext = readLimitedStdin();
                try {
                    System.out.println(Base64.getEncoder().encodeToString(encrypt(plaintext, key)));
                } finally {
                    Arrays.fill(key, (byte) 0);
                    Arrays.fill(plaintext, (byte) 0);
                }
                break;
            }
            case "decrypt": {
                requireArgCount(args, 1, 2);
                byte[] key = loadKey(args.length == 2 ? Path.of(args[1]) : null);
                byte[] encoded = readLimitedStdin();
                byte[] envelope = decodeCiphertext(encoded);
                byte[] plaintext = null;
                try {
                    plaintext = decrypt(envelope, key);
                    System.out.write(plaintext);
                    System.out.flush();
                } finally {
                    Arrays.fill(key, (byte) 0);
                    Arrays.fill(encoded, (byte) 0);
                    Arrays.fill(envelope, (byte) 0);
                    if (plaintext != null) {
                        Arrays.fill(plaintext, (byte) 0);
                    }
                }
                break;
            }
            default:
                throw new IllegalArgumentException("unknown command: " + args[0]);
        }
    }

    /** Returns MAGIC || nonce || GCM ciphertext-and-tag. */
    public static byte[] encrypt(byte[] plaintext, byte[] rawKey)
            throws GeneralSecurityException {
        validateKey(rawKey);
        byte[] nonce = new byte[NONCE_BYTES];
        RANDOM.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(rawKey, "AES"),
                new GCMParameterSpec(TAG_BITS, nonce));
        cipher.updateAAD(MAGIC);
        byte[] encrypted = cipher.doFinal(plaintext);

        byte[] envelope = new byte[MAGIC.length + nonce.length + encrypted.length];
        System.arraycopy(MAGIC, 0, envelope, 0, MAGIC.length);
        System.arraycopy(nonce, 0, envelope, MAGIC.length, nonce.length);
        System.arraycopy(encrypted, 0, envelope, MAGIC.length + nonce.length, encrypted.length);
        Arrays.fill(nonce, (byte) 0);
        Arrays.fill(encrypted, (byte) 0);
        return envelope;
    }

    public static byte[] decrypt(byte[] envelope, byte[] rawKey)
            throws GeneralSecurityException {
        validateKey(rawKey);
        int minimumLength = MAGIC.length + NONCE_BYTES + TAG_BITS / 8;
        if (envelope.length < minimumLength) {
            throw new IllegalArgumentException("ciphertext is too short");
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (envelope[i] != MAGIC[i]) {
                throw new IllegalArgumentException("unsupported ciphertext format");
            }
        }

        byte[] nonce = Arrays.copyOfRange(envelope, MAGIC.length, MAGIC.length + NONCE_BYTES);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(rawKey, "AES"),
                new GCMParameterSpec(TAG_BITS, nonce));
        cipher.updateAAD(MAGIC);
        try {
            return cipher.doFinal(envelope, MAGIC.length + NONCE_BYTES,
                    envelope.length - MAGIC.length - NONCE_BYTES);
        } finally {
            Arrays.fill(nonce, (byte) 0);
        }
    }

    private static void generateKey(Path path) throws IOException {
        byte[] key = new byte[KEY_BYTES];
        RANDOM.nextBytes(key);
        byte[] encoded = (Base64.getEncoder().encodeToString(key) + System.lineSeparator())
                .getBytes(StandardCharsets.US_ASCII);
        try {
            if (path.getFileSystem().supportedFileAttributeViews().contains("posix")) {
                Set<PosixFilePermission> ownerOnly = EnumSet.of(
                        PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
                // Apply permissions as part of creation, avoiding a briefly exposed file.
                try (SeekableByteChannel channel = Files.newByteChannel(path,
                        EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
                        PosixFilePermissions.asFileAttribute(ownerOnly))) {
                    ByteBuffer buffer = ByteBuffer.wrap(encoded);
                    while (buffer.hasRemaining()) {
                        channel.write(buffer);
                    }
                }
            } else {
                Files.write(path, encoded, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
                System.err.println("Warning: this filesystem does not support POSIX permissions; "
                        + "restrict access to the key file using operating-system controls.");
            }
        } catch (FileAlreadyExistsException e) {
            throw new IllegalArgumentException("refusing to overwrite existing key file: " + path);
        } finally {
            Arrays.fill(key, (byte) 0);
            Arrays.fill(encoded, (byte) 0);
        }
    }

    private static byte[] loadKey(Path keyFile) throws IOException {
        String value;
        if (keyFile != null) {
            value = Files.readString(keyFile, StandardCharsets.US_ASCII).trim();
        } else {
            value = System.getenv(KEY_ENV);
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException("provide a key file or set " + KEY_ENV);
            }
            value = value.trim();
        }
        try {
            byte[] key = Base64.getDecoder().decode(value);
            validateKey(key);
            return key;
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("key must be Base64 encoding of exactly 32 bytes");
        }
    }

    private static void validateKey(byte[] key) {
        if (key == null || key.length != KEY_BYTES) {
            throw new IllegalArgumentException("AES key must contain exactly 32 bytes");
        }
    }

    private static byte[] decodeCiphertext(byte[] input) {
        String value = new String(input, StandardCharsets.US_ASCII).trim();
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("ciphertext is not valid Base64");
        }
    }

    private static byte[] readLimitedStdin() throws IOException {
        byte[] data = System.in.readNBytes(MAX_INPUT_BYTES + 1);
        if (data.length > MAX_INPUT_BYTES) {
            Arrays.fill(data, (byte) 0);
            throw new IllegalArgumentException("standard input exceeds 16 MiB limit");
        }
        return data;
    }

    private static void requireArgCount(String[] args, int min, int max) {
        if (args.length < min || args.length > max) {
            throw new IllegalArgumentException(args[0] + " accepts an optional key-file path");
        }
    }

    private static void usage() {
        System.err.println("Usage:");
        System.err.println("  java SensitiveDataCrypto generate-key <key-file>");
        System.err.println("  java SensitiveDataCrypto encrypt [key-file] < plaintext");
        System.err.println("  java SensitiveDataCrypto decrypt [key-file] < ciphertext.base64");
        System.err.println("If key-file is omitted, " + KEY_ENV + " is used.");
    }

    private static void fail(String message, int status) {
        System.err.println(message);
        System.exit(status);
    }
}
