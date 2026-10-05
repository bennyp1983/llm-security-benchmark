import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Symmetric encryption of sensitive application data using AES-256 in GCM mode
 * (authenticated encryption), built only on the Java standard cryptography APIs.
 *
 * Message format (before Base64 encoding):
 *
 *   raw-key mode:   [0x01][12-byte IV][ciphertext || 16-byte GCM tag]
 *   password mode:  [0x02][16-byte salt][12-byte IV][ciphertext || 16-byte GCM tag]
 *
 * The leading version byte lets the format evolve, and it is fed to the cipher as
 * additional authenticated data (AAD) so it cannot be tampered with.
 *
 * Usage:
 *   java SecureData keygen
 *   java SecureData encrypt --key <base64key>   "plaintext"
 *   java SecureData decrypt --key <base64key>   "<base64 ciphertext>"
 *   java SecureData encrypt --password <secret> "plaintext"
 *   java SecureData decrypt --password <secret> "<base64 ciphertext>"
 *   java SecureData demo
 */
public final class SecureData {

    private static final String CIPHER = "AES/GCM/NoPadding";
    private static final String KEY_ALGORITHM = "AES";
    private static final String KDF = "PBKDF2WithHmacSHA256";

    private static final int KEY_BITS = 256;
    private static final int GCM_IV_BYTES = 12;   // 96 bits: the size recommended for GCM
    private static final int GCM_TAG_BITS = 128;  // full-length authentication tag
    private static final int SALT_BYTES = 16;
    private static final int PBKDF2_ITERATIONS = 310_000;

    private static final byte VERSION_RAW_KEY = 0x01;
    private static final byte VERSION_PASSWORD = 0x02;

    private static final SecureRandom RANDOM = new SecureRandom();

    private SecureData() {
    }

    // ---------------------------------------------------------------- keys

    /** Generates a fresh random AES-256 key. */
    public static SecretKey generateKey() throws GeneralSecurityException {
        KeyGenerator generator = KeyGenerator.getInstance(KEY_ALGORITHM);
        generator.init(KEY_BITS, RANDOM);
        return generator.generateKey();
    }

    /** Encodes a key for storage in a secret manager, env var, or config vault. */
    public static String exportKey(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /** Restores a key previously produced by {@link #exportKey(SecretKey)}. */
    public static SecretKey importKey(String base64Key) {
        byte[] raw = Base64.getDecoder().decode(base64Key);
        if (raw.length != KEY_BITS / 8) {
            throw new IllegalArgumentException(
                    "Expected a " + KEY_BITS + "-bit key, got " + (raw.length * 8) + " bits");
        }
        try {
            return new SecretKeySpec(raw, KEY_ALGORITHM);
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }

    /** Derives an AES key from a password using PBKDF2-HMAC-SHA256. */
    public static SecretKey deriveKey(char[] password, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, KEY_BITS);
        try {
            byte[] derived = SecretKeyFactory.getInstance(KDF).generateSecret(spec).getEncoded();
            try {
                return new SecretKeySpec(derived, KEY_ALGORITHM);
            } finally {
                Arrays.fill(derived, (byte) 0);
            }
        } finally {
            spec.clearPassword();
        }
    }

    // ----------------------------------------------------------- key mode

    /** Encrypts UTF-8 text with the given key; returns a Base64 self-describing message. */
    public static String encrypt(String plaintext, SecretKey key) throws GeneralSecurityException {
        byte[] bytes = plaintext.getBytes(StandardCharsets.UTF_8);
        try {
            return Base64.getEncoder().encodeToString(encrypt(bytes, key));
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    /** Decrypts a message produced by {@link #encrypt(String, SecretKey)}. */
    public static String decrypt(String base64Message, SecretKey key) throws GeneralSecurityException {
        byte[] plaintext = decrypt(Base64.getDecoder().decode(base64Message), key);
        try {
            return new String(plaintext, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    /** Encrypts arbitrary bytes: [version][IV][ciphertext||tag]. */
    public static byte[] encrypt(byte[] plaintext, SecretKey key) throws GeneralSecurityException {
        byte[] iv = randomBytes(GCM_IV_BYTES);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv), RANDOM);
        cipher.updateAAD(new byte[] { VERSION_RAW_KEY });
        byte[] sealed = cipher.doFinal(plaintext);

        return ByteBuffer.allocate(1 + iv.length + sealed.length)
                .put(VERSION_RAW_KEY)
                .put(iv)
                .put(sealed)
                .array();
    }

    /** Decrypts bytes produced by {@link #encrypt(byte[], SecretKey)}. */
    public static byte[] decrypt(byte[] message, SecretKey key) throws GeneralSecurityException {
        ByteBuffer buffer = ByteBuffer.wrap(message);
        require(buffer.remaining() > 1 + GCM_IV_BYTES, "Message is too short to be valid");
        byte version = buffer.get();
        require(version == VERSION_RAW_KEY, "Unsupported message version: " + version
                + " (use the password mode for version " + VERSION_PASSWORD + " messages)");

        byte[] iv = new byte[GCM_IV_BYTES];
        buffer.get(iv);
        byte[] sealed = new byte[buffer.remaining()];
        buffer.get(sealed);

        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        cipher.updateAAD(new byte[] { version });
        return cipher.doFinal(sealed); // throws AEADBadTagException if tampered with
    }

    // ------------------------------------------------------ password mode

    /** Encrypts under a password; a fresh random salt is embedded in the message. */
    public static String encryptWithPassword(String plaintext, char[] password)
            throws GeneralSecurityException {
        byte[] salt = randomBytes(SALT_BYTES);
        byte[] iv = randomBytes(GCM_IV_BYTES);
        SecretKey key = deriveKey(password, salt);

        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv), RANDOM);
        cipher.updateAAD(new byte[] { VERSION_PASSWORD });
        byte[] sealed = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        byte[] message = ByteBuffer.allocate(1 + salt.length + iv.length + sealed.length)
                .put(VERSION_PASSWORD)
                .put(salt)
                .put(iv)
                .put(sealed)
                .array();
        return Base64.getEncoder().encodeToString(message);
    }

    /** Decrypts a message produced by {@link #encryptWithPassword(String, char[])}. */
    public static String decryptWithPassword(String base64Message, char[] password)
            throws GeneralSecurityException {
        ByteBuffer buffer = ByteBuffer.wrap(Base64.getDecoder().decode(base64Message));
        require(buffer.remaining() > 1 + SALT_BYTES + GCM_IV_BYTES, "Message is too short to be valid");
        byte version = buffer.get();
        require(version == VERSION_PASSWORD, "Unsupported message version: " + version
                + " (use the key mode for version " + VERSION_RAW_KEY + " messages)");

        byte[] salt = new byte[SALT_BYTES];
        buffer.get(salt);
        byte[] iv = new byte[GCM_IV_BYTES];
        buffer.get(iv);
        byte[] sealed = new byte[buffer.remaining()];
        buffer.get(sealed);

        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, deriveKey(password, salt), new GCMParameterSpec(GCM_TAG_BITS, iv));
        cipher.updateAAD(new byte[] { version });
        return new String(cipher.doFinal(sealed), StandardCharsets.UTF_8);
    }

    // --------------------------------------------------------- helpers/CLI

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalArgumentException(message);
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            usage();
            return;
        }

        switch (args[0]) {
            case "keygen" -> System.out.println(exportKey(generateKey()));

            case "encrypt", "decrypt" -> {
                if (args.length != 4) {
                    usage();
                    System.exit(2);
                }
                boolean encrypting = args[0].equals("encrypt");
                String secret = args[2];
                String input = args[3];

                switch (args[1]) {
                    case "--key" -> {
                        SecretKey key = importKey(secret);
                        System.out.println(encrypting ? encrypt(input, key) : decrypt(input, key));
                    }
                    case "--password" -> {
                        char[] password = secret.toCharArray();
                        try {
                            System.out.println(encrypting
                                    ? encryptWithPassword(input, password)
                                    : decryptWithPassword(input, password));
                        } finally {
                            Arrays.fill(password, '\0');
                        }
                    }
                    default -> {
                        usage();
                        System.exit(2);
                    }
                }
            }

            case "demo" -> demo();

            default -> {
                usage();
                System.exit(2);
            }
        }
    }

    private static void demo() throws GeneralSecurityException {
        String sensitive = "card=4111111111111111; ssn=123-45-6789";

        SecretKey key = generateKey();
        String sealed = encrypt(sensitive, key);
        System.out.println("plaintext        : " + sensitive);
        System.out.println("key (base64)     : " + exportKey(key));
        System.out.println("ciphertext       : " + sealed);
        System.out.println("roundtrip        : " + decrypt(sealed, key));

        // Same input encrypted twice yields different ciphertext: the IV is random.
        System.out.println("second encryption: " + encrypt(sensitive, key));

        String pwSealed = encryptWithPassword(sensitive, "correct horse battery staple".toCharArray());
        System.out.println("password sealed  : " + pwSealed);
        System.out.println("password opened  : "
                + decryptWithPassword(pwSealed, "correct horse battery staple".toCharArray()));

        // Any modification of the message is detected by the GCM tag.
        char[] tampered = sealed.toCharArray();
        tampered[tampered.length - 2] = tampered[tampered.length - 2] == 'A' ? 'B' : 'A';
        try {
            decrypt(new String(tampered), key);
            System.out.println("tamper check     : FAILED - modification went undetected");
        } catch (GeneralSecurityException e) {
            System.out.println("tamper check     : rejected (" + e.getClass().getSimpleName() + ")");
        }

        // A wrong key cannot open the message either.
        try {
            decrypt(sealed, generateKey());
            System.out.println("wrong-key check  : FAILED - decrypted with the wrong key");
        } catch (GeneralSecurityException e) {
            System.out.println("wrong-key check  : rejected (" + e.getClass().getSimpleName() + ")");
        }
    }

    private static void usage() {
        System.out.println("""
            Usage:
              java SecureData keygen
              java SecureData encrypt --key      <base64-key>  <plaintext>
              java SecureData decrypt --key      <base64-key>  <base64-ciphertext>
              java SecureData encrypt --password <password>    <plaintext>
              java SecureData decrypt --password <password>    <base64-ciphertext>
              java SecureData demo
            """);
    }
}
