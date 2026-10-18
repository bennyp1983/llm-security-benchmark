import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Password-based or key-based authenticated symmetric encryption for application
 * secrets, built only on the JDK's own crypto APIs (javax.crypto + java.security).
 *
 * Cipher:  AES-256 in GCM mode (authenticated encryption, 128-bit tag).
 * Keys:    either a raw 256-bit AES key, or a passphrase stretched with
 *          PBKDF2WithHmacSHA256 (310,000 iterations by default).
 * Output:  a single portable text token, "aesgcm$v1&base64url(header||ciphertext||tag)".
 *
 * Each call to encrypt() draws a fresh 16-byte salt and a fresh 12-byte IV from
 * SecureRandom, so encrypting the same value twice never yields the same token.
 * The header (version, KDF id, iteration count, salt, IV) is fed to GCM as
 * additional authenticated data, so flipping any header byte makes decryption
 * fail instead of silently changing how the key is derived.
 *
 * See README.md for the token layout, the CLI, and the security notes.
 */
public final class SymmetricCrypto {

    /** Text prefix written in front of every token, so a token is self-describing. */
    public static final String SCHEME_PREFIX = "aesgcm$v1$";

    private static final byte VERSION = 1;
    private static final byte KDF_PBKDF2_SHA256 = 1;
    private static final byte KDF_RAW_KEY = 2;

    private static final int SALT_LEN = 16;
    private static final int IV_LEN = 12;
    private static final int TAG_BITS = 128;
    private static final int KEY_BITS = 256;
    private static final int KEY_BYTES = KEY_BITS / 8;

    /** OWASP 2023 floor for PBKDF2-HMAC-SHA256. */
    public static final int DEFAULT_ITERATIONS = 310_000;
    private static final int MIN_ITERATIONS = 100_000;
    private static final int MAX_ITERATIONS = 5_000_000;

    /** Guard against unbounded memory use on hostile or accidental input. */
    public static final int MAX_INPUT_BYTES = 64 * 1024 * 1024;

    // Byte offsets inside the decoded token payload, for the self test's tampering.
    // layout: 0=version 1=kdf id 2..5=iterations 6=salt length 7..=salt | iv length | iv
    private static final int HDR_ITER = 2;
    private static final int HDR_SALT = 7;
    private static final int HDR_IV = HDR_SALT + SALT_LEN + 1;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder TOKEN_ENCODER =
            Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder TOKEN_DECODER = Base64.getUrlDecoder();

    /** Strategy for turning a token's header back into the key that sealed it. */
    public interface KeyResolver {
        SecretKey resolve(byte kdfId, int iterations, byte[] salt) throws GeneralSecurityException;
    }

    private SymmetricCrypto() {
    }

    // ---------------------------------------------------------------- keying

    /** Generates a fresh random 256-bit AES key, Base64 encoded for storage. */
    public static String generateBase64Key() {
        byte[] key = new byte[KEY_BYTES];
        RANDOM.nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }

    /**
     * Decodes a Base64 key (standard or URL-safe alphabet) into an AES key.
     *
     * @throws IllegalArgumentException if the text is not Base64 or not 16/24/32 bytes
     */
    public static SecretKey aesKeyFromBase64(String base64) {
        // Whitespace is tolerated so a key pasted from a wrapped file still works, but
        // the alphabet itself is checked strictly: the MIME decoder would quietly drop
        // junk characters and hand back whatever bytes survived.
        String text = base64.trim().replaceAll("\\s", "");
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(text);
        } catch (IllegalArgumentException standard) {
            try {
                raw = Base64.getUrlDecoder().decode(text);
            } catch (IllegalArgumentException urlSafe) {
                urlSafe.addSuppressed(standard);
                throw new IllegalArgumentException("key is not valid Base64", urlSafe);
            }
        }
        try {
            requireKeyLength(raw.length);
            return new SecretKeySpec(raw, "AES");
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }

    private static void requireKeyLength(int length) {
        if (length != 16 && length != 24 && length != 32) {
            throw new IllegalArgumentException("AES key must be 16, 24 or 32 bytes, got "
                    + length);
        }
    }

    /**
     * Stretches a passphrase into an AES key. The caller keeps ownership of
     * {@code passphrase}; it is not modified here (PBEKeySpec copies it).
     */
    public static SecretKey deriveKey(char[] passphrase, byte[] salt, int iterations)
            throws GeneralSecurityException {
        if (passphrase == null || passphrase.length == 0) {
            throw new GeneralSecurityException("passphrase is empty");
        }
        if (salt == null || salt.length < 8) {
            throw new GeneralSecurityException("salt is too short");
        }
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
            throw new GeneralSecurityException(
                    "iteration count " + iterations + " is outside the accepted range "
                            + MIN_ITERATIONS + ".." + MAX_ITERATIONS);
        }
        PBEKeySpec spec = new PBEKeySpec(passphrase, salt, iterations, KEY_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] encoded = factory.generateSecret(spec).getEncoded();
            try {
                return new SecretKeySpec(encoded, "AES");
            } finally {
                Arrays.fill(encoded, (byte) 0);
            }
        } finally {
            spec.clearPassword();
        }
    }

    private static void requireAESKey(SecretKey key) {
        if (key == null || !"AES".equalsIgnoreCase(key.getAlgorithm())) {
            throw new IllegalArgumentException("an AES key is required");
        }
        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new IllegalArgumentException("key material is not extractable");
        }
        try {
            requireKeyLength(encoded.length);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    // ------------------------------------------------------------ encrypt

    /** Encrypts with a passphrase-derived key using {@link #DEFAULT_ITERATIONS}. */
    public static String encryptWithPassphrase(char[] passphrase, byte[] plaintext)
            throws GeneralSecurityException {
        return encryptWithPassphrase(passphrase, plaintext, DEFAULT_ITERATIONS);
    }

    /** Encrypts with a passphrase-derived key, stretching it with PBKDF2. */
    public static String encryptWithPassphrase(char[] passphrase, byte[] plaintext, int iterations)
            throws GeneralSecurityException {
        requirePlaintext(plaintext);
        byte[] salt = new byte[SALT_LEN];
        RANDOM.nextBytes(salt);
        SecretKey key = deriveKey(passphrase, salt, iterations);
        return seal(key, plaintext, KDF_PBKDF2_SHA256, iterations, salt);
    }

    /** Encrypts with a caller-supplied AES key (no KDF, no salt). */
    public static String encryptWithKey(SecretKey key, byte[] plaintext)
            throws GeneralSecurityException {
        requirePlaintext(plaintext);
        requireAESKey(key);
        return seal(key, plaintext, KDF_RAW_KEY, 0, new byte[0]);
    }

    private static void requirePlaintext(byte[] plaintext) {
        if (plaintext == null) {
            throw new IllegalArgumentException("plaintext is null");
        }
        if (plaintext.length > MAX_INPUT_BYTES) {
            throw new IllegalArgumentException("input of " + plaintext.length
                    + " bytes exceeds the " + MAX_INPUT_BYTES + " byte limit");
        }
    }

    /**
     * Core seal. Header is authenticated as additional authenticated data, so the
     * returned ciphertext is bound to the exact salt/IV/iteration parameters used.
     */
    private static String seal(SecretKey key, byte[] plaintext, byte kdfId, int iterations,
                               byte[] salt) throws GeneralSecurityException {
        byte[] iv = new byte[IV_LEN];
        RANDOM.nextBytes(iv);

        ByteBuffer header = ByteBuffer.allocate(2 + Integer.BYTES + 1 + salt.length
                + 1 + iv.length);
        header.put(VERSION)
                .put(kdfId)
                .putInt(iterations)
                .put((byte) salt.length).put(salt)
                .put((byte) iv.length).put(iv);
        byte[] headerBytes = header.array();

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
        cipher.updateAAD(headerBytes);
        byte[] body = cipher.doFinal(plaintext);

        ByteBuffer token = ByteBuffer.allocate(headerBytes.length + body.length);
        token.put(headerBytes).put(body);
        Arrays.fill(iv, (byte) 0);
        return SCHEME_PREFIX + TOKEN_ENCODER.encodeToString(token.array());
    }

    // ------------------------------------------------------------ decrypt

    /** Decrypts a token with a passphrase. */
    public static byte[] decryptWithPassphrase(String token, char[] passphrase)
            throws GeneralSecurityException {
        return decrypt(token, (kdfId, iterations, salt) -> {
            if (kdfId != KDF_PBKDF2_SHA256) {
                throw new GeneralSecurityException(
                        "token was sealed with a raw key, not a passphrase; use --key");
            }
            return deriveKey(passphrase, salt, iterations);
        });
    }

    /** Decrypts a token with a raw AES key. */
    public static byte[] decryptWithKey(String token, SecretKey key)
            throws GeneralSecurityException {
        return decrypt(token, (kdfId, iterations, salt) -> {
            if (kdfId != KDF_RAW_KEY) {
                throw new GeneralSecurityException(
                        "token was sealed with a passphrase-derived key; supply the passphrase");
            }
            requireAESKey(key);
            return key;
        });
    }

    /** Decrypts a token, obtaining the key through {@code resolver}. */
    public static byte[] decrypt(String token, KeyResolver resolver)
            throws GeneralSecurityException {
        if (token == null) {
            throw new GeneralSecurityException("token is null");
        }
        String trimmed = token.trim();
        if (!trimmed.startsWith(SCHEME_PREFIX)) {
            throw new GeneralSecurityException(
                    "token does not start with the expected prefix " + SCHEME_PREFIX);
        }
        byte[] payload;
        try {
            payload = TOKEN_DECODER.decode(trimmed.substring(SCHEME_PREFIX.length()));
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("token body is not valid base64url", e);
        }

        ByteBuffer in = ByteBuffer.wrap(payload);
        byte version = in.get();
        if (version != VERSION) {
            throw new GeneralSecurityException("unsupported token version " + version);
        }
        byte kdfId = in.get();
        if (kdfId != KDF_PBKDF2_SHA256 && kdfId != KDF_RAW_KEY) {
            throw new GeneralSecurityException("unknown key derivation id " + kdfId);
        }
        int iterations = in.getInt();
        byte[] salt = readVarField(in, "salt", 64);
        byte[] iv = readVarField(in, "iv", IV_LEN);
        if (iv.length != IV_LEN) {
            throw new GeneralSecurityException("iv must be " + IV_LEN + " bytes, found "
                    + iv.length);
        }
        if (kdfId == KDF_RAW_KEY && (iterations != 0 || salt.length != 0)) {
            throw new GeneralSecurityException("raw-key token must carry no salt or iterations");
        }
        if (kdfId == KDF_PBKDF2_SHA256 && salt.length < 8) {
            throw new GeneralSecurityException("token carries a salt that is too short");
        }

        // The header ends here; the AAD must cover exactly these bytes, so record the
        // position before the body is consumed from the buffer.
        int headerLen = in.position();
        byte[] body = new byte[in.remaining()];
        in.get(body);
        if (body.length < TAG_BITS / 8) {
            throw new GeneralSecurityException("token is truncated: no room for the GCM tag");
        }
        byte[] headerBytes = Arrays.copyOf(payload, headerLen);

        SecretKey key = resolver.resolve(kdfId, iterations, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
        cipher.updateAAD(headerBytes);
        try {
            return cipher.doFinal(body);
        } finally {
            Arrays.fill(iv, (byte) 0);
            Arrays.fill(salt, (byte) 0);
        }
    }

    private static byte[] readVarField(ByteBuffer in, String name, int maxLen)
            throws GeneralSecurityException {
        if (!in.hasRemaining()) {
            throw new GeneralSecurityException("token is truncated: missing " + name);
        }
        int len = in.get() & 0xFF;
        if (len > maxLen || len > in.remaining()) {
            throw new GeneralSecurityException("token declares an invalid " + name
                    + " length (" + len + ")");
        }
        byte[] out = new byte[len];
        in.get(out);
        return out;
    }

    // -------------------------------------------------------------- self-test

    /**
     * Round-trip and tamper-detection checks. {@code main} turns the tally into an
     * exit code.
     */
    static Checks runSelfTest(PrintStream out) {
        Checks c = new Checks(out);
        char[] pw = "correct horse battery staple".toCharArray();
        char[] wrong = "correct horse battery stapl3".toCharArray();

        try {
            byte[] ascii = "db-password=s3cr3t!".getBytes(StandardCharsets.UTF_8);
            String t1 = encryptWithPassphrase(pw, ascii);
            c.check("passphrase round trip preserves bytes",
                    Arrays.equals(ascii, decryptWithPassphrase(t1, pw)));
            c.check("token carries the scheme prefix", t1.startsWith(SCHEME_PREFIX));
            c.check("token body is base64url", isBase64Url(t1.substring(SCHEME_PREFIX.length())));

            String t2 = encryptWithPassphrase(pw, ascii);
            c.check("encrypting twice yields different tokens", !t1.equals(t2));
            c.check("both tokens decrypt to the same plaintext",
                    Arrays.equals(decryptWithPassphrase(t1, pw),
                            decryptWithPassphrase(t2, pw)));

            // Non-ASCII built from code points so this source stays pure ASCII.
            String unicode = "api-token-" + new String(new int[] {0x4F60, 0x597D}, 0, 2)
                    + new String(Character.toChars(0x1F510)) + " cafe" + (char) 0xE9;
            byte[] uniBytes = unicode.getBytes(StandardCharsets.UTF_8);
            c.check("UTF-8 multibyte round trip",
                    Arrays.equals(uniBytes,
                            decryptWithPassphrase(encryptWithPassphrase(pw, uniBytes), pw)));

            c.check("empty plaintext round trip",
                    decryptWithPassphrase(encryptWithPassphrase(pw, new byte[0]), pw).length == 0);

            byte[] big = new byte[1024 * 1024];
            RANDOM.nextBytes(big);
            c.check("1 MiB binary round trip",
                    Arrays.equals(big, decryptWithPassphrase(encryptWithPassphrase(pw, big), pw)));

            SecretKey raw = aesKeyFromBase64(generateBase64Key());
            String t3 = encryptWithKey(raw, ascii);
            c.check("raw-key round trip preserves bytes",
                    Arrays.equals(ascii, decryptWithKey(t3, raw)));
            c.check("raw-key token authenticates too",
                    !t3.equals(encryptWithKey(raw, ascii)));

            c.expectFailure("wrong passphrase is rejected", GeneralSecurityException.class,
                    () -> decryptWithPassphrase(t1, wrong));
            c.expectFailure("wrong raw key is rejected", GeneralSecurityException.class,
                    () -> decryptWithKey(t3, aesKeyFromBase64(generateBase64Key())));
            c.expectFailure("passphrase cannot open a raw-key token",
                    GeneralSecurityException.class, () -> decryptWithPassphrase(t3, pw));
            c.expectFailure("raw key cannot open a passphrase token",
                    GeneralSecurityException.class, () -> decryptWithKey(t1, raw));

            c.expectFailure("tampered GCM tag is rejected",
                    GeneralSecurityException.class,
                    () -> decryptWithPassphrase(mutate(t1, -1, (byte) 0x01), pw));
            c.expectFailure("tampered ciphertext byte is rejected",
                    GeneralSecurityException.class,
                    () -> decryptWithPassphrase(mutate(t1, -18, (byte) 0x01), pw));
            c.expectFailure("tampered salt is rejected",
                    GeneralSecurityException.class,
                    () -> decryptWithPassphrase(mutate(t1, HDR_SALT, (byte) 0x80), pw));
            c.expectFailure("tampered iteration count is rejected",
                    GeneralSecurityException.class,
                    () -> decryptWithPassphrase(mutate(t1, HDR_ITER + 3, (byte) 0x01), pw));
            c.expectFailure("tampered IV is rejected",
                    GeneralSecurityException.class,
                    () -> decryptWithPassphrase(mutate(t1, HDR_IV, (byte) 0x40), pw));

            c.expectFailure("truncated token is rejected", GeneralSecurityException.class,
                    () -> decryptWithPassphrase(t1.substring(0, t1.length() - 8), pw));
            c.expectFailure("non-base64 token body is rejected", GeneralSecurityException.class,
                    () -> decryptWithPassphrase(SCHEME_PREFIX + "not base64 !!!", pw));
            c.expectFailure("foreign prefix is rejected", GeneralSecurityException.class,
                    () -> decryptWithPassphrase("aesgcm$v9$" + t1.substring(SCHEME_PREFIX.length()),
                            pw));

            // A token that advertises a cheap KDF must be refused by the iteration floor,
            // not merely fail on a key mismatch: seal it with a key derived at exactly the
            // advertised (too low) round count, so the policy is the only thing standing
            // between this token and a successful decrypt.
            byte[] weakSalt = new byte[SALT_LEN];
            RANDOM.nextBytes(weakSalt);
            int weakRounds = 1_000;
            PBEKeySpec weakSpec = new PBEKeySpec(pw, weakSalt, weakRounds, KEY_BITS);
            SecretKey weakKey = new SecretKeySpec(
                    SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                            .generateSecret(weakSpec).getEncoded(), "AES");
            String cheap = seal(weakKey, ascii, KDF_PBKDF2_SHA256, weakRounds, weakSalt);
            c.expectFailure("weak iteration count is refused", GeneralSecurityException.class,
                    () -> decryptWithPassphrase(cheap, pw));

            c.expectFailure("short AES key is refused", IllegalArgumentException.class,
                    () -> aesKeyFromBase64(Base64.getEncoder().encodeToString(new byte[8])));
            c.expectFailure("non-base64 key argument is refused", IllegalArgumentException.class,
                    () -> aesKeyFromBase64("not-a-key!"));
            c.expectFailure("undersized raw SecretKeySpec is refused",
                    IllegalArgumentException.class,
                    () -> encryptWithKey(new SecretKeySpec(new byte[8], "AES"), ascii));
            c.expectFailure("null plaintext is refused", IllegalArgumentException.class,
                    () -> encryptWithKey(raw, null));

            c.check("generateBase64Key yields a 256-bit key",
                    aesKeyFromBase64(generateBase64Key()).getEncoded().length == KEY_BYTES);
        } catch (Exception e) {
            c.fail("unexpected exception escaped the self test: " + e);
        } finally {
            Arrays.fill(pw, '\0');
            Arrays.fill(wrong, '\0');
        }
        return c;
    }

    /**
     * Re-encodes a token with one decoded-payload byte XORed. Negative indexes count
     * back from the end of the payload. Test-only.
     */
    private static String mutate(String token, int payloadIndex, byte xor) {
        byte[] payload = TOKEN_DECODER.decode(token.substring(SCHEME_PREFIX.length()));
        int i = payloadIndex < 0 ? payload.length + payloadIndex : payloadIndex;
        if (i < 0 || i >= payload.length) {
            throw new IllegalArgumentException("mutation index out of range: " + payloadIndex);
        }
        payload[i] ^= xor;
        return SCHEME_PREFIX + TOKEN_ENCODER.encodeToString(payload);
    }

    private static boolean isBase64Url(String s) {
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            boolean ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
                    || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_';
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    private static final class Checks {
        private final PrintStream out;
        private int checks;
        private int failures;

        Checks(PrintStream out) {
            this.out = out;
        }

        void check(String label, boolean ok) {
            checks++;
            if (ok) {
                out.println("  PASS  " + label);
            } else {
                failures++;
                out.println("  FAIL  " + label);
            }
        }

        void expectFailure(String label, Class<? extends Throwable> expected,
                           ThrowingCall call) {
            checks++;
            try {
                call.call();
                failures++;
                out.println("  FAIL  " + label + " (nothing was thrown)");
            } catch (Throwable e) {
                if (expected.isInstance(e)) {
                    out.println("  PASS  " + label);
                } else {
                    failures++;
                    out.println("  FAIL  " + label + " (threw " + e.getClass().getName() + ")");
                }
            }
        }

        void fail(String label) {
            checks++;
            failures++;
            out.println("  FAIL  " + label);
        }
    }

    private interface ThrowingCall {
        Object call() throws Exception;
    }

    // ------------------------------------------------------------ CLI plumbing

    public static void main(String[] args) {
        try {
            System.exit(run(args, System.out, System.err, System.in));
        } catch (UsageError e) {
            System.err.println("error: " + e.getMessage());
            System.exit(2);
        } catch (Exception e) {
            System.err.println("error: " + e.getMessage());
            System.exit(1);
        }
    }

    /** CLI entry point, parameterised so the self test stays out of the way. */
    static int run(String[] args, PrintStream out, PrintStream err, InputStream stdin)
            throws Exception {
        if (args.length == 0 || isHelp(args[0])) {
            printUsage(out);
            return 0;
        }

        String command = args[0];
        switch (command) {
            case "selftest": {
                out.println("running self test");
                Checks c = runSelfTest(out);
                out.println(c.failures == 0
                        ? "SELFTEST PASSED (" + c.checks + " checks)"
                        : "SELFTEST FAILED: " + c.failures + " of " + c.checks + " checks failed");
                return c.failures == 0 ? 0 : 1;
            }
            case "keygen": {
                out.println(generateBase64Key());
                return 0;
            }
            case "demo": {
                demo(out);
                return 0;
            }
            case "encrypt":
            case "decrypt":
                break;
            default:
                printUsage(err);
                return 2;
        }

        Options o = Options.parse(command, Arrays.copyOfRange(args, 1, args.length));
        Input input = readInput(o, stdin);

        if ("encrypt".equals(command)) {
            String token = sealWithInputKey(o, input);
            writeOutput(o, token.getBytes(StandardCharsets.US_ASCII), out);
            if (o.outFile != null) {
                err.println("wrote token to " + o.outFile);
            }
            return 0;
        }

        String token = new String(input.payload, StandardCharsets.UTF_8).trim();
        byte[] plain;
        try {
            plain = openWithInputKey(o, token, input);
        } catch (GeneralSecurityException e) {
            err.println("decryption failed: " + e.getMessage());
            err.println("(wrong key/passphrase, or the token was tampered with)");
            return 3;
        }
        writeOutput(o, plain, out);
        return 0;
    }

    private static void demo(PrintStream out) throws Exception {
        char[] pw = "demo-passphrase-not-for-production".toCharArray();
        try {
            String secret = "stripe_secret=sk_live_51H8xK2eZv";
            String token = encryptWithPassphrase(pw, secret.getBytes(StandardCharsets.UTF_8));
            out.println("plaintext : " + secret);
            out.println("encrypted : " + token);
            out.println("decrypted : " + new String(decryptWithPassphrase(token, pw),
                    StandardCharsets.UTF_8));
            out.println();
            String key = generateBase64Key();
            SecretKey sk = aesKeyFromBase64(key);
            String t2 = encryptWithKey(sk, secret.getBytes(StandardCharsets.UTF_8));
            out.println("raw key   : " + key);
            out.println("encrypted : " + t2);
            out.println("decrypted : " + new String(decryptWithKey(t2, sk),
                    StandardCharsets.UTF_8));
            out.println();
            out.println("note: never hardcode passphrases like the one above; read them");
            out.println("from a secret manager, an env var, or a prompt.");
        } finally {
            Arrays.fill(pw, '\0');
        }
    }

    private static String sealWithInputKey(Options o, Input input) throws Exception {
        if (o.base64Key != null) {
            return encryptWithKey(aesKeyFromBase64(o.base64Key), input.payload);
        }
        char[] pw = acquirePassphrase(o, input, true);
        try {
            return encryptWithPassphrase(pw, input.payload, o.iterations);
        } finally {
            Arrays.fill(pw, '\0');
        }
    }

    private static byte[] openWithInputKey(Options o, String token, Input input)
            throws Exception {
        if (o.base64Key != null) {
            return decryptWithKey(token, aesKeyFromBase64(o.base64Key));
        }
        char[] pw = acquirePassphrase(o, input, false);
        try {
            return decryptWithPassphrase(token, pw);
        } finally {
            Arrays.fill(pw, '\0');
        }
    }

    private static char[] acquirePassphrase(Options o, Input input, boolean confirm)
            throws IOException {
        if (o.passphrase != null) {
            return o.passphrase.toCharArray();
        }
        if (input.passphrase != null) {
            return input.passphrase.toCharArray();
        }
        if (o.passphraseEnv != null) {
            String value = System.getenv(o.passphraseEnv);
            if (value == null || value.isEmpty()) {
                throw new UsageError("environment variable " + o.passphraseEnv
                        + " is not set or is empty");
            }
            return value.toCharArray();
        }
        if (o.passphraseFile != null) {
            byte[] raw = Files.readAllBytes(o.passphraseFile);
            String text = stripTrailingNewlines(new String(raw, StandardCharsets.UTF_8));
            Arrays.fill(raw, (byte) 0);
            if (text.isEmpty()) {
                throw new UsageError("passphrase file " + o.passphraseFile + " is empty");
            }
            return text.toCharArray();
        }
        Console console = System.console();
        if (console == null) {
            throw new UsageError("no interactive console: pass the key with --key, "
                    + "--passphrase, --passphrase-env, --passphrase-file or --passphrase-stdin");
        }
        char[] first = console.readPassword("passphrase: ");
        if (first == null || first.length == 0) {
            throw new UsageError("empty passphrase");
        }
        if (!confirm) {
            return first;
        }
        char[] again = console.readPassword("repeat passphrase: ");
        if (!Arrays.equals(first, again)) {
            Arrays.fill(first, '\0');
            Arrays.fill(again, '\0');
            throw new UsageError("passphrases did not match");
        }
        Arrays.fill(again, '\0');
        return first;
    }

    /** Payload plus, for --passphrase-stdin, the passphrase read ahead of it. */
    private static final class Input {
        byte[] payload = new byte[0];
        String passphrase;
    }

    private static Input readInput(Options o, InputStream stdin) throws IOException {
        if (o.textualArgument != null && o.inFile != null) {
            throw new UsageError("give either a value argument or --in, not both");
        }
        Input input = new Input();
        boolean payloadFromStdin = o.textualArgument == null && o.inFile == null;
        if (o.textualArgument != null) {
            input.payload = o.textualArgument.getBytes(StandardCharsets.UTF_8);
        } else if (o.inFile != null) {
            input.payload = Files.readAllBytes(o.inFile);
        }

        if (o.wantsStdinPassphrase()) {
            // Convention: with --passphrase-stdin the first stdin line is the passphrase.
            // If the payload is not supplied elsewhere, the remaining lines are the payload.
            byte[] all = stdin.readAllBytes();
            int cut = indexOfFirstNewline(all);
            if (payloadFromStdin) {
                if (cut < 0) {
                    input.passphrase = new String(all, StandardCharsets.UTF_8);
                } else {
                    input.passphrase = new String(Arrays.copyOf(all, cut),
                            StandardCharsets.UTF_8);
                    input.payload = stripTrailingNewlinesBytes(
                            Arrays.copyOfRange(all, cut + 1, all.length));
                }
            } else {
                input.passphrase = new String(
                        cut < 0 ? all : Arrays.copyOf(all, cut), StandardCharsets.UTF_8);
            }
            if (input.passphrase.isEmpty()) {
                throw new UsageError("empty passphrase on stdin");
            }
        } else if (payloadFromStdin) {
            input.payload = stripTrailingNewlinesBytes(stdin.readAllBytes());
        }

        if (input.payload.length > MAX_INPUT_BYTES) {
            throw new UsageError("input of " + input.payload.length + " bytes exceeds the "
                    + MAX_INPUT_BYTES + " byte limit");
        }
        return input;
    }

    private static int indexOfFirstNewline(byte[] data) {
        for (int i = 0; i < data.length; i++) {
            if (data[i] == '\n') {
                return i;
            }
        }
        return -1;
    }

    private static byte[] stripTrailingNewlinesBytes(byte[] data) {
        int end = data.length;
        while (end > 0 && (data[end - 1] == '\n' || data[end - 1] == '\r')) {
            end--;
        }
        return end == data.length ? data : Arrays.copyOf(data, end);
    }

    private static String stripTrailingNewlines(String s) {
        int end = s.length();
        while (end > 0 && (s.charAt(end - 1) == '\n' || s.charAt(end - 1) == '\r')) {
            end--;
        }
        return s.substring(0, end);
    }

    private static void writeOutput(Options o, byte[] data, PrintStream out) throws IOException {
        if (o.outFile == null) {
            // Raw bytes, not println: the payload may be binary. A newline is appended for
            // readability only when the caller asked for text and did not supply one.
            out.write(data, 0, data.length);
            if (data.length == 0 || data[data.length - 1] != '\n') {
                out.write('\n');
            }
            out.flush();
            return;
        }
        if (Files.exists(o.outFile) && !o.force) {
            throw new UsageError(o.outFile + " already exists (use --force to overwrite)");
        }
        Files.write(o.outFile, data);
    }

    // ------------------------------------------------------------------ usage

    private static boolean isHelp(String arg) {
        return "-h".equals(arg) || "--help".equals(arg) || "help".equals(arg);
    }

    private static void printUsage(PrintStream out) {
        out.println("SymmetricCrypto - AES-256-GCM encryption for application secrets");
        out.println();
        out.println("usage: java SymmetricCrypto <command> [options] [value]");
        out.println();
        out.println("commands:");
        out.println("  keygen                     print a new random 256-bit key (Base64)");
        out.println("  encrypt [value]            print an aesgcm$v1$ token");
        out.println("  decrypt   <token>          print the recovered plaintext");
        out.println("  selftest                   run the built-in correctness and tamper tests");
        out.println("  demo                       show an encrypt/decrypt round trip");
        out.println();
        out.println("key options (choose one):");
        out.println("  --key <base64>             raw AES key, 16/24/32 bytes Base64 encoded");
        out.println("  --passphrase <text>        insecure: visible in the process list");
        out.println("  --passphrase-env <VAR>     read the passphrase from an env var");
        out.println("  --passphrase-file <path>   read the passphrase from a file");
        out.println("  --passphrase-stdin         1st stdin line = passphrase, rest = payload");
        out.println("  (omitted)                  prompt on an interactive console");
        out.println();
        out.println("input/output options:");
        out.println("  value                      the text to encrypt/decrypt (UTF-8)");
        out.println("  -i, --in <file>            read bytes from a file instead");
        out.println("  -o, --out <file>           write result to a file instead of stdout");
        out.println("  -f, --force                allow --out to overwrite an existing file");
        out.println("  --iterations <n>           PBKDF2 rounds for encrypt (default "
                + DEFAULT_ITERATIONS + ", " + MIN_ITERATIONS + ".." + MAX_ITERATIONS + ")");
        out.println();
        out.println("examples:");
        out.println("  java SymmetricCrypto keygen > key.b64");
        out.println("  java SymmetricCrypto encrypt --key \"$(cat key.b64)\" 'db-password'");
        out.println("  java SymmetricCrypto decrypt --key \"$(cat key.b64)\" 'aesgcm$v1$...'");
        out.println("  java SymmetricCrypto encrypt --passphrase-file pw.txt -i secret.txt -o token.txt");
    }

    private static final class UsageError extends RuntimeException {
        private static final long serialVersionUID = 1L;

        UsageError(String message) {
            super(message);
        }
    }

    /** Parsed command line. */
    static final class Options {
        String base64Key;
        String passphrase;
        String passphraseEnv;
        Path passphraseFile;
        boolean passphraseStdin;
        Path inFile;
        Path outFile;
        boolean force;
        int iterations = DEFAULT_ITERATIONS;
        String textualArgument;

        static Options parse(String command, String[] args) {
            Options o = new Options();
            for (int i = 0; i < args.length; i++) {
                String arg = args[i];
                switch (arg) {
                    case "--key":
                        o.base64Key = value(args, ++i, arg);
                        break;
                    case "--passphrase":
                        o.passphrase = value(args, ++i, arg);
                        break;
                    case "--passphrase-env":
                        o.passphraseEnv = value(args, ++i, arg);
                        break;
                    case "--passphrase-file":
                        o.passphraseFile = Paths.get(value(args, ++i, arg));
                        break;
                    case "--passphrase-stdin":
                        o.passphraseStdin = true;
                        break;
                    case "-i":
                    case "--in":
                        o.inFile = Paths.get(value(args, ++i, arg));
                        break;
                    case "-o":
                    case "--out":
                        o.outFile = Paths.get(value(args, ++i, arg));
                        break;
                    case "-f":
                    case "--force":
                        o.force = true;
                        break;
                    case "--iterations":
                        o.iterations = parseInt(value(args, ++i, arg), arg);
                        break;
                    case "-h":
                    case "--help":
                        break;
                    default:
                        if (arg.startsWith("-")) {
                            throw new UsageError("unknown option " + arg);
                        }
                        if (o.textualArgument != null) {
                            throw new UsageError("more than one value argument given; quote it?");
                        }
                        o.textualArgument = arg;
                }
            }
            if (o.base64Key != null && o.base64Key.trim().isEmpty()) {
                throw new UsageError("--key needs a Base64 value");
            }
            if (o.wantsStdinPassphrase() && "decrypt".equals(command)
                    && o.textualArgument == null && o.inFile == null) {
                throw new UsageError("with --passphrase-stdin the token must come from the "
                        + "argument or --in, because stdin carries the passphrase");
            }
            if (o.iterations < MIN_ITERATIONS || o.iterations > MAX_ITERATIONS) {
                throw new UsageError("--iterations must be between " + MIN_ITERATIONS + " and "
                        + MAX_ITERATIONS);
            }
            return o;
        }

        /** True when the passphrase is to be read from stdin rather than from a tty. */
        boolean wantsStdinPassphrase() {
            return passphraseStdin && base64Key == null;
        }

        private static String value(String[] args, int index, String option) {
            if (index >= args.length) {
                throw new UsageError(option + " expects a value");
            }
            return args[index];
        }

        private static int parseInt(String text, String option) {
            try {
                return Integer.parseInt(text.trim());
            } catch (NumberFormatException e) {
                throw new UsageError(option + " expects a number, got " + text);
            }
        }
    }
}
