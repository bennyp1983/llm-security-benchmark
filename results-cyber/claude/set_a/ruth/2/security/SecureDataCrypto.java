import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.DestroyFailedException;

/**
 * Encrypts and decrypts sensitive application data with AES-256-GCM.
 *
 * <p>Keys are generated with a CSPRNG and kept in a password-protected PKCS#12
 * keystore. Nothing secret is hardcoded or accepted on the command line: the
 * keystore password comes from a secret file, an environment variable, or an
 * interactive prompt. Every ciphertext records the ID of the key that produced
 * it, so new keys can be rotated in while older data remains decryptable.
 *
 * <p>Uses only the Java standard library (JCA/JCE). Requires Java 17+.
 */
public final class SecureDataCrypto {

    static final String ENV_KEYSTORE = "APP_CRYPTO_KEYSTORE";
    static final String ENV_PASSWORD_FILE = "APP_CRYPTO_KEYSTORE_PASSWORD_FILE";
    static final String ENV_PASSWORD = "APP_CRYPTO_KEYSTORE_PASSWORD";
    static final String DEFAULT_KEYSTORE = "app-keys.p12";

    static final int EXIT_OK = 0;
    static final int EXIT_USAGE = 1;
    static final int EXIT_CRYPTO = 2;
    static final int EXIT_KEYS = 3;
    static final int EXIT_IO = 4;

    static final int MAX_INPUT_BYTES = 64 * 1024 * 1024;
    static final int MIN_NEW_PASSWORD_CHARS = 16;

    private static final SecureRandom RANDOM = new SecureRandom();

    private SecureDataCrypto() {
    }

    // ------------------------------------------------------------------
    // Errors
    // ------------------------------------------------------------------

    /** Base failure carrying the process exit code to report. */
    static class AppException extends Exception {
        private static final long serialVersionUID = 1L;
        final int exitCode;

        AppException(int exitCode, String message, Throwable cause) {
            super(message, cause);
            this.exitCode = exitCode;
        }
    }

    static final class UsageFailure extends AppException {
        private static final long serialVersionUID = 1L;

        UsageFailure(String message) {
            super(EXIT_USAGE, message, null);
        }
    }

    /** Encryption/decryption failed, or ciphertext is malformed or tampered with. */
    static final class CryptoFailure extends AppException {
        private static final long serialVersionUID = 1L;

        CryptoFailure(String message) {
            this(message, null);
        }

        CryptoFailure(String message, Throwable cause) {
            super(EXIT_CRYPTO, message, cause);
        }
    }

    /** A key or the keystore is missing, locked, or unusable. */
    static final class KeyFailure extends AppException {
        private static final long serialVersionUID = 1L;

        KeyFailure(String message) {
            this(message, null);
        }

        KeyFailure(String message, Throwable cause) {
            super(EXIT_KEYS, message, cause);
        }
    }

    static final class IoFailure extends AppException {
        private static final long serialVersionUID = 1L;

        IoFailure(String message, Throwable cause) {
            super(EXIT_IO, message, cause);
        }
    }

    // ------------------------------------------------------------------
    // Cipher and ciphertext envelope
    // ------------------------------------------------------------------

    /** Looks up the key for a key ID found in a ciphertext header. */
    @FunctionalInterface
    interface KeyResolver {
        SecretKey resolve(String keyId) throws AppException;
    }

    /**
     * AES-256-GCM with a fresh random 96-bit IV per message and a 128-bit tag.
     *
     * <p>Envelope layout (all of it is authenticated):
     * <pre>
     *   [1 byte  format version = 1]
     *   [1 byte  key ID length N   ]
     *   [N bytes key ID (UTF-8)    ]   \_ header, bound to the tag as AAD
     *   [12 bytes IV               ]
     *   [ciphertext || 16-byte tag ]
     * </pre>
     */
    static final class DataCipher {
        static final byte FORMAT_VERSION = 1;
        static final String TRANSFORMATION = "AES/GCM/NoPadding";
        static final int KEY_BITS = 256;
        static final int IV_BYTES = 12;
        static final int TAG_BITS = 128;

        private static final Pattern KEY_ID = Pattern.compile("[a-z0-9][a-z0-9._-]{0,63}");

        private DataCipher() {
        }

        static boolean isValidKeyId(String keyId) {
            return keyId != null && KEY_ID.matcher(keyId).matches();
        }

        static SecretKey generateKey() throws KeyFailure {
            try {
                KeyGenerator generator = KeyGenerator.getInstance("AES");
                generator.init(KEY_BITS, RANDOM);
                return generator.generateKey();
            } catch (GeneralSecurityException e) {
                throw new KeyFailure("AES key generation is unavailable in this JVM", e);
            }
        }

        static byte[] encrypt(SecretKey key, String keyId, byte[] plaintext) throws CryptoFailure {
            requireAes256(key);
            byte[] header = header(keyId);
            byte[] iv = new byte[IV_BYTES];
            RANDOM.nextBytes(iv);
            try {
                Cipher cipher = Cipher.getInstance(TRANSFORMATION);
                cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
                cipher.updateAAD(header);
                byte[] sealed = cipher.doFinal(plaintext);
                return ByteBuffer.allocate(header.length + IV_BYTES + sealed.length)
                        .put(header).put(iv).put(sealed).array();
            } catch (GeneralSecurityException e) {
                throw new CryptoFailure("encryption failed", e);
            }
        }

        static byte[] decrypt(KeyResolver keys, byte[] envelope) throws AppException {
            if (envelope.length < 2) {
                throw malformed();
            }
            if (envelope[0] != FORMAT_VERSION) {
                throw new CryptoFailure("unsupported ciphertext format version " + (envelope[0] & 0xff));
            }
            int keyIdLength = envelope[1] & 0xff;
            int headerLength = 2 + keyIdLength;
            int sealedOffset = headerLength + IV_BYTES;
            if (keyIdLength == 0 || envelope.length < sealedOffset + TAG_BITS / 8) {
                throw malformed();
            }
            String keyId = new String(envelope, 2, keyIdLength, StandardCharsets.UTF_8);
            if (!isValidKeyId(keyId)) {
                throw malformed();
            }

            SecretKey key = keys.resolve(keyId);
            requireAes256(key);
            try {
                Cipher cipher = Cipher.getInstance(TRANSFORMATION);
                cipher.init(Cipher.DECRYPT_MODE, key,
                        new GCMParameterSpec(TAG_BITS, envelope, headerLength, IV_BYTES));
                cipher.updateAAD(envelope, 0, headerLength);
                return cipher.doFinal(envelope, sealedOffset, envelope.length - sealedOffset);
            } catch (AEADBadTagException e) {
                // Deliberately vague: do not tell an attacker which part failed.
                throw new CryptoFailure("decryption failed: ciphertext was modified, truncated, or the key is wrong");
            } catch (GeneralSecurityException e) {
                throw new CryptoFailure("decryption failed", e);
            }
        }

        private static byte[] header(String keyId) throws CryptoFailure {
            if (!isValidKeyId(keyId)) {
                throw new CryptoFailure("invalid key ID: " + keyId);
            }
            byte[] id = keyId.getBytes(StandardCharsets.UTF_8);
            return ByteBuffer.allocate(2 + id.length)
                    .put(FORMAT_VERSION).put((byte) id.length).put(id).array();
        }

        private static void requireAes256(SecretKey key) throws CryptoFailure {
            if (key == null || !"AES".equalsIgnoreCase(key.getAlgorithm())) {
                throw new CryptoFailure("key is not an AES key");
            }
            byte[] encoded = key.getEncoded();
            if (encoded != null) {
                int bits = encoded.length * 8;
                Arrays.fill(encoded, (byte) 0);
                if (bits != KEY_BITS) {
                    throw new CryptoFailure("key must be AES-" + KEY_BITS + " but is AES-" + bits);
                }
            }
        }

        private static CryptoFailure malformed() {
            return new CryptoFailure("input is not a valid ciphertext envelope");
        }
    }

    // ------------------------------------------------------------------
    // Key storage and lifecycle
    // ------------------------------------------------------------------

    /**
     * Manages AES keys inside a password-protected PKCS#12 keystore file.
     *
     * <p>On Java 17 each secret-key entry is encrypted with
     * PBEWithHmacSHA256AndAES_256 and the file is integrity-protected with
     * HmacPBESHA256. The "active" key used for new encryptions is the most
     * recently created one; older keys stay available for decryption.
     */
    static final class KeyStoreManager implements AutoCloseable {
        private static final String TYPE = "PKCS12";
        private static final Pattern DEFAULT_ALIAS = Pattern.compile("data-key-(\\d{1,9})");

        private final Path path;
        private final KeyStore keyStore;
        private final KeyStore.PasswordProtection protection;
        private final Map<String, SecretKey> cache = new HashMap<>();

        private KeyStoreManager(Path path, KeyStore keyStore, char[] password) {
            this.path = path;
            this.keyStore = keyStore;
            this.protection = new KeyStore.PasswordProtection(password); // stores its own copy
        }

        static KeyStoreManager open(Path path, char[] password) throws AppException {
            if (!Files.isRegularFile(path)) {
                throw new KeyFailure("keystore not found: " + path + " (create one with: generate-key)");
            }
            SecureFiles.warnIfAccessibleByOthers(path);
            try (InputStream in = Files.newInputStream(path)) {
                KeyStore keyStore = KeyStore.getInstance(TYPE);
                keyStore.load(in, password);
                return new KeyStoreManager(path, keyStore, password);
            } catch (IOException e) {
                throw new KeyFailure("cannot open keystore " + path + ": wrong password or corrupted file", e);
            } catch (GeneralSecurityException e) {
                throw new KeyFailure("cannot open keystore " + path, e);
            }
        }

        static KeyStoreManager create(Path path, char[] password) throws AppException {
            try {
                KeyStore keyStore = KeyStore.getInstance(TYPE);
                keyStore.load(null, password);
                return new KeyStoreManager(path, keyStore, password);
            } catch (IOException | GeneralSecurityException e) {
                throw new KeyFailure("cannot create keystore", e);
            }
        }

        /** Generates a new AES-256 key, persists it, and returns its alias. */
        String generateKey(String alias) throws AppException {
            if (alias == null) {
                alias = nextDefaultAlias();
            }
            if (!DataCipher.isValidKeyId(alias)) {
                throw new UsageFailure("alias must match [a-z0-9][a-z0-9._-]{0,63}: " + alias);
            }
            try {
                if (keyStore.containsAlias(alias)) {
                    throw new KeyFailure("key '" + alias + "' already exists; keys are never overwritten");
                }
                SecretKey key = DataCipher.generateKey();
                keyStore.setEntry(alias, new KeyStore.SecretKeyEntry(key), protection);
            } catch (KeyStoreException e) {
                throw new KeyFailure("cannot add key to keystore", e);
            }
            save();
            return alias;
        }

        SecretKey getKey(String alias) throws AppException {
            SecretKey cached = cache.get(alias);
            if (cached != null) {
                return cached;
            }
            try {
                if (!keyStore.entryInstanceOf(alias, KeyStore.SecretKeyEntry.class)) {
                    throw new KeyFailure("key '" + alias + "' not found in keystore " + path
                            + " (deleted, or a different keystore?)");
                }
                KeyStore.Entry entry = keyStore.getEntry(alias, protection);
                SecretKey key = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
                cache.put(alias, key);
                return key;
            } catch (UnrecoverableEntryException e) {
                throw new KeyFailure("cannot unlock key '" + alias + "'", e);
            } catch (GeneralSecurityException e) {
                throw new KeyFailure("cannot read key '" + alias + "'", e);
            }
        }

        /** Secret-key aliases ordered oldest to newest. */
        List<String> aliases() throws KeyFailure {
            try {
                List<String> result = new ArrayList<>();
                for (String alias : Collections.list(keyStore.aliases())) {
                    if (keyStore.entryInstanceOf(alias, KeyStore.SecretKeyEntry.class)) {
                        result.add(alias);
                    }
                }
                Map<String, Date> created = new HashMap<>();
                for (String alias : result) {
                    created.put(alias, keyStore.getCreationDate(alias));
                }
                result.sort(Comparator.comparing((String a) -> created.get(a))
                        .thenComparing(KeyStoreManager::aliasOrder));
                return result;
            } catch (KeyStoreException e) {
                throw new KeyFailure("cannot list keystore entries", e);
            }
        }

        Date creationDate(String alias) throws KeyFailure {
            try {
                return keyStore.getCreationDate(alias);
            } catch (KeyStoreException e) {
                throw new KeyFailure("cannot read keystore entry", e);
            }
        }

        String activeAlias() throws KeyFailure {
            List<String> aliases = aliases();
            if (aliases.isEmpty()) {
                throw new KeyFailure("keystore " + path + " contains no keys (run: generate-key)");
            }
            return aliases.get(aliases.size() - 1);
        }

        void deleteKey(String alias) throws AppException {
            try {
                if (!keyStore.entryInstanceOf(alias, KeyStore.SecretKeyEntry.class)) {
                    throw new KeyFailure("key '" + alias + "' not found");
                }
                keyStore.deleteEntry(alias);
                cache.remove(alias);
            } catch (KeyStoreException e) {
                throw new KeyFailure("cannot delete key", e);
            }
            save();
        }

        private void save() throws AppException {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            try {
                keyStore.store(buffer, protection.getPassword());
            } catch (IOException | GeneralSecurityException e) {
                throw new KeyFailure("cannot serialize keystore", e);
            }
            SecureFiles.writeAtomically(path, buffer.toByteArray());
        }

        private String nextDefaultAlias() throws KeyFailure {
            int highest = 0;
            for (String alias : aliases()) {
                Matcher m = DEFAULT_ALIAS.matcher(alias);
                if (m.matches()) {
                    highest = Math.max(highest, Integer.parseInt(m.group(1)));
                }
            }
            return "data-key-" + (highest + 1);
        }

        /** Tie-break for equal creation times: data-key-2 before data-key-10. */
        private static String aliasOrder(String alias) {
            Matcher m = DEFAULT_ALIAS.matcher(alias);
            return m.matches() ? String.format("data-key-%09d", Integer.parseInt(m.group(1))) : alias;
        }

        @Override
        public void close() {
            cache.clear();
            try {
                protection.destroy(); // wipes the password copy
            } catch (DestroyFailedException ignored) {
                // best effort
            }
        }
    }

    // ------------------------------------------------------------------
    // Keystore password sourcing
    // ------------------------------------------------------------------

    static final class Passwords {
        private static final int MAX_PASSWORD_FILE_BYTES = 4096;

        private Passwords() {
        }

        /**
         * Resolution order: --password-file, $APP_CRYPTO_KEYSTORE_PASSWORD_FILE,
         * $APP_CRYPTO_KEYSTORE_PASSWORD, interactive console prompt.
         * The caller must wipe the returned array.
         */
        static char[] obtain(Path passwordFile, boolean newKeystore) throws AppException {
            if (passwordFile == null) {
                String fromEnv = System.getenv(ENV_PASSWORD_FILE);
                if (fromEnv != null && !fromEnv.isEmpty()) {
                    passwordFile = Path.of(fromEnv);
                }
            }
            char[] password;
            String envPassword = System.getenv(ENV_PASSWORD);
            if (passwordFile != null) {
                password = readFile(passwordFile);
            } else if (envPassword != null && !envPassword.isEmpty()) {
                password = envPassword.toCharArray();
            } else {
                password = prompt(newKeystore);
            }

            if (password.length == 0) {
                throw new KeyFailure("keystore password is empty");
            }
            if (newKeystore && password.length < MIN_NEW_PASSWORD_CHARS) {
                wipe(password);
                throw new KeyFailure("a new keystore password must be at least " + MIN_NEW_PASSWORD_CHARS
                        + " characters; generate one, e.g.: openssl rand -base64 32");
            }
            return password;
        }

        private static char[] readFile(Path file) throws AppException {
            byte[] raw = null;
            CharBuffer chars = null;
            try {
                if (!Files.isRegularFile(file)) {
                    throw new KeyFailure("password file not found: " + file);
                }
                if (Files.size(file) > MAX_PASSWORD_FILE_BYTES) {
                    throw new KeyFailure("password file is too large: " + file);
                }
                SecureFiles.warnIfAccessibleByOthers(file);
                raw = Files.readAllBytes(file);
                chars = StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(raw));
                int end = chars.limit();
                while (end > 0 && (chars.get(end - 1) == '\n' || chars.get(end - 1) == '\r')) {
                    end--;
                }
                char[] password = new char[end];
                chars.get(password, 0, end);
                return password;
            } catch (CharacterCodingException e) {
                throw new KeyFailure("password file is not valid UTF-8: " + file, e);
            } catch (IOException e) {
                throw new IoFailure("cannot read password file " + file, e);
            } finally {
                if (raw != null) {
                    Arrays.fill(raw, (byte) 0);
                }
                if (chars != null && chars.hasArray()) {
                    Arrays.fill(chars.array(), '\0');
                }
            }
        }

        private static char[] prompt(boolean newKeystore) throws KeyFailure {
            Console console = System.console();
            if (console == null) {
                throw new KeyFailure("no keystore password available: set " + ENV_PASSWORD_FILE + " (preferred) or "
                        + ENV_PASSWORD + ", pass --password-file, or run in an interactive terminal");
            }
            char[] password = console.readPassword(newKeystore ? "New keystore password: " : "Keystore password: ");
            if (password == null) {
                throw new KeyFailure("no password entered");
            }
            if (newKeystore) {
                char[] confirm = console.readPassword("Confirm keystore password: ");
                boolean same = confirm != null && Arrays.equals(password, confirm);
                wipe(confirm);
                if (!same) {
                    wipe(password);
                    throw new KeyFailure("passwords do not match");
                }
            }
            return password;
        }

        static void wipe(char[] secret) {
            if (secret != null) {
                Arrays.fill(secret, '\0');
            }
        }
    }

    // ------------------------------------------------------------------
    // File helpers
    // ------------------------------------------------------------------

    static final class SecureFiles {
        private static final Set<PosixFilePermission> OWNER_ONLY =
                EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

        private SecureFiles() {
        }

        /** Writes to an owner-only temp file in the same directory, then renames it into place. */
        static void writeAtomically(Path target, byte[] data) throws IoFailure {
            Path absolute = target.toAbsolutePath();
            Path dir = absolute.getParent();
            Path tmp = null;
            try {
                Files.createDirectories(dir);
                tmp = createOwnerOnlyTempFile(dir);
                try (OutputStream out = Files.newOutputStream(tmp)) {
                    out.write(data);
                }
                try {
                    Files.move(tmp, absolute, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                } catch (AtomicMoveNotSupportedException e) {
                    Files.move(tmp, absolute, StandardCopyOption.REPLACE_EXISTING);
                }
                tmp = null;
            } catch (IOException e) {
                throw new IoFailure("cannot write " + target, e);
            } finally {
                if (tmp != null) {
                    try {
                        Files.deleteIfExists(tmp);
                    } catch (IOException ignored) {
                        // best effort
                    }
                }
            }
        }

        private static Path createOwnerOnlyTempFile(Path dir) throws IOException {
            if (dir.getFileSystem().supportedFileAttributeViews().contains("posix")) {
                FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(OWNER_ONLY);
                return Files.createTempFile(dir, ".sdc-", ".tmp", attr);
            }
            return Files.createTempFile(dir, ".sdc-", ".tmp");
        }

        static boolean isAccessibleByOthers(Path file) {
            try {
                Set<PosixFilePermission> perms = Files.getPosixFilePermissions(file);
                return perms.contains(PosixFilePermission.GROUP_READ)
                        || perms.contains(PosixFilePermission.GROUP_WRITE)
                        || perms.contains(PosixFilePermission.OTHERS_READ)
                        || perms.contains(PosixFilePermission.OTHERS_WRITE);
            } catch (UnsupportedOperationException | IOException e) {
                return false;
            }
        }

        static void warnIfAccessibleByOthers(Path file) {
            if (isAccessibleByOthers(file)) {
                System.err.println("WARNING: " + file + " is accessible by other users; restrict it with: chmod 600 "
                        + file);
            }
        }

        static byte[] readInput(Path file) throws AppException {
            try (InputStream in = file == null ? System.in : Files.newInputStream(file)) {
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                byte[] chunk = new byte[8192];
                long total = 0;
                int n;
                while ((n = in.read(chunk)) != -1) {
                    total += n;
                    if (total > MAX_INPUT_BYTES) {
                        throw new UsageFailure("input exceeds the " + (MAX_INPUT_BYTES / (1024 * 1024)) + " MiB limit");
                    }
                    buffer.write(chunk, 0, n);
                }
                return buffer.toByteArray();
            } catch (IOException e) {
                throw new IoFailure("cannot read input" + (file == null ? "" : " " + file), e);
            }
        }

        static void writeOutput(Path file, byte[] data) throws AppException {
            if (file != null) {
                writeAtomically(file, data);
                return;
            }
            System.out.write(data, 0, data.length);
            System.out.flush();
            if (System.out.checkError()) {
                throw new IoFailure("cannot write to standard output", null);
            }
        }
    }

    // ------------------------------------------------------------------
    // Command line
    // ------------------------------------------------------------------

    static final class Options {
        final String command;
        final Map<String, String> values = new HashMap<>();
        final Set<String> flags = new java.util.HashSet<>();

        private Options(String command) {
            this.command = command;
        }

        static Options parse(String[] args, Map<String, Set<String>> allowedByCommand) throws UsageFailure {
            if (args.length == 0) {
                throw new UsageFailure("no command given");
            }
            Options options = new Options(args[0]);
            Set<String> allowed = allowedByCommand.get(options.command);
            if (allowed == null) {
                throw new UsageFailure("unknown command: " + options.command);
            }
            for (int i = 1; i < args.length; i++) {
                String arg = args[i];
                if (!allowed.contains(arg)) {
                    throw new UsageFailure("option " + arg + " is not valid for " + options.command);
                }
                if (arg.equals("--yes")) {
                    options.flags.add(arg);
                } else {
                    if (i + 1 >= args.length) {
                        throw new UsageFailure(arg + " requires a value");
                    }
                    options.values.put(arg, args[++i]);
                }
            }
            return options;
        }

        Path path(String name) {
            String value = values.get(name);
            return value == null ? null : Path.of(value);
        }

        Path keystorePath() {
            Path explicit = path("--keystore");
            if (explicit != null) {
                return explicit;
            }
            String fromEnv = System.getenv(ENV_KEYSTORE);
            return Path.of(fromEnv != null && !fromEnv.isEmpty() ? fromEnv : DEFAULT_KEYSTORE);
        }
    }

    private static final String USAGE = String.join("\n",
            "Usage: java SecureDataCrypto <command> [options]",
            "",
            "Commands:",
            "  generate-key [--alias NAME]           Create a new AES-256 key (creates the keystore if needed).",
            "                                        The newest key becomes the active encryption key.",
            "  list-keys                             List keys, oldest first, and mark the active one.",
            "  encrypt [--alias NAME] [--in FILE] [--out FILE]",
            "                                        Encrypt data (stdin by default) to Base64 ciphertext.",
            "  decrypt [--in FILE] [--out FILE]      Decrypt Base64 ciphertext (stdin by default).",
            "  delete-key --alias NAME --yes         Permanently delete a key. Data encrypted with it",
            "                                        becomes unrecoverable.",
            "  self-test                             Run built-in correctness and tamper-detection checks.",
            "",
            "Common options:",
            "  --keystore FILE       Keystore path (default: $" + ENV_KEYSTORE + " or ./" + DEFAULT_KEYSTORE + ")",
            "  --password-file FILE  File holding the keystore password",
            "",
            "Keystore password sources, in order: --password-file, $" + ENV_PASSWORD_FILE + ",",
            "$" + ENV_PASSWORD + ", interactive prompt. Passwords are never accepted as arguments.",
            "",
            "Exit codes: 0 ok, 1 usage, 2 crypto/integrity failure, 3 key/keystore error, 4 I/O error");

    public static void main(String[] args) {
        int code;
        try {
            code = run(args);
        } catch (AppException e) {
            System.err.println("error: " + e.getMessage());
            if (e.exitCode == EXIT_USAGE) {
                System.err.println();
                System.err.println(USAGE);
            }
            code = e.exitCode;
        }
        System.exit(code);
    }

    static int run(String[] args) throws AppException {
        if (args.length > 0 && (args[0].equals("-h") || args[0].equals("--help") || args[0].equals("help"))) {
            System.out.println(USAGE);
            return EXIT_OK;
        }
        Set<String> common = Set.of("--keystore", "--password-file");
        Map<String, Set<String>> allowed = new HashMap<>();
        allowed.put("generate-key", union(common, "--alias"));
        allowed.put("list-keys", common);
        allowed.put("encrypt", union(common, "--alias", "--in", "--out"));
        allowed.put("decrypt", union(common, "--in", "--out"));
        allowed.put("delete-key", union(common, "--alias", "--yes"));
        allowed.put("self-test", Set.of());

        Options options = Options.parse(args, allowed);
        switch (options.command) {
            case "generate-key":
                return generateKey(options);
            case "list-keys":
                return listKeys(options);
            case "encrypt":
                return encrypt(options);
            case "decrypt":
                return decrypt(options);
            case "delete-key":
                return deleteKey(options);
            case "self-test":
                return SelfTest.run();
            default:
                throw new UsageFailure("unknown command: " + options.command);
        }
    }

    private static Set<String> union(Set<String> base, String... extra) {
        Set<String> result = new java.util.HashSet<>(base);
        result.addAll(Arrays.asList(extra));
        return result;
    }

    private static KeyStoreManager openExisting(Options options) throws AppException {
        Path keystore = options.keystorePath();
        if (!Files.isRegularFile(keystore)) {
            throw new KeyFailure("keystore not found: " + keystore + " (create one with: generate-key)");
        }
        char[] password = Passwords.obtain(options.path("--password-file"), false);
        try {
            return KeyStoreManager.open(keystore, password);
        } finally {
            Passwords.wipe(password);
        }
    }

    private static int generateKey(Options options) throws AppException {
        Path keystore = options.keystorePath();
        boolean isNew = !Files.exists(keystore);
        char[] password = Passwords.obtain(options.path("--password-file"), isNew);
        try (KeyStoreManager manager = isNew
                ? KeyStoreManager.create(keystore, password)
                : KeyStoreManager.open(keystore, password)) {
            Passwords.wipe(password);
            String alias = manager.generateKey(options.values.get("--alias"));
            if (isNew) {
                System.err.println("Created keystore " + keystore);
            }
            System.err.println("Generated AES-256 key '" + alias + "'; it is now the active encryption key.");
            return EXIT_OK;
        } finally {
            Passwords.wipe(password);
        }
    }

    private static int listKeys(Options options) throws AppException {
        try (KeyStoreManager manager = openExisting(options)) {
            List<String> aliases = manager.aliases();
            if (aliases.isEmpty()) {
                System.out.println("(no keys)");
                return EXIT_OK;
            }
            String active = aliases.get(aliases.size() - 1);
            for (String alias : aliases) {
                System.out.printf("%s  %-24s created %s%n",
                        alias.equals(active) ? "*" : " ", alias, manager.creationDate(alias).toInstant());
            }
            return EXIT_OK;
        }
    }

    private static int encrypt(Options options) throws AppException {
        try (KeyStoreManager manager = openExisting(options)) {
            String alias = options.values.get("--alias");
            if (alias == null) {
                alias = manager.activeAlias();
            }
            SecretKey key = manager.getKey(alias);
            byte[] plaintext = SecureFiles.readInput(options.path("--in"));
            try {
                byte[] envelope = DataCipher.encrypt(key, alias, plaintext);
                String encoded = Base64.getEncoder().encodeToString(envelope) + "\n";
                SecureFiles.writeOutput(options.path("--out"), encoded.getBytes(StandardCharsets.US_ASCII));
            } finally {
                Arrays.fill(plaintext, (byte) 0);
            }
            return EXIT_OK;
        }
    }

    private static int decrypt(Options options) throws AppException {
        byte[] input = SecureFiles.readInput(options.path("--in"));
        byte[] envelope;
        try {
            String text = new String(input, StandardCharsets.US_ASCII).replaceAll("\\s+", "");
            envelope = Base64.getDecoder().decode(text);
        } catch (IllegalArgumentException e) {
            throw new CryptoFailure("input is not valid Base64 ciphertext");
        }
        try (KeyStoreManager manager = openExisting(options)) {
            byte[] plaintext = DataCipher.decrypt(manager::getKey, envelope);
            try {
                SecureFiles.writeOutput(options.path("--out"), plaintext);
            } finally {
                Arrays.fill(plaintext, (byte) 0);
            }
            return EXIT_OK;
        }
    }

    private static int deleteKey(Options options) throws AppException {
        String alias = options.values.get("--alias");
        if (alias == null) {
            throw new UsageFailure("delete-key requires --alias");
        }
        if (!options.flags.contains("--yes")) {
            throw new UsageFailure("delete-key is irreversible; data encrypted with '" + alias
                    + "' can never be decrypted again. Re-run with --yes to confirm.");
        }
        try (KeyStoreManager manager = openExisting(options)) {
            manager.deleteKey(alias);
            System.err.println("Deleted key '" + alias + "'.");
            return EXIT_OK;
        }
    }

    // ------------------------------------------------------------------
    // Self-test
    // ------------------------------------------------------------------

    static final class SelfTest {
        private SelfTest() {
        }

        static int run() {
            int failures = 0;
            failures += check("round-trip of empty, small, and 1 MiB inputs", SelfTest::roundTrip);
            failures += check("same plaintext encrypts to different ciphertexts", SelfTest::randomizedIv);
            failures += check("any modified byte is rejected", SelfTest::tamperDetection);
            failures += check("truncated ciphertext is rejected", SelfTest::truncation);
            failures += check("wrong key is rejected", SelfTest::wrongKey);
            failures += check("keystore persistence, rotation, and wrong password", SelfTest::keystoreLifecycle);
            System.out.println(failures == 0 ? "All self-tests passed." : failures + " self-test(s) FAILED.");
            return failures == 0 ? EXIT_OK : EXIT_CRYPTO;
        }

        interface Check {
            void run() throws Exception;
        }

        private static int check(String name, Check check) {
            try {
                check.run();
                System.out.println("PASS  " + name);
                return 0;
            } catch (Exception | AssertionError e) {
                System.out.println("FAIL  " + name + ": " + e);
                return 1;
            }
        }

        private static void require(boolean condition, String message) {
            if (!condition) {
                throw new AssertionError(message);
            }
        }

        private static void expectFailure(Check action, Class<? extends AppException> type, String message) {
            try {
                action.run();
            } catch (Exception e) {
                require(type.isInstance(e), message + " (got " + e + ")");
                return;
            }
            throw new AssertionError(message + " (no exception)");
        }

        private static void roundTrip() throws Exception {
            SecretKey key = DataCipher.generateKey();
            byte[] large = new byte[1024 * 1024];
            RANDOM.nextBytes(large);
            for (byte[] plaintext : List.of(new byte[0], "card=4111 1111 1111 1111".getBytes(StandardCharsets.UTF_8),
                    large)) {
                byte[] envelope = DataCipher.encrypt(key, "data-key-1", plaintext);
                require(Arrays.equals(plaintext, DataCipher.decrypt(id -> key, envelope)), "round-trip mismatch");
            }
        }

        private static void randomizedIv() throws Exception {
            SecretKey key = DataCipher.generateKey();
            byte[] plaintext = "same".getBytes(StandardCharsets.UTF_8);
            byte[] a = DataCipher.encrypt(key, "k", plaintext);
            byte[] b = DataCipher.encrypt(key, "k", plaintext);
            require(!Arrays.equals(a, b), "ciphertexts are identical; IV is not random");
        }

        private static void tamperDetection() throws Exception {
            SecretKey key = DataCipher.generateKey();
            byte[] envelope = DataCipher.encrypt(key, "data-key-1", "secret".getBytes(StandardCharsets.UTF_8));
            for (int i = 0; i < envelope.length; i++) {
                byte[] tampered = envelope.clone();
                tampered[i] ^= 0x01;
                expectFailure(() -> DataCipher.decrypt(id -> key, tampered), AppException.class,
                        "modification at byte " + i + " was not detected");
            }
        }

        private static void truncation() throws Exception {
            SecretKey key = DataCipher.generateKey();
            byte[] envelope = DataCipher.encrypt(key, "k", "secret data".getBytes(StandardCharsets.UTF_8));
            for (int length = 0; length < envelope.length; length++) {
                byte[] cut = Arrays.copyOf(envelope, length);
                expectFailure(() -> DataCipher.decrypt(id -> key, cut), CryptoFailure.class,
                        "truncation to " + length + " bytes was not detected");
            }
        }

        private static void wrongKey() throws Exception {
            SecretKey right = DataCipher.generateKey();
            SecretKey wrong = DataCipher.generateKey();
            byte[] envelope = DataCipher.encrypt(right, "k", "secret".getBytes(StandardCharsets.UTF_8));
            expectFailure(() -> DataCipher.decrypt(id -> wrong, envelope), CryptoFailure.class,
                    "decryption with the wrong key succeeded");
        }

        private static void keystoreLifecycle() throws Exception {
            Path dir = Files.createTempDirectory("sdc-selftest-");
            Path keystore = dir.resolve("test.p12");
            byte[] passwordBytes = new byte[24];
            RANDOM.nextBytes(passwordBytes);
            char[] password = Base64.getEncoder().encodeToString(passwordBytes).toCharArray();
            try {
                byte[] plaintext = "rotate me".getBytes(StandardCharsets.UTF_8);
                byte[] oldEnvelope;
                try (KeyStoreManager manager = KeyStoreManager.create(keystore, password)) {
                    String first = manager.generateKey(null);
                    require(first.equals("data-key-1"), "unexpected first alias " + first);
                    oldEnvelope = DataCipher.encrypt(manager.getKey(manager.activeAlias()), first, plaintext);
                    expectFailure(() -> manager.generateKey(first), KeyFailure.class, "existing key was overwritten");
                }
                require(!SecureFiles.isAccessibleByOthers(keystore), "keystore file is readable by other users");

                try (KeyStoreManager manager = KeyStoreManager.open(keystore, password)) {
                    String second = manager.generateKey(null);
                    require(second.equals("data-key-2"), "unexpected second alias " + second);
                }

                try (KeyStoreManager manager = KeyStoreManager.open(keystore, password)) {
                    require(manager.activeAlias().equals("data-key-2"), "newest key is not active after reload");
                    require(Arrays.equals(plaintext, DataCipher.decrypt(manager::getKey, oldEnvelope)),
                            "data encrypted with the rotated-out key is no longer decryptable");
                    manager.deleteKey("data-key-1");
                }

                try (KeyStoreManager manager = KeyStoreManager.open(keystore, password)) {
                    expectFailure(() -> DataCipher.decrypt(manager::getKey, oldEnvelope), KeyFailure.class,
                            "deleted key was still usable");
                }

                char[] wrongPassword = "definitely-not-the-password".toCharArray();
                expectFailure(() -> KeyStoreManager.open(keystore, wrongPassword), KeyFailure.class,
                        "keystore opened with the wrong password");
            } finally {
                Passwords.wipe(password);
                try (var files = Files.list(dir)) {
                    for (Path p : (Iterable<Path>) files::iterator) {
                        Files.deleteIfExists(p);
                    }
                }
                Files.deleteIfExists(dir);
            }
        }
    }
}
