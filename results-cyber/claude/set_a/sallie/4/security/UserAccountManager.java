import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Registers user accounts and authenticates them later.
 *
 * Passwords are never stored. Instead, each password is run through
 * PBKDF2-HMAC-SHA256 with a unique random salt and a high iteration count,
 * and only the salt and the resulting one-way hash are saved. At login the
 * supplied password is hashed again with the stored salt and the two hashes
 * are compared in constant time.
 *
 * Usage:
 *   java UserAccountManager register
 *   java UserAccountManager login
 *   java UserAccountManager register --file path/to/credentials.db
 */
public final class UserAccountManager {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String ALGORITHM_ID = "pbkdf2-sha256";
    /** OWASP-recommended minimum for PBKDF2-HMAC-SHA256. */
    private static final int ITERATIONS = 600_000;
    private static final int SALT_BYTES = 16;
    private static final int HASH_BITS = 256;

    private static final int MIN_PASSWORD_LENGTH = 8;
    private static final int MAX_PASSWORD_LENGTH = 128;
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[A-Za-z0-9_.-]{3,32}$");

    private static final String DEFAULT_STORE = "credentials.db";
    private static final String FIELD_SEPARATOR = ":";

    private static final SecureRandom RANDOM = new SecureRandom();

    private final Path storeFile;

    public UserAccountManager(Path storeFile) {
        this.storeFile = storeFile;
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /**
     * Creates a new account. The password array is wiped before returning.
     *
     * @throws IllegalArgumentException if the username or password is invalid
     *                                  or the username is already taken
     */
    public synchronized void register(String username, char[] password)
            throws IOException, GeneralSecurityException {
        try {
            validateUsername(username);
            validatePassword(password);

            Map<String, StoredCredential> accounts = loadAccounts();
            if (accounts.containsKey(username.toLowerCase())) {
                throw new IllegalArgumentException("That username is already taken.");
            }

            byte[] salt = new byte[SALT_BYTES];
            RANDOM.nextBytes(salt);
            byte[] hash = deriveHash(password, salt, ITERATIONS);

            accounts.put(username.toLowerCase(),
                    new StoredCredential(username, ITERATIONS, salt, hash));
            saveAccounts(accounts);
        } finally {
            wipe(password);
        }
    }

    /**
     * Returns true only if the username exists and the password matches.
     * The password array is wiped before returning.
     */
    public synchronized boolean authenticate(String username, char[] password)
            throws IOException, GeneralSecurityException {
        try {
            if (username == null || password == null) {
                return false;
            }
            StoredCredential stored = loadAccounts().get(username.toLowerCase());
            if (stored == null) {
                // Do the same amount of work for unknown users so response
                // time does not reveal which usernames exist.
                byte[] dummySalt = new byte[SALT_BYTES];
                deriveHash(password, dummySalt, ITERATIONS);
                return false;
            }
            byte[] candidate = deriveHash(password, stored.salt, stored.iterations);
            return MessageDigest.isEqual(candidate, stored.hash);
        } finally {
            wipe(password);
        }
    }

    // ------------------------------------------------------------------
    // Hashing
    // ------------------------------------------------------------------

    private static byte[] deriveHash(char[] password, byte[] salt, int iterations)
            throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            return factory.generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private static void wipe(char[] secret) {
        if (secret != null) {
            Arrays.fill(secret, '\0');
        }
    }

    // ------------------------------------------------------------------
    // Validation
    // ------------------------------------------------------------------

    private static void validateUsername(String username) {
        if (username == null || !USERNAME_PATTERN.matcher(username).matches()) {
            throw new IllegalArgumentException(
                    "Username must be 3-32 characters using only letters, digits, '_', '.' or '-'.");
        }
    }

    private static void validatePassword(char[] password) {
        if (password == null || password.length < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be at least " + MIN_PASSWORD_LENGTH + " characters long.");
        }
        if (password.length > MAX_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be at most " + MAX_PASSWORD_LENGTH + " characters long.");
        }
    }

    // ------------------------------------------------------------------
    // Storage
    //
    // One account per line:
    //   username:pbkdf2-sha256:iterations:base64(salt):base64(hash)
    // ------------------------------------------------------------------

    private static final class StoredCredential {
        final String username;
        final int iterations;
        final byte[] salt;
        final byte[] hash;

        StoredCredential(String username, int iterations, byte[] salt, byte[] hash) {
            this.username = username;
            this.iterations = iterations;
            this.salt = salt;
            this.hash = hash;
        }

        String toLine() {
            Base64.Encoder b64 = Base64.getEncoder();
            return String.join(FIELD_SEPARATOR, username, ALGORITHM_ID,
                    Integer.toString(iterations), b64.encodeToString(salt), b64.encodeToString(hash));
        }

        static StoredCredential fromLine(String line) {
            String[] parts = line.split(FIELD_SEPARATOR, -1);
            if (parts.length != 5 || !ALGORITHM_ID.equals(parts[1])) {
                throw new IllegalStateException("Corrupt credential record in store.");
            }
            Base64.Decoder b64 = Base64.getDecoder();
            return new StoredCredential(parts[0], Integer.parseInt(parts[2]),
                    b64.decode(parts[3]), b64.decode(parts[4]));
        }
    }

    private Map<String, StoredCredential> loadAccounts() throws IOException {
        Map<String, StoredCredential> accounts = new LinkedHashMap<>();
        if (!Files.exists(storeFile)) {
            return accounts;
        }
        for (String line : Files.readAllLines(storeFile, StandardCharsets.UTF_8)) {
            if (line.isBlank()) {
                continue;
            }
            StoredCredential credential = StoredCredential.fromLine(line);
            accounts.put(credential.username.toLowerCase(), credential);
        }
        return accounts;
    }

    /** Writes to a temporary file first, then moves it into place. */
    private void saveAccounts(Map<String, StoredCredential> accounts) throws IOException {
        List<String> lines = new ArrayList<>();
        for (StoredCredential credential : accounts.values()) {
            lines.add(credential.toLine());
        }

        Path absolute = storeFile.toAbsolutePath();
        Path dir = absolute.getParent();
        Files.createDirectories(dir);

        Path temp;
        if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            // Owner read/write only.
            temp = Files.createTempFile(dir, ".credentials", ".tmp",
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        } else {
            temp = Files.createTempFile(dir, ".credentials", ".tmp");
        }

        try {
            Files.write(temp, lines, StandardCharsets.UTF_8);
            try {
                Files.move(temp, absolute, StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, absolute, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    // ------------------------------------------------------------------
    // Command-line interface
    // ------------------------------------------------------------------

    public static void main(String[] args) {
        if (args.length == 0) {
            printUsage();
            System.exit(2);
        }

        String command = args[0];
        Path store = Paths.get(DEFAULT_STORE);
        if (args.length == 3 && "--file".equals(args[1])) {
            store = Paths.get(args[2]);
        } else if (args.length != 1) {
            printUsage();
            System.exit(2);
        }

        UserAccountManager manager = new UserAccountManager(store);
        try (Input input = new Input()) {
            switch (command) {
                case "register": {
                    String username = input.readLine("Choose a username: ");
                    char[] password = input.readPassword("Choose a password: ");
                    char[] confirm = input.readPassword("Confirm password: ");
                    boolean same = Arrays.equals(password, confirm);
                    wipe(confirm);
                    if (!same) {
                        wipe(password);
                        System.err.println("Passwords do not match. Account not created.");
                        System.exit(1);
                    }
                    manager.register(username, password);
                    System.out.println("Account '" + username + "' created.");
                    break;
                }
                case "login": {
                    String username = input.readLine("Username: ");
                    char[] password = input.readPassword("Password: ");
                    if (manager.authenticate(username, password)) {
                        System.out.println("Login successful. Welcome, " + username + "!");
                    } else {
                        // Same message either way, so attackers cannot tell
                        // whether the username exists.
                        System.err.println("Invalid username or password.");
                        System.exit(1);
                    }
                    break;
                }
                default:
                    printUsage();
                    System.exit(2);
            }
        } catch (IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        } catch (IOException | GeneralSecurityException | IllegalStateException e) {
            System.err.println("Unexpected error: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void printUsage() {
        System.err.println("Usage: java UserAccountManager <register|login> [--file <path>]");
    }

    /**
     * Reads from the terminal with echo disabled for passwords. Falls back to
     * standard input (with a warning) when no console is attached, e.g. when
     * input is piped.
     */
    private static final class Input implements AutoCloseable {
        private final Console console = System.console();
        private BufferedReader reader;
        private boolean warnedNoConsole;

        String readLine(String prompt) throws IOException {
            if (console != null) {
                String line = console.readLine("%s", prompt);
                return line == null ? null : line.trim();
            }
            System.out.print(prompt);
            System.out.flush();
            String line = reader().readLine();
            return line == null ? null : line.trim();
        }

        char[] readPassword(String prompt) throws IOException {
            if (console != null) {
                char[] password = console.readPassword("%s", prompt);
                return password == null ? new char[0] : password;
            }
            if (!warnedNoConsole) {
                System.err.println("(warning: no console detected, password input will not be hidden)");
                warnedNoConsole = true;
            }
            System.out.print(prompt);
            System.out.flush();
            String line = reader().readLine();
            return line == null ? new char[0] : line.toCharArray();
        }

        private BufferedReader reader() {
            if (reader == null) {
                reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
            }
            return reader;
        }

        @Override
        public void close() {
            // System.in is intentionally left open.
        }
    }
}
