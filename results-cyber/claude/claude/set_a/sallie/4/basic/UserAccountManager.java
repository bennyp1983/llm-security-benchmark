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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
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
 * A small command-line program that registers user accounts and authenticates
 * them later.
 *
 * Passwords are never stored in plain text. Each password is hashed with
 * PBKDF2-HMAC-SHA256 using a unique random salt, and only the salt, iteration
 * count and resulting hash are written to the credentials file.
 *
 * Credentials file format (one account per line):
 *   username:iterations:base64(salt):base64(hash)
 */
public class UserAccountManager {

    private static final String DEFAULT_STORE = "users.db";

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 600_000;
    private static final int SALT_BYTES = 16;
    private static final int HASH_BITS = 256;

    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[A-Za-z0-9_.-]{3,32}$");
    private static final int MIN_PASSWORD_LENGTH = 8;
    private static final int MAX_PASSWORD_LENGTH = 128;

    private final Path storePath;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, StoredCredential> accounts = new LinkedHashMap<>();

    /** Dummy credential used to keep login timing similar for unknown usernames. */
    private final StoredCredential dummyCredential;

    public UserAccountManager(Path storePath) throws IOException {
        this.storePath = storePath;
        load();
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        this.dummyCredential = new StoredCredential(ITERATIONS, salt, new byte[HASH_BITS / 8]);
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /**
     * Registers a new account.
     *
     * @throws IllegalArgumentException if the username or password is invalid,
     *                                  or the username is already taken
     */
    public synchronized void register(String username, char[] password) throws IOException {
        validateUsername(username);
        validatePassword(password);
        String key = normalize(username);
        if (accounts.containsKey(key)) {
            throw new IllegalArgumentException("That username is already taken.");
        }

        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] hash = hash(password, salt, ITERATIONS);

        accounts.put(key, new StoredCredential(ITERATIONS, salt, hash));
        try {
            save();
        } catch (IOException e) {
            accounts.remove(key); // keep memory consistent with the file
            throw e;
        }
    }

    /** Returns true only if the username exists and the password matches. */
    public synchronized boolean authenticate(String username, char[] password) {
        if (username == null || password == null) {
            return false;
        }
        StoredCredential stored = accounts.get(normalize(username));
        StoredCredential target = (stored != null) ? stored : dummyCredential;

        byte[] candidate = hash(password, target.salt, target.iterations);
        boolean matches = MessageDigest.isEqual(candidate, target.hash);
        Arrays.fill(candidate, (byte) 0);
        return stored != null && matches;
    }

    // ------------------------------------------------------------------
    // Validation
    // ------------------------------------------------------------------

    private static void validateUsername(String username) {
        if (username == null || !USERNAME_PATTERN.matcher(username).matches()) {
            throw new IllegalArgumentException(
                    "Username must be 3-32 characters and use only letters, digits, '_', '.' or '-'.");
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

    /** Usernames are case-insensitive: "Alice" and "alice" are the same account. */
    private static String normalize(String username) {
        return username.trim().toLowerCase(java.util.Locale.ROOT);
    }

    // ------------------------------------------------------------------
    // Hashing
    // ------------------------------------------------------------------

    private static byte[] hash(char[] password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_BITS);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Password hashing is unavailable on this JVM", e);
        } finally {
            spec.clearPassword();
        }
    }

    // ------------------------------------------------------------------
    // Persistence
    // ------------------------------------------------------------------

    private void load() throws IOException {
        if (!Files.exists(storePath)) {
            return;
        }
        List<String> lines = Files.readAllLines(storePath, StandardCharsets.UTF_8);
        Base64.Decoder decoder = Base64.getDecoder();
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            if (line.isEmpty()) {
                continue;
            }
            String[] parts = line.split(":");
            try {
                if (parts.length != 4) {
                    throw new IllegalArgumentException("expected 4 fields");
                }
                int iterations = Integer.parseInt(parts[1]);
                byte[] salt = decoder.decode(parts[2]);
                byte[] hash = decoder.decode(parts[3]);
                accounts.put(parts[0], new StoredCredential(iterations, salt, hash));
            } catch (IllegalArgumentException e) {
                throw new IOException("Corrupt credentials file at line " + (i + 1) + ": " + e.getMessage(), e);
            }
        }
    }

    /** Writes all accounts to a temp file, then atomically replaces the store. */
    private void save() throws IOException {
        Base64.Encoder encoder = Base64.getEncoder();
        List<String> lines = new ArrayList<>();
        for (Map.Entry<String, StoredCredential> entry : accounts.entrySet()) {
            StoredCredential c = entry.getValue();
            lines.add(entry.getKey() + ":" + c.iterations + ":"
                    + encoder.encodeToString(c.salt) + ":" + encoder.encodeToString(c.hash));
        }

        Path absolute = storePath.toAbsolutePath();
        Path tmp = Files.createTempFile(absolute.getParent(), ".users", ".tmp");
        try {
            restrictToOwner(tmp);
            Files.write(tmp, lines, StandardCharsets.UTF_8);
            try {
                Files.move(tmp, absolute, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, absolute, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    /** On POSIX systems, make the file readable and writable by the owner only. */
    private static void restrictToOwner(Path path) throws IOException {
        if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        }
    }

    private static final class StoredCredential {
        final int iterations;
        final byte[] salt;
        final byte[] hash;

        StoredCredential(int iterations, byte[] salt, byte[] hash) {
            this.iterations = iterations;
            this.salt = salt;
            this.hash = hash;
        }
    }

    // ------------------------------------------------------------------
    // Command-line interface
    // ------------------------------------------------------------------

    public static void main(String[] args) {
        Path store = Paths.get(args.length > 0 ? args[0] : DEFAULT_STORE);
        UserAccountManager manager;
        try {
            manager = new UserAccountManager(store);
        } catch (IOException e) {
            System.err.println("Could not open credentials file: " + e.getMessage());
            System.exit(1);
            return;
        }

        Input input = new Input();
        System.out.println("User Account Manager (credentials file: " + store.toAbsolutePath() + ")");

        while (true) {
            System.out.println();
            System.out.println("1) Register a new account");
            System.out.println("2) Log in");
            System.out.println("3) Quit");
            String choice = input.readLine("Choose an option: ");
            if (choice == null) {
                return; // end of input
            }

            switch (choice.trim()) {
                case "1":
                    handleRegister(manager, input);
                    break;
                case "2":
                    handleLogin(manager, input);
                    break;
                case "3":
                    System.out.println("Goodbye.");
                    return;
                default:
                    System.out.println("Please enter 1, 2 or 3.");
            }
        }
    }

    private static void handleRegister(UserAccountManager manager, Input input) {
        String username = input.readLine("Choose a username: ");
        char[] password = input.readPassword("Choose a password: ");
        char[] confirm = input.readPassword("Confirm the password: ");
        try {
            if (username == null || password == null || confirm == null) {
                System.out.println("Registration cancelled.");
                return;
            }
            if (!Arrays.equals(password, confirm)) {
                System.out.println("The passwords do not match. Account not created.");
                return;
            }
            manager.register(username.trim(), password);
            System.out.println("Account '" + username.trim() + "' created successfully.");
        } catch (IllegalArgumentException e) {
            System.out.println("Could not create account: " + e.getMessage());
        } catch (IOException e) {
            System.out.println("Could not save account: " + e.getMessage());
        } finally {
            wipe(password);
            wipe(confirm);
        }
    }

    private static void handleLogin(UserAccountManager manager, Input input) {
        String username = input.readLine("Username: ");
        char[] password = input.readPassword("Password: ");
        try {
            if (username != null && password != null && manager.authenticate(username, password)) {
                System.out.println("Login successful. Welcome, " + username.trim() + "!");
            } else {
                // Deliberately vague: don't reveal whether the username exists.
                System.out.println("Login failed: invalid username or password.");
            }
        } finally {
            wipe(password);
        }
    }

    private static void wipe(char[] chars) {
        if (chars != null) {
            Arrays.fill(chars, '\0');
        }
    }

    /**
     * Reads from the terminal when one is available (so passwords are hidden
     * while typing), otherwise falls back to standard input.
     */
    private static final class Input {
        private final Console console = System.console();
        private final BufferedReader reader =
                new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));

        String readLine(String prompt) {
            if (console != null) {
                return console.readLine("%s", prompt);
            }
            System.out.print(prompt);
            System.out.flush();
            try {
                return reader.readLine();
            } catch (IOException e) {
                return null;
            }
        }

        char[] readPassword(String prompt) {
            if (console != null) {
                return console.readPassword("%s", prompt);
            }
            String line = readLine(prompt);
            return line == null ? null : line.toCharArray();
        }
    }
}
