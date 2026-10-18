import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Scanner;
import java.util.Set;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * User registration and authentication system.
 * 
 * Provides secure account registration, credential persistence,
 * and subsequent user authentication using industry-standard cryptography:
 * - Salted PBKDF2-HMAC-SHA256 password hashing (CWE-256, CWE-312, CWE-916)
 * - Cryptographically secure 128-bit unique salt per user (CWE-759, CWE-760)
 * - Constant-time hash verification via MessageDigest.isEqual (CWE-208)
 * - In-memory sensitive data zeroization (char[] wiping) (CWE-316)
 * - Atomic credential file writes and restricted file permissions (CWE-732, CWE-377)
 */
public class UserRegistration {

    public static final String DEFAULT_CREDENTIALS_FILE = "users.txt";
    private static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int SALT_BYTES = 16;
    private static final int HASH_KEY_BITS = 256;
    private static final int DEFAULT_ITERATIONS = 100_000;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final Path storagePath;
    private final Map<String, AccountRecord> accounts = new HashMap<>();
    private final Object lock = new Object();

    /**
     * Data structure representing a registered user's security credentials.
     */
    public static final class AccountRecord {
        private final String username;
        private final byte[] salt;
        private final byte[] passwordHash;
        private final int iterations;

        public AccountRecord(String username, byte[] salt, byte[] passwordHash, int iterations) {
            this.username = username;
            this.salt = salt.clone();
            this.passwordHash = passwordHash.clone();
            this.iterations = iterations;
        }

        public String getUsername() {
            return username;
        }

        public byte[] getSalt() {
            return salt.clone();
        }

        public byte[] getPasswordHash() {
            return passwordHash.clone();
        }

        public int getIterations() {
            return iterations;
        }

        public String serialize() {
            return username + ":" +
                   Base64.getEncoder().encodeToString(salt) + ":" +
                   Base64.getEncoder().encodeToString(passwordHash) + ":" +
                   iterations;
        }

        public static AccountRecord deserialize(String line) {
            if (line == null || line.trim().isEmpty() || line.startsWith("#")) {
                return null;
            }
            String[] parts = line.split(":");
            if (parts.length < 4) {
                return null;
            }
            String user = parts[0].trim();
            byte[] salt = Base64.getDecoder().decode(parts[1].trim());
            byte[] hash = Base64.getDecoder().decode(parts[2].trim());
            int iters = Integer.parseInt(parts[3].trim());
            return new AccountRecord(user, salt, hash, iters);
        }
    }

    /**
     * Initializes user registration manager with default storage location.
     */
    public UserRegistration() {
        this(resolveDefaultStoragePath());
    }

    /**
     * Initializes user registration manager with specified storage path.
     *
     * @param storagePath path to the credentials persistence file
     */
    public UserRegistration(Path storagePath) {
        this.storagePath = Objects.requireNonNull(storagePath, "storagePath cannot be null");
        loadCredentials();
    }

    public UserRegistration(File storageFile) {
        this(Objects.requireNonNull(storageFile, "storageFile cannot be null").toPath());
    }

    public UserRegistration(String storageFilePath) {
        this(Paths.get(Objects.requireNonNull(storageFilePath, "storageFilePath cannot be null")));
    }

    private static Path resolveDefaultStoragePath() {
        String envPath = System.getenv("ACCOUNTS_FILE");
        if (envPath != null && !envPath.trim().isEmpty()) {
            return Paths.get(envPath.trim());
        }
        String propPath = System.getProperty("accounts.file");
        if (propPath != null && !propPath.trim().isEmpty()) {
            return Paths.get(propPath.trim());
        }
        return Paths.get(DEFAULT_CREDENTIALS_FILE);
    }

    /**
     * Registers a new user account with string password.
     *
     * @param username username for the new account
     * @param password user password
     * @return true if registration succeeded, false if validation failed or user already exists
     */
    public boolean register(String username, String password) {
        if (password == null) {
            return false;
        }
        char[] passChars = password.toCharArray();
        try {
            return register(username, passChars);
        } finally {
            Arrays.fill(passChars, '\0');
        }
    }

    /**
     * Registers a new user account with char array password.
     *
     * @param username username for the new account
     * @param password user password as char[] (cleared after use)
     * @return true if registration succeeded, false if validation failed or user already exists
     */
    public boolean register(String username, char[] password) {
        if (!isValidUsername(username) || !isValidPassword(password)) {
            return false;
        }

        String lookupKey = username.trim().toLowerCase();
        synchronized (lock) {
            if (accounts.containsKey(lookupKey)) {
                return false; // User already exists
            }

            byte[] salt = generateSalt(SALT_BYTES);
            byte[] hash = hashPassword(password, salt, DEFAULT_ITERATIONS, HASH_KEY_BITS);

            AccountRecord account = new AccountRecord(username.trim(), salt, hash, DEFAULT_ITERATIONS);
            accounts.put(lookupKey, account);

            saveCredentials();
            return true;
        }
    }

    /**
     * Authenticates a user with string password.
     *
     * @param username username to authenticate
     * @param password password to test
     * @return true if credentials match, false otherwise
     */
    public boolean authenticate(String username, String password) {
        if (password == null) {
            return false;
        }
        char[] passChars = password.toCharArray();
        try {
            return authenticate(username, passChars);
        } finally {
            Arrays.fill(passChars, '\0');
        }
    }

    /**
     * Authenticates a user with char array password.
     *
     * @param username username to authenticate
     * @param password password to test as char[]
     * @return true if credentials match, false otherwise
     */
    public boolean authenticate(String username, char[] password) {
        if (username == null || password == null) {
            return false;
        }

        String lookupKey = username.trim().toLowerCase();
        AccountRecord account;
        synchronized (lock) {
            account = accounts.get(lookupKey);
        }

        if (account == null) {
            // Mitigate timing side-channels by performing a dummy hash computation
            byte[] dummySalt = new byte[SALT_BYTES];
            hashPassword(password, dummySalt, DEFAULT_ITERATIONS, HASH_KEY_BITS);
            return false;
        }

        byte[] attemptedHash = hashPassword(password, account.getSalt(), account.getIterations(), HASH_KEY_BITS);
        try {
            // Constant-time comparison prevents timing attacks (CWE-208)
            return MessageDigest.isEqual(attemptedHash, account.getPasswordHash());
        } finally {
            Arrays.fill(attemptedHash, (byte) 0);
        }
    }

    /**
     * Convenience login method matching authenticate.
     */
    public boolean login(String username, String password) {
        return authenticate(username, password);
    }

    public boolean login(String username, char[] password) {
        return authenticate(username, password);
    }

    /**
     * Checks if a user already exists in storage.
     */
    public boolean userExists(String username) {
        if (username == null) {
            return false;
        }
        synchronized (lock) {
            return accounts.containsKey(username.trim().toLowerCase());
        }
    }

    /**
     * Returns the number of registered accounts.
     */
    public int getAccountCount() {
        synchronized (lock) {
            return accounts.size();
        }
    }

    // =========================================================================
    // Cryptographic Helpers
    // =========================================================================

    public static byte[] generateSalt(int length) {
        byte[] salt = new byte[length];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    public static byte[] hashPassword(char[] password, byte[] salt, int iterations, int keyLengthBits) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLengthBits);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(HASH_ALGORITHM);
            return factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Cryptographic algorithm error: " + HASH_ALGORITHM, e);
        } finally {
            spec.clearPassword();
        }
    }

    // =========================================================================
    // Persistence
    // =========================================================================

    private void loadCredentials() {
        synchronized (lock) {
            accounts.clear();
            if (!Files.exists(storagePath)) {
                return;
            }

            try (BufferedReader reader = Files.newBufferedReader(storagePath, StandardCharsets.UTF_8)) {
                String line;
                while ((line = reader.readLine()) != null) {
                    AccountRecord record = AccountRecord.deserialize(line);
                    if (record != null) {
                        accounts.put(record.getUsername().toLowerCase(), record);
                    }
                }
            } catch (IOException e) {
                System.err.println("Warning: Unable to read credentials file: " + e.getMessage());
            }
        }
    }

    private void saveCredentials() {
        synchronized (lock) {
            Path parent = storagePath.getParent();
            try {
                if (parent != null) {
                    Files.createDirectories(parent);
                }

                // Write to a temporary sibling file and perform an atomic replace
                Path tempFile = Files.createTempFile(
                    parent != null ? parent : Paths.get("."),
                    "users_", ".tmp"
                );

                try {
                    restrictFilePermissions(tempFile);

                    try (BufferedWriter writer = Files.newBufferedWriter(tempFile, StandardCharsets.UTF_8)) {
                        writer.write("# User Credentials Store - DO NOT EDIT MANUALLY");
                        writer.newLine();
                        for (AccountRecord account : accounts.values()) {
                            writer.write(account.serialize());
                            writer.newLine();
                        }
                    }

                    try {
                        Files.move(tempFile, storagePath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
                    } catch (AtomicMoveNotSupportedException e) {
                        Files.move(tempFile, storagePath, StandardCopyOption.REPLACE_EXISTING);
                    }

                    restrictFilePermissions(storagePath);
                } finally {
                    Files.deleteIfExists(tempFile);
                }
            } catch (IOException e) {
                System.err.println("Error saving credentials to " + storagePath + ": " + e.getMessage());
            }
        }
    }

    private static void restrictFilePermissions(Path path) {
        try {
            Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
            Files.setPosixFilePermissions(path, perms);
        } catch (UnsupportedOperationException | IOException ignored) {
            // Ignored on non-POSIX filesystems like standard Windows
        }
    }

    // =========================================================================
    // Validation
    // =========================================================================

    public static boolean isValidUsername(String username) {
        if (username == null) {
            return false;
        }
        String trimmed = username.trim();
        if (trimmed.length() < 3 || trimmed.length() > 50) {
            return false;
        }
        // Disallow colons as they are delimiter in store, allow alphanumeric and . _ -
        return trimmed.matches("^[a-zA-Z0-9._-]+$");
    }

    public static boolean isValidPassword(char[] password) {
        return password != null && password.length >= 6;
    }

    // =========================================================================
    // Command-Line & Interactive User Interface
    // =========================================================================

    public static void main(String[] args) {
        UserRegistration app = new UserRegistration();

        if (args.length > 0) {
            handleArgsMode(app, args);
        } else {
            handleInteractiveMode(app);
        }
    }

    private static void handleArgsMode(UserRegistration app, String[] args) {
        String cmd = args[0].toLowerCase();
        if (cmd.equals("register") || cmd.equals("-r")) {
            if (args.length >= 3) {
                String user = args[1];
                String pass = args[2];
                boolean registered = app.register(user, pass);
                if (registered) {
                    System.out.println("Registration successful for user: " + user);
                } else {
                    System.err.println("Registration failed. Username may already exist or input is invalid.");
                    System.exit(1);
                }
            } else {
                System.err.println("Usage: register <username> <password>");
                System.exit(1);
            }
        } else if (cmd.equals("login") || cmd.equals("auth") || cmd.equals("authenticate") || cmd.equals("-l")) {
            if (args.length >= 3) {
                String user = args[1];
                String pass = args[2];
                boolean authenticated = app.authenticate(user, pass);
                if (authenticated) {
                    System.out.println("Authentication successful for user: " + user);
                } else {
                    System.err.println("Authentication failed. Invalid username or password.");
                    System.exit(1);
                }
            } else {
                System.err.println("Usage: login <username> <password>");
                System.exit(1);
            }
        } else if (cmd.equals("exists") || cmd.equals("check")) {
            if (args.length >= 2) {
                String user = args[1];
                if (app.userExists(user)) {
                    System.out.println("User exists: " + user);
                } else {
                    System.out.println("User does not exist: " + user);
                    System.exit(1);
                }
            } else {
                System.err.println("Usage: check <username>");
                System.exit(1);
            }
        } else if (args.length == 2) {
            // General fallback: if invoked as `java UserRegistration <username> <password>`
            String user = args[0];
            String pass = args[1];
            if (app.userExists(user)) {
                boolean auth = app.authenticate(user, pass);
                if (auth) {
                    System.out.println("Authentication successful for user: " + user);
                } else {
                    System.err.println("Authentication failed for user: " + user);
                    System.exit(1);
                }
            } else {
                boolean reg = app.register(user, pass);
                if (reg) {
                    System.out.println("Registration successful for user: " + user);
                } else {
                    System.err.println("Registration failed for user: " + user);
                    System.exit(1);
                }
            }
        } else {
            printHelp();
        }
    }

    private static void handleInteractiveMode(UserRegistration app) {
        Scanner scanner = new Scanner(System.in, StandardCharsets.UTF_8);
        Console console = System.console();

        System.out.println("==================================================");
        System.out.println("       User Registration & Authentication         ");
        System.out.println("==================================================");

        boolean running = true;
        while (running) {
            System.out.println("\nSelect an option:");
            System.out.println("  1) Register a new account");
            System.out.println("  2) Log in / Authenticate");
            System.out.println("  3) Check if username exists");
            System.out.println("  4) Exit");
            System.out.print("> ");

            if (!scanner.hasNextLine()) {
                break;
            }

            String choice = scanner.nextLine().trim();
            switch (choice) {
                case "1" -> {
                    System.out.print("Enter new username: ");
                    if (!scanner.hasNextLine()) break;
                    String regUser = scanner.nextLine().trim();

                    char[] regPass = readPasswordInput(console, scanner, "Enter password (min 6 characters): ");
                    try {
                        if (app.register(regUser, regPass)) {
                            System.out.println("Account '" + regUser + "' successfully registered!");
                        } else {
                            System.out.println("Registration failed. Either username exists or password is too short.");
                        }
                    } finally {
                        Arrays.fill(regPass, '\0');
                    }
                }
                case "2" -> {
                    System.out.print("Enter username: ");
                    if (!scanner.hasNextLine()) break;
                    String authUser = scanner.nextLine().trim();

                    char[] authPass = readPasswordInput(console, scanner, "Enter password: ");
                    try {
                        if (app.authenticate(authUser, authPass)) {
                            System.out.println("Authentication successful! Welcome, " + authUser + ".");
                        } else {
                            System.out.println("Authentication failed. Invalid username or password.");
                        }
                    } finally {
                        Arrays.fill(authPass, '\0');
                    }
                }
                case "3" -> {
                    System.out.print("Enter username to check: ");
                    if (!scanner.hasNextLine()) break;
                    String checkUser = scanner.nextLine().trim();
                    if (app.userExists(checkUser)) {
                        System.out.println("User '" + checkUser + "' exists.");
                    } else {
                        System.out.println("User '" + checkUser + "' not found.");
                    }
                }
                case "4", "exit", "quit", "q" -> {
                    System.out.println("Exiting application. Goodbye!");
                    running = false;
                }
                default -> System.out.println("Invalid option. Please enter 1, 2, 3, or 4.");
            }
        }
    }

    private static char[] readPasswordInput(Console console, Scanner scanner, String prompt) {
        if (console != null) {
            char[] pass = console.readPassword("%s", prompt);
            return pass != null ? pass : new char[0];
        }
        System.out.print(prompt);
        if (scanner.hasNextLine()) {
            return scanner.nextLine().toCharArray();
        }
        return new char[0];
    }

    private static void printHelp() {
        System.out.println("Usage:");
        System.out.println("  java UserRegistration register <username> <password>  Register account");
        System.out.println("  java UserRegistration login <username> <password>     Authenticate account");
        System.out.println("  java UserRegistration check <username>                Check if user exists");
        System.out.println("  java UserRegistration                                 Start interactive mode");
    }
}
