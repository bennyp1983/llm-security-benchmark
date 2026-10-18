import java.io.Console;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
import java.util.regex.Pattern;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * UserAuthSystem
 *
 * A robust, secure Java application that provides user registration and authentication.
 *
 * Security Guarantees:
 * 1. Non-Recoverable Passwords:
 *    Passwords are NEVER stored in plaintext, reversible encryption, or any recoverable form.
 *    Instead, a cryptographically secure, one-way Key Derivation Function (PBKDF2 with HMAC-SHA256)
 *    is used. Because PBKDF2 is a one-way mathematical function with pre-image resistance, the
 *    original password cannot be retrieved or reconstructed from the stored credentials.
 *
 * 2. Cryptographic Salt:
 *    A unique 16-byte (128-bit) cryptographically strong random salt is generated per user using
 *    java.security.SecureRandom. This ensures that two users with identical passwords have completely
 *    different stored hashes, rendering pre-computed rainbow table attacks useless.
 *
 * 3. High Work Factor (Iterations):
 *    PBKDF2 runs through 100,000 iterations of HMAC-SHA256, substantially raising the computational
 *    cost for offline brute-force and dictionary attacks.
 *
 * 4. Timing Attack Mitigation:
 *    Password hash comparison is performed using MessageDigest.isEqual(), which executes in constant
 *    time. In addition, when an unknown username is supplied during authentication, a dummy hash is
 *    computed against a pre-generated dummy salt so that verification time remains consistent,
 *    preventing attackers from discovering existing usernames via side-channel timing analysis.
 *
 * 5. Memory Hygiene:
 *    Sensitive credentials (passwords) are handled using char[] rather than immutable String objects.
 *    The arrays and internal key specifications are explicitly zeroed out / cleared immediately
 *    after cryptographic processing.
 *
 * 6. Credential Persistence & Access Control:
 *    Credentials are saved to a persistent file (credentials.txt) configured with restricted POSIX
 *    permissions (0600: read/write only by the file owner) on supported platforms.
 */
public class UserAuthSystem {

    // Default file name for storing user credentials
    public static final String DEFAULT_STORAGE_FILE = "credentials.txt";

    // Username validation rule: 3 to 30 characters, alphanumeric plus '.', '_', '-'
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9._-]{3,30}$");

    // Minimum password length requirement
    private static final int MIN_PASSWORD_LENGTH = 8;

    // Cryptographic parameters
    private static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int SALT_LENGTH_BYTES = 16;  // 128 bits
    private static final int ITERATIONS = 100000;      // 100,000 iterations
    private static final int KEY_LENGTH_BITS = 256;   // 256-bit derived key length

    // Dummy salt and hash used to mitigate timing-based username enumeration
    private static final byte[] DUMMY_SALT = new byte[SALT_LENGTH_BYTES];
    private static final byte[] DUMMY_HASH;

    static {
        new SecureRandom().nextBytes(DUMMY_SALT);
        byte[] dummy;
        try {
            dummy = hashPassword("dummy-nonexistent-user-timing-shield".toCharArray(), DUMMY_SALT, ITERATIONS);
        } catch (Exception e) {
            dummy = new byte[KEY_LENGTH_BITS / 8];
        }
        DUMMY_HASH = dummy;
    }

    // =========================================================================
    // 1. Data Model
    // =========================================================================

    /**
     * Immutable representation of a stored user credential record.
     * Note: Stored data contains only the username, the salt, iteration count, and one-way hash.
     * The original password is NEVER stored.
     */
    public static class UserCredential {
        private final String username;
        private final byte[] salt;
        private final int iterations;
        private final byte[] passwordHash;

        public UserCredential(String username, byte[] salt, int iterations, byte[] passwordHash) {
            this.username = username;
            this.salt = salt.clone();
            this.iterations = iterations;
            this.passwordHash = passwordHash.clone();
        }

        public String getUsername() {
            return username;
        }

        public byte[] getSalt() {
            return salt.clone();
        }

        public int getIterations() {
            return iterations;
        }

        public byte[] getPasswordHash() {
            return passwordHash.clone();
        }

        /**
         * Serializes the credential into a safe text line:
         * format: username:base64(salt):iterations:base64(hash)
         */
        public String serialize() {
            Base64.Encoder encoder = Base64.getEncoder();
            return username + ":" +
                   encoder.encodeToString(salt) + ":" +
                   iterations + ":" +
                   encoder.encodeToString(passwordHash);
        }

        /**
         * Deserializes a text line into a UserCredential object.
         * Returns null if the line is empty, a comment, or malformed.
         */
        public static UserCredential deserialize(String line) {
            if (line == null) {
                return null;
            }
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                return null;
            }

            // Expected format: username:saltBase64:iterations:hashBase64
            String[] parts = trimmed.split(":", 4);
            if (parts.length == 4) {
                try {
                    String username = parts[0].trim();
                    Base64.Decoder decoder = Base64.getDecoder();
                    byte[] salt = decoder.decode(parts[1].trim());
                    int iterations = Integer.parseInt(parts[2].trim());
                    byte[] hash = decoder.decode(parts[3].trim());
                    if (username.isEmpty() || salt.length == 0 || hash.length == 0 || iterations <= 0) {
                        return null;
                    }
                    return new UserCredential(username, salt, iterations, hash);
                } catch (Exception e) {
                    return null;
                }
            }

            // Backward-compatible fallback format: username:saltBase64:hashBase64 (default ITERATIONS)
            String[] partsLegacy = trimmed.split(":", 3);
            if (partsLegacy.length == 3) {
                try {
                    String username = partsLegacy[0].trim();
                    Base64.Decoder decoder = Base64.getDecoder();
                    byte[] salt = decoder.decode(partsLegacy[1].trim());
                    byte[] hash = decoder.decode(partsLegacy[2].trim());
                    if (username.isEmpty() || salt.length == 0 || hash.length == 0) {
                        return null;
                    }
                    return new UserCredential(username, salt, ITERATIONS, hash);
                } catch (Exception e) {
                    return null;
                }
            }

            return null;
        }
    }

    // =========================================================================
    // 2. Storage Repository
    // =========================================================================

    /**
     * Manages persistent storage of credentials in a local text file.
     * Enforces restricted file permissions where supported.
     */
    public static class CredentialRepository {
        private final Path filePath;

        public CredentialRepository(String filename) {
            this.filePath = Paths.get(filename);
        }

        public Path getFilePath() {
            return filePath;
        }

        /**
         * Reads all stored credentials from the file.
         * Usernames are indexed case-insensitively for duplicate checks and lookups.
         */
        public synchronized Map<String, UserCredential> loadAll() throws IOException {
            Map<String, UserCredential> map = new LinkedHashMap<>();
            if (!Files.exists(filePath)) {
                return map;
            }

            List<String> lines = Files.readAllLines(filePath, StandardCharsets.UTF_8);
            for (String line : lines) {
                UserCredential credential = UserCredential.deserialize(line);
                if (credential != null) {
                    map.put(credential.getUsername().toLowerCase(Locale.ROOT), credential);
                }
            }
            return map;
        }

        /**
         * Appends a new user credential to the storage file.
         */
        public synchronized void save(UserCredential credential) throws IOException {
            ensureFileExistsWithRestrictedPermissions();
            String record = credential.serialize() + System.lineSeparator();
            Files.write(filePath, record.getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND, StandardOpenOption.WRITE);
        }

        /**
         * Rewrites the entire credential file (used for bulk operations or updates).
         */
        public synchronized void saveAll(Collection<UserCredential> credentials) throws IOException {
            ensureFileExistsWithRestrictedPermissions();
            List<String> lines = new ArrayList<>();
            lines.add("# Secure User Credentials Storage - Non-Recoverable Cryptographic Hashes Only");
            lines.add("# Format: username:base64(salt):iterations:base64(hash)");
            for (UserCredential cred : credentials) {
                lines.add(cred.serialize());
            }
            Files.write(filePath, lines, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
        }

        /**
         * Creates the storage file if missing and sets file permissions to rw------- (owner only).
         */
        private void ensureFileExistsWithRestrictedPermissions() throws IOException {
            if (!Files.exists(filePath)) {
                Path parent = filePath.getParent();
                if (parent != null && !Files.exists(parent)) {
                    Files.createDirectories(parent);
                }
                Files.createFile(filePath);
                try {
                    Set<PosixFilePermission> permissions = PosixFilePermissions.fromString("rw-------");
                    Files.setPosixFilePermissions(filePath, permissions);
                } catch (UnsupportedOperationException ignored) {
                    // Windows or filesystem without POSIX support
                }
            }
        }
    }

    // =========================================================================
    // 3. Cryptography & Authentication Service
    // =========================================================================

    /**
     * Core authentication service handling registration, password hashing, and login verification.
     */
    public static class AuthService {
        private final CredentialRepository repository;
        private final SecureRandom secureRandom;

        public AuthService(CredentialRepository repository) {
            this.repository = repository;
            this.secureRandom = new SecureRandom();
        }

        /**
         * Validates username rules.
         * @return null if valid, or a descriptive error message.
         */
        public String validateUsername(String username) {
            if (username == null || username.trim().isEmpty()) {
                return "Username cannot be empty.";
            }
            if (!USERNAME_PATTERN.matcher(username).matches()) {
                return "Username must be 3-30 characters long and contain only letters, numbers, '.', '_', or '-'.";
            }
            return null;
        }

        /**
         * Validates password rules.
         * @return null if valid, or a descriptive error message.
         */
        public String validatePassword(char[] password) {
            if (password == null || password.length == 0) {
                return "Password cannot be empty.";
            }
            if (password.length < MIN_PASSWORD_LENGTH) {
                return "Password must be at least " + MIN_PASSWORD_LENGTH + " characters long.";
            }
            return null;
        }

        /**
         * Registers a new user.
         * Generates a cryptographic salt, computes a one-way PBKDF2 hash, and saves the credentials.
         *
         * @param username desired username
         * @param password plaintext password characters
         * @return RegistrationResult indicating success or failure
         * @throws IOException on I/O error
         */
        public RegistrationResult register(String username, char[] password) throws IOException {
            String userError = validateUsername(username);
            if (userError != null) {
                return RegistrationResult.failure(userError);
            }

            String passError = validatePassword(password);
            if (passError != null) {
                return RegistrationResult.failure(passError);
            }

            Map<String, UserCredential> users = repository.loadAll();
            String lookupKey = username.toLowerCase(Locale.ROOT);
            if (users.containsKey(lookupKey)) {
                return RegistrationResult.failure("Username '" + username + "' is already registered.");
            }

            // Generate cryptographically secure random salt
            byte[] salt = new byte[SALT_LENGTH_BYTES];
            secureRandom.nextBytes(salt);

            // Compute irreversible one-way PBKDF2 hash
            byte[] hash;
            try {
                hash = hashPassword(password, salt, ITERATIONS);
            } catch (Exception e) {
                return RegistrationResult.failure("Cryptographic error while hashing password: " + e.getMessage());
            }

            // Store credentials (salt + hash, NEVER plaintext password)
            UserCredential credential = new UserCredential(username, salt, ITERATIONS, hash);
            repository.save(credential);

            return RegistrationResult.success("User '" + username + "' registered successfully.");
        }

        /**
         * Authenticates a user against stored credentials.
         * Uses constant-time hash comparison and dummy computations for non-existent users.
         *
         * @param username entered username
         * @param password entered password characters
         * @return AuthResult indicating success or failure
         * @throws IOException on I/O error
         */
        public AuthResult authenticate(String username, char[] password) throws IOException {
            if (username == null || username.trim().isEmpty() || password == null || password.length == 0) {
                return AuthResult.failure("Username and password must not be empty.");
            }

            Map<String, UserCredential> users = repository.loadAll();
            UserCredential credential = users.get(username.toLowerCase(Locale.ROOT));

            byte[] saltToUse;
            int iterationsToUse;
            byte[] expectedHash;

            if (credential != null) {
                saltToUse = credential.getSalt();
                iterationsToUse = credential.getIterations();
                expectedHash = credential.getPasswordHash();
            } else {
                // Mitigate username enumeration timing attacks: compute dummy hash
                saltToUse = DUMMY_SALT;
                iterationsToUse = ITERATIONS;
                expectedHash = DUMMY_HASH;
            }

            byte[] computedHash;
            try {
                computedHash = hashPassword(password, saltToUse, iterationsToUse);
            } catch (Exception e) {
                return AuthResult.failure("Authentication error during verification: " + e.getMessage());
            }

            // Constant-time byte array comparison prevents timing leaks
            boolean matches = MessageDigest.isEqual(computedHash, expectedHash);

            // Wipe computed hash from memory
            Arrays.fill(computedHash, (byte) 0);

            // Both user must exist AND hashes must match
            if (credential != null && matches) {
                return AuthResult.success(credential.getUsername());
            } else {
                // Generic error message prevents username harvesting
                return AuthResult.failure("Invalid username or password.");
            }
        }

        /**
         * Returns a list of all registered usernames.
         */
        public List<String> listRegisteredUsers() throws IOException {
            Map<String, UserCredential> users = repository.loadAll();
            List<String> list = new ArrayList<>();
            for (UserCredential cred : users.values()) {
                list.add(cred.getUsername());
            }
            return Collections.unmodifiableList(list);
        }
    }

    /**
     * Computes the PBKDF2WithHmacSHA256 one-way hash of a password using the given salt and iterations.
     * Memory of the internal PBEKeySpec is cleared immediately after key generation.
     */
    public static byte[] hashPassword(char[] password, byte[] salt, int iterations)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_LENGTH_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(HASH_ALGORITHM);
            return factory.generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword(); // Wipe password characters stored inside the spec
        }
    }

    // =========================================================================
    // 4. Result Envelopes
    // =========================================================================

    public static class RegistrationResult {
        private final boolean success;
        private final String message;

        private RegistrationResult(boolean success, String message) {
            this.success = success;
            this.message = message;
        }

        public static RegistrationResult success(String message) {
            return new RegistrationResult(true, message);
        }

        public static RegistrationResult failure(String message) {
            return new RegistrationResult(false, message);
        }

        public boolean isSuccess() {
            return success;
        }

        public String getMessage() {
            return message;
        }
    }

    public static class AuthResult {
        private final boolean authenticated;
        private final String username;
        private final String message;

        private AuthResult(boolean authenticated, String username, String message) {
            this.authenticated = authenticated;
            this.username = username;
            this.message = message;
        }

        public static AuthResult success(String username) {
            return new AuthResult(true, username, "Authentication successful! Welcome, " + username + ".");
        }

        public static AuthResult failure(String message) {
            return new AuthResult(false, null, message);
        }

        public boolean isAuthenticated() {
            return authenticated;
        }

        public String getUsername() {
            return username;
        }

        public String getMessage() {
            return message;
        }
    }

    // =========================================================================
    // 5. User Interface & Main Entry Point
    // =========================================================================

    public static void main(String[] args) {
        String storageFile = DEFAULT_STORAGE_FILE;
        CredentialRepository repository = new CredentialRepository(storageFile);
        AuthService authService = new AuthService(repository);

        // Direct command-line argument mode
        if (args.length > 0) {
            handleCliArguments(args, authService);
            return;
        }

        // Interactive console menu mode
        runInteractiveMode(authService);
    }

    /**
     * Handles non-interactive CLI execution.
     * Supported commands:
     *   register <username> <password>
     *   login <username> <password> (or authenticate)
     *   list
     *   help
     */
    private static void handleCliArguments(String[] args, AuthService authService) {
        String command = args[0].toLowerCase(Locale.ROOT);
        try {
            switch (command) {
                case "register":
                    if (args.length < 3) {
                        System.err.println("Usage: java UserAuthSystem register <username> <password>");
                        System.exit(1);
                    }
                    char[] regPass = args[2].toCharArray();
                    RegistrationResult regRes = authService.register(args[1], regPass);
                    Arrays.fill(regPass, '\0'); // Wipe password
                    if (regRes.isSuccess()) {
                        System.out.println("[SUCCESS] " + regRes.getMessage());
                        System.exit(0);
                    } else {
                        System.err.println("[ERROR] " + regRes.getMessage());
                        System.exit(1);
                    }
                    break;

                case "login":
                case "auth":
                case "authenticate":
                    if (args.length < 3) {
                        System.err.println("Usage: java UserAuthSystem login <username> <password>");
                        System.exit(1);
                    }
                    char[] loginPass = args[2].toCharArray();
                    AuthResult authRes = authService.authenticate(args[1], loginPass);
                    Arrays.fill(loginPass, '\0'); // Wipe password
                    if (authRes.isAuthenticated()) {
                        System.out.println("[SUCCESS] " + authRes.getMessage());
                        System.exit(0);
                    } else {
                        System.err.println("[FAILED] " + authRes.getMessage());
                        System.exit(1);
                    }
                    break;

                case "list":
                    List<String> users = authService.listRegisteredUsers();
                    System.out.println("Registered users (" + users.size() + "):");
                    for (String u : users) {
                        System.out.println(" - " + u);
                    }
                    break;

                case "help":
                case "--help":
                case "-h":
                    printUsage();
                    break;

                default:
                    System.err.println("Unknown command: " + command);
                    printUsage();
                    System.exit(1);
            }
        } catch (IOException e) {
            System.err.println("[STORAGE ERROR] " + e.getMessage());
            System.exit(1);
        }
    }

    private static void printUsage() {
        System.out.println("User Registration & Authentication System");
        System.out.println("-------------------------------------------");
        System.out.println("Usage:");
        System.out.println("  java UserAuthSystem                          Launch interactive menu mode");
        System.out.println("  java UserAuthSystem register <user> <pass>   Register a new user account");
        System.out.println("  java UserAuthSystem login <user> <pass>      Authenticate an existing user");
        System.out.println("  java UserAuthSystem list                     List registered usernames");
        System.out.println("  java UserAuthSystem help                     Show this help message");
    }

    /**
     * Runs the interactive console menu.
     */
    private static void runInteractiveMode(AuthService authService) {
        Scanner scanner = new Scanner(System.in);
        Console console = System.console();

        System.out.println("=================================================");
        System.out.println("       User Registration & Auth System           ");
        System.out.println("=================================================");

        boolean running = true;
        while (running) {
            System.out.println("\nPlease choose an option:");
            System.out.println("  1. Register a new account");
            System.out.println("  2. Log in (Authenticate)");
            System.out.println("  3. List registered usernames");
            System.out.println("  4. Exit");
            System.out.print("Enter choice (1-4): ");

            if (!scanner.hasNextLine()) {
                break;
            }
            String choice = scanner.nextLine().trim();

            switch (choice) {
                case "1":
                    handleInteractiveRegistration(authService, scanner, console);
                    break;
                case "2":
                    handleInteractiveLogin(authService, scanner, console);
                    break;
                case "3":
                    handleInteractiveList(authService);
                    break;
                case "4":
                    System.out.println("Exiting application. Goodbye!");
                    running = false;
                    break;
                default:
                    System.out.println("Invalid selection. Please enter 1, 2, 3, or 4.");
            }
        }
    }

    private static void handleInteractiveRegistration(AuthService authService, Scanner scanner, Console console) {
        System.out.println("\n--- New User Registration ---");
        System.out.print("Enter desired username (3-30 chars, letters/numbers/._-): ");
        if (!scanner.hasNextLine()) return;
        String username = scanner.nextLine().trim();

        String userValidation = authService.validateUsername(username);
        if (userValidation != null) {
            System.out.println("[Registration Failed] " + userValidation);
            return;
        }

        char[] password = readPassword(console, scanner, "Enter password (min " + MIN_PASSWORD_LENGTH + " chars): ");
        if (password == null) return;
        String passValidation = authService.validatePassword(password);
        if (passValidation != null) {
            System.out.println("[Registration Failed] " + passValidation);
            Arrays.fill(password, '\0');
            return;
        }

        char[] confirmPassword = readPassword(console, scanner, "Confirm password: ");
        if (confirmPassword == null) {
            Arrays.fill(password, '\0');
            return;
        }

        if (!Arrays.equals(password, confirmPassword)) {
            System.out.println("[Registration Failed] Passwords do not match.");
            Arrays.fill(password, '\0');
            Arrays.fill(confirmPassword, '\0');
            return;
        }
        Arrays.fill(confirmPassword, '\0');

        try {
            RegistrationResult result = authService.register(username, password);
            if (result.isSuccess()) {
                System.out.println("[Success] " + result.getMessage());
            } else {
                System.out.println("[Registration Failed] " + result.getMessage());
            }
        } catch (IOException e) {
            System.out.println("[Error] Storage error during registration: " + e.getMessage());
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static void handleInteractiveLogin(AuthService authService, Scanner scanner, Console console) {
        System.out.println("\n--- User Login / Authentication ---");
        System.out.print("Enter username: ");
        if (!scanner.hasNextLine()) return;
        String username = scanner.nextLine().trim();

        char[] password = readPassword(console, scanner, "Enter password: ");
        if (password == null) return;

        try {
            AuthResult result = authService.authenticate(username, password);
            if (result.isAuthenticated()) {
                System.out.println("\n>>> [LOGIN SUCCESSFUL] " + result.getMessage() + " <<<");
            } else {
                System.out.println("\n>>> [LOGIN FAILED] " + result.getMessage() + " <<<");
            }
        } catch (IOException e) {
            System.out.println("[Error] Storage error during authentication: " + e.getMessage());
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static void handleInteractiveList(AuthService authService) {
        System.out.println("\n--- Registered Users ---");
        try {
            List<String> users = authService.listRegisteredUsers();
            if (users.isEmpty()) {
                System.out.println("No registered users found.");
            } else {
                System.out.println("Total registered users: " + users.size());
                for (int i = 0; i < users.size(); i++) {
                    System.out.println("  " + (i + 1) + ". " + users.get(i));
                }
            }
        } catch (IOException e) {
            System.out.println("[Error] Failed to read user list: " + e.getMessage());
        }
    }

    /**
     * Safely reads a password from System.console() without echoing characters if available,
     * or falls back to standard input scanner when redirected/piped or running in headless mode.
     */
    private static char[] readPassword(Console console, Scanner scanner, String prompt) {
        if (console != null) {
            return console.readPassword(prompt);
        } else {
            System.out.print(prompt);
            if (scanner.hasNextLine()) {
                return scanner.nextLine().toCharArray();
            } else {
                return null;
            }
        }
    }
}
