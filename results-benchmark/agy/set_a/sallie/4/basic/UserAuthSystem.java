import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.regex.Pattern;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * UserAuthSystem - A complete, secure user registration and authentication application in Java.
 *
 * Key Features:
 *  - Secure password hashing using PBKDF2 with HMAC-SHA256 and per-user cryptographic salts.
 *  - Constant-time hash verification to mitigate timing attacks.
 *  - Input validation for usernames and passwords.
 *  - Persistent credential storage to a local file with restricted permissions.
 *  - Dual mode: interactive console menu and direct command-line arguments.
 *  - Zero external dependencies (standard Java library only).
 */
public class UserAuthSystem {

    // Default credential storage filename
    public static final String DEFAULT_STORAGE_FILE = "credentials.txt";

    // Regular expression for validating usernames: 3-30 chars, alphanumeric, dots, underscores, hyphens
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9._-]{3,30}$");
    private static final int MIN_PASSWORD_LENGTH = 8;

    // Cryptographic parameters recommended by OWASP
    private static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int SALT_LENGTH_BYTES = 16;     // 128 bits of salt
    private static final int ITERATIONS = 65536;         // OWASP recommended iteration count
    private static final int KEY_LENGTH_BITS = 256;      // 256-bit derived key length

    // Dummy salt and hash used for constant-time mitigation when a user does not exist
    private static final byte[] DUMMY_SALT = new byte[SALT_LENGTH_BYTES];
    private static final byte[] DUMMY_HASH;

    static {
        new SecureRandom().nextBytes(DUMMY_SALT);
        byte[] hash;
        try {
            hash = hashPassword("dummy-password".toCharArray(), DUMMY_SALT);
        } catch (Exception e) {
            hash = new byte[KEY_LENGTH_BITS / 8];
        }
        DUMMY_HASH = hash;
    }

    // =========================================================================
    // Data Model
    // =========================================================================

    /**
     * Represents a stored user credential record.
     */
    public static class UserCredential {
        private final String username;
        private final byte[] salt;
        private final byte[] passwordHash;

        public UserCredential(String username, byte[] salt, byte[] passwordHash) {
            this.username = username;
            this.salt = salt.clone();
            this.passwordHash = passwordHash.clone();
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

        /**
         * Serializes the credential into a safe text line: username:base64(salt):base64(hash)
         */
        public String serialize() {
            Base64.Encoder encoder = Base64.getEncoder();
            return username + ":" + encoder.encodeToString(salt) + ":" + encoder.encodeToString(passwordHash);
        }

        /**
         * Parses a serialized line into a UserCredential object.
         */
        public static UserCredential deserialize(String line) {
            if (line == null || line.trim().isEmpty() || line.startsWith("#")) {
                return null;
            }
            String[] parts = line.split(":", 3);
            if (parts.length != 3) {
                return null;
            }
            try {
                String username = parts[0].trim();
                Base64.Decoder decoder = Base64.getDecoder();
                byte[] salt = decoder.decode(parts[1].trim());
                byte[] hash = decoder.decode(parts[2].trim());
                return new UserCredential(username, salt, hash);
            } catch (IllegalArgumentException e) {
                return null; // Malformed Base64
            }
        }
    }

    // =========================================================================
    // Storage Repository
    // =========================================================================

    /**
     * Handles reading and writing credentials to a persistent text file.
     */
    public static class CredentialRepository {
        private final Path filePath;

        public CredentialRepository(String filename) {
            this.filePath = Paths.get(filename);
        }

        /**
         * Loads all credentials from the file into an in-memory map.
         * Usernames are stored in a case-preserving map, with case-insensitive lookup.
         */
        public synchronized Map<String, UserCredential> loadAll() throws IOException {
            Map<String, UserCredential> users = new LinkedHashMap<>();
            if (!Files.exists(filePath)) {
                return users;
            }

            List<String> lines = Files.readAllLines(filePath, StandardCharsets.UTF_8);
            for (String line : lines) {
                UserCredential cred = UserCredential.deserialize(line);
                if (cred != null) {
                    users.put(cred.getUsername().toLowerCase(Locale.ROOT), cred);
                }
            }
            return users;
        }

        /**
         * Appends a new user credential to the storage file.
         */
        public synchronized void save(UserCredential credential) throws IOException {
            ensureFileExistsWithSecurePermissions();
            String line = credential.serialize() + System.lineSeparator();
            Files.write(filePath, line.getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND, StandardOpenOption.WRITE);
        }

        /**
         * Rewrites all credentials (e.g., after a password change or delete).
         */
        public synchronized void saveAll(Collection<UserCredential> credentials) throws IOException {
            ensureFileExistsWithSecurePermissions();
            List<String> lines = new ArrayList<>();
            lines.add("# User Credentials Storage - DO NOT MODIFY DIRECTLY");
            for (UserCredential cred : credentials) {
                lines.add(cred.serialize());
            }
            Files.write(filePath, lines, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
        }

        private void ensureFileExistsWithSecurePermissions() throws IOException {
            if (!Files.exists(filePath)) {
                Files.createFile(filePath);
                try {
                    Set<PosixFilePermission> permissions = PosixFilePermissions.fromString("rw-------");
                    Files.setPosixFilePermissions(filePath, permissions);
                } catch (UnsupportedOperationException ignored) {
                    // Windows or filesystems that do not support POSIX permissions
                }
            }
        }
    }

    // =========================================================================
    // Cryptography & Authentication Service
    // =========================================================================

    /**
     * Service providing password hashing, registration, and authentication logic.
     */
    public static class AuthService {
        private final CredentialRepository repository;
        private final SecureRandom secureRandom;

        public AuthService(CredentialRepository repository) {
            this.repository = repository;
            this.secureRandom = new SecureRandom();
        }

        /**
         * Validates username format.
         * @return null if valid, or an error message describing the violation.
         */
        public String validateUsername(String username) {
            if (username == null || username.trim().isEmpty()) {
                return "Username cannot be empty.";
            }
            if (!USERNAME_PATTERN.matcher(username).matches()) {
                return "Username must be 3-30 characters long and contain only letters, digits, '.', '_', or '-'.";
            }
            return null;
        }

        /**
         * Validates password strength.
         * @return null if valid, or an error message describing the violation.
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
         *
         * @param username the desired username
         * @param password the plaintext password characters
         * @return registration result status
         * @throws IOException on storage failure
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

            // Generate a cryptographic salt and compute PBKDF2 hash
            byte[] salt = new byte[SALT_LENGTH_BYTES];
            secureRandom.nextBytes(salt);

            byte[] hash;
            try {
                hash = hashPassword(password, salt);
            } catch (Exception e) {
                return RegistrationResult.failure("Error hashing password: " + e.getMessage());
            }

            UserCredential newCredential = new UserCredential(username, salt, hash);
            repository.save(newCredential);

            return RegistrationResult.success("User '" + username + "' registered successfully.");
        }

        /**
         * Authenticates an existing user.
         *
         * @param username the username
         * @param password the password characters
         * @return authentication result status
         * @throws IOException on storage failure
         */
        public AuthResult authenticate(String username, char[] password) throws IOException {
            if (username == null || username.trim().isEmpty() || password == null || password.length == 0) {
                return AuthResult.failure("Username and password must not be empty.");
            }

            Map<String, UserCredential> users = repository.loadAll();
            UserCredential credential = users.get(username.toLowerCase(Locale.ROOT));

            byte[] saltToUse;
            byte[] expectedHash;

            if (credential != null) {
                saltToUse = credential.getSalt();
                expectedHash = credential.getPasswordHash();
            } else {
                // User not found: compute dummy hash to prevent timing-based user enumeration
                saltToUse = DUMMY_SALT;
                expectedHash = DUMMY_HASH;
            }

            byte[] computedHash;
            try {
                computedHash = hashPassword(password, saltToUse);
            } catch (Exception e) {
                return AuthResult.failure("Authentication error: " + e.getMessage());
            }

            // MessageDigest.isEqual performs constant-time comparison
            boolean matches = MessageDigest.isEqual(computedHash, expectedHash);

            // Clean up temporary computed hash
            Arrays.fill(computedHash, (byte) 0);

            if (credential != null && matches) {
                return AuthResult.success(credential.getUsername());
            } else {
                return AuthResult.failure("Invalid username or password.");
            }
        }

        /**
         * Returns a list of all registered usernames.
         */
        public List<String> listRegisteredUsers() throws IOException {
            Map<String, UserCredential> users = repository.loadAll();
            List<String> names = new ArrayList<>();
            for (UserCredential cred : users.values()) {
                names.add(cred.getUsername());
            }
            return Collections.unmodifiableList(names);
        }
    }

    /**
     * Hashes a password using PBKDF2WithHmacSHA256.
     */
    public static byte[] hashPassword(char[] password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH_BITS);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(HASH_ALGORITHM);
        byte[] hash = factory.generateSecret(spec).getEncoded();
        spec.clearPassword(); // Wipe sensitive characters from key spec memory
        return hash;
    }

    // =========================================================================
    // Result Types
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
    // User Interface & Main Entry Point
    // =========================================================================

    public static void main(String[] args) {
        String storageFile = DEFAULT_STORAGE_FILE;
        CredentialRepository repository = new CredentialRepository(storageFile);
        AuthService authService = new AuthService(repository);

        // Check if command line arguments were supplied
        if (args.length > 0) {
            handleCliArguments(args, authService);
            return;
        }

        // Run interactive menu
        runInteractiveMode(authService);
    }

    /**
     * Handles non-interactive CLI invocation.
     * Examples:
     *   java UserAuthSystem register <username> <password>
     *   java UserAuthSystem login <username> <password>
     *   java UserAuthSystem list
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
                    Arrays.fill(regPass, ' ');
                    if (regRes.isSuccess()) {
                        System.out.println("[SUCCESS] " + regRes.getMessage());
                        System.exit(0);
                    } else {
                        System.err.println("[ERROR] " + regRes.getMessage());
                        System.exit(1);
                    }
                    break;

                case "login":
                case "authenticate":
                    if (args.length < 3) {
                        System.err.println("Usage: java UserAuthSystem login <username> <password>");
                        System.exit(1);
                    }
                    char[] loginPass = args[2].toCharArray();
                    AuthResult authRes = authService.authenticate(args[1], loginPass);
                    Arrays.fill(loginPass, ' ');
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
                    System.out.println("Registered users count: " + users.size());
                    for (String user : users) {
                        System.out.println(" - " + user);
                    }
                    break;

                case "help":
                case "--help":
                case "-h":
                    printHelp();
                    break;

                default:
                    System.err.println("Unknown command: " + command);
                    printHelp();
                    System.exit(1);
            }
        } catch (IOException e) {
            System.err.println("[STORAGE ERROR] " + e.getMessage());
            System.exit(1);
        }
    }

    private static void printHelp() {
        System.out.println("User Authentication System CLI");
        System.out.println("-------------------------------------------");
        System.out.println("Usage:");
        System.out.println("  java UserAuthSystem                          Launch interactive menu");
        System.out.println("  java UserAuthSystem register <user> <pass>   Register a new account");
        System.out.println("  java UserAuthSystem login <user> <pass>      Authenticate an existing account");
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

        char[] password = readPassword(console, scanner, "Enter password (min 8 chars): ");
        if (password == null) return;
        String passValidation = authService.validatePassword(password);
        if (passValidation != null) {
            System.out.println("[Registration Failed] " + passValidation);
            Arrays.fill(password, ' ');
            return;
        }

        char[] confirmPassword = readPassword(console, scanner, "Confirm password: ");
        if (confirmPassword == null) {
            Arrays.fill(password, ' ');
            return;
        }
        if (!Arrays.equals(password, confirmPassword)) {
            System.out.println("[Registration Failed] Passwords do not match.");
            Arrays.fill(password, ' ');
            Arrays.fill(confirmPassword, ' ');
            return;
        }
        Arrays.fill(confirmPassword, ' ');

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
            Arrays.fill(password, ' ');
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
            Arrays.fill(password, ' ');
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
            System.out.println("[Error] Failed to load user list: " + e.getMessage());
        }
    }

    /**
     * Reads a password safely using System.console() if available (with masking),
     * or falls back to standard Scanner if piped or in an IDE console.
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
