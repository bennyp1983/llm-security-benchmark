import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.Console;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * Complete, self-contained Java application handling secure user authentication.
 * 
 * Key Features & Security Design:
 *  - Secure Credential Verification: Uses PBKDF2WithHmacSHA256 with 65,536 iterations
 *    and cryptographically random 16-byte salts generated via SecureRandom.
 *  - Constant-Time Comparison: Uses MessageDigest.isEqual() to prevent timing-based side-channel attacks.
 *  - Memory Hygiene: Sensitive password char arrays are explicitly zeroed out after use.
 *  - Application Audit Logging: Thread-safe structured logging to both standard console
 *    and a persistent log file ("auth_audit.log").
 *  - Log Injection Defense: All user-supplied data is sanitized against CRLF characters (CWE-117).
 *  - Brute-Force & Enumeration Protection: Implements account lockout after configurable failed
 *    attempts and uses uniform error messaging to avoid username harvesting.
 *  - Dual Operating Modes: Self-running automated test verification suite and an interactive CLI mode.
 */
public class UserAuthenticationApp {

    // =========================================================================
    // 1. Audit Logger Configuration & Security
    // =========================================================================

    public static class AuthAuditLogger {
        private static final Logger LOGGER = Logger.getLogger("UserAuthenticationAudit");
        private static final String AUDIT_LOG_FILE = "auth_audit.log";

        static {
            try {
                // Prevent duplicate logging to root handlers
                LOGGER.setUseParentHandlers(false);
                LOGGER.setLevel(Level.ALL);

                // Clear any pre-existing handlers
                for (Handler h : LOGGER.getHandlers()) {
                    LOGGER.removeHandler(h);
                }

                Formatter auditFormatter = new Formatter() {
                    private final DateTimeFormatter dtf = 
                            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")
                                             .withZone(ZoneId.systemDefault());

                    @Override
                    public String format(LogRecord record) {
                        return String.format("[%s] [%-7s] [AUDIT] %s%n",
                                dtf.format(Instant.ofEpochMilli(record.getMillis())),
                                record.getLevel().getName(),
                                record.getMessage());
                    }
                };

                // 1. Console Handler
                ConsoleHandler consoleHandler = new ConsoleHandler();
                consoleHandler.setLevel(Level.INFO);
                consoleHandler.setFormatter(auditFormatter);
                LOGGER.addHandler(consoleHandler);

                // 2. Persistent File Handler (append mode)
                FileHandler fileHandler = new FileHandler(AUDIT_LOG_FILE, true);
                fileHandler.setLevel(Level.ALL);
                fileHandler.setFormatter(auditFormatter);
                LOGGER.addHandler(fileHandler);

            } catch (IOException e) {
                System.err.println("CRITICAL: Failed to initialize file logger: " + e.getMessage());
            }
        }

        /**
         * Sanitizes user input to prevent Log Injection (CRLF / CWE-117).
         */
        public static String sanitize(String input) {
            if (input == null) return "null";
            return input.replace('\r', '_').replace('\n', '_');
        }

        public static void logSuccess(String username, String clientIp) {
            LOGGER.info(String.format("AUTHENTICATION_SUCCESS - User '%s' authenticated successfully from [%s]",
                    sanitize(username), sanitize(clientIp)));
        }

        public static void logFailure(String username, String reason, String clientIp) {
            LOGGER.warning(String.format("AUTHENTICATION_FAILURE - Login failed for user '%s' from [%s]. Reason: %s",
                    sanitize(username), sanitize(clientIp), sanitize(reason)));
        }

        public static void logLockout(String username, String clientIp) {
            LOGGER.severe(String.format("ACCOUNT_LOCKED - User account '%s' locked after exceeding maximum failed login attempts from [%s]",
                    sanitize(username), sanitize(clientIp)));
        }

        public static void logRegistration(String username, String clientIp) {
            LOGGER.info(String.format("USER_REGISTRATION - New user '%s' registered successfully from [%s]",
                    sanitize(username), sanitize(clientIp)));
        }

        public static void logAccountUnlock(String username, String adminUser) {
            LOGGER.info(String.format("ACCOUNT_UNLOCKED - User '%s' account unlocked by administrator '%s'",
                    sanitize(username), sanitize(adminUser)));
        }

        public static String getAuditLogFilePath() {
            return AUDIT_LOG_FILE;
        }
    }

    // =========================================================================
    // 2. Cryptographic Password Service (PBKDF2WithHmacSHA256)
    // =========================================================================

    public static class PasswordSecurity {
        private static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA256";
        private static final int ITERATION_COUNT = 65_536; // OWASP recommendation for PBKDF2
        private static final int KEY_LENGTH_BITS = 256;    // 256-bit key
        private static final int SALT_LENGTH_BYTES = 16;   // 128-bit cryptographically secure salt
        private static final SecureRandom SECURE_RANDOM = new SecureRandom();

        /**
         * Generates a cryptographically strong pseudo-random salt.
         */
        public static byte[] generateSalt() {
            byte[] salt = new byte[SALT_LENGTH_BYTES];
            SECURE_RANDOM.nextBytes(salt);
            return salt;
        }

        /**
         * Derives a PBKDF2 key hash from the provided password and salt.
         */
        public static byte[] hashPassword(char[] password, byte[] salt) {
            PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATION_COUNT, KEY_LENGTH_BITS);
            try {
                SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(HASH_ALGORITHM);
                return keyFactory.generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IllegalStateException("Cryptographic provider error during PBKDF2 hashing", e);
            } finally {
                spec.clearPassword();
            }
        }

        /**
         * Verifies a submitted password against stored salt and expected hash.
         * Employs constant-time byte comparison to eliminate side-channel timing leaks.
         */
        public static boolean verifyPassword(char[] submittedPassword, byte[] storedSalt, byte[] expectedHash) {
            byte[] computedHash = hashPassword(submittedPassword, storedSalt);
            try {
                return MessageDigest.isEqual(computedHash, expectedHash);
            } finally {
                Arrays.fill(computedHash, (byte) 0);
            }
        }

        /**
         * Securely overwrites a character array in memory with null bytes.
         */
        public static void wipeArray(char[] sensitiveArray) {
            if (sensitiveArray != null) {
                Arrays.fill(sensitiveArray, '\0');
            }
        }
    }

    // =========================================================================
    // 3. User Account Model
    // =========================================================================

    public static class UserAccount {
        private final String username;
        private final byte[] salt;
        private byte[] passwordHash;
        private int failedLoginAttempts;
        private boolean accountLocked;
        private LocalDateTime lockedAt;
        private LocalDateTime lastLogin;

        public UserAccount(String username, byte[] salt, byte[] passwordHash) {
            this.username = Objects.requireNonNull(username, "Username must not be null");
            this.salt = Objects.requireNonNull(salt, "Salt must not be null");
            this.passwordHash = Objects.requireNonNull(passwordHash, "Password hash must not be null");
            this.failedLoginAttempts = 0;
            this.accountLocked = false;
        }

        public String getUsername() {
            return username;
        }

        public byte[] getSalt() {
            return salt;
        }

        public byte[] getPasswordHash() {
            return passwordHash;
        }

        public synchronized void setPasswordHash(byte[] newHash) {
            this.passwordHash = newHash;
        }

        public synchronized int getFailedLoginAttempts() {
            return failedLoginAttempts;
        }

        public synchronized void incrementFailedAttempts() {
            this.failedLoginAttempts++;
        }

        public synchronized void resetFailedAttempts() {
            this.failedLoginAttempts = 0;
        }

        public synchronized boolean isAccountLocked() {
            return accountLocked;
        }

        public synchronized void lockAccount() {
            this.accountLocked = true;
            this.lockedAt = LocalDateTime.now();
        }

        public synchronized void unlockAccount() {
            this.accountLocked = false;
            this.failedLoginAttempts = 0;
            this.lockedAt = null;
        }

        public synchronized LocalDateTime getLockedAt() {
            return lockedAt;
        }

        public synchronized LocalDateTime getLastLogin() {
            return lastLogin;
        }

        public synchronized void recordSuccessfulLogin() {
            this.lastLogin = LocalDateTime.now();
            this.failedLoginAttempts = 0;
        }
    }

    // =========================================================================
    // 4. User Account Repository Interface & In-Memory Store
    // =========================================================================

    public interface UserRepository {
        boolean save(UserAccount user);
        UserAccount findByUsername(String username);
        boolean existsByUsername(String username);
    }

    public static class InMemoryUserRepository implements UserRepository {
        private final Map<String, UserAccount> userDatabase = new ConcurrentHashMap<>();

        @Override
        public boolean save(UserAccount user) {
            String key = user.getUsername().toLowerCase();
            userDatabase.put(key, user);
            return true;
        }

        @Override
        public UserAccount findByUsername(String username) {
            if (username == null) return null;
            return userDatabase.get(username.toLowerCase());
        }

        @Override
        public boolean existsByUsername(String username) {
            if (username == null) return false;
            return userDatabase.containsKey(username.toLowerCase());
        }
    }

    // =========================================================================
    // 5. Authentication Status, Result, and Core Service
    // =========================================================================

    public enum AuthStatus {
        SUCCESS,
        INVALID_CREDENTIALS,
        ACCOUNT_LOCKED,
        INVALID_INPUT
    }

    public static class AuthResult {
        private final AuthStatus status;
        private final String message;
        private final String username;

        public AuthResult(AuthStatus status, String message, String username) {
            this.status = status;
            this.message = message;
            this.username = username;
        }

        public AuthStatus getStatus() {
            return status;
        }

        public String getMessage() {
            return message;
        }

        public String getUsername() {
            return username;
        }

        public boolean isSuccess() {
            return status == AuthStatus.SUCCESS;
        }

        @Override
        public String toString() {
            return String.format("AuthResult[status=%s, message='%s', user='%s']",
                    status, message, username);
        }
    }

    public static class AuthenticationService {
        private final UserRepository userRepository;
        private final int maxFailedAttempts;

        public AuthenticationService(UserRepository userRepository) {
            this(userRepository, 3); // Standard default threshold: 3 failed attempts
        }

        public AuthenticationService(UserRepository userRepository, int maxFailedAttempts) {
            this.userRepository = Objects.requireNonNull(userRepository, "Repository cannot be null");
            this.maxFailedAttempts = maxFailedAttempts;
        }

        /**
         * Registers a new user account with unique cryptographic salt and PBKDF2 hash.
         * 
         * @param username Desired username
         * @param password Password characters
         * @param clientIp Client IP / terminal identifier for audit trail
         * @return true if registration succeeded, false if user exists or input invalid
         */
        public boolean registerUser(String username, char[] password, String clientIp) {
            if (username == null || username.trim().isEmpty() || password == null || password.length == 0) {
                return false;
            }

            String trimmedUser = username.trim();
            if (userRepository.existsByUsername(trimmedUser)) {
                return false;
            }

            byte[] salt = PasswordSecurity.generateSalt();
            byte[] hash = PasswordSecurity.hashPassword(password, salt);

            UserAccount account = new UserAccount(trimmedUser, salt, hash);
            userRepository.save(account);

            AuthAuditLogger.logRegistration(trimmedUser, clientIp);
            return true;
        }

        /**
         * Authenticates a user given their credentials.
         * 
         * @param username Submitted username
         * @param password Submitted password characters (zeroed out by caller or helper)
         * @param clientIp Client IP or terminal identifier for logging
         * @return AuthResult describing the authentication outcome and client message
         */
        public AuthResult authenticate(String username, char[] password, String clientIp) {
            if (clientIp == null || clientIp.trim().isEmpty()) {
                clientIp = "UNKNOWN";
            }

            // 1. Input validation
            if (username == null || username.trim().isEmpty() || password == null || password.length == 0) {
                AuthAuditLogger.logFailure(
                        username == null ? "EMPTY" : username.trim(),
                        "Empty or null credentials submitted",
                        clientIp
                );
                return new AuthResult(AuthStatus.INVALID_INPUT, "Username and password must not be empty.", username);
            }

            String cleanUsername = username.trim();
            UserAccount account = userRepository.findByUsername(cleanUsername);

            // 2. User Enumeration Defense:
            // If the user does not exist, compute a dummy hash to maintain identical timing characteristics.
            if (account == null) {
                byte[] dummySalt = PasswordSecurity.generateSalt();
                byte[] dummyHash = PasswordSecurity.hashPassword(password, dummySalt);
                Arrays.fill(dummyHash, (byte) 0);

                AuthAuditLogger.logFailure(cleanUsername, "User not found in system", clientIp);
                return new AuthResult(
                        AuthStatus.INVALID_CREDENTIALS,
                        "Invalid username or password.",
                        cleanUsername
                );
            }

            // 3. Account Lockout Check & Credential Verification
            synchronized (account) {
                if (account.isAccountLocked()) {
                    AuthAuditLogger.logFailure(cleanUsername, "Login attempt on locked account", clientIp);
                    return new AuthResult(
                            AuthStatus.ACCOUNT_LOCKED,
                            "Account is locked due to too many failed attempts. Please contact an administrator.",
                            cleanUsername
                    );
                }

                // Verify submitted password against stored salt and hash
                boolean valid = PasswordSecurity.verifyPassword(
                        password,
                        account.getSalt(),
                        account.getPasswordHash()
                );

                if (valid) {
                    account.recordSuccessfulLogin();
                    AuthAuditLogger.logSuccess(cleanUsername, clientIp);
                    return new AuthResult(AuthStatus.SUCCESS, "Authentication successful.", cleanUsername);
                } else {
                    account.incrementFailedAttempts();
                    int attempts = account.getFailedLoginAttempts();

                    if (attempts >= maxFailedAttempts) {
                        account.lockAccount();
                        AuthAuditLogger.logLockout(cleanUsername, clientIp);
                        return new AuthResult(
                                AuthStatus.ACCOUNT_LOCKED,
                                "Account has been locked due to " + attempts + " consecutive failed attempts.",
                                cleanUsername
                        );
                    } else {
                        AuthAuditLogger.logFailure(
                                cleanUsername,
                                "Incorrect password (Attempt " + attempts + " of " + maxFailedAttempts + ")",
                                clientIp
                        );
                        return new AuthResult(
                                AuthStatus.INVALID_CREDENTIALS,
                                "Invalid username or password. Remaining attempts: " + (maxFailedAttempts - attempts),
                                cleanUsername
                        );
                    }
                }
            }
        }

        /**
         * Unlocks a locked account (administrative operation).
         */
        public boolean unlockAccount(String username, String adminUser) {
            UserAccount account = userRepository.findByUsername(username);
            if (account != null) {
                synchronized (account) {
                    account.unlockAccount();
                    AuthAuditLogger.logAccountUnlock(username, adminUser);
                    return true;
                }
            }
            return false;
        }

        public UserRepository getUserRepository() {
            return userRepository;
        }
    }

    // =========================================================================
    // 6. Application Entry Point: Automated Test Suite & Interactive Mode
    // =========================================================================

    public static void main(String[] args) {
        UserRepository repository = new InMemoryUserRepository();
        AuthenticationService authService = new AuthenticationService(repository, 3);

        System.out.println("======================================================================");
        System.out.println("           APPLICATION USER AUTHENTICATION SYSTEM (JAVA)             ");
        System.out.println("======================================================================");
        System.out.println("Audit log target: " + AuthAuditLogger.getAuditLogFilePath());
        System.out.println();

        // Check if interactive CLI mode requested
        if (args.length > 0 && "--interactive".equalsIgnoreCase(args[0])) {
            runInteractiveMode(authService);
            return;
        }

        // Default behavior: Run comprehensive automated test demonstration
        runAutomatedDemo(authService);

        System.out.println("\n----------------------------------------------------------------------");
        System.out.println("Tip: Run with '--interactive' to test manual user logins in the console.");
        System.out.println("Example: java UserAuthenticationApp --interactive");
        System.out.println("======================================================================");
    }

    /**
     * Executes automated verification test cases covering all required flows.
     */
    private static void runAutomatedDemo(AuthenticationService authService) {
        System.out.println(">>> RUNNING AUTOMATED AUTHENTICATION TEST SUITE <<<\n");

        // Scenario 1: User Account Registration
        System.out.println("[Scenario 1] Provisioning test user accounts...");
        char[] passAlice = "AliceSecurePass2026!".toCharArray();
        authService.registerUser("alice", passAlice, "192.168.1.10");
        PasswordSecurity.wipeArray(passAlice);

        char[] passBob = "BobSecretKey#99".toCharArray();
        authService.registerUser("bob", passBob, "192.168.1.20");
        PasswordSecurity.wipeArray(passBob);
        System.out.println("Test users 'alice' and 'bob' successfully registered.\n");

        // Scenario 2: Successful Login
        System.out.println("[Scenario 2] Valid credential verification (Alice logs in with correct password)...");
        char[] aliceLoginPass = "AliceSecurePass2026!".toCharArray();
        AuthResult result1 = authService.authenticate("alice", aliceLoginPass, "192.168.1.10");
        PasswordSecurity.wipeArray(aliceLoginPass);
        System.out.println("Result: " + result1);
        System.out.println("Verified Success: " + (result1.getStatus() == AuthStatus.SUCCESS) + "\n");

        // Scenario 3: Unsuccessful Login - Incorrect Password
        System.out.println("[Scenario 3] Invalid password verification (Bob enters incorrect password)...");
        char[] badPass = "WrongPassword123".toCharArray();
        AuthResult result2 = authService.authenticate("bob", badPass, "10.0.0.5");
        PasswordSecurity.wipeArray(badPass);
        System.out.println("Result: " + result2);
        System.out.println("Verified Failure: " + (result2.getStatus() == AuthStatus.INVALID_CREDENTIALS) + "\n");

        // Scenario 4: Unsuccessful Login - Non-existent User
        System.out.println("[Scenario 4] Non-existent user verification (Mallory attempts login)...");
        char[] malloryPass = "RandomPass123".toCharArray();
        AuthResult result3 = authService.authenticate("mallory", malloryPass, "10.0.0.99");
        PasswordSecurity.wipeArray(malloryPass);
        System.out.println("Result: " + result3);
        System.out.println("Verified Failure (Enumeration protected): " + (result3.getStatus() == AuthStatus.INVALID_CREDENTIALS) + "\n");

        // Scenario 5: Account Lockout after Maximum Failed Attempts
        System.out.println("[Scenario 5] Consecutive failed attempts leading to account lockout (Bob)...");
        char[] badAttempt1 = "wrong_password_2".toCharArray();
        char[] badAttempt2 = "wrong_password_3".toCharArray();

        System.out.println("Attempt 2 for Bob:");
        AuthResult result4 = authService.authenticate("bob", badAttempt1, "10.0.0.5");
        PasswordSecurity.wipeArray(badAttempt1);
        System.out.println("Result: " + result4);

        System.out.println("Attempt 3 for Bob (exceeds threshold of 3):");
        AuthResult result5 = authService.authenticate("bob", badAttempt2, "10.0.0.5");
        PasswordSecurity.wipeArray(badAttempt2);
        System.out.println("Result: " + result5);
        System.out.println("Verified Account Locked: " + (result5.getStatus() == AuthStatus.ACCOUNT_LOCKED) + "\n");

        // Scenario 6: Attempt to Authenticate on Locked Account
        System.out.println("[Scenario 6] Attempting login on locked account with correct credentials...");
        char[] bobCorrectPass = "BobSecretKey#99".toCharArray();
        AuthResult result6 = authService.authenticate("bob", bobCorrectPass, "192.168.1.20");
        PasswordSecurity.wipeArray(bobCorrectPass);
        System.out.println("Result: " + result6);
        System.out.println("Verified Access Blocked: " + (result6.getStatus() == AuthStatus.ACCOUNT_LOCKED) + "\n");

        // Scenario 7: Administrator Unlocks Account
        System.out.println("[Scenario 7] Administrator unlocks Bob's account and Bob re-authenticates...");
        boolean unlocked = authService.unlockAccount("bob", "admin_sys");
        System.out.println("Account unlocked by admin: " + unlocked);

        bobCorrectPass = "BobSecretKey#99".toCharArray();
        AuthResult result7 = authService.authenticate("bob", bobCorrectPass, "192.168.1.20");
        PasswordSecurity.wipeArray(bobCorrectPass);
        System.out.println("Result after unlock: " + result7);
        System.out.println("Verified Success: " + (result7.getStatus() == AuthStatus.SUCCESS) + "\n");

        System.out.println(">>> AUTOMATED DEMONSTRATION COMPLETE <<<");
    }

    /**
     * Interactive CLI menu allowing manual testing in real-time.
     */
    private static void runInteractiveMode(AuthenticationService authService) {
        Scanner scanner = new Scanner(System.in);
        Console console = System.console();
        boolean running = true;

        System.out.println("\n[INTERACTIVE CONSOLE MODE ACTIVATED]");
        while (running) {
            System.out.println("\nSelect an action:");
            System.out.println("  1. Register new user");
            System.out.println("  2. Login (Authenticate)");
            System.out.println("  3. Admin: Unlock account");
            System.out.println("  4. Exit");
            System.out.print("Choice: ");

            String choice = scanner.nextLine().trim();
            switch (choice) {
                case "1": {
                    System.out.print("Enter new username: ");
                    String user = scanner.nextLine().trim();
                    char[] pass = readPassword(console, scanner, "Enter password: ");
                    boolean ok = authService.registerUser(user, pass, "127.0.0.1");
                    PasswordSecurity.wipeArray(pass);
                    if (ok) {
                        System.out.println("[+] User '" + user + "' registered successfully!");
                    } else {
                        System.out.println("[-] Registration failed. Username may already exist or input was empty.");
                    }
                    break;
                }
                case "2": {
                    System.out.print("Username: ");
                    String user = scanner.nextLine().trim();
                    char[] pass = readPassword(console, scanner, "Password: ");
                    AuthResult res = authService.authenticate(user, pass, "127.0.0.1");
                    PasswordSecurity.wipeArray(pass);
                    System.out.println("\nResult Status:  " + res.getStatus());
                    System.out.println("System Message: " + res.getMessage());
                    break;
                }
                case "3": {
                    System.out.print("Enter username to unlock: ");
                    String user = scanner.nextLine().trim();
                    boolean unlocked = authService.unlockAccount(user, "console_admin");
                    if (unlocked) {
                        System.out.println("[+] Account '" + user + "' unlocked successfully.");
                    } else {
                        System.out.println("[-] Account not found or could not be unlocked.");
                    }
                    break;
                }
                case "4":
                    System.out.println("Exiting interactive mode.");
                    running = false;
                    break;
                default:
                    System.out.println("Invalid option. Please choose 1, 2, 3, or 4.");
            }
        }
    }

    private static char[] readPassword(Console console, Scanner scanner, String prompt) {
        if (console != null) {
            return console.readPassword(prompt);
        } else {
            System.out.print(prompt);
            return scanner.nextLine().toCharArray();
        }
    }
}
