import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.Console;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ============================================================================
 * Internal Employee Portal - Secure Authentication Module
 * ============================================================================
 *
 * Core Security Capabilities:
 *  1. Credential Verification:
 *     - Authenticates employee usernames and passwords against a record store.
 *     - Salted password hashing using PBKDF2 with HMAC-SHA256 (100,000 iterations).
 *     - Cryptographically secure random 128-bit salt per account.
 *     - Constant-time comparison (MessageDigest.isEqual) against timing attacks (CWE-208).
 *     - Uniform response timing for non-existent users via dummy PBKDF2 hash (CWE-204).
 *     - Explicit memory scrubbing of sensitive password buffers (char[] and byte[]).
 *
 *  2. Brute-Force & Consecutive Attempt Protection (CWE-307):
 *     - Enforces account lockout after exceeding consecutive failed login attempts (default: 5).
 *     - While locked, all subsequent authentication attempts are rejected (even with correct password).
 *     - Automatic unlocking after configured lockout duration (default: 15 minutes), or via admin unlock.
 *     - Successful authentication immediately resets the failed attempts counter.
 *
 *  3. Audit Logging:
 *     - Comprehensive security audit log for logins, failed attempts, lockouts, and unlocks.
 *     - Sensitive data (passwords, raw hashes) are never written to logs.
 *
 *  4. Portable Execution:
 *     - Self-contained in standard Java 17 (no external dependencies required).
 *     - Supports interactive CLI, programmatic API, and automated test suite (`--test`).
 */
public class EmployeeAuthenticationPortal {

    // ========================================================================
    // 1. ENUMS & DATA MODELS
    // ========================================================================

    /**
     * Operational account statuses for employees.
     */
    public enum AccountStatus {
        ACTIVE,
        LOCKED
    }

    /**
     * Authentication result status codes.
     */
    public enum AuthStatus {
        SUCCESS,
        INVALID_CREDENTIALS,
        ACCOUNT_LOCKED
    }

    /**
     * Represents an employee record held within the records store.
     */
    public static class EmployeeRecord {
        private final String employeeId;
        private final String username;
        private final String fullName;
        private final String department;
        private final String role;

        // Security credentials
        private String passwordHashBase64;
        private byte[] salt;
        private int iterations;

        // Security state & lockout tracking
        private AccountStatus status;
        private int failedAttempts;
        private Instant lockedUntil;
        private Instant lastLoginAt;
        private final Instant createdAt;

        public EmployeeRecord(String employeeId, String username, String fullName,
                              String department, String role, String passwordHashBase64,
                              byte[] salt, int iterations, AccountStatus status) {
            this.employeeId = Objects.requireNonNull(employeeId, "employeeId cannot be null");
            this.username = Objects.requireNonNull(username, "username cannot be null").trim().toLowerCase();
            this.fullName = Objects.requireNonNull(fullName, "fullName cannot be null");
            this.department = Objects.requireNonNull(department, "department cannot be null");
            this.role = Objects.requireNonNull(role, "role cannot be null");
            this.passwordHashBase64 = Objects.requireNonNull(passwordHashBase64, "passwordHashBase64 cannot be null");
            this.salt = Objects.requireNonNull(salt, "salt cannot be null").clone();
            this.iterations = iterations > 0 ? iterations : PasswordSecurity.DEFAULT_ITERATIONS;
            this.status = status != null ? status : AccountStatus.ACTIVE;
            this.failedAttempts = 0;
            this.lockedUntil = null;
            this.lastLoginAt = null;
            this.createdAt = Instant.now();
        }

        // Getters
        public String getEmployeeId() { return employeeId; }
        public String getUsername() { return username; }
        public String getFullName() { return fullName; }
        public String getDepartment() { return department; }
        public String getRole() { return role; }
        public String getPasswordHashBase64() { return passwordHashBase64; }
        public byte[] getSalt() { return salt.clone(); }
        public int getIterations() { return iterations; }
        public synchronized AccountStatus getStatus() { return status; }
        public synchronized int getFailedAttempts() { return failedAttempts; }
        public synchronized Instant getLockedUntil() { return lockedUntil; }
        public synchronized Instant getLastLoginAt() { return lastLoginAt; }
        public Instant getCreatedAt() { return createdAt; }

        /**
         * Determines whether the account is currently locked.
         * Automatically transitions back to ACTIVE if temporary lockout duration has passed.
         */
        public synchronized boolean isLocked(Instant now) {
            if (status != AccountStatus.LOCKED) {
                return false;
            }
            if (lockedUntil != null && now.isAfter(lockedUntil)) {
                // Lockout window expired; automatically re-activate account
                this.status = AccountStatus.ACTIVE;
                this.failedAttempts = 0;
                this.lockedUntil = null;
                return false;
            }
            return true;
        }

        /**
         * Records a failed login attempt and locks account if threshold is reached.
         */
        public synchronized boolean recordFailedAttempt(int maxAttempts, Duration lockoutDuration, Instant now) {
            this.failedAttempts++;
            if (this.failedAttempts >= maxAttempts) {
                this.status = AccountStatus.LOCKED;
                this.lockedUntil = (lockoutDuration != null) ? now.plus(lockoutDuration) : null;
                return true; // Newly locked
            }
            return false;
        }

        /**
         * Resets the failed attempts counter upon successful login.
         */
        public synchronized void recordSuccessfulLogin(Instant now) {
            this.status = AccountStatus.ACTIVE;
            this.failedAttempts = 0;
            this.lockedUntil = null;
            this.lastLoginAt = now;
        }

        /**
         * Administratively unlocks the account and resets failed attempts.
         */
        public synchronized void unlock() {
            this.status = AccountStatus.ACTIVE;
            this.failedAttempts = 0;
            this.lockedUntil = null;
        }

        @Override
        public String toString() {
            return String.format("EmployeeRecord[id=%s, user=%s, name='%s', dept='%s', role='%s', status=%s, failed=%d]",
                    employeeId, username, fullName, department, role, status, failedAttempts);
        }
    }

    /**
     * Authenticated employee portal session.
     */
    public static class PortalSession {
        private final String sessionId;
        private final String username;
        private final String employeeId;
        private final String fullName;
        private final String role;
        private final Instant loginTime;
        private final Instant expiresAt;

        public PortalSession(EmployeeRecord employee, Duration sessionDuration) {
            this.sessionId = UUID.randomUUID().toString();
            this.username = employee.getUsername();
            this.employeeId = employee.getEmployeeId();
            this.fullName = employee.getFullName();
            this.role = employee.getRole();
            this.loginTime = Instant.now();
            this.expiresAt = this.loginTime.plus(sessionDuration);
        }

        public String getSessionId() { return sessionId; }
        public String getUsername() { return username; }
        public String getEmployeeId() { return employeeId; }
        public String getFullName() { return fullName; }
        public String getRole() { return role; }
        public Instant getLoginTime() { return loginTime; }
        public Instant getExpiresAt() { return expiresAt; }
        public boolean isExpired() { return Instant.now().isAfter(expiresAt); }
    }

    /**
     * Result of an authentication request.
     */
    public static class AuthenticationResult {
        private final boolean success;
        private final AuthStatus status;
        private final String message;
        private final EmployeeRecord employee;
        private final PortalSession session;
        private final int remainingAttempts;

        private AuthenticationResult(boolean success, AuthStatus status, String message,
                                     EmployeeRecord employee, PortalSession session, int remainingAttempts) {
            this.success = success;
            this.status = status;
            this.message = message;
            this.employee = employee;
            this.session = session;
            this.remainingAttempts = remainingAttempts;
        }

        public static AuthenticationResult granted(EmployeeRecord employee, PortalSession session) {
            return new AuthenticationResult(true, AuthStatus.SUCCESS,
                    "Access granted. Welcome to the portal, " + employee.getFullName() + ".",
                    employee, session, -1);
        }

        public static AuthenticationResult denied(AuthStatus status, String message, int remainingAttempts) {
            return new AuthenticationResult(false, status, message, null, null, remainingAttempts);
        }

        public boolean isSuccess() { return success; }
        public AuthStatus getStatus() { return status; }
        public String getMessage() { return message; }
        public EmployeeRecord getEmployee() { return employee; }
        public PortalSession getSession() { return session; }
        public int getRemainingAttempts() { return remainingAttempts; }
    }

    // ========================================================================
    // 2. CRYPTOGRAPHIC UTILITIES (PBKDF2-HMAC-SHA256)
    // ========================================================================

    /**
     * Industry-standard password hashing, salt generation, constant-time validation,
     * and memory wiping per NIST SP 800-63B and OWASP guidelines.
     */
    public static class PasswordSecurity {
        public static final String ALGORITHM = "PBKDF2WithHmacSHA256";
        public static final int DEFAULT_ITERATIONS = 100_000;
        public static final int KEY_LENGTH_BITS = 256;
        public static final int SALT_LENGTH_BYTES = 16; // 128-bit salt

        private static final SecureRandom SECURE_RANDOM = new SecureRandom();

        // Pre-computed dummy salt for uniform timing comparison against non-existent accounts
        private static final byte[] DUMMY_SALT = new byte[SALT_LENGTH_BYTES];
        static {
            SECURE_RANDOM.nextBytes(DUMMY_SALT);
        }

        /**
         * Generates a cryptographically strong random salt.
         */
        public static byte[] generateSalt() {
            byte[] salt = new byte[SALT_LENGTH_BYTES];
            SECURE_RANDOM.nextBytes(salt);
            return salt;
        }

        /**
         * Computes PBKDF2 hash for a password using the specified salt and iteration count.
         */
        public static byte[] hashPasswordRaw(char[] password, byte[] salt, int iterations) {
            try {
                KeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_LENGTH_BITS);
                SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
                return factory.generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new SecurityException("Cryptographic algorithm error during password hashing: " + e.getMessage(), e);
            }
        }

        /**
         * Hashes password and returns Base64-encoded string representation.
         */
        public static String hashPassword(char[] password, byte[] salt, int iterations) {
            byte[] hash = hashPasswordRaw(password, salt, iterations);
            try {
                return Base64.getEncoder().encodeToString(hash);
            } finally {
                wipe(hash);
            }
        }

        /**
         * Verifies a password against stored Base64 salt and hash using constant-time comparison.
         * Mitigates CWE-208 (Observable Timing Discrepancy).
         */
        public static boolean verifyPassword(char[] password, byte[] salt,
                                             String storedHashBase64, int iterations) {
            if (password == null || salt == null || storedHashBase64 == null) {
                return false;
            }

            byte[] expectedHash = null;
            byte[] computedHash = null;
            try {
                expectedHash = Base64.getDecoder().decode(storedHashBase64);
                computedHash = hashPasswordRaw(password, salt, iterations);

                // Constant-time array comparison prevents timing side-channel attacks
                return MessageDigest.isEqual(expectedHash, computedHash);
            } catch (IllegalArgumentException e) {
                return false;
            } finally {
                if (expectedHash != null) wipe(expectedHash);
                if (computedHash != null) wipe(computedHash);
            }
        }

        /**
         * Performs a dummy PBKDF2 calculation to normalize response times when a requested
         * username does not exist in the record store. This defeats timing-based user enumeration (CWE-204).
         */
        public static void performDummyHash(char[] password) {
            byte[] dummy = null;
            try {
                dummy = hashPasswordRaw(password, DUMMY_SALT, DEFAULT_ITERATIONS);
            } catch (Exception ignored) {
            } finally {
                if (dummy != null) wipe(dummy);
            }
        }

        /**
         * Overwrites sensitive char array in memory with null characters.
         */
        public static void wipe(char[] array) {
            if (array != null) {
                Arrays.fill(array, '\0');
            }
        }

        /**
         * Overwrites sensitive byte array in memory with zeros.
         */
        public static void wipe(byte[] array) {
            if (array != null) {
                Arrays.fill(array, (byte) 0);
            }
        }
    }

    // ========================================================================
    // 3. AUDIT LOGGER
    // ========================================================================

    /**
     * Security audit logger recording authentication events for compliance and intrusion detection.
     */
    public static class AuditLogger {
        private static final DateTimeFormatter FORMATTER =
                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

        private final List<String> memoryLog = Collections.synchronizedList(new ArrayList<>());
        private final boolean echoToConsole;

        public AuditLogger(boolean echoToConsole) {
            this.echoToConsole = echoToConsole;
        }

        public synchronized void log(String eventType, String username, boolean success, String details) {
            String timestamp = FORMATTER.format(Instant.now());
            String sanitizedUser = (username != null && !username.isBlank())
                    ? username.replaceAll("[\\r\\n]", "")
                    : "ANONYMOUS";
            String sanitizedDetails = (details != null)
                    ? details.replaceAll("[\\r\\n]", " ")
                    : "";

            String entry = String.format("[%s] [AUDIT] [%-16s] User: %-15s Result: %-7s Details: %s",
                    timestamp, eventType, sanitizedUser, success ? "SUCCESS" : "FAILURE", sanitizedDetails);

            memoryLog.add(entry);
            if (echoToConsole) {
                System.out.println(entry);
            }
        }

        public List<String> getRecentEntries(int count) {
            synchronized (memoryLog) {
                int size = memoryLog.size();
                int from = Math.max(0, size - count);
                return new ArrayList<>(memoryLog.subList(from, size));
            }
        }
    }

    // ========================================================================
    // 4. EMPLOYEE RECORDS STORE
    // ========================================================================

    /**
     * Contract defining storage operations for employee credential records.
     */
    public interface EmployeeRecordStore {
        Optional<EmployeeRecord> findByUsername(String username);
        void save(EmployeeRecord record);
        boolean unlockAccount(String username);
        List<EmployeeRecord> getAllEmployees();
    }

    /**
     * Thread-safe in-memory employee record store pre-populated with standard accounts.
     */
    public static class InMemoryEmployeeRecordStore implements EmployeeRecordStore {
        private final Map<String, EmployeeRecord> records = new ConcurrentHashMap<>();

        public InMemoryEmployeeRecordStore() {
            seedDefaultRecords();
        }

        private void seedDefaultRecords() {
            register("EMP-1001", "sarah.connor", "Sarah Connor", "Cybersecurity Operations",
                    "SECURITY_LEAD", "CyberGuard#2026!");
            register("EMP-1002", "alex.chen", "Alex Chen", "Software Engineering",
                    "DEVELOPER", "CodeCraft$9876");
            register("EMP-1003", "maria.rodriguez", "Maria Rodriguez", "Human Resources",
                    "HR_SPECIALIST", "HR_Portal#4321");
            register("EMP-0001", "admin", "System Administrator", "IT Infrastructure",
                    "ADMIN", "PortalAdmin@2026!");
        }

        public void register(String empId, String username, String fullName,
                             String dept, String role, String plainPassword) {
            char[] pass = plainPassword.toCharArray();
            byte[] salt = PasswordSecurity.generateSalt();
            String hash = PasswordSecurity.hashPassword(pass, salt, PasswordSecurity.DEFAULT_ITERATIONS);
            PasswordSecurity.wipe(pass);

            EmployeeRecord record = new EmployeeRecord(
                    empId, username, fullName, dept, role, hash, salt,
                    PasswordSecurity.DEFAULT_ITERATIONS, AccountStatus.ACTIVE
            );
            records.put(record.getUsername(), record);
        }

        @Override
        public Optional<EmployeeRecord> findByUsername(String username) {
            if (username == null) return Optional.empty();
            return Optional.ofNullable(records.get(username.trim().toLowerCase()));
        }

        @Override
        public void save(EmployeeRecord record) {
            Objects.requireNonNull(record, "record cannot be null");
            records.put(record.getUsername(), record);
        }

        @Override
        public boolean unlockAccount(String username) {
            if (username == null) return false;
            EmployeeRecord record = records.get(username.trim().toLowerCase());
            if (record != null) {
                record.unlock();
                return true;
            }
            return false;
        }

        @Override
        public List<EmployeeRecord> getAllEmployees() {
            return new ArrayList<>(records.values());
        }
    }

    // ========================================================================
    // 5. AUTHENTICATION SERVICE (CORE BUSINESS LOGIC & RATE LIMITING)
    // ========================================================================

    /**
     * Core authentication service enforcing:
     *  - Credential verification against the record store.
     *  - Prevention of password guessing by locking accounts after consecutive failed attempts.
     *  - Timing attack defense via constant-time verification & uniform dummy calculation.
     *  - Session generation upon successful authentication.
     */
    public static class AuthenticationService {

        public static final int DEFAULT_MAX_CONSECUTIVE_ATTEMPTS = 5;
        public static final Duration DEFAULT_LOCKOUT_DURATION = Duration.ofMinutes(15);
        public static final Duration DEFAULT_SESSION_DURATION = Duration.ofHours(8);

        private final EmployeeRecordStore recordStore;
        private final AuditLogger auditLogger;
        private final int maxConsecutiveAttempts;
        private final Duration lockoutDuration;
        private final Duration sessionDuration;

        public AuthenticationService(EmployeeRecordStore recordStore, AuditLogger auditLogger) {
            this(recordStore, auditLogger, DEFAULT_MAX_CONSECUTIVE_ATTEMPTS, DEFAULT_LOCKOUT_DURATION, DEFAULT_SESSION_DURATION);
        }

        public AuthenticationService(EmployeeRecordStore recordStore, AuditLogger auditLogger,
                                     int maxConsecutiveAttempts, Duration lockoutDuration, Duration sessionDuration) {
            this.recordStore = Objects.requireNonNull(recordStore, "recordStore cannot be null");
            this.auditLogger = auditLogger;
            this.maxConsecutiveAttempts = Math.max(1, maxConsecutiveAttempts);
            this.lockoutDuration = lockoutDuration;
            this.sessionDuration = (sessionDuration != null) ? sessionDuration : DEFAULT_SESSION_DURATION;
        }

        /**
         * Authenticates an employee using their username and password.
         *
         * @param username The entered username (case-insensitive)
         * @param password The entered password as a char array (cleared immediately after use)
         * @return AuthenticationResult indicating success or denial
         */
        public AuthenticationResult authenticate(String username, char[] password) {
            Instant now = Instant.now();

            // 1. Validate inputs
            if (username == null || username.trim().isEmpty() || password == null || password.length == 0) {
                if (auditLogger != null) {
                    auditLogger.log("LOGIN_DENIED", username, false, "Missing username or password");
                }
                PasswordSecurity.wipe(password);
                return AuthenticationResult.denied(AuthStatus.INVALID_CREDENTIALS,
                        "Access denied: Username and password are required.", -1);
            }

            String normalizedUser = username.trim().toLowerCase();

            try {
                // 2. Query record store
                Optional<EmployeeRecord> optRecord = recordStore.findByUsername(normalizedUser);

                // 3. User enumeration defense:
                // If user does NOT exist, execute dummy PBKDF2 hash computation
                if (optRecord.isEmpty()) {
                    PasswordSecurity.performDummyHash(password);
                    if (auditLogger != null) {
                        auditLogger.log("LOGIN_FAILED", normalizedUser, false, "Username not found in records store");
                    }
                    // Generic error message to prevent account enumeration (CWE-204)
                    return AuthenticationResult.denied(AuthStatus.INVALID_CREDENTIALS,
                            "Access denied: Invalid username or password.", -1);
                }

                EmployeeRecord record = optRecord.get();

                // 4. Check if account is currently locked
                if (record.isLocked(now)) {
                    String lockMessage = "Access denied: Account is locked due to consecutive failed login attempts.";
                    if (record.getLockedUntil() != null) {
                        long minutesLeft = Math.max(1, Duration.between(now, record.getLockedUntil()).toMinutes() + 1);
                        lockMessage += " Please try again in ~" + minutesLeft + " minute(s) or contact your administrator.";
                    } else {
                        lockMessage += " Please contact your system administrator to unlock your account.";
                    }

                    if (auditLogger != null) {
                        auditLogger.log("LOGIN_BLOCKED", normalizedUser, false,
                                "Account is currently LOCKED; authentication blocked.");
                    }
                    return AuthenticationResult.denied(AuthStatus.ACCOUNT_LOCKED, lockMessage, 0);
                }

                // 5. Verify password hash using constant-time comparison
                boolean passwordValid = PasswordSecurity.verifyPassword(
                        password,
                        record.getSalt(),
                        record.getPasswordHashBase64(),
                        record.getIterations()
                );

                // 6. Handle credential mismatch
                if (!passwordValid) {
                    Instant failTime = Instant.now();
                    boolean newlyLocked = record.recordFailedAttempt(maxConsecutiveAttempts, lockoutDuration, failTime);

                    if (newlyLocked) {
                        if (auditLogger != null) {
                            auditLogger.log("ACCOUNT_LOCKED", normalizedUser, false,
                                    "Account locked after reaching " + maxConsecutiveAttempts + " consecutive failed attempts");
                        }
                        return AuthenticationResult.denied(AuthStatus.ACCOUNT_LOCKED,
                                "Access denied: Account has been locked due to " + maxConsecutiveAttempts +
                                " consecutive failed attempts. Contact system administration.", 0);
                    } else {
                        int remaining = maxConsecutiveAttempts - record.getFailedAttempts();
                        if (auditLogger != null) {
                            auditLogger.log("LOGIN_FAILED", normalizedUser, false,
                                    "Incorrect password. Failed attempt " + record.getFailedAttempts() +
                                    " of " + maxConsecutiveAttempts + " (" + remaining + " remaining)");
                        }
                        return AuthenticationResult.denied(AuthStatus.INVALID_CREDENTIALS,
                                "Access denied: Invalid username or password. Remaining attempts before lockout: " + remaining,
                                remaining);
                    }
                }

                // 7. Successful authentication
                record.recordSuccessfulLogin(now);
                PortalSession session = new PortalSession(record, sessionDuration);

                if (auditLogger != null) {
                    auditLogger.log("LOGIN_SUCCESS", normalizedUser, true,
                            "Access granted for " + record.getFullName() + " (" + record.getRole() + ")");
                }

                return AuthenticationResult.granted(record, session);

            } finally {
                // Ensure sensitive password characters are zeroed out from memory
                PasswordSecurity.wipe(password);
            }
        }

        /**
         * Convenience wrapper for string passwords.
         */
        public AuthenticationResult authenticate(String username, String password) {
            char[] chars = (password != null) ? password.toCharArray() : new char[0];
            return authenticate(username, chars);
        }

        /**
         * Administratively unlocks an employee account.
         */
        public boolean unlockAccount(String adminUsername, String targetUsername) {
            Optional<EmployeeRecord> adminOpt = recordStore.findByUsername(adminUsername);
            if (adminOpt.isEmpty() || !"ADMIN".equalsIgnoreCase(adminOpt.get().getRole())) {
                if (auditLogger != null) {
                    auditLogger.log("UNLOCK_DENIED", adminUsername, false,
                            "Unauthorized attempt to unlock user '" + targetUsername + "'");
                }
                return false;
            }

            boolean unlocked = recordStore.unlockAccount(targetUsername);
            if (unlocked && auditLogger != null) {
                auditLogger.log("ACCOUNT_UNLOCKED", targetUsername, true,
                        "Account unlocked by administrator: " + adminUsername);
            }
            return unlocked;
        }

        public EmployeeRecordStore getRecordStore() { return recordStore; }
        public AuditLogger getAuditLogger() { return auditLogger; }
        public int getMaxConsecutiveAttempts() { return maxConsecutiveAttempts; }
        public Duration getLockoutDuration() { return lockoutDuration; }
    }

    // ========================================================================
    // 6. INTERACTIVE CONSOLE UI
    // ========================================================================

    /**
     * Interactive terminal interface for employee portal access.
     */
    public static class PortalUI {
        private final AuthenticationService authService;
        private final Scanner scanner;
        private final Console console;

        public PortalUI(AuthenticationService authService) {
            this.authService = authService;
            this.scanner = new Scanner(System.in);
            this.console = System.console();
        }

        private String readLine() {
            return scanner.hasNextLine() ? scanner.nextLine() : null;
        }

        public void run() {
            printBanner();
            boolean running = true;
            while (running) {
                System.out.println("\n========================================================");
                System.out.println("              PORTAL NAVIGATION MENU                    ");
                System.out.println("========================================================");
                System.out.println(" 1. Employee Login");
                System.out.println(" 2. View Configured Test Accounts");
                System.out.println(" 3. Admin: Unlock Locked Account");
                System.out.println(" 4. Run Automated Security Test Suite");
                System.out.println(" 5. View Recent Audit Logs");
                System.out.println(" 6. Exit");
                System.out.print("Select an option (1-6): ");

                String choice = readLine();
                if (choice == null) break;

                switch (choice.trim()) {
                    case "1" -> handleLoginPrompt();
                    case "2" -> displayTestAccounts();
                    case "3" -> handleAdminUnlock();
                    case "4" -> SelfTestRunner.runAllTests(authService);
                    case "5" -> displayAuditLogs();
                    case "6" -> {
                        System.out.println("\nExiting Internal Employee Portal. Goodbye!");
                        running = false;
                    }
                    default -> System.out.println("[!] Invalid choice. Please select an option from 1 to 6.");
                }
            }
        }

        private void handleLoginPrompt() {
            System.out.println("\n--------------------------------------------------------");
            System.out.println("                 EMPLOYEE LOGIN                         ");
            System.out.println("--------------------------------------------------------");
            System.out.print("Username: ");
            String username = readLine();
            if (username == null || username.trim().isEmpty()) {
                System.out.println("[!] Username cannot be empty.");
                return;
            }

            char[] password;
            if (console != null) {
                password = console.readPassword("Password: ");
            } else {
                System.out.print("Password: ");
                String p = readLine();
                password = (p != null) ? p.toCharArray() : new char[0];
            }

            System.out.println("\nVerifying credentials against records store...");
            AuthenticationResult result = authService.authenticate(username, password);

            if (result.isSuccess()) {
                EmployeeRecord emp = result.getEmployee();
                PortalSession session = result.getSession();
                System.out.println("\n>>> [ACCESS GRANTED] " + result.getMessage());
                System.out.println("--------------------------------------------------------");
                System.out.println(" Employee ID:   " + emp.getEmployeeId());
                System.out.println(" Name:          " + emp.getFullName());
                System.out.println(" Department:    " + emp.getDepartment());
                System.out.println(" Role:          " + emp.getRole());
                System.out.println(" Session ID:    " + session.getSessionId());
                System.out.println(" Session Valid: 8 hours");
                System.out.println("--------------------------------------------------------");
                System.out.println("Available Services: [1] Timesheets  [2] Benefits  [3] Directory");
            } else {
                System.out.println("\n>>> [ACCESS DENIED] " + result.getMessage());
                if (result.getStatus() == AuthStatus.ACCOUNT_LOCKED) {
                    System.out.println("[SECURITY ALERT] This account is currently locked against brute-force guessing.");
                }
            }
        }

        private void displayTestAccounts() {
            System.out.println("\n==========================================================================");
            System.out.println("                     CONFIGURED EMPLOYEE ACCOUNTS                         ");
            System.out.println("==========================================================================");
            System.out.printf("%-10s | %-16s | %-20s | %-18s | %-8s%n",
                    "Emp ID", "Username", "Password", "Department", "Status");
            System.out.println("--------------------------------------------------------------------------");
            System.out.printf("%-10s | %-16s | %-20s | %-18s | %-8s%n",
                    "EMP-1001", "sarah.connor", "CyberGuard#2026!", "Security Ops", "ACTIVE");
            System.out.printf("%-10s | %-16s | %-20s | %-18s | %-8s%n",
                    "EMP-1002", "alex.chen", "CodeCraft$9876", "Engineering", "ACTIVE");
            System.out.printf("%-10s | %-16s | %-20s | %-18s | %-8s%n",
                    "EMP-1003", "maria.rodriguez", "HR_Portal#4321", "Human Resources", "ACTIVE");
            System.out.printf("%-10s | %-16s | %-20s | %-18s | %-8s%n",
                    "EMP-0001", "admin", "PortalAdmin@2026!", "IT Infrastructure", "ACTIVE");
            System.out.println("==========================================================================");
        }

        private void handleAdminUnlock() {
            System.out.println("\n--- ADMINISTRATIVE ACCOUNT UNLOCK ---");
            System.out.print("Enter Target Username to Unlock: ");
            String target = readLine();
            if (target == null || target.trim().isEmpty()) return;

            boolean unlocked = authService.unlockAccount("admin", target.trim());
            if (unlocked) {
                System.out.println("[SUCCESS] Account for '" + target.trim() + "' has been successfully unlocked.");
            } else {
                System.out.println("[FAILED] Target account not found or unlock operation failed.");
            }
        }

        private void displayAuditLogs() {
            System.out.println("\n--- RECENT SECURITY AUDIT LOG ENTRIES ---");
            List<String> logs = authService.getAuditLogger().getRecentEntries(10);
            if (logs.isEmpty()) {
                System.out.println(" (No audit log entries recorded yet)");
            } else {
                logs.forEach(System.out::println);
            }
        }

        private void printBanner() {
            System.out.println("========================================================================");
            System.out.println("            ACME ENTERPRISE INTERNAL EMPLOYEE PORTAL                    ");
            System.out.println("                  SECURE AUTHENTICATION SYSTEM                          ");
            System.out.println("========================================================================");
            System.out.println(" Security Features: PBKDF2-HMAC-SHA256 | Constant-Time Verification");
            System.out.println(" Account Lockout Protection: Max 5 Consecutive Failed Attempts");
            System.out.println("========================================================================");
        }
    }

    // ========================================================================
    // 7. COMPREHENSIVE AUTOMATED TEST SUITE
    // ========================================================================

    /**
     * Automated test suite verifying:
     *  - Authentication credential checking
     *  - Brute-force lockout after consecutive failed attempts
     *  - Denial of locked accounts even with valid credentials
     *  - Recovery via admin unlock and expiration
     *  - Timing defense and memory scrubbing
     */
    public static class SelfTestRunner {

        public static void runAllTests(AuthenticationService authService) {
            System.out.println("\n----------------------------------------------------------------");
            System.out.println("    RUNNING EMPLOYEE PORTAL AUTHENTICATION TEST SUITE           ");
            System.out.println("----------------------------------------------------------------");

            int passed = 0;
            int total = 10;

            // Test 1: Successful login with valid credentials
            passed += test("Test 1: Valid credentials grant access", () -> {
                AuthenticationResult res = authService.authenticate("sarah.connor", "CyberGuard#2026!");
                assertTrue(res.isSuccess(), "Login should succeed for valid credentials");
                assertEquals(AuthStatus.SUCCESS, res.getStatus(), "Status must be SUCCESS");
                assertNotNull(res.getSession(), "Session must be generated");
                assertEquals("EMP-1001", res.getEmployee().getEmployeeId(), "Employee ID mismatch");
            });

            // Test 2: Incorrect password denies access and decrements remaining attempts
            passed += test("Test 2: Incorrect password denies access", () -> {
                AuthenticationResult res = authService.authenticate("sarah.connor", "WrongPassword!123");
                assertFalse(res.isSuccess(), "Login should fail for incorrect password");
                assertEquals(AuthStatus.INVALID_CREDENTIALS, res.getStatus(), "Status must be INVALID_CREDENTIALS");
                assertNull(res.getSession(), "Session must not be issued");
                assertTrue(res.getRemainingAttempts() >= 0, "Remaining attempts should be reported");
            });

            // Test 3: Non-existent username denies access safely
            passed += test("Test 3: Non-existent username denies access", () -> {
                AuthenticationResult res = authService.authenticate("nonexistent.user", "SomeSecret#123");
                assertFalse(res.isSuccess(), "Non-existent user must be rejected");
                assertEquals(AuthStatus.INVALID_CREDENTIALS, res.getStatus(), "Status must be INVALID_CREDENTIALS");
            });

            // Test 4: Timing attack resistance (Dummy hash executes for missing user)
            passed += test("Test 4: Timing side-channel dummy hash defense", () -> {
                char[] pw = "TimingTestPassword#2026!".toCharArray();
                long start = System.nanoTime();
                PasswordSecurity.performDummyHash(pw);
                long duration = System.nanoTime() - start;
                assertTrue(duration > 0, "Dummy hash must execute without errors");
                PasswordSecurity.wipe(pw);
            });

            // Test 5: Account lockout after consecutive failed attempts
            passed += test("Test 5: Account lockout after consecutive failed attempts", () -> {
                String testUser = "alex.chen";
                authService.getRecordStore().unlockAccount(testUser);

                AuthenticationResult lastResult = null;
                int max = authService.getMaxConsecutiveAttempts();
                for (int i = 0; i < max; i++) {
                    lastResult = authService.authenticate(testUser, "BadPasswordGuess#" + i);
                }

                assertNotNull(lastResult, "Result must not be null");
                assertEquals(AuthStatus.ACCOUNT_LOCKED, lastResult.getStatus(),
                        "Account should lock upon reaching " + max + " consecutive failed attempts");

                EmployeeRecord rec = authService.getRecordStore().findByUsername(testUser).orElseThrow();
                assertEquals(AccountStatus.LOCKED, rec.getStatus(), "Record status must be LOCKED");
            });

            // Test 6: Locked account rejects even the CORRECT password
            passed += test("Test 6: Locked account rejects valid credentials while locked", () -> {
                String testUser = "alex.chen"; // Locked in Test 5
                AuthenticationResult res = authService.authenticate(testUser, "CodeCraft$9876");
                assertFalse(res.isSuccess(), "Locked account must reject authentication even with valid password");
                assertEquals(AuthStatus.ACCOUNT_LOCKED, res.getStatus(), "Status must remain ACCOUNT_LOCKED");
            });

            // Test 7: Admin unlocks locked account and restores access
            passed += test("Test 7: Administrative unlock restores access", () -> {
                String testUser = "alex.chen";
                boolean unlocked = authService.unlockAccount("admin", testUser);
                assertTrue(unlocked, "Administrator must be able to unlock user");

                AuthenticationResult res = authService.authenticate(testUser, "CodeCraft$9876");
                assertTrue(res.isSuccess(), "Access must be granted after administrative unlock");
                assertEquals(0, res.getEmployee().getFailedAttempts(), "Failed attempts counter should be reset");
            });

            // Test 8: Successful login resets failed attempts counter
            passed += test("Test 8: Successful login resets failed attempts counter", () -> {
                String testUser = "maria.rodriguez";
                authService.getRecordStore().unlockAccount(testUser);

                // Fail 2 times
                authService.authenticate(testUser, "WrongPassword1");
                authService.authenticate(testUser, "WrongPassword2");

                EmployeeRecord rec = authService.getRecordStore().findByUsername(testUser).orElseThrow();
                assertEquals(2, rec.getFailedAttempts(), "Failed attempts counter should be 2");

                // Successful login
                AuthenticationResult ok = authService.authenticate(testUser, "HR_Portal#4321");
                assertTrue(ok.isSuccess(), "Login should succeed");
                assertEquals(0, rec.getFailedAttempts(), "Failed attempts must be reset to 0 after success");
            });

            // Test 9: Memory scrubbing zeroing validation
            passed += test("Test 9: Sensitive memory wiping verification", () -> {
                char[] secret = "SensitivePortalPassword!".toCharArray();
                PasswordSecurity.wipe(secret);
                for (char c : secret) {
                    assertEquals('\0', c, "Sensitive character array must be zeroed");
                }
            });

            // Test 10: Automatic lockout expiration
            passed += test("Test 10: Automatic lockout expiration logic", () -> {
                // Short lockout test (1 second lockout window)
                InMemoryEmployeeRecordStore testStore = new InMemoryEmployeeRecordStore();
                AuthenticationService fastLockoutService = new AuthenticationService(
                        testStore, null, 2, Duration.ofSeconds(1), Duration.ofHours(1)
                );

                String user = "sarah.connor";
                fastLockoutService.authenticate(user, "wrong1");
                fastLockoutService.authenticate(user, "wrong2");

                // Account should be locked now
                AuthenticationResult lockedRes = fastLockoutService.authenticate(user, "CyberGuard#2026!");
                assertEquals(AuthStatus.ACCOUNT_LOCKED, lockedRes.getStatus(), "Account should be locked initially");

                // Wait for lockout window to expire (1.1 seconds)
                Thread.sleep(1100);

                // Now valid credentials should be accepted
                AuthenticationResult expiredRes = fastLockoutService.authenticate(user, "CyberGuard#2026!");
                assertTrue(expiredRes.isSuccess(), "Account should automatically unlock after expiration window");
            });

            System.out.println("----------------------------------------------------------------");
            System.out.printf("Test Results: %d / %d Passed (%d%%)%n", passed, total, (passed * 100) / total);
            System.out.println("----------------------------------------------------------------\n");
        }

        private static int test(String name, TestCase testCase) {
            try {
                testCase.run();
                System.out.printf(" [PASS] %s%n", name);
                return 1;
            } catch (AssertionError | Exception e) {
                System.out.printf(" [FAIL] %s - %s%n", name, e.getMessage());
                return 0;
            }
        }

        @FunctionalInterface
        interface TestCase {
            void run() throws Exception;
        }

        private static void assertTrue(boolean condition, String message) {
            if (!condition) throw new AssertionError(message);
        }

        private static void assertFalse(boolean condition, String message) {
            if (condition) throw new AssertionError(message);
        }

        private static void assertEquals(Object expected, Object actual, String message) {
            if (!Objects.equals(expected, actual)) {
                throw new AssertionError(message + " (Expected: " + expected + ", Actual: " + actual + ")");
            }
        }

        private static void assertNotNull(Object obj, String message) {
            if (obj == null) throw new AssertionError(message + " (Was null)");
        }

        private static void assertNull(Object obj, String message) {
            if (obj != null) throw new AssertionError(message + " (Expected null, was: " + obj + ")");
        }
    }

    // ========================================================================
    // 8. MAIN ENTRY POINT
    // ========================================================================

    public static void main(String[] args) {
        InMemoryEmployeeRecordStore recordStore = new InMemoryEmployeeRecordStore();
        AuditLogger auditLogger = new AuditLogger(false);
        AuthenticationService authService = new AuthenticationService(recordStore, auditLogger);

        // Command-line options
        if (args.length > 0) {
            String command = args[0].trim().toLowerCase();
            switch (command) {
                case "--test" -> {
                    SelfTestRunner.runAllTests(authService);
                    System.exit(0);
                }
                case "--login", "-l" -> {
                    if (args.length >= 3) {
                        String user = args[1];
                        String pass = args[2];
                        AuthenticationResult res = authService.authenticate(user, pass);
                        if (res.isSuccess()) {
                            System.out.println("STATUS: GRANTED");
                            System.out.println("EMPLOYEE_ID: " + res.getEmployee().getEmployeeId());
                            System.out.println("FULL_NAME: " + res.getEmployee().getFullName());
                            System.out.println("DEPARTMENT: " + res.getEmployee().getDepartment());
                            System.out.println("ROLE: " + res.getEmployee().getRole());
                            System.out.println("SESSION_ID: " + res.getSession().getSessionId());
                            System.exit(0);
                        } else {
                            System.err.println("STATUS: DENIED");
                            System.err.println("REASON: " + res.getMessage());
                            System.exit(1);
                        }
                    } else {
                        System.err.println("Usage: java EmployeeAuthenticationPortal --login <username> <password>");
                        System.exit(1);
                    }
                }
                case "--unlock" -> {
                    if (args.length >= 2) {
                        String target = args[1];
                        boolean ok = recordStore.unlockAccount(target);
                        if (ok) {
                            System.out.println("User '" + target + "' unlocked successfully.");
                            System.exit(0);
                        } else {
                            System.err.println("User '" + target + "' not found.");
                            System.exit(1);
                        }
                    } else {
                        System.err.println("Usage: java EmployeeAuthenticationPortal --unlock <username>");
                        System.exit(1);
                    }
                }
                case "--help", "-h" -> {
                    System.out.println("Acme Internal Employee Portal Authentication Program");
                    System.out.println("Usage:");
                    System.out.println("  java EmployeeAuthenticationPortal               (Start interactive CLI portal)");
                    System.out.println("  java EmployeeAuthenticationPortal --test        (Run automated verification suite)");
                    System.out.println("  java EmployeeAuthenticationPortal --login <u> <p> (Authenticate via CLI)");
                    System.out.println("  java EmployeeAuthenticationPortal --unlock <u>  (Unlock an employee account)");
                    System.exit(0);
                }
                default -> {
                    System.err.println("Unknown command: " + command + ". Run with --help for options.");
                    System.exit(1);
                }
            }
        }

        // Default to interactive portal
        PortalUI ui = new PortalUI(authService);
        ui.run();
    }
}
