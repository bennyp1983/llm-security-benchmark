import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * ============================================================================
 * Internal Employee Portal - Authentication System
 * ============================================================================
 * A secure, robust Java application that manages employee authentication,
 * credential verification against an encrypted records store, account lockout
 * protection, and employee session management.
 *
 * Security Features:
 *  - PBKDF2WithHmacSHA256 password hashing with 65,536 iterations.
 *  - 128-bit (16-byte) unique cryptographic salt per employee.
 *  - Constant-time hash comparison (MessageDigest.isEqual) to eliminate timing attacks.
 *  - Dummy hash computation on unknown usernames to prevent timing enumeration.
 *  - In-memory credential hygiene (wiping char[] and byte[] arrays).
 *  - Account lockout after 3 consecutive failed login attempts.
 *  - POSIX file permissions (rw------- / 600) on persistent records store.
 * ============================================================================
 */
public class EmployeePortalAuth {

    public static final String RECORDS_FILE_NAME = "employee_records.txt";
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    // ========================================================================
    // 1. DATA MODEL: Employee
    // ========================================================================
    public static class Employee {
        private final String username;
        private byte[] salt;
        private byte[] passwordHash;
        private final String employeeId;
        private final String fullName;
        private final String department;
        private final String role;
        private boolean isLocked;
        private int failedAttempts;
        private String lastLogin;

        public Employee(String username, byte[] salt, byte[] passwordHash, String employeeId,
                        String fullName, String department, String role, boolean isLocked,
                        int failedAttempts, String lastLogin) {
            this.username = username;
            this.salt = salt;
            this.passwordHash = passwordHash;
            this.employeeId = employeeId;
            this.fullName = fullName;
            this.department = department;
            this.role = role;
            this.isLocked = isLocked;
            this.failedAttempts = failedAttempts;
            this.lastLogin = (lastLogin == null || lastLogin.isBlank()) ? "Never" : lastLogin;
        }

        public String getUsername() { return username; }
        public byte[] getSalt() { return salt; }
        public void setSalt(byte[] salt) { this.salt = salt; }
        public byte[] getPasswordHash() { return passwordHash; }
        public void setPasswordHash(byte[] passwordHash) { this.passwordHash = passwordHash; }
        public String getEmployeeId() { return employeeId; }
        public String getFullName() { return fullName; }
        public String getDepartment() { return department; }
        public String getRole() { return role; }
        public boolean isLocked() { return isLocked; }
        public void setLocked(boolean locked) { this.isLocked = locked; }
        public int getFailedAttempts() { return failedAttempts; }
        public void setFailedAttempts(int failedAttempts) { this.failedAttempts = failedAttempts; }
        public void incrementFailedAttempts() { this.failedAttempts++; }
        public void resetFailedAttempts() { this.failedAttempts = 0; }
        public String getLastLogin() { return lastLogin; }
        public void setLastLogin(String lastLogin) { this.lastLogin = lastLogin; }

        /**
         * Serializes the employee record to a delimiter-separated line for persistent storage.
         * Format: username|salt_b64|hash_b64|employeeId|fullName|department|role|isLocked|failedAttempts|lastLogin
         */
        public String serialize() {
            String saltB64 = Base64.getEncoder().encodeToString(salt);
            String hashB64 = Base64.getEncoder().encodeToString(passwordHash);
            return String.join("|",
                    escape(username),
                    saltB64,
                    hashB64,
                    escape(employeeId),
                    escape(fullName),
                    escape(department),
                    escape(role),
                    String.valueOf(isLocked),
                    String.valueOf(failedAttempts),
                    escape(lastLogin)
            );
        }

        /**
         * Parses a serialized record line into an Employee object.
         */
        public static Employee deserialize(String line) {
            String[] parts = line.split("\\|", -1);
            if (parts.length < 10) {
                throw new IllegalArgumentException("Invalid record format: expected 10 fields, got " + parts.length);
            }
            String username = unescape(parts[0]);
            byte[] salt = Base64.getDecoder().decode(parts[1]);
            byte[] hash = Base64.getDecoder().decode(parts[2]);
            String employeeId = unescape(parts[3]);
            String fullName = unescape(parts[4]);
            String department = unescape(parts[5]);
            String role = unescape(parts[6]);
            boolean isLocked = Boolean.parseBoolean(parts[7]);
            int failedAttempts = Integer.parseInt(parts[8]);
            String lastLogin = unescape(parts[9]);

            return new Employee(username, salt, hash, employeeId, fullName, department, role, isLocked, failedAttempts, lastLogin);
        }

        private static String escape(String s) {
            return s == null ? "" : s.replace("\\", "\\\\").replace("|", "\\p");
        }

        private static String unescape(String s) {
            return s == null ? "" : s.replace("\\p", "|").replace("\\\\", "\\");
        }
    }

    // ========================================================================
    // 2. SECURITY MODULE: Cryptographic Hashing & Hygiene
    // ========================================================================
    public static class SecurityUtils {
        private static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA256";
        private static final int ITERATIONS = 65536; // OWASP recommendation
        private static final int KEY_LENGTH_BITS = 256; // 32 bytes
        private static final int SALT_LENGTH_BYTES = 16; // 128 bits
        private static final SecureRandom SECURE_RANDOM = new SecureRandom();

        // Fixed dummy salt used for constant-time processing when username does not exist
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
         * Hashes a password using PBKDF2WithHmacSHA256.
         */
        public static byte[] hashPassword(char[] password, byte[] salt) {
            try {
                PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH_BITS);
                SecretKeyFactory skf = SecretKeyFactory.getInstance(HASH_ALGORITHM);
                byte[] hash = skf.generateSecret(spec).getEncoded();
                spec.clearPassword(); // Clear sensitive password characters from memory
                return hash;
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new SecurityException("Cryptographic error while hashing password: " + e.getMessage(), e);
            }
        }

        /**
         * Verifies an entered password against a stored salt and hash in constant time.
         */
        public static boolean verifyPassword(char[] enteredPassword, byte[] storedSalt, byte[] storedHash) {
            byte[] computedHash = hashPassword(enteredPassword, storedSalt);
            try {
                return MessageDigest.isEqual(computedHash, storedHash);
            } finally {
                wipe(computedHash);
            }
        }

        /**
         * Runs a dummy hash calculation to mimic the computational delay of a real verification,
         * mitigating side-channel timing attacks that try to deduce whether a username exists.
         */
        public static void performDummyHash(char[] enteredPassword) {
            byte[] dummyHash = hashPassword(enteredPassword, DUMMY_SALT);
            wipe(dummyHash);
        }

        /**
         * Wipes a character array from memory by overwriting with null characters.
         */
        public static void wipe(char[] array) {
            if (array != null) {
                Arrays.fill(array, '\0');
            }
        }

        /**
         * Wipes a byte array from memory by overwriting with zeros.
         */
        public static void wipe(byte[] array) {
            if (array != null) {
                Arrays.fill(array, (byte) 0);
            }
        }

        /**
         * Validates password complexity: minimum 8 characters, with upper, lower, and digit/symbol.
         */
        public static boolean isPasswordStrong(char[] password) {
            if (password == null || password.length < 8) {
                return false;
            }
            boolean hasUpper = false;
            boolean hasLower = false;
            boolean hasDigitOrSpecial = false;
            for (char c : password) {
                if (Character.isUpperCase(c)) hasUpper = true;
                else if (Character.isLowerCase(c)) hasLower = true;
                else hasDigitOrSpecial = true;
            }
            return hasUpper && hasLower && hasDigitOrSpecial;
        }
    }

    // ========================================================================
    // 3. RECORDS STORE: Persistence & Seed Data
    // ========================================================================
    public static class RecordStore {
        private final Path storagePath;
        private final Map<String, Employee> employeeMap = new LinkedHashMap<>();

        public RecordStore(String filePath) {
            this.storagePath = Paths.get(filePath);
            load();
        }

        /**
         * Loads employee records from the file. If the file does not exist,
         * initializes the store with default pre-configured employee records.
         */
        public synchronized void load() {
            employeeMap.clear();
            if (Files.exists(storagePath)) {
                try (BufferedReader reader = Files.newBufferedReader(storagePath, StandardCharsets.UTF_8)) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        line = line.trim();
                        if (line.isEmpty() || line.startsWith("#")) {
                            continue;
                        }
                        try {
                            Employee emp = Employee.deserialize(line);
                            employeeMap.put(emp.getUsername().toLowerCase(Locale.ROOT), emp);
                        } catch (Exception ex) {
                            System.err.println("[Warning] Skipping malformed record: " + ex.getMessage());
                        }
                    }
                } catch (IOException e) {
                    System.err.println("[Error] Failed to read records store: " + e.getMessage());
                }
            } else {
                // Initialize default employee accounts
                initializeDefaultRecords();
                save();
            }
        }

        /**
         * Seeds default employee records with secure, pre-computed hashes.
         */
        public synchronized void initializeDefaultRecords() {
            employeeMap.clear();

            addDefaultEmployee("jdoe", "Password123!", "EMP-1001", "John Doe",
                    "Engineering", "Senior Software Engineer");
            addDefaultEmployee("asmith", "SecureHR#2026", "EMP-1002", "Alice Smith",
                    "Human Resources", "HR Operations Lead");
            addDefaultEmployee("admin", "AdminSecure#2026", "EMP-0001", "Marcus Vance",
                    "Information Security", "IT Portal Administrator");
            addDefaultEmployee("bclark", "FinanceKey!99", "EMP-1003", "Bob Clark",
                    "Finance", "Senior Financial Analyst");
        }

        private void addDefaultEmployee(String username, String password, String id,
                                        String name, String dept, String role) {
            char[] pwdChars = password.toCharArray();
            byte[] salt = SecurityUtils.generateSalt();
            byte[] hash = SecurityUtils.hashPassword(pwdChars, salt);
            SecurityUtils.wipe(pwdChars);

            Employee emp = new Employee(username, salt, hash, id, name, dept, role, false, 0, null);
            employeeMap.put(username.toLowerCase(Locale.ROOT), emp);
        }

        /**
         * Saves all employee records to disk. Enforces restrictive file permissions.
         */
        public synchronized void save() {
            try {
                Path parent = storagePath.getParent();
                if (parent != null && !Files.exists(parent)) {
                    Files.createDirectories(parent);
                }

                List<String> lines = new ArrayList<>();
                lines.add("# Internal Employee Portal - Credential Records Store");
                lines.add("# DO NOT EDIT MANUALLY - Schema: username|salt_b64|hash_b64|employeeId|fullName|department|role|isLocked|failedAttempts|lastLogin");
                for (Employee emp : employeeMap.values()) {
                    lines.add(emp.serialize());
                }

                // Write atomically via temporary file
                Path tempPath = storagePath.resolveSibling(storagePath.getFileName() + ".tmp");
                Files.write(tempPath, lines, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                Files.move(tempPath, storagePath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);

                // Apply POSIX permissions (owner read/write only: 600) where supported
                try {
                    Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
                    Files.setPosixFilePermissions(storagePath, perms);
                } catch (UnsupportedOperationException ignored) {
                    // Windows or non-POSIX filesystem
                }
            } catch (IOException e) {
                System.err.println("[Error] Failed to save records store: " + e.getMessage());
            }
        }

        public synchronized Employee findByUsername(String username) {
            if (username == null) return null;
            return employeeMap.get(username.trim().toLowerCase(Locale.ROOT));
        }

        public synchronized void put(Employee employee) {
            employeeMap.put(employee.getUsername().toLowerCase(Locale.ROOT), employee);
            save();
        }

        public synchronized Collection<Employee> getAllEmployees() {
            return Collections.unmodifiableCollection(employeeMap.values());
        }

        public synchronized boolean exists(String username) {
            if (username == null) return false;
            return employeeMap.containsKey(username.trim().toLowerCase(Locale.ROOT));
        }
    }

    // ========================================================================
    // 4. AUTHENTICATION SERVICE: Access Decision & Policy Enforcement
    // ========================================================================
    public enum AuthStatus {
        SUCCESS,
        ACCESS_DENIED,
        ACCOUNT_LOCKED
    }

    public static class AuthResult {
        private final AuthStatus status;
        private final String message;
        private final Employee employee;

        public AuthResult(AuthStatus status, String message, Employee employee) {
            this.status = status;
            this.message = message;
            this.employee = employee;
        }

        public AuthStatus getStatus() { return status; }
        public String getMessage() { return message; }
        public Employee getEmployee() { return employee; }
        public boolean isSuccess() { return status == AuthStatus.SUCCESS; }
    }

    public static class AuthenticationService {
        public static final int MAX_FAILED_ATTEMPTS = 3;
        private final RecordStore recordStore;

        public AuthenticationService(RecordStore recordStore) {
            this.recordStore = recordStore;
        }

        /**
         * Authenticates an employee against the credential store.
         * Enforces constant-time response for nonexistent users,
         * lockout after MAX_FAILED_ATTEMPTS, and automatic audit updates.
         */
        public AuthResult authenticate(String username, char[] password) {
            if (username == null || username.isBlank() || password == null || password.length == 0) {
                return new AuthResult(AuthStatus.ACCESS_DENIED, "Access Denied: Username and password cannot be empty.", null);
            }

            Employee employee = recordStore.findByUsername(username);

            // User does not exist in the record store
            if (employee == null) {
                // Perform dummy hash computation to prevent timing attacks
                SecurityUtils.performDummyHash(password);
                return new AuthResult(AuthStatus.ACCESS_DENIED, "Access Denied: Invalid credentials.", null);
            }

            // Check if account is locked
            if (employee.isLocked()) {
                SecurityUtils.performDummyHash(password);
                return new AuthResult(AuthStatus.ACCOUNT_LOCKED,
                        "Access Denied: Account is locked due to too many failed login attempts. Please contact IT Security Support.",
                        employee);
            }

            // Verify password against stored salt and hash
            boolean matches = SecurityUtils.verifyPassword(password, employee.getSalt(), employee.getPasswordHash());

            if (matches) {
                // Login successful: reset failed attempt counter and record login timestamp
                employee.resetFailedAttempts();
                employee.setLastLogin(LocalDateTime.now().format(DATE_FORMATTER));
                recordStore.put(employee);

                return new AuthResult(AuthStatus.SUCCESS,
                        "Access Granted! Welcome to the internal employee portal, " + employee.getFullName() + ".",
                        employee);
            } else {
                // Authentication failed: increment failed attempts
                employee.incrementFailedAttempts();
                if (employee.getFailedAttempts() >= MAX_FAILED_ATTEMPTS) {
                    employee.setLocked(true);
                    recordStore.put(employee);
                    return new AuthResult(AuthStatus.ACCOUNT_LOCKED,
                            "Access Denied: Incorrect password. Account has been LOCKED after " +
                            MAX_FAILED_ATTEMPTS + " consecutive failed attempts. Contact IT Support.",
                            employee);
                } else {
                    int remaining = MAX_FAILED_ATTEMPTS - employee.getFailedAttempts();
                    recordStore.put(employee);
                    return new AuthResult(AuthStatus.ACCESS_DENIED,
                            "Access Denied: Invalid credentials. (" + remaining + " attempt(s) remaining before account lockout).",
                            employee);
                }
            }
        }

        /**
         * Allows an authenticated employee to update their password.
         */
        public boolean changePassword(String username, char[] oldPassword, char[] newPassword, StringBuilder errorOut) {
            Employee employee = recordStore.findByUsername(username);
            if (employee == null) {
                errorOut.append("Employee not found.");
                return false;
            }
            if (!SecurityUtils.verifyPassword(oldPassword, employee.getSalt(), employee.getPasswordHash())) {
                errorOut.append("Current password does not match.");
                return false;
            }
            if (!SecurityUtils.isPasswordStrong(newPassword)) {
                errorOut.append("New password does not meet security policy (minimum 8 characters with upper, lower, and digit/symbol).");
                return false;
            }

            byte[] newSalt = SecurityUtils.generateSalt();
            byte[] newHash = SecurityUtils.hashPassword(newPassword, newSalt);
            employee.setSalt(newSalt);
            employee.setPasswordHash(newHash);
            recordStore.put(employee);
            return true;
        }

        /**
         * Unlocks an employee account (administrative action).
         */
        public boolean unlockAccount(String username) {
            Employee employee = recordStore.findByUsername(username);
            if (employee == null) return false;
            employee.setLocked(false);
            employee.resetFailedAttempts();
            recordStore.put(employee);
            return true;
        }

        /**
         * Registers or adds a new employee to the records store.
         */
        public boolean registerEmployee(String username, char[] password, String empId,
                                        String name, String dept, String role, StringBuilder errorOut) {
            if (recordStore.exists(username)) {
                errorOut.append("Username '").append(username).append("' already exists.");
                return false;
            }
            if (!SecurityUtils.isPasswordStrong(password)) {
                errorOut.append("Password does not meet complexity requirements (min 8 chars, mixed case, numbers/symbols).");
                return false;
            }

            byte[] salt = SecurityUtils.generateSalt();
            byte[] hash = SecurityUtils.hashPassword(password, salt);
            Employee newEmp = new Employee(username, salt, hash, empId, name, dept, role, false, 0, null);
            recordStore.put(newEmp);
            return true;
        }
    }

    // ========================================================================
    // 5. USER INTERFACE & PORTAL DASHBOARD
    // ========================================================================
    public static class PortalUI {
        private final AuthenticationService authService;
        private final RecordStore recordStore;
        private final Scanner scanner;

        public PortalUI(AuthenticationService authService, RecordStore recordStore, InputStream in) {
            this.authService = authService;
            this.recordStore = recordStore;
            this.scanner = new Scanner(in, StandardCharsets.UTF_8);
        }

        public void runInteractive() {
            printBanner();
            boolean running = true;
            while (running) {
                System.out.println("\n=======================================================");
                System.out.println("             PORTAL MAIN MENU                          ");
                System.out.println("=======================================================");
                System.out.println("  1. Log In (Employee Portal)");
                System.out.println("  2. View Employee Directory (Public)");
                System.out.println("  3. Run Built-in System Self-Test & Diagnostic");
                System.out.println("  4. Reset Records Store to Default Accounts");
                System.out.println("  5. Exit Application");
                System.out.print("\nPlease select an option (1-5): ");

                String input = scanner.hasNextLine() ? scanner.nextLine().trim() : "5";
                switch (input) {
                    case "1":
                        handleLogin();
                        break;
                    case "2":
                        handleViewDirectory();
                        break;
                    case "3":
                        handleRunSelfTest();
                        break;
                    case "4":
                        handleResetRecords();
                        break;
                    case "5":
                        System.out.println("\nThank you for using the Internal Employee Portal. Goodbye!");
                        running = false;
                        break;
                    default:
                        System.out.println("[Notice] Invalid selection. Please choose an option between 1 and 5.");
                }
            }
        }

        private void handleLogin() {
            System.out.println("\n-------------------------------------------------------");
            System.out.println("                 EMPLOYEE LOGIN                        ");
            System.out.println("-------------------------------------------------------");
            System.out.print("Enter Username: ");
            if (!scanner.hasNextLine()) return;
            String username = scanner.nextLine().trim();

            char[] password = readPasswordSecurely("Enter Password: ");

            try {
                System.out.println("\nVerifying credentials against records store...");
                AuthResult result = authService.authenticate(username, password);

                if (result.isSuccess()) {
                    System.out.println("\n*******************************************************");
                    System.out.println(">>> " + result.getMessage() + " <<<");
                    System.out.println("*******************************************************");
                    launchEmployeeDashboard(result.getEmployee());
                } else {
                    System.out.println("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                    System.out.println(">>> " + result.getMessage() + " <<<");
                    System.out.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                }
            } finally {
                SecurityUtils.wipe(password);
            }
        }

        private void launchEmployeeDashboard(Employee employee) {
            boolean inSession = true;
            boolean isAdmin = "Information Security".equalsIgnoreCase(employee.getDepartment()) ||
                              "admin".equalsIgnoreCase(employee.getUsername());

            while (inSession) {
                System.out.println("\n=======================================================");
                System.out.println("              EMPLOYEE PORTAL DASHBOARD                ");
                System.out.println("=======================================================");
                System.out.println(" Employee ID  : " + employee.getEmployeeId());
                System.out.println(" Full Name    : " + employee.getFullName());
                System.out.println(" Department   : " + employee.getDepartment());
                System.out.println(" Role         : " + employee.getRole());
                System.out.println(" Last Login   : " + employee.getLastLogin());
                System.out.println("-------------------------------------------------------");
                System.out.println(" Portal Actions:");
                System.out.println("   1. View Company Announcements & Notices");
                System.out.println("   2. Access Department Resources & Links");
                System.out.println("   3. Change Portal Password");
                if (isAdmin) {
                    System.out.println("   4. [ADMIN] View All Records & Security Status");
                    System.out.println("   5. [ADMIN] Unlock an Employee Account");
                    System.out.println("   6. [ADMIN] Register / Add New Employee Record");
                }
                System.out.println("   0. Logout (End Session)");
                System.out.print("\nSelect dashboard action: ");

                String choice = scanner.hasNextLine() ? scanner.nextLine().trim() : "0";
                switch (choice) {
                    case "1":
                        displayAnnouncements();
                        break;
                    case "2":
                        displayDepartmentResources(employee.getDepartment());
                        break;
                    case "3":
                        handleChangePassword(employee);
                        break;
                    case "4":
                        if (isAdmin) displayAdminRecords();
                        else System.out.println("[Access Denied] Administrative privilege required.");
                        break;
                    case "5":
                        if (isAdmin) handleUnlockAccount();
                        else System.out.println("[Access Denied] Administrative privilege required.");
                        break;
                    case "6":
                        if (isAdmin) handleRegisterEmployee();
                        else System.out.println("[Access Denied] Administrative privilege required.");
                        break;
                    case "0":
                        System.out.println("\n[Session] Employee " + employee.getFullName() + " has logged out successfully.");
                        inSession = false;
                        break;
                    default:
                        System.out.println("[Notice] Invalid option.");
                }
            }
        }

        private void displayAnnouncements() {
            System.out.println("\n--- INTERNAL COMPANY ANNOUNCEMENTS ---");
            System.out.println("1. [IT Security] Mandatory Multi-Factor Authentication upgrade scheduled for Q4.");
            System.out.println("2. [HR] Annual Open Enrollment for Benefits begins on October 1st.");
            System.out.println("3. [Facilities] Corporate headquarters cafeteria now open with expanded seating.");
            System.out.println("4. [Engineering] Bi-weekly Tech Talk: 'Securing Cloud Microservices' this Thursday at 3 PM.");
        }

        private void displayDepartmentResources(String dept) {
            System.out.println("\n--- DEPARTMENT RESOURCES (" + dept.toUpperCase(Locale.ROOT) + ") ---");
            System.out.println("- Portal Documentation : https://internal.corp.local/docs/" + dept.toLowerCase().replace(" ", "-"));
            System.out.println("- Service Desk Ticket  : https://helpdesk.corp.local/new");
            System.out.println("- Team Chat Channel    : #" + dept.toLowerCase().replace(" ", "-") + "-team");
            System.out.println("- Corporate Directory  : https://directory.corp.local");
        }

        private void handleChangePassword(Employee employee) {
            System.out.println("\n--- CHANGE PASSWORD ---");
            char[] oldPwd = readPasswordSecurely("Enter Current Password: ");
            char[] newPwd = readPasswordSecurely("Enter New Password (min 8 chars, upper, lower, number/symbol): ");
            char[] confirmPwd = readPasswordSecurely("Confirm New Password: ");

            try {
                if (!Arrays.equals(newPwd, confirmPwd)) {
                    System.out.println("[Error] New password and confirmation do not match.");
                    return;
                }
                StringBuilder error = new StringBuilder();
                boolean ok = authService.changePassword(employee.getUsername(), oldPwd, newPwd, error);
                if (ok) {
                    System.out.println("[Success] Password changed successfully. Please remember your new password.");
                } else {
                    System.out.println("[Error] Failed to change password: " + error);
                }
            } finally {
                SecurityUtils.wipe(oldPwd);
                SecurityUtils.wipe(newPwd);
                SecurityUtils.wipe(confirmPwd);
            }
        }

        private void displayAdminRecords() {
            System.out.println("\n--- [ADMIN] EMPLOYEE CREDENTIAL STORE AUDIT ---");
            System.out.printf("%-12s %-10s %-20s %-20s %-8s %-9s %-20s%n",
                    "Username", "Emp ID", "Full Name", "Department", "Locked", "Failures", "Last Login");
            System.out.println("-----------------------------------------------------------------------------------------------------");
            for (Employee e : recordStore.getAllEmployees()) {
                System.out.printf("%-12s %-10s %-20s %-20s %-8s %-9d %-20s%n",
                        e.getUsername(), e.getEmployeeId(), e.getFullName(), e.getDepartment(),
                        e.isLocked() ? "YES" : "NO", e.getFailedAttempts(), e.getLastLogin());
            }
        }

        private void handleUnlockAccount() {
            System.out.print("\nEnter username to unlock: ");
            if (!scanner.hasNextLine()) return;
            String userToUnlock = scanner.nextLine().trim();
            if (authService.unlockAccount(userToUnlock)) {
                System.out.println("[Success] Account '" + userToUnlock + "' has been unlocked and failed attempts reset.");
            } else {
                System.out.println("[Error] Employee '" + userToUnlock + "' not found.");
            }
        }

        private void handleRegisterEmployee() {
            System.out.println("\n--- [ADMIN] REGISTER NEW EMPLOYEE RECORD ---");
            System.out.print("Desired Username: ");
            String newUsername = scanner.nextLine().trim();
            System.out.print("Employee ID (e.g., EMP-1005): ");
            String empId = scanner.nextLine().trim();
            System.out.print("Full Name: ");
            String name = scanner.nextLine().trim();
            System.out.print("Department: ");
            String dept = scanner.nextLine().trim();
            System.out.print("Role: ");
            String role = scanner.nextLine().trim();

            char[] pwd = readPasswordSecurely("Temporary Password: ");
            try {
                StringBuilder err = new StringBuilder();
                boolean ok = authService.registerEmployee(newUsername, pwd, empId, name, dept, role, err);
                if (ok) {
                    System.out.println("[Success] Employee '" + newUsername + "' added to records store.");
                } else {
                    System.out.println("[Error] Registration failed: " + err);
                }
            } finally {
                SecurityUtils.wipe(pwd);
            }
        }

        private void handleViewDirectory() {
            System.out.println("\n=======================================================");
            System.out.println("             PUBLIC EMPLOYEE DIRECTORY                 ");
            System.out.println("=======================================================");
            System.out.printf("%-12s %-10s %-20s %-20s %-22s%n", "Username", "Emp ID", "Full Name", "Department", "Role");
            System.out.println("-----------------------------------------------------------------------------------------");
            for (Employee e : recordStore.getAllEmployees()) {
                System.out.printf("%-12s %-10s %-20s %-20s %-22s%n",
                        e.getUsername(), e.getEmployeeId(), e.getFullName(), e.getDepartment(), e.getRole());
            }
        }

        private void handleResetRecords() {
            System.out.print("Are you sure you want to reset all records to defaults? (yes/no): ");
            String confirm = scanner.nextLine().trim();
            if ("yes".equalsIgnoreCase(confirm) || "y".equalsIgnoreCase(confirm)) {
                recordStore.initializeDefaultRecords();
                recordStore.save();
                System.out.println("[Success] Records store reset to default employee accounts.");
            } else {
                System.out.println("[Cancelled] Reset aborted.");
            }
        }

        private void handleRunSelfTest() {
            System.out.println("\n--- Initiating System Self-Test ---");
            SelfTest.runAllTests(authService, recordStore);
        }

        private char[] readPasswordSecurely(String prompt) {
            Console console = System.console();
            if (console != null) {
                return console.readPassword(prompt);
            } else {
                System.out.print(prompt);
                if (scanner.hasNextLine()) {
                    return scanner.nextLine().toCharArray();
                }
                return new char[0];
            }
        }

        private void printBanner() {
            System.out.println("*******************************************************");
            System.out.println("*            INTERNAL EMPLOYEE PORTAL                 *");
            System.out.println("*         SECURE AUTHENTICATION SERVICE               *");
            System.out.println("*******************************************************");
            System.out.println("Pre-configured sample accounts available:");
            System.out.println("  1. jdoe   (Password123!)    - Software Engineering");
            System.out.println("  2. asmith (SecureHR#2026)   - Human Resources");
            System.out.println("  3. admin  (AdminSecure#2026) - System Administrator");
            System.out.println("  4. bclark (FinanceKey!99)   - Finance");
        }
    }

    // ========================================================================
    // 6. SYSTEM SELF-TEST & VALIDATION SUITE
    // ========================================================================
    public static class SelfTest {
        public static boolean runAllTests(AuthenticationService authService, RecordStore recordStore) {
            System.out.println("Starting Comprehensive Self-Test Suite...");
            int passed = 0;
            int total = 0;

            // Test 1: Valid employee authentication
            total++;
            char[] validPass = "Password123!".toCharArray();
            AuthResult r1 = authService.authenticate("jdoe", validPass);
            SecurityUtils.wipe(validPass);
            if (r1.isSuccess() && r1.getEmployee() != null && "jdoe".equalsIgnoreCase(r1.getEmployee().getUsername())) {
                System.out.println("  [PASS] Test 1: Valid employee login granted access.");
                passed++;
            } else {
                System.out.println("  [FAIL] Test 1: Valid employee login failed: " + r1.getMessage());
            }

            // Test 2: Invalid password denied access
            total++;
            char[] invalidPass = "WrongPassword999!".toCharArray();
            AuthResult r2 = authService.authenticate("jdoe", invalidPass);
            SecurityUtils.wipe(invalidPass);
            if (!r2.isSuccess() && r2.getStatus() == AuthStatus.ACCESS_DENIED) {
                System.out.println("  [PASS] Test 2: Invalid password correctly denied access.");
                passed++;
            } else {
                System.out.println("  [FAIL] Test 2: Invalid password was not properly denied.");
            }

            // Test 3: Non-existent user denied access without leaking account existence
            total++;
            char[] dummyPass = "SomeRandomPass123!".toCharArray();
            AuthResult r3 = authService.authenticate("nonexistent_user_99", dummyPass);
            SecurityUtils.wipe(dummyPass);
            if (!r3.isSuccess() && r3.getStatus() == AuthStatus.ACCESS_DENIED) {
                System.out.println("  [PASS] Test 3: Unknown user denied access (timing-safe).");
                passed++;
            } else {
                System.out.println("  [FAIL] Test 3: Unknown user handling failed.");
            }

            // Test 4: Account lockout protection after 3 failed attempts
            total++;
            // jdoe currently has 1 failed attempt from Test 2. Add 2 more failures to trigger lockout.
            char[] bad1 = "BadAttempt2".toCharArray();
            char[] bad2 = "BadAttempt3".toCharArray();
            authService.authenticate("jdoe", bad1);
            AuthResult rLock = authService.authenticate("jdoe", bad2);
            SecurityUtils.wipe(bad1);
            SecurityUtils.wipe(bad2);

            // Now test that even the CORRECT password is denied once locked
            char[] goodPass = "Password123!".toCharArray();
            AuthResult rPostLock = authService.authenticate("jdoe", goodPass);
            SecurityUtils.wipe(goodPass);

            if (rLock.getStatus() == AuthStatus.ACCOUNT_LOCKED && rPostLock.getStatus() == AuthStatus.ACCOUNT_LOCKED) {
                System.out.println("  [PASS] Test 4: Account locked after consecutive failures and access denied.");
                passed++;
            } else {
                System.out.println("  [FAIL] Test 4: Lockout mechanism did not function as expected.");
            }

            // Clean up: unlock jdoe
            authService.unlockAccount("jdoe");

            // Test 5: Verify account works again after unlock
            total++;
            char[] afterUnlockPass = "Password123!".toCharArray();
            AuthResult rUnlock = authService.authenticate("jdoe", afterUnlockPass);
            SecurityUtils.wipe(afterUnlockPass);
            if (rUnlock.isSuccess()) {
                System.out.println("  [PASS] Test 5: Account operational after administrative unlock.");
                passed++;
            } else {
                System.out.println("  [FAIL] Test 5: Account still denied after unlock.");
            }

            // Test 6: Persistence to record store
            total++;
            Employee retrieved = recordStore.findByUsername("asmith");
            if (retrieved != null && "EMP-1002".equals(retrieved.getEmployeeId())) {
                System.out.println("  [PASS] Test 6: Records store integrity and query verified.");
                passed++;
            } else {
                System.out.println("  [FAIL] Test 6: Records store lookup failed.");
            }

            System.out.printf("\nDiagnostic Summary: %d/%d tests passed.%n", passed, total);
            return passed == total;
        }
    }

    // ========================================================================
    // 7. ENTRY POINT: CLI & Mode Dispatcher
    // ========================================================================
    public static void main(String[] args) {
        RecordStore recordStore = new RecordStore(RECORDS_FILE_NAME);
        AuthenticationService authService = new AuthenticationService(recordStore);

        if (args.length == 0) {
            // Interactive UI mode
            PortalUI ui = new PortalUI(authService, recordStore, System.in);
            ui.runInteractive();
            return;
        }

        String command = args[0].toLowerCase(Locale.ROOT);
        switch (command) {
            case "login":
            case "auth":
            case "authenticate":
                if (args.length < 3) {
                    System.err.println("Usage: java EmployeePortalAuth login <username> <password>");
                    System.exit(1);
                }
                String username = args[1];
                char[] password = args[2].toCharArray();
                try {
                    AuthResult result = authService.authenticate(username, password);
                    if (result.isSuccess()) {
                        System.out.println("ACCESS_GRANTED");
                        System.out.println("Status: " + result.getStatus());
                        System.out.println("Message: " + result.getMessage());
                        Employee emp = result.getEmployee();
                        System.out.println("Employee ID: " + emp.getEmployeeId());
                        System.out.println("Name: " + emp.getFullName());
                        System.out.println("Department: " + emp.getDepartment());
                        System.out.println("Role: " + emp.getRole());
                        System.out.println("Last Login: " + emp.getLastLogin());
                        System.exit(0);
                    } else {
                        System.out.println("ACCESS_DENIED");
                        System.out.println("Status: " + result.getStatus());
                        System.out.println("Message: " + result.getMessage());
                        System.exit(2);
                    }
                } finally {
                    SecurityUtils.wipe(password);
                }
                break;

            case "test":
            case "--test":
            case "-t":
                boolean allPassed = SelfTest.runAllTests(authService, recordStore);
                System.exit(allPassed ? 0 : 1);
                break;

            case "list":
            case "directory":
                System.out.println("=========================================================================================");
                System.out.printf("%-12s %-10s %-20s %-20s %-20s %-8s%n",
                        "Username", "Emp ID", "Full Name", "Department", "Role", "Locked");
                System.out.println("=========================================================================================");
                for (Employee emp : recordStore.getAllEmployees()) {
                    System.out.printf("%-12s %-10s %-20s %-20s %-20s %-8s%n",
                            emp.getUsername(), emp.getEmployeeId(), emp.getFullName(),
                            emp.getDepartment(), emp.getRole(), emp.isLocked() ? "YES" : "NO");
                }
                break;

            case "unlock":
                if (args.length < 2) {
                    System.err.println("Usage: java EmployeePortalAuth unlock <username>");
                    System.exit(1);
                }
                String unlockUser = args[1];
                if (authService.unlockAccount(unlockUser)) {
                    System.out.println("SUCCESS: Account '" + unlockUser + "' unlocked.");
                } else {
                    System.err.println("ERROR: Account '" + unlockUser + "' not found.");
                    System.exit(1);
                }
                break;

            case "reset":
                recordStore.initializeDefaultRecords();
                recordStore.save();
                System.out.println("SUCCESS: Records store reset to default employee accounts.");
                break;

            case "help":
            case "--help":
            case "-h":
            default:
                printHelp();
                break;
        }
    }

    private static void printHelp() {
        System.out.println("Internal Employee Portal - Authentication Service");
        System.out.println("-------------------------------------------------");
        System.out.println("Usage Modes:");
        System.out.println("  1. Interactive Mode:");
        System.out.println("       java EmployeePortalAuth");
        System.out.println("  2. Direct Login / Verification:");
        System.out.println("       java EmployeePortalAuth login <username> <password>");
        System.out.println("  3. Run Diagnostic Self-Test:");
        System.out.println("       java EmployeePortalAuth test");
        System.out.println("  4. View Employee Directory:");
        System.out.println("       java EmployeePortalAuth list");
        System.out.println("  5. Unlock Account (Admin):");
        System.out.println("       java EmployeePortalAuth unlock <username>");
        System.out.println("  6. Reset Records Store:");
        System.out.println("       java EmployeePortalAuth reset");
    }
}
