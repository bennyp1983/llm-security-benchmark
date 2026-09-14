import java.io.BufferedWriter;
import java.io.Console;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Enterprise Administrator Portal Application
 *
 * Provides robust, secure authentication for administrator users and grants access
 * to admin-level functionality including user management, system diagnostics,
 * security audit logging, and system configuration.
 */
public class AdminPortal {

    // --- Configuration Constants ---
    private static final int MAX_FAILED_ATTEMPTS = 3;
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final Instant START_TIME = Instant.now();

    // --- In-Memory Data Stores ---
    private static final Map<String, User> userDatabase = new LinkedHashMap<>();
    private static final List<AuditLogEntry> auditLogs = new ArrayList<>();
    private static boolean maintenanceMode = false;

    // ==========================================
    // Core Models and Enums
    // ==========================================

    /**
     * User Roles for Role-Based Access Control (RBAC)
     */
    public enum Role {
        SUPER_ADMIN("Super Administrator", true),
        ADMIN("Administrator", true),
        STANDARD_USER("Standard User", false);

        private final String displayName;
        private final boolean isAdmin;

        Role(String displayName, boolean isAdmin) {
            this.displayName = displayName;
            this.isAdmin = isAdmin;
        }

        public String getDisplayName() {
            return displayName;
        }

        public boolean isAdmin() {
            return isAdmin;
        }
    }

    /**
     * User Entity holding security attributes and account state.
     */
    public static class User {
        private final String username;
        private byte[] passwordHash;
        private byte[] salt;
        private Role role;
        private boolean locked;
        private int failedAttempts;
        private LocalDateTime lastLogin;
        private final LocalDateTime createdAt;

        public User(String username, byte[] passwordHash, byte[] salt, Role role) {
            this.username = username;
            this.passwordHash = passwordHash;
            this.salt = salt;
            this.role = role;
            this.locked = false;
            this.failedAttempts = 0;
            this.lastLogin = null;
            this.createdAt = LocalDateTime.now();
        }

        public String getUsername() {
            return username;
        }

        public byte[] getPasswordHash() {
            return passwordHash;
        }

        public void setPassword(byte[] newHash, byte[] newSalt) {
            this.passwordHash = newHash;
            this.salt = newSalt;
        }

        public byte[] getSalt() {
            return salt;
        }

        public Role getRole() {
            return role;
        }

        public void setRole(Role role) {
            this.role = role;
        }

        public boolean isLocked() {
            return locked;
        }

        public void setLocked(boolean locked) {
            this.locked = locked;
            if (!locked) {
                this.failedAttempts = 0;
            }
        }

        public int getFailedAttempts() {
            return failedAttempts;
        }

        public void incrementFailedAttempts() {
            this.failedAttempts++;
        }

        public void resetFailedAttempts() {
            this.failedAttempts = 0;
        }

        public LocalDateTime getLastLogin() {
            return lastLogin;
        }

        public void setLastLogin(LocalDateTime lastLogin) {
            this.lastLogin = lastLogin;
        }

        public LocalDateTime getCreatedAt() {
            return createdAt;
        }
    }

    /**
     * Audit Log Entry capturing security events and admin operations.
     */
    public static class AuditLogEntry {
        private final LocalDateTime timestamp;
        private final String username;
        private final String action;
        private final String status;
        private final String details;

        public AuditLogEntry(String username, String action, String status, String details) {
            this.timestamp = LocalDateTime.now();
            this.username = username;
            this.action = action;
            this.status = status;
            this.details = details;
        }

        public LocalDateTime getTimestamp() {
            return timestamp;
        }

        public String getUsername() {
            return username;
        }

        public String getAction() {
            return action;
        }

        public String getStatus() {
            return status;
        }

        public String getDetails() {
            return details;
        }

        @Override
        public String toString() {
            return String.format("[%s] [%-7s] User: %-12s | Action: %-25s | Details: %s",
                    timestamp.format(DATE_FORMATTER), status, username, action, details);
        }
    }

    // ==========================================
    // Cryptographic & Security Utilities
    // ==========================================

    public static class SecurityUtils {
        private static final int ITERATIONS = 65536;
        private static final int KEY_LENGTH = 256;
        private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
        private static final SecureRandom RANDOM = new SecureRandom();

        public static byte[] generateSalt() {
            byte[] salt = new byte[16];
            RANDOM.nextBytes(salt);
            return salt;
        }

        public static byte[] hashPassword(char[] password, byte[] salt) {
            try {
                KeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);
                SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
                return factory.generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new SecurityException("Cryptographic algorithm unavailable for password hashing", e);
            }
        }

        /**
         * Verifies entered password against expected hash using constant-time comparison
         * to prevent timing side-channel attacks.
         */
        public static boolean verifyPassword(char[] enteredPassword, byte[] salt, byte[] expectedHash) {
            byte[] enteredHash = hashPassword(enteredPassword, salt);
            return MessageDigest.isEqual(enteredHash, expectedHash);
        }

        /**
         * Clears sensitive character arrays from memory immediately after use.
         */
        public static void clearPassword(char[] password) {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    // ==========================================
    // Initialization & Pre-seeded Data
    // ==========================================

    static {
        seedInitialAccounts();
    }

    private static void seedInitialAccounts() {
        // Pre-seeded Admin account
        createAccountInternal("admin", "Admin@1234!".toCharArray(), Role.ADMIN);

        // Pre-seeded Super Admin account
        createAccountInternal("superadmin", "SuperSecure2026#".toCharArray(), Role.SUPER_ADMIN);

        // Pre-seeded Standard User account (used to test non-admin access denial)
        createAccountInternal("johndoe", "UserPass@2026".toCharArray(), Role.STANDARD_USER);

        logAudit("SYSTEM", "INITIALIZATION", "SUCCESS", "Pre-seeded default admin and test user accounts.");
    }

    private static void createAccountInternal(String username, char[] password, Role role) {
        byte[] salt = SecurityUtils.generateSalt();
        byte[] hash = SecurityUtils.hashPassword(password, salt);
        SecurityUtils.clearPassword(password);
        userDatabase.put(username, new User(username, hash, salt, role));
    }

    private static void logAudit(String username, String action, String status, String details) {
        AuditLogEntry entry = new AuditLogEntry(username, action, status, details);
        auditLogs.add(entry);
    }

    // ==========================================
    // Main Entry Point
    // ==========================================

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        Console console = System.console();

        printHeader("WELCOME TO THE ENTERPRISE ADMINISTRATOR PORTAL");
        System.out.println("System Version : 2.4.0 (LTS)");
        System.out.println("Security Engine: PBKDF2-HMAC-SHA256 with Cryptographic Salt");
        System.out.println("Access Policy  : Role-Based Access Control (RBAC)");
        System.out.println();
        System.out.println("Pre-configured Accounts for Testing:");
        System.out.println("  1. Administrator  : Username: admin       | Password: Admin@1234!");
        System.out.println("  2. Super Admin    : Username: superadmin  | Password: SuperSecure2026#");
        System.out.println("  3. Standard User  : Username: johndoe     | Password: UserPass@2026  (Access Denied)");
        System.out.println("--------------------------------------------------------------------------------");

        boolean running = true;
        while (running) {
            System.out.println("\n--- Portal Gateway ---");
            System.out.println("1. Login to Administrator Portal");
            System.out.println("2. View Demo Account Information");
            System.out.println("3. Exit System");
            System.out.print("Select an option (1-3): ");

            String choice = readLine(scanner);
            if (choice == null) {
                System.out.println("\nInput stream closed. Exiting portal.");
                break;
            }

            switch (choice.trim()) {
                case "1":
                    handleLoginFlow(scanner, console);
                    break;
                case "2":
                    displayDemoCredentials();
                    break;
                case "3":
                    System.out.println("\nExiting Administrator Portal. Goodbye!");
                    logAudit("SYSTEM", "SHUTDOWN", "SUCCESS", "User exited application cleanly.");
                    running = false;
                    break;
                default:
                    System.out.println("[!] Invalid option. Please enter 1, 2, or 3.");
            }
        }

        scanner.close();
    }

    // ==========================================
    // Authentication Logic
    // ==========================================

    private static void handleLoginFlow(Scanner scanner, Console console) {
        printSubHeader("ADMINISTRATOR AUTHENTICATION");

        System.out.print("Enter username: ");
        String username = readLine(scanner);
        if (username == null || username.trim().isEmpty()) {
            System.out.println("[!] Authentication failed: Username cannot be empty.");
            return;
        }
        username = username.trim();

        char[] password = readPassword(scanner, console, "Enter password: ");
        if (password == null || password.length == 0) {
            System.out.println("[!] Authentication failed: Password cannot be empty.");
            return;
        }

        try {
            authenticateAndRoute(username, password, scanner, console);
        } finally {
            SecurityUtils.clearPassword(password);
        }
    }

    /**
     * Performs credential verification, account lockout checks, and RBAC enforcement.
     */
    private static void authenticateAndRoute(String username, char[] password, Scanner scanner, Console console) {
        User user = userDatabase.get(username);

        // Mitigate user enumeration timing attack by performing dummy hash if user doesn't exist
        if (user == null) {
            byte[] dummySalt = SecurityUtils.generateSalt();
            SecurityUtils.hashPassword(password, dummySalt);
            logAudit(username, "AUTHENTICATION", "FAILURE", "Unknown username provided.");
            System.out.println("\n[X] ACCESS DENIED: Invalid username or password.");
            return;
        }

        // Check if account is locked
        if (user.isLocked()) {
            logAudit(username, "AUTHENTICATION", "FAILURE", "Login rejected; account is locked.");
            System.out.println("\n[X] ACCESS DENIED: Account is LOCKED due to excessive failed attempts.");
            System.out.println("    Please contact a Super Administrator to unlock this account.");
            return;
        }

        // Verify credentials
        boolean isMatch = SecurityUtils.verifyPassword(password, user.getSalt(), user.getPasswordHash());

        if (!isMatch) {
            user.incrementFailedAttempts();
            int remaining = MAX_FAILED_ATTEMPTS - user.getFailedAttempts();

            if (user.getFailedAttempts() >= MAX_FAILED_ATTEMPTS) {
                user.setLocked(true);
                logAudit(username, "ACCOUNT_LOCKOUT", "WARNING", "Account locked after " + MAX_FAILED_ATTEMPTS + " consecutive failed attempts.");
                System.out.println("\n[X] ACCESS DENIED: Invalid credentials.");
                System.out.println("[!] SECURITY ALERT: Account '" + username + "' has been LOCKED due to " + MAX_FAILED_ATTEMPTS + " consecutive failed attempts.");
            } else {
                logAudit(username, "AUTHENTICATION", "FAILURE", "Incorrect password. Attempt " + user.getFailedAttempts() + "/" + MAX_FAILED_ATTEMPTS);
                System.out.println("\n[X] ACCESS DENIED: Invalid username or password.");
                System.out.println("    Warning: " + remaining + " attempt(s) remaining before account lockout.");
            }
            return;
        }

        // Credentials valid; verify administrative role
        if (!user.getRole().isAdmin()) {
            logAudit(username, "AUTHORIZATION", "DENIED", "Valid credentials, but user role '" + user.getRole().getDisplayName() + "' lacks admin privileges.");
            System.out.println("\n[!] AUTHENTICATION SUCCESSFUL, BUT ACCESS TO ADMIN PORTAL IS DENIED.");
            System.out.println("    Role '" + user.getRole().getDisplayName() + "' does not have administrative privileges.");
            System.out.println("    Admin-level functionality is restricted to administrators only.");
            return;
        }

        // Authentication & Authorization successful
        user.resetFailedAttempts();
        user.setLastLogin(LocalDateTime.now());
        logAudit(username, "AUTHENTICATION", "SUCCESS", "User authenticated with role " + user.getRole().name());

        System.out.println("\n================================================================================");
        System.out.println(" [+] AUTHENTICATION SUCCESSFUL: ACCESS GRANTED");
        System.out.println(" Welcome, " + user.getUsername() + " (" + user.getRole().getDisplayName() + ")!");
        System.out.println(" Last Login: " + (user.getLastLogin() != null ? user.getLastLogin().format(DATE_FORMATTER) : "First Session"));
        System.out.println("================================================================================");

        // Grant access to administrative functionality
        runAdminSession(user, scanner, console);
    }

    // ==========================================
    // Administrator-Level Functionality
    // ==========================================

    private static void runAdminSession(User currentUser, Scanner scanner, Console console) {
        boolean inSession = true;

        while (inSession) {
            printSubHeader("ADMINISTRATOR CONTROL PANEL - LOGGED IN AS: " + currentUser.getUsername().toUpperCase());
            if (maintenanceMode) {
                System.out.println("[!] SYSTEM NOTICE: Portal is currently in MAINTENANCE MODE.");
            }
            System.out.println("1. User Management (View, Create, Lock/Unlock, Delete Users)");
            System.out.println("2. System Health & Diagnostics");
            System.out.println("3. Security Audit Logs (View & Export)");
            System.out.println("4. System Configuration & Maintenance");
            System.out.println("5. Change My Administrator Password");
            System.out.println("6. Logout / Terminate Session");
            System.out.print("Select an admin option (1-6): ");

            String option = readLine(scanner);
            if (option == null) {
                System.out.println("\nSession disconnected.");
                break;
            }

            switch (option.trim()) {
                case "1":
                    handleUserManagement(currentUser, scanner, console);
                    break;
                case "2":
                    displaySystemDiagnostics(currentUser);
                    break;
                case "3":
                    handleAuditLogs(currentUser, scanner);
                    break;
                case "4":
                    handleSystemConfiguration(currentUser, scanner);
                    break;
                case "5":
                    handleChangeAdminPassword(currentUser, scanner, console);
                    break;
                case "6":
                    logAudit(currentUser.getUsername(), "LOGOUT", "SUCCESS", "Administrator initiated clean logout.");
                    System.out.println("\n[+] Administrator session terminated. Logged out successfully.");
                    inSession = false;
                    break;
                default:
                    System.out.println("[!] Invalid choice. Please choose an option from 1 to 6.");
            }
        }
    }

    // --- Admin Function 1: User Management ---

    private static void handleUserManagement(User currentUser, Scanner scanner, Console console) {
        boolean managing = true;
        while (managing) {
            printSubHeader("USER MANAGEMENT MODULE");
            System.out.println("1. List All Registered Users");
            System.out.println("2. Register New User / Administrator");
            System.out.println("3. Lock / Unlock User Account");
            System.out.println("4. Reset User Password");
            System.out.println("5. Delete User Account");
            System.out.println("6. Return to Main Admin Menu");
            System.out.print("Enter choice (1-6): ");

            String choice = readLine(scanner);
            if (choice == null) return;

            switch (choice.trim()) {
                case "1":
                    listAllUsers();
                    break;
                case "2":
                    registerNewUser(currentUser, scanner, console);
                    break;
                case "3":
                    toggleAccountLock(currentUser, scanner);
                    break;
                case "4":
                    resetUserPasswordByAdmin(currentUser, scanner, console);
                    break;
                case "5":
                    deleteUserAccount(currentUser, scanner);
                    break;
                case "6":
                    managing = false;
                    break;
                default:
                    System.out.println("[!] Invalid option. Please select 1-6.");
            }
        }
    }

    private static void listAllUsers() {
        printSubHeader("REGISTERED USERS DIRECTORY");
        System.out.printf("%-15s | %-22s | %-10s | %-16s | %-20s%n",
                "Username", "Role", "Status", "Failed Attempts", "Last Login");
        System.out.println("---------------------------------------------------------------------------------------------");
        for (User user : userDatabase.values()) {
            String status = user.isLocked() ? "LOCKED" : "ACTIVE";
            String lastLoginStr = (user.getLastLogin() != null)
                    ? user.getLastLogin().format(DATE_FORMATTER)
                    : "Never";
            System.out.printf("%-15s | %-22s | %-10s | %-16d | %-20s%n",
                    user.getUsername(),
                    user.getRole().getDisplayName(),
                    status,
                    user.getFailedAttempts(),
                    lastLoginStr);
        }
        System.out.println("Total Accounts: " + userDatabase.size());
    }

    private static void registerNewUser(User currentUser, Scanner scanner, Console console) {
        printSubHeader("CREATE NEW ACCOUNT");
        System.out.print("Enter new username (alphanumeric, 3-20 chars): ");
        String newUsername = readLine(scanner);
        if (newUsername == null) return;
        newUsername = newUsername.trim();

        if (!newUsername.matches("^[a-zA-Z0-9_-]{3,20}$")) {
            System.out.println("[!] Error: Username must be 3-20 alphanumeric characters or underscores/dashes.");
            return;
        }

        if (userDatabase.containsKey(newUsername)) {
            System.out.println("[!] Error: User '" + newUsername + "' already exists.");
            return;
        }

        char[] newPassword = readPassword(scanner, console, "Enter new password (min 8 chars): ");
        if (newPassword == null) return;

        if (newPassword.length < 8) {
            System.out.println("[!] Error: Password must be at least 8 characters long.");
            SecurityUtils.clearPassword(newPassword);
            return;
        }

        char[] confirmPassword = readPassword(scanner, console, "Confirm new password: ");
        if (confirmPassword == null || !Arrays.equals(newPassword, confirmPassword)) {
            System.out.println("[!] Error: Passwords do not match.");
            SecurityUtils.clearPassword(newPassword);
            SecurityUtils.clearPassword(confirmPassword);
            return;
        }
        SecurityUtils.clearPassword(confirmPassword);

        System.out.println("Select Account Role:");
        System.out.println("  1. Standard User (Non-admin)");
        System.out.println("  2. Administrator (Full admin portal access)");
        System.out.println("  3. Super Administrator (Elevated privileges)");
        System.out.print("Select role (1-3, default 1): ");
        String roleChoice = readLine(scanner);
        Role role = Role.STANDARD_USER;
        if ("2".equals(roleChoice != null ? roleChoice.trim() : "")) {
            role = Role.ADMIN;
        } else if ("3".equals(roleChoice != null ? roleChoice.trim() : "")) {
            if (currentUser.getRole() != Role.SUPER_ADMIN) {
                System.out.println("[!] Only a Super Administrator can assign the Super Administrator role.");
                System.out.println("    Defaulting to standard Administrator role.");
                role = Role.ADMIN;
            } else {
                role = Role.SUPER_ADMIN;
            }
        }

        createAccountInternal(newUsername, newPassword, role);
        logAudit(currentUser.getUsername(), "CREATE_USER", "SUCCESS", "Created user '" + newUsername + "' with role " + role.name());
        System.out.println("[+] User '" + newUsername + "' successfully created with role: " + role.getDisplayName());
    }

    private static void toggleAccountLock(User currentUser, Scanner scanner) {
        printSubHeader("LOCK / UNLOCK ACCOUNT");
        System.out.print("Enter username to lock/unlock: ");
        String targetUsername = readLine(scanner);
        if (targetUsername == null) return;
        targetUsername = targetUsername.trim();

        User target = userDatabase.get(targetUsername);
        if (target == null) {
            System.out.println("[!] User not found.");
            return;
        }

        if (target.getUsername().equalsIgnoreCase(currentUser.getUsername())) {
            System.out.println("[!] Operation rejected: You cannot lock your own account.");
            return;
        }

        boolean newLockedState = !target.isLocked();
        target.setLocked(newLockedState);

        String stateStr = newLockedState ? "LOCKED" : "UNLOCKED";
        logAudit(currentUser.getUsername(), "CHANGE_LOCK_STATUS", "SUCCESS",
                "Account '" + targetUsername + "' status changed to " + stateStr);
        System.out.println("[+] Account '" + targetUsername + "' is now " + stateStr + ".");
    }

    private static void resetUserPasswordByAdmin(User currentUser, Scanner scanner, Console console) {
        printSubHeader("ADMINISTRATIVE PASSWORD RESET");
        System.out.print("Enter username to reset password: ");
        String targetUsername = readLine(scanner);
        if (targetUsername == null) return;
        targetUsername = targetUsername.trim();

        User target = userDatabase.get(targetUsername);
        if (target == null) {
            System.out.println("[!] User not found.");
            return;
        }

        char[] newPass = readPassword(scanner, console, "Enter new password for " + targetUsername + " (min 8 chars): ");
        if (newPass == null) return;

        if (newPass.length < 8) {
            System.out.println("[!] Password must be at least 8 characters.");
            SecurityUtils.clearPassword(newPass);
            return;
        }

        byte[] newSalt = SecurityUtils.generateSalt();
        byte[] newHash = SecurityUtils.hashPassword(newPass, newSalt);
        SecurityUtils.clearPassword(newPass);

        target.setPassword(newHash, newSalt);
        target.setLocked(false);
        logAudit(currentUser.getUsername(), "PASSWORD_RESET", "SUCCESS", "Password reset for user '" + targetUsername + "'");
        System.out.println("[+] Password for user '" + targetUsername + "' has been successfully reset.");
    }

    private static void deleteUserAccount(User currentUser, Scanner scanner) {
        printSubHeader("DELETE USER ACCOUNT");
        System.out.print("Enter username to permanently delete: ");
        String targetUsername = readLine(scanner);
        if (targetUsername == null) return;
        targetUsername = targetUsername.trim();

        if (targetUsername.equalsIgnoreCase(currentUser.getUsername())) {
            System.out.println("[!] Error: You cannot delete your own account while logged in.");
            return;
        }

        User target = userDatabase.get(targetUsername);
        if (target == null) {
            System.out.println("[!] User '" + targetUsername + "' not found.");
            return;
        }

        System.out.print("Are you sure you want to permanently delete user '" + targetUsername + "'? (yes/no): ");
        String confirm = readLine(scanner);
        if (confirm != null && "yes".equalsIgnoreCase(confirm.trim())) {
            userDatabase.remove(targetUsername);
            logAudit(currentUser.getUsername(), "DELETE_USER", "SUCCESS", "Deleted user '" + targetUsername + "'");
            System.out.println("[+] User '" + targetUsername + "' has been permanently deleted.");
        } else {
            System.out.println("[i] Deletion canceled.");
        }
    }

    // --- Admin Function 2: System Health & Diagnostics ---

    private static void displaySystemDiagnostics(User currentUser) {
        printSubHeader("SYSTEM HEALTH & RUNTIME DIAGNOSTICS");
        logAudit(currentUser.getUsername(), "VIEW_DIAGNOSTICS", "INFO", "Inspected system diagnostics.");

        Runtime runtime = Runtime.getRuntime();
        long maxMemoryMB = runtime.maxMemory() / (1024 * 1024);
        long totalMemoryMB = runtime.totalMemory() / (1024 * 1024);
        long freeMemoryMB = runtime.freeMemory() / (1024 * 1024);
        long usedMemoryMB = totalMemoryMB - freeMemoryMB;

        ThreadMXBean threadBean = ManagementFactory.getThreadMXBean();
        Duration uptime = Duration.between(START_TIME, Instant.now());
        long hours = uptime.toHours();
        long minutes = uptime.toMinutesPart();
        long seconds = uptime.toSecondsPart();

        System.out.println("Operating System       : " + System.getProperty("os.name") + " (" + System.getProperty("os.arch") + ")");
        System.out.println("Java Virtual Machine   : " + System.getProperty("java.vm.name") + " v" + System.getProperty("java.version"));
        System.out.println("Java Vendor            : " + System.getProperty("java.vendor"));
        System.out.println("Available CPU Cores    : " + runtime.availableProcessors());
        System.out.println("Active Thread Count    : " + threadBean.getThreadCount());
        System.out.printf("Portal Uptime          : %02d hours, %02d minutes, %02d seconds%n", hours, minutes, seconds);
        System.out.println("--------------------------------------------------------------------------------");
        System.out.printf("Memory - Allocated     : %d MB%n", totalMemoryMB);
        System.out.printf("Memory - Used          : %d MB%n", usedMemoryMB);
        System.out.printf("Memory - Free          : %d MB%n", freeMemoryMB);
        System.out.printf("Memory - Maximum Cap   : %d MB%n", maxMemoryMB);

        int barLength = 20;
        int usedBars = (int) (((double) usedMemoryMB / Math.max(1, totalMemoryMB)) * barLength);
        StringBuilder bar = new StringBuilder("[");
        for (int i = 0; i < barLength; i++) {
            bar.append(i < usedBars ? "#" : "-");
        }
        bar.append("]");
        System.out.println("Memory Utilization     : " + bar + " " + String.format("%.1f%%", ((double) usedMemoryMB / Math.max(1, totalMemoryMB)) * 100));
        System.out.println("Maintenance Status     : " + (maintenanceMode ? "MAINTENANCE ACTIVE" : "NORMAL OPERATION"));
    }

    // --- Admin Function 3: Security Audit Logs ---

    private static void handleAuditLogs(User currentUser, Scanner scanner) {
        printSubHeader("SECURITY AUDIT LOGS");
        System.out.println("1. View Recent Audit Logs (Screen)");
        System.out.println("2. Export Audit Logs to Text File");
        System.out.println("3. Back to Admin Menu");
        System.out.print("Select an option (1-3): ");

        String choice = readLine(scanner);
        if (choice == null) return;

        switch (choice.trim()) {
            case "1":
                displayAuditLogs();
                break;
            case "2":
                exportAuditLogsToFile(currentUser, scanner);
                break;
            case "3":
                break;
            default:
                System.out.println("[!] Invalid option.");
        }
    }

    private static void displayAuditLogs() {
        printSubHeader("RECORDED SECURITY AUDIT LOGS (Total: " + auditLogs.size() + ")");
        if (auditLogs.isEmpty()) {
            System.out.println("(No audit logs recorded)");
            return;
        }

        int limit = Math.min(25, auditLogs.size());
        System.out.println("Showing most recent " + limit + " log entries:");
        System.out.println("---------------------------------------------------------------------------------------------------------");
        for (int i = auditLogs.size() - limit; i < auditLogs.size(); i++) {
            System.out.println(auditLogs.get(i));
        }
        System.out.println("---------------------------------------------------------------------------------------------------------");
    }

    private static void exportAuditLogsToFile(User currentUser, Scanner scanner) {
        System.out.print("Enter export filename (default: audit_report.log): ");
        String filename = readLine(scanner);
        if (filename == null) return;
        filename = filename.trim();
        if (filename.isEmpty()) {
            filename = "audit_report.log";
        }

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename))) {
            writer.write("========================================================================\n");
            writer.write("ENTERPRISE ADMINISTRATOR PORTAL - SECURITY AUDIT LOG EXPORT\n");
            writer.write("Exported at : " + LocalDateTime.now().format(DATE_FORMATTER) + "\n");
            writer.write("Exported by : " + currentUser.getUsername() + "\n");
            writer.write("Total Logs  : " + auditLogs.size() + "\n");
            writer.write("========================================================================\n\n");

            for (AuditLogEntry entry : auditLogs) {
                writer.write(entry.toString());
                writer.newLine();
            }
            writer.flush();
            System.out.println("[+] Successfully exported " + auditLogs.size() + " audit log entries to '" + filename + "'.");
            logAudit(currentUser.getUsername(), "EXPORT_AUDIT_LOGS", "SUCCESS", "Exported logs to " + filename);
        } catch (IOException e) {
            System.out.println("[!] Failed to export logs: " + e.getMessage());
            logAudit(currentUser.getUsername(), "EXPORT_AUDIT_LOGS", "FAILURE", "Export error: " + e.getMessage());
        }
    }

    // --- Admin Function 4: System Configuration & Maintenance ---

    private static void handleSystemConfiguration(User currentUser, Scanner scanner) {
        printSubHeader("SYSTEM CONFIGURATION & MAINTENANCE");
        System.out.println("Current Settings:");
        System.out.println("  * Maintenance Mode         : " + (maintenanceMode ? "ENABLED (Locked for non-admins)" : "DISABLED"));
        System.out.println("  * Max Failed Login Limit   : " + MAX_FAILED_ATTEMPTS + " attempts");
        System.out.println("  * Password Hash Algorithm  : PBKDF2WithHmacSHA256 (65,536 iterations, 256-bit)");
        System.out.println("--------------------------------------------------------------------------------");
        System.out.println("1. Toggle Maintenance Mode (" + (maintenanceMode ? "Turn OFF" : "Turn ON") + ")");
        System.out.println("2. Trigger Garbage Collection Simulation");
        System.out.println("3. Return to Admin Menu");
        System.out.print("Select an option (1-3): ");

        String choice = readLine(scanner);
        if (choice == null) return;

        switch (choice.trim()) {
            case "1":
                maintenanceMode = !maintenanceMode;
                String status = maintenanceMode ? "ACTIVATED" : "DEACTIVATED";
                logAudit(currentUser.getUsername(), "TOGGLE_MAINTENANCE", "SUCCESS", "Maintenance mode " + status);
                System.out.println("[+] Maintenance Mode has been " + status + ".");
                break;
            case "2":
                long beforeMemory = (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / (1024 * 1024);
                System.gc();
                long afterMemory = (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / (1024 * 1024);
                logAudit(currentUser.getUsername(), "MEMORY_CLEANUP", "SUCCESS", "GC triggered. Memory before: " + beforeMemory + "MB, after: " + afterMemory + "MB");
                System.out.println("[+] Garbage collection requested. Memory delta: " + (beforeMemory - afterMemory) + " MB reclaimed.");
                break;
            case "3":
                break;
            default:
                System.out.println("[!] Invalid option.");
        }
    }

    // --- Admin Function 5: Change Own Password ---

    private static void handleChangeAdminPassword(User currentUser, Scanner scanner, Console console) {
        printSubHeader("CHANGE ADMINISTRATOR PASSWORD");

        char[] currentPass = readPassword(scanner, console, "Enter current password: ");
        if (currentPass == null) return;

        boolean valid = SecurityUtils.verifyPassword(currentPass, currentUser.getSalt(), currentUser.getPasswordHash());
        SecurityUtils.clearPassword(currentPass);

        if (!valid) {
            System.out.println("[!] Verification failed: Current password is incorrect.");
            logAudit(currentUser.getUsername(), "PASSWORD_CHANGE", "FAILURE", "Current password check failed.");
            return;
        }

        char[] newPass = readPassword(scanner, console, "Enter new password (min 8 chars): ");
        if (newPass == null) return;

        if (newPass.length < 8) {
            System.out.println("[!] Password must be at least 8 characters long.");
            SecurityUtils.clearPassword(newPass);
            return;
        }

        char[] confirmPass = readPassword(scanner, console, "Confirm new password: ");
        if (confirmPass == null || !Arrays.equals(newPass, confirmPass)) {
            System.out.println("[!] Passwords do not match.");
            SecurityUtils.clearPassword(newPass);
            SecurityUtils.clearPassword(confirmPass);
            return;
        }
        SecurityUtils.clearPassword(confirmPass);

        byte[] newSalt = SecurityUtils.generateSalt();
        byte[] newHash = SecurityUtils.hashPassword(newPass, newSalt);
        SecurityUtils.clearPassword(newPass);

        currentUser.setPassword(newHash, newSalt);
        logAudit(currentUser.getUsername(), "PASSWORD_CHANGE", "SUCCESS", "Administrator successfully changed their password.");
        System.out.println("[+] Your administrator password has been updated successfully.");
    }

    // ==========================================
    // Helper & Input Methods
    // ==========================================

    private static void displayDemoCredentials() {
        printSubHeader("DEFAULT DEMO CREDENTIALS");
        System.out.println("Use these accounts to test authentication and role enforcement:");
        System.out.println();
        System.out.println("  1. Standard Administrator:");
        System.out.println("     * Username: admin");
        System.out.println("     * Password: Admin@1234!");
        System.out.println("     * Role    : Administrator (Grants admin portal access)");
        System.out.println();
        System.out.println("  2. Super Administrator:");
        System.out.println("     * Username: superadmin");
        System.out.println("     * Password: SuperSecure2026#");
        System.out.println("     * Role    : Super Administrator (Full access + can grant super admin role)");
        System.out.println();
        System.out.println("  3. Standard User (Non-Admin):");
        System.out.println("     * Username: johndoe");
        System.out.println("     * Password: UserPass@2026");
        System.out.println("     * Role    : Standard User (Access is DENIED to admin portal)");
        System.out.println();
        System.out.println("Security feature test: Entering the wrong password 3 times will lock the account.");
    }

    private static void printHeader(String title) {
        System.out.println("\n================================================================================");
        System.out.println("                    " + title);
        System.out.println("================================================================================");
    }

    private static void printSubHeader(String title) {
        System.out.println("\n--- " + title + " ---");
    }

    private static String readLine(Scanner scanner) {
        try {
            if (scanner.hasNextLine()) {
                return scanner.nextLine();
            }
        } catch (Exception ignored) {}
        return null;
    }

    /**
     * Reads a password securely. Uses System.console().readPassword() when available
     * to prevent shoulder-surfing, falling back to Scanner when running in piped
     * or non-interactive environments.
     */
    private static char[] readPassword(Scanner scanner, Console console, String prompt) {
        if (console != null) {
            return console.readPassword(prompt);
        } else {
            System.out.print(prompt);
            try {
                if (scanner.hasNextLine()) {
                    return scanner.nextLine().toCharArray();
                }
            } catch (Exception ignored) {}
            return null;
        }
    }
}
