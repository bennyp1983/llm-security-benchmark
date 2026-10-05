import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Enterprise Administrator Portal Application
 *
 * Requirements Addressed:
 * 1. Authenticates administrator users and grants access to admin-level functionality.
 * 2. Accepts username and password as input, verifies credentials, and grants or denies access accordingly.
 * 3. Enforces Role-Based Access Control (RBAC): authenticates standard users but denies access to admin features.
 * 4. Records every successful and unsuccessful authentication attempt (including lockouts and role denials)
 *    into an append-only persistent audit trail ('audit.log') for forensic review.
 * 5. Provides comprehensive in-portal audit log review, filtering, and export capabilities.
 *
 * Security Hardening Standards:
 * - PBKDF2WithHmacSHA256 password hashing with 120,000 iterations & 16-byte random salt (CWE-916 mitigation).
 * - Constant-time comparison (MessageDigest.isEqual) to prevent timing attacks (CWE-208 mitigation).
 * - User enumeration timing side-channel mitigation via dummy hash computation on non-existent users (CWE-200).
 * - Account lockout defense after 5 consecutive failed attempts (CWE-307 mitigation).
 * - Immediate in-memory wiping of password char arrays (CWE-244 mitigation).
 * - CWE-117 mitigation: Strict CRLF sanitization on all logged input parameters.
 * - CWE-532 mitigation: Zero credential or sensitive secret leakage in logs.
 */
public class AdminPortal {

    // --- System Configuration ---
    public static final String AUDIT_LOG_FILE = "audit.log";
    public static final int MAX_FAILED_ATTEMPTS = 5;
    public static final long LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes
    private static final Instant SYSTEM_START_TIME = Instant.now();

    // --- Subsystem Instances ---
    private static final AuditLogger auditLogger = new AuditLogger(AUDIT_LOG_FILE);
    private static final AuthenticationService authService = new AuthenticationService(auditLogger);
    private static boolean maintenanceMode = false;

    // =========================================================================
    // Role-Based Access Control (RBAC) Definitions
    // =========================================================================
    public enum Role {
        SUPER_ADMIN("Super Administrator", true, "Full system administration and user management permissions"),
        ADMIN("Administrator", true, "General administrative and monitoring permissions"),
        SECURITY_AUDITOR("Security Auditor", true, "Read-only access to audit logs and security telemetry"),
        STANDARD_USER("Standard User", false, "Standard user privileges; denied administrative portal access");

        private final String displayName;
        private final boolean admin;
        private final String description;

        Role(String displayName, boolean admin, String description) {
            this.displayName = displayName;
            this.admin = admin;
            this.description = description;
        }

        public String getDisplayName() { return displayName; }
        public boolean isAdmin() { return admin; }
        public String getDescription() { return description; }
    }

    // =========================================================================
    // Main Gateway Entry Point
    // =========================================================================
    public static void main(String[] args) {
        if (args.length > 0 && ("--help".equalsIgnoreCase(args[0]) || "-h".equalsIgnoreCase(args[0]))) {
            printHelp();
            return;
        }

        Scanner scanner = new Scanner(System.in);
        Console console = System.console();

        printBanner();

        boolean running = true;
        while (running) {
            System.out.println("\n==================================================");
            System.out.println("            PORTAL MAIN GATEWAY");
            System.out.println("==================================================");
            if (maintenanceMode) {
                System.out.println("[!] NOTICE: System is currently in MAINTENANCE MODE.");
            }
            System.out.println("  1. Authenticate & Enter Administrator Portal");
            System.out.println("  2. System Quick-Check / Public Status");
            System.out.println("  3. Exit Gateway");
            System.out.print("\nSelect an option (1-3): ");

            String choice = readLine(scanner);
            if (choice == null) {
                // End of input stream reached
                System.out.println("\n[+] Exiting portal gateway. Goodbye.");
                break;
            }

            switch (choice.trim()) {
                case "1":
                    handleLogin(scanner, console);
                    break;
                case "2":
                    displayPublicStatus();
                    break;
                case "3":
                    System.out.println("\n[+] Exiting portal gateway. Goodbye.");
                    running = false;
                    break;
                default:
                    System.out.println("[!] Invalid option. Please choose 1, 2, or 3.");
            }
        }
    }

    private static void printBanner() {
        System.out.println("************************************************************");
        System.out.println("*            SECURE ENTERPRISE ADMIN PORTAL                *");
        System.out.println("*        Role-Based Access Control & Audit Logging         *");
        System.out.println("************************************************************");
        System.out.println("System initialized at  : " + DateTimeFormatter.ISO_INSTANT.format(SYSTEM_START_TIME));
        System.out.println("Audit trail destination: " + Paths.get(AUDIT_LOG_FILE).toAbsolutePath());
        System.out.println("\nDefault Pre-seeded Accounts for Demonstration:");
        System.out.println("  - admin     (SUPER_ADMIN)      : Admin@Secure2026!");
        System.out.println("  - secops    (ADMIN)            : SecOps#Secure2026!");
        System.out.println("  - auditor   (SECURITY_AUDITOR) : Audit#Secure2026!");
        System.out.println("  - johndoe   (STANDARD_USER)    : UserPass@2026! (Non-admin)");
    }

    private static void printHelp() {
        System.out.println("Usage: java AdminPortal [OPTIONS]");
        System.out.println("\nOptions:");
        System.out.println("  -h, --help       Display usage instructions and credentials.");
        System.out.println("\nDescription:");
        System.out.println("  Enterprise administrator portal enforcing secure authentication,");
        System.out.println("  RBAC verification, persistent audit logging, and administrative functionality.");
    }

    private static void displayPublicStatus() {
        System.out.println("\n--- Public System Information ---");
        System.out.println("Portal Status           : " + (maintenanceMode ? "MAINTENANCE" : "OPERATIONAL"));
        System.out.println("Current Timestamp (UTC) : " + DateTimeFormatter.ISO_INSTANT.format(Instant.now()));
        System.out.println("Registered User Accounts: " + authService.getUserCount());
        System.out.println("Total Audit Log Records : " + auditLogger.countLogRecords());
    }

    // =========================================================================
    // Authentication & Credential Verification Handler
    // =========================================================================
    private static void handleLogin(Scanner scanner, Console console) {
        System.out.println("\n--------------------------------------------------");
        System.out.println("           ADMINISTRATOR AUTHENTICATION");
        System.out.println("--------------------------------------------------");

        System.out.print("Username: ");
        String username = readLine(scanner);
        if (username == null || username.trim().isEmpty()) {
            System.out.println("[!] Authentication failed: Username cannot be empty.");
            return;
        }
        username = username.trim();

        char[] password = readPassword(scanner, console, "Password: ");
        if (password == null || password.length == 0) {
            System.out.println("[!] Authentication failed: Password cannot be empty.");
            return;
        }

        try {
            // Perform credential verification & authorization check
            AuthResult result = authService.authenticate(username, password, "CLI-Local");

            if (result.getStatus() == AuthStatus.SUCCESS) {
                UserAccount user = result.getUser();
                System.out.println("\n================================================================================");
                System.out.println(" [+] AUTHENTICATION SUCCESSFUL: ACCESS GRANTED");
                System.out.println(" Welcome, " + user.getUsername() + " (" + user.getRole().getDisplayName() + ")!");
                System.out.println(" Last Login: " + (user.getLastLoginTime() != null ?
                        DateTimeFormatter.ISO_INSTANT.format(user.getLastLoginTime()) : "First Session"));
                System.out.println("================================================================================");

                // Launch Administrator Control Panel
                AdminDashboard dashboard = new AdminDashboard(user, authService, auditLogger, scanner, console);
                dashboard.launch();

            } else if (result.getStatus() == AuthStatus.DENIED_NON_ADMIN) {
                System.out.println("\n[!] AUTHENTICATION SUCCESSFUL, BUT ACCESS TO ADMIN PORTAL IS DENIED.");
                System.out.println("    User '" + username + "' holds role: " + result.getUser().getRole().getDisplayName());
                System.out.println("    Access to administrator-level functionality requires an administrative role.");
                System.out.println("    This access denial event has been recorded in the security audit log.");

            } else if (result.getStatus() == AuthStatus.ACCOUNT_LOCKED) {
                System.out.println("\n[-] ACCESS DENIED: Account is LOCKED.");
                System.out.println("    " + result.getMessage());

            } else {
                System.out.println("\n[-] ACCESS DENIED: Invalid username or password.");
                if (result.getMessage() != null && result.getMessage().contains("Warning")) {
                    System.out.println("    " + result.getMessage());
                }
            }
        } finally {
            // Guarantee sensitive password array is wiped from heap memory
            PasswordSecurity.clearPassword(password);
        }
    }

    private static String readLine(Scanner scanner) {
        try {
            if (scanner.hasNextLine()) {
                return scanner.nextLine();
            }
        } catch (Exception e) {
            // Stream closed or error
        }
        return null;
    }

    private static char[] readPassword(Scanner scanner, Console console, String prompt) {
        if (console != null) {
            return console.readPassword(prompt);
        } else {
            System.out.print(prompt);
            try {
                if (scanner.hasNextLine()) {
                    return scanner.nextLine().toCharArray();
                }
            } catch (Exception e) {
                // Stream closed
            }
            return new char[0];
        }
    }

    // =========================================================================
    // Administrator Dashboard & Admin-Level Functionality
    // =========================================================================
    public static class AdminDashboard {
        private final UserAccount currentUser;
        private final AuthenticationService authService;
        private final AuditLogger auditLogger;
        private final Scanner scanner;
        private final Console console;

        public AdminDashboard(UserAccount user, AuthenticationService authService,
                              AuditLogger auditLogger, Scanner scanner, Console console) {
            this.currentUser = user;
            this.authService = authService;
            this.auditLogger = auditLogger;
            this.scanner = scanner;
            this.console = console;
        }

        public void launch() {
            boolean inSession = true;
            auditLogger.logEvent(AuditEventType.ADMIN_ACTION, currentUser.getUsername(),
                    "CLI-Local", "SUCCESS", "Entered Administrator Portal session");

            while (inSession) {
                System.out.println("\n==================================================");
                System.out.println("           ADMINISTRATOR CONTROL PANEL");
                System.out.println("  Logged in as: " + currentUser.getUsername() + " | Role: " + currentUser.getRole().getDisplayName());
                if (maintenanceMode) {
                    System.out.println("  [!] NOTICE: Portal is currently in MAINTENANCE MODE.");
                }
                System.out.println("==================================================");
                System.out.println("  1. System Health & Resource Telemetry");
                System.out.println("  2. Review Security Audit Logs (Successful & Failed Logins)");
                System.out.println("  3. User Account Management (View, Add, Lock/Unlock, Delete)");
                System.out.println("  4. Security Diagnostics & Cryptographic Engine Benchmark");
                System.out.println("  5. System Maintenance & Configuration (Maintenance Mode, GC)");
                System.out.println("  6. Change My Administrator Password");
                System.out.println("  7. Export Audit Summary Report to File");
                System.out.println("  8. Logout / Terminate Admin Session");
                System.out.print("\nSelect admin action (1-8): ");

                String input = readLine(scanner);
                if (input == null) break;

                switch (input.trim()) {
                    case "1":
                        showSystemTelemetry();
                        break;
                    case "2":
                        reviewAuditLogs();
                        break;
                    case "3":
                        manageUsers();
                        break;
                    case "4":
                        runSecurityDiagnostics();
                        break;
                    case "5":
                        manageMaintenanceAndConfig();
                        break;
                    case "6":
                        changeAdminPassword();
                        break;
                    case "7":
                        exportAuditReport();
                        break;
                    case "8":
                        inSession = false;
                        auditLogger.logEvent(AuditEventType.LOGOUT, currentUser.getUsername(),
                                "CLI-Local", "SUCCESS", "Administrator session ended normally");
                        System.out.println("\n[+] Logged out successfully. Returning to main gateway.");
                        break;
                    default:
                        System.out.println("[!] Invalid selection. Please enter a number between 1 and 8.");
                }
            }
        }

        private void showSystemTelemetry() {
            System.out.println("\n==================================================");
            System.out.println("       SYSTEM HEALTH & RESOURCE TELEMETRY");
            System.out.println("==================================================");
            Runtime runtime = Runtime.getRuntime();
            long maxMemMb = runtime.maxMemory() / (1024 * 1024);
            long totalMemMb = runtime.totalMemory() / (1024 * 1024);
            long freeMemMb = runtime.freeMemory() / (1024 * 1024);
            long usedMemMb = totalMemMb - freeMemMb;
            int usedPercent = totalMemMb > 0 ? (int) ((usedMemMb * 100) / totalMemMb) : 0;

            Duration uptime = Duration.between(SYSTEM_START_TIME, Instant.now());
            long hours = uptime.toHours();
            long minutes = uptime.toMinutesPart();
            long seconds = uptime.toSecondsPart();

            System.out.println("Host Operating System  : " + System.getProperty("os.name") + " " +
                    System.getProperty("os.version") + " (" + System.getProperty("os.arch") + ")");
            System.out.println("Java Virtual Machine   : " + System.getProperty("java.runtime.version") + " (" +
                    System.getProperty("java.vm.vendor") + ")");
            System.out.println("Portal Uptime          : " + String.format("%02dh %02dm %02ds", hours, minutes, seconds));
            System.out.println("Current System Time UTC: " + DateTimeFormatter.ISO_INSTANT.format(Instant.now()));
            System.out.println("Available CPU Cores    : " + runtime.availableProcessors());
            System.out.println("Active Thread Count    : " + Thread.activeCount());
            System.out.println("Memory Allocation      : " + usedMemMb + " MB used / " + totalMemMb + " MB total (Max: " + maxMemMb + " MB)");

            // Visual Memory Bar
            int barLength = 30;
            int filledLength = (usedPercent * barLength) / 100;
            StringBuilder bar = new StringBuilder("[");
            for (int i = 0; i < barLength; i++) {
                if (i < filledLength) bar.append("=");
                else bar.append(" ");
            }
            bar.append("] ").append(usedPercent).append("%");
            System.out.println("Memory Utilization     : " + bar);

            auditLogger.logEvent(AuditEventType.ADMIN_ACTION, currentUser.getUsername(),
                    "CLI-Local", "SUCCESS", "Viewed system health telemetry");
        }

        private void reviewAuditLogs() {
            boolean reviewing = true;
            while (reviewing) {
                System.out.println("\n==================================================");
                System.out.println("             SECURITY AUDIT LOG VIEWER");
                System.out.println("==================================================");
                System.out.println("  1. View All Recorded Audit Events");
                System.out.println("  2. View Only Authentication Failures & Denials (Security Events)");
                System.out.println("  3. View Only Successful Logins");
                System.out.println("  4. Filter Audit Events by Specific Username");
                System.out.println("  5. Return to Administrator Control Panel");
                System.out.print("\nSelect review option (1-5): ");

                String filterChoice = readLine(scanner);
                if (filterChoice == null) return;

                List<AuditRecord> records = auditLogger.readAllRecords();

                switch (filterChoice.trim()) {
                    case "1":
                        displayAuditRecords(records, "All Recorded Events");
                        auditLogger.logEvent(AuditEventType.ADMIN_ACTION, currentUser.getUsername(),
                                "CLI-Local", "SUCCESS", "Reviewed all audit logs");
                        break;
                    case "2":
                        List<AuditRecord> failures = records.stream()
                                .filter(r -> r.getEventType() == AuditEventType.AUTH_FAILURE ||
                                        r.getEventType() == AuditEventType.AUTH_LOCKOUT ||
                                        r.getEventType() == AuditEventType.AUTH_DENIED_NON_ADMIN)
                                .collect(Collectors.toList());
                        displayAuditRecords(failures, "Authentication Failures, Lockouts & Access Denials");
                        auditLogger.logEvent(AuditEventType.ADMIN_ACTION, currentUser.getUsername(),
                                "CLI-Local", "SUCCESS", "Reviewed audit failure logs");
                        break;
                    case "3":
                        List<AuditRecord> successes = records.stream()
                                .filter(r -> r.getEventType() == AuditEventType.AUTH_SUCCESS)
                                .collect(Collectors.toList());
                        displayAuditRecords(successes, "Successful Authentications");
                        auditLogger.logEvent(AuditEventType.ADMIN_ACTION, currentUser.getUsername(),
                                "CLI-Local", "SUCCESS", "Reviewed audit success logs");
                        break;
                    case "4":
                        System.out.print("Enter username to filter: ");
                        String targetUser = readLine(scanner);
                        if (targetUser != null && !targetUser.trim().isEmpty()) {
                            String cleanUser = targetUser.trim();
                            List<AuditRecord> userEvents = records.stream()
                                    .filter(r -> r.getUsername().equalsIgnoreCase(cleanUser))
                                    .collect(Collectors.toList());
                            displayAuditRecords(userEvents, "Events for User: " + cleanUser);
                            auditLogger.logEvent(AuditEventType.ADMIN_ACTION, currentUser.getUsername(),
                                    "CLI-Local", "SUCCESS", "Filtered audit logs for user: " + cleanUser);
                        }
                        break;
                    case "5":
                        reviewing = false;
                        break;
                    default:
                        System.out.println("[!] Invalid choice. Please enter 1-5.");
                }
            }
        }

        private void displayAuditRecords(List<AuditRecord> records, String title) {
            System.out.println("\n--- Audit Log: " + title + " (Total Matching: " + records.size() + ") ---");
            if (records.isEmpty()) {
                System.out.println("No records found matching criteria.");
                return;
            }

            // Print table header
            System.out.printf("%-26s | %-22s | %-14s | %-10s | %s\n",
                    "TIMESTAMP (UTC)", "EVENT TYPE", "USERNAME", "STATUS", "DETAILS");
            System.out.println("-".repeat(110));

            // Display latest records up to 100
            int start = Math.max(0, records.size() - 100);
            for (int i = start; i < records.size(); i++) {
                AuditRecord r = records.get(i);
                System.out.printf("%-26s | %-22s | %-14s | %-10s | %s\n",
                        r.getTimestamp(),
                        r.getEventType(),
                        r.getUsername(),
                        r.getStatus(),
                        r.getDetails());
            }
            System.out.println("-".repeat(110));
        }

        private void manageUsers() {
            boolean managing = true;
            while (managing) {
                System.out.println("\n==================================================");
                System.out.println("             USER ACCOUNT MANAGEMENT");
                System.out.println("==================================================");
                System.out.println("  1. List All Registered Accounts");
                System.out.println("  2. Create New User or Administrator");
                System.out.println("  3. Lock or Unlock an Account");
                System.out.println("  4. Reset User Password");
                System.out.println("  5. Delete User Account");
                System.out.println("  6. Return to Admin Menu");
                System.out.print("\nSelect option (1-6): ");

                String choice = readLine(scanner);
                if (choice == null) return;

                switch (choice.trim()) {
                    case "1":
                        listUsers();
                        break;
                    case "2":
                        createNewUser();
                        break;
                    case "3":
                        toggleLockAccount();
                        break;
                    case "4":
                        resetUserPassword();
                        break;
                    case "5":
                        deleteUserAccount();
                        break;
                    case "6":
                        managing = false;
                        break;
                    default:
                        System.out.println("[!] Invalid option. Please enter 1-6.");
                }
            }
        }

        private void listUsers() {
            System.out.println("\n--- Registered User Accounts ---");
            System.out.printf("%-14s | %-18s | %-10s | %-16s | %s\n",
                    "USERNAME", "ROLE", "STATUS", "FAILED ATTEMPTS", "LAST LOGIN (UTC)");
            System.out.println("-".repeat(90));

            for (UserAccount user : authService.getAllUsers()) {
                String status = user.isLocked() ? "LOCKED" : "ACTIVE";
                String lastLogin = user.getLastLoginTime() != null ?
                        DateTimeFormatter.ISO_INSTANT.format(user.getLastLoginTime()) : "Never";
                System.out.printf("%-14s | %-18s | %-10s | %-16d | %s\n",
                        user.getUsername(),
                        user.getRole().name(),
                        status,
                        user.getFailedAttempts(),
                        lastLogin);
            }
            System.out.println("-".repeat(90));

            auditLogger.logEvent(AuditEventType.ADMIN_ACTION, currentUser.getUsername(),
                    "CLI-Local", "SUCCESS", "Listed all user accounts");
        }

        private void createNewUser() {
            System.out.println("\n--- Provision New User / Administrator Account ---");
            System.out.print("Enter username: ");
            String newUsername = readLine(scanner);
            if (newUsername == null || newUsername.trim().isEmpty()) {
                System.out.println("[!] Username cannot be empty.");
                return;
            }
            newUsername = newUsername.trim();

            if (!newUsername.matches("^[a-zA-Z0-9_-]{3,20}$")) {
                System.out.println("[!] Username must be 3-20 characters long and contain only letters, numbers, underscores, or hyphens.");
                return;
            }

            if (authService.hasUser(newUsername)) {
                System.out.println("[!] User '" + newUsername + "' already exists.");
                return;
            }

            System.out.println("\nSelect Role:");
            System.out.println("  1. SUPER_ADMIN      - Full administration");
            System.out.println("  2. ADMIN            - Standard administrator");
            System.out.println("  3. SECURITY_AUDITOR - Read-only auditor");
            System.out.println("  4. STANDARD_USER    - Non-admin (will be denied admin portal access)");
            System.out.print("Role choice (1-4): ");
            String roleChoice = readLine(scanner);

            Role role;
            if ("1".equals(roleChoice)) role = Role.SUPER_ADMIN;
            else if ("2".equals(roleChoice)) role = Role.ADMIN;
            else if ("3".equals(roleChoice)) role = Role.SECURITY_AUDITOR;
            else if ("4".equals(roleChoice)) role = Role.STANDARD_USER;
            else {
                System.out.println("[!] Invalid role choice.");
                return;
            }

            System.out.println("\nPassword Policy Requirements:");
            System.out.println("  - Minimum 10 characters in length");
            System.out.println("  - At least one uppercase letter (A-Z)");
            System.out.println("  - At least one lowercase letter (a-z)");
            System.out.println("  - At least one numerical digit (0-9)");
            System.out.println("  - At least one special symbol (!@#$%^&*()-_+=<>?)");

            char[] newPass = readPassword(scanner, console, "Enter password: ");
            if (newPass == null || newPass.length == 0) {
                System.out.println("[!] Password cannot be empty.");
                return;
            }

            char[] confirmPass = readPassword(scanner, console, "Confirm password: ");
            if (!Arrays.equals(newPass, confirmPass)) {
                System.out.println("[!] Passwords do not match.");
                PasswordSecurity.clearPassword(newPass);
                PasswordSecurity.clearPassword(confirmPass);
                return;
            }
            PasswordSecurity.clearPassword(confirmPass);

            String policyError = PasswordSecurity.validatePasswordStrength(newPass);
            if (policyError != null) {
                System.out.println("[!] Password policy rejection: " + policyError);
                PasswordSecurity.clearPassword(newPass);
                return;
            }

            try {
                boolean created = authService.registerUser(newUsername, newPass, role);
                if (created) {
                    System.out.println("[+] User account '" + newUsername + "' successfully created with role: " + role.getDisplayName());
                    auditLogger.logEvent(AuditEventType.ADMIN_ACTION, currentUser.getUsername(),
                            "CLI-Local", "SUCCESS", "Created new user '" + newUsername + "' with role " + role.name());
                } else {
                    System.out.println("[-] Failed to create user.");
                }
            } finally {
                PasswordSecurity.clearPassword(newPass);
            }
        }

        private void toggleLockAccount() {
            System.out.println("\n--- Lock / Unlock Account ---");
            System.out.print("Enter username: ");
            String targetUser = readLine(scanner);
            if (targetUser == null || targetUser.trim().isEmpty()) return;
            targetUser = targetUser.trim();

            if (targetUser.equalsIgnoreCase(currentUser.getUsername())) {
                System.out.println("[!] Security restriction: You cannot lock or modify your own active account.");
                return;
            }

            UserAccount acc = authService.getUser(targetUser);
            if (acc == null) {
                System.out.println("[!] User '" + targetUser + "' not found.");
                return;
            }

            if (acc.isLocked()) {
                acc.setLocked(false);
                acc.resetFailedAttempts();
                System.out.println("[+] Account '" + targetUser + "' has been UNLOCKED.");
                auditLogger.logEvent(AuditEventType.ADMIN_ACTION, currentUser.getUsername(),
                        "CLI-Local", "SUCCESS", "Unlocked account for user: " + targetUser);
            } else {
                acc.setLocked(true);
                acc.setLockoutTime(System.currentTimeMillis());
                System.out.println("[+] Account '" + targetUser + "' has been LOCKED by administrator.");
                auditLogger.logEvent(AuditEventType.ADMIN_ACTION, currentUser.getUsername(),
                        "CLI-Local", "SUCCESS", "Manually locked account: " + targetUser);
            }
        }

        private void resetUserPassword() {
            System.out.println("\n--- Reset User Password ---");
            System.out.print("Enter target username: ");
            String targetUser = readLine(scanner);
            if (targetUser == null || targetUser.trim().isEmpty()) return;
            targetUser = targetUser.trim();

            UserAccount acc = authService.getUser(targetUser);
            if (acc == null) {
                System.out.println("[!] User '" + targetUser + "' not found.");
                return;
            }

            char[] newPass = readPassword(scanner, console, "Enter new temporary password: ");
            if (newPass == null || newPass.length == 0) return;

            String policyError = PasswordSecurity.validatePasswordStrength(newPass);
            if (policyError != null) {
                System.out.println("[!] Password policy rejection: " + policyError);
                PasswordSecurity.clearPassword(newPass);
                return;
            }

            try {
                authService.updateUserPassword(targetUser, newPass);
                System.out.println("[+] Password for '" + targetUser + "' has been successfully reset.");
                auditLogger.logEvent(AuditEventType.ADMIN_ACTION, currentUser.getUsername(),
                        "CLI-Local", "SUCCESS", "Reset password for user: " + targetUser);
            } finally {
                PasswordSecurity.clearPassword(newPass);
            }
        }

        private void deleteUserAccount() {
            System.out.println("\n--- Delete User Account ---");
            System.out.print("Enter username to delete: ");
            String targetUser = readLine(scanner);
            if (targetUser == null || targetUser.trim().isEmpty()) return;
            targetUser = targetUser.trim();

            if (targetUser.equalsIgnoreCase(currentUser.getUsername())) {
                System.out.println("[!] Safety guard: You cannot delete your own logged-in account.");
                return;
            }

            System.out.print("Are you sure you want to permanently delete '" + targetUser + "'? (yes/no): ");
            String confirm = readLine(scanner);
            if ("yes".equalsIgnoreCase(confirm != null ? confirm.trim() : "")) {
                boolean deleted = authService.deleteUser(targetUser);
                if (deleted) {
                    System.out.println("[+] User account '" + targetUser + "' deleted.");
                    auditLogger.logEvent(AuditEventType.ADMIN_ACTION, currentUser.getUsername(),
                            "CLI-Local", "SUCCESS", "Deleted user account: " + targetUser);
                } else {
                    System.out.println("[!] User '" + targetUser + "' does not exist.");
                }
            } else {
                System.out.println("[-] Deletion canceled.");
            }
        }

        private void runSecurityDiagnostics() {
            System.out.println("\n==================================================");
            System.out.println("         SECURITY & INTEGRITY DIAGNOSTICS");
            System.out.println("==================================================");
            File logFile = new File(AUDIT_LOG_FILE);
            System.out.println("Audit Log File Path   : " + logFile.getAbsolutePath());
            System.out.println("Audit Log Exists      : " + logFile.exists());
            System.out.println("Audit Log Writable    : " + logFile.canWrite());
            System.out.println("Audit Log Readable    : " + logFile.canRead());
            System.out.println("Audit Log Size        : " + logFile.length() + " bytes");

            long totalLines = 0;
            if (logFile.exists()) {
                try (BufferedReader reader = new BufferedReader(new FileReader(logFile, StandardCharsets.UTF_8))) {
                    while (reader.readLine() != null) totalLines++;
                } catch (IOException e) {
                    System.out.println("[!] Error reading audit log: " + e.getMessage());
                }
            }
            System.out.println("Total Audit Records   : " + totalLines);

            System.out.println("\nCryptographic Subsystem Benchmark:");
            System.out.println("  Algorithm           : " + PasswordSecurity.ALGORITHM);
            System.out.println("  PBKDF2 Iterations   : " + PasswordSecurity.ITERATIONS);
            System.out.println("  Key Length          : " + PasswordSecurity.KEY_LENGTH + " bits");
            System.out.println("  Salt Size           : " + PasswordSecurity.SALT_BYTES + " bytes");

            long start = System.nanoTime();
            byte[] testSalt = PasswordSecurity.generateSalt();
            byte[] testHash = PasswordSecurity.hashPassword("BenchmarkPassword#2026".toCharArray(), testSalt);
            long durationMs = (System.nanoTime() - start) / 1_000_000;
            System.out.println("  Sample Hash Time    : " + durationMs + " ms");
            System.out.println("  Cryptographic Status: HEALTHY");

            auditLogger.logEvent(AuditEventType.ADMIN_ACTION, currentUser.getUsername(),
                    "CLI-Local", "SUCCESS", "Ran security and cryptographic diagnostics");
        }

        private void manageMaintenanceAndConfig() {
            boolean managing = true;
            while (managing) {
                System.out.println("\n==================================================");
                System.out.println("       SYSTEM MAINTENANCE & CONFIGURATION");
                System.out.println("==================================================");
                System.out.println("Current Maintenance Mode: " + (maintenanceMode ? "ENABLED (ON)" : "DISABLED (OFF)"));
                System.out.println("  1. Toggle Maintenance Mode");
                System.out.println("  2. Trigger JVM Garbage Collection");
                System.out.println("  3. Return to Admin Menu");
                System.out.print("\nSelect option (1-3): ");

                String choice = readLine(scanner);
                if (choice == null) return;

                switch (choice.trim()) {
                    case "1":
                        maintenanceMode = !maintenanceMode;
                        System.out.println("[+] Maintenance mode is now: " + (maintenanceMode ? "ENABLED" : "DISABLED"));
                        auditLogger.logEvent(AuditEventType.ADMIN_ACTION, currentUser.getUsername(),
                                "CLI-Local", "SUCCESS", "Toggled maintenance mode to " + maintenanceMode);
                        break;
                    case "2":
                        System.out.println("Invoking System.gc()...");
                        long beforeMem = Runtime.getRuntime().freeMemory();
                        System.gc();
                        long afterMem = Runtime.getRuntime().freeMemory();
                        long reclaimed = Math.max(0, afterMem - beforeMem) / (1024 * 1024);
                        System.out.println("[+] Garbage collection complete. Reclaimed approx: " + reclaimed + " MB.");
                        auditLogger.logEvent(AuditEventType.ADMIN_ACTION, currentUser.getUsername(),
                                "CLI-Local", "SUCCESS", "Triggered garbage collection cleanup");
                        break;
                    case "3":
                        managing = false;
                        break;
                    default:
                        System.out.println("[!] Invalid option. Please enter 1-3.");
                }
            }
        }

        private void changeAdminPassword() {
            System.out.println("\n--- Change Administrator Password ---");
            char[] currentPass = readPassword(scanner, console, "Enter CURRENT password: ");
            if (currentPass == null || currentPass.length == 0) return;

            // Verify current password
            byte[] currentHash = PasswordSecurity.hashPassword(currentPass, currentUser.getPasswordSalt());
            boolean matches = MessageDigest.isEqual(currentHash, currentUser.getPasswordHash());
            PasswordSecurity.clearPassword(currentPass);

            if (!matches) {
                System.out.println("[!] Verification failed: Current password incorrect.");
                auditLogger.logEvent(AuditEventType.ADMIN_ACTION, currentUser.getUsername(),
                        "CLI-Local", "FAILED", "Password change attempt failed: invalid current password");
                return;
            }

            char[] newPass = readPassword(scanner, console, "Enter NEW password: ");
            if (newPass == null || newPass.length == 0) return;

            char[] confirmPass = readPassword(scanner, console, "Confirm NEW password: ");
            if (!Arrays.equals(newPass, confirmPass)) {
                System.out.println("[!] New passwords do not match.");
                PasswordSecurity.clearPassword(newPass);
                PasswordSecurity.clearPassword(confirmPass);
                return;
            }
            PasswordSecurity.clearPassword(confirmPass);

            String policyError = PasswordSecurity.validatePasswordStrength(newPass);
            if (policyError != null) {
                System.out.println("[!] Password policy rejection: " + policyError);
                PasswordSecurity.clearPassword(newPass);
                return;
            }

            try {
                authService.updateUserPassword(currentUser.getUsername(), newPass);
                System.out.println("[+] Password successfully changed.");
                auditLogger.logEvent(AuditEventType.ADMIN_ACTION, currentUser.getUsername(),
                        "CLI-Local", "SUCCESS", "Administrator changed their password");
            } finally {
                PasswordSecurity.clearPassword(newPass);
            }
        }

        private void exportAuditReport() {
            String exportFileName = "audit_report_" + System.currentTimeMillis() + ".txt";
            System.out.println("\nExporting audit log report to " + exportFileName + "...");
            try {
                List<AuditRecord> records = auditLogger.readAllRecords();
                try (PrintWriter writer = new PrintWriter(new FileWriter(exportFileName, StandardCharsets.UTF_8))) {
                    writer.println("==========================================================================================");
                    writer.println("                      ENTERPRISE AUDIT TRAIL FORENSIC REPORT");
                    writer.println("  Report Timestamp (UTC) : " + DateTimeFormatter.ISO_INSTANT.format(Instant.now()));
                    writer.println("  Generated By Admin     : " + currentUser.getUsername() + " (" + currentUser.getRole().getDisplayName() + ")");
                    writer.println("  Total Recorded Events  : " + records.size());
                    writer.println("==========================================================================================");
                    writer.printf("%-26s | %-22s | %-14s | %-10s | %s\n",
                            "TIMESTAMP (UTC)", "EVENT TYPE", "USERNAME", "STATUS", "DETAILS");
                    writer.println("-".repeat(110));
                    for (AuditRecord r : records) {
                        writer.printf("%-26s | %-22s | %-14s | %-10s | %s\n",
                                r.getTimestamp(), r.getEventType(), r.getUsername(), r.getStatus(), r.getDetails());
                    }
                    writer.println("==========================================================================================");
                    writer.println("                                 END OF REPORT");
                    writer.println("==========================================================================================");
                }
                System.out.println("[+] Comprehensive audit report exported successfully to: " + Paths.get(exportFileName).toAbsolutePath());
                auditLogger.logEvent(AuditEventType.ADMIN_ACTION, currentUser.getUsername(),
                        "CLI-Local", "SUCCESS", "Exported audit report to " + exportFileName);
            } catch (IOException e) {
                System.out.println("[!] Failed to export audit report: " + e.getMessage());
            }
        }
    }

    // =========================================================================
    // Authentication Service & User Management Subsystem
    // =========================================================================
    public static class AuthenticationService {
        private final Map<String, UserAccount> users = new ConcurrentHashMap<>();
        private final AuditLogger auditLogger;
        private final byte[] dummySalt = PasswordSecurity.generateSalt();

        public AuthenticationService(AuditLogger auditLogger) {
            this.auditLogger = auditLogger;
            seedDefaultAccounts();
        }

        private void seedDefaultAccounts() {
            // Pre-seed Super Administrator
            byte[] salt1 = PasswordSecurity.generateSalt();
            byte[] hash1 = PasswordSecurity.hashPassword("Admin@Secure2026!".toCharArray(), salt1);
            users.put("admin", new UserAccount("admin", hash1, salt1, Role.SUPER_ADMIN));

            // Pre-seed Security Administrator
            byte[] salt2 = PasswordSecurity.generateSalt();
            byte[] hash2 = PasswordSecurity.hashPassword("SecOps#Secure2026!".toCharArray(), salt2);
            users.put("secops", new UserAccount("secops", hash2, salt2, Role.ADMIN));

            // Pre-seed Security Auditor
            byte[] salt3 = PasswordSecurity.generateSalt();
            byte[] hash3 = PasswordSecurity.hashPassword("Audit#Secure2026!".toCharArray(), salt3);
            users.put("auditor", new UserAccount("auditor", hash3, salt3, Role.SECURITY_AUDITOR));

            // Pre-seed Standard User (Demonstrates non-admin RBAC rejection)
            byte[] salt4 = PasswordSecurity.generateSalt();
            byte[] hash4 = PasswordSecurity.hashPassword("UserPass@2026!".toCharArray(), salt4);
            users.put("johndoe", new UserAccount("johndoe", hash4, salt4, Role.STANDARD_USER));
        }

        public AuthResult authenticate(String username, char[] password, String source) {
            String lookupKey = username.toLowerCase(Locale.ROOT);
            UserAccount account = users.get(lookupKey);

            // User Enumeration Timing Attack Defense:
            // If user doesn't exist, hash anyway with dummy salt so computation time is indistinguishable
            if (account == null) {
                PasswordSecurity.hashPassword(password, dummySalt);
                auditLogger.logEvent(AuditEventType.AUTH_FAILURE, username, source, "FAILED",
                        "Authentication rejected: invalid credentials (unknown user)");
                return new AuthResult(AuthStatus.FAILURE, "Invalid username or password.", null);
            }

            // Check Account Lockout
            if (account.isLocked()) {
                long elapsed = System.currentTimeMillis() - account.getLockoutTime();
                if (elapsed > LOCKOUT_DURATION_MS) {
                    // Lockout expired; automatically unlock
                    account.setLocked(false);
                    account.resetFailedAttempts();
                    auditLogger.logEvent(AuditEventType.ADMIN_ACTION, username, source, "SUCCESS",
                            "Account lockout window expired; account automatically reactivated");
                } else {
                    long remainingMin = Math.max(1, (LOCKOUT_DURATION_MS - elapsed) / 60000);
                    auditLogger.logEvent(AuditEventType.AUTH_LOCKOUT, username, source, "DENIED",
                            "Authentication rejected: account is locked (" + remainingMin + "m cooldown remaining)");
                    return new AuthResult(AuthStatus.ACCOUNT_LOCKED,
                            "Account is temporarily locked due to excessive failed attempts. Try again in " +
                                    remainingMin + " minute(s) or contact an administrator.", null);
                }
            }

            // Verify Password using constant-time comparison
            byte[] computedHash = PasswordSecurity.hashPassword(password, account.getPasswordSalt());
            boolean match = MessageDigest.isEqual(computedHash, account.getPasswordHash());

            if (!match) {
                int attempts = account.incrementFailedAttempts();
                if (attempts >= MAX_FAILED_ATTEMPTS) {
                    account.setLocked(true);
                    account.setLockoutTime(System.currentTimeMillis());
                    auditLogger.logEvent(AuditEventType.AUTH_LOCKOUT, username, source, "LOCKED",
                            "Account locked after reaching " + attempts + " consecutive failed attempts");
                    return new AuthResult(AuthStatus.ACCOUNT_LOCKED,
                            "Warning: Account is now LOCKED due to " + attempts + " consecutive failed attempts.", null);
                } else {
                    int remaining = MAX_FAILED_ATTEMPTS - attempts;
                    auditLogger.logEvent(AuditEventType.AUTH_FAILURE, username, source, "FAILED",
                            "Invalid credentials provided (attempt " + attempts + " of " + MAX_FAILED_ATTEMPTS + ")");
                    return new AuthResult(AuthStatus.FAILURE,
                            "Warning: " + remaining + " login attempt(s) remaining before account lockout.", null);
                }
            }

            // Credentials are valid; verify Administrative Access (RBAC)
            if (!account.getRole().isAdmin()) {
                auditLogger.logEvent(AuditEventType.AUTH_DENIED_NON_ADMIN, username, source, "DENIED",
                        "Credentials verified, but user role '" + account.getRole().getDisplayName() + "' lacks admin privileges");
                return new AuthResult(AuthStatus.DENIED_NON_ADMIN,
                        "User is authenticated but does not have administrator privileges.", account);
            }

            // Success: Reset failed attempts counter and update last login
            account.resetFailedAttempts();
            account.setLastLoginTime(Instant.now());
            auditLogger.logEvent(AuditEventType.AUTH_SUCCESS, username, source, "SUCCESS",
                    "Authentication successful with role: " + account.getRole().name());

            return new AuthResult(AuthStatus.SUCCESS, "Authentication successful.", account);
        }

        public boolean registerUser(String username, char[] password, Role role) {
            String key = username.toLowerCase(Locale.ROOT);
            if (users.containsKey(key)) return false;
            byte[] salt = PasswordSecurity.generateSalt();
            byte[] hash = PasswordSecurity.hashPassword(password, salt);
            users.put(key, new UserAccount(username, hash, salt, role));
            return true;
        }

        public void updateUserPassword(String username, char[] newPassword) {
            UserAccount account = users.get(username.toLowerCase(Locale.ROOT));
            if (account != null) {
                byte[] salt = PasswordSecurity.generateSalt();
                byte[] hash = PasswordSecurity.hashPassword(newPassword, salt);
                account.setPassword(hash, salt);
            }
        }

        public boolean deleteUser(String username) {
            return users.remove(username.toLowerCase(Locale.ROOT)) != null;
        }

        public UserAccount getUser(String username) {
            return users.get(username.toLowerCase(Locale.ROOT));
        }

        public boolean hasUser(String username) {
            return users.containsKey(username.toLowerCase(Locale.ROOT));
        }

        public Collection<UserAccount> getAllUsers() {
            return Collections.unmodifiableCollection(users.values());
        }

        public int getUserCount() {
            return users.size();
        }
    }

    // =========================================================================
    // User Account Entity
    // =========================================================================
    public static class UserAccount {
        private final String username;
        private byte[] passwordHash;
        private byte[] passwordSalt;
        private Role role;
        private boolean locked;
        private int failedAttempts;
        private long lockoutTime;
        private Instant lastLoginTime;

        public UserAccount(String username, byte[] passwordHash, byte[] passwordSalt, Role role) {
            this.username = username;
            this.passwordHash = passwordHash;
            this.passwordSalt = passwordSalt;
            this.role = role;
            this.locked = false;
            this.failedAttempts = 0;
            this.lockoutTime = 0;
            this.lastLoginTime = null;
        }

        public String getUsername() { return username; }
        public synchronized byte[] getPasswordHash() { return passwordHash; }
        public synchronized byte[] getPasswordSalt() { return passwordSalt; }
        public synchronized Role getRole() { return role; }
        public synchronized boolean isLocked() { return locked; }
        public synchronized int getFailedAttempts() { return failedAttempts; }
        public synchronized long getLockoutTime() { return lockoutTime; }
        public synchronized Instant getLastLoginTime() { return lastLoginTime; }

        public synchronized void setPassword(byte[] newHash, byte[] newSalt) {
            this.passwordHash = newHash;
            this.passwordSalt = newSalt;
        }

        public synchronized void setRole(Role role) { this.role = role; }
        public synchronized void setLocked(boolean locked) { this.locked = locked; }
        public synchronized void setLockoutTime(long lockoutTime) { this.lockoutTime = lockoutTime; }
        public synchronized void setLastLoginTime(Instant lastLoginTime) { this.lastLoginTime = lastLoginTime; }

        public synchronized int incrementFailedAttempts() {
            this.failedAttempts++;
            return this.failedAttempts;
        }

        public synchronized void resetFailedAttempts() {
            this.failedAttempts = 0;
        }
    }

    // =========================================================================
    // Authentication Status & Result Models
    // =========================================================================
    public enum AuthStatus {
        SUCCESS,
        FAILURE,
        DENIED_NON_ADMIN,
        ACCOUNT_LOCKED
    }

    public static class AuthResult {
        private final AuthStatus status;
        private final String message;
        private final UserAccount user;

        public AuthResult(AuthStatus status, String message, UserAccount user) {
            this.status = status;
            this.message = message;
            this.user = user;
        }

        public AuthStatus getStatus() { return status; }
        public String getMessage() { return message; }
        public UserAccount getUser() { return user; }
    }

    // =========================================================================
    // Cryptographic Security Engine
    // =========================================================================
    public static class PasswordSecurity {
        public static final String ALGORITHM = "PBKDF2WithHmacSHA256";
        public static final int ITERATIONS = 120_000;
        public static final int KEY_LENGTH = 256;
        public static final int SALT_BYTES = 16;
        private static final SecureRandom SECURE_RANDOM = new SecureRandom();

        public static byte[] generateSalt() {
            byte[] salt = new byte[SALT_BYTES];
            SECURE_RANDOM.nextBytes(salt);
            return salt;
        }

        public static byte[] hashPassword(char[] password, byte[] salt) {
            try {
                PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);
                SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
                byte[] hash = skf.generateSecret(spec).getEncoded();
                spec.clearPassword();
                return hash;
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new RuntimeException("Cryptographic failure in password hashing: " + e.getMessage(), e);
            }
        }

        public static void clearPassword(char[] password) {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }

        public static String validatePasswordStrength(char[] password) {
            if (password == null || password.length < 10) {
                return "Password must be at least 10 characters in length.";
            }
            boolean hasUpper = false;
            boolean hasLower = false;
            boolean hasDigit = false;
            boolean hasSpecial = false;
            String specialChars = "!@#$%^&*()-_+=<>?/[]{}|~";

            for (char c : password) {
                if (Character.isUpperCase(c)) hasUpper = true;
                else if (Character.isLowerCase(c)) hasLower = true;
                else if (Character.isDigit(c)) hasDigit = true;
                else if (specialChars.indexOf(c) >= 0) hasSpecial = true;
            }

            if (!hasUpper) return "Password must contain at least one uppercase letter (A-Z).";
            if (!hasLower) return "Password must contain at least one lowercase letter (a-z).";
            if (!hasDigit) return "Password must contain at least one numerical digit (0-9).";
            if (!hasSpecial) return "Password must contain at least one special symbol (!@#$%^&*...).";

            return null; // Passes complexity policy
        }
    }

    // =========================================================================
    // Persistent Audit Logging Subsystem (CWE-117, CWE-532 Compliant)
    // =========================================================================
    public enum AuditEventType {
        AUTH_SUCCESS,
        AUTH_FAILURE,
        AUTH_LOCKOUT,
        AUTH_DENIED_NON_ADMIN,
        ADMIN_ACTION,
        LOGOUT
    }

    public static class AuditRecord {
        private final String timestamp;
        private final AuditEventType eventType;
        private final String username;
        private final String source;
        private final String status;
        private final String details;

        public AuditRecord(String timestamp, AuditEventType eventType, String username,
                           String source, String status, String details) {
            this.timestamp = timestamp;
            this.eventType = eventType;
            this.username = username;
            this.source = source;
            this.status = status;
            this.details = details;
        }

        public String getTimestamp() { return timestamp; }
        public AuditEventType getEventType() { return eventType; }
        public String getUsername() { return username; }
        public String getSource() { return source; }
        public String getStatus() { return status; }
        public String getDetails() { return details; }

        public String toLogLine() {
            return String.format("[%s] [%s] User: %s | Source: %s | Status: %s | Details: %s",
                    timestamp, eventType.name(), username, source, status, details);
        }

        public static AuditRecord fromLogLine(String line) {
            try {
                if (!line.startsWith("[")) return null;
                int endTs = line.indexOf("]");
                if (endTs == -1) return null;
                String ts = line.substring(1, endTs);

                int startType = line.indexOf("[", endTs);
                int endType = line.indexOf("]", startType);
                if (startType == -1 || endType == -1) return null;
                String typeStr = line.substring(startType + 1, endType);
                AuditEventType type = AuditEventType.valueOf(typeStr);

                String remainder = line.substring(endType + 1);
                String[] parts = remainder.split(" \\| ");
                String user = "UNKNOWN";
                String source = "UNKNOWN";
                String status = "UNKNOWN";
                String details = "";

                for (String part : parts) {
                    part = part.trim();
                    if (part.startsWith("User:")) {
                        user = part.substring(5).trim();
                    } else if (part.startsWith("Source:")) {
                        source = part.substring(7).trim();
                    } else if (part.startsWith("Status:")) {
                        status = part.substring(7).trim();
                    } else if (part.startsWith("Details:")) {
                        details = part.substring(8).trim();
                    }
                }
                return new AuditRecord(ts, type, user, source, status, details);
            } catch (Exception e) {
                return new AuditRecord(DateTimeFormatter.ISO_INSTANT.format(Instant.now()),
                        AuditEventType.ADMIN_ACTION, "SYSTEM", "INTERNAL", "LOG_PARSE_WARN", line);
            }
        }
    }

    public static class AuditLogger {
        private final File logFile;
        private final Object lock = new Object();

        public AuditLogger(String logFilePath) {
            this.logFile = new File(logFilePath);
        }

        public void logEvent(AuditEventType eventType, String rawUsername, String rawSource,
                             String rawStatus, String rawDetails) {
            // Prevent Log Injection (CRLF injection / CWE-117)
            String safeUser = sanitize(rawUsername);
            String safeSource = sanitize(rawSource);
            String safeStatus = sanitize(rawStatus);
            String safeDetails = sanitize(rawDetails);

            String timestamp = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
            AuditRecord record = new AuditRecord(timestamp, eventType, safeUser, safeSource, safeStatus, safeDetails);
            String line = record.toLogLine();

            synchronized (lock) {
                try (BufferedWriter writer = new BufferedWriter(
                        new OutputStreamWriter(new FileOutputStream(logFile, true), StandardCharsets.UTF_8))) {
                    writer.write(line);
                    writer.newLine();
                    writer.flush();
                } catch (IOException e) {
                    System.err.println("[CRITICAL AUDIT ERROR] Failed writing to audit trail: " + e.getMessage());
                }
            }
        }

        public List<AuditRecord> readAllRecords() {
            List<AuditRecord> list = new ArrayList<>();
            if (!logFile.exists()) return list;

            synchronized (lock) {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(new FileInputStream(logFile), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (line.trim().isEmpty()) continue;
                        AuditRecord record = AuditRecord.fromLogLine(line);
                        if (record != null) {
                            list.add(record);
                        }
                    }
                } catch (IOException e) {
                    System.err.println("[AUDIT ERROR] Failed reading audit log: " + e.getMessage());
                }
            }
            return list;
        }

        public long countLogRecords() {
            if (!logFile.exists()) return 0;
            long count = 0;
            synchronized (lock) {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(new FileInputStream(logFile), StandardCharsets.UTF_8))) {
                    while (reader.readLine() != null) count++;
                } catch (IOException e) {
                    return 0;
                }
            }
            return count;
        }

        private String sanitize(String input) {
            if (input == null) return "N/A";
            return input.replaceAll("[\r\n]", "_")
                        .replaceAll("[\t]", " ")
                        .replaceAll("[\\p{Cntrl}]", "");
        }
    }
}
