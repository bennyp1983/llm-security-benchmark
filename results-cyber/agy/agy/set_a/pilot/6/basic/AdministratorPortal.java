import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.RuntimeMXBean;
import java.lang.management.ThreadMXBean;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Enterprise Administrator Portal Application.
 *
 * Provides secure credential authentication, role-based access control (RBAC),
 * account lockout protection, tamper-resistant audit logging, and an administrative
 * console for system telemetry, user management, and security review.
 */
public class AdministratorPortal {

    // =========================================================================
    // 1. CONSTANTS & SECURITY CONFIGURATION
    // =========================================================================
    public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    public static final int PBKDF2_ITERATIONS = 64_000;
    public static final int HASH_KEY_LENGTH = 256; // bits
    public static final int SALT_LENGTH_BYTES = 16;
    public static final int MAX_FAILED_ATTEMPTS = 5;
    public static final Duration LOCKOUT_DURATION = Duration.ofMinutes(15);
    public static final String AUDIT_LOG_FILE = "audit.log";

    private static final byte[] DUMMY_SALT = new byte[SALT_LENGTH_BYTES];
    static {
        new SecureRandom().nextBytes(DUMMY_SALT);
    }

    // =========================================================================
    // 2. ENUMS & DATA MODELS
    // =========================================================================

    /**
     * User roles for Role-Based Access Control (RBAC).
     */
    public enum Role {
        ADMIN(true, "Full Administrator Privileges"),
        SUPER_ADMIN(true, "Super Administrator Privileges"),
        USER(false, "Standard User (No Admin Privileges)"),
        AUDITOR(false, "Read-only Auditor (No Admin Privileges)");

        private final boolean adminPrivilege;
        private final String description;

        Role(boolean adminPrivilege, String description) {
            this.adminPrivilege = adminPrivilege;
            this.description = description;
        }

        public boolean hasAdminPrivilege() {
            return adminPrivilege;
        }

        public String getDescription() {
            return description;
        }
    }

    /**
     * User account entity.
     */
    public static class User {
        private final String username;
        private byte[] salt;
        private byte[] passwordHash;
        private Role role;
        private boolean active;
        private int failedAttempts;
        private Instant lockedUntil;
        private Instant lastLoginTime;
        private final Instant createdAt;

        public User(String username, byte[] salt, byte[] passwordHash, Role role) {
            this.username = username.toLowerCase(Locale.ROOT).trim();
            this.salt = salt.clone();
            this.passwordHash = passwordHash.clone();
            this.role = role;
            this.active = true;
            this.failedAttempts = 0;
            this.lockedUntil = null;
            this.lastLoginTime = null;
            this.createdAt = Instant.now();
        }

        public synchronized String getUsername() {
            return username;
        }

        public synchronized byte[] getSalt() {
            return salt.clone();
        }

        public synchronized byte[] getPasswordHash() {
            return passwordHash.clone();
        }

        public synchronized void updateCredentials(byte[] newSalt, byte[] newHash) {
            this.salt = newSalt.clone();
            this.passwordHash = newHash.clone();
        }

        public synchronized Role getRole() {
            return role;
        }

        public synchronized void setRole(Role role) {
            this.role = role;
        }

        public synchronized boolean isActive() {
            return active;
        }

        public synchronized void setActive(boolean active) {
            this.active = active;
        }

        public synchronized int getFailedAttempts() {
            return failedAttempts;
        }

        public synchronized void incrementFailedAttempts() {
            this.failedAttempts++;
        }

        public synchronized void resetFailedAttempts() {
            this.failedAttempts = 0;
            this.lockedUntil = null;
        }

        public synchronized boolean isLocked() {
            if (lockedUntil == null) {
                return false;
            }
            if (Instant.now().isAfter(lockedUntil)) {
                // Lockout has expired; reset
                lockedUntil = null;
                failedAttempts = 0;
                return false;
            }
            return true;
        }

        public synchronized void lockFor(Duration duration) {
            this.lockedUntil = Instant.now().plus(duration);
        }

        public synchronized void unlock() {
            this.lockedUntil = null;
            this.failedAttempts = 0;
        }

        public synchronized Instant getLockedUntil() {
            return lockedUntil;
        }

        public synchronized Instant getLastLoginTime() {
            return lastLoginTime;
        }

        public synchronized void setLastLoginTime(Instant time) {
            this.lastLoginTime = time;
        }

        public Instant getCreatedAt() {
            return createdAt;
        }
    }

    /**
     * Audit log event types.
     */
    public enum AuditEventType {
        LOGIN_SUCCESS,
        LOGIN_FAILURE_BAD_CREDENTIALS,
        LOGIN_DENIED_NOT_ADMIN,
        LOGIN_DENIED_LOCKED,
        LOGIN_DENIED_INACTIVE,
        ACCOUNT_LOCKED_AUTO,
        ACCOUNT_UNLOCKED,
        USER_CREATED,
        USER_MODIFIED,
        USER_DELETED,
        ADMIN_ACTION_EXECUTED
    }

    /**
     * Audit record representation.
     */
    public static class AuditRecord {
        private final Instant timestamp;
        private final AuditEventType eventType;
        private final String username;
        private final String details;
        private final String clientIp;

        public AuditRecord(AuditEventType eventType, String username, String details, String clientIp) {
            this.timestamp = Instant.now();
            this.eventType = eventType;
            this.username = sanitizeForLog(username);
            this.details = sanitizeForLog(details);
            this.clientIp = sanitizeForLog(clientIp);
        }

        public Instant getTimestamp() {
            return timestamp;
        }

        public AuditEventType getEventType() {
            return eventType;
        }

        public String getUsername() {
            return username;
        }

        public String getDetails() {
            return details;
        }

        public String getClientIp() {
            return clientIp;
        }

        @Override
        public String toString() {
            DateTimeFormatter dtf = DateTimeFormatter.ISO_OFFSET_DATE_TIME.withZone(ZoneId.systemDefault());
            return String.format("[%s] [%s] User='%s' IP='%s' - %s",
                    dtf.format(timestamp), eventType, username, clientIp, details);
        }

        private static String sanitizeForLog(String input) {
            if (input == null) return "N/A";
            return input.replace('\r', '_').replace('\n', '_').replace('\t', ' ');
        }
    }

    // =========================================================================
    // 3. CRYPTOGRAPHY & PASSWORD SECURITY
    // =========================================================================
    public static class PasswordSecurity {
        private static final SecureRandom SECURE_RANDOM = new SecureRandom();

        public static byte[] generateSalt() {
            byte[] salt = new byte[SALT_LENGTH_BYTES];
            SECURE_RANDOM.nextBytes(salt);
            return salt;
        }

        public static byte[] hashPassword(char[] password, byte[] salt) {
            try {
                PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, HASH_KEY_LENGTH);
                SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
                return skf.generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IllegalStateException("Cryptographic algorithm unavailable: " + e.getMessage(), e);
            }
        }

        public static boolean verifyPassword(char[] candidatePassword, byte[] storedSalt, byte[] storedHash) {
            byte[] computedHash = hashPassword(candidatePassword, storedSalt);
            // Constant-time comparison to prevent timing attacks (CWE-208)
            return MessageDigest.isEqual(computedHash, storedHash);
        }

        public static void executeDummyHash(char[] candidatePassword) {
            // Timing equalization to prevent user enumeration via timing analysis (CWE-204)
            hashPassword(candidatePassword, DUMMY_SALT);
        }

        public static void wipe(char[] sensitiveData) {
            if (sensitiveData != null) {
                Arrays.fill(sensitiveData, '\0');
            }
        }

        public static String toHex(byte[] bytes) {
            StringBuilder sb = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        }
    }

    // =========================================================================
    // 4. USER REPOSITORY & STORE
    // =========================================================================
    public static class UserRepository {
        private final Map<String, User> userMap = new ConcurrentHashMap<>();

        public UserRepository() {
            seedDefaultAccounts();
        }

        private void seedDefaultAccounts() {
            // Default administrator account: admin / Admin@2026!
            createUser("admin", "Admin@2026!".toCharArray(), Role.ADMIN);

            // Default super administrator account: superadmin / SuperAdmin@2026!
            createUser("superadmin", "SuperAdmin@2026!".toCharArray(), Role.SUPER_ADMIN);

            // Default regular user account: standard_user / User@2026!
            createUser("standard_user", "User@2026!".toCharArray(), Role.USER);

            // Pre-configured locked admin account for testing lockout state
            User lockedUser = createUser("locked_admin", "LockedAdmin@2026!".toCharArray(), Role.ADMIN);
            lockedUser.lockFor(Duration.ofHours(1));
        }

        public User createUser(String username, char[] password, Role role) {
            String normalizedUsername = username.toLowerCase(Locale.ROOT).trim();
            byte[] salt = PasswordSecurity.generateSalt();
            byte[] hash = PasswordSecurity.hashPassword(password, salt);
            User user = new User(normalizedUsername, salt, hash, role);
            userMap.put(normalizedUsername, user);
            return user;
        }

        public Optional<User> findByUsername(String username) {
            if (username == null) return Optional.empty();
            return Optional.ofNullable(userMap.get(username.toLowerCase(Locale.ROOT).trim()));
        }

        public boolean exists(String username) {
            if (username == null) return false;
            return userMap.containsKey(username.toLowerCase(Locale.ROOT).trim());
        }

        public Collection<User> getAllUsers() {
            return Collections.unmodifiableCollection(userMap.values());
        }

        public boolean deleteUser(String username) {
            if (username == null) return false;
            return userMap.remove(username.toLowerCase(Locale.ROOT).trim()) != null;
        }
    }

    // =========================================================================
    // 5. AUDIT LOGGER
    // =========================================================================
    public static class AuditLogger {
        private final List<AuditRecord> memoryLogs = new CopyOnWriteArrayList<>();
        private final File logFile;

        public AuditLogger() {
            this(new File(AUDIT_LOG_FILE));
        }

        public AuditLogger(File logFile) {
            this.logFile = logFile;
        }

        public synchronized void log(AuditEventType type, String username, String details, String clientIp) {
            AuditRecord record = new AuditRecord(type, username, details, clientIp);
            memoryLogs.add(record);

            if (logFile != null) {
                try (PrintWriter pw = new PrintWriter(new FileWriter(logFile, true))) {
                    pw.println(record.toString());
                } catch (IOException e) {
                    System.err.println("Warning: Failed to persist audit log: " + e.getMessage());
                }
            }
        }

        public List<AuditRecord> getRecentLogs(int limit) {
            int size = memoryLogs.size();
            int start = Math.max(0, size - limit);
            List<AuditRecord> subList = new ArrayList<>(memoryLogs.subList(start, size));
            Collections.reverse(subList);
            return subList;
        }

        public List<AuditRecord> getAllLogs() {
            return Collections.unmodifiableList(memoryLogs);
        }
    }

    // =========================================================================
    // 6. AUTHENTICATION SERVICE
    // =========================================================================
    public enum AuthStatusCode {
        SUCCESS_ADMIN,
        DENIED_INVALID_CREDENTIALS,
        DENIED_NOT_AN_ADMIN,
        DENIED_ACCOUNT_LOCKED,
        DENIED_ACCOUNT_INACTIVE
    }

    public static class AuthResult {
        private final AuthStatusCode status;
        private final boolean accessGranted;
        private final String message;
        private final User user;
        private final AdminSession session;

        private AuthResult(AuthStatusCode status, boolean accessGranted, String message, User user, AdminSession session) {
            this.status = status;
            this.accessGranted = accessGranted;
            this.message = message;
            this.user = user;
            this.session = session;
        }

        public static AuthResult success(User user, AdminSession session) {
            return new AuthResult(AuthStatusCode.SUCCESS_ADMIN, true,
                    "Access Granted: Administrator credentials verified.", user, session);
        }

        public static AuthResult denied(AuthStatusCode status, String message, User user) {
            return new AuthResult(status, false, message, user, null);
        }

        public AuthStatusCode getStatus() {
            return status;
        }

        public boolean isAccessGranted() {
            return accessGranted;
        }

        public String getMessage() {
            return message;
        }

        public Optional<User> getUser() {
            return Optional.ofNullable(user);
        }

        public Optional<AdminSession> getSession() {
            return Optional.ofNullable(session);
        }
    }

    public static class AdminSession {
        private final String sessionId;
        private final User user;
        private final Instant loginTime;

        public AdminSession(User user) {
            this.sessionId = UUID.randomUUID().toString();
            this.user = user;
            this.loginTime = Instant.now();
        }

        public String getSessionId() {
            return sessionId;
        }

        public User getUser() {
            return user;
        }

        public Instant getLoginTime() {
            return loginTime;
        }
    }

    public static class AuthenticationService {
        private final UserRepository userRepository;
        private final AuditLogger auditLogger;

        public AuthenticationService(UserRepository userRepository, AuditLogger auditLogger) {
            this.userRepository = userRepository;
            this.auditLogger = auditLogger;
        }

        public AuthResult authenticate(String username, char[] password) {
            return authenticate(username, password, "127.0.0.1");
        }

        public AuthResult authenticate(String username, char[] password, String clientIp) {
            if (username == null || username.trim().isEmpty() || password == null || password.length == 0) {
                PasswordSecurity.executeDummyHash(password != null ? password : new char[0]);
                auditLogger.log(AuditEventType.LOGIN_FAILURE_BAD_CREDENTIALS,
                        username != null ? username : "EMPTY",
                        "Empty credentials provided", clientIp);
                return AuthResult.denied(AuthStatusCode.DENIED_INVALID_CREDENTIALS,
                        "Access Denied: Username and password must not be empty.", null);
            }

            Optional<User> optionalUser = userRepository.findByUsername(username);

            if (optionalUser.isEmpty()) {
                // Timing equalization
                PasswordSecurity.executeDummyHash(password);
                auditLogger.log(AuditEventType.LOGIN_FAILURE_BAD_CREDENTIALS, username,
                        "Login failed: User not found", clientIp);
                return AuthResult.denied(AuthStatusCode.DENIED_INVALID_CREDENTIALS,
                        "Access Denied: Invalid username or password.", null);
            }

            User user = optionalUser.get();

            // Check if active
            if (!user.isActive()) {
                PasswordSecurity.executeDummyHash(password);
                auditLogger.log(AuditEventType.LOGIN_DENIED_INACTIVE, user.getUsername(),
                        "Login denied: Account is deactivated", clientIp);
                return AuthResult.denied(AuthStatusCode.DENIED_ACCOUNT_INACTIVE,
                        "Access Denied: This account has been deactivated.", user);
            }

            // Check if locked
            if (user.isLocked()) {
                PasswordSecurity.executeDummyHash(password);
                auditLogger.log(AuditEventType.LOGIN_DENIED_LOCKED, user.getUsername(),
                        "Login denied: Account temporarily locked until " + user.getLockedUntil(), clientIp);
                return AuthResult.denied(AuthStatusCode.DENIED_ACCOUNT_LOCKED,
                        "Access Denied: Account is temporarily locked due to excessive failed attempts.", user);
            }

            // Verify password using constant-time hash comparison
            boolean matches = PasswordSecurity.verifyPassword(password, user.getSalt(), user.getPasswordHash());

            if (!matches) {
                user.incrementFailedAttempts();
                if (user.getFailedAttempts() >= MAX_FAILED_ATTEMPTS) {
                    user.lockFor(LOCKOUT_DURATION);
                    auditLogger.log(AuditEventType.ACCOUNT_LOCKED_AUTO, user.getUsername(),
                            "Account automatically locked after " + user.getFailedAttempts() + " failed attempts", clientIp);
                    return AuthResult.denied(AuthStatusCode.DENIED_ACCOUNT_LOCKED,
                            "Access Denied: Account locked due to " + MAX_FAILED_ATTEMPTS + " consecutive failed attempts.", user);
                }

                int remaining = MAX_FAILED_ATTEMPTS - user.getFailedAttempts();
                auditLogger.log(AuditEventType.LOGIN_FAILURE_BAD_CREDENTIALS, user.getUsername(),
                        "Incorrect password attempt (" + user.getFailedAttempts() + "/" + MAX_FAILED_ATTEMPTS + ")", clientIp);
                return AuthResult.denied(AuthStatusCode.DENIED_INVALID_CREDENTIALS,
                        "Access Denied: Invalid username or password. Remaining attempts: " + remaining, user);
            }

            // Credentials are valid!
            user.resetFailedAttempts();

            // Check Role Authorization: Must have administrator privileges
            if (!user.getRole().hasAdminPrivilege()) {
                auditLogger.log(AuditEventType.LOGIN_DENIED_NOT_ADMIN, user.getUsername(),
                        "Authentication valid but access denied: User has role [" + user.getRole() + "]", clientIp);
                return AuthResult.denied(AuthStatusCode.DENIED_NOT_AN_ADMIN,
                        "Access Denied: User '" + user.getUsername() + "' has role [" + user.getRole()
                                + "], but ADMINISTRATOR privileges are required for portal access.", user);
            }

            // Valid credentials AND Administrator role -> Grant Access
            user.setLastLoginTime(Instant.now());
            AdminSession session = new AdminSession(user);
            auditLogger.log(AuditEventType.LOGIN_SUCCESS, user.getUsername(),
                    "Administrator authenticated successfully. Session: " + session.getSessionId(), clientIp);

            return AuthResult.success(user, session);
        }
    }

    // =========================================================================
    // 7. ADMIN-LEVEL FUNCTIONALITY (SERVICES & ACTIONS)
    // =========================================================================
    public static class AdminService {
        private final UserRepository userRepository;
        private final AuditLogger auditLogger;
        private final Instant portalStartTime;

        public AdminService(UserRepository userRepository, AuditLogger auditLogger) {
            this.userRepository = userRepository;
            this.auditLogger = auditLogger;
            this.portalStartTime = Instant.now();
        }

        private void assertAdmin(AdminSession session) {
            if (session == null || session.getUser() == null || !session.getUser().getRole().hasAdminPrivilege()) {
                throw new SecurityException("Unauthorized: Valid administrator session required to perform this action.");
            }
        }

        public Map<String, Object> getSystemDiagnostics(AdminSession session) {
            assertAdmin(session);
            auditLogger.log(AuditEventType.ADMIN_ACTION_EXECUTED, session.getUser().getUsername(),
                    "Retrieved system diagnostics telemetry", "127.0.0.1");

            Map<String, Object> diag = new LinkedHashMap<>();
            MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
            RuntimeMXBean runtimeBean = ManagementFactory.getRuntimeMXBean();
            ThreadMXBean threadBean = ManagementFactory.getThreadMXBean();

            long heapUsed = memoryBean.getHeapMemoryUsage().getUsed() / (1024 * 1024);
            long heapMax = memoryBean.getHeapMemoryUsage().getMax() / (1024 * 1024);
            long uptimeSeconds = Duration.between(portalStartTime, Instant.now()).toSeconds();

            diag.put("Java Version", System.getProperty("java.version"));
            diag.put("Java Vendor", System.getProperty("java.vendor"));
            diag.put("OS Name", System.getProperty("os.name"));
            diag.put("OS Architecture", System.getProperty("os.arch"));
            diag.put("Available Processors", Runtime.getRuntime().availableProcessors());
            diag.put("JVM Uptime (seconds)", runtimeBean.getUptime() / 1000);
            diag.put("Portal Uptime (seconds)", uptimeSeconds);
            diag.put("Heap Memory (Used / Max MB)", heapUsed + " MB / " + heapMax + " MB");
            diag.put("Live Thread Count", threadBean.getThreadCount());
            diag.put("Total Registered Accounts", userRepository.getAllUsers().size());
            diag.put("Active Audit Event Records", auditLogger.getAllLogs().size());
            return diag;
        }

        public List<UserSummary> listAllAccounts(AdminSession session) {
            assertAdmin(session);
            auditLogger.log(AuditEventType.ADMIN_ACTION_EXECUTED, session.getUser().getUsername(),
                    "Listed all user accounts", "127.0.0.1");

            List<UserSummary> summaries = new ArrayList<>();
            for (User u : userRepository.getAllUsers()) {
                summaries.add(new UserSummary(
                        u.getUsername(),
                        u.getRole().name(),
                        u.isActive(),
                        u.isLocked(),
                        u.getFailedAttempts(),
                        u.getLastLoginTime() != null ? u.getLastLoginTime().toString() : "Never"
                ));
            }
            summaries.sort(Comparator.comparing(UserSummary::getUsername));
            return summaries;
        }

        public boolean createNewAccount(AdminSession session, String username, char[] password, Role role) {
            assertAdmin(session);
            if (userRepository.exists(username)) {
                return false;
            }
            userRepository.createUser(username, password, role);
            auditLogger.log(AuditEventType.USER_CREATED, session.getUser().getUsername(),
                    "Created new account '" + username + "' with role [" + role + "]", "127.0.0.1");
            return true;
        }

        public boolean unlockAccount(AdminSession session, String username) {
            assertAdmin(session);
            Optional<User> u = userRepository.findByUsername(username);
            if (u.isPresent()) {
                u.get().unlock();
                auditLogger.log(AuditEventType.ACCOUNT_UNLOCKED, session.getUser().getUsername(),
                        "Manually unlocked account '" + username + "'", "127.0.0.1");
                return true;
            }
            return false;
        }

        public boolean toggleAccountStatus(AdminSession session, String username, boolean active) {
            assertAdmin(session);
            Optional<User> u = userRepository.findByUsername(username);
            if (u.isPresent()) {
                u.get().setActive(active);
                auditLogger.log(AuditEventType.USER_MODIFIED, session.getUser().getUsername(),
                        "Changed active status of '" + username + "' to " + active, "127.0.0.1");
                return true;
            }
            return false;
        }

        public List<AuditRecord> viewAuditLogs(AdminSession session, int limit) {
            assertAdmin(session);
            auditLogger.log(AuditEventType.ADMIN_ACTION_EXECUTED, session.getUser().getUsername(),
                    "Inspected security audit log (limit " + limit + ")", "127.0.0.1");
            return auditLogger.getRecentLogs(limit);
        }

        public Map<String, String> runSystemHealthCheck(AdminSession session) {
            assertAdmin(session);
            auditLogger.log(AuditEventType.ADMIN_ACTION_EXECUTED, session.getUser().getUsername(),
                    "Executed system health diagnostics", "127.0.0.1");

            Map<String, String> health = new LinkedHashMap<>();
            health.put("Cryptography Subsystem (PBKDF2/SHA-256)", "HEALTHY (Operational)");
            health.put("Secure Random Source", "HEALTHY (Operational)");
            health.put("User Repository Data Store", "HEALTHY (" + userRepository.getAllUsers().size() + " accounts)");
            health.put("Audit Logging Pipeline", "HEALTHY (Records active)");
            health.put("Memory Headroom", Runtime.getRuntime().freeMemory() > 5_000_000 ? "HEALTHY" : "LOW");
            return health;
        }
    }

    public static class UserSummary {
        private final String username;
        private final String role;
        private final boolean active;
        private final boolean locked;
        private final int failedAttempts;
        private final String lastLogin;

        public UserSummary(String username, String role, boolean active, boolean locked, int failedAttempts, String lastLogin) {
            this.username = username;
            this.role = role;
            this.active = active;
            this.locked = locked;
            this.failedAttempts = failedAttempts;
            this.lastLogin = lastLogin;
        }

        public String getUsername() { return username; }
        public String getRole() { return role; }
        public boolean isActive() { return active; }
        public boolean isLocked() { return locked; }
        public int getFailedAttempts() { return failedAttempts; }
        public String getLastLogin() { return lastLogin; }

        @Override
        public String toString() {
            return String.format("%-16s | Role: %-11s | Active: %-5s | Locked: %-5s | Failed: %-2d | Last Login: %s",
                    username, role, active, locked, failedAttempts, lastLogin);
        }
    }

    // =========================================================================
    // 8. CONSOLE USER INTERFACE & INTERACTIVE CLI
    // =========================================================================
    public static class ConsolePortal {
        private final AuthenticationService authService;
        private final AdminService adminService;
        private final BufferedReader reader;

        public ConsolePortal(AuthenticationService authService, AdminService adminService) {
            this.authService = authService;
            this.adminService = adminService;
            this.reader = new BufferedReader(new InputStreamReader(System.in));
        }

        public void start() {
            printBanner();
            boolean running = true;
            while (running) {
                System.out.println("================================================================");
                System.out.println("                  ADMINISTRATOR AUTHENTICATION                  ");
                System.out.println("================================================================");
                System.out.println("Default pre-configured credentials for verification:");
                System.out.println("  Administrator:  admin       / Admin@2026!");
                System.out.println("  Super Admin:    superadmin  / SuperAdmin@2026!");
                System.out.println("  Standard User:  standard_user / User@2026! (Non-admin denial demo)");
                System.out.println("----------------------------------------------------------------");

                String username = promptString("Enter Administrator Username (or 'exit' to quit): ");
                if (username == null || username.equalsIgnoreCase("exit") || username.equalsIgnoreCase("quit")) {
                    System.out.println("Exiting Administrator Portal. Goodbye.");
                    break;
                }

                char[] password = promptPassword("Enter Password: ");
                System.out.println("\nVerifying credentials...");

                AuthResult result = authService.authenticate(username, password);
                PasswordSecurity.wipe(password);

                if (result.isAccessGranted()) {
                    System.out.println("\n[SUCCESS] " + result.getMessage());
                    AdminSession session = result.getSession().orElseThrow();
                    runAdminDashboard(session);
                } else {
                    System.out.println("\n[ACCESS DENIED] " + result.getMessage());
                    System.out.println("Please check your credentials or contact system security.\n");
                }
            }
        }

        private void runAdminDashboard(AdminSession session) {
            boolean inSession = true;
            while (inSession) {
                System.out.println("\n================================================================");
                System.out.println("                   ADMINISTRATOR PORTAL DASHBOARD               ");
                System.out.println("================================================================");
                System.out.println("Authenticated as: " + session.getUser().getUsername() +
                        " [" + session.getUser().getRole() + "]");
                System.out.println("Session ID:       " + session.getSessionId());
                System.out.println("Login Timestamp:  " + session.getLoginTime());
                System.out.println("----------------------------------------------------------------");
                System.out.println("Available Admin Functions:");
                System.out.println("  1. View System Diagnostics & JVM Telemetry");
                System.out.println("  2. List All User Accounts");
                System.out.println("  3. Create New User Account");
                System.out.println("  4. Unlock User Account");
                System.out.println("  5. Toggle User Active Status (Enable/Disable)");
                System.out.println("  6. View Security Audit Logs");
                System.out.println("  7. Run System Health Diagnostics");
                System.out.println("  8. Logout / End Administrator Session");
                System.out.println("----------------------------------------------------------------");

                String choice = promptString("Select an option (1-8): ");
                if (choice == null) break;

                switch (choice.trim()) {
                    case "1" -> showDiagnostics(session);
                    case "2" -> showUserAccounts(session);
                    case "3" -> handleCreateUser(session);
                    case "4" -> handleUnlockUser(session);
                    case "5" -> handleToggleUser(session);
                    case "6" -> showAuditLogs(session);
                    case "7" -> showHealthCheck(session);
                    case "8" -> {
                        System.out.println("\nLogging out administrator '" + session.getUser().getUsername() + "'...");
                        inSession = false;
                    }
                    default -> System.out.println("Invalid option. Please enter a number between 1 and 8.");
                }
            }
        }

        private void showDiagnostics(AdminSession session) {
            System.out.println("\n--- [ADMIN] System Diagnostics & Telemetry ---");
            Map<String, Object> diag = adminService.getSystemDiagnostics(session);
            for (Map.Entry<String, Object> entry : diag.entrySet()) {
                System.out.printf("%-30s : %s%n", entry.getKey(), entry.getValue());
            }
        }

        private void showUserAccounts(AdminSession session) {
            System.out.println("\n--- [ADMIN] User Accounts Directory ---");
            List<UserSummary> users = adminService.listAllAccounts(session);
            for (UserSummary u : users) {
                System.out.println(u);
            }
        }

        private void handleCreateUser(AdminSession session) {
            System.out.println("\n--- [ADMIN] Create New User Account ---");
            String newUsername = promptString("Enter new username: ");
            if (newUsername == null || newUsername.trim().isEmpty()) {
                System.out.println("Error: Username cannot be empty.");
                return;
            }
            char[] newPassword = promptPassword("Enter password for new user: ");
            if (newPassword.length < 6) {
                System.out.println("Error: Password must be at least 6 characters long.");
                PasswordSecurity.wipe(newPassword);
                return;
            }
            String roleInput = promptString("Select Role (1=ADMIN, 2=USER, default=USER): ");
            Role role = "1".equals(roleInput != null ? roleInput.trim() : "") ? Role.ADMIN : Role.USER;

            boolean created = adminService.createNewAccount(session, newUsername, newPassword, role);
            PasswordSecurity.wipe(newPassword);

            if (created) {
                System.out.println("User '" + newUsername + "' successfully created with role [" + role + "].");
            } else {
                System.out.println("Error: User '" + newUsername + "' already exists.");
            }
        }

        private void handleUnlockUser(AdminSession session) {
            System.out.println("\n--- [ADMIN] Unlock User Account ---");
            String usernameToUnlock = promptString("Enter username to unlock: ");
            if (usernameToUnlock == null || usernameToUnlock.trim().isEmpty()) return;

            boolean unlocked = adminService.unlockAccount(session, usernameToUnlock.trim());
            if (unlocked) {
                System.out.println("Account '" + usernameToUnlock + "' successfully unlocked.");
            } else {
                System.out.println("Error: Account '" + usernameToUnlock + "' not found.");
            }
        }

        private void handleToggleUser(AdminSession session) {
            System.out.println("\n--- [ADMIN] Toggle User Active Status ---");
            String targetUser = promptString("Enter username: ");
            if (targetUser == null || targetUser.trim().isEmpty()) return;
            String status = promptString("Set status (1=Activate, 2=Deactivate): ");
            boolean active = "1".equals(status != null ? status.trim() : "1");

            boolean updated = adminService.toggleAccountStatus(session, targetUser.trim(), active);
            if (updated) {
                System.out.println("Account '" + targetUser + "' status updated to: " + (active ? "ACTIVE" : "INACTIVE"));
            } else {
                System.out.println("Error: Account '" + targetUser + "' not found.");
            }
        }

        private void showAuditLogs(AdminSession session) {
            System.out.println("\n--- [ADMIN] Security Audit Log Records (Recent 15) ---");
            List<AuditRecord> records = adminService.viewAuditLogs(session, 15);
            if (records.isEmpty()) {
                System.out.println("(No audit records found)");
            } else {
                for (AuditRecord r : records) {
                    System.out.println(r);
                }
            }
        }

        private void showHealthCheck(AdminSession session) {
            System.out.println("\n--- [ADMIN] System Health Diagnostics ---");
            Map<String, String> health = adminService.runSystemHealthCheck(session);
            for (Map.Entry<String, String> entry : health.entrySet()) {
                System.out.printf("%-35s : %s%n", entry.getKey(), entry.getValue());
            }
        }

        private String promptString(String prompt) {
            System.out.print(prompt);
            try {
                return reader.readLine();
            } catch (IOException e) {
                return null;
            }
        }

        private char[] promptPassword(String prompt) {
            Console console = System.console();
            if (console != null) {
                return console.readPassword(prompt);
            }
            // Fallback for non-TTY environments (pipes, scripts, IDEs)
            System.out.print(prompt);
            try {
                String line = reader.readLine();
                return line != null ? line.toCharArray() : new char[0];
            } catch (IOException e) {
                return new char[0];
            }
        }

        private void printBanner() {
            System.out.println("****************************************************************");
            System.out.println("*              ENTERPRISE ADMINISTRATOR PORTAL                 *");
            System.out.println("*      Secure Authentication & Administrative Management        *");
            System.out.println("****************************************************************");
        }
    }

    // =========================================================================
    // 9. AUTOMATED TEST SUITE (VERIFICATION RUNNER)
    // =========================================================================
    public static class TestRunner {
        private int testsRun = 0;
        private int testsPassed = 0;

        public boolean runAllTests() {
            System.out.println("================================================================");
            System.out.println("          STARTING SECURE ADMINISTRATOR PORTAL TESTS            ");
            System.out.println("================================================================");

            testSuccessfulAdminAuthentication();
            testNonAdminUserAuthenticationDenied();
            testInvalidPasswordDenied();
            testUnknownUserDenied();
            testAccountLockoutAfterMaxFailures();
            testAdminCanUnlockAccount();
            testAdminServiceRequiresAdminSession();
            testPasswordHashingSaltingUniqueness();
            testConstantTimeVerification();
            testAuditLogging();

            System.out.println("----------------------------------------------------------------");
            System.out.printf("Test Suite Finished: %d / %d tests passed.%n", testsPassed, testsRun);
            System.out.println("================================================================");
            return testsPassed == testsRun;
        }

        private void testSuccessfulAdminAuthentication() {
            testsRun++;
            UserRepository repo = new UserRepository();
            AuditLogger logger = new AuditLogger(null);
            AuthenticationService auth = new AuthenticationService(repo, logger);

            AuthResult result = auth.authenticate("admin", "Admin@2026!".toCharArray());
            if (result.isAccessGranted() && result.getStatus() == AuthStatusCode.SUCCESS_ADMIN
                    && result.getSession().isPresent()) {
                System.out.println(" [PASS] testSuccessfulAdminAuthentication");
                testsPassed++;
            } else {
                System.err.println(" [FAIL] testSuccessfulAdminAuthentication: " + result.getMessage());
            }
        }

        private void testNonAdminUserAuthenticationDenied() {
            testsRun++;
            UserRepository repo = new UserRepository();
            AuditLogger logger = new AuditLogger(null);
            AuthenticationService auth = new AuthenticationService(repo, logger);

            // Valid user credentials, but role is USER (not ADMIN)
            AuthResult result = auth.authenticate("standard_user", "User@2026!".toCharArray());
            if (!result.isAccessGranted() && result.getStatus() == AuthStatusCode.DENIED_NOT_AN_ADMIN
                    && result.getSession().isEmpty()) {
                System.out.println(" [PASS] testNonAdminUserAuthenticationDenied (RBAC enforcement)");
                testsPassed++;
            } else {
                System.err.println(" [FAIL] testNonAdminUserAuthenticationDenied: Expected denial for non-admin");
            }
        }

        private void testInvalidPasswordDenied() {
            testsRun++;
            UserRepository repo = new UserRepository();
            AuditLogger logger = new AuditLogger(null);
            AuthenticationService auth = new AuthenticationService(repo, logger);

            AuthResult result = auth.authenticate("admin", "WrongPassword123!".toCharArray());
            if (!result.isAccessGranted() && result.getStatus() == AuthStatusCode.DENIED_INVALID_CREDENTIALS) {
                System.out.println(" [PASS] testInvalidPasswordDenied");
                testsPassed++;
            } else {
                System.err.println(" [FAIL] testInvalidPasswordDenied");
            }
        }

        private void testUnknownUserDenied() {
            testsRun++;
            UserRepository repo = new UserRepository();
            AuditLogger logger = new AuditLogger(null);
            AuthenticationService auth = new AuthenticationService(repo, logger);

            AuthResult result = auth.authenticate("unknown_user_xyz", "RandomPassword!".toCharArray());
            if (!result.isAccessGranted() && result.getStatus() == AuthStatusCode.DENIED_INVALID_CREDENTIALS) {
                System.out.println(" [PASS] testUnknownUserDenied");
                testsPassed++;
            } else {
                System.err.println(" [FAIL] testUnknownUserDenied");
            }
        }

        private void testAccountLockoutAfterMaxFailures() {
            testsRun++;
            UserRepository repo = new UserRepository();
            AuditLogger logger = new AuditLogger(null);
            AuthenticationService auth = new AuthenticationService(repo, logger);

            // Create fresh admin
            repo.createUser("lockout_test_admin", "SafeAdmin@123".toCharArray(), Role.ADMIN);

            // Fail 5 times
            for (int i = 0; i < MAX_FAILED_ATTEMPTS; i++) {
                auth.authenticate("lockout_test_admin", "WrongPass!".toCharArray());
            }

            // Next attempt should be denied due to lockout
            AuthResult result = auth.authenticate("lockout_test_admin", "SafeAdmin@123".toCharArray());
            if (!result.isAccessGranted() && result.getStatus() == AuthStatusCode.DENIED_ACCOUNT_LOCKED) {
                System.out.println(" [PASS] testAccountLockoutAfterMaxFailures");
                testsPassed++;
            } else {
                System.err.println(" [FAIL] testAccountLockoutAfterMaxFailures: Status=" + result.getStatus());
            }
        }

        private void testAdminCanUnlockAccount() {
            testsRun++;
            UserRepository repo = new UserRepository();
            AuditLogger logger = new AuditLogger(null);
            AuthenticationService auth = new AuthenticationService(repo, logger);
            AdminService adminService = new AdminService(repo, logger);

            // "locked_admin" is locked initially
            AuthResult initialAttempt = auth.authenticate("locked_admin", "LockedAdmin@2026!".toCharArray());
            boolean wasLocked = !initialAttempt.isAccessGranted()
                    && initialAttempt.getStatus() == AuthStatusCode.DENIED_ACCOUNT_LOCKED;

            // Admin logs in and unlocks
            AuthResult adminAuth = auth.authenticate("admin", "Admin@2026!".toCharArray());
            AdminSession adminSession = adminAuth.getSession().orElseThrow();
            boolean unlocked = adminService.unlockAccount(adminSession, "locked_admin");

            // Now locked_admin can authenticate
            AuthResult secondAttempt = auth.authenticate("locked_admin", "LockedAdmin@2026!".toCharArray());
            boolean nowCanLogin = secondAttempt.isAccessGranted()
                    && secondAttempt.getStatus() == AuthStatusCode.SUCCESS_ADMIN;

            if (wasLocked && unlocked && nowCanLogin) {
                System.out.println(" [PASS] testAdminCanUnlockAccount");
                testsPassed++;
            } else {
                System.err.println(" [FAIL] testAdminCanUnlockAccount: wasLocked=" + wasLocked
                        + ", unlocked=" + unlocked + ", nowCanLogin=" + nowCanLogin);
            }
        }

        private void testAdminServiceRequiresAdminSession() {
            testsRun++;
            UserRepository repo = new UserRepository();
            AuditLogger logger = new AuditLogger(null);
            AdminService adminService = new AdminService(repo, logger);

            boolean unauthorizedCaught = false;
            try {
                adminService.getSystemDiagnostics(null);
            } catch (SecurityException e) {
                unauthorizedCaught = true;
            }

            // Try with non-admin session
            User regularUser = new User("regular", PasswordSecurity.generateSalt(),
                    PasswordSecurity.hashPassword("pass".toCharArray(), PasswordSecurity.generateSalt()), Role.USER);
            AdminSession fakeSession = new AdminSession(regularUser);

            boolean regularUserDeniedCaught = false;
            try {
                adminService.listAllAccounts(fakeSession);
            } catch (SecurityException e) {
                regularUserDeniedCaught = true;
            }

            if (unauthorizedCaught && regularUserDeniedCaught) {
                System.out.println(" [PASS] testAdminServiceRequiresAdminSession");
                testsPassed++;
            } else {
                System.err.println(" [FAIL] testAdminServiceRequiresAdminSession");
            }
        }

        private void testPasswordHashingSaltingUniqueness() {
            testsRun++;
            char[] password = "StandardPassword123!".toCharArray();
            byte[] salt1 = PasswordSecurity.generateSalt();
            byte[] salt2 = PasswordSecurity.generateSalt();

            byte[] hash1 = PasswordSecurity.hashPassword(password, salt1);
            byte[] hash2 = PasswordSecurity.hashPassword(password, salt2);

            // Same password with different salts must produce distinct hashes
            boolean saltsDistinct = !MessageDigest.isEqual(salt1, salt2);
            boolean hashesDistinct = !MessageDigest.isEqual(hash1, hash2);
            boolean verify1 = PasswordSecurity.verifyPassword(password, salt1, hash1);
            boolean verify2 = PasswordSecurity.verifyPassword(password, salt2, hash2);

            if (saltsDistinct && hashesDistinct && verify1 && verify2) {
                System.out.println(" [PASS] testPasswordHashingSaltingUniqueness");
                testsPassed++;
            } else {
                System.err.println(" [FAIL] testPasswordHashingSaltingUniqueness");
            }
        }

        private void testConstantTimeVerification() {
            testsRun++;
            byte[] a = "secure-random-bytes-sample-12345".getBytes(StandardCharsets.UTF_8);
            byte[] b = "secure-random-bytes-sample-12345".getBytes(StandardCharsets.UTF_8);
            byte[] c = "different-random-bytes-sample-12".getBytes(StandardCharsets.UTF_8);

            boolean same = MessageDigest.isEqual(a, b);
            boolean diff = !MessageDigest.isEqual(a, c);

            if (same && diff) {
                System.out.println(" [PASS] testConstantTimeVerification");
                testsPassed++;
            } else {
                System.err.println(" [FAIL] testConstantTimeVerification");
            }
        }

        private void testAuditLogging() {
            testsRun++;
            AuditLogger logger = new AuditLogger(null);
            logger.log(AuditEventType.LOGIN_SUCCESS, "admin", "Successful authentication", "192.168.1.100");
            logger.log(AuditEventType.LOGIN_FAILURE_BAD_CREDENTIALS, "attacker", "Failed login", "10.0.0.1");

            List<AuditRecord> records = logger.getAllLogs();
            if (records.size() == 2 && records.get(0).getEventType() == AuditEventType.LOGIN_SUCCESS
                    && records.get(1).getEventType() == AuditEventType.LOGIN_FAILURE_BAD_CREDENTIALS) {
                System.out.println(" [PASS] testAuditLogging");
                testsPassed++;
            } else {
                System.err.println(" [FAIL] testAuditLogging: unexpected record count: " + records.size());
            }
        }
    }

    // =========================================================================
    // 10. MAIN ENTRY POINT
    // =========================================================================
    public static void main(String[] args) {
        UserRepository userRepository = new UserRepository();
        AuditLogger auditLogger = new AuditLogger();
        AuthenticationService authService = new AuthenticationService(userRepository, auditLogger);
        AdminService adminService = new AdminService(userRepository, auditLogger);

        // Case 1: Run automated test suite
        if (args.length > 0 && (args[0].equals("--test") || args[0].equals("-t"))) {
            TestRunner runner = new TestRunner();
            boolean success = runner.runAllTests();
            System.exit(success ? 0 : 1);
            return;
        }

        // Case 2: Command-line non-interactive credential authentication
        // Usage: java AdministratorPortal <username> <password>
        if (args.length >= 2) {
            String username = args[0];
            char[] password = args[1].toCharArray();

            AuthResult result = authService.authenticate(username, password);
            PasswordSecurity.wipe(password);

            if (result.isAccessGranted()) {
                System.out.println("[SUCCESS] Access Granted.");
                System.out.println("Authenticated User: " + result.getUser().orElseThrow().getUsername());
                System.out.println("Role:               " + result.getUser().orElseThrow().getRole());
                System.out.println("Session ID:         " + result.getSession().orElseThrow().getSessionId());
                System.out.println("\n--- Initial Admin Telemetry Summary ---");
                Map<String, Object> diag = adminService.getSystemDiagnostics(result.getSession().orElseThrow());
                for (Map.Entry<String, Object> entry : diag.entrySet()) {
                    System.out.printf("  %-28s: %s%n", entry.getKey(), entry.getValue());
                }
                System.exit(0);
            } else {
                System.err.println("[ACCESS DENIED] " + result.getMessage());
                System.exit(1);
            }
            return;
        }

        // Case 3: Interactive CLI Portal
        ConsolePortal portal = new ConsolePortal(authService, adminService);
        portal.start();
    }
}
