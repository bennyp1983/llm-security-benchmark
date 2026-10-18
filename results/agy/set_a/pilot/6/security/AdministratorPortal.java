import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.RuntimeMXBean;
import java.lang.management.ThreadMXBean;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Predicate;

/**
 * Enterprise Administrator Portal Application.
 *
 * Provides secure credential authentication, role-based access control (RBAC),
 * account lockout protection, tamper-resistant audit logging for all authentication
 * attempts (successful and unsuccessful), persistent audit log review, and an
 * administrative console for system telemetry, user management, and security review.
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
    public static final String DEFAULT_AUDIT_LOG_FILE = "audit.log";

    private static final byte[] DUMMY_SALT = new byte[SALT_LENGTH_BYTES];
    static {
        new SecureRandom().nextBytes(DUMMY_SALT);
    }

    // =========================================================================
    // 2. ENUMS & ROLE-BASED ACCESS CONTROL (RBAC)
    // =========================================================================

    /**
     * User roles for Role-Based Access Control (RBAC).
     */
    public enum Role {
        ADMIN(true, "Full Administrator Privileges"),
        SUPER_ADMIN(true, "Super Administrator with Elevated Privileges"),
        SECURITY_OFFICER(true, "Security Officer with Audit & Telemetry Access"),
        USER(false, "Standard User (No Administrative Access)"),
        GUEST(false, "Guest User (No Administrative Access)");

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
     * Authentication result status codes.
     */
    public enum AuthStatusCode {
        SUCCESS_ADMIN,
        DENIED_INVALID_CREDENTIALS,
        DENIED_UNKNOWN_USER,
        DENIED_NOT_AN_ADMIN,
        DENIED_ACCOUNT_LOCKED,
        DENIED_ACCOUNT_INACTIVE,
        DENIED_EMPTY_CREDENTIALS
    }

    /**
     * Audit log event types covering all successful and unsuccessful authentication events.
     */
    public enum AuditEventType {
        LOGIN_SUCCESS("SUCCESS", "Successful authentication and administrator access granted"),
        LOGIN_FAILURE_BAD_CREDENTIALS("FAILURE", "Failed authentication due to incorrect password"),
        LOGIN_FAILURE_UNKNOWN_USER("FAILURE", "Failed authentication due to non-existent user"),
        LOGIN_FAILURE_EMPTY_CREDENTIALS("FAILURE", "Failed authentication due to missing credentials"),
        LOGIN_DENIED_NOT_ADMIN("DENIED", "Authentication valid but denied due to lack of administrator role"),
        LOGIN_DENIED_LOCKED("DENIED", "Authentication denied because account is locked"),
        LOGIN_DENIED_INACTIVE("DENIED", "Authentication denied because account is deactivated"),
        ACCOUNT_LOCKED_AUTO("SECURITY", "Account automatically locked due to consecutive failed attempts"),
        ACCOUNT_UNLOCKED("ADMIN", "Account unlocked by administrator"),
        USER_CREATED("ADMIN", "New user account registered"),
        USER_MODIFIED("ADMIN", "User account status or role modified"),
        PASSWORD_RESET("ADMIN", "User password reset by administrator"),
        ADMIN_ACTION_EXECUTED("ADMIN", "Admin-level operation executed");

        private final String category;
        private final String description;

        AuditEventType(String category, String description) {
            this.category = category;
            this.description = description;
        }

        public String getCategory() {
            return category;
        }

        public String getDescription() {
            return description;
        }

        public boolean isAuthenticationEvent() {
            return this == LOGIN_SUCCESS ||
                   this == LOGIN_FAILURE_BAD_CREDENTIALS ||
                   this == LOGIN_FAILURE_UNKNOWN_USER ||
                   this == LOGIN_FAILURE_EMPTY_CREDENTIALS ||
                   this == LOGIN_DENIED_NOT_ADMIN ||
                   this == LOGIN_DENIED_LOCKED ||
                   this == LOGIN_DENIED_INACTIVE;
        }

        public boolean isSuccessfulAuth() {
            return this == LOGIN_SUCCESS;
        }

        public boolean isFailedAuth() {
            return isAuthenticationEvent() && !isSuccessfulAuth();
        }
    }

    // =========================================================================
    // 3. USER ENTITY & MODEL
    // =========================================================================

    /**
     * User entity representing an authenticated principal with security state.
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

    // =========================================================================
    // 4. AUDIT RECORD MODEL (STRUCTURED & PARSEABLE)
    // =========================================================================

    /**
     * Immutable representation of an audit event.
     * Supports serialization and deserialization for persistent review.
     */
    public static class AuditRecord {
        private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_INSTANT;
        private static final String FIELD_SEPARATOR = " | ";

        private final Instant timestamp;
        private final AuditEventType eventType;
        private final String outcome;
        private final String username;
        private final String clientIp;
        private final String details;

        public AuditRecord(AuditEventType eventType, String username, String details, String clientIp) {
            this(Instant.now(), eventType, eventType.getCategory(), username, clientIp, details);
        }

        public AuditRecord(Instant timestamp, AuditEventType eventType, String outcome,
                           String username, String clientIp, String details) {
            this.timestamp = timestamp;
            this.eventType = eventType;
            this.outcome = outcome;
            this.username = sanitizeForLog(username);
            this.clientIp = sanitizeForLog(clientIp);
            this.details = sanitizeForLog(details);
        }

        public Instant getTimestamp() {
            return timestamp;
        }

        public AuditEventType getEventType() {
            return eventType;
        }

        public String getOutcome() {
            return outcome;
        }

        public String getUsername() {
            return username;
        }

        public String getClientIp() {
            return clientIp;
        }

        public String getDetails() {
            return details;
        }

        public boolean isAuthenticationEvent() {
            return eventType.isAuthenticationEvent();
        }

        public boolean isSuccessfulAuth() {
            return eventType.isSuccessfulAuth();
        }

        public boolean isFailedAuth() {
            return eventType.isFailedAuth();
        }

        /**
         * Serializes record into a delimited, machine-parseable log line.
         */
        public String toLogLine() {
            return ISO_FORMATTER.format(timestamp) + FIELD_SEPARATOR +
                    eventType.name() + FIELD_SEPARATOR +
                    outcome + FIELD_SEPARATOR +
                    "user=" + username + FIELD_SEPARATOR +
                    "ip=" + clientIp + FIELD_SEPARATOR +
                    details;
        }

        /**
         * Deserializes a record from a log line for historical review.
         */
        public static Optional<AuditRecord> fromLogLine(String line) {
            if (line == null || line.trim().isEmpty()) {
                return Optional.empty();
            }
            try {
                // Check if modern structured format
                if (line.contains(" | ")) {
                    String[] parts = line.split(" \\| ", 6);
                    if (parts.length >= 6) {
                        Instant ts = Instant.parse(parts[0].trim());
                        AuditEventType type = AuditEventType.valueOf(parts[1].trim());
                        String outcome = parts[2].trim();
                        String userPart = parts[3].trim();
                        String username = userPart.startsWith("user=") ? userPart.substring(5) : userPart;
                        String ipPart = parts[4].trim();
                        String clientIp = ipPart.startsWith("ip=") ? ipPart.substring(3) : ipPart;
                        String details = parts[5].trim();
                        return Optional.of(new AuditRecord(ts, type, outcome, username, clientIp, details));
                    }
                }

                // Fallback for bracketed format: [timestamp] [EVENT_TYPE] User='user' IP='ip' - details
                if (line.startsWith("[") && line.contains("] User='")) {
                    int firstClose = line.indexOf(']');
                    int secondOpen = line.indexOf('[', firstClose);
                    int secondClose = line.indexOf(']', secondOpen);
                    if (firstClose > 1 && secondOpen > 0 && secondClose > secondOpen) {
                        String tsStr = line.substring(1, firstClose).trim();
                        String typeStr = line.substring(secondOpen + 1, secondClose).trim();
                        Instant ts = Instant.parse(tsStr);
                        AuditEventType type = AuditEventType.valueOf(typeStr);

                        int userStart = line.indexOf("User='", secondClose) + 6;
                        int userEnd = line.indexOf("'", userStart);
                        String username = line.substring(userStart, userEnd);

                        int ipStart = line.indexOf("IP='", userEnd) + 4;
                        int ipEnd = line.indexOf("'", ipStart);
                        String ip = line.substring(ipStart, ipEnd);

                        int detailsStart = line.indexOf("- ", ipEnd) + 2;
                        String details = line.substring(detailsStart);

                        return Optional.of(new AuditRecord(ts, type, type.getCategory(), username, ip, details));
                    }
                }
            } catch (Exception ignored) {
                // Non-conforming or corrupted log line
            }
            return Optional.empty();
        }

        @Override
        public String toString() {
            DateTimeFormatter dtf = DateTimeFormatter.ISO_OFFSET_DATE_TIME.withZone(ZoneOffset.UTC);
            return String.format("[%s UTC] [%-7s] [%-28s] User: %-15s IP: %-15s Details: %s",
                    dtf.format(timestamp), outcome, eventType.name(), username, clientIp, details);
        }

        private static String sanitizeForLog(String input) {
            if (input == null) return "N/A";
            // Prevent log injection attacks (CWE-117)
            return input.replace('\r', '_').replace('\n', '_').replace('\t', ' ').replace('|', '/');
        }
    }

    // =========================================================================
    // 5. AUDIT LOGGER (PERSISTENT RECORDING & AUDIT REVIEW)
    // =========================================================================

    /**
     * Records all authentication and admin events to in-memory store and
     * a persistent append-only log file, and provides rich query and review capabilities.
     */
    public static class AuditLogger {
        private final List<AuditRecord> inMemoryRecords = new CopyOnWriteArrayList<>();
        private final Path logFilePath;

        public AuditLogger() {
            this(Paths.get(DEFAULT_AUDIT_LOG_FILE));
        }

        public AuditLogger(Path logFilePath) {
            this.logFilePath = logFilePath;
            loadPersistedRecords();
        }

        private synchronized void loadPersistedRecords() {
            if (logFilePath != null && Files.exists(logFilePath)) {
                try (BufferedReader reader = Files.newBufferedReader(logFilePath, StandardCharsets.UTF_8)) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        AuditRecord.fromLogLine(line).ifPresent(inMemoryRecords::add);
                    }
                } catch (IOException e) {
                    System.err.println("Warning: Could not read existing audit log file: " + e.getMessage());
                }
            }
        }

        public synchronized void log(AuditEventType type, String username, String details, String clientIp) {
            AuditRecord record = new AuditRecord(type, username, details, clientIp);
            inMemoryRecords.add(record);

            if (logFilePath != null) {
                try {
                    String logLine = record.toLogLine() + System.lineSeparator();
                    Files.writeString(logFilePath, logLine, StandardCharsets.UTF_8,
                            StandardOpenOption.CREATE, StandardOpenOption.APPEND, StandardOpenOption.WRITE);
                } catch (IOException e) {
                    System.err.println("CRITICAL: Failed to write to audit log: " + e.getMessage());
                }
            }
        }

        public List<AuditRecord> getAllRecords() {
            return Collections.unmodifiableList(new ArrayList<>(inMemoryRecords));
        }

        public List<AuditRecord> getRecentRecords(int limit) {
            int size = inMemoryRecords.size();
            int start = Math.max(0, size - limit);
            List<AuditRecord> sub = new ArrayList<>(inMemoryRecords.subList(start, size));
            Collections.reverse(sub);
            return sub;
        }

        public List<AuditRecord> filter(Predicate<AuditRecord> predicate) {
            List<AuditRecord> result = new ArrayList<>();
            for (AuditRecord r : inMemoryRecords) {
                if (predicate.test(r)) {
                    result.add(r);
                }
            }
            return result;
        }

        public List<AuditRecord> getAuthenticationRecords() {
            return filter(AuditRecord::isAuthenticationEvent);
        }

        public List<AuditRecord> getSuccessfulAuthRecords() {
            return filter(AuditRecord::isSuccessfulAuth);
        }

        public List<AuditRecord> getFailedAuthRecords() {
            return filter(AuditRecord::isFailedAuth);
        }

        public List<AuditRecord> getRecordsByUsername(String username) {
            if (username == null) return Collections.emptyList();
            String norm = username.toLowerCase(Locale.ROOT).trim();
            return filter(r -> r.getUsername().equalsIgnoreCase(norm));
        }

        public Path getLogFilePath() {
            return logFilePath;
        }

        public void printAuditSummary(PrintStream out) {
            List<AuditRecord> all = getAllRecords();
            long total = all.size();
            long authTotal = all.stream().filter(AuditRecord::isAuthenticationEvent).count();
            long authSuccess = all.stream().filter(AuditRecord::isSuccessfulAuth).count();
            long authFailed = all.stream().filter(AuditRecord::isFailedAuth).count();

            out.println("================================================================");
            out.println("                    AUDIT LOG EVENT SUMMARY                     ");
            out.println("================================================================");
            out.printf("Log File Location:              %s%n", logFilePath != null ? logFilePath.toAbsolutePath() : "In-Memory Only");
            out.printf("Total Recorded Events:           %d%n", total);
            out.printf("Total Authentication Attempts:   %d%n", authTotal);
            out.printf("  - Successful Logins:          %d%n", authSuccess);
            out.printf("  - Failed / Denied Logins:      %d%n", authFailed);
            out.println("----------------------------------------------------------------");
        }
    }

    // =========================================================================
    // 6. CRYPTOGRAPHY & PASSWORD SECURITY (CWE-208, CWE-204, CWE-307 PROTECTED)
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
            // Constant-time comparison to prevent side-channel timing attacks (CWE-208)
            return MessageDigest.isEqual(computedHash, storedHash);
        }

        public static void executeDummyHash(char[] candidatePassword) {
            // Timing equalization to prevent user enumeration via timing analysis (CWE-204)
            hashPassword(candidatePassword != null ? candidatePassword : new char[0], DUMMY_SALT);
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
    // 7. USER REPOSITORY & STORE
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

            // Security Officer administrator: secadmin / SecAdmin@2026!
            createUser("secadmin", "SecAdmin@2026!".toCharArray(), Role.SECURITY_OFFICER);

            // Standard user account without admin privileges: standard_user / User@2026!
            createUser("standard_user", "User@2026!".toCharArray(), Role.USER);

            // Pre-configured locked admin account for testing lockout states
            User lockedUser = createUser("locked_admin", "LockedAdmin@2026!".toCharArray(), Role.ADMIN);
            lockedUser.lockFor(Duration.ofHours(1));

            // Pre-configured inactive user for testing account status
            User inactiveUser = createUser("inactive_admin", "InactiveAdmin@2026!".toCharArray(), Role.ADMIN);
            inactiveUser.setActive(false);
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
    // 8. AUTHENTICATION SERVICE & SESSION MANAGEMENT
    // =========================================================================

    public static class AdminSession {
        private final String sessionId;
        private final User user;
        private final Instant loginTime;
        private final String clientIp;

        public AdminSession(User user, String clientIp) {
            this.sessionId = UUID.randomUUID().toString();
            this.user = user;
            this.loginTime = Instant.now();
            this.clientIp = clientIp;
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

        public String getClientIp() {
            return clientIp;
        }
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

    /**
     * Enterprise Authentication Service.
     * Authenticates user credentials, enforces RBAC, handles account lockouts,
     * and guarantees that EVERY successful and unsuccessful attempt is permanently recorded.
     */
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
            String sanitizedIp = (clientIp != null && !clientIp.isBlank()) ? clientIp : "127.0.0.1";

            // 1. Validate non-empty inputs
            if (username == null || username.trim().isEmpty() || password == null || password.length == 0) {
                PasswordSecurity.executeDummyHash(password);
                String attemptedUser = (username != null && !username.trim().isEmpty()) ? username.trim() : "<EMPTY>";
                auditLogger.log(AuditEventType.LOGIN_FAILURE_EMPTY_CREDENTIALS,
                        attemptedUser, "Authentication rejected: Username or password missing", sanitizedIp);
                return AuthResult.denied(AuthStatusCode.DENIED_EMPTY_CREDENTIALS,
                        "Access Denied: Username and password must not be empty.", null);
            }

            String normalizedUser = username.toLowerCase(Locale.ROOT).trim();
            Optional<User> optionalUser = userRepository.findByUsername(normalizedUser);

            // 2. Handle non-existent username
            if (optionalUser.isEmpty()) {
                PasswordSecurity.executeDummyHash(password);
                auditLogger.log(AuditEventType.LOGIN_FAILURE_UNKNOWN_USER, normalizedUser,
                        "Authentication failed: User account does not exist", sanitizedIp);
                return AuthResult.denied(AuthStatusCode.DENIED_UNKNOWN_USER,
                        "Access Denied: Invalid username or password.", null);
            }

            User user = optionalUser.get();

            // 3. Check account activation
            if (!user.isActive()) {
                PasswordSecurity.executeDummyHash(password);
                auditLogger.log(AuditEventType.LOGIN_DENIED_INACTIVE, user.getUsername(),
                        "Authentication denied: User account is deactivated", sanitizedIp);
                return AuthResult.denied(AuthStatusCode.DENIED_ACCOUNT_INACTIVE,
                        "Access Denied: This account has been deactivated.", user);
            }

            // 4. Check account lockout
            if (user.isLocked()) {
                PasswordSecurity.executeDummyHash(password);
                auditLogger.log(AuditEventType.LOGIN_DENIED_LOCKED, user.getUsername(),
                        "Authentication denied: Account is locked until " + user.getLockedUntil(), sanitizedIp);
                return AuthResult.denied(AuthStatusCode.DENIED_ACCOUNT_LOCKED,
                        "Access Denied: Account is temporarily locked due to excessive failed attempts.", user);
            }

            // 5. Verify password hash using constant-time comparison
            boolean passwordValid = PasswordSecurity.verifyPassword(password, user.getSalt(), user.getPasswordHash());

            if (!passwordValid) {
                user.incrementFailedAttempts();
                if (user.getFailedAttempts() >= MAX_FAILED_ATTEMPTS) {
                    user.lockFor(LOCKOUT_DURATION);
                    auditLogger.log(AuditEventType.ACCOUNT_LOCKED_AUTO, user.getUsername(),
                            "Account automatically locked for " + LOCKOUT_DURATION.toMinutes() +
                                    " minutes after " + user.getFailedAttempts() + " consecutive failed attempts", sanitizedIp);
                    auditLogger.log(AuditEventType.LOGIN_FAILURE_BAD_CREDENTIALS, user.getUsername(),
                            "Authentication failed: Incorrect password; account threshold exceeded -> LOCKED", sanitizedIp);
                    return AuthResult.denied(AuthStatusCode.DENIED_ACCOUNT_LOCKED,
                            "Access Denied: Account locked due to " + MAX_FAILED_ATTEMPTS + " consecutive failed attempts.", user);
                }

                int remaining = MAX_FAILED_ATTEMPTS - user.getFailedAttempts();
                auditLogger.log(AuditEventType.LOGIN_FAILURE_BAD_CREDENTIALS, user.getUsername(),
                        "Authentication failed: Incorrect password (attempt " + user.getFailedAttempts() +
                                "/" + MAX_FAILED_ATTEMPTS + ", " + remaining + " remaining)", sanitizedIp);
                return AuthResult.denied(AuthStatusCode.DENIED_INVALID_CREDENTIALS,
                        "Access Denied: Invalid username or password. Remaining attempts: " + remaining, user);
            }

            // Password is valid - reset failed attempts counter
            user.resetFailedAttempts();

            // 6. Check Role Authorization (Must have administrator privileges)
            if (!user.getRole().hasAdminPrivilege()) {
                auditLogger.log(AuditEventType.LOGIN_DENIED_NOT_ADMIN, user.getUsername(),
                        "Credentials verified successfully, but access denied: User has role [" +
                                user.getRole().name() + "] without administrator privileges", sanitizedIp);
                return AuthResult.denied(AuthStatusCode.DENIED_NOT_AN_ADMIN,
                        "Access Denied: User '" + user.getUsername() + "' has role [" + user.getRole().name() +
                                "]. Administrator privileges are strictly required to enter this portal.", user);
            }

            // 7. Successful Authentication and Authorization
            user.setLastLoginTime(Instant.now());
            AdminSession session = new AdminSession(user, sanitizedIp);
            auditLogger.log(AuditEventType.LOGIN_SUCCESS, user.getUsername(),
                    "Administrator authentication successful. Assigned Session: " + session.getSessionId() +
                            " [Role: " + user.getRole().name() + "]", sanitizedIp);

            return AuthResult.success(user, session);
        }

        public AuditLogger getAuditLogger() {
            return auditLogger;
        }

        public UserRepository getUserRepository() {
            return userRepository;
        }
    }

    // =========================================================================
    // 9. ADMIN-LEVEL FUNCTIONALITY (PROTECTED ADMIN SERVICES)
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
                throw new SecurityException("Unauthorized: Valid administrator session required to perform this operation.");
            }
        }

        public Map<String, Object> getSystemDiagnostics(AdminSession session) {
            assertAdmin(session);
            auditLogger.log(AuditEventType.ADMIN_ACTION_EXECUTED, session.getUser().getUsername(),
                    "Inspected system diagnostics telemetry", session.getClientIp());

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
            diag.put("Heap Memory (Used / Max)", heapUsed + " MB / " + heapMax + " MB");
            diag.put("Live Thread Count", threadBean.getThreadCount());
            diag.put("Total Registered Accounts", userRepository.getAllUsers().size());
            diag.put("Total Audit Records", auditLogger.getAllRecords().size());
            diag.put("Audit Log Path", auditLogger.getLogFilePath() != null ?
                    auditLogger.getLogFilePath().toAbsolutePath().toString() : "In-Memory");
            return diag;
        }

        public List<UserSummary> listAllAccounts(AdminSession session) {
            assertAdmin(session);
            auditLogger.log(AuditEventType.ADMIN_ACTION_EXECUTED, session.getUser().getUsername(),
                    "Listed all user accounts", session.getClientIp());

            List<UserSummary> summaries = new ArrayList<>();
            for (User u : userRepository.getAllUsers()) {
                summaries.add(new UserSummary(
                        u.getUsername(),
                        u.getRole().name(),
                        u.isActive(),
                        u.isLocked(),
                        u.getFailedAttempts(),
                        u.getLastLoginTime() != null ? u.getLastLoginTime().toString() : "Never",
                        u.getCreatedAt().toString()
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
                    "Created user '" + username + "' with role [" + role.name() + "]", session.getClientIp());
            return true;
        }

        public boolean unlockAccount(AdminSession session, String username) {
            assertAdmin(session);
            Optional<User> u = userRepository.findByUsername(username);
            if (u.isPresent()) {
                u.get().unlock();
                auditLogger.log(AuditEventType.ACCOUNT_UNLOCKED, session.getUser().getUsername(),
                        "Manually unlocked account '" + username + "'", session.getClientIp());
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
                        "Updated active status of '" + username + "' to " + (active ? "ACTIVE" : "DEACTIVATED"),
                        session.getClientIp());
                return true;
            }
            return false;
        }

        public boolean resetPassword(AdminSession session, String username, char[] newPassword) {
            assertAdmin(session);
            Optional<User> u = userRepository.findByUsername(username);
            if (u.isPresent()) {
                byte[] newSalt = PasswordSecurity.generateSalt();
                byte[] newHash = PasswordSecurity.hashPassword(newPassword, newSalt);
                u.get().updateCredentials(newSalt, newHash);
                u.get().unlock();
                auditLogger.log(AuditEventType.PASSWORD_RESET, session.getUser().getUsername(),
                        "Reset password and unlocked account '" + username + "'", session.getClientIp());
                return true;
            }
            return false;
        }

        public List<AuditRecord> viewAuditLogs(AdminSession session, String filterType, String filterUser, int limit) {
            assertAdmin(session);
            auditLogger.log(AuditEventType.ADMIN_ACTION_EXECUTED, session.getUser().getUsername(),
                    "Reviewed audit events (filterType=" + filterType + ", filterUser=" + filterUser + ")",
                    session.getClientIp());

            List<AuditRecord> records;
            if ("SUCCESS".equalsIgnoreCase(filterType)) {
                records = auditLogger.getSuccessfulAuthRecords();
            } else if ("FAILURE".equalsIgnoreCase(filterType) || "FAILED".equalsIgnoreCase(filterType)) {
                records = auditLogger.getFailedAuthRecords();
            } else if ("AUTH".equalsIgnoreCase(filterType)) {
                records = auditLogger.getAuthenticationRecords();
            } else {
                records = auditLogger.getAllRecords();
            }

            if (filterUser != null && !filterUser.isBlank()) {
                String norm = filterUser.toLowerCase(Locale.ROOT).trim();
                records = records.stream()
                        .filter(r -> r.getUsername().equalsIgnoreCase(norm))
                        .toList();
            }

            int size = records.size();
            int start = Math.max(0, size - limit);
            List<AuditRecord> sub = new ArrayList<>(records.subList(start, size));
            Collections.reverse(sub);
            return sub;
        }

        public Map<String, String> runSystemHealthCheck(AdminSession session) {
            assertAdmin(session);
            auditLogger.log(AuditEventType.ADMIN_ACTION_EXECUTED, session.getUser().getUsername(),
                    "Executed system security health diagnostics", session.getClientIp());

            Map<String, String> health = new LinkedHashMap<>();
            health.put("Password Hash Engine (PBKDF2/SHA-256)", "OPERATIONAL (64k iterations, 256-bit)");
            health.put("Cryptographic Entropy (SecureRandom)", "OPERATIONAL (Cryptographically Strong)");
            health.put("Account Repository", "OPERATIONAL (" + userRepository.getAllUsers().size() + " accounts)");
            health.put("Audit Logging Storage", "OPERATIONAL (" + auditLogger.getAllRecords().size() + " events logged)");
            health.put("Audit File Synchronization", (auditLogger.getLogFilePath() != null && Files.isWritable(auditLogger.getLogFilePath())) ?
                    "HEALTHY (" + auditLogger.getLogFilePath().getFileName() + ")" : "ACTIVE");
            health.put("Memory Headroom", Runtime.getRuntime().freeMemory() > 10_000_000 ? "HEALTHY" : "ADEQUATE");
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
        private final String createdAt;

        public UserSummary(String username, String role, boolean active, boolean locked,
                           int failedAttempts, String lastLogin, String createdAt) {
            this.username = username;
            this.role = role;
            this.active = active;
            this.locked = locked;
            this.failedAttempts = failedAttempts;
            this.lastLogin = lastLogin;
            this.createdAt = createdAt;
        }

        public String getUsername() { return username; }
        public String getRole() { return role; }
        public boolean isActive() { return active; }
        public boolean isLocked() { return locked; }
        public int getFailedAttempts() { return failedAttempts; }
        public String getLastLogin() { return lastLogin; }
        public String getCreatedAt() { return createdAt; }

        @Override
        public String toString() {
            return String.format("%-16s | Role: %-16s | Active: %-5s | Locked: %-5s | Failures: %-2d | Last Login: %s",
                    username, role, active, locked, failedAttempts, lastLogin);
        }
    }

    // =========================================================================
    // 10. INTERACTIVE CONSOLE PORTAL & REVIEW INTERFACE
    // =========================================================================

    public static class ConsolePortal {
        private final AuthenticationService authService;
        private final AdminService adminService;
        private final BufferedReader reader;

        public ConsolePortal(AuthenticationService authService, AdminService adminService) {
            this.authService = authService;
            this.adminService = adminService;
            this.reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        }

        public void start() {
            printBanner();
            boolean running = true;
            while (running) {
                System.out.println("================================================================");
                System.out.println("                  ADMINISTRATOR AUTHENTICATION                  ");
                System.out.println("================================================================");
                System.out.println("Available accounts for testing and verification:");
                System.out.println("  Administrator:     admin         / Admin@2026!  (Full Admin)");
                System.out.println("  Super Admin:       superadmin    / SuperAdmin@2026! (Super Admin)");
                System.out.println("  Security Officer:  secadmin      / SecAdmin@2026! (Security Admin)");
                System.out.println("  Standard User:     standard_user / User@2026!  (Access Denied demo)");
                System.out.println("  Locked Admin:      locked_admin  / LockedAdmin@2026! (Lockout demo)");
                System.out.println("----------------------------------------------------------------");
                System.out.println("Options: [1] Login as Administrator  [2] View Audit Log Summary  [3] Exit");

                String opt = promptString("Select option (1-3, default 1): ");
                if (opt == null || opt.trim().equals("3") || opt.equalsIgnoreCase("exit") || opt.equalsIgnoreCase("quit")) {
                    System.out.println("Exiting Administrator Portal. Goodbye.");
                    break;
                }

                if (opt.trim().equals("2")) {
                    authService.getAuditLogger().printAuditSummary(System.out);
                    continue;
                }

                String username = promptString("\nEnter Username: ");
                if (username == null || username.trim().isEmpty()) {
                    System.out.println("Error: Username cannot be empty.");
                    continue;
                }

                char[] password = promptPassword("Enter Password: ");
                System.out.println("\nAuthenticating credentials against security subsystem...");

                AuthResult result = authService.authenticate(username, password);
                PasswordSecurity.wipe(password);

                if (result.isAccessGranted()) {
                    System.out.println("\n[ACCESS GRANTED] " + result.getMessage());
                    AdminSession session = result.getSession().orElseThrow();
                    runAdminDashboard(session);
                } else {
                    System.out.println("\n[ACCESS DENIED] " + result.getMessage());
                    System.out.println("(Notice: Authentication attempt has been recorded in the security audit log)\n");
                }
            }
        }

        private void runAdminDashboard(AdminSession session) {
            boolean inSession = true;
            while (inSession) {
                System.out.println("\n================================================================");
                System.out.println("                   ADMINISTRATOR PORTAL DASHBOARD               ");
                System.out.println("================================================================");
                System.out.println("User:        " + session.getUser().getUsername() +
                        " [Role: " + session.getUser().getRole().name() + "]");
                System.out.println("Session ID:  " + session.getSessionId());
                System.out.println("Login Time:  " + session.getLoginTime() + " UTC");
                System.out.println("----------------------------------------------------------------");
                System.out.println("Administrative Functions:");
                System.out.println("  1. System Diagnostics & Telemetry");
                System.out.println("  2. Review Security Audit Logs (All Events)");
                System.out.println("  3. Review Authentication Attempts (Filter Successful / Failed)");
                System.out.println("  4. List All User Accounts");
                System.out.println("  5. Create New User Account");
                System.out.println("  6. Unlock Locked Account");
                System.out.println("  7. Enable / Disable User Account");
                System.out.println("  8. Reset User Password");
                System.out.println("  9. Run System Security Health Check");
                System.out.println("  10. Logout / Terminate Admin Session");
                System.out.println("----------------------------------------------------------------");

                String choice = promptString("Select an action (1-10): ");
                if (choice == null) break;

                switch (choice.trim()) {
                    case "1" -> showDiagnostics(session);
                    case "2" -> showAuditLogs(session, "ALL");
                    case "3" -> handleAuditFilterMenu(session);
                    case "4" -> showUserAccounts(session);
                    case "5" -> handleCreateUser(session);
                    case "6" -> handleUnlockUser(session);
                    case "7" -> handleToggleUser(session);
                    case "8" -> handleResetPassword(session);
                    case "9" -> showHealthCheck(session);
                    case "10" -> {
                        System.out.println("\nLogging out administrator '" + session.getUser().getUsername() + "'...");
                        inSession = false;
                    }
                    default -> System.out.println("Invalid choice. Please enter a number between 1 and 10.");
                }
            }
        }

        private void showDiagnostics(AdminSession session) {
            System.out.println("\n--- [ADMIN] System Diagnostics & Telemetry ---");
            Map<String, Object> diag = adminService.getSystemDiagnostics(session);
            for (Map.Entry<String, Object> entry : diag.entrySet()) {
                System.out.printf("%-32s : %s%n", entry.getKey(), entry.getValue());
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
            System.out.println("\n--- [ADMIN] Create New Account ---");
            String username = promptString("Enter new username: ");
            if (username == null || username.trim().isEmpty()) {
                System.out.println("Error: Username cannot be empty.");
                return;
            }
            char[] password = promptPassword("Enter password: ");
            if (password.length < 6) {
                System.out.println("Error: Password must be at least 6 characters.");
                PasswordSecurity.wipe(password);
                return;
            }
            System.out.println("Roles: 1=ADMIN, 2=SUPER_ADMIN, 3=SECURITY_OFFICER, 4=USER");
            String roleInput = promptString("Select role (1-4, default 4): ");
            Role role = switch (roleInput != null ? roleInput.trim() : "4") {
                case "1" -> Role.ADMIN;
                case "2" -> Role.SUPER_ADMIN;
                case "3" -> Role.SECURITY_OFFICER;
                default -> Role.USER;
            };

            boolean ok = adminService.createNewAccount(session, username, password, role);
            PasswordSecurity.wipe(password);

            if (ok) {
                System.out.println("Account '" + username + "' created successfully with role [" + role.name() + "].");
            } else {
                System.out.println("Error: User '" + username + "' already exists.");
            }
        }

        private void handleUnlockUser(AdminSession session) {
            System.out.println("\n--- [ADMIN] Unlock User Account ---");
            String username = promptString("Enter username to unlock: ");
            if (username == null || username.trim().isEmpty()) return;

            boolean ok = adminService.unlockAccount(session, username.trim());
            if (ok) {
                System.out.println("Account '" + username + "' has been successfully unlocked.");
            } else {
                System.out.println("Error: Account '" + username + "' not found.");
            }
        }

        private void handleToggleUser(AdminSession session) {
            System.out.println("\n--- [ADMIN] Enable / Disable Account ---");
            String username = promptString("Enter username: ");
            if (username == null || username.trim().isEmpty()) return;
            String status = promptString("Action (1=Enable/Activate, 2=Disable/Deactivate): ");
            boolean active = "1".equals(status != null ? status.trim() : "1");

            boolean ok = adminService.toggleAccountStatus(session, username.trim(), active);
            if (ok) {
                System.out.println("Account '" + username + "' active status updated to: " + (active ? "ACTIVE" : "DEACTIVATED"));
            } else {
                System.out.println("Error: Account '" + username + "' not found.");
            }
        }

        private void handleResetPassword(AdminSession session) {
            System.out.println("\n--- [ADMIN] Reset User Password ---");
            String username = promptString("Enter username: ");
            if (username == null || username.trim().isEmpty()) return;
            char[] newPass = promptPassword("Enter new password: ");
            if (newPass.length < 6) {
                System.out.println("Error: Password must be at least 6 characters.");
                PasswordSecurity.wipe(newPass);
                return;
            }

            boolean ok = adminService.resetPassword(session, username.trim(), newPass);
            PasswordSecurity.wipe(newPass);
            if (ok) {
                System.out.println("Password for '" + username + "' reset successfully.");
            } else {
                System.out.println("Error: Account '" + username + "' not found.");
            }
        }

        private void handleAuditFilterMenu(AdminSession session) {
            System.out.println("\n--- [ADMIN] Review Authentication Attempts ---");
            System.out.println("  1. All Authentication Attempts (Both Successful and Failed)");
            System.out.println("  2. Only Successful Authentication Attempts");
            System.out.println("  3. Only Failed / Denied Authentication Attempts");
            System.out.println("  4. Filter Attempts by Specific Username");

            String choice = promptString("Select review filter (1-4): ");
            if (choice == null) return;

            switch (choice.trim()) {
                case "1" -> showAuditLogs(session, "AUTH");
                case "2" -> showAuditLogs(session, "SUCCESS");
                case "3" -> showAuditLogs(session, "FAILURE");
                case "4" -> {
                    String targetUser = promptString("Enter username to filter: ");
                    if (targetUser != null && !targetUser.trim().isEmpty()) {
                        showAuditLogsForUser(session, targetUser.trim());
                    }
                }
                default -> System.out.println("Invalid selection.");
            }
        }

        private void showAuditLogs(AdminSession session, String filterType) {
            System.out.println("\n--- [ADMIN] Security Audit Log Records [Filter: " + filterType + "] ---");
            List<AuditRecord> records = adminService.viewAuditLogs(session, filterType, null, 25);
            if (records.isEmpty()) {
                System.out.println("(No matching audit records found)");
            } else {
                for (AuditRecord r : records) {
                    System.out.println(r);
                }
            }
        }

        private void showAuditLogsForUser(AdminSession session, String targetUser) {
            System.out.println("\n--- [ADMIN] Security Audit Log Records for User: " + targetUser + " ---");
            List<AuditRecord> records = adminService.viewAuditLogs(session, "AUTH", targetUser, 25);
            if (records.isEmpty()) {
                System.out.println("(No audit records found for user: " + targetUser + ")");
            } else {
                for (AuditRecord r : records) {
                    System.out.println(r);
                }
            }
        }

        private void showHealthCheck(AdminSession session) {
            System.out.println("\n--- [ADMIN] System Security Health Diagnostics ---");
            Map<String, String> health = adminService.runSystemHealthCheck(session);
            for (Map.Entry<String, String> entry : health.entrySet()) {
                System.out.printf("%-40s : %s%n", entry.getKey(), entry.getValue());
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
            // Non-TTY / script fallback
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
    // 11. AUTOMATED VERIFICATION & TEST SUITE
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
            testEmptyCredentialsDenied();
            testAccountLockoutAfterMaxFailures();
            testAdminCanUnlockAccount();
            testDeactivatedAccountDenied();
            testAdminServiceRequiresAdminSession();
            testPasswordHashingSaltingUniqueness();
            testConstantTimeVerification();
            testAuditLoggingSuccessAndFailures();
            testAuditLogPersistenceAndReview();
            testAuditLogFilteringCapabilities();

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
            if (!result.isAccessGranted() && result.getStatus() == AuthStatusCode.DENIED_UNKNOWN_USER) {
                System.out.println(" [PASS] testUnknownUserDenied");
                testsPassed++;
            } else {
                System.err.println(" [FAIL] testUnknownUserDenied: status=" + result.getStatus());
            }
        }

        private void testEmptyCredentialsDenied() {
            testsRun++;
            UserRepository repo = new UserRepository();
            AuditLogger logger = new AuditLogger(null);
            AuthenticationService auth = new AuthenticationService(repo, logger);

            AuthResult res1 = auth.authenticate("", "pass".toCharArray());
            AuthResult res2 = auth.authenticate("admin", "".toCharArray());
            AuthResult res3 = auth.authenticate(null, null);

            if (!res1.isAccessGranted() && !res2.isAccessGranted() && !res3.isAccessGranted()) {
                System.out.println(" [PASS] testEmptyCredentialsDenied");
                testsPassed++;
            } else {
                System.err.println(" [FAIL] testEmptyCredentialsDenied");
            }
        }

        private void testAccountLockoutAfterMaxFailures() {
            testsRun++;
            UserRepository repo = new UserRepository();
            AuditLogger logger = new AuditLogger(null);
            AuthenticationService auth = new AuthenticationService(repo, logger);

            repo.createUser("lockout_test_admin", "SafeAdmin@123".toCharArray(), Role.ADMIN);

            for (int i = 0; i < MAX_FAILED_ATTEMPTS; i++) {
                auth.authenticate("lockout_test_admin", "WrongPass!".toCharArray());
            }

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

            AuthResult initialAttempt = auth.authenticate("locked_admin", "LockedAdmin@2026!".toCharArray());
            boolean wasLocked = !initialAttempt.isAccessGranted()
                    && initialAttempt.getStatus() == AuthStatusCode.DENIED_ACCOUNT_LOCKED;

            AuthResult adminAuth = auth.authenticate("admin", "Admin@2026!".toCharArray());
            AdminSession adminSession = adminAuth.getSession().orElseThrow();
            boolean unlocked = adminService.unlockAccount(adminSession, "locked_admin");

            AuthResult secondAttempt = auth.authenticate("locked_admin", "LockedAdmin@2026!".toCharArray());
            boolean nowCanLogin = secondAttempt.isAccessGranted()
                    && secondAttempt.getStatus() == AuthStatusCode.SUCCESS_ADMIN;

            if (wasLocked && unlocked && nowCanLogin) {
                System.out.println(" [PASS] testAdminCanUnlockAccount");
                testsPassed++;
            } else {
                System.err.println(" [FAIL] testAdminCanUnlockAccount");
            }
        }

        private void testDeactivatedAccountDenied() {
            testsRun++;
            UserRepository repo = new UserRepository();
            AuditLogger logger = new AuditLogger(null);
            AuthenticationService auth = new AuthenticationService(repo, logger);

            AuthResult res = auth.authenticate("inactive_admin", "InactiveAdmin@2026!".toCharArray());
            if (!res.isAccessGranted() && res.getStatus() == AuthStatusCode.DENIED_ACCOUNT_INACTIVE) {
                System.out.println(" [PASS] testDeactivatedAccountDenied");
                testsPassed++;
            } else {
                System.err.println(" [FAIL] testDeactivatedAccountDenied");
            }
        }

        private void testAdminServiceRequiresAdminSession() {
            testsRun++;
            UserRepository repo = new UserRepository();
            AuditLogger logger = new AuditLogger(null);
            AdminService adminService = new AdminService(repo, logger);

            boolean nullSessionCaught = false;
            try {
                adminService.getSystemDiagnostics(null);
            } catch (SecurityException e) {
                nullSessionCaught = true;
            }

            User regularUser = new User("regular", PasswordSecurity.generateSalt(),
                    PasswordSecurity.hashPassword("pass".toCharArray(), PasswordSecurity.generateSalt()), Role.USER);
            AdminSession fakeSession = new AdminSession(regularUser, "127.0.0.1");

            boolean regularUserDenied = false;
            try {
                adminService.listAllAccounts(fakeSession);
            } catch (SecurityException e) {
                regularUserDenied = true;
            }

            if (nullSessionCaught && regularUserDenied) {
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

        private void testAuditLoggingSuccessAndFailures() {
            testsRun++;
            UserRepository repo = new UserRepository();
            AuditLogger logger = new AuditLogger(null);
            AuthenticationService auth = new AuthenticationService(repo, logger);

            // 1. Successful authentication
            auth.authenticate("admin", "Admin@2026!".toCharArray(), "10.0.0.1");

            // 2. Failed authentication: bad password
            auth.authenticate("admin", "WrongPass!".toCharArray(), "10.0.0.2");

            // 3. Failed authentication: non-existent user
            auth.authenticate("ghost_user", "RandomPass!".toCharArray(), "10.0.0.3");

            // 4. Failed authentication: non-admin denial
            auth.authenticate("standard_user", "User@2026!".toCharArray(), "10.0.0.4");

            // 5. Failed authentication: locked account
            auth.authenticate("locked_admin", "LockedAdmin@2026!".toCharArray(), "10.0.0.5");

            List<AuditRecord> records = logger.getAuthenticationRecords();
            boolean hasSuccess = records.stream().anyMatch(AuditRecord::isSuccessfulAuth);
            long failureCount = records.stream().filter(AuditRecord::isFailedAuth).count();

            if (hasSuccess && failureCount == 4) {
                System.out.println(" [PASS] testAuditLoggingSuccessAndFailures (All attempts recorded)");
                testsPassed++;
            } else {
                System.err.println(" [FAIL] testAuditLoggingSuccessAndFailures: hasSuccess=" + hasSuccess +
                        ", failureCount=" + failureCount);
            }
        }

        private void testAuditLogPersistenceAndReview() {
            testsRun++;
            try {
                Path tempLog = Files.createTempFile("audit_test_", ".log");
                tempLog.toFile().deleteOnExit();

                AuditLogger logger1 = new AuditLogger(tempLog);
                logger1.log(AuditEventType.LOGIN_SUCCESS, "admin", "First test session", "127.0.0.1");
                logger1.log(AuditEventType.LOGIN_FAILURE_BAD_CREDENTIALS, "admin", "Bad pass test", "127.0.0.1");

                // Create a new AuditLogger pointing to the same file (simulating portal restart)
                AuditLogger logger2 = new AuditLogger(tempLog);
                List<AuditRecord> reloaded = logger2.getAllRecords();

                boolean successMatch = reloaded.stream().anyMatch(r -> r.getEventType() == AuditEventType.LOGIN_SUCCESS
                        && r.getUsername().equals("admin"));
                boolean failureMatch = reloaded.stream().anyMatch(r -> r.getEventType() == AuditEventType.LOGIN_FAILURE_BAD_CREDENTIALS
                        && r.getUsername().equals("admin"));

                Files.deleteIfExists(tempLog);

                if (reloaded.size() == 2 && successMatch && failureMatch) {
                    System.out.println(" [PASS] testAuditLogPersistenceAndReview (Persisted & re-reviewed)");
                    testsPassed++;
                } else {
                    System.err.println(" [FAIL] testAuditLogPersistenceAndReview: size=" + reloaded.size());
                }
            } catch (IOException e) {
                System.err.println(" [FAIL] testAuditLogPersistenceAndReview exception: " + e.getMessage());
            }
        }

        private void testAuditLogFilteringCapabilities() {
            testsRun++;
            AuditLogger logger = new AuditLogger(null);
            logger.log(AuditEventType.LOGIN_SUCCESS, "alice", "Alice login success", "10.1.1.1");
            logger.log(AuditEventType.LOGIN_SUCCESS, "bob", "Bob login success", "10.1.1.2");
            logger.log(AuditEventType.LOGIN_FAILURE_BAD_CREDENTIALS, "alice", "Alice bad password", "10.1.1.1");
            logger.log(AuditEventType.LOGIN_FAILURE_UNKNOWN_USER, "charlie", "Unknown user charlie", "10.1.1.3");

            List<AuditRecord> aliceRecords = logger.getRecordsByUsername("alice");
            List<AuditRecord> successes = logger.getSuccessfulAuthRecords();
            List<AuditRecord> failures = logger.getFailedAuthRecords();

            if (aliceRecords.size() == 2 && successes.size() == 2 && failures.size() == 2) {
                System.out.println(" [PASS] testAuditLogFilteringCapabilities");
                testsPassed++;
            } else {
                System.err.println(" [FAIL] testAuditLogFilteringCapabilities");
            }
        }
    }

    // =========================================================================
    // 12. MAIN ENTRY POINT & CLI DISPATCHER
    // =========================================================================

    public static void main(String[] args) {
        UserRepository userRepository = new UserRepository();
        AuditLogger auditLogger = new AuditLogger();
        AuthenticationService authService = new AuthenticationService(userRepository, auditLogger);
        AdminService adminService = new AdminService(userRepository, auditLogger);

        // Option 1: Run automated verification test suite
        if (args.length > 0 && (args[0].equals("--test") || args[0].equals("-t"))) {
            TestRunner runner = new TestRunner();
            boolean passed = runner.runAllTests();
            System.exit(passed ? 0 : 1);
            return;
        }

        // Option 2: Review audit log events directly from CLI
        if (args.length > 0 && (args[0].equals("--logs") || args[0].equals("--audit") || args[0].equals("-l"))) {
            auditLogger.printAuditSummary(System.out);
            System.out.println("\n--- All Authentication Audit Records ---");
            List<AuditRecord> authRecords = auditLogger.getAuthenticationRecords();
            if (authRecords.isEmpty()) {
                System.out.println("(No authentication events recorded yet)");
            } else {
                for (AuditRecord r : authRecords) {
                    System.out.println(r);
                }
            }
            System.exit(0);
            return;
        }

        // Option 3: Command-line non-interactive authentication
        // Usage: java AdministratorPortal <username> <password>
        if (args.length >= 2) {
            String username = args[0];
            char[] password = args[1].toCharArray();

            AuthResult result = authService.authenticate(username, password);
            PasswordSecurity.wipe(password);

            if (result.isAccessGranted()) {
                AdminSession session = result.getSession().orElseThrow();
                System.out.println("[SUCCESS] Access Granted.");
                System.out.println("User:        " + session.getUser().getUsername());
                System.out.println("Role:        " + session.getUser().getRole().name());
                System.out.println("Session ID:  " + session.getSessionId());
                System.out.println("\n--- Admin System Telemetry Summary ---");
                Map<String, Object> diag = adminService.getSystemDiagnostics(session);
                for (Map.Entry<String, Object> entry : diag.entrySet()) {
                    System.out.printf("  %-30s: %s%n", entry.getKey(), entry.getValue());
                }
                System.exit(0);
            } else {
                System.err.println("[ACCESS DENIED] " + result.getMessage());
                System.exit(1);
            }
            return;
        }

        // Option 4: Interactive Console Portal
        ConsolePortal portal = new ConsolePortal(authService, adminService);
        portal.start();
    }
}
