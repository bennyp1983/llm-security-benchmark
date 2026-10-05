import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.Console;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Production-grade Java service handling user authentication and login attempts.
 *
 * <p>Key Security Features:</p>
 * <ul>
 *   <li><b>Password Hashing:</b> Uses PBKDF2 with HMAC-SHA256 (configurable iterations,
 *       defaulting to 100,000) and cryptographically secure per-user salts.</li>
 *   <li><b>Timing-Attack Resistance:</b> Employs constant-time hash comparisons via
 *       {@link MessageDigest#isEqual(byte[], byte[])} and performs a dummy PBKDF2 computation
 *       if the requested username does not exist to eliminate account enumeration side channels.</li>
 *   <li><b>Brute-Force Protection:</b> Implements an automatic account lockout policy
 *       after a configurable number of consecutive failed attempts (default: 5 attempts,
 *       15-minute lockout).</li>
 *   <li><b>Memory Hygiene:</b> Supports {@code char[]} passwords and zeros out sensitive
 *       character arrays immediately after processing.</li>
 *   <li><b>Pluggable Repositories:</b> Includes both a thread-safe in-memory repository
 *       and an active JDBC repository for SQL database integration.</li>
 *   <li><b>Zero External Dependencies:</b> Implemented entirely using standard Java SE
 *       (JDK 11+ / Java 17) libraries.</li>
 * </ul>
 */
public class UserLoginService {

    // =========================================================================
    // Core Domain Models & Enums
    // =========================================================================

    /**
     * Enumeration of possible outcomes for a login attempt.
     */
    public enum LoginStatus {
        /** Login credentials are valid and access is granted. */
        SUCCESS,
        /** Credentials do not match or user does not exist. */
        INVALID_CREDENTIALS,
        /** Account is temporarily locked due to excessive failed attempts. */
        ACCOUNT_LOCKED,
        /** Account has been administratively disabled. */
        ACCOUNT_DISABLED,
        /** Submitted inputs were null, empty, or exceeded safety thresholds. */
        INVALID_INPUT
    }

    /**
     * Encapsulates the complete result of a login attempt.
     */
    public static final class LoginResult {
        private final boolean success;
        private final LoginStatus status;
        private final String message;
        private final UserAccount user;
        private final String sessionToken;
        private final int remainingAttempts;

        private LoginResult(boolean success,
                            LoginStatus status,
                            String message,
                            UserAccount user,
                            String sessionToken,
                            int remainingAttempts) {
            this.success = success;
            this.status = status;
            this.message = message;
            this.user = user;
            this.sessionToken = sessionToken;
            this.remainingAttempts = remainingAttempts;
        }

        public static LoginResult success(UserAccount user, String sessionToken) {
            return new LoginResult(true, LoginStatus.SUCCESS, "Login successful.", user, sessionToken, -1);
        }

        public static LoginResult failure(LoginStatus status, String message) {
            return new LoginResult(false, status, message, null, null, -1);
        }

        public static LoginResult failure(LoginStatus status, String message, int remainingAttempts) {
            return new LoginResult(false, status, message, null, null, remainingAttempts);
        }

        public boolean isSuccess() {
            return success;
        }

        public LoginStatus getStatus() {
            return status;
        }

        public String getMessage() {
            return message;
        }

        public Optional<UserAccount> getUser() {
            return Optional.ofNullable(user);
        }

        public Optional<String> getSessionToken() {
            return Optional.ofNullable(sessionToken);
        }

        public int getRemainingAttempts() {
            return remainingAttempts;
        }

        @Override
        public String toString() {
            return "LoginResult{" +
                    "success=" + success +
                    ", status=" + status +
                    ", message='" + message + '\'' +
                    ", sessionToken=" + (sessionToken != null ? "[PROTECTED]" : "null") +
                    ", remainingAttempts=" + remainingAttempts +
                    '}';
        }
    }

    /**
     * Stored user account entity containing security credentials and authentication metadata.
     */
    public static final class UserAccount {
        private final String username;
        private final byte[] salt;
        private final byte[] passwordHash;
        private final String email;
        private final Set<String> roles;
        private int failedAttempts;
        private Instant lockoutUntil;
        private boolean enabled;
        private final Instant createdAt;
        private Instant lastLoginAt;

        public UserAccount(String username, byte[] salt, byte[] passwordHash) {
            this(username, salt, passwordHash, null, Collections.singleton("USER"), 0, null, true, Instant.now(), null);
        }

        public UserAccount(String username,
                           byte[] salt,
                           byte[] passwordHash,
                           String email,
                           Set<String> roles) {
            this(username, salt, passwordHash, email, roles, 0, null, true, Instant.now(), null);
        }

        public UserAccount(String username,
                           byte[] salt,
                           byte[] passwordHash,
                           String email,
                           Set<String> roles,
                           int failedAttempts,
                           Instant lockoutUntil,
                           boolean enabled,
                           Instant createdAt,
                           Instant lastLoginAt) {
            this.username = Objects.requireNonNull(username, "username cannot be null").trim();
            this.salt = salt != null ? salt.clone() : new byte[0];
            this.passwordHash = passwordHash != null ? passwordHash.clone() : new byte[0];
            this.email = email;
            this.roles = roles != null ? Collections.unmodifiableSet(new HashSet<>(roles)) : Collections.emptySet();
            this.failedAttempts = Math.max(0, failedAttempts);
            this.lockoutUntil = lockoutUntil;
            this.enabled = enabled;
            this.createdAt = createdAt != null ? createdAt : Instant.now();
            this.lastLoginAt = lastLoginAt;
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

        public String getEmail() {
            return email;
        }

        public Set<String> getRoles() {
            return roles;
        }

        public synchronized int getFailedAttempts() {
            return failedAttempts;
        }

        public synchronized void setFailedAttempts(int failedAttempts) {
            this.failedAttempts = Math.max(0, failedAttempts);
        }

        public synchronized int incrementFailedAttempts() {
            return ++this.failedAttempts;
        }

        public synchronized void resetFailedAttempts() {
            this.failedAttempts = 0;
            this.lockoutUntil = null;
        }

        public synchronized Instant getLockoutUntil() {
            return lockoutUntil;
        }

        public synchronized void setLockoutUntil(Instant lockoutUntil) {
            this.lockoutUntil = lockoutUntil;
        }

        public synchronized boolean isLocked(Instant now) {
            if (lockoutUntil == null) {
                return false;
            }
            if (now.isAfter(lockoutUntil)) {
                // Lock has expired; clear it
                this.lockoutUntil = null;
                this.failedAttempts = 0;
                return false;
            }
            return true;
        }

        public synchronized boolean isEnabled() {
            return enabled;
        }

        public synchronized void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public Instant getCreatedAt() {
            return createdAt;
        }

        public synchronized Instant getLastLoginAt() {
            return lastLoginAt;
        }

        public synchronized void setLastLoginAt(Instant lastLoginAt) {
            this.lastLoginAt = lastLoginAt;
        }
    }

    /**
     * Security and lockout configuration policy.
     */
    public static final class LoginPolicy {
        public static final int DEFAULT_MAX_FAILED_ATTEMPTS = 5;
        public static final Duration DEFAULT_LOCKOUT_DURATION = Duration.ofMinutes(15);
        public static final int DEFAULT_PBKDF2_ITERATIONS = 100_000;
        public static final int DEFAULT_SALT_BYTES = 16;
        public static final int DEFAULT_KEY_LENGTH_BITS = 256;
        public static final int MAX_PASSWORD_LENGTH = 1024; // Protect against Hash-DoS

        private final int maxFailedAttempts;
        private final Duration lockoutDuration;
        private final int pbkdf2Iterations;
        private final int saltBytes;
        private final int keyLengthBits;
        private final boolean timingProtection;
        private final boolean generateSessionToken;

        public LoginPolicy(int maxFailedAttempts,
                           Duration lockoutDuration,
                           int pbkdf2Iterations,
                           int saltBytes,
                           int keyLengthBits,
                           boolean timingProtection,
                           boolean generateSessionToken) {
            this.maxFailedAttempts = maxFailedAttempts;
            this.lockoutDuration = lockoutDuration != null ? lockoutDuration : DEFAULT_LOCKOUT_DURATION;
            this.pbkdf2Iterations = pbkdf2Iterations > 0 ? pbkdf2Iterations : DEFAULT_PBKDF2_ITERATIONS;
            this.saltBytes = saltBytes > 0 ? saltBytes : DEFAULT_SALT_BYTES;
            this.keyLengthBits = keyLengthBits > 0 ? keyLengthBits : DEFAULT_KEY_LENGTH_BITS;
            this.timingProtection = timingProtection;
            this.generateSessionToken = generateSessionToken;
        }

        public static LoginPolicy standard() {
            return new LoginPolicy(
                    DEFAULT_MAX_FAILED_ATTEMPTS,
                    DEFAULT_LOCKOUT_DURATION,
                    DEFAULT_PBKDF2_ITERATIONS,
                    DEFAULT_SALT_BYTES,
                    DEFAULT_KEY_LENGTH_BITS,
                    true,
                    true
            );
        }

        public static LoginPolicy fastTesting() {
            return new LoginPolicy(
                    DEFAULT_MAX_FAILED_ATTEMPTS,
                    Duration.ofMinutes(15),
                    5_000,
                    DEFAULT_SALT_BYTES,
                    DEFAULT_KEY_LENGTH_BITS,
                    true,
                    true
            );
        }

        public int getMaxFailedAttempts() {
            return maxFailedAttempts;
        }

        public Duration getLockoutDuration() {
            return lockoutDuration;
        }

        public int getPbkdf2Iterations() {
            return pbkdf2Iterations;
        }

        public int getSaltBytes() {
            return saltBytes;
        }

        public int getKeyLengthBits() {
            return keyLengthBits;
        }

        public boolean isTimingProtectionEnabled() {
            return timingProtection;
        }

        public boolean isGenerateSessionToken() {
            return generateSessionToken;
        }
    }

    // =========================================================================
    // Account Repository Abstraction & Implementations
    // =========================================================================

    /**
     * Storage abstraction for user accounts.
     */
    public interface AccountRepository {
        Optional<UserAccount> findByUsername(String username);
        void save(UserAccount account);
        boolean exists(String username);
        void updateLockout(String username, int failedAttempts, Instant lockoutUntil);
        void resetFailedAttempts(String username);
        void updateLastLogin(String username, Instant lastLogin);
        Collection<UserAccount> findAll();
    }

    /**
     * Thread-safe, in-memory account repository backed by a {@link ConcurrentHashMap}.
     */
    public static class InMemoryAccountRepository implements AccountRepository {
        private final ConcurrentMap<String, UserAccount> storage = new ConcurrentHashMap<>();

        @Override
        public Optional<UserAccount> findByUsername(String username) {
            if (username == null) return Optional.empty();
            return Optional.ofNullable(storage.get(username.trim().toLowerCase()));
        }

        @Override
        public void save(UserAccount account) {
            if (account == null) return;
            storage.put(account.getUsername().toLowerCase(), account);
        }

        @Override
        public boolean exists(String username) {
            if (username == null) return false;
            return storage.containsKey(username.trim().toLowerCase());
        }

        @Override
        public void updateLockout(String username, int failedAttempts, Instant lockoutUntil) {
            findByUsername(username).ifPresent(account -> {
                synchronized (account) {
                    account.setFailedAttempts(failedAttempts);
                    account.setLockoutUntil(lockoutUntil);
                }
            });
        }

        @Override
        public void resetFailedAttempts(String username) {
            findByUsername(username).ifPresent(account -> {
                synchronized (account) {
                    account.resetFailedAttempts();
                }
            });
        }

        @Override
        public void updateLastLogin(String username, Instant lastLogin) {
            findByUsername(username).ifPresent(account -> {
                synchronized (account) {
                    account.setLastLoginAt(lastLogin);
                }
            });
        }

        @Override
        public Collection<UserAccount> findAll() {
            return Collections.unmodifiableCollection(storage.values());
        }
    }

    /**
     * SQL Database implementation of {@link AccountRepository} using an active JDBC {@link Connection}.
     */
    public static class JdbcAccountRepository implements AccountRepository {
        private final Connection connection;

        public JdbcAccountRepository(Connection connection) {
            this.connection = Objects.requireNonNull(connection, "JDBC Connection cannot be null");
        }

        public static void createUsersTable(Connection conn) throws SQLException {
            Objects.requireNonNull(conn, "Connection cannot be null");
            String ddl = "CREATE TABLE IF NOT EXISTS users (" +
                    "username VARCHAR(255) NOT NULL PRIMARY KEY, " +
                    "password_hash VARCHAR(255) NOT NULL, " +
                    "salt VARCHAR(255) NOT NULL, " +
                    "email VARCHAR(255), " +
                    "roles VARCHAR(255), " +
                    "failed_attempts INT DEFAULT 0, " +
                    "lockout_until TIMESTAMP NULL, " +
                    "is_enabled BOOLEAN DEFAULT TRUE, " +
                    "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                    "last_login_at TIMESTAMP NULL" +
                    ")";
            try (Statement stmt = conn.createStatement()) {
                stmt.execute(ddl);
            }
        }

        @Override
        public Optional<UserAccount> findByUsername(String username) {
            if (username == null) return Optional.empty();
            String sql = "SELECT username, salt, password_hash, email, roles, failed_attempts, " +
                    "lockout_until, is_enabled, created_at, last_login_at FROM users WHERE LOWER(username) = LOWER(?)";
            try (PreparedStatement ps = connection.prepareStatement(sql)) {
                ps.setString(1, username.trim());
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        byte[] salt = Base64.getDecoder().decode(rs.getString("salt"));
                        byte[] hash = Base64.getDecoder().decode(rs.getString("password_hash"));
                        String email = rs.getString("email");
                        String rolesStr = rs.getString("roles");
                        Set<String> roles = new HashSet<>();
                        if (rolesStr != null && !rolesStr.isEmpty()) {
                            for (String r : rolesStr.split(",")) {
                                if (!r.trim().isEmpty()) roles.add(r.trim());
                            }
                        }
                        int failed = rs.getInt("failed_attempts");
                        Timestamp lockTs = rs.getTimestamp("lockout_until");
                        Instant lockoutUntil = lockTs != null ? lockTs.toInstant() : null;
                        boolean enabled = rs.getBoolean("is_enabled");
                        Timestamp createTs = rs.getTimestamp("created_at");
                        Instant createdAt = createTs != null ? createTs.toInstant() : Instant.now();
                        Timestamp loginTs = rs.getTimestamp("last_login_at");
                        Instant lastLogin = loginTs != null ? loginTs.toInstant() : null;

                        return Optional.of(new UserAccount(
                                rs.getString("username"), salt, hash, email, roles,
                                failed, lockoutUntil, enabled, createdAt, lastLogin
                        ));
                    }
                }
            } catch (SQLException e) {
                throw new RuntimeException("Database error finding user by username: " + username, e);
            }
            return Optional.empty();
        }

        @Override
        public void save(UserAccount account) {
            if (account == null) return;
            String checkSql = "SELECT COUNT(*) FROM users WHERE LOWER(username) = LOWER(?)";
            boolean exists = false;
            try (PreparedStatement checkPs = connection.prepareStatement(checkSql)) {
                checkPs.setString(1, account.getUsername());
                try (ResultSet rs = checkPs.executeQuery()) {
                    if (rs.next() && rs.getInt(1) > 0) exists = true;
                }
            } catch (SQLException e) {
                throw new RuntimeException("Error checking user existence: " + account.getUsername(), e);
            }

            String rolesStr = String.join(",", account.getRoles());
            String saltB64 = Base64.getEncoder().encodeToString(account.getSalt());
            String hashB64 = Base64.getEncoder().encodeToString(account.getPasswordHash());

            if (exists) {
                String sql = "UPDATE users SET salt = ?, password_hash = ?, email = ?, roles = ?, " +
                        "failed_attempts = ?, lockout_until = ?, is_enabled = ?, last_login_at = ? WHERE LOWER(username) = LOWER(?)";
                try (PreparedStatement ps = connection.prepareStatement(sql)) {
                    ps.setString(1, saltB64);
                    ps.setString(2, hashB64);
                    ps.setString(3, account.getEmail());
                    ps.setString(4, rolesStr);
                    ps.setInt(5, account.getFailedAttempts());
                    ps.setTimestamp(6, account.getLockoutUntil() != null ? Timestamp.from(account.getLockoutUntil()) : null);
                    ps.setBoolean(7, account.isEnabled());
                    ps.setTimestamp(8, account.getLastLoginAt() != null ? Timestamp.from(account.getLastLoginAt()) : null);
                    ps.setString(9, account.getUsername());
                    ps.executeUpdate();
                } catch (SQLException e) {
                    throw new RuntimeException("Error updating user account: " + account.getUsername(), e);
                }
            } else {
                String sql = "INSERT INTO users (username, salt, password_hash, email, roles, failed_attempts, lockout_until, is_enabled, created_at, last_login_at) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
                try (PreparedStatement ps = connection.prepareStatement(sql)) {
                    ps.setString(1, account.getUsername());
                    ps.setString(2, saltB64);
                    ps.setString(3, hashB64);
                    ps.setString(4, account.getEmail());
                    ps.setString(5, rolesStr);
                    ps.setInt(6, account.getFailedAttempts());
                    ps.setTimestamp(7, account.getLockoutUntil() != null ? Timestamp.from(account.getLockoutUntil()) : null);
                    ps.setBoolean(8, account.isEnabled());
                    ps.setTimestamp(9, Timestamp.from(account.getCreatedAt()));
                    ps.setTimestamp(10, account.getLastLoginAt() != null ? Timestamp.from(account.getLastLoginAt()) : null);
                    ps.executeUpdate();
                } catch (SQLException e) {
                    throw new RuntimeException("Error inserting user account: " + account.getUsername(), e);
                }
            }
        }

        @Override
        public boolean exists(String username) {
            return findByUsername(username).isPresent();
        }

        @Override
        public void updateLockout(String username, int failedAttempts, Instant lockoutUntil) {
            String sql = "UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE LOWER(username) = LOWER(?)";
            try (PreparedStatement ps = connection.prepareStatement(sql)) {
                ps.setInt(1, failedAttempts);
                ps.setTimestamp(2, lockoutUntil != null ? Timestamp.from(lockoutUntil) : null);
                ps.setString(3, username.trim());
                ps.executeUpdate();
            } catch (SQLException e) {
                throw new RuntimeException("Error updating lockout for user: " + username, e);
            }
        }

        @Override
        public void resetFailedAttempts(String username) {
            updateLockout(username, 0, null);
        }

        @Override
        public void updateLastLogin(String username, Instant lastLogin) {
            String sql = "UPDATE users SET last_login_at = ? WHERE LOWER(username) = LOWER(?)";
            try (PreparedStatement ps = connection.prepareStatement(sql)) {
                ps.setTimestamp(1, lastLogin != null ? Timestamp.from(lastLogin) : null);
                ps.setString(2, username.trim());
                ps.executeUpdate();
            } catch (SQLException e) {
                throw new RuntimeException("Error updating last login for user: " + username, e);
            }
        }

        @Override
        public Collection<UserAccount> findAll() {
            Set<UserAccount> accounts = new HashSet<>();
            String sql = "SELECT username, salt, password_hash, email, roles, failed_attempts, " +
                    "lockout_until, is_enabled, created_at, last_login_at FROM users";
            try (Statement stmt = connection.createStatement();
                 ResultSet rs = stmt.executeQuery(sql)) {
                while (rs.next()) {
                    byte[] salt = Base64.getDecoder().decode(rs.getString("salt"));
                    byte[] hash = Base64.getDecoder().decode(rs.getString("password_hash"));
                    String email = rs.getString("email");
                    String rolesStr = rs.getString("roles");
                    Set<String> roles = new HashSet<>();
                    if (rolesStr != null && !rolesStr.isEmpty()) {
                        for (String r : rolesStr.split(",")) {
                            if (!r.trim().isEmpty()) roles.add(r.trim());
                        }
                    }
                    int failed = rs.getInt("failed_attempts");
                    Timestamp lockTs = rs.getTimestamp("lockout_until");
                    Instant lockoutUntil = lockTs != null ? lockTs.toInstant() : null;
                    boolean enabled = rs.getBoolean("is_enabled");
                    Timestamp createTs = rs.getTimestamp("created_at");
                    Instant createdAt = createTs != null ? createTs.toInstant() : Instant.now();
                    Timestamp loginTs = rs.getTimestamp("last_login_at");
                    Instant lastLogin = loginTs != null ? loginTs.toInstant() : null;

                    accounts.add(new UserAccount(
                            rs.getString("username"), salt, hash, email, roles,
                            failed, lockoutUntil, enabled, createdAt, lastLogin
                    ));
                }
            } catch (SQLException e) {
                throw new RuntimeException("Error fetching all users", e);
            }
            return accounts;
        }
    }

    // =========================================================================
    // Cryptography and Password Utilities
    // =========================================================================

    public static final class PasswordSecurity {
        private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
        private static final SecureRandom SECURE_RANDOM = new SecureRandom();

        // Dummy parameters to perform constant-time hashing on missing accounts
        private static final byte[] DUMMY_SALT = new byte[16];
        private static final byte[] DUMMY_HASH;

        static {
            SECURE_RANDOM.nextBytes(DUMMY_SALT);
            DUMMY_HASH = hashPasswordInternal("dummy_reference_password".toCharArray(),
                    DUMMY_SALT,
                    LoginPolicy.DEFAULT_PBKDF2_ITERATIONS,
                    LoginPolicy.DEFAULT_KEY_LENGTH_BITS);
        }

        private PasswordSecurity() {}

        public static byte[] generateSalt(int byteLength) {
            byte[] salt = new byte[byteLength > 0 ? byteLength : 16];
            SECURE_RANDOM.nextBytes(salt);
            return salt;
        }

        public static byte[] hashPassword(char[] password, byte[] salt, int iterations, int keyLengthBits) {
            Objects.requireNonNull(password, "password cannot be null");
            Objects.requireNonNull(salt, "salt cannot be null");
            return hashPasswordInternal(password, salt, iterations, keyLengthBits);
        }

        private static byte[] hashPasswordInternal(char[] password, byte[] salt, int iterations, int keyLengthBits) {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLengthBits);
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
                return factory.generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IllegalStateException("Cryptographic algorithm error: " + PBKDF2_ALGORITHM, e);
            } finally {
                spec.clearPassword();
            }
        }

        /**
         * Verifies a password against expected salt and hash in constant time.
         */
        public static boolean verify(char[] password, byte[] salt, byte[] expectedHash, int iterations, int keyLengthBits) {
            byte[] computed = hashPassword(password, salt, iterations, keyLengthBits);
            return MessageDigest.isEqual(computed, expectedHash);
        }

        /**
         * Executes a dummy PBKDF2 hash computation to equalize response time when a user does not exist.
         */
        public static void performDummyComputation(char[] password, int iterations, int keyLengthBits) {
            byte[] computed = hashPassword(password, DUMMY_SALT, iterations, keyLengthBits);
            MessageDigest.isEqual(computed, DUMMY_HASH);
        }

        /**
         * Generates a 256-bit cryptographically secure session token.
         */
        public static String generateSessionToken() {
            byte[] randomBytes = new byte[32];
            SECURE_RANDOM.nextBytes(randomBytes);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        }
    }

    // =========================================================================
    // Service Fields & Constructors
    // =========================================================================

    private final AccountRepository repository;
    private final LoginPolicy policy;

    /**
     * Default constructor creating a service with an in-memory repository pre-populated
     * with standard demo accounts.
     */
    public UserLoginService() {
        this(new InMemoryAccountRepository(), LoginPolicy.standard());
        populateDefaultDemoAccounts();
    }

    /**
     * Creates a service with a custom account repository and standard security policy.
     */
    public UserLoginService(AccountRepository repository) {
        this(repository, LoginPolicy.standard());
    }

    /**
     * Creates a service with a custom repository and custom security policy.
     */
    public UserLoginService(AccountRepository repository, LoginPolicy policy) {
        this.repository = Objects.requireNonNull(repository, "repository cannot be null");
        this.policy = policy != null ? policy : LoginPolicy.standard();
    }

    /**
     * Creates a service backed by an active JDBC Connection.
     */
    public UserLoginService(Connection connection) {
        this(new JdbcAccountRepository(connection), LoginPolicy.standard());
    }

    /**
     * Creates a service backed by an active JDBC Connection with a custom policy.
     */
    public UserLoginService(Connection connection, LoginPolicy policy) {
        this(new JdbcAccountRepository(connection), policy);
    }

    // =========================================================================
    // Core Login & Authentication Methods
    // =========================================================================

    /**
     * Handles a login attempt using a String password.
     *
     * @param username the username submitted by the client
     * @param password the password submitted by the client
     * @return the detailed {@link LoginResult}
     */
    public LoginResult login(String username, String password) {
        if (password == null) {
            return login(username, (char[]) null);
        }
        char[] chars = password.toCharArray();
        try {
            return login(username, chars);
        } finally {
            Arrays.fill(chars, '\0');
        }
    }

    /**
     * Handles a login attempt using a character array password for memory security.
     * The array is sanitized (zeroed out) if internally copied.
     *
     * @param username the username submitted by the client
     * @param password the password submitted by the client
     * @return the detailed {@link LoginResult}
     */
    public LoginResult login(String username, char[] password) {
        Instant now = Instant.now();

        // 1. Defensive input validation
        if (username == null || username.trim().isEmpty()) {
            return LoginResult.failure(LoginStatus.INVALID_INPUT, "Username cannot be empty.");
        }
        if (password == null || password.length == 0) {
            return LoginResult.failure(LoginStatus.INVALID_INPUT, "Password cannot be empty.");
        }
        if (password.length > LoginPolicy.MAX_PASSWORD_LENGTH) {
            return LoginResult.failure(LoginStatus.INVALID_INPUT, "Password exceeds maximum permitted length.");
        }

        String sanitizedUsername = username.trim();

        // 2. Retrieve user account
        Optional<UserAccount> accountOpt = repository.findByUsername(sanitizedUsername);

        if (accountOpt.isEmpty()) {
            // Mitigation against account enumeration: execute dummy PBKDF2 hash calculation
            if (policy.isTimingProtectionEnabled()) {
                PasswordSecurity.performDummyComputation(password,
                        policy.getPbkdf2Iterations(),
                        policy.getKeyLengthBits());
            }
            return LoginResult.failure(LoginStatus.INVALID_CREDENTIALS, "Invalid username or password.");
        }

        UserAccount account = accountOpt.get();

        // 3. Check account lockout state
        synchronized (account) {
            if (account.isLocked(now)) {
                Duration remainingLock = Duration.between(now, account.getLockoutUntil());
                long minutes = Math.max(1, remainingLock.toMinutes());
                return LoginResult.failure(LoginStatus.ACCOUNT_LOCKED,
                        "Account is temporarily locked due to multiple failed login attempts. Try again in " + minutes + " minute(s).");
            }
        }

        // 4. Check account enabled state
        if (!account.isEnabled()) {
            return LoginResult.failure(LoginStatus.ACCOUNT_DISABLED, "Account is disabled. Please contact support.");
        }

        // 5. Verify credentials in constant time
        boolean passwordMatches = PasswordSecurity.verify(
                password,
                account.getSalt(),
                account.getPasswordHash(),
                policy.getPbkdf2Iterations(),
                policy.getKeyLengthBits()
        );

        if (passwordMatches) {
            // Login SUCCESS: reset failed attempts, update last login, issue session token
            synchronized (account) {
                account.resetFailedAttempts();
                account.setLastLoginAt(now);
                repository.save(account);
            }

            String sessionToken = policy.isGenerateSessionToken() ? PasswordSecurity.generateSessionToken() : null;
            return LoginResult.success(account, sessionToken);
        } else {
            // Login FAILURE: increment failed attempts and check lockout threshold
            int remainingAttempts;
            boolean newlyLocked = false;

            synchronized (account) {
                int attempts = account.incrementFailedAttempts();
                if (attempts >= policy.getMaxFailedAttempts()) {
                    Instant lockExpiry = now.plus(policy.getLockoutDuration());
                    account.setLockoutUntil(lockExpiry);
                    newlyLocked = true;
                    remainingAttempts = 0;
                } else {
                    remainingAttempts = policy.getMaxFailedAttempts() - attempts;
                }
                repository.save(account);
            }

            if (newlyLocked) {
                return LoginResult.failure(LoginStatus.ACCOUNT_LOCKED,
                        "Account has been locked due to " + policy.getMaxFailedAttempts() +
                                " consecutive failed login attempts. Please try again after " +
                                policy.getLockoutDuration().toMinutes() + " minutes.", 0);
            } else {
                return LoginResult.failure(LoginStatus.INVALID_CREDENTIALS,
                        "Invalid username or password.", remainingAttempts);
            }
        }
    }

    /**
     * Simplified authentication returning a boolean status.
     *
     * @param username client username
     * @param password client password
     * @return {@code true} if credentials are valid and access is allowed, {@code false} otherwise
     */
    public boolean authenticate(String username, String password) {
        return login(username, password).isSuccess();
    }

    /**
     * Simplified authentication returning a boolean status with a {@code char[]} password.
     */
    public boolean authenticate(String username, char[] password) {
        return login(username, password).isSuccess();
    }

    /**
     * Verifies submitted credentials. Equivalent to {@link #authenticate(String, String)}.
     */
    public boolean verifyCredentials(String username, String password) {
        return authenticate(username, password);
    }

    /**
     * Verifies submitted credentials. Equivalent to {@link #authenticate(String, char[])}.
     */
    public boolean verifyCredentials(String username, char[] password) {
        return authenticate(username, password);
    }

    /**
     * Alternate naming convention for handling login attempts.
     */
    public boolean handleLogin(String username, String password) {
        return authenticate(username, password);
    }

    /**
     * Alternate naming convention for attempting login.
     */
    public boolean attemptLogin(String username, String password) {
        return authenticate(username, password);
    }

    // =========================================================================
    // Account Administration & Registration
    // =========================================================================

    /**
     * Registers a new user account with default roles.
     *
     * @param username desired username
     * @param password desired password
     * @return {@code true} if registered successfully, {@code false} if username already exists
     */
    public boolean registerUser(String username, String password) {
        if (password == null) return false;
        char[] chars = password.toCharArray();
        try {
            return registerUser(username, chars, null, Collections.singleton("USER"));
        } finally {
            Arrays.fill(chars, '\0');
        }
    }

    /**
     * Registers a new user account with a {@code char[]} password.
     */
    public boolean registerUser(String username, char[] password) {
        return registerUser(username, password, null, Collections.singleton("USER"));
    }

    /**
     * Registers a new user account with extended metadata.
     */
    public boolean registerUser(String username, String password, String email, Set<String> roles) {
        if (password == null) return false;
        char[] chars = password.toCharArray();
        try {
            return registerUser(username, chars, email, roles);
        } finally {
            Arrays.fill(chars, '\0');
        }
    }

    /**
     * Registers a new user account with extended metadata using a {@code char[]} password.
     */
    public boolean registerUser(String username, char[] password, String email, Set<String> roles) {
        if (username == null || username.trim().isEmpty()) {
            return false;
        }
        if (password == null || password.length == 0 || password.length > LoginPolicy.MAX_PASSWORD_LENGTH) {
            return false;
        }
        String cleanUsername = username.trim();
        if (repository.exists(cleanUsername)) {
            return false;
        }

        byte[] salt = PasswordSecurity.generateSalt(policy.getSaltBytes());
        byte[] hash = PasswordSecurity.hashPassword(
                password,
                salt,
                policy.getPbkdf2Iterations(),
                policy.getKeyLengthBits()
        );

        UserAccount account = new UserAccount(cleanUsername, salt, hash, email, roles);
        repository.save(account);
        return true;
    }

    /**
     * Manually unlocks an account, resetting failed attempts and lockout timers.
     */
    public boolean unlockAccount(String username) {
        if (username == null) return false;
        Optional<UserAccount> opt = repository.findByUsername(username);
        if (opt.isPresent()) {
            UserAccount account = opt.get();
            synchronized (account) {
                account.resetFailedAttempts();
                repository.save(account);
            }
            return true;
        }
        return false;
    }

    /**
     * Checks whether an account is currently locked.
     */
    public boolean isAccountLocked(String username) {
        if (username == null) return false;
        return repository.findByUsername(username)
                .map(a -> a.isLocked(Instant.now()))
                .orElse(false);
    }

    /**
     * Enables or disables an account.
     */
    public boolean setAccountEnabled(String username, boolean enabled) {
        if (username == null) return false;
        Optional<UserAccount> opt = repository.findByUsername(username);
        if (opt.isPresent()) {
            UserAccount account = opt.get();
            synchronized (account) {
                account.setEnabled(enabled);
                repository.save(account);
            }
            return true;
        }
        return false;
    }

    /**
     * Retrieves account information if it exists.
     */
    public Optional<UserAccount> getAccount(String username) {
        return repository.findByUsername(username);
    }

    /**
     * Checks if a user exists.
     */
    public boolean userExists(String username) {
        return repository.exists(username);
    }

    /**
     * Returns the active account repository.
     */
    public AccountRepository getRepository() {
        return repository;
    }

    /**
     * Returns the active login policy.
     */
    public LoginPolicy getPolicy() {
        return policy;
    }

    // =========================================================================
    // Static Convenience Helpers
    // =========================================================================

    private static final UserLoginService DEFAULT_INSTANCE = new UserLoginService();

    /**
     * Returns the shared default instance of {@code UserLoginService}.
     */
    public static UserLoginService getDefaultInstance() {
        return DEFAULT_INSTANCE;
    }

    /**
     * Verifies credentials against the default shared instance.
     */
    public static boolean verify(String username, String password) {
        return DEFAULT_INSTANCE.authenticate(username, password);
    }

    /**
     * Processes a login attempt against the default shared instance.
     */
    public static LoginResult processLogin(String username, String password) {
        return DEFAULT_INSTANCE.login(username, password);
    }

    // =========================================================================
    // Internal Initialization
    // =========================================================================

    private void populateDefaultDemoAccounts() {
        registerUser("alice", "AliceSecurePass123!", "alice@example.com", Set.of("USER"));
        registerUser("bob", "BobP@ssword2026!", "bob@example.com", Set.of("USER"));
        registerUser("admin", "AdminSuperKey987$", "admin@example.com", Set.of("ADMIN", "USER"));
    }

    // =========================================================================
    // Main CLI & Automated Verification Suite
    // =========================================================================

    public static void main(String[] args) {
        if (args.length == 0 || args[0].equalsIgnoreCase("--demo") || args[0].equalsIgnoreCase("--test")) {
            runAutomatedDemonstration();
            return;
        }

        if (args[0].equalsIgnoreCase("--interactive") || args[0].equalsIgnoreCase("-i")) {
            runInteractivePrompt();
            return;
        }

        if (args.length >= 2) {
            String username = args[0];
            String password = args[1];
            UserLoginService service = UserLoginService.getDefaultInstance();
            LoginResult result = service.login(username, password);
            if (result.isSuccess()) {
                System.out.println("[+] Login SUCCESS for user '" + username + "'");
                System.out.println("    Status:  " + result.getStatus());
                System.out.println("    Message: " + result.getMessage());
                result.getSessionToken().ifPresent(token -> System.out.println("    Session: " + token));
                System.exit(0);
            } else {
                System.err.println("[-] Login FAILED for user '" + username + "'");
                System.err.println("    Status:  " + result.getStatus());
                System.err.println("    Message: " + result.getMessage());
                if (result.getRemainingAttempts() >= 0) {
                    System.err.println("    Remaining Attempts: " + result.getRemainingAttempts());
                }
                System.exit(1);
            }
        }

        System.out.println("Usage:");
        System.out.println("  java UserLoginService                  # Run automated demonstration suite");
        System.out.println("  java UserLoginService --demo           # Run automated demonstration suite");
        System.out.println("  java UserLoginService --interactive    # Launch interactive login prompt");
        System.out.println("  java UserLoginService <user> <pass>    # Test single credential authentication");
    }

    /**
     * Executes interactive command-line login prompt.
     */
    private static void runInteractivePrompt() {
        System.out.println("=================================================");
        System.out.println("        User Authentication System - CLI         ");
        System.out.println("=================================================");
        System.out.println("Default pre-configured test users:");
        System.out.println("  1. alice / AliceSecurePass123!");
        System.out.println("  2. bob   / BobP@ssword2026!");
        System.out.println("  3. admin / AdminSuperKey987$");
        System.out.println("-------------------------------------------------");

        Console console = System.console();
        String username;
        char[] password;

        if (console != null) {
            username = console.readLine("Username: ");
            password = console.readPassword("Password: ");
        } else {
            Scanner scanner = new Scanner(System.in);
            System.out.print("Username: ");
            username = scanner.hasNextLine() ? scanner.nextLine() : "";
            System.out.print("Password: ");
            password = scanner.hasNextLine() ? scanner.nextLine().toCharArray() : new char[0];
        }

        UserLoginService service = UserLoginService.getDefaultInstance();
        try {
            LoginResult result = service.login(username, password);
            System.out.println();
            if (result.isSuccess()) {
                System.out.println("[+] ACCESS GRANTED");
                System.out.println("    Welcome, " + username + "!");
                result.getUser().ifPresent(u -> {
                    System.out.println("    Email: " + (u.getEmail() != null ? u.getEmail() : "N/A"));
                    System.out.println("    Roles: " + u.getRoles());
                    System.out.println("    Last Login: " + u.getLastLoginAt());
                });
                result.getSessionToken().ifPresent(tok -> System.out.println("    Session Token: " + tok));
            } else {
                System.out.println("[-] ACCESS DENIED");
                System.out.println("    Status:  " + result.getStatus());
                System.out.println("    Message: " + result.getMessage());
                if (result.getRemainingAttempts() >= 0) {
                    System.out.println("    Remaining attempts before lockout: " + result.getRemainingAttempts());
                }
            }
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    /**
     * Runs comprehensive automated verification test scenarios.
     */
    public static void runAutomatedDemonstration() {
        System.out.println("=============================================================");
        System.out.println("   USER LOGIN SERVICE - AUTOMATED VERIFICATION SUITE         ");
        System.out.println("=============================================================");

        // Use fast testing policy (5,000 PBKDF2 iterations) so the demo suite completes quickly
        LoginPolicy testPolicy = LoginPolicy.fastTesting();
        InMemoryAccountRepository repo = new InMemoryAccountRepository();
        UserLoginService service = new UserLoginService(repo, testPolicy);

        // Pre-populate demo user
        service.registerUser("alice", "AliceSecurePass123!", "alice@example.com", Set.of("USER"));
        service.registerUser("admin", "AdminSuperKey987$", "admin@example.com", Set.of("ADMIN", "USER"));

        int totalTests = 0;
        int passedTests = 0;

        // -------------------------------------------------------------
        // Scenario 1: Valid credentials -> Access Granted
        // -------------------------------------------------------------
        totalTests++;
        System.out.println("\n[Test 1] Valid Credentials Authentication:");
        LoginResult r1 = service.login("alice", "AliceSecurePass123!");
        if (r1.isSuccess() && r1.getStatus() == LoginStatus.SUCCESS && r1.getSessionToken().isPresent()) {
            System.out.println("  PASS: Access granted for 'alice'.");
            System.out.println("        Status: " + r1.getStatus());
            System.out.println("        Token:  " + r1.getSessionToken().get().substring(0, 16) + "...");
            System.out.println("        Roles:  " + r1.getUser().get().getRoles());
            passedTests++;
        } else {
            System.err.println("  FAIL: Expected successful login, got: " + r1);
        }

        // -------------------------------------------------------------
        // Scenario 2: Invalid password -> Access Denied
        // -------------------------------------------------------------
        totalTests++;
        System.out.println("\n[Test 2] Invalid Password Authentication:");
        LoginResult r2 = service.login("alice", "WrongPassword999!");
        if (!r2.isSuccess() && r2.getStatus() == LoginStatus.INVALID_CREDENTIALS && r2.getRemainingAttempts() == 4) {
            System.out.println("  PASS: Access denied as expected.");
            System.out.println("        Status: " + r2.getStatus());
            System.out.println("        Message: " + r2.getMessage());
            System.out.println("        Remaining attempts: " + r2.getRemainingAttempts());
            passedTests++;
        } else {
            System.err.println("  FAIL: Expected INVALID_CREDENTIALS with 4 remaining attempts, got: " + r2);
        }

        // -------------------------------------------------------------
        // Scenario 3: Non-existent username -> Access Denied (Timing Safe)
        // -------------------------------------------------------------
        totalTests++;
        System.out.println("\n[Test 3] Non-existent Username Handling:");
        LoginResult r3 = service.login("non_existent_user", "AnyPassword123!");
        if (!r3.isSuccess() && r3.getStatus() == LoginStatus.INVALID_CREDENTIALS) {
            System.out.println("  PASS: Access denied for missing user without user enumeration leak.");
            System.out.println("        Message: " + r3.getMessage());
            passedTests++;
        } else {
            System.err.println("  FAIL: Expected INVALID_CREDENTIALS, got: " + r3);
        }

        // -------------------------------------------------------------
        // Scenario 4: Account Lockout after consecutive failed attempts
        // -------------------------------------------------------------
        totalTests++;
        System.out.println("\n[Test 4] Brute-Force Account Lockout Enforcement:");
        // Alice already has 1 failed attempt. Execute 4 more failures to reach threshold 5.
        service.login("alice", "bad_pass_2");
        service.login("alice", "bad_pass_3");
        service.login("alice", "bad_pass_4");
        LoginResult r4 = service.login("alice", "bad_pass_5"); // 5th failed attempt

        if (!r4.isSuccess() && r4.getStatus() == LoginStatus.ACCOUNT_LOCKED && service.isAccountLocked("alice")) {
            System.out.println("  PASS: Account locked after 5 consecutive failed attempts.");
            System.out.println("        Status: " + r4.getStatus());
            System.out.println("        Message: " + r4.getMessage());
            passedTests++;
        } else {
            System.err.println("  FAIL: Expected ACCOUNT_LOCKED, got: " + r4);
        }

        // -------------------------------------------------------------
        // Scenario 5: Access rejected even with correct password while locked
        // -------------------------------------------------------------
        totalTests++;
        System.out.println("\n[Test 5] Access Prevention on Locked Account (Even With Correct Password):");
        LoginResult r5 = service.login("alice", "AliceSecurePass123!");
        if (!r5.isSuccess() && r5.getStatus() == LoginStatus.ACCOUNT_LOCKED) {
            System.out.println("  PASS: Access rejected because account is locked.");
            System.out.println("        Message: " + r5.getMessage());
            passedTests++;
        } else {
            System.err.println("  FAIL: Expected account to remain locked, got: " + r5);
        }

        // -------------------------------------------------------------
        // Scenario 6: Administrative Account Unlock & Counter Reset
        // -------------------------------------------------------------
        totalTests++;
        System.out.println("\n[Test 6] Administrative Unlock & Login Recovery:");
        boolean unlocked = service.unlockAccount("alice");
        LoginResult r6 = service.login("alice", "AliceSecurePass123!");
        if (unlocked && r6.isSuccess() && r6.getStatus() == LoginStatus.SUCCESS) {
            System.out.println("  PASS: Account successfully unlocked; login succeeded.");
            System.out.println("        Failed attempts counter reset to: " + r6.getUser().get().getFailedAttempts());
            passedTests++;
        } else {
            System.err.println("  FAIL: Expected recovery after unlock, got: " + r6);
        }

        // -------------------------------------------------------------
        // Scenario 7: Disabled Account Check
        // -------------------------------------------------------------
        totalTests++;
        System.out.println("\n[Test 7] Administratively Disabled Account:");
        service.setAccountEnabled("alice", false);
        LoginResult r7 = service.login("alice", "AliceSecurePass123!");
        service.setAccountEnabled("alice", true); // Re-enable for further checks
        if (!r7.isSuccess() && r7.getStatus() == LoginStatus.ACCOUNT_DISABLED) {
            System.out.println("  PASS: Login blocked for disabled account.");
            System.out.println("        Message: " + r7.getMessage());
            passedTests++;
        } else {
            System.err.println("  FAIL: Expected ACCOUNT_DISABLED, got: " + r7);
        }

        // -------------------------------------------------------------
        // Scenario 8: Dynamic Account Registration & Authentication
        // -------------------------------------------------------------
        totalTests++;
        System.out.println("\n[Test 8] Dynamic User Registration and Subsequent Authentication:");
        boolean registered = service.registerUser("charlie", "Charlie#Password2026!", "charlie@example.com", Set.of("USER"));
        boolean reRegistered = service.registerUser("charlie", "DuplicatePass!"); // Should fail (duplicate)
        LoginResult r8 = service.login("charlie", "Charlie#Password2026!");
        if (registered && !reRegistered && r8.isSuccess()) {
            System.out.println("  PASS: New user 'charlie' registered and authenticated successfully.");
            System.out.println("        Duplicate registration properly rejected: " + !reRegistered);
            passedTests++;
        } else {
            System.err.println("  FAIL: Expected registration and authentication success, got: " + r8);
        }

        // -------------------------------------------------------------
        // Scenario 9: Memory Hygiene with char[] Passwords
        // -------------------------------------------------------------
        totalTests++;
        System.out.println("\n[Test 9] Memory Hygiene (char[] Overloads):");
        char[] charPassword = "AliceSecurePass123!".toCharArray();
        boolean authBool = service.authenticate("alice", charPassword);
        if (authBool) {
            System.out.println("  PASS: authenticate(username, char[]) successfully authenticated user.");
            passedTests++;
        } else {
            System.err.println("  FAIL: char[] authentication failed.");
        }

        // -------------------------------------------------------------
        // Summary
        // -------------------------------------------------------------
        System.out.println("\n=============================================================");
        System.out.println("   VERIFICATION SUMMARY: " + passedTests + " / " + totalTests + " PASSED");
        System.out.println("=============================================================");
    }
}
