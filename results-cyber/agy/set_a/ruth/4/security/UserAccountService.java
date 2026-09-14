import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Production-ready service for securely registering and authenticating users
 * in an SQL database using an active JDBC Connection.
 *
 * <p><b>Security Architecture &amp; Password Handling:</b></p>
 * <ul>
 *   <li><b>Handling Before Storage (In-Memory Hygiene):</b>
 *     <ul>
 *       <li>Accepts passwords primarily as mutable {@code char[]} arrays rather than
 *           immutable {@code java.lang.String} objects. Strings reside on the JVM heap and
 *           string intern pool until garbage collection (and even after GC until memory reuse),
 *           leaving sensitive credentials exposed to heap inspection, memory dumps, or swap files.</li>
 *       <li>Explicitly zeroes out character arrays and temporary byte buffers with {@code '\0'}
 *           and {@code (byte) 0} as soon as cryptographic hashing completes.</li>
 *       <li>Invokes {@link PBEKeySpec#clearPassword()} in {@code finally} blocks to guarantee
 *           internal password copies held by the cryptographic key specification are wiped.</li>
 *       <li>Enforces input length bounds (minimum 8 characters, maximum 128 characters) to
 *           mitigate CPU exhaustion / algorithmic denial-of-service (DoS) attacks on PBKDF2.</li>
 *     </ul>
 *   </li>
 *   <li><b>Handling During Storage (Cryptographic Security):</b>
 *     <ul>
 *       <li>Never stores plaintext or weakly hashed passwords. Uses standard
 *           <b>PBKDF2WithHmacSHA512</b> with <b>210,000 iterations</b> (exceeding OWASP guidelines).</li>
 *       <li>Uses a cryptographically strong pseudo-random number generator ({@link SecureRandom})
 *           to generate an independent 128-bit (16-byte) unique salt for each user.</li>
 *       <li>Stores the iteration count and algorithm name alongside the salt and hash in the database,
 *           enabling seamless cryptographic agility and parameter upgrades over time.</li>
 *       <li>Uses parameterized {@link PreparedStatement} for all queries to eliminate SQL injection.</li>
 *     </ul>
 *   </li>
 *   <li><b>Handling During Authentication (Timing Attack Defense):</b>
 *     <ul>
 *       <li>Uses {@link MessageDigest#isEqual(byte[], byte[])} for constant-time hash byte verification,
 *           preventing timing side-channel attacks against hash comparison.</li>
 *       <li>Executes a dummy PBKDF2 derivation with identical work factor when an unknown username
 *           is queried, ensuring non-existent accounts take the same response time as existing accounts
 *           and preventing user enumeration via timing discrepancies.</li>
 *     </ul>
 *   </li>
 * </ul>
 */
public class UserAccountService {

    // -------------------------------------------------------------------------
    // Cryptographic & Security Constants
    // -------------------------------------------------------------------------

    /** Default Key Derivation Function: PBKDF2 with HMAC-SHA512. */
    public static final String DEFAULT_ALGORITHM = "PBKDF2WithHmacSHA512";

    /**
     * OWASP recommended minimum iterations for PBKDF2-HMAC-SHA512.
     * High computational work factor defends against GPU/ASIC brute-force attacks.
     */
    public static final int DEFAULT_ITERATIONS = 210_000;

    /** 128-bit (16 bytes) salt provides strong cryptographic entropy. */
    public static final int DEFAULT_SALT_BYTES = 16;

    /** 512-bit derived key length matching SHA-512 digest size. */
    public static final int DEFAULT_KEY_LENGTH_BITS = 512;

    /** Minimum allowed password length (NIST SP 800-63B guidelines). */
    public static final int DEFAULT_MIN_PASSWORD_LENGTH = 8;

    /** Maximum allowed password length to mitigate CPU exhaustion / PBKDF2 DoS attacks. */
    public static final int DEFAULT_MAX_PASSWORD_LENGTH = 128;

    /** Allowed username format: 3-64 characters (alphanumeric, dot, underscore, hyphen, @). */
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_.@-]{3,64}$");

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Dummy salt pre-generated once at startup for timing-attack mitigation
     * when authenticating non-existent accounts.
     */
    private static final byte[] DUMMY_SALT = new byte[DEFAULT_SALT_BYTES];

    static {
        SECURE_RANDOM.nextBytes(DUMMY_SALT);
    }

    // -------------------------------------------------------------------------
    // User Account DTO Record
    // -------------------------------------------------------------------------

    /**
     * Public representation of user account metadata (excluding sensitive credentials).
     */
    public record UserAccount(String username, Instant createdAt, int iterations, String algorithm) {}

    // -------------------------------------------------------------------------
    // Instance Configuration
    // -------------------------------------------------------------------------

    private final String algorithm;
    private final int iterations;
    private final int saltBytes;
    private final int keyLengthBits;
    private final int minPasswordLength;
    private final int maxPasswordLength;

    /**
     * Constructs a new {@code UserAccountService} with default security settings.
     */
    public UserAccountService() {
        this(DEFAULT_ALGORITHM, DEFAULT_ITERATIONS, DEFAULT_SALT_BYTES, DEFAULT_KEY_LENGTH_BITS,
             DEFAULT_MIN_PASSWORD_LENGTH, DEFAULT_MAX_PASSWORD_LENGTH);
    }

    /**
     * Constructs a new {@code UserAccountService} with custom security parameters.
     *
     * @param algorithm         the PBKDF2 algorithm name (e.g., "PBKDF2WithHmacSHA512")
     * @param iterations        the iteration count (must be >= 10,000)
     * @param saltBytes         the salt length in bytes (must be >= 16)
     * @param keyLengthBits     the derived key length in bits (e.g., 512)
     * @param minPasswordLength minimum allowed password length (>= 8)
     * @param maxPasswordLength maximum allowed password length
     */
    public UserAccountService(String algorithm, int iterations, int saltBytes, int keyLengthBits,
                              int minPasswordLength, int maxPasswordLength) {
        if (iterations < 10_000) {
            throw new IllegalArgumentException("Iteration count must be at least 10,000 for adequate security.");
        }
        if (saltBytes < 16) {
            throw new IllegalArgumentException("Salt size must be at least 16 bytes (128 bits).");
        }
        if (minPasswordLength < 8) {
            throw new IllegalArgumentException("Minimum password length must be at least 8 characters.");
        }
        if (maxPasswordLength < minPasswordLength) {
            throw new IllegalArgumentException("Max password length cannot be less than min password length.");
        }
        this.algorithm = Objects.requireNonNull(algorithm, "Algorithm cannot be null");
        this.iterations = iterations;
        this.saltBytes = saltBytes;
        this.keyLengthBits = keyLengthBits;
        this.minPasswordLength = minPasswordLength;
        this.maxPasswordLength = maxPasswordLength;
    }

    // -------------------------------------------------------------------------
    // Database Schema Initialization
    // -------------------------------------------------------------------------

    /**
     * Initializes the database schema by creating the {@code users} table if it does
     * not already exist. ANSI SQL standard syntax is used for cross-database compatibility
     * across PostgreSQL, MySQL, SQLite, H2, Oracle, and SQL Server.
     *
     * @param conn an active JDBC {@link Connection}
     * @throws SQLException if a database access error occurs
     */
    public void initializeDatabase(Connection conn) throws SQLException {
        Objects.requireNonNull(conn, "Database connection must not be null.");

        String sql = "CREATE TABLE IF NOT EXISTS users (" +
                     "  username VARCHAR(64) PRIMARY KEY, " +
                     "  password_hash VARCHAR(128) NOT NULL, " +
                     "  salt VARCHAR(64) NOT NULL, " +
                     "  iterations INT NOT NULL, " +
                     "  algorithm VARCHAR(64) NOT NULL, " +
                     "  created_at TIMESTAMP NOT NULL" +
                     ")";

        try (Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
        }
    }

    // -------------------------------------------------------------------------
    // User Registration
    // -------------------------------------------------------------------------

    /**
     * Registers a new user account with a char array password.
     * Automatically zeroes out the passed password array after registration completes.
     *
     * @param conn     an active JDBC {@link Connection}
     * @param username the desired username (3-64 chars: alphanumeric, dot, underscore, hyphen, @)
     * @param password the user's password as a char array (will be wiped after hashing)
     * @throws SQLException               if a database error occurs
     * @throws UserAlreadyExistsException if the username is already registered
     * @throws ValidationException        if username or password fails validation
     */
    public void registerUser(Connection conn, String username, char[] password)
            throws SQLException, UserAlreadyExistsException, ValidationException {
        registerUser(conn, username, password, true);
    }

    /**
     * Registers a new user account with control over password zeroization.
     *
     * @param conn         an active JDBC {@link Connection}
     * @param username     the desired username
     * @param password     the user's password as a char array
     * @param wipePassword whether to overwrite the password char array with '\0' upon completion
     * @throws SQLException               if a database error occurs
     * @throws UserAlreadyExistsException if the username is already registered
     * @throws ValidationException        if username or password fails validation
     */
    public void registerUser(Connection conn, String username, char[] password, boolean wipePassword)
            throws SQLException, UserAlreadyExistsException, ValidationException {
        Objects.requireNonNull(conn, "Database connection must not be null.");
        validateUsername(username);
        validatePassword(password);

        // Pre-check existence before expensive hashing computation
        if (isUserExists(conn, username)) {
            if (wipePassword && password != null) {
                Arrays.fill(password, '\0');
            }
            throw new UserAlreadyExistsException("User '" + username + "' is already registered.");
        }

        // 1. Generate unique cryptographically secure salt
        byte[] salt = new byte[this.saltBytes];
        SECURE_RANDOM.nextBytes(salt);

        byte[] derivedHash = null;
        try {
            // 2. Derive password hash using PBKDF2-HMAC-SHA512
            derivedHash = hashPassword(password, salt, this.iterations, this.keyLengthBits, this.algorithm);

            // 3. Encode salt and hash to Base64 for safe SQL text storage
            String saltBase64 = Base64.getEncoder().encodeToString(salt);
            String hashBase64 = Base64.getEncoder().encodeToString(derivedHash);

            // 4. Store user credentials using parameterized PreparedStatement
            String insertSql = "INSERT INTO users (username, password_hash, salt, iterations, algorithm, created_at) " +
                               "VALUES (?, ?, ?, ?, ?, ?)";

            try (PreparedStatement stmt = conn.prepareStatement(insertSql)) {
                stmt.setString(1, username);
                stmt.setString(2, hashBase64);
                stmt.setString(3, saltBase64);
                stmt.setInt(4, this.iterations);
                stmt.setString(5, this.algorithm);
                stmt.setTimestamp(6, Timestamp.from(Instant.now()));
                stmt.executeUpdate();
            } catch (SQLException e) {
                // Catch concurrent race-condition duplicate insertions
                if (isUniqueConstraintViolation(e) || isUserExists(conn, username)) {
                    throw new UserAlreadyExistsException("User '" + username + "' is already registered.", e);
                }
                throw e;
            }
        } finally {
            // 5. Memory Hygiene: wipe sensitive intermediate salt, hash, and password arrays
            Arrays.fill(salt, (byte) 0);
            if (derivedHash != null) {
                Arrays.fill(derivedHash, (byte) 0);
            }
            if (wipePassword && password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    /**
     * Convenience overload accepting a String password.
     *
     * <p><b>Note:</b> In high-security contexts, prefer passing {@code char[]} to enable
     * guaranteed memory wiping. Strings reside in the JVM heap until garbage collection occurs.</p>
     *
     * @param conn     an active JDBC {@link Connection}
     * @param username the desired username
     * @param password the user's password as a String
     * @throws SQLException               if a database error occurs
     * @throws UserAlreadyExistsException if the username is already registered
     * @throws ValidationException        if username or password fails validation
     */
    public void registerUser(Connection conn, String username, String password)
            throws SQLException, UserAlreadyExistsException, ValidationException {
        if (password == null) {
            throw new ValidationException("Password cannot be null.");
        }
        char[] passwordChars = password.toCharArray();
        try {
            registerUser(conn, username, passwordChars, true);
        } finally {
            Arrays.fill(passwordChars, '\0');
        }
    }

    // -------------------------------------------------------------------------
    // User Authentication
    // -------------------------------------------------------------------------

    /**
     * Authenticates a user against stored database credentials.
     * Automatically zeroes out the passed password array after verification.
     *
     * @param conn     an active JDBC {@link Connection}
     * @param username the username to authenticate
     * @param password the raw password as a char array (will be wiped after verification)
     * @return {@code true} if credentials match; {@code false} otherwise
     * @throws SQLException        if a database access error occurs
     * @throws ValidationException if username is invalid or password is null
     */
    public boolean authenticateUser(Connection conn, String username, char[] password)
            throws SQLException, ValidationException {
        return authenticateUser(conn, username, password, true);
    }

    /**
     * Authenticates a user against stored database credentials with control over password zeroization.
     *
     * @param conn         an active JDBC {@link Connection}
     * @param username     the username to authenticate
     * @param password     the raw password as a char array
     * @param wipePassword whether to overwrite the password char array with '\0' upon completion
     * @return {@code true} if credentials match; {@code false} otherwise
     * @throws SQLException        if a database access error occurs
     * @throws ValidationException if username is invalid or password is null
     */
    public boolean authenticateUser(Connection conn, String username, char[] password, boolean wipePassword)
            throws SQLException, ValidationException {
        Objects.requireNonNull(conn, "Database connection must not be null.");
        validateUsername(username);
        if (password == null) {
            throw new ValidationException("Password cannot be null.");
        }

        String querySql = "SELECT password_hash, salt, iterations, algorithm FROM users WHERE username = ?";

        try (PreparedStatement stmt = conn.prepareStatement(querySql)) {
            stmt.setString(1, username);
            try (ResultSet rs = stmt.executeQuery()) {
                if (!rs.next()) {
                    // Timing Attack Mitigation: User does not exist in the database.
                    // Execute a dummy PBKDF2 hash calculation with the same work factor so that
                    // non-existent users require identical execution time to existing accounts,
                    // mitigating user enumeration via side-channel latency observation.
                    byte[] dummyComputed = null;
                    try {
                        dummyComputed = hashPassword(password, DUMMY_SALT, this.iterations,
                                                     this.keyLengthBits, this.algorithm);
                    } finally {
                        if (dummyComputed != null) {
                            Arrays.fill(dummyComputed, (byte) 0);
                        }
                        if (wipePassword) {
                            Arrays.fill(password, '\0');
                        }
                    }
                    return false;
                }

                // Retrieve stored user security metadata
                String storedHashBase64 = rs.getString("password_hash");
                String saltBase64 = rs.getString("salt");
                int userIterations = rs.getInt("iterations");
                String userAlgorithm = rs.getString("algorithm");

                byte[] salt = Base64.getDecoder().decode(saltBase64);
                byte[] expectedHash = Base64.getDecoder().decode(storedHashBase64);
                byte[] computedHash = null;

                try {
                    // Derive hash using the user's stored parameters
                    computedHash = hashPassword(password, salt, userIterations,
                                                expectedHash.length * 8, userAlgorithm);

                    // Constant-Time Comparison:
                    // MessageDigest.isEqual() prevents timing side-channel attacks on hash bytes
                    return MessageDigest.isEqual(expectedHash, computedHash);
                } finally {
                    // Memory Hygiene: immediately clear all sensitive byte arrays
                    Arrays.fill(salt, (byte) 0);
                    Arrays.fill(expectedHash, (byte) 0);
                    if (computedHash != null) {
                        Arrays.fill(computedHash, (byte) 0);
                    }
                    if (wipePassword) {
                        Arrays.fill(password, '\0');
                    }
                }
            }
        }
    }

    /**
     * Convenience overload for authentication accepting a String password.
     *
     * @param conn     an active JDBC {@link Connection}
     * @param username the username to authenticate
     * @param password the password as a String
     * @return {@code true} if credentials match; {@code false} otherwise
     * @throws SQLException        if a database error occurs
     * @throws ValidationException if username is invalid or password is null
     */
    public boolean authenticateUser(Connection conn, String username, String password)
            throws SQLException, ValidationException {
        if (password == null) {
            throw new ValidationException("Password cannot be null.");
        }
        char[] passwordChars = password.toCharArray();
        try {
            return authenticateUser(conn, username, passwordChars, true);
        } finally {
            Arrays.fill(passwordChars, '\0');
        }
    }

    // -------------------------------------------------------------------------
    // Helper Methods & Account Metadata
    // -------------------------------------------------------------------------

    /**
     * Checks whether a username is already present in the database.
     *
     * @param conn     active JDBC {@link Connection}
     * @param username username to check
     * @return {@code true} if user exists; {@code false} otherwise
     * @throws SQLException if a database error occurs
     */
    public boolean isUserExists(Connection conn, String username) throws SQLException {
        Objects.requireNonNull(conn, "Database connection must not be null.");
        String checkSql = "SELECT 1 FROM users WHERE username = ?";
        try (PreparedStatement stmt = conn.prepareStatement(checkSql)) {
            stmt.setString(1, username);
            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next();
            }
        }
    }

    /**
     * Retrieves public account metadata for a user (without exposing password hash or salt).
     *
     * @param conn     active JDBC {@link Connection}
     * @param username username to retrieve
     * @return {@link Optional} containing {@link UserAccount} if found, or empty
     * @throws SQLException if a database error occurs
     */
    public Optional<UserAccount> getUserAccount(Connection conn, String username) throws SQLException {
        Objects.requireNonNull(conn, "Database connection must not be null.");
        String sql = "SELECT username, created_at, iterations, algorithm FROM users WHERE username = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, username);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    Timestamp ts = rs.getTimestamp("created_at");
                    Instant instant = ts != null ? ts.toInstant() : Instant.EPOCH;
                    return Optional.of(new UserAccount(
                        rs.getString("username"),
                        instant,
                        rs.getInt("iterations"),
                        rs.getString("algorithm")
                    ));
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Checks whether a stored user's cryptographic parameters are outdated and should be upgraded.
     * For example, if system iterations were increased from 100,000 to 210,000.
     *
     * @param conn     active JDBC {@link Connection}
     * @param username username to inspect
     * @return {@code true} if the user's password should be re-hashed on next successful login
     * @throws SQLException if a database error occurs
     */
    public boolean needsRehash(Connection conn, String username) throws SQLException {
        Objects.requireNonNull(conn, "Database connection must not be null.");
        String sql = "SELECT iterations, algorithm FROM users WHERE username = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, username);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    int storedIterations = rs.getInt("iterations");
                    String storedAlgorithm = rs.getString("algorithm");
                    return storedIterations < this.iterations || !this.algorithm.equalsIgnoreCase(storedAlgorithm);
                }
            }
        }
        return false;
    }

    /**
     * Updates an existing user's password with new salt and current service parameters.
     *
     * @param conn        active JDBC {@link Connection}
     * @param username    username to update
     * @param newPassword new password char array
     * @throws SQLException        if a database error occurs
     * @throws ValidationException if username or password fails validation
     */
    public void updatePassword(Connection conn, String username, char[] newPassword)
            throws SQLException, ValidationException {
        Objects.requireNonNull(conn, "Database connection must not be null.");
        validateUsername(username);
        validatePassword(newPassword);

        byte[] salt = new byte[this.saltBytes];
        SECURE_RANDOM.nextBytes(salt);
        byte[] hash = null;

        try {
            hash = hashPassword(newPassword, salt, this.iterations, this.keyLengthBits, this.algorithm);
            String saltBase64 = Base64.getEncoder().encodeToString(salt);
            String hashBase64 = Base64.getEncoder().encodeToString(hash);

            String updateSql = "UPDATE users SET password_hash = ?, salt = ?, iterations = ?, algorithm = ? WHERE username = ?";
            try (PreparedStatement stmt = conn.prepareStatement(updateSql)) {
                stmt.setString(1, hashBase64);
                stmt.setString(2, saltBase64);
                stmt.setInt(3, this.iterations);
                stmt.setString(4, this.algorithm);
                stmt.setString(5, username);
                stmt.executeUpdate();
            }
        } finally {
            Arrays.fill(salt, (byte) 0);
            if (hash != null) {
                Arrays.fill(hash, (byte) 0);
            }
            if (newPassword != null) {
                Arrays.fill(newPassword, '\0');
            }
        }
    }

    // -------------------------------------------------------------------------
    // Core Cryptographic Hashing
    // -------------------------------------------------------------------------

    /**
     * Derives a cryptographic key/hash from a char[] password and byte[] salt using PBKDF2.
     * Safely wipes the internal password copy in {@link PBEKeySpec} upon completion.
     */
    private byte[] hashPassword(char[] password, byte[] salt, int iterCount, int keyLenBits, String algo) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterCount, keyLenBits);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(algo);
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new SecurityConfigurationException("Cryptographic algorithm not available on this JVM: " + algo, e);
        } catch (InvalidKeySpecException e) {
            throw new SecurityConfigurationException("Invalid key specification for PBKDF2: " + e.getMessage(), e);
        } finally {
            // Crucial: clears internal char[] copy retained by PBEKeySpec
            spec.clearPassword();
        }
    }

    // -------------------------------------------------------------------------
    // Input Validation
    // -------------------------------------------------------------------------

    private void validateUsername(String username) throws ValidationException {
        if (username == null || username.trim().isEmpty()) {
            throw new ValidationException("Username cannot be null or blank.");
        }
        if (!USERNAME_PATTERN.matcher(username).matches()) {
            throw new ValidationException(
                "Username '" + username + "' is invalid. Must be 3-64 characters matching pattern: " +
                USERNAME_PATTERN.pattern()
            );
        }
    }

    private void validatePassword(char[] password) throws ValidationException {
        if (password == null) {
            throw new ValidationException("Password cannot be null.");
        }
        if (password.length < this.minPasswordLength) {
            throw new ValidationException(
                "Password is too short. Minimum required length is " + this.minPasswordLength + " characters."
            );
        }
        if (password.length > this.maxPasswordLength) {
            throw new ValidationException(
                "Password exceeds maximum allowable length of " + this.maxPasswordLength + " characters."
            );
        }
    }

    private boolean isUniqueConstraintViolation(SQLException e) {
        String sqlState = e.getSQLState();
        if (sqlState != null && sqlState.startsWith("23")) {
            return true; // ANSI SQL Class 23: Integrity Constraint Violation
        }
        int code = e.getErrorCode();
        return code == 1062 || code == 19 || code == 1; // MySQL, SQLite, Oracle
    }

    // -------------------------------------------------------------------------
    // Custom Domain Exceptions
    // -------------------------------------------------------------------------

    /** Thrown when an attempt is made to register a username that is already taken. */
    public static class UserAlreadyExistsException extends Exception {
        private static final long serialVersionUID = 1L;

        public UserAlreadyExistsException(String message) {
            super(message);
        }
        public UserAlreadyExistsException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** Thrown when username or password input fails validation rules. */
    public static class ValidationException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;

        public ValidationException(String message) {
            super(message);
        }
    }

    /** Thrown when cryptographic algorithm configuration or JVM provider fails. */
    public static class SecurityConfigurationException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public SecurityConfigurationException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    // -------------------------------------------------------------------------
    // Demonstration & Verification Entry Point
    // -------------------------------------------------------------------------

    /**
     * Runnable demonstration verifying database initialization, registration,
     * authentication, duplicate detection, input validation, memory wiping, and timing mitigation.
     *
     * <p>Run with: {@code java -cp .:lib/h2.jar UserAccountService}</p>
     */
    public static void main(String[] args) {
        System.out.println("================================================================================");
        System.out.println("       SECURE USER REGISTRATION & AUTHENTICATION DEMONSTRATION                  ");
        System.out.println("================================================================================");

        // Determine JDBC URL: supports in-memory H2, SQLite, or custom database URL
        String jdbcUrl = "jdbc:h2:mem:userauthdb;DB_CLOSE_DELAY=-1";
        if (args.length > 0) {
            jdbcUrl = args[0];
        }

        System.out.println("[*] Connecting to JDBC URL: " + jdbcUrl);

        try (Connection conn = DriverManager.getConnection(jdbcUrl, "sa", "")) {
            UserAccountService authService = new UserAccountService();

            // 1. Initialize Database Schema
            System.out.println("\n[+] 1. Initializing database schema...");
            authService.initializeDatabase(conn);
            System.out.println("    Users table successfully created/verified.");

            // 2. Register New User Account
            System.out.println("\n[+] 2. Registering new user 'alice_security'...");
            char[] alicePassword = "CorrectHorseBatteryStaple!2026".toCharArray();
            authService.registerUser(conn, "alice_security", alicePassword, false);
            System.out.println("    User 'alice_security' successfully registered.");
            System.out.println("    Stored password hash is salted and derived with PBKDF2-HMAC-SHA512.");

            // 3. Authenticate with Correct Password
            System.out.println("\n[+] 3. Authenticating 'alice_security' with VALID password...");
            char[] attemptPassword = "CorrectHorseBatteryStaple!2026".toCharArray();
            boolean authSuccess = authService.authenticateUser(conn, "alice_security", attemptPassword, true);
            System.out.println("    Authentication Result: " + (authSuccess ? "SUCCESS (Expected)" : "FAILURE (Unexpected)"));
            if (!authSuccess) {
                throw new IllegalStateException("Assertion failed: Expected authentication to succeed!");
            }

            // 4. Authenticate with Incorrect Password
            System.out.println("\n[+] 4. Authenticating 'alice_security' with INVALID password...");
            char[] badPassword = "WrongPassword999!".toCharArray();
            boolean authFail = authService.authenticateUser(conn, "alice_security", badPassword, true);
            System.out.println("    Authentication Result: " + (!authFail ? "REJECTED (Expected)" : "SUCCESS (Security Issue!)"));
            if (authFail) {
                throw new IllegalStateException("Assertion failed: Expected authentication to fail!");
            }

            // 5. Attempt Duplicate Registration
            System.out.println("\n[+] 5. Attempting to register duplicate username 'alice_security'...");
            try {
                authService.registerUser(conn, "alice_security", "AnotherPassword123!".toCharArray());
                System.err.println("    ERROR: Duplicate registration was permitted!");
                throw new IllegalStateException("Duplicate user was not rejected!");
            } catch (UserAlreadyExistsException e) {
                System.out.println("    Caught Expected Exception: " + e.getMessage());
            }

            // 6. Test Input Validation (Password too short)
            System.out.println("\n[+] 6. Attempting to register with short password (under 8 chars)...");
            try {
                authService.registerUser(conn, "bob_weak", "short".toCharArray());
                System.err.println("    ERROR: Short password was permitted!");
                throw new IllegalStateException("Short password was not rejected!");
            } catch (ValidationException e) {
                System.out.println("    Caught Expected Validation Exception: " + e.getMessage());
            }

            // 7. Timing Attack Defense (Non-existent user authentication)
            System.out.println("\n[+] 7. Authenticating NON-EXISTENT user 'ghost_user'...");
            long startTiming = System.currentTimeMillis();
            boolean ghostAuth = authService.authenticateUser(conn, "ghost_user", "AnyPassword123!".toCharArray());
            long elapsed = System.currentTimeMillis() - startTiming;
            System.out.println("    Authentication Result: " + (!ghostAuth ? "REJECTED (Expected)" : "SUCCESS (Error)"));
            System.out.println("    Elapsed Time: " + elapsed + " ms (Timing mitigated via dummy PBKDF2 computation).");
            if (ghostAuth) {
                throw new IllegalStateException("Assertion failed: Non-existent user must not authenticate!");
            }

            // 8. Verify Memory Zeroization
            System.out.println("\n[+] 8. Verifying memory zeroization of password array...");
            char[] testMemoryPass = "SensitiveData123!".toCharArray();
            authService.registerUser(conn, "charlie_wipe", testMemoryPass, true);

            boolean isZeroed = true;
            for (char c : testMemoryPass) {
                if (c != '\0') {
                    isZeroed = false;
                    break;
                }
            }
            System.out.println("    Password array zeroed out after registration: " + isZeroed + " (Expected: true)");
            if (!isZeroed) {
                throw new IllegalStateException("Password array should have been zeroed out in memory!");
            }

            // 9. Verify Account Metadata Retrieval
            System.out.println("\n[+] 9. Verifying account metadata retrieval (excluding credentials)...");
            Optional<UserAccount> userMeta = authService.getUserAccount(conn, "alice_security");
            if (userMeta.isPresent()) {
                System.out.println("    User found: " + userMeta.get().username() +
                                   ", Created: " + userMeta.get().createdAt() +
                                   ", Iterations: " + userMeta.get().iterations() +
                                   ", Algorithm: " + userMeta.get().algorithm());
            } else {
                throw new IllegalStateException("Expected metadata for 'alice_security'!");
            }

            System.out.println("\n================================================================================");
            System.out.println("       ALL SECURITY & FUNCTIONAL VERIFICATIONS PASSED SUCCESSFULLY!             ");
            System.out.println("================================================================================");

        } catch (SQLException e) {
            System.err.println("\nDatabase error occurred: " + e.getMessage());
            if (e.getMessage() != null && e.getMessage().contains("No suitable driver")) {
                System.err.println("\n[!] HINT: No JDBC driver was found on your classpath.");
                System.err.println("    To run the embedded demo with H2, include the H2 jar on the classpath:");
                System.err.println("      java -cp .:lib/h2.jar UserAccountService");
                System.err.println("    Or specify your own JDBC driver and URL:");
                System.err.println("      java -cp .:/path/to/driver.jar UserAccountService \"jdbc:your-db://...\"");
            } else {
                e.printStackTrace();
            }
        } catch (Exception e) {
            System.err.println("Unexpected error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
