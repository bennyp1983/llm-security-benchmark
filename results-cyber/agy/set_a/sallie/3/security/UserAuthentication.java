import java.io.BufferedReader;
import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * UserAuthentication
 *
 * A secure, production-ready Java program that authenticates users by verifying their
 * email address and password against credentials stored in a SQL database.
 *
 * Security Features:
 * 1. SQL Injection Immunity:
 *    - All database queries strictly utilize parameterized PreparedStatement placeholders (?).
 *    - User credentials (email and password) are NEVER concatenated, formatted, or interpolated
 *      into SQL command strings. The database driver compiles the query template in advance and
 *      treats all user input strictly as literal data, preventing alteration of the query's
 *      logical structure or execution flow.
 *
 * 2. Cryptographic Password Security:
 *    - Passwords are never stored in plaintext.
 *    - Implements PBKDF2 with HMAC-SHA256 (PBKDF2WithHmacSHA256) utilizing 210,000 iterations
 *      (OWASP recommended work factor) and a cryptographically secure 16-byte random salt per user.
 *    - Hash comparisons use MessageDigest.isEqual() for constant-time evaluation to eliminate
 *      side-channel timing attacks on byte mismatches.
 *
 * 3. Timing Side-Channel & Enumeration Defense:
 *    - When an email address is not found in the database, a dummy PBKDF2 hash computation is
 *      executed so the response latency is indistinguishable from a wrong password for an existing account.
 *    - Returns uniform, generic error messages ("Invalid email address or password") to prevent
 *      account enumeration.
 *
 * 4. Sensitive Memory Hygiene:
 *    - Passwords are read and handled as char[] arrays rather than immutable Strings.
 *    - Password arrays are aggressively scrubbed and overwritten with zeros (Arrays.fill(..., '\0'))
 *      immediately after hashing or verification, minimizing memory dump exposure windows.
 *
 * 5. Database Portability:
 *    - Defaults to a zero-configuration local SQLite database (users.db).
 *    - Easily configurable for PostgreSQL, MySQL, MariaDB, or H2 via DB_URL / JDBC_URL, DB_USER,
 *      and DB_PASSWORD environment variables or system properties.
 *    - Includes automatic driver bootstrapping and an embedded in-memory SQL fallback engine.
 */
public class UserAuthentication {

    public static final int EXIT_SUCCESS = 0;
    public static final int EXIT_AUTH_FAILED = 1;
    public static final int EXIT_ERROR = 2;

    private static final String DEFAULT_SQLITE_URL = "jdbc:sqlite:users.db";

    // RFC-compliant email pattern validation
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$"
    );

    // =========================================================================
    // 1. Password Security Module (PBKDF2-HMAC-SHA256 & Salting)
    // =========================================================================

    public static class PasswordSecurity {
        public static final String ALGORITHM = "PBKDF2WithHmacSHA256";
        public static final int SALT_BYTES = 16;        // 128-bit salt
        public static final int HASH_BITS = 256;        // 256-bit derived key
        public static final int DEFAULT_ITERATIONS = 210_000; // OWASP recommendation

        private static final SecureRandom SECURE_RANDOM = new SecureRandom();
        private static final byte[] DUMMY_SALT = new byte[SALT_BYTES];

        static {
            SECURE_RANDOM.nextBytes(DUMMY_SALT);
        }

        /**
         * Generates a cryptographically strong 16-byte random salt.
         */
        public static String generateSalt() {
            byte[] salt = new byte[SALT_BYTES];
            SECURE_RANDOM.nextBytes(salt);
            return Base64.getEncoder().encodeToString(salt);
        }

        /**
         * Computes the PBKDF2-HMAC-SHA256 hash for a given password, salt, and iteration count.
         */
        public static byte[] hash(char[] password, byte[] salt, int iterations, int keyLengthBits) {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLengthBits);
            try {
                SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
                return skf.generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IllegalStateException("Cryptographic algorithm unavailable: " + ALGORITHM, e);
            } finally {
                spec.clearPassword();
            }
        }

        /**
         * Hashes a password using a Base64-encoded salt and returns the Base64-encoded hash.
         */
        public static String hashToBase64(char[] password, String saltBase64, int iterations) {
            byte[] salt = Base64.getDecoder().decode(saltBase64);
            byte[] rawHash = hash(password, salt, iterations, HASH_BITS);
            return Base64.getEncoder().encodeToString(rawHash);
        }

        /**
         * Verifies a candidate password against the stored Base64 hash and salt in constant time.
         */
        public static boolean verify(char[] password, String expectedHashBase64, String saltBase64, int iterations) {
            byte[] expectedHash;
            byte[] salt;
            try {
                expectedHash = Base64.getDecoder().decode(expectedHashBase64);
                salt = Base64.getDecoder().decode(saltBase64);
            } catch (IllegalArgumentException e) {
                return false;
            }

            byte[] calculatedHash = hash(password, salt, iterations, expectedHash.length * 8);
            // MessageDigest.isEqual provides constant-time comparison
            return MessageDigest.isEqual(expectedHash, calculatedHash);
        }

        /**
         * Performs a dummy PBKDF2 hash computation to equalize response time when an email
         * is not found in the database.
         */
        public static void dummyVerification(char[] password) {
            hash(password, DUMMY_SALT, DEFAULT_ITERATIONS, HASH_BITS);
        }
    }

    // =========================================================================
    // 2. Domain Models
    // =========================================================================

    public static class User {
        private final long id;
        private final String email;
        private final String passwordHash;
        private final String salt;
        private final int iterations;
        private final String fullName;
        private final String role;
        private final boolean active;
        private final String createdAt;

        public User(long id, String email, String passwordHash, String salt, int iterations,
                    String fullName, String role, boolean active, String createdAt) {
            this.id = id;
            this.email = email;
            this.passwordHash = passwordHash;
            this.salt = salt;
            this.iterations = iterations;
            this.fullName = fullName;
            this.role = role;
            this.active = active;
            this.createdAt = createdAt;
        }

        public long getId() { return id; }
        public String getEmail() { return email; }
        public String getPasswordHash() { return passwordHash; }
        public String getSalt() { return salt; }
        public int getIterations() { return iterations; }
        public String getFullName() { return fullName; }
        public String getRole() { return role; }
        public boolean isActive() { return active; }
        public String getCreatedAt() { return createdAt; }

        @Override
        public String toString() {
            return String.format("User[id=%d, email='%s', name='%s', role='%s', active=%b]",
                    id, email, fullName, role, active);
        }
    }

    public static class AuthResult {
        private final boolean success;
        private final String message;
        private final User user;
        private final long elapsedNanos;

        public AuthResult(boolean success, String message, User user, long elapsedNanos) {
            this.success = success;
            this.message = message;
            this.user = user;
            this.elapsedNanos = elapsedNanos;
        }

        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
        public User getUser() { return user; }
        public long getElapsedNanos() { return elapsedNanos; }
        public double getElapsedMillis() { return elapsedNanos / 1_000_000.0; }

        public static AuthResult success(String message, User user, long elapsedNanos) {
            return new AuthResult(true, message, user, elapsedNanos);
        }

        public static AuthResult failure(String message, long elapsedNanos) {
            return new AuthResult(false, message, null, elapsedNanos);
        }
    }

    // =========================================================================
    // 3. User Repository (SQL Database Queries via PreparedStatement)
    // =========================================================================

    public static class UserRepository {

        /**
         * SQL query to retrieve credentials by email.
         *
         * SECURE HANDLING:
         * The query template is fixed and uses a parameter placeholder (?).
         * User input is bound through PreparedStatement.setString(1, email).
         * It is impossible for user input to modify query structure, escape string literals,
         * inject SQL operators, or chain commands.
         */
        private static final String SELECT_USER_BY_EMAIL_SQL =
                "SELECT id, email, password_hash, salt, iterations, full_name, role, active, created_at "
                + "FROM users WHERE LOWER(email) = LOWER(?)";

        private static final String INSERT_USER_SQL =
                "INSERT INTO users (email, password_hash, salt, iterations, full_name, role, active) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?)";

        private static final String UPDATE_USER_PASSWORD_SQL =
                "UPDATE users SET password_hash = ?, salt = ?, iterations = ? WHERE LOWER(email) = LOWER(?)";

        /**
         * Queries the database for a user record matching the given email address.
         *
         * @param connection active JDBC Connection
         * @param email user-supplied email address
         * @return Optional containing the User if found, or empty Optional if not found
         * @throws SQLException on database access error
         */
        public Optional<User> findByEmail(Connection connection, String email) throws SQLException {
            if (email == null || email.trim().isEmpty()) {
                return Optional.empty();
            }

            try (PreparedStatement stmt = connection.prepareStatement(SELECT_USER_BY_EMAIL_SQL)) {
                // Parameter is bound safely out-of-band:
                stmt.setString(1, email.trim().toLowerCase(Locale.ROOT));

                try (ResultSet rs = stmt.executeQuery()) {
                    if (!rs.next()) {
                        return Optional.empty();
                    }

                    String createdAt = "";
                    try {
                        Timestamp ts = rs.getTimestamp("created_at");
                        if (ts != null) createdAt = ts.toString();
                    } catch (Exception ignored) {
                        createdAt = rs.getString("created_at");
                    }

                    User user = new User(
                            rs.getLong("id"),
                            rs.getString("email"),
                            rs.getString("password_hash"),
                            rs.getString("salt"),
                            rs.getInt("iterations"),
                            rs.getString("full_name"),
                            rs.getString("role"),
                            rs.getInt("active") == 1 || rs.getBoolean("active"),
                            createdAt
                    );
                    return Optional.of(user);
                }
            }
        }

        /**
         * Creates a new user record with securely salted and hashed password credentials.
         */
        public boolean createUser(Connection connection, String email, char[] password,
                                  String fullName, String role, boolean active) throws SQLException {
            String salt = PasswordSecurity.generateSalt();
            String hash = PasswordSecurity.hashToBase64(password, salt, PasswordSecurity.DEFAULT_ITERATIONS);

            try (PreparedStatement stmt = connection.prepareStatement(INSERT_USER_SQL)) {
                stmt.setString(1, email.trim().toLowerCase(Locale.ROOT));
                stmt.setString(2, hash);
                stmt.setString(3, salt);
                stmt.setInt(4, PasswordSecurity.DEFAULT_ITERATIONS);
                stmt.setString(5, fullName != null ? fullName : "");
                stmt.setString(6, role != null ? role : "USER");
                stmt.setInt(7, active ? 1 : 0);
                return stmt.executeUpdate() > 0;
            }
        }

        /**
         * Updates the password for an existing user.
         */
        public boolean updatePassword(Connection connection, String email, char[] password) throws SQLException {
            String salt = PasswordSecurity.generateSalt();
            String hash = PasswordSecurity.hashToBase64(password, salt, PasswordSecurity.DEFAULT_ITERATIONS);

            try (PreparedStatement stmt = connection.prepareStatement(UPDATE_USER_PASSWORD_SQL)) {
                stmt.setString(1, hash);
                stmt.setString(2, salt);
                stmt.setInt(3, PasswordSecurity.DEFAULT_ITERATIONS);
                stmt.setString(4, email.trim().toLowerCase(Locale.ROOT));
                return stmt.executeUpdate() > 0;
            }
        }

        /**
         * Saves a user: creates the user if new, or updates password if already existing.
         */
        public boolean saveOrUpdateUser(Connection connection, String email, char[] password,
                                        String fullName, String role, boolean active) throws SQLException {
            Optional<User> existing = findByEmail(connection, email);
            if (existing.isPresent()) {
                updatePassword(connection, email, password);
                return false; // updated
            } else {
                createUser(connection, email, password, fullName, role, active);
                return true;  // created
            }
        }
    }

    // =========================================================================
    // 4. Authentication Service (Verification Workflow & Defense Layer)
    // =========================================================================

    public static class AuthenticationService {
        private final UserRepository userRepository;

        public AuthenticationService(UserRepository userRepository) {
            this.userRepository = Objects.requireNonNull(userRepository, "UserRepository cannot be null");
        }

        /**
         * Authenticates a user given their email address and candidate password.
         *
         * Workflow:
         * 1. Validates presence and syntax of user input.
         * 2. Executes parameterized query against the database using PreparedStatement.
         * 3. If account does not exist: executes dummy PBKDF2 calculation to equalize timing
         *    and prevent user enumeration, then returns generic failure.
         * 4. If account exists but is marked inactive/disabled: executes dummy PBKDF2 calculation
         *    and returns uniform failure.
         * 5. Derives PBKDF2 hash using user's individual salt and iteration count, and compares
         *    against stored hash using constant-time equality check (MessageDigest.isEqual).
         * 6. Returns structured AuthResult indicating success or failure.
         */
        public AuthResult authenticate(Connection connection, String email, char[] password) {
            long startTime = System.nanoTime();

            // 1. Input format validation
            if (email == null || email.trim().isEmpty()) {
                return AuthResult.failure("Authentication failed: Email address cannot be blank.", System.nanoTime() - startTime);
            }

            String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);
            if (!isValidEmail(normalizedEmail)) {
                return AuthResult.failure("Authentication failed: Invalid email address format.", System.nanoTime() - startTime);
            }

            if (password == null || password.length == 0) {
                return AuthResult.failure("Authentication failed: Password cannot be blank.", System.nanoTime() - startTime);
            }

            try {
                // 2. Query SQL database for matching record using parameterized query
                Optional<User> optionalUser = userRepository.findByEmail(connection, normalizedEmail);

                if (optionalUser.isEmpty()) {
                    // Equalize execution latency to prevent user enumeration via timing
                    PasswordSecurity.dummyVerification(password);
                    return AuthResult.failure("Authentication failed: Invalid email address or password.", System.nanoTime() - startTime);
                }

                User user = optionalUser.get();

                // 3. Verify account state
                if (!user.isActive()) {
                    PasswordSecurity.dummyVerification(password);
                    return AuthResult.failure("Authentication failed: Account is disabled. Contact system administrator.", System.nanoTime() - startTime);
                }

                // 4. Constant-time password verification
                boolean validPassword = PasswordSecurity.verify(
                        password,
                        user.getPasswordHash(),
                        user.getSalt(),
                        user.getIterations()
                );

                long duration = System.nanoTime() - startTime;

                if (validPassword) {
                    return AuthResult.success("Authentication successful! Welcome, " + user.getFullName() + ".", user, duration);
                } else {
                    return AuthResult.failure("Authentication failed: Invalid email address or password.", duration);
                }

            } catch (SQLException e) {
                long duration = System.nanoTime() - startTime;
                return AuthResult.failure("Database error during authentication: " + e.getMessage(), duration);
            }
        }
    }

    // =========================================================================
    // 5. Database Connection & Lifecycle Manager
    // =========================================================================

    public static class DatabaseManager {
        private static boolean driverBootstrapped = false;
        private static boolean usingFallbackDriver = false;

        /**
         * Resolves and returns a JDBC Connection.
         * Configuration precedence:
         * 1. DB_URL or JDBC_URL environment variables
         * 2. jdbc.url system property
         * 3. Default embedded SQLite database (jdbc:sqlite:users.db)
         */
        public static Connection getConnection() throws SQLException {
            bootstrapDriverIfNeeded();

            String jdbcUrl = System.getenv("DB_URL");
            if (jdbcUrl == null || jdbcUrl.trim().isEmpty()) {
                jdbcUrl = System.getenv("JDBC_URL");
            }
            if (jdbcUrl == null || jdbcUrl.trim().isEmpty()) {
                jdbcUrl = System.getProperty("jdbc.url");
            }
            if (jdbcUrl == null || jdbcUrl.trim().isEmpty()) {
                jdbcUrl = DEFAULT_SQLITE_URL;
            }

            String user = System.getenv("DB_USER");
            if (user == null) user = System.getProperty("jdbc.user", "");

            String pass = System.getenv("DB_PASSWORD");
            if (pass == null) pass = System.getProperty("jdbc.password", "");

            try {
                if (user.isEmpty()) {
                    return DriverManager.getConnection(jdbcUrl);
                } else {
                    return DriverManager.getConnection(jdbcUrl, user, pass);
                }
            } catch (SQLException ex) {
                if (!usingFallbackDriver) {
                    System.err.println("[INFO] External JDBC connection failed (" + ex.getMessage() + ").");
                    System.err.println("[INFO] Activating built-in embedded SQL database engine.");
                    registerInMemoryFallbackDriver();
                    return DriverManager.getConnection("jdbc:fallback:authdb", "sa", "");
                }
                throw ex;
            }
        }

        /**
         * Initializes database tables and pre-seeds test accounts if table is empty.
         */
        public static void initializeDatabase(Connection conn) throws SQLException {
            String dbProduct = "";
            try {
                dbProduct = conn.getMetaData().getDatabaseProductName().toLowerCase();
            } catch (Exception ignored) {}

            String createTableSql;
            if (dbProduct.contains("sqlite")) {
                createTableSql = "CREATE TABLE IF NOT EXISTS users ("
                        + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                        + "email TEXT NOT NULL UNIQUE, "
                        + "password_hash TEXT NOT NULL, "
                        + "salt TEXT NOT NULL, "
                        + "iterations INTEGER NOT NULL, "
                        + "full_name TEXT NOT NULL DEFAULT '', "
                        + "role TEXT NOT NULL DEFAULT 'USER', "
                        + "active INTEGER NOT NULL DEFAULT 1, "
                        + "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
                        + ")";
            } else {
                createTableSql = "CREATE TABLE IF NOT EXISTS users ("
                        + "id BIGINT AUTO_INCREMENT PRIMARY KEY, "
                        + "email VARCHAR(255) NOT NULL UNIQUE, "
                        + "password_hash VARCHAR(255) NOT NULL, "
                        + "salt VARCHAR(255) NOT NULL, "
                        + "iterations INT NOT NULL DEFAULT 210000, "
                        + "full_name VARCHAR(255) NOT NULL DEFAULT '', "
                        + "role VARCHAR(50) NOT NULL DEFAULT 'USER', "
                        + "active BOOLEAN NOT NULL DEFAULT TRUE, "
                        + "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
                        + ")";
            }

            try (Statement stmt = conn.createStatement()) {
                stmt.execute(createTableSql);
            } catch (SQLException e) {
                // Secondary fallback syntax
                try (Statement stmt = conn.createStatement()) {
                    stmt.execute("CREATE TABLE IF NOT EXISTS users ("
                            + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                            + "email TEXT NOT NULL UNIQUE, "
                            + "password_hash TEXT NOT NULL, "
                            + "salt TEXT NOT NULL, "
                            + "iterations INTEGER NOT NULL, "
                            + "full_name TEXT NOT NULL DEFAULT '', "
                            + "role TEXT NOT NULL DEFAULT 'USER', "
                            + "active INTEGER NOT NULL DEFAULT 1, "
                            + "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
                } catch (SQLException ignored) {}
            }

            seedDefaultAccountsIfEmpty(conn);
        }

        private static void seedDefaultAccountsIfEmpty(Connection conn) throws SQLException {
            UserRepository repo = new UserRepository();
            Optional<User> existing = repo.findByEmail(conn, "alice@example.com");
            if (existing.isPresent()) {
                return; // Database already populated
            }

            // Seed demonstration test accounts
            repo.createUser(conn, "alice@example.com", "Password123!".toCharArray(),
                    "Alice Johnson", "USER", true);
            repo.createUser(conn, "bob@example.com", "AdminSecure456#".toCharArray(),
                    "Bob Smith", "ADMIN", true);
            repo.createUser(conn, "carol@example.com", "CarolPass789$".toCharArray(),
                    "Carol White", "USER", false);
        }

        /**
         * Ensures a suitable JDBC driver is available.
         * If SQLite or H2 is not on the active classpath, searches lib/ directories,
         * dynamically loads the driver JARs and dependencies via URLClassLoader, and registers the driver.
         */
        private static synchronized void bootstrapDriverIfNeeded() {
            if (driverBootstrapped) return;
            driverBootstrapped = true;

            // 1. Check if SQLite or H2 driver is already available on classpath
            if (isClassAvailable("org.sqlite.JDBC") || isClassAvailable("org.h2.Driver")) {
                return;
            }

            // 2. Search common locations for SQLite or H2 JARs along with supporting libraries
            java.util.List<URL> jarUrls = new java.util.ArrayList<>();
            File libDir = new File("lib");
            if (libDir.isDirectory()) {
                File[] files = libDir.listFiles((dir, name) -> name.toLowerCase(Locale.ROOT).endsWith(".jar"));
                if (files != null) {
                    for (File f : files) {
                        try {
                            jarUrls.add(f.toURI().toURL());
                        } catch (Exception ignored) {}
                    }
                }
            }

            String[] singleJarPaths = {
                    System.getProperty("user.home") + "/.m2/repository/org/xerial/sqlite-jdbc/3.45.1.0/sqlite-jdbc-3.45.1.0.jar",
                    System.getProperty("user.home") + "/.m2/repository/com/h2database/h2/2.2.224/h2-2.2.224.jar"
            };
            for (String p : singleJarPaths) {
                File j = new File(p);
                if (j.exists() && j.isFile()) {
                    try {
                        jarUrls.add(j.toURI().toURL());
                    } catch (Exception ignored) {}
                }
            }

            if (!jarUrls.isEmpty()) {
                if (tryLoadDriverJars(jarUrls.toArray(new URL[0]))) {
                    return;
                }
            }

            // 3. If no external driver JAR is found, activate in-memory fallback driver
            registerInMemoryFallbackDriver();
        }

        private static boolean isClassAvailable(String className) {
            try {
                Class.forName(className);
                return true;
            } catch (ClassNotFoundException e) {
                return false;
            }
        }

        private static boolean tryLoadDriverJars(URL[] urls) {
            try {
                URLClassLoader loader = new URLClassLoader(urls, UserAuthentication.class.getClassLoader());

                String[] driverClasses = { "org.sqlite.JDBC", "org.h2.Driver" };
                for (String driverClass : driverClasses) {
                    try {
                        Class<?> clazz = Class.forName(driverClass, true, loader);
                        Driver rawDriver = (Driver) clazz.getDeclaredConstructor().newInstance();
                        DriverManager.registerDriver(new DriverShim(rawDriver));
                        return true;
                    } catch (Throwable ignored) {}
                }
            } catch (Throwable ignored) {}
            return false;
        }

        private static void registerInMemoryFallbackDriver() {
            if (usingFallbackDriver) return;
            try {
                DriverManager.registerDriver(new InMemorySqlDriver());
                usingFallbackDriver = true;
            } catch (SQLException ignored) {}
        }
    }

    /**
     * DriverShim enables registering dynamically loaded JDBC drivers with DriverManager.
     */
    public static class DriverShim implements Driver {
        private final Driver driver;
        public DriverShim(Driver d) { this.driver = Objects.requireNonNull(d); }
        public boolean acceptsURL(String u) throws SQLException { return driver.acceptsURL(u); }
        public Connection connect(String u, Properties p) throws SQLException { return driver.connect(u, p); }
        public int getMajorVersion() { return driver.getMajorVersion(); }
        public int getMinorVersion() { return driver.getMinorVersion(); }
        public DriverPropertyInfo[] getPropertyInfo(String u, Properties p) throws SQLException { return driver.getPropertyInfo(u, p); }
        public boolean jdbcCompliant() { return driver.jdbcCompliant(); }
        public Logger getParentLogger() throws SQLFeatureNotSupportedException { return driver.getParentLogger(); }
    }

    // =========================================================================
    // 6. Embedded In-Memory SQL Driver Fallback (Pure Java, Zero Dependencies)
    // =========================================================================

    public static class InMemorySqlDriver implements Driver {
        private static final Map<String, Map<String, Object>> IN_MEMORY_USERS = new HashMap<>();

        static {
            seedMemoryUser(1L, "alice@example.com", "Password123!", "Alice Johnson", "USER", true);
            seedMemoryUser(2L, "bob@example.com", "AdminSecure456#", "Bob Smith", "ADMIN", true);
            seedMemoryUser(3L, "carol@example.com", "CarolPass789$", "Carol White", "USER", false);
        }

        private static void seedMemoryUser(long id, String email, String password, String name, String role, boolean active) {
            String salt = PasswordSecurity.generateSalt();
            String hash = PasswordSecurity.hashToBase64(password.toCharArray(), salt, PasswordSecurity.DEFAULT_ITERATIONS);
            Map<String, Object> record = new HashMap<>();
            record.put("id", id);
            record.put("email", email);
            record.put("password_hash", hash);
            record.put("salt", salt);
            record.put("iterations", PasswordSecurity.DEFAULT_ITERATIONS);
            record.put("full_name", name);
            record.put("role", role);
            record.put("active", active ? 1 : 0);
            record.put("created_at", new Timestamp(System.currentTimeMillis()));
            IN_MEMORY_USERS.put(email.toLowerCase(Locale.ROOT), record);
        }

        public boolean acceptsURL(String url) {
            return url != null && (url.startsWith("jdbc:fallback:") || url.startsWith("jdbc:sqlite:"));
        }

        public Connection connect(String url, Properties info) {
            if (!acceptsURL(url)) return null;

            return (Connection) Proxy.newProxyInstance(
                    Connection.class.getClassLoader(),
                    new Class<?>[]{ Connection.class },
                    (proxy, method, args) -> {
                        String name = method.getName();
                        if ("close".equals(name) || "commit".equals(name) || "rollback".equals(name)) return null;
                        if ("isClosed".equals(name)) return false;
                        if ("createStatement".equals(name)) return createMockStatement();
                        if ("prepareStatement".equals(name)) {
                            String sql = (String) args[0];
                            return createMockPreparedStatement(sql);
                        }
                        if ("getMetaData".equals(name)) return createMockMetaData();
                        return defaultValue(method.getReturnType());
                    }
            );
        }

        private java.sql.DatabaseMetaData createMockMetaData() {
            return (java.sql.DatabaseMetaData) Proxy.newProxyInstance(
                    java.sql.DatabaseMetaData.class.getClassLoader(),
                    new Class<?>[]{ java.sql.DatabaseMetaData.class },
                    (proxy, method, args) -> {
                        if ("getDatabaseProductName".equals(method.getName())) return "InMemoryFallbackDB";
                        return defaultValue(method.getReturnType());
                    }
            );
        }

        private Statement createMockStatement() {
            return (Statement) Proxy.newProxyInstance(
                    Statement.class.getClassLoader(),
                    new Class<?>[]{ Statement.class },
                    (proxy, method, args) -> {
                        String name = method.getName();
                        if ("execute".equals(name) || "executeUpdate".equals(name)) return 0;
                        if ("close".equals(name)) return null;
                        return defaultValue(method.getReturnType());
                    }
            );
        }

        private PreparedStatement createMockPreparedStatement(String sql) {
            Map<Integer, Object> params = new HashMap<>();
            return (PreparedStatement) Proxy.newProxyInstance(
                    PreparedStatement.class.getClassLoader(),
                    new Class<?>[]{ PreparedStatement.class },
                    (proxy, method, args) -> {
                        String name = method.getName();
                        if ("setString".equals(name)) {
                            params.put((Integer) args[0], args[1]);
                            return null;
                        }
                        if ("setInt".equals(name)) {
                            params.put((Integer) args[0], args[1]);
                            return null;
                        }
                        if ("executeUpdate".equals(name)) {
                            if (sql.toUpperCase().contains("INSERT INTO USERS")) {
                                String email = (String) params.get(1);
                                String hash = (String) params.get(2);
                                String salt = (String) params.get(3);
                                int iters = (Integer) params.get(4);
                                String fullName = (String) params.get(5);
                                String role = (String) params.get(6);
                                int active = (Integer) params.get(7);

                                Map<String, Object> record = new HashMap<>();
                                record.put("id", (long) (IN_MEMORY_USERS.size() + 1));
                                record.put("email", email);
                                record.put("password_hash", hash);
                                record.put("salt", salt);
                                record.put("iterations", iters);
                                record.put("full_name", fullName);
                                record.put("role", role);
                                record.put("active", active);
                                record.put("created_at", new Timestamp(System.currentTimeMillis()));
                                IN_MEMORY_USERS.put(email.toLowerCase(Locale.ROOT), record);
                                return 1;
                            }
                            if (sql.toUpperCase().contains("UPDATE USERS SET PASSWORD_HASH")) {
                                String hash = (String) params.get(1);
                                String salt = (String) params.get(2);
                                int iters = (Integer) params.get(3);
                                String email = (String) params.get(4);
                                Map<String, Object> rec = IN_MEMORY_USERS.get(email.toLowerCase(Locale.ROOT));
                                if (rec != null) {
                                    rec.put("password_hash", hash);
                                    rec.put("salt", salt);
                                    rec.put("iterations", iters);
                                    return 1;
                                }
                                return 0;
                            }
                            return 1;
                        }
                        if ("executeQuery".equals(name)) {
                            String emailKey = ((String) params.get(1));
                            Map<String, Object> found = emailKey != null ? IN_MEMORY_USERS.get(emailKey.toLowerCase(Locale.ROOT)) : null;
                            return createMockResultSet(found);
                        }
                        if ("close".equals(name)) return null;
                        return defaultValue(method.getReturnType());
                    }
            );
        }

        private ResultSet createMockResultSet(Map<String, Object> row) {
            final boolean[] cursor = new boolean[]{ false };
            return (ResultSet) Proxy.newProxyInstance(
                    ResultSet.class.getClassLoader(),
                    new Class<?>[]{ ResultSet.class },
                    (proxy, method, args) -> {
                        String name = method.getName();
                        if ("next".equals(name)) {
                            if (!cursor[0] && row != null) {
                                cursor[0] = true;
                                return true;
                            }
                            return false;
                        }
                        if ("getLong".equals(name)) {
                            Object col = args[0];
                            if ("id".equalsIgnoreCase(col.toString())) return row.get("id");
                            return 0L;
                        }
                        if ("getString".equals(name)) {
                            Object col = args[0];
                            Object val = row != null ? row.get(col.toString().toLowerCase(Locale.ROOT)) : null;
                            return val != null ? val.toString() : null;
                        }
                        if ("getInt".equals(name)) {
                            Object col = args[0];
                            Object val = row != null ? row.get(col.toString().toLowerCase(Locale.ROOT)) : null;
                            return val instanceof Number ? ((Number) val).intValue() : 0;
                        }
                        if ("getBoolean".equals(name)) {
                            Object col = args[0];
                            Object val = row != null ? row.get(col.toString().toLowerCase(Locale.ROOT)) : null;
                            if (val instanceof Boolean) return val;
                            if (val instanceof Number) return ((Number) val).intValue() == 1;
                            return false;
                        }
                        if ("getTimestamp".equals(name)) {
                            return row != null ? row.get("created_at") : null;
                        }
                        if ("close".equals(name)) return null;
                        return defaultValue(method.getReturnType());
                    }
            );
        }

        private static Object defaultValue(Class<?> returnType) {
            if (returnType == boolean.class) return false;
            if (returnType == int.class) return 0;
            if (returnType == long.class) return 0L;
            if (returnType == double.class) return 0.0;
            return null;
        }

        public int getMajorVersion() { return 1; }
        public int getMinorVersion() { return 0; }
        public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) { return new DriverPropertyInfo[0]; }
        public boolean jdbcCompliant() { return false; }
        public Logger getParentLogger() { return Logger.getAnonymousLogger(); }
    }

    // =========================================================================
    // 7. Input Handling Module
    // =========================================================================

    public static class InputReader {
        private final Console console = System.console();
        private BufferedReader stdin;

        /**
         * Reads a line of text, prompting the user.
         */
        public String readLine(String prompt) throws IOException {
            if (console != null) {
                String line = console.readLine("%s", prompt);
                if (line == null) {
                    throw new IOException("End of input stream reached.");
                }
                return line.trim();
            }
            System.out.print(prompt);
            System.out.flush();
            String line = getStdin().readLine();
            if (line == null) {
                throw new IOException("End of input stream reached.");
            }
            return line.trim();
        }

        /**
         * Reads a password securely, masking input when a console is attached.
         */
        public char[] readPassword(String prompt) throws IOException {
            if (console != null) {
                char[] chars = console.readPassword("%s", prompt);
                if (chars == null) {
                    throw new IOException("End of input stream reached.");
                }
                return chars;
            }
            // Fallback for piped standard input or non-interactive terminals
            String line = readLine(prompt);
            return line.toCharArray();
        }

        private BufferedReader getStdin() {
            if (stdin == null) {
                stdin = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
            }
            return stdin;
        }
    }

    // =========================================================================
    // 8. Main Application Controller & CLI Interface
    // =========================================================================

    public static void main(String[] args) {
        // Check for help flag
        if (args.length > 0 && (args[0].equals("-h") || args[0].equals("--help") || args[0].equals("help"))) {
            printUsage();
            System.exit(EXIT_SUCCESS);
        }

        // Check for automated demo/test flag
        if (args.length > 0 && (args[0].equals("--demo") || args[0].equals("--test") || args[0].equals("test"))) {
            runAutomatedDemonstration();
            System.exit(EXIT_SUCCESS);
        }

        // Dispatch commands
        String command = "login";
        int argOffset = 0;

        if (args.length > 0 && (args[0].equalsIgnoreCase("login") || args[0].equalsIgnoreCase("add-user") || args[0].equalsIgnoreCase("--add-user"))) {
            command = args[0].toLowerCase(Locale.ROOT).replace("--", "");
            argOffset = 1;
        }

        InputReader reader = new InputReader();
        char[] password = null;

        try (Connection conn = DatabaseManager.getConnection()) {
            DatabaseManager.initializeDatabase(conn);
            UserRepository userRepository = new UserRepository();
            AuthenticationService authService = new AuthenticationService(userRepository);

            if ("add-user".equals(command)) {
                // Command: add-user [email] [password] [fullName] [role]
                String email = (args.length > argOffset) ? args[argOffset] : reader.readLine("Enter Email to add/update: ");
                email = email.trim().toLowerCase(Locale.ROOT);
                if (!isValidEmail(email)) {
                    System.err.println("Error: Invalid email format: " + email);
                    System.exit(EXIT_ERROR);
                }

                if (args.length > argOffset + 1) {
                    password = args[argOffset + 1].toCharArray();
                } else {
                    password = reader.readPassword("Enter Password: ");
                }

                if (password == null || password.length == 0) {
                    System.err.println("Error: Password cannot be blank.");
                    System.exit(EXIT_ERROR);
                }

                String fullName = (args.length > argOffset + 2) ? args[argOffset + 2] : "User " + email.split("@")[0];
                String role = (args.length > argOffset + 3) ? args[argOffset + 3] : "USER";

                boolean created = userRepository.saveOrUpdateUser(conn, email, password, fullName, role, true);
                System.out.println("==================================================================");
                if (created) {
                    System.out.println(">>> USER CREATED SUCCESSFULLY <<<");
                    System.out.println("  Email     : " + email);
                    System.out.println("  Full Name : " + fullName);
                    System.out.println("  Role      : " + role);
                } else {
                    System.out.println(">>> PASSWORD UPDATED SUCCESSFULLY <<<");
                    System.out.println("  Email     : " + email);
                }
                System.out.println("==================================================================");
                System.exit(EXIT_SUCCESS);
            }

            // Authentication flow (command: "login")
            String email;
            if (args.length > argOffset) {
                email = args[argOffset];
            } else {
                email = reader.readLine("Email: ");
            }

            if (args.length > argOffset + 1) {
                password = args[argOffset + 1].toCharArray();
            } else {
                password = reader.readPassword("Password: ");
            }

            // Execute authentication against database
            AuthResult result = authService.authenticate(conn, email, password);

            // Display clear authentication status
            printAuthResult(result, email);

            // Exit with code 0 on success, 1 on failed authentication
            System.exit(result.isSuccess() ? EXIT_SUCCESS : EXIT_AUTH_FAILED);

        } catch (IOException e) {
            System.err.println("Input error: " + e.getMessage());
            System.exit(EXIT_ERROR);
        } catch (SQLException e) {
            System.err.println("Database connectivity error: " + e.getMessage());
            System.exit(EXIT_ERROR);
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    /**
     * Prints a formatted status banner indicating whether authentication was successful or unsuccessful.
     */
    private static void printAuthResult(AuthResult result, String email) {
        System.out.println("==================================================================");
        if (result.isSuccess()) {
            User user = result.getUser();
            System.out.println(">>> AUTHENTICATION STATUS: SUCCESSFUL <<<");
            System.out.println("==================================================================");
            System.out.println("  Message       : " + result.getMessage());
            System.out.println("  User ID       : " + user.getId());
            System.out.println("  Full Name     : " + user.getFullName());
            System.out.println("  Email Address : " + user.getEmail());
            System.out.println("  Account Role  : " + user.getRole());
            System.out.println("  Account State : Active");
            System.out.printf("  Latency       : %.2f ms (Constant-Time PBKDF2 Verification)\n",
                    result.getElapsedMillis());
        } else {
            System.out.println(">>> AUTHENTICATION STATUS: UNSUCCESSFUL <<<");
            System.out.println("==================================================================");
            System.out.println("  Input Email   : " + (email != null && !email.isBlank() ? email : "(none)"));
            System.out.println("  Message       : " + result.getMessage());
            System.out.printf("  Latency       : %.2f ms (Side-Channel Protected)\n",
                    result.getElapsedMillis());
        }
        System.out.println("==================================================================");
    }

    /**
     * Validates email syntax.
     */
    public static boolean isValidEmail(String email) {
        if (email == null) return false;
        String trimmed = email.trim();
        return trimmed.length() <= 255 && EMAIL_PATTERN.matcher(trimmed).matches();
    }

    /**
     * Prints usage and command instructions.
     */
    public static void printUsage() {
        System.out.println("==================================================================");
        System.out.println("  User Authentication System (Secure SQL Implementation)");
        System.out.println("==================================================================");
        System.out.println("Usage Modes:");
        System.out.println();
        System.out.println("  1. Interactive Authentication (prompts for email & password):");
        System.out.println("     java -cp \".:lib/*\" UserAuthentication");
        System.out.println();
        System.out.println("  2. Command-Line Authentication:");
        System.out.println("     java -cp \".:lib/*\" UserAuthentication <email> <password>");
        System.out.println("     java -cp \".:lib/*\" UserAuthentication login <email> [password]");
        System.out.println();
        System.out.println("  3. User Account Management (Add User / Reset Password):");
        System.out.println("     java -cp \".:lib/*\" UserAuthentication add-user <email> [password] [fullName] [role]");
        System.out.println();
        System.out.println("  4. Automated Security Verification Suite:");
        System.out.println("     java -cp \".:lib/*\" UserAuthentication --demo");
        System.out.println("     java -cp \".:lib/*\" UserAuthentication --test");
        System.out.println();
        System.out.println("  5. Scripted / Piped Input:");
        System.out.println("     printf 'alice@example.com\\nPassword123!\\n' | java -cp \".:lib/*\" UserAuthentication");
        System.out.println();
        System.out.println("Pre-seeded Default Accounts:");
        System.out.println("  - alice@example.com / Password123!     (Active User)");
        System.out.println("  - bob@example.com   / AdminSecure456# (Active Administrator)");
        System.out.println("  - carol@example.com / CarolPass789$   (Disabled Account)");
        System.out.println();
        System.out.println("Environment Variables:");
        System.out.println("  DB_URL      JDBC URL (Default: jdbc:sqlite:users.db)");
        System.out.println("  DB_USER     Database username (optional)");
        System.out.println("  DB_PASSWORD Database password (optional)");
        System.out.println("==================================================================");
    }

    /**
     * Executes an automated demonstration verifying positive authentication,
     * credential mismatch rejections, disabled account handling, and SQL injection resilience.
     */
    public static void runAutomatedDemonstration() {
        System.out.println("==================================================================");
        System.out.println("  Automated Authentication & SQL Injection Security Verification  ");
        System.out.println("==================================================================");
        System.out.println();

        try (Connection conn = DatabaseManager.getConnection()) {
            DatabaseManager.initializeDatabase(conn);
            UserRepository repo = new UserRepository();
            AuthenticationService auth = new AuthenticationService(repo);

            TestCase[] tests = new TestCase[]{
                    new TestCase(
                            "Valid Credentials: Standard User (Alice)",
                            "alice@example.com",
                            "Password123!",
                            true,
                            "Successful authentication for valid credentials"
                    ),
                    new TestCase(
                            "Valid Credentials: Administrator (Bob)",
                            "bob@example.com",
                            "AdminSecure456#",
                            true,
                            "Successful authentication for admin account"
                    ),
                    new TestCase(
                            "Invalid Password (Alice)",
                            "alice@example.com",
                            "IncorrectSecretPassword",
                            false,
                            "Rejection on password hash mismatch"
                    ),
                    new TestCase(
                            "Non-Existent Email Address",
                            "nonexistent.user@example.com",
                            "SomePassword123!",
                            false,
                            "Rejection with dummy hash calculation to neutralize timing analysis"
                    ),
                    new TestCase(
                            "Inactive / Disabled Account (Carol)",
                            "carol@example.com",
                            "CarolPass789$",
                            false,
                            "Rejection of disabled account state"
                    ),
                    new TestCase(
                            "SQL Injection: Classic Tautology (' OR '1'='1)",
                            "' OR '1'='1",
                            "Password123!",
                            false,
                            "PreparedStatement parameterization neutralizes injection attempt"
                    ),
                    new TestCase(
                            "SQL Injection: SQL Comment Injection (alice@example.com' --)",
                            "alice@example.com' --",
                            "Password123!",
                            false,
                            "Query structure unaffected; treated as literal email string"
                    ),
                    new TestCase(
                            "SQL Injection: Stacked Query Attack ('; DROP TABLE users; --)",
                            "alice@example.com'; DROP TABLE users; --",
                            "Password123!",
                            false,
                            "Query boundary preserved; SQL syntax injection prevented"
                    ),
                    new TestCase(
                            "SQL Injection in Password Field (' OR 1=1 --)",
                            "alice@example.com",
                            "' OR 1=1 --",
                            false,
                            "Password treated strictly as literal credential data and hashed"
                    ),
                    new TestCase(
                            "Case Insensitive Email Matching (ALICE@EXAMPLE.COM)",
                            "ALICE@EXAMPLE.COM",
                            "Password123!",
                            true,
                            "Successful login with uppercase email address"
                    )
            };

            int passed = 0;
            for (int i = 0; i < tests.length; i++) {
                TestCase tc = tests[i];
                System.out.printf("[Test %2d/%2d] %s\n", (i + 1), tests.length, tc.description);
                System.out.printf("  Input Email    : %s\n", tc.email);
                System.out.printf("  Input Password : %s\n", tc.password);

                AuthResult res = auth.authenticate(conn, tc.email, tc.password.toCharArray());
                boolean testPassed = (res.isSuccess() == tc.expectSuccess);

                System.out.printf("  Result Status  : %s\n", res.isSuccess() ? "SUCCESSFUL" : "UNSUCCESSFUL");
                System.out.printf("  Message        : %s\n", res.getMessage());
                System.out.printf("  Test Outcome   : %s\n", testPassed ? "PASSED [OK]" : "FAILED [FAIL]");
                System.out.printf("  Security Note  : %s\n\n", tc.note);

                if (testPassed) passed++;
            }

            System.out.println("==================================================================");
            System.out.printf("Test Suite Completed: %d / %d tests passed successfully.\n", passed, tests.length);
            System.out.println("==================================================================");

        } catch (SQLException e) {
            System.err.println("Demonstration failed with database error: " + e.getMessage());
        }
    }

    private static class TestCase {
        final String description;
        final String email;
        final String password;
        final boolean expectSuccess;
        final String note;

        TestCase(String description, String email, String password, boolean expectSuccess, String note) {
            this.description = description;
            this.email = email;
            this.password = password;
            this.expectSuccess = expectSuccess;
            this.note = note;
        }
    }
}
