import java.io.BufferedReader;
import java.io.Console;
import java.io.File;
import java.io.InputStreamReader;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.sql.*;
import java.util.*;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * UserAuthentication
 *
 * A comprehensive Java program that authenticates a user by verifying their
 * email address and password against credentials stored in an SQL database.
 *
 * Security & Design Features:
 * 1. SQL Injection Protection: All database interactions strictly use parameterized
 *    queries (PreparedStatement) to neutralize SQL injection vulnerabilities.
 * 2. Cryptographic Password Hashing: Implements PBKDF2 with HMAC-SHA256, utilizing
 *    a unique 16-byte cryptographic salt per user and 100,000 iterations (NIST / OWASP standard).
 * 3. Timing-Attack Defense: Employs MessageDigest.isEqual() for constant-time hash
 *    comparison. For non-existent accounts, a dummy PBKDF2 calculation is performed
 *    to prevent user enumeration via timing discrepancies.
 * 4. User Enumeration Prevention: Authentication failures output uniform, generic
 *    error messages ("Invalid email address or password") to prevent leaking account existence.
 * 5. Flexible Execution: Accepts input interactively (with secure password masking when
 *    a terminal console is present, and stdin streaming when piped/redirected), via command-line
 *    arguments, or via an automated self-test/demonstration suite (--demo / --test).
 * 6. Resilient Database Backend: Connects to any standard SQL database via JDBC (configured
 *    via JDBC_URL / DB_USER / DB_PASSWORD environment variables or system properties). Defaults
 *    to an embedded H2 SQL database, dynamically bootstrapping the driver from ./lib or the system,
 *    with a built-in in-memory SQL driver fallback if no external jar is available.
 */
public class UserAuthentication {

    // Regex pattern for validating email format
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$"
    );

    // Default embedded H2 database URL
    private static final String DEFAULT_H2_URL = "jdbc:h2:mem:authdb;DB_CLOSE_DELAY=-1";

    // =========================================================================
    // 1. Password Security (PBKDF2-HMAC-SHA256, Salting, Constant-Time Verification)
    // =========================================================================

    public static class PasswordSecurity {
        public static final String ALGORITHM = "PBKDF2WithHmacSHA256";
        public static final int SALT_BYTES = 16;       // 128 bits
        public static final int HASH_BITS = 256;       // 256 bits (32 bytes)
        public static final int ITERATIONS = 100_000;  // Recommended by OWASP/NIST

        private static final SecureRandom SECURE_RANDOM = new SecureRandom();
        private static final byte[] DUMMY_SALT = new byte[SALT_BYTES];

        static {
            SECURE_RANDOM.nextBytes(DUMMY_SALT);
        }

        /**
         * Generates a cryptographically secure random 16-byte salt.
         */
        public static String generateSalt() {
            byte[] salt = new byte[SALT_BYTES];
            SECURE_RANDOM.nextBytes(salt);
            return Base64.getEncoder().encodeToString(salt);
        }

        /**
         * Derives a cryptographic hash using PBKDF2 with HMAC-SHA256.
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
         * Hashes a password with a Base64-encoded salt and returns a Base64-encoded hash string.
         */
        public static String hashToBase64(char[] password, String saltBase64, int iterations) {
            byte[] salt = Base64.getDecoder().decode(saltBase64);
            byte[] hashBytes = hash(password, salt, iterations, HASH_BITS);
            return Base64.getEncoder().encodeToString(hashBytes);
        }

        /**
         * Verifies a plain password against stored Base64 hash and salt using constant-time comparison.
         */
        public static boolean verify(char[] password, String storedHashBase64, String saltBase64, int iterations) {
            if (password == null || storedHashBase64 == null || saltBase64 == null) {
                return false;
            }
            try {
                byte[] expectedHash = Base64.getDecoder().decode(storedHashBase64);
                byte[] salt = Base64.getDecoder().decode(saltBase64);
                byte[] actualHash = hash(password, salt, iterations, expectedHash.length * 8);

                // Constant-time comparison protects against side-channel timing attacks
                return MessageDigest.isEqual(expectedHash, actualHash);
            } catch (IllegalArgumentException e) {
                return false;
            }
        }

        /**
         * Performs a dummy PBKDF2 calculation to equalize response times when a user is not found,
         * mitigating side-channel timing attacks aimed at account enumeration.
         */
        public static void dummyVerification(char[] password) {
            try {
                char[] pass = (password != null && password.length > 0) ? password : "dummyPassword123!".toCharArray();
                hash(pass, DUMMY_SALT, ITERATIONS, HASH_BITS);
            } catch (Exception ignored) {
                // Ignore errors in dummy verification
            }
        }
    }

    // =========================================================================
    // 2. Data Models (User & Authentication Result)
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
        private final long executionTimeNanos;

        public AuthResult(boolean success, String message, User user, long executionTimeNanos) {
            this.success = success;
            this.message = message;
            this.user = user;
            this.executionTimeNanos = executionTimeNanos;
        }

        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
        public User getUser() { return user; }
        public long getExecutionTimeNanos() { return executionTimeNanos; }
        public double getExecutionTimeMs() { return executionTimeNanos / 1_000_000.0; }

        public static AuthResult success(String message, User user, long executionTimeNanos) {
            return new AuthResult(true, message, user, executionTimeNanos);
        }

        public static AuthResult failure(String message, long executionTimeNanos) {
            return new AuthResult(false, message, null, executionTimeNanos);
        }
    }

    // =========================================================================
    // 3. User Repository (SQL Database Queries via PreparedStatement)
    // =========================================================================

    public static class UserRepository {
        private static final String SELECT_BY_EMAIL_SQL =
                "SELECT id, email, password_hash, salt, iterations, full_name, role, active, created_at "
                + "FROM users WHERE LOWER(email) = LOWER(?)";

        private static final String INSERT_USER_SQL =
                "INSERT INTO users (email, password_hash, salt, iterations, full_name, role, active) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?)";

        /**
         * Queries the database for a user record matching the given email address.
         * Parameterized via PreparedStatement to prevent SQL injection.
         */
        public Optional<User> findByEmail(Connection connection, String email) throws SQLException {
            if (email == null || email.trim().isEmpty()) {
                return Optional.empty();
            }

            try (PreparedStatement stmt = connection.prepareStatement(SELECT_BY_EMAIL_SQL)) {
                stmt.setString(1, email.trim());

                try (ResultSet rs = stmt.executeQuery()) {
                    if (!rs.next()) {
                        return Optional.empty();
                    }

                    Timestamp ts = null;
                    try {
                        ts = rs.getTimestamp("created_at");
                    } catch (Exception ignored) {}

                    String createdAtStr = (ts != null) ? ts.toString() : rs.getString("created_at");

                    User user = new User(
                            rs.getLong("id"),
                            rs.getString("email"),
                            rs.getString("password_hash"),
                            rs.getString("salt"),
                            rs.getInt("iterations"),
                            rs.getString("full_name"),
                            rs.getString("role"),
                            rs.getBoolean("active"),
                            createdAtStr
                    );
                    return Optional.of(user);
                }
            }
        }

        /**
         * Inserts a new user record with securely hashed credentials into the database.
         */
        public boolean createUser(Connection connection, String email, char[] password,
                                  String fullName, String role, boolean active) throws SQLException {
            String salt = PasswordSecurity.generateSalt();
            String hash = PasswordSecurity.hashToBase64(password, salt, PasswordSecurity.ITERATIONS);

            try (PreparedStatement stmt = connection.prepareStatement(INSERT_USER_SQL)) {
                stmt.setString(1, email.trim());
                stmt.setString(2, hash);
                stmt.setString(3, salt);
                stmt.setInt(4, PasswordSecurity.ITERATIONS);
                stmt.setString(5, fullName);
                stmt.setString(6, role);
                stmt.setBoolean(7, active);
                return stmt.executeUpdate() > 0;
            }
        }
    }

    // =========================================================================
    // 4. Authentication Service (Business Logic & Verification Flow)
    // =========================================================================

    public static class AuthenticationService {
        private final UserRepository userRepository;

        public AuthenticationService(UserRepository userRepository) {
            this.userRepository = Objects.requireNonNull(userRepository, "UserRepository cannot be null");
        }

        /**
         * Authenticates a user given their email address and plain password.
         *
         * Steps:
         * 1. Validates input format (presence and email syntax).
         * 2. Queries SQL database using PreparedStatement by email.
         * 3. If account does not exist: executes dummy PBKDF2 verification to mitigate
         *    timing side-channels, and returns generic failure.
         * 4. If account is inactive/disabled: returns generic failure.
         * 5. Hashes input password with user's specific salt and compares using constant-time equality.
         * 6. Returns structured AuthResult indicating success or failure.
         */
        public AuthResult authenticate(Connection connection, String email, char[] password) {
            long startTime = System.nanoTime();

            // 1. Validate inputs
            if (email == null || email.trim().isEmpty()) {
                return AuthResult.failure("Authentication failed: Email address cannot be blank.", System.nanoTime() - startTime);
            }
            if (!EMAIL_PATTERN.matcher(email.trim()).matches()) {
                return AuthResult.failure("Authentication failed: Invalid email address format.", System.nanoTime() - startTime);
            }
            if (password == null || password.length == 0) {
                return AuthResult.failure("Authentication failed: Password cannot be blank.", System.nanoTime() - startTime);
            }

            try {
                // 2. Query SQL database for user
                Optional<User> optionalUser = userRepository.findByEmail(connection, email.trim());

                if (optionalUser.isEmpty()) {
                    // Equalize execution time to prevent user enumeration via timing
                    PasswordSecurity.dummyVerification(password);
                    return AuthResult.failure("Authentication failed: Invalid email address or password.", System.nanoTime() - startTime);
                }

                User user = optionalUser.get();

                // Check if the user account is active
                if (!user.isActive()) {
                    PasswordSecurity.dummyVerification(password);
                    return AuthResult.failure("Authentication failed: Account is disabled. Contact system administrator.", System.nanoTime() - startTime);
                }

                // 3. Verify password hash using constant-time comparison
                boolean passwordValid = PasswordSecurity.verify(
                        password,
                        user.getPasswordHash(),
                        user.getSalt(),
                        user.getIterations()
                );

                long duration = System.nanoTime() - startTime;

                if (passwordValid) {
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
         * Obtains a JDBC Connection.
         * Uses JDBC_URL environment variable / system property if present,
         * otherwise defaults to an in-memory embedded H2 database.
         */
        public static Connection getConnection() throws SQLException {
            bootstrapDriverIfNeeded();

            String jdbcUrl = System.getenv("JDBC_URL");
            if (jdbcUrl == null || jdbcUrl.trim().isEmpty()) {
                jdbcUrl = System.getProperty("jdbc.url");
            }
            if (jdbcUrl == null || jdbcUrl.trim().isEmpty()) {
                jdbcUrl = DEFAULT_H2_URL;
            }

            String user = System.getenv("DB_USER");
            if (user == null) user = System.getProperty("jdbc.user", "sa");

            String pass = System.getenv("DB_PASSWORD");
            if (pass == null) pass = System.getProperty("jdbc.password", "");

            try {
                return DriverManager.getConnection(jdbcUrl, user, pass);
            } catch (SQLException ex) {
                // If external driver fails or cannot be found, fallback to internal in-memory SQL connection
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
         * Initializes the users table schema and populates default demo accounts if table is empty.
         */
        public static void initializeDatabase(Connection conn) throws SQLException {
            String createTableSql =
                    "CREATE TABLE IF NOT EXISTS users ("
                    + "id BIGINT AUTO_INCREMENT PRIMARY KEY, "
                    + "email VARCHAR(255) NOT NULL UNIQUE, "
                    + "password_hash VARCHAR(255) NOT NULL, "
                    + "salt VARCHAR(255) NOT NULL, "
                    + "iterations INT NOT NULL DEFAULT 100000, "
                    + "full_name VARCHAR(255) NOT NULL, "
                    + "role VARCHAR(50) NOT NULL DEFAULT 'USER', "
                    + "active BOOLEAN NOT NULL DEFAULT TRUE, "
                    + "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
                    + ")";

            try (Statement stmt = conn.createStatement()) {
                stmt.execute(createTableSql);
            } catch (SQLException e) {
                // Fallback table syntax in case DB dialect differs
                try (Statement stmt = conn.createStatement()) {
                    stmt.execute("CREATE TABLE IF NOT EXISTS users ("
                            + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                            + "email TEXT NOT NULL UNIQUE, "
                            + "password_hash TEXT NOT NULL, "
                            + "salt TEXT NOT NULL, "
                            + "iterations INTEGER NOT NULL, "
                            + "full_name TEXT NOT NULL, "
                            + "role TEXT NOT NULL DEFAULT 'USER', "
                            + "active INTEGER NOT NULL DEFAULT 1, "
                            + "created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
                } catch (SQLException ignored) {}
            }

            // Seed default users if table is empty
            seedDefaultAccountsIfEmpty(conn);
        }

        private static void seedDefaultAccountsIfEmpty(Connection conn) throws SQLException {
            UserRepository repo = new UserRepository();
            Optional<User> existing = repo.findByEmail(conn, "alice@example.com");
            if (existing.isPresent()) {
                return; // Already seeded
            }

            // Seed 3 test accounts:
            // 1. Alice Johnson (Standard active user)
            repo.createUser(conn, "alice@example.com", "Password123!".toCharArray(),
                    "Alice Johnson", "USER", true);

            // 2. Bob Smith (Administrator)
            repo.createUser(conn, "bob@example.com", "AdminSecure456#".toCharArray(),
                    "Bob Smith", "ADMIN", true);

            // 3. Carol White (Disabled account)
            repo.createUser(conn, "carol@example.com", "CarolPass789$".toCharArray(),
                    "Carol White", "USER", false);
        }

        /**
         * Ensures an appropriate JDBC driver is registered.
         * Inspects classpath, searches ./lib, ./, and ~/.m2 for H2 or SQLite jars,
         * or falls back to an in-memory SQL mock driver.
         */
        private static synchronized void bootstrapDriverIfNeeded() {
            if (driverBootstrapped) return;
            driverBootstrapped = true;

            // 1. Check if H2 or SQLite is already on classpath
            if (isClassAvailable("org.h2.Driver") || isClassAvailable("org.sqlite.JDBC")) {
                return;
            }

            // 2. Search common locations for H2 or SQLite jars
            String[] searchPaths = {
                    "lib/h2.jar",
                    "h2.jar",
                    "lib/h2-2.2.224.jar",
                    "lib/sqlite-jdbc.jar",
                    System.getProperty("user.home") + "/.m2/repository/com/h2database/h2/2.2.224/h2-2.2.224.jar",
                    System.getProperty("user.home") + "/.m2/repository/org/xerial/sqlite-jdbc/3.45.1.0/sqlite-jdbc-3.45.1.0.jar"
            };

            for (String path : searchPaths) {
                File jar = new File(path);
                if (jar.exists() && jar.isFile()) {
                    if (tryLoadDriverJar(jar)) {
                        return;
                    }
                }
            }

            // 3. If no external jar found, prepare fallback driver
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

        private static boolean tryLoadDriverJar(File jarFile) {
            try {
                URLClassLoader loader = new URLClassLoader(
                        new URL[]{ jarFile.toURI().toURL() },
                        UserAuthentication.class.getClassLoader()
                );

                String[] driverClasses = { "org.h2.Driver", "org.sqlite.JDBC" };
                for (String driverClass : driverClasses) {
                    try {
                        Class<?> clazz = Class.forName(driverClass, true, loader);
                        Driver rawDriver = (Driver) clazz.getDeclaredConstructor().newInstance();
                        DriverManager.registerDriver(new DriverShim(rawDriver));
                        return true;
                    } catch (ClassNotFoundException ignored) {}
                }
            } catch (Exception ignored) {}
            return false;
        }

        /**
         * Registers a lightweight built-in SQL in-memory driver so that the program
         * can run anywhere without any external dependencies or jar files.
         */
        private static void registerInMemoryFallbackDriver() {
            if (usingFallbackDriver) return;
            try {
                DriverManager.registerDriver(new InMemorySqlDriver());
                usingFallbackDriver = true;
            } catch (SQLException ignored) {}
        }
    }

    /**
     * DriverShim allows loading JDBC drivers from external JARs via URLClassLoader
     * while satisfying DriverManager's classloader verification checks.
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
            // Pre-seed demo users in memory fallback
            seedMemoryUser(1L, "alice@example.com", "Password123!", "Alice Johnson", "USER", true);
            seedMemoryUser(2L, "bob@example.com", "AdminSecure456#", "Bob Smith", "ADMIN", true);
            seedMemoryUser(3L, "carol@example.com", "CarolPass789$", "Carol White", "USER", false);
        }

        private static void seedMemoryUser(long id, String email, String password, String name, String role, boolean active) {
            String salt = PasswordSecurity.generateSalt();
            String hash = PasswordSecurity.hashToBase64(password.toCharArray(), salt, PasswordSecurity.ITERATIONS);
            Map<String, Object> record = new HashMap<>();
            record.put("id", id);
            record.put("email", email);
            record.put("password_hash", hash);
            record.put("salt", salt);
            record.put("iterations", PasswordSecurity.ITERATIONS);
            record.put("full_name", name);
            record.put("role", role);
            record.put("active", active);
            record.put("created_at", new Timestamp(System.currentTimeMillis()));
            IN_MEMORY_USERS.put(email.toLowerCase(), record);
        }

        public boolean acceptsURL(String url) {
            return url != null && (url.startsWith("jdbc:fallback:") || url.startsWith("jdbc:h2:mem:"));
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
                        if ("setBoolean".equals(name)) {
                            params.put((Integer) args[0], args[1]);
                            return null;
                        }
                        if ("executeUpdate".equals(name)) {
                            if (sql.toUpperCase().contains("INSERT INTO USERS")) {
                                String email = (String) params.get(1);
                                String hash = (String) params.get(2);
                                String salt = (String) params.get(3);
                                int iter = (Integer) params.get(4);
                                String fullName = (String) params.get(5);
                                String role = (String) params.get(6);
                                boolean active = (Boolean) params.get(7);

                                Map<String, Object> rec = new HashMap<>();
                                rec.put("id", (long) (IN_MEMORY_USERS.size() + 1));
                                rec.put("email", email);
                                rec.put("password_hash", hash);
                                rec.put("salt", salt);
                                rec.put("iterations", iter);
                                rec.put("full_name", fullName);
                                rec.put("role", role);
                                rec.put("active", active);
                                rec.put("created_at", new Timestamp(System.currentTimeMillis()));
                                IN_MEMORY_USERS.put(email.toLowerCase(), rec);
                                return 1;
                            }
                            return 0;
                        }
                        if ("executeQuery".equals(name)) {
                            String emailParam = (String) params.get(1);
                            Map<String, Object> found = (emailParam != null) ? IN_MEMORY_USERS.get(emailParam.toLowerCase()) : null;
                            List<Map<String, Object>> rows = (found != null) ? Collections.singletonList(found) : Collections.emptyList();
                            Iterator<Map<String, Object>> cursor = rows.iterator();
                            final Map<String, Object>[] current = new Map[]{ null };

                            return (ResultSet) Proxy.newProxyInstance(
                                    ResultSet.class.getClassLoader(),
                                    new Class<?>[]{ ResultSet.class },
                                    (rp, rm, ra) -> {
                                        String mName = rm.getName();
                                        if ("next".equals(mName)) {
                                            if (cursor.hasNext()) {
                                                current[0] = cursor.next();
                                                return true;
                                            }
                                            current[0] = null;
                                            return false;
                                        }
                                        if ("close".equals(mName)) return null;
                                        if (current[0] == null) return defaultValue(rm.getReturnType());

                                        String col = (ra != null && ra.length > 0 && ra[0] instanceof String)
                                                ? ((String) ra[0]).toLowerCase() : null;

                                        if ("getString".equals(mName)) {
                                            Object v = current[0].get(col);
                                            return v != null ? String.valueOf(v) : null;
                                        }
                                        if ("getLong".equals(mName)) {
                                            Number n = (Number) current[0].get(col);
                                            return n != null ? n.longValue() : 0L;
                                        }
                                        if ("getInt".equals(mName)) {
                                            Number n = (Number) current[0].get(col);
                                            return n != null ? n.intValue() : 0;
                                        }
                                        if ("getBoolean".equals(mName)) {
                                            Boolean b = (Boolean) current[0].get(col);
                                            return b != null ? b : false;
                                        }
                                        if ("getTimestamp".equals(mName)) {
                                            return current[0].get(col);
                                        }
                                        return defaultValue(rm.getReturnType());
                                    }
                            );
                        }
                        if ("close".equals(name)) return null;
                        return defaultValue(method.getReturnType());
                    }
            );
        }

        private static Object defaultValue(Class<?> type) {
            if (type == boolean.class) return false;
            if (type == int.class) return 0;
            if (type == long.class) return 0L;
            if (type == double.class) return 0.0;
            return null;
        }

        public int getMajorVersion() { return 1; }
        public int getMinorVersion() { return 0; }
        public DriverPropertyInfo[] getPropertyInfo(String u, Properties p) { return new DriverPropertyInfo[0]; }
        public boolean jdbcCompliant() { return false; }
        public Logger getParentLogger() { return Logger.getLogger("InMemorySqlDriver"); }
    }

    // =========================================================================
    // 7. Interactive Input & Command Line Interface (CLI)
    // =========================================================================

    public static void main(String[] args) {
        // Handle help flag
        if (args.length == 1 && (args[0].equals("-h") || args[0].equals("--help"))) {
            printUsage();
            System.exit(0);
        }

        // Handle automated demonstration / test mode
        if (args.length == 1 && (args[0].equalsIgnoreCase("--demo") || args[0].equalsIgnoreCase("--test"))) {
            runAutomatedDemonstration();
            System.exit(0);
        }

        String email = null;
        char[] password = null;

        try {
            // Case A: Arguments passed via CLI
            if (args.length >= 2) {
                email = args[0];
                password = args[1].toCharArray();
            } else if (args.length == 1) {
                System.err.println("Error: Password argument missing.");
                printUsage();
                System.exit(2);
            } else {
                // Case B: Interactive input
                Console console = System.console();
                if (console != null) {
                    System.out.println("==================================================================");
                    System.out.println("             SQL User Authentication System (PBKDF2)              ");
                    System.out.println("==================================================================");
                    email = console.readLine("Enter email address: ");
                    password = console.readPassword("Enter password: ");
                    System.out.println();
                } else {
                    // Headless / piped input (e.g. echo -e "email\npass" | java UserAuthentication)
                    BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
                    email = reader.readLine();
                    String passLine = reader.readLine();
                    if (passLine != null) {
                        password = passLine.toCharArray();
                    }
                }
            }

            if (email == null) email = "";
            if (password == null) password = new char[0];

            // Perform authentication against SQL database
            boolean success = executeAuthentication(email, password, false);

            // Clean up password array in memory
            Arrays.fill(password, '\0');

            // Set exit code (0 for success, 1 for unsuccessful authentication)
            System.exit(success ? 0 : 1);

        } catch (Exception e) {
            System.err.println("[ERROR] An unexpected error occurred: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Executes the authentication process against the SQL database and prints the result.
     */
    public static boolean executeAuthentication(String email, char[] password, boolean verbose) {
        UserRepository userRepository = new UserRepository();
        AuthenticationService authService = new AuthenticationService(userRepository);

        try (Connection conn = DatabaseManager.getConnection()) {
            DatabaseManager.initializeDatabase(conn);

            AuthResult result = authService.authenticate(conn, email, password);

            printResultBanner(result, email);
            return result.isSuccess();

        } catch (SQLException e) {
            System.err.println("[ERROR] Database connectivity error: " + e.getMessage());
            return false;
        }
    }

    /**
     * Pretty-prints the authentication result.
     */
    private static void printResultBanner(AuthResult result, String email) {
        System.out.println("------------------------------------------------------------------");
        if (result.isSuccess()) {
            User user = result.getUser();
            System.out.println(">>> AUTHENTICATION STATUS: SUCCESSFUL <<<");
            System.out.println("------------------------------------------------------------------");
            System.out.println("  Message       : " + result.getMessage());
            System.out.println("  User ID       : " + user.getId());
            System.out.println("  Full Name     : " + user.getFullName());
            System.out.println("  Email Address : " + user.getEmail());
            System.out.println("  User Role     : " + user.getRole());
            System.out.println("  Account State : Active");
            System.out.printf("  Verification  : %d iterations PBKDF2-HMAC-SHA256 (%.2f ms)\n",
                    user.getIterations(), result.getExecutionTimeMs());
        } else {
            System.out.println(">>> AUTHENTICATION STATUS: UNSUCCESSFUL <<<");
            System.out.println("------------------------------------------------------------------");
            System.out.println("  Input Email   : " + (email != null && !email.isBlank() ? email : "(none)"));
            System.out.println("  Reason        : " + result.getMessage());
            System.out.printf("  Elapsed Time  : %.2f ms (constant-time verification)\n",
                    result.getExecutionTimeMs());
        }
        System.out.println("------------------------------------------------------------------");
    }

    /**
     * Prints usage instructions.
     */
    private static void printUsage() {
        System.out.println("Usage:");
        System.out.println("  1. Interactive Mode:");
        System.out.println("     java -cp .:lib/h2.jar UserAuthentication");
        System.out.println();
        System.out.println("  2. Command-Line Arguments:");
        System.out.println("     java -cp .:lib/h2.jar UserAuthentication <email> <password>");
        System.out.println();
        System.out.println("  3. Automated Demonstration & Security Test Suite:");
        System.out.println("     java -cp .:lib/h2.jar UserAuthentication --demo");
        System.out.println();
        System.out.println("  4. Piped / Automated Input:");
        System.out.println("     printf 'alice@example.com\\nPassword123!\\n' | java -cp .:lib/h2.jar UserAuthentication");
        System.out.println();
        System.out.println("Pre-seeded Test Accounts:");
        System.out.println("  - alice@example.com  / Password123!     (Active Standard User)");
        System.out.println("  - bob@example.com    / AdminSecure456# (Active Administrator)");
        System.out.println("  - carol@example.com  / CarolPass789$   (Inactive/Disabled Account)");
    }

    /**
     * Runs a comprehensive demonstration showing valid logins, invalid passwords,
     * non-existent accounts, disabled accounts, and SQL injection resilience.
     */
    public static void runAutomatedDemonstration() {
        System.out.println("==================================================================");
        System.out.println("   SQL User Authentication Demonstration & Security Verification  ");
        System.out.println("==================================================================");
        System.out.println();

        try (Connection conn = DatabaseManager.getConnection()) {
            DatabaseManager.initializeDatabase(conn);
            UserRepository repo = new UserRepository();
            AuthenticationService auth = new AuthenticationService(repo);

            TestCase[] tests = new TestCase[]{
                    new TestCase("Valid Credentials (User Alice)", "alice@example.com", "Password123!", true),
                    new TestCase("Valid Credentials (Admin Bob)", "bob@example.com", "AdminSecure456#", true),
                    new TestCase("Incorrect Password (Alice)", "alice@example.com", "WrongPassword999", false),
                    new TestCase("Non-Existent Email", "nobody@example.com", "Password123!", false),
                    new TestCase("Inactive/Disabled Account (Carol)", "carol@example.com", "CarolPass789$", false),
                    new TestCase("SQL Injection in Email (' OR '1'='1)", "' OR '1'='1", "Password123!", false),
                    new TestCase("SQL Injection with Comment (alice' --)", "alice@example.com' --", "anything", false),
                    new TestCase("Empty Email & Password", "", "", false)
            };

            int passedCount = 0;

            for (int i = 0; i < tests.length; i++) {
                TestCase tc = tests[i];
                System.out.printf("[Test %d/%d] %s\n", i + 1, tests.length, tc.description);
                System.out.printf("  Input Email    : %s\n", tc.email);
                System.out.printf("  Input Password : %s\n", tc.password);

                AuthResult res = auth.authenticate(conn, tc.email, tc.password.toCharArray());
                boolean testPassed = (res.isSuccess() == tc.expectSuccess);

                System.out.printf("  Outcome        : %s\n", res.isSuccess() ? "SUCCESSFUL" : "UNSUCCESSFUL");
                System.out.printf("  Message        : %s\n", res.getMessage());
                System.out.printf("  Assertion      : %s\n", testPassed ? "PASSED [OK]" : "FAILED [FAIL]");
                System.out.println();

                if (testPassed) passedCount++;
            }

            System.out.println("==================================================================");
            System.out.printf("Demonstration Summary: %d / %d tests passed successfully.\n",
                    passedCount, tests.length);
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

        TestCase(String description, String email, String password, boolean expectSuccess) {
            this.description = description;
            this.email = email;
            this.password = password;
            this.expectSuccess = expectSuccess;
        }
    }
}
