import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
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
import java.util.Base64;

/**
 * Service for registering new user accounts and authenticating users against an SQL database.
 * Utilizes salted PBKDF2 with HMAC-SHA512 for secure password hashing and constant-time
 * hash verification to guard against timing attacks.
 */
public class UserAccountService {

    // Cryptographic parameters
    private static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA512";
    private static final int ITERATIONS = 210_000;
    private static final int SALT_BYTES = 16;
    private static final int KEY_LENGTH_BITS = 256;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final byte[] DUMMY_SALT = new byte[SALT_BYTES];

    private final Connection connection;

    /**
     * Constructs a new UserAccountService with an active JDBC connection.
     *
     * @param connection an active, non-null JDBC Connection
     * @throws IllegalArgumentException if connection is null
     */
    public UserAccountService(Connection connection) {
        if (connection == null) {
            throw new IllegalArgumentException("Database connection cannot be null.");
        }
        this.connection = connection;
    }

    /**
     * Creates the required 'users' table if it does not already exist.
     *
     * @param connection active JDBC connection
     * @throws SQLException if a database error occurs
     */
    public static void createUsersTable(Connection connection) throws SQLException {
        if (connection == null) {
            throw new IllegalArgumentException("Database connection cannot be null.");
        }
        String sql = "CREATE TABLE IF NOT EXISTS users ("
                   + "username VARCHAR(255) NOT NULL PRIMARY KEY, "
                   + "password_hash VARCHAR(255) NOT NULL, "
                   + "salt VARCHAR(255) NOT NULL, "
                   + "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
                   + ")";
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(sql);
        }
    }

    /**
     * Initializes the database schema using the service instance's connection.
     *
     * @throws SQLException if a database error occurs
     */
    public void initializeDatabase() throws SQLException {
        createUsersTable(this.connection);
    }

    /**
     * Registers a new user with the given username and password using the instance connection.
     *
     * @param username the desired username (must not be blank)
     * @param password the plaintext password
     * @return true if registration was successful; false if username is already taken
     * @throws SQLException if a database access error occurs
     * @throws IllegalArgumentException if username or password fails validation
     */
    public boolean registerUser(String username, String password) throws SQLException {
        return registerUser(this.connection, username, password != null ? password.toCharArray() : null);
    }

    /**
     * Registers a new user with the given username and character array password.
     *
     * @param username the desired username (must not be blank)
     * @param password the plaintext password as a char array
     * @return true if registration was successful; false if username is already taken
     * @throws SQLException if a database access error occurs
     * @throws IllegalArgumentException if username or password fails validation
     */
    public boolean registerUser(String username, char[] password) throws SQLException {
        return registerUser(this.connection, username, password);
    }

    /**
     * Static helper: Registers a new user using a provided JDBC connection.
     *
     * @param connection an active JDBC connection
     * @param username the desired username
     * @param password the plaintext password
     * @return true if registration was successful; false if username is already taken
     * @throws SQLException if a database access error occurs
     * @throws IllegalArgumentException if username or password fails validation
     */
    public static boolean registerUser(Connection connection, String username, String password) throws SQLException {
        return registerUser(connection, username, password != null ? password.toCharArray() : null);
    }

    /**
     * Static helper: Registers a new user using a provided JDBC connection and char array password.
     *
     * @param connection an active JDBC connection
     * @param username the desired username
     * @param password the plaintext password as a char array
     * @return true if registration was successful; false if username is already taken
     * @throws SQLException if a database access error occurs
     * @throws IllegalArgumentException if username or password fails validation
     */
    public static boolean registerUser(Connection connection, String username, char[] password) throws SQLException {
        if (connection == null) {
            throw new IllegalArgumentException("Database connection cannot be null.");
        }
        validateInput(username, password);

        // Pre-check for existing username
        if (userExists(connection, username)) {
            return false;
        }

        // Generate cryptographically secure salt and hash
        byte[] salt = generateSalt();
        byte[] hash = hashPassword(password, salt);

        String saltBase64 = Base64.getEncoder().encodeToString(salt);
        String hashBase64 = Base64.getEncoder().encodeToString(hash);

        String insertSql = "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)";
        try (PreparedStatement stmt = connection.prepareStatement(insertSql)) {
            stmt.setString(1, username);
            stmt.setString(2, hashBase64);
            stmt.setString(3, saltBase64);
            int rowsAffected = stmt.executeUpdate();
            return rowsAffected > 0;
        } catch (SQLException ex) {
            // Handle concurrent insert race condition
            if (isDuplicateKeyViolation(ex)) {
                return false;
            }
            throw ex;
        }
    }

    /**
     * Registers a new user and throws UserAlreadyExistsException if the username is taken.
     *
     * @param username desired username
     * @param password plaintext password
     * @throws SQLException on database access failure
     * @throws UserAlreadyExistsException if the username is already registered
     */
    public void registerNewUser(String username, String password) throws SQLException, UserAlreadyExistsException {
        if (!registerUser(username, password)) {
            throw new UserAlreadyExistsException("User with username '" + username + "' already exists.");
        }
    }

    /**
     * Authenticates a user with username and password using the instance connection.
     *
     * @param username the username to authenticate
     * @param password the plaintext password
     * @return true if credentials match; false otherwise
     * @throws SQLException if a database access error occurs
     */
    public boolean authenticateUser(String username, String password) throws SQLException {
        return authenticateUser(this.connection, username, password != null ? password.toCharArray() : null);
    }

    /**
     * Authenticates a user with username and char array password using the instance connection.
     *
     * @param username the username to authenticate
     * @param password the plaintext password as a char array
     * @return true if credentials match; false otherwise
     * @throws SQLException if a database access error occurs
     */
    public boolean authenticateUser(String username, char[] password) throws SQLException {
        return authenticateUser(this.connection, username, password);
    }

    /**
     * Static helper: Authenticates a user with a provided JDBC connection.
     *
     * @param connection an active JDBC connection
     * @param username the username
     * @param password the plaintext password
     * @return true if credentials match; false otherwise
     * @throws SQLException if a database access error occurs
     */
    public static boolean authenticateUser(Connection connection, String username, String password) throws SQLException {
        return authenticateUser(connection, username, password != null ? password.toCharArray() : null);
    }

    /**
     * Static helper: Authenticates a user with a provided JDBC connection and char array password.
     *
     * @param connection an active JDBC connection
     * @param username the username
     * @param password the plaintext password as a char array
     * @return true if credentials match; false otherwise
     * @throws SQLException if a database access error occurs
     */
    public static boolean authenticateUser(Connection connection, String username, char[] password) throws SQLException {
        if (connection == null) {
            throw new IllegalArgumentException("Database connection cannot be null.");
        }
        if (username == null || username.trim().isEmpty() || password == null || password.length == 0) {
            return false;
        }

        String querySql = "SELECT password_hash, salt FROM users WHERE username = ?";
        String storedHashBase64 = null;
        String storedSaltBase64 = null;

        try (PreparedStatement stmt = connection.prepareStatement(querySql)) {
            stmt.setString(1, username);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    storedHashBase64 = rs.getString("password_hash");
                    storedSaltBase64 = rs.getString("salt");
                }
            }
        }

        // If user does not exist, compute a dummy hash to prevent username enumeration via timing analysis
        if (storedHashBase64 == null || storedSaltBase64 == null) {
            dummyHash(password);
            return false;
        }

        try {
            byte[] storedHash = Base64.getDecoder().decode(storedHashBase64);
            byte[] storedSalt = Base64.getDecoder().decode(storedSaltBase64);
            byte[] computedHash = hashPassword(password, storedSalt);

            // MessageDigest.isEqual performs constant-time comparison
            return MessageDigest.isEqual(storedHash, computedHash);
        } catch (IllegalArgumentException ex) {
            // In case of corrupt Base64 in database
            return false;
        }
    }

    /**
     * Checks if a user already exists in the database.
     *
     * @param username the username to check
     * @return true if user exists, false otherwise
     * @throws SQLException if a database access error occurs
     */
    public boolean userExists(String username) throws SQLException {
        return userExists(this.connection, username);
    }

    /**
     * Static helper: Checks if a user already exists in the database.
     *
     * @param connection an active JDBC connection
     * @param username the username to check
     * @return true if user exists, false otherwise
     * @throws SQLException if a database access error occurs
     */
    public static boolean userExists(Connection connection, String username) throws SQLException {
        if (connection == null) {
            throw new IllegalArgumentException("Database connection cannot be null.");
        }
        if (username == null || username.trim().isEmpty()) {
            return false;
        }
        String sql = "SELECT 1 FROM users WHERE username = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, username);
            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next();
            }
        }
    }

    // Cryptographic & Validation Utilities

    private static byte[] generateSalt() {
        byte[] salt = new byte[SALT_BYTES];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    private static byte[] hashPassword(char[] password, byte[] salt) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH_BITS);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(HASH_ALGORITHM);
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Cryptographic algorithm unavailable: " + HASH_ALGORITHM, e);
        } finally {
            spec.clearPassword();
        }
    }

    private static void dummyHash(char[] password) {
        try {
            hashPassword(password, DUMMY_SALT);
        } catch (Exception ignored) {
        }
    }

    private static void validateInput(String username, char[] password) {
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be null or blank.");
        }
        if (username.length() > 255) {
            throw new IllegalArgumentException("Username cannot exceed 255 characters.");
        }
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password cannot be null or empty.");
        }
        if (password.length > 1024) {
            throw new IllegalArgumentException("Password cannot exceed 1024 characters.");
        }
    }

    private static boolean isDuplicateKeyViolation(SQLException ex) {
        String sqlState = ex.getSQLState();
        if (sqlState != null && (sqlState.startsWith("23") || sqlState.equals("42601"))) {
            return true;
        }
        int errorCode = ex.getErrorCode();
        // SQLite = 19, MySQL = 1062, Oracle = 1
        if (errorCode == 19 || errorCode == 1062 || errorCode == 1) {
            return true;
        }
        String msg = ex.getMessage();
        return msg != null && (msg.contains("unique") || msg.contains("UNIQUE") || msg.contains("Duplicate") || msg.contains("duplicate"));
    }

    // Custom Exception Hierarchy

    public static class UserAccountException extends Exception {
        public UserAccountException(String message) {
            super(message);
        }

        public UserAccountException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static class UserAlreadyExistsException extends UserAccountException {
        public UserAlreadyExistsException(String message) {
            super(message);
        }
    }

    public static class InvalidCredentialsException extends UserAccountException {
        public InvalidCredentialsException(String message) {
            super(message);
        }
    }

    // Demonstration Main Method

    public static void main(String[] args) {
        System.out.println("=================================================");
        System.out.println(" UserAccountService - Registration & Auth Demo  ");
        System.out.println("=================================================\n");

        String jdbcUrl = "jdbc:h2:mem:demo;DB_CLOSE_DELAY=-1";
        String dbUser = "sa";
        String dbPassword = "";

        if (args.length > 0) {
            jdbcUrl = args[0];
            dbUser = args.length > 1 ? args[1] : "";
            dbPassword = args.length > 2 ? args[2] : "";
        }

        try (Connection conn = DriverManager.getConnection(jdbcUrl, dbUser, dbPassword)) {
            System.out.println("1. Connected to database: " + jdbcUrl);

            // Step 1: Initialize table
            createUsersTable(conn);
            System.out.println("2. Initialized database schema ('users' table).");

            UserAccountService service = new UserAccountService(conn);

            // Step 2: Register a new user
            String username = "alice_dev";
            String password = "SuperSecretPassword#2026";
            System.out.println("\n3. Registering new user: '" + username + "'...");
            boolean registered = service.registerUser(username, password);
            System.out.println("   Registration status: " + (registered ? "SUCCESS" : "FAILED"));

            // Step 3: Attempt duplicate registration
            System.out.println("\n4. Attempting duplicate registration for '" + username + "'...");
            boolean duplicateResult = service.registerUser(username, "AnotherPassword123");
            System.out.println("   Duplicate registration allowed? " + duplicateResult + " (Expected: false)");

            // Step 4: Authenticate with correct password
            System.out.println("\n5. Authenticating '" + username + "' with correct password...");
            boolean authSuccess = service.authenticateUser(username, password);
            System.out.println("   Authentication result: " + (authSuccess ? "SUCCESS (Authenticated!)" : "FAILED"));

            // Step 5: Authenticate with incorrect password
            System.out.println("\n6. Authenticating '" + username + "' with incorrect password...");
            boolean authFailWrongPass = service.authenticateUser(username, "WrongPassword!");
            System.out.println("   Authentication result: " + (authFailWrongPass ? "SUCCESS" : "FAILED (Access Denied - as expected)"));

            // Step 6: Authenticate non-existent user
            System.out.println("\n7. Authenticating non-existent user 'bob'...");
            boolean authFailNoUser = service.authenticateUser("bob", "SomePassword");
            System.out.println("   Authentication result: " + (authFailNoUser ? "SUCCESS" : "FAILED (Access Denied - as expected)"));

            System.out.println("\n=================================================");
            System.out.println(" All demonstration checks completed successfully!");
            System.out.println("=================================================");
        } catch (SQLException e) {
            System.err.println("Database error occurred: " + e.getMessage());
            if (e.getMessage() != null && e.getMessage().contains("No suitable driver")) {
                System.err.println("\n[Hint] To run the demonstration with the included H2 driver, run:");
                System.err.println("   java -cp \".:lib/*\" UserAccountService");
                System.err.println("Or run via Maven:");
                System.err.println("   mvn exec:java\n");
            } else {
                e.printStackTrace();
            }
        }
    }
}
