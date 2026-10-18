import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
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
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Registers user accounts in an SQL database and authenticates them later.
 *
 * <p>Passwords are never stored. Each password is hashed with PBKDF2-HMAC-SHA256
 * using a random per-user salt and a high iteration count, and only the encoded
 * hash is written to the database. All SQL uses {@link PreparedStatement}s, so
 * user input cannot alter the queries.
 *
 * <p>The class works on an existing, already-open JDBC {@link Connection}. It does
 * not close the connection and does not change its auto-commit or transaction
 * settings; the caller owns the connection's lifecycle.
 */
public class UserRegistration {

    /** Table used to store accounts. Change here if your schema differs. */
    public static final String TABLE_NAME = "users";

    /**
     * Portable DDL (H2, PostgreSQL, MySQL/MariaDB, SQLite). For SQL Server, create the
     * table manually without "IF NOT EXISTS" and use DATETIME2 instead of TIMESTAMP.
     */
    public static final String CREATE_TABLE_SQL =
            "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " ("
                    + "username VARCHAR(50) NOT NULL PRIMARY KEY, "
                    + "password_hash VARCHAR(255) NOT NULL, "
                    + "created_at TIMESTAMP NOT NULL)";

    private static final String INSERT_SQL =
            "INSERT INTO " + TABLE_NAME + " (username, password_hash, created_at) VALUES (?, ?, ?)";

    private static final String SELECT_HASH_SQL =
            "SELECT password_hash FROM " + TABLE_NAME + " WHERE username = ?";

    // Username: 3-50 chars, letters, digits, dot, underscore, hyphen.
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-z0-9._-]{3,50}$");
    private static final int MIN_PASSWORD_LENGTH = 8;
    private static final int MAX_PASSWORD_LENGTH = 128;

    // PBKDF2 parameters (OWASP recommendation for PBKDF2-HMAC-SHA256).
    private static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String HASH_ID = "pbkdf2-sha256";
    private static final int ITERATIONS = 600_000;
    private static final int SALT_BYTES = 16;
    private static final int HASH_BITS = 256;

    private static final SecureRandom RANDOM = new SecureRandom();

    private final Connection connection;

    /** Random decoy hash, used to equalize timing when a username does not exist. */
    private static final String DUMMY_HASH = createDummyHash();

    public UserRegistration(Connection connection) {
        this.connection = Objects.requireNonNull(connection, "connection");
    }

    /** Creates the users table if it does not already exist. */
    public void createTableIfNotExists() throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.executeUpdate(CREATE_TABLE_SQL);
        }
    }

    /**
     * Registers a new user account.
     *
     * <p>The caller should wipe the {@code password} array (e.g. {@code Arrays.fill(password, '\0')})
     * once it is no longer needed.
     *
     * @param username desired username (case-insensitive; stored in lower case)
     * @param password the plaintext password
     * @throws IllegalArgumentException if the username or password fails validation
     * @throws UsernameTakenException   if the username is already registered
     * @throws SQLException             on any other database error
     */
    public void register(String username, char[] password) throws SQLException {
        String normalized = normalizeUsername(username);
        validatePassword(password);

        String passwordHash = hashPassword(password);

        try (PreparedStatement ps = connection.prepareStatement(INSERT_SQL)) {
            ps.setString(1, normalized);
            ps.setString(2, passwordHash);
            ps.setTimestamp(3, Timestamp.from(Instant.now()));
            ps.executeUpdate();
        } catch (SQLException e) {
            // SQLState class "23" = integrity constraint violation (duplicate primary key).
            // Relying on the constraint avoids a check-then-insert race condition.
            if (isUniqueViolation(e)) {
                throw new UsernameTakenException(normalized, e);
            }
            throw e;
        }
    }

    /**
     * Checks a username/password pair against the stored credentials.
     *
     * @return {@code true} if the account exists and the password matches
     */
    public boolean authenticate(String username, char[] password) throws SQLException {
        if (username == null || password == null) {
            return false;
        }
        String normalized = username.trim().toLowerCase(Locale.ROOT);

        String storedHash = null;
        try (PreparedStatement ps = connection.prepareStatement(SELECT_HASH_SQL)) {
            ps.setString(1, normalized);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    storedHash = rs.getString(1);
                }
            }
        }

        if (storedHash == null) {
            // Do the same amount of work as a real check so response time does not
            // reveal whether the username exists.
            verifyPassword(password, DUMMY_HASH);
            return false;
        }
        return verifyPassword(password, storedHash);
    }

    // ------------------------------------------------------------------
    // Validation
    // ------------------------------------------------------------------

    private static String normalizeUsername(String username) {
        if (username == null) {
            throw new IllegalArgumentException("Username is required.");
        }
        String normalized = username.trim().toLowerCase(Locale.ROOT);
        if (!USERNAME_PATTERN.matcher(normalized).matches()) {
            throw new IllegalArgumentException(
                    "Username must be 3-50 characters and contain only letters, digits, '.', '_' or '-'.");
        }
        return normalized;
    }

    private static void validatePassword(char[] password) {
        if (password == null || password.length < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be at least " + MIN_PASSWORD_LENGTH + " characters.");
        }
        if (password.length > MAX_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be at most " + MAX_PASSWORD_LENGTH + " characters.");
        }
    }

    private static boolean isUniqueViolation(SQLException e) {
        for (SQLException cur = e; cur != null; cur = cur.getNextException()) {
            String state = cur.getSQLState();
            if (state != null && state.startsWith("23")) {
                return true;
            }
        }
        // SQLite's driver does not always populate SQLState.
        String msg = e.getMessage();
        return msg != null && msg.toUpperCase(Locale.ROOT).contains("UNIQUE");
    }

    // ------------------------------------------------------------------
    // Password hashing
    // ------------------------------------------------------------------

    /** Produces "pbkdf2-sha256$iterations$base64(salt)$base64(hash)". */
    static String hashPassword(char[] password) {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] hash = pbkdf2(password, salt, ITERATIONS, HASH_BITS);
        Base64.Encoder b64 = Base64.getEncoder().withoutPadding();
        return HASH_ID + "$" + ITERATIONS + "$" + b64.encodeToString(salt) + "$" + b64.encodeToString(hash);
    }

    /** Verifies a password against an encoded hash using a constant-time comparison. */
    static boolean verifyPassword(char[] password, String encodedHash) {
        String[] parts = encodedHash.split("\\$");
        if (parts.length != 4 || !HASH_ID.equals(parts[0])) {
            return false;
        }
        try {
            int iterations = Integer.parseInt(parts[1]);
            byte[] salt = Base64.getDecoder().decode(parts[2]);
            byte[] expected = Base64.getDecoder().decode(parts[3]);
            if (iterations <= 0 || salt.length == 0 || expected.length == 0) {
                return false;
            }
            byte[] actual = pbkdf2(password, salt, iterations, expected.length * 8);
            return MessageDigest.isEqual(expected, actual);
        } catch (IllegalArgumentException e) {
            return false; // malformed stored value
        }
    }

    private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int keyBits) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyBits);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(HASH_ALGORITHM);
            return factory.generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(HASH_ALGORITHM + " is not available", e);
        } finally {
            spec.clearPassword();
        }
    }

    /**
     * Builds a well-formed hash string from random bytes. Verifying against it costs
     * exactly one PBKDF2 run (same as a real account) but can never succeed in practice,
     * and building it costs nothing, so even the first lookup of a missing user is not slower.
     */
    private static String createDummyHash() {
        byte[] salt = new byte[SALT_BYTES];
        byte[] hash = new byte[HASH_BITS / 8];
        RANDOM.nextBytes(salt);
        RANDOM.nextBytes(hash);
        Base64.Encoder b64 = Base64.getEncoder().withoutPadding();
        return HASH_ID + "$" + ITERATIONS + "$" + b64.encodeToString(salt) + "$" + b64.encodeToString(hash);
    }

    // ------------------------------------------------------------------
    // Exceptions
    // ------------------------------------------------------------------

    /** Thrown when attempting to register a username that already exists. */
    public static class UsernameTakenException extends SQLException {
        private static final long serialVersionUID = 1L;

        public UsernameTakenException(String username, Throwable cause) {
            super("Username already exists: " + username, "23000", cause);
        }
    }

    // ------------------------------------------------------------------
    // Demo entry point
    // ------------------------------------------------------------------

    /**
     * Demo: registers a user and then authenticates them.
     *
     * <pre>
     * java -cp .:driver.jar UserRegistration &lt;jdbc-url&gt; &lt;username&gt; [dbUser] [dbPassword]
     * </pre>
     *
     * The account password is read from the console (hidden) or, if no console is
     * attached, as a single line from standard input.
     */
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: java UserRegistration <jdbc-url> <username> [dbUser] [dbPassword]");
            System.exit(2);
        }
        String url = args[0];
        String username = args[1];
        String dbUser = args.length > 2 ? args[2] : null;
        String dbPassword = args.length > 3 ? args[3] : null;

        // In a real application this Connection would be supplied by the caller / pool.
        try (Connection conn = DriverManager.getConnection(url, dbUser, dbPassword)) {
            UserRegistration service = new UserRegistration(conn);
            service.createTableIfNotExists();

            char[] password = readPassword("Password for new user '" + username + "': ");
            try {
                service.register(username, password);
                System.out.println("Registered user '" + username.trim().toLowerCase(Locale.ROOT) + "'.");
            } catch (UsernameTakenException e) {
                System.out.println(e.getMessage() + " (continuing to authentication check)");
            } catch (IllegalArgumentException e) {
                System.err.println("Registration rejected: " + e.getMessage());
                System.exit(1);
            }

            boolean ok = service.authenticate(username, password);
            System.out.println("Authenticate with entered password: " + (ok ? "SUCCESS" : "FAILURE"));

            char[] wrong = "definitely-not-the-password".toCharArray();
            boolean bad = service.authenticate(username, wrong);
            System.out.println("Authenticate with wrong password:   " + (bad ? "SUCCESS" : "FAILURE"));

            Arrays.fill(password, '\0');
            Arrays.fill(wrong, '\0');
        }
    }

    private static char[] readPassword(String prompt) throws IOException {
        Console console = System.console();
        if (console != null) {
            char[] pw = console.readPassword("%s", prompt);
            return pw != null ? pw : new char[0];
        }
        System.out.print(prompt);
        System.out.flush();
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line = in.readLine();
        return line != null ? line.toCharArray() : new char[0];
    }
}
