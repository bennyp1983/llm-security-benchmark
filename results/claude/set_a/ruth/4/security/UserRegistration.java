import java.io.Console;
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
import java.sql.SQLIntegrityConstraintViolationException;
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
 * <p>Password handling:
 * <ul>
 *   <li>Plaintext passwords are never stored, logged, or put in a {@code String}.
 *       They are accepted as {@code char[]} and wiped from memory after use.</li>
 *   <li>Each password is hashed with PBKDF2-HMAC-SHA256, 600,000 iterations
 *       (OWASP recommendation), and a unique 16-byte random salt from
 *       {@link SecureRandom}.</li>
 *   <li>The stored value is self-describing
 *       ({@code pbkdf2-sha256$iterations$salt$hash}), so the work factor can be
 *       raised later; old hashes are transparently upgraded on successful login.</li>
 *   <li>Hash comparison is constant-time, and logins for unknown usernames
 *       still perform a full hash computation to limit user enumeration via timing.</li>
 *   <li>All SQL uses {@link PreparedStatement} parameters (no SQL injection).</li>
 * </ul>
 *
 * <p>Uses only the JDK standard library; any JDBC driver can supply the {@link Connection}.
 */
public final class UserRegistration {

    /** Thrown when a registration request is rejected (invalid input or duplicate user). */
    public static final class RegistrationException extends Exception {
        private static final long serialVersionUID = 1L;

        public RegistrationException(String message) {
            super(message);
        }
    }

    // ------------------------------------------------------------------
    // Configuration
    // ------------------------------------------------------------------

    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-z0-9._-]{3,64}$");
    private static final int MIN_PASSWORD_LENGTH = 12;
    // Upper bound prevents denial of service via extremely long inputs.
    private static final int MAX_PASSWORD_LENGTH = 256;

    private static final String CREATE_TABLE_SQL =
            "CREATE TABLE IF NOT EXISTS users ("
            + " username      VARCHAR(64)  NOT NULL PRIMARY KEY,"
            + " password_hash VARCHAR(255) NOT NULL,"
            + " created_at    TIMESTAMP    NOT NULL"
            + ")";
    private static final String INSERT_USER_SQL =
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)";
    private static final String SELECT_HASH_SQL =
            "SELECT password_hash FROM users WHERE username = ?";
    private static final String UPDATE_HASH_SQL =
            "UPDATE users SET password_hash = ? WHERE username = ?";

    private final Connection connection;

    /**
     * @param connection an open JDBC connection; this class does not close it
     *                   and does not change its auto-commit/transaction settings
     */
    public UserRegistration(Connection connection) {
        this.connection = Objects.requireNonNull(connection, "connection");
    }

    /** Creates the {@code users} table if it does not already exist. */
    public void createSchema() throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(CREATE_TABLE_SQL);
        }
    }

    /**
     * Registers a new user. The password array is always wiped before this method returns.
     *
     * @throws RegistrationException if the username/password is invalid or the username is taken
     * @throws SQLException          on any other database error
     */
    public void register(String username, char[] password) throws RegistrationException, SQLException {
        try {
            String normalized = normalizeUsername(username);
            if (!USERNAME_PATTERN.matcher(normalized).matches()) {
                throw new RegistrationException(
                        "Username must be 3-64 characters: letters, digits, '.', '_' or '-'.");
            }
            validatePassword(password);

            String encodedHash = PasswordHasher.hash(password);

            try (PreparedStatement ps = connection.prepareStatement(INSERT_USER_SQL)) {
                ps.setString(1, normalized);
                ps.setString(2, encodedHash);
                ps.setTimestamp(3, Timestamp.from(Instant.now()));
                ps.executeUpdate();
            } catch (SQLException e) {
                if (isUniqueViolation(e)) {
                    throw new RegistrationException("Username is already taken.");
                }
                throw e;
            }
        } finally {
            wipe(password);
        }
    }

    /**
     * Checks a username/password pair against the stored hash.
     * The password array is always wiped before this method returns.
     *
     * @return {@code true} only if the user exists and the password matches
     */
    public boolean authenticate(String username, char[] password) throws SQLException {
        try {
            if (username == null || password == null || password.length > MAX_PASSWORD_LENGTH) {
                return false;
            }
            String normalized = normalizeUsername(username);

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
                // Unknown user: do equivalent work so response time does not reveal it.
                PasswordHasher.verify(password, PasswordHasher.DUMMY_HASH);
                return false;
            }

            if (!PasswordHasher.verify(password, storedHash)) {
                return false;
            }

            if (PasswordHasher.needsRehash(storedHash)) {
                try (PreparedStatement ps = connection.prepareStatement(UPDATE_HASH_SQL)) {
                    ps.setString(1, PasswordHasher.hash(password));
                    ps.setString(2, normalized);
                    ps.executeUpdate();
                }
            }
            return true;
        } finally {
            wipe(password);
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static String normalizeUsername(String username) {
        return username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
    }

    private static void validatePassword(char[] password) throws RegistrationException {
        if (password == null || password.length < MIN_PASSWORD_LENGTH) {
            throw new RegistrationException(
                    "Password must be at least " + MIN_PASSWORD_LENGTH + " characters long.");
        }
        if (password.length > MAX_PASSWORD_LENGTH) {
            throw new RegistrationException(
                    "Password must be at most " + MAX_PASSWORD_LENGTH + " characters long.");
        }
    }

    private static boolean isUniqueViolation(SQLException e) {
        for (SQLException cur = e; cur != null; cur = cur.getNextException()) {
            if (cur instanceof SQLIntegrityConstraintViolationException) {
                return true;
            }
            String state = cur.getSQLState();
            if (state != null && state.startsWith("23")) { // SQL standard: integrity constraint violation
                return true;
            }
            // Some drivers (e.g. sqlite-jdbc) do not set SQLState; fall back to the message.
            String msg = cur.getMessage();
            if (msg != null && msg.toUpperCase(Locale.ROOT).contains("UNIQUE")) {
                return true;
            }
        }
        return false;
    }

    private static void wipe(char[] data) {
        if (data != null) {
            Arrays.fill(data, '\0');
        }
    }

    // ------------------------------------------------------------------
    // Password hashing (PBKDF2-HMAC-SHA256, JDK built-in)
    // ------------------------------------------------------------------

    static final class PasswordHasher {
        private static final String ALGORITHM_ID = "pbkdf2-sha256";
        private static final String JCA_ALGORITHM = "PBKDF2WithHmacSHA256";
        private static final int ITERATIONS = 600_000;
        private static final int SALT_BYTES = 16;
        private static final int HASH_BITS = 256;
        // Sanity bounds when parsing stored hashes.
        private static final int MIN_ITERATIONS = 10_000;
        private static final int MAX_ITERATIONS = 10_000_000;

        private static final SecureRandom RANDOM = new SecureRandom();
        private static final Base64.Encoder B64_ENC = Base64.getEncoder().withoutPadding();
        private static final Base64.Decoder B64_DEC = Base64.getDecoder();

        /** Valid-format hash of a random value; used to equalize timing for unknown users. */
        static final String DUMMY_HASH;

        static {
            byte[] randomBytes = new byte[24];
            RANDOM.nextBytes(randomBytes);
            char[] random = B64_ENC.encodeToString(randomBytes).toCharArray();
            DUMMY_HASH = hash(random);
            wipe(random);
        }

        private PasswordHasher() {
        }

        /** Returns {@code pbkdf2-sha256$<iterations>$<base64 salt>$<base64 hash>}. */
        static String hash(char[] password) {
            byte[] salt = new byte[SALT_BYTES];
            RANDOM.nextBytes(salt);
            byte[] derived = pbkdf2(password, salt, ITERATIONS, HASH_BITS);
            try {
                return ALGORITHM_ID + "$" + ITERATIONS + "$"
                        + B64_ENC.encodeToString(salt) + "$" + B64_ENC.encodeToString(derived);
            } finally {
                Arrays.fill(derived, (byte) 0);
            }
        }

        /** Constant-time verification of a password against an encoded hash. */
        static boolean verify(char[] password, String encoded) {
            ParsedHash parsed = ParsedHash.parse(encoded);
            if (parsed == null) {
                return false;
            }
            byte[] candidate = pbkdf2(password, parsed.salt, parsed.iterations, parsed.hash.length * 8);
            try {
                return MessageDigest.isEqual(candidate, parsed.hash);
            } finally {
                Arrays.fill(candidate, (byte) 0);
            }
        }

        /** True if the stored hash uses weaker parameters than the current configuration. */
        static boolean needsRehash(String encoded) {
            ParsedHash parsed = ParsedHash.parse(encoded);
            return parsed == null
                    || parsed.iterations < ITERATIONS
                    || parsed.salt.length < SALT_BYTES
                    || parsed.hash.length * 8 < HASH_BITS;
        }

        private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int keyBits) {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyBits);
            try {
                return SecretKeyFactory.getInstance(JCA_ALGORITHM).generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IllegalStateException("PBKDF2 is unavailable", e);
            } finally {
                spec.clearPassword();
            }
        }

        private static final class ParsedHash {
            final int iterations;
            final byte[] salt;
            final byte[] hash;

            private ParsedHash(int iterations, byte[] salt, byte[] hash) {
                this.iterations = iterations;
                this.salt = salt;
                this.hash = hash;
            }

            static ParsedHash parse(String encoded) {
                if (encoded == null) {
                    return null;
                }
                String[] parts = encoded.split("\\$");
                if (parts.length != 4 || !ALGORITHM_ID.equals(parts[0])) {
                    return null;
                }
                try {
                    int iterations = Integer.parseInt(parts[1]);
                    byte[] salt = B64_DEC.decode(parts[2]);
                    byte[] hash = B64_DEC.decode(parts[3]);
                    if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS
                            || salt.length == 0 || hash.length == 0) {
                        return null;
                    }
                    return new ParsedHash(iterations, salt, hash);
                } catch (IllegalArgumentException e) {
                    return null;
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Demo entry point
    // ------------------------------------------------------------------

    /**
     * Usage: {@code java -cp .:<driver.jar> UserRegistration <jdbc-url> [db-user] [db-password]}
     *
     * <p>With an interactive console, prompts for a username and password (input not echoed).
     * Without one, runs a scripted demo using sample credentials.
     */
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: java -cp .:<jdbc-driver.jar> UserRegistration <jdbc-url> [db-user] [db-password]");
            System.exit(2);
        }
        String url = args[0];
        String dbUser = args.length > 1 ? args[1] : null;
        String dbPass = args.length > 2 ? args[2] : null;

        try (Connection conn = DriverManager.getConnection(url, dbUser, dbPass)) {
            UserRegistration users = new UserRegistration(conn);
            users.createSchema();

            Console console = System.console();
            if (console != null) {
                runInteractive(console, users);
            } else {
                runScripted(users);
            }
        }
    }

    private static void runInteractive(Console console, UserRegistration users) throws SQLException {
        String username = console.readLine("New username: ");
        char[] password = console.readPassword("New password: ");
        char[] confirm = console.readPassword("Confirm password: ");
        try {
            if (password == null || confirm == null || !Arrays.equals(password, confirm)) {
                console.printf("Passwords do not match.%n");
                return;
            }
            users.register(username, password);
            console.printf("User registered.%n");
        } catch (RegistrationException e) {
            console.printf("Registration failed: %s%n", e.getMessage());
            return;
        } finally {
            wipe(password);
            wipe(confirm);
        }

        String loginUser = console.readLine("Log in - username: ");
        char[] loginPass = console.readPassword("Log in - password: ");
        console.printf(users.authenticate(loginUser, loginPass)
                ? "Authentication succeeded.%n" : "Invalid username or password.%n");
    }

    private static void runScripted(UserRegistration users) throws SQLException {
        System.out.println("No console detected; running scripted demo with sample credentials.");
        // Sample values for demonstration only. Real code must obtain passwords from the user.
        String user = "alice";
        String pw = "correct horse battery staple";

        tryRegister(users, user, pw.toCharArray());
        tryRegister(users, user, "another long password".toCharArray()); // duplicate
        tryRegister(users, "bob", "short".toCharArray());                  // weak password
        tryRegister(users, "x'; DROP TABLE users; --", "irrelevant-password".toCharArray()); // rejected username

        System.out.println("login alice / correct password -> " + users.authenticate(user, pw.toCharArray()));
        System.out.println("login ALICE / correct password -> " + users.authenticate("ALICE", pw.toCharArray()));
        System.out.println("login alice / wrong password   -> " + users.authenticate(user, "wrong password!!".toCharArray()));
        System.out.println("login nobody                   -> " + users.authenticate("nobody", pw.toCharArray()));

        try (PreparedStatement ps = users.connection.prepareStatement(SELECT_HASH_SQL)) {
            ps.setString(1, user);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    System.out.println("stored value for alice: " + rs.getString(1));
                }
            }
        }
    }

    private static void tryRegister(UserRegistration users, String username, char[] password) throws SQLException {
        try {
            users.register(username, password);
            System.out.println("register '" + username + "' -> OK");
        } catch (RegistrationException e) {
            System.out.println("register '" + username + "' -> rejected: " + e.getMessage());
        }
    }
}
