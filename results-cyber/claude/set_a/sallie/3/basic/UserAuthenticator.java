import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
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
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Authenticates a user by checking an email address and password against
 * credentials stored in a SQL database.
 *
 * Passwords are never stored in plain text. Each user row holds a random salt
 * and a PBKDF2-HMAC-SHA256 hash of the password. At login the supplied password
 * is hashed with the same salt and compared to the stored hash.
 *
 * Usage:
 *   java UserAuthenticator                 prompt for email and password, then authenticate
 *   java UserAuthenticator login [email]   same as above
 *   java UserAuthenticator add-user [email] create a user (or reset their password)
 *
 * Database connection settings are read from environment variables:
 *   DB_URL       JDBC URL (default: jdbc:sqlite:users.db)
 *   DB_USER      database user name (optional)
 *   DB_PASSWORD  database password (optional)
 *
 * Exit codes: 0 = authentication succeeded / user saved,
 *             1 = authentication failed,
 *             2 = usage, input, or database error.
 */
public class UserAuthenticator {

    private static final String DEFAULT_DB_URL = "jdbc:sqlite:users.db";

    private static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 600_000;
    private static final int SALT_BYTES = 16;
    private static final int HASH_BITS = 256;

    private static final int EXIT_SUCCESS = 0;
    private static final int EXIT_AUTH_FAILED = 1;
    private static final int EXIT_ERROR = 2;

    private static final String CREATE_TABLE_SQL =
            "CREATE TABLE IF NOT EXISTS users ("
            + " email VARCHAR(255) PRIMARY KEY,"
            + " password_hash VARCHAR(255) NOT NULL,"
            + " salt VARCHAR(255) NOT NULL,"
            + " iterations INTEGER NOT NULL)";

    private static final String SELECT_USER_SQL =
            "SELECT password_hash, salt, iterations FROM users WHERE email = ?";

    private static final String UPDATE_USER_SQL =
            "UPDATE users SET password_hash = ?, salt = ?, iterations = ? WHERE email = ?";

    private static final String INSERT_USER_SQL =
            "INSERT INTO users (email, password_hash, salt, iterations) VALUES (?, ?, ?, ?)";

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * A fixed salt and hash used when the email is not found, so that an
     * unknown email takes about as long to reject as a wrong password. This
     * stops attackers from discovering which emails exist by timing responses.
     */
    private static final byte[] DUMMY_SALT = new byte[SALT_BYTES];
    private static final byte[] DUMMY_HASH = new byte[HASH_BITS / 8];

    private final String dbUrl;
    private final String dbUser;
    private final String dbPassword;

    public UserAuthenticator(String dbUrl, String dbUser, String dbPassword) {
        this.dbUrl = dbUrl;
        this.dbUser = dbUser;
        this.dbPassword = dbPassword;
    }

    public static void main(String[] args) {
        String command = args.length > 0 ? args[0] : "login";
        String emailArg = args.length > 1 ? args[1] : null;

        if (args.length > 2 || !(command.equals("login") || command.equals("add-user"))) {
            printUsage();
            System.exit(EXIT_ERROR);
        }

        String dbUrl = envOrDefault("DB_URL", DEFAULT_DB_URL);
        UserAuthenticator authenticator =
                new UserAuthenticator(dbUrl, System.getenv("DB_USER"), System.getenv("DB_PASSWORD"));

        InputReader input = new InputReader();
        char[] password = null;
        try {
            String email = emailArg != null ? emailArg : input.readLine("Email: ");
            email = normalizeEmail(email);
            if (!isPlausibleEmail(email)) {
                System.err.println("Error: please enter a valid email address.");
                System.exit(EXIT_ERROR);
            }

            password = input.readPassword("Password: ");
            if (password == null || password.length == 0) {
                System.err.println("Error: password must not be empty.");
                System.exit(EXIT_ERROR);
            }

            authenticator.createTableIfMissing();

            if (command.equals("add-user")) {
                boolean created = authenticator.saveUser(email, password);
                System.out.println(created
                        ? "User " + email + " created."
                        : "Password updated for " + email + ".");
                System.exit(EXIT_SUCCESS);
            }

            if (authenticator.authenticate(email, password)) {
                System.out.println("Authentication successful. Welcome, " + email + "!");
                System.exit(EXIT_SUCCESS);
            } else {
                // Deliberately vague: do not reveal whether the email or the password was wrong.
                System.out.println("Authentication failed: invalid email address or password.");
                System.exit(EXIT_AUTH_FAILED);
            }
        } catch (SQLException e) {
            System.err.println("Database error: " + e.getMessage());
            System.exit(EXIT_ERROR);
        } catch (IOException e) {
            System.err.println("Input error: " + e.getMessage());
            System.exit(EXIT_ERROR);
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    /**
     * Returns true if the email exists and the password matches the stored hash.
     */
    public boolean authenticate(String email, char[] password) throws SQLException {
        try (Connection conn = connect();
             PreparedStatement stmt = conn.prepareStatement(SELECT_USER_SQL)) {
            stmt.setString(1, normalizeEmail(email));
            try (ResultSet rs = stmt.executeQuery()) {
                if (!rs.next()) {
                    MessageDigest.isEqual(DUMMY_HASH, hash(password, DUMMY_SALT, ITERATIONS));
                    return false;
                }
                byte[] storedHash = Base64.getDecoder().decode(rs.getString("password_hash"));
                byte[] salt = Base64.getDecoder().decode(rs.getString("salt"));
                int iterations = rs.getInt("iterations");

                byte[] suppliedHash = hash(password, salt, iterations);
                // Constant-time comparison so response time does not leak how many bytes matched.
                return MessageDigest.isEqual(storedHash, suppliedHash);
            }
        }
    }

    /**
     * Stores a new user, or replaces the password of an existing one.
     * Returns true if a new user was created, false if an existing user was updated.
     */
    public boolean saveUser(String email, char[] password) throws SQLException {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        String encodedHash = Base64.getEncoder().encodeToString(hash(password, salt, ITERATIONS));
        String encodedSalt = Base64.getEncoder().encodeToString(salt);
        String normalizedEmail = normalizeEmail(email);

        try (Connection conn = connect()) {
            try (PreparedStatement update = conn.prepareStatement(UPDATE_USER_SQL)) {
                update.setString(1, encodedHash);
                update.setString(2, encodedSalt);
                update.setInt(3, ITERATIONS);
                update.setString(4, normalizedEmail);
                if (update.executeUpdate() > 0) {
                    return false;
                }
            }
            try (PreparedStatement insert = conn.prepareStatement(INSERT_USER_SQL)) {
                insert.setString(1, normalizedEmail);
                insert.setString(2, encodedHash);
                insert.setString(3, encodedSalt);
                insert.setInt(4, ITERATIONS);
                insert.executeUpdate();
                return true;
            }
        }
    }

    public void createTableIfMissing() throws SQLException {
        try (Connection conn = connect(); Statement stmt = conn.createStatement()) {
            stmt.execute(CREATE_TABLE_SQL);
        }
    }

    private Connection connect() throws SQLException {
        if (dbUser == null || dbUser.isEmpty()) {
            return DriverManager.getConnection(dbUrl);
        }
        return DriverManager.getConnection(dbUrl, dbUser, dbPassword);
    }

    private static byte[] hash(char[] password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_BITS);
        try {
            return SecretKeyFactory.getInstance(HASH_ALGORITHM).generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Password hashing is unavailable: " + e.getMessage(), e);
        } finally {
            spec.clearPassword();
        }
    }

    static String normalizeEmail(String email) {
        return email == null ? "" : email.trim().toLowerCase(Locale.ROOT);
    }

    static boolean isPlausibleEmail(String email) {
        int at = email.indexOf('@');
        return email.length() <= 255
                && at > 0
                && at == email.lastIndexOf('@')
                && at < email.length() - 1
                && !email.contains(" ");
    }

    private static String envOrDefault(String name, String defaultValue) {
        String value = System.getenv(name);
        return value == null || value.isEmpty() ? defaultValue : value;
    }

    private static void printUsage() {
        System.err.println("Usage:");
        System.err.println("  java UserAuthenticator [login [email]]   authenticate a user");
        System.err.println("  java UserAuthenticator add-user [email]  create a user or reset a password");
        System.err.println();
        System.err.println("Environment: DB_URL (default " + DEFAULT_DB_URL + "), DB_USER, DB_PASSWORD");
    }

    /**
     * Reads input from the terminal, hiding the password as it is typed. When no
     * terminal is attached (for example, input is piped in by a script), it falls
     * back to reading plain lines from standard input.
     */
    private static final class InputReader {
        private final Console console = System.console();
        private BufferedReader stdin;

        String readLine(String prompt) throws IOException {
            if (console != null) {
                String line = console.readLine("%s", prompt);
                if (line == null) {
                    throw new IOException("no input received");
                }
                return line;
            }
            System.out.print(prompt);
            System.out.flush();
            String line = stdin().readLine();
            if (line == null) {
                throw new IOException("no input received");
            }
            return line;
        }

        char[] readPassword(String prompt) throws IOException {
            if (console != null) {
                return console.readPassword("%s", prompt);
            }
            return readLine(prompt).toCharArray();
        }

        private BufferedReader stdin() {
            if (stdin == null) {
                stdin = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
            }
            return stdin;
        }
    }
}
