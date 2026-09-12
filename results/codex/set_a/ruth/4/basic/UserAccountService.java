import java.io.Console;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Registers and authenticates local user accounts using an existing JDBC
 * connection. Passwords are stored as salted PBKDF2 hashes, never as plaintext.
 *
 * <p>The supplied connection remains owned by the caller and is never closed by
 * this class.</p>
 */
public final class UserAccountService {
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 210_000;
    private static final int SALT_BYTES = 16;
    private static final int HASH_BYTES = 32;
    private static final int MAX_USERNAME_LENGTH = 255;
    private static final int MAX_PASSWORD_LENGTH = 1024;
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String CREATE_TABLE_SQL =
            "CREATE TABLE IF NOT EXISTS user_account ("
                    + "username VARCHAR(255) PRIMARY KEY, "
                    + "password_hash VARCHAR(128) NOT NULL, "
                    + "password_salt VARCHAR(64) NOT NULL, "
                    + "password_iterations INTEGER NOT NULL, "
                    + "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
                    + ")";

    private static final String INSERT_SQL =
            "INSERT INTO user_account "
                    + "(username, password_hash, password_salt, password_iterations) "
                    + "VALUES (?, ?, ?, ?)";

    private static final String FIND_SQL =
            "SELECT password_hash, password_salt, password_iterations "
                    + "FROM user_account WHERE username = ?";

    private final Connection connection;

    public UserAccountService(Connection connection) {
        this.connection = Objects.requireNonNull(connection, "connection");
    }

    /** Creates the account table. In production, this SQL can instead be a migration. */
    public void initializeSchema() throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate(CREATE_TABLE_SQL);
        }
    }

    /**
     * Registers a new username and password.
     *
     * @throws DuplicateUsernameException if the username is already registered
     * @throws IllegalArgumentException for an invalid username or password
     */
    public void register(String username, char[] password) throws SQLException {
        validateCredentials(username, password);

        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] hash = deriveHash(password, salt, ITERATIONS);

        try (PreparedStatement statement = connection.prepareStatement(INSERT_SQL)) {
            statement.setString(1, username);
            statement.setString(2, Base64.getEncoder().encodeToString(hash));
            statement.setString(3, Base64.getEncoder().encodeToString(salt));
            statement.setInt(4, ITERATIONS);
            statement.executeUpdate();
        } catch (SQLException error) {
            // SQLState class 23 means an integrity constraint violation. The only
            // user-provided constrained value in this INSERT is the primary key.
            if (error.getSQLState() != null && error.getSQLState().startsWith("23")) {
                throw new DuplicateUsernameException(username, error);
            }
            throw error;
        } finally {
            Arrays.fill(hash, (byte) 0);
            Arrays.fill(salt, (byte) 0);
        }
    }

    /** Returns true only when the supplied credentials match a stored account. */
    public boolean authenticate(String username, char[] password) throws SQLException {
        if (!isValidUsername(username) || password == null
                || password.length == 0 || password.length > MAX_PASSWORD_LENGTH) {
            return false;
        }

        try (PreparedStatement statement = connection.prepareStatement(FIND_SQL)) {
            statement.setString(1, username);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    return false;
                }

                try {
                    byte[] expected = Base64.getDecoder().decode(result.getString("password_hash"));
                    byte[] salt = Base64.getDecoder().decode(result.getString("password_salt"));
                    int iterations = result.getInt("password_iterations");
                    byte[] actual = deriveHash(password, salt, iterations);
                    try {
                        return MessageDigest.isEqual(expected, actual);
                    } finally {
                        Arrays.fill(expected, (byte) 0);
                        Arrays.fill(actual, (byte) 0);
                        Arrays.fill(salt, (byte) 0);
                    }
                } catch (IllegalArgumentException error) {
                    throw new SQLException("Stored password data is invalid", error);
                }
            }
        }
    }

    private static byte[] deriveHash(char[] password, byte[] salt, int iterations) {
        if (iterations <= 0) {
            throw new IllegalArgumentException("Password iteration count must be positive");
        }
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_BYTES * 8);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException error) {
            throw new IllegalStateException(ALGORITHM + " is unavailable", error);
        } finally {
            spec.clearPassword();
        }
    }

    private static void validateCredentials(String username, char[] password) {
        if (!isValidUsername(username)) {
            throw new IllegalArgumentException(
                    "Username must be nonblank and at most " + MAX_USERNAME_LENGTH + " characters");
        }
        if (password == null || password.length == 0 || password.length > MAX_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must contain 1 to " + MAX_PASSWORD_LENGTH + " characters");
        }
    }

    private static boolean isValidUsername(String username) {
        return username != null
                && !username.trim().isEmpty()
                && username.length() <= MAX_USERNAME_LENGTH;
    }

    public static final class DuplicateUsernameException extends SQLException {
        private static final long serialVersionUID = 1L;

        public DuplicateUsernameException(String username, SQLException cause) {
            super("Username is already registered: " + username,
                    cause.getSQLState(), cause.getErrorCode(), cause);
        }
    }

    /**
     * Small command-line demonstration. Application code normally constructs the
     * service directly with its already-open Connection instead.
     */
    public static void main(String[] args) {
        if (args.length < 3 || args.length > 4) {
            printUsage();
            System.exit(2);
        }

        String jdbcUrl = args[0];
        String databaseUser = args[1];
        String command = args[2];
        String username = args.length == 4 ? args[3] : null;
        String databasePassword = System.getenv("JDBC_PASSWORD");
        if (databasePassword == null) {
            databasePassword = "";
        }

        try (Connection connection = DriverManager.getConnection(
                jdbcUrl, databaseUser, databasePassword)) {
            UserAccountService accounts = new UserAccountService(connection);
            accounts.initializeSchema();

            if ("init".equals(command) && username == null) {
                System.out.println("Account table is ready.");
                return;
            }
            if (username == null
                    || !("register".equals(command) || "authenticate".equals(command))) {
                printUsage();
                System.exit(2);
            }

            char[] password = readPassword("Account password: ");
            try {
                if ("register".equals(command)) {
                    accounts.register(username, password);
                    System.out.println("Account registered.");
                } else {
                    boolean authenticated = accounts.authenticate(username, password);
                    System.out.println(authenticated
                            ? "Credentials are valid."
                            : "Credentials are invalid.");
                    if (!authenticated) {
                        System.exit(1);
                    }
                }
            } finally {
                Arrays.fill(password, '\0');
            }
        } catch (SQLException | IOException error) {
            System.err.println("Account operation failed: " + error.getMessage());
            System.exit(1);
        }
    }

    private static char[] readPassword(String prompt) throws IOException {
        Console console = System.console();
        if (console == null) {
            throw new IOException("No interactive console is available");
        }
        char[] password = console.readPassword("%s", prompt);
        if (password == null) {
            throw new IOException("No password was entered");
        }
        return password;
    }

    private static void printUsage() {
        System.err.println("Usage:");
        System.err.println("  java ... UserAccountService <jdbc-url> <db-user> init");
        System.err.println(
                "  java ... UserAccountService <jdbc-url> <db-user> register <username>");
        System.err.println(
                "  java ... UserAccountService <jdbc-url> <db-user> authenticate <username>");
        System.err.println("Set JDBC_PASSWORD in the environment when the database requires it.");
    }
}
