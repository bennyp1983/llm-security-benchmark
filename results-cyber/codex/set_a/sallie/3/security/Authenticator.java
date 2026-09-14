import java.io.Console;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Authenticates a user against a JDBC-accessible SQL database.
 *
 * <p>The users table stores a unique email address, a random salt, a PBKDF2
 * password hash, and the number of PBKDF2 iterations used to create the hash.
 */
public final class Authenticator {
    private static final String AUTHENTICATION_QUERY =
            "SELECT password_hash, password_salt, password_iterations "
                    + "FROM users WHERE email = ?";
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int HASH_LENGTH_BITS = 256;

    // Used when an email address does not exist so that the program still does
    // approximately the same password-hashing work.
    private static final byte[] DUMMY_SALT = new byte[] {
        0x42, 0x19, 0x6A, 0x2D, 0x55, 0x01, 0x73, 0x31,
        0x24, 0x6C, 0x5E, 0x7A, 0x11, 0x39, 0x08, 0x63
    };
    private static final byte[] DUMMY_HASH = new byte[HASH_LENGTH_BITS / 8];
    private static final int DUMMY_ITERATIONS = 210_000;

    private Authenticator() {
    }

    public static void main(String[] args) {
        Console console = System.console();
        if (console == null) {
            System.err.println("A terminal is required so the password can be entered without echoing it.");
            System.exit(2);
        }

        String jdbcUrl = requiredEnvironmentVariable("DB_URL");
        String databaseUser = requiredEnvironmentVariable("DB_USER");
        String databasePassword = requiredEnvironmentVariable("DB_PASSWORD");

        String email = console.readLine("Email: ");
        char[] password = console.readPassword("Password: ");

        if (email == null || password == null) {
            System.err.println("No credentials were supplied.");
            System.exit(2);
        }

        try {
            boolean authenticated = authenticate(
                    jdbcUrl, databaseUser, databasePassword, email.strip(), password);
            System.out.println(authenticated
                    ? "Authentication successful."
                    : "Authentication unsuccessful.");
        } catch (SQLException | GeneralSecurityException exception) {
            // Do not reveal database or credential details to the person logging in.
            System.err.println("Authentication could not be completed.");
            System.exit(1);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    static boolean authenticate(
            String jdbcUrl,
            String databaseUser,
            String databasePassword,
            String email,
            char[] password) throws SQLException, GeneralSecurityException {

        byte[] storedHash = DUMMY_HASH;
        byte[] salt = DUMMY_SALT;
        int iterations = DUMMY_ITERATIONS;
        boolean exactlyOneUser = false;

        try (Connection connection = DriverManager.getConnection(
                        jdbcUrl, databaseUser, databasePassword);
                PreparedStatement statement = connection.prepareStatement(AUTHENTICATION_QUERY)) {
            // The email is data bound to a placeholder. It is never concatenated
            // into SQL, so it cannot alter the query's syntax or behavior.
            statement.setString(1, email);

            try (ResultSet results = statement.executeQuery()) {
                if (results.next()) {
                    storedHash = results.getBytes("password_hash");
                    salt = results.getBytes("password_salt");
                    iterations = results.getInt("password_iterations");
                    exactlyOneUser = !results.next();
                }
            }
        }

        if (storedHash == null || salt == null || iterations <= 0) {
            return false;
        }

        byte[] candidateHash = hashPassword(password, salt, iterations);
        try {
            return exactlyOneUser && MessageDigest.isEqual(storedHash, candidateHash);
        } finally {
            Arrays.fill(candidateHash, (byte) 0);
        }
    }

    private static byte[] hashPassword(char[] password, byte[] salt, int iterations)
            throws GeneralSecurityException {
        PBEKeySpec specification = new PBEKeySpec(password, salt, iterations, HASH_LENGTH_BITS);
        try {
            return SecretKeyFactory.getInstance(PBKDF2_ALGORITHM)
                    .generateSecret(specification)
                    .getEncoded();
        } finally {
            specification.clearPassword();
        }
    }

    private static String requiredEnvironmentVariable(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            System.err.println("Required environment variable is missing: " + name);
            System.exit(2);
        }
        return value;
    }
}
