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
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Authenticates a user by email address and password against a SQL database.
 *
 * Security measures:
 *  - The query is a PreparedStatement with a bound parameter, so user input is
 *    always treated as data and can never alter the SQL statement.
 *  - Passwords are never stored or compared in plain text. The database holds a
 *    salted PBKDF2-HMAC-SHA256 hash, and hashes are compared in constant time.
 *  - A dummy hash is checked when the email is unknown, so response time does
 *    not reveal which email addresses exist.
 *  - The same generic failure message is shown for every kind of failure.
 *  - Passwords are read without echo and wiped from memory after use.
 *  - Database connection settings come from environment variables, not code.
 *
 * Expected table:
 *   CREATE TABLE users (
 *       email         VARCHAR(254) NOT NULL PRIMARY KEY,
 *       password_hash VARCHAR(255) NOT NULL
 *   );
 *
 * Usage:
 *   java -cp .:<jdbc-driver.jar> UserAuthenticator [email]
 *   java UserAuthenticator --hash        (create a hash to store in the database)
 *
 * Exit codes: 0 = authenticated, 1 = not authenticated, 2 = system error.
 */
public final class UserAuthenticator {

    private static final String QUERY =
            "SELECT password_hash FROM users WHERE email = ?";

    private static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String HASH_PREFIX = "pbkdf2_sha256";
    private static final int ITERATIONS = 600_000;
    private static final int SALT_BYTES = 16;
    private static final int HASH_BITS = 256;
    private static final int MIN_ITERATIONS = 10_000;
    private static final int MAX_ITERATIONS = 10_000_000;

    private static final int MAX_EMAIL_LENGTH = 254;
    private static final int MAX_PASSWORD_LENGTH = 1024;

    private static final int EXIT_SUCCESS = 0;
    private static final int EXIT_FAILURE = 1;
    private static final int EXIT_ERROR = 2;

    private static final SecureRandom RANDOM = new SecureRandom();

    /** Checked when an email is not found, so unknown users take as long as known ones. */
    private static final String DUMMY_HASH = hashPassword("dummy-password".toCharArray());

    private final String jdbcUrl;
    private final String dbUser;
    private final String dbPassword;

    public UserAuthenticator(String jdbcUrl, String dbUser, String dbPassword) {
        this.jdbcUrl = jdbcUrl;
        this.dbUser = dbUser;
        this.dbPassword = dbPassword;
    }

    /**
     * Returns true only if the email exists and the password matches its stored hash.
     * The password array is cleared before this method returns.
     *
     * @throws SQLException if the database cannot be queried
     */
    public boolean authenticate(String email, char[] password) throws SQLException {
        try {
            String normalizedEmail = normalizeEmail(email);
            if (normalizedEmail == null || password == null
                    || password.length == 0 || password.length > MAX_PASSWORD_LENGTH) {
                verifyPassword(password == null ? new char[0] : password, DUMMY_HASH);
                return false;
            }

            String storedHash = findPasswordHash(normalizedEmail);
            if (storedHash == null) {
                verifyPassword(password, DUMMY_HASH);
                return false;
            }
            return verifyPassword(password, storedHash);
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    /** Looks up the stored hash with a parameterized query. Returns null if not found. */
    private String findPasswordHash(String email) throws SQLException {
        try (Connection connection = DriverManager.getConnection(jdbcUrl, dbUser, dbPassword);
             PreparedStatement statement = connection.prepareStatement(QUERY)) {
            // The email is bound as a value; it is never concatenated into the SQL text.
            statement.setString(1, email);
            statement.setMaxRows(1);
            try (ResultSet results = statement.executeQuery()) {
                return results.next() ? results.getString("password_hash") : null;
            }
        }
    }

    /** Trims and lower-cases the email and applies basic sanity checks. Returns null if invalid. */
    static String normalizeEmail(String email) {
        if (email == null) {
            return null;
        }
        String trimmed = email.trim().toLowerCase(Locale.ROOT);
        if (trimmed.isEmpty() || trimmed.length() > MAX_EMAIL_LENGTH) {
            return null;
        }
        for (int i = 0; i < trimmed.length(); i++) {
            if (Character.isISOControl(trimmed.charAt(i)) || Character.isWhitespace(trimmed.charAt(i))) {
                return null;
            }
        }
        int at = trimmed.indexOf('@');
        if (at <= 0 || at != trimmed.lastIndexOf('@') || at == trimmed.length() - 1) {
            return null;
        }
        return trimmed;
    }

    /** Creates a salted hash in the form pbkdf2_sha256$iterations$salt$hash. */
    public static String hashPassword(char[] password) {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] hash = pbkdf2(password, salt, ITERATIONS, HASH_BITS);
        Base64.Encoder encoder = Base64.getEncoder();
        return HASH_PREFIX + "$" + ITERATIONS + "$"
                + encoder.encodeToString(salt) + "$" + encoder.encodeToString(hash);
    }

    /** Checks a password against a stored hash using a constant-time comparison. */
    static boolean verifyPassword(char[] password, String storedHash) {
        if (storedHash == null) {
            return false;
        }
        String[] parts = storedHash.split("\\$");
        if (parts.length != 4 || !HASH_PREFIX.equals(parts[0])) {
            return false;
        }
        try {
            int iterations = Integer.parseInt(parts[1]);
            if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
                return false;
            }
            Base64.Decoder decoder = Base64.getDecoder();
            byte[] salt = decoder.decode(parts[2]);
            byte[] expected = decoder.decode(parts[3]);
            if (salt.length == 0 || expected.length == 0) {
                return false;
            }
            byte[] actual = pbkdf2(password, salt, iterations, expected.length * 8);
            return MessageDigest.isEqual(expected, actual);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int bits) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bits);
        try {
            return SecretKeyFactory.getInstance(HASH_ALGORITHM).generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Password hashing is unavailable", e);
        } finally {
            spec.clearPassword();
        }
    }

    // ---------------------------------------------------------------------
    // Command-line interface
    // ---------------------------------------------------------------------

    public static void main(String[] args) {
        System.exit(run(args));
    }

    private static int run(String[] args) {
        try {
            if (args.length == 1 && "--hash".equals(args[0])) {
                return printHash();
            }
            if (args.length > 1 || (args.length == 1 && args[0].startsWith("--"))) {
                System.err.println("Usage: java UserAuthenticator [email]");
                System.err.println("       java UserAuthenticator --hash");
                return EXIT_ERROR;
            }

            String jdbcUrl = System.getenv("DB_URL");
            if (jdbcUrl == null || jdbcUrl.isBlank()) {
                System.err.println("Error: the DB_URL environment variable is not set.");
                return EXIT_ERROR;
            }
            UserAuthenticator authenticator = new UserAuthenticator(
                    jdbcUrl, System.getenv("DB_USER"), System.getenv("DB_PASSWORD"));

            String email = args.length == 1 ? args[0] : readLine("Email address: ");
            char[] password = readSecret("Password: ");

            if (authenticator.authenticate(email, password)) {
                System.out.println("Authentication successful.");
                return EXIT_SUCCESS;
            }
            System.out.println("Authentication failed: invalid email address or password.");
            return EXIT_FAILURE;
        } catch (SQLException e) {
            // Keep database details out of user-facing output.
            System.err.println("Error: could not reach the credential database.");
            return EXIT_ERROR;
        } catch (IOException | RuntimeException e) {
            System.err.println("Error: authentication could not be completed.");
            return EXIT_ERROR;
        }
    }

    private static int printHash() throws IOException {
        char[] password = readSecret("Password to hash: ");
        try {
            if (password.length == 0 || password.length > MAX_PASSWORD_LENGTH) {
                System.err.println("Error: password must be 1 to " + MAX_PASSWORD_LENGTH + " characters.");
                return EXIT_ERROR;
            }
            System.out.println(hashPassword(password));
            return EXIT_SUCCESS;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static BufferedReader stdin;

    private static String readLine(String prompt) throws IOException {
        Console console = System.console();
        if (console != null) {
            String line = console.readLine("%s", prompt);
            return line == null ? "" : line;
        }
        String line = stdinReader().readLine();
        return line == null ? "" : line;
    }

    /** Reads a password without echoing it when a terminal is available. */
    private static char[] readSecret(String prompt) throws IOException {
        Console console = System.console();
        if (console != null) {
            char[] secret = console.readPassword("%s", prompt);
            return secret == null ? new char[0] : secret;
        }
        String line = stdinReader().readLine();
        return line == null ? new char[0] : line.toCharArray();
    }

    private static BufferedReader stdinReader() {
        if (stdin == null) {
            stdin = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        }
        return stdin;
    }
}
