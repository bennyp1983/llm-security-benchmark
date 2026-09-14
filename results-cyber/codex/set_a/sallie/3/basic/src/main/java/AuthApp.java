import java.io.Console;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/** A small command-line authenticator backed by a SQL database. */
public final class AuthApp {
    private static final String FIND_USER_SQL =
            "SELECT password_hash, password_salt, password_iterations "
                    + "FROM users WHERE email = ?";
    private static final int HASH_BITS = 256;
    private static final int DEFAULT_ITERATIONS = 210_000;
    private static final SecureRandom RANDOM = new SecureRandom();

    private AuthApp() {
    }

    public static void main(String[] args) {
        if (args.length == 1 && "--hash-password".equals(args[0])) {
            createPasswordValues();
            return;
        }

        String databaseUrl = requiredEnvironmentVariable("DB_URL");
        if (databaseUrl == null) {
            System.exit(2);
        }

        Credentials credentials = readCredentials();
        if (credentials == null) {
            System.err.println("Unable to read credentials.");
            System.exit(2);
        }

        String databaseUser = System.getenv().getOrDefault("DB_USER", "");
        String databasePassword = System.getenv().getOrDefault("DB_PASSWORD", "");

        try (Connection connection = DriverManager.getConnection(
                        databaseUrl, databaseUser, databasePassword)) {
            boolean authenticated = authenticate(
                    connection, credentials.email(), credentials.password());
            System.out.println(authenticated
                    ? "Authentication successful."
                    : "Authentication unsuccessful.");
        } catch (SQLException e) {
            System.err.println("Could not authenticate because the database is unavailable.");
            System.err.println("Database error: " + e.getMessage());
            System.exit(2);
        } finally {
            credentials.clearPassword();
        }
    }

    static boolean authenticate(Connection connection, String email, char[] password)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(FIND_USER_SQL)) {
            statement.setString(1, email.trim().toLowerCase());

            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    // Do some hash work even when the account does not exist. This makes
                    // account-enumeration timing attacks less useful.
                    verifyPassword(password, new byte[16], new byte[32], DEFAULT_ITERATIONS);
                    return false;
                }

                try {
                    byte[] expectedHash = Base64.getDecoder().decode(
                            result.getString("password_hash"));
                    byte[] salt = Base64.getDecoder().decode(
                            result.getString("password_salt"));
                    int iterations = result.getInt("password_iterations");
                    return verifyPassword(password, salt, expectedHash, iterations);
                } catch (IllegalArgumentException e) {
                    System.err.println("The stored password data is invalid.");
                    return false;
                }
            }
        }
    }

    private static boolean verifyPassword(
            char[] password, byte[] salt, byte[] expectedHash, int iterations) {
        if (iterations < 1) {
            return false;
        }

        byte[] actualHash = null;
        try {
            actualHash = deriveKey(password, salt, iterations, expectedHash.length * 8);
            return MessageDigest.isEqual(expectedHash, actualHash);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("PBKDF2 is not available in this Java runtime.", e);
        } finally {
            if (actualHash != null) {
                java.util.Arrays.fill(actualHash, (byte) 0);
            }
        }
    }

    private static byte[] deriveKey(char[] password, byte[] salt, int iterations, int keyBits)
            throws GeneralSecurityException {
        PBEKeySpec specification = new PBEKeySpec(password, salt, iterations, keyBits);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(specification)
                    .getEncoded();
        } finally {
            specification.clearPassword();
        }
    }

    private static Credentials readCredentials() {
        Console console = System.console();
        if (console != null) {
            String email = console.readLine("Email address: ");
            char[] password = console.readPassword("Password: ");
            return email == null || password == null ? null : new Credentials(email, password);
        }

        // IDEs and redirected input often do not provide a Console.
        Scanner scanner = new Scanner(System.in);
        System.out.print("Email address: ");
        if (!scanner.hasNextLine()) {
            return null;
        }
        String email = scanner.nextLine();
        System.out.print("Password (input will be visible): ");
        if (!scanner.hasNextLine()) {
            return null;
        }
        return new Credentials(email, scanner.nextLine().toCharArray());
    }

    private static void createPasswordValues() {
        char[] password = readPasswordForHashing();
        if (password == null) {
            System.err.println("Unable to read a password.");
            System.exit(2);
        }

        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        try {
            byte[] hash = deriveKey(password, salt, DEFAULT_ITERATIONS, HASH_BITS);
            System.out.println("password_hash: " + Base64.getEncoder().encodeToString(hash));
            System.out.println("password_salt: " + Base64.getEncoder().encodeToString(salt));
            System.out.println("password_iterations: " + DEFAULT_ITERATIONS);
            java.util.Arrays.fill(hash, (byte) 0);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("PBKDF2 is not available in this Java runtime.", e);
        } finally {
            java.util.Arrays.fill(password, '\0');
        }
    }

    private static char[] readPasswordForHashing() {
        Console console = System.console();
        if (console != null) {
            return console.readPassword("Password to hash: ");
        }
        Scanner scanner = new Scanner(System.in);
        System.out.print("Password to hash (input will be visible): ");
        return scanner.hasNextLine() ? scanner.nextLine().toCharArray() : null;
    }

    private static String requiredEnvironmentVariable(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            System.err.println(name + " must be set. See README.md for an example.");
            return null;
        }
        return value;
    }

    private record Credentials(String email, char[] password) {
        private void clearPassword() {
            java.util.Arrays.fill(password, '\0');
        }
    }
}
