import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * A small console-based administrator portal.
 *
 * Credentials are read from environment variables so that a password is not
 * stored in the source code. This example is suitable for learning and local
 * use; a production application should use a proper identity provider or a
 * password-hashing library and persistent user store.
 */
public final class AdminPortal {
    private static final String USERNAME_VARIABLE = "ADMIN_USERNAME";
    private static final String PASSWORD_VARIABLE = "ADMIN_PASSWORD";

    private AdminPortal() {
        // This class is not meant to be instantiated.
    }

    public static void main(String[] args) {
        String expectedUsername = System.getenv(USERNAME_VARIABLE);
        String expectedPassword = System.getenv(PASSWORD_VARIABLE);

        if (isBlank(expectedUsername) || isBlank(expectedPassword)) {
            System.err.println("Administrator credentials are not configured.");
            System.err.println("Set ADMIN_USERNAME and ADMIN_PASSWORD before starting the portal.");
            return;
        }

        try {
            Credentials supplied = readCredentials();
            boolean authenticated = credentialsMatch(
                    supplied.username,
                    supplied.password,
                    expectedUsername,
                    expectedPassword.toCharArray());

            if (authenticated) {
                System.out.println("Access granted. Welcome to the administrator portal.");
                showAdminFunctions();
            } else {
                System.out.println("Access denied. Invalid username or password.");
            }

            Arrays.fill(supplied.password, '\0');
        } catch (IOException exception) {
            System.err.println("Unable to read credentials: " + exception.getMessage());
        }
    }

    private static Credentials readCredentials() throws IOException {
        Console console = System.console();
        if (console != null) {
            String username = console.readLine("Username: ");
            char[] password = console.readPassword("Password: ");
            return new Credentials(username, password == null ? new char[0] : password);
        }

        // Some IDEs and redirected test sessions do not provide a Console.
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("Username: ");
        String username = reader.readLine();
        System.out.print("Password (input is visible in this environment): ");
        String password = reader.readLine();
        return new Credentials(
                username,
                password == null ? new char[0] : password.toCharArray());
    }

    private static boolean credentialsMatch(
            String suppliedUsername,
            char[] suppliedPassword,
            String expectedUsername,
            char[] expectedPassword) {
        try {
            return constantTimeEquals(suppliedUsername, expectedUsername)
                    && constantTimeEquals(suppliedPassword, expectedPassword);
        } finally {
            Arrays.fill(expectedPassword, '\0');
        }
    }

    private static boolean constantTimeEquals(String first, String second) {
        byte[] firstBytes = (first == null ? "" : first).getBytes(StandardCharsets.UTF_8);
        byte[] secondBytes = (second == null ? "" : second).getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(firstBytes, secondBytes);
    }

    private static boolean constantTimeEquals(char[] first, char[] second) {
        byte[] firstBytes = new String(first).getBytes(StandardCharsets.UTF_8);
        byte[] secondBytes = new String(second).getBytes(StandardCharsets.UTF_8);
        try {
            return MessageDigest.isEqual(firstBytes, secondBytes);
        } finally {
            Arrays.fill(firstBytes, (byte) 0);
            Arrays.fill(secondBytes, (byte) 0);
        }
    }

    private static void showAdminFunctions() {
        System.out.println();
        System.out.println("Administrator functions:");
        System.out.println("1. Manage users");
        System.out.println("2. View audit logs");
        System.out.println("3. Change system settings");
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private static final class Credentials {
        private final String username;
        private final char[] password;

        private Credentials(String username, char[] password) {
            this.username = username;
            this.password = password;
        }
    }
}
