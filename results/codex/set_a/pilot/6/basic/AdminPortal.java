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
 * <p>The administrator credentials are supplied through the ADMIN_USERNAME and
 * ADMIN_PASSWORD environment variables. Keeping credentials out of the source
 * code makes it possible to change them without rebuilding the application.</p>
 */
public final class AdminPortal {
    private static final String USERNAME_VARIABLE = "ADMIN_USERNAME";
    private static final String PASSWORD_VARIABLE = "ADMIN_PASSWORD";

    private AdminPortal() {
        // Utility class
    }

    public static void main(String[] args) {
        String configuredUsername = System.getenv(USERNAME_VARIABLE);
        String configuredPassword = System.getenv(PASSWORD_VARIABLE);

        if (isBlank(configuredUsername) || isBlank(configuredPassword)) {
            System.err.println("Administrator credentials are not configured.");
            System.err.println("Set ADMIN_USERNAME and ADMIN_PASSWORD before starting the portal.");
            return;
        }

        char[] enteredPassword = null;
        char[] expectedPassword = configuredPassword.toCharArray();

        try {
            Credentials enteredCredentials = readCredentials();
            enteredPassword = enteredCredentials.password;

            if (authenticate(
                    enteredCredentials.username,
                    enteredPassword,
                    configuredUsername,
                    expectedPassword)) {
                System.out.println("Access granted. Welcome to the administrator portal.");
                showAdminFunctionality();
            } else {
                System.out.println("Access denied. Invalid username or password.");
            }
        } catch (IOException exception) {
            System.err.println("Unable to read credentials: " + exception.getMessage());
        } finally {
            clear(enteredPassword);
            clear(expectedPassword);
        }
    }

    private static Credentials readCredentials() throws IOException {
        Console console = System.console();
        if (console != null) {
            String username = console.readLine("Username: ");
            char[] password = console.readPassword("Password: ");
            return new Credentials(username, password == null ? new char[0] : password);
        }

        // System.console() is normally unavailable in IDEs and redirected input.
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("Username: ");
        String username = reader.readLine();
        System.out.print("Password: ");
        String password = reader.readLine();
        return new Credentials(
                username,
                password == null ? new char[0] : password.toCharArray());
    }

    static boolean authenticate(
            String enteredUsername,
            char[] enteredPassword,
            String expectedUsername,
            char[] expectedPassword) {
        if (enteredUsername == null || enteredPassword == null) {
            return false;
        }

        // Evaluate both comparisons so the password check is not skipped when
        // the username is wrong.
        return constantTimeEquals(enteredUsername, expectedUsername)
                & constantTimeEquals(enteredPassword, expectedPassword);
    }

    private static boolean constantTimeEquals(String first, String second) {
        if (first == null || second == null) {
            return false;
        }
        return MessageDigest.isEqual(
                first.getBytes(StandardCharsets.UTF_8),
                second.getBytes(StandardCharsets.UTF_8));
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

    private static void showAdminFunctionality() {
        System.out.println("Admin dashboard:");
        System.out.println("- Manage users");
        System.out.println("- View audit logs");
        System.out.println("- Configure system settings");
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private static void clear(char[] value) {
        if (value != null) {
            Arrays.fill(value, '\0');
        }
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
