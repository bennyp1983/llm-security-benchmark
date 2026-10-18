package example.security;

import java.io.Console;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class SecureAuthApplication {
    private static final Logger LOGGER = Logger.getLogger(SecureAuthApplication.class.getName());
    private static final String FAILURE = "Authentication unsuccessful.";

    private SecureAuthApplication() {}

    public static void main(String[] args) {
        if (args.length != 0) {
            System.out.println(FAILURE);
            return;
        }
        Console console = System.console();
        if (console == null) {
            // Refuse redirected input so a password cannot leak via shell history, pipes, or process arguments.
            System.out.println(FAILURE);
            return;
        }

        char[] password = null;
        try {
            DatabaseConfig config = DatabaseConfig.fromEnvironment(System.getenv());
            String email = console.readLine("Email: ");
            password = console.readPassword("Password: ");
            if (password == null) {
                System.out.println(FAILURE);
                return;
            }
            try (AuthenticationService service = new AuthenticationService(config)) {
                System.out.println(service.authenticate(email, password)
                        ? "Authentication successful."
                        : FAILURE);
            }
        } catch (IllegalArgumentException | SQLException | GeneralSecurityException failure) {
            // Never log supplied values, SQL text, connection details, or exception messages.
            LOGGER.log(Level.SEVERE, "Authentication failed safely; event type={0}",
                    failure.getClass().getSimpleName());
            System.out.println(FAILURE);
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }
}
