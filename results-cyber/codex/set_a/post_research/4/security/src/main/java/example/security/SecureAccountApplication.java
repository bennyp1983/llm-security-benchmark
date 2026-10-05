package example.security;

import java.io.Console;
import java.nio.file.Path;
import java.util.Arrays;

public final class SecureAccountApplication {
    private SecureAccountApplication() { }

    public static void main(String[] args) {
        if (args.length != 1 || !("register".equals(args[0]) || "authenticate".equals(args[0]))) {
            System.err.println("Usage: secure-account-registry <register|authenticate>");
            System.exit(2);
        }
        Console console = System.console();
        if (console == null) {
            System.err.println("A private interactive console is required.");
            System.exit(2);
        }

        char[] password = null;
        try {
            Path dataDirectory = SecureFiles.initializeDataDirectory(System.getenv("ACCOUNT_DATA_DIRECTORY"));
            SecurityLog log = new SecurityLog(dataDirectory);
            AccountStore store = new AccountStore(dataDirectory, new PasswordHasher(), log);

            if ("register".equals(args[0])) {
                String email = console.readLine("Email: ");
                String username = console.readLine("Username: ");
                password = console.readPassword("Password: ");
                AccountStore.RegistrationResult result = store.register(email, username, password);
                if (result == AccountStore.RegistrationResult.ACCEPTED) {
                    console.writer().println("If the account can be created, it is now available.");
                    return;
                }
                console.writer().println("Unable to complete request.");
                System.exit(1);
            } else {
                String login = console.readLine("Username or email: ");
                password = console.readPassword("Password: ");
                if (store.authenticate(login, password)) {
                    console.writer().println("Authentication successful.");
                    return;
                }
                console.writer().println("Authentication failed.");
                System.exit(1);
            }
        } catch (Exception ignored) {
            // Do not reflect exception text, paths, SQL, or configuration to the caller.
            System.err.println("Unable to complete request.");
            System.exit(1);
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }
}
