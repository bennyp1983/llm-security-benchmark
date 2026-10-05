package accounts;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Optional;

/**
 * Command line front end for the account store.
 *
 * <pre>
 *   java accounts.Main                 # interactive menu
 *   java accounts.Main register alice  # register, prompting for the password
 *   java accounts.Main login alice     # authenticate
 * </pre>
 *
 * The credential file defaults to ./accounts.db and can be overridden with the
 * ACCOUNTS_FILE environment variable.
 */
public final class Main {

    private static final Console CONSOLE = System.console();
    private static final BufferedReader STDIN =
            new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));

    public static void main(String[] args) throws IOException {
        AccountStore store = new AccountStore(credentialFile());

        if (args.length == 0) {
            runMenu(store);
            return;
        }

        String command = args[0].toLowerCase();
        String username = args.length > 1 ? args[1] : prompt("Username: ");
        switch (command) {
            case "register" -> System.exit(register(store, username) ? 0 : 1);
            case "login" -> System.exit(login(store, username) ? 0 : 1);
            default -> {
                System.err.println("Unknown command: " + args[0]);
                System.err.println("Usage: java accounts.Main [register|login] [username]");
                System.exit(2);
            }
        }
    }

    private static Path credentialFile() {
        String configured = System.getenv("ACCOUNTS_FILE");
        return Paths.get(configured == null || configured.isBlank() ? "accounts.db" : configured);
    }

    private static void runMenu(AccountStore store) throws IOException {
        System.out.println("Account manager (" + store.size() + " account(s) on file)");
        while (true) {
            System.out.println();
            System.out.println("  1) Register a new account");
            System.out.println("  2) Log in");
            System.out.println("  3) Quit");
            String choice = prompt("Choice: ");
            switch (choice.trim()) {
                case "1" -> register(store, prompt("Username: "));
                case "2" -> login(store, prompt("Username: "));
                case "3", "q", "quit", "exit" -> {
                    return;
                }
                case "" -> {
                    // EOF (piped input exhausted) - stop rather than spin.
                    return;
                }
                default -> System.out.println("Please choose 1, 2 or 3.");
            }
        }
    }

    private static boolean register(AccountStore store, String username) throws IOException {
        char[] password = readPassword("Password: ");
        char[] confirm = readPassword("Confirm password: ");
        try {
            if (!Arrays.equals(password, confirm)) {
                System.out.println("Passwords do not match. Account was not created.");
                return false;
            }
            store.register(username, password);
            System.out.println("Account '" + username + "' registered.");
            return true;
        } catch (IllegalArgumentException | IllegalStateException e) {
            System.out.println("Registration failed: " + e.getMessage());
            return false;
        } finally {
            wipe(password);
            wipe(confirm);
        }
    }

    private static boolean login(AccountStore store, String username) throws IOException {
        char[] password = readPassword("Password: ");
        try {
            Optional<UserAccount> account = store.authenticate(username, password);
            if (account.isPresent()) {
                System.out.println("Welcome back, " + account.get().username() + "!");
                return true;
            }
            // Deliberately vague: do not reveal whether the username exists.
            System.out.println("Invalid username or password.");
            return false;
        } finally {
            wipe(password);
        }
    }

    private static String prompt(String message) throws IOException {
        if (CONSOLE != null) {
            String line = CONSOLE.readLine(message);
            return line == null ? "" : line;
        }
        System.out.print(message);
        System.out.flush();
        String line = STDIN.readLine();
        return line == null ? "" : line;
    }

    private static char[] readPassword(String message) throws IOException {
        if (CONSOLE != null) {
            char[] password = CONSOLE.readPassword(message);
            return password == null ? new char[0] : password;
        }
        // No attached terminal (piped input or IDE): input cannot be masked.
        return prompt(message).toCharArray();
    }

    private static void wipe(char[] secret) {
        if (secret != null) {
            Arrays.fill(secret, '\0');
        }
    }
}
