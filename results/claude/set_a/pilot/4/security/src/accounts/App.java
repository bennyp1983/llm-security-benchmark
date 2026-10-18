package accounts;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

/**
 * Command-line front end for the account store.
 *
 * <pre>
 *   java accounts.App register   -- create an account
 *   java accounts.App login      -- authenticate with stored credentials
 *   java accounts.App passwd     -- change an existing password
 * </pre>
 *
 * The account file defaults to {@code accounts.db}; override it with -Daccounts.file=PATH.
 */
public final class App {

    private static final Console CONSOLE = System.console();
    private static final BufferedReader STDIN =
            new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));

    public static void main(String[] args) {
        String command = args.length > 0 ? args[0].toLowerCase() : "help";
        Path file = Paths.get(System.getProperty("accounts.file", "accounts.db"));
        UserStore store = new UserStore(file);

        switch (command) {
            case "register" -> register(store);
            case "login" -> login(store);
            case "passwd" -> changePassword(store);
            default -> usage();
        }
    }

    private static void register(UserStore store) {
        String username = readLine("Username: ");
        char[] password = readPassword("Password: ");
        char[] confirm = readPassword("Confirm password: ");
        try {
            if (!Arrays.equals(password, confirm)) {
                System.out.println("Passwords do not match. Nothing was saved.");
                return;
            }
            store.register(username, password);
            System.out.println("Account created for '" + username.trim().toLowerCase() + "'.");
        } catch (IllegalArgumentException | IllegalStateException e) {
            System.out.println("Registration failed: " + e.getMessage());
        } finally {
            wipe(password);
            wipe(confirm);
        }
    }

    private static void login(UserStore store) {
        String username = readLine("Username: ");
        char[] password = readPassword("Password: ");
        try {
            // Deliberately identical wording for both failure modes, so a wrong guess
            // never reveals whether the username exists.
            System.out.println(store.authenticate(username, password)
                    ? "Authenticated. Welcome back, " + username.trim().toLowerCase() + "."
                    : "Invalid username or password.");
        } finally {
            wipe(password);
        }
    }

    private static void changePassword(UserStore store) {
        String username = readLine("Username: ");
        char[] current = readPassword("Current password: ");
        char[] updated = readPassword("New password: ");
        try {
            System.out.println(store.changePassword(username, current, updated)
                    ? "Password updated."
                    : "Invalid username or password.");
        } catch (IllegalArgumentException e) {
            System.out.println("Password not changed: " + e.getMessage());
        } finally {
            wipe(current);
            wipe(updated);
        }
    }

    private static void usage() {
        System.out.println("""
                Usage: java accounts.App <command>

                  register   create a new account
                  login      authenticate against the stored credentials
                  passwd     change the password on an existing account

                Account file: -Daccounts.file=PATH (default: accounts.db)""");
    }

    private static String readLine(String prompt) {
        if (CONSOLE != null) {
            return orEmpty(CONSOLE.readLine(prompt));
        }
        System.out.print(prompt);
        System.out.flush();
        try {
            return orEmpty(STDIN.readLine());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Reads a password without echoing it when a real terminal is attached. Falls back
     * to plain stdin (piped input, IDE consoles) where no console is available.
     */
    private static char[] readPassword(String prompt) {
        if (CONSOLE != null) {
            char[] entered = CONSOLE.readPassword(prompt);
            return entered == null ? new char[0] : entered;
        }
        return readLine(prompt).toCharArray();
    }

    private static String orEmpty(String value) {
        return value == null ? "" : value;
    }

    private static void wipe(char[] password) {
        Arrays.fill(password, '\0');
    }

    private App() {
    }
}
