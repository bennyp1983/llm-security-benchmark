package com.example.portal.auth;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * Console front end for the employee portal.
 *
 * <pre>
 *   java com.example.portal.auth.PortalApp [--store &lt;file&gt;] login
 *   java com.example.portal.auth.PortalApp [--store &lt;file&gt;] add-user &lt;username&gt; [display name] [role]
 * </pre>
 *
 * <p>{@code login} is the default. The store defaults to {@code employees.tsv} in the
 * working directory, or to the value of the {@code PORTAL_STORE} environment variable.
 */
public final class PortalApp {

    private static final String DEFAULT_STORE = "employees.tsv";
    private static final int MAX_PROMPTS = 3;

    private PortalApp() {
    }

    public static void main(String[] args) {
        Path storePath = Path.of(
                System.getenv().getOrDefault("PORTAL_STORE", DEFAULT_STORE));
        int i = 0;
        if (i < args.length && args[i].equals("--store")) {
            if (i + 1 >= args.length) {
                System.err.println("--store requires a file path.");
                System.exit(2);
            }
            storePath = Path.of(args[i + 1]);
            i += 2;
        }
        String command = i < args.length ? args[i] : "login";
        String[] rest = Arrays.copyOfRange(args, Math.min(i + 1, args.length), args.length);

        try {
            CredentialStore store = new FileCredentialStore(storePath);
            AuthenticationService service =
                    new AuthenticationService(store, AuditLog.toStream(System.err));
            switch (command) {
                case "login":
                    System.exit(login(service));
                    break;
                case "add-user":
                    System.exit(addUser(service, rest));
                    break;
                default:
                    System.err.println("Unknown command: " + command
                            + " (expected 'login' or 'add-user')");
                    System.exit(2);
            }
        } catch (IOException e) {
            System.err.println("Could not open the credential store: " + e.getMessage());
            System.exit(1);
        }
    }

    /** Prompts for credentials up to {@value #MAX_PROMPTS} times. */
    private static int login(AuthenticationService service) throws IOException {
        Prompter prompter = Prompter.create();
        System.out.println("=== Internal Employee Portal ===");
        for (int attempt = 1; attempt <= MAX_PROMPTS; attempt++) {
            String username = prompter.readLine("Username: ");
            char[] password = prompter.readPassword("Password: ");
            if (username == null || password == null) {
                System.out.println("\nSign-in cancelled.");
                return 1;
            }
            try {
                AuthenticationResult result = service.authenticate(username, password);
                System.out.println(result.userMessage());
                if (result.granted()) {
                    EmployeeRecord employee = result.employee().orElseThrow();
                    System.out.println("Role: " + employee.role());
                    return 0;
                }
                if (result.status() == AuthenticationResult.Status.LOCKED_OUT) {
                    return 1;
                }
            } finally {
                // Overwrite the password buffer as soon as it is no longer needed.
                Arrays.fill(password, '\0');
            }
            if (attempt < MAX_PROMPTS) {
                System.out.println("Attempts remaining: " + (MAX_PROMPTS - attempt));
            }
        }
        System.out.println("Too many failed attempts. Contact the IT service desk.");
        return 1;
    }

    /** Administrative helper: create an account or reset a password. */
    private static int addUser(AuthenticationService service, String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("Usage: add-user <username> [display name] [role]");
            return 2;
        }
        String username = args[0];
        String displayName = args.length > 1 ? args[1] : username;
        String role = args.length > 2 ? args[2] : "employee";

        Prompter prompter = Prompter.create();
        char[] password = prompter.readPassword("New password: ");
        char[] confirm = prompter.readPassword("Confirm password: ");
        try {
            if (password == null || confirm == null) {
                System.err.println("Cancelled.");
                return 1;
            }
            if (!Arrays.equals(password, confirm)) {
                System.err.println("Passwords do not match.");
                return 1;
            }
            service.register(username, password, displayName, role, true);
            System.out.println("Saved credentials for '"
                    + EmployeeRecord.normalizeUsername(username) + "'.");
            return 0;
        } catch (IllegalArgumentException e) {
            System.err.println(e.getMessage());
            return 1;
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
            if (confirm != null) {
                Arrays.fill(confirm, '\0');
            }
        }
    }

    /**
     * Reads input from the terminal, hiding the password where the platform allows it.
     * {@link System#console()} is null when input is piped or under some IDEs, in which
     * case the password is echoed and the user is told so.
     */
    private static final class Prompter {

        private final Console console;
        private final BufferedReader reader;

        private Prompter(Console console, BufferedReader reader) {
            this.console = console;
            this.reader = reader;
        }

        static Prompter create() {
            Console console = System.console();
            if (console != null) {
                return new Prompter(console, null);
            }
            System.out.println("[warning] No interactive console: typed passwords will be visible.");
            return new Prompter(null, new BufferedReader(
                    new InputStreamReader(System.in, StandardCharsets.UTF_8)));
        }

        /** @return the line entered, or null at end of input */
        String readLine(String prompt) throws IOException {
            if (console != null) {
                return console.readLine("%s", prompt);
            }
            System.out.print(prompt);
            System.out.flush();
            return reader.readLine();
        }

        /** @return the password entered, or null at end of input */
        char[] readPassword(String prompt) throws IOException {
            if (console != null) {
                return console.readPassword("%s", prompt);
            }
            String line = readLine(prompt);
            return line == null ? null : line.toCharArray();
        }
    }
}
