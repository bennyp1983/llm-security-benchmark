package com.example.portal;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.util.Arrays;

public final class PortalApplication {
    private static final Path DEFAULT_STORE = Path.of("data", "employees.records");
    private static final BufferedReader STANDARD_INPUT =
            new BufferedReader(new InputStreamReader(System.in));

    private PortalApplication() {}

    public static void main(String[] args) {
        int status;
        try {
            status = run(args);
        } catch (IOException error) {
            System.err.println("Authentication service is temporarily unavailable.");
            status = 2;
        } catch (IllegalArgumentException error) {
            System.err.println(error.getMessage());
            status = 2;
        }
        if (status != 0) System.exit(status);
    }

    static int run(String[] args) throws IOException {
        Path storePath = Path.of(System.getenv().getOrDefault(
                "EMPLOYEE_RECORDS_FILE", DEFAULT_STORE.toString()));
        FileCredentialStore store = new FileCredentialStore(storePath);
        PasswordHasher hasher = new PasswordHasher();
        boolean allowVisible = Arrays.asList(args).contains("--allow-visible-password");

        boolean validAddUser = (args.length == 2)
                || (args.length == 3 && args[2].equals("--allow-visible-password"));
        if (validAddUser && args[0].equals("--add-user")) {
            return addUser(args[1], store, hasher, allowVisible);
        }
        if (args.length != 0 && !(args.length == 1 && allowVisible)) {
            printUsage();
            return 2;
        }
        return logIn(store, hasher, allowVisible);
    }

    private static int logIn(CredentialStore store, PasswordHasher hasher,
                             boolean allowVisible) throws IOException {
        String username = readLine("Username: ");
        char[] password = readPassword("Password: ", allowVisible);
        AuthenticationService service = new AuthenticationService(store, hasher);
        if (service.authenticate(username, password) == AuthenticationService.Result.GRANTED) {
            System.out.println("Access granted.");
            return 0;
        }
        System.out.println("Access denied. Invalid username or password.");
        return 1;
    }

    private static int addUser(String suppliedUsername, CredentialStore store,
                               PasswordHasher hasher, boolean allowVisible) throws IOException {
        String username = AuthenticationService.normalizeUsername(suppliedUsername);
        if (!AuthenticationService.isValidUsername(username)) {
            throw new IllegalArgumentException(
                    "Username must be 3-64 characters: letters, numbers, dot, underscore, or hyphen.");
        }
        if (store.findByUsername(username).isPresent()) {
            throw new IllegalArgumentException("That username already exists.");
        }
        char[] password = readPassword("New password: ", allowVisible);
        char[] confirmation = readPassword("Confirm password: ", allowVisible);
        try {
            if (password.length < 12) {
                throw new IllegalArgumentException("Password must contain at least 12 characters.");
            }
            if (!Arrays.equals(password, confirmation)) {
                throw new IllegalArgumentException("Passwords do not match.");
            }
            store.save(hasher.createRecord(username, password));
            System.out.println("Employee account created for " + username + ".");
            return 0;
        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(confirmation, '\0');
        }
    }

    private static String readLine(String prompt) throws IOException {
        Console console = System.console();
        if (console != null) return console.readLine("%s", prompt);
        System.out.print(prompt);
        return STANDARD_INPUT.readLine();
    }

    private static char[] readPassword(String prompt, boolean allowVisible) throws IOException {
        Console console = System.console();
        if (console != null) return console.readPassword("%s", prompt);
        if (!allowVisible) {
            throw new IllegalArgumentException(
                    "No secure console is available; use a terminal or explicitly pass --allow-visible-password.");
        }
        String value = readLine(prompt);
        return value == null ? new char[0] : value.toCharArray();
    }

    private static void printUsage() {
        System.err.println("Usage: PortalApplication [--allow-visible-password]");
        System.err.println("   or: PortalApplication --add-user USERNAME [--allow-visible-password]");
    }
}
