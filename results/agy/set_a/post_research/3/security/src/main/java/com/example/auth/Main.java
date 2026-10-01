package com.example.auth;

import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Arrays;

/**
 * Command-line entry point for secure user authentication and management.
 * <p>
 * Satisfies:
 * - Rule 1: All user inputs across CLI / Stdin are treated as untrusted and validated.
 * - Rule 2: No credentials hardcoded; passwords read securely via Console.readPassword (no echo)
 *   or direct character stream, never stored in Strings or logged.
 * - Rule 5: Passwords are wiped from memory immediately after invocation.
 * - Rule 6: Generic failure messages printed to users; sensitive details suppressed.
 */
public final class Main {

    public static void main(String[] args) {
        int exitCode = run(args);
        if (exitCode != 0) {
            System.exit(exitCode);
        }
    }

    public static int run(String[] args) {
        boolean registerMode = false;

        for (String arg : args) {
            if ("--help".equals(arg) || "-h".equals(arg)) {
                printUsage();
                return 0;
            } else if ("--register".equals(arg) || "-r".equals(arg)) {
                registerMode = true;
            }
        }

        try (DatabaseManager dbManager = new DatabaseManager()) {
            AuthenticationService authService = new AuthenticationService(dbManager);
            Console console = System.console();

            if (registerMode) {
                return handleRegistration(authService, console);
            } else {
                // If database has 0 users, offer prompt to initialize/register first
                try (Connection conn = dbManager.getConnection()) {
                    UserRepository userRepo = new UserRepository();
                    if (userRepo.countUsers(conn) == 0) {
                        System.out.println("[INFO] No user accounts found in database.");
                        System.out.println("[INFO] Please create an account first.");
                        return handleRegistration(authService, console);
                    }
                } catch (SQLException e) {
                    System.err.println(AuthenticationResult.MSG_INTERNAL_ERROR);
                    return 1;
                }

                return handleAuthentication(authService, console);
            }
        } catch (Exception e) {
            System.err.println(AuthenticationResult.MSG_INTERNAL_ERROR);
            return 1;
        }
    }

    private static int handleAuthentication(AuthenticationService authService, Console console) {
        String email = readEmail(console, "Enter email: ");
        char[] password = readPassword(console, "Enter password: ");

        try {
            String sourceId = System.getenv("AUTH_SOURCE_ID");
            if (sourceId == null || sourceId.isBlank()) {
                sourceId = "cli-local";
            }

            AuthenticationResult result = authService.authenticate(email, password, sourceId);

            if (result.isSuccess()) {
                System.out.println("[SUCCESS] " + result.getUserMessage());
                result.getSession().ifPresent(session -> {
                    System.out.println("Session Token: " + SecurityLogger.maskToken(session.sessionId()));
                    System.out.println("Cookie: " + session.cookieHeader());
                });
                return 0;
            } else {
                System.out.println("[FAILURE] " + result.getUserMessage());
                return 1;
            }
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    private static int handleRegistration(AuthenticationService authService, Console console) {
        System.out.println("--- Register New User ---");
        String email = readEmail(console, "Enter email: ");
        char[] password = readPassword(console, "Enter password (min 8 chars): ");
        char[] confirm = readPassword(console, "Confirm password: ");

        try {
            if (!Arrays.equals(password, confirm)) {
                System.out.println("[FAILURE] Passwords do not match.");
                return 1;
            }

            if (!InputValidator.isValidPasswordForCreation(password)) {
                System.out.println("[FAILURE] Password does not meet security criteria (8 to 128 characters).");
                return 1;
            }

            boolean registered = authService.registerUser(email, password);
            if (registered) {
                System.out.println("[SUCCESS] User registered successfully. You may now authenticate.");
                return 0;
            } else {
                System.out.println("[FAILURE] Registration failed. Invalid email or user already exists.");
                return 1;
            }
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
            if (confirm != null) {
                Arrays.fill(confirm, '\0');
            }
        }
    }

    private static String readEmail(Console console, String prompt) {
        if (console != null) {
            String line = console.readLine(prompt);
            return line != null ? line.trim() : "";
        } else {
            System.out.print(prompt);
            try {
                return readLineFromStream(System.in).trim();
            } catch (IOException e) {
                return "";
            }
        }
    }

    private static char[] readPassword(Console console, String prompt) {
        if (console != null) {
            char[] chars = console.readPassword(prompt);
            return chars != null ? chars : new char[0];
        } else {
            System.out.print(prompt);
            try {
                return readPasswordDirect(System.in);
            } catch (IOException e) {
                return new char[0];
            }
        }
    }

    private static String readLineFromStream(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') {
                break;
            }
            if (b != '\r') {
                sb.append((char) b);
            }
        }
        return sb.toString();
    }

    private static char[] readPasswordDirect(InputStream in) throws IOException {
        char[] buffer = new char[InputValidator.MAX_PASSWORD_LENGTH + 2];
        int len = 0;
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') {
                break;
            }
            if (b != '\r') {
                if (len < InputValidator.MAX_PASSWORD_LENGTH) {
                    buffer[len++] = (char) b;
                }
            }
        }
        char[] password = Arrays.copyOf(buffer, len);
        Arrays.fill(buffer, '\0');
        return password;
    }

    private static void printUsage() {
        System.out.println("Usage: java -jar secure-auth-system-1.0.0.jar [OPTIONS]");
        System.out.println("Options:");
        System.out.println("  -r, --register   Create a new user account interactively");
        System.out.println("  -h, --help       Display this help message");
        System.out.println();
        System.out.println("Environment variables:");
        System.out.println("  AUTH_DB_URL      JDBC database URL (default: in-memory H2 database)");
        System.out.println("  AUTH_DB_USER     Database user (default: sa)");
        System.out.println("  AUTH_DB_PASSWORD Database password (default: empty)");
        System.out.println("  AUTH_SOURCE_ID   Client source/IP identifier (default: cli-local)");
    }
}
