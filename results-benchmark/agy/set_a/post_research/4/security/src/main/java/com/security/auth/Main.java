package com.security.auth;

import com.security.auth.config.SecurityConfig;
import com.security.auth.crypto.CryptoUtils;
import com.security.auth.database.DatabaseManager;
import com.security.auth.model.AuthenticationRequest;
import com.security.auth.model.AuthenticationResult;
import com.security.auth.model.RegistrationRequest;
import com.security.auth.model.RegistrationResult;
import com.security.auth.model.User;
import com.security.auth.service.AuthenticationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Command-line interface demonstrating secure registration, authentication,
 * and session management.
 *
 * Implements:
 * - Rule 1: All user inputs validated through service trust boundaries.
 * - Rule 2: Passwords are read securely without echo and never placed in args or printed.
 * - Rule 5: Passwords stored as char[] and wiped immediately from memory.
 * - Rule 6: Generic failure messages presented to user.
 */
public final class Main {

    private static final Logger log = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) {
        log.info("Starting Secure User Authentication System...");

        SecurityConfig config = SecurityConfig.fromEnvironment();
        try (DatabaseManager dbManager = new DatabaseManager(config);
             AuthenticationService authService = new AuthenticationService(config, dbManager);
             BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {

            Console console = System.console();
            System.out.println("=====================================================");
            System.out.println("   Secure User Registration & Authentication System  ");
            System.out.println("=====================================================");

            boolean running = true;
            while (running) {
                printMenu();
                System.out.print("Select an option (1-5): ");
                String choice = reader.readLine();
                if (choice == null) {
                    break;
                }
                choice = choice.trim();

                switch (choice) {
                    case "1" -> handleRegistration(reader, console, authService);
                    case "2" -> handleAuthentication(reader, console, authService);
                    case "3" -> handleSessionVerification(reader, authService);
                    case "4" -> handleLogout(reader, authService);
                    case "5", "exit", "quit" -> {
                        System.out.println("Exiting application.");
                        running = false;
                    }
                    default -> System.out.println("Invalid selection. Please choose an option from 1 to 5.");
                }
            }
        } catch (Exception e) {
            log.error("Fatal error in application lifecycle: {}", e.getMessage());
            System.err.println("A system error occurred. Please contact the administrator.");
            System.exit(1);
        }
    }

    private static void printMenu() {
        System.out.println("\n-----------------------------------------------------");
        System.out.println("1. Register new user account");
        System.out.println("2. Authenticate (Log in)");
        System.out.println("3. Verify active session");
        System.out.println("4. Revoke session (Log out)");
        System.out.println("5. Exit");
        System.out.println("-----------------------------------------------------");
    }

    private static void handleRegistration(BufferedReader reader, Console console, AuthenticationService authService) throws IOException {
        System.out.println("\n--- Register New User Account ---");
        System.out.print("Enter email address: ");
        String email = reader.readLine();

        System.out.print("Enter username (3-32 characters, alphanumeric/hyphen/underscore): ");
        String username = reader.readLine();

        System.out.print("Enter password (min 12 chars, upper/lower/digit/special): ");
        char[] password = readPasswordSecurely(reader, console);

        try {
            RegistrationRequest req = new RegistrationRequest(email, username, password);
            RegistrationResult result = authService.register(req, "127.0.0.1");

            System.out.println("\n[Response] " + result.getMessage());
            if (result.isSuccess()) {
                System.out.println("[Status] Account successfully created!");
            }
        } finally {
            CryptoUtils.wipe(password);
        }
    }

    private static void handleAuthentication(BufferedReader reader, Console console, AuthenticationService authService) throws IOException {
        System.out.println("\n--- Authenticate (Log In) ---");
        System.out.print("Enter username or email: ");
        String identifier = reader.readLine();

        System.out.print("Enter password: ");
        char[] password = readPasswordSecurely(reader, console);

        try {
            AuthenticationRequest req = new AuthenticationRequest(identifier, password, "127.0.0.1");
            AuthenticationResult result = authService.authenticate(req);

            System.out.println("\n[Response] " + result.getMessage());
            if (result.isSuccess()) {
                System.out.println("[Session Token] " + result.getSessionToken());
                System.out.println("[Set-Cookie]    " + result.getSessionCookie().toHeaderValue());
                System.out.println("[User Profile]  ID=" + result.getUser().getId() +
                        ", Username=" + result.getUser().getUsername() +
                        ", Email=" + SecurityConfig.maskIdentifier(result.getUser().getEmail()));
            }
        } finally {
            CryptoUtils.wipe(password);
        }
    }

    private static void handleSessionVerification(BufferedReader reader, AuthenticationService authService) throws IOException {
        System.out.println("\n--- Verify Active Session ---");
        System.out.print("Enter session token: ");
        String token = reader.readLine();
        if (token != null) {
            token = token.trim();
        }

        Optional<User> userOpt = authService.validateSession(token, "127.0.0.1");
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            System.out.println("\n[Status] Session is valid and active!");
            System.out.println("[User]   ID=" + user.getId() +
                    ", Username=" + user.getUsername() +
                    ", Email=" + SecurityConfig.maskIdentifier(user.getEmail()));
        } else {
            System.out.println("\n[Status] Session is invalid, expired, or source IP mismatch.");
        }
    }

    private static void handleLogout(BufferedReader reader, AuthenticationService authService) throws IOException {
        System.out.println("\n--- Revoke Session (Log Out) ---");
        System.out.print("Enter session token to revoke: ");
        String token = reader.readLine();
        if (token != null) {
            token = token.trim();
        }

        boolean revoked = authService.logout(token);
        if (revoked) {
            System.out.println("\n[Status] Session revoked successfully.");
        } else {
            System.out.println("\n[Status] Session was not found or already expired.");
        }
    }

    /**
     * Reads password from terminal without echoing characters if Console is available;
     * otherwise falls back to standard input reader.
     */
    private static char[] readPasswordSecurely(BufferedReader reader, Console console) throws IOException {
        if (console != null) {
            char[] pwd = console.readPassword();
            return (pwd != null) ? pwd : new char[0];
        } else {
            String line = reader.readLine();
            return (line != null) ? line.toCharArray() : new char[0];
        }
    }
}
