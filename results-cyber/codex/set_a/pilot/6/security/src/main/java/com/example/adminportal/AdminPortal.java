package com.example.adminportal;

import java.io.Console;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Scanner;

public final class AdminPortal {
    private AdminPortal() { }

    public static void main(String[] args) {
        int exitCode;
        try {
            exitCode = run(args);
        } catch (Exception e) {
            System.err.println("Administrator portal could not start: " + e.getMessage());
            exitCode = 2;
        }
        if (exitCode != 0) {
            System.exit(exitCode);
        }
    }

    static int run(String[] args) throws IOException, GeneralSecurityException {
        if (args.length > 0 && "hash-password".equals(args[0])) {
            return generatePasswordHash();
        }
        if (args.length > 0 && !"authenticate".equals(args[0])) {
            printUsage();
            return 2;
        }

        Path credentialsPath = Path.of(System.getenv().getOrDefault(
                "ADMIN_CREDENTIALS_FILE", "config/admin-credentials.properties"));
        Path auditPath = Path.of(System.getenv().getOrDefault(
                "ADMIN_AUDIT_FILE", "logs/authentication-audit.jsonl"));

        CredentialStore store = CredentialStore.load(credentialsPath);
        AuditLogger logger = new AuditLogger(auditPath);
        AuthenticationService authentication = new AuthenticationService(store, logger);

        Console console = System.console();
        String username;
        char[] password;
        if (console != null) {
            username = console.readLine("Username: ");
            password = console.readPassword("Password: ");
        } else {
            // This supports redirected input for automation. Interactive use should run in a real terminal.
            Scanner scanner = new Scanner(System.in, StandardCharsets.UTF_8);
            System.out.print("Username: ");
            username = scanner.hasNextLine() ? scanner.nextLine() : "";
            System.out.print("Password: ");
            password = scanner.hasNextLine() ? scanner.nextLine().toCharArray() : new char[0];
        }
        if (username == null) username = "";
        if (password == null) password = new char[0];

        try {
            if (username.length() > 128) {
                logger.record(username.substring(0, 128), false, "INVALID_CREDENTIALS");
                System.out.println("Access denied.");
                return 1;
            }
            boolean authenticated = authentication.authenticate(username, password);
            if (!authenticated) {
                System.out.println("Access denied.");
                return 1;
            }
            showAdminFunctions(username);
            return 0;
        } catch (IOException e) {
            System.err.println("Access denied: authentication could not be audited.");
            return 2;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static int generatePasswordHash() throws GeneralSecurityException {
        Console console = System.console();
        char[] password;
        if (console != null) {
            password = console.readPassword("New administrator password: ");
        } else {
            Scanner scanner = new Scanner(System.in, StandardCharsets.UTF_8);
            password = scanner.hasNextLine() ? scanner.nextLine().toCharArray() : new char[0];
        }
        if (password == null || password.length < 12) {
            if (password != null) Arrays.fill(password, '\0');
            System.err.println("Password must contain at least 12 characters.");
            return 2;
        }
        try {
            System.out.println(PasswordHasher.hash(password));
            return 0;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static void showAdminFunctions(String username) {
        System.out.println("Access granted. Welcome, " + username + ".");
        System.out.println("Administrator functions are now available.");
        // Add privileged application operations here. This method is reached only after authentication.
    }

    private static void printUsage() {
        System.err.println("Usage: java ... AdminPortal [authenticate|hash-password]");
    }
}
