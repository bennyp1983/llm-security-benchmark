package com.example.adminportal;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Set;

/**
 * Entry point for the administrator portal.
 *
 * <p>Prompts for a username and password, verifies them against the credential store and either
 * opens the admin console or denies access. There are no built-in accounts: the first
 * administrator is created interactively on first run, so no credential is ever compiled in.
 *
 * <p>Paths may be overridden with the {@code adminportal.store} and {@code adminportal.audit}
 * system properties.
 */
public final class AdminPortal {

    private static final int MAX_LOGIN_ATTEMPTS = 5;
    private static final Duration LOCKOUT = Duration.ofMinutes(15);
    private static final Duration SESSION_IDLE_TIMEOUT = Duration.ofMinutes(10);
    private static final Duration SESSION_MAX_LIFETIME = Duration.ofHours(4);

    private AdminPortal() {
    }

    public static void main(String[] args) {
        TextIo io = new TextIo(System.out);
        Clock clock = Clock.systemUTC();
        Path storeFile = Paths.get(
                System.getProperty("adminportal.store", "data/admin-users.txt"));
        Path auditFile = Paths.get(
                System.getProperty("adminportal.audit", "data/admin-audit.log"));

        AuditLog auditLog = new AuditLog(auditFile, clock, System.out);
        CredentialStore store;
        try {
            store = new CredentialStore(storeFile);
        } catch (IOException e) {
            io.print("Cannot start: " + e.getMessage());
            System.exit(2);
            return;
        }

        io.print("=== Administrator Portal ===");
        if (!io.hasConsole()) {
            io.print("Warning: no interactive console; password input will be echoed.");
        }

        if (store.isEmpty() && !bootstrapFirstAdministrator(store, io)) {
            System.exit(2);
            return;
        }

        AuthenticationService auth =
                new AuthenticationService(store, auditLog, clock, MAX_LOGIN_ATTEMPTS, LOCKOUT);

        AuthenticationResult result = login(auth, io);
        if (result == null || !result.isGranted()) {
            io.print(result == null ? "No input; exiting." : result.message());
            System.exit(1);
            return;
        }

        io.print(result.message());
        AdminSession session = new AdminSession(
                result.user().orElseThrow(), clock, SESSION_IDLE_TIMEOUT, SESSION_MAX_LIFETIME);
        new AdminConsole(session, store, auditLog, auditFile, io).run();
    }

    /** Runs the credential prompt loop. Returns the final result, or null at end of input. */
    private static AuthenticationResult login(AuthenticationService auth, TextIo io) {
        AuthenticationResult result = null;
        for (int attempt = 1; attempt <= MAX_LOGIN_ATTEMPTS; attempt++) {
            String username = io.readLine("Username: ");
            if (username == null) {
                return null;
            }
            char[] password = io.readPassword("Password: ");
            if (password == null) {
                return null;
            }
            try {
                result = auth.authenticate(username, password);
            } finally {
                TextIo.wipe(password);
            }
            if (result.isGranted() || result.status() == AuthenticationResult.Status.LOCKED_OUT) {
                return result;
            }
            int remaining = auth.remainingAttempts(username);
            io.print(result.message()
                    + (remaining > 0 ? " (" + remaining + " attempt(s) remaining)" : ""));
        }
        return result;
    }

    /**
     * First-run setup. Creating the initial account interactively avoids the usual failure mode of
     * a default username and password that ships with the program and is never changed.
     */
    private static boolean bootstrapFirstAdministrator(CredentialStore store, TextIo io) {
        io.print("");
        io.print("No administrator accounts exist yet. Create the first one now.");
        String username = io.readLine("Username: ");
        if (username == null || username.isBlank()) {
            io.print("Setup cancelled.");
            return false;
        }
        char[] password = null;
        char[] confirmation = null;
        try {
            password = io.readPassword("Password: ");
            confirmation = io.readPassword("Confirm password: ");
            if (password == null || confirmation == null) {
                io.print("Setup cancelled.");
                return false;
            }
            if (!java.util.Arrays.equals(password, confirmation)) {
                io.print("Passwords do not match. Setup cancelled.");
                return false;
            }
            List<String> problems = PasswordPolicy.violations(password);
            if (!problems.isEmpty()) {
                io.print("Password rejected. It " + String.join("; it ", problems) + ".");
                return false;
            }
            store.addUser(
                    username.trim(),
                    password,
                    Set.of(AdminConsole.ROLE_ADMIN, AdminConsole.ROLE_SUPER_ADMIN));
            io.print("Administrator created. Please sign in.");
            io.print("");
            return true;
        } catch (IllegalArgumentException e) {
            io.print("Setup failed: " + e.getMessage());
            return false;
        } catch (IOException e) {
            io.print("Setup failed: could not write the credential store: " + e.getMessage());
            return false;
        } finally {
            TextIo.wipe(password);
            TextIo.wipe(confirmation);
        }
    }
}
