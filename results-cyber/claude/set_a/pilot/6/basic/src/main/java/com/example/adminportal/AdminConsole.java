package com.example.adminportal;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/**
 * The admin-level functionality reached only after successful authentication.
 *
 * <p>Every action re-checks the session and the role it requires, rather than trusting that the
 * menu was only rendered to someone entitled to see it.
 */
final class AdminConsole {

    static final String ROLE_ADMIN = "ADMIN";
    static final String ROLE_SUPER_ADMIN = "SUPER_ADMIN";

    private final AdminSession session;
    private final CredentialStore store;
    private final AuditLog auditLog;
    private final Path auditLogFile;
    private final TextIo io;

    AdminConsole(
            AdminSession session,
            CredentialStore store,
            AuditLog auditLog,
            Path auditLogFile,
            TextIo io) {
        this.session = session;
        this.store = store;
        this.auditLog = auditLog;
        this.auditLogFile = auditLogFile;
        this.io = io;
    }

    void run() {
        io.print("");
        io.print("Welcome, " + session.user().username()
                + " (roles: " + String.join(", ", session.user().roles()) + ")");
        io.print("Session " + session.id().substring(0, 8) + "... started.");

        while (session.isActive()) {
            printMenu();
            String choice = io.readLine("> ");
            if (choice == null) {
                break;
            }
            if (!session.isActive()) {
                break;
            }
            session.touch();
            switch (choice.trim()) {
                case "1" -> showSystemStatus();
                case "2" -> listAdministrators();
                case "3" -> createAdministrator();
                case "4" -> showRecentAuditEntries();
                case "5" -> {
                    logout();
                    return;
                }
                default -> io.print("Unrecognised option.");
            }
        }
        io.print("Session expired. Please sign in again.");
        auditLog.record(session.user().username(), "SESSION_EXPIRED");
    }

    private void printMenu() {
        io.print("");
        io.print("Administrator menu");
        io.print("  1) System status");
        io.print("  2) List administrator accounts        [" + ROLE_ADMIN + "]");
        io.print("  3) Create administrator account       [" + ROLE_SUPER_ADMIN + "]");
        io.print("  4) Recent authentication audit events [" + ROLE_ADMIN + "]");
        io.print("  5) Log out");
    }

    /** Returns true and logs a denial when the session lacks {@code role}. */
    private boolean denied(String role, String action) {
        if (session.isAuthorised(role)) {
            return false;
        }
        auditLog.record(session.user().username(), "DENIED_ACTION:" + action);
        io.print("Denied: this action requires the " + role + " role.");
        return true;
    }

    private void showSystemStatus() {
        io.print("Portal status: online");
        io.print("Administrator accounts configured: " + store.usernames().size());
        io.print("Credential hashing: PBKDF2-HMAC-SHA256, per-user salt");
    }

    private void listAdministrators() {
        if (denied(ROLE_ADMIN, "LIST_ADMINS")) {
            return;
        }
        io.print("Administrator accounts:");
        for (String username : store.usernames()) {
            store.find(username).ifPresent(user -> io.print(
                    "  - " + user.username()
                            + " roles=" + String.join(",", user.roles())
                            + " enabled=" + user.enabled()));
        }
        auditLog.record(session.user().username(), "LIST_ADMINS");
    }

    private void createAdministrator() {
        if (denied(ROLE_SUPER_ADMIN, "CREATE_ADMIN")) {
            return;
        }
        String username = io.readLine("New administrator username: ");
        if (username == null || username.isBlank()) {
            io.print("Cancelled.");
            return;
        }
        boolean superAdmin = "y".equalsIgnoreCase(
                String.valueOf(io.readLine("Grant " + ROLE_SUPER_ADMIN + "? [y/N]: ")).trim());
        Set<String> roles = superAdmin ? Set.of(ROLE_ADMIN, ROLE_SUPER_ADMIN) : Set.of(ROLE_ADMIN);

        char[] password = null;
        char[] confirmation = null;
        try {
            password = io.readPassword("New password: ");
            confirmation = io.readPassword("Confirm password: ");
            if (password == null || confirmation == null) {
                io.print("Cancelled.");
                return;
            }
            if (!java.util.Arrays.equals(password, confirmation)) {
                io.print("Passwords do not match. No account created.");
                return;
            }
            List<String> problems = PasswordPolicy.violations(password);
            if (!problems.isEmpty()) {
                io.print("Password rejected. It " + String.join("; it ", problems) + ".");
                return;
            }
            store.addUser(username.trim(), password, roles);
            io.print("Created administrator '" + username.trim().toLowerCase(java.util.Locale.ROOT)
                    + "' with roles " + roles + ".");
            auditLog.record(session.user().username(), "CREATE_ADMIN:" + username.trim());
        } catch (IllegalArgumentException e) {
            io.print("Could not create account: " + e.getMessage());
        } catch (IOException e) {
            io.print("Could not write the credential store: " + e.getMessage());
        } finally {
            TextIo.wipe(password);
            TextIo.wipe(confirmation);
        }
    }

    private void showRecentAuditEntries() {
        if (denied(ROLE_ADMIN, "VIEW_AUDIT")) {
            return;
        }
        try {
            if (!Files.exists(auditLogFile)) {
                io.print("No audit entries yet.");
                return;
            }
            List<String> lines = Files.readAllLines(auditLogFile, StandardCharsets.UTF_8);
            io.print("Most recent authentication events:");
            for (String line : lines.subList(Math.max(0, lines.size() - 10), lines.size())) {
                io.print("  " + line);
            }
        } catch (IOException e) {
            io.print("Could not read the audit log: " + e.getMessage());
        }
        auditLog.record(session.user().username(), "VIEW_AUDIT");
    }

    private void logout() {
        session.terminate();
        auditLog.record(session.user().username(), "LOGOUT");
        io.print("Logged out.");
    }
}
