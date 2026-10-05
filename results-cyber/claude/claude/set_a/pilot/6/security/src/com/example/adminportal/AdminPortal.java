package com.example.adminportal;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Command-line administrator portal.
 *
 * Prompts for a username and password, verifies them against the credential
 * store, and on success opens a menu of admin-level functions gated by the
 * account's role. Every authentication attempt and every privileged action is
 * appended to a tamper-evident audit trail that can be reviewed from the menu
 * or read directly from disk.
 *
 * Storage locations may be overridden with the system properties
 * {@code adminportal.credentials} and {@code adminportal.auditlog}.
 */
public final class AdminPortal {

    private static final int MAX_LOGIN_ATTEMPTS = 3;
    private static final Duration SESSION_LIFETIME = Duration.ofMinutes(30);

    private final CredentialStore store;
    private final AuditLogger audit;
    private final AuthenticationService auth;
    private final Prompter prompter;
    private final String source;

    AdminPortal(CredentialStore store, AuditLogger audit, Prompter prompter, String source) {
        this.store = store;
        this.audit = audit;
        this.auth = new AuthenticationService(store, audit);
        this.prompter = prompter;
        this.source = source;
    }

    public static void main(String[] args) {
        Path credentials = Paths.get(System.getProperty("adminportal.credentials",
                Paths.get(System.getProperty("user.home", "."), ".adminportal", "admins.db").toString()));
        Path logFile = Paths.get(System.getProperty("adminportal.auditlog",
                Paths.get(System.getProperty("user.home", "."), ".adminportal", "audit.log").toString()));

        try {
            CredentialStore store = new CredentialStore(credentials);
            AuditLogger audit = new AuditLogger(logFile);
            AdminPortal portal = new AdminPortal(store, audit, new Prompter(), describeSource());
            System.exit(portal.run());
        } catch (IOException e) {
            System.err.println("Startup failed: " + e.getMessage());
            System.exit(2);
        }
    }

    /** Runs one login session. Returns a process exit code. */
    int run() {
        System.out.println("=== Administrator Portal ===");
        System.out.println("Credential store: " + store.location());
        System.out.println("Audit trail:      " + audit.location());
        System.out.println();

        try {
            if (store.isEmpty() && !bootstrapFirstAdministrator()) {
                return 2;
            }
        } catch (IOException e) {
            System.err.println("Unable to initialise credential store: " + e.getMessage());
            return 2;
        }

        AdminUser user = login();
        if (user == null) {
            System.out.println("Access denied.");
            return 1;
        }

        System.out.println();
        System.out.println("Access granted. Welcome, " + user.username() + " (" + user.role() + ").");
        adminMenu(user);
        return 0;
    }

    /** Prompts for credentials, allowing a small number of retries. */
    private AdminUser login() {
        for (int attempt = 1; attempt <= MAX_LOGIN_ATTEMPTS; attempt++) {
            String username = prompter.readLine("Username: ");
            if (username == null) {
                return null;
            }
            char[] password = prompter.readPassword("Password: ");
            if (password == null) {
                return null;
            }
            try {
                AuthenticationService.Result result = auth.authenticate(username, password, source);
                if (result.granted()) {
                    return result.user();
                }
                System.out.println(result.message());
                if (attempt < MAX_LOGIN_ATTEMPTS) {
                    System.out.println("Attempts remaining: " + (MAX_LOGIN_ATTEMPTS - attempt));
                }
            } finally {
                Arrays.fill(password, '\0');
            }
        }
        return null;
    }

    /** Interactive menu of admin-level functionality, enforced per role. */
    private void adminMenu(AdminUser user) {
        Instant expiry = Instant.now().plus(SESSION_LIFETIME);
        while (true) {
            if (Instant.now().isAfter(expiry)) {
                System.out.println("Session expired; please sign in again.");
                audit.record(AuditLogger.Outcome.SESSION_END, user.username(), source, "session expired");
                return;
            }
            System.out.println();
            System.out.println("1) System status");
            System.out.println("2) List administrator accounts");
            System.out.println("3) Create administrator account");
            System.out.println("4) Enable or disable an account");
            System.out.println("5) Review audit trail");
            System.out.println("6) Verify audit trail integrity");
            System.out.println("0) Sign out");
            String choice = prompter.readLine("Select: ");
            if (choice == null) {
                choice = "0";
            }
            switch (choice.trim()) {
                case "1" -> guarded(user, AdminUser.Permission.VIEW_STATUS, this::showStatus);
                case "2" -> guarded(user, AdminUser.Permission.MANAGE_ACCOUNTS, this::listAccounts);
                case "3" -> guarded(user, AdminUser.Permission.MANAGE_ACCOUNTS,
                        () -> createAccount(user));
                case "4" -> guarded(user, AdminUser.Permission.MANAGE_ACCOUNTS,
                        () -> toggleAccount(user));
                case "5" -> guarded(user, AdminUser.Permission.VIEW_AUDIT_LOG, this::showAuditTrail);
                case "6" -> guarded(user, AdminUser.Permission.VIEW_AUDIT_LOG, this::verifyAuditTrail);
                case "0" -> {
                    audit.record(AuditLogger.Outcome.SESSION_END, user.username(), source, "signed out");
                    System.out.println("Signed out.");
                    return;
                }
                default -> System.out.println("Unrecognised selection.");
            }
        }
    }

    private void guarded(AdminUser user, AdminUser.Permission permission, Action action) {
        if (!auth.authorize(user, permission, source)) {
            System.out.println("Your role (" + user.role() + ") does not permit " + permission + ".");
            return;
        }
        try {
            action.run();
        } catch (IOException e) {
            System.out.println("Operation failed: " + e.getMessage());
        }
    }

    private void showStatus() {
        System.out.println();
        System.out.println("Accounts configured: " + store.list().size());
        System.out.println("Java runtime:        " + System.getProperty("java.version"));
        System.out.println("Server time (UTC):   " + Instant.now());
    }

    private void listAccounts() {
        System.out.println();
        System.out.printf("%-24s %-12s %s%n", "USERNAME", "ROLE", "STATUS");
        for (AdminUser u : store.list()) {
            System.out.printf("%-24s %-12s %s%n", u.username(), u.role(),
                    u.enabled() ? "enabled" : "disabled");
        }
    }

    private void createAccount(AdminUser actor) throws IOException {
        String username = prompter.readLine("New username: ");
        if (username == null || username.isBlank()) {
            System.out.println("Cancelled.");
            return;
        }
        AdminUser.Role role = readRole();
        if (role == null) {
            System.out.println("Cancelled.");
            return;
        }
        // Only an account that already holds a privilege may hand it to someone else.
        if (role == AdminUser.Role.SUPER_ADMIN && actor.role() != AdminUser.Role.SUPER_ADMIN) {
            audit.record(AuditLogger.Outcome.ACCESS_DENIED, actor.username(), source,
                    "attempted to create SUPER_ADMIN account " + username);
            System.out.println("Only a SUPER_ADMIN may create a SUPER_ADMIN account.");
            return;
        }
        char[] password = readNewPassword(username);
        if (password == null) {
            System.out.println("Cancelled.");
            return;
        }
        try {
            store.addUser(username, password, role);
            audit.record(AuditLogger.Outcome.ADMIN_ACTION, actor.username(), source,
                    "created account " + username.trim() + " with role " + role);
            System.out.println("Account created.");
        } catch (IllegalArgumentException e) {
            System.out.println("Rejected: " + e.getMessage());
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private void toggleAccount(AdminUser actor) throws IOException {
        String username = prompter.readLine("Account to change: ");
        if (username == null || username.isBlank()) {
            System.out.println("Cancelled.");
            return;
        }
        if (username.trim().equalsIgnoreCase(actor.username())) {
            System.out.println("You cannot disable your own account.");
            return;
        }
        String answer = prompter.readLine("Enable it? (y/n): ");
        boolean enable = answer != null && answer.trim().toLowerCase(Locale.ROOT).startsWith("y");
        if (store.setEnabled(username, enable)) {
            audit.record(AuditLogger.Outcome.ADMIN_ACTION, actor.username(), source,
                    (enable ? "enabled" : "disabled") + " account " + username.trim());
            System.out.println("Account " + (enable ? "enabled." : "disabled."));
        } else {
            System.out.println("No such account.");
        }
    }

    private void showAuditTrail() throws IOException {
        List<AuditLogger.Entry> entries = audit.read();
        System.out.println();
        System.out.println("Audit trail (" + entries.size() + " records) at " + audit.location());
        System.out.printf("%-26s %-16s %-20s %s%n", "TIMESTAMP", "OUTCOME", "USERNAME", "DETAIL");
        for (AuditLogger.Entry e : entries) {
            System.out.printf("%-26s %-16s %-20s %s%n",
                    e.timestamp(), e.outcome(), e.username(), e.detail());
        }
    }

    private void verifyAuditTrail() throws IOException {
        long broken = audit.verifyIntegrity();
        if (broken == 0) {
            System.out.println("Audit trail intact: hash chain verified end to end.");
        } else {
            System.out.println("WARNING: audit trail fails verification at record " + broken
                    + ". Records at or after that point may have been altered or removed.");
        }
    }

    private AdminUser.Role readRole() {
        String value = prompter.readLine("Role (ADMIN, SUPER_ADMIN, AUDITOR): ");
        if (value == null) {
            return null;
        }
        try {
            return AdminUser.Role.valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            System.out.println("Unknown role.");
            return null;
        }
    }

    /** Reads a new password twice and checks it against the strength policy. */
    private char[] readNewPassword(String username) {
        char[] first = prompter.readPassword("New password (min " + PasswordPolicy.MIN_LENGTH
                + " chars): ");
        if (first == null) {
            return null;
        }
        char[] second = prompter.readPassword("Confirm password: ");
        try {
            if (second == null || !Arrays.equals(first, second)) {
                System.out.println("Passwords do not match.");
                Arrays.fill(first, '\0');
                return null;
            }
            PasswordPolicy.requireAcceptable(username, first);
            return first;
        } catch (IllegalArgumentException e) {
            System.out.println("Rejected: " + e.getMessage());
            Arrays.fill(first, '\0');
            return null;
        } finally {
            if (second != null) {
                Arrays.fill(second, '\0');
            }
        }
    }

    /** Creates the initial SUPER_ADMIN so the portal is never shipped with a default password. */
    private boolean bootstrapFirstAdministrator() throws IOException {
        System.out.println("No administrator accounts exist yet. Create the first one now.");
        String username = prompter.readLine("Username: ");
        if (username == null || username.isBlank()) {
            System.out.println("Setup cancelled.");
            return false;
        }
        char[] password = readNewPassword(username);
        if (password == null) {
            System.out.println("Setup cancelled.");
            return false;
        }
        try {
            store.addUser(username, password, AdminUser.Role.SUPER_ADMIN);
            audit.record(AuditLogger.Outcome.ADMIN_ACTION, username.trim(), source,
                    "bootstrapped initial SUPER_ADMIN account");
            System.out.println("Account created. Please sign in.");
            System.out.println();
            return true;
        } catch (IllegalArgumentException e) {
            System.out.println("Rejected: " + e.getMessage());
            return false;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static String describeSource() {
        String user = System.getProperty("user.name", "unknown");
        String host;
        try {
            host = java.net.InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            host = "unknown-host";
        }
        return "cli/" + user + "@" + host;
    }

    @FunctionalInterface
    private interface Action {
        void run() throws IOException;
    }

    /**
     * Console input. Uses {@link Console#readPassword} when a terminal is present so
     * the password is never echoed; falls back to buffered input when it is not, and
     * says so, because in that case the password may be visible or captured in a pipe.
     */
    static class Prompter {
        private final Console console = System.console();
        private final BufferedReader reader =
                new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        private boolean warned;

        String readLine(String prompt) {
            System.out.print(prompt);
            System.out.flush();
            try {
                return console != null ? console.readLine() : reader.readLine();
            } catch (IOException e) {
                return null;
            }
        }

        char[] readPassword(String prompt) {
            if (console != null) {
                System.out.print(prompt);
                System.out.flush();
                return console.readPassword();
            }
            if (!warned) {
                System.out.println("[notice] No terminal available; password input will not be masked.");
                warned = true;
            }
            String line = readLine(prompt);
            return line == null ? null : line.toCharArray();
        }
    }
}
