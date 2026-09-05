package portal.cli;

import java.io.PrintStream;
import java.util.List;
import java.util.Locale;

import portal.admin.AccessDeniedException;
import portal.admin.AdminGate;
import portal.admin.AdminOperations;
import portal.admin.AdminPrincipal;
import portal.admin.AdminRole;
import portal.admin.AuthResult;
import portal.admin.AuthenticationService;
import portal.admin.SessionManager;
import portal.security.PasswordPolicy;

/**
 * Sign-in prompt plus the role-gated menu. Two things are deliberate:
 *
 * <ul>
 *   <li>The console only ever holds the session token. The principal is re-derived from it
 *       on every command by {@link AdminGate}, so revoking a session takes effect on the
 *       very next keystroke rather than when the menu is redrawn.</li>
 *   <li>Failures print {@link AuthResult#GENERIC_FAILURE} and nothing else. How many tries
 *       remain is written to the audit trail, not to the screen, because "2 attempts
 *       remaining for user alice" confirms that alice exists.</li>
 * </ul>
 */
public final class AdminConsole {

    /** Client-side backstop so a stuck operator cannot spin against the lockout forever. */
    public static final int MAX_SIGNIN_TURNS = 5;

    private final AuthenticationService authentication;
    private final SessionManager sessions;
    private final AdminOperations operations;
    private final AdminGate gate;
    private final InteractiveReader reader;
    private final PrintStream out;

    private String sessionToken;

    public AdminConsole(AuthenticationService authentication, SessionManager sessions,
                        AdminOperations operations, AdminGate gate,
                        InteractiveReader reader, PrintStream out) {
        this.authentication = authentication;
        this.sessions = sessions;
        this.operations = operations;
        this.gate = gate;
        this.reader = reader;
        this.out = out;
    }

    /** @return process exit code: 0 clean sign-out, 3 not provisioned, 4 too many failures */
    public int run() {
        printBanner();
        for (int attempt = 1; attempt <= MAX_SIGNIN_TURNS; attempt++) {
            AuthResult result = promptForCredentials();
            if (result.granted()) {
                sessionToken = sessions.issue(result.principal()).tokenId();
                out.println();
                out.println("Access granted. Signed in as " + result.principal() + '.');
                return menuLoop();
            }
            out.println(result.userMessage());
            if (result.retryAfterSeconds() > 0) {
                out.println("Retry is possible in " + result.retryAfterSeconds() + " seconds.");
            }
            if (result.status() == AuthResult.Status.NOT_CONFIGURED) {
                out.println("Nothing to sign in to yet. Re-run with --bootstrap-first-admin.");
                return 3;
            }
        }
        out.println("Sign-in has been stopped for this terminal after " + MAX_SIGNIN_TURNS + " attempts.");
        return 4;
    }

    private AuthResult promptForCredentials() {
        String username = reader.readLine("username: ");
        char[] password = reader.readSecret("password: ");
        try {
            if (username == null) {
                return AuthResult.of(AuthResult.Status.INVALID_INPUT, AuthResult.GENERIC_FAILURE);
            }
            return authentication.authenticate(username.trim(), password);
        } finally {
            TerminalReader.erase(password);
        }
    }

    private int menuLoop() {
        while (true) {
            out.println();
            out.println(menu());
            String command = reader.readLine("admin> ");
            if (command == null) {
                signOut();
                return 0;
            }
            command = command.trim().toLowerCase(Locale.ROOT);
            if (command.isEmpty()) {
                continue;
            }
            switch (command) {
                case "q":
                case "signout":
                case "logout":
                    signOut();
                    return 0;
                case "whoami":
                    whoami();
                    break;
                case "1":
                    listAccounts();
                    break;
                case "2":
                    createAdministrator();
                    break;
                case "3":
                    resetPassword();
                    break;
                case "4":
                    changeState(true);
                    break;
                case "5":
                    changeState(false);
                    break;
                case "6":
                    changeRole();
                    break;
                case "7":
                    sessionsView();
                    break;
                case "8":
                    auditView();
                    break;
                default:
                    out.println("Unrecognised choice \"" + command + "\". Enter a number from the menu, "
                            + "whoami, or q.");
            }
        }
    }

    private String menu() {
        return "Administrator portal\n"
                + "  1. List administrator accounts\n"
                + "  2. Create an administrator\n"
                + "  3. Reset an administrator password\n"
                + "  4. Enable an account\n"
                + "  5. Disable an account\n"
                + "  6. Change an account role\n"
                + "  7. List / revoke live sessions\n"
                + "  8. Review recent audit events\n"
                + "  whoami  show my identity and permissions\n"
                + "  q       sign out";
    }

    private void whoami() {
        try {
            AdminPrincipal me = gate.requireSignedIn(sessionToken);
            out.println("signed in as " + me.username() + ", role " + me.role());
            out.println("permissions:");
            for (AdminRole.Permission permission : me.permissions()) {
                out.println("  - " + permission + " (" + permission.description() + ')');
            }
        } catch (AccessDeniedException e) {
            out.println(e.getMessage());
            sessionToken = null;
        }
    }

    private void listAccounts() {
        guarded("list accounts", () -> {
            List<AdminOperations.AccountView> accounts = operations.listAccounts(sessionToken);
            if (accounts.isEmpty()) {
                out.println("No administrator accounts are configured.");
                return;
            }
            for (AdminOperations.AccountView account : accounts) {
                out.println("  " + account);
            }
        });
    }

    private void createAdministrator() {
        String username = reader.readLine("new username: ");
        if (username == null) {
            return;
        }
        out.println("Password must be at least " + PasswordPolicy.MIN_LENGTH
                + " characters and mix character classes.");
        char[] first = reader.readSecret("new password: ");
        char[] second = reader.readSecret("confirm password: ");
        AdminRole role = readRole();
        try {
            guarded("create administrator", () -> report(operations.createAdministrator(
                    sessionToken, username.trim(), first, second, role)));
        } finally {
            TerminalReader.erase(first);
            TerminalReader.erase(second);
        }
    }

    private void resetPassword() {
        String username = reader.readLine("account to reset: ");
        if (username == null) {
            return;
        }
        char[] first = reader.readSecret("new password: ");
        char[] second = reader.readSecret("confirm password: ");
        try {
            guarded("reset password", () -> report(operations.resetPassword(
                    sessionToken, username.trim(), first, second)));
        } finally {
            TerminalReader.erase(first);
            TerminalReader.erase(second);
        }
    }

    private void changeState(boolean enable) {
        String username = reader.readLine(enable ? "account to enable: " : "account to disable: ");
        if (username == null) {
            return;
        }
        guarded(enable ? "enable account" : "disable account", () -> report(enable
                ? operations.enableAccount(sessionToken, username.trim())
                : operations.disableAccount(sessionToken, username.trim())));
    }

    private void changeRole() {
        String username = reader.readLine("account to change: ");
        if (username == null) {
            return;
        }
        AdminRole role = readRole();
        if (role == null) {
            out.println("No role selected; nothing changed.");
            return;
        }
        guarded("change role", () -> report(operations.changeRole(sessionToken, username.trim(), role)));
    }

    private void sessionsView() {
        guarded("list sessions", () -> {
            List<String> live = operations.liveSessions(sessionToken);
            if (live.isEmpty()) {
                out.println("No live sessions.");
                return;
            }
            for (String line : live) {
                out.println("  " + line);
            }
            String target = reader.readLine("revoke all sessions for a username (blank for none): ");
            if (target != null && !target.trim().isEmpty()) {
                report(operations.revokeSessions(sessionToken, target.trim()));
            }
        });
    }

    private void auditView() {
        guarded("review audit events", () -> {
            List<String> events = operations.recentAuditEvents(sessionToken, 40);
            if (events.isEmpty()) {
                out.println("This audit sink does not retain history for review.");
                return;
            }
            for (String line : events) {
                out.println("  " + line);
            }
        });
    }

    private AdminRole readRole() {
        out.println("roles: " + AdminRole.ALL);
        String entered = reader.readLine("role [HELPDESK]: ");
        if (entered == null) {
            return AdminRole.HELPDESK;
        }
        entered = entered.trim().toUpperCase(Locale.ROOT);
        if (entered.isEmpty()) {
            return AdminRole.HELPDESK;
        }
        try {
            return AdminRole.valueOf(entered);
        } catch (IllegalArgumentException e) {
            out.println("Unknown role \"" + entered + "\"; using HELPDESK.");
            return AdminRole.HELPDESK;
        }
    }

    private void report(AdminOperations.OperationOutcome outcome) {
        out.println(outcome.message());
    }

    /**
     * Runs a privileged action, converting an authorization failure into a readable line.
     * A missing session is terminal for the menu: the token is dropped so the next command
     * cannot keep retrying with a dead credential.
     */
    private void guarded(String what, Runnable action) {
        try {
            action.run();
        } catch (AccessDeniedException e) {
            out.println("ACCESS DENIED: " + e.getMessage());
            if (e.permission() == null) {
                out.println("Your session is gone; commands now need a fresh sign-in.");
                sessionToken = null;
            }
        } catch (IllegalStateException e) {
            out.println("COULD NOT COMPLETE " + what + ": " + e.getMessage());
        }
    }

    private void signOut() {
        if (sessionToken != null) {
            sessions.revoke(sessionToken);
            sessionToken = null;
            out.println("Signed out.");
        }
    }

    private void printBanner() {
        out.println("Administrator portal - privileged access.");
        out.println("Every sign-in attempt, success or failure, is recorded in the audit trail.");
        if (!reader.supportsSecretEntry()) {
            out.println("NOTE: passwords will be echoed unless a terminal or "
                    + "ADMIN_PORTAL_PASSWORD_FILE is available.");
        }
        out.println();
    }
}
