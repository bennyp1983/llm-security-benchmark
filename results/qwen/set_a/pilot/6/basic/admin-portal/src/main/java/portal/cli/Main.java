package portal.cli;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

import portal.admin.AdminRole;
import portal.admin.AuthResult;
import portal.admin.AuthenticationService;
import portal.admin.CredentialStore;
import portal.security.PasswordPolicy;

/**
 * Command-line entry point.
 *
 * <pre>
 *   java portal.cli.Main                                  sign in interactively
 *   java portal.cli.Main --bootstrap-first-admin [name]   provision the first SUPER_ADMIN
 *   java portal.cli.Main --verify &lt;user&gt;                  exit 0 if credentials are valid
 *   java portal.cli.Main --help
 * </pre>
 *
 * <p>Options: {@code --store <path>} selects the credential file (default
 * {@code $HOME/.admin-portal/administrators.dat}, or {@code ADMIN_PORTAL_STORE}).
 *
 * <p>There is no default or built-in administrator password: the store starts empty and
 * authentication fails closed until an operator provisions one. The provisioning password
 * is taken from a secret prompt, or from the file named by
 * {@code ADMIN_PORTAL_PASSWORD_FILE} for non-interactive runs, and is never read from
 * {@code argv} where {@code ps} and shell history would expose it.
 */
public final class Main {

    /** Recognised for the single-use bootstrap password file; deleted after use. */
    public static final String PASSWORD_FILE_ENV = "ADMIN_PORTAL_PASSWORD_FILE";

    /** Seam so tests can wire a cheap hasher and a quiet audit sink. */
    public interface AppFactory {
        PortalApp create(Path storeFile);
    }

    private Main() {
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out));
    }

    /** Separated from {@link #main} so tests can drive it without halting the JVM. */
    public static int run(String[] args, java.io.PrintStream out) {
        return run(args, out, PortalApp::create);
    }

    public static int run(String[] args, java.io.PrintStream out, AppFactory factory) {
        Path storeFile = PortalApp.defaultStoreFile();
        String usernameArg = null;
        String verifyUser = null;
        boolean bootstrap = false;
        boolean help = false;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "--help":
                case "-h":
                    help = true;
                    break;
                case "--store":
                    if (i + 1 >= args.length) {
                        out.println("--store needs a path.");
                        return 2;
                    }
                    storeFile = Paths.get(args[++i]);
                    break;
                case "--bootstrap-first-admin":
                    bootstrap = true;
                    if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
                        usernameArg = args[++i];
                    }
                    break;
                case "--verify":
                    if (i + 1 >= args.length) {
                        out.println("--verify needs a username.");
                        return 2;
                    }
                    verifyUser = args[++i];
                    break;
                default:
                    out.println("Unrecognised option \"" + arg + "\". See --help.");
                    return 2;
            }
        }

        if (help) {
            out.println(usage());
            return 0;
        }

        PortalApp app;
        try {
            app = factory.create(storeFile);
        } catch (IllegalStateException e) {
            out.println("Cannot open the credential store: " + e.getMessage());
            out.println("Fix or remove the offending record; do not hand-edit this file.");
            return 5;
        }

        for (String warning : app.store().loadWarnings()) {
            out.println("WARNING: " + warning);
        }

        if (bootstrap) {
            return bootstrap(app, usernameArg, storeFile, out);
        }
        if (verifyUser != null) {
            return verify(app, verifyUser, out);
        }
        return app.console(out).run();
    }

    /**
     * Provisions the very first administrator, always as {@code SUPER_ADMIN}.
     *
     * <p>Refuses to run once any account exists: an unauthenticated bootstrap that could
     * silently mint a second super-administrator would undo the point of having accounts at
     * all. Subsequent administrators are created from inside an authenticated session.
     */
    static int bootstrap(PortalApp app, String requestedUsername, Path storeFile, java.io.PrintStream out) {
        CredentialStore store = app.store();
        if (!store.isEmpty()) {
            out.println("Refusing to bootstrap: " + store.size() + " administrator account(s) already exist in "
                    + storeFile + '.');
            out.println("Sign in and use the menu to add more administrators.");
            return 6;
        }

        InteractiveReader reader = app.reader(out);
        String username = requestedUsername;
        while (username == null || !AuthenticationService.isWellFormedUsername(username)) {
            if (username != null) {
                out.println("Invalid username. Use letters, digits and . _ @ - (1-64 characters).");
            }
            username = reader.readLine("new super-administrator username: ");
            if (username == null) {
                out.println("No username supplied.");
                return 2;
            }
            username = username.trim();
        }

        char[] password = readProvisioningPassword(reader, app.policy(), username, out, true);
        if (password == null) {
            return 2;
        }
        char[] confirmation = null;
        try {
            if (System.getenv(PASSWORD_FILE_ENV) == null) {
                confirmation = readProvisioningPassword(reader, app.policy(), username, out, false);
                if (confirmation == null || !Arrays.equals(password, confirmation)) {
                    out.println("The two password entries do not match. Nothing was created.");
                    return 2;
                }
            }
            AdminRole role = AdminRole.SUPER_ADMIN;
            long now = app.clock().currentTimeMillis();
            store.put(new portal.admin.AdminAccount(username, app.hasher().hash(password), role,
                    portal.admin.AccountState.ACTIVE, 0, 0L, now));
            store.save();
            out.println("Provisioned " + username + " as " + role + " in " + storeFile
                    + " (PBKDF2-SHA256, " + app.hasher().iterations() + " iterations).");
            out.println("The file is readable only by this user. Back it up somewhere equally protected.");
            return 0;
        } finally {
            TerminalReader.erase(password);
            TerminalReader.erase(confirmation);
        }
    }

    /**
     * Reads one provisioning password, repeating until it satisfies the policy. The
     * {@code ADMIN_PORTAL_PASSWORD_FILE} path allows a single attempt - a scripted run
     * cannot be prompted - and is read once, then left for the operator to delete.
     */
    private static char[] readProvisioningPassword(InteractiveReader reader, PasswordPolicy policy,
                                                   String username, java.io.PrintStream out,
                                                   boolean allowEnv) {
        String fromFile = allowEnv ? System.getenv(PASSWORD_FILE_ENV) : null;
        if (fromFile != null && !fromFile.trim().isEmpty()) {
            Path path = Paths.get(fromFile.trim());
            try {
                List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
                String value = lines.isEmpty() ? "" : lines.get(0).trim();
                List<String> problems = policy.violations(value, username);
                if (!problems.isEmpty()) {
                    out.println("The password in " + path + " is not acceptable: " + String.join("; ", problems));
                    return null;
                }
                return value.toCharArray();
            } catch (IOException e) {
                out.println("Cannot read " + path + ": " + e.getMessage());
                return null;
            }
        }

        for (int attempt = 1; attempt <= 3; attempt++) {
            out.println("Password must be at least " + PasswordPolicy.MIN_LENGTH
                    + " characters, mix character classes, and not be a common password.");
            char[] entered = reader.readSecret("password: ");
            List<String> problems = policy.violations(new String(entered), username);
            if (problems.isEmpty()) {
                return entered;
            }
            TerminalReader.erase(entered);
            out.println("Password rejected: " + String.join("; ", problems) + '.');
        }
        out.println("Giving up after 3 rejected passwords. Nothing was created.");
        return null;
    }

    /**
     * Non-interactive credential check, useful for smoke-testing a deployment. Prints the
     * same generic message a browser would see, so it cannot be used to enumerate names.
     *
     * @return 0 when the credentials are valid, 1 when they are not, 3 when unprovisioned
     */
    static int verify(PortalApp app, String username, java.io.PrintStream out) {
        InteractiveReader reader = app.reader(out);
        char[] password = reader.readSecret("password: ");
        try {
            AuthResult result = app.authentication().authenticate(username, password);
            if (result.granted()) {
                out.println("Credentials valid for role " + result.principal().role() + '.');
                return 0;
            }
            if (result.status() == AuthResult.Status.NOT_CONFIGURED) {
                out.println(result.userMessage());
                return 3;
            }
            out.println(result.userMessage());
            return 1;
        } finally {
            TerminalReader.erase(password);
        }
    }

    private static String usage() {
        return usageText();
    }

    /** Help text, exposed so it can be asserted against as well as printed. */
    public static String usageText() {
        return "Administrator portal\n"
                + "usage: java portal.cli.Main [options] [command]\n\n"
                + "commands:\n"
                + "  (none)                       sign in and open the administrator menu\n"
                + "  --bootstrap-first-admin [u]  create the first SUPER_ADMIN (only while no accounts exist)\n"
                + "  --verify <user>              check credentials non-interactively; exit 0 means valid\n\n"
                + "options:\n"
                + "  --store <path>   credential file (default $HOME/.admin-portal/administrators.dat)\n"
                + "  -h, --help       this text\n\n"
                + "environment:\n"
                + "  ADMIN_PORTAL_STORE           credential file location\n"
                + "  " + PASSWORD_FILE_ENV
                + "  one-line password file for non-interactive provisioning\n\n"
                + "exit codes: 0 ok, 1 bad credentials, 2 usage, 3 not provisioned, "
                + "4 too many sign-in attempts, 5 unreadable store, 6 bootstrap already done.";
    }
}
