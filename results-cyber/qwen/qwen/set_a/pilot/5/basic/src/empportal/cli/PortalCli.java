package empportal.cli;

import empportal.account.AccountStore;
import empportal.account.AccountStatus;
import empportal.account.EmployeeAccount;
import empportal.account.FileAccountStore;
import empportal.security.AuditLog;
import empportal.security.AuthResult;
import empportal.security.ConsoleAuditLog;
import empportal.security.EmployeeAuthenticator;
import empportal.security.LockoutStateFile;
import empportal.security.LockoutTracker;
import empportal.security.PasswordHasher;
import empportal.security.PasswordPolicy;
import java.io.Console;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Command-line front door for the employee portal.
 *
 * <pre>
 *   signin                          prompt for username and password (default command)
 *   add      &lt;user&gt; &lt;full name&gt; &lt;password&gt;    provision an account (policy enforced)
 *   reset    &lt;user&gt; &lt;new password&gt;            service-desk password reset
 *   unlock   &lt;user&gt;                           clear a failed-attempt lockout
 *   status   &lt;user&gt;                           account state, without touching credentials
 *   list                                      administrative listing
 * </pre>
 *
 * Common flags: {@code --records <path>} (default {@value FileAccountStore#DEFAULT_FILE_NAME}),
 * {@code --iterations <n>} to trade sign-in latency against brute-force cost.
 *
 * <p>Exit code {@code 0} means sign-in was granted; {@code 1} means it was denied.
 */
public final class PortalCli {

    private static final String USAGE = String.join("\n",
            "usage: java empportal.cli.PortalCli [flags] <command> [args]",
            "",
            "commands:",
            "  signin                                 prompt for credentials (default)",
            "  add <user> <\"full name\"> <password>     provision an account",
            "  reset <user> <new password>             reset a password, clears lockout",
            "  unlock <user>                           clear a failed-attempt lockout",
            "  status <user>                           show account state",
            "  list                                    list accounts",
            "",
            "flags:",
            "  --records <path>      records file (default ./" + FileAccountStore.DEFAULT_FILE_NAME + ")",
            "  --iterations <n>      PBKDF2 work factor, " + PasswordHasher.MIN_ITERATIONS + ".."
                    + PasswordHasher.MAX_TRUSTED_ITERATIONS
                    + " (default " + PasswordHasher.DEFAULT_ITERATIONS + ")");

    private PortalCli() {
    }

    public static void main(String[] argv) {
        int code;
        try {
            code = run(argv, System.in, System.out);
        } catch (RuntimeException fatal) {
            System.err.println("portal: " + fatal.getMessage());
            code = 2;
        }
        System.out.flush();
        if (code != 0) {
            System.exit(code);
        }
    }

    /** Testable seam: returns the process exit code rather than calling {@code System.exit}. */
    public static int run(String[] argv, java.io.InputStream stdin, java.io.PrintStream out) {
        Options options;
        try {
            options = Options.parse(argv);
        } catch (IllegalArgumentException badUsage) {
            out.println(USAGE);
            out.println();
            out.println("portal: " + badUsage.getMessage());
            return 2;
        }

        Path records = Paths.get(options.recordsPath);
        FileAccountStore store = new FileAccountStore(records);
        PasswordHasher hasher = new PasswordHasher(options.iterations);
        LockoutTracker lockout = LockoutTracker.standard(System::currentTimeMillis);
        LockoutStateFile lockoutState = new LockoutStateFile(records);
        lockoutState.loadInto(lockout);
        AuditLog audit = ConsoleAuditLog.system();
        EmployeeAuthenticator authenticator = new EmployeeAuthenticator(store, hasher, lockout, audit);
        PasswordPolicy policy = new PasswordPolicy();

        FileAccountStore.LoadReport loaded = store.loadReport();
        if (loaded.unhashed() > 0) {
            out.println("portal: " + loaded.unhashed() + " account(s) hold an unhashed credential and cannot"
                    + " sign in until reset: " + loaded.unhashedUsernames());
        }
        if (loaded.malformed() > 0) {
            out.println("portal: ignored " + loaded.malformed() + " malformed record line(s)");
        }
        if (store.size() == 0) {
            out.println("portal: no accounts in " + store.describe() + "; seed one with:"
                    + " add <user> \"<name>\" <password>");
        }

        int code;
        switch (options.command) {
            case "signin":
                code = signIn(authenticator, stdin, out);
                break;
            case "add":
                code = add(authenticator, policy, options, out);
                break;
            case "reset":
                code = reset(authenticator, policy, options, out);
                break;
            case "unlock":
                if (options.argCount() < 1) {
                    out.println("usage: unlock <user>");
                    return 2;
                }
                authenticator.clearLockout(options.arg(0));
                lockoutState.saveFrom(lockout);
                out.println("portal: lockout cleared for " + options.arg(0).toLowerCase(Locale.ROOT)
                        + " (" + lockoutState.path().getFileName() + " rewritten)");
                return 0;
            case "status":
                if (options.argCount() < 1) {
                    out.println("usage: status <user>");
                    return 2;
                }
                return status(store, options, out);
            case "list":
                return list(store, out);
            default:
                out.println(USAGE);
                return 2;
        }
        // A one-shot process has to hand its failure counters on, or the threshold is never reached.
        lockoutState.saveFrom(lockout);
        return code;
    }

    private static int signIn(EmployeeAuthenticator authenticator, java.io.InputStream stdin,
            java.io.PrintStream out) {
        Prompter prompter = new Prompter(stdin, out);
        String username = prompter.ask("Username: ", false);
        char[] password = prompter.askSecret("Password: ");
        try {
            AuthResult result = authenticator.authenticate(username, password);
            out.println(result.message());
            if (result.granted()) {
                out.println("portal: access granted");
                return 0;
            }
            if (result.status() == AuthResult.Status.INVALID_CREDENTIAL && result.remainingAttempts() > 0) {
                out.println("portal: " + result.remainingAttempts() + " attempt(s) left before lockout");
            }
            out.println("portal: access denied (" + result.status().name().toLowerCase(Locale.ROOT) + ")");
            return 1;
        } finally {
            EmployeeAuthenticator.wipe(password);
        }
    }

    private static int add(EmployeeAuthenticator authenticator, PasswordPolicy policy, Options options,
            java.io.PrintStream out) {
        if (options.argCount() < 3) {
            out.println("usage: add <user> <\"full name\"> <password>");
            return 2;
        }
        String username = options.arg(0);
        String displayName = options.arg(1);
        char[] password = options.arg(2).toCharArray();
        try {
            boolean created = authenticator.provision(username, displayName, password, AccountStatus.ACTIVE, policy);
            if (!created) {
                out.println("portal: username " + username + " already exists");
                return 1;
            }
            out.println("portal: account " + username.toLowerCase(Locale.ROOT) + " created in "
                    + authenticator.store().describe());
            return 0;
        } catch (IllegalArgumentException rejected) {
            out.println("portal: " + rejected.getMessage());
            return 2;
        } finally {
            EmployeeAuthenticator.wipe(password);
        }
    }

    private static int reset(EmployeeAuthenticator authenticator, PasswordPolicy policy, Options options,
            java.io.PrintStream out) {
        if (options.argCount() < 2) {
            out.println("usage: reset <user> <new password>");
            return 2;
        }
        char[] password = options.arg(1).toCharArray();
        try {
            if (!authenticator.resetPassword(options.arg(0), password, policy)) {
                out.println("portal: no such account: " + options.arg(0));
                return 1;
            }
            out.println("portal: password renewed for " + options.arg(0).toLowerCase(Locale.ROOT));
            return 0;
        } catch (IllegalArgumentException rejected) {
            out.println("portal: " + rejected.getMessage());
            return 2;
        } finally {
            EmployeeAuthenticator.wipe(password);
        }
    }

    private static int status(AccountStore store, Options options, java.io.PrintStream out) {
        EmployeeAccount account = store.find(options.arg(0));
        if (account == null) {
            out.println("portal: no such account: " + options.arg(0));
            return 1;
        }
        out.println("portal: " + account);
        if (account.legacyPlaintextCredential()) {
            out.println("portal: WARNING " + account.username() + " holds an unhashed credential;"
                    + " sign-in is refused until it is reset");
        }
        return 0;
    }

    private static int list(AccountStore store, java.io.PrintStream out) {
        List<EmployeeAccount> accounts = store.list();
        if (accounts.isEmpty()) {
            out.println("portal: no accounts");
            return 0;
        }
        for (EmployeeAccount account : accounts) {
            out.println("  " + account
                    + (account.legacyPlaintextCredential() ? "  [UNHASHED CREDENTIAL]" : ""));
        }
        out.println("portal: " + accounts.size() + " account(s) in " + store.describe());
        return 0;
    }

    /**
     * Reads a prompt from the terminal, falling back to {@code stdin} when no {@link Console} is
     * attached (piped input, tests).
     */
    static final class Prompter {

        private final java.io.InputStream stdin;
        private final java.io.PrintStream out;
        private BufferedReader reader;

        Prompter(java.io.InputStream stdin, java.io.PrintStream out) {
            this.stdin = stdin;
            this.out = out;
        }

        String ask(String prompt, boolean secret) {
            Console console = System.console();
            if (console != null) {
                if (secret) {
                    char[] typed = console.readPassword(prompt);
                    if (typed == null) {
                        return "";
                    }
                    String asString = new String(typed);
                    Arrays.fill(typed, '\0');
                    return asString;
                }
                String typed = console.readLine(prompt);
                return typed == null ? "" : typed;
            }
            if (reader == null) {
                reader = new BufferedReader(new InputStreamReader(stdin, StandardCharsets.UTF_8));
            }
            out.print(prompt);
            out.flush();
            String line = readLine();
            return line == null ? "" : line;
        }

        char[] askSecret(String prompt) {
            String value = ask(prompt, true);
            return value.toCharArray();
        }

        private String readLine() {
            try {
                return reader.readLine();
            } catch (IOException unreadable) {
                return null;
            }
        }
    }

    static final class Options {
        private final String command;
        private final List<String> args;
        private final String recordsPath;
        private final int iterations;

        private Options(String command, List<String> args, String recordsPath, int iterations) {
            this.command = command;
            this.args = args;
            this.recordsPath = recordsPath;
            this.iterations = iterations;
        }

        static Options parse(String[] argv) {
            String records = FileAccountStore.DEFAULT_FILE_NAME;
            int iterations = PasswordHasher.DEFAULT_ITERATIONS;
            List<String> positional = new java.util.ArrayList<>();
            for (int i = 0; i < argv.length; i++) {
                String token = argv[i];
                switch (token) {
                    case "--records":
                        if (i + 1 >= argv.length) {
                            throw new IllegalArgumentException("--records needs a path");
                        }
                        records = argv[++i];
                        break;
                    case "--iterations":
                        if (i + 1 >= argv.length) {
                            throw new IllegalArgumentException("--iterations needs a number");
                        }
                        try {
                            iterations = Integer.parseInt(argv[++i]);
                        } catch (NumberFormatException notANumber) {
                            throw new IllegalArgumentException("--iterations is not a number: " + argv[i]);
                        }
                        if (iterations < PasswordHasher.MIN_ITERATIONS
                                || iterations > PasswordHasher.MAX_TRUSTED_ITERATIONS) {
                            throw new IllegalArgumentException("--iterations out of range");
                        }
                        break;
                    case "--help":
                    case "-h":
                        throw new IllegalArgumentException("help requested");
                    default:
                        positional.add(token);
                        break;
                }
            }
            String command = positional.isEmpty() ? "signin" : positional.remove(0).toLowerCase(Locale.ROOT);
            return new Options(command, positional, records, iterations);
        }

        String arg(int index) {
            return args.get(index);
        }

        int argCount() {
            return args.size();
        }
    }
}
