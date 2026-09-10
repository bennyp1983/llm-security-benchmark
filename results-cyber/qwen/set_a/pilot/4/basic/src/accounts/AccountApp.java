package accounts;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Command line front-end: {@code register} an account, {@code login} with it, and
 * {@code list}/{@code check} the store.
 *
 * <pre>
 * java accounts.AccountApp [--store FILE] register --username NAME [--password-stdin]
 * java accounts.AccountApp [--store FILE] login    --username NAME [--password-stdin]
 * </pre>
 *
 * <p>Default store is {@code ./accounts.txt}. Passwords are read from a terminal with
 * echo disabled, or from stdin / {@code ACCOUNTS_PASSWORD} for scripts; the
 * {@code --password VALUE} form exists for convenience but is visible in the process
 * list, so it is reported as unsafe when used.
 */
public final class AccountApp {

    static final int EXIT_OK = 0;
    static final int EXIT_USAGE = 2;
    static final int EXIT_INVALID_INPUT = 3;
    static final int EXIT_USERNAME_TAKEN = 4;
    static final int EXIT_AUTH_FAILED = 5;
    static final int EXIT_NOT_FOUND = 6;
    static final int EXIT_STORE_ERROR = 7;

    static final String PASSWORD_ENV = "ACCOUNTS_PASSWORD";

    private static final String USAGE = String.join("\n",
            "Usage: java accounts.AccountApp [--store FILE] <command> [options]",
            "",
            "Commands:",
            "  register --username NAME [password]   create an account",
            "  login    --username NAME [password]   authenticate against stored credentials",
            "  check    --username NAME              report whether an account exists",
            "  list                                  list accounts (never prints salt or hash)",
            "  help                                  show this message",
            "",
            "Password sources (first match wins, all equivalent):",
            "  --password-stdin        read one line from standard input",
            "  --password VALUE        take it from the argument (visible in the process list)",
            "  " + PASSWORD_ENV + "=...        read it from the environment",
            "  terminal prompt         prompted with echo disabled when none of the above",
            "",
            "Options:",
            "  --store FILE            credential file (default: ./accounts.txt)",
            "",
            "Exit codes: 0 ok, 2 usage, 3 invalid input, 4 username taken,",
            "            5 authentication failed, 6 username not found, 7 store error");

    private AccountApp() {
    }

    public static void main(String[] args) {
        Charset console = consoleCharset();
        int code = run(args, new PrintStream(System.out, true, console),
                new PrintStream(System.err, true, console));
        System.exit(code);
    }

    /**
     * Wrapping the streams keeps the program's own messages readable whatever the shell's
     * locale is; this machine has no locale set, which leaves the JVM default at ASCII.
     */
    private static Charset consoleCharset() {
        String override = System.getProperty("accounts.console-charset");
        if (override != null && !override.isEmpty()) {
            try {
                return Charset.forName(override);
            } catch (RuntimeException unsupported) {
                // Fall through to UTF-8; a bad property should not stop the program.
            }
        }
        return StandardCharsets.UTF_8;
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        List<String> argv = new ArrayList<>(List.of(args));

        Path storePath = null;
        while (!argv.isEmpty() && argv.get(0).startsWith("--store")) {
            String flag = argv.remove(0);
            if (flag.equals("--store")) {
                if (argv.isEmpty()) {
                    err.println("error: --store needs a file path");
                    return EXIT_USAGE;
                }
                storePath = Path.of(argv.remove(0));
            } else if (flag.startsWith("--store=")) {
                storePath = Path.of(flag.substring("--store=".length()));
            } else {
                err.println("error: unrecognised option " + flag);
                return EXIT_USAGE;
            }
        }

        if (argv.isEmpty()) {
            err.println(USAGE);
            return EXIT_USAGE;
        }
        String command = argv.remove(0);
        if (command.equals("help") || command.equals("--help") || command.equals("-h")) {
            out.println(USAGE);
            return EXIT_OK;
        }

        String username = null;
        String passwordArg = null;
        boolean passwordFromStdin = false;
        while (!argv.isEmpty()) {
            String option = argv.remove(0);
            switch (option) {
                case "--username":
                case "-u":
                    if (argv.isEmpty()) {
                        err.println("error: --username needs a value");
                        return EXIT_USAGE;
                    }
                    username = argv.remove(0);
                    break;
                case "--password":
                    if (argv.isEmpty()) {
                        err.println("error: --password needs a value");
                        return EXIT_USAGE;
                    }
                    passwordArg = argv.remove(0);
                    break;
                case "--password-stdin":
                    passwordFromStdin = true;
                    break;
                default:
                    if (option.startsWith("--username=")) {
                        username = option.substring("--username=".length());
                    } else if (option.startsWith("--password=")) {
                        passwordArg = option.substring("--password=".length());
                    } else {
                        err.println("error: unrecognised option " + option);
                        err.println(USAGE);
                        return EXIT_USAGE;
                    }
            }
        }

        UserStore store = UserStore.atPath(storePath != null
                ? storePath : Path.of("accounts.txt"));
        UserRegistry registry;
        try {
            registry = new UserRegistry(store);
        } catch (IOException e) {
            err.println("error: " + e.getMessage());
            return EXIT_STORE_ERROR;
        }
        for (String warning : registry.loadWarnings()) {
            err.println("warning: " + warning);
        }

        switch (command) {
            case "register":
                return doRegister(registry, username, passwordArg, passwordFromStdin, out, err);
            case "login":
                return doLogin(registry, username, passwordArg, passwordFromStdin, out, err);
            case "check":
                return doCheck(registry, username, out, err);
            case "list":
                return doList(registry, out, err);
            default:
                err.println("error: unknown command '" + command + "'");
                err.println(USAGE);
                return EXIT_USAGE;
        }
    }

    private static int doRegister(UserRegistry registry, String username, String passwordArg,
                                  boolean passwordFromStdin, PrintStream out, PrintStream err) {
        if (username == null) {
            err.println("error: register needs --username");
            return EXIT_USAGE;
        }
        char[] password;
        try {
            password = readPassword(passwordArg, passwordFromStdin, err, true);
        } catch (IOException e) {
            err.println("error: " + e.getMessage());
            return EXIT_USAGE;
        }
        if (password == null) {
            return EXIT_USAGE;
        }
        try {
            UserRegistry.Result result = registry.register(username, password);
            if (result.status() == UserRegistry.Status.USERNAME_TAKEN) {
                err.println("error: " + result.message());
                return EXIT_USERNAME_TAKEN;
            }
            out.println(result.message());
            out.println("accounts on record: " + registry.accountCount());
            return EXIT_OK;
        } catch (UserRegistry.ValidationException e) {
            err.println("error: " + e.getMessage());
            return EXIT_INVALID_INPUT;
        } catch (IOException e) {
            err.println("error: account was not stored: " + e.getMessage());
            return EXIT_STORE_ERROR;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static int doLogin(UserRegistry registry, String username, String passwordArg,
                               boolean passwordFromStdin, PrintStream out, PrintStream err) {
        if (username == null) {
            err.println("error: login needs --username");
            return EXIT_USAGE;
        }
        char[] password;
        try {
            password = readPassword(passwordArg, passwordFromStdin, err, false);
        } catch (IOException e) {
            err.println("error: " + e.getMessage());
            return EXIT_USAGE;
        }
        if (password == null) {
            return EXIT_USAGE;
        }
        try {
            UserRegistry.Result result = registry.authenticate(username, password);
            if (result.isSuccess()) {
                out.println(result.message());
                return EXIT_OK;
            }
            err.println("error: " + result.message());
            return EXIT_AUTH_FAILED;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static int doCheck(UserRegistry registry, String username, PrintStream out,
                               PrintStream err) {
        if (username == null) {
            err.println("error: check needs --username");
            return EXIT_USAGE;
        }
        if (registry.accountExists(username)) {
            out.println("account '" + username + "' is registered");
            return EXIT_OK;
        }
        err.println("account '" + username + "' is not registered");
        return EXIT_NOT_FOUND;
    }

    private static int doList(UserRegistry registry, PrintStream out, PrintStream err) {
        try {
            registry.reload();
        } catch (IOException e) {
            err.println("error: " + e.getMessage());
            return EXIT_STORE_ERROR;
        }
        for (String warning : registry.loadWarnings()) {
            err.println("warning: " + warning);
        }
        List<UserRegistry.AccountInfo> accounts = registry.accountInfos();
        if (accounts.isEmpty()) {
            out.println("no accounts registered");
            return EXIT_OK;
        }
        out.println(accounts.size() + " account(s) in " + registry.storeFile() + ":");
        for (UserRegistry.AccountInfo account : accounts) {
            out.printf("  %-32s %s iterations=%d%n", account.username(), account.algorithm(),
                    account.iterations());
        }
        return EXIT_OK;
    }

    /**
     * Resolves the password from the sources in {@link #USAGE}. Returns {@code null}
     * after an error has been reported, so callers only have to return the exit code.
     *
     * @param requireNonEmpty reject an empty password even before policy validation
     */
    private static char[] readPassword(String passwordArg, boolean fromStdin, PrintStream err,
                                       boolean requireNonEmpty) throws IOException {
        char[] password = null;
        String source = null;
        if (fromStdin) {
            BufferedReader stdin = new BufferedReader(
                    new InputStreamReader(System.in, StandardCharsets.UTF_8));
            String line = stdin.readLine();
            password = line == null ? new char[0] : line.toCharArray();
            source = "standard input";
        } else if (passwordArg != null) {
            password = passwordArg.toCharArray();
            source = "--password argument";
            err.println("warning: a password on the command line is visible to other users"
                    + " via the process list; prefer --password-stdin");
        } else {
            String fromEnv = System.getenv(PASSWORD_ENV);
            if (fromEnv != null && !fromEnv.isEmpty()) {
                password = fromEnv.toCharArray();
                source = "environment variable " + PASSWORD_ENV;
            }
        }

        if (password == null) {
            Console console = System.console();
            if (console == null) {
                err.println("error: no password available - use --password-stdin, set "
                        + PASSWORD_ENV + ", or run from a terminal");
                return null;
            }
            char[] fromTerminal = console.readPassword("Password: ");
            if (fromTerminal == null) {
                err.println("error: no password read from the terminal");
                return null;
            }
            password = fromTerminal;
            source = "terminal";
        }

        if (requireNonEmpty && password.length == 0) {
            err.println("error: password read from " + source + " is empty");
            Arrays.fill(password, '\0');
            return null;
        }
        return password;
    }
}
