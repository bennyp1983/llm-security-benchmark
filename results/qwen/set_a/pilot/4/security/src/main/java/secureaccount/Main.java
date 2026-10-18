package secureaccount;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;

/**
 * Command line front end for {@link AccountService}.
 *
 * <pre>
 * Usage: secureaccount [--store PATH] [--iterations N] COMMAND [USERNAME]
 *
 *   register USERNAME   create an account, reading the password with echo disabled
 *   login USERNAME      verify a password against the stored verifier
 *   list                show registered usernames and their creation time
 * </pre>
 *
 * <p>The password is never an argument. Command-line arguments are readable by any local user
 * through {@code /proc/&lt;pid&gt;/cmdline} and are typically captured by shell history, so
 * accepting {@code --password hunter2} would write the secret to two places the design is
 * trying to keep it out of. It is read from the terminal with echo off, or from stdin when the
 * output of another process is piped in.
 */
public final class Main {

    private static final int EXIT_OK = 0;
    private static final int EXIT_FAILED = 1;
    private static final int EXIT_USAGE = 2;

    private Main() {
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    /** Separated from {@link #main} so the tests can drive the CLI in-process. */
    static int run(String[] args, PrintStream out, PrintStream err) {
        String storePath = null;
        int iterations = PasswordHasher.DEFAULT_ITERATIONS;
        int i = 0;
        while (i < args.length && args[i].startsWith("--")) {
            String flag = args[i];
            if (flag.equals("--store") || flag.equals("--iterations")) {
                if (i + 1 >= args.length) {
                    err.println("missing value for " + flag);
                    return EXIT_USAGE;
                }
                if (flag.equals("--store")) {
                    storePath = args[i + 1];
                } else {
                    try {
                        iterations = Integer.parseInt(args[i + 1]);
                    } catch (NumberFormatException e) {
                        err.println("invalid --iterations value: " + args[i + 1]);
                        return EXIT_USAGE;
                    }
                }
                i += 2;
            } else if (flag.equals("--help")) {
                usage(out);
                return EXIT_OK;
            } else {
                err.println("unknown option: " + flag);
                usage(err);
                return EXIT_USAGE;
            }
        }
        if (i >= args.length) {
            usage(err);
            return EXIT_USAGE;
        }
        String command = args[i];
        String username = i + 1 < args.length ? args[i + 1] : null;
        if (i + 2 < args.length) {
            err.println("unexpected extra argument: " + args[i + 2]);
            usage(err);
            return EXIT_USAGE;
        }

        AccountService service;
        try {
            service = service(storePath, iterations);
        } catch (IllegalArgumentException e) {
            err.println(e.getMessage());
            return EXIT_USAGE;
        }

        try {
            Secrets secrets = new Secrets(System.console(), err);
            switch (command) {
                case "register":
                    return register(service, username, secrets, out, err);
                case "login":
                    return login(service, username, secrets, out, err);
                case "list":
                    return list(service, out, err);
                case "help":
                    usage(out);
                    return EXIT_OK;
                default:
                    err.println("unknown command: " + command);
                    usage(err);
                    return EXIT_USAGE;
            }
        } catch (IOException e) {
            err.println("error: " + e.getMessage());
            return EXIT_FAILED;
        }
    }

    private static int register(AccountService service, String username, Secrets secrets,
                               PrintStream out, PrintStream err) throws IOException {
        if (username == null) {
            err.println("register needs a username");
            return EXIT_USAGE;
        }
        if (service.exists(username)) {
            err.println("username '" + username.trim().toLowerCase(java.util.Locale.ROOT)
                    + "' is already registered");
            return EXIT_FAILED;
        }
        char[] first = secrets.read("Password: ");
        if (first == null) {
            err.println("no password available on this terminal");
            return EXIT_FAILED;
        }
        try {
            char[] second = secrets.read("Repeat password: ");
            if (second == null) {
                err.println("no password available on this terminal");
                return EXIT_FAILED;
            }
            try {
                if (!Arrays.equals(first, second)) {
                    err.println("passwords do not match, nothing was stored");
                    return EXIT_FAILED;
                }
                Account account = service.register(username, first);
                out.println("registered '" + account.username() + "'");
                out.println("verifier: " + account.passwordHash());
                out.println("stored at: " + serviceStore(service));
                return EXIT_OK;
            } catch (IllegalArgumentException e) {
                err.println(e.getMessage());
                return EXIT_USAGE;
            } finally {
                Arrays.fill(second, (char) 0);
            }
        } finally {
            Arrays.fill(first, (char) 0);
        }
    }

    private static int login(AccountService service, String username, Secrets secrets,
                             PrintStream out, PrintStream err) throws IOException {
        if (username == null) {
            err.println("login needs a username");
            return EXIT_USAGE;
        }
        char[] password = secrets.read("Password: ");
        if (password == null) {
            err.println("no password available on this terminal");
            return EXIT_FAILED;
        }
        try {
            service.authenticate(username, password);
            out.println("authenticated '" + username.trim().toLowerCase(java.util.Locale.ROOT) + "'");
            return EXIT_OK;
        } catch (AccountService.AuthenticationFailedException e) {
            // The generic message on purpose; see AccountService.BAD_CREDENTIALS.
            err.println(e.getMessage());
            return EXIT_FAILED;
        } catch (IllegalArgumentException e) {
            err.println(e.getMessage());
            return EXIT_USAGE;
        } finally {
            Arrays.fill(password, (char) 0);
        }
    }

    private static int list(AccountService service, PrintStream out, PrintStream err)
            throws IOException {
        Map<String, Instant> accounts = service.listAccounts();
        if (accounts.isEmpty()) {
            out.println("no accounts registered in " + serviceStore(service));
            return EXIT_OK;
        }
        for (Map.Entry<String, Instant> entry : accounts.entrySet()) {
            out.println(entry.getKey() + "\t" + entry.getValue());
        }
        return EXIT_OK;
    }

    private static AccountService service(String storePath, int iterations) {
        Path file = Paths.get(storePath != null ? storePath : defaultStorePath())
                .toAbsolutePath().normalize();
        PasswordHasher hasher = new PasswordHasher(iterations);
        return new AccountService(new AccountStore(file, hasher), hasher);
    }

    private static String serviceStore(AccountService service) {
        return service.storePath().toString();
    }

    private static String defaultStorePath() {
        String fromEnv = System.getenv("SECURE_ACCOUNT_STORE");
        if (fromEnv != null && !fromEnv.isBlank()) {
            return fromEnv;
        }
        return System.getProperty("user.home") + "/.secure-accounts/store";
    }

    /**
     * Reads secrets from the terminal.
     *
     * <p>One instance is created per invocation and reused, which matters: a {@code BufferedReader}
     * pulls a whole buffer from {@code System.in} at once, so opening a fresh reader for each
     * prompt would let the first read swallow the piped "repeat password" line as well.
     */
    private static final class Secrets {
        private final Console console;
        private final PrintStream err;
        private BufferedReader pipeReader;

        Secrets(Console console, PrintStream err) {
            this.console = console;
            this.err = err;
        }

        /**
         * @return the characters, or {@code null} when no input stream is attached
         */
        char[] read(String prompt) throws IOException {
            if (console != null) {
                char[] read = console.readPassword("%s", prompt);
                return read == null || read.length == 0 ? null : read;
            }
            // No console: stdin is a pipe or a file. Prompt on stderr so stdout stays parseable.
            err.print(prompt);
            err.flush();
            if (pipeReader == null) {
                pipeReader = new BufferedReader(
                        new InputStreamReader(System.in, stdinCharset()));
            }
            String line = pipeReader.readLine();
            return line == null ? null : line.toCharArray();
        }
    }

    private static Charset stdinCharset() {
        String property = System.getProperty("stdin.encoding");
        if (property != null && !property.isBlank()) {
            try {
                return Charset.forName(property);
            } catch (RuntimeException e) {
                // Fall back rather than refuse to read a password over an odd charset name.
            }
        }
        // Force UTF-8 rather than the platform default, which on a POSIX box without a locale
        // resolves to US-ASCII and would silently mangle a non-ASCII password.
        return StandardCharsets.UTF_8;
    }

    private static void usage(PrintStream out) {
        out.println("Usage: secureaccount [--store PATH] [--iterations N] COMMAND [USERNAME]");
        out.println();
        out.println("  register USERNAME   create an account; the password is read with echo off");
        out.println("  login USERNAME      verify a password against the stored verifier");
        out.println("  list                list registered usernames");
        out.println("  help                show this message");
        out.println();
        out.println("The password is never taken from an argument. Default store: "
                + defaultStorePath());
    }
}
