package portal.auth;

import java.io.IOException;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Locale;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Command-line sign-in screen for the employee portal.
 *
 * <p>Run with {@code --help} for the options. With no options it starts with three demo employees
 * so the lockout can be tried out immediately.
 */
public final class EmployeePortalApp {

    private static final int DEMO_MAX_FAILURES = 5;
    private static final int DEMO_LOCK_MINUTES = 15;

    private final CredentialStore store;
    private final LoginAttemptTracker tracker;
    private final CredentialPrompter prompter;
    private final Authenticator authenticator;
    private final Clock clock;

    public EmployeePortalApp(CredentialStore store, LoginAttemptTracker tracker,
                             Authenticator authenticator, CredentialPrompter prompter, Clock clock) {
        this.store = store;
        this.tracker = tracker;
        this.prompter = prompter;
        this.authenticator = authenticator;
        this.clock = clock;
    }

    /** @return process exit code: 0 when the session ended cleanly */
    public int run() {
        greet();
        while (true) {
            String input;
            try {
                input = prompter.readLine("username>");
            } catch (IOException e) {
                System.out.println("(input failed: " + e.getMessage() + ")");
                return 1;
            }
            if (input == null) {
                System.out.println();
                return 0;
            }
            if (input.isBlank()) {
                continue;
            }
            // The typed text goes to sign-in as it arrived: rewriting it here would quietly undo
            // the rule that a tab is not a space. Only command words are trimmed.
            String command = firstWord(input.strip()).toLowerCase(Locale.ROOT);
            switch (command) {
                case "quit", "exit" -> {
                    return 0;
                }
                case "help" -> printHelp();
                case "add" -> addEmployee(input.strip());
                case "status" -> showStatus(input.strip());
                case "unlock" -> unlock(input.strip());
                default -> signIn(input);
            }
        }
    }

    private void signIn(String username) {
        char[] password = null;
        try {
            password = prompter.readSecret("password>");
            if (password == null) {
                System.out.println();
                return;
            }
            LoginResult result = authenticator.login(username, password);
            System.out.println(result.message());
            if (result.isSuccess()) {
                EmployeeRecord record = recordFor(username);
                System.out.println(record == null ? "Welcome."
                        : "Welcome, " + record.displayName() + ".");
            } else if (result.lockSecondsRemaining() > 0) {
                System.out.println("Try again in " + human(result.lockSecondsRemaining()) + ".");
            }
        } catch (IOException e) {
            System.out.println("(input failed: " + e.getMessage() + ")");
        } catch (RuntimeException e) {
            // Anything unexpected is a refusal, never an accidental grant.
            System.out.println(AuthResult.INVALID_CREDENTIALS.message());
            System.err.println("sign-in aborted: " + e);
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    /** Looks the typed name up the same way the authenticator does; null when it is unusable. */
    private EmployeeRecord recordFor(String typedUsername) {
        try {
            return store.find(CredentialValidator.canonicalUsername(typedUsername));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private void addEmployee(String line) {
        if (!(store instanceof CredentialStore.Mutable mutable)) {
            System.out.println("The records file is read-only; add lines to it and restart."
                    + " See: java portal.auth.PasswordHash <username>");
            return;
        }
        String username = restOf(line);
        if (username.isEmpty()) {
            username = ask("new username>");
        }
        if (username.isEmpty()) {
            System.out.println("No username given.");
            return;
        }
        String displayName = ask("display name>");
        char[] first = askSecret("new password>");
        char[] again = askSecret("repeat password>");
        try {
            if (!Arrays.equals(first, again)) {
                System.out.println("Passwords do not match; nothing stored.");
                return;
            }
            EmployeeRecord record = mutable.addEmployee(username, displayName, first);
            System.out.println("Stored " + record.username() + " ("
                    + PasswordHash.TAG + ", " + record.passwordHash().iterations() + " rounds).");
        } catch (IllegalArgumentException e) {
            System.out.println("Rejected: " + e.getMessage());
        } finally {
            Arrays.fill(first, '\0');
            Arrays.fill(again, '\0');
        }
    }

    /**
     * Operator aid. It deliberately says nothing about whether the name belongs to an employee:
     * the sign-in path keeps that unlearnable, and this command would hand it back for free.
     */
    private void showStatus(String line) {
        String username = restOf(line);
        username = username.isEmpty() ? ask("username to inspect>") : username;
        try {
            String canonical = CredentialValidator.canonicalUsername(username);
            Instant now = clock.instant();
            boolean locked = tracker.isLocked(canonical, now);
            System.out.println("failed attempts: " + tracker.consecutiveFailures(canonical, now)
                    + " of " + tracker.maxConsecutiveFailures());
            System.out.println("locked         : " + (locked
                    ? "yes, " + human(tracker.lockRemaining(canonical, now).getSeconds()) + " left"
                    : "no"));
        } catch (IllegalArgumentException e) {
            System.out.println("Rejected: " + e.getMessage());
        }
    }

    private void unlock(String line) {
        String username = restOf(line);
        username = username.isEmpty() ? ask("username to unlock>") : username;
        try {
            tracker.unlock(CredentialValidator.canonicalUsername(username));
            System.out.println("Counters cleared for " + username + ".");
        } catch (IllegalArgumentException e) {
            System.out.println("Rejected: " + e.getMessage());
        }
    }

    private String ask(String prompt) {
        try {
            String value = prompter.readLine(prompt);
            return value == null ? "" : value.strip();
        } catch (IOException e) {
            return "";
        }
    }

    private char[] askSecret(String prompt) {
        try {
            char[] value = prompter.readSecret(prompt);
            return value == null ? new char[0] : value;
        } catch (IOException e) {
            return new char[0];
        }
    }

    private void greet() {
        System.out.println("Employee Portal - sign in.");
        if (!prompter.hidesSecret()) {
            System.out.println("Note: no terminal was found, so typed passwords are not hidden."
                    + " This mode is for scripts and demos.");
        }
        printHelp();
    }

    private void printHelp() {
        System.out.println("Commands:");
        System.out.println("  <username>            sign in (you will be asked for a password)");
        System.out.println("  add [username]        add an employee to the in-memory store");
        System.out.println("  status <username>     show failed attempts and lock state");
        System.out.println("  unlock <username>     clear the counters for an account");
        System.out.println("  help | quit           this list, or leave");
        System.out.println("status and unlock are operator commands. This sign-in screen has no");
        System.out.println("roles of its own, so a real deployment keeps them behind an");
        System.out.println("administrator console instead of offering them here.");
    }

    private static String firstWord(String line) {
        int end = 0;
        while (end < line.length() && !Character.isWhitespace(line.charAt(end))) {
            end++;
        }
        return line.substring(0, end);
    }

    private static String restOf(String line) {
        int start = firstWord(line).length();
        return start >= line.length() ? "" : line.substring(start).strip();
    }

    private static String human(long seconds) {
        return seconds >= 60 ? (seconds / 60) + "m " + (seconds % 60) + "s" : seconds + "s";
    }

    public static void main(String[] args) {
        configureLogging();
        Options options;
        try {
            options = Options.parse(args);
        } catch (IllegalArgumentException e) {
            System.err.println("error: " + e.getMessage());
            Options.usage();
            System.exit(2);
            return;
        }
        if (options.help) {
            Options.usage();
            return;
        }
        CredentialStore store;
        try {
            store = options.recordsFile == null
                    ? demoStore(options.iterations)
                    : new TextFileCredentialStore(options.recordsFile,
                            Math.min(PasswordHash.MIN_STORED_ITERATIONS, options.iterations));
        } catch (IOException e) {
            System.err.println("cannot load the records: " + e.getMessage());
            System.exit(1);
            return;
        }
        LoginAttemptTracker tracker =
                new LoginAttemptTracker(options.maxFailures, Duration.ofMinutes(options.lockMinutes));
        Clock clock = Clock.systemUTC();
        Authenticator authenticator = new Authenticator(store, tracker, clock, options.iterations);
        EmployeePortalApp app = new EmployeePortalApp(store, tracker, authenticator,
                CredentialPrompter.system(), clock);
        System.exit(app.run());
    }

    /** Three working accounts so the portal can be tried out with nothing set up. */
    private static InMemoryCredentialStore demoStore(int iterations) {
        InMemoryCredentialStore store = new InMemoryCredentialStore(new SecureRandom(), iterations);
        char[][] secrets = {
                "Wint3r!Sky-2026".toCharArray(),
                "C0ffee#Mug77".toCharArray(),
                "Helpdesk!42-Pipe".toCharArray(),
        };
        store.addEmployee("alice.jones", "Alice Jones", secrets[0]);
        store.addEmployee("bob.smith", "Bob Smith", secrets[1]);
        store.addEmployee("it.support", "IT Service Desk", secrets[2]);
        for (char[] secret : secrets) {
            Arrays.fill(secret, '\0');
        }
        System.out.println("Demo accounts: alice.jones / Wint3r!Sky-2026,"
                + " bob.smith / C0ffee#Mug77, it.support / Helpdesk!42-Pipe");
        System.out.println("(a demo convenience - a real deployment loads a records file)");
        return store;
    }

    /** WARNING from everything else, INFO from the portal: sign-ins, failures, locks. */
    private static void configureLogging() {
        // Read by SimpleFormatter on every record, so setting it here still takes effect.
        System.setProperty("java.util.logging.SimpleFormatter.format",
                "%1$tF %1$tT %4$s %3$s %5$s%n");
        Logger root = Logger.getLogger("");
        root.setLevel(Level.WARNING);
        for (Handler handler : root.getHandlers()) {
            handler.setLevel(Level.INFO);
        }
        Logger.getLogger("portal").setLevel(Level.INFO);
    }

    /** Command line switches. */
    static final class Options {

        // Read by the test suite, which lives in this package.
        int maxFailures = DEMO_MAX_FAILURES;
        long lockMinutes = DEMO_LOCK_MINUTES;
        int iterations = PasswordHash.DEFAULT_ITERATIONS;
        boolean help;
        Path recordsFile;

        static Options parse(String[] args) {
            Options options = new Options();
            for (int i = 0; i < args.length; i++) {
                String flag = args[i];
                switch (flag) {
                    case "--help", "-h" -> options.help = true;
                    case "--records" -> options.recordsFile = Path.of(required(args, ++i, flag));
                    case "--max-failures" -> options.maxFailures = positiveInt(required(args, ++i, flag), flag);
                    case "--lock-minutes" -> options.lockMinutes = positiveInt(required(args, ++i, flag), flag);
                    case "--iterations" -> options.iterations = positiveInt(required(args, ++i, flag), flag);
                    default -> throw new IllegalArgumentException("unknown option " + flag);
                }
            }
            if (options.iterations < PasswordHash.MIN_CREATED_ITERATIONS
                    || options.iterations > PasswordHash.MAX_ITERATIONS) {
                throw new IllegalArgumentException("--iterations must be between "
                        + PasswordHash.MIN_CREATED_ITERATIONS + " and " + PasswordHash.MAX_ITERATIONS);
            }
            return options;
        }

        static void usage() {
            System.out.println("""
                    Usage: java portal.auth.EmployeePortalApp [options]

                      --records <file>        tab-separated employee records (read-only);
                                              without it three demo accounts are created
                      --max-failures <n>      consecutive failures before a lock (default 5)
                      --lock-minutes <n>      how long a lock lasts (default 15)
                      --iterations <n>        PBKDF2 rounds for new/demo records (default 100000)
                      --help                  this text
                    """);
        }

        private static String required(String[] args, int index, String flag) {
            if (index >= args.length) {
                throw new IllegalArgumentException(flag + " needs a value");
            }
            return args[index];
        }

        private static int positiveInt(String value, String flag) {
            try {
                int parsed = Integer.parseInt(value);
                if (parsed < 1) {
                    throw new IllegalArgumentException(flag + " must be 1 or more");
                }
                return parsed;
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(flag + " needs a whole number, got " + value);
            }
        }
    }
}
