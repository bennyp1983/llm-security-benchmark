import java.io.Console;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

/**
 * Command line front end.
 *
 * <pre>
 *   java UserAccountApp register &lt;username&gt; [password]
 *   java UserAccountApp login    &lt;username&gt; [password]
 *   java UserAccountApp inspect  &lt;username&gt;
 *   java UserAccountApp selftest
 * </pre>
 *
 * Omit the password argument to be prompted (echo is switched off when a console exists).
 * Pass {@code -} as the password to read it from standard input without echoing helpers.
 * The store file defaults to {@code accounts.txt} next to the working directory and can be
 * overridden with {@code --store <path>} or the {@code ACCOUNT_STORE} environment variable.
 */
public final class UserAccountApp {

    private static final String DEFAULT_STORE = "accounts.txt";

    public static void main(String[] args) {
        Path store = Path.of(storePathFrom(args));
        AccountStore accountStore = new AccountStore(store).load();
        UserAccountService service = new UserAccountService(accountStore, new PasswordHasher());

        String[] positional = positional(args);
        String command = positional.length > 0 ? positional[0] : "help";
        String[] rest = java.util.Arrays.copyOfRange(positional, 1, positional.length);
        switch (command) {
            case "register" -> register(service, rest);
            case "login" -> login(service, rest);
            case "inspect" -> inspect(service, rest);
            case "selftest" -> SelfTest.main(new String[0]);
            case "help", "--help", "-h" -> printUsage();
            default -> {
                System.out.println("Unknown command: " + command);
                printUsage();
                System.exit(2);
            }
        }
    }

    private static void register(UserAccountService service, String[] rest) {
        if (rest.length == 0) {
            System.out.println("Usage: register <username> [password]");
            System.exit(2);
        }
        char[] password = takePassword(rest, 1, "Choose a password for " + rest[0] + ": ");
        UserAccountService.Outcome outcome = service.register(rest[0], password);
        Passwords.wipe(password);
        switch (outcome.status()) {
            case OK -> {
                System.out.println("Registered account '" + Usernames.normalize(rest[0]) + "'.");
                System.out.println("Stored verifier: "
                        + service.storedVerifier(rest[0]).orElse("(unavailable)"));
                System.out.println("No password was stored; only this salted hash was.");
            }
            case INVALID_USERNAME -> System.out.println("Rejected: username must be "
                    + Usernames.MIN_LENGTH + "-" + Usernames.MAX_LENGTH
                    + " characters of letters, digits, dot, underscore, hyphen or @.");
            case INVALID_PASSWORD -> System.out.println("Rejected: password must be "
                    + Passwords.MIN_LENGTH + "-" + Passwords.MAX_LENGTH
                    + " characters, mix at least two character classes, and contain no NUL"
                    + " or lone surrogate characters.");
            case ACCOUNT_EXISTS -> System.out.println("Rejected: that account already exists.");
            default -> System.out.println("Rejected.");
        }
        System.exit(outcome.succeeded() ? 0 : 1);
    }

    private static void login(UserAccountService service, String[] rest) {
        if (rest.length == 0) {
            System.out.println("Usage: login <username> [password]");
            System.exit(2);
        }
        char[] password = takePassword(rest, 1, "Password for " + rest[0] + ": ");
        UserAccountService.Outcome outcome = service.login(rest[0], password);
        Passwords.wipe(password);
        System.out.println(outcome.succeeded()
                ? "Login succeeded for '" + Usernames.normalize(rest[0]) + "'."
                : "Login failed.");
        System.exit(outcome.succeeded() ? 0 : 1);
    }

    /** Shows what is on disk for an account, to demonstrate that no password is recoverable. */
    private static void inspect(UserAccountService service, String[] rest) {
        if (rest.length == 0) {
            System.out.println("Usage: inspect <username>");
            System.exit(2);
        }
        Optional<String> stored = service.storedVerifier(rest[0]);
        if (stored.isEmpty()) {
            System.out.println("No such account.");
            System.exit(1);
        }
        PasswordHasher.StoredRecord record = PasswordHasher.tryParse(stored.get());
        System.out.println("stored string : " + stored.get());
        System.out.println("algorithm     : " + PasswordHasher.FORMAT_TAG);
        System.out.println("iterations    : " + record.iterations());
        System.out.println("salt (base64) : " + java.util.Base64.getEncoder()
                .encodeToString(record.salt()));
        System.out.println("hash (base64) : " + java.util.Base64.getEncoder()
                .encodeToString(record.digest()));
        System.out.println("The hash is one-way: the password cannot be recovered from it.");
    }

    private static char[] takePassword(String[] args, int index, String prompt) {
        if (args.length > index && !"-".equals(args[index])) {
            return args[index].toCharArray();
        }
        Console console = System.console();
        if (console != null) {
            char[] read = console.readPassword("%s", prompt);
            return read == null ? new char[0] : read;
        }
        try (BufferedReader in = new BufferedReader(
                new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
            System.out.print(prompt);
            System.out.flush();
            String line = in.readLine();
            return line == null ? new char[0] : line.toCharArray();
        } catch (java.io.IOException e) {
            System.out.println("Unable to read the password: " + e.getMessage());
            System.exit(2);
            return new char[0];
        }
    }

    private static String storePathFrom(String[] args) {
        for (int i = 0; i < args.length - 1; i++) {
            if ("--store".equals(args[i])) {
                return args[i + 1];
            }
        }
        String fromEnv = System.getenv("ACCOUNT_STORE");
        return (fromEnv == null || fromEnv.isEmpty()) ? DEFAULT_STORE : fromEnv;
    }

    /** Drops options anywhere in the command line, keeping a lone "-" as the stdin marker. */
    private static String[] positional(String[] args) {
        List<String> kept = new java.util.ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            if ("--store".equals(args[i])) {
                i++;
                continue;
            }
            if (args[i].startsWith("-") && args[i].length() > 1) {
                continue;
            }
            kept.add(args[i]);
        }
        return kept.toArray(new String[0]);
    }

    private static void printUsage() {
        System.out.println("Commands:");
        System.out.println("  register <username> [password]   create an account");
        System.out.println("  login    <username> [password]   authenticate against the store");
        System.out.println("  inspect  <username>              show the stored verifier");
        System.out.println("  selftest                         run the built-in checks");
        System.out.println("Options:");
        System.out.println("  --store <path>                   account store file (default "
                + DEFAULT_STORE + ")");
    }
}
