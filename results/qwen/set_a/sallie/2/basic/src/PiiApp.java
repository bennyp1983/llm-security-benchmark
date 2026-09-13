import java.io.Console;
import java.util.Arrays;

/**
 * Command line demo: read a name and an email address, encrypt them with AES,
 * then decrypt the result back to the original values.
 *
 * <pre>
 *   java PiiApp                         interactive prompts
 *   java PiiApp "Ada Lovelace" "ada@example.com"
 * </pre>
 *
 * <p>The passphrase is never taken as an argument, because command lines are
 * visible to every process on the machine and land in shell history. It is read
 * from the terminal without echoing, or from the {@code PII_PASSPHRASE} variable.
 */
public final class PiiApp {

    private static final int MIN_PASSPHRASE_LENGTH = 10;

    /** Exit codes: 0 worked, 1 the user must fix something, 2 something unanticipated. */
    public static void main(String[] args) {
        try {
            run(args);
        } catch (PiiCrypto.PiiCryptoException | IllegalArgumentException | IllegalStateException e) {
            // These three are the ways bad input can arrive: rejected values, a short
            // passphrase, and no terminal to read from. All of them are explainable.
            System.out.println("FAILED: " + e.getMessage());
            System.exit(1);
        } catch (Exception e) {
            System.out.println("UNEXPECTED FAILURE: " + e.getClass().getSimpleName()
                    + (e.getMessage() == null ? "" : ": " + e.getMessage()));
            System.exit(2);
        }
    }

    private static void run(String[] args) throws Exception {
        if (args.length == 1 && ("-h".equals(args[0]) || "--help".equals(args[0]))) {
            printUsage();
            return;
        }
        if (args.length > 2) {
            printUsage();
            System.exit(1);
            return;
        }

        String name = args.length > 0 ? args[0] : prompt("Name:  ");
        String email = args.length > 1 ? args[1] : prompt("Email: ");

        System.out.println();
        System.out.println("Plain text (what you typed, this is the sensitive part)");
        System.out.println("  name : " + name);
        System.out.println("  email: " + email);

        char[] passphrase = readPassphrase();
        try {
            String token = PiiCrypto.encrypt(name, email, passphrase);
            System.out.println();
            System.out.println("Encrypted with AES-256-GCM (store this, it is safe to store)");
            System.out.println("  " + token);

            // Two encryptions of the same input differ, because the salt and the
            // initial value are fresh each time. Show it so nobody mistakes the
            // token for a hash they could compare.
            String again = PiiCrypto.encrypt(name, email, passphrase);
            System.out.println();
            System.out.println("Same input encrypted a second time (a different token, same record)");
            System.out.println("  " + again);
            System.out.println("  tokens identical: " + token.equals(again));

            PiiRecord recovered = PiiCrypto.decrypt(token, passphrase);
            System.out.println();
            System.out.println("Decrypted again with the same passphrase");
            System.out.println("  name : " + recovered.name());
            System.out.println("  email: " + recovered.email());
            System.out.println();
            System.out.println("Round trip identical to the input: "
                    + (name.equals(recovered.name()) && email.equals(recovered.email())));

            showWrongPassphraseIsRefused(token, passphrase);
        } finally {
            Arrays.fill(passphrase, '\0');
        }
    }

    private static void showWrongPassphraseIsRefused(String token, char[] passphrase) throws Exception {
        char[] wrong = passphrase.clone();
        wrong[0] = wrong[0] == 'x' ? 'y' : 'x';
        try {
            PiiCrypto.decrypt(token, wrong);
            System.out.println();
            System.out.println("PROBLEM: a wrong passphrase was accepted.");
        } catch (PiiCrypto.PiiCryptoException e) {
            System.out.println();
            System.out.println("Same token with a wrong passphrase, refused as expected");
            System.out.println("  " + e.getMessage());
        } finally {
            Arrays.fill(wrong, '\0');
        }
    }

    private static void printUsage() {
        System.out.println("Usage: java PiiApp [\"name\" \"email@example.com\"]");
        System.out.println("Without arguments both values are asked for.");
        System.out.println("Set PII_PASSPHRASE to supply the passphrase non-interactively,");
        System.out.println("otherwise it is prompted for without echoing.");
    }

    private static String prompt(String label) throws Exception {
        Console console = System.console();
        if (console == null) {
            throw new IllegalStateException("no terminal available: pass the name and email as arguments");
        }
        String value = console.readLine(label);
        if (value == null) {
            throw new IllegalStateException("input ended before a value was given");
        }
        return value.trim();
    }

    private static char[] readPassphrase() throws Exception {
        String fromEnvironment = System.getenv("PII_PASSPHRASE");
        if (fromEnvironment != null && !fromEnvironment.isEmpty()) {
            System.out.println();
            System.out.println("Using the passphrase from PII_PASSPHRASE.");
            char[] fromVar = fromEnvironment.toCharArray();
            if (fromVar.length < MIN_PASSPHRASE_LENGTH) {
                Arrays.fill(fromVar, '\0');
                throw new IllegalArgumentException(
                        "the passphrase in PII_PASSPHRASE must be at least " + MIN_PASSPHRASE_LENGTH + " characters");
            }
            return fromVar;
        }

        Console console = System.console();
        if (console == null) {
            throw new IllegalStateException(
                    "no terminal available: set PII_PASSPHRASE to the passphrase you want to use");
        }
        char[] first = console.readPassword(
                "Passphrase (at least " + MIN_PASSPHRASE_LENGTH + " characters, not echoed): ");
        if (first == null || first.length < MIN_PASSPHRASE_LENGTH) {
            if (first != null) {
                Arrays.fill(first, '\0');
            }
            throw new IllegalArgumentException("the passphrase must be at least " + MIN_PASSPHRASE_LENGTH + " characters");
        }
        char[] second = console.readPassword("Type it again:            ");
        boolean matched = second != null && Arrays.equals(first, second);
        if (second != null) {
            Arrays.fill(second, '\0');
        }
        if (!matched) {
            Arrays.fill(first, '\0');
            throw new IllegalArgumentException("the two passphrases did not match");
        }
        return first;
    }

    private PiiApp() {
    }
}
