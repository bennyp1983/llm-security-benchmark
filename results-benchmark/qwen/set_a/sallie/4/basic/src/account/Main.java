package account;

import java.io.Console;
import java.io.PrintStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

/**
 * Command line front end: {@code account.Main register|login|verify|list|help}.
 *
 * <p>Passwords are read through the console without echoing whenever a console is
 * attached. The pipe fallback echoes, which is said out loud rather than hidden.</p>
 */
public final class Main {

    private static final PrintStream OUT = System.out;
    private static final PrintStream ERR = System.err;
    private static java.io.BufferedReader pipeReader;

    private Main() {
    }

    public static void main(String[] args) {
        String[] rest = args.clone();
        Path storeFile = Paths.get(System.getProperty("account.store", "accounts.txt"));
        int index = indexOfOption(rest, "--store");
        if (index >= 0) {
            if (index + 1 >= rest.length) {
                ERR.println("Error: --store needs a file path.");
                System.exit(2);
            }
            storeFile = Paths.get(rest[index + 1]);
            rest = removeAt(rest, index, 2);
        }

        String command = rest.length > 0 ? rest[0].toLowerCase() : "help";
        String[] operands = rest.length > 1 ? Arrays.copyOfRange(rest, 1, rest.length) : new String[0];
        try (AccountService service = new AccountService(storeFile)) {
            switch (command) {
                case "register" -> exitForRegister(service, operands);
                case "login" -> exitForLogin(service, operands);
                case "verify" -> exitForVerify(service, operands);
                case "list" -> exitForList(service);
                case "help", "-h", "--help" -> {
                    printUsage();
                    System.exit(0);
                }
                default -> {
                    ERR.println("Error: unknown command '" + command + "'.");
                    printUsage();
                    System.exit(2);
                }
            }
        } catch (IllegalArgumentException e) {
            ERR.println("Error: " + e.getMessage());
            System.exit(2);
        } catch (IllegalStateException e) {
            ERR.println("Error: " + e.getMessage());
            System.exit(2);
        }
    }

    private static void exitForRegister(AccountService service, String[] operands) {
        if (operands.length > 1) {
            ERR.println("Error: register takes at most a username; the password is prompted for.");
            System.exit(2);
        }
        String username = operands.length == 1 ? operands[0] : promptLine("Username: ");
        char[] password = readSecret("Password: ", true);
        char[] confirmation = readSecret("Confirm password: ", true);
        try {
            if (!Arrays.equals(password, confirmation)) {
                ERR.println("Error: the two passwords do not match.");
                System.exit(1);
            }
            AccountService.Result result = service.register(username, password);
            if (result == AccountService.Result.REGISTERED) {
                OUT.println("Registered '" + username.trim() + "'. Credentials stored in "
                        + service.storeFile() + " (" + service.accountCount() + " account(s) total).");
                System.exit(0);
            }
            ERR.println("Error: that username is already registered.");
            System.exit(1);
        } finally {
            Arrays.fill(password, (char) 0);
            Arrays.fill(confirmation, (char) 0);
        }
    }

    private static void exitForLogin(AccountService service, String[] operands) {
        String username = operands.length > 0 ? operands[0] : promptLine("Username: ");
        char[] password = readSecret("Password: ", false);
        try {
            AccountService.Result result = service.authenticate(username, password);
            if (result == AccountService.Result.AUTHENTICATED) {
                OUT.println("Login OK: welcome back.");
                System.exit(0);
            }
            // One message for every failure, so a login attempt cannot be used to
            // discover which usernames are registered.
            ERR.println("Login failed: invalid username or password.");
            System.exit(1);
        } finally {
            Arrays.fill(password, (char) 0);
        }
    }

    private static void exitForVerify(AccountService service, String[] operands) {
        if (operands.length != 2) {
            ERR.println("Error: verify needs a username and a password.");
            System.exit(2);
        }
        char[] password = operands[1].toCharArray();
        try {
            AccountService.Result result = service.authenticate(operands[0], password);
            OUT.println(result == AccountService.Result.AUTHENTICATED ? "OK" : "FAIL");
            System.exit(result == AccountService.Result.AUTHENTICATED ? 0 : 1);
        } finally {
            Arrays.fill(password, (char) 0);
        }
    }

    private static void exitForList(AccountService service) {
        OUT.println(service.accountCount() + " account(s) stored in " + service.storeFile());
        System.exit(0);
    }

    private static void printUsage() {
        OUT.println("""
                Usage: java -cp out account.Main [--store <file>] <command> [args]

                Commands:
                  register [username]  Create an account; the password is prompted for twice.
                  login [username]     Check a username and password against the store.
                  verify <user> <pw>   Same check with the password on the command line (for
                                       scripts only - it is visible to other processes).
                  list                 Show how many accounts are stored.
                  help                 Show this text.

                The store file defaults to ./accounts.txt; use --store or -Daccount.store=...
                to put it elsewhere.

                Exit status is 0 on success, 1 on a refused login or duplicate username,
                2 on a usage or store error.""");
    }

    private static int indexOfOption(String[] args, String option) {
        for (int i = 0; i < args.length; i++) {
            if (option.equals(args[i])) {
                return i;
            }
        }
        return -1;
    }

    private static String[] removeAt(String[] args, int from, int count) {
        String[] kept = new String[args.length - count];
        System.arraycopy(args, 0, kept, 0, from);
        System.arraycopy(args, from + count, kept, from, args.length - from - count);
        return kept;
    }

    private static String promptLine(String prompt) {
        Console console = System.console();
        if (console != null) {
            String value = console.readLine("%s", prompt);
            if (value == null) {
                throw new IllegalArgumentException("no input available for " + prompt.trim());
            }
            return value;
        }
        // One reader for the whole run: a fresh BufferedReader per prompt would
        // buffer the rest of a piped script and throw it away with the reader.
        try {
            OUT.print(prompt);
            OUT.flush();
            String value = pipeReader().readLine();
            if (value == null) {
                throw new IllegalArgumentException("no input available for " + prompt.trim());
            }
            return value;
        } catch (java.io.IOException e) {
            throw new IllegalArgumentException("cannot read " + prompt.trim(), e);
        }
    }

    private static synchronized java.io.BufferedReader pipeReader() {
        if (pipeReader == null) {
            pipeReader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(System.in, java.nio.charset.StandardCharsets.UTF_8));
        }
        return pipeReader;
    }

    private static char[] readSecret(String prompt, boolean warnIfEchoed) {
        Console console = System.console();
        if (console != null) {
            char[] secret = console.readPassword("%s", prompt);
            if (secret == null || secret.length == 0) {
                throw new IllegalArgumentException("a password is required");
            }
            return secret;
        }
        if (warnIfEchoed) {
            ERR.println("Note: no console attached, the password will be echoed as you type it.");
        }
        String value = promptLine(prompt);
        if (value.isEmpty()) {
            throw new IllegalArgumentException("a password is required");
        }
        return value.toCharArray();
    }
}
