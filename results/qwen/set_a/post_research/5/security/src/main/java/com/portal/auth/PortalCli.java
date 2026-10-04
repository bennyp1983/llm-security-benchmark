package com.portal.auth;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Operator and employee command line.
 *
 * <h2>Inputs and how each is handled</h2>
 * <ul>
 *   <li><b>argv</b>: a fixed subcommand allowlist and {@code --flag=value} options. An
 *       unknown subcommand or flag is a refusal, never a fallback. <b>No secret may be
 *       passed on argv</b> -- command lines are readable by any user through
 *       {@code /proc/<pid>/cmdline} -- so {@code add-user} takes no password argument and
 *       reads it from the terminal instead.</li>
 *   <li><b>stdin</b>: the username line, and the password when there is no controlling
 *       terminal (batch mode). Neither is trimmed: a trailing TAB is a character the user
 *       typed, and {@link InputPolicy} refuses it rather than folding the value onto a
 *       real account.</li>
 *   <li><b>environment</b>: see {@link PortalConfig}; the data directory is required.</li>
 * </ul>
 *
 * <p>Output discipline: a denial always prints {@link #GENERIC_DENIED}, which says nothing
 * about whether the name exists, the password was close, or the budget is spent. Details go
 * to the audit log only. The session id a login mints is <b>not</b> printed: nothing here
 * consumes it, so printing it would only put a credential on the terminal, in the
 * scrollback and in the shell history for no benefit.
 */
public final class PortalCli {

    public static final String GENERIC_DENIED = "Access denied.";
    public static final String GENERIC_GRANTED = "Access granted.";

    private static final List<String> SUBCOMMANDS =
            List.of("login", "add-user", "set-password", "disable-user", "status", "version");

    private final PortalConfig config;
    private final java.io.PrintStream out;
    /**
     * Wrapped in a one-slot pushback by {@link #readRawLine} so a lone CR can terminate a
     * line without eating the character that follows it. Nothing else reads from this
     * reader, so the two views cannot disagree about the stream position.
     */
    private final java.io.PushbackReader in;
    private final Console console;
    private final boolean haveConsole;

    public PortalCli(PortalConfig config, java.io.PrintStream out, BufferedReader in,
                     Console console) {
        this.config = config;
        this.out = out;
        this.in = new java.io.PushbackReader(in, 1);
        this.console = console;
        this.haveConsole = console != null;
    }

    public static void main(String[] argv) {
        PortalConfig cfg;
        try {
            cfg = PortalConfig.fromEnvironment();
        } catch (RuntimeException refusal) {
            // Machine token only: the message may name a key, never a value.
            System.err.println("startup-refused reason=" + safeToken(refusal.getMessage()));
            System.exit(2);
            return;
        }
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(System.in, StandardCharsets.UTF_8));
        int code = new PortalCli(cfg, System.out, reader, System.console())
                .run(new ArrayList<>(List.of(argv)));
        System.exit(code);
    }

    /** @return process exit code: 0 granted/ok, 1 denied, 2 refused-to-run */
    public int run(List<String> argv) {
        if (argv.size() < 1 || argv.size() > 3) {
            out.println("usage: portal <" + String.join("|", SUBCOMMANDS) + ">");
            return 2;
        }
        String command = argv.get(0);
        if (!SUBCOMMANDS.contains(command)) {
            out.println("unknown command.");
            return 2;
        }
        try {
            return switch (command) {
                case "version" -> version();
                case "login" -> login();
                case "add-user" -> addUser(true);
                case "set-password" -> addUser(false);
                case "disable-user" -> disableUser(argv);
                case "status" -> status();
                default -> {
                    out.println("unknown command.");
                    yield 2;
                }
            };
        } catch (IllegalStateException refusal) {
            // A startup/consistency refusal (unusable data dir, roster below the KDF
            // floor, corrupt ledger). Fail closed: no command runs, and the operator gets
            // a machine token, not the message -- which can name a path.
            out.println("operation-refused reason=" + safeToken(refusal.getMessage()));
            return 2;
        } catch (IllegalArgumentException | IOException failure) {
            out.println("operation-failed.");
            return 2;
        }
    }

    private int version() {
        out.println("portal-auth java=" + System.getProperty("java.vm.version", "unknown")
                + " kdf=" + PasswordHasher.ALG + "-" + PasswordHasher.HASH_ALG
                + " iterations=" + config.iterations());
        return 0;
    }

    private int login() throws IOException {
        char[] username = readLineChars("username: ");
        char[] password = readSecretChars("password: ");
        if (username == null || password == null) {
            // Neither array reaches authenticate() here, so nothing downstream will
            // clear them for us.
            Crypto.wipe(username);
            Crypto.wipe(password);
            out.println("input-unavailable.");
            return 2;
        }
        PortalRuntime runtime = PortalRuntime.open(config);
        Authenticator.Result result = runtime.authenticator()
                .authenticate(username, password, SourceRef.LOCAL_LABEL);
        if (result.isSuccess()) {
            out.println(GENERIC_GRANTED + " user=" + result.username());
            return 0;
        }
        out.println(GENERIC_DENIED);
        return 1;
    }

    /** Creates (or resets, for {@code set-password}) one account, reading a private secret. */
    private int addUser(boolean mustNotExist) throws IOException {
        char[] username = readLineChars("username: ");
        if (username == null) {
            Crypto.wipe(username);
            out.println("input-unavailable.");
            return 2;
        }
        String name;
        try {
            name = new String(Authenticator.foldAsciiCase(username));
        } finally {
            Crypto.wipe(username);
        }
        if (!InputPolicy.isUsername(name)) {
            out.println("Username must be " + InputPolicy.USERNAME_MIN + "-"
                    + InputPolicy.USERNAME_MAX + " characters from a-z, 0-9, '.', '_' or '-'"
                    + ", starting and ending with a letter or digit.");
            return 2;
        }
        char[] first = readSecretChars("new password: ");
        char[] second = readSecretChars("repeat password: ");
        if (first == null || second == null) {
            Crypto.wipe(first);
            Crypto.wipe(second);
            out.println("input-unavailable.");
            return 2;
        }
        try {
            if (!Crypto.equalChars(first, second)) {
                out.println("Passwords do not match.");
                return 2;
            }
            String weakness = InputPolicy.strengthFailure(first, name.toCharArray());
            if (weakness != null) {
                // Enrolment is the only place a password-quality message belongs. At login
                // time the same words would be an enumeration channel.
                out.println(weakness);
                return 2;
            }
            PortalRuntime runtime = PortalRuntime.open(config);
            // Read the flag before the write: resetting the secret of a disabled account
            // replaces the unusable marker, so it also lifts the disable. The operator must
            // see that, or they will believe a disabled account is still disabled after they
            // have just handed somebody its new secret.
            boolean reEnabled = !mustNotExist && runtime.store().isDisabled(name);
            EmployeeStore.CreateResult created = mustNotExist
                    ? runtime.store().create(name, first)
                    : runtime.store().setSecret(name, first);
            return switch (created) {
                case CREATED -> {
                    out.println(reEnabled
                            ? "ok. (the account was disabled; this reset re-enabled it)"
                            : "ok.");
                    yield 0;
                }
                case NAME_TAKEN -> {
                    out.println("That username already exists.");
                    yield 2;
                }
                case WEAK_PASSWORD -> {
                    out.println("Password rejected by policy.");
                    yield 2;
                }
                case INVALID_NAME -> {
                    out.println("Username is not valid.");
                    yield 2;
                }
                case IO_FAILURE -> {
                    out.println("operation-failed.");
                    yield 2;
                }
            };
        } finally {
            Crypto.wipe(first);
            Crypto.wipe(second);
        }
    }

    private int disableUser(List<String> argv) {
        if (argv.size() != 2 || !argv.get(1).startsWith("--user=")) {
            out.println("usage: portal disable-user --user=<name>");
            return 2;
        }
        String name = argv.get(1).substring("--user=".length());
        if (!InputPolicy.isUsername(name)) {
            out.println("Username is not valid.");
            return 2;
        }
        PortalRuntime runtime = PortalRuntime.open(config);
        if (!runtime.store().exists(name)) {
            // Administrative context, and deliberately vague: this command is run by
            // somebody who is already trusted with the roster.
            out.println("No such account.");
            return 2;
        }
        runtime.store().disableAccount(name);
        runtime.sessions().revokeAllFor(name);
        out.println("ok.");
        return 0;
    }

    private int status() {
        PortalRuntime runtime = PortalRuntime.open(config);
        out.println("accounts=" + runtime.store().size()
                + " sessions=" + runtime.sessions().liveSessionCount()
                + " login-ok=" + runtime.throttle().countOf(ThrottleManager.Kind.ALLOWED)
                + " login-denied=" + runtime.throttle().countOf(ThrottleManager.Kind.THROTTLED)
                + " kdf-iterations=" + config.iterations());
        return 0;
    }

    /**
     * Reads a line without trimming. The line terminator is framing, not content, so
     * discarding it is correct; discarding a trailing space or TAB would not be.
     */
    private char[] readLineChars(String prompt) throws IOException {
        if (haveConsole) {
            String line = console.readLine(prompt);
            return line == null ? null : line.toCharArray();
        }
        // Print the prompt in batch mode too. A caller that feeds lines positionally has
        // no other way to notice that a prompt was consumed by the wrong field, which is
        // precisely how a password gets read as a username and turns into a generic
        // "unknown account" denial several lines later.
        out.print(prompt);
        out.flush();
        return readRawLine();
    }

    /**
     * Reads a secret as {@code char[]} and never as a {@code String}. With a terminal we
     * use {@link Console#readPassword()} (no echo, no line logging); in batch mode we read
     * a line from standard input, which is a pipe or file the caller already owns. It is
     * never taken from an argument, where every other user could read it.
     */
    private char[] readSecretChars(String prompt) throws IOException {
        if (haveConsole) {
            char[] secret = console.readPassword(prompt);
            if (secret == null) {
                return null;
            }
            // readPassword strips only the line terminator.
            return secret;
        }
        out.print(prompt);
        out.flush();
        return readRawLine();
    }

    /**
     * Bounded line read. {@code BufferedReader.readLine} allocates for a line of any
     * length, so a multi-gigabyte stdin would be a memory-exhaustion DoS against a program
     * whose own policy refuses anything longer than {@link InputPolicy#LINE_MAX}. One
     * character past the cap and the remainder of the line is drained and discarded.
     *
     * <p>On overflow we return an array that is deliberately too long to be a valid
     * credential, so the caller's own boundary check produces the generic refusal. We do
     * not truncate: a truncated password is a different secret from the one typed, and a
     * truncated username could land on somebody else's real account.
     *
     * <h2>Carriage returns terminate a line, they are never deleted</h2>
     * An earlier draft wrote {@code if (c == '\r') continue;} to accept CRLF input, which
     * silently deleted every CR in the <em>middle</em> of a line as well. Measured against
     * the shipped binary that folded {@code "ali\rce"} onto the real account {@code alice}
     * and made {@code "Fresh-Quiver-7\r1!"} verify as the real password -- both granted with
     * exit code {@code 0}. Deleting an invisible character from a credential is exactly the
     * identity folding {@link InputPolicy} refuses to do with {@code trim()}; it was
     * happening in the one reader that policy never sees.
     *
     * <p>CR is therefore a line terminator with {@code BufferedReader.readLine} semantics:
     * {@code LF}, {@code CRLF} or a lone {@code CR} ends the line, and the character after a
     * lone {@code CR} begins the next one. A terminator can only <em>split</em> a credential,
     * and a split is always safe here -- each half is a different string from any real
     * credential, so the outcome is a refusal rather than a login as somebody else. Keeping
     * CR as content instead would be equally safe but would reject a legitimate CRLF batch
     * file, which pushes operators to pre-strip input by hand -- a workaround that eventually
     * strips something that mattered.
     */
    private char[] readRawLine() throws IOException {
        char[] buf = new char[InputPolicy.LINE_MAX];
        int n = 0;
        boolean overflowed = false;
        int c = -1;
        while ((c = in.read()) >= 0) {
            if (c == '\n') {
                break;
            }
            if (c == '\r') {
                int after = in.read();
                if (after >= 0 && after != '\n') {
                    in.unread(after);
                }
                break;
            }
            if (n < buf.length) {
                buf[n++] = (char) c;
            } else {
                overflowed = true;
            }
        }
        if (c < 0 && n == 0) {
            Crypto.wipe(buf);
            return null;
        }
        if (overflowed) {
            Crypto.wipe(buf);
            return new char[InputPolicy.PASSWORD_MAX + 1];
        }
        char[] exact = new char[n];
        System.arraycopy(buf, 0, exact, 0, n);
        Crypto.wipe(buf);
        return exact;
    }

    /**
     * Reduces an internal exception message to a printable machine token. Kept in one
     * place (this is the only implementation; {@link Main} delegates here) because two
     * copies of a redaction rule are how one of them ends up permitting something the
     * other refuses.
     *
     * <p>Our own refusals are "{@code token: free detail}" where the detail may name a
     * path or a key, so everything from the first space is dropped. What survives must
     * then match a small alphabet with no slash, no backslash, no quote and no space, so
     * neither a path nor any value an operator typed can reach a terminal or a log line.
     */
    static String safeToken(String message) {
        if (message == null || message.isEmpty()) {
            return "unspecified";
        }
        int cut = message.indexOf(' ');
        String head = cut > 0 ? message.substring(0, cut) : message;
        if (head.isEmpty() || head.length() > 80) {
            return "unspecified";
        }
        for (int i = 0; i < head.length(); i++) {
            char c = head.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.' || c == ':';
            if (!ok) {
                return "unspecified";
            }
        }
        return head;
    }


}
