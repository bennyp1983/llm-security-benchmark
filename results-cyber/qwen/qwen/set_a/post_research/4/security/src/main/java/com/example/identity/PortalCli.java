package com.example.identity;

import java.io.Console;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Locale;

/**
 * Command line front end.
 *
 * <pre>
 *   IDENTITY_DB_PASSWORD='...' java -cp lib/h2.jar:bin com.example.identity.PortalCli register
 *   IDENTITY_DB_PASSWORD='...' java -cp lib/h2.jar:bin com.example.identity.PortalCli login
 *   IDENTITY_DB_PASSWORD='...' java -cp lib/h2.jar:bin com.example.identity.PortalCli status
 * </pre>
 *
 * <h2>No secret is ever a command-line argument</h2>
 * {@code argv} is world-readable on Linux through {@code /proc/<pid>/cmdline} to any local user, and
 * it lands in shell history and in the audit trail of every process recorder on the box. So:
 * <ul>
 *   <li>The database passphrase comes only from {@code IDENTITY_DB_PASSWORD} (see
 *     {@link Config}; the environment is not perfect either - it is readable by the same uid and by
 *     root - but it is not world-readable and is the accepted boundary here. README "Limitations"
 *     names the stronger option).</li>
 *   <li>The user's password is read from the terminal with echo disabled, or from stdin when
 *     piped.</li>
 *   <li>Argument count is <em>checked</em>, not ignored. Passing an extra argument that looks like a
 *     credential is refused with a message that says why, and the value is never echoed back.</li>
 * </ul>
 *
 * <h2>Output discipline</h2>
 * Success and refusal go to stdout as the generic {@link Reason} message and nothing else. Failure
 * details go to the log file, never to stdout or stderr - stderr carries only the operator's own
 * invocation errors, which contain no server state. Nothing this program prints is a secret: the
 * session token a successful sign-in creates is deliberately not displayed (see {@link #doLogin}).
 *
 * <h2>Input bound</h2>
 * Every line read is length-capped before it is examined, so a hostile 4 GB stdin cannot exhaust
 * memory before validation runs.
 */
public final class PortalCli {

    private static final int MAX_LINE_CHARS = 1024;
    static final String DEFAULT_CONFIG = "identity.properties";

    private PortalCli() {
    }

    public static void main(String[] args) {
        int exit = run(args, System.console(), System.in, System.out,
                Path.of(System.getProperty("portal.config", DEFAULT_CONFIG)));
        System.exit(exit);
    }

    /**
     * Testable body. {@code console} is null when stdin is a pipe, which is exactly the shape that
     * has to work for the scripted tests - so both paths are implemented, not just the pretty one.
     */
    static int run(String[] args, Console console, java.io.InputStream stdin,
                   java.io.PrintStream out, Path configPath) {
        // Refuse credential-shaped arguments before anything else, including before we open the
        // database: if someone typed a password as an argument it is already in /proc, and the
        // least we can do is not copy it further and tell them how to pass it instead.
        for (String a : args) {
            if (a != null && a.length() >= 8 && looksLikeCredentialArgument(a)) {
                System.err.println("refusing to accept a credential as a command-line argument;"
                        + " enter it when prompted");
                return 2;
            }
        }
        if (args.length != 1) {
            System.err.println("usage: register | login | status");
            return 2;
        }
        String command = args[0].toLowerCase(Locale.ROOT);
        if (!command.equals("register") && !command.equals("login") && !command.equals("status")) {
            System.err.println("usage: register | login | status");
            return 2;
        }

        Config config;
        try {
            config = Config.load(configPath, () -> System.getenv(Config.ENV_DB_PASSWORD));
        } catch (IdentityStoreException e) {
            // Config problems are the operator's own; naming the offending key is how they fix it,
            // and Config guarantees the value never reaches this message.
            System.err.println("configuration error: " + e.detail());
            return 3;
        }

        SqlIdentityStore store = null;
        AuditLog audit = null;
        try {
            store = SqlIdentityStore.open(config, TimeSource.system());
            audit = new AuditLog(config);
            AuthApi api = new AuthApi(store, new PasswordHasher(config), audit, config, TimeSource.system());
            for (String warning : api.startupWarnings()) {
                System.err.println("warning: " + warning);
            }
            audit.appendEvent(AuditEvent.STARTED);
            // One reader for the whole run, constructed exactly once. A reader per prompt (a
            // BufferedReader each time, or a BufferedInputStream with its own buffer) fills its
            // buffer from the pipe on the first call, so prompts two and three would read
            // end-of-input and the run would refuse its own scripted input. LineReader is buffered
            // deliberately nowhere: see its javadoc for why buffering the secret line is the one
            // thing it must not do.
            LineReader input = new LineReader(stdin);
            return switch (command) {
                case "register" -> doRegister(api, console, input, out);
                case "login" -> doLogin(api, console, input, out);
                default -> doStatus(api, out);
            };
        } catch (IdentityStoreException e) {
            // Rule 6: the user gets the generic sentence; the detail goes to the log only. The log is
            // recorded non-throwingly here: the reason being reported is already fixed, and a second
            // failure must not replace it (that is how the earlier shape reported an audit problem to
            // a user whose registration had in fact committed).
            if (audit != null) {
                audit.record(e.reason(), null);
            }
            out.println(e.userMessage());
            return e.reason() == Reason.STORAGE_UNAVAILABLE ? 4 : 1;
        } catch (IOException e) {
            // stdin/stdout trouble: the operator's terminal, not server state. Generic sentence.
            out.println(Reason.INVALID_REQUEST.genericUserMessage());
            return 2;
        } catch (RuntimeException e) {
            // Unexpected: still a generic sentence, and still fail-closed. The trace goes to stderr
            // for the operator; no exception message in this program is built from caller input, so
            // the trace cannot carry a password or token.
            out.println(Reason.STORAGE_UNAVAILABLE.genericUserMessage());
            e.printStackTrace(System.err);
            return 4;
        } finally {
            config.eraseDatabasePassword();
            if (audit != null) {
                audit.close();
            }
            if (store != null) {
                store.close();
            }
        }
    }

    private static int doRegister(AuthApi api, Console console, LineReader in,
                                  java.io.PrintStream out) throws IOException, IdentityStoreException {
        String email = readLine(console, in, out, "email: ");
        if (email == null) {
            out.println(Reason.INVALID_REQUEST.genericUserMessage());
            return 1;
        }
        String username = readLine(console, in, out, "username: ");
        if (username == null) {
            out.println(Reason.INVALID_REQUEST.genericUserMessage());
            return 1;
        }
        char[] password = readSecret(console, in, out, "password: ");
        if (password == null) {
            out.println(Reason.INVALID_REQUEST.genericUserMessage());
            return 1;
        }
        AuthResult r = api.register(email, username, password, SourceId.LOCAL);
        out.println(r.userMessage());
        return r.isSuccess() ? 0 : 1;
    }

    private static int doLogin(AuthApi api, Console console, LineReader in,
                               java.io.PrintStream out) throws IOException, IdentityStoreException {
        String identifier = readLine(console, in, out, "email or username: ");
        if (identifier == null) {
            out.println(Reason.INVALID_REQUEST.genericUserMessage());
            return 1;
        }
        char[] password = readSecret(console, in, out, "password: ");
        if (password == null) {
            out.println(Reason.INVALID_REQUEST.genericUserMessage());
            return 1;
        }
        AuthResult r = api.signIn(identifier, password, SourceId.LOCAL);
        // Deliberately nothing else. The token this call creates is a live bearer credential, and
        // this CLI has no command that consumes one, so printing it would buy no capability while
        // putting it in terminal scrollback, a script's captured stdout and any CI log. It would
        // also be revoked by the very next process to open the store - {@link SqlIdentityStore#open}
        // drops every session a previous run left behind - so the displayed value is worthless the
        // moment it is displayed. A deployment with a transport hands the value to CookieSpec and
        // never prints it either.
        out.println(r.userMessage());
        return r.isSuccess() ? 0 : 1;
    }

    private static int doStatus(AuthApi api, java.io.PrintStream out) throws IdentityStoreException {
        // unrecorded=N is the audit trail's own health: a full or blocked log makes security events
        // invisible, and a status line that stayed silent about it would let an operator read an
        // empty trail as a quiet system. Non-zero means the log needs attention, not that an account
        // was compromised - it carries no subject and no caller bytes.
        out.println("accounts=" + api.accountCount()
                + " liveSessions=" + api.liveSessionCount()
                + " attemptCounters=" + api.throttleRowCount()
                + " unrecorded=" + api.unrecordedAuditEvents());
        return 0;
    }

    // ------------------------------------------------------------------ input

    /**
     * Reads one bounded line. Never echoes a prompt containing server state.
     */
    private static String readLine(Console console, LineReader in,
                                   java.io.PrintStream out, String prompt) throws IOException {
        out.print(prompt);
        out.flush();
        if (console != null) {
            String line = console.readLine();
            return line == null || line.length() > MAX_LINE_CHARS ? null : line;
        }
        return in.readLine(MAX_LINE_CHARS);
    }

    /**
     * Reads a secret with echo disabled where the platform allows it.
     *
     * <p>{@link Console#readPassword()} returns {@code char[]} precisely so the caller can erase it;
     * a {@code readLine()} would pin it as an immutable String for the process lifetime. The piped
     * branch has to keep that property too, so it goes through {@link LineReader#readSecretChars}
     * rather than any {@code readLine()}: the only thing that ever holds the typed characters
     * besides the returned array is a buffer this method zeroes before returning. Reading it with
     * {@code String line = in.readLine(); return line.toCharArray();} was the earlier shape, and it
     * silently voided every {@code Password} erasure guarantee on exactly the path the class header
     * advertises - a {@code String} cannot be cleared, so a heap dump, a core dump or a same-uid
     * ptrace still yields the plaintext after the {@code char[]} has been wiped.
     *
     * <p>When stdin is a pipe there is no console and no way to disable echo, which is acceptable
     * only because the only thing on that pipe is a test harness or an operator's own deliberate
     * choice.
     */
    private static char[] readSecret(Console console, LineReader in,
                                     java.io.PrintStream out, String prompt) throws IOException {
        out.print(prompt);
        out.flush();
        if (console != null) {
            return console.readPassword();
        }
        return in.readSecretChars(Password.MAX_CP);
    }

    /**
     * Heuristic for "this argument is somebody's password": long enough to be one, no flag prefix,
     * and containing the mixed character classes a password has. Deliberately over-broad - a false
     * positive costs one re-typed command, a false negative leaks a credential into {@code /proc}.
     */
    static boolean looksLikeCredentialArgument(String a) {
        if (a.startsWith("-") || a.startsWith("/")) {
            return false;
        }
        boolean hasLower = false;
        boolean hasUpperOrDigit = false;
        boolean hasSymbol = false;
        for (int i = 0; i < a.length(); i++) {
            char c = a.charAt(i);
            if (c >= 'a' && c <= 'z') {
                hasLower = true;
            } else if (c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
                hasUpperOrDigit = true;
            } else if (!Character.isLetterOrDigit(c)) {
                hasSymbol = true;
            }
        }
        return hasLower && hasUpperOrDigit && hasSymbol;
    }
}
