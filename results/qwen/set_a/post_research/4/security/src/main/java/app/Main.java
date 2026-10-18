package app;

import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.time.Clock;
import java.util.Arrays;
import java.util.function.Function;

/**
 * Command line for registration, sign-in, session validation and sign-out.
 *
 * <p>Input handling:
 * <ul>
 *   <li>A password is read with {@code Console.readPassword()} whenever a terminal is attached, so
 *       it is never echoed. Only when standard input is redirected is a line read from it; even
 *       then nothing is echoed and the value is never written anywhere except into the hash.</li>
 *   <li>Every line read is length-capped <em>while reading</em>, so an oversized line cannot be
 *       buffered in full and rejected afterwards.</li>
 *   <li>Every buffer that held a credential is erased in a {@code finally} block. Erasure is
 *       best effort - the JVM copies {@code char[]} and {@code String} values in ways this class
 *       cannot control - and the README says so instead of overclaiming.</li>
 *   <li>Nothing the user typed is echoed back or written to the trail. What is printed is a fixed
 *       sentence plus, on a successful sign-in, the session cookie: the only way the person who
 *       just proved the password can use the session. On that path they already know the password,
 *       so the cookie is not a disclosure to a third party; it is never logged.</li>
 * </ul>
 *
 * <p>No credential is ever accepted as a command-line argument, so none can appear in a process
 * listing. That rule includes a session cookie: it is a bearer credential, valid to whoever holds
 * it, so {@code verify} and {@code logout} prompt for it on standard input and refuse a leftover
 * operand rather than using it. A prompted cookie is erased after use and reduced to a salted tag
 * in the trail.
 */
public final class Main {

    /** Stable exit codes so a caller can branch without parsing prose. */
    static final int OK = 0;
    static final int REFUSED = 2;
    static final int BAD_CONFIG = 3;
    static final int UNAVAILABLE = 4;
    static final int BAD_USAGE = 64;

    private static final String USAGE = """
        Usage:
          register               create an account (email, username, password are prompted)
          login                  sign in and print the session cookie
          verify                 report whether a session cookie is currently valid (prompted)
          logout                 revoke a session cookie (prompted)
          revoke-sessions        revoke every live session of the named account

        The session cookie for verify and logout is prompted for, never taken as an argument: an
        argument is visible in other users' process listings, and a cookie is a bearer credential.

        Environment:
          APP_DATA_DIR           directory for the account store and audit log (required)
          APP_DB_PASSWORD        database password, or APP_DB_PASSWORD_FILE naming a 0600 file
          APP_ARGON2_MEMORY_KIB / APP_ARGON2_ITERATIONS / APP_ARGON2_PARALLELISM
                                 optional; each is bounded to a range the store can also hold
        """;

    public static void main(String[] argv) {
        System.exit(run(argv, System.getenv()::get, System.in, System.out, System.err));
    }

    static int run(String[] argv, Function<String, String> env, InputStream in,
        PrintStream out, PrintStream err) {
        // Options may appear before or after the command word, so the command is the first
        // argument that is not a --option. Everything after it that is not an option is positional.
        for (String argument : argv) {
            if (argument.equals("--help") || argument.equals("-h")) {
                out.print(USAGE);
                return OK;
            }
        }
        String command = null;
        java.util.List<String> positional = new java.util.ArrayList<>();
        for (String argument : argv) {
            if (argument.startsWith("--")) {
                continue;
            }
            if (command == null) {
                command = argument;
            } else {
                positional.add(argument);
            }
        }
        if (command == null) {
            err.print(USAGE);
            return BAD_USAGE;
        }
        String[] operands = positional.toArray(new String[0]);

        Config config = null;
        Db database = null;
        try {
            config = Config.fromEnvironment(env, argv);
            database = config.openDatabase();
            // Schema first, explicitly: the throttle and session tables must exist before any
            // command can consume a budget or issue a session.
            database.applySchema();

            PasswordHasher hasher = new PasswordHasher(config.argon2MemoryKib(),
                config.argon2Iterations(), config.argon2Parallelism());
            AuditLog audit = new AuditLog(config.auditLogFile());
            Gate gate = new Gate(audit);
            Clock clock = Clock.systemUTC();
            Throttle throttle = new Throttle(database, clock);
            AccountStore accounts = new AccountStore(database, hasher, throttle, gate, clock);
            SessionStore sessions = new SessionStore(database, gate, clock);
            AuthService auth = new AuthService(accounts, throttle, sessions, hasher, gate, clock);
            Maintenance maintenance = new Maintenance(sessions, throttle, gate);
            Main main = new Main(new Reader(in, System.console(), out), out, err, gate);

            // Housekeeping before the command runs: expired/revoked sessions and throttle state
            // whose window has elapsed are deleted so the tables the feature fills stay bounded.
            // A failed sweep is reported and does not deny the command.
            maintenance.run();
            return switch (command) {
                case "register" -> main.register(accounts);
                case "login" -> main.login(auth);
                case "verify" -> main.verify(operands, auth, main.reader);
                case "logout" -> main.logout(operands, auth, main.reader);
                case "revoke-sessions" -> main.revokeSessions(accounts, sessions);
                default -> {
                    err.print(USAGE);
                    yield BAD_USAGE;
                }
            };
        } catch (Config.ConfigException badEnvironment) {
            // Configuration messages name the setting and the rule, never the value.
            err.println("Configuration error: " + badEnvironment.getMessage());
            err.print(USAGE);
            return BAD_CONFIG;
        } catch (Config.AppConfiguredException storeUnreachable) {
            err.println(AuthService.INTERNAL_MESSAGE);
            return UNAVAILABLE;
        } catch (SQLException | java.security.GeneralSecurityException storeFault) {
            // The cause stays here, on the operator's own terminal, and never in a file that
            // might outlive the process world-readable. The user-facing outcome is generic.
            err.println(AuthService.INTERNAL_MESSAGE);
            return UNAVAILABLE;
        } catch (AuditLog.AuditException auditUnwritable) {
            err.println(AuthService.INTERNAL_MESSAGE);
            return UNAVAILABLE;
        } catch (IOException inputClosed) {
            err.println("The input ended before the command finished.");
            return UNAVAILABLE;
        } catch (RuntimeException crash) {
            // An unexpected defect - ours or a dependency's - must not print a stack trace where the
            // user reads. A trace names absolute paths, the dependency layout and, through its cause
            // chain, whatever a message happened to interpolate. The operator gets a generic line
            // plus the exception's one-line identity: enough to look up in the source, not enough to
            // fingerprint the deployment from the outside. Access is refused, not allowed.
            err.println(AuthService.INTERNAL_MESSAGE);
            err.println("NOTE unexpected failure of type " + crash.getClass().getName());
            return UNAVAILABLE;
        } finally {
            if (database != null) {
                database.close();
            }
            if (config != null) {
                config.close();
            }
        }
    }

    private final Reader reader;
    private final PrintStream out;
    private final PrintStream err;
    private final Gate gate;

    private Main(Reader reader, PrintStream out, PrintStream err, Gate gate) {
        this.reader = reader;
        this.out = out;
        this.err = err;
        this.gate = gate;
    }

    // ------------------------------------------------------------------ commands

    private int register(AccountStore accounts)
        throws IOException, SQLException, AuditLog.AuditException {
        char[] emailChars;
        char[] usernameChars;
        char[] passwordChars;
        try {
            emailChars = reader.readLine("Email: ");
            usernameChars = reader.readLine("Username: ");
            passwordChars = reader.readSecret("Password: ");
        } catch (InputTooLong oversized) {
            out.println(REFUSED_MESSAGE);
            recordQuietly(AuditLog.Event.REGISTRATION_REFUSED_INVALID_INPUT, "input line too long");
            return REFUSED;
        }
        try {
            String email;
            String username;
            try {
                email = InputPolicy.email(emailChars);
                username = InputPolicy.username(usernameChars);
                InputPolicy.password(passwordChars);
                InputPolicy.passwordNotRelatedTo(passwordChars, username, email);
            } catch (InputPolicy.ValidationException invalid) {
                // The rule is printed to the person attempting their own registration - a
                // legitimate feedback channel - and recorded as a rule name, never a value.
                out.println("Registration refused: " + invalid.getMessage() + ".");
                recordQuietly(AuditLog.Event.REGISTRATION_REFUSED_INVALID_INPUT, invalid.getMessage());
                return REFUSED;
            }

            String sourceId = sourceKey("register");
            AccountStore.RegisterOutcome outcome;
            try {
                outcome = accounts.register(passwordChars, email, username, sourceId);
            } catch (AuditLog.AuditException auditUnwritable) {
                // Every registration record is written inside the registering transaction, so an
                // unwritable trail means the row was rolled back: refuse rather than create an
                // account that nobody can account for.
                err.println(AuthService.INTERNAL_MESSAGE);
                return UNAVAILABLE;
            }
            // Identical sentence for CREATED and DUPLICATE, so this cannot enumerate accounts.
            out.println(outcome.message());
            return outcome.status() == AccountStore.RegisterStatus.THROTTLED ? REFUSED : OK;
        } finally {
            Arrays.fill(passwordChars, '\0');
            Arrays.fill(emailChars, '\0');
            Arrays.fill(usernameChars, '\0');
        }
    }

    private int login(AuthService auth) throws IOException {
        char[] identifierChars;
        char[] passwordChars;
        try {
            identifierChars = reader.readLine("Email or username: ");
            passwordChars = reader.readSecret("Password: ");
        } catch (InputTooLong oversized) {
            out.println(AuthService.INVALID_MESSAGE);
            recordQuietly(AuditLog.Event.LOGIN_REFUSED_INVALID_INPUT, "input line too long");
            return REFUSED;
        }
        try {
            AuthService.Result result = auth.login(identifierChars, passwordChars, sourceKey("login"));
            out.println(result.message());
            if (!result.authenticated()) {
                return result.status() == AuthService.Status.UNAVAILABLE ? UNAVAILABLE : REFUSED;
            }
            String cookie = CookiePolicy.sessionCookie(result.session().token(),
                result.session().expiresAt(), java.time.Instant.now().getEpochSecond(), "/");
            out.println("Set-Cookie: " + cookie);
            return OK;
        } finally {
            Arrays.fill(passwordChars, '\0');
            Arrays.fill(identifierChars, '\0');
        }
    }

    /**
     * The session handle is read from standard input, never taken as an argument: {@code verify}
     * and {@code logout} receive a bearer credential, and a value in argv is visible to every other
     * user on the machine in a process listing. A leftover {@code <cookie>} operand is refused with
     * the generic invalid-session answer rather than being used or echoed.
     */
    private int verify(String[] operands, AuthService auth, Reader reader) throws IOException {
        Long accountId = auth.resolveSession(sessionHandleFrom(operands, reader));
        if (accountId == null) {
            out.println("The session is not valid.");
            return REFUSED;
        }
        out.println("The session is valid.");
        return OK;
    }

    private int logout(String[] operands, AuthService auth, Reader reader) throws IOException {
        String token = sessionHandleFrom(operands, reader);
        if (token == null) {
            // No usable handle: it was given as an argument, the input ended, or it was malformed.
            // Nothing was revoked, so this must not claim the session is gone - the whole point of
            // sign-out is that a captured token stops working, and reporting a revocation that never
            // happened is exactly the failure that leaves a stolen bearer credential live.
            out.println("The session is not valid.");
            return REFUSED;
        }
        AuthService.LogoutStatus status = auth.logout(token);
        if (status == AuthService.LogoutStatus.UNAVAILABLE) {
            // The store could not confirm the revocation. Report unavailability and do not emit the
            // expired cookie, whose Max-Age=0 would tell the client the credential is dead when the
            // server has not actually proven that.
            err.println(AuthService.INTERNAL_MESSAGE);
            return UNAVAILABLE;
        }
        // REVOKED and NO_LIVE_SESSION are worded identically, so this cannot probe session identifiers.
        out.println("Sign-out is complete.");
        out.println("Set-Cookie: " + CookiePolicy.expiredSessionCookie("/"));
        return OK;
    }

    private int revokeSessions(AccountStore accounts, SessionStore sessions)
        throws IOException, SQLException, AuditLog.AuditException {
        char[] usernameChars;
        try {
            usernameChars = reader.readLine("Username: ");
        } catch (InputTooLong oversized) {
            out.println("Sign-out is complete.");
            recordQuietly(AuditLog.Event.ADMIN_REVOKE_REFUSED_INVALID_INPUT, "input line too long");
            return REFUSED;
        }
        try {
            String username;
            try {
                username = InputPolicy.username(usernameChars);
            } catch (InputPolicy.ValidationException invalid) {
                // Same wording as the success path: this command must not reveal whether an
                // account exists either. The event names the operation that was refused, not
                // registration - a trail that labelled an admin refusal as a sign-up would send
                // whoever reads it looking for the wrong attack.
                out.println("Sign-out is complete.");
                recordQuietly(AuditLog.Event.ADMIN_REVOKE_REFUSED_INVALID_INPUT, invalid.getMessage());
                return REFUSED;
            }
            AccountStore.Account account = accounts.findByUsername(username);
            int revoked = account == null ? 0 : sessions.revokeAllForAccount(account.id());
            // The operator action is recorded here; SessionStore records the sessions it actually
            // ended. Both are needed: one names the request, the other names the effect.
            gate.record(AuditLog.Event.ADMIN_REVOKE_REQUESTED,
                "username", gate.usernameTag(username),
                "account", account == null ? "none" : gate.accountTag(account.id()),
                "count", Integer.toString(revoked));
            out.println("Sign-out is complete.");
            return OK;
        } finally {
            Arrays.fill(usernameChars, '\0');
        }
    }

    // ------------------------------------------------------------------ helpers

    private void recordQuietly(AuditLog.Event event, String reason) {
        try {
            gate.record(event, "reason", reason);
        } catch (AuditLog.AuditException auditUnwritable) {
            // This path has already refused the request, which is the safe direction, and never
            // touched a credential; the note tells the operator the trail is incomplete.
            err.println("NOTE an audit record for a refused request could not be written");
        }
    }

    /**
     * Reads the session handle from standard input, tolerating the {@code name=value} and
     * {@code ; attribute} framing a real cookie header carries, and refuses anything whose shape is
     * wrong before any lookup happens.
     *
     * <p>A {@code <cookie>} given as an operand is refused outright rather than used. A bearer
     * credential in argv is readable by every other account on the machine through the process
     * list, which is exactly the exposure the rest of this class goes out of its way to avoid for
     * passwords; the operand form is therefore not supported even though it is the convenient one.
     */
    private String sessionHandleFrom(String[] operands, Reader reader) {
        if (operands.length > 0) {
            err.println("The session cookie must be typed on standard input, not given as an"
                + " argument: arguments are visible in other users' process listings.");
            return null;
        }
        char[] entered;
        try {
            entered = reader.readSecret("Session cookie: ");
        } catch (IOException inputEnded) {
            // InputTooLong is an IOException: an oversized cookie is the same refusal as none.
            return null;
        }
        try {
            String value = new String(entered);
            int equals = value.indexOf('=');
            if (equals >= 0) {
                value = value.substring(equals + 1);
            }
            int semicolon = value.indexOf(';');
            if (semicolon >= 0) {
                value = value.substring(0, semicolon);
            }
            return SessionStore.isWellFormedToken(value) ? value : null;
        } finally {
            Arrays.fill(entered, '\0');
        }
    }

    /**
     * The per-source key. This deliverable has no network layer, so the only honest source
     * identifier is the OS user running the process. It must be a value the caller cannot choose on
     * the launch line: {@code System.getProperty("user.name")} and {@code os.name} are both trivially
     * forged with {@code -Duser.name=$RANDOM}, which lets anyone who can exec the program mint a
     * fresh, full rate-limit bucket per attempt and defeats the per-source half of the limit
     * entirely. The effective uid from {@code /proc/self/status} is maintained by the kernel, not by
     * the JVM's argument parsing, so it cannot be overridden that way; changing it means becoming
     * another user, which is a stronger claim than launching a process.
     *
     * <p>Where the kernel uid is genuinely unreadable, the fallback is one <em>shared</em> bucket for
     * the whole host, never a fresh one: a shared budget can still be exhausted but cannot be reset,
     * which is the fail-closed direction for a flood control. A deployment behind a gateway must
     * supply the authenticated client or tenant key instead and validate it as opaque
     * {@code [A-Za-z0-9._:-]{1,64}} before it is used as a bucket key - it is attacker-reachable and
     * must not be able to choose another tenant's bucket. The remaining risk is stated in the README.
     */
    private static String sourceKey(String scope) {
        String principal = kernelPrincipal();
        return Digests.sha256Hex((scope + ':' + principal).getBytes(StandardCharsets.UTF_8))
            .substring(0, 32);
    }

    /** Cached once per process: the uid cannot change under a running JVM that did not setuid. */
    private static final String KERNEL_PRINCIPAL = readKernelPrincipal();

    private static String kernelPrincipal() {
        return KERNEL_PRINCIPAL;
    }

    /**
     * Effective uid from {@code /proc/self/status} as {@code uid:<n>}, or the shared-bucket sentinel
     * when it cannot be read. Every failure mode resolves to the sentinel; this never throws, because
     * a source key that cannot be computed must degrade to a shared budget rather than to none.
     */
    private static String readKernelPrincipal() {
        try {
            for (String line : java.nio.file.Files.readAllLines(
                java.nio.file.Path.of("/proc/self/status"), java.nio.charset.StandardCharsets.US_ASCII)) {
                if (!line.startsWith("Uid:")) {
                    continue;
                }
                String[] fields = line.substring("Uid:".length()).trim().split("\\s+");
                // real, effective, saved, filesystem - the effective uid is what gates file access.
                if (fields.length >= 2 && isAllDigits(fields[1])) {
                    return "uid:" + fields[1];
                }
                break;
            }
        } catch (java.io.IOException | RuntimeException unreadable) {
            // fall through to the shared sentinel below
        }
        return "shared-local";
    }

    private static boolean isAllDigits(String value) {
        if (value.isEmpty()) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) < '0' || value.charAt(i) > '9') {
                return false;
            }
        }
        return true;
    }

    private static final String REFUSED_MESSAGE = "The details supplied are not acceptable.";

    // ------------------------------------------------------------------ input

    /**
     * Line reader with a hard cap applied during the read. The terminal path uses
     * {@code Console.readPassword} for secrets so nothing is echoed; the byte path is reached when
     * standard input is a pipe or file, which is how a scripted session and the test suite drive
     * the real binary.
     */
    static final class Reader {

        private final InputStream in;
        private final Console console;
        private final PrintStream promptStream;

        Reader(InputStream in, Console console, PrintStream promptStream) {
            this.in = in;
            this.console = console;
            this.promptStream = promptStream;
        }

        char[] readLine(String promptText) throws IOException {
            if (console != null) {
                String entered = console.readLine("%s", promptText);
                if (entered == null) {
                    throw new IOException("the input stream ended unexpectedly");
                }
                if (entered.length() > InputPolicy.MAX_FIELD_CHARS) {
                    throw new InputTooLong();
                }
                return entered.toCharArray();
            }
            return readCapped(promptText, InputPolicy.MAX_FIELD_CHARS, true);
        }

        char[] readSecret(String promptText) throws IOException {
            if (console != null) {
                char[] entered = console.readPassword("%s", promptText);
                if (entered == null) {
                    throw new IOException("the input stream ended unexpectedly");
                }
                return entered;
            }
            // On a terminal the keystroke that submits the password supplies the line break; on a
            // pipe nothing is echoed, so this path ends the prompt line itself. A newline carries no
            // information about the secret, and without it the next output line would render as part
            // of the prompt.
            return readCapped(promptText, InputPolicy.PASSWORD_MAX, true);
        }

        /** Reads up to {@code max} bytes before the newline; anything longer is refused outright. */
        private char[] readCapped(String promptText, int max, boolean echoNewline) throws IOException {
            promptStream.print(promptText);
            promptStream.flush();
            byte[] buffer = new byte[max + 1];
            int length = 0;
            boolean sawByte = false;
            int value;
            while ((value = in.read()) >= 0) {
                sawByte = true;
                if (value == '\n') {
                    break;
                }
                if (value == '\r') {
                    continue;
                }
                if (length >= buffer.length) {
                    // Cap reached: drain the rest of the line so the next prompt is not fed the
                    // tail of an oversized input, erase what we hold, then refuse.
                    while ((value = in.read()) >= 0 && value != '\n') {
                        // discarded on purpose
                    }
                    Arrays.fill(buffer, (byte) 0);
                    throw new InputTooLong();
                }
                buffer[length++] = (byte) value;
            }
            if (!sawByte) {
                throw new IOException("the input stream ended unexpectedly");
            }
            byte[] exact = Arrays.copyOf(buffer, length);
            Arrays.fill(buffer, (byte) 0);
            String decoded = new String(exact, StandardCharsets.UTF_8);
            Arrays.fill(exact, (byte) 0);
            if (echoNewline) {
                promptStream.println();
            }
            return decoded.toCharArray();
        }
    }

    /** Signals an oversized input line; mapped to the same generic refusal as any invalid input. */
    static final class InputTooLong extends IOException {
        private static final long serialVersionUID = 1L;
    }
}
