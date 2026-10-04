package com.example.auth;

import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Locale;
import java.util.Map;

/**
 * Command line front end.
 *
 * <p>Secrets never travel through the argument vector, so {@code ps} and a shell history file cannot
 * leak them: the credential being checked is read from the terminal with echo suppressed
 * ({@link Console#readPassword(char[])}) or from standard input, and the storage credential comes
 * from {@code AUTH_DB_PASSWORD} or a hidden prompt.
 *
 * <p>Only two strings are ever printed for an authentication attempt - one success, one failure - and
 * the failure string is identical for every internal reason: unknown address, wrong password, spent
 * budget, malformed input, unusable stored row, storage down. Reason codes go to the audit log only.
 *
 * <p>Charset discipline: a console whose charset is not UTF-8 decodes a non-ASCII password lossily
 * (US-ASCII maps every byte above 0x7F to {@code '?'}), which can make two different passwords verify
 * identically. When that is detected the program refuses to start rather than authenticate over a
 * lossy transport. On the piped path the bytes are decoded here, strictly, so an invalid UTF-8
 * sequence is refused instead of replaced by U+FFFD; the decoded secret goes straight into a
 * {@code char[]} and no {@code String} ever holds it.
 */
public final class Main {

    static final String SUCCESS_MESSAGE = "Authentication successful.";
    static final String FAILURE_MESSAGE = "Authentication failed.";
    static final String SEED_SUCCESS_MESSAGE = "Account created.";
    static final String SEED_FAILURE_MESSAGE = "account not created";
    private static final String USAGE =
            "usage: java -cp <classes>:<h2.jar> com.example.auth.Main [command]\n"
                    + "  login   authenticate an email address and password (default)\n"
                    + "  seed    add one account to the credential store\n"
                    + "  help    show this text\n"
                    + "required environment: AUTH_DB_PATH, AUTH_DB_USER (see README.md)";

    private static final int MAX_LINE_BYTES = 4096;
    static final int EXIT_GRANTED = 0;
    static final int EXIT_DENIED = 1;
    static final int EXIT_USAGE = 2;
    static final int EXIT_BOOT = 3;

    private Main() {
    }

    public static void main(String[] args) {
        int code = run(args, System.getenv(), System.console(), System.in, System.out, System.err);
        // halt() rather than exit() so no shutdown hook runs after we return, including the JDBC
        // driver's DB_CLOSE_ON_EXIT finaliser. Every resource is closed on every path below and
        // nothing of ours survives the process either way.
        Runtime.getRuntime().halt(code);
    }

    /**
     * Everything {@link #main} does, with its environment injectable so the front end is testable
     * in-process. Returns the exit code instead of calling {@code System.exit}.
     */
    static int run(String[] args, Map<String, String> env, Console console, InputStream stdin,
            PrintStream out, PrintStream err) {
        String command = "login";
        if (args.length == 1) {
            command = args[0];
        } else if (args.length > 1) {
            err.println(USAGE);
            return EXIT_USAGE;
        }
        if ("help".equals(command) || "--help".equals(command) || "-h".equals(command)) {
            out.println(USAGE);
            return EXIT_GRANTED;
        }
        if (!"login".equals(command) && !"seed".equals(command)) {
            err.println(USAGE);
            return EXIT_USAGE;
        }

        Config config;
        try {
            config = Config.load(env);
        } catch (Config.ConfigException e) {
            // Configuration faults are operator-facing. The message is a fixed code token that
            // Config built from the name of the offending setting, never from its value.
            err.println("startup refused: " + e.getMessage());
            return EXIT_BOOT;
        }

        // hasConfiguredDbPassword() must be read before takeDbPassword() clears the field.
        boolean credentialConfigured = config.hasConfiguredDbPassword();
        char[] dbPassword = config.takeDbPassword();
        try (Stdin in = new Stdin(stdin, console, err)) {
            try {
                if (!credentialConfigured) {
                    if (!in.consoleIsUsable()) {
                        // Refusing beats two worse outcomes: creating a credential store protected by
                        // an empty storage credential, or prompting on a stream we cannot prompt on.
                        err.println("startup refused: storage_credential_unavailable");
                        return EXIT_BOOT;
                    }
                    wipe(dbPassword);
                    dbPassword = in.promptStorageCredential(config.dbUser());
                    if (dbPassword.length == 0) {
                        err.println("startup refused: storage_credential_unavailable");
                        return EXIT_BOOT;
                    }
                }
                return operate(config, command, dbPassword, in, out, err);
            } catch (BootRefusal e) {
                return EXIT_BOOT;
            }
        } finally {
            wipe(dbPassword);
        }
    }

    /**
     * Opens the store and runs one command. {@code dbPassword} is wiped by {@link Database#open}
     * itself; the caller's {@code finally} re-zeroes the same (already empty) buffer, which is
     * harmless and also covers the paths that never reach {@code open}.
     */
    private static int operate(Config config, String command, char[] dbPassword, Stdin in,
            PrintStream out, PrintStream err) {
        Path auditPath = config.auditLogPath() == null
                ? Path.of(config.dbPath() + ".audit.log")
                : Path.of(config.auditLogPath());
        LogWriter audit;
        try {
            audit = LogWriter.open(auditPath);
        } catch (IOException | RuntimeException e) {
            // Never echo the exception message: it can name the configured path.
            err.println("startup refused: audit_log_unavailable");
            throw new BootRefusal();
        }
        try (LogWriter store = audit) {
            Database db;
            try {
                db = Database.open(config, dbPassword);
            } catch (Database.StorageException e) {
                store.log(LogWriter.Event.BOOT_FAIL, "*", 0);
                err.println("startup refused: " + e.getMessage());
                throw new BootRefusal();
            }
            try (Database opened = db) {
                store.log(LogWriter.Event.BOOT_OK, "*", 0);
                if ("seed".equals(command)) {
                    return doSeed(config, opened, store, in, out, err);
                }
                AuthService service = new AuthService(config, opened, store);
                return doLogin(config, service, in, out, err);
            }
        }
    }

    private static int doLogin(Config config, AuthService service, Stdin in, PrintStream out,
            PrintStream err) {
        String email = in.readLine("Email address: ");
        char[] password = in.readSecret("Password: ");
        try {
            AuthService.Result result = service.authenticate(email, password);
            if (result.granted()) {
                out.println(SUCCESS_MESSAGE);
                if (config.emitSession() && result.sessionToken != null) {
                    // A bearer credential: stderr only, never the audit log, and only when the
                    // operator asked for it.
                    err.println("session (bearer credential, " + config.sessionTtlSec()
                            + "s, cookie attributes: " + SessionStore.cookieAttributesFor() + "): "
                            + result.sessionToken);
                }
                return EXIT_GRANTED;
            }
            out.println(FAILURE_MESSAGE);
            return EXIT_DENIED;
        } finally {
            wipe(password);
        }
    }

    private static int doSeed(Config config, Database db, LogWriter audit, Stdin in,
            PrintStream out, PrintStream err) {
        String email = in.readLine("New account email: ");
        char[] first = in.readSecret("New password: ");
        char[] again = in.readSecret("Repeat password: ");
        try {
            if (first.length == 0 || !Arrays.equals(first, again)) {
                err.println(SEED_FAILURE_MESSAGE);
                return EXIT_DENIED;
            }
            AccountSeeder seeder = new AccountSeeder(config, db, audit);
            AccountSeeder.SeedResult result;
            try {
                result = seeder.seed(email, first);
            } catch (Database.StorageException e) {
                audit.log(LogWriter.Event.BOOT_FAIL, "*", 0);
                err.println("seed refused: " + e.getMessage());
                return EXIT_BOOT;
            }
            if (result == AccountSeeder.SeedResult.CREATED) {
                out.println(SEED_SUCCESS_MESSAGE);
                return EXIT_GRANTED;
            }
            err.println(SEED_FAILURE_MESSAGE);
            return result == AccountSeeder.SeedResult.ALREADY_EXISTS ? EXIT_DENIED : EXIT_USAGE;
        } finally {
            wipe(first);
            wipe(again);
        }
    }

    private static void wipe(char[] buffer) {
        if (buffer != null) {
            Arrays.fill(buffer, (char) 0);
        }
    }

    /**
     * Bounded input from the terminal or from a pipe. Every read is capped in bytes; an over-long
     * line, invalid UTF-8, or end of input yields nothing, and every caller treats "nothing" as a
     * refusal - never as an empty credential and never as a reason to retry.
     */
    static final class Stdin implements AutoCloseable {

        private final InputStream raw;
        private final Console console;
        private final PrintStream err;
        private final CharsetDecoder strictUtf8 = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);

        Stdin(InputStream raw, Console console, PrintStream err) {
            this.raw = raw;
            this.console = console;
            this.err = err;
            if (console != null && !isUtf8(console.charset())) {
                err.println("startup refused: console_charset_unsupported ("
                        + (console.charset() == null ? "unknown" : console.charset().name())
                        + "); run under a UTF-8 locale");
                throw new BootRefusal();
            }
        }

        private static boolean isUtf8(Charset cs) {
            if (cs == null) {
                return false;
            }
            String n = cs.name().toUpperCase(Locale.ROOT);
            return "UTF-8".equals(n) || "UTF8".equals(n);
        }

        boolean consoleIsUsable() {
            return console != null;
        }

        char[] promptStorageCredential(String user) {
            char[] pw = console.readPassword("Storage credential for %s: ", user);
            return pw == null ? new char[0] : pw;
        }

        /** One line of text, or null on end of input, over-long line, or invalid encoding. */
        String readLine(String prompt) {
            if (console != null) {
                String line = console.readLine("%s", prompt);
                return (line == null || line.length() > MAX_LINE_BYTES) ? null : line;
            }
            prompt(prompt);
            byte[] bytes = readLineBytes();
            if (bytes == null) {
                return null;
            }
            try {
                // decode() resets the decoder first, so one instance is safe to reuse.
                return strictUtf8.decode(ByteBuffer.wrap(bytes)).toString();
            } catch (CharacterCodingException e) {
                return null;
            } finally {
                Arrays.fill(bytes, (byte) 0);
            }
        }

        /** A secret, decoded into a fresh {@code char[]} with no intervening {@code String}. */
        char[] readSecret(String prompt) {
            if (console != null) {
                char[] pw = console.readPassword("%s", prompt);
                if (pw == null) {
                    return new char[0];
                }
                if (InputValidator.utf8Length(pw) > InputValidator.PASSWORD_MAX_UTF8_BYTES) {
                    Arrays.fill(pw, (char) 0);
                    return new char[0];
                }
                return pw;
            }
            prompt(prompt);
            byte[] bytes = readLineBytes();
            if (bytes == null) {
                return new char[0];
            }
            CharBuffer chars = null;
            try {
                chars = strictUtf8.decode(ByteBuffer.wrap(bytes));
                char[] pw = new char[chars.length()];
                chars.get(pw);
                return pw;
            } catch (CharacterCodingException e) {
                return new char[0];
            } finally {
                Arrays.fill(bytes, (byte) 0);
                if (chars != null && chars.hasArray()) {
                    Arrays.fill(chars.array(), (char) 0);
                }
            }
        }

        private void prompt(String text) {
            // Prompts go to stderr so the two outcome messages on stdout stay machine-readable and a
            // prompt can never be mistaken for a result.
            err.print(text);
            err.flush();
        }

        /**
         * Reads up to and including the next newline. Returns null for end-of-input-with-no-data, an
         * over-long line, or a read error. The caller owns the returned array and zeroes it.
         */
        private byte[] readLineBytes() {
            byte[] buf = new byte[MAX_LINE_BYTES];
            int len = 0;
            boolean overrun = false;
            boolean sawData = false;
            int b;
            try {
                while ((b = raw.read()) != -1) {
                    sawData = true;
                    if (b == '\n') {
                        break;
                    }
                    if (b == '\r') {
                        continue;
                    }
                    if (len < MAX_LINE_BYTES) {
                        buf[len++] = (byte) b;
                    } else {
                        overrun = true;
                    }
                }
            } catch (IOException e) {
                Arrays.fill(buf, (byte) 0);
                return null;
            }
            if (!sawData || overrun || len == 0) {
                Arrays.fill(buf, (byte) 0);
                return null;
            }
            return Arrays.copyOf(buf, len);
        }

        @Override
        public void close() {
            // The standard streams belong to the caller; closing them here would break the caller.
        }
    }

    /** A startup refusal that has already been reported; unwinds {@link #run} silently. */
    static final class BootRefusal extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }
}
