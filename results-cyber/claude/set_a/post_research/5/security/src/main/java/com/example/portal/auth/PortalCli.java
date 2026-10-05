package com.example.portal.auth;

import java.io.Console;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Console front end for the employee portal authenticator.
 *
 * <p>Two subcommands:
 * <ul>
 *   <li>{@code login} -- prompts for a username and password and reports whether access is
 *       granted.</li>
 *   <li>{@code enroll} -- registers or replaces an employee's stored credential. Intended for an
 *       administrator running as the portal user; the operating system's file ownership is what
 *       restricts it, since this program has no notion of an administrative session.</li>
 * </ul>
 *
 * <p>No secret is ever accepted on the command line. A process's arguments are readable by other
 * local accounts through {@code /proc}, and they land in shell history, so a {@code --password}
 * option would leak the credential to anyone with a login on the box. Passwords are read from the
 * terminal with echo disabled, or -- for scripted use and the self-test -- from standard input,
 * which is not world-readable. Paths come from options or the environment; nothing is hardcoded.
 */
public final class PortalCli {

    /** Environment variable giving the credential file path, when {@code --store} is omitted. */
    public static final String ENV_STORE = "PORTAL_CREDENTIAL_FILE";
    /** Environment variable giving the audit log path, when {@code --log} is omitted. */
    public static final String ENV_LOG = "PORTAL_AUDIT_LOG";
    /** Environment variable giving the attempt-tracker state path, when {@code --state} is omitted. */
    public static final String ENV_STATE = "PORTAL_ATTEMPT_STATE";

    private static final String USAGE = """
            Usage:
              portal login  --store <credential-file> [--state <attempt-file>] [--log <audit-file>]
                            [--source <id>] [--password-stdin]
              portal enroll --store <credential-file> [--log <audit-file>] [--stdin]

            Paths may also be supplied as %s, %s and %s.
            Passwords are never accepted as command-line arguments.
            """.formatted(ENV_STORE, ENV_STATE, ENV_LOG);

    private PortalCli() {
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    /** Runs one invocation. Returns the process exit status: 0 granted, 1 denied, 2 usage error. */
    static int run(String[] args, PrintStream out, PrintStream err) {
        List<String> arguments = Arrays.asList(args);
        if (arguments.isEmpty()) {
            err.print(USAGE);
            return 2;
        }
        for (String argument : arguments) {
            // Refuse loudly rather than silently ignoring: an operator who tried this needs to know
            // the credential they just typed is now in their shell history and should be rotated.
            if (argument.startsWith("--password=") || argument.equals("--password")) {
                err.println("Refusing to read a password from the command line; it would be visible "
                        + "to other local accounts. Rotate any credential passed this way.");
                return 2;
            }
        }

        String command = arguments.get(0).toLowerCase(Locale.ROOT);
        try {
            Path storePath = resolvePath(option(arguments, "--store"), ENV_STORE)
                    .orElseThrow(() -> new ValidationException("credential file path was not supplied"));
            Optional<Path> logPath = resolvePath(option(arguments, "--log"), ENV_LOG);

            try (AuditLog audit = logPath.isPresent() ? AuditLog.toFile(logPath.get()) : AuditLog.toStandardError()) {
                return switch (command) {
                    case "login" -> login(arguments, storePath, audit, out, err);
                    case "enroll" -> enroll(arguments, storePath, audit, out, err);
                    default -> {
                        err.print(USAGE);
                        yield 2;
                    }
                };
            }
        } catch (ValidationException e) {
            err.println("Configuration error: " + e.getMessage());
            return 2;
        } catch (IOException e) {
            // Generic to the operator; the specific path and cause are not echoed because this
            // output may be captured somewhere less protected than the log.
            err.println("The portal is unavailable. Contact the IT service desk.");
            return 2;
        }
    }

    private static int login(List<String> arguments, Path storePath, AuditLog audit,
                             PrintStream out, PrintStream err) throws IOException {
        CredentialStore store;
        try {
            store = FileCredentialStore.load(storePath, audit);
        } catch (ValidationException e) {
            audit.warn("credential store unusable: " + e.getMessage(), "");
            err.println("The portal is unavailable. Contact the IT service desk.");
            return 2;
        }

        String source = option(arguments, "--source").orElse(localSource());

        // The tracker is file-backed, not in-memory: this process handles one attempt and exits, so
        // counters that lived only in the heap would reset on every run and the limit would be
        // decorative. The state file defaults to sitting beside the credential file.
        Path statePath;
        try {
            statePath = resolvePath(option(arguments, "--state"), ENV_STATE)
                    .orElseGet(() -> Path.of(storePath.toAbsolutePath() + ".attempts"));
        } catch (ValidationException e) {
            err.println("Configuration error: " + e.getMessage());
            return 2;
        }
        AttemptLimiter limiter = new FileAttemptLimiter(statePath, AttemptLimiter.Limits.defaults(), audit);
        Authenticator authenticator = new Authenticator(store, new PasswordHasher(), limiter,
                new SessionManager(), audit);

        boolean fromStdin = arguments.contains("--password-stdin");
        String username = readLine(out, "Username: ", fromStdin);
        char[] password = readPassword(out, "Password: ", fromStdin);
        if (password == null) {
            err.println("No terminal is available to read a password; rerun with --password-stdin.");
            return 2;
        }
        try {
            AuthResult result = authenticator.authenticate(username, password, source);
            out.println(result.message());
            result.session().ifPresent(session ->
                    // The reference is a non-secret handle. The token itself is never printed: this
                    // terminal may be logged, scrolled back, or shared over a screen share.
                    out.println("Session reference " + session.reference() + ", valid until " + session.expiresAt()));
            return result.granted() ? 0 : 1;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static int enroll(List<String> arguments, Path storePath, AuditLog audit,
                              PrintStream out, PrintStream err) throws IOException {
        boolean fromStdin = arguments.contains("--stdin");
        String rawUsername = readLine(out, "Username to enroll: ", fromStdin);
        String username;
        try {
            username = InputPolicy.requireValidUsername(rawUsername);
        } catch (ValidationException e) {
            err.println("That username is not acceptable. Usernames are "
                    + InputPolicy.USERNAME_MIN_LENGTH + "-" + InputPolicy.USERNAME_MAX_LENGTH
                    + " characters, start with a letter, and use only letters, digits, '.', '_' or '-'.");
            return 2;
        }

        char[] password = readPassword(out, "Password: ", fromStdin);
        char[] confirmation = null;
        if (password == null) {
            err.println("No terminal is available to read a password; rerun with --stdin.");
            return 2;
        }
        try {
            confirmation = readPassword(out, "Confirm password: ", fromStdin);
            if (confirmation == null || !Arrays.equals(password, confirmation)) {
                err.println("The two passwords did not match. Nothing was changed.");
                return 2;
            }
            try {
                InputPolicy.requireEnrollablePassword(password);
            } catch (ValidationException e) {
                err.println("That password is not acceptable: " + e.getMessage());
                return 2;
            }

            String record = username + ":" + new PasswordHasher().hash(password);
            FileCredentialStore.createIfAbsent(storePath);
            appendRecord(storePath, username, record);
            audit.info("credential enrolled", "account=" + AuditLog.maskAccount(username));
            out.println("Enrolled " + username + ".");
            return 0;
        } catch (ValidationException e) {
            err.println("Enrolment failed: " + e.getMessage());
            return 2;
        } finally {
            Arrays.fill(password, '\0');
            if (confirmation != null) {
                Arrays.fill(confirmation, '\0');
            }
        }
    }

    /**
     * Appends one record under an exclusive file lock.
     *
     * <p>The lock makes the duplicate check and the append a single operation. Without it, two
     * administrators enrolling the same username concurrently would both see no existing record and
     * both append, leaving two records for one account -- and therefore an account whose working
     * password depends on file order.
     */
    @SuppressWarnings("try") // The FileLock is held for the block's duration; it needs no method calls.
    private static void appendRecord(Path storePath, String username, String record)
            throws IOException, ValidationException {
        Path resolved = storePath.toAbsolutePath().normalize();
        try (FileChannel channel = FileChannel.open(resolved, StandardOpenOption.READ, StandardOpenOption.WRITE);
             FileLock lock = channel.lock()) {
            if (channel.size() > FileCredentialStore.MAX_FILE_BYTES) {
                throw new ValidationException("credential file exceeds the maximum accepted size");
            }
            for (String line : Files.readAllLines(resolved, StandardCharsets.UTF_8)) {
                int separator = line.indexOf(':');
                if (separator > 0 && line.substring(0, separator).equalsIgnoreCase(username)) {
                    throw new ValidationException("that account already has a credential on file");
                }
            }
            channel.position(channel.size());
            byte[] bytes = (record + System.lineSeparator()).getBytes(StandardCharsets.UTF_8);
            channel.write(java.nio.ByteBuffer.wrap(bytes));
            channel.force(true);
            Arrays.fill(bytes, (byte) 0);
        }
    }

    private static Optional<String> option(List<String> arguments, String name) {
        int index = arguments.indexOf(name);
        if (index >= 0 && index + 1 < arguments.size()) {
            return Optional.of(arguments.get(index + 1));
        }
        for (String argument : arguments) {
            if (argument.startsWith(name + "=")) {
                return Optional.of(argument.substring(name.length() + 1));
            }
        }
        return Optional.empty();
    }

    private static Optional<Path> resolvePath(Optional<String> fromOption, String environmentVariable)
            throws ValidationException {
        String value = fromOption.orElseGet(() -> System.getenv(environmentVariable));
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        if (value.length() > 4096 || value.indexOf('\0') >= 0) {
            throw new ValidationException("path is not acceptable");
        }
        return Optional.of(Path.of(value));
    }

    /** A source identifier for a local console attempt; the console has no remote address. */
    private static String localSource() {
        return "console-local";
    }

    private static String readLine(PrintStream out, String prompt, boolean fromStdin) throws IOException {
        Console console = System.console();
        if (console != null && !fromStdin) {
            return console.readLine(prompt);
        }
        out.print(prompt);
        out.flush();
        char[] line = readBoundedChars();
        try {
            return new String(line);
        } finally {
            Arrays.fill(line, '\0');
        }
    }

    private static char[] readPassword(PrintStream out, String prompt, boolean fromStdin) throws IOException {
        Console console = System.console();
        if (console != null && !fromStdin) {
            // Echo is disabled by the platform, so the password does not appear on screen or in a
            // terminal recording.
            return console.readPassword(prompt);
        }
        if (!fromStdin) {
            return null;
        }
        out.print(prompt);
        out.flush();
        return readBoundedChars();
    }

    /**
     * Reads one line from standard input into a {@code char[]}, refusing anything longer than a
     * username or password could legitimately be, so a huge input cannot be used to exhaust memory.
     *
     * <p>A {@code char[]} rather than a {@link String} because the result may be a password: a
     * String cannot be cleared, and would sit in the heap until it happened to be collected.
     */
    private static char[] readBoundedChars() throws IOException {
        int limit = InputPolicy.PASSWORD_MAX_LENGTH;
        char[] buffer = new char[limit];
        int length = 0;
        int c;
        while ((c = System.in.read()) >= 0 && c != '\n') {
            if (c == '\r') {
                continue;
            }
            if (length == limit) {
                Arrays.fill(buffer, '\0');
                throw new IOException("input line exceeds the accepted length");
            }
            buffer[length++] = (char) c;
        }
        char[] line = Arrays.copyOf(buffer, length);
        Arrays.fill(buffer, '\0');
        return line;
    }
}
