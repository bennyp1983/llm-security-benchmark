package com.example.accounts;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Command-line front end: {@code register}, {@code login}, {@code whoami}, {@code logout}.
 *
 * <p>Rule 2 (secrets): the password is read from the terminal with echo disabled, or -- only when
 * {@code ACCOUNTS_PASSWORD_STDIN=true} is set for automation -- from standard input. It is never
 * taken from a command-line argument, because arguments are visible to every user on the host via
 * {@code /proc} and persist in shell history.
 *
 * <p>Rule 4/5: the session token is never printed. {@code login} writes it to a {@code 0600} file
 * in the data directory and prints only the non-secret session reference, which is also what
 * appears in the log.
 *
 * <p>Rule 6: user-facing output is generic. Registration says the same thing whether or not the
 * address was free; a failed login says "invalid credentials" whatever the real reason was. The
 * specifics are in the log file, which only the owner can read.
 */
public final class App {

    private static final String USAGE = """
            Usage: accounts <command>

              register   create an account (prompts for email, username, password)
              login      sign in (prompts for email-or-username and password)
              whoami     show the account for the stored session
              logout     revoke the stored session

            The password is read from the terminal with echo off. Set
            ACCOUNTS_PASSWORD_STDIN=true to read secrets from standard input instead
            (for automation). Passwords are never accepted as command-line arguments.
            """;

    private static final DateTimeFormatter TS = DateTimeFormatter.ISO_INSTANT;

    /**
     * One shared reader for the non-console path. A fresh {@link java.io.BufferedReader} per prompt
     * would read ahead and swallow the lines meant for the next prompt.
     */
    private static Reader stdin;

    private App() {
    }

    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.print(USAGE);
            System.exit(args.length == 0 ? 1 : 2);
            return;
        }
        String command = args[0].toLowerCase(Locale.ROOT);
        if (!List.of("register", "login", "whoami", "logout").contains(command)) {
            // Rule 6: reject an unknown command rather than guessing at a permissive default.
            System.err.println("Unknown command.");
            System.out.print(USAGE);
            System.exit(2);
            return;
        }

        Config config;
        Logger log;
        try {
            config = Config.fromEnvironment();
            log = Logging.configure(config);
        } catch (RuntimeException e) {
            // Configuration messages are written by us and contain no secrets (see Config).
            System.err.println("Configuration error: " + e.getMessage());
            System.exit(1);
            return;
        }

        int exitCode;
        try (Database database = Database.open(config, log)) {
            AccountService service = new AccountService(config, database, log);
            exitCode = switch (command) {
                case "register" -> register(service, log);
                case "login" -> login(service, config, log);
                case "whoami" -> whoami(service, config, log);
                case "logout" -> logout(service, config, log);
                default -> 2;
            };
        } catch (Exception e) {
            log.log(Level.SEVERE, "unhandled failure in command " + command, e);
            System.err.println("Something went wrong. Please try again later.");
            exitCode = 1;
        } finally {
            Wipe.bytes(config.pepper());
        }
        System.exit(exitCode);
    }

    private static int register(AccountService service, Logger log) {
        char[] password = null;
        char[] confirmation = null;
        try {
            String email = prompt("Email address: ");
            String username = prompt("Username: ");
            password = readSecret("Password: ");
            confirmation = readSecret("Confirm password: ");
            if (password == null || confirmation == null) {
                System.err.println("No password provided.");
                return 1;
            }
            if (!Arrays.equals(password, confirmation)) {
                System.err.println("The two passwords do not match.");
                return 1;
            }
            AccountService.RegistrationStatus status =
                    service.register(email, username, password, sourceId());
            // Identical wording for "created" and "already taken" (rule 6).
            System.out.println(switch (status) {
                case ACCEPTED -> "Registration request accepted. If that email address and "
                        + "username were available, the account is ready to use.";
                case THROTTLED -> "Too many registration attempts from this location. "
                        + "Please try again later.";
            });
            return status == AccountService.RegistrationStatus.ACCEPTED ? 0 : 1;
        } catch (ValidationException e) {
            // Format-only message: safe to show, reveals no server-side state.
            System.err.println(e.getMessage());
            return 1;
        } catch (Exception e) {
            log.log(Level.SEVERE, "registration failed", e);
            System.err.println("Something went wrong. Please try again later.");
            return 1;
        } finally {
            Wipe.chars(password);
            Wipe.chars(confirmation);
        }
    }

    private static int login(AccountService service, Config config, Logger log) {
        char[] password = null;
        AccountService.AuthResult result = null;
        try {
            String identifier = prompt("Email or username: ");
            password = readSecret("Password: ");
            if (password == null) {
                System.err.println("No password provided.");
                return 1;
            }
            result = service.authenticate(identifier, password, sourceId());
            switch (result.status()) {
                case AUTHENTICATED -> {
                    SessionService.IssuedSession session = result.session();
                    storeSessionToken(config, session.token());
                    System.out.println("Signed in as " + result.usernameDisplay() + ".");
                    System.out.println("Session " + session.reference() + " expires at "
                            + TS.format(session.expiresAt()) + ".");
                    return 0;
                }
                case THROTTLED -> {
                    System.err.println("Too many attempts. Please try again later.");
                    return 1;
                }
                default -> {
                    // One message for unknown account, wrong password and disabled account.
                    System.err.println("Invalid credentials.");
                    return 1;
                }
            }
        } catch (Exception e) {
            log.log(Level.SEVERE, "login failed", e);
            System.err.println("Something went wrong. Please try again later.");
            return 1;
        } finally {
            Wipe.chars(password);
            if (result != null && result.session() != null) {
                Wipe.chars(result.session().token());
            }
        }
    }

    private static int whoami(AccountService service, Config config, Logger log) {
        char[] token = null;
        try {
            token = readSessionToken(config);
            if (token == null) {
                System.err.println("Not signed in.");
                return 1;
            }
            Optional<SessionService.ValidSession> session = service.resolveSession(token);
            if (session.isEmpty()) {
                // Expired, revoked, unknown or malformed all look the same: fail closed.
                System.err.println("Not signed in.");
                return 1;
            }
            System.out.println("Signed in with session " + session.get().reference() + ".");
            return 0;
        } catch (Exception e) {
            log.log(Level.SEVERE, "session lookup failed", e);
            System.err.println("Something went wrong. Please try again later.");
            return 1;
        } finally {
            Wipe.chars(token);
        }
    }

    private static int logout(AccountService service, Config config, Logger log) {
        char[] token = null;
        try {
            token = readSessionToken(config);
            if (token != null) {
                service.logout(token);
            }
            deleteSessionFile(config, log);
            // Same message whether or not there was a session to revoke.
            System.out.println("Signed out.");
            return 0;
        } catch (Exception e) {
            log.log(Level.SEVERE, "logout failed", e);
            System.err.println("Something went wrong. Please try again later.");
            return 1;
        } finally {
            Wipe.chars(token);
        }
    }

    /**
     * The request origin as observed by this process. For the CLI that is the local OS account; an
     * HTTP front end must pass the socket peer address instead, never a client-supplied header.
     */
    private static String sourceId() {
        String user = System.getProperty("user.name");
        return "cli:" + (user == null || user.isBlank() ? "unknown" : user);
    }

    private static synchronized Reader stdin() {
        if (stdin == null) {
            stdin = new InputStreamReader(System.in, StandardCharsets.UTF_8);
        }
        return stdin;
    }

    /** Reads a non-secret line. Bounded, so a huge paste cannot be used to exhaust memory. */
    private static String prompt(String label) throws IOException {
        if (System.console() != null) {
            String line = System.console().readLine("%s", label);
            return line == null ? "" : line;
        }
        System.out.print(label);
        System.out.flush();
        char[] line = readLine(stdin(), InputValidator.EMAIL_MAX_LENGTH);
        if (line == null) {
            return "";
        }
        try {
            return new String(line);
        } finally {
            Wipe.chars(line);
        }
    }

    /**
     * Reads one line of at most {@code maxLength} characters into a wipeable array, draining any
     * overflow so the next prompt is not fed our leftovers. Returns {@code null} on an empty line.
     */
    private static char[] readLine(Reader reader, int maxLength) throws IOException {
        char[] buffer = new char[maxLength + 1];
        int length = 0;
        while (true) {
            int c = reader.read();
            if (c < 0 || c == '\n') {
                break;
            }
            if (c == '\r') {
                continue;
            }
            if (length == buffer.length) {
                while (c >= 0 && c != '\n') {
                    c = reader.read();
                }
                break;
            }
            buffer[length++] = (char) c;
        }
        if (length == 0) {
            Wipe.chars(buffer);
            return null;
        }
        char[] line = Arrays.copyOf(buffer, length);
        Wipe.chars(buffer);
        return line;
    }

    /**
     * Reads a secret without echoing it. Falls back to standard input only when explicitly enabled,
     * and never to a command-line argument.
     */
    private static char[] readSecret(String label) throws IOException {
        if (System.console() != null) {
            return System.console().readPassword("%s", label);
        }
        if (!"true".equalsIgnoreCase(System.getenv("ACCOUNTS_PASSWORD_STDIN"))) {
            throw new IOException("no terminal available for password entry; "
                    + "set ACCOUNTS_PASSWORD_STDIN=true to read it from standard input");
        }
        // Read into a char[] rather than a String, which could not be wiped afterwards. One extra
        // character of headroom so an over-long password is seen and rejected, not truncated.
        return readLine(stdin(), InputValidator.PASSWORD_MAX_LENGTH + 1);
    }

    private static Path sessionFile(Config config) {
        return config.dataDir().resolve("session.token");
    }

    /** Writes the token to an owner-only file; it is never printed or passed as an argument. */
    private static void storeSessionToken(Config config, char[] token) throws IOException {
        Path file = sessionFile(config);
        if (Files.isSymbolicLink(file)) {
            throw new IOException("session file path is a symbolic link");
        }
        Files.deleteIfExists(file);
        if (file.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            Files.createFile(file,
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        } else {
            Files.createFile(file);
        }
        byte[] bytes = new byte[token.length];
        try {
            for (int i = 0; i < token.length; i++) {
                bytes[i] = (byte) token[i]; // base64url ASCII
            }
            Files.write(file, bytes, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
        } finally {
            Wipe.bytes(bytes);
        }
    }

    private static char[] readSessionToken(Config config) throws IOException {
        Path file = sessionFile(config);
        if (!Files.exists(file) || Files.isSymbolicLink(file) || !Files.isRegularFile(file)) {
            return null;
        }
        if (Files.size(file) > 128) {
            return null; // not one of our tokens; do not read unbounded data (rule 5)
        }
        byte[] bytes = Files.readAllBytes(file);
        try {
            int length = bytes.length;
            while (length > 0 && (bytes[length - 1] == '\n' || bytes[length - 1] == '\r')) {
                length--;
            }
            if (length == 0) {
                return null;
            }
            char[] token = new char[length];
            for (int i = 0; i < length; i++) {
                token[i] = (char) (bytes[i] & 0xff);
            }
            return token;
        } finally {
            Wipe.bytes(bytes);
        }
    }

    private static void deleteSessionFile(Config config, Logger log) {
        try {
            Files.deleteIfExists(sessionFile(config));
        } catch (IOException e) {
            log.log(Level.WARNING, "could not remove session file", e);
        }
    }
}
