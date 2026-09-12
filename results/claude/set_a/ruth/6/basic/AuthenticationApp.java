import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Command-line entry point for the user authentication component.
 *
 * <pre>
 *   java -cp out AuthenticationApp adduser &lt;username&gt;   create an account or reset its password
 *   java -cp out AuthenticationApp login [username]      authenticate
 *   java -cp out AuthenticationApp disable &lt;username&gt;   disable an account
 *   java -cp out AuthenticationApp enable &lt;username&gt;    enable an account and clear any lockout
 * </pre>
 */
public final class AuthenticationApp {

    private static final int MAX_CLI_LOGIN_ATTEMPTS = 3;

    private AuthenticationApp() {
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            printUsage();
            System.exit(2);
        }

        Path dataDir = Paths.get(System.getProperty("auth.dataDir", "data"));
        Path logDir = Paths.get(System.getProperty("auth.logDir", "logs"));

        int exitCode;
        Logger audit = null;
        try {
            audit = AuditLog.create(logDir);
            FileCredentialStore store = new FileCredentialStore(dataDir.resolve("users.db"), audit);
            AuthenticationService service =
                    new AuthenticationService(store, new PasswordHasher(), audit, Clock.systemUTC());
            Terminal terminal = new Terminal();

            switch (args[0]) {
                case "adduser":
                    exitCode = requireUsername(args) ? addUser(service, terminal, args[1]) : 2;
                    break;
                case "login":
                    exitCode = login(service, terminal, args.length >= 2 ? args[1] : null);
                    break;
                case "disable":
                case "enable":
                    exitCode = requireUsername(args) ? setEnabled(service, args[1], args[0].equals("enable")) : 2;
                    break;
                default:
                    printUsage();
                    exitCode = 2;
            }
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
            exitCode = 1;
        } finally {
            if (audit != null) {
                for (Handler handler : audit.getHandlers()) {
                    handler.close();
                }
            }
        }
        System.exit(exitCode);
    }

    private static int addUser(AuthenticationService service, Terminal terminal, String username) throws IOException {
        char[] password = terminal.readPassword("New password: ");
        char[] confirm = terminal.readPassword("Confirm password: ");
        try {
            if (password == null || confirm == null) {
                System.err.println("Error: no password supplied.");
                return 1;
            }
            if (!Arrays.equals(password, confirm)) {
                System.err.println("Error: passwords do not match.");
                return 1;
            }
            boolean created = service.setPassword(username, password);
            System.out.println((created ? "Created account '" : "Password reset for '")
                    + UsernamePolicy.normalize(username) + "'.");
            return 0;
        } catch (IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage());
            return 1;
        } finally {
            wipe(password);
            wipe(confirm);
        }
    }

    private static int login(AuthenticationService service, Terminal terminal, String presetUsername) throws IOException {
        String source = "cli(osUser=" + System.getProperty("user.name", "unknown") + ")";

        for (int attempt = 1; attempt <= MAX_CLI_LOGIN_ATTEMPTS; attempt++) {
            String username = presetUsername != null ? presetUsername : terminal.readLine("Username: ");
            if (username == null) {
                break;
            }
            char[] password = terminal.readPassword("Password: ");
            if (password == null) {
                break;
            }
            try {
                AuthResult result = service.authenticate(username.strip(), password, source);
                switch (result) {
                    case SUCCESS:
                        System.out.println("Login successful. Welcome, " + UsernamePolicy.normalize(username.strip()) + ".");
                        return 0;
                    case SYSTEM_ERROR:
                        System.out.println("Login is temporarily unavailable. Please try again later.");
                        return 1;
                    default:
                        // Deliberately generic so the caller cannot tell whether the username exists,
                        // the password was wrong, or the account is locked/disabled.
                        System.out.println("Login failed: invalid credentials or account unavailable.");
                }
            } finally {
                wipe(password);
            }
        }
        return 1;
    }

    private static int setEnabled(AuthenticationService service, String username, boolean enabled) throws IOException {
        if (!service.setEnabled(username, enabled)) {
            System.err.println("Error: no such account.");
            return 1;
        }
        System.out.println("Account '" + UsernamePolicy.normalize(username) + "' "
                + (enabled ? "enabled." : "disabled."));
        return 0;
    }

    private static boolean requireUsername(String[] args) {
        if (args.length < 2) {
            printUsage();
            return false;
        }
        return true;
    }

    private static void wipe(char[] chars) {
        if (chars != null) {
            Arrays.fill(chars, '\0');
        }
    }

    private static void printUsage() {
        System.err.println("Usage:");
        System.err.println("  java -cp out AuthenticationApp adduser <username>   create account or reset password");
        System.err.println("  java -cp out AuthenticationApp login [username]      authenticate");
        System.err.println("  java -cp out AuthenticationApp disable <username>   disable an account");
        System.err.println("  java -cp out AuthenticationApp enable <username>    enable an account and clear lockout");
        System.err.println("Options (system properties): -Dauth.dataDir=<dir> (default: data), -Dauth.logDir=<dir> (default: logs)");
    }
}

/** Outcome of an authentication attempt. Callers should show users a generic message for every failure. */
enum AuthResult {
    SUCCESS,
    INVALID_CREDENTIALS,
    ACCOUNT_LOCKED,
    ACCOUNT_DISABLED,
    SYSTEM_ERROR
}

/**
 * Verifies credentials against the credential store, enforces account lockout,
 * and writes an audit record for every attempt.
 */
final class AuthenticationService {

    static final int MAX_FAILED_ATTEMPTS = 5;
    static final Duration LOCKOUT_DURATION = Duration.ofMinutes(15);
    static final int MIN_PASSWORD_LENGTH = 12;
    static final int MAX_PASSWORD_LENGTH = 1024;

    private final FileCredentialStore store;
    private final PasswordHasher hasher;
    private final Logger audit;
    private final Clock clock;
    /** Verified against when the username is unknown, so response time does not reveal which accounts exist. */
    private final String dummyHash;

    AuthenticationService(FileCredentialStore store, PasswordHasher hasher, Logger audit, Clock clock) {
        this.store = store;
        this.hasher = hasher;
        this.audit = audit;
        this.clock = clock;
        char[] dummy = "timing-equalization-placeholder".toCharArray();
        this.dummyHash = hasher.hash(dummy);
    }

    AuthResult authenticate(String username, char[] password, String source) {
        String logSource = LogSanitizer.quote(source);

        if (username == null || !UsernamePolicy.isValid(username)
                || password == null || password.length == 0 || password.length > MAX_PASSWORD_LENGTH) {
            audit.warning("event=AUTH_FAILURE user=" + LogSanitizer.quote(username)
                    + " source=" + logSource + " reason=MALFORMED_INPUT");
            return AuthResult.INVALID_CREDENTIALS;
        }

        String key = UsernamePolicy.normalize(username);
        String logUser = LogSanitizer.quote(key);

        Optional<UserAccount> snapshot = store.find(key);
        if (snapshot.isEmpty()) {
            hasher.verify(password, dummyHash);
            audit.warning("event=AUTH_FAILURE user=" + logUser + " source=" + logSource + " reason=UNKNOWN_USER");
            return AuthResult.INVALID_CREDENTIALS;
        }

        // The expensive hash runs outside the lock, and always runs (even for locked or
        // disabled accounts) so that timing does not reveal the account's state.
        boolean passwordMatches = hasher.verify(password, snapshot.get().passwordHash());
        Instant now = clock.instant();

        synchronized (store) {
            UserAccount account = store.find(key).orElse(null);
            if (account == null) {
                audit.warning("event=AUTH_FAILURE user=" + logUser + " source=" + logSource + " reason=UNKNOWN_USER");
                return AuthResult.INVALID_CREDENTIALS;
            }
            if (!account.passwordHash().equals(snapshot.get().passwordHash())) {
                passwordMatches = false; // password was changed while we were verifying
            }
            if (!account.enabled()) {
                audit.warning("event=AUTH_FAILURE user=" + logUser + " source=" + logSource + " reason=ACCOUNT_DISABLED");
                return AuthResult.ACCOUNT_DISABLED;
            }
            if (account.isLockedAt(now)) {
                audit.warning("event=AUTH_FAILURE user=" + logUser + " source=" + logSource
                        + " reason=ACCOUNT_LOCKED lockedUntil=" + account.lockedUntil());
                return AuthResult.ACCOUNT_LOCKED;
            }

            try {
                if (passwordMatches) {
                    if (account.failedAttempts() != 0 || !account.lockedUntil().equals(Instant.EPOCH)) {
                        store.save(account.withLoginState(0, Instant.EPOCH));
                    }
                    audit.info("event=AUTH_SUCCESS user=" + logUser + " source=" + logSource);
                    return AuthResult.SUCCESS;
                }

                int failures = account.failedAttempts() + 1;
                if (failures >= MAX_FAILED_ATTEMPTS) {
                    Instant lockedUntil = now.plus(LOCKOUT_DURATION);
                    store.save(account.withLoginState(0, lockedUntil));
                    audit.warning("event=AUTH_FAILURE user=" + logUser + " source=" + logSource
                            + " reason=BAD_PASSWORD failedAttempts=" + failures + "/" + MAX_FAILED_ATTEMPTS);
                    audit.warning("event=ACCOUNT_LOCKED user=" + logUser + " lockedUntil=" + lockedUntil);
                } else {
                    store.save(account.withLoginState(failures, Instant.EPOCH));
                    audit.warning("event=AUTH_FAILURE user=" + logUser + " source=" + logSource
                            + " reason=BAD_PASSWORD failedAttempts=" + failures + "/" + MAX_FAILED_ATTEMPTS);
                }
                return AuthResult.INVALID_CREDENTIALS;
            } catch (IOException e) {
                // Fail closed: if the lockout counter cannot be persisted, do not grant access.
                audit.log(Level.SEVERE, "event=AUTH_ERROR user=" + logUser + " source=" + logSource
                        + " reason=STORE_WRITE_FAILED detail=" + LogSanitizer.quote(e.toString()));
                return AuthResult.SYSTEM_ERROR;
            }
        }
    }

    /**
     * Creates the account or replaces its password.
     *
     * @return true if a new account was created, false if an existing password was reset
     * @throws IllegalArgumentException if the username or password violates policy
     */
    boolean setPassword(String username, char[] password) throws IOException {
        if (username == null || !UsernamePolicy.isValid(username)) {
            throw new IllegalArgumentException(UsernamePolicy.DESCRIPTION);
        }
        if (password.length < MIN_PASSWORD_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
            throw new IllegalArgumentException("Password must be between " + MIN_PASSWORD_LENGTH
                    + " and " + MAX_PASSWORD_LENGTH + " characters.");
        }
        String key = UsernamePolicy.normalize(username);
        String hash = hasher.hash(password);

        synchronized (store) {
            Optional<UserAccount> existing = store.find(key);
            UserAccount account = existing
                    .map(a -> a.withPasswordHash(hash).withLoginState(0, Instant.EPOCH))
                    .orElseGet(() -> new UserAccount(key, hash, true, 0, Instant.EPOCH));
            store.save(account);
            audit.info("event=" + (existing.isPresent() ? "PASSWORD_RESET" : "ACCOUNT_CREATED")
                    + " user=" + LogSanitizer.quote(key));
            return existing.isEmpty();
        }
    }

    /** Enables or disables an account. Enabling also clears any active lockout. */
    boolean setEnabled(String username, boolean enabled) throws IOException {
        if (username == null || !UsernamePolicy.isValid(username)) {
            return false;
        }
        String key = UsernamePolicy.normalize(username);
        synchronized (store) {
            Optional<UserAccount> existing = store.find(key);
            if (existing.isEmpty()) {
                return false;
            }
            UserAccount account = existing.get().withEnabled(enabled);
            if (enabled) {
                account = account.withLoginState(0, Instant.EPOCH);
            }
            store.save(account);
            audit.info("event=" + (enabled ? "ACCOUNT_ENABLED" : "ACCOUNT_DISABLED") + " user=" + LogSanitizer.quote(key));
            return true;
        }
    }
}

/** Stored account information. Only a salted password hash is kept, never the password. */
record UserAccount(String username, String passwordHash, boolean enabled, int failedAttempts, Instant lockedUntil) {

    boolean isLockedAt(Instant now) {
        return lockedUntil.isAfter(now);
    }

    UserAccount withPasswordHash(String hash) {
        return new UserAccount(username, hash, enabled, failedAttempts, lockedUntil);
    }

    UserAccount withEnabled(boolean value) {
        return new UserAccount(username, passwordHash, value, failedAttempts, lockedUntil);
    }

    UserAccount withLoginState(int failures, Instant until) {
        return new UserAccount(username, passwordHash, enabled, failures, until);
    }

    /** Format: username:enabled:failedAttempts:lockedUntilEpochSeconds:passwordHash */
    String serialize() {
        return String.join(":", username, Boolean.toString(enabled), Integer.toString(failedAttempts),
                Long.toString(lockedUntil.getEpochSecond()), passwordHash);
    }

    static UserAccount parse(String line) {
        String[] fields = line.split(":", 5);
        if (fields.length != 5 || !UsernamePolicy.isValid(fields[0])
                || !(fields[1].equals("true") || fields[1].equals("false"))
                || !fields[4].startsWith(PasswordHasher.SCHEME + "$")) {
            throw new IllegalArgumentException("malformed account record");
        }
        int failures = Integer.parseInt(fields[2]);
        if (failures < 0) {
            throw new IllegalArgumentException("malformed account record");
        }
        return new UserAccount(UsernamePolicy.normalize(fields[0]), fields[4], Boolean.parseBoolean(fields[1]),
                failures, Instant.ofEpochSecond(Long.parseLong(fields[3])));
    }
}

/** Persists accounts in a flat file, rewritten atomically on every change. */
final class FileCredentialStore {

    private final Path file;
    private final Map<String, UserAccount> accounts = new ConcurrentHashMap<>();

    FileCredentialStore(Path file, Logger audit) throws IOException {
        this.file = file.toAbsolutePath();
        if (Files.exists(this.file)) {
            List<String> lines = Files.readAllLines(this.file, StandardCharsets.UTF_8);
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i).strip();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                try {
                    UserAccount account = UserAccount.parse(line);
                    accounts.put(account.username(), account);
                } catch (IllegalArgumentException e) {
                    // The line itself is not logged: it may contain a password hash.
                    audit.warning("event=STORE_WARNING file=" + LogSanitizer.quote(this.file.toString())
                            + " line=" + (i + 1) + " reason=MALFORMED_RECORD");
                }
            }
        }
    }

    Optional<UserAccount> find(String normalizedUsername) {
        return Optional.ofNullable(accounts.get(normalizedUsername));
    }

    synchronized void save(UserAccount account) throws IOException {
        Map<String, UserAccount> updated = new TreeMap<>(accounts);
        updated.put(account.username(), account);

        List<String> lines = new ArrayList<>();
        lines.add("# username:enabled:failedAttempts:lockedUntilEpochSeconds:passwordHash");
        for (UserAccount a : updated.values()) {
            lines.add(a.serialize());
        }

        Path dir = file.getParent();
        SecureDirectories.create(dir);
        // createTempFile uses owner-only permissions (rw-------) on POSIX file systems.
        Path tmp = Files.createTempFile(dir, ".users", ".tmp");
        try {
            Files.write(tmp, lines, StandardCharsets.UTF_8);
            try {
                Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
        accounts.put(account.username(), account);
    }
}

/** PBKDF2-HMAC-SHA256 password hashing with a per-password random salt. */
final class PasswordHasher {

    static final String SCHEME = "pbkdf2-sha256";
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 600_000;
    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;

    private final SecureRandom random = new SecureRandom();

    /** Returns an encoded hash of the form {@code pbkdf2-sha256$iterations$salt$hash}. */
    String hash(char[] password) {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] derived = derive(password, salt, ITERATIONS, KEY_BITS);
        Base64.Encoder b64 = Base64.getEncoder().withoutPadding();
        return SCHEME + "$" + ITERATIONS + "$" + b64.encodeToString(salt) + "$" + b64.encodeToString(derived);
    }

    boolean verify(char[] password, String encoded) {
        String[] parts = encoded.split("\\$");
        if (parts.length != 4 || !parts[0].equals(SCHEME)) {
            return false;
        }
        int iterations;
        byte[] salt;
        byte[] expected;
        try {
            iterations = Integer.parseInt(parts[1]);
            salt = Base64.getDecoder().decode(parts[2]);
            expected = Base64.getDecoder().decode(parts[3]);
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (iterations < 1 || salt.length == 0 || expected.length == 0) {
            return false;
        }
        byte[] actual = derive(password, salt, iterations, expected.length * 8);
        return MessageDigest.isEqual(expected, actual); // constant-time comparison
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations, int keyBits) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyBits);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Password hashing unavailable", e);
        } finally {
            spec.clearPassword();
        }
    }
}

final class UsernamePolicy {

    static final String DESCRIPTION =
            "Username must be 3-64 characters using letters, digits, '.', '_', '-' or '@'.";
    private static final Pattern VALID = Pattern.compile("[A-Za-z0-9._@-]{3,64}");

    private UsernamePolicy() {
    }

    static boolean isValid(String username) {
        return username != null && VALID.matcher(username).matches();
    }

    /** Usernames are case-insensitive; they are stored and compared in lower case. */
    static String normalize(String username) {
        return username.toLowerCase(Locale.ROOT);
    }
}

/** Neutralizes untrusted values before they are written to the log (prevents log forging/injection). */
final class LogSanitizer {

    private static final int MAX_LENGTH = 128;

    private LogSanitizer() {
    }

    static String quote(String value) {
        if (value == null) {
            return "\"-\"";
        }
        StringBuilder sb = new StringBuilder("\"");
        int limit = Math.min(value.length(), MAX_LENGTH);
        for (int i = 0; i < limit; i++) {
            char c = value.charAt(i);
            if (c == '"' || c == '\\') {
                sb.append('\\').append(c);
            } else if (Character.isISOControl(c) || c == ' ' || c == 0x2028 || c == 0x2029
                    || Character.getType(c) == Character.FORMAT) {
                sb.append(String.format("\\u%04x", (int) c));
            } else {
                sb.append(c);
            }
        }
        if (value.length() > MAX_LENGTH) {
            sb.append("...");
        }
        return sb.append('"').toString();
    }
}

/** Configures the authentication audit log (rotating files, one event per line). */
final class AuditLog {

    private static final int MAX_FILE_BYTES = 10 * 1024 * 1024;
    private static final int FILE_COUNT = 5;

    private AuditLog() {
    }

    static Logger create(Path logDir) throws IOException {
        Path dir = logDir.toAbsolutePath();
        SecureDirectories.create(dir);

        Logger logger = Logger.getLogger("app.auth.audit");
        logger.setUseParentHandlers(false);
        logger.setLevel(Level.INFO);

        FileHandler handler = new FileHandler(dir.resolve("auth%g.log").toString(), MAX_FILE_BYTES, FILE_COUNT, true);
        handler.setEncoding("UTF-8");
        handler.setFormatter(new Formatter() {
            @Override
            public String format(LogRecord record) {
                return DateTimeFormatter.ISO_INSTANT.format(record.getInstant()) + " "
                        + String.format("%-7s", record.getLevel().getName()) + " " + record.getMessage()
                        + System.lineSeparator();
            }
        });
        logger.addHandler(handler);
        return logger;
    }
}

final class SecureDirectories {

    private SecureDirectories() {
    }

    /** Creates the directory (owner-only access on POSIX systems) if it does not already exist. */
    static void create(Path dir) throws IOException {
        if (Files.isDirectory(dir)) {
            return;
        }
        if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            Files.createDirectories(dir, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        } else {
            Files.createDirectories(dir);
        }
    }
}

/** Reads input from the console (no echo for passwords) or, when unavailable, from standard input. */
final class Terminal {

    private final Console console = System.console();
    private BufferedReader stdin;
    private boolean warned;

    String readLine(String prompt) throws IOException {
        if (console != null) {
            return console.readLine("%s", prompt);
        }
        System.out.print(prompt);
        System.out.flush();
        return stdin().readLine();
    }

    char[] readPassword(String prompt) throws IOException {
        if (console != null) {
            return console.readPassword("%s", prompt);
        }
        if (!warned) {
            System.err.println("Warning: no interactive console; reading password from standard input.");
            warned = true;
        }
        String line = readLine(prompt);
        return line == null ? null : line.toCharArray();
    }

    private BufferedReader stdin() {
        if (stdin == null) {
            stdin = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        }
        return stdin;
    }
}
