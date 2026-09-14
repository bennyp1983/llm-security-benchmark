import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Authentication module for the internal employee portal.
 *
 * <p>Employees log in with a username and password. Credentials are checked against a
 * file-based records store that holds only salted PBKDF2 password hashes, never plain
 * passwords. To stop password guessing, each account is locked after a fixed number of
 * consecutive failed attempts. Each new lockout lasts longer than the one before. The
 * lockout state is saved to disk, so restarting the program does not clear it.
 *
 * <p>Usage:
 * <pre>
 *   java EmployeePortalAuth                     # interactive login
 *   java EmployeePortalAuth add-user &lt;name&gt;     # create or reset an account (administrator)
 *   java EmployeePortalAuth unlock &lt;name&gt;       # clear a lockout (administrator)
 * </pre>
 *
 * <p>The data directory defaults to {@code ./portal-data}. It can be changed with the
 * {@code -Dportal.dataDir=...} system property or the {@code PORTAL_DATA_DIR} environment variable.
 */
public final class EmployeePortalAuth {

    // ---------------------------------------------------------------------------------------
    // Security policy settings
    // ---------------------------------------------------------------------------------------

    /** Consecutive failed attempts allowed before the account is locked. */
    static final int MAX_CONSECUTIVE_FAILURES = 5;

    /** Length of the first lockout. Each further lockout doubles, up to MAX_LOCKOUT. */
    static final Duration BASE_LOCKOUT = Duration.ofMinutes(15);

    /** Upper limit for any single lockout. */
    static final Duration MAX_LOCKOUT = Duration.ofHours(24);

    /** Quiet time (no failures and no active lock) after which the escalation resets. */
    static final Duration ESCALATION_RESET_WINDOW = Duration.ofHours(24);

    /** Fixed pause after every failed attempt to slow down scripted guessing. */
    static final long FAILURE_DELAY_MILLIS = 1_000;

    static final int MIN_PASSWORD_LENGTH = 12;
    static final int MAX_PASSWORD_LENGTH = 128;

    /** Usernames are normalised to lower case and must match this pattern. */
    static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-z0-9._-]{1,64}$");

    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z").withZone(ZoneId.systemDefault());

    private EmployeePortalAuth() {
    }

    // ---------------------------------------------------------------------------------------
    // Entry point
    // ---------------------------------------------------------------------------------------

    public static void main(String[] args) {
        Path dataDir = resolveDataDir();
        Terminal terminal = new Terminal();
        try {
            Storage.ensurePrivateDirectory(dataDir);
            CredentialStore store = new CredentialStore(dataDir.resolve("users.db"));
            LoginAttemptTracker tracker =
                    new LoginAttemptTracker(dataDir.resolve("lockouts.db"), Clock.systemUTC());
            AuditLog audit = new AuditLog(dataDir.resolve("audit.log"), Clock.systemUTC());
            Authenticator authenticator = new Authenticator(store, tracker, audit);

            if (args.length == 0) {
                runLogin(terminal, authenticator);
            } else if (args.length == 2 && args[0].equals("add-user")) {
                runAddUser(terminal, store, tracker, audit, args[1]);
            } else if (args.length == 2 && args[0].equals("unlock")) {
                runUnlock(terminal, tracker, audit, args[1]);
            } else {
                terminal.println("Usage:");
                terminal.println("  java EmployeePortalAuth                  (log in)");
                terminal.println("  java EmployeePortalAuth add-user <name>  (create or reset an account)");
                terminal.println("  java EmployeePortalAuth unlock <name>    (clear an account lockout)");
                System.exit(2);
            }
        } catch (IOException | UncheckedIOException e) {
            System.err.println("Error: the portal records could not be read or written: " + e.getMessage());
            System.exit(1);
        }
    }

    private static Path resolveDataDir() {
        String dir = System.getProperty("portal.dataDir");
        if (dir == null || dir.isBlank()) {
            dir = System.getenv("PORTAL_DATA_DIR");
        }
        if (dir == null || dir.isBlank()) {
            dir = "portal-data";
        }
        return Paths.get(dir);
    }

    private static void runLogin(Terminal terminal, Authenticator authenticator) throws IOException {
        terminal.println("=== Employee Portal Login ===");
        while (true) {
            String username = terminal.readLine("Username (leave blank to quit): ");
            if (username == null || username.isBlank()) {
                terminal.println("Goodbye.");
                return;
            }
            char[] password = terminal.readPassword("Password: ");
            if (password == null) {
                return;
            }

            AuthOutcome outcome;
            try {
                outcome = authenticator.authenticate(username, password);
            } finally {
                Arrays.fill(password, '\0');
            }

            switch (outcome.status()) {
                case SUCCESS:
                    terminal.println("Access granted. Welcome, " + outcome.username() + ".");
                    return;
                case LOCKED_OUT:
                    terminal.println("Access denied. Too many failed attempts. This account is locked until "
                            + TIME_FORMAT.format(outcome.lockedUntil()) + ".");
                    break;
                case INVALID_CREDENTIALS:
                default:
                    terminal.println("Access denied. Invalid username or password.");
                    break;
            }
        }
    }

    private static void runAddUser(Terminal terminal, CredentialStore store, LoginAttemptTracker tracker,
                                   AuditLog audit, String rawUsername) throws IOException {
        String username = Authenticator.normalizeUsername(rawUsername);
        if (username == null) {
            terminal.println("Invalid username. Use 1-64 characters: letters, digits, '.', '_' or '-'.");
            System.exit(2);
        }
        char[] first = terminal.readPassword("New password for " + username + ": ");
        char[] second = terminal.readPassword("Repeat password: ");
        try {
            if (first == null || second == null || !Arrays.equals(first, second)) {
                terminal.println("The passwords do not match. No changes were made.");
                System.exit(2);
            }
            if (first.length < MIN_PASSWORD_LENGTH || first.length > MAX_PASSWORD_LENGTH) {
                terminal.println("Passwords must be between " + MIN_PASSWORD_LENGTH + " and "
                        + MAX_PASSWORD_LENGTH + " characters. No changes were made.");
                System.exit(2);
            }
            boolean existed = store.find(username).isPresent();
            store.save(UserRecord.create(username, first));
            tracker.reset(username);
            audit.record(existed ? "PASSWORD_RESET" : "USER_CREATED", username);
            terminal.println(existed ? "Password updated for " + username + "." : "Account created for " + username + ".");
        } finally {
            if (first != null) {
                Arrays.fill(first, '\0');
            }
            if (second != null) {
                Arrays.fill(second, '\0');
            }
        }
    }

    private static void runUnlock(Terminal terminal, LoginAttemptTracker tracker, AuditLog audit,
                                  String rawUsername) {
        String username = Authenticator.normalizeUsername(rawUsername);
        if (username == null) {
            terminal.println("Invalid username.");
            System.exit(2);
        }
        tracker.reset(username);
        audit.record("ADMIN_UNLOCK", username);
        terminal.println("Lockout cleared for " + username + ".");
    }

    // ---------------------------------------------------------------------------------------
    // Authentication logic
    // ---------------------------------------------------------------------------------------

    enum AuthStatus { SUCCESS, INVALID_CREDENTIALS, LOCKED_OUT }

    record AuthOutcome(AuthStatus status, String username, Instant lockedUntil) {
    }

    static final class Authenticator {
        private final CredentialStore store;
        private final LoginAttemptTracker tracker;
        private final AuditLog audit;

        // Used for unknown usernames so that the response time does not show which accounts exist.
        private final byte[] dummySalt;
        private final byte[] dummyHash;

        Authenticator(CredentialStore store, LoginAttemptTracker tracker, AuditLog audit) {
            this.store = store;
            this.tracker = tracker;
            this.audit = audit;
            this.dummySalt = PasswordHasher.newSalt();
            char[] randomPassword = Base64.getEncoder().encodeToString(PasswordHasher.newSalt()).toCharArray();
            this.dummyHash = PasswordHasher.hash(randomPassword, dummySalt, PasswordHasher.ITERATIONS);
        }

        static String normalizeUsername(String raw) {
            if (raw == null) {
                return null;
            }
            String username = raw.trim().toLowerCase(Locale.ROOT);
            return USERNAME_PATTERN.matcher(username).matches() ? username : null;
        }

        AuthOutcome authenticate(String rawUsername, char[] password) {
            String username = normalizeUsername(rawUsername);
            if (username == null) {
                // No account can have this name. Do the same work as a real check anyway.
                PasswordHasher.verify(password, dummySalt, PasswordHasher.ITERATIONS, dummyHash);
                audit.record("LOGIN_FAILED_MALFORMED_USERNAME", null);
                pauseAfterFailure();
                return new AuthOutcome(AuthStatus.INVALID_CREDENTIALS, null, null);
            }

            // Unknown usernames are tracked and locked the same way as real accounts. Otherwise an
            // attacker could learn which usernames exist by watching for lockout messages.
            LoginAttemptTracker.AccountState state = tracker.stateFor(username);

            // Checking the lock, verifying the password and recording the result happen under one
            // per-account lock. Parallel requests therefore cannot get past the attempt limit.
            synchronized (state) {
                Instant lockedUntil = tracker.activeLockout(state);
                if (lockedUntil != null) {
                    // The password is not checked while the account is locked. A correct guess
                    // during a lockout therefore reveals nothing.
                    audit.record("LOGIN_REJECTED_LOCKED", username);
                    return new AuthOutcome(AuthStatus.LOCKED_OUT, username, lockedUntil);
                }

                Optional<UserRecord> record = store.find(username);
                boolean valid;
                if (record.isPresent()) {
                    UserRecord r = record.get();
                    valid = PasswordHasher.verify(password, r.salt(), r.iterations(), r.hash());
                } else {
                    PasswordHasher.verify(password, dummySalt, PasswordHasher.ITERATIONS, dummyHash);
                    valid = false;
                }

                if (valid) {
                    tracker.recordSuccess(state);
                    audit.record("LOGIN_SUCCESS", username);
                    return new AuthOutcome(AuthStatus.SUCCESS, username, null);
                }

                tracker.recordFailure(state);
                lockedUntil = tracker.activeLockout(state);
                audit.record(lockedUntil != null ? "LOGIN_FAILED_ACCOUNT_LOCKED" : "LOGIN_FAILED", username);
                // The pause happens while the per-account lock is held, so guesses at one account
                // are handled one at a time.
                pauseAfterFailure();
                return lockedUntil != null
                        ? new AuthOutcome(AuthStatus.LOCKED_OUT, username, lockedUntil)
                        : new AuthOutcome(AuthStatus.INVALID_CREDENTIALS, username, null);
            }
        }

        private static void pauseAfterFailure() {
            try {
                Thread.sleep(FAILURE_DELAY_MILLIS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Password hashing
    // ---------------------------------------------------------------------------------------

    static final class PasswordHasher {
        static final String ALGORITHM = "PBKDF2WithHmacSHA256";
        static final int ITERATIONS = 210_000;
        static final int MIN_ITERATIONS = 10_000;
        static final int MAX_ITERATIONS = 5_000_000;
        private static final int SALT_BYTES = 16;
        private static final int KEY_BITS = 256;
        private static final SecureRandom RANDOM = new SecureRandom();

        private PasswordHasher() {
        }

        static byte[] newSalt() {
            byte[] salt = new byte[SALT_BYTES];
            RANDOM.nextBytes(salt);
            return salt;
        }

        static byte[] hash(char[] password, byte[] salt, int iterations) {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
            try {
                return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IllegalStateException("Password hashing is unavailable", e);
            } finally {
                spec.clearPassword();
            }
        }

        /** Compares the hashes in constant time. Empty or over-long passwords are always rejected. */
        static boolean verify(char[] password, byte[] salt, int iterations, byte[] expectedHash) {
            if (password == null || password.length == 0 || password.length > MAX_PASSWORD_LENGTH) {
                return false;
            }
            byte[] candidate = hash(password, salt, iterations);
            try {
                return MessageDigest.isEqual(candidate, expectedHash);
            } finally {
                Arrays.fill(candidate, (byte) 0);
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Credential records store
    // ---------------------------------------------------------------------------------------

    record UserRecord(String username, int iterations, byte[] salt, byte[] hash) {
        static UserRecord create(String username, char[] password) {
            byte[] salt = PasswordHasher.newSalt();
            return new UserRecord(username, PasswordHasher.ITERATIONS, salt,
                    PasswordHasher.hash(password, salt, PasswordHasher.ITERATIONS));
        }

        String toLine() {
            Base64.Encoder b64 = Base64.getEncoder();
            return username + ":" + iterations + ":" + b64.encodeToString(salt) + ":" + b64.encodeToString(hash);
        }

        static UserRecord fromLine(String line) {
            String[] parts = line.split(":", -1);
            if (parts.length != 4 || !USERNAME_PATTERN.matcher(parts[0]).matches()) {
                throw new IllegalArgumentException("bad format");
            }
            int iterations = Integer.parseInt(parts[1]);
            if (iterations < PasswordHasher.MIN_ITERATIONS || iterations > PasswordHasher.MAX_ITERATIONS) {
                throw new IllegalArgumentException("iteration count out of range");
            }
            Base64.Decoder b64 = Base64.getDecoder();
            return new UserRecord(parts[0], iterations, b64.decode(parts[2]), b64.decode(parts[3]));
        }
    }

    /**
     * Stores one account per line: {@code username:iterations:base64(salt):base64(hash)}.
     */
    static final class CredentialStore {
        private final Path file;
        private final Map<String, UserRecord> users = new ConcurrentHashMap<>();

        CredentialStore(Path file) throws IOException {
            this.file = file;
            if (Files.exists(file)) {
                List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
                for (int i = 0; i < lines.size(); i++) {
                    String line = lines.get(i).trim();
                    if (line.isEmpty() || line.startsWith("#")) {
                        continue;
                    }
                    try {
                        UserRecord record = UserRecord.fromLine(line);
                        users.put(record.username(), record);
                    } catch (IllegalArgumentException e) {
                        throw new IOException(file + " line " + (i + 1) + " is malformed (" + e.getMessage() + ")");
                    }
                }
            }
        }

        Optional<UserRecord> find(String username) {
            return Optional.ofNullable(users.get(username));
        }

        synchronized void save(UserRecord record) throws IOException {
            users.put(record.username(), record);
            List<String> lines = new ArrayList<>();
            lines.add("# Employee portal credentials. Format: username:iterations:salt:hash");
            users.values().stream().sorted((a, b) -> a.username().compareTo(b.username()))
                    .forEach(r -> lines.add(r.toLine()));
            Storage.writeAtomically(file, lines);
        }
    }

    // ---------------------------------------------------------------------------------------
    // Failed-attempt tracking and lockout
    // ---------------------------------------------------------------------------------------

    /**
     * Keeps a failure counter and lockout details for each username. The data is saved to disk
     * after every change. Line format: {@code username:consecutiveFailures:lockoutCount:lockedUntilMillis:lastFailureMillis}.
     */
    static final class LoginAttemptTracker {
        static final class AccountState {
            // Changed only while holding this object's monitor. The fields are volatile so that
            // persist() can read them without taking every account's lock.
            volatile int consecutiveFailures;
            volatile int lockoutCount;
            volatile long lockedUntilMillis;
            volatile long lastFailureMillis;

            boolean isClear() {
                return consecutiveFailures == 0 && lockoutCount == 0 && lockedUntilMillis == 0;
            }
        }

        private final Path file;
        private final Clock clock;
        private final ConcurrentHashMap<String, AccountState> states = new ConcurrentHashMap<>();

        LoginAttemptTracker(Path file, Clock clock) throws IOException {
            this.file = file;
            this.clock = clock;
            if (Files.exists(file)) {
                List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
                for (int i = 0; i < lines.size(); i++) {
                    String line = lines.get(i).trim();
                    if (line.isEmpty() || line.startsWith("#")) {
                        continue;
                    }
                    String[] p = line.split(":", -1);
                    try {
                        if (p.length != 5 || !USERNAME_PATTERN.matcher(p[0]).matches()) {
                            throw new IllegalArgumentException("bad format");
                        }
                        AccountState s = new AccountState();
                        s.consecutiveFailures = Integer.parseInt(p[1]);
                        s.lockoutCount = Integer.parseInt(p[2]);
                        s.lockedUntilMillis = Long.parseLong(p[3]);
                        s.lastFailureMillis = Long.parseLong(p[4]);
                        states.put(p[0], s);
                    } catch (IllegalArgumentException e) {
                        // Stop rather than skip the line. Skipping it would quietly remove a lockout.
                        throw new IOException(file + " line " + (i + 1) + " is malformed");
                    }
                }
            }
        }

        /** Returns the single shared state object for a username. It is never removed from the map. */
        AccountState stateFor(String username) {
            return states.computeIfAbsent(username, k -> new AccountState());
        }

        /** Returns the lockout end time, or null if the account is not locked. Caller must hold the state lock. */
        Instant activeLockout(AccountState s) {
            long now = clock.millis();
            return now < s.lockedUntilMillis ? Instant.ofEpochMilli(s.lockedUntilMillis) : null;
        }

        /** Caller must hold the state lock. */
        void recordFailure(AccountState s) {
            long now = clock.millis();
            long quietSince = Math.max(s.lastFailureMillis, s.lockedUntilMillis);
            if (quietSince > 0 && now - quietSince > ESCALATION_RESET_WINDOW.toMillis()) {
                s.consecutiveFailures = 0;
                s.lockoutCount = 0;
            }
            s.lastFailureMillis = now;
            s.consecutiveFailures = s.consecutiveFailures + 1;
            if (s.consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
                s.lockedUntilMillis = now + lockoutDuration(s.lockoutCount).toMillis();
                s.lockoutCount = s.lockoutCount + 1;
                s.consecutiveFailures = 0;
            }
            persist();
        }

        /** Caller must hold the state lock. */
        void recordSuccess(AccountState s) {
            if (s.isClear()) {
                return;
            }
            s.consecutiveFailures = 0;
            s.lockoutCount = 0;
            s.lockedUntilMillis = 0;
            s.lastFailureMillis = 0;
            persist();
        }

        /** Administrator action: clears failures and any lockout for the account. */
        void reset(String username) {
            AccountState s = stateFor(username);
            synchronized (s) {
                s.consecutiveFailures = 0;
                s.lockoutCount = 0;
                s.lockedUntilMillis = 0;
                s.lastFailureMillis = 0;
                persist();
            }
        }

        static Duration lockoutDuration(int previousLockouts) {
            int shift = Math.min(previousLockouts, 20);
            Duration d = BASE_LOCKOUT.multipliedBy(1L << shift);
            return d.compareTo(MAX_LOCKOUT) > 0 ? MAX_LOCKOUT : d;
        }

        private synchronized void persist() {
            List<String> lines = new ArrayList<>();
            lines.add("# Employee portal lockout state. Format: username:failures:lockouts:lockedUntil:lastFailure");
            states.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(e -> {
                AccountState s = e.getValue();
                if (!s.isClear()) {
                    lines.add(e.getKey() + ":" + s.consecutiveFailures + ":" + s.lockoutCount + ":"
                            + s.lockedUntilMillis + ":" + s.lastFailureMillis);
                }
            });
            try {
                Storage.writeAtomically(file, lines);
            } catch (IOException e) {
                // Fail closed: the caller gets an error, not a successful login.
                throw new UncheckedIOException("could not save lockout state", e);
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Audit log
    // ---------------------------------------------------------------------------------------

    static final class AuditLog {
        private final Path file;
        private final Clock clock;

        AuditLog(Path file, Clock clock) {
            this.file = file;
            this.clock = clock;
        }

        /** Records an event. Passwords are never written to the log. */
        synchronized void record(String event, String username) {
            String line = Instant.now(clock) + " " + event + " user=" + (username == null ? "<invalid>" : username)
                    + System.lineSeparator();
            try {
                if (!Files.exists(file)) {
                    Storage.createPrivateFile(file);
                }
                Files.writeString(file, line, StandardCharsets.UTF_8, StandardOpenOption.APPEND);
            } catch (IOException e) {
                System.err.println("Warning: could not write audit log: " + e.getMessage());
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // File helpers
    // ---------------------------------------------------------------------------------------

    static final class Storage {
        private Storage() {
        }

        private static boolean posix(Path path) {
            return path.getFileSystem().supportedFileAttributeViews().contains("posix");
        }

        static void ensurePrivateDirectory(Path dir) throws IOException {
            if (Files.notExists(dir)) {
                Files.createDirectories(dir);
                if (posix(dir)) {
                    Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
                }
            }
        }

        static void createPrivateFile(Path file) throws IOException {
            try {
                if (posix(file)) {
                    Files.createFile(file, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
                } else {
                    Files.createFile(file);
                }
            } catch (FileAlreadyExistsException ignored) {
                // Another writer created it first. That is fine.
            }
        }

        /** Writes to a temporary file first, then moves it into place so a crash cannot leave a half-written file. */
        static void writeAtomically(Path file, List<String> lines) throws IOException {
            Path dir = file.toAbsolutePath().getParent();
            Path temp = posix(dir)
                    ? Files.createTempFile(dir, file.getFileName().toString(), ".tmp",
                            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
                    : Files.createTempFile(dir, file.getFileName().toString(), ".tmp");
            try {
                Files.write(temp, lines, StandardCharsets.UTF_8);
                try {
                    Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                } catch (AtomicMoveNotSupportedException e) {
                    Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
                }
            } finally {
                Files.deleteIfExists(temp);
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Console input
    // ---------------------------------------------------------------------------------------

    static final class Terminal {
        private final Console console = System.console();
        private BufferedReader fallback;

        String readLine(String prompt) throws IOException {
            if (console != null) {
                return console.readLine("%s", prompt);
            }
            System.out.print(prompt);
            System.out.flush();
            return fallback().readLine();
        }

        /** Reads a password without echoing it. Without a real console, input is visible, so a warning is shown. */
        char[] readPassword(String prompt) throws IOException {
            if (console != null) {
                return console.readPassword("%s", prompt);
            }
            String line = readLine(prompt);
            return line == null ? null : line.toCharArray();
        }

        void println(String message) {
            if (console != null) {
                console.printf("%s%n", message);
            } else {
                System.out.println(message);
            }
        }

        private BufferedReader fallback() {
            if (fallback == null) {
                System.err.println("Warning: no interactive console detected; typed passwords will be visible.");
                fallback = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
            }
            return fallback;
        }
    }
}
