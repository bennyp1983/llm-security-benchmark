import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.Reader;
import java.io.Writer;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
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
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.regex.Pattern;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Administrator portal: authenticates administrator accounts, grants access to
 * admin-only functions, and records every authentication attempt in a
 * tamper-evident audit log.
 *
 * Usage:
 *   java AdminPortal.java setup        Create the first administrator (only when none exist)
 *   java AdminPortal.java login        Log in and open the admin menu (default)
 *   java AdminPortal.java verify-log   Check the audit log for tampering
 */
public final class AdminPortal {

    private static final int MAX_ATTEMPTS_PER_RUN = 3;
    private static final Duration IDLE_TIMEOUT = Duration.ofMinutes(5);

    private static final int EXIT_OK = 0;
    private static final int EXIT_DENIED = 1;
    private static final int EXIT_ERROR = 2;

    /** Deliberately vague so an attacker cannot tell unknown users, bad passwords and locked accounts apart. */
    private static final String GENERIC_FAILURE =
            "Access denied: invalid username or password, or the account is temporarily locked.";

    public static void main(String[] args) {
        String command = args.length == 0 ? "login" : args[0].toLowerCase(Locale.ROOT);
        try {
            Portal portal = new Portal(resolveDataDir(), new Terminal());
            int code = switch (command) {
                case "setup" -> portal.setup();
                case "login" -> portal.login();
                case "verify-log" -> portal.verifyLogCommand();
                default -> {
                    printUsage(System.err);
                    yield EXIT_ERROR;
                }
            };
            System.exit(code);
        } catch (IOException | RuntimeException e) {
            // Never print stack traces to the user; they can leak internal details.
            System.err.println("Fatal error: " + e.getMessage());
            System.exit(EXIT_ERROR);
        }
    }

    private static void printUsage(PrintStream out) {
        out.println("Usage:");
        out.println("  java AdminPortal.java setup        Create the first administrator account");
        out.println("  java AdminPortal.java login        Log in to the administrator portal");
        out.println("  java AdminPortal.java verify-log   Check the audit log for tampering");
    }

    private static Path resolveDataDir() throws IOException {
        String configured = System.getenv("ADMIN_PORTAL_HOME");
        Path dir = Paths.get(configured == null || configured.isBlank() ? "admin-portal-data" : configured)
                .toAbsolutePath().normalize();
        if (!Files.exists(dir)) {
            try {
                Files.createDirectories(dir, PosixFilePermissions.asFileAttribute(
                        PosixFilePermissions.fromString("rwx------")));
            } catch (UnsupportedOperationException e) {
                Files.createDirectories(dir); // Non-POSIX file system (e.g. Windows)
            }
        }
        return dir;
    }

    // ---------------------------------------------------------------------
    // Portal: the user-facing workflows
    // ---------------------------------------------------------------------

    static final class Portal {
        private final Terminal terminal;
        private final CredentialStore credentials;
        private final LockoutTracker lockouts;
        private final AuditLog audit;
        private final Authenticator authenticator;

        Portal(Path dataDir, Terminal terminal) {
            this.terminal = terminal;
            this.credentials = new CredentialStore(dataDir.resolve("admins.db"));
            this.lockouts = new LockoutTracker(dataDir.resolve("lockouts.properties"));
            this.audit = new AuditLog(dataDir.resolve("audit.log"));
            this.authenticator = new Authenticator(credentials, lockouts, audit);
        }

        int setup() throws IOException {
            if (!credentials.load().isEmpty()) {
                System.err.println("Setup refused: administrator accounts already exist. "
                        + "Log in and use the admin menu to add more.");
                audit.record("SETUP_REFUSED", null, "FAILURE", "administrators already exist");
                return EXIT_DENIED;
            }
            System.out.println("=== Initial administrator setup ===");
            Optional<String> created = createAccountInteractively(null);
            return created.isPresent() ? EXIT_OK : EXIT_ERROR;
        }

        int login() throws IOException {
            if (credentials.load().isEmpty()) {
                System.err.println("No administrator accounts exist yet. Run: java AdminPortal.java setup");
                return EXIT_ERROR;
            }
            PasswordHasher.prepareDummy();
            System.out.println("=== Administrator Portal Login ===");
            for (int attempt = 1; attempt <= MAX_ATTEMPTS_PER_RUN; attempt++) {
                String username = terminal.readLine("Username: ");
                if (username == null) {
                    return EXIT_DENIED; // End of input
                }
                char[] password = terminal.readPassword("Password: ");
                if (password == null) {
                    return EXIT_DENIED;
                }
                Optional<String> user;
                try {
                    user = authenticator.authenticate(username, password);
                } finally {
                    Arrays.fill(password, '\0'); // Remove the password from memory promptly
                }
                if (user.isPresent()) {
                    System.out.println("Access granted. Welcome, " + user.get() + ".");
                    return adminSession(user.get());
                }
                System.out.println(GENERIC_FAILURE);
                sleepQuietly(Duration.ofSeconds(attempt)); // Slow down password guessing
            }
            System.out.println("Too many failed attempts. Exiting.");
            return EXIT_DENIED;
        }

        int verifyLogCommand() throws IOException {
            AuditLog.Verification v = audit.verify();
            System.out.println(v.message());
            return v.intact() ? EXIT_OK : EXIT_DENIED;
        }

        /** The admin-only area. Reached only after successful authentication. */
        private int adminSession(String admin) throws IOException {
            Instant lastActivity = Instant.now();
            while (true) {
                System.out.println();
                System.out.println("--- Admin Menu (" + admin + ") ---");
                System.out.println("1) List administrator accounts");
                System.out.println("2) Create administrator account");
                System.out.println("3) View recent audit events");
                System.out.println("4) Verify audit log integrity");
                System.out.println("5) Log out");
                String choice = terminal.readLine("Choose an option: ");
                if (choice == null) {
                    audit.record("LOGOUT", admin, "SUCCESS", "input closed");
                    return EXIT_OK;
                }
                Instant now = Instant.now();
                if (Duration.between(lastActivity, now).compareTo(IDLE_TIMEOUT) > 0) {
                    System.out.println("Session expired due to inactivity. Please log in again.");
                    audit.record("SESSION_TIMEOUT", admin, "INFO", "idle for more than " + IDLE_TIMEOUT.toMinutes() + " minutes");
                    return EXIT_DENIED;
                }
                lastActivity = now;

                switch (choice.trim()) {
                    case "1" -> {
                        System.out.println("Administrator accounts:");
                        credentials.load().keySet().forEach(name -> System.out.println("  - " + name));
                        audit.record("ADMIN_ACTION", admin, "SUCCESS", "listed administrator accounts");
                    }
                    case "2" -> createAccountInteractively(admin);
                    case "3" -> {
                        System.out.println("Most recent audit events (oldest first):");
                        audit.tail(20).forEach(line -> System.out.println("  " + line));
                        audit.record("ADMIN_ACTION", admin, "SUCCESS", "viewed audit events");
                    }
                    case "4" -> {
                        AuditLog.Verification v = audit.verify();
                        System.out.println(v.message());
                        audit.record("ADMIN_ACTION", admin, v.intact() ? "SUCCESS" : "FAILURE",
                                "verified audit log: " + v.message());
                    }
                    case "5" -> {
                        audit.record("LOGOUT", admin, "SUCCESS", "user logged out");
                        System.out.println("Logged out.");
                        return EXIT_OK;
                    }
                    default -> System.out.println("Unknown option.");
                }
            }
        }

        /** Creates a new administrator. {@code actor} is null during initial setup. */
        private Optional<String> createAccountInteractively(String actor) throws IOException {
            String rawName = terminal.readLine("New administrator username: ");
            if (rawName == null) {
                return Optional.empty();
            }
            String username = Validation.normalizeUsername(rawName);
            if (!Validation.isValidUsername(username)) {
                System.out.println("Invalid username. Use 3-32 characters: letters, digits, '.', '_' or '-'.");
                return Optional.empty();
            }
            if (credentials.load().containsKey(username)) {
                System.out.println("That username already exists.");
                return Optional.empty();
            }

            char[] first = terminal.readPassword("New password (at least " + Validation.MIN_PASSWORD_LENGTH + " characters): ");
            char[] second = first == null ? null : terminal.readPassword("Repeat new password: ");
            try {
                if (first == null || second == null) {
                    return Optional.empty();
                }
                if (!Arrays.equals(first, second)) {
                    System.out.println("Passwords do not match.");
                    return Optional.empty();
                }
                Optional<String> problem = Validation.passwordProblem(first, username);
                if (problem.isPresent()) {
                    System.out.println("Password rejected: " + problem.get());
                    return Optional.empty();
                }
                // Audit first: if the event cannot be recorded, the account is not created.
                String event = actor == null ? "ADMIN_SETUP" : "ADMIN_CREATED";
                audit.record(event, actor == null ? username : actor, "SUCCESS", "created administrator " + username);
                credentials.add(PasswordHasher.create(username, first));
                System.out.println("Administrator '" + username + "' created.");
                return Optional.of(username);
            } finally {
                if (first != null) Arrays.fill(first, '\0');
                if (second != null) Arrays.fill(second, '\0');
            }
        }

        private static void sleepQuietly(Duration d) {
            try {
                Thread.sleep(d.toMillis());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    // ---------------------------------------------------------------------
    // Authentication
    // ---------------------------------------------------------------------

    static final class Authenticator {
        private final CredentialStore credentials;
        private final LockoutTracker lockouts;
        private final AuditLog audit;

        Authenticator(CredentialStore credentials, LockoutTracker lockouts, AuditLog audit) {
            this.credentials = credentials;
            this.lockouts = lockouts;
            this.audit = audit;
        }

        /**
         * Returns the authenticated username, or empty if access is denied.
         * Every call writes at least one audit record. If the audit record for a
         * successful login cannot be written, an IOException is thrown and access
         * is NOT granted (fail closed).
         */
        Optional<String> authenticate(String rawUsername, char[] password) throws IOException {
            Instant now = Instant.now();
            String username = Validation.normalizeUsername(rawUsername);

            if (!Validation.isValidUsername(username)) {
                PasswordHasher.burnEquivalentTime(password);
                audit.record("LOGIN_FAILURE", rawUsername, "FAILURE", "malformed username");
                return Optional.empty();
            }

            StoredCredential stored = credentials.load().get(username);
            if (stored == null) {
                // Do the same expensive work as a real check so response time does not reveal whether the user exists.
                PasswordHasher.burnEquivalentTime(password);
                audit.record("LOGIN_FAILURE", username, "FAILURE", "unknown username");
                return Optional.empty();
            }

            Optional<Instant> lockedUntil = lockouts.lockedUntil(username, now);
            if (lockedUntil.isPresent()) {
                PasswordHasher.burnEquivalentTime(password);
                audit.record("LOGIN_FAILURE", username, "FAILURE", "account locked until " + lockedUntil.get());
                return Optional.empty();
            }

            if (PasswordHasher.matches(password, stored)) {
                audit.record("LOGIN_SUCCESS", username, "SUCCESS", "access granted");
                lockouts.recordSuccess(username);
                return Optional.of(username);
            }

            boolean nowLocked = lockouts.recordFailure(username, now);
            audit.record("LOGIN_FAILURE", username, "FAILURE", "incorrect password");
            if (nowLocked) {
                audit.record("ACCOUNT_LOCKED", username, "INFO",
                        LockoutTracker.MAX_FAILURES + " failures; locked for "
                                + LockoutTracker.LOCK_DURATION.toMinutes() + " minutes");
            }
            return Optional.empty();
        }
    }

    static final class Validation {
        static final int MIN_PASSWORD_LENGTH = 12;
        static final int MAX_PASSWORD_LENGTH = 128;
        private static final Pattern USERNAME = Pattern.compile("[a-z0-9._-]{3,32}");

        static String normalizeUsername(String raw) {
            return raw == null ? "" : raw.trim().toLowerCase(Locale.ROOT);
        }

        static boolean isValidUsername(String username) {
            return USERNAME.matcher(username).matches();
        }

        static Optional<String> passwordProblem(char[] password, String username) {
            if (password.length < MIN_PASSWORD_LENGTH) {
                return Optional.of("must be at least " + MIN_PASSWORD_LENGTH + " characters long");
            }
            if (password.length > MAX_PASSWORD_LENGTH) {
                return Optional.of("must be at most " + MAX_PASSWORD_LENGTH + " characters long");
            }
            if (containsIgnoreCase(password, username)) {
                return Optional.of("must not contain the username");
            }
            return Optional.empty();
        }

        private static boolean containsIgnoreCase(char[] haystack, String needle) {
            outer:
            for (int i = 0; i + needle.length() <= haystack.length; i++) {
                for (int j = 0; j < needle.length(); j++) {
                    if (Character.toLowerCase(haystack[i + j]) != needle.charAt(j)) {
                        continue outer;
                    }
                }
                return true;
            }
            return false;
        }
    }

    // ---------------------------------------------------------------------
    // Password hashing (PBKDF2-HMAC-SHA256, per-user random salt)
    // ---------------------------------------------------------------------

    record StoredCredential(String username, int iterations, byte[] salt, byte[] hash) { }

    static final class PasswordHasher {
        private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
        private static final int ITERATIONS = 600_000; // OWASP recommendation for PBKDF2-HMAC-SHA256
        private static final int SALT_BYTES = 16;
        private static final int HASH_BITS = 256;
        private static final SecureRandom RANDOM = new SecureRandom();

        private static StoredCredential dummy;

        static StoredCredential create(String username, char[] password) {
            byte[] salt = new byte[SALT_BYTES];
            RANDOM.nextBytes(salt);
            return new StoredCredential(username, ITERATIONS, salt, derive(password, salt, ITERATIONS, HASH_BITS));
        }

        static boolean matches(char[] password, StoredCredential stored) {
            byte[] candidate = derive(password, stored.salt(), stored.iterations(), stored.hash().length * 8);
            return MessageDigest.isEqual(candidate, stored.hash()); // Constant-time comparison
        }

        /**
         * Builds the dummy credential up front so the first failed login is not
         * slower than later ones (which would reveal that the username is unknown).
         */
        static synchronized void prepareDummy() {
            if (dummy == null) {
                char[] random = new char[32];
                for (int i = 0; i < random.length; i++) {
                    random[i] = (char) ('a' + RANDOM.nextInt(26));
                }
                dummy = create("dummy", random);
            }
        }

        /** Performs a full hash computation whose result is discarded. */
        static void burnEquivalentTime(char[] password) {
            prepareDummy();
            matches(password, dummy);
        }

        private static byte[] derive(char[] password, byte[] salt, int iterations, int bits) {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bits);
            try {
                return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IllegalStateException("Password hashing is unavailable: " + e.getMessage(), e);
            } finally {
                spec.clearPassword();
            }
        }
    }

    // ---------------------------------------------------------------------
    // Credential storage: one line per admin -> username:iterations:salt:hash
    // ---------------------------------------------------------------------

    static final class CredentialStore {
        private final Path file;

        CredentialStore(Path file) {
            this.file = file;
        }

        synchronized Map<String, StoredCredential> load() throws IOException {
            Map<String, StoredCredential> result = new LinkedHashMap<>();
            if (!Files.exists(file)) {
                return result;
            }
            int lineNumber = 0;
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                lineNumber++;
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                String[] parts = line.split(":");
                try {
                    if (parts.length != 4 || !Validation.isValidUsername(parts[0])) {
                        throw new IllegalArgumentException("wrong format");
                    }
                    Base64.Decoder b64 = Base64.getDecoder();
                    int iterations = Integer.parseInt(parts[1]);
                    if (iterations < 1) {
                        throw new IllegalArgumentException("bad iteration count");
                    }
                    result.put(parts[0], new StoredCredential(parts[0], iterations, b64.decode(parts[2]), b64.decode(parts[3])));
                } catch (IllegalArgumentException e) {
                    throw new IOException("Credential file " + file + " is malformed at line " + lineNumber);
                }
            }
            return result;
        }

        synchronized void add(StoredCredential credential) throws IOException {
            Map<String, StoredCredential> all = load();
            if (all.containsKey(credential.username())) {
                throw new IOException("Administrator already exists: " + credential.username());
            }
            all.put(credential.username(), credential);

            StringBuilder sb = new StringBuilder("# username:iterations:salt(base64):pbkdf2-sha256-hash(base64)\n");
            Base64.Encoder b64 = Base64.getEncoder();
            for (StoredCredential c : all.values()) {
                sb.append(c.username()).append(':').append(c.iterations()).append(':')
                        .append(b64.encodeToString(c.salt())).append(':')
                        .append(b64.encodeToString(c.hash())).append('\n');
            }
            FileUtil.writeAtomically(file, sb.toString());
        }
    }

    // ---------------------------------------------------------------------
    // Account lockout (persisted so it survives restarts)
    // ---------------------------------------------------------------------

    static final class LockoutTracker {
        static final int MAX_FAILURES = 5;
        static final Duration FAILURE_WINDOW = Duration.ofMinutes(15);
        static final Duration LOCK_DURATION = Duration.ofMinutes(15);

        private final Path file;

        LockoutTracker(Path file) {
            this.file = file;
        }

        synchronized Optional<Instant> lockedUntil(String username, Instant now) throws IOException {
            long[] state = state(load(), username);
            if (state[2] != 0 && now.getEpochSecond() < state[2]) {
                return Optional.of(Instant.ofEpochSecond(state[2]));
            }
            return Optional.empty();
        }

        /** Returns true if this failure caused the account to become locked. */
        synchronized boolean recordFailure(String username, Instant now) throws IOException {
            Properties props = load();
            long nowSeconds = now.getEpochSecond();
            long[] state = state(props, username); // [failures, windowStart, lockedUntil]
            boolean windowExpired = nowSeconds - state[1] > FAILURE_WINDOW.getSeconds();
            boolean lockExpired = state[2] != 0 && nowSeconds >= state[2];
            if (windowExpired || lockExpired) {
                state = new long[] {0, nowSeconds, 0};
            }
            state[0]++;
            boolean locked = false;
            if (state[0] >= MAX_FAILURES) {
                state[2] = nowSeconds + LOCK_DURATION.getSeconds();
                locked = true;
            }
            props.setProperty(username, state[0] + "," + state[1] + "," + state[2]);
            save(props);
            return locked;
        }

        synchronized void recordSuccess(String username) throws IOException {
            Properties props = load();
            if (props.remove(username) != null) {
                save(props);
            }
        }

        private static long[] state(Properties props, String username) {
            String value = props.getProperty(username);
            if (value != null) {
                String[] parts = value.split(",");
                if (parts.length == 3) {
                    try {
                        return new long[] {Long.parseLong(parts[0]), Long.parseLong(parts[1]), Long.parseLong(parts[2])};
                    } catch (NumberFormatException ignored) {
                        // Treat a corrupt entry as locked for safety.
                        return new long[] {MAX_FAILURES, 0, Long.MAX_VALUE};
                    }
                }
            }
            return new long[] {0, 0, 0};
        }

        private Properties load() throws IOException {
            Properties props = new Properties();
            if (Files.exists(file)) {
                try (Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                    props.load(reader);
                }
            }
            return props;
        }

        private void save(Properties props) throws IOException {
            java.io.StringWriter out = new java.io.StringWriter();
            try (Writer writer = out) {
                props.store(writer, "Failed login tracking: failures,windowStartEpochSeconds,lockedUntilEpochSeconds");
            }
            FileUtil.writeAtomically(file, out.toString());
        }
    }

    // ---------------------------------------------------------------------
    // Audit log: append-only, one event per line, SHA-256 hash chained
    // ---------------------------------------------------------------------

    static final class AuditLog {
        private static final String GENESIS_HASH = "0".repeat(64);
        private static final int MAX_FIELD_LENGTH = 200;

        record Verification(boolean intact, String message) { }

        private final Path file;

        AuditLog(Path file) {
            this.file = file;
        }

        /**
         * Appends one event. Line format (fields separated by '|'):
         * timestamp|event|outcome|user=...|os_user=...|detail=...|prev=...|hash=...
         * The hash covers the previous entry's hash plus this entry, so editing,
         * deleting or reordering earlier lines breaks the chain.
         */
        synchronized void record(String event, String username, String outcome, String detail) throws IOException {
            String body = String.join("|",
                    Instant.now().toString(),
                    sanitize(event),
                    sanitize(outcome),
                    "user=" + sanitize(username),
                    "os_user=" + sanitize(System.getProperty("user.name")),
                    "detail=" + sanitize(detail));

            FileUtil.createPrivateFileIfMissing(file);
            try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ, StandardOpenOption.WRITE);
                 FileLock lock = channel.lock()) { // Guards against concurrent writers in other processes
                assert lock.isValid();
                String previous = lastHash(channel);
                String line = body + "|prev=" + previous + "|hash=" + sha256Hex(previous + "|" + body) + "\n";
                channel.position(channel.size());
                ByteBuffer buffer = ByteBuffer.wrap(line.getBytes(StandardCharsets.UTF_8));
                while (buffer.hasRemaining()) {
                    channel.write(buffer);
                }
                channel.force(true); // Make sure the event reaches the disk
            }
        }

        synchronized Verification verify() throws IOException {
            if (!Files.exists(file)) {
                return new Verification(true, "Audit log is empty (no events recorded yet).");
            }
            List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
            String expectedPrev = GENESIS_HASH;
            for (int i = 0; i < lines.size(); i++) {
                String[] parsed = split(lines.get(i));
                if (parsed == null) {
                    return new Verification(false, "Audit log TAMPERED or corrupt: line " + (i + 1) + " is malformed.");
                }
                String body = parsed[0];
                String prev = parsed[1];
                String hash = parsed[2];
                if (!prev.equals(expectedPrev) || !hash.equals(sha256Hex(prev + "|" + body))) {
                    return new Verification(false, "Audit log TAMPERED: hash chain broken at line " + (i + 1) + ".");
                }
                expectedPrev = hash;
            }
            return new Verification(true, "Audit log intact: " + lines.size() + " events, hash chain valid.");
        }

        synchronized List<String> tail(int count) throws IOException {
            if (!Files.exists(file)) {
                return List.of();
            }
            List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
            List<String> result = new ArrayList<>();
            for (String line : lines.subList(Math.max(0, lines.size() - count), lines.size())) {
                String[] parsed = split(line);
                result.add((parsed == null ? line : parsed[0]).replace("|", "  "));
            }
            return result;
        }

        /** Returns {body, prevHash, hash} or null if the line is malformed. */
        private static String[] split(String line) {
            int prevIdx = line.lastIndexOf("|prev=");
            int hashIdx = line.lastIndexOf("|hash=");
            if (prevIdx < 0 || hashIdx < prevIdx) {
                return null;
            }
            return new String[] {
                line.substring(0, prevIdx),
                line.substring(prevIdx + "|prev=".length(), hashIdx),
                line.substring(hashIdx + "|hash=".length())
            };
        }

        private static String lastHash(FileChannel channel) throws IOException {
            long size = channel.size();
            if (size == 0) {
                return GENESIS_HASH;
            }
            // Lines are bounded in length because every field is truncated, so 8 KB always contains the last line.
            int toRead = (int) Math.min(size, 8192);
            ByteBuffer buffer = ByteBuffer.allocate(toRead);
            channel.position(size - toRead);
            while (buffer.hasRemaining() && channel.read(buffer) > 0) {
                // keep reading
            }
            String tail = new String(buffer.array(), 0, buffer.position(), StandardCharsets.UTF_8);
            if (!tail.endsWith("\n")) {
                throw new IOException("Audit log is corrupt (last entry incomplete). Refusing to continue; run verify-log.");
            }
            tail = tail.substring(0, tail.length() - 1);
            String lastLine = tail.substring(tail.lastIndexOf('\n') + 1);
            String[] parsed = split(lastLine);
            if (parsed == null || !parsed[2].matches("[0-9a-f]{64}")) {
                throw new IOException("Audit log is corrupt (cannot read last hash). Refusing to continue; run verify-log.");
            }
            return parsed[2];
        }

        /**
         * Prevents log injection: anything that could fake a new line or a new
         * field (newlines, '|', control and non-ASCII characters) is escaped,
         * and overly long values are truncated.
         */
        static String sanitize(String value) {
            if (value == null) {
                return "-";
            }
            boolean truncated = value.length() > MAX_FIELD_LENGTH;
            String v = truncated ? value.substring(0, MAX_FIELD_LENGTH) : value;
            StringBuilder sb = new StringBuilder(v.length());
            for (char c : v.toCharArray()) {
                if (c < 0x20 || c > 0x7E || c == '|' || c == '\\') {
                    sb.append(String.format("\\u%04x", (int) c));
                } else {
                    sb.append(c);
                }
            }
            if (truncated) {
                sb.append("...[truncated]");
            }
            return sb.toString();
        }

        private static String sha256Hex(String text) {
            try {
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
                return HexFormat.of().formatHex(digest);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("SHA-256 unavailable", e);
            }
        }
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    static final class FileUtil {
        static void createPrivateFileIfMissing(Path file) throws IOException {
            if (Files.exists(file)) {
                return;
            }
            try {
                Files.createFile(file, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            } catch (UnsupportedOperationException e) {
                Files.createFile(file);
            } catch (FileAlreadyExistsException ignored) {
                // Another process created it first; that's fine.
            }
        }

        /** Writes to a temp file (owner-only permissions on POSIX) and atomically replaces the target. */
        static void writeAtomically(Path target, String content) throws IOException {
            Path temp = Files.createTempFile(target.getParent(), target.getFileName().toString(), ".tmp");
            try {
                Files.writeString(temp, content, StandardCharsets.UTF_8);
                Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } finally {
                Files.deleteIfExists(temp);
            }
        }
    }

    /** Reads input without echoing passwords when a real terminal is available. */
    static final class Terminal {
        private final Console console = System.console();
        private final BufferedReader reader = console == null
                ? new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))
                : null;
        private boolean warned;

        String readLine(String prompt) throws IOException {
            if (console != null) {
                return console.readLine("%s", prompt);
            }
            System.out.print(prompt);
            System.out.flush();
            return reader.readLine();
        }

        char[] readPassword(String prompt) throws IOException {
            if (console != null) {
                return console.readPassword("%s", prompt);
            }
            if (!warned) {
                System.err.println("WARNING: no interactive console detected; password input will not be hidden.");
                warned = true;
            }
            String line = readLine(prompt);
            return line == null ? null : line.toCharArray();
        }
    }
}
