/*
 * Employee portal authentication.
 *
 * A console program that asks an employee for a username and a password, checks them
 * against a records store on disk, and either grants or denies access.
 *
 * Build and run:
 *     javac EmployeePortalAuth.java
 *     java EmployeePortalAuth
 *
 * Design notes worth knowing before you read the code:
 *
 *   - Passwords are never stored or logged. Each account keeps a random 16 byte salt and a
 *     32 byte PBKDF2-HMAC-SHA256 digest of the password, both base64 encoded.
 *   - A login always performs exactly one password derivation, even for an unknown username
 *     or a malformed username, so the response time does not reveal whether an account exists.
 *   - Usernames are matched against a strict character whitelist. Names are never printed
 *     back to the terminal unless they passed that whitelist, so typed input cannot smuggle
 *     terminal escape sequences into the output.
 *   - Repeated failures on one account lock that account for a while.
 */

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/** Command line entry point for the employee portal. */
public final class EmployeePortalAuth {

    private EmployeePortalAuth() {
    }

    public static void main(String[] args) {
        Config config;
        try {
            config = Config.parse(args, System.getProperties()::getProperty);
        } catch (IllegalArgumentException badInvocation) {
            System.out.println("startup failed: " + badInvocation.getMessage());
            System.out.println("Type the same command with --help for the option list.");
            System.exit(2);
            return;
        }
        if (config.showHelp) {
            System.out.println(Config.usage());
            return;
        }

        PrintStream out = System.out;
        AuditLog audit = new AuditLog(System.out, TimeSource.system());
        SecureRandom random = new SecureRandom();
        FileRecordStore store;
        try {
            store = new FileRecordStore(config.storePath);
        } catch (IOException unreadableStore) {
            out.println("cannot open the records store " + config.storePath.toAbsolutePath()
                    + ": " + unreadableStore.getMessage());
            System.exit(2);
            return;
        }

        out.println("employee portal - records store: " + store.path().toAbsolutePath());
        if (store.malformedLineCount() > 0) {
            out.println("WARNING: ignored " + store.malformedLineCount() + " unreadable line(s) in the store;"
                    + " the accounts on those lines cannot sign in until the file is repaired");
        }
        if (store.duplicateLineCount() > 0) {
            out.println("WARNING: ignored " + store.duplicateLineCount() + " duplicate username line(s) in the store");
        }
        out.println("accounts on file: " + store.size()
                + ", password cost: " + config.iterations + " PBKDF2 iterations");
        if (store.size() == 0) {
            out.println("No accounts exist yet. Create one with: add <username>");
        }

        LoginAttemptTracker tracker = new LoginAttemptTracker(config.maxFailures, config.lockDuration);
        SessionRegistry sessions = new SessionRegistry(config.sessionDuration, random, TimeSource.system());
        PortalAuthService service;
        try {
            service = new PortalAuthService(store, tracker, sessions, audit, random,
                    config.iterations, TimeSource.system());
        } catch (IllegalStateException brokenCrypto) {
            out.println("this JVM cannot hash passwords: " + brokenCrypto.getMessage());
            System.exit(2);
            return;
        }

        PortalConsole console = new PortalConsole(store, service, sessions, audit, out, System.in);
        try {
            console.run();
        } catch (IOException terminalProblem) {
            out.println("terminal error: " + terminalProblem.getMessage());
            System.exit(1);
        }
    }
}

/** Command line options, with the defaults used when an option is left out. */
final class Config {

    static final int DEFAULT_ITERATIONS = 210_000;
    static final int DEFAULT_MAX_FAILURES = 5;
    static final int DEFAULT_LOCK_MINUTES = 15;
    static final int DEFAULT_SESSION_MINUTES = 30;
    static final String DEFAULT_STORE_FILE = "portal-records.txt";

    final Path storePath;
    final int iterations;
    final int maxFailures;
    final Duration lockDuration;
    final Duration sessionDuration;
    final boolean showHelp;

    private Config(Path storePath, int iterations, int maxFailures, Duration lockDuration,
                   Duration sessionDuration, boolean showHelp) {
        this.storePath = storePath;
        this.iterations = iterations;
        this.maxFailures = maxFailures;
        this.lockDuration = lockDuration;
        this.sessionDuration = sessionDuration;
        this.showHelp = showHelp;
    }

    static String usage() {
        return String.join(System.lineSeparator(),
                "usage: java EmployeePortalAuth [options]",
                "",
                "  --store <file>          records store to read and write"
                        + " (default: " + DEFAULT_STORE_FILE + ")",
                "  --iterations <n>        PBKDF2 rounds for new passwords, "
                        + PasswordHash.MIN_ITERATIONS + ".." + PasswordHash.MAX_ITERATIONS
                        + " (default: " + DEFAULT_ITERATIONS + ")",
                "  --max-failures <n>      failed logins before an account locks, 1..1000"
                        + " (default: " + DEFAULT_MAX_FAILURES + ")",
                "  --lock-minutes <n>      how long a locked account stays locked, 1..1440"
                        + " (default: " + DEFAULT_LOCK_MINUTES + ")",
                "  --session-minutes <n>   how long a granted login stays valid, 1..1440"
                        + " (default: " + DEFAULT_SESSION_MINUTES + ")",
                "  --help                  print this message and exit",
                "",
                "Inside the program, type help to list its commands.");
    }

    /**
     * @param systemProperty lookup for JVM properties, so {@code -Dportal.pbkdf2.iterations} can
     *                       also set the hashing cost (handy for a test run that must not wait)
     */
    static Config parse(String[] args, Function<String, String> systemProperty) {
        Path storePath = Paths.get(DEFAULT_STORE_FILE);
        int iterations = DEFAULT_ITERATIONS;
        int maxFailures = DEFAULT_MAX_FAILURES;
        int lockMinutes = DEFAULT_LOCK_MINUTES;
        int sessionMinutes = DEFAULT_SESSION_MINUTES;
        boolean showHelp = false;

        String costOverride = systemProperty.apply("portal.pbkdf2.iterations");
        if (costOverride != null && !costOverride.isEmpty()) {
            iterations = parseInt(costOverride, "portal.pbkdf2.iterations",
                    PasswordHash.MIN_ITERATIONS, PasswordHash.MAX_ITERATIONS);
        }

        for (int i = 0; i < args.length; i++) {
            String option = args[i];
            switch (option) {
                case "--help":
                case "-h":
                    showHelp = true;
                    break;
                case "--store":
                    storePath = Paths.get(nextValue(args, i, option));
                    i++;
                    break;
                case "--iterations":
                    iterations = parseInt(nextValue(args, i, option), option,
                            PasswordHash.MIN_ITERATIONS, PasswordHash.MAX_ITERATIONS);
                    i++;
                    break;
                case "--max-failures":
                    maxFailures = parseInt(nextValue(args, i, option), option, 1, 1_000);
                    i++;
                    break;
                case "--lock-minutes":
                    lockMinutes = parseInt(nextValue(args, i, option), option, 1, 1_440);
                    i++;
                    break;
                case "--session-minutes":
                    sessionMinutes = parseInt(nextValue(args, i, option), option, 1, 1_440);
                    i++;
                    break;
                default:
                    throw new IllegalArgumentException("unknown option: " + option);
            }
        }
        return new Config(storePath, iterations, maxFailures, Duration.ofMinutes(lockMinutes),
                Duration.ofMinutes(sessionMinutes), showHelp);
    }

    private static String nextValue(String[] args, int index, String option) {
        if (index + 1 >= args.length) {
            throw new IllegalArgumentException(option + " needs a value");
        }
        return args[index + 1];
    }

    private static int parseInt(String text, String option, int low, int high) {
        int value;
        try {
            value = Integer.parseInt(text.trim());
        } catch (NumberFormatException notANumber) {
            throw new IllegalArgumentException(option + " needs a whole number, not '" + text + "'");
        }
        if (value < low || value > high) {
            throw new IllegalArgumentException(option + " must be between " + low + " and " + high);
        }
        return value;
    }
}

/** Where the program gets its notion of "now", so a test can move the clock forward. */
interface TimeSource {
    Instant now();

    static TimeSource system() {
        return Instant::now;
    }
}

/** One account: its name, the salt and digest of its password, and whether it may sign in. */
final class EmployeeRecord {

    private final String userName;
    private final String salt;
    private final String hash;
    private final int iterations;
    private final AccountStatus status;

    EmployeeRecord(String userName, String salt, String hash, int iterations, AccountStatus status) {
        this.userName = Objects.requireNonNull(userName, "userName");
        this.salt = Objects.requireNonNull(salt, "salt");
        this.hash = Objects.requireNonNull(hash, "hash");
        this.iterations = iterations;
        this.status = Objects.requireNonNull(status, "status");
    }

    String userName() {
        return userName;
    }

    String salt() {
        return salt;
    }

    String hash() {
        return hash;
    }

    int iterations() {
        return iterations;
    }

    AccountStatus status() {
        return status;
    }

    EmployeeRecord withStatus(AccountStatus newStatus) {
        return new EmployeeRecord(userName, salt, hash, iterations, newStatus);
    }

    /** Salt and hash are stored as base64 text; this checks the text really is usable. */
    boolean isWellFormed() {
        if (iterations < PasswordHash.MIN_ITERATIONS || iterations > PasswordHash.MAX_ITERATIONS) {
            return false;
        }
        if (!UsernameRules.normalize(userName).map(userName::equals).orElse(false)) {
            return false;
        }
        return PasswordHash.decodeCanonical(salt, PasswordHash.SALT_BYTES) != null
                && PasswordHash.decodeCanonical(hash, PasswordHash.HASH_BYTES) != null;
    }

    @Override
    public String toString() {
        return "EmployeeRecord[" + userName + ", iterations=" + iterations + ", status=" + status + "]";
    }
}

/** Whether an account is allowed to sign in at all. */
enum AccountStatus {

    ACTIVE,
    DISABLED;

    static Optional<AccountStatus> parse(String text) {
        for (AccountStatus candidate : values()) {
            if (candidate.name().equalsIgnoreCase(text)) {
                return Optional.of(candidate);
            }
        }
        return Optional.empty();
    }
}

/**
 * A plain text file of records, one per line:
 *
 *     username|salt|hash|iterations|status
 *
 * Blank lines and lines that start with '#' are comments. A line that does not parse is left
 * alone in the file and reported as malformed rather than silently dropped, so a typo cannot
 * quietly turn into an account that accepts a different password. Rewrites go through a
 * temporary file and an atomic move, with owner-only permissions.
 */
final class FileRecordStore {

    static final String HEADER = "# employee-portal records v1: username|salt|hash|iterations|status";

    private final Path path;
    private final Map<String, EmployeeRecord> records = new LinkedHashMap<>();
    private int malformedLines;
    private int duplicateLines;

    FileRecordStore(Path path) throws IOException {
        this.path = path;
        if (Files.exists(path)) {
            reload();
        }
    }

    Path path() {
        return path;
    }

    synchronized int size() {
        return records.size();
    }

    synchronized int malformedLineCount() {
        return malformedLines;
    }

    synchronized int duplicateLineCount() {
        return duplicateLines;
    }

    synchronized List<String> names() {
        return new ArrayList<>(records.keySet());
    }

    synchronized Optional<EmployeeRecord> find(String normalizedUserName) {
        return Optional.ofNullable(records.get(normalizedUserName));
    }

    /** Inserts or replaces a record and flushes the whole store to disk. */
    synchronized void put(EmployeeRecord record) throws IOException {
        if (!record.isWellFormed()) {
            throw new IllegalArgumentException("refusing to store a malformed record for "
                    + record.userName());
        }
        records.put(record.userName(), record);
        flush();
    }

    /** Adds a record only when the username is free. Returns false when it is taken. */
    synchronized boolean createIfAbsent(EmployeeRecord record) throws IOException {
        if (records.containsKey(record.userName())) {
            return false;
        }
        put(record);
        return true;
    }

    private void reload() throws IOException {
        records.clear();
        malformedLines = 0;
        duplicateLines = 0;
        for (String line : Files.readAllLines(path, StandardCharsets.US_ASCII)) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            String[] field = trimmed.split("\\|", -1);
            if (field.length != 5) {
                malformedLines++;
                continue;
            }
            String name = UsernameRules.normalize(field[0]).orElse(null);
            if (name == null || !name.equals(field[0])) {
                malformedLines++;
                continue;
            }
            int iterations;
            try {
                iterations = Integer.parseInt(field[3]);
            } catch (NumberFormatException notANumber) {
                malformedLines++;
                continue;
            }
            AccountStatus status = AccountStatus.parse(field[4]).orElse(null);
            if (status == null) {
                malformedLines++;
                continue;
            }
            EmployeeRecord candidate =
                    new EmployeeRecord(name, field[1], field[2], iterations, status);
            if (!candidate.isWellFormed()) {
                malformedLines++;
                continue;
            }
            if (records.containsKey(name)) {
                duplicateLines++;
                continue;
            }
            records.put(name, candidate);
        }
    }

    private void flush() throws IOException {
        List<String> lines = new ArrayList<>(records.size() + 1);
        lines.add(HEADER);
        for (EmployeeRecord record : records.values()) {
            lines.add(String.join("|", record.userName(), record.salt(), record.hash(),
                    Integer.toString(record.iterations()), record.status().name()));
        }
        Path parent = path.toAbsolutePath().getParent();
        Files.createDirectories(parent);
        Path temp = Files.createTempFile(parent, path.getFileName().toString(), ".tmp");
        try {
            Files.write(temp, lines, StandardCharsets.US_ASCII);
            restrictToOwner(temp);
            try {
                Files.move(temp, path, StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException platformWithoutAtomicMove) {
                Files.move(temp, path, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    private void restrictToOwner(Path file) {
        try {
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException | IOException notPosix) {
            // Best effort: a file system without POSIX permissions keeps its defaults.
        }
    }
}

/**
 * Turns salt and password bytes into a digest, and back again.
 *
 * The base64 helpers are strict on purpose: {@link Base64.Decoder} happily accepts unpadded
 * input and ignores nothing else, so a stored digest is only accepted when re-encoding it
 * reproduces the exact text that was decoded.
 */
final class PasswordHash {

    static final int SALT_BYTES = 16;
    static final int HASH_BYTES = 32;
    static final int MIN_ITERATIONS = 1_000;
    static final int MAX_ITERATIONS = 5_000_000;

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final Base64.Encoder BASE64_ENCODER = Base64.getEncoder();
    private static final Base64.Decoder BASE64_DECODER = Base64.getDecoder();

    private PasswordHash() {
    }

    static byte[] newSalt(SecureRandom random) {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        return salt;
    }

    /** Derives the digest. Throws if this JVM lacks PBKDF2 or the inputs are out of range. */
    static byte[] derive(char[] password, byte[] salt, int iterations) {
        if (password == null) {
            throw new IllegalArgumentException("no password to hash");
        }
        if (salt == null || salt.length != SALT_BYTES) {
            throw new IllegalArgumentException("salt must be exactly " + SALT_BYTES + " bytes");
        }
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
            throw new IllegalArgumentException("iterations must be between " + MIN_ITERATIONS
                    + " and " + MAX_ITERATIONS);
        }
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_BYTES * 8);
        try {
            byte[] digest = SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
            if (digest.length != HASH_BYTES) {
                throw new IllegalStateException("expected " + HASH_BYTES + " digest bytes, got "
                        + digest.length);
            }
            return digest;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException unavailable) {
            throw new IllegalStateException(ALGORITHM + " is not usable here: "
                    + unavailable.getMessage(), unavailable);
        } finally {
            spec.clearPassword();
        }
    }

    /** Compares a candidate password with a stored digest without leaking the digest. */
    static boolean matches(char[] candidate, byte[] salt, byte[] storedDigest, int iterations) {
        return MessageDigest.isEqual(derive(candidate, salt, iterations), storedDigest);
    }

    static String encode(byte[] raw) {
        return BASE64_ENCODER.encodeToString(raw);
    }

    /** Returns the bytes, or null when the text is not the canonical base64 of that many bytes. */
    static byte[] decodeCanonical(String text, int expectedBytes) {
        if (text == null || text.isEmpty()) {
            return null;
        }
        byte[] raw;
        try {
            raw = BASE64_DECODER.decode(text);
        } catch (IllegalArgumentException notBase64) {
            return null;
        }
        if (!BASE64_ENCODER.encodeToString(raw).equals(text) || raw.length != expectedBytes) {
            return null;
        }
        return raw;
    }
}

/**
 * Username syntax and the canonical form used to look an account up.
 *
 * Only plain spaces are stripped from the ends. {@code String.trim()} also deletes control
 * characters, which would fold "alice" followed by an invisible NUL onto the real account, so
 * this class strips spaces and then requires every remaining character to be on the whitelist.
 */
final class UsernameRules {

    static final int MIN_LENGTH = 3;
    static final int MAX_LENGTH = 64;

    private UsernameRules() {
    }

    /** Returns the lower-case canonical name, or empty when the input is not a usable name. */
    static Optional<String> normalize(String raw) {
        if (raw == null) {
            return Optional.empty();
        }
        int from = 0;
        int to = raw.length();
        while (from < to && raw.charAt(from) == ' ') {
            from++;
        }
        while (to > from && raw.charAt(to - 1) == ' ') {
            to--;
        }
        int length = to - from;
        if (length < MIN_LENGTH || length > MAX_LENGTH) {
            return Optional.empty();
        }
        char[] canonical = new char[length];
        for (int i = 0; i < length; i++) {
            char c = raw.charAt(from + i);
            if (c >= 'a' && c <= 'z') {
                canonical[i] = c;
            } else if (c >= 'A' && c <= 'Z') {
                canonical[i] = (char) (c - 'A' + 'a');
            } else if ((c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
                canonical[i] = c;
            } else {
                // Rejects spaces, tabs, newlines, NUL, escapes, accented letters, everything.
                return Optional.empty();
            }
        }
        if (!isLetterOrDigit(canonical[0]) || !isLetterOrDigit(canonical[length - 1])) {
            return Optional.empty();
        }
        return Optional.of(new String(canonical));
    }

    private static boolean isLetterOrDigit(char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
    }
}

/**
 * Password sanity checks, run before anything is hashed.
 *
 * {@link PBEKeySpec} is not a faithful copy of the characters it is given: it drops trailing
 * NULs and turns an unpaired surrogate into '?'. Two different inputs would then hash to the
 * same value, so control characters and lone surrogates are refused up front.
 */
final class PasswordRules {

    static final int MAX_LENGTH = 1_024;
    static final int CREATION_MIN_LENGTH = 10;

    private PasswordRules() {
    }

    /** Empty when the characters can be hashed faithfully. */
    static Optional<String> structuralProblem(char[] password) {
        if (password == null || password.length == 0) {
            return Optional.of("no password entered");
        }
        if (password.length > MAX_LENGTH) {
            return Optional.of("password longer than " + MAX_LENGTH + " characters");
        }
        for (int i = 0; i < password.length; i++) {
            char c = password[i];
            if (c < 0x20 || c == 0x7F) {
                return Optional.of("password contains a control character");
            }
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= password.length || !Character.isLowSurrogate(password[i + 1])) {
                    return Optional.of("password contains half of a surrogate pair");
                }
                i++;
            } else if (Character.isLowSurrogate(c)) {
                return Optional.of("password contains half of a surrogate pair");
            }
        }
        return Optional.empty();
    }

    /** Structural checks plus the minimum strength asked of a brand new password. */
    static Optional<String> creationProblem(char[] password) {
        Optional<String> problem = structuralProblem(password);
        if (problem.isPresent()) {
            return problem;
        }
        if (password.length < CREATION_MIN_LENGTH) {
            return Optional.of("a new password needs at least " + CREATION_MIN_LENGTH + " characters");
        }
        boolean hasLetter = false;
        boolean hasDigit = false;
        for (char c : password) {
            hasLetter |= Character.isLetter(c);
            hasDigit |= Character.isDigit(c);
        }
        if (!hasLetter || !hasDigit) {
            return Optional.of("a new password needs at least one letter and one digit");
        }
        return Optional.empty();
    }
}

/** Counted failed logins and the temporary lock that follows them. */
final class LoginAttemptTracker {

    enum Phase {
        OPEN,
        LOCKED
    }

    record Inspection(Phase phase, int failures, Instant lockedUntil) {

        static Inspection open() {
            return new Inspection(Phase.OPEN, 0, null);
        }
    }

    private static final class State {

        private int failures;
        private Instant lockedUntil;
    }

    private final int maxFailures;
    private final Duration lockDuration;
    private final Map<String, State> states = new LinkedHashMap<>();

    LoginAttemptTracker(int maxFailures, Duration lockDuration) {
        this.maxFailures = maxFailures;
        this.lockDuration = lockDuration;
    }

    synchronized Inspection inspect(String userName, Instant now) {
        State state = states.get(userName);
        if (state == null) {
            return Inspection.open();
        }
        if (state.lockedUntil != null) {
            if (now.isBefore(state.lockedUntil)) {
                return new Inspection(Phase.LOCKED, state.failures, state.lockedUntil);
            }
            // The lock has expired, so start the count over rather than resume it.
            states.remove(userName);
            return Inspection.open();
        }
        return new Inspection(Phase.OPEN, state.failures, null);
    }

    /**
     * Records one failed login.
     *
     * @return true when this particular failure is the one that closed the account
     */
    synchronized boolean registerFailure(String userName, Instant now) {
        if (inspect(userName, now).phase() == Phase.LOCKED) {
            return false;
        }
        State state = states.computeIfAbsent(userName, key -> new State());
        state.failures++;
        if (state.failures >= maxFailures) {
            state.lockedUntil = now.plus(lockDuration);
            return true;
        }
        return false;
    }

    synchronized void registerSuccess(String userName) {
        states.remove(userName);
    }

    synchronized void unlock(String userName) {
        states.remove(userName);
    }

    synchronized int failures(String userName, Instant now) {
        return inspect(userName, now).failures();
    }

    synchronized Duration remainingLock(String userName, Instant now) {
        Inspection inspection = inspect(userName, now);
        if (inspection.phase() != Phase.LOCKED) {
            return Duration.ZERO;
        }
        Duration remaining = Duration.between(now, inspection.lockedUntil());
        return remaining.isNegative() ? Duration.ZERO : remaining;
    }
}

/** A login that went through: who it belongs to, when it was issued and when it lapses. */
record AccessSession(String token, String userName, Instant issuedAt, Instant expiresAt) {

    boolean isCurrentAt(Instant now) {
        return now.isBefore(expiresAt);
    }

    /** A short handle for the log; the full token stays out of the log. */
    String fingerprint() {
        return token.length() <= 8 ? token : token.substring(0, 8);
    }
}

/** Issues and checks access sessions for logins that were granted. */
final class SessionRegistry {

    private static final Base64.Encoder TOKEN_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final int TOKEN_BYTES = 32;

    private final Duration timeToLive;
    private final SecureRandom random;
    private final TimeSource time;
    private final Map<String, AccessSession> live = new LinkedHashMap<>();

    SessionRegistry(Duration timeToLive, SecureRandom random, TimeSource time) {
        this.timeToLive = timeToLive;
        this.random = random;
        this.time = time;
    }

    synchronized AccessSession issue(String userName) {
        byte[] raw = new byte[TOKEN_BYTES];
        random.nextBytes(raw);
        Instant now = time.now();
        AccessSession session =
                new AccessSession(TOKEN_ENCODER.encodeToString(raw), userName, now, now.plus(timeToLive));
        live.put(session.token(), session);
        return session;
    }

    /** Returns the session only while its token is valid and unexpired. */
    synchronized Optional<AccessSession> validate(String token, Instant now) {
        AccessSession session = live.get(token);
        if (session == null) {
            return Optional.empty();
        }
        if (!session.isCurrentAt(now)) {
            live.remove(token);
            return Optional.empty();
        }
        return Optional.of(session);
    }

    synchronized boolean revoke(String token) {
        return live.remove(token) != null;
    }

    synchronized int activeCount() {
        return live.size();
    }
}

/** The decision made about one login attempt. */
final class LoginOutcome {

    enum Status {
        /** Credentials matched and an access session was issued. */
        GRANTED,
        /** Wrong username or wrong password, or input that is not a possible credential. */
        DENIED,
        /** Too many earlier failures on this account; try again once the lock lapses. */
        LOCKED,
        /** The account is on file but switched off by an operator. */
        UNAVAILABLE
    }

    private final Status status;
    private final String auditReason;
    private final String userName;
    private final AccessSession session;
    private final Duration lockRemaining;

    private LoginOutcome(Status status, String auditReason, String userName, AccessSession session,
                         Duration lockRemaining) {
        this.status = status;
        this.auditReason = auditReason;
        this.userName = userName;
        this.session = session;
        this.lockRemaining = lockRemaining;
    }

    static LoginOutcome granted(String userName, AccessSession session) {
        return new LoginOutcome(Status.GRANTED, "ok", userName, session, Duration.ZERO);
    }

    static LoginOutcome denied(String auditReason) {
        return new LoginOutcome(Status.DENIED, auditReason, null, null, Duration.ZERO);
    }

    static LoginOutcome locked(Duration remaining) {
        return new LoginOutcome(Status.LOCKED, "account-locked", null, null, remaining);
    }

    static LoginOutcome unavailable(String auditReason) {
        return new LoginOutcome(Status.UNAVAILABLE, auditReason, null, null, Duration.ZERO);
    }

    Status status() {
        return status;
    }

    /** Internal cause, meant for the log line rather than for the person typing. */
    String auditReason() {
        return auditReason;
    }

    /** The signed-in name, or null unless the attempt was granted. */
    String userName() {
        return userName;
    }

    AccessSession session() {
        return session;
    }

    Duration lockRemaining() {
        return lockRemaining;
    }

    long lockRemainingMinutes() {
        long seconds = lockRemaining.getSeconds();
        return seconds <= 0 ? 1 : (seconds + 59) / 60;
    }
}

/**
 * Decides whether a username and password combination may use the portal.
 *
 * Every path through {@link #login} performs exactly one PBKDF2 derivation. Unknown usernames,
 * malformed usernames and locked accounts are all answered at the same cost as a real
 * credential check, which is what stops response time from announcing which names exist.
 */
final class PortalAuthService {

    /** Hashed in place of a real candidate when there is no account to check against. */
    private static final char[] PROBE_PASSWORD =
            "portal-timing-probe-passphrase".toCharArray();

    private final FileRecordStore store;
    private final LoginAttemptTracker tracker;
    private final SessionRegistry sessions;
    private final AuditLog audit;
    private final SecureRandom random;
    private final int policyIterations;
    private final TimeSource time;
    private final byte[] probeSalt;
    private final byte[] probeDigest;

    PortalAuthService(FileRecordStore store, LoginAttemptTracker tracker, SessionRegistry sessions,
                      AuditLog audit, SecureRandom random, int policyIterations, TimeSource time) {
        this.store = store;
        this.tracker = tracker;
        this.sessions = sessions;
        this.audit = audit;
        this.random = random;
        this.policyIterations = policyIterations;
        this.time = time;
        this.probeSalt = PasswordHash.newSalt(random);
        this.probeDigest = PasswordHash.derive(PROBE_PASSWORD, probeSalt, policyIterations);
        // A probe digest that quietly failed to compute would make every unknown username
        // return instantly, so prove the probe works before serving a single login.
        if (!PasswordHash.matches(PROBE_PASSWORD, probeSalt, probeDigest, policyIterations)
                || PasswordHash.matches("not-the-probe-passphrase".toCharArray(), probeSalt,
                        probeDigest, policyIterations)) {
            throw new IllegalStateException("the timing probe does not behave as expected");
        }
    }

    /**
     * Checks one login attempt. The password array is the caller's: this method never clears or
     * rewrites it, so the caller stays free to use it (the console wipes it when done).
     */
    LoginOutcome login(String rawUserName, char[] password) {
        Instant now = time.now();
        Optional<String> canonicalName = UsernameRules.normalize(rawUserName);
        Optional<String> passwordProblem = PasswordRules.structuralProblem(password);
        if (canonicalName.isEmpty() || passwordProblem.isPresent()) {
            burnOneDerivation(PROBE_PASSWORD, probeSalt, probeDigest);
            audit.record("login-rejected", canonicalName.orElse("<unusable-name>"),
                    passwordProblem.orElse("unusable username"));
            return LoginOutcome.denied(passwordProblem.isPresent()
                    ? passwordProblem.get() : "unusable username");
        }

        String userName = canonicalName.get();
        EmployeeRecord record = store.find(userName).orElse(null);
        if (record == null) {
            burnOneDerivation(PROBE_PASSWORD, probeSalt, probeDigest);
            audit.record("login-denied", userName, "no such account");
            return LoginOutcome.denied("no such account");
        }

        byte[] salt = PasswordHash.decodeCanonical(record.salt(), PasswordHash.SALT_BYTES);
        byte[] digest = PasswordHash.decodeCanonical(record.hash(), PasswordHash.HASH_BYTES);
        // isWellFormed() already proved both decode, so a null here means the record was built
        // somewhere other than the store. Treat it as a bad account rather than trusting it.
        if (salt == null || digest == null) {
            burnOneDerivation(PROBE_PASSWORD, probeSalt, probeDigest);
            audit.record("login-denied", userName, "record on file is unreadable");
            return LoginOutcome.unavailable("record on file is unreadable");
        }

        boolean credentialsMatch = PasswordHash.matches(password, salt, digest, record.iterations());
        LoginAttemptTracker.Inspection before = tracker.inspect(userName, now);
        if (record.status() == AccountStatus.DISABLED) {
            audit.record("login-denied", userName, "account disabled");
            return LoginOutcome.unavailable("account disabled");
        }
        if (before.phase() == LoginAttemptTracker.Phase.LOCKED) {
            Duration remaining = tracker.remainingLock(userName, now);
            audit.record("login-refused", userName,
                    "locked for " + remaining.getSeconds() + " more second(s)");
            return LoginOutcome.locked(remaining);
        }
        if (!credentialsMatch) {
            boolean trippedLock = tracker.registerFailure(userName, now);
            audit.record("login-denied", userName,
                    trippedLock ? "wrong password, account now locked" : "wrong password");
            return LoginOutcome.denied("wrong password");
        }

        tracker.registerSuccess(userName);
        if (record.iterations() < policyIterations) {
            raiseCost(userName, password, record, salt);
        }
        AccessSession session = sessions.issue(userName);
        audit.record("login-granted", userName, "session " + session.fingerprint());
        return LoginOutcome.granted(userName, session);
    }

    /** Accounts are switched off by an operator, so count nothing and say the account is off. */
    private void burnOneDerivation(char[] candidate, byte[] salt, byte[] digest) {
        PasswordHash.matches(candidate, salt, digest, policyIterations);
    }

    /**
     * When an account was created with a cheaper setting than the portal now requires, and the
     * plain password happens to be in hand, re-hash it at today's cost while we can.
     */
    private void raiseCost(String userName, char[] password, EmployeeRecord record, byte[] salt) {
        try {
            EmployeeRecord raised = new EmployeeRecord(userName, record.salt(),
                    PasswordHash.encode(PasswordHash.derive(password, salt, policyIterations)),
                    policyIterations, record.status());
            store.put(raised);
            audit.record("password-cost-raised", userName,
                    record.iterations() + " -> " + policyIterations + " iterations");
        } catch (IOException couldNotWrite) {
            audit.record("password-cost-not-raised", userName, couldNotWrite.getMessage());
        }
    }

    /** Creates a new account, or returns the reason it was refused. */
    Optional<String> createAccount(String rawUserName, char[] password) {
        Optional<String> canonicalName = UsernameRules.normalize(rawUserName);
        if (canonicalName.isEmpty()) {
            return Optional.of("username must be " + UsernameRules.MIN_LENGTH + "-"
                    + UsernameRules.MAX_LENGTH + " letters, digits, dot, underscore or hyphen");
        }
        Optional<String> problem = PasswordRules.creationProblem(password);
        if (problem.isPresent()) {
            return problem;
        }
        byte[] salt = PasswordHash.newSalt(random);
        EmployeeRecord record = new EmployeeRecord(canonicalName.get(), PasswordHash.encode(salt),
                PasswordHash.encode(PasswordHash.derive(password, salt, policyIterations)),
                policyIterations, AccountStatus.ACTIVE);
        try {
            if (!store.createIfAbsent(record)) {
                return Optional.of("an account named " + canonicalName.get() + " already exists");
            }
        } catch (IOException couldNotWrite) {
            return Optional.of("could not write the records store: " + couldNotWrite.getMessage());
        }
        audit.record("account-created", canonicalName.get(), "cost " + policyIterations);
        return Optional.empty();
    }

    /** Turns an account's ability to sign in on or off. */
    Optional<String> setStatus(String rawUserName, AccountStatus status) {
        Optional<String> canonicalName = UsernameRules.normalize(rawUserName);
        if (canonicalName.isEmpty()) {
            return Optional.of("that is not a usable username");
        }
        EmployeeRecord record = store.find(canonicalName.get()).orElse(null);
        if (record == null) {
            return Optional.of("no account named " + canonicalName.get());
        }
        try {
            store.put(record.withStatus(status));
        } catch (IOException couldNotWrite) {
            return Optional.of("could not write the records store: " + couldNotWrite.getMessage());
        }
        if (status == AccountStatus.ACTIVE) {
            tracker.unlock(canonicalName.get());
        }
        audit.record("account-" + status.name().toLowerCase(java.util.Locale.ROOT),
                canonicalName.get(), "by operator");
        return Optional.empty();
    }

    /** Clears the failure count and the lock on an account. */
    Optional<String> unlockAccount(String rawUserName) {
        Optional<String> canonicalName = UsernameRules.normalize(rawUserName);
        if (canonicalName.isEmpty()) {
            return Optional.of("that is not a usable username");
        }
        if (store.find(canonicalName.get()).isEmpty()) {
            return Optional.of("no account named " + canonicalName.get());
        }
        tracker.unlock(canonicalName.get());
        audit.record("account-unlocked", canonicalName.get(), "by operator");
        return Optional.empty();
    }

    AuditLog auditLog() {
        return audit;
    }

    LoginAttemptTracker tracker() {
        return tracker;
    }

    /** The same clock every part of this service reads, so nothing drifts. */
    Instant now() {
        return time.now();
    }
}

/** One timestamped line per security relevant event. Never contains a password or a digest. */
final class AuditLog {

    private final PrintStream out;
    private final TimeSource time;

    AuditLog(PrintStream out, TimeSource time) {
        this.out = out;
        this.time = time;
    }

    synchronized void record(String event, String subject, String detail) {
        out.println("[audit] " + time.now() + " " + event + " user=" + subject + " detail=" + detail);
    }
}

/**
 * The terminal loop: reads a username and password, hands them to the service, reports the
 * answer, and offers the handful of operator commands the portal needs to be usable.
 */
final class PortalConsole {

    private final FileRecordStore store;
    private final PortalAuthService service;
    private final SessionRegistry sessions;
    private final AuditLog audit;
    private final PrintStream out;
    private final BufferedReader pipedInput;
    private final Console terminal;
    private AccessSession currentSession;
    private boolean running = true;

    PortalConsole(FileRecordStore store, PortalAuthService service, SessionRegistry sessions,
                  AuditLog audit, PrintStream out, java.io.InputStream in) {
        this.store = store;
        this.service = service;
        this.sessions = sessions;
        this.audit = audit;
        this.out = out;
        this.terminal = System.console();
        this.pipedInput = terminal == null
                ? new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8)) : null;
    }

    void run() throws IOException {
        out.println("Type your username, or help for the list of commands.");
        while (running) {
            out.print("portal> ");
            out.flush();
            String line = readLine();
            if (line == null) {
                out.println();
                break;
            }
            handleLine(line);
        }
        if (currentSession != null && sessions.revoke(currentSession.token())) {
            audit.record("session-ended", currentSession.userName(), "program exit");
        }
        out.println("goodbye");
    }

    void handleLine(String line) {
        String command = line.trim();
        if (command.isEmpty()) {
            return;
        }
        String head = firstWord(command).toLowerCase(java.util.Locale.ROOT);
        String argument = command.length() > head.length() ? command.substring(head.length()).trim() : "";
        switch (head) {
            case "help":
            case "?":
                out.println(Config.usage());
                out.println("portal commands:");
                out.println("  <username>            sign in (you will be asked for a password)");
                out.println("  add <username>        create an account");
                out.println("  status <username>     show an account and its failure count");
                out.println("  disable <username>    stop an account from signing in");
                out.println("  enable <username>     allow an account to sign in again");
                out.println("  unlock <username>     clear a temporary lock on an account");
                out.println("  whoami                show the current session");
                out.println("  logout                end the current session");
                out.println("  quit                  leave");
                return;
            case "quit":
            case "exit":
                running = false;
                return;
            case "whoami":
                whoami();
                return;
            case "logout":
                logout();
                return;
            case "add":
                addAccount(argument);
                return;
            case "status":
                status(argument);
                return;
            case "disable":
                changeStatus(argument, AccountStatus.DISABLED);
                return;
            case "enable":
                changeStatus(argument, AccountStatus.ACTIVE);
                return;
            case "unlock":
                reportOperatorResult(unlockAccount(argument));
                return;
            default:
                signIn(line);
        }
    }

    private void signIn(String rawUserName) {
        char[] password = null;
        try {
            password = readPassword();
            if (password == null) {
                out.println("no password entered");
                return;
            }
            LoginOutcome outcome = service.login(rawUserName, password);
            switch (outcome.status()) {
                case GRANTED:
                    currentSession = outcome.session();
                    out.println("Access granted for " + outcome.userName() + ".");
                    out.println("Session " + currentSession.fingerprint() + " is valid until "
                            + currentSession.expiresAt());
                    break;
                case LOCKED:
                    out.println("Access denied: this account is locked for about "
                            + outcome.lockRemainingMinutes() + " more minute(s).");
                    break;
                case UNAVAILABLE:
                    out.println("Access denied: that account cannot be used right now."
                            + " Ask the portal administrator.");
                    break;
                case DENIED:
                default:
                    // One wording for a wrong name and a wrong password, so typing a name here
                    // cannot be used to find out whether the portal knows it.
                    out.println("Access denied: invalid username or password.");
                    break;
            }
        } finally {
            wipe(password);
        }
    }

    private void addAccount(String argument) {
        if (argument.isEmpty()) {
            out.println("usage: add <username>");
            return;
        }
        char[] first = null;
        char[] second = null;
        try {
            first = readPassword("new password: ");
            if (first == null) {
                out.println("no password entered");
                return;
            }
            second = readPassword("repeat it:    ");
            if (second == null) {
                out.println("no password entered");
                return;
            }
            if (!Arrays.equals(first, second)) {
                out.println("the two passwords do not match, nothing was created");
                return;
            }
            reportOperatorResult(service.createAccount(argument, first));
        } finally {
            wipe(first);
            wipe(second);
        }
    }

    private void changeStatus(String argument, AccountStatus status) {
        if (argument.isEmpty()) {
            out.println("usage: " + status.name().toLowerCase(java.util.Locale.ROOT) + " <username>");
            return;
        }
        reportOperatorResult(service.setStatus(argument, status));
    }

    private Optional<String> unlockAccount(String argument) {
        if (argument.isEmpty()) {
            return Optional.of("usage: unlock <username>");
        }
        return service.unlockAccount(argument);
    }

    private void reportOperatorResult(Optional<String> problem) {
        if (problem.isPresent()) {
            out.println("could not do that: " + problem.get());
        } else {
            out.println("done");
        }
    }

    private void status(String argument) {
        Optional<String> canonicalName = UsernameRules.normalize(argument);
        if (canonicalName.isEmpty()) {
            out.println("usage: status <username>");
            return;
        }
        EmployeeRecord record = store.find(canonicalName.get()).orElse(null);
        if (record == null) {
            out.println("no account named " + canonicalName.get());
            return;
        }
        out.println("account " + record.userName() + ": " + record.status() + ", password cost "
                + record.iterations() + " iterations");
        LoginAttemptTracker.Inspection inspection =
                service.tracker().inspect(record.userName(), service.now());
        out.println("failed logins since the last success: " + inspection.failures()
                + (inspection.phase() == LoginAttemptTracker.Phase.LOCKED
                        ? ", locked until " + inspection.lockedUntil() : ""));
    }

    private void whoami() {
        if (currentSession == null) {
            out.println("no session");
            return;
        }
        Optional<AccessSession> live = sessions.validate(currentSession.token(), service.now());
        if (live.isEmpty()) {
            out.println("the session for " + currentSession.userName() + " has lapsed");
            currentSession = null;
            return;
        }
        out.println("signed in as " + live.get().userName() + " until " + live.get().expiresAt());
    }

    private void logout() {
        if (currentSession == null) {
            out.println("no session to end");
            return;
        }
        boolean revoked = sessions.revoke(currentSession.token());
        audit.record("session-ended", currentSession.userName(), "signed out");
        out.println(revoked ? "signed out" : "that session had already lapsed");
        currentSession = null;
    }

    private static String firstWord(String text) {
        int end = 0;
        while (end < text.length() && text.charAt(end) != ' ' && text.charAt(end) != '\t') {
            end++;
        }
        return text.substring(0, end);
    }

    private String readLine() throws IOException {
        return terminal != null ? terminal.readLine() : pipedInput.readLine();
    }

    private char[] readPassword() {
        return readPassword("password: ");
    }

    private char[] readPassword(String prompt) {
        if (terminal != null) {
            return terminal.readPassword(prompt);
        }
        out.print(prompt);
        out.flush();
        try {
            String line = pipedInput.readLine();
            return line == null ? null : line.toCharArray();
        } catch (IOException terminalProblem) {
            return null;
        }
    }

    private static void wipe(char[] secret) {
        if (secret != null) {
            Arrays.fill(secret, ' ');
        }
    }
}
