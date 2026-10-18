import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.Console;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Password authentication service with an audit log.
 *
 * <p>Public API: {@link #register(String, char[])}, {@link #authenticate(String, char[])} and
 * {@link #authenticate(String, char[], String)}. An {@link Result} carries the caller-facing
 * outcome plus an internal {@link Reason} that is meant for the audit trail only.
 *
 * <p>Design points that are load bearing and easy to get wrong:
 * <ul>
 *   <li>Passwords are stored only as PBKDF2-HMAC-SHA256 digests with a per-account random salt
 *       (self-describing encoding, see {@link PasswordHash#encode()}). The plaintext password is
 *       never stored, logged or returned.</li>
 *   <li>Every attempt derives exactly one key, including attempts that are refused before the
 *       credential check (unknown user, malformed username, malformed password, corrupt record,
 *       disabled account, locked account). Without that, response time alone tells an attacker
 *       which usernames exist. The equal-work value is generated at construction time by a real
 *       key derivation, never pasted in as a literal.</li>
 *   <li>Key comparison is constant time ({@link MessageDigest#isEqual(byte[], byte[])}).</li>
 *   <li>Candidates that the JCE would silently collapse onto another password are rejected before
 *       hashing: {@link #isHashablePassword(char[])} explains why.</li>
 *   <li>Every attempt is written to an {@link EventLogger}. Log fields are sanitized so that a
 *       username containing CR/LF cannot forge a log record.</li>
 * </ul>
 *
 * <p>See README.md for compile/run instructions and for the documented limitations.
 */
public final class UserAuthentication {

    /** Caller-facing outcome. Deliberately does not distinguish "no such user" from "wrong
     * password", so a login screen can render one message for both. */
    public enum Outcome {
        SUCCESS,
        INVALID_CREDENTIALS,
        ACCOUNT_LOCKED,
        ACCOUNT_DISABLED,
        INVALID_INPUT
    }

    /** Internal cause. Audit-trail data: rendering this to an end user would leak whether an
     * account exists. */
    public enum Reason {
        OK,
        UNKNOWN_USER,
        BAD_PASSWORD,
        ACCOUNT_LOCKED,
        ACCOUNT_DISABLED,
        MALFORMED_USERNAME,
        MALFORMED_PASSWORD,
        CORRUPT_RECORD
    }

    /** Event kinds written to the application log. */
    public enum EventType {
        LOGIN_SUCCESS,
        LOGIN_FAILURE,
        LOGIN_REFUSED,
        ACCOUNT_REGISTERED,
        ACCOUNT_LOCKED_OUT,
        ACCOUNT_UNLOCKED
    }

    public static final int DEFAULT_ITERATIONS = 120_000;
    private static final int SALT_BYTES = 16;
    private static final int KEY_BYTES = 32;
    private static final String KDF = "PBKDF2WithHmacSHA256";
    private static final String HASH_PREFIX = "pbkdf2-sha256";
    private static final int USERNAME_MIN = 3;
    private static final int USERNAME_MAX = 64;
    private static final int PASSWORD_MAX = 1024;
    private static final Pattern USERNAME_PATTERN = Pattern.compile("[a-z0-9._-]+");
    /** Password used for the equal-work derivation. It matches no stored account. */
    private static final char[] EQUAL_WORK_SECRET =
        "equal-work-placeholder-never-a-real-secret".toCharArray();

    private final AccountStore accounts;
    private final EventLogger log;
    private final Config config;
    private final SecureRandom random = new SecureRandom();
    /** Real digest of {@link #EQUAL_WORK_SECRET} at {@link Config#iterations}: the work unit that
     * every refused attempt has to pay. */
    private final PasswordHash equalWorkHash;

    public UserAuthentication(AccountStore accounts, EventLogger log, Config config) {
        if (accounts == null || log == null || config == null) {
            throw new IllegalArgumentException("accounts, log and config are required");
        }
        this.accounts = accounts;
        this.log = log;
        this.config = config;
        this.equalWorkHash = PasswordHash.generate(EQUAL_WORK_SECRET, config.iterations, new SecureRandom());
    }

    /** Service backed by an in-memory store, handy for tests, demos and single-process apps. */
    public static UserAuthentication withInMemoryStore(EventLogger log, Config config) {
        return new UserAuthentication(new InMemoryAccountStore(), log, config);
    }

    // --------------------------------------------------------------------------------------------
    // Configuration
    // --------------------------------------------------------------------------------------------

    /** Tunables. Lower the iteration count only in tests; 120k is a reasonable 2026 baseline. */
    public static final class Config {
        public final int iterations;
        public final int maxFailures;
        public final Duration lockDuration;
        public final Duration failureWindow;
        public final Clock clock;

        public Config(int iterations, int maxFailures, Duration lockDuration,
                      Duration failureWindow, Clock clock) {
            if (iterations < 1_000) {
                throw new IllegalArgumentException("iterations must be >= 1000, got " + iterations);
            }
            if (maxFailures < 1) {
                throw new IllegalArgumentException("maxFailures must be >= 1, got " + maxFailures);
            }
            if (lockDuration == null || lockDuration.isNegative() || lockDuration.isZero()) {
                throw new IllegalArgumentException("lockDuration must be positive");
            }
            if (failureWindow == null || failureWindow.isNegative() || failureWindow.isZero()) {
                throw new IllegalArgumentException("failureWindow must be positive");
            }
            this.iterations = iterations;
            this.maxFailures = maxFailures;
            this.lockDuration = lockDuration;
            this.failureWindow = failureWindow;
            this.clock = clock == null ? Clock.systemUTC() : clock;
        }

        public static Config defaults() {
            return new Config(DEFAULT_ITERATIONS, 5, Duration.ofMinutes(15),
                Duration.ofMinutes(30), Clock.systemUTC());
        }

        /** Same lockout policy, fewer KDF rounds: keeps test suites and demos fast. */
        public static Config fast(int iterations) {
            return new Config(iterations, 5, Duration.ofMinutes(15), Duration.ofMinutes(30),
                Clock.systemUTC());
        }

        /** Non-locking policy for suites that want many failed attempts on one account. */
        public Config withoutLockout(int strikes) {
            return new Config(iterations, strikes, lockDuration, failureWindow, clock);
        }
    }

    // --------------------------------------------------------------------------------------------
    // Result / log record value types
    // --------------------------------------------------------------------------------------------

    /** Immutable outcome of one {@code authenticate} or {@code register} call. */
    public static final class Result {
        private final Outcome outcome;
        private final Reason reason;
        private final String username;
        private final Instant timestamp;
        private final long durationMillis;
        private final int failedAttempts;

        Result(Outcome outcome, Reason reason, String username, Instant timestamp,
               long durationMillis, int failedAttempts) {
            this.outcome = outcome;
            this.reason = reason;
            this.username = username;
            this.timestamp = timestamp;
            this.durationMillis = durationMillis;
            this.failedAttempts = failedAttempts;
        }

        public Outcome outcome() {
            return outcome;
        }

        /** Audit-only cause; use {@link #userMessage()} for anything a user can see. */
        public Reason auditReason() {
            return reason;
        }

        /** Normalized username, or the sanitized raw input when the name itself was rejected. */
        public String username() {
            return username;
        }

        public Instant timestamp() {
            return timestamp;
        }

        /** Wall time of this attempt, including the key derivation. */
        public long durationMillis() {
            return durationMillis;
        }

        /** Failed attempts recorded for the account after this one (0 when unrelated). */
        public int failedAttempts() {
            return failedAttempts;
        }

        public boolean isSuccess() {
            return outcome == Outcome.SUCCESS;
        }

        /** Wording suitable for a login screen. */
        public String userMessage() {
            switch (outcome) {
                case SUCCESS:
                    return "Login successful.";
                case ACCOUNT_LOCKED:
                    return "Account temporarily locked. Try again later.";
                case ACCOUNT_DISABLED:
                    return "Account is not active. Contact support.";
                case INVALID_INPUT:
                    return "Invalid login request.";
                default:
                    return "Invalid username or password.";
            }
        }

        @Override
        public String toString() {
            return "Result[" + outcome + ", reason=" + reason + ", user=" + username
                + ", durationMs=" + durationMillis + ", failedAttempts=" + failedAttempts + "]";
        }
    }

    /** One audit record. Field values are already sanitized: ASCII, no CR/LF, no '|'. */
    public static final class Event {
        public final Instant timestamp;
        public final EventType type;
        public final String username;
        public final Outcome outcome;
        public final Reason reason;
        public final String remoteAddress;
        public final long durationMillis;
        public final int failedAttempts;
        public final String detail;

        Event(EventType type, String username, Outcome outcome, Reason reason,
              String remoteAddress, long durationMillis, int failedAttempts, String detail) {
            this.timestamp = Instant.now();
            this.type = type;
            this.username = sanitizeField(username);
            this.outcome = outcome;
            this.reason = reason;
            this.remoteAddress = sanitizeField(remoteAddress);
            this.durationMillis = durationMillis;
            this.failedAttempts = failedAttempts;
            this.detail = sanitizeField(detail);
        }

        /** Single-line pipe separated record; {@link #parseLine(String)} reads it back. */
        public String format() {
            StringBuilder sb = new StringBuilder(160);
            sb.append(DateTimeFormatter.ISO_INSTANT.format(timestamp.truncatedTo(java.time.temporal.ChronoUnit.MILLIS)));
            sb.append("|event=").append(type);
            sb.append("|user=").append(username);
            sb.append("|outcome=").append(outcome == null ? "-" : outcome.name());
            sb.append("|reason=").append(reason == null ? "-" : reason.name());
            sb.append("|addr=").append(remoteAddress);
            sb.append("|durationMs=").append(durationMillis);
            sb.append("|failures=").append(failedAttempts);
            sb.append("|detail=").append(detail);
            return sb.toString();
        }

        @Override
        public String toString() {
            return format();
        }

        /** Inverse of {@link #format()} for log shipping and tests. Returns null if unparseable. */
        public static Event parseLine(String line) {
            if (line == null) {
                return null;
            }
            String[] parts = line.split("\\|");
            if (parts.length < 9) {
                return null;
            }
            try {
                EventType type = EventType.valueOf(valueOf(parts[1], "event="));
                Outcome outcome = "-".equals(valueOf(parts[3], "outcome=")) ? null
                    : Outcome.valueOf(valueOf(parts[3], "outcome="));
                Reason reason = "-".equals(valueOf(parts[4], "reason=")) ? null
                    : Reason.valueOf(valueOf(parts[4], "reason="));
                return new Event(type, valueOf(parts[2], "user="), outcome, reason,
                    valueOf(parts[5], "addr="), Long.parseLong(valueOf(parts[6], "durationMs=")),
                    Integer.parseInt(valueOf(parts[7], "failures=")), valueOf(parts[8], "detail="));
            } catch (RuntimeException malformed) {
                return null;
            }
        }

        private static String valueOf(String field, String prefix) {
            return field.startsWith(prefix) ? field.substring(prefix.length()) : field;
        }
    }

    /** Sink for authentication activity. Implementations must be thread safe. */
    public interface EventLogger {
        void log(Event event);

        /** Discards everything; useful when a caller has its own audit pipeline. */
        static EventLogger nullLogger() {
            return event -> {
            };
        }
    }

    /** Console logger. */
    public static final class ConsoleEventLogger implements EventLogger {
        private final PrintStream out;

        public ConsoleEventLogger() {
            this(System.out);
        }

        public ConsoleEventLogger(PrintStream out) {
            this.out = out;
        }

        @Override
        public void log(Event event) {
            out.println(event.format());
        }
    }

    /**
     * Appends one flushed line per event to a file, so a crash cannot lose the last attempt.
     * Writing and flushing happen under the instance lock, which keeps concurrent logins from
     * interleaving partial lines.
     */
    public static final class FileEventLogger implements EventLogger, AutoCloseable {
        private final Object lock = new Object();
        private final Path file;
        private final PrintStream echo;
        private BufferedWriter writer;

        public FileEventLogger(Path file) {
            this(file, null);
        }

        public FileEventLogger(Path file, PrintStream echo) {
            if (file == null) {
                throw new IllegalArgumentException("file is required");
            }
            this.file = file;
            this.echo = echo;
            try {
                if (file.getParent() != null) {
                    Files.createDirectories(file.getParent());
                }
                this.writer = Files.newBufferedWriter(file, StandardCharsets.US_ASCII,
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND);
            } catch (IOException cannotOpen) {
                throw new UncheckedIOException("cannot open audit log " + file, cannotOpen);
            }
        }

        @Override
        public void log(Event event) {
            String line = event.format();
            synchronized (lock) {
                try {
                    writer.write(line);
                    writer.newLine();
                    writer.flush();
                } catch (IOException writeFailed) {
                    throw new UncheckedIOException("cannot write audit log " + file, writeFailed);
                }
            }
            if (echo != null) {
                echo.println(line);
            }
        }

        public Path file() {
            return file;
        }

        /** Lines currently on disk; package-visible so the test suite can inspect the log. */
        java.util.List<String> readAll() {
            try {
                return Files.readAllLines(file, StandardCharsets.US_ASCII);
            } catch (IOException unreadable) {
                throw new UncheckedIOException("cannot read audit log " + file, unreadable);
            }
        }

        @Override
        public void close() {
            synchronized (lock) {
                try {
                    writer.close();
                } catch (IOException ignored) {
                    // Already on its way out; nothing useful to do with a failed close.
                }
            }
        }
    }

    // --------------------------------------------------------------------------------------------
    // Public operations
    // --------------------------------------------------------------------------------------------

    /**
     * Creates an account.
     *
     * @return true when the account was created, false when the username is already taken
     * @throws IllegalArgumentException if the username or the password form is not acceptable
     */
    public boolean register(String rawUsername, char[] password) {
        String username = normalizeUsername(rawUsername);
        if (username == null) {
            throw new IllegalArgumentException("username must be " + USERNAME_MIN + "-"
                + USERNAME_MAX + " characters of [A-Za-z0-9._-] after trimming");
        }
        if (!isHashablePassword(password)) {
            throw new IllegalArgumentException("password is empty, too long, ends with NUL or "
                + "contains an unpaired surrogate");
        }
        PasswordHash hash = PasswordHash.generate(password, config.iterations, random);
        boolean created = accounts.register(username, hash);
        log.log(new Event(EventType.ACCOUNT_REGISTERED, username, null, Reason.OK, null, 0, 0,
            created ? "created" : "duplicate"));
        return created;
    }

    public Result authenticate(String username, char[] password) {
        return authenticate(username, password, null);
    }

    /**
     * Verifies one credential pair and records the attempt.
     *
     * @param remoteAddress optional client address, recorded verbatim (sanitized) in the log
     */
    public Result authenticate(String rawUsername, char[] password, String remoteAddress) {
        Instant startedAt = config.clock.instant();
        long nanos = System.nanoTime();

        String username = normalizeUsername(rawUsername);
        boolean passwordUsable = isHashablePassword(password);
        Account account = username == null ? null : accounts.find(username);
        PasswordHash stored = account == null ? null : account.passwordHash();

        // Exactly one key derivation per attempt, on every path, including the paths that refuse
        // the attempt before the credential check.
        boolean derivable = username != null && passwordUsable && stored != null;
        byte[] presented = derivable ? stored.deriveKey(password)
            : equalWorkHash.deriveKey(EQUAL_WORK_SECRET);

        if (username == null) {
            return refuse(EventType.LOGIN_REFUSED, Outcome.INVALID_INPUT, Reason.MALFORMED_USERNAME,
                rawUsername, remoteAddress, startedAt, nanos, 0, "username rejected");
        }
        if (!passwordUsable) {
            return refuse(EventType.LOGIN_REFUSED, Outcome.INVALID_INPUT, Reason.MALFORMED_PASSWORD,
                username, remoteAddress, startedAt, nanos, 0, "password rejected");
        }
        if (account == null) {
            return refuse(EventType.LOGIN_FAILURE, Outcome.INVALID_CREDENTIALS, Reason.UNKNOWN_USER,
                username, remoteAddress, startedAt, nanos, 0, "equal work paid");
        }
        if (stored == null) {
            return refuse(EventType.LOGIN_FAILURE, Outcome.INVALID_CREDENTIALS, Reason.CORRUPT_RECORD,
                username, remoteAddress, startedAt, nanos, 0, "stored hash unreadable");
        }
        if (!account.enabled()) {
            return refuse(EventType.LOGIN_FAILURE, Outcome.ACCOUNT_DISABLED, Reason.ACCOUNT_DISABLED,
                username, remoteAddress, startedAt, nanos, 0, "account disabled");
        }

        Account.LockState lockState = account.lockStateAt(startedAt);
        if (lockState == Account.LockState.ACTIVE) {
            return refuse(EventType.LOGIN_FAILURE, Outcome.ACCOUNT_LOCKED, Reason.ACCOUNT_LOCKED,
                username, remoteAddress, startedAt, nanos, account.failedAttempts(),
                "locked for another " + account.lockRemainingSeconds(startedAt) + "s");
        }
        if (lockState == Account.LockState.EXPIRED) {
            log.log(new Event(EventType.ACCOUNT_UNLOCKED, username, null, Reason.OK, remoteAddress,
                elapsedMillis(nanos), 0, "lock expired"));
        }

        if (!stored.matches(presented)) {
            FailureState state = account.recordFailure(startedAt, config);
            if (state.tripped()) {
                log.log(new Event(EventType.ACCOUNT_LOCKED_OUT, username, null,
                    Reason.ACCOUNT_LOCKED, remoteAddress, elapsedMillis(nanos), state.failures(),
                    config.maxFailures + " consecutive failures"));
            }
            // The attempt that trips the lock is still reported as a bad credential, so a caller
            // cannot tell from this response alone whether the threshold was reached.
            return refuse(EventType.LOGIN_FAILURE, Outcome.INVALID_CREDENTIALS, Reason.BAD_PASSWORD,
                username, remoteAddress, startedAt, nanos, state.failures(),
                state.tripped() ? "lock tripped" : "wrong password");
        }

        int cleared = account.recordSuccess(startedAt);
        Result result = new Result(Outcome.SUCCESS, Reason.OK, username, startedAt,
            elapsedMillis(nanos), 0);
        log.log(new Event(EventType.LOGIN_SUCCESS, username, Outcome.SUCCESS, Reason.OK,
            remoteAddress, result.durationMillis(), 0,
            cleared > 0 ? "prior failures cleared" : "ok"));
        return result;
    }

    /** Enables or disables an account; disabled accounts are refused before any credential use. */
    public boolean setEnabled(String username, boolean enabled) {
        String name = normalizeUsername(username);
        Account account = name == null ? null : accounts.find(name);
        if (account == null) {
            return false;
        }
        account.setEnabled(enabled);
        return true;
    }

    /** Drops the lock on an account, e.g. after an operator verified the user. */
    public boolean unlock(String username) {
        String name = normalizeUsername(username);
        Account account = name == null ? null : accounts.find(name);
        if (account == null) {
            return false;
        }
        account.forceUnlock();
        log.log(new Event(EventType.ACCOUNT_UNLOCKED, name, null, Reason.OK, null, 0, 0,
            "unlocked by operator"));
        return true;
    }

    public boolean accountExists(String username) {
        String name = normalizeUsername(username);
        return name != null && accounts.find(name) != null;
    }

    private Result refuse(EventType type, Outcome outcome, Reason reason, String username,
                          String remoteAddress, Instant startedAt, long nanos, int failures,
                          String detail) {
        long duration = elapsedMillis(nanos);
        Result result = new Result(outcome, reason,
            outcome == Outcome.INVALID_INPUT ? sanitizeField(username) : username, startedAt,
            duration, failures);
        log.log(new Event(type, result.username(), outcome, reason, remoteAddress, duration,
            failures, detail));
        return result;
    }

    private long elapsedMillis(long startNanos) {
        return Math.max(0L, (System.nanoTime() - startNanos) / 1_000_000L);
    }

    /** The digest every refused attempt is charged for. Package visible so tests can time it. */
    PasswordHash equalWorkHash() {
        return equalWorkHash;
    }

    // --------------------------------------------------------------------------------------------
    // Input validation
    // --------------------------------------------------------------------------------------------

    /**
     * NFKC-normalizes, trims, lowercases and validates a username, so that " Alice " and "alice"
     * name the same account.
     *
     * @return the storage key, or null when the input cannot be a username
     */
    static String normalizeUsername(String raw) {
        if (raw == null) {
            return null;
        }
        String value = Normalizer.normalize(raw, Normalizer.Form.NFKC);
        int start = 0;
        int end = value.length();
        while (start < end && value.charAt(start) <= ' ') {
            start++;
        }
        while (end > start && value.charAt(end - 1) <= ' ') {
            end--;
        }
        value = value.substring(start, end).toLowerCase(Locale.ROOT);
        if (value.length() < USERNAME_MIN || value.length() > USERNAME_MAX) {
            return null;
        }
        return USERNAME_PATTERN.matcher(value).matches() ? value : null;
    }

    /**
     * {@code PBEKeySpec} converts a {@code char[]} with a lossy UTF-8 encoder: trailing NUL
     * characters are dropped and every unpaired surrogate becomes '?'. Distinct passwords
     * therefore collide on the same digest, which would let one holder of "pw" log in as the
     * holder of "pw\0". Those forms are rejected rather than silently trimmed, because trimming
     * changes the secret. Interior NULs and well-formed surrogate pairs are unaffected and stay
     * legal.
     */
    static boolean isHashablePassword(char[] password) {
        if (password == null || password.length == 0 || password.length > PASSWORD_MAX) {
            return false;
        }
        if (password[password.length - 1] == 0) {
            return false;
        }
        for (int i = 0; i < password.length; i++) {
            char c = password[i];
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= password.length || !Character.isLowSurrogate(password[i + 1])) {
                    return false;
                }
                i++;
            } else if (Character.isLowSurrogate(c)) {
                return false;
            }
        }
        return true;
    }

    /** ASCII, single line, no '|' : a username can never forge or split a log record. */
    static String sanitizeField(String raw) {
        if (raw == null || raw.isEmpty()) {
            return "-";
        }
        StringBuilder sb = new StringBuilder(Math.min(raw.length(), 72));
        for (int i = 0; i < raw.length() && sb.length() < 64; i++) {
            char c = raw.charAt(i);
            boolean printable = c >= 0x20 && c <= 0x7E && c != '|';
            sb.append(printable ? c : '.');
        }
        if (raw.length() > 64) {
            sb.append('~');
        }
        return sb.length() == 0 ? "-" : sb.toString();
    }

    // --------------------------------------------------------------------------------------------
    // Password hashing
    // --------------------------------------------------------------------------------------------

    /**
     * Immutable PBKDF2-HMAC-SHA256 record: {@code pbkdf2-sha256$iterations$base64(salt)$base64(key)}.
     * Byte arrays are copied in and out; {@link #encode()} never exposes the derived key.
     */
    static final class PasswordHash {
        private final int iterations;
        private final byte[] salt;
        private final byte[] key;

        PasswordHash(int iterations, byte[] salt, byte[] key) {
            if (iterations < 1_000) {
                throw new IllegalArgumentException("iterations must be >= 1000, got " + iterations);
            }
            if (salt == null || salt.length < 8 || salt.length > 64) {
                throw new IllegalArgumentException("salt must be 8-64 bytes");
            }
            if (key == null || key.length < 16 || key.length > 64) {
                throw new IllegalArgumentException("derived key must be 16-64 bytes");
            }
            this.iterations = iterations;
            this.salt = salt.clone();
            this.key = key.clone();
        }

        static PasswordHash generate(char[] password, int iterations, SecureRandom random) {
            byte[] salt = new byte[SALT_BYTES];
            random.nextBytes(salt);
            byte[] key = derive(password, salt, iterations);
            return new PasswordHash(iterations, salt, key);
        }

        /**
         * Strict parser. The Base64 decoder that ships with the JDK accepts stray characters in
         * MIME mode, so every field is re-encoded and compared: a stored value that only decodes
         * because the decoder ignored junk is rejected here instead of becoming a weaker key.
         */
        static PasswordHash parse(String encoded) {
            if (encoded == null) {
                throw new IllegalArgumentException("encoded hash is null");
            }
            String[] parts = encoded.split("\\$");
            if (parts.length != 4 || !HASH_PREFIX.equals(parts[0])) {
                throw new IllegalArgumentException("expected " + HASH_PREFIX + "$iterations$salt$key");
            }
            int rounds;
            try {
                rounds = Integer.parseInt(parts[1]);
            } catch (NumberFormatException notNumeric) {
                throw new IllegalArgumentException("iterations is not a number", notNumeric);
            }
            byte[] salt = strictBase64(parts[2]);
            byte[] key = strictBase64(parts[3]);
            return new PasswordHash(rounds, salt, key);
        }

        private static byte[] strictBase64(String field) {
            if (field.isEmpty() || field.length() % 4 != 0) {
                throw new IllegalArgumentException("base64 field has invalid length");
            }
            byte[] decoded;
            try {
                decoded = Base64.getDecoder().decode(field);
            } catch (IllegalArgumentException notBase64) {
                throw new IllegalArgumentException("base64 field is not strictly encoded", notBase64);
            }
            if (!Base64.getEncoder().encodeToString(decoded).equals(field)) {
                throw new IllegalArgumentException("base64 field carries non-canonical bits");
            }
            return decoded;
        }

        String encode() {
            return HASH_PREFIX + "$" + iterations + "$"
                + Base64.getEncoder().encodeToString(salt) + "$"
                + Base64.getEncoder().encodeToString(key);
        }

        int iterations() {
            return iterations;
        }

        byte[] salt() {
            return salt.clone();
        }

        /** Runs the KDF; the caller owns the returned array. */
        byte[] deriveKey(char[] password) {
            return derive(password, salt, iterations);
        }

        boolean matches(byte[] candidateKey) {
            return candidateKey != null && MessageDigest.isEqual(key, candidateKey);
        }

        private static byte[] derive(char[] password, byte[] salt, int iterations) {
            if (!isHashablePassword(password)) {
                throw new IllegalArgumentException("password form cannot be hashed safely");
            }
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BYTES * 8);
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF);
                return factory.generateSecret(spec).getEncoded();
            } catch (GeneralSecurityException unsupported) {
                throw new IllegalStateException(KDF + " is unavailable on this JVM", unsupported);
            } finally {
                spec.clearPassword();
            }
        }

        @Override
        public String toString() {
            return "PasswordHash[redacted]";
        }
    }

    // --------------------------------------------------------------------------------------------
    // Stored accounts
    // --------------------------------------------------------------------------------------------

    /** Persistence seam. Implementations must be thread safe; swap in a JDBC store here. */
    interface AccountStore {
        Account find(String normalizedUsername);

        /** @return true when created, false when the username was already present */
        boolean register(String normalizedUsername, PasswordHash hash);

        int failuresOf(String normalizedUsername);
    }

    /** Process-local store; state is lost on restart. */
    static final class InMemoryAccountStore implements AccountStore {
        private final Map<String, Account> byName = new ConcurrentHashMap<>();

        @Override
        public Account find(String normalizedUsername) {
            return normalizedUsername == null ? null : byName.get(normalizedUsername);
        }

        @Override
        public boolean register(String normalizedUsername, PasswordHash hash) {
            return byName.putIfAbsent(normalizedUsername, new Account(normalizedUsername, hash)) == null;
        }

        @Override
        public int failuresOf(String normalizedUsername) {
            Account account = byName.get(normalizedUsername);
            return account == null ? 0 : account.failedAttempts();
        }

        int size() {
            return byName.size();
        }
    }

    /** Mutable account state; every accessor that touches it holds the intrinsic lock. */
    static final class Account {
        enum LockState { NONE, ACTIVE, EXPIRED }

        private final String username;
        private final PasswordHash passwordHash;
        private final Instant createdAt;
        private boolean enabled = true;
        private int failures;
        private Instant lastFailure;
        private Instant lockedUntil;
        private Instant lastLoginAt;

        Account(String username, PasswordHash passwordHash) {
            this.username = username;
            this.passwordHash = passwordHash;
            this.createdAt = Instant.now();
        }

        /** Test/repair hook for a record whose stored digest cannot be parsed. */
        static Account withCorruptHash(String username) {
            return new Account(username, null);
        }

        String username() {
            return username;
        }

        PasswordHash passwordHash() {
            return passwordHash;
        }

        synchronized boolean enabled() {
            return enabled;
        }

        synchronized void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        synchronized int failedAttempts() {
            return failures;
        }

        synchronized Instant lastLoginAt() {
            return lastLoginAt;
        }

        synchronized Instant createdAt() {
            return createdAt;
        }

        synchronized LockState lockStateAt(Instant now) {
            if (lockedUntil == null) {
                return LockState.NONE;
            }
            if (now.isBefore(lockedUntil)) {
                return LockState.ACTIVE;
            }
            lockedUntil = null;
            failures = 0;
            lastFailure = null;
            return LockState.EXPIRED;
        }

        synchronized long lockRemainingSeconds(Instant now) {
            if (lockedUntil == null || !now.isBefore(lockedUntil)) {
                return 0L;
            }
            return Duration.between(now, lockedUntil).getSeconds() + 1;
        }

        /** @return failure count after this failure and whether it tripped the lock */
        synchronized FailureState recordFailure(Instant now, Config config) {
            if (lastFailure != null
                && Duration.between(lastFailure, now).compareTo(config.failureWindow) > 0) {
                failures = 0;
            }
            failures++;
            lastFailure = now;
            boolean tripped = failures >= config.maxFailures;
            if (tripped) {
                lockedUntil = now.plus(config.lockDuration);
            }
            return new FailureState(failures, tripped);
        }

        /**
         * Full state reset on a verified credential. A locked account is refused before the
         * credential check, so clearing {@code lockedUntil} here is defensive: it keeps the account
         * coherent if the guard order above ever changes.
         *
         * @return number of failures that a successful login cleared
         */
        synchronized int recordSuccess(Instant now) {
            int cleared = failures;
            failures = 0;
            lastFailure = null;
            lockedUntil = null;
            lastLoginAt = now;
            return cleared;
        }

        synchronized void forceUnlock() {
            failures = 0;
            lastFailure = null;
            lockedUntil = null;
        }

        @Override
        public String toString() {
            return "Account[" + username + ", enabled=" + enabled + ", failures=" + failures + "]";
        }
    }

    /** Failure counter snapshot. No array components, so record sharing is not a concern. */
    record FailureState(int failures, boolean tripped) {
    }

    // --------------------------------------------------------------------------------------------
    // Demo / interactive entry point
    // --------------------------------------------------------------------------------------------

    /**
     * Runs the demo ({@code java UserAuthentication}), an interactive prompt
     * ({@code java UserAuthentication --interactive}) or a scripted scenario file
     * ({@code java UserAuthentication --script user:pass ...}).
     */
    public static void main(String[] args) throws Exception {
        PrintStream out = new PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.out),
            true, StandardCharsets.UTF_8);
        Path logFile = pathArgument(args, "--log", "auth-demo.log");
        int iterations = Integer.parseInt(argument(args, "--iterations", "60000"));

        try (FileEventLogger fileLogger = new FileEventLogger(logFile, out)) {
            Config config = new Config(iterations, 3, Duration.ofMinutes(15),
                Duration.ofMinutes(30), Clock.systemUTC());
            UserAuthentication auth = withInMemoryStore(fileLogger, config);

            auth.register("alice", "winter-Frost-42".toCharArray());
            auth.register("bob", "correct horse battery staple".toCharArray());
            auth.register("dave", "hunter2-hunter2".toCharArray());
            auth.register("erin", "sup3r-Secret!".toCharArray());
            auth.setEnabled("erin", false);
            out.println();
            out.println("Demo accounts: alice / winter-Frost-42, bob / correct horse battery staple");
            out.println("Accounts dave (lockout demo) and erin (disabled) also exist.");
            out.println("Authentication activity is appended to " + logFile.toAbsolutePath()
                + " and echoed above.");
            out.println();

            if (hasFlag(args, "--interactive")) {
                interactive(auth, out);
                return;
            }
            if (hasFlag(args, "--script")) {
                scripted(auth, args, out);
                return;
            }

            show(out, "alice + correct password", auth.authenticate("alice", "winter-Frost-42".toCharArray()));
            show(out, "alice + wrong password", auth.authenticate("alice", "winter-Frost-41".toCharArray()));
            show(out, "unknown user carol", auth.authenticate("carol", "whatever-123".toCharArray()));
            show(out, "'  ALICE  ' (same account)", auth.authenticate("  ALICE  ", "winter-Frost-42".toCharArray()));
            show(out, "empty password", auth.authenticate("alice", new char[0]));
            show(out, "log-injection username",
                auth.authenticate("mallory\r\n|event=LOGIN_SUCCESS|user=admin", "whatever-123".toCharArray()));
            for (int i = 1; i <= 3; i++) {
                show(out, "dave bad password #" + i,
                    auth.authenticate("dave", ("nope-" + i + "-nope").toCharArray()));
            }
            show(out, "dave + real password while locked", auth.authenticate("dave", "hunter2-hunter2".toCharArray()));
            show(out, "erin (disabled)", auth.authenticate("erin", "sup3r-Secret!".toCharArray()));
            out.println();
            out.println("Failed attempts recorded for dave: " + auth.accounts.failuresOf("dave"));
            out.println("Operator unlock for dave: " + auth.unlock("dave"));
            show(out, "dave after operator unlock", auth.authenticate("dave", "hunter2-hunter2".toCharArray()));
            out.println();
            out.println("Audit log lines written: " + fileLogger.readAll().size());
        }
    }

    private static void interactive(UserAuthentication auth, PrintStream out) throws IOException {
        Console console = System.console();
        BufferedReader in = new BufferedReader(new java.io.InputStreamReader(System.in,
            StandardCharsets.UTF_8));
        out.println("Interactive demo. Type 'quit' as the username to exit.");
        while (true) {
            String username;
            char[] password;
            if (console != null) {
                username = console.readLine("username: ");
                password = username == null ? null : console.readPassword("password: ");
            } else {
                out.print("username: ");
                out.flush();
                username = in.readLine();
                out.print("password: ");
                out.flush();
                String line = in.readLine();
                password = line == null ? null : line.toCharArray();
            }
            if (username == null || "quit".equalsIgnoreCase(username.trim())) {
                return;
            }
            show(out, "login", auth.authenticate(username, password == null ? new char[0] : password, "stdin"));
        }
    }

    private static void scripted(UserAuthentication auth, String[] args, PrintStream out) {
        for (String pair : args) {
            // Usernames can never contain ':', so splitting at the last one lets the password do so.
            int at = pair.lastIndexOf(':');
            if (at < 0 || pair.startsWith("--")) {
                continue;
            }
            show(out, pair.substring(0, at),
                auth.authenticate(pair.substring(0, at), pair.substring(at + 1).toCharArray(), "cli"));
        }
    }

    private static void show(PrintStream out, String label, Result result) {
        out.println("-- " + label);
        out.println("   outcome=" + result.outcome() + "  auditReason=" + result.auditReason()
            + "  " + result.durationMillis() + "ms");
        out.println("   message=\"" + result.userMessage() + "\"");
    }

    private static boolean hasFlag(String[] args, String flag) {
        for (String arg : args) {
            if (flag.equals(arg)) {
                return true;
            }
        }
        return false;
    }

    private static String argument(String[] args, String name, String fallback) {
        for (int i = 0; i + 1 < args.length; i++) {
            if (name.equals(args[i])) {
                return args[i + 1];
            }
        }
        return fallback;
    }

    private static Path pathArgument(String[] args, String name, String fallback) {
        return Path.of(argument(args, name, fallback));
    }
}
