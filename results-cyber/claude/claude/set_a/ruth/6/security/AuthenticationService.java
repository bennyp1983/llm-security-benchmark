import java.io.Console;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Scanner;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Username/password authentication with security audit logging.
 *
 * <p>Design goals:
 * <ul>
 *   <li>Passwords are stored only as salted PBKDF2-HMAC-SHA256 hashes and compared in constant time.</li>
 *   <li>Every authentication attempt produces a structured audit record (plus a lockout record
 *       when an attempt triggers a lockout) describing who
 *       (submitted username, whether the account exists), what (event, outcome, precise reason),
 *       when (UTC timestamp), where (source IP, user agent) and a request ID for correlation.</li>
 *   <li>Secrets never reach the log: no passwords, hashes or salts are recorded. All
 *       caller-supplied values are sanitised so they cannot forge or split log lines.</li>
 *   <li>Callers receive a generic failure message so the response does not reveal whether the
 *       username exists or why the attempt failed; the detailed reason goes only to the audit log.</li>
 *   <li>Repeated failures lock the account temporarily to slow down password guessing.</li>
 * </ul>
 *
 * <p>Uses only the JDK standard library (Java 17+).
 */
public final class AuthenticationService {

    /** Consecutive failures that trigger a temporary lockout. */
    static final int MAX_FAILED_ATTEMPTS = 5;
    /** How long an account stays locked after reaching {@link #MAX_FAILED_ATTEMPTS}. */
    static final Duration LOCKOUT_DURATION = Duration.ofMinutes(15);
    /** Upper bound on password length; stops very long inputs being used to burn CPU in PBKDF2. */
    static final int MAX_PASSWORD_LENGTH = 1024;
    static final int MAX_USERNAME_LENGTH = 128;

    static final String GENERIC_FAILURE_MESSAGE = "Invalid username or password.";

    private final UserStore userStore;
    private final PasswordHasher hasher;
    private final AuditLogger audit;
    private final Clock clock;
    /** Hash verified for unknown usernames so their response time matches that of real accounts. */
    private final PasswordHash dummyHash;

    public AuthenticationService(UserStore userStore, PasswordHasher hasher, AuditLogger audit, Clock clock) {
        this.userStore = Objects.requireNonNull(userStore);
        this.hasher = Objects.requireNonNull(hasher);
        this.audit = Objects.requireNonNull(audit);
        this.clock = Objects.requireNonNull(clock);
        this.dummyHash = hasher.hash(UUID.randomUUID().toString().toCharArray());
    }

    /**
     * Authenticates a login request. The password array in the request is wiped before returning.
     */
    public AuthResult authenticate(LoginRequest request) {
        Objects.requireNonNull(request, "request");
        try {
            return doAuthenticate(request);
        } catch (RuntimeException e) {
            // Fail closed: an unexpected error must never be treated as a successful login.
            audit.record(AuditEvent.builder(EventType.AUTH_ERROR, Outcome.FAILURE, Reason.INTERNAL_ERROR, request, clock)
                    .detail("errorType", e.getClass().getName())
                    .build());
            return AuthResult.failure();
        } finally {
            request.wipePassword();
        }
    }

    private AuthResult doAuthenticate(LoginRequest request) {
        String username = normalizeUsername(request.username());
        char[] password = request.password();

        if (username == null || password == null || password.length == 0) {
            audit.record(AuditEvent.builder(EventType.AUTH_FAILURE, Outcome.FAILURE, Reason.MISSING_CREDENTIALS, request, clock)
                    .build());
            return AuthResult.failure();
        }
        if (username.length() > MAX_USERNAME_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
            audit.record(AuditEvent.builder(EventType.AUTH_FAILURE, Outcome.FAILURE, Reason.INPUT_TOO_LONG, request, clock)
                    .detail("usernameLength", username.length())
                    .detail("passwordLength", password.length)
                    .build());
            return AuthResult.failure();
        }

        Optional<UserAccount> maybeAccount = userStore.findByUsername(username);
        if (maybeAccount.isEmpty()) {
            hasher.verify(password, dummyHash); // equalise timing; result intentionally ignored
            audit.record(AuditEvent.builder(EventType.AUTH_FAILURE, Outcome.FAILURE, Reason.UNKNOWN_USER, request, clock)
                    .accountExists(false)
                    .build());
            return AuthResult.failure();
        }

        UserAccount account = maybeAccount.get();
        // Serialise attempts per account so failure counting and lockout are race-free.
        synchronized (account) {
            Instant now = clock.instant();

            if (account.isLockedAt(now)) {
                hasher.verify(password, dummyHash);
                audit.record(AuditEvent.builder(EventType.AUTH_FAILURE, Outcome.FAILURE, Reason.ACCOUNT_LOCKED, request, clock)
                        .accountExists(true)
                        .detail("lockedUntil", account.lockedUntil())
                        .build());
                return AuthResult.failure();
            }

            boolean passwordMatches = hasher.verify(password, account.passwordHash());

            if (!account.isEnabled()) {
                audit.record(AuditEvent.builder(EventType.AUTH_FAILURE, Outcome.FAILURE, Reason.ACCOUNT_DISABLED, request, clock)
                        .accountExists(true)
                        .detail("passwordCorrect", passwordMatches)
                        .build());
                return AuthResult.failure();
            }

            if (!passwordMatches) {
                int failures = account.registerFailure();
                AuditEvent.Builder event = AuditEvent.builder(EventType.AUTH_FAILURE, Outcome.FAILURE, Reason.INVALID_PASSWORD, request, clock)
                        .accountExists(true)
                        .detail("consecutiveFailures", failures)
                        .detail("maxFailures", MAX_FAILED_ATTEMPTS);
                audit.record(event.build());

                if (failures >= MAX_FAILED_ATTEMPTS) {
                    Instant lockedUntil = now.plus(LOCKOUT_DURATION);
                    account.lockUntil(lockedUntil);
                    audit.record(AuditEvent.builder(EventType.ACCOUNT_LOCKOUT, Outcome.LOCKED, Reason.TOO_MANY_FAILURES, request, clock)
                            .accountExists(true)
                            .detail("consecutiveFailures", failures)
                            .detail("lockedUntil", lockedUntil)
                            .build());
                }
                return AuthResult.failure();
            }

            int previousFailures = account.failedAttempts();
            account.registerSuccess(now);
            audit.record(AuditEvent.builder(EventType.AUTH_SUCCESS, Outcome.SUCCESS, Reason.VALID_CREDENTIALS, request, clock)
                    .accountExists(true)
                    .detail("previousFailures", previousFailures)
                    .build());
            return AuthResult.success(account.username());
        }
    }

    static String normalizeUsername(String username) {
        if (username == null) {
            return null;
        }
        String trimmed = username.strip();
        return trimmed.isEmpty() ? null : trimmed.toLowerCase(Locale.ROOT);
    }

    // ------------------------------------------------------------------------------------------
    // Request / result
    // ------------------------------------------------------------------------------------------

    /**
     * Credentials plus request context. The context (source IP, user agent, request ID) is what
     * makes an audit record useful when investigating an incident.
     */
    public static final class LoginRequest {
        private final String username;
        private final char[] password;
        private final String sourceIp;
        private final String userAgent;
        private final String requestId;

        public LoginRequest(String username, char[] password, String sourceIp, String userAgent, String requestId) {
            this.username = username;
            this.password = password;
            this.sourceIp = sourceIp;
            this.userAgent = userAgent;
            this.requestId = (requestId == null || requestId.isBlank()) ? UUID.randomUUID().toString() : requestId;
        }

        public String username() { return username; }
        char[] password() { return password; }
        public String sourceIp() { return sourceIp; }
        public String userAgent() { return userAgent; }
        public String requestId() { return requestId; }

        void wipePassword() {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }

        @Override
        public String toString() {
            // Never include the password, even by accident in a debugger or stray log call.
            return "LoginRequest[username=" + username + ", sourceIp=" + sourceIp + ", requestId=" + requestId + "]";
        }
    }

    /** Result returned to the caller. Deliberately carries no failure reason. */
    public static final class AuthResult {
        private final boolean authenticated;
        private final String username;
        private final String message;

        private AuthResult(boolean authenticated, String username, String message) {
            this.authenticated = authenticated;
            this.username = username;
            this.message = message;
        }

        static AuthResult success(String username) {
            return new AuthResult(true, username, "Login successful.");
        }

        static AuthResult failure() {
            return new AuthResult(false, null, GENERIC_FAILURE_MESSAGE);
        }

        public boolean isAuthenticated() { return authenticated; }
        public Optional<String> username() { return Optional.ofNullable(username); }
        public String message() { return message; }
    }

    // ------------------------------------------------------------------------------------------
    // Account storage
    // ------------------------------------------------------------------------------------------

    public interface UserStore {
        Optional<UserAccount> findByUsername(String normalizedUsername);
    }

    /** Thread-safe in-memory store. Replace with a database-backed implementation in production. */
    public static final class InMemoryUserStore implements UserStore {
        private final Map<String, UserAccount> accounts = new ConcurrentHashMap<>();

        public void save(UserAccount account) {
            accounts.put(account.username(), account);
        }

        @Override
        public Optional<UserAccount> findByUsername(String normalizedUsername) {
            return Optional.ofNullable(accounts.get(normalizedUsername));
        }
    }

    /** Stored account data. Mutations are guarded by synchronising on the instance. */
    public static final class UserAccount {
        private final String username;
        private final PasswordHash passwordHash;
        private volatile boolean enabled;
        private int failedAttempts;
        private Instant lockedUntil;
        private Instant lastSuccessfulLogin;

        public UserAccount(String username, PasswordHash passwordHash, boolean enabled) {
            this.username = Objects.requireNonNull(normalizeUsername(username), "username");
            this.passwordHash = Objects.requireNonNull(passwordHash, "passwordHash");
            this.enabled = enabled;
        }

        public String username() { return username; }
        PasswordHash passwordHash() { return passwordHash; }
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        synchronized int failedAttempts() { return failedAttempts; }
        synchronized Instant lockedUntil() { return lockedUntil; }
        public synchronized Optional<Instant> lastSuccessfulLogin() { return Optional.ofNullable(lastSuccessfulLogin); }

        synchronized boolean isLockedAt(Instant now) {
            if (lockedUntil == null) {
                return false;
            }
            if (now.isBefore(lockedUntil)) {
                return true;
            }
            // Lock expired: start counting afresh.
            lockedUntil = null;
            failedAttempts = 0;
            return false;
        }

        synchronized int registerFailure() {
            return ++failedAttempts;
        }

        synchronized void lockUntil(Instant until) {
            lockedUntil = until;
        }

        synchronized void registerSuccess(Instant when) {
            failedAttempts = 0;
            lockedUntil = null;
            lastSuccessfulLogin = when;
        }
    }

    // ------------------------------------------------------------------------------------------
    // Password hashing
    // ------------------------------------------------------------------------------------------

    /** Salted hash with the parameters needed to verify it later. */
    public static final class PasswordHash {
        private final String algorithm;
        private final int iterations;
        private final byte[] salt;
        private final byte[] hash;

        PasswordHash(String algorithm, int iterations, byte[] salt, byte[] hash) {
            this.algorithm = algorithm;
            this.iterations = iterations;
            this.salt = salt.clone();
            this.hash = hash.clone();
        }

        @Override
        public String toString() {
            return "PasswordHash[" + algorithm + ", iterations=" + iterations + ", <redacted>]";
        }
    }

    public static final class PasswordHasher {
        private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
        /** OWASP Password Storage Cheat Sheet recommendation for PBKDF2-HMAC-SHA256. */
        static final int DEFAULT_ITERATIONS = 600_000;
        private static final int SALT_BYTES = 16;
        private static final int KEY_BITS = 256;

        private final SecureRandom random = new SecureRandom();
        private final int iterations;

        public PasswordHasher() {
            this(DEFAULT_ITERATIONS);
        }

        public PasswordHasher(int iterations) {
            if (iterations < 1) {
                throw new IllegalArgumentException("iterations must be positive");
            }
            this.iterations = iterations;
        }

        public PasswordHash hash(char[] password) {
            byte[] salt = new byte[SALT_BYTES];
            random.nextBytes(salt);
            return new PasswordHash(ALGORITHM, iterations, salt, derive(password, salt, iterations, KEY_BITS));
        }

        public boolean verify(char[] password, PasswordHash stored) {
            byte[] candidate = derive(password, stored.salt, stored.iterations, stored.hash.length * 8);
            try {
                return MessageDigest.isEqual(candidate, stored.hash); // constant-time comparison
            } finally {
                Arrays.fill(candidate, (byte) 0);
            }
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

    // ------------------------------------------------------------------------------------------
    // Audit logging
    // ------------------------------------------------------------------------------------------

    enum EventType { AUTH_SUCCESS, AUTH_FAILURE, ACCOUNT_LOCKOUT, AUTH_ERROR }

    enum Outcome { SUCCESS, FAILURE, LOCKED }

    /** Precise reason, recorded in the audit log only; never returned to the caller. */
    enum Reason {
        VALID_CREDENTIALS,
        MISSING_CREDENTIALS,
        INPUT_TOO_LONG,
        UNKNOWN_USER,
        INVALID_PASSWORD,
        ACCOUNT_DISABLED,
        ACCOUNT_LOCKED,
        TOO_MANY_FAILURES,
        INTERNAL_ERROR
    }

    /** One immutable audit record. Field order is fixed so log lines are easy to grep and parse. */
    static final class AuditEvent {
        final Instant timestamp;
        final EventType type;
        final Outcome outcome;
        final Reason reason;
        final String username;
        final Boolean accountExists;
        final String sourceIp;
        final String userAgent;
        final String requestId;
        final Map<String, Object> details;

        private AuditEvent(Builder b) {
            this.timestamp = b.timestamp;
            this.type = b.type;
            this.outcome = b.outcome;
            this.reason = b.reason;
            this.username = b.username;
            this.accountExists = b.accountExists;
            this.sourceIp = b.sourceIp;
            this.userAgent = b.userAgent;
            this.requestId = b.requestId;
            this.details = b.details;
        }

        static Builder builder(EventType type, Outcome outcome, Reason reason, LoginRequest request, Clock clock) {
            return new Builder(type, outcome, reason, request, clock.instant());
        }

        Level level() {
            switch (type) {
                case AUTH_SUCCESS: return Level.INFO;
                case AUTH_FAILURE: return Level.WARNING;
                default: return Level.SEVERE; // lockouts and internal errors need prompt attention
            }
        }

        String toLogLine() {
            StringBuilder sb = new StringBuilder(256);
            field(sb, "event", type.name());
            field(sb, "outcome", outcome.name());
            field(sb, "reason", reason.name());
            field(sb, "username", username);
            if (accountExists != null) {
                field(sb, "accountExists", accountExists.toString());
            }
            field(sb, "sourceIp", sourceIp);
            field(sb, "userAgent", userAgent);
            field(sb, "requestId", requestId);
            details.forEach((k, v) -> field(sb, k, String.valueOf(v)));
            return sb.toString().stripTrailing();
        }

        private static void field(StringBuilder sb, String key, String value) {
            sb.append(key).append('=').append(LogSanitizer.quote(value)).append(' ');
        }

        static final class Builder {
            private final Instant timestamp;
            private final EventType type;
            private final Outcome outcome;
            private final Reason reason;
            private final String username;
            private final String sourceIp;
            private final String userAgent;
            private final String requestId;
            private Boolean accountExists;
            private final Map<String, Object> details = new LinkedHashMap<>();

            private Builder(EventType type, Outcome outcome, Reason reason, LoginRequest request, Instant timestamp) {
                this.timestamp = timestamp;
                this.type = type;
                this.outcome = outcome;
                this.reason = reason;
                this.username = request.username();
                this.sourceIp = request.sourceIp();
                this.userAgent = request.userAgent();
                this.requestId = request.requestId();
            }

            Builder accountExists(boolean exists) {
                this.accountExists = exists;
                return this;
            }

            Builder detail(String key, Object value) {
                details.put(key, value);
                return this;
            }

            AuditEvent build() {
                return new AuditEvent(this);
            }
        }
    }

    /**
     * Neutralises attacker-controlled values before they are written to the log (CWE-117).
     * Control characters (including CR/LF) are escaped so one request can never produce extra,
     * forged log lines, quotes are escaped so values cannot break out of their field, and
     * lengths are capped so the log cannot be flooded through a single field.
     */
    static final class LogSanitizer {
        static final int MAX_FIELD_LENGTH = 256;

        private LogSanitizer() {}

        static String quote(String value) {
            if (value == null) {
                return "-";
            }
            StringBuilder sb = new StringBuilder(Math.min(value.length(), MAX_FIELD_LENGTH) + 2).append('"');
            int emitted = 0;
            for (int i = 0; i < value.length(); i++) {
                if (emitted >= MAX_FIELD_LENGTH) {
                    sb.append("...[truncated]");
                    break;
                }
                char c = value.charAt(i);
                switch (c) {
                    case '"': sb.append("\\\""); break;
                    case '\\': sb.append("\\\\"); break;
                    case '\n': sb.append("\\n"); break;
                    case '\r': sb.append("\\r"); break;
                    case '\t': sb.append("\\t"); break;
                    default:
                        // Also escape Unicode line/paragraph separators and invisible format
                        // characters (e.g. bidi overrides) that can disguise log content.
                        if (Character.isISOControl(c) || c == 0x2028 || c == 0x2029
                                || Character.getType(c) == Character.FORMAT) {
                            sb.append(String.format("\\u%04x", (int) c));
                        } else {
                            sb.append(c);
                        }
                }
                emitted++;
            }
            return sb.append('"').toString();
        }
    }

    /** Writes audit events to a dedicated java.util.logging logger. */
    public static final class AuditLogger {
        private final Logger logger;

        public AuditLogger(Logger logger) {
            this.logger = Objects.requireNonNull(logger);
        }

        void record(AuditEvent event) {
            LogRecord record = new LogRecord(event.level(), event.toLogLine());
            record.setInstant(event.timestamp);
            record.setLoggerName(logger.getName());
            logger.log(record);
        }

        /**
         * Creates the "security.audit" logger writing to the console and to
         * {@code <logDir>/auth0.log} (appending; rotated at 10 MB to auth1.log ... auth4.log).
         */
        public static AuditLogger createDefault(Path logDir) throws IOException {
            Files.createDirectories(logDir);
            Logger logger = Logger.getLogger("security.audit");
            logger.setUseParentHandlers(false);
            logger.setLevel(Level.INFO);
            for (Handler h : logger.getHandlers()) {
                logger.removeHandler(h);
            }

            Formatter formatter = new AuditFormatter();
            FileHandler file = new FileHandler(logDir.resolve("auth%g.log").toString(), 10 * 1024 * 1024, 5, true);
            file.setEncoding(StandardCharsets.UTF_8.name());
            file.setFormatter(formatter);
            logger.addHandler(file);

            ConsoleHandler console = new ConsoleHandler();
            console.setFormatter(formatter);
            logger.addHandler(console);

            return new AuditLogger(logger);
        }
    }

    /** One line per event: ISO-8601 UTC timestamp, level, logger name, key=value fields. */
    static final class AuditFormatter extends Formatter {
        @Override
        public String format(LogRecord record) {
            return record.getInstant() + " " + record.getLevel().getName() + " "
                    + record.getLoggerName() + " " + record.getMessage() + System.lineSeparator();
        }
    }

    // ------------------------------------------------------------------------------------------
    // Demo entry point
    // ------------------------------------------------------------------------------------------

    /**
     * Usage:
     * <pre>
     *   java AuthenticationService              # run scripted demo scenarios
     *   java AuthenticationService --login      # prompt for username and password
     * </pre>
     * Set {@code -Dauth.log.dir=<dir>} to change the log directory (default: ./logs).
     */
    public static void main(String[] args) throws IOException {
        Path logDir = Paths.get(System.getProperty("auth.log.dir", "logs"));
        AuditLogger audit = AuditLogger.createDefault(logDir);
        PasswordHasher hasher = new PasswordHasher();

        InMemoryUserStore store = new InMemoryUserStore();
        store.save(new UserAccount("alice", hasher.hash("Correct-Horse-Battery-9".toCharArray()), true));
        store.save(new UserAccount("bob", hasher.hash("B0b-Secure-Pass!".toCharArray()), true));
        store.save(new UserAccount("carol", hasher.hash("Carol-Pass-2024".toCharArray()), false));

        AuthenticationService service = new AuthenticationService(store, hasher, audit, Clock.systemUTC());

        if (args.length > 0 && "--login".equals(args[0])) {
            interactiveLogin(service);
        } else {
            runDemo(service);
        }
        System.out.println("Audit log written to " + logDir.toAbsolutePath().resolve("auth0.log"));
    }

    private static void interactiveLogin(AuthenticationService service) {
        Console console = System.console();
        String username;
        char[] password;
        if (console != null) {
            username = console.readLine("Username: ");
            password = console.readPassword("Password: ");
        } else {
            System.err.println("(No console available: password input will be echoed.)");
            Scanner in = new Scanner(System.in, StandardCharsets.UTF_8);
            System.out.print("Username: ");
            username = in.hasNextLine() ? in.nextLine() : null;
            System.out.print("Password: ");
            password = in.hasNextLine() ? in.nextLine().toCharArray() : null;
        }
        AuthResult result = service.authenticate(new LoginRequest(username, password, "127.0.0.1", "cli", null));
        System.out.println(result.message());
    }

    private static void runDemo(AuthenticationService service) {
        String ip = "203.0.113.10";
        String ua = "Mozilla/5.0 (demo)";

        attempt(service, "Successful login", "alice", "Correct-Horse-Battery-9", ip, ua);
        attempt(service, "Wrong password", "alice", "wrong-password", ip, ua);
        attempt(service, "Unknown user", "mallory", "guess123", "198.51.100.23", "curl/8.0");
        attempt(service, "Disabled account", "carol", "Carol-Pass-2024", ip, ua);
        attempt(service, "Missing password", "bob", "", ip, ua);
        attempt(service, "Log-injection attempt in username",
                "admin\n2026-01-01T00:00:00Z INFO security.audit event=\"AUTH_SUCCESS\" username=\"admin\"",
                "x", "198.51.100.23", "evil\r\nagent");

        System.out.println("\n--- Brute force against bob (lockout after " + MAX_FAILED_ATTEMPTS + " failures) ---");
        for (int i = 1; i <= MAX_FAILED_ATTEMPTS; i++) {
            attempt(service, "Guess #" + i, "bob", "guess-" + i, "192.0.2.77", "python-requests/2.31");
        }
        attempt(service, "Correct password while locked", "bob", "B0b-Secure-Pass!", "192.0.2.77", "python-requests/2.31");
    }

    private static void attempt(AuthenticationService service, String label, String user, String pass,
                                String ip, String ua) {
        AuthResult r = service.authenticate(new LoginRequest(user, pass.toCharArray(), ip, ua, null));
        System.out.printf("%n[%s] -> %s%n", label, r.message());
    }
}
