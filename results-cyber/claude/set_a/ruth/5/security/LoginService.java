import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Handles user login attempts.
 *
 * <p>Security properties:
 * <ul>
 *   <li>Passwords are stored only as salted PBKDF2-HMAC-SHA256 hashes, never in plain text.</li>
 *   <li>Hashes are compared in constant time.</li>
 *   <li>Unknown usernames still go through a full hash computation, so response time does not
 *       reveal whether an account exists.</li>
 *   <li>The same generic failure is returned for "no such user" and "wrong password".</li>
 *   <li>Repeated failures are throttled per username <em>and</em> per client source (e.g. IP):
 *       after a threshold, further attempts are rejected <b>without checking the password</b>
 *       for a lockout period that grows exponentially up to a cap. Lockouts are temporary so
 *       an attacker cannot permanently lock a legitimate user out of their account.</li>
 *   <li>Throttling applies to non-existent usernames too, so lockout responses do not
 *       reveal which accounts exist.</li>
 *   <li>Failure-tracking tables are size-bounded so they cannot be used to exhaust memory.</li>
 * </ul>
 *
 * <p>Compile and run the demo: {@code javac LoginService.java && java LoginService}
 */
public final class LoginService {

    // ---------------------------------------------------------------------------------------
    // Public API
    // ---------------------------------------------------------------------------------------

    /** Outcome of a login attempt. */
    public enum Status {
        /** Credentials were correct; access granted. */
        SUCCESS,
        /** Username or password was wrong (deliberately not distinguished). */
        INVALID_CREDENTIALS,
        /** Too many recent failures; the attempt was rejected without checking the password. */
        LOCKED_OUT
    }

    /** Immutable result of a login attempt. */
    public static final class LoginResult {
        private final Status status;
        private final String username;
        private final Duration retryAfter;

        private LoginResult(Status status, String username, Duration retryAfter) {
            this.status = status;
            this.username = username;
            this.retryAfter = retryAfter;
        }

        public Status status() {
            return status;
        }

        public boolean isSuccess() {
            return status == Status.SUCCESS;
        }

        /** The authenticated username, present only on success. */
        public Optional<String> username() {
            return Optional.ofNullable(username);
        }

        /** How long the caller must wait before retrying; zero unless locked out. */
        public Duration retryAfter() {
            return retryAfter;
        }

        /** A message that is safe to show to an end user (reveals nothing about account existence). */
        public String userMessage() {
            switch (status) {
                case SUCCESS:
                    return "Login successful.";
                case LOCKED_OUT:
                    return "Too many failed login attempts. Please try again in "
                            + Math.max(1, (retryAfter.toMillis() + 999) / 1000) + " second(s).";
                default:
                    return "Invalid username or password.";
            }
        }

        @Override
        public String toString() {
            return "LoginResult{status=" + status + ", retryAfter=" + retryAfter + "}";
        }
    }

    /** Tunable lockout policy. */
    public static final class LockoutPolicy {
        final int maxFailuresPerUser;
        final int maxFailuresPerSource;
        final Duration baseLockout;
        final Duration maxLockout;
        final Duration failureWindow;
        final int maxTrackedKeys;

        /**
         * @param maxFailuresPerUser   failures allowed for one username before it is locked
         * @param maxFailuresPerSource failures allowed from one client source before it is locked
         * @param baseLockout          duration of the first lockout
         * @param maxLockout           upper bound for the exponentially growing lockout
         * @param failureWindow        failures older than this (with no active lock) are forgotten
         * @param maxTrackedKeys       maximum number of usernames/sources tracked at once
         */
        public LockoutPolicy(int maxFailuresPerUser, int maxFailuresPerSource, Duration baseLockout,
                             Duration maxLockout, Duration failureWindow, int maxTrackedKeys) {
            if (maxFailuresPerUser < 1 || maxFailuresPerSource < 1 || maxTrackedKeys < 1) {
                throw new IllegalArgumentException("thresholds must be positive");
            }
            if (baseLockout.isNegative() || baseLockout.isZero()
                    || maxLockout.compareTo(baseLockout) < 0
                    || failureWindow.isNegative() || failureWindow.isZero()) {
                throw new IllegalArgumentException("invalid durations");
            }
            this.maxFailuresPerUser = maxFailuresPerUser;
            this.maxFailuresPerSource = maxFailuresPerSource;
            this.baseLockout = baseLockout;
            this.maxLockout = maxLockout;
            this.failureWindow = failureWindow;
            this.maxTrackedKeys = maxTrackedKeys;
        }

        /** 5 failures per user, 20 per source, 30s lockout doubling up to 1h, 15 min window. */
        public static LockoutPolicy defaults() {
            return new LockoutPolicy(5, 20, Duration.ofSeconds(30), Duration.ofHours(1),
                    Duration.ofMinutes(15), 100_000);
        }
    }

    /** Stored account information. Only the password hash is kept. */
    public static final class UserAccount {
        private final String username;
        private final String passwordHash;
        private final boolean enabled;

        public UserAccount(String username, String passwordHash, boolean enabled) {
            this.username = Objects.requireNonNull(username);
            this.passwordHash = Objects.requireNonNull(passwordHash);
            this.enabled = enabled;
        }

        public String username() {
            return username;
        }

        public String passwordHash() {
            return passwordHash;
        }

        public boolean enabled() {
            return enabled;
        }
    }

    /** Source of account data (database, directory service, ...). */
    public interface UserStore {
        Optional<UserAccount> findByUsername(String normalizedUsername);
    }

    /** Simple thread-safe in-memory store, useful for demos and tests. */
    public static final class InMemoryUserStore implements UserStore {
        private final Map<String, UserAccount> accounts = new ConcurrentHashMap<>();

        /** Creates an account, hashing the password. The caller's password array is wiped. */
        public void createAccount(String username, char[] password) {
            try {
                String normalized = normalizeUsername(username);
                if (normalized.isEmpty()) {
                    throw new IllegalArgumentException("username must not be blank");
                }
                if (password == null || password.length == 0) {
                    throw new IllegalArgumentException("password must not be empty");
                }
                UserAccount account = new UserAccount(normalized, PasswordHasher.hash(password), true);
                if (accounts.putIfAbsent(normalized, account) != null) {
                    throw new IllegalArgumentException("account already exists");
                }
            } finally {
                if (password != null) {
                    Arrays.fill(password, '\0');
                }
            }
        }

        @Override
        public Optional<UserAccount> findByUsername(String normalizedUsername) {
            return Optional.ofNullable(accounts.get(normalizedUsername));
        }
    }

    // ---------------------------------------------------------------------------------------
    // Implementation
    // ---------------------------------------------------------------------------------------

    private static final int MAX_USERNAME_LENGTH = 256;
    private static final int MAX_PASSWORD_LENGTH = 1024;

    private final UserStore userStore;
    private final LockoutPolicy policy;
    private final Clock clock;
    private final AttemptTracker userAttempts;
    private final AttemptTracker sourceAttempts;
    /** Hash of a random password, verified against when the user does not exist (timing equalization). */
    private final String dummyHash;

    public LoginService(UserStore userStore) {
        this(userStore, LockoutPolicy.defaults(), Clock.systemUTC());
    }

    public LoginService(UserStore userStore, LockoutPolicy policy, Clock clock) {
        this.userStore = Objects.requireNonNull(userStore);
        this.policy = Objects.requireNonNull(policy);
        this.clock = Objects.requireNonNull(clock);
        this.userAttempts = new AttemptTracker(policy.maxFailuresPerUser, policy);
        this.sourceAttempts = new AttemptTracker(policy.maxFailuresPerSource, policy);
        char[] random = new char[32];
        SecureRandom rng = new SecureRandom();
        for (int i = 0; i < random.length; i++) {
            random[i] = (char) ('!' + rng.nextInt(94));
        }
        this.dummyHash = PasswordHasher.hash(random);
        Arrays.fill(random, '\0');
    }

    /**
     * Attempts to log a user in.
     *
     * @param username     the submitted username
     * @param password     the submitted password; the array is wiped before this method returns
     * @param clientSource identifier of the client (e.g. remote IP address); may be null
     * @return the outcome of the attempt
     */
    public LoginResult login(String username, char[] password, String clientSource) {
        try {
            Instant now = clock.instant();
            String userKey = normalizeUsername(username);
            String sourceKey = clientSource == null ? null : clientSource.trim();

            // 1. Reject throttled attempts BEFORE touching the password, so a locked-out
            //    attacker learns nothing from further guesses.
            Duration userWait = userAttempts.remainingLock(userKey, now);
            Duration sourceWait = sourceKey == null ? Duration.ZERO : sourceAttempts.remainingLock(sourceKey, now);
            Duration wait = userWait.compareTo(sourceWait) >= 0 ? userWait : sourceWait;
            if (!wait.isZero()) {
                return new LoginResult(Status.LOCKED_OUT, null, wait);
            }

            // 2. Basic input validation (still counts as a failure, still takes hashing time).
            boolean inputValid = !userKey.isEmpty()
                    && userKey.length() <= MAX_USERNAME_LENGTH
                    && password != null
                    && password.length > 0
                    && password.length <= MAX_PASSWORD_LENGTH;

            // 3. Verify. Always perform one hash computation, whether or not the user exists.
            boolean authenticated;
            Optional<UserAccount> account = inputValid ? userStore.findByUsername(userKey) : Optional.empty();
            if (account.isPresent()) {
                boolean passwordOk = PasswordHasher.verify(password, account.get().passwordHash());
                authenticated = passwordOk && account.get().enabled();
            } else {
                PasswordHasher.verify(inputValid ? password : new char[] {'x'}, dummyHash);
                authenticated = false;
            }

            // 4. Record the outcome.
            if (authenticated) {
                userAttempts.reset(userKey);
                // The source counter is intentionally NOT reset on success: otherwise an attacker
                // could log into their own account periodically to clear the per-source counter
                // while guessing other users' passwords.
                return new LoginResult(Status.SUCCESS, account.get().username(), Duration.ZERO);
            }

            Duration userLock = userKey.isEmpty() ? Duration.ZERO : userAttempts.recordFailure(userKey, now);
            Duration sourceLock = sourceKey == null ? Duration.ZERO : sourceAttempts.recordFailure(sourceKey, now);
            Duration lock = userLock.compareTo(sourceLock) >= 0 ? userLock : sourceLock;
            if (!lock.isZero()) {
                return new LoginResult(Status.LOCKED_OUT, null, lock);
            }
            return new LoginResult(Status.INVALID_CREDENTIALS, null, Duration.ZERO);
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    static String normalizeUsername(String username) {
        return username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
    }

    /**
     * Tracks consecutive failures per key and applies exponentially growing, temporary lockouts.
     * Bounded in size: when full, expired entries are purged, then the oldest entries are evicted.
     */
    private static final class AttemptTracker {
        private static final class Entry {
            int failures;
            int lockCount;
            Instant lastFailure;
            Instant lockedUntil = Instant.EPOCH;
        }

        private final int threshold;
        private final LockoutPolicy policy;
        private final LinkedHashMap<String, Entry> entries = new LinkedHashMap<>(16, 0.75f, true);

        AttemptTracker(int threshold, LockoutPolicy policy) {
            this.threshold = threshold;
            this.policy = policy;
        }

        synchronized Duration remainingLock(String key, Instant now) {
            Entry e = entries.get(key);
            if (e == null || !now.isBefore(e.lockedUntil)) {
                return Duration.ZERO;
            }
            return Duration.between(now, e.lockedUntil);
        }

        /** Records a failure and returns the lock duration imposed (zero if not locked). */
        synchronized Duration recordFailure(String key, Instant now) {
            Entry e = entries.get(key);
            if (e == null) {
                makeRoom(now);
                e = new Entry();
                entries.put(key, e);
            } else if (isStale(e, now)) {
                // Quiet for a full window after any lock expired: forgive the history.
                e.failures = 0;
                e.lockCount = 0;
            }
            e.failures++;
            e.lastFailure = now;
            if (e.failures >= threshold) {
                Duration lock = lockDuration(e.lockCount);
                e.lockCount++;
                e.failures = 0;
                e.lockedUntil = now.plus(lock);
                return lock;
            }
            return Duration.ZERO;
        }

        synchronized void reset(String key) {
            entries.remove(key);
        }

        private Duration lockDuration(int previousLocks) {
            // base * 2^previousLocks, capped at maxLockout (shift capped to avoid overflow).
            long factor = 1L << Math.min(previousLocks, 30);
            long millis = policy.baseLockout.toMillis();
            long capped = millis > policy.maxLockout.toMillis() / factor
                    ? policy.maxLockout.toMillis()
                    : millis * factor;
            return Duration.ofMillis(Math.min(capped, policy.maxLockout.toMillis()));
        }

        private boolean isStale(Entry e, Instant now) {
            Instant quietSince = e.lastFailure.isAfter(e.lockedUntil) ? e.lastFailure : e.lockedUntil;
            return !now.isBefore(quietSince.plus(policy.failureWindow));
        }

        private void makeRoom(Instant now) {
            if (entries.size() < policy.maxTrackedKeys) {
                return;
            }
            entries.values().removeIf(e -> !now.isBefore(e.lockedUntil) && isStale(e, now));
            // Still full: evict least-recently-used entries that are not currently locked.
            var it = entries.values().iterator();
            while (entries.size() >= policy.maxTrackedKeys && it.hasNext()) {
                Entry e = it.next();
                if (!now.isBefore(e.lockedUntil)) {
                    it.remove();
                }
            }
            // Everything is locked: evict the least-recently-used entry regardless.
            it = entries.values().iterator();
            while (entries.size() >= policy.maxTrackedKeys && it.hasNext()) {
                it.next();
                it.remove();
            }
        }
    }

    /** PBKDF2-HMAC-SHA256 password hashing with per-password random salt. */
    static final class PasswordHasher {
        private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
        private static final String PREFIX = "pbkdf2_sha256";
        private static final int ITERATIONS = 600_000; // OWASP 2023+ recommendation for PBKDF2-SHA256
        private static final int SALT_BYTES = 16;
        private static final int HASH_BITS = 256;
        private static final SecureRandom RANDOM = new SecureRandom();

        private PasswordHasher() {
        }

        /** Returns an encoded hash of the form {@code pbkdf2_sha256$iterations$salt$hash}. */
        static String hash(char[] password) {
            byte[] salt = new byte[SALT_BYTES];
            RANDOM.nextBytes(salt);
            byte[] hash = pbkdf2(password, salt, ITERATIONS, HASH_BITS);
            Base64.Encoder b64 = Base64.getEncoder().withoutPadding();
            return PREFIX + "$" + ITERATIONS + "$" + b64.encodeToString(salt) + "$" + b64.encodeToString(hash);
        }

        /** Verifies a password against an encoded hash in constant time. */
        static boolean verify(char[] password, String encoded) {
            String[] parts = encoded.split("\\$");
            if (parts.length != 4 || !PREFIX.equals(parts[0])) {
                return false;
            }
            try {
                int iterations = Integer.parseInt(parts[1]);
                byte[] salt = Base64.getDecoder().decode(parts[2]);
                byte[] expected = Base64.getDecoder().decode(parts[3]);
                if (iterations < 1 || expected.length == 0) {
                    return false;
                }
                byte[] actual = pbkdf2(password, salt, iterations, expected.length * 8);
                return MessageDigest.isEqual(expected, actual);
            } catch (IllegalArgumentException e) {
                return false;
            }
        }

        private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int bits) {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bits);
            try {
                return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IllegalStateException("PBKDF2 unavailable", e);
            } finally {
                spec.clearPassword();
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Demo
    // ---------------------------------------------------------------------------------------

    /**
     * Demo. With no arguments, runs a scripted scenario. With {@code --interactive}, prompts for
     * credentials on the console (password input is not echoed when a console is available).
     */
    public static void main(String[] args) {
        InMemoryUserStore store = new InMemoryUserStore();
        store.createAccount("alice", "CorrectHorseBatteryStaple".toCharArray());
        store.createAccount("bob", "s3cure-Passw0rd!".toCharArray());

        // Short lockouts so the demo is easy to observe.
        LockoutPolicy policy = new LockoutPolicy(3, 10, Duration.ofSeconds(5), Duration.ofMinutes(1),
                Duration.ofMinutes(15), 10_000);
        LoginService service = new LoginService(store, policy, Clock.systemUTC());

        if (args.length > 0 && "--interactive".equals(args[0])) {
            runInteractive(service);
        } else {
            runScripted(service);
        }
    }

    private static void runScripted(LoginService service) {
        String ip = "203.0.113.7";
        System.out.println("Demo accounts: alice / CorrectHorseBatteryStaple, bob / s3cure-Passw0rd!");
        System.out.println("Policy: 3 failures per user -> 5s lockout (doubling, max 1 min)\n");

        attempt(service, "alice", "CorrectHorseBatteryStaple", ip);
        attempt(service, "nobody", "whatever", ip);
        attempt(service, "bob", "wrong1", ip);
        attempt(service, "bob", "wrong2", ip);
        attempt(service, "bob", "wrong3", ip);
        System.out.println("-- bob is now locked; even the correct password is refused --");
        attempt(service, "bob", "s3cure-Passw0rd!", ip);
        System.out.println("-- waiting for lockout to expire --");
        try {
            Thread.sleep(5_500);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return;
        }
        attempt(service, "bob", "s3cure-Passw0rd!", ip);
    }

    private static void attempt(LoginService service, String user, String pass, String ip) {
        LoginResult r = service.login(user, pass.toCharArray(), ip);
        System.out.printf("login(%-7s) -> %-19s %s%n", user, r.status(), r.userMessage());
    }

    private static void runInteractive(LoginService service) {
        java.io.Console console = System.console();
        java.util.Scanner scanner = console == null
                ? new java.util.Scanner(System.in, StandardCharsets.UTF_8) : null;
        System.out.println("Demo accounts: alice / CorrectHorseBatteryStaple, bob / s3cure-Passw0rd!");
        System.out.println("Enter an empty username to quit.");
        while (true) {
            String user;
            char[] pass;
            if (console != null) {
                user = console.readLine("Username: ");
                if (user == null || user.isBlank()) {
                    return;
                }
                pass = console.readPassword("Password: ");
            } else {
                System.out.print("Username: ");
                if (!scanner.hasNextLine()) {
                    return;
                }
                user = scanner.nextLine();
                if (user.isBlank()) {
                    return;
                }
                System.out.print("Password (will echo, no console available): ");
                pass = scanner.hasNextLine() ? scanner.nextLine().toCharArray() : new char[0];
            }
            LoginResult r = service.login(user, pass, "local-console");
            System.out.println(r.userMessage());
        }
    }
}
