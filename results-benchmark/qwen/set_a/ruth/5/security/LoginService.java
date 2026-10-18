import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Credential verification with per-account lockout.
 *
 * <p>The unit of behaviour is {@link #login(String, char[])}: it returns
 * {@link LoginStatus#SUCCESS} only when the username names an enabled account whose
 * stored key matches the submitted password, and it refuses everything else. Repeated
 * failures are counted per username by {@link LoginAttemptTracker}; crossing the
 * threshold suspends authentication for that account for a while, correct password or
 * not.
 *
 * <p>Security properties this class is responsible for:
 * <ul>
 *   <li>Passwords are stored only as PBKDF2-HMAC-SHA256 digests with a per-account
 *       random salt, never in plaintext, and are compared in constant time.</li>
 *   <li>Every refusal is worded the same way except for the lock notice, and every
 *       refusal costs the same amount of work, so a caller cannot learn whether a
 *       username exists from either the message or the response time.</li>
 *   <li>Username and password are shape-validated before anything touches the account
 *       store, so a backing store never receives a value that cannot be an account
 *       key.</li>
 * </ul>
 *
 * <p>Everything is in the default package and in this one file so that the whole
 * implementation can be read, compiled and run as a unit.
 */
public final class LoginService {

    /** Refusal wording shared by every non-lock rejection, so the reason is not leaked. */
    public static final String INVALID_MESSAGE = "Invalid username or password.";

    /**
     * The one message that differs, because a person who is locked out has to be told
     * when to come back. It does say the username exists, which is the deliberate
     * trade-off of offering lockout at all; every other refusal stays generic.
     */
    public static final String LOCKED_MESSAGE = "Account temporarily locked. Try again later.";

    /**
     * Username shape: 1-64 characters, alphanumeric first, then alphanumerics or
     * {@code . _ -}. Matching is exact - no trimming and no case folding - because
     * normalising would merge distinct inputs into one account key. Anything else is
     * rejected before the store is consulted.
     */
    private static final Pattern USERNAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,63}");

    public enum LoginStatus { SUCCESS, INVALID_CREDENTIALS, ACCOUNT_LOCKED }

    /** Result of one {@link LoginService#login} call. */
    public static final class LoginOutcome {

        private final LoginStatus status;
        private final String message;
        private final long retryInSeconds;

        private LoginOutcome(LoginStatus status, String message, long retryInSeconds) {
            this.status = status;
            this.message = message;
            this.retryInSeconds = retryInSeconds;
        }

        public LoginStatus status() { return status; }

        /** Wording safe to show the person attempting to log in. */
        public String message() { return message; }

        /** True only for {@link LoginStatus#SUCCESS}; grant access on this and nothing else. */
        public boolean granted() { return status == LoginStatus.SUCCESS; }

        /** Seconds until authentication is retried for a locked account; 0 otherwise. */
        public long retryInSeconds() { return retryInSeconds; }

        @Override public String toString() {
            return status + (retryInSeconds > 0 ? " (retry in " + retryInSeconds + "s)" : "");
        }
    }

    /**
     * Read side of the account directory. Implementations that talk to a database or an
     * LDAP server must keep the credential comparison above the constant-time path in
     * {@link PasswordHasher} and must surface lookup failures as {@link Optional#empty()}
     * only when the account genuinely does not exist - never on error.
     */
    public interface AccountStore {
        Optional<Account> find(String username);
    }

    /**
     * A stored account. {@code hashedPassword} is a {@link PasswordHasher} encoded
     * record, never the password itself.
     */
    public record Account(String username, String hashedPassword, boolean enabled) {}

    /** Hook for recording authentication activity. It must never be given the password. */
    public interface AuditSink {

        AuditSink NOOP = (username, status, retryInSeconds) -> { };

        void record(String username, LoginStatus status, long retryInSeconds);

        /** Sink that prints one line per attempt; usernames only, never credentials. */
        static AuditSink println() {
            return (username, status, retryInSeconds) -> System.out.println("    audit "
                    + status + " username=" + username + " retryInSeconds=" + retryInSeconds);
        }
    }

    private final AccountStore accounts;
    private final PasswordHasher hasher;
    private final LoginAttemptTracker tracker;
    private final AuditSink audit;

    public LoginService(AccountStore accounts, PasswordHasher hasher, LoginAttemptTracker tracker) {
        this(accounts, hasher, tracker, AuditSink.NOOP);
    }

    public LoginService(AccountStore accounts, PasswordHasher hasher, LoginAttemptTracker tracker,
                        AuditSink audit) {
        if (accounts == null || hasher == null || tracker == null || audit == null) {
            throw new IllegalArgumentException("collaborators must not be null");
        }
        this.accounts = accounts;
        this.hasher = hasher;
        this.tracker = tracker;
        this.audit = audit;
    }

    /**
     * Verifies a submitted credential pair.
     *
     * <p>Every path through this method that does not grant access performs exactly one
     * full key derivation - either against the account's real record or against a
     * throwaway record built at {@link PasswordHasher} construction - so that a refusal
     * for an unknown username, a malformed name, an unusable password or a locked
     * account takes the same time as a genuine password check. Removing any one of
     * those charges turns login into an account-enumeration oracle, which is why the
     * test suite times each of the five refusal shapes separately.
     *
     * @param username   candidate username, matched exactly
     * @param password   candidate password; the array is left untouched, so the caller
     *                   stays free to overwrite it once the call returns
     * @return the outcome; only {@link LoginStatus#SUCCESS} authorises access
     */
    public LoginOutcome login(String username, char[] password) {
        if (!isWellFormedUsername(username)) {
            hasher.burnWork();
            return refuse(null, LoginStatus.INVALID_CREDENTIALS, 0L);
        }

        long lockedFor = tracker.remainingLockMillis(username);
        if (lockedFor > 0L) {
            // Refusing early would make the lock state readable by stopwatch.
            hasher.burnWork();
            return refuse(username, LoginStatus.ACCOUNT_LOCKED, secondsUp(lockedFor));
        }

        if (!PasswordHasher.isHashable(password)) {
            hasher.burnWork();
            tracker.recordFailure(username);
            return refuse(username, LoginStatus.INVALID_CREDENTIALS, 0L);
        }

        Optional<Account> found = accounts.find(username);
        if (found.isEmpty() || !found.get().enabled()) {
            // Derive against a record that cannot match anything: same cost, same answer
            // as a wrong password, so neither time nor wording says "no such user".
            hasher.burnWork();
            tracker.recordFailure(username);
            return refuse(username, LoginStatus.INVALID_CREDENTIALS, 0L);
        }

        if (hasher.matches(password, found.get().hashedPassword())) {
            tracker.recordSuccess(username);
            audit.record(username, LoginStatus.SUCCESS, 0L);
            return new LoginOutcome(LoginStatus.SUCCESS, "Access granted.", 0L);
        }

        // The failure that crosses the threshold still reports INVALID_CREDENTIALS; the
        // lock becomes visible on the next attempt. Counting the trip here and reporting
        // it there keeps the two responses worded identically for as long as the
        // submitted password is simply wrong.
        tracker.recordFailure(username);
        return refuse(username, LoginStatus.INVALID_CREDENTIALS, 0L);
    }

    /**
     * Whether {@code username} can name an account at all. A malformed name is not a
     * login attempt against anybody, so it is refused without consulting the store or
     * accumulating failures under an attacker-chosen key.
     */
    public static boolean isWellFormedUsername(String username) {
        return username != null && USERNAME.matcher(username).matches();
    }

    private LoginOutcome refuse(String username, LoginStatus status, long retryInSeconds) {
        audit.record(username, status, retryInSeconds);
        String message = status == LoginStatus.ACCOUNT_LOCKED ? LOCKED_MESSAGE : INVALID_MESSAGE;
        return new LoginOutcome(status, message, retryInSeconds);
    }

    private static long secondsUp(long millis) {
        return (millis + 999L) / 1000L;
    }

    // ------------------------------------------------------------------ hashing

    /**
     * PBKDF2-HMAC-SHA256 password records in the form
     * {@code pbkdf2$<iterations>$<base64 salt>$<base64 key>}.
     *
     * <p>{@link #matches(char[], String)} re-derives with the iteration count embedded in
     * the record, so stored records keep verifying after the cost parameter is raised for
     * new passwords.
     */
    public static final class PasswordHasher {

        private static final String PREFIX = "pbkdf2";
        private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
        private static final int SALT_BYTES = 16;
        private static final int KEY_BITS = 256;

        /** Stored iteration counts outside this range are treated as a corrupt record. */
        public static final int MIN_ITERATIONS = 1_000;
        public static final int MAX_ITERATIONS = 5_000_000;

        /** Cost of a new password; about 0.3s per derivation on a 2026-class x86 core. */
        public static final int DEFAULT_ITERATIONS = 210_000;

        private final int iterations;
        private final SecureRandom random = new SecureRandom();

        /**
         * A real record derived from a random password that no caller can present.
         * {@link #burnWork()} verifies against it, which is what makes the equalised
         * refusal paths cost the same as a real check. A hand-written constant would not
         * do: if it failed to parse, the equalising derivation would never run and the
         * branch would silently cost nothing.
         */
        private final String dummyRecord;
        private final char[] dummyPassword;

        public PasswordHasher() {
            this(DEFAULT_ITERATIONS);
        }

        public PasswordHasher(int iterations) {
            if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
                throw new IllegalArgumentException("iterations out of range: " + iterations);
            }
            this.iterations = iterations;
            byte[] seed = new byte[24];
            this.random.nextBytes(seed);
            this.dummyPassword = Base64.getUrlEncoder().withoutPadding().encodeToString(seed).toCharArray();
            this.dummyRecord = hash(this.dummyPassword);
        }

        /**
         * Whether {@code password} can be hashed without the JCE silently changing it.
         *
         * <p>{@link PBEKeySpec} converts the {@code char[]} with its own UTF-8 encoder,
         * which is not injective over the whole domain: trailing NULs are dropped and
         * every unpaired surrogate becomes {@code ?}. Those inputs therefore collide with
         * other, shorter passwords, so one person's secret would verify as another's. They
         * are refused rather than trimmed, because trimming would quietly change the
         * secret. Interior NULs and correctly paired surrogates are fine.
         */
        public static boolean isHashable(char[] password) {
            if (password == null || password.length == 0 || password.length > 1_024) {
                return false;
            }
            if (password[password.length - 1] == '\0') {
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

        /** Encodes a new password with a fresh random salt. */
        public String hash(char[] password) {
            if (!isHashable(password)) {
                throw new IllegalArgumentException("password cannot be hashed safely");
            }
            byte[] salt = new byte[SALT_BYTES];
            random.nextBytes(salt);
            byte[] key = derive(password, salt, iterations);
            return PREFIX + "$" + iterations + "$"
                    + Base64.getEncoder().encodeToString(salt) + "$"
                    + Base64.getEncoder().encodeToString(key);
        }

        /**
         * Re-derives {@code password} under the record's salt and cost and compares in
         * constant time. A malformed or tampered record yields {@code false} after paying
         * the normal cost, never an exception, so a corrupt row cannot be probed by
         * error or by stopwatch.
         */
        public boolean matches(char[] password, String stored) {
            Record record = parse(stored);
            if (record == null || !isHashable(password)) {
                burnWork();
                return false;
            }
            byte[] candidate = derive(password, record.salt, record.iterations);
            return MessageDigest.isEqual(record.key, candidate);
        }

        /** Spends one derivation on a record that matches nothing, to equalise timing. */
        public void burnWork() {
            matches(dummyPassword, dummyRecord);
        }

        /** Iteration count used for newly hashed passwords. */
        public int iterations() { return iterations; }

        private static byte[] derive(char[] password, byte[] salt, int iterations) {
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
                PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
                byte[] key = factory.generateSecret(spec).getEncoded();
                spec.clearPassword();
                return key;
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException(ALGORITHM + " unavailable", e);
            }
        }

        private static Record parse(String stored) {
            if (stored == null) {
                return null;
            }
            String[] parts = stored.split("\\$", -1);
            if (parts.length != 4 || !PREFIX.equals(parts[0])) {
                return null;
            }
            int iterations;
            try {
                iterations = Integer.parseInt(parts[1]);
            } catch (NumberFormatException e) {
                return null;
            }
            if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
                return null;
            }
            byte[] salt;
            byte[] key;
            try {
                salt = Base64.getDecoder().decode(parts[2]);
                key = Base64.getDecoder().decode(parts[3]);
            } catch (IllegalArgumentException e) {
                return null;
            }
            if (salt.length == 0 || salt.length > 64 || key.length != KEY_BITS / 8) {
                return null;
            }
            return new Record(iterations, salt, key);
        }

        private record Record(int iterations, byte[] salt, byte[] key) {}
    }

    // ----------------------------------------------------------------- lockout

    /**
     * Counts failed attempts per username and suspends authentication once a username
     * accumulates too many of them.
     *
     * <p>Details that matter:
     * <ul>
     *   <li>Failures only count while they fall inside a rolling {@code failureWindow};
     *       older ones are forgotten, so a slow trickle of typos never locks anybody
     *       out.</li>
     *   <li>Crossing {@code maxFailures} locks the account for {@code lockDuration},
     *       multiplied by {@code backoffFactor} for each consecutive lock, capped at
     *       {@code maxLockDuration}. The counter resets when the lock trips, so a
     *       released account gets a fresh budget.</li>
     *   <li>A lock is lifted only by its own timer or by an operator calling
     *       {@link #clear(String)}. A later success can never lift it, which keeps the
     *       lockout meaningful when the correct password is guessed during the window.</li>
     *   <li>Transitions run inside {@code ConcurrentHashMap.compute}, so concurrent
     *       attempts against the same username are serialised and cannot race past the
     *       threshold.</li>
     *   <li>Entries for usernames that were never real accounts are kept only for
     *       {@code retention} and then swept, so the map cannot be grown without bound by
     *       trying random names.</li>
     * </ul>
     */
    public static final class LoginAttemptTracker {

        private final int maxFailures;
        private final long lockMillis;
        private final double backoffFactor;
        private final long maxLockMillis;
        private final long failureWindowMillis;
        private final long retentionMillis;
        private final long purgeIntervalMillis;
        private final LongSupplier clock;

        private final ConcurrentHashMap<String, State> states = new ConcurrentHashMap<>();
        private final Object purgeLock = new Object();
        private volatile long lastPurgeMillis;

        /** Typical policy: five failures in ten minutes suspends an account for fifteen minutes. */
        public LoginAttemptTracker(int maxFailures, Duration lockDuration, Duration failureWindow) {
            this(maxFailures, lockDuration, 1.0d, lockDuration, failureWindow,
                    failureWindow.plus(lockDuration.multipliedBy(2)), System::currentTimeMillis);
        }

        public LoginAttemptTracker(int maxFailures, Duration lockDuration, double backoffFactor,
                                   Duration maxLockDuration, Duration failureWindow,
                                   Duration retention, LongSupplier clock) {
            if (maxFailures < 1) {
                throw new IllegalArgumentException("maxFailures must be at least 1");
            }
            if (lockDuration == null || lockDuration.isNegative() || lockDuration.isZero()) {
                throw new IllegalArgumentException("lockDuration must be positive");
            }
            if (backoffFactor < 1.0d || Double.isNaN(backoffFactor)) {
                throw new IllegalArgumentException("backoffFactor must be at least 1.0");
            }
            if (maxLockDuration == null || maxLockDuration.compareTo(lockDuration) < 0) {
                throw new IllegalArgumentException("maxLockDuration must cover lockDuration");
            }
            if (failureWindow == null || failureWindow.isNegative() || failureWindow.isZero()) {
                throw new IllegalArgumentException("failureWindow must be positive");
            }
            if (retention == null || retention.isNegative() || retention.isZero()) {
                throw new IllegalArgumentException("retention must be positive");
            }
            if (clock == null) {
                throw new IllegalArgumentException("clock must not be null");
            }
            this.maxFailures = maxFailures;
            this.lockMillis = lockDuration.toMillis();
            this.backoffFactor = backoffFactor;
            this.maxLockMillis = maxLockDuration.toMillis();
            this.failureWindowMillis = failureWindow.toMillis();
            this.retentionMillis = retention.toMillis();
            this.purgeIntervalMillis = Math.max(1L, Math.min(this.retentionMillis, 60_000L) / 4L);
            this.clock = clock;
            this.lastPurgeMillis = clock.getAsLong();
        }

        /**
         * Registers a failed attempt.
         *
         * @return {@code true} if this failure is the one that locked the account
         */
        public boolean recordFailure(String username) {
            requireKey(username);
            purgeIfNeeded();
            boolean[] tripped = new boolean[1];
            states.compute(username, (key, state) -> {
                long now = clock.getAsLong();
                if (state == null) {
                    state = new State();
                }
                state.lastTouchMillis = now;
                if (state.lockedUntilMillis > now) {
                    return state; // already suspended: no double counting, no extension
                }
                if (state.failures == 0 || now - state.windowStartMillis > failureWindowMillis) {
                    state.failures = 0;
                    state.windowStartMillis = now;
                }
                state.failures++;
                if (state.failures >= maxFailures) {
                    state.consecutiveLocks++;
                    state.lockedUntilMillis = now + lockDurationMillis(state.consecutiveLocks);
                    state.failures = 0;
                    tripped[0] = true;
                }
                return state;
            });
            return tripped[0];
        }

        /**
         * Notes a successful login. Failures and the escalating-lock counter are forgotten,
         * but an active lock survives: only its timer or {@link #clear(String)} ends it.
         */
        public void recordSuccess(String username) {
            requireKey(username);
            states.compute(username, (key, state) -> {
                if (state == null) {
                    return null;
                }
                if (state.lockedUntilMillis > clock.getAsLong()) {
                    return state;
                }
                return null;
            });
        }

        /** Millis of lock left for {@code username}; 0 when authentication is allowed. */
        public long remainingLockMillis(String username) {
            requireKey(username);
            long[] remaining = new long[1];
            states.compute(username, (key, state) -> {
                if (state == null) {
                    return null;
                }
                long now = clock.getAsLong();
                if (state.lockedUntilMillis > now) {
                    // Deliberately does not touch lastTouchMillis: a suspended account is
                    // probed repeatedly, and refreshing the idle stamp on every read would
                    // make the entry look permanently busy so it is never swept.
                    remaining[0] = state.lockedUntilMillis - now;
                    return state;
                }
                state.lockedUntilMillis = 0L;
                if (state.failures == 0 && now - state.lastTouchMillis > retentionMillis) {
                    return null;
                }
                if (now - state.windowStartMillis > failureWindowMillis) {
                    state.failures = 0;
                }
                return state;
            });
            return remaining[0];
        }

        /** Failures counted inside the current window; for operators and tests. */
        public int failureCount(String username) {
            requireKey(username);
            int[] count = new int[1];
            states.compute(username, (key, state) -> {
                if (state == null) {
                    return null;
                }
                long now = clock.getAsLong();
                if (state.lockedUntilMillis <= now
                        && now - state.windowStartMillis > failureWindowMillis) {
                    state.failures = 0;
                }
                count[0] = state.failures;
                return state;
            });
            return count[0];
        }

        /** Operator override: lift a lock and forget the failures for one username. */
        public void clear(String username) {
            requireKey(username);
            states.remove(username);
        }

        /** Usernames currently held in memory; bounded by {@code retention}. */
        public int trackedKeys() {
            return states.size();
        }

        /** Drops state for usernames idle beyond {@code retention}; swept automatically too. */
        public int purgeExpired() {
            long now = clock.getAsLong();
            int[] removed = new int[1];
            states.entrySet().removeIf(entry -> {
                State state = entry.getValue();
                boolean idle = state.lockedUntilMillis <= now
                        && now - state.lastTouchMillis > retentionMillis;
                if (idle) {
                    removed[0]++;
                }
                return idle;
            });
            synchronized (purgeLock) {
                lastPurgeMillis = now;
            }
            return removed[0];
        }

        private long lockDurationMillis(int consecutiveLocks) {
            long duration = lockMillis;
            for (int i = 1; i < consecutiveLocks && duration < maxLockMillis; i++) {
                duration = Math.min(maxLockMillis, (long) (duration * backoffFactor));
            }
            return Math.max(lockMillis, Math.min(duration, maxLockMillis));
        }

        private void purgeIfNeeded() {
            if (clock.getAsLong() - lastPurgeMillis >= purgeIntervalMillis) {
                purgeExpired();
            }
        }

        private static void requireKey(String username) {
            if (username == null || username.isEmpty()) {
                throw new IllegalArgumentException("username must not be null or empty");
            }
        }

        /** Mutable only while held by the enclosing {@code compute}, which serialises per key. */
        private static final class State {
            int failures;
            long windowStartMillis;
            int consecutiveLocks;
            long lockedUntilMillis;
            long lastTouchMillis;
        }
    }

    // -------------------------------------------------------------------- store

    /** In-memory {@link AccountStore} used by the demo and the tests. */
    public static final class InMemoryAccountStore implements AccountStore {

        private final Map<String, Account> accounts = new ConcurrentHashMap<>();
        private final PasswordHasher hasher;

        public InMemoryAccountStore(PasswordHasher hasher) {
            if (hasher == null) {
                throw new IllegalArgumentException("hasher must not be null");
            }
            this.hasher = hasher;
        }

        public Account register(String username, char[] password) {
            return register(username, password, true);
        }

        public Account register(String username, char[] password, boolean enabled) {
            if (!isWellFormedUsername(username)) {
                throw new IllegalArgumentException("username cannot name an account: " + username);
            }
            if (!PasswordHasher.isHashable(password)) {
                throw new IllegalArgumentException("password cannot be hashed safely");
            }
            Account account = new Account(username, hasher.hash(password), enabled);
            accounts.put(username, account);
            return account;
        }

        /**
         * Replaces a password. The caller must also lift any lockout with
         * {@link LoginAttemptTracker#clear(String)}, otherwise a locked account stays
         * locked after a password reset.
         */
        public Account changePassword(String username, char[] password) {
            Account existing = accounts.get(username);
            if (existing == null) {
                throw new IllegalArgumentException("no such account: " + username);
            }
            return register(username, password, existing.enabled());
        }

        @Override public Optional<Account> find(String username) {
            return username == null ? Optional.empty() : Optional.ofNullable(accounts.get(username));
        }

        public int size() { return accounts.size(); }
    }

    // --------------------------------------------------------------------- demo

    /**
     * Scripted walkthrough, or a credential prompt with {@code --interactive}.
     */
    public static void main(String[] args) {
        if (args.length > 0 && "--interactive".equals(args[0])) {
            interactive();
            return;
        }
        PasswordHasher hasher = new PasswordHasher();
        InMemoryAccountStore store = new InMemoryAccountStore(hasher);
        store.register("alice", "Corr3ct-Horse-Battery".toCharArray());
        store.register("bob", "hunter2-hunter2!".toCharArray());
        store.register("svc-batch", "d1sabled-s3cret-pw".toCharArray(), false);

        LoginAttemptTracker tracker = new LoginAttemptTracker(
                3, Duration.ofSeconds(2), Duration.ofMinutes(10));
        LoginService service = new LoginService(store, hasher, tracker, AuditSink.println());

        System.out.println("Stored record for alice: " + store.find("alice").orElseThrow().hashedPassword());
        System.out.println();

        System.out.println("[1] correct password");
        attempt(service, "alice", "Corr3ct-Horse-Battery");

        System.out.println("[2] wrong password");
        attempt(service, "alice", "wrong-password");

        System.out.println("[3] username that does not exist - same wording, same cost");
        attempt(service, "mallory", "whatever-123456");

        System.out.println("[4] three failures in a row trip the lock");
        attempt(service, "bob", "nope-1");
        attempt(service, "bob", "nope-2");
        attempt(service, "bob", "nope-3");

        System.out.println("[5] bob is locked, so even the right password is refused");
        attempt(service, "bob", "hunter2-hunter2!");

        System.out.println("[6] after the lock expires bob is back in");
        sleepMillis(2_100L);
        attempt(service, "bob", "hunter2-hunter2!");

        System.out.println("[7] a disabled account never authenticates");
        attempt(service, "svc-batch", "d1sabled-s3cret-pw");

        System.out.println("[8] an unknown username is throttled by the same policy");
        for (int i = 1; i <= 4; i++) {
            attempt(service, "admin", "guessed-" + i);
        }

        System.out.println();
        System.out.println("tracked usernames still held in memory: " + tracker.trackedKeys());
    }

    private static void attempt(LoginService service, String username, String password) {
        char[] candidate = password.toCharArray();
        LoginOutcome outcome = service.login(username, candidate);
        System.out.println("    -> " + outcome + " | " + outcome.message());
    }

    private static void interactive() {
        java.io.Console console = System.console();
        if (console == null) {
            System.out.println("No console attached; run without --interactive for the scripted demo.");
            return;
        }
        PasswordHasher hasher = new PasswordHasher();
        InMemoryAccountStore store = new InMemoryAccountStore(hasher);
        store.register("alice", "Corr3ct-Horse-Battery".toCharArray());
        LoginAttemptTracker tracker = new LoginAttemptTracker(
                3, Duration.ofMinutes(15), Duration.ofMinutes(10));
        LoginService service = new LoginService(store, hasher, tracker, AuditSink.println());

        System.out.print("username: ");
        String username = console.readLine();
        char[] password = console.readPassword("password: ");
        LoginOutcome outcome = service.login(username, password);
        System.out.println(outcome + " | " + outcome.message());
    }

    private static void sleepMillis(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
