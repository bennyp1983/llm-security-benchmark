import java.io.Console;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Password-based login for an application.
 *
 * <p>Accounts hold a salted PBKDF2-HMAC-SHA256 digest, never a password. A login attempt is
 * accepted only when the candidate password re-derives the stored digest, and is refused with one
 * generic reason for every other case (wrong password, unknown account, malformed stored digest,
 * candidate this class refuses to hash). Every attempt costs exactly one key derivation, so
 * response time does not disclose whether the named account exists.
 *
 * <p>Run {@code java LoginService} for a scripted demo, {@code java LoginService -i} for an
 * interactive console.
 */
public final class LoginService {

    private static final System.Logger LOG = System.getLogger(LoginService.class.getName());

    /**
     * Names are matched byte-for-byte, so the character set is restricted instead of folded:
     * case- or Unicode-folded lookup is not injective (for example {@code 'I'} and the dotless
     * {@code U+0131} can collide), which would let one name resolve to another account.
     */
    public static boolean isWellFormedUsername(String username) {
        return username != null && USERNAME_PATTERN.matcher(username).matches();
    }

    private static final Pattern USERNAME_PATTERN = Pattern.compile("[A-Za-z0-9._-]{3,32}");

    private final AccountStore store;
    private final PasswordHasher hasher;
    private final LoginAttemptTracker tracker;
    private final LongSupplier clock;
    private final SecureRandom random = new SecureRandom();

    public LoginService(AccountStore store, PasswordHasher hasher) {
        this(store, hasher, LoginAttemptTracker.defaults(), System::currentTimeMillis);
    }

    public LoginService(AccountStore store, PasswordHasher hasher, LoginAttemptTracker tracker,
            LongSupplier clock) {
        this.store = store;
        this.hasher = hasher;
        this.tracker = tracker;
        this.clock = clock;
    }

    /**
     * Verifies submitted credentials and grants access when they are correct.
     *
     * @param username account name
     * @param password candidate password
     * @return outcome carrying {@link LoginStatus#SUCCESS} and a session token, or a refusal whose
     *     {@link LoginOutcome#message()} is the same for every failed credential
     */
    public LoginOutcome login(String username, String password) {
        if (!isWellFormedUsername(username)) {
            hasher.chargeOneDerivation(password);
            return LoginOutcome.invalidCredentials();
        }
        if (tracker.isLocked(username, clock.getAsLong())) {
            hasher.chargeOneDerivation(password);
            return LoginOutcome.locked(username);
        }

        Account account = store.find(username);
        PasswordHasher.Verdict verdict = hasher.verify(password,
                account == null ? null : account.passwordHash());

        if (verdict == PasswordHasher.Verdict.MATCH) {
            tracker.recordSuccess(username);
            return LoginOutcome.success(username, newSessionToken());
        }
        if (verdict == PasswordHasher.Verdict.MALFORMED_RECORD) {
            LOG.log(System.Logger.Level.WARNING, "stored digest for account ''{0}'' is unreadable", username);
        }
        tracker.recordFailure(username, clock.getAsLong());
        return LoginOutcome.invalidCredentials();
    }

    /**
     * Stores a new account from a cleartext password; only the digest is kept.
     *
     * @return {@link Registration#STORED}, or the reason the request was rejected
     */
    public Registration register(String username, String password) {
        if (!isWellFormedUsername(username)) {
            return Registration.INVALID_USERNAME;
        }
        if (PasswordHasher.enrollmentRejection(password) != null) {
            return Registration.PASSWORD_REJECTED;
        }
        if (store.putIfAbsent(new Account(username, hasher.hash(password)))) {
            LOG.log(System.Logger.Level.INFO, "registered account ''{0}''", username);
            return Registration.STORED;
        }
        return Registration.DUPLICATE_USERNAME;
    }

    private String newSessionToken() {
        byte[] token = new byte[32];
        random.nextBytes(token);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
    }

    /** An account as persisted: name plus a self-describing password digest. */
    public record Account(String username, String passwordHash) {
        public Account {
            if (username == null || username.isEmpty()) {
                throw new IllegalArgumentException("username is required");
            }
            if (passwordHash == null || passwordHash.isEmpty()) {
                throw new IllegalArgumentException("passwordHash is required");
            }
        }
    }

    /** Persistence boundary; an implementation may sit on a database or a directory. */
    public interface AccountStore {
        /** @return the account, or {@code null} when no such account exists */
        Account find(String username);

        /** @return {@code true} if the account was stored, {@code false} if the name was taken */
        boolean putIfAbsent(Account account);

        int count();
    }

    /** Process-local store for the demo and the tests. */
    public static final class InMemoryAccountStore implements AccountStore {
        private final Map<String, Account> accounts = new ConcurrentHashMap<>();

        @Override
        public Account find(String username) {
            return username == null ? null : accounts.get(username);
        }

        @Override
        public boolean putIfAbsent(Account account) {
            return accounts.putIfAbsent(account.username(), account) == null;
        }

        @Override
        public int count() {
            return accounts.size();
        }
    }

    /** Outcome of {@link LoginService#register}. */
    public enum Registration {
        STORED,
        INVALID_USERNAME,
        PASSWORD_REJECTED,
        DUPLICATE_USERNAME
    }

    public enum LoginStatus {
        SUCCESS,
        INVALID_CREDENTIALS,
        LOCKED
    }

    /** Result of a login attempt. */
    public record LoginOutcome(LoginStatus status, String username, String sessionToken) {

        static LoginOutcome success(String username, String sessionToken) {
            return new LoginOutcome(LoginStatus.SUCCESS, username, sessionToken);
        }

        static LoginOutcome invalidCredentials() {
            return new LoginOutcome(LoginStatus.INVALID_CREDENTIALS, null, null);
        }

        static LoginOutcome locked(String username) {
            return new LoginOutcome(LoginStatus.LOCKED, username, null);
        }

        /** @return {@code true} when access is granted */
        public boolean granted() {
            return status == LoginStatus.SUCCESS;
        }

        /** Text safe to show a caller: one wording for every failed credential. */
        public String message() {
            switch (status) {
                case SUCCESS:
                    return "Authenticated.";
                case LOCKED:
                    return "Account temporarily locked after repeated failed attempts.";
                case INVALID_CREDENTIALS:
                default:
                    return "Invalid username or password.";
            }
        }
    }

    /**
     * Salted PBKDF2-HMAC-SHA256 password digests.
     *
     * <p>Encoded form {@code pbkdf2-sha256$<iterations>$<base64 salt>$<base64 digest>}, so a stored
     * digest carries the parameters it was made with and the work factor can be raised later
     * without invalidating existing accounts.
     */
    public static final class PasswordHasher {

        private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
        private static final String PREFIX = "pbkdf2-sha256";
        private static final int SALT_BYTES = 16;
        private static final int KEY_BITS = 256;
        private static final int MIN_ITERATIONS = 1_000;
        private static final int MAX_STORED_ITERATIONS = 20_000_000;
        private static final int MIN_ENROLLMENT_CHARS = 8;
        private static final int MAX_CANDIDATE_CHARS = 4_096;

        private static final Base64.Encoder ENCODER = Base64.getEncoder();
        private static final Base64.Decoder DECODER = Base64.getDecoder();

        public enum Verdict {
            MATCH,
            NO_MATCH,
            MALFORMED_RECORD
        }

        private final int iterations;
        private final SecureRandom random = new SecureRandom();
        private final Digest dummyDigest;

        public PasswordHasher() {
            this(210_000);
        }

        public PasswordHasher(int iterations) {
            if (iterations < MIN_ITERATIONS || iterations > MAX_STORED_ITERATIONS) {
                throw new IllegalArgumentException("iterations must be in [" + MIN_ITERATIONS + ", "
                        + MAX_STORED_ITERATIONS + "], was " + iterations);
            }
            this.iterations = iterations;
            this.dummyDigest = buildDummyDigest();
        }

        public int iterations() {
            return iterations;
        }

        /** The digest refusals are made against; it matches no password anyone can present. */
        Digest dummyDigest() {
            return dummyDigest;
        }

        /** @return a fresh self-describing digest of {@code password} */
        public String hash(String password) {
            if (structuralRejection(password) != null) {
                throw new IllegalArgumentException("password cannot be hashed safely");
            }
            byte[] salt = randomSalt();
            return encode(iterations, salt, derive(toChars(password), salt, iterations));
        }

        /**
         * Checks a candidate against a stored digest at the cost of one derivation, whatever the
         * answer.
         *
         * @param storedDigest digest from {@link #hash}, or {@code null} for an unknown account
         */
        public Verdict verify(String candidate, String storedDigest) {
            if (structuralRejection(candidate) != null) {
                derive(new char[0], this.dummyDigest.salt(), this.dummyDigest.iterations());
                return Verdict.NO_MATCH;
            }
            char[] password = toChars(candidate);
            if (storedDigest == null) {
                derive(password, this.dummyDigest.salt(), this.dummyDigest.iterations());
                return Verdict.NO_MATCH;
            }
            Digest stored = parse(storedDigest);
            if (stored == null) {
                derive(password, this.dummyDigest.salt(), this.dummyDigest.iterations());
                return Verdict.MALFORMED_RECORD;
            }
            byte[] derived = derive(password, stored.salt(), stored.iterations());
            return MessageDigest.isEqual(derived, stored.digest()) ? Verdict.MATCH : Verdict.NO_MATCH;
        }

        /**
         * Buys the candidate no account to check, but still pays for a derivation, so a request
         * refused before verification cannot be told apart from a wrong password by timing.
         */
        void chargeOneDerivation(String candidate) {
            char[] password = structuralRejection(candidate) == null ? toChars(candidate) : new char[0];
            derive(password, dummyDigest.salt(), dummyDigest.iterations());
        }

        /** @return the parameters in a stored digest, or {@code null} when it is unreadable */
        static Digest parse(String encoded) {
            if (encoded == null) {
                return null;
            }
            String[] parts = encoded.split("\\$", -1);
            if (parts.length != 4 || !PREFIX.equals(parts[0])) {
                return null;
            }
            int rounds;
            byte[] salt;
            byte[] digest;
            try {
                rounds = Integer.parseInt(parts[1]);
                salt = DECODER.decode(parts[2]);
                digest = DECODER.decode(parts[3]);
            } catch (IllegalArgumentException e) {
                return null;
            }
            if (rounds < MIN_ITERATIONS || rounds > MAX_STORED_ITERATIONS) {
                return null;
            }
            if (salt.length < 8 || salt.length > 64 || digest.length < 16 || digest.length > 64) {
                return null;
            }
            return new Digest(rounds, salt, digest);
        }

        /** @return why {@code password} may not be enrolled, or {@code null} when it may */
        static String enrollmentRejection(String password) {
            String structural = structuralRejection(password);
            if (structural != null) {
                return structural;
            }
            return password.length() < MIN_ENROLLMENT_CHARS ? "too-short" : null;
        }

        /**
         * @return why this class refuses to hash {@code password} at all, or {@code null} when it
         *     will hash it
         *
         * <p>{@link PBEKeySpec} converts the candidate with a lossy UTF-8 mapping: trailing NULs are
         * dropped and every unpaired surrogate becomes {@code '?'}, so distinct passwords share one
         * digest and whoever enrolled one can be signed in as by whoever presents another. Such
         * candidates are refused, not repaired -- trimming would silently change the secret.
         */
        static String structuralRejection(String password) {
            if (password == null) {
                return "missing";
            }
            int length = password.length();
            if (length == 0) {
                return "empty";
            }
            if (length > MAX_CANDIDATE_CHARS) {
                return "too-long";
            }
            if (password.charAt(length - 1) == '\0') {
                return "trailing-nul";
            }
            for (int i = 0; i < length; i++) {
                char c = password.charAt(i);
                if (Character.isHighSurrogate(c)) {
                    if (i + 1 >= length || !Character.isLowSurrogate(password.charAt(i + 1))) {
                        return "unpaired-surrogate";
                    }
                    i++;
                } else if (Character.isLowSurrogate(c)) {
                    return "unpaired-surrogate";
                }
            }
            return null;
        }

        /** A digest over random bytes at this hasher's work factor, readable back by {@link #parse}. */
        private Digest buildDummyDigest() {
            char[] filler = new char[44];
            for (int i = 0; i < filler.length; i++) {
                filler[i] = ALPHABET[random.nextInt(ALPHABET.length)];
            }
            byte[] salt = randomSalt();
            Digest parsed = parse(encode(iterations, salt, derive(filler, salt, iterations)));
            if (parsed == null) {
                throw new IllegalStateException("generated dummy digest does not parse; refusals would"
                        + " skip the work they exist to equalize");
            }
            return parsed;
        }

        private static final char[] ALPHABET =
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-".toCharArray();

        private byte[] randomSalt() {
            byte[] salt = new byte[SALT_BYTES];
            random.nextBytes(salt);
            return salt;
        }

        private static byte[] derive(char[] password, byte[] salt, int rounds) {
            PBEKeySpec spec = new PBEKeySpec(password, salt, rounds, KEY_BITS);
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
                return factory.generateSecret(spec).getEncoded();
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("password hashing unavailable: " + ALGORITHM, e);
            } finally {
                spec.clearPassword();
                Arrays.fill(password, '\0');
            }
        }

        private static char[] toChars(String value) {
            return value.toCharArray();
        }

        private static String encode(int rounds, byte[] salt, byte[] digest) {
            return PREFIX + '$' + rounds + '$' + ENCODER.encodeToString(salt) + '$'
                    + ENCODER.encodeToString(digest);
        }

        /** A decoded digest; the arrays belong to this record and must never be overwritten. */
        record Digest(int iterations, byte[] salt, byte[] digest) {
        }
    }

    /**
     * Throttles repeated failures per account.
     *
     * <p>Counters are keyed by name, so guessing invented names cannot grow the map without bound:
     * entries whose window has passed are dropped once {@value #MAX_TRACKED_ACCOUNTS} are tracked.
     */
    public static final class LoginAttemptTracker {

        private static final int MAX_TRACKED_ACCOUNTS = 100_000;

        private final int maxFailures;
        private final long windowMillis;
        private final long lockMillis;
        private final Map<String, Counter> counters = new ConcurrentHashMap<>();

        public LoginAttemptTracker(int maxFailures, long windowMillis, long lockMillis) {
            if (maxFailures < 1 || windowMillis <= 0 || lockMillis <= 0) {
                throw new IllegalArgumentException("tracker limits must be positive");
            }
            this.maxFailures = maxFailures;
            this.windowMillis = windowMillis;
            this.lockMillis = lockMillis;
        }

        /** Five failures in five minutes locks the account for fifteen. */
        public static LoginAttemptTracker defaults() {
            return new LoginAttemptTracker(5, 5 * 60_000L, 15 * 60_000L);
        }

        public boolean isLocked(String username, long nowMillis) {
            Counter counter = counters.get(username);
            if (counter == null) {
                return false;
            }
            synchronized (counter) {
                return counter.lockedUntil > nowMillis;
            }
        }

        public int failures(String username, long nowMillis) {
            Counter counter = counters.get(username);
            if (counter == null) {
                return 0;
            }
            synchronized (counter) {
                if (counter.lockedUntil > nowMillis) {
                    return maxFailures;
                }
                return withinFailureWindow(counter, nowMillis) ? counter.failures : 0;
            }
        }

        public void recordFailure(String username, long nowMillis) {
            if (counters.size() > MAX_TRACKED_ACCOUNTS) {
                purgeExpired(nowMillis);
            }
            Counter counter = counters.computeIfAbsent(username, key -> new Counter());
            synchronized (counter) {
                if (counter.lockedUntil > nowMillis) {
                    return;
                }
                if (counter.lockedUntil > 0) {
                    counter.lockedUntil = 0;
                }
                if (!withinFailureWindow(counter, nowMillis)) {
                    counter.windowStart = nowMillis;
                    counter.failures = 0;
                }
                counter.failures++;
                if (counter.failures >= maxFailures) {
                    counter.lockedUntil = nowMillis + lockMillis;
                }
            }
        }

        /** An expired window must read as no failures now, not only once the next one lands. */
        private boolean withinFailureWindow(Counter counter, long nowMillis) {
            return counter.windowStart != 0 && nowMillis - counter.windowStart <= windowMillis;
        }

        public void recordSuccess(String username) {
            counters.remove(username);
        }

        /** Clears an account's state, for an operator-assisted unlock. */
        public void unlock(String username) {
            counters.remove(username);
        }

        private void purgeExpired(long nowMillis) {
            counters.entrySet().removeIf(entry -> {
                Counter counter = entry.getValue();
                synchronized (counter) {
                    return counter.lockedUntil <= nowMillis
                            && (counter.windowStart == 0 || nowMillis - counter.windowStart > windowMillis);
                }
            });
        }

        private static final class Counter {
            private int failures;
            private long windowStart;
            private long lockedUntil;
        }
    }

    // ------------------------------------------------------------------
    // Command line entry points
    // ------------------------------------------------------------------

    public static void main(String[] args) {
        if (args.length > 0 && "-i".equals(args[0])) {
            interactive();
        } else {
            demo();
        }
    }

    private static void demo() {
        InMemoryAccountStore store = new InMemoryAccountStore();
        LoginService service = new LoginService(store, new PasswordHasher(60_000));

        System.out.println("register alice: " + service.register("alice", "correct horse"));
        System.out.println("register bob  : " + service.register("bob", "Tr0ubador&x9"));
        System.out.println("stored digest : " + store.find("alice").passwordHash());
        System.out.println();

        System.out.println("-- credentials --");
        report(service, "alice", "correct horse");
        report(service, "alice", "Correct horse");
        report(service, "alice", "correct horses");
        report(service, "bob", "Tr0ubador&x9");
        report(service, "dave", "correct horse");
        System.out.println("accounts now: " + store.count() + " (the unknown name was not created)");
        System.out.println();

        System.out.println("-- lockout after five failures --");
        for (int i = 1; i <= 5; i++) {
            report(service, "alice", "guess-" + i);
        }
        report(service, "alice", "correct horse");
        System.out.println();

        System.out.println("-- one derivation per attempt, whoever is named --");
        time(service, "carol", "Tr0ubador&x9");
        service.register("carol", "Tr0ubador&x9");
        time(service, "carol", "Tr0ubador&x9");
        time(service, "carol", "wrong-password");
        time(service, "nobody", "Tr0ubador&x9");
    }

    private static void report(LoginService service, String username, String password) {
        LoginOutcome outcome = service.login(username, password);
        System.out.printf("%-10s %-16s -> %-19s %s%n", username, shorten(password), outcome.status(),
                outcome.message());
    }

    private static void time(LoginService service, String username, String password) {
        long start = System.nanoTime();
        LoginOutcome outcome = service.login(username, password);
        long millis = (System.nanoTime() - start) / 1_000_000;
        System.out.printf("%-10s %-16s -> %-19s %4d ms%n", username, shorten(password), outcome.status(), millis);
    }

    private static String shorten(String password) {
        return password.length() > 15 ? password.substring(0, 12) + "..." : password;
    }

    private static void interactive() {
        Console console = System.console();
        if (console == null) {
            System.out.println("Interactive mode needs a terminal. Run with no arguments for the"
                    + " scripted demo instead.");
            return;
        }
        InMemoryAccountStore store = new InMemoryAccountStore();
        LoginService service = new LoginService(store, new PasswordHasher());
        console.format("Accounts live in memory only, so nothing is kept after you quit.");
        console.format("Commands: register <name>, login <name>, unlock <name>, quit%n");
        while (true) {
            String line = console.readLine("app> ");
            if (line == null || "quit".equalsIgnoreCase(line.trim())) {
                return;
            }
            String[] parts = line.trim().split("\\s+", 2);
            String command = parts[0].toLowerCase(java.util.Locale.ROOT);
            String username = parts.length > 1 ? parts[1].trim() : null;
            if (username == null || username.isEmpty()) {
                console.format("Say 'register <name>', 'login <name>' or 'unlock <name>'.%n");
                continue;
            }
            char[] secret = null;
            switch (command) {
                case "register":
                    secret = console.readPassword("password for %s: ", username);
                    if (secret == null) {
                        return;
                    }
                    console.format("%s%n", service.register(username, new String(secret)));
                    break;
                case "login":
                    secret = console.readPassword("password for %s: ", username);
                    if (secret == null) {
                        return;
                    }
                    LoginOutcome outcome = service.login(username, new String(secret));
                    console.format("%s%n", outcome.message());
                    if (outcome.granted()) {
                        console.format("session token: %s%n", outcome.sessionToken());
                    }
                    break;
                case "unlock":
                    service.tracker.unlock(username);
                    console.format("cleared failed-attempt state for %s%n", username);
                    break;
                default:
                    console.format("Unknown command '%s'.%n", command);
            }
            if (secret != null) {
                Arrays.fill(secret, '\0');
            }
        }
    }
}
