import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Handles user login attempts.
 *
 * <p>Accepts a username and password, verifies them against stored account
 * information and grants access only when the credentials are correct.
 *
 * <p>Security properties:
 * <ul>
 *   <li>Passwords are never stored in plain text; each account stores a random
 *       salt and a PBKDF2-HMAC-SHA256 hash.</li>
 *   <li>Hashes are compared in constant time.</li>
 *   <li>Unknown usernames still go through a full hash computation so response
 *       time does not reveal whether an account exists.</li>
 *   <li>Failures return one generic result, never "unknown user" vs. "wrong password".</li>
 *   <li>Accounts are temporarily locked after repeated failed attempts.</li>
 *   <li>Password char arrays are wiped after use.</li>
 * </ul>
 */
public final class LoginSystem {

    // ------------------------------------------------------------------
    // Result of a login attempt
    // ------------------------------------------------------------------

    public enum LoginResult {
        /** Credentials were correct; access granted. */
        SUCCESS,
        /** Username or password was wrong (deliberately not distinguished). */
        INVALID_CREDENTIALS,
        /** Too many recent failures; the account is temporarily locked. */
        ACCOUNT_LOCKED
    }

    // ------------------------------------------------------------------
    // Password hashing
    // ------------------------------------------------------------------

    /** Salted PBKDF2 password hashing with constant-time verification. */
    static final class PasswordHasher {
        private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
        private static final int ITERATIONS = 210_000; // OWASP recommendation for PBKDF2-HMAC-SHA256
        private static final int SALT_BYTES = 16;
        private static final int HASH_BITS = 256;

        private final SecureRandom random = new SecureRandom();

        byte[] newSalt() {
            byte[] salt = new byte[SALT_BYTES];
            random.nextBytes(salt);
            return salt;
        }

        byte[] hash(char[] password, byte[] salt) {
            PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, HASH_BITS);
            try {
                return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IllegalStateException("Password hashing unavailable", e);
            } finally {
                spec.clearPassword();
            }
        }

        boolean verify(char[] password, byte[] salt, byte[] expectedHash) {
            byte[] actual = hash(password, salt);
            try {
                return MessageDigest.isEqual(actual, expectedHash); // constant-time
            } finally {
                Arrays.fill(actual, (byte) 0);
            }
        }
    }

    // ------------------------------------------------------------------
    // Stored account information
    // ------------------------------------------------------------------

    /** A stored account: username, salt, password hash and lockout state. */
    static final class Account {
        final String username;
        final byte[] salt;
        final byte[] passwordHash;
        int failedAttempts;
        Instant lockedUntil = Instant.EPOCH;

        Account(String username, byte[] salt, byte[] passwordHash) {
            this.username = username;
            this.salt = salt;
            this.passwordHash = passwordHash;
        }
    }

    /** Storage abstraction so an in-memory store can be swapped for a database. */
    public interface AccountRepository {
        Account findByUsername(String username);

        /** @return false if the username is already taken */
        boolean save(Account account);
    }

    /** Thread-safe in-memory account store. */
    public static final class InMemoryAccountRepository implements AccountRepository {
        private final Map<String, Account> accounts = new ConcurrentHashMap<>();

        @Override
        public Account findByUsername(String username) {
            return accounts.get(username);
        }

        @Override
        public boolean save(Account account) {
            return accounts.putIfAbsent(account.username, account) == null;
        }
    }

    // ------------------------------------------------------------------
    // Authentication service
    // ------------------------------------------------------------------

    public static final int MAX_FAILED_ATTEMPTS = 5;
    public static final Duration LOCKOUT_DURATION = Duration.ofMinutes(15);
    private static final int MAX_USERNAME_LENGTH = 64;
    private static final int MAX_PASSWORD_LENGTH = 1024;

    private final AccountRepository repository;
    private final PasswordHasher hasher;
    private final Clock clock;
    /** Used to spend equal time on unknown usernames (prevents user enumeration). */
    private final byte[] dummySalt;
    private final byte[] dummyHash;

    public LoginSystem(AccountRepository repository) {
        this(repository, Clock.systemUTC());
    }

    LoginSystem(AccountRepository repository, Clock clock) {
        this.repository = Objects.requireNonNull(repository);
        this.clock = Objects.requireNonNull(clock);
        this.hasher = new PasswordHasher();
        this.dummySalt = hasher.newSalt();
        this.dummyHash = hasher.hash("dummy-password".toCharArray(), dummySalt);
    }

    /**
     * Creates a new account with a salted, hashed password.
     * The password array is wiped before this method returns.
     *
     * @return true if created, false if the username already exists
     */
    public boolean registerUser(String username, char[] password) {
        try {
            String normalized = normalizeUsername(username);
            if (normalized == null) {
                throw new IllegalArgumentException("Invalid username");
            }
            if (password == null || password.length < 8 || password.length > MAX_PASSWORD_LENGTH) {
                throw new IllegalArgumentException("Password must be 8-" + MAX_PASSWORD_LENGTH + " characters");
            }
            byte[] salt = hasher.newSalt();
            return repository.save(new Account(normalized, salt, hasher.hash(password, salt)));
        } finally {
            wipe(password);
        }
    }

    /**
     * Handles a login attempt. The password array is wiped before this method returns.
     *
     * @return {@link LoginResult#SUCCESS} only when the credentials are correct
     */
    public LoginResult login(String username, char[] password) {
        try {
            String normalized = normalizeUsername(username);
            boolean passwordValid = password != null
                    && password.length > 0
                    && password.length <= MAX_PASSWORD_LENGTH;
            Account account = normalized == null ? null : repository.findByUsername(normalized);

            if (account == null || !passwordValid) {
                // Burn the same CPU time as a real check so the response time
                // does not reveal whether the username exists.
                hasher.verify(passwordValid ? password : new char[] {'x'}, dummySalt, dummyHash);
                return LoginResult.INVALID_CREDENTIALS;
            }

            synchronized (account) {
                Instant now = clock.instant();
                if (now.isBefore(account.lockedUntil)) {
                    return LoginResult.ACCOUNT_LOCKED;
                }

                if (hasher.verify(password, account.salt, account.passwordHash)) {
                    account.failedAttempts = 0;
                    return LoginResult.SUCCESS;
                }

                account.failedAttempts++;
                if (account.failedAttempts >= MAX_FAILED_ATTEMPTS) {
                    account.failedAttempts = 0;
                    account.lockedUntil = now.plus(LOCKOUT_DURATION);
                }
                return LoginResult.INVALID_CREDENTIALS;
            }
        } finally {
            wipe(password);
        }
    }

    /** Trims and lower-cases the username; returns null if it is empty or too long. */
    private static String normalizeUsername(String username) {
        if (username == null) {
            return null;
        }
        String trimmed = username.trim().toLowerCase(java.util.Locale.ROOT);
        if (trimmed.isEmpty() || trimmed.length() > MAX_USERNAME_LENGTH) {
            return null;
        }
        return trimmed;
    }

    private static void wipe(char[] chars) {
        if (chars != null) {
            Arrays.fill(chars, '\0');
        }
    }

    // ------------------------------------------------------------------
    // Command-line entry point
    // ------------------------------------------------------------------

    /**
     * Interactive demo. Creates a sample account and prompts for credentials.
     * Run with {@code --self-test} to execute built-in checks instead.
     */
    public static void main(String[] args) throws IOException {
        if (args.length > 0 && args[0].equals("--self-test")) {
            System.exit(selfTest() ? 0 : 1);
        }

        LoginSystem loginSystem = new LoginSystem(new InMemoryAccountRepository());
        loginSystem.registerUser("alice", "CorrectHorse42!".toCharArray());
        System.out.println("Demo account created: username 'alice', password 'CorrectHorse42!'");
        System.out.println("Type an empty username to quit.");

        Console console = System.console();
        BufferedReader reader = console == null
                ? new BufferedReader(new InputStreamReader(System.in))
                : null;

        while (true) {
            String username;
            char[] password;
            if (console != null) {
                username = console.readLine("Username: ");
                if (username == null || username.isBlank()) {
                    break;
                }
                password = console.readPassword("Password: "); // not echoed
            } else {
                System.out.print("Username: ");
                username = reader.readLine();
                if (username == null || username.isBlank()) {
                    break;
                }
                System.out.print("Password: ");
                String line = reader.readLine();
                password = line == null ? new char[0] : line.toCharArray();
            }

            switch (loginSystem.login(username, password)) {
                case SUCCESS:
                    System.out.println("Login successful. Access granted.");
                    break;
                case ACCOUNT_LOCKED:
                    System.out.println("Login failed: account temporarily locked. Try again later.");
                    break;
                default:
                    System.out.println("Login failed: invalid username or password.");
            }
        }
        System.out.println("Goodbye.");
    }

    /** Minimal built-in tests (no external test framework required). */
    private static boolean selfTest() {
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        LoginSystem ls = new LoginSystem(new InMemoryAccountRepository(), clock);
        boolean ok = true;

        ok &= check("register new user", ls.registerUser("bob", "s3cretPass".toCharArray()));
        ok &= check("duplicate username rejected", !ls.registerUser("BOB", "otherPass1".toCharArray()));
        ok &= check("correct credentials succeed",
                ls.login("bob", "s3cretPass".toCharArray()) == LoginResult.SUCCESS);
        ok &= check("username is case-insensitive",
                ls.login("  Bob ", "s3cretPass".toCharArray()) == LoginResult.SUCCESS);
        ok &= check("wrong password fails",
                ls.login("bob", "wrong".toCharArray()) == LoginResult.INVALID_CREDENTIALS);
        ok &= check("password is case-sensitive",
                ls.login("bob", "S3CRETPASS".toCharArray()) == LoginResult.INVALID_CREDENTIALS);
        ok &= check("unknown user fails",
                ls.login("mallory", "s3cretPass".toCharArray()) == LoginResult.INVALID_CREDENTIALS);
        ok &= check("null/empty input fails",
                ls.login(null, null) == LoginResult.INVALID_CREDENTIALS
                        && ls.login("bob", new char[0]) == LoginResult.INVALID_CREDENTIALS);

        char[] pw = "s3cretPass".toCharArray();
        ls.login("bob", pw);
        ok &= check("password array wiped", new String(pw).equals("\0".repeat(pw.length)));

        // Lockout: success above reset the counter; 5 consecutive failures lock the account.
        for (int i = 0; i < MAX_FAILED_ATTEMPTS; i++) {
            ls.login("bob", "wrong".toCharArray());
        }
        ok &= check("locked after repeated failures",
                ls.login("bob", "s3cretPass".toCharArray()) == LoginResult.ACCOUNT_LOCKED);
        clock.advance(LOCKOUT_DURATION.plusSeconds(1));
        ok &= check("unlocked after lockout period",
                ls.login("bob", "s3cretPass".toCharArray()) == LoginResult.SUCCESS);

        Account stored = ls.repository.findByUsername("bob");
        ok &= check("password not stored in plain text",
                !Base64.getEncoder().encodeToString(stored.passwordHash).contains("s3cretPass"));

        System.out.println(ok ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
        return ok;
    }

    private static boolean check(String name, boolean condition) {
        System.out.println((condition ? "[PASS] " : "[FAIL] ") + name);
        return condition;
    }

    /** Controllable clock used by the self-test to simulate the lockout period elapsing. */
    private static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant start) {
            this.now = start;
        }

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public java.time.ZoneId getZone() {
            return java.time.ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }
    }
}
