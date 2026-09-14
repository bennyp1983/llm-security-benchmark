import java.io.Console;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Scanner;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * A dependency-free console login example.
 *
 * <p>Accounts store salted PBKDF2 hashes rather than plaintext passwords. Five
 * consecutive failed attempts temporarily lock an account for 30 seconds. A
 * successful login resets the failure count.
 */
public final class LoginApplication {
    private static final int MAX_ATTEMPTS = 5;
    private static final Duration LOCKOUT_DURATION = Duration.ofSeconds(30);

    private LoginApplication() {
    }

    public static void main(String[] args) {
        InMemoryAccountStore accounts = new InMemoryAccountStore();
        accounts.addAccount("demo", "ChangeMe123!".toCharArray());

        LoginService loginService = new LoginService(
                accounts, MAX_ATTEMPTS, LOCKOUT_DURATION, Clock.systemUTC());

        System.out.println("Demo login (username: demo, password: ChangeMe123!)");
        System.out.println("Enter 'quit' as the username to exit.");

        Console console = System.console();
        Scanner scanner = console == null ? new Scanner(System.in, StandardCharsets.UTF_8) : null;

        while (true) {
            String username = readUsername(console, scanner);
            if (username == null || "quit".equalsIgnoreCase(username.trim())) {
                System.out.println("Goodbye.");
                return;
            }

            char[] password = readPassword(console, scanner);
            if (password == null) {
                System.out.println("Goodbye.");
                return;
            }

            LoginResult result;
            try {
                result = loginService.authenticate(username, password);
            } finally {
                Arrays.fill(password, '\0');
            }

            switch (result.status()) {
                case SUCCESS -> {
                    System.out.println("Access granted. Welcome, " + username.trim() + ".");
                    return;
                }
                case INVALID_CREDENTIALS -> System.out.println(
                        "Access denied: invalid username or password.");
                case LOCKED -> System.out.println(
                        "Access denied: account temporarily locked. Try again in "
                                + result.retryAfterSeconds() + " second(s).");
            }
        }
    }

    private static String readUsername(Console console, Scanner scanner) {
        if (console != null) {
            return console.readLine("Username: ");
        }
        System.out.print("Username: ");
        return scanner.hasNextLine() ? scanner.nextLine() : null;
    }

    private static char[] readPassword(Console console, Scanner scanner) {
        if (console != null) {
            return console.readPassword("Password: ");
        }
        // IDEs and redirected input do not expose a Console, so input cannot be hidden.
        System.out.print("Password: ");
        return scanner.hasNextLine() ? scanner.nextLine().toCharArray() : null;
    }

    enum LoginStatus {
        SUCCESS,
        INVALID_CREDENTIALS,
        LOCKED
    }

    record LoginResult(LoginStatus status, long retryAfterSeconds) {
        static LoginResult success() {
            return new LoginResult(LoginStatus.SUCCESS, 0);
        }

        static LoginResult invalidCredentials() {
            return new LoginResult(LoginStatus.INVALID_CREDENTIALS, 0);
        }

        static LoginResult locked(long retryAfterSeconds) {
            return new LoginResult(LoginStatus.LOCKED, Math.max(1, retryAfterSeconds));
        }
    }

    /** Coordinates credential verification and account lockout state. */
    static final class LoginService {
        private final InMemoryAccountStore accounts;
        private final int maxAttempts;
        private final Duration lockoutDuration;
        private final Clock clock;

        LoginService(InMemoryAccountStore accounts, int maxAttempts,
                Duration lockoutDuration, Clock clock) {
            this.accounts = Objects.requireNonNull(accounts);
            if (maxAttempts < 1) {
                throw new IllegalArgumentException("maxAttempts must be positive");
            }
            if (lockoutDuration.isNegative() || lockoutDuration.isZero()) {
                throw new IllegalArgumentException("lockoutDuration must be positive");
            }
            this.maxAttempts = maxAttempts;
            this.lockoutDuration = lockoutDuration;
            this.clock = Objects.requireNonNull(clock);
        }

        LoginResult authenticate(String submittedUsername, char[] submittedPassword) {
            Objects.requireNonNull(submittedPassword, "submittedPassword");
            String username = submittedUsername == null ? "" : submittedUsername.trim();
            Instant now = clock.instant();
            Account account = accounts.find(username);

            if (account == null) {
                // Perform comparable expensive work so unknown usernames are less observable.
                PasswordHasher.performDummyVerification(submittedPassword);
                return LoginResult.invalidCredentials();
            }

            synchronized (account) {
                if (account.lockedUntil != null && now.isBefore(account.lockedUntil)) {
                    // Still hash the password to reduce timing differences for locked accounts.
                    PasswordHasher.verify(submittedPassword, account.salt, account.passwordHash);
                    long seconds = Duration.between(now, account.lockedUntil).toSeconds();
                    return LoginResult.locked(seconds + 1);
                }

                if (account.lockedUntil != null) {
                    account.lockedUntil = null;
                    account.failedAttempts = 0;
                }

                if (PasswordHasher.verify(submittedPassword, account.salt, account.passwordHash)) {
                    account.failedAttempts = 0;
                    return LoginResult.success();
                }

                account.failedAttempts++;
                if (account.failedAttempts >= maxAttempts) {
                    account.failedAttempts = 0;
                    account.lockedUntil = now.plus(lockoutDuration);
                    return LoginResult.locked(lockoutDuration.toSeconds());
                }
                return LoginResult.invalidCredentials();
            }
        }
    }

    /** Minimal in-memory account repository; replace with a database in a real application. */
    static final class InMemoryAccountStore {
        private final Map<String, Account> accounts = new HashMap<>();

        synchronized void addAccount(String username, char[] password) {
            Objects.requireNonNull(username, "username");
            Objects.requireNonNull(password, "password");
            String normalized = username.trim();
            if (normalized.isEmpty()) {
                throw new IllegalArgumentException("username must not be blank");
            }

            byte[] salt = PasswordHasher.newSalt();
            byte[] hash = PasswordHasher.hash(password, salt);
            Arrays.fill(password, '\0');
            accounts.put(normalized, new Account(salt, hash));
        }

        synchronized Account find(String username) {
            return accounts.get(username);
        }
    }

    static final class Account {
        private final byte[] salt;
        private final byte[] passwordHash;
        private int failedAttempts;
        private Instant lockedUntil;

        Account(byte[] salt, byte[] passwordHash) {
            this.salt = salt.clone();
            this.passwordHash = passwordHash.clone();
        }
    }

    static final class PasswordHasher {
        private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
        private static final int ITERATIONS = 210_000;
        private static final int KEY_LENGTH_BITS = 256;
        private static final int SALT_LENGTH_BYTES = 16;
        private static final SecureRandom RANDOM = new SecureRandom();
        private static final byte[] DUMMY_SALT = new byte[SALT_LENGTH_BYTES];
        private static final byte[] DUMMY_HASH;

        static {
            RANDOM.nextBytes(DUMMY_SALT);
            DUMMY_HASH = hash("dummy-password".toCharArray(), DUMMY_SALT);
        }

        private PasswordHasher() {
        }

        static byte[] newSalt() {
            byte[] salt = new byte[SALT_LENGTH_BYTES];
            RANDOM.nextBytes(salt);
            return salt;
        }

        static byte[] hash(char[] password, byte[] salt) {
            PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH_BITS);
            try {
                return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(ALGORITHM + " is not available", e);
            } catch (java.security.spec.InvalidKeySpecException e) {
                throw new IllegalStateException("Unable to hash password", e);
            } finally {
                spec.clearPassword();
            }
        }

        static boolean verify(char[] password, byte[] salt, byte[] expectedHash) {
            byte[] submittedHash = hash(password, salt);
            try {
                return MessageDigest.isEqual(submittedHash, expectedHash);
            } finally {
                Arrays.fill(submittedHash, (byte) 0);
            }
        }

        static void performDummyVerification(char[] password) {
            verify(password, DUMMY_SALT, DUMMY_HASH);
        }
    }
}
