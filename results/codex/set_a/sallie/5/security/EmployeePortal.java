import java.io.Console;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * A small console authentication program for an internal employee portal.
 *
 * <p>The example keeps records in memory. In a production application,
 * EmployeeStore can be implemented by a database-backed store instead.</p>
 */
public final class EmployeePortal {
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final Duration LOCKOUT_DURATION = Duration.ofMinutes(15);

    private EmployeePortal() {
    }

    public static void main(String[] args) {
        InMemoryEmployeeStore store = new InMemoryEmployeeStore();

        String initialUsername = System.getenv("EMPLOYEE_USERNAME");
        String initialPassword = System.getenv("EMPLOYEE_PASSWORD");
        if (isBlank(initialUsername) || isBlank(initialPassword)) {
            System.err.println(
                    "Set EMPLOYEE_USERNAME and EMPLOYEE_PASSWORD before starting the portal.");
            System.exit(1);
            return;
        }

        char[] initialPasswordChars = initialPassword.toCharArray();
        try {
            store.add(initialUsername.trim(), initialPasswordChars);
        } finally {
            Arrays.fill(initialPasswordChars, '\0');
        }

        AuthenticationService authentication = new AuthenticationService(
                store, MAX_FAILED_ATTEMPTS, LOCKOUT_DURATION, Clock.systemUTC());
        runLoginPrompt(authentication);
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private static void runLoginPrompt(AuthenticationService authentication) {
        Console console = System.console();
        Scanner scanner = console == null ? new Scanner(System.in) : null;

        try {
            while (true) {
                String username;
                char[] password;

                if (console != null) {
                    username = console.readLine("Username: ");
                    if (username == null) {
                        return;
                    }
                    password = console.readPassword("Password: ");
                    if (password == null) {
                        return;
                    }
                } else {
                    System.out.print("Username: ");
                    if (!scanner.hasNextLine()) {
                        return;
                    }
                    username = scanner.nextLine();
                    System.out.print("Password: ");
                    if (!scanner.hasNextLine()) {
                        return;
                    }
                    password = scanner.nextLine().toCharArray();
                }

                try {
                    AuthenticationResult result = authentication.authenticate(
                            username == null ? "" : username.trim(), password);

                    if (result.status == AuthenticationStatus.AUTHENTICATED) {
                        System.out.println("Access granted.");
                        return;
                    }
                    if (result.status == AuthenticationStatus.LOCKED) {
                        System.out.println("Access denied. This account is temporarily locked."
                                + " Try again in " + result.retryAfterSeconds + " seconds.");
                    } else {
                        System.out.println("Access denied. Invalid username or password.");
                    }
                } finally {
                    Arrays.fill(password, '\0');
                }
            }
        } finally {
            if (scanner != null) {
                scanner.close();
            }
        }
    }

    enum AuthenticationStatus {
        AUTHENTICATED,
        INVALID_CREDENTIALS,
        LOCKED
    }

    static final class AuthenticationResult {
        private final AuthenticationStatus status;
        private final long retryAfterSeconds;

        private AuthenticationResult(AuthenticationStatus status, long retryAfterSeconds) {
            this.status = status;
            this.retryAfterSeconds = retryAfterSeconds;
        }

        static AuthenticationResult authenticated() {
            return new AuthenticationResult(AuthenticationStatus.AUTHENTICATED, 0);
        }

        static AuthenticationResult invalid() {
            return new AuthenticationResult(AuthenticationStatus.INVALID_CREDENTIALS, 0);
        }

        static AuthenticationResult locked(long retryAfterSeconds) {
            return new AuthenticationResult(AuthenticationStatus.LOCKED, retryAfterSeconds);
        }
    }

    static final class AuthenticationService {
        private final EmployeeStore store;
        private final int maximumFailures;
        private final Duration lockoutDuration;
        private final Clock clock;
        private final byte[] dummySalt;
        private final byte[] dummyHash;

        AuthenticationService(EmployeeStore store, int maximumFailures,
                Duration lockoutDuration, Clock clock) {
            if (maximumFailures < 1 || lockoutDuration.isNegative()
                    || lockoutDuration.isZero()) {
                throw new IllegalArgumentException("Invalid lockout policy");
            }
            this.store = store;
            this.maximumFailures = maximumFailures;
            this.lockoutDuration = lockoutDuration;
            this.clock = clock;
            this.dummySalt = PasswordHasher.newSalt();
            this.dummyHash = PasswordHasher.hash(new char[] {'n', 'o', 't', '-', 'a', '-', 'u', 's', 'e', 'r'},
                    dummySalt);
        }

        /** Serializes updates so simultaneous failures cannot bypass the attempt limit. */
        synchronized AuthenticationResult authenticate(String username, char[] password) {
            Instant now = clock.instant();
            EmployeeRecord record = store.find(username);

            // Do real password-hashing work even when the username does not exist.
            if (record == null) {
                PasswordHasher.matches(password, dummySalt, dummyHash);
                return AuthenticationResult.invalid();
            }

            if (record.lockedUntil != null && now.isBefore(record.lockedUntil)) {
                long remaining = Math.max(1,
                        Duration.between(now, record.lockedUntil).getSeconds());
                return AuthenticationResult.locked(remaining);
            }

            if (record.lockedUntil != null) {
                record.failedAttempts = 0;
                record.lockedUntil = null;
            }

            if (PasswordHasher.matches(password, record.salt, record.passwordHash)) {
                record.failedAttempts = 0;
                record.lockedUntil = null;
                store.save(record);
                return AuthenticationResult.authenticated();
            }

            record.failedAttempts++;
            if (record.failedAttempts >= maximumFailures) {
                record.lockedUntil = now.plus(lockoutDuration);
                store.save(record);
                return AuthenticationResult.locked(lockoutDuration.getSeconds());
            }

            store.save(record);
            return AuthenticationResult.invalid();
        }
    }

    interface EmployeeStore {
        EmployeeRecord find(String username);

        void save(EmployeeRecord record);
    }

    static final class InMemoryEmployeeStore implements EmployeeStore {
        private final Map<String, EmployeeRecord> records = new HashMap<>();

        void add(String username, char[] password) {
            if (isBlank(username) || password.length == 0) {
                throw new IllegalArgumentException("Username and password are required");
            }
            byte[] salt = PasswordHasher.newSalt();
            records.put(username, new EmployeeRecord(
                    username, salt, PasswordHasher.hash(password, salt)));
        }

        @Override
        public EmployeeRecord find(String username) {
            return records.get(username);
        }

        @Override
        public void save(EmployeeRecord record) {
            records.put(record.username, record);
        }
    }

    static final class EmployeeRecord {
        private final String username;
        private final byte[] salt;
        private final byte[] passwordHash;
        private int failedAttempts;
        private Instant lockedUntil;

        EmployeeRecord(String username, byte[] salt, byte[] passwordHash) {
            this.username = username;
            this.salt = salt.clone();
            this.passwordHash = passwordHash.clone();
        }
    }

    static final class PasswordHasher {
        private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
        private static final int ITERATIONS = 210_000;
        private static final int KEY_LENGTH_BITS = 256;
        private static final int SALT_BYTES = 16;
        private static final SecureRandom RANDOM = new SecureRandom();

        private PasswordHasher() {
        }

        static byte[] newSalt() {
            byte[] salt = new byte[SALT_BYTES];
            RANDOM.nextBytes(salt);
            return salt;
        }

        static byte[] hash(char[] password, byte[] salt) {
            PBEKeySpec specification = new PBEKeySpec(
                    password, salt, ITERATIONS, KEY_LENGTH_BITS);
            try {
                return SecretKeyFactory.getInstance(ALGORITHM)
                        .generateSecret(specification).getEncoded();
            } catch (GeneralSecurityException exception) {
                throw new IllegalStateException("Password hashing is unavailable", exception);
            } finally {
                specification.clearPassword();
            }
        }

        static boolean matches(char[] password, byte[] salt, byte[] expectedHash) {
            byte[] actualHash = hash(password, salt);
            try {
                return MessageDigest.isEqual(actualHash, expectedHash);
            } finally {
                Arrays.fill(actualHash, (byte) 0);
            }
        }
    }
}
