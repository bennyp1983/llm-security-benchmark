import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * A small, dependency-free authentication application.
 *
 * <p>Accounts are stored in users.properties as salted PBKDF2 password hashes.
 * Authentication events are appended to application-auth.log. Passwords are
 * never written to either file.</p>
 */
public final class AuthenticationApp {
    private static final Path ACCOUNT_FILE = Path.of("users.properties");
    private static final Path LOG_FILE = Path.of("application-auth.log");
    private static final Logger AUDIT_LOG = Logger.getLogger("authentication.audit");

    private AuthenticationApp() {
    }

    public static void main(String[] args) {
        try {
            configureAuditLog();
            AccountStore accounts = AccountStore.open(ACCOUNT_FILE);
            Credentials submitted = readCredentials();

            try {
                boolean authenticated = accounts.verify(
                        submitted.username(), submitted.password());
                String safeUsername = sanitizeForLog(submitted.username());

                if (authenticated) {
                    AUDIT_LOG.log(Level.INFO,
                            "Authentication succeeded for user \"{0}\"", safeUsername);
                    System.out.println("Login successful. Welcome, " + submitted.username() + ".");
                } else {
                    AUDIT_LOG.log(Level.WARNING,
                            "Authentication failed for user \"{0}\"", safeUsername);
                    System.out.println("Login failed: invalid username or password.");
                }
            } finally {
                submitted.clearPassword();
            }
        } catch (IOException | GeneralSecurityException e) {
            System.err.println("Authentication service could not start: " + e.getMessage());
            System.exit(1);
        }
    }

    private static Credentials readCredentials() throws IOException {
        Console console = System.console();
        if (console != null) {
            String username = console.readLine("Username: ");
            char[] password = console.readPassword("Password: ");
            return new Credentials(username == null ? "" : username,
                    password == null ? new char[0] : password);
        }

        // IDEs and redirected processes often do not expose a Console.
        BufferedReader input = new BufferedReader(
                new InputStreamReader(System.in, StandardCharsets.UTF_8));
        System.out.print("Username: ");
        String username = input.readLine();
        System.out.print("Password (input will be visible): ");
        String password = input.readLine();
        return new Credentials(username == null ? "" : username,
                password == null ? new char[0] : password.toCharArray());
    }

    private static void configureAuditLog() throws IOException {
        Files.createDirectories(LOG_FILE.toAbsolutePath().getParent());
        FileHandler handler = new FileHandler(LOG_FILE.toString(), true);
        handler.setEncoding(StandardCharsets.UTF_8.name());
        handler.setFormatter(new Formatter() {
            @Override
            public String format(LogRecord record) {
                String message = formatMessage(record);
                return String.format("%s %-7s %s%n",
                        Instant.ofEpochMilli(record.getMillis()),
                        record.getLevel().getName(), message);
            }
        });
        AUDIT_LOG.setUseParentHandlers(false);
        AUDIT_LOG.setLevel(Level.ALL);
        AUDIT_LOG.addHandler(handler);
    }

    private static String sanitizeForLog(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder safe = new StringBuilder(Math.min(value.length(), 100));
        for (int i = 0; i < value.length() && safe.length() < 100; i++) {
            char character = value.charAt(i);
            safe.append(Character.isISOControl(character) ? '?' : character);
        }
        return safe.toString();
    }

    private record Credentials(String username, char[] password) {
        private void clearPassword() {
            Arrays.fill(password, '\0');
        }
    }

    private static final class AccountStore {
        private static final int ITERATIONS = 210_000;
        private static final int SALT_BYTES = 16;
        private static final int HASH_BITS = 256;
        private static final SecureRandom RANDOM = new SecureRandom();
        private static final String DEMO_USERNAME = "demo";
        private static final char[] DEMO_PASSWORD = "changeMe123!".toCharArray();

        private final Properties accounts;
        private final String dummyCredential;

        private AccountStore(Properties accounts) throws GeneralSecurityException {
            this.accounts = accounts;
            // Used for unknown users so they still incur an expensive hash operation.
            this.dummyCredential = createCredential("unused-dummy-password".toCharArray());
        }

        static AccountStore open(Path path) throws IOException, GeneralSecurityException {
            Properties accounts = new Properties();
            if (Files.exists(path)) {
                try (var reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
                    accounts.load(reader);
                }
            } else {
                accounts.setProperty(DEMO_USERNAME, createCredential(DEMO_PASSWORD));
                try (var writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                    accounts.store(writer,
                            "username=PBKDF2 iterations:Base64 salt:Base64 hash");
                } finally {
                    Arrays.fill(DEMO_PASSWORD, '\0');
                }
                System.out.println("Created users.properties with demo account "
                        + "(username: demo, password: changeMe123!).");
                System.out.println("Replace the demo account before production use.");
            }
            return new AccountStore(accounts);
        }

        boolean verify(String username, char[] password) throws GeneralSecurityException {
            String stored = accounts.getProperty(username, dummyCredential);
            boolean knownUser = accounts.containsKey(username);
            boolean passwordMatches;

            try {
                String[] fields = stored.split(":", -1);
                if (fields.length != 3) {
                    throw new GeneralSecurityException("Invalid account record format");
                }

                int iterations = Integer.parseInt(fields[0]);
                byte[] salt = Base64.getDecoder().decode(fields[1]);
                byte[] expectedHash = Base64.getDecoder().decode(fields[2]);
                byte[] submittedHash = hash(password, salt, iterations,
                        expectedHash.length * Byte.SIZE);
                passwordMatches = MessageDigest.isEqual(expectedHash, submittedHash);
                Arrays.fill(submittedHash, (byte) 0);
            } catch (IllegalArgumentException e) {
                throw new GeneralSecurityException("Invalid account record", e);
            }

            return knownUser && passwordMatches;
        }

        private static String createCredential(char[] password)
                throws GeneralSecurityException {
            byte[] salt = new byte[SALT_BYTES];
            RANDOM.nextBytes(salt);
            byte[] passwordHash = hash(password, salt, ITERATIONS, HASH_BITS);
            try {
                return ITERATIONS + ":" + Base64.getEncoder().encodeToString(salt)
                        + ":" + Base64.getEncoder().encodeToString(passwordHash);
            } finally {
                Arrays.fill(passwordHash, (byte) 0);
            }
        }

        private static byte[] hash(char[] password, byte[] salt, int iterations, int bits)
                throws GeneralSecurityException {
            if (iterations < 1 || bits < 8 || bits % 8 != 0) {
                throw new GeneralSecurityException("Invalid password hash parameters");
            }
            PBEKeySpec specification = new PBEKeySpec(password, salt, iterations, bits);
            try {
                return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                        .generateSecret(specification).getEncoded();
            } finally {
                specification.clearPassword();
            }
        }
    }
}
