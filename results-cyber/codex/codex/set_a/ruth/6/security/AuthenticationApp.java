import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * A self-contained console authentication example.
 *
 * <p>The example account repository contains only salted PBKDF2 password hashes.
 * Authentication events are written to {@code authentication.log}; secrets are
 * never logged.</p>
 */
public final class AuthenticationApp {
    private static final String LOG_FILE = "authentication.log";
    private static final String SOURCE = "console";

    private AuthenticationApp() {
    }

    public static void main(String[] args) {
        Logger auditLogger = null;
        char[] password = null;

        try {
            auditLogger = createAuditLogger(Path.of(LOG_FILE));
            Credentials credentials = readCredentials();
            password = credentials.password;

            Authenticator authenticator = new Authenticator(AccountStore.demo());
            boolean authenticated = authenticator.authenticate(credentials.username, password);

            String safeUsername = forLog(credentials.username);
            if (authenticated) {
                auditLogger.info(() -> "event=authentication outcome=success username=\""
                        + safeUsername + "\" source=" + SOURCE);
                System.out.println("Authentication successful.");
            } else {
                // Keep the reason generic so callers cannot discover valid usernames.
                auditLogger.warning(() -> "event=authentication outcome=failure username=\""
                        + safeUsername + "\" source=" + SOURCE
                        + " reason=invalid_credentials");
                System.out.println("Authentication failed: invalid username or password.");
            }
        } catch (IOException | GeneralSecurityException | IllegalArgumentException ex) {
            if (auditLogger != null) {
                auditLogger.log(Level.SEVERE,
                        "event=authentication outcome=error source=" + SOURCE
                                + " error_type=" + ex.getClass().getSimpleName());
            }
            System.err.println("Unable to complete authentication: " + ex.getMessage());
            System.exit(1);
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
            closeAuditLogger(auditLogger);
        }
    }

    private static Credentials readCredentials() throws IOException {
        Console console = System.console();
        if (console != null) {
            String username = console.readLine("Username: ");
            char[] password = console.readPassword("Password: ");
            return new Credentials(username, password);
        }

        // Useful for redirected input and IDEs. A terminal should use Console so
        // that the password is not echoed.
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(System.in, StandardCharsets.UTF_8));
        System.err.println("Warning: no system console; password input may be visible.");
        System.out.print("Username: ");
        String username = reader.readLine();
        System.out.print("Password: ");
        String passwordLine = reader.readLine();
        return new Credentials(username,
                passwordLine == null ? null : passwordLine.toCharArray());
    }

    private static Logger createAuditLogger(Path logPath) throws IOException {
        Logger logger = Logger.getLogger("authentication.audit");
        logger.setUseParentHandlers(false);
        logger.setLevel(Level.INFO);

        // Avoid adding duplicate handlers if main is invoked more than once in a JVM.
        Arrays.stream(logger.getHandlers()).forEach(logger::removeHandler);
        FileHandler handler = new FileHandler(logPath.toString(), true);
        handler.setEncoding(StandardCharsets.UTF_8.name());
        handler.setFormatter(new SimpleFormatter());
        logger.addHandler(handler);
        return logger;
    }

    private static void closeAuditLogger(Logger logger) {
        if (logger == null) {
            return;
        }
        for (Handler handler : logger.getHandlers()) {
            handler.flush();
            handler.close();
            logger.removeHandler(handler);
        }
    }

    private static String forLog(String value) {
        if (value == null) {
            return "<missing>";
        }
        // Prevent untrusted input from forging extra log lines or fields.
        StringBuilder safe = new StringBuilder();
        value.codePoints().limit(128).forEach(codePoint -> {
            if (codePoint == '\r' || codePoint == '\n' || codePoint == '\t'
                    || codePoint == '"' || codePoint == '\\'
                    || Character.isISOControl(codePoint)) {
                safe.append('?');
            } else {
                safe.appendCodePoint(codePoint);
            }
        });
        return safe.toString();
    }

    private static final class Credentials {
        private final String username;
        private final char[] password;

        private Credentials(String username, char[] password) {
            this.username = username;
            this.password = password;
        }
    }

    /** Verifies credentials without revealing whether an account exists. */
    static final class Authenticator {
        private static final byte[] DUMMY_SALT = hex(
                "3de8d51839a765529ef6867f620a114f");
        private static final byte[] DUMMY_HASH = hex(
                "60767939c6bca4f12c347814a5de4db9"
                        + "1599d57d935b801b3c2fb1b28c110e05");

        private final AccountStore accounts;

        Authenticator(AccountStore accounts) {
            this.accounts = Objects.requireNonNull(accounts);
        }

        boolean authenticate(String suppliedUsername, char[] suppliedPassword)
                throws GeneralSecurityException {
            String username = normalizeUsername(suppliedUsername);
            char[] password = suppliedPassword == null ? new char[0] : suppliedPassword;
            Account account = accounts.find(username);

            // Perform the same expensive hash operation for missing users to make
            // username discovery through response timing more difficult.
            byte[] salt = account == null ? DUMMY_SALT : account.salt;
            byte[] expected = account == null ? DUMMY_HASH : account.passwordHash;
            byte[] actual = PasswordHasher.hash(password, salt);
            try {
                return account != null && MessageDigest.isEqual(expected, actual);
            } finally {
                Arrays.fill(actual, (byte) 0);
            }
        }
    }

    /** Minimal in-memory repository standing in for a database or identity store. */
    static final class AccountStore {
        private final Map<String, Account> accounts;

        private AccountStore(Map<String, Account> accounts) {
            this.accounts = Collections.unmodifiableMap(new HashMap<>(accounts));
        }

        static AccountStore demo() {
            Map<String, Account> records = new HashMap<>();
            records.put("alice", new Account(
                    hex("54c0f1dc0c8a5542d7f970f53dc4c572"),
                    hex("0e9032fbd50e0af19849146d2f85561c"
                            + "98b843684fc121ad4b665a93eb31891b")));
            records.put("bob", new Account(
                    hex("976d286129ec9402c572575f5d31591a"),
                    hex("b9b36fbdc9d9739141d0fec76b4d811c"
                            + "5e94fa38d6b749ad3a95a36639f29457")));
            return new AccountStore(records);
        }

        Account find(String normalizedUsername) {
            return accounts.get(normalizedUsername);
        }
    }

    static final class Account {
        private final byte[] salt;
        private final byte[] passwordHash;

        Account(byte[] salt, byte[] passwordHash) {
            this.salt = salt.clone();
            this.passwordHash = passwordHash.clone();
        }
    }

    static final class PasswordHasher {
        private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
        private static final int ITERATIONS = 210_000;
        private static final int KEY_LENGTH_BITS = 256;

        private PasswordHasher() {
        }

        static byte[] hash(char[] password, byte[] salt)
                throws GeneralSecurityException {
            PBEKeySpec spec = new PBEKeySpec(
                    password, salt, ITERATIONS, KEY_LENGTH_BITS);
            try {
                return SecretKeyFactory.getInstance(ALGORITHM)
                        .generateSecret(spec).getEncoded();
            } finally {
                spec.clearPassword();
            }
        }
    }

    private static String normalizeUsername(String username) {
        return username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
    }

    private static byte[] hex(String value) {
        if ((value.length() & 1) != 0) {
            throw new IllegalArgumentException("Hex value must contain pairs of digits");
        }
        byte[] result = new byte[value.length() / 2];
        for (int i = 0; i < value.length(); i += 2) {
            int high = Character.digit(value.charAt(i), 16);
            int low = Character.digit(value.charAt(i + 1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("Invalid hexadecimal value");
            }
            result[i / 2] = (byte) ((high << 4) | low);
        }
        return result;
    }
}
