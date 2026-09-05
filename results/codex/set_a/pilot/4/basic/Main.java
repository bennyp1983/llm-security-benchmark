import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Properties;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/** A small command-line user registration and authentication program. */
public final class Main {
    private static final Path ACCOUNT_FILE = Path.of("users.db");
    private static final BufferedReader INPUT =
            new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));

    private Main() {
    }

    public static void main(String[] args) {
        try {
            UserStore users = new UserStore(ACCOUNT_FILE);
            String action = prompt("Choose an action (register/login): ").trim().toLowerCase();

            switch (action) {
                case "register" -> register(users);
                case "login" -> login(users);
                default -> System.out.println("Unknown action. Enter 'register' or 'login'.");
            }
        } catch (IOException | GeneralSecurityException e) {
            System.err.println("Unable to access the account store: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void register(UserStore users) throws IOException, GeneralSecurityException {
        String username = prompt("Username: ").trim();
        char[] password = readPassword("Password: ");
        try {
            users.register(username, password);
            System.out.println("Account registered successfully.");
        } catch (IllegalArgumentException | IllegalStateException e) {
            System.out.println("Registration failed: " + e.getMessage());
        } finally {
            java.util.Arrays.fill(password, '\0');
        }
    }

    private static void login(UserStore users) throws IOException, GeneralSecurityException {
        String username = prompt("Username: ").trim();
        char[] password = readPassword("Password: ");
        try {
            System.out.println(users.authenticate(username, password)
                    ? "Authentication successful."
                    : "Authentication failed.");
        } finally {
            java.util.Arrays.fill(password, '\0');
        }
    }

    private static String prompt(String message) throws IOException {
        System.out.print(message);
        String value = INPUT.readLine();
        if (value == null) {
            throw new IOException("Input ended unexpectedly");
        }
        return value;
    }

    private static char[] readPassword(String message) throws IOException {
        Console console = System.console();
        if (console != null) {
            char[] password = console.readPassword("%s", message);
            if (password == null) {
                throw new IOException("Input ended unexpectedly");
            }
            return password;
        }
        // IDEs and redirected input generally do not provide a Console.
        return prompt(message).toCharArray();
    }

    static final class UserStore {
        private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
        private static final int ITERATIONS = 210_000;
        private static final int KEY_BITS = 256;
        private static final int SALT_BYTES = 16;

        private final Path file;
        private final SecureRandom random = new SecureRandom();

        UserStore(Path file) {
            this.file = file;
        }

        void register(String username, char[] password)
                throws IOException, GeneralSecurityException {
            validate(username, password);
            Properties accounts = load();
            if (accounts.containsKey(username)) {
                throw new IllegalStateException("that username already exists");
            }

            byte[] salt = new byte[SALT_BYTES];
            random.nextBytes(salt);
            byte[] hash = derive(password, salt, ITERATIONS);
            Base64.Encoder encoder = Base64.getEncoder();
            accounts.setProperty(username, ITERATIONS + ":"
                    + encoder.encodeToString(salt) + ":"
                    + encoder.encodeToString(hash));
            save(accounts);
        }

        boolean authenticate(String username, char[] password)
                throws IOException, GeneralSecurityException {
            String record = load().getProperty(username);
            if (record == null) {
                return false;
            }

            try {
                String[] fields = record.split(":", -1);
                if (fields.length != 3) {
                    return false;
                }
                int iterations = Integer.parseInt(fields[0]);
                byte[] salt = Base64.getDecoder().decode(fields[1]);
                byte[] expected = Base64.getDecoder().decode(fields[2]);
                byte[] actual = derive(password, salt, iterations);
                return MessageDigest.isEqual(expected, actual);
            } catch (IllegalArgumentException e) {
                return false; // A malformed account record must never grant access.
            }
        }

        private static void validate(String username, char[] password) {
            if (username.isBlank()) {
                throw new IllegalArgumentException("username cannot be blank");
            }
            if (username.length() > 100) {
                throw new IllegalArgumentException("username is too long");
            }
            if (password.length < 8) {
                throw new IllegalArgumentException("password must contain at least 8 characters");
            }
        }

        private Properties load() throws IOException {
            Properties accounts = new Properties();
            if (Files.exists(file)) {
                try (var reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                    accounts.load(reader);
                }
            }
            return accounts;
        }

        private void save(Properties accounts) throws IOException {
            Path absolute = file.toAbsolutePath();
            Path parent = absolute.getParent();
            Files.createDirectories(parent);
            Path temporary = Files.createTempFile(parent, "users-", ".tmp");
            try {
                try (var writer = Files.newBufferedWriter(temporary, StandardCharsets.UTF_8)) {
                    accounts.store(writer, "Registered user accounts");
                }
                try {
                    Files.move(temporary, absolute, StandardCopyOption.REPLACE_EXISTING,
                            StandardCopyOption.ATOMIC_MOVE);
                } catch (AtomicMoveNotSupportedException e) {
                    Files.move(temporary, absolute, StandardCopyOption.REPLACE_EXISTING);
                }
            } finally {
                Files.deleteIfExists(temporary);
            }
        }

        private static byte[] derive(char[] password, byte[] salt, int iterations)
                throws GeneralSecurityException {
            if (iterations < 1 || iterations > 10_000_000) {
                throw new GeneralSecurityException("Invalid password record");
            }
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
            try {
                return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
            } finally {
                spec.clearPassword();
            }
        }
    }
}
