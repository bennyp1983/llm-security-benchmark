import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/** A small command-line application for registering and authenticating users. */
public final class UserAccountApp {
    private static final Path CREDENTIAL_FILE = Path.of("credentials.properties");
    private static final int PBKDF2_ITERATIONS = 210_000;
    private static final int HASH_LENGTH_BITS = 256;
    private static final int SALT_LENGTH_BYTES = 16;

    private final BufferedReader input;
    private final Console console;
    private final Properties accounts = new Properties();

    private UserAccountApp() throws IOException {
        input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        console = System.console();
        loadAccounts();
    }

    public static void main(String[] args) {
        try {
            new UserAccountApp().run();
        } catch (IOException | GeneralSecurityException exception) {
            System.err.println("The account operation failed: " + exception.getMessage());
            System.exit(1);
        }
    }

    private void run() throws IOException, GeneralSecurityException {
        System.out.println("User Account Manager");

        while (true) {
            System.out.println("\n1. Register a new account");
            System.out.println("2. Log in");
            System.out.println("3. Exit");
            String choice = readLine("Choose an option: ");

            if (choice == null || "3".equals(choice.trim())) {
                System.out.println("Goodbye.");
                return;
            }

            switch (choice.trim()) {
                case "1" -> register();
                case "2" -> authenticate();
                default -> System.out.println("Please enter 1, 2, or 3.");
            }
        }
    }

    private void register() throws IOException, GeneralSecurityException {
        String username = readLine("Username: ");
        if (!isValidUsername(username)) {
            System.out.println("A username must be 1-50 characters and cannot contain spaces.");
            return;
        }
        if (accounts.containsKey(username)) {
            System.out.println("That username is already registered.");
            return;
        }

        char[] password = readPassword("Password: ");
        try {
            if (password == null || password.length < 8) {
                System.out.println("The password must contain at least 8 characters.");
                return;
            }

            byte[] salt = new byte[SALT_LENGTH_BYTES];
            new SecureRandom().nextBytes(salt);
            byte[] hash = hashPassword(password, salt, PBKDF2_ITERATIONS);
            String value = PBKDF2_ITERATIONS + ":"
                    + Base64.getEncoder().encodeToString(salt) + ":"
                    + Base64.getEncoder().encodeToString(hash);
            accounts.setProperty(username, value);
            saveAccounts();
            System.out.println("Account registered successfully.");
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    private void authenticate() throws IOException, GeneralSecurityException {
        String username = readLine("Username: ");
        char[] password = readPassword("Password: ");
        boolean authenticated = false;

        try {
            String savedValue = username == null ? null : accounts.getProperty(username);
            if (savedValue != null && password != null) {
                String[] fields = savedValue.split(":", 3);
                if (fields.length == 3) {
                    int iterations = Integer.parseInt(fields[0]);
                    byte[] salt = Base64.getDecoder().decode(fields[1]);
                    byte[] expectedHash = Base64.getDecoder().decode(fields[2]);
                    byte[] suppliedHash = hashPassword(password, salt, iterations);
                    authenticated = MessageDigest.isEqual(expectedHash, suppliedHash);
                }
            }
        } catch (IllegalArgumentException ignored) {
            // A malformed credential entry is treated as a failed login.
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }

        System.out.println(authenticated ? "Authentication successful." : "Invalid username or password.");
    }

    private void loadAccounts() throws IOException {
        if (Files.exists(CREDENTIAL_FILE)) {
            try (Reader reader = Files.newBufferedReader(CREDENTIAL_FILE, StandardCharsets.UTF_8)) {
                accounts.load(reader);
            }
        }
    }

    private void saveAccounts() throws IOException {
        Path absoluteFile = CREDENTIAL_FILE.toAbsolutePath();
        Path parent = absoluteFile.getParent();
        Files.createDirectories(parent);
        Path temporaryFile = Files.createTempFile(parent, "credentials-", ".tmp");
        try {
            try (var writer = Files.newBufferedWriter(
                    temporaryFile,
                    StandardCharsets.UTF_8,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                accounts.store(writer, "User credentials: PBKDF2 iteration count, salt, and password hash");
            }
            try {
                Files.move(
                        temporaryFile,
                        absoluteFile,
                        StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (java.nio.file.AtomicMoveNotSupportedException ignored) {
                Files.move(temporaryFile, absoluteFile, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temporaryFile);
        }
    }

    private static byte[] hashPassword(char[] password, byte[] salt, int iterations)
            throws GeneralSecurityException {
        PBEKeySpec specification = new PBEKeySpec(password, salt, iterations, HASH_LENGTH_BITS);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(specification)
                    .getEncoded();
        } finally {
            specification.clearPassword();
        }
    }

    private static boolean isValidUsername(String username) {
        return username != null
                && username.length() >= 1
                && username.length() <= 50
                && username.chars().noneMatch(Character::isWhitespace);
    }

    private String readLine(String prompt) throws IOException {
        System.out.print(prompt);
        System.out.flush();
        return input.readLine();
    }

    private char[] readPassword(String prompt) throws IOException {
        if (console != null) {
            return console.readPassword("%s", prompt);
        }
        String password = readLine(prompt);
        return password == null ? null : password.toCharArray();
    }
}
