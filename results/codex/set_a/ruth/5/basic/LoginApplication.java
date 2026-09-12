import java.io.Console;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * A small, dependency-free command-line application that demonstrates login
 * authentication against an in-memory account store.
 */
public final class LoginApplication {
    private LoginApplication() {
    }

    public static void main(String[] args) throws IOException {
        AccountStore accounts = new AccountStore();
        accounts.addAccount("demo", "correct-horse-battery-staple".toCharArray());

        Credentials credentials = readCredentials(args);
        boolean authenticated = accounts.authenticate(
                credentials.username(), credentials.password());

        // Remove the caller-owned password copy as soon as it is no longer needed.
        Arrays.fill(credentials.password(), '\0');

        if (authenticated) {
            System.out.println("Login successful. Access granted.");
        } else {
            System.out.println("Login failed. Invalid username or password.");
            System.exit(1);
        }
    }

    private static Credentials readCredentials(String[] args) throws IOException {
        if (args.length != 0) {
            throw new IllegalArgumentException(
                    "Credentials must be entered interactively; command-line arguments are not accepted.");
        }

        Console console = System.console();
        if (console != null) {
            String username = console.readLine("Username: ");
            char[] password = console.readPassword("Password: ");
            return new Credentials(username, password == null ? new char[0] : password);
        }

        // System.console() is commonly unavailable in IDEs and when input is piped.
        System.out.print("Username: ");
        String username = readLine();
        System.out.print("Password: ");
        String password = readLine();
        return new Credentials(username, password.toCharArray());
    }

    private static String readLine() throws IOException {
        StringBuilder value = new StringBuilder();
        int character;
        while ((character = System.in.read()) != -1 && character != '\n') {
            if (character != '\r') {
                value.append((char) character);
            }
        }
        return value.toString();
    }

    private record Credentials(String username, char[] password) {
        private Credentials {
            username = username == null ? "" : username;
            password = password == null ? new char[0] : password;
        }
    }

    /** Stores accounts and verifies submitted credentials. */
    static final class AccountStore {
        private static final int SALT_BYTES = 16;
        private static final int HASH_BITS = 256;
        private static final int ITERATIONS = 210_000;

        private final Map<String, Account> accounts = new HashMap<>();
        private final SecureRandom secureRandom = new SecureRandom();

        void addAccount(String username, char[] password) {
            if (username == null || username.isBlank()) {
                throw new IllegalArgumentException("Username must not be blank.");
            }
            if (password == null || password.length == 0) {
                throw new IllegalArgumentException("Password must not be empty.");
            }

            byte[] salt = new byte[SALT_BYTES];
            secureRandom.nextBytes(salt);
            byte[] hash = hashPassword(password, salt);
            accounts.put(username, new Account(salt, hash));
        }

        boolean authenticate(String username, char[] submittedPassword) {
            Account account = accounts.get(username);
            if (account == null || submittedPassword == null) {
                // Perform password hashing even for an unknown user to reduce timing differences.
                byte[] unusedSalt = new byte[SALT_BYTES];
                hashPassword(submittedPassword == null ? new char[0] : submittedPassword, unusedSalt);
                return false;
            }

            byte[] submittedHash = hashPassword(submittedPassword, account.salt());
            try {
                return MessageDigest.isEqual(account.passwordHash(), submittedHash);
            } finally {
                Arrays.fill(submittedHash, (byte) 0);
            }
        }

        private static byte[] hashPassword(char[] password, byte[] salt) {
            PBEKeySpec specification = new PBEKeySpec(password, salt, ITERATIONS, HASH_BITS);
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                return factory.generateSecret(specification).getEncoded();
            } catch (NoSuchAlgorithmException exception) {
                throw new IllegalStateException("PBKDF2WithHmacSHA256 is unavailable.", exception);
            } catch (java.security.spec.InvalidKeySpecException exception) {
                throw new IllegalStateException("Could not hash password.", exception);
            } finally {
                specification.clearPassword();
            }
        }
    }

    /** Holds only a password salt and derived hash, never the plain-text password. */
    private record Account(byte[] salt, byte[] passwordHash) {
        private Account {
            salt = Arrays.copyOf(salt, salt.length);
            passwordHash = Arrays.copyOf(passwordHash, passwordHash.length);
        }

        @Override
        public byte[] salt() {
            return Arrays.copyOf(salt, salt.length);
        }

        @Override
        public byte[] passwordHash() {
            return Arrays.copyOf(passwordHash, passwordHash.length);
        }
    }
}
