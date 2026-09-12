import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Registers users and verifies their passwords using an existing JDBC connection.
 *
 * <p>The app_users table must contain a VARCHAR username primary key and a
 * VARCHAR(512) password_hash column. Passwords are never stored directly. Each
 * credential is encoded as algorithm$iterations$salt$derived-key.</p>
 */
public final class UserAccountService {
    private static final String KDF = "PBKDF2WithHmacSHA256";
    private static final String FORMAT_NAME = "pbkdf2-sha256";
    private static final int ITERATIONS = 600_000;
    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;
    private static final int MAX_USERNAME_LENGTH = 128;
    private static final int MAX_PASSWORD_LENGTH = 1024;

    private static final String INSERT_USER =
            "INSERT INTO app_users (username, password_hash) VALUES (?, ?)";
    private static final String SELECT_CREDENTIAL =
            "SELECT password_hash FROM app_users WHERE username = ?";

    private final Connection connection;
    private final SecureRandom secureRandom;

    public UserAccountService(Connection connection) {
        this(connection, new SecureRandom());
    }

    UserAccountService(Connection connection, SecureRandom secureRandom) {
        this.connection = Objects.requireNonNull(connection, "connection");
        this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom");
    }

    /**
     * Registers a new account. The caller keeps ownership of {@code password}
     * and should clear it when it is no longer needed.
     *
     * @throws IllegalArgumentException if either value violates the input rules
     * @throws SQLException if the insert fails (including a duplicate username)
     */
    public void register(String username, char[] password) throws SQLException {
        validateUsername(username);
        validatePassword(password);

        char[] workingPassword = password.clone();
        try {
            String storedCredential = createStoredCredential(workingPassword);
            try (PreparedStatement statement = connection.prepareStatement(INSERT_USER)) {
                statement.setString(1, username);
                statement.setString(2, storedCredential);
                if (statement.executeUpdate() != 1) {
                    throw new SQLException("User registration did not insert exactly one row");
                }
            }
        } finally {
            Arrays.fill(workingPassword, '\0');
        }
    }

    /**
     * Returns true only when the supplied password matches the stored account.
     * Malformed/unsupported stored credentials fail closed.
     */
    public boolean authenticate(String username, char[] password) throws SQLException {
        if (!isValidUsername(username)
                || password == null
                || password.length == 0
                || password.length > MAX_PASSWORD_LENGTH) {
            return false;
        }

        String storedCredential = null;
        try (PreparedStatement statement = connection.prepareStatement(SELECT_CREDENTIAL)) {
            statement.setString(1, username);
            try (ResultSet results = statement.executeQuery()) {
                if (results.next()) {
                    storedCredential = results.getString(1);
                }
            }
        }

        if (storedCredential == null) {
            return false;
        }

        char[] workingPassword = password.clone();
        try {
            return verifyStoredCredential(workingPassword, storedCredential);
        } finally {
            Arrays.fill(workingPassword, '\0');
        }
    }

    private String createStoredCredential(char[] password) {
        byte[] salt = new byte[SALT_BYTES];
        secureRandom.nextBytes(salt);
        byte[] hash = deriveKey(password, salt, ITERATIONS, KEY_BITS);
        try {
            Base64.Encoder encoder = Base64.getEncoder();
            return FORMAT_NAME + "$" + ITERATIONS + "$"
                    + encoder.encodeToString(salt) + "$" + encoder.encodeToString(hash);
        } finally {
            Arrays.fill(hash, (byte) 0);
        }
    }

    private boolean verifyStoredCredential(char[] password, String encoded) {
        byte[] expected = null;
        byte[] actual = null;
        byte[] salt = null;
        try {
            String[] fields = encoded.split("\\$", -1);
            if (fields.length != 4 || !FORMAT_NAME.equals(fields[0])) {
                return false;
            }

            int iterations = Integer.parseInt(fields[1]);
            if (iterations < 1 || iterations > ITERATIONS * 10) {
                return false;
            }

            Base64.Decoder decoder = Base64.getDecoder();
            salt = decoder.decode(fields[2].getBytes(StandardCharsets.US_ASCII));
            expected = decoder.decode(fields[3].getBytes(StandardCharsets.US_ASCII));
            if (salt.length < SALT_BYTES || expected.length < 16 || expected.length > 64) {
                return false;
            }

            actual = deriveKey(password, salt, iterations, expected.length * Byte.SIZE);
            return MessageDigest.isEqual(expected, actual);
        } catch (IllegalArgumentException exception) {
            return false;
        } finally {
            clear(expected);
            clear(actual);
            clear(salt);
        }
    }

    private static byte[] deriveKey(char[] password, byte[] salt, int iterations, int keyBits) {
        PBEKeySpec specification = new PBEKeySpec(password, salt, iterations, keyBits);
        try {
            return SecretKeyFactory.getInstance(KDF).generateSecret(specification).getEncoded();
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException(KDF + " is unavailable in this Java runtime", exception);
        } finally {
            specification.clearPassword();
        }
    }

    private static void validateUsername(String username) {
        if (!isValidUsername(username)) {
            throw new IllegalArgumentException(
                    "Username must be 1-" + MAX_USERNAME_LENGTH
                            + " characters and have no leading or trailing whitespace");
        }
    }

    private static boolean isValidUsername(String username) {
        return username != null
                && !username.isEmpty()
                && username.length() <= MAX_USERNAME_LENGTH
                && username.equals(username.trim());
    }

    private static void validatePassword(char[] password) {
        if (password == null || password.length == 0 || password.length > MAX_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be 1-" + MAX_PASSWORD_LENGTH + " characters");
        }
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
