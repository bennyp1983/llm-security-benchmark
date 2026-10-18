package example.security;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Optional;

final class AuthenticationService implements AutoCloseable {
    private static final int SOURCE_LIMIT_PER_MINUTE = 10;
    private static final int ACCOUNT_LIMIT_PER_MINUTE = 5;
    private static final String INVALID_EMAIL = "invalid@invalid.invalid";
    private static final String SOURCE_BUCKET = digest("server-defined:local-console:v1");
    private final DatabaseConfig config;
    private final PasswordVerifier passwordVerifier;

    AuthenticationService(DatabaseConfig config) throws GeneralSecurityException {
        this.config = config;
        this.passwordVerifier = new PasswordVerifier();
    }

    boolean authenticate(String suppliedEmail, char[] password) throws SQLException, GeneralSecurityException {
        Optional<String> canonical = InputValidator.canonicalEmail(suppliedEmail);
        boolean passwordValid = InputValidator.validPassword(password);
        boolean inputValid = canonical.isPresent() && passwordValid;

        try (Connection connection = DriverManager.getConnection(config.jdbcUrl(), config.properties())) {
            connection.setReadOnly(false);
            connection.setAutoCommit(false);
            connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
            try {
                int sourceAttempts = incrementBucket(connection, "source", SOURCE_BUCKET);
                boolean sourceBlocked = sourceAttempts > SOURCE_LIMIT_PER_MINUTE;
                // Once the source is blocked, collapse attacker-chosen account keys and queries to
                // constants. This bounds database growth while preserving comparable failure work.
                String emailForQuery = sourceBlocked ? INVALID_EMAIL : canonical.orElse(INVALID_EMAIL);
                CredentialRecord record = readCredential(connection, emailForQuery);
                // Unknown accounts share one bucket. Only a server-side credential row can cause
                // a distinct persistent account key to be created.
                String accountBucket = digest(record == null ? INVALID_EMAIL : emailForQuery);
                int accountAttempts = incrementBucket(connection, "account", accountBucket);
                boolean passwordMatches;
                char[] boundedPassword = passwordValid ? password : "invalid-input-placeholder".toCharArray();
                try {
                    passwordMatches = passwordVerifier.verify(boundedPassword, record);
                } finally {
                    if (boundedPassword != password) {
                        Arrays.fill(boundedPassword, '\0');
                    }
                    if (record != null) {
                        clear(record.salt(), record.passwordHash());
                    }
                }
                boolean allowed = !sourceBlocked && accountAttempts <= ACCOUNT_LIMIT_PER_MINUTE;
                boolean authenticated = inputValid && allowed && passwordMatches;
                connection.commit(); // No success is returned unless all checks commit atomically.
                return authenticated;
            } catch (SQLException | GeneralSecurityException | RuntimeException failure) {
                try {
                    connection.rollback();
                } catch (SQLException rollbackFailure) {
                    failure.addSuppressed(rollbackFailure);
                }
                throw failure;
            }
        }
    }

    private static int incrementBucket(Connection connection, String scope, String bucket) throws SQLException {
        String sql = """
                INSERT INTO auth_rate_limit (scope, bucket_key, window_start, attempt_count)
                VALUES (?, ?, date_trunc('minute', CURRENT_TIMESTAMP), 1)
                ON CONFLICT (scope, bucket_key)
                DO UPDATE SET
                    window_start = EXCLUDED.window_start,
                    attempt_count = CASE
                        WHEN auth_rate_limit.window_start = EXCLUDED.window_start
                        THEN LEAST(auth_rate_limit.attempt_count + 1, 1000000)
                        ELSE 1
                    END
                RETURNING attempt_count
                """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, scope);
            statement.setString(2, bucket);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new SQLException("rate limit update returned no row");
                }
                int count = result.getInt(1);
                if (result.wasNull() || count < 1 || count > 1_000_000 || result.next()) {
                    throw new SQLException("invalid rate limit state");
                }
                return count;
            }
        }
    }

    private static CredentialRecord readCredential(Connection connection, String email) throws SQLException {
        String sql = """
                SELECT password_algorithm, password_iterations, password_salt, password_hash, enabled
                FROM app_user
                WHERE email_canonical = ?
                """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, email);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    return null;
                }
                String algorithm = result.getString(1);
                int iterations = result.getInt(2);
                boolean iterationsNull = result.wasNull();
                byte[] salt = result.getBytes(3);
                byte[] hash = result.getBytes(4);
                boolean enabled = result.getBoolean(5);
                boolean enabledNull = result.wasNull();
                if (result.next() || iterationsNull || enabledNull) {
                    clear(salt, hash);
                    return null;
                }
                return new CredentialRecord(algorithm, iterations, salt, hash, enabled);
            }
        }
    }

    private static String digest(String value) {
        try {
            byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(bytes);
            Arrays.fill(bytes, (byte) 0);
            return HexFormat.of().formatHex(hash);
        } catch (GeneralSecurityException impossible) {
            throw new ExceptionInInitializerError(impossible);
        }
    }

    private static void clear(byte[]... values) {
        for (byte[] value : values) {
            if (value != null) {
                Arrays.fill(value, (byte) 0);
            }
        }
    }

    @Override
    public void close() {
        passwordVerifier.close();
    }
}
