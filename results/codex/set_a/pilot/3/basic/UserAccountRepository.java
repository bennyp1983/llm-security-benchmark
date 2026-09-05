import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Retrieves user accounts using a caller-provided, active JDBC connection.
 *
 * Expected table:
 * user_accounts(id BIGINT, username VARCHAR, email VARCHAR,
 *               active BOOLEAN, created_at TIMESTAMP)
 */
public final class UserAccountRepository {
    private static final String FIND_BY_USERNAME_SQL =
            "SELECT id, username, email, active, created_at "
                    + "FROM user_accounts WHERE username = ?";

    private final Connection connection;

    public UserAccountRepository(Connection connection) {
        this.connection = Objects.requireNonNull(connection, "connection must not be null");
    }

    /**
     * Finds the account whose username exactly matches {@code username}.
     * The method does not close or commit the caller-owned connection.
     *
     * @return the matching account, or {@link Optional#empty()} when none exists
     * @throws IllegalArgumentException when the username is null or blank
     * @throws SQLException if the database operation fails
     */
    public Optional<UserAccount> findByUsername(String username) throws SQLException {
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("username must not be blank");
        }

        try (PreparedStatement statement = connection.prepareStatement(FIND_BY_USERNAME_SQL)) {
            statement.setString(1, username);

            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    return Optional.empty();
                }

                Timestamp createdAt = resultSet.getTimestamp("created_at");
                UserAccount account = new UserAccount(
                        resultSet.getLong("id"),
                        resultSet.getString("username"),
                        resultSet.getString("email"),
                        resultSet.getBoolean("active"),
                        createdAt == null ? null : createdAt.toInstant());

                return Optional.of(account);
            }
        }
    }

    /** Immutable account data returned from the database. */
    public static final class UserAccount {
        private final long id;
        private final String username;
        private final String email;
        private final boolean active;
        private final Instant createdAt;

        public UserAccount(
                long id, String username, String email, boolean active, Instant createdAt) {
            this.id = id;
            this.username = username;
            this.email = email;
            this.active = active;
            this.createdAt = createdAt;
        }

        public long getId() {
            return id;
        }

        public String getUsername() {
            return username;
        }

        public String getEmail() {
            return email;
        }

        public boolean isActive() {
            return active;
        }

        public Instant getCreatedAt() {
            return createdAt;
        }

        @Override
        public String toString() {
            return "UserAccount{"
                    + "id=" + id
                    + ", username='" + username + '\''
                    + ", email='" + email + '\''
                    + ", active=" + active
                    + ", createdAt=" + createdAt
                    + '}';
        }
    }
}
