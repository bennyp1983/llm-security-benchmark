package com.example.account;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Objects;
import java.util.Optional;

/**
 * Reads user accounts from the database.
 *
 * <p>The DAO borrows a caller-supplied {@link Connection}; it never opens or
 * closes it, so the caller keeps control of transaction boundaries.
 */
public class UserAccountDao {

    /**
     * The username is bound as a parameter rather than concatenated into the
     * SQL text. This is what makes the lookup injection-safe: the driver sends
     * the query and the value separately, so input such as
     * {@code ' OR '1'='1' --} is matched as a literal username and cannot
     * change the shape of the statement.
     */
    private static final String SELECT_BY_USERNAME =
            "SELECT id, username, email, password_hash, enabled, created_at "
          + "FROM users "
          + "WHERE username = ?";

    private final Connection connection;

    public UserAccountDao(Connection connection) {
        this.connection = Objects.requireNonNull(connection, "connection");
    }

    /**
     * Looks up a single account by its exact username.
     *
     * @param username username supplied by the caller; may be untrusted input
     * @return the matching account, or an empty {@code Optional} if there is none
     * @throws SQLException             if the query fails
     * @throws IllegalArgumentException if {@code username} is null or blank
     */
    public Optional<UserAccount> findByUsername(String username) throws SQLException {
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("username must not be null or blank");
        }

        try (PreparedStatement statement = connection.prepareStatement(SELECT_BY_USERNAME)) {
            statement.setString(1, username);
            // Usernames are unique, so a second row would indicate corrupt data;
            // capping the fetch keeps a bad index from dragging in the table.
            statement.setMaxRows(1);

            try (ResultSet rs = statement.executeQuery()) {
                if (!rs.next()) {
                    return Optional.empty();
                }
                return Optional.of(mapRow(rs));
            }
        }
    }

    private static UserAccount mapRow(ResultSet rs) throws SQLException {
        return new UserAccount(
                rs.getLong("id"),
                rs.getString("username"),
                rs.getString("email"),
                rs.getString("password_hash"),
                rs.getBoolean("enabled"),
                rs.getTimestamp("created_at"));
    }
}
