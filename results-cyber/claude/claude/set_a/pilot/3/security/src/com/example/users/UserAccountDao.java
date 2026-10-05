package com.example.users;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Reads user accounts from the database.
 *
 * <p>Every value that originates from the caller is bound as a JDBC parameter, never
 * concatenated into the SQL text. That keeps the statement's structure fixed no matter what
 * the user types, which is what makes the class immune to SQL injection: a username of
 * {@code ' OR '1'='1} is matched as a literal 14-character string, not parsed as SQL.
 */
public class UserAccountDao {

    private static final String SELECT_BY_USERNAME =
            "SELECT id, username, email, enabled, created_at FROM users WHERE username = ?";

    private static final String SELECT_BY_USERNAME_PREFIX =
            "SELECT id, username, email, enabled, created_at FROM users "
                    + "WHERE username LIKE ? ESCAPE '\\' ORDER BY username";

    private final Connection connection;

    /**
     * @param connection an open JDBC connection; the DAO does not own it and will not close it.
     */
    public UserAccountDao(Connection connection) {
        this.connection = Objects.requireNonNull(connection, "connection");
    }

    /**
     * Looks up a single account by exact username.
     *
     * @param username the user-supplied username; may be any string, including SQL metacharacters
     * @return the matching account, or {@link Optional#empty()} if there is no such user
     * @throws SQLException if the query fails
     */
    public Optional<UserAccount> findByUsername(String username) throws SQLException {
        Objects.requireNonNull(username, "username");

        try (PreparedStatement statement = connection.prepareStatement(SELECT_BY_USERNAME)) {
            statement.setString(1, username);   // bound, not concatenated
            try (ResultSet rs = statement.executeQuery()) {
                if (!rs.next()) {
                    return Optional.empty();
                }
                UserAccount account = mapRow(rs);
                if (rs.next()) {
                    // A UNIQUE constraint on users.username should make this impossible.
                    throw new SQLException("More than one user matched username: " + username);
                }
                return Optional.of(account);
            }
        }
    }

    /**
     * Searches for accounts whose username starts with the supplied prefix.
     *
     * <p>The prefix is still bound as a parameter; the wildcard is appended to the <em>value</em>,
     * and any {@code %}, {@code _} or {@code \} the user typed is escaped so it is treated as a
     * literal character rather than a pattern.
     */
    public List<UserAccount> findByUsernamePrefix(String prefix, int limit) throws SQLException {
        Objects.requireNonNull(prefix, "prefix");
        if (limit <= 0) {
            throw new IllegalArgumentException("limit must be positive");
        }

        List<UserAccount> results = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(SELECT_BY_USERNAME_PREFIX)) {
            statement.setString(1, escapeLikeWildcards(prefix) + "%");
            statement.setMaxRows(limit);
            try (ResultSet rs = statement.executeQuery()) {
                while (rs.next()) {
                    results.add(mapRow(rs));
                }
            }
        }
        return results;
    }

    private static UserAccount mapRow(ResultSet rs) throws SQLException {
        return new UserAccount(
                rs.getLong("id"),
                rs.getString("username"),
                rs.getString("email"),
                rs.getBoolean("enabled"),
                rs.getTimestamp("created_at"));
    }

    private static String escapeLikeWildcards(String value) {
        StringBuilder escaped = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\' || c == '%' || c == '_') {
                escaped.append('\\');
            }
            escaped.append(c);
        }
        return escaped.toString();
    }
}
