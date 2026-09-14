package com.example.security;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Reads user accounts from the {@code users} table.
 *
 * <p>The caller supplies an already-open JDBC {@link Connection}; this class never opens,
 * commits, rolls back or closes it, so transaction ownership stays with the caller.
 *
 * <p>Every lookup that takes user-supplied input goes through {@link PreparedStatement} with
 * the SQL text held in a compile-time constant. The username is only ever delivered as a bound
 * parameter, never as part of the statement string, so no input can change the structure of the
 * query. See the README for the threat this closes and for the negative tests that pin it.
 */
public final class UserRepository {

    /**
     * The one and only SQL text this repository executes. Deliberately a constant with a single
     * placeholder: nothing derived from user input is ever concatenated, formatted or appended
     * to it, so the statement is fully parsed and planned before the value is known.
     */
    static final String SELECT_BY_USERNAME =
            "SELECT id, username, email, full_name, status, password_hash, created_at"
          + "   FROM users"
          + "  WHERE username = ?";

    /** Width of {@code users.username}; longer input can never match and is rejected early. */
    public static final int MAX_USERNAME_LENGTH = 254;

    /** Two, not one: the extra row is read only to prove the match was unique. */
    private static final int ROW_PROBE_LIMIT = 2;

    private final Connection connection;

    public UserRepository(Connection connection) {
        this.connection = Objects.requireNonNull(connection, "connection");
    }

    /**
     * Looks up the account whose {@code users.username} equals {@code username}.
     *
     * @param username the name to search for; compared exactly, after trimming surrounding
     *                 whitespace. Case sensitivity follows the database collation.
     * @return the account, or {@link Optional#empty()} when no row matches
     * @throws IllegalArgumentException if the input is null, blank, longer than the column, or
     *                                  contains control characters
     * @throws UserRepositoryException if the query fails or more than one row matches
     */
    public Optional<UserAccount> findByUsername(String username) {
        String canonical = normalizeAndValidate(username);

        try (PreparedStatement statement = connection.prepareStatement(SELECT_BY_USERNAME)) {
            statement.setMaxRows(ROW_PROBE_LIMIT);
            statement.setString(1, canonical);

            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    return Optional.empty();
                }
                UserAccount first = mapRow(rows);
                if (rows.next()) {
                    // Ambiguous match: reporting one of them would hand a caller whichever row
                    // the engine happened to return first, so refuse instead of guessing.
                    throw new UserRepositoryException(
                            "account lookup is ambiguous: the username matched more than one row "
                          + "and users.username is expected to be unique");
                }
                return Optional.of(first);
            }
        } catch (SQLException ex) {
            throw new UserRepositoryException("account lookup failed for the supplied username", ex);
        }
    }

    /**
     * Boundary validation only. The value is passed to the database unchanged otherwise - the
     * parameter binding, not a denylist, is what makes the query safe.
     */
    private static String normalizeAndValidate(String raw) {
        if (raw == null) {
            throw new IllegalArgumentException("username must not be null");
        }
        String value = raw.trim();
        if (value.isEmpty()) {
            throw new IllegalArgumentException("username must not be blank");
        }
        if (value.length() > MAX_USERNAME_LENGTH) {
            throw new IllegalArgumentException(
                    "username must not be longer than " + MAX_USERNAME_LENGTH + " characters");
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x20 || c == 0x7F) {
                // Not an SQL concern - control bytes reach the audit log and would forge extra
                // log lines (CRLF injection) and never match a stored username anyway.
                throw new IllegalArgumentException("username must not contain control characters");
            }
        }
        return value;
    }

    /** Columns are read by label; the row shape is fixed by {@link #SELECT_BY_USERNAME}. */
    private static UserAccount mapRow(ResultSet rows) throws SQLException {
        Timestamp createdAt = rows.getTimestamp("created_at");
        return new UserAccount(
                rows.getLong("id"),
                rows.getString("username"),
                rows.getString("email"),
                rows.getString("full_name"),
                rows.getString("status"),
                rows.getString("password_hash"),
                createdAt == null ? null : createdAt.toInstant());
    }
}
