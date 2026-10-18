package com.example.users;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Reads {@link UserAccount} rows through a JDBC connection that the caller owns.
 *
 * <p>Expected schema (a unique index on {@code user_name} is what makes a lookup return at most
 * one row):
 *
 * <pre>{@code
 * CREATE TABLE users (
 *     id            BIGINT        PRIMARY KEY,
 *     user_name     VARCHAR(64)   NOT NULL UNIQUE,
 *     email         VARCHAR(320)  NOT NULL,
 *     display_name  VARCHAR(128),
 *     enabled       BOOLEAN       NOT NULL DEFAULT TRUE,
 *     created_at    TIMESTAMP     NOT NULL,
 *     last_login_at TIMESTAMP,
 *     password_hash VARCHAR(255)  NOT NULL
 * );
 * }</pre>
 */
public class UserAccountRepository {

    /**
     * The column list is explicit and omits {@code password_hash}: this lookup identifies an
     * account, it does not authenticate one, so leaking the hash through a general-purpose
     * accessor would only widen the blast radius of a logging or serialisation mistake.
     */
    private static final String FIND_BY_USER_NAME = """
            SELECT id, user_name, email, display_name, enabled, created_at, last_login_at \
              FROM users \
             WHERE user_name = ?
            """;

    /**
     * Looks up the account whose {@code user_name} equals {@code userName}.
     *
     * <p>The value is bound as a statement parameter, so it is always data: quotes, comment
     * markers and terminator sequences in it cannot alter the SQL. The match is exact, which means
     * {@code ALICE} does not find {@code alice} unless the column collation itself is
     * case-insensitive (MySQL's default is, H2's and PostgreSQL's are not).
     *
     * @param connection an open, ready-to-use connection; it is not closed, committed or rolled
     *                   back here, the caller keeps ownership
     * @param userName   the sign-in name to search for, ignoring surrounding whitespace
     * @return the matching account, or {@link Optional#empty()} if no row matches
     * @throws IllegalArgumentException if {@code userName} is {@code null} or blank
     * @throws SQLException             if the database rejects or fails the query
     */
    public Optional<UserAccount> findByUserName(Connection connection, String userName) throws SQLException {
        Objects.requireNonNull(connection, "connection");
        try (PreparedStatement statement = connection.prepareStatement(FIND_BY_USER_NAME)) {
            statement.setString(1, requireUserName(userName));
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    return Optional.empty();
                }
                return Optional.of(mapRow(rows));
            }
        }
    }

    /**
     * Same as {@link #findByUserName(Connection, String)} but treats a missing row as an error.
     *
     * @param connection an open, ready-to-use connection; ownership stays with the caller
     * @param userName   the sign-in name to search for, ignoring surrounding whitespace
     * @return the matching account, never {@code null}
     * @throws UserAccountNotFoundException if no row matches
     * @throws IllegalArgumentException     if {@code userName} is {@code null} or blank
     * @throws SQLException                 if the database rejects or fails the query
     */
    public UserAccount requireByUserName(Connection connection, String userName) throws SQLException {
        String name = requireUserName(userName);
        return findByUserName(connection, name)
                .orElseThrow(() -> new UserAccountNotFoundException(name));
    }

    private static UserAccount mapRow(ResultSet row) throws SQLException {
        return new UserAccount(
                row.getLong("id"),
                row.getString("user_name"),
                row.getString("email"),
                row.getString("display_name"),
                row.getBoolean("enabled"),
                toInstant(row.getTimestamp("created_at")),
                toInstant(row.getTimestamp("last_login_at")));
    }

    private static Instant toInstant(Timestamp value) {
        return value == null ? null : value.toInstant();
    }

    private static String requireUserName(String userName) {
        if (userName == null || userName.isBlank()) {
            throw new IllegalArgumentException("userName must not be null or blank");
        }
        return userName.trim();
    }
}
