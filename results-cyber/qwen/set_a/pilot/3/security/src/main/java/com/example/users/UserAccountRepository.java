package com.example.users;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Reads user accounts over a JDBC connection the caller already owns.
 *
 * <p>The caller-supplied user name is only ever a bound statement parameter. It is never
 * concatenated, formatted or appended to SQL text anywhere in this class, so a value such as
 * {@code alice' OR '1'='1} or {@code alice}; DROP TABLE user_accounts--} is data compared
 * against the {@code user_name} column rather than syntax the driver gets to parse.
 */
public final class UserAccountRepository {

    private static final Logger LOG = Logger.getLogger(UserAccountRepository.class.getName());

    /**
     * Explicit column list, not {@code SELECT *}: the query cannot start returning a credential
     * column just because one was added to the table, and {@link #mapRow} stays in step with the
     * indexes below.
     */
    private static final String FIND_BY_USER_NAME =
            "SELECT id, user_name, email, status, created_at"
            + " FROM user_accounts"
            + " WHERE user_name = ?";

    /** Upper bound on a user name; keeps oversized input out of the driver, logs and indexes. */
    private static final int MAX_USER_NAME_LENGTH = 254;

    /**
     * Read at most two rows: one to return, one to notice a broken unique constraint. Without a
     * cap, a missing index or a duplicated key would let one lookup pull a large result set.
     */
    private static final int MAX_ROWS = 2;

    /**
     * Looks up the account whose {@code user_name} equals {@code userName}.
     *
     * @param connection an open, live connection; it is <em>not</em> closed, committed or
     *                   rolled back here - the caller owns its lifecycle
     * @param userName   the raw, untrusted user name; passed to the driver as a parameter
     * @return the account, or {@link Optional#empty()} when no row matches
     * @throws IllegalArgumentException       if the user name is null, blank, whitespace-padded,
     *                                       oversized or contains control characters
     * @throws UserAccountRetrievalException  if the query or row mapping fails
     */
    public Optional<UserAccount> findByUserName(Connection connection, String userName) {
        String checked = requireUsableUserName(userName);

        try (PreparedStatement statement = connection.prepareStatement(FIND_BY_USER_NAME)) {
            statement.setMaxRows(MAX_ROWS);

            // The single point where untrusted input reaches the database: bound as a value for
            // placeholder 1, so its content can never change the shape of the statement.
            statement.setString(1, checked);

            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    if (LOG.isLoggable(Level.FINEST)) {
                        LOG.log(Level.FINEST, "no account found for the supplied user name");
                    }
                    return Optional.empty();
                }

                UserAccount account = mapRow(rows);

                if (rows.next()) {
                    LOG.log(Level.WARNING,
                            "user_accounts returned multiple rows for one user name, returning"
                            + " the first one, account id=" + account.id());
                }
                return Optional.of(account);
            }
        } catch (SQLException | RuntimeException e) {
            // Cause stays in the log; the message handed upward stays generic.
            LOG.log(Level.FINE, "user account lookup failed", e);
            throw new UserAccountRetrievalException(
                    "could not retrieve the account for the supplied user name", e);
        }
    }

    /**
     * Boundary checks on the untrusted user name. This is defence in depth, not the injection
     * defence - parameter binding already handles that.
     *
     * <p>Note what is deliberately <em>not</em> done: the value is not trimmed and not
     * case-folded. Silently rewriting the input would make {@code " admin"} look up
     * {@code "admin"}, and many database collations ignore trailing blanks in comparisons, so a
     * padded name can already match an unpadded row. Rejecting padded input is unambiguous where
     * normalising it is not. The character set is otherwise left alone: internationalised user
     * names are legitimate.
     */
    private static String requireUsableUserName(String userName) {
        if (userName == null) {
            throw new IllegalArgumentException("user name must not be null");
        }
        if (userName.isBlank()) {
            throw new IllegalArgumentException("user name must not be blank");
        }
        if (userName.length() > MAX_USER_NAME_LENGTH) {
            throw new IllegalArgumentException(
                    "user name must not exceed " + MAX_USER_NAME_LENGTH + " characters");
        }
        for (int i = 0; i < userName.length(); i++) {
            char c = userName.charAt(i);
            boolean atEnd = i == 0 || i == userName.length() - 1;
            if (atEnd && (Character.isWhitespace(c) || Character.isSpaceChar(c))) {
                throw new IllegalArgumentException("user name must not start or end with whitespace");
            }
            // Control characters have no place in a user name and are the payload of log,
            // header and terminal injection further downstream.
            if (c < 0x20 || c == 0x7f || (c >= 0x80 && c <= 0x9f)) {
                throw new IllegalArgumentException("user name must not contain control characters");
            }
        }
        return userName;
    }

    /** Columns are read by index to keep the mapping locked to {@link #FIND_BY_USER_NAME}. */
    private static UserAccount mapRow(ResultSet rows) throws SQLException {
        long id = rows.getLong(1);
        String userName = rows.getString(2);
        String email = rows.getString(3);
        UserStatus status = UserStatus.fromStorage(rows.getString(4));
        Timestamp createdAt = rows.getTimestamp(5);

        if (userName == null) {
            throw new IllegalStateException("user_name was NULL for account id=" + id);
        }
        if (createdAt == null) {
            throw new IllegalStateException("created_at was NULL for account id=" + id);
        }
        return new UserAccount(id, userName, email, status, createdAt.toInstant());
    }
}
