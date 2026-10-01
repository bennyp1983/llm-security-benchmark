package com.example.accounts;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Optional;

/**
 * All SQL touching the {@code account} table.
 *
 * <p>Rule 1 (trust boundaries): every statement here is a {@link PreparedStatement} with bound
 * parameters. No user-controlled value is ever concatenated into SQL, so there is no injection
 * surface, and the values that are bound have already been through {@link InputValidator}.
 */
public final class AccountRepository {

    /** An account row. Deliberately carries no plaintext -- only the stored hash. */
    public record Account(long id, String emailCanonical, String usernameCanonical,
                          String usernameDisplay, String passwordHash, boolean disabled) {
    }

    private static final String INSERT_SQL = """
            INSERT INTO account (email_canonical, username_canonical, username_display,
                                 password_hash, created_at, password_changed_at, disabled)
            VALUES (?, ?, ?, ?, ?, ?, 0)
            """;

    private static final String SELECT_BY_LOGIN_SQL = """
            SELECT id, email_canonical, username_canonical, username_display, password_hash, disabled
            FROM account
            WHERE email_canonical = ? OR username_canonical = ?
            """;

    private static final String UPDATE_HASH_SQL = """
            UPDATE account SET password_hash = ?, password_changed_at = ? WHERE id = ?
            """;

    /**
     * Inserts a new account.
     *
     * <p>Rule 7 (concurrency): uniqueness is decided by the UNIQUE constraints, not by a preceding
     * SELECT. A duplicate surfaces as a constraint violation that this method reports as
     * {@code false}, which is exactly what makes two simultaneous registrations for one address
     * safe -- one of them loses, deterministically.
     *
     * @return {@code true} if the row was created, {@code false} if the email or username is taken
     */
    public boolean insert(Connection connection, String emailCanonical, String usernameCanonical,
                          String usernameDisplay, String passwordHash, Instant now)
            throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(INSERT_SQL)) {
            ps.setString(1, emailCanonical);
            ps.setString(2, usernameCanonical);
            ps.setString(3, usernameDisplay);
            ps.setString(4, passwordHash);
            ps.setLong(5, now.getEpochSecond());
            ps.setLong(6, now.getEpochSecond());
            ps.executeUpdate();
            return true;
        } catch (SQLException e) {
            if (isUniqueViolation(e)) {
                return false;
            }
            throw e;
        }
    }

    /** Looks up an account by canonical email or canonical username (the two login identifiers). */
    public Optional<Account> findByLogin(Connection connection, String canonicalIdentifier)
            throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(SELECT_BY_LOGIN_SQL)) {
            ps.setString(1, canonicalIdentifier);
            ps.setString(2, canonicalIdentifier);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return Optional.empty();
                }
                Account account = new Account(
                        rs.getLong("id"),
                        rs.getString("email_canonical"),
                        rs.getString("username_canonical"),
                        rs.getString("username_display"),
                        rs.getString("password_hash"),
                        rs.getInt("disabled") != 0);
                return Optional.of(account);
            }
        }
    }

    /** Replaces the stored hash, used when login succeeds against outdated Argon2 parameters. */
    public void updatePasswordHash(Connection connection, long accountId, String passwordHash,
                                   Instant now) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(UPDATE_HASH_SQL)) {
            ps.setString(1, passwordHash);
            ps.setLong(2, now.getEpochSecond());
            ps.setLong(3, accountId);
            ps.executeUpdate();
        }
    }

    /**
     * True for a UNIQUE/PRIMARY KEY violation.
     *
     * <p>Checked through the portable {@link SQLException#getSQLState()} class 23 (integrity
     * constraint) first, with a narrow SQLite-specific fallback because sqlite-jdbc reports
     * {@code null} SQL states.
     */
    private static boolean isUniqueViolation(SQLException e) {
        for (SQLException current = e; current != null; current = current.getNextException()) {
            String state = current.getSQLState();
            if (state != null && state.startsWith("23")) {
                return true;
            }
            if (current instanceof java.sql.SQLIntegrityConstraintViolationException) {
                return true;
            }
            String message = current.getMessage();
            if (message != null && message.contains("SQLITE_CONSTRAINT_UNIQUE")) {
                return true;
            }
        }
        return false;
    }
}
