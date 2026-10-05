package com.example.auth;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;

/**
 * Reads and writes credential rows. Every statement is a {@link PreparedStatement} with
 * bound parameters - no SQL text is ever assembled from input - and every column read
 * back is range-checked before it is used.
 */
public final class CredentialRepository {

    private static final String SELECT_FOR_UPDATE =
            "SELECT user_id, password_hash, is_active FROM app_user WHERE email = ? FOR UPDATE";

    private static final String UPSERT =
            "UPDATE app_user SET password_hash = ?, is_active = TRUE WHERE email = ?";

    private static final String INSERT =
            "INSERT INTO app_user (email, password_hash, is_active, created_at) "
            + "VALUES (?, ?, TRUE, CURRENT_TIMESTAMP)";

    /** A stored credential. The hash is kept only for the life of one verification. */
    public record Credential(long userId, String passwordHash, boolean active) {
    }

    /**
     * Locks and returns the credential row for an email address.
     *
     * <p>The row is locked for the duration of the caller's transaction so that
     * "verify the password, then issue a session" cannot interleave with a concurrent
     * password change or deactivation.
     *
     * @param email an address already validated by {@link InputValidator}
     */
    public Optional<Credential> findForUpdate(Connection connection, String email) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(SELECT_FOR_UPDATE)) {
            ps.setString(1, email);
            ps.setMaxFieldSize(512); // bound what a hostile row can make us read
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return Optional.empty();
                }
                long userId = rs.getLong("user_id");
                String hash = rs.getString("password_hash");
                boolean active = rs.getBoolean("is_active");
                if (rs.wasNull() || userId <= 0 || hash == null || hash.isBlank()) {
                    // Malformed row: treat as unusable rather than as a pass.
                    return Optional.of(new Credential(Math.max(userId, 1), "", false));
                }
                return Optional.of(new Credential(userId, hash, active));
            }
        }
    }

    /** Creates or replaces a user's password hash. Used by the admin tool only. */
    public void saveCredential(Connection connection, String email, String encodedHash)
            throws SQLException {
        try (PreparedStatement update = connection.prepareStatement(UPSERT)) {
            update.setString(1, encodedHash);
            update.setString(2, email);
            if (update.executeUpdate() > 0) {
                return;
            }
        }
        try (PreparedStatement insert = connection.prepareStatement(INSERT)) {
            insert.setString(1, email);
            insert.setString(2, encodedHash);
            insert.executeUpdate();
        }
    }
}
