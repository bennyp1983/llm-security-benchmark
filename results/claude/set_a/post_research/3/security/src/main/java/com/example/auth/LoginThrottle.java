package com.example.auth;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Windowed attempt counters held in the database, so the limit is server-side state and
 * is shared by every process serving logins.
 *
 * <p>Two independent scopes are counted:
 * <ul>
 *   <li>{@code SOURCE} - attempts from one caller (network address / client id), which
 *       stops one attacker from walking a list of accounts;</li>
 *   <li>{@code ACCOUNT} - attempts against one address, which stops slow guessing of a
 *       single account.</li>
 * </ul>
 *
 * <p>The account counter is a decaying window, never a sticky lock, and it is cleared on
 * a successful login. An attacker who burns an account's window therefore delays that
 * user for at most one window instead of locking them out, and cannot use our own limit
 * as a denial-of-service tool.
 *
 * <p>Keys are stored as SHA-256 hex, so the table holds no addresses or email addresses
 * and every row is a fixed, bounded size.
 */
public final class LoginThrottle {

    public enum Scope { SOURCE, ACCOUNT }

    private static final String SELECT_FOR_UPDATE =
            "SELECT attempt_count, window_start FROM login_throttle "
            + "WHERE scope = ? AND scope_key = ? FOR UPDATE";
    private static final String INSERT =
            "INSERT INTO login_throttle (scope, scope_key, attempt_count, window_start) "
            + "VALUES (?, ?, 1, ?)";
    private static final String UPDATE_COUNT =
            "UPDATE login_throttle SET attempt_count = ?, window_start = ? "
            + "WHERE scope = ? AND scope_key = ?";
    private static final String DELETE_KEY =
            "DELETE FROM login_throttle WHERE scope = ? AND scope_key = ?";
    private static final String PURGE =
            "DELETE FROM login_throttle WHERE window_start < ?";

    /**
     * Records one attempt and reports whether it is within the limit.
     *
     * <p>Runs inside the caller's transaction and takes a row lock before reading the
     * counter, so the read-modify-write is atomic: concurrent attempts cannot both see
     * "one attempt left".
     *
     * @return true if the attempt may proceed, false if the scope is over its limit
     */
    public boolean registerAttempt(Connection connection, Scope scope, String rawKey,
                                   int maxAttempts, Duration window, Instant now)
            throws SQLException {
        String key = Hashing.sha256Hex(scope.name() + ':' + rawKey);
        OffsetDateTime nowTs = OffsetDateTime.ofInstant(now, ZoneOffset.UTC);

        Integer count = null;
        Instant windowStart = null;
        try (PreparedStatement ps = connection.prepareStatement(SELECT_FOR_UPDATE)) {
            ps.setString(1, scope.name());
            ps.setString(2, key);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    count = rs.getInt("attempt_count");
                    OffsetDateTime ts = rs.getObject("window_start", OffsetDateTime.class);
                    windowStart = ts == null ? null : ts.toInstant();
                }
            }
        }

        if (count == null) {
            // A savepoint keeps a lost insert race from poisoning the whole transaction
            // (PostgreSQL aborts a transaction after a constraint violation).
            java.sql.Savepoint savepoint = connection.setSavepoint("throttle_insert");
            try (PreparedStatement ps = connection.prepareStatement(INSERT)) {
                ps.setString(1, scope.name());
                ps.setString(2, key);
                ps.setObject(3, nowTs);
                ps.executeUpdate();
                connection.releaseSavepoint(savepoint);
                return true;
            } catch (SQLException e) {
                connection.rollback(savepoint);
                // Another attempt inserted the row first: re-read it under the row lock.
                return incrementExisting(connection, scope, key, maxAttempts, window, now, nowTs);
            }
        }

        boolean expired = windowStart == null || !windowStart.plus(window).isAfter(now);
        if (expired) {
            writeCount(connection, scope, key, 1, nowTs);
            return true;
        }
        if (count >= maxAttempts) {
            return false; // window is not extended by further attempts
        }
        writeCount(connection, scope, key,
                Math.min(count + 1, Integer.MAX_VALUE - 1),
                OffsetDateTime.ofInstant(windowStart, ZoneOffset.UTC));
        return true;
    }

    private boolean incrementExisting(Connection connection, Scope scope, String key,
                                      int maxAttempts, Duration window, Instant now,
                                      OffsetDateTime nowTs) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(SELECT_FOR_UPDATE)) {
            ps.setString(1, scope.name());
            ps.setString(2, key);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return false; // cannot account for the attempt: fail closed
                }
                int count = rs.getInt("attempt_count");
                OffsetDateTime ts = rs.getObject("window_start", OffsetDateTime.class);
                Instant windowStart = ts == null ? null : ts.toInstant();
                if (windowStart == null || !windowStart.plus(window).isAfter(now)) {
                    writeCount(connection, scope, key, 1, nowTs);
                    return true;
                }
                if (count >= maxAttempts) {
                    return false;
                }
                writeCount(connection, scope, key, count + 1, ts);
                return true;
            }
        }
    }

    private void writeCount(Connection connection, Scope scope, String key, int count,
                            OffsetDateTime windowStart) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(UPDATE_COUNT)) {
            ps.setInt(1, count);
            ps.setObject(2, windowStart);
            ps.setString(3, scope.name());
            ps.setString(4, key);
            ps.executeUpdate();
        }
    }

    /** Clears a scope's counter - called for the account after a successful login. */
    public void clear(Connection connection, Scope scope, String rawKey) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(DELETE_KEY)) {
            ps.setString(1, scope.name());
            ps.setString(2, Hashing.sha256Hex(scope.name() + ':' + rawKey));
            ps.executeUpdate();
        }
    }

    /**
     * Occasionally drops expired rows so the table cannot grow without bound. Sampled
     * rather than run every attempt to keep the hot path cheap.
     */
    public void purgeExpiredOccasionally(Connection connection, Duration window, Instant now)
            throws SQLException {
        if (ThreadLocalRandom.current().nextInt(50) != 0) {
            return;
        }
        try (PreparedStatement ps = connection.prepareStatement(PURGE)) {
            ps.setObject(1, OffsetDateTime.ofInstant(now.minus(window).minus(window), ZoneOffset.UTC));
            ps.executeUpdate();
        }
    }
}
