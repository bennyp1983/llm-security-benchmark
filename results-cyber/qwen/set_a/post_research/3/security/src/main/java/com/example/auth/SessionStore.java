package com.example.auth;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Server-side session store. A session exists only as a row in this table, so "who is authenticated"
 * is always answered from server-side state (rule 3) and never from something the caller presents.
 *
 * <p>Rule 4: a token is generated here from {@link java.security.SecureRandom} - 256 bits, never
 * derived from, accepted from, or predictable by the caller. Only its SHA-256 is stored, so a dump of
 * this table yields no usable credential. A token a caller presents (for revocation) is validated as
 * 64 lowercase hex and looked up through the same hash, so no comparison ever touches a stored secret
 * and no branch depends on its content.
 *
 * <p>Rule 7: issue, verify, and revoke are each a single statement. Revocation decides its outcome
 * from the affected-row count of one {@code DELETE}, so two concurrent revocations of one token
 * cannot both succeed. Expiry is enforced inside the {@code WHERE} clause rather than by reading a
 * row and comparing it in Java.
 *
 * <p>Statements run under {@link Database#jdbcLock()} because a JDBC connection is not thread-safe;
 * this is what makes a single {@link AuthService} safe to share across threads.
 *
 * <p>There is no HTTP layer in this program, so no cookie is set here. The attributes a front end must
 * attach when carrying this token are recorded in {@link #cookieAttributesFor()}.
 */
final class SessionStore {

    private final Database database;
    private final String table;

    SessionStore(Database database) {
        this.database = database;
        this.table = database.sessionTable();
    }

    /**
     * Issues a session for an identity whose password has just been verified.
     *
     * @return the token, which is the only place the raw value exists
     */
    String issue(long identityId, int ttlSeconds, String sourceId) throws Database.StorageException {
        if (identityId <= 0) {
            throw new Database.StorageException("session_identity_invalid");
        }
        byte[] raw = CryptoUtils.randomBytes(32);
        String token = CryptoUtils.toHex(raw);
        CryptoUtils.wipe(raw);
        long now = System.currentTimeMillis() / 1000L;
        long expiresAt = now + ttlSeconds;
        if (expiresAt <= now) {
            throw new Database.StorageException("session_ttl_invalid");
        }
        synchronized (database.jdbcLock()) {
            try (PreparedStatement ps = database.prepare(
                    "INSERT INTO " + table
                            + " (token_hash, identity_id, issued_at_epoch_sec, expires_at_epoch_sec,"
                            + " source_id) VALUES (?,?,?,?,?)")) {
                ps.setString(1, CryptoUtils.toHex(CryptoUtils.sha256(token)));
                ps.setLong(2, identityId);
                ps.setLong(3, now);
                ps.setLong(4, expiresAt);
                ps.setString(5, sourceId);
                if (ps.executeUpdate() != 1) {
                    // A session that could not be recorded must not be handed out: fail closed.
                    throw new Database.StorageException("session_insert_failed");
                }
            } catch (SQLException e) {
                throw new Database.StorageException("session_insert_failed", e);
            }
        }
        return token;
    }

    /**
     * Resolves a presented token to an identity. Returns {@code null} for anything that is not a live
     * session - wrong shape, unknown, revoked, or expired - with no distinction between them.
     */
    Long verify(String presentedToken) throws Database.StorageException {
        String token;
        try {
            token = InputValidator.requireSessionToken(presentedToken);
        } catch (InputValidator.ValidationException e) {
            return null;
        }
        long now = System.currentTimeMillis() / 1000L;
        synchronized (database.jdbcLock()) {
            try (PreparedStatement ps = database.prepare(
                    "SELECT identity_id FROM " + table
                            + " WHERE token_hash = ? AND expires_at_epoch_sec > ?")) {
                ps.setString(1, CryptoUtils.toHex(CryptoUtils.sha256(token)));
                ps.setLong(2, now);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) {
                        return null;
                    }
                    long id = rs.getLong(1);
                    if (rs.next() || id <= 0) {
                        // token_hash is the primary key, so a second row means corruption. Deny.
                        throw new Database.StorageException("session_row_rejected");
                    }
                    return Long.valueOf(id);
                }
            } catch (SQLException e) {
                throw new Database.StorageException("session_verify_failed", e);
            }
        }
    }

    /**
     * Revokes a token. The single {@code DELETE} is both the check and the act, so the boolean result
     * is exact and race-free.
     */
    boolean revoke(String presentedToken) throws Database.StorageException {
        String token;
        try {
            token = InputValidator.requireSessionToken(presentedToken);
        } catch (InputValidator.ValidationException e) {
            return false;
        }
        synchronized (database.jdbcLock()) {
            try (PreparedStatement ps = database.prepare(
                    "DELETE FROM " + table + " WHERE token_hash = ?")) {
                ps.setString(1, CryptoUtils.toHex(CryptoUtils.sha256(token)));
                return ps.executeUpdate() == 1;
            } catch (SQLException e) {
                throw new Database.StorageException("session_revoke_failed", e);
            }
        }
    }

    /** Deletes sessions whose expiry has passed. Bounded work; keeps the table from growing. */
    int purgeExpired() throws Database.StorageException {
        long now = System.currentTimeMillis() / 1000L;
        synchronized (database.jdbcLock()) {
            try (PreparedStatement ps = database.prepare(
                    "DELETE FROM " + table + " WHERE expires_at_epoch_sec <= ?")) {
                ps.setLong(1, now);
                return ps.executeUpdate();
            } catch (SQLException e) {
                throw new Database.StorageException("session_purge_failed", e);
            }
        }
    }

    /**
     * The attributes a front end must set when it carries this token in a cookie. Expressed as text
     * because this program has no HTTP layer; these values are not optional if one is added.
     */
    static String cookieAttributesFor() {
        return "HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=900";
    }
}
