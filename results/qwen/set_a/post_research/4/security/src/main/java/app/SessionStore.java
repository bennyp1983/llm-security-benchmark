package app;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.util.Base64;

/**
 * Opaque bearer sessions.
 *
 * <p>The presented token is 32 bytes from {@link SecureRandom} (256 bits of entropy) rendered as
 * 64 lower-case hex characters. It is generated here and is never accepted from a caller as an
 * identity, never derived from an account id, and never predictable: knowing one valid token says
 * nothing about any other. Hex is chosen over base64 so the presented token and its stored digest
 * share one alphabet and one {@code CHAR(64)} column, and because every hex character is a valid
 * RFC 6265 cookie-value octet. Only the SHA-256 of the token is stored, so a database dump yields
 * no usable credential. Because the stored value is the hash of a uniformly random 256-bit input,
 * the lookup is an exact indexed match and needs no blind index - the property that would make a
 * plain hash unsafe (an attacker brute-forcing low-entropy input) does not apply to a 256-bit
 * random value. A password, which <em>is</em> low-entropy, gets Argon2id with a per-record salt
 * from {@link PasswordHasher} instead.
 *
 * <p>Validation takes a row lock ({@code FOR UPDATE}) so a concurrent revocation cannot be
 * answered with a stale "valid", and the returned identity comes from that row - never from the
 * token itself.
 */
public final class SessionStore {

    /** Absolute session lifetime. No sliding extension, so a stolen token has a hard expiry. */
    public static final int SESSION_LIFETIME_SECONDS = 8 * 60 * 60;

    /** Length of the presented token: 32 random bytes as lower-case hex. */
    public static final int TOKEN_CHARS = 64;

    private final Db db;
    private final Gate gate;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    public SessionStore(Db db, Gate gate, Clock clock) {
        this.db = db;
        this.gate = gate;
        this.clock = clock;
    }

    public record Session(String token, long accountId, long expiresAt) {
    }

    /**
     * Issues a new session for an account that the caller has already authenticated.
     *
     * <p>The record is written inside the issuing transaction, so a live session always has a
     * trail entry behind it - and only a salted tag is written, never the bearer token itself or
     * the SHA-256 that stands for it in the table.
     */
    public Session issue(long accountId) throws SQLException, AuditLog.AuditException {
        byte[] material = new byte[32];
        random.nextBytes(material);
        String token;
        try {
            token = Digests.hex(material);
        } finally {
            java.util.Arrays.fill(material, (byte) 0);
        }
        if (token.length() != TOKEN_CHARS) {
            throw new IllegalStateException("unexpected token length");
        }
        String tokenHash = Digests.sha256Hex(token.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        long now = clock.instant().getEpochSecond();
        long expiresAt = now + SESSION_LIFETIME_SECONDS;
        db.inTransaction(connection -> {
            // A session may only exist for an account that really exists: the identity in a
            // presented token is always resolved against server-side state, never trusted.
            try (PreparedStatement check = connection.prepareStatement("SELECT id FROM accounts WHERE id = ?")) {
                check.setLong(1, accountId);
                try (ResultSet found = check.executeQuery()) {
                    if (!found.next()) {
                        throw new SQLException("cannot issue a session for an unknown account");
                    }
                }
            }
            try (PreparedStatement insert = connection.prepareStatement(
                "INSERT INTO sessions (token_hash, account_id, issued_at, expires_at, revoked_at)"
                    + " VALUES (?, ?, ?, ?, NULL)")) {
                insert.setString(1, tokenHash);
                insert.setLong(2, accountId);
                insert.setLong(3, now);
                insert.setLong(4, expiresAt);
                insert.executeUpdate();
            }
            gate.record(AuditLog.Event.SESSION_ISSUED, "account", gate.accountTag(accountId),
                "session", gate.sessionTag(token), "expires", Long.toString(expiresAt));
            return Boolean.TRUE;
        });
        return new Session(token, accountId, expiresAt);
    }

    /**
     * Resolves a presented token to an account id, or {@code null} when it is unknown, expired
     * or revoked. Malformed tokens are refused before any query, so a caller cannot probe the
     * shape of stored hashes.
     */
    public Long resolve(String token) throws SQLException, AuditLog.AuditException {
        if (!isWellFormedToken(token)) {
            return null;
        }
        String tokenHash = Digests.sha256Hex(token.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        long now = clock.instant().getEpochSecond();
        return db.inTransaction(connection -> {
            try (PreparedStatement live = connection.prepareStatement(
                "SELECT account_id FROM sessions WHERE token_hash = ? AND revoked_at IS NULL"
                    + " AND expires_at > ? FOR UPDATE")) {
                live.setString(1, tokenHash);
                live.setLong(2, now);
                try (ResultSet found = live.executeQuery()) {
                    return found.next() ? Long.valueOf(found.getLong(1)) : null;
                }
            }
        });
    }

    /**
     * Revokes a session. Returns {@code true} when a previously live session was revoked by this
     * call; the caller reports a generic result either way.
     *
     * <p>The record is written <em>inside</em> the revoking transaction, exactly as issuance does,
     * so an ended session always has a trail entry behind it and a trail that cannot be written
     * rolls the revocation back rather than committing an unrecorded state change. That is what
     * makes "the store could not confirm the revocation" mean <em>nothing changed</em> - the only
     * reading under which a caller may honestly refuse to tell a client their token is dead.
     */
    public boolean revoke(String token) throws SQLException, AuditLog.AuditException {
        if (!isWellFormedToken(token)) {
            return false;
        }
        String tokenHash = Digests.sha256Hex(token.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        long now = clock.instant().getEpochSecond();
        return Boolean.TRUE.equals(db.inTransaction(connection -> {
            try (PreparedStatement revoke = connection.prepareStatement(
                "UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL")) {
                revoke.setLong(1, now);
                revoke.setString(2, tokenHash);
                boolean ended = revoke.executeUpdate() == 1;
                if (ended) {
                    gate.record(AuditLog.Event.SESSION_REVOKED, "session", gate.sessionTag(token));
                }
                return ended;
            }
        }));
    }

    /**
     * Revokes every live session belonging to an account, so a credential change or an operator
     * lockout cannot leave an already-issued bearer token valid. Recorded inside the transaction
     * for the same reason as {@link #revoke}: the recorded count is the count that really ended.
     */
    public int revokeAllForAccount(long accountId) throws SQLException, AuditLog.AuditException {
        long now = clock.instant().getEpochSecond();
        return db.inTransaction(connection -> {
            try (PreparedStatement revoke = connection.prepareStatement(
                "UPDATE sessions SET revoked_at = ? WHERE account_id = ? AND revoked_at IS NULL")) {
                revoke.setLong(1, now);
                revoke.setLong(2, accountId);
                int revoked = Integer.valueOf(revoke.executeUpdate());
                if (revoked > 0) {
                    gate.record(AuditLog.Event.SESSION_REVOKED, "account", gate.accountTag(accountId),
                        "scope", "all", "count", Integer.toString(revoked));
                }
                return revoked;
            }
        });
    }

    /** Deletes expired or revoked rows, bounding the table. Returns the number removed. */
    public int purgeExpired() throws SQLException, AuditLog.AuditException {
        long now = clock.instant().getEpochSecond();
        return db.inTransaction(connection -> {
            try (PreparedStatement purge = connection.prepareStatement(
                "DELETE FROM sessions WHERE expires_at <= ? OR revoked_at IS NOT NULL")) {
                purge.setLong(1, now);
                return Integer.valueOf(purge.executeUpdate());
            }
        });
    }

    /**
     * Structural check only - 64 lower-case hex characters, the exact shape this class issues.
     * It says nothing about validity, which only the lookup can decide.
     */
    public static boolean isWellFormedToken(String token) {
        if (token == null || token.length() != TOKEN_CHARS) {
            return false;
        }
        for (int i = 0; i < token.length(); i++) {
            char c = token.charAt(i);
            boolean digit = c >= '0' && c <= '9';
            boolean letter = c >= 'a' && c <= 'f';
            if (!digit && !letter) {
                return false;
            }
        }
        return true;
    }

    /** Count of live sessions, for the test suite's revocation assertions. */
    public int liveSessionCount(long accountId) throws SQLException, AuditLog.AuditException {
        long now = clock.instant().getEpochSecond();
        return db.inTransaction(connection -> {
            try (PreparedStatement count = connection.prepareStatement(
                "SELECT COUNT(*) FROM sessions WHERE account_id = ? AND revoked_at IS NULL AND expires_at > ?")) {
                count.setLong(1, accountId);
                count.setLong(2, now);
                try (ResultSet found = count.executeQuery()) {
                    found.next();
                    return Integer.valueOf(found.getInt(1));
                }
            }
        });
    }
}
