package com.example.accounts;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

/**
 * Server-side session storage.
 *
 * <p>Rule 4 (identifiers and tokens): the token is 32 bytes from {@link SecureRandom} -- generated
 * here, never derived from the account, the time, or anything a caller supplies, and never accepted
 * as a caller-chosen value (no session fixation). Only {@code SHA-256(token)} is stored, so a
 * reader of the database cannot replay a session, and lookups are by that digest.
 *
 * <p>Rule 3: {@link #validate} is the only way to turn a token into an account id, and it checks
 * revocation, idle expiry and absolute expiry against this table -- server-side state. Anything it
 * cannot positively confirm returns empty: fail closed.
 */
public final class SessionService {

    /** 32 bytes -> 43 unpadded base64url characters. */
    private static final int TOKEN_BYTES = 32;
    private static final int TOKEN_CHARS = 43;
    private static final int REF_BYTES = 16;

    private static final String INSERT_SQL = """
            INSERT INTO auth_session (token_hash, session_ref, account_id, created_at,
                                      last_used_at, absolute_expires_at, revoked)
            VALUES (?, ?, ?, ?, ?, ?, 0)
            """;

    private static final String SELECT_SQL = """
            SELECT session_ref, account_id, last_used_at, absolute_expires_at, revoked
            FROM auth_session WHERE token_hash = ?
            """;

    private static final String TOUCH_SQL = """
            UPDATE auth_session SET last_used_at = ? WHERE token_hash = ? AND revoked = 0
            """;

    private static final String REVOKE_SQL = """
            UPDATE auth_session SET revoked = 1 WHERE token_hash = ?
            """;

    private static final String REVOKE_ACCOUNT_SQL = """
            UPDATE auth_session SET revoked = 1 WHERE account_id = ?
            """;

    private static final String PRUNE_SQL = """
            DELETE FROM auth_session WHERE absolute_expires_at <= ? OR revoked = 1
            """;

    /**
     * A freshly issued session. {@code token} is the only copy of the secret and is the caller's to
     * wipe; {@code reference} is a non-secret handle safe to put in logs.
     */
    public record IssuedSession(String reference, char[] token, Instant expiresAt) {
    }

    private final Config config;
    private final SecureRandom random = new SecureRandom();

    public SessionService(Config config) {
        this.config = config;
    }

    /** Creates a session for {@code accountId}. Call only after authentication has succeeded. */
    public IssuedSession issue(Connection connection, long accountId, Instant now)
            throws SQLException {
        byte[] tokenBytes = new byte[TOKEN_BYTES];
        random.nextBytes(tokenBytes);
        byte[] refBytes = new byte[REF_BYTES];
        random.nextBytes(refBytes);

        char[] token = null;
        try {
            token = base64Url(tokenBytes);
            String reference = Hex.encode(refBytes);
            String tokenHash = hashToken(token);
            Instant absoluteExpiry = now.plus(config.sessionAbsoluteTimeout());

            try (PreparedStatement ps = connection.prepareStatement(INSERT_SQL)) {
                ps.setString(1, tokenHash);
                ps.setString(2, reference);
                ps.setLong(3, accountId);
                ps.setLong(4, now.getEpochSecond());
                ps.setLong(5, now.getEpochSecond());
                ps.setLong(6, absoluteExpiry.getEpochSecond());
                ps.executeUpdate();
            }
            prune(connection, now);

            Instant idleExpiry = now.plus(config.sessionIdleTimeout());
            Instant expiresAt = idleExpiry.isBefore(absoluteExpiry) ? idleExpiry : absoluteExpiry;
            IssuedSession issued = new IssuedSession(reference, token, expiresAt);
            token = null; // ownership transferred to the caller
            return issued;
        } finally {
            Wipe.bytes(tokenBytes);
            Wipe.bytes(refBytes);
            Wipe.chars(token);
        }
    }

    /** The account a valid token belongs to, or empty. Also refreshes the idle timer. */
    public Optional<ValidSession> validate(Connection connection, char[] token, Instant now)
            throws SQLException {
        if (!isWellFormedToken(token)) {
            return Optional.empty();
        }
        String tokenHash = hashToken(token);
        String reference;
        long accountId;
        try (PreparedStatement ps = connection.prepareStatement(SELECT_SQL)) {
            ps.setString(1, tokenHash);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return Optional.empty();
                }
                if (rs.getInt("revoked") != 0) {
                    return Optional.empty();
                }
                long lastUsed = rs.getLong("last_used_at");
                long absoluteExpiry = rs.getLong("absolute_expires_at");
                long nowSeconds = now.getEpochSecond();
                if (nowSeconds >= absoluteExpiry) {
                    return Optional.empty();
                }
                if (nowSeconds - lastUsed >= config.sessionIdleTimeout().getSeconds()) {
                    return Optional.empty();
                }
                reference = rs.getString("session_ref");
                accountId = rs.getLong("account_id");
            }
        }
        // Same transaction as the checks above (rule 7): the row cannot be revoked between the
        // decision and the refresh.
        try (PreparedStatement ps = connection.prepareStatement(TOUCH_SQL)) {
            ps.setLong(1, now.getEpochSecond());
            ps.setString(2, tokenHash);
            if (ps.executeUpdate() != 1) {
                return Optional.empty();
            }
        }
        return Optional.of(new ValidSession(reference, accountId));
    }

    /** A session that passed every server-side check. */
    public record ValidSession(String reference, long accountId) {
    }

    /** Revokes one session. Succeeds silently for an unknown token: nothing to disclose. */
    public void revoke(Connection connection, char[] token) throws SQLException {
        if (!isWellFormedToken(token)) {
            return;
        }
        try (PreparedStatement ps = connection.prepareStatement(REVOKE_SQL)) {
            ps.setString(1, hashToken(token));
            ps.executeUpdate();
        }
    }

    /** Revokes every session of an account, e.g. after a password change. */
    public void revokeAllForAccount(Connection connection, long accountId) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(REVOKE_ACCOUNT_SQL)) {
            ps.setLong(1, accountId);
            ps.executeUpdate();
        }
    }

    private void prune(Connection connection, Instant now) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(PRUNE_SQL)) {
            ps.setLong(1, now.getEpochSecond());
            ps.executeUpdate();
        }
    }

    /**
     * Strict format check before the token is used for anything (rule 1 and rule 4): fixed length,
     * base64url alphabet only. A value that cannot be one of our tokens never reaches a query.
     */
    static boolean isWellFormedToken(char[] token) {
        if (token == null || token.length != TOKEN_CHARS) {
            return false;
        }
        for (char c : token) {
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    private static String hashToken(char[] token) {
        byte[] ascii = new byte[token.length];
        try {
            for (int i = 0; i < token.length; i++) {
                ascii[i] = (byte) token[i]; // validated to be base64url ASCII
            }
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Hex.encode(digest.digest(ascii));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        } finally {
            Wipe.bytes(ascii);
        }
    }

    private static char[] base64Url(byte[] bytes) {
        byte[] encoded = Base64.getUrlEncoder().withoutPadding().encode(bytes);
        try {
            char[] out = new char[encoded.length];
            for (int i = 0; i < encoded.length; i++) {
                out[i] = (char) (encoded[i] & 0xff);
            }
            return out;
        } finally {
            Wipe.bytes(encoded);
        }
    }
}
