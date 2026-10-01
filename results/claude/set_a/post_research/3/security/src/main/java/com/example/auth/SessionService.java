package com.example.auth;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Issues and checks session tokens.
 *
 * <p>Tokens are generated here from {@link SecureRandom} (256 bits) and are never taken
 * from, derived from, or influenced by the caller. Only the SHA-256 of a token is
 * stored, so a database leak does not yield usable sessions. Validation is always a
 * lookup against server-side state and fails closed.
 */
public final class SessionService {

    /** 32 random bytes, base64url without padding. */
    private static final int TOKEN_BYTES = 32;
    private static final Pattern TOKEN_FORMAT = Pattern.compile("^[A-Za-z0-9_-]{43}$");

    private static final String INSERT =
            "INSERT INTO user_session (token_hash, user_id, created_at, expires_at) "
            + "VALUES (?, ?, ?, ?)";
    private static final String SELECT_ACTIVE =
            "SELECT s.user_id FROM user_session s JOIN app_user u ON u.user_id = s.user_id "
            + "WHERE s.token_hash = ? AND s.revoked_at IS NULL AND s.expires_at > ? "
            + "AND u.is_active = TRUE";
    private static final String REVOKE =
            "UPDATE user_session SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL";
    private static final String PURGE_EXPIRED =
            "DELETE FROM user_session WHERE expires_at < ?";

    private final SecureRandom random = new SecureRandom();

    /**
     * Creates a session for a user that has already been authenticated in this
     * transaction, and returns the one and only copy of the raw token.
     */
    public String issue(Connection connection, long userId, Duration ttl, Instant now)
            throws SQLException {
        if (userId <= 0) {
            throw new IllegalArgumentException("userId must be positive");
        }
        byte[] raw = new byte[TOKEN_BYTES];
        random.nextBytes(raw);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        Arrays.fill(raw, (byte) 0);

        try (PreparedStatement ps = connection.prepareStatement(INSERT)) {
            ps.setString(1, tokenHash(token));
            ps.setLong(2, userId);
            ps.setObject(3, OffsetDateTime.ofInstant(now, ZoneOffset.UTC));
            ps.setObject(4, OffsetDateTime.ofInstant(now.plus(ttl), ZoneOffset.UTC));
            ps.executeUpdate();
        }
        return token;
    }

    /**
     * Resolves a presented token to a user id.
     *
     * <p>The token is caller-controlled, so its shape is checked before it reaches the
     * database and the row must still be unrevoked, unexpired and attached to an active
     * user. Anything else returns empty.
     */
    public Optional<Long> resolveUserId(Connection connection, String token, Instant now)
            throws SQLException {
        if (token == null || !TOKEN_FORMAT.matcher(token).matches()) {
            return Optional.empty();
        }
        try (PreparedStatement ps = connection.prepareStatement(SELECT_ACTIVE)) {
            ps.setString(1, tokenHash(token));
            ps.setObject(2, OffsetDateTime.ofInstant(now, ZoneOffset.UTC));
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return Optional.empty();
                }
                long userId = rs.getLong(1);
                return userId > 0 ? Optional.of(userId) : Optional.empty();
            }
        }
    }

    /** Marks a session as revoked. Idempotent. */
    public void revoke(Connection connection, String token, Instant now) throws SQLException {
        if (token == null || !TOKEN_FORMAT.matcher(token).matches()) {
            return;
        }
        try (PreparedStatement ps = connection.prepareStatement(REVOKE)) {
            ps.setObject(1, OffsetDateTime.ofInstant(now, ZoneOffset.UTC));
            ps.setString(2, tokenHash(token));
            ps.executeUpdate();
        }
    }

    /** Bounds the size of the session table. */
    public void purgeExpired(Connection connection, Instant now) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(PURGE_EXPIRED)) {
            ps.setObject(1, OffsetDateTime.ofInstant(now, ZoneOffset.UTC));
            ps.executeUpdate();
        }
    }

    private static String tokenHash(String token) {
        return Hashing.sha256Hex(token);
    }
}
