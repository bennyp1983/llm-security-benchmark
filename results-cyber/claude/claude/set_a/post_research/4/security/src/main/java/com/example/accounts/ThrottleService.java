package com.example.accounts;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;

/**
 * Attempt counting for login and registration.
 *
 * <p>Rule 3 (authentication and access): failures are counted <em>per source</em> and
 * <em>per account</em>. The per-source counter is what actually stops credential stuffing, because
 * it bites regardless of how many different accounts the attacker spreads across. The per-account
 * counter is the backstop for a distributed attack on one high-value account.
 *
 * <p>The per-account counter is deliberately a <em>short sliding window</em>, not a lock: it never
 * needs an administrator to clear it, it expires on its own after
 * {@link Config#throttleWindow()} (15 minutes by default) and any successful login clears it
 * immediately. So the worst an attacker can do by burning a victim's counter is delay that victim
 * for one window -- they cannot park a legitimate user outside their account indefinitely, which is
 * the lockout-as-denial-of-service trap the rule warns about.
 *
 * <p>Rule 5: the identifier being counted (a client IP, an email) is never stored in the clear.
 * Only a SHA-256 digest over a domain-separated, optionally peppered input is kept, so the table is
 * useful for rate limiting but is not a log of who tried to log in from where.
 *
 * <p>Rule 7: callers must invoke these methods inside one {@link Database#inTransaction} unit, so
 * that read-check-increment cannot interleave with another request's increment.
 */
public final class ThrottleService {

    /** Outcome of a throttle check. */
    public enum Decision {
        ALLOW,
        /** Too many recent failures from this source. */
        SOURCE_THROTTLED,
        /** Too many recent failures against this account identifier. */
        ACCOUNT_THROTTLED;

        public boolean allowed() {
            return this == ALLOW;
        }
    }

    private static final String SCOPE_ACCOUNT = "account";
    private static final String SCOPE_SOURCE = "source";

    private static final String SELECT_SQL = """
            SELECT window_start, failures FROM auth_attempt WHERE scope = ? AND scope_key = ?
            """;

    private static final String UPSERT_SQL = """
            INSERT INTO auth_attempt (scope, scope_key, window_start, failures)
            VALUES (?, ?, ?, 1)
            ON CONFLICT (scope, scope_key) DO UPDATE SET
              window_start = CASE WHEN auth_attempt.window_start <= ? THEN excluded.window_start
                                  ELSE auth_attempt.window_start END,
              failures     = CASE WHEN auth_attempt.window_start <= ? THEN 1
                                  ELSE auth_attempt.failures + 1 END
            """;

    private static final String DELETE_SQL = """
            DELETE FROM auth_attempt WHERE scope = ? AND scope_key = ?
            """;

    private static final String PRUNE_SQL = """
            DELETE FROM auth_attempt WHERE window_start <= ?
            """;

    private final Config config;
    private final byte[] pepper;

    public ThrottleService(Config config) {
        this.config = config;
        this.pepper = config.pepper().clone();
    }

    /**
     * Atomically checks both counters and, if the attempt is allowed, counts it.
     *
     * <p>Rule 7 (concurrency): the check and the increment happen in one statement pair inside the
     * caller's transaction, which holds the write lock. There is no window in which two requests
     * both observe "one attempt left" and both proceed.
     *
     * <p>The attempt is counted whether it later succeeds or fails; a successful login then clears
     * the account counter via {@link #clearAccount}. A blocked attempt is <em>not</em> counted, so
     * an attacker cannot keep renewing a victim's window forever -- once the source is blocked its
     * traffic stops feeding the account counter and that counter ages out.
     *
     * @param sourceId          server-observed origin of the request (peer address or local actor),
     *                          never a client-supplied header
     * @param accountIdentifier the identifier being attempted, or {@code null} for source-only
     *                          limiting (registration, where there is no account to protect yet)
     */
    public Decision tryAcquire(Connection connection, String sourceId, String accountIdentifier,
                               Instant now) throws SQLException {
        long cutoff = windowCutoff(now);
        String sourceKey = key(SCOPE_SOURCE, sourceId);
        if (failures(connection, SCOPE_SOURCE, sourceKey, cutoff) >= config.maxFailuresPerSource()) {
            return Decision.SOURCE_THROTTLED;
        }
        String accountKey = accountIdentifier == null ? null : key(SCOPE_ACCOUNT, accountIdentifier);
        if (accountKey != null
                && failures(connection, SCOPE_ACCOUNT, accountKey, cutoff)
                        >= config.maxFailuresPerAccount()) {
            return Decision.ACCOUNT_THROTTLED;
        }
        bump(connection, SCOPE_SOURCE, sourceKey, now, cutoff);
        if (accountKey != null) {
            bump(connection, SCOPE_ACCOUNT, accountKey, now, cutoff);
        }
        prune(connection, cutoff);
        return Decision.ALLOW;
    }

    /**
     * Clears the account-scope counter after a successful authentication, so a victim's own
     * successful login immediately undoes an attacker's failed attempts against them.
     *
     * <p>The source-scope counter is deliberately <em>not</em> cleared: otherwise an attacker who
     * holds one valid credential could log in to reset their own budget between probes and the
     * per-source limit would be worthless.
     */
    public void clearAccount(Connection connection, String accountIdentifier, Instant now)
            throws SQLException {
        if (accountIdentifier != null) {
            clear(connection, SCOPE_ACCOUNT, key(SCOPE_ACCOUNT, accountIdentifier));
        }
        prune(connection, windowCutoff(now));
    }

    private int failures(Connection connection, String scope, String scopeKey, long cutoff)
            throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(SELECT_SQL)) {
            ps.setString(1, scope);
            ps.setString(2, scopeKey);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return 0;
                }
                long windowStart = rs.getLong("window_start");
                if (windowStart <= cutoff) {
                    return 0; // window expired; the row is stale
                }
                int failures = rs.getInt("failures");
                return Math.max(failures, 0);
            }
        }
    }

    private void bump(Connection connection, String scope, String scopeKey, Instant now, long cutoff)
            throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(UPSERT_SQL)) {
            ps.setString(1, scope);
            ps.setString(2, scopeKey);
            ps.setLong(3, now.getEpochSecond());
            ps.setLong(4, cutoff);
            ps.setLong(5, cutoff);
            ps.executeUpdate();
        }
    }

    private void clear(Connection connection, String scope, String scopeKey) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(DELETE_SQL)) {
            ps.setString(1, scope);
            ps.setString(2, scopeKey);
            ps.executeUpdate();
        }
    }

    /** Keeps the table bounded (rule 5) -- expired windows carry no information. */
    private void prune(Connection connection, long cutoff) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(PRUNE_SQL)) {
            ps.setLong(1, cutoff);
            ps.executeUpdate();
        }
    }

    private long windowCutoff(Instant now) {
        Duration window = config.throttleWindow();
        return now.minus(window).getEpochSecond();
    }

    /** Domain-separated digest of the identifier; 64 lowercase hex characters. */
    private String key(String scope, String identifier) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
        if (pepper.length > 0) {
            digest.update(pepper);
        }
        digest.update(scope.getBytes(StandardCharsets.UTF_8));
        digest.update((byte) ':');
        digest.update(identifier.getBytes(StandardCharsets.UTF_8));
        return Hex.encode(digest.digest());
    }
}
