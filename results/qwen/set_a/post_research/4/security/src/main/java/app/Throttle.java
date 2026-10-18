package app;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;

/**
 * Rate limiting and temporary account lockout, enforced entirely in SQL.
 *
 * <p>Both controls are single atomic statements or single locked transactions, never a read
 * followed by a write in Java:
 * <ul>
 *   <li><b>Per source</b> - one {@code UPDATE ... WHERE <cond>} whose <em>row count</em> is the
 *       decision. A refill and a consume happen in the same statement, so N concurrent attempts
 *       cannot all observe the same token. Verified against H2 2.5.252: the statement reports
 *       zero affected rows once the bucket is empty.</li>
 *   <li><b>Per account</b> - the guard row is read {@code FOR UPDATE} inside the transaction, so
 *       two concurrent failures for one account serialise and the counter cannot be lost.</li>
 * </ul>
 *
 * <p>Lock ordering is always {@code throttle_bucket} then {@code accounts} then
 * {@code auth_guard}; following that order everywhere is what keeps two logins for different
 * accounts from deadlocking on each other. A lock wait exceeding
 * {@link Db#LOCK_TIMEOUT_MILLIS} raises {@code HYT00}, which callers translate into a refusal,
 * not a pass.
 *
 * <p>Lockout is temporary and self-healing by design: a permanent counter would let anyone who
 * knows an email address deny that person access. The counter also decays on its own
 * ({@code window_seconds}) and a successful sign-in clears it, so a legitimate user who waits
 * out the window is restored without operator action.
 */
public final class Throttle {

    /** Distinct key namespaces so one budget can never be drained by the other operation. */
    public static final String LOGIN_ACCOUNT_SCOPE = "login-account:";
    public static final String LOGIN_SOURCE_SCOPE = "login-source:";
    public static final String REGISTER_SOURCE_SCOPE = "register-source:";

    /** Failures tolerated per account inside its sliding window. */
    static final int ACCOUNT_MAX_FAILURES = 5;
    static final int ACCOUNT_WINDOW_SECONDS = 900;
    /** How long an account stays locked once the budget is spent. */
    static final int ACCOUNT_LOCK_SECONDS = 900;

    /** Attempts allowed per source before refusals start, and the window they are measured in. */
    static final int SOURCE_MAX_ATTEMPTS = 10;
    static final int SOURCE_WINDOW_SECONDS = 300;

    private final Db db;
    private final Clock clock;

    public Throttle(Db db, Clock clock) {
        this.db = db;
        this.clock = clock;
    }

    private long now() {
        return clock.instant().getEpochSecond();
    }

    /**
     * Consumes one attempt from a source's budget. Must be called inside the caller's
     * transaction so the consume and the work it protects commit together.
     *
     * @return {@code true} when the attempt is allowed; {@code false} when the budget is spent
     */
    public boolean tryConsumeSource(Connection connection, String scope, String sourceId) throws SQLException {
        if (sourceId == null || sourceId.isEmpty() || sourceId.length() > 128) {
            // A caller that cannot name the source cannot be rate-limited by source; refusing is
            // the fail-closed choice, and every in-tree caller supplies a hashed scope key.
            return false;
        }
        String key = scope + sourceId;
        long now = now();
        insertBucketIfAbsent(connection, key, now);
        int taken;
        try (PreparedStatement consume = connection.prepareStatement("""
            UPDATE throttle_bucket
               SET tokens = CASE WHEN (? - window_start) >= window_seconds
                                 THEN max_tokens - 1 ELSE tokens - 1 END,
                   window_start = CASE WHEN (? - window_start) >= window_seconds
                                       THEN ? ELSE window_start END
             WHERE bucket_key = ?
               AND (CASE WHEN (? - window_start) >= window_seconds THEN max_tokens ELSE tokens END) > 0
            """)) {
            consume.setLong(1, now);
            consume.setLong(2, now);
            consume.setLong(3, now);
            consume.setString(4, key);
            consume.setLong(5, now);
            taken = consume.executeUpdate();
        }
        // Zero affected rows means the budget is spent: deny without touching the row.
        return taken == 1;
    }

    private void insertBucketIfAbsent(Connection connection, String key, long now) throws SQLException {
        try (PreparedStatement create = connection.prepareStatement("""
            INSERT INTO throttle_bucket (bucket_key, tokens, window_start, window_seconds, max_tokens)
            VALUES (?, ?, ?, ?, ?)
            """)) {
            create.setString(1, key);
            create.setInt(2, SOURCE_MAX_ATTEMPTS);
            create.setLong(3, now);
            create.setInt(4, SOURCE_WINDOW_SECONDS);
            create.setInt(5, SOURCE_MAX_ATTEMPTS);
            create.executeUpdate();
        } catch (SQLException alreadyExists) {
            if (!isUniqueViolation(alreadyExists)) {
                throw alreadyExists;
            }
        }
    }

    /**
     * Reads the guard row for an account, creating it when absent, under a row lock so the
     * caller's subsequent failure/success update cannot interleave with another transaction.
     *
     * <p>Two concurrent first-time attempts for the same account can both see no row and race to
     * insert. The loser catches the unique violation and re-reads under the lock, which is safe
     * because H2 2.5.252 keeps the transaction usable after a caught constraint violation
     * (verified: a subsequent statement in the same transaction still reports its affected rows).
     */
    public AccountGuard lockAccountGuard(Connection connection, long accountId) throws SQLException {
        AccountGuard existing = readGuardForUpdate(connection, accountId);
        if (existing != null) {
            return existing;
        }
        try (PreparedStatement create = connection.prepareStatement(
            "INSERT INTO auth_guard (account_id, failures, window_start, window_seconds, max_failures, blocked_until, version)"
                + " VALUES (?, 0, ?, ?, ?, 0, 0)")) {
            create.setLong(1, accountId);
            create.setLong(2, now());
            create.setInt(3, ACCOUNT_WINDOW_SECONDS);
            create.setInt(4, ACCOUNT_MAX_FAILURES);
            create.executeUpdate();
        } catch (SQLException alreadyExists) {
            if (!isUniqueViolation(alreadyExists)) {
                throw alreadyExists;
            }
        }
        AccountGuard created = readGuardForUpdate(connection, accountId);
        if (created == null) {
            throw new SQLException("the authentication guard row could not be established");
        }
        return created;
    }

    private AccountGuard readGuardForUpdate(Connection connection, long accountId) throws SQLException {
        try (PreparedStatement read = connection.prepareStatement(
            "SELECT failures, window_start, blocked_until FROM auth_guard WHERE account_id = ? FOR UPDATE")) {
            read.setLong(1, accountId);
            try (ResultSet found = read.executeQuery()) {
                return found.next() ? new AccountGuard(found.getInt(1), found.getLong(2), found.getLong(3)) : null;
            }
        }
    }

    /**
     * Charges one failure against an account. Locks once the budget is spent. The caller still
     * reports the generic invalid-credential result for this attempt; {@code LOCKED} is only
     * reported when a later attempt is refused without checking the password at all.
     *
     * @return the remaining lock state, for logging
     */
    public long chargeFailure(Connection connection, long accountId, AccountGuard before) throws SQLException {
        long now = now();
        int failures = before.windowExpired(now) ? 1 : before.failures() + 1;
        long windowStart = before.windowExpired(now) ? now : before.windowStart();
        long blockedUntil = failures >= ACCOUNT_MAX_FAILURES ? now + ACCOUNT_LOCK_SECONDS : 0;
        try (PreparedStatement write = connection.prepareStatement("""
            UPDATE auth_guard
               SET failures = ?, window_start = ?, blocked_until = ?, version = version + 1
             WHERE account_id = ?
            """)) {
            write.setInt(1, failures);
            write.setLong(2, windowStart);
            write.setLong(3, blockedUntil);
            write.setLong(4, accountId);
            int written = write.executeUpdate();
            if (written != 1) {
                throw new SQLException("the authentication guard row disappeared mid-transaction");
            }
        }
        return blockedUntil;
    }

    /** Clears the failure counter and any lock: a proven sign-in resets the account's history. */
    public void clearFailures(Connection connection, long accountId) throws SQLException {
        try (PreparedStatement clear = connection.prepareStatement(
            "UPDATE auth_guard SET failures = 0, window_start = ?, blocked_until = 0, version = version + 1"
                + " WHERE account_id = ?")) {
            clear.setLong(1, now());
            clear.setLong(2, accountId);
            clear.executeUpdate();
        }
    }

    /**
     * Deletes throttle state that can no longer affect a decision, so the two tables cannot grow
     * without bound as a program runs.
     *
     * <p>Only expired state is removed, and a live budget is never touched: a source bucket is
     * eligible only once its whole window has elapsed, which is exactly when its next attempt would
     * refill it anyway. The elapsed test reads the row's own {@code window_seconds}, the same column
     * the refill test reads, so the sweep can never disagree with the decision it is cleaning up
     * after - a constant here would delete a bucket that the refill path still considered alive
     * whenever the two disagreed. Deleting a bucket therefore cannot shorten a denial that is in
     * force - a sweep must not be a way to reset someone's rate limit.
     *
     * <p>Recency alone is deliberately <em>not</em> enough to retire a guard row. An account
     * outside {@code recentAccountsToKeep} may still be sitting on a lockout that has not expired,
     * and deleting its row would silently restore the right to retry: the next attempt would
     * re-create a zeroed guard, so the sweep would become a lockout-reset primitive available to
     * anyone who can register enough accounts to push a target out of the retention window. A guard
     * is therefore removed only when it is outside the retention window <em>and</em> holds no live
     * state - no lock in force and a failure window that has already decayed - which is precisely
     * the state its next attempt would rebuild as "no history" anyway.
     *
     * @return the number of rows removed
     */
    public int purgeStaleState(int recentAccountsToKeep) throws SQLException, AuditLog.AuditException {
        long now = now();
        if (recentAccountsToKeep < 1) {
            throw new IllegalArgumentException("recentAccountsToKeep must be positive");
        }
        return db.inTransaction(connection -> {
            int removed = 0;
            try (PreparedStatement buckets = connection.prepareStatement(
                "DELETE FROM throttle_bucket WHERE (? - window_start) >= window_seconds")) {
                buckets.setLong(1, now);
                removed += buckets.executeUpdate();
            }
            try (PreparedStatement guards = connection.prepareStatement("""
                DELETE FROM auth_guard
                 WHERE account_id NOT IN (SELECT id FROM accounts ORDER BY id DESC LIMIT ?)
                   AND blocked_until <= ?
                   AND (? - window_start) >= ?
                """)) {
                guards.setInt(1, recentAccountsToKeep);
                guards.setLong(2, now);
                guards.setLong(3, now);
                guards.setInt(4, ACCOUNT_WINDOW_SECONDS);
                removed += guards.executeUpdate();
            }
            return Integer.valueOf(removed);
        });
    }

    /** Counts of the rows a sweep can remove, for the test suite's bound assertions. */
    public int bucketRowCount() throws SQLException, AuditLog.AuditException {
        return count("SELECT COUNT(*) FROM throttle_bucket");
    }

    public int guardRowCount() throws SQLException, AuditLog.AuditException {
        return count("SELECT COUNT(*) FROM auth_guard");
    }

    private int count(String sql) throws SQLException, AuditLog.AuditException {
        return db.inTransaction(connection -> {
            try (PreparedStatement read = connection.prepareStatement(sql);
                ResultSet found = read.executeQuery()) {
                found.next();
                return Integer.valueOf(found.getInt(1));
            }
        });
    }

    public static final class AccountGuard {
        private final int failures;
        private final long windowStart;
        private final long blockedUntil;

        AccountGuard(int failures, long windowStart, long blockedUntil) {
            this.failures = failures;
            this.windowStart = windowStart;
            this.blockedUntil = blockedUntil;
        }

        public int failures() {
            return failures;
        }

        public long windowStart() {
            return windowStart;
        }

        public boolean isBlocked(long nowEpochSeconds) {
            return blockedUntil > nowEpochSeconds;
        }

        boolean windowExpired(long nowEpochSeconds) {
            return (nowEpochSeconds - windowStart) >= ACCOUNT_WINDOW_SECONDS;
        }
    }

    static boolean isUniqueViolation(SQLException failure) {
        String state = failure.getSQLState();
        return state != null && state.startsWith("23");
    }
}
