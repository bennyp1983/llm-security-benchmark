package com.example.auth;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

/**
 * Rate limiting whose check and act are one SQL transaction (rule 7).
 *
 * <p>Each attempt reserves a slot on every budget it consumes. {@link #reserve} begins a
 * transaction, takes {@code SELECT ... FOR UPDATE} on each budget row in sorted key order, only then
 * reads the counter, and either commits the increment or rolls it back. Two concurrent attempts
 * therefore cannot both consume the last slot: whichever loses the row lock blocks, re-reads the
 * committed value, and is refused. Sorted lock order is what stops two attempts that touch the same
 * two budgets (one account, one source) from deadlocking each other.
 *
 * <p>Two independent budgets per attempt: one keyed on the account, one keyed on the request source.
 * The per-account budget alone is a lockout weapon - anyone who knows an address can burn it - so the
 * per-source budget is what bounds how many accounts one source can lock out per window, and
 * {@link Config} refuses a configuration where the source budget is smaller than the account budget.
 *
 * <p>Deliberate choice: a <em>successful</em> login refunds its own account budget ({@link #refund})
 * and consumes no source slot. Otherwise an attacker holding one valid credential could keep spending
 * budget with genuine authentications - or let a legitimate user's correct sign-ins do it for them -
 * until the account or source is locked, turning the limit into a denial-of-service tool. Only failed
 * and refused attempts are charged.
 *
 * <p>Fail-closed: if a reservation cannot be completed - engine error, lock timeout, a stored
 * counter outside the range this code could have written - the attempt is refused, never allowed.
 *
 * <p>Transactions are explicit: auto-commit is turned off for the duration of one operation and
 * restored afterwards, so the credential read on the same connection always runs in its own
 * auto-committed statement.
 */
final class ThrottleStore implements AutoCloseable {

    private static final String IDENTITY_PREFIX = "i:";
    private static final String SOURCE_PREFIX = "s:";
    /** Length of the account-key prefix used when clearing budgets for a recreated account. */
    private static final int CLEAR_PREFIX_LEN = 12;

    private final Database database;
    private final Connection connection;
    private final String table;

    /** Injectable clock; production uses the wall clock, tests drive window rollover directly. */
    interface TimeSource {
        long epochMillis();
    }

    static final TimeSource SYSTEM_CLOCK = System::currentTimeMillis;

    ThrottleStore(Database database) {
        this.database = database;
        this.connection = database.transactionConnection();
        this.table = database.throttleTable();
    }

    /**
     * Atomically consumes one slot from each budget, or none at all.
     *
     * <p>{@code synchronized} serialises reservations inside this process; the row locks serialise
     * them across processes. Both are needed: the shared transaction connection means two threads
     * must not interleave statements in one transaction, and the row locks are what make the
     * reservation correct against another JVM holding the same store.
     *
     * @param keys budget keys; the caller supplies a small fixed number
     * @return true when every budget had a free slot and the increment is now committed
     */
    boolean reserve(List<BudgetKey> keys, long nowMillis) throws Database.StorageException {
        List<BudgetKey> ordered = new ArrayList<>(keys);
        ordered.sort(Comparator.comparing(BudgetKey::key));
        return inTransaction(tx -> {
            for (BudgetKey k : ordered) {
                if (!reserveOne(tx, k, nowMillis)) {
                    // Signal "refuse" by unwinding; nothing is committed.
                    throw new Refused();
                }
            }
            return true;
        }).booleanValue();
    }

    /** true when the slot was taken and the row updated; false means this budget is exhausted. */
    private boolean reserveOne(Tx tx, BudgetKey k, long nowMillis) throws SQLException {
        int current;
        long windowStart;
        try (PreparedStatement lock = tx.prepare(
                "SELECT used, window_started_at_epoch_ms FROM " + table
                        + " WHERE tkey = ? FOR UPDATE")) {
            lock.setString(1, k.key());
            try (ResultSet rs = lock.executeQuery()) {
                if (rs.next()) {
                    current = rs.getInt(1);
                    windowStart = rs.getLong(2);
                } else {
                    current = 0;
                    windowStart = nowMillis;
                    try (PreparedStatement ins = tx.prepare(
                            "INSERT INTO " + table
                                    + " (tkey, window_started_at_epoch_ms, used, limit_value,"
                                    + " updated_at_epoch_ms) VALUES (?,?,?,?,?)")) {
                        ins.setString(1, k.key());
                        ins.setLong(2, windowStart);
                        ins.setInt(3, 0);
                        ins.setInt(4, k.limit());
                        ins.setLong(5, nowMillis);
                        if (ins.executeUpdate() != 1) {
                            throw new SQLException("throttle_insert_failed");
                        }
                    }
                }
            }
        }
        if (nowMillis < windowStart) {
            // The clock stepped backwards (NTP correction). A window that the clock has already
            // passed cannot be trusted to bound anything, so restart it.
            windowStart = nowMillis;
            current = 0;
        } else if (nowMillis - windowStart >= k.windowMillis()) {
            windowStart = nowMillis;
            current = 0;
        }
        if (current < 0) {
            // A negative counter is something this code could never have written: the row is not
            // trustworthy, so the attempt is refused as a storage failure rather than trusted to
            // bound anything.
            throw new SQLException("throttle_state_rejected");
        }
        if (current >= k.limit()) {
            // Covers both the normal exhausted case and an operator having lowered the configured
            // limit below a counter written under the old one. Both mean "no slot left"; treating
            // the second as an error would lock every account with a live counter out of the
            // system on an ordinary config change. The window roll above clears the counter.
            return false;
        }
        try (PreparedStatement upd = tx.prepare(
                "UPDATE " + table + " SET used = ?, window_started_at_epoch_ms = ?,"
                        + " limit_value = ?, updated_at_epoch_ms = ? WHERE tkey = ?")) {
            upd.setInt(1, current + 1);
            upd.setLong(2, windowStart);
            upd.setInt(3, k.limit());
            upd.setLong(4, nowMillis);
            upd.setString(5, k.key());
            if (upd.executeUpdate() != 1) {
                throw new SQLException("throttle_update_failed");
            }
        }
        return true;
    }

    /**
     * Gives one slot back to an account budget after a verified sign-in. One conditional statement,
     * so there is no read-then-write window; the {@code used > 0} predicate stops a concurrent
     * refund driving the counter negative.
     */
    void refund(BudgetKey key, long nowMillis) throws Database.StorageException {
        inTransaction(tx -> {
            try (PreparedStatement ps = tx.prepare(
                    "UPDATE " + table + " SET used = used - 1, updated_at_epoch_ms = ?"
                            + " WHERE tkey = ? AND used > 0")) {
                ps.setLong(1, nowMillis);
                ps.setString(2, key.key());
                ps.executeUpdate();
            }
            return Boolean.TRUE;
        });
    }

    /**
     * Drops account budget rows belonging to an identity prefix, so a re-seeded account cannot
     * inherit a stale counter. The pattern is built only from hex this code generated.
     */
    void clearIdentityBudgets(String emailHash) throws Database.StorageException {
        if (emailHash == null || emailHash.length() < CLEAR_PREFIX_LEN) {
            throw new Database.StorageException("throttle_clear_key");
        }
        String hashPrefix = emailHash.substring(0, CLEAR_PREFIX_LEN);
        inTransaction(tx -> {
            try (PreparedStatement ps = tx.prepare(
                    "DELETE FROM " + table + " WHERE tkey LIKE ?")) {
                ps.setString(1, IDENTITY_PREFIX + hashPrefix + "%");
                ps.executeUpdate();
            }
            return Boolean.TRUE;
        });
    }

    /** Reads a budget for tests and diagnostics; never used to make a security decision. */
    long[] inspect(BudgetKey key) throws Database.StorageException {
        Long[] out = inTransaction(tx -> {
            try (PreparedStatement ps = tx.prepare(
                    "SELECT used, window_started_at_epoch_ms FROM " + table + " WHERE tkey = ?")) {
                ps.setString(1, key.key());
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) {
                        return new Long[]{-1L, -1L};
                    }
                    return new Long[]{(long) rs.getInt(1), rs.getLong(2)};
                }
            }
        });
        return new long[]{out[0].longValue(), out[1].longValue()};
    }

    /**
     * Runs {@code body} inside one transaction; commits on success, rolls back on any failure.
     *
     * <p>The monitor is the connection itself, not {@code this}: two {@link AuthService} instances
     * over one {@link Database} each own a {@code ThrottleStore}, and both drive the same shared
     * transaction connection. Interleaving two reservations there would let one thread's statement be
     * committed by another's {@code commit()}.
     */
    private <T> T inTransaction(TxBody<T> body) throws Database.StorageException {
        synchronized (connection) {
            return inTransactionLocked(body);
        }
    }

    private <T> T inTransactionLocked(TxBody<T> body) throws Database.StorageException {
        Tx tx = new Tx();
        boolean restored = false;
        try {
            connection.setAutoCommit(false);
        } catch (SQLException e) {
            throw new Database.StorageException("throttle_txn_begin_failed", e);
        }
        T result;
        try {
            result = body.run(tx);
            connection.commit();
        } catch (Refused refused) {
            rollback();
            return cast(false);
        } catch (SQLException e) {
            rollback();
            throw new Database.StorageException("throttle_txn_failed", e);
        } catch (Exception e) {
            rollback();
            throw new Database.StorageException("throttle_txn_unexpected", e);
        } finally {
            try {
                connection.setAutoCommit(true);
                restored = true;
            } catch (SQLException ignored) {
                // Falls through to the storage failure below.
            }
        }
        if (!restored) {
            throw new Database.StorageException("throttle_txn_autocommit");
        }
        return result;
    }

    private void rollback() {
        try {
            connection.rollback();
        } catch (SQLException ignored) {
            // The engine dropped the transaction; the next attempt fails closed on its own.
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> T cast(Object value) {
        return (T) value;
    }

    interface TxBody<T> {
        T run(Tx tx) throws Exception;
    }

    /** Statement factory bound to the transaction's connection. */
    final class Tx {
        PreparedStatement prepare(String sql) throws SQLException {
            return connection.prepareStatement(sql);
        }
    }

    /** Unwinds a reservation whose budget was already spent; not an error. */
    private static final class Refused extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }

    static BudgetKey identityBudget(String emailHash, int limit, int windowSec) {
        return new BudgetKey(IDENTITY_PREFIX + emailHash, limit, windowSec * 1000L);
    }

    /**
     * The source budget key is a hash of the source label so its length is fixed and it cannot
     * smuggle characters into the key column. The label itself is validated before it reaches here,
     * and remains attacker-influenceable - see residual risk R6 in THREAT-MODEL.md.
     */
    static BudgetKey sourceBudget(String sourceId, int limit, int windowSec) {
        String h = CryptoUtils.toHex(CryptoUtils.sha256(
                PasswordHasher.utf8(sourceId))).substring(0, 32);
        return new BudgetKey(SOURCE_PREFIX + h, limit, windowSec * 1000L);
    }

    /** A budget: opaque key plus the limits this process was configured with. */
    static final class BudgetKey {
        private final String key;
        private final int limit;
        private final long windowMillis;

        BudgetKey(String key, int limit, long windowMillis) {
            this.key = key;
            this.limit = limit;
            this.windowMillis = windowMillis;
        }

        String key() {
            return key;
        }

        int limit() {
            return limit;
        }

        long windowMillis() {
            return windowMillis;
        }
    }

    static List<BudgetKey> attemptBudgets(String emailHash, String sourceId, Config config) {
        return Arrays.asList(
                identityBudget(emailHash, config.identityMaxFailures(), config.identityWindowSec()),
                sourceBudget(sourceId, config.sourceMaxAttempts(), config.sourceWindowSec()));
    }

    @Override
    public void close() {
        database.hardenEngineFiles();
    }
}
