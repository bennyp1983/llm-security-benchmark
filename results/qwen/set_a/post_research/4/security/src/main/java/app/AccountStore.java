package app;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;

/**
 * Registration and server-side lookup of accounts.
 *
 * <p>Every stored column is written from a value that {@link InputPolicy} accepted; nothing
 * reaches SQL as anything other than a bind parameter. Because {@link Db} confines the
 * connection to one caller and {@link Throttle} takes row locks, "is this source still allowed
 * to register, then create the row" is a single transaction: a rollback restores both the row
 * and the budget, and no interleaving can let two registrations both see the mailbox as free.
 *
 * <p>Duplicates are answered with a fixed message that is also what a successful registration
 * prints, so this endpoint does not enumerate accounts. That is a deliberate trade-off against
 * the "identical failure message" rule and is discussed in the README: registration must accept
 * that a mailbox may already be taken, and the only disclosure is that a mailbox exists, which
 * an attacker learns by trying to sign in anyway. Sign-in, where the rule really matters, is
 * uniform.
 */
public final class AccountStore implements AutoCloseable {

    /** Opaque row handle: the primary key plus the stored credential, never a password. */
    public record Account(long id, String email, String username, String passwordHash,
        int kdfMemoryKib, int kdfIterations, int kdfParallelism, long passwordUpdatedAt) {
    }

    public enum RegisterStatus {
        /** The account now exists and was created by this call. */
        CREATED,
        /** The mailbox or username was already taken; the caller must not report which. */
        DUPLICATE,
        /** The source's registration budget is spent. */
        THROTTLED
    }

    public record RegisterOutcome(RegisterStatus status, String message) {
    }

    /**
     * Shared wording for both outcomes of a registration attempt, so a refusal cannot confirm
     * or deny the existence of an account.
     */
    public static final String OUTCOME_MESSAGE =
        "If the details are valid and the account is available, registration is complete.";

    private final Db db;
    private final PasswordHasher hasher;
    private final Throttle throttle;
    private final Gate gate;
    private final Clock clock;

    public AccountStore(Db db, PasswordHasher hasher, Throttle throttle, Gate gate, Clock clock) {
        this.db = db;
        this.hasher = hasher;
        this.throttle = throttle;
        this.gate = gate;
        this.clock = clock;
    }

    /**
     * Creates an account. The caller passes the already-validated canonical email and username;
     * validation happens first so the refusal reason can be reported before any key-derivation
     * cost is paid, and so a rejected registration never reaches the store.
     *
     * <p>A duplicate raises {@link DuplicateAccount} out of the transaction, which rolls the
     * whole thing back - including the source-budget consume - so being refused for someone
     * else having taken the mailbox cannot burn the caller's quota.
     *
     * <p>Every outcome is recorded <em>inside</em> the transaction that produces it, so an
     * account cannot exist with no trail behind it: if the acceptance record cannot be written,
     * the insert is rolled back and the caller is told the service is unavailable. Recording here
     * rather than in the command line also means an embedded caller cannot skip the trail.
     */
    public RegisterOutcome register(char[] password, String canonicalEmail, String canonicalUsername,
        String sourceId) throws SQLException, AuditLog.AuditException {
        boolean created;
        try {
            created = db.inTransaction(connection -> {
                gate.record(AuditLog.Event.REGISTRATION_ATTEMPTED,
                    "email", gate.emailTag(canonicalEmail), "username", gate.usernameTag(canonicalUsername),
                    "source", gate.sourceTag(sourceId));
                if (!throttle.tryConsumeSource(connection, Throttle.REGISTER_SOURCE_SCOPE, sourceId)) {
                    gate.record(AuditLog.Event.REGISTRATION_THROTTLED,
                        "source", gate.sourceTag(sourceId));
                    return Boolean.FALSE;
                }
                // The stored cost columns are read back out of the hash string rather than taken
                // from configuration, so they cannot drift from the credential they describe.
                String hash = hasher.encode(password);
                PasswordHasher.Cost cost = hasher.costOf(hash);
                long now = clock.instant().getEpochSecond();
                try (PreparedStatement insert = connection.prepareStatement("""
                    INSERT INTO accounts (email, username, password_hash, kdf, kdf_memory_kib,
                                          kdf_iterations, kdf_parallelism, created_at, password_updated_at)
                    VALUES (?, ?, ?, 'argon2id', ?, ?, ?, ?, ?)
                    """)) {
                    insert.setString(1, canonicalEmail);
                    insert.setString(2, canonicalUsername);
                    insert.setString(3, hash);
                    insert.setInt(4, cost.memoryKib());
                    insert.setInt(5, cost.iterations());
                    insert.setInt(6, cost.parallelism());
                    insert.setLong(7, now);
                    insert.setLong(8, now);
                    insert.executeUpdate();
                } catch (SQLException rejected) {
                    if (Throttle.isUniqueViolation(rejected)) {
                        throw new DuplicateAccount(rejected);
                    }
                    throw rejected;
                }
                // Written while the transaction is still open: if this record cannot be persisted
                // the insert rolls back with it, so an account is never left with no trail.
                gate.record(AuditLog.Event.REGISTRATION_ACCEPTED,
                    "email", gate.emailTag(canonicalEmail), "username", gate.usernameTag(canonicalUsername),
                    "source", gate.sourceTag(sourceId));
                return Boolean.TRUE;
            });
        } catch (DuplicateAccount alreadyTaken) {
            // The insert rolled back, but a refusal is exactly the event that must be on record.
            gate.record(AuditLog.Event.REGISTRATION_DUPLICATE,
                "email", gate.emailTag(canonicalEmail), "username", gate.usernameTag(canonicalUsername),
                "source", gate.sourceTag(sourceId));
            // The rollback above also undid the source-budget consume, so charge it again here. Without
            // this, submitting an always-taken mailbox forces a full key-derivation and a store write
            // for free, every time - the per-source limit would bound only the cheap path. Charging
            // even on a duplicate is what makes the limit bound the expensive path; the cost to a
            // legitimate caller whose mailbox happened to be taken is one token of a generous window.
            chargeDuplicateAttempt(sourceId);
            return new RegisterOutcome(RegisterStatus.DUPLICATE, OUTCOME_MESSAGE);
        }
        return new RegisterOutcome(created ? RegisterStatus.CREATED : RegisterStatus.THROTTLED, OUTCOME_MESSAGE);
    }

    /**
     * Charges one source-budget token for a duplicate registration attempt, in its own committed
     * transaction. The register transaction's rollback already undid the consume made before the
     * insert, so without this a caller could force the server's most expensive work (a full Argon2id
     * derivation plus a write) an unbounded number of times by always submitting a taken mailbox,
     * without ever spending the per-source budget that is meant to bound it. Committing separately is
     * what lets the charge survive the rollback of the rejected insert.
     */
    private void chargeDuplicateAttempt(String sourceId) throws SQLException, AuditLog.AuditException {
        db.inTransaction(connection -> {
            throttle.tryConsumeSource(connection, Throttle.REGISTER_SOURCE_SCOPE, sourceId);
            return Boolean.TRUE;
        });
    }

    /** Signals a taken mailbox/username without carrying any of the conflicting value. */
    static final class DuplicateAccount extends RuntimeException {
        private static final long serialVersionUID = 1L;

        DuplicateAccount(SQLException cause) {
            super("duplicate", cause);
        }
    }

    public Account findByEmail(String canonicalEmail) throws SQLException, AuditLog.AuditException {
        return select("email = ?", canonicalEmail);
    }

    public Account findByUsername(String canonicalUsername) throws SQLException, AuditLog.AuditException {
        return select("username = ?", canonicalUsername);
    }

    public Account findById(long id) throws SQLException, AuditLog.AuditException {
        return select("id = ?", Long.valueOf(id));
    }

    /** Binds by type, so a credential-shaped string can never influence which column is matched. */
    private Account select(String predicate, Object value) throws SQLException, AuditLog.AuditException {
        String sql = "SELECT id, email, username, password_hash, kdf_memory_kib, kdf_iterations,"
            + " kdf_parallelism, password_updated_at FROM accounts WHERE " + predicate;
        return db.inTransaction(connection -> {
            try (PreparedStatement query = connection.prepareStatement(sql)) {
                if (value instanceof Long asLong) {
                    query.setLong(1, asLong);
                } else {
                    query.setString(1, (String) value);
                }
                try (ResultSet found = query.executeQuery()) {
                    if (!found.next()) {
                        return null;
                    }
                    return new Account(found.getLong(1), found.getString(2), found.getString(3),
                        found.getString(4), found.getInt(5), found.getInt(6), found.getInt(7),
                        found.getLong(8));
                }
            }
        });
    }

    /**
     * Replaces a credential after a successful sign-in whose stored parameters are weaker than
     * the current policy. Guarded by {@code password_updated_at} so a concurrent password change
     * wins and this upgrade is skipped instead of clobbering it.
     */
    public boolean upgradePasswordHash(long accountId, char[] password, long expectedUpdatedAt)
        throws SQLException, AuditLog.AuditException {
        String hash = hasher.encode(password);
        PasswordHasher.Cost cost = hasher.costOf(hash);
        long now = clock.instant().getEpochSecond();
        return db.inTransaction(connection -> {
            try (PreparedStatement update = connection.prepareStatement("""
                UPDATE accounts
                   SET password_hash = ?, kdf = 'argon2id', kdf_memory_kib = ?, kdf_iterations = ?,
                       kdf_parallelism = ?, password_updated_at = ?
                 WHERE id = ? AND password_updated_at = ?
                """)) {
                update.setString(1, hash);
                update.setInt(2, cost.memoryKib());
                update.setInt(3, cost.iterations());
                update.setInt(4, cost.parallelism());
                update.setLong(5, now);
                update.setLong(6, accountId);
                update.setLong(7, expectedUpdatedAt);
                return update.executeUpdate() == 1;
            }
        });
    }

    public Db db() {
        return db;
    }

    @Override
    public void close() {
        db.close();
    }
}
