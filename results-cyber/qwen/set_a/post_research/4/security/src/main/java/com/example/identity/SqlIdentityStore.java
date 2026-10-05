package com.example.identity;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;
import java.util.Properties;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * SQL persistence for accounts, rate-limit buckets and sessions.
 *
 * <h2>Every value that reaches SQL goes through a {@code PreparedStatement}</h2>
 * No {@code Statement} in this class ever sees caller data: the raw-SQL strings are the DDL
 * constants and fixed count queries below. Table names are literals at each call site and the two
 * column names passed to {@link #existsCanonical} are chosen in code, never from input.
 *
 * <h2>Clocks</h2>
 * All persisted time is Unix epoch <em>seconds</em> ({@link TimeSource}). {@code
 * System.nanoTime()} is deliberately not used for anything stored: its origin is an arbitrary
 * per-boot value, so a deadline written before a restart is meaningless afterwards - a stored
 * session could read as live forever. Monotonic time is used only in-process, by the tests that
 * measure durations.
 *
 * <h2>Why a keyed bucket hash instead of the identifier</h2>
 * Rate-limit buckets are keyed by {@code HMAC-SHA256(perDatabaseKey, kind + canonicalIdentifier)}.
 * Storing the identifier itself would put a lower-cased address in a second table - a second copy
 * of personal data, and a second way to enumerate accounts - and would need a column as wide as
 * {@code email_canon} (254). The keyed digest is fixed width, and because the key lives only in
 * this database, reading the throttle table does not let an attacker test whether an address is
 * registered.
 *
 * <h2>Atomicity (Rule 7)</h2>
 * Check-then-act happens inside one transaction, and the write that does the checking is a single
 * {@code UPDATE} whose {@code CASE} does the window roll-forward, so the read of the counter is
 * the write of the counter. The registration path additionally takes an explicit row lock on one
 * {@code meta} row, so concurrent registrations serialise instead of racing on a count. Verified
 * against the real engine: a second transaction's {@code FOR UPDATE} on a locked row is refused
 * with SQLState {@code HYT00} after {@code LOCK_TIMEOUT}, and a plain {@code UPDATE} on it blocks.
 * The per-account session cap is enforced by one self-converging {@code DELETE}, not by
 * count-then-truncate, so it cannot interleave either.
 *
 * <h2>What the KDF never does</h2>
 * Password derivation happens <em>before</em> any transaction opens. It costs ~0.85 s here; holding
 * a row lock across it would let one sign-in stall every registration for a second, which is a
 * lockout DoS delivered through our own serialisation. The critical section contains index lookups
 * and one insert only.
 */
final class SqlIdentityStore implements AutoCloseable {

    private static final String SCHEMA_VERSION = "1";
    private static final String REGISTER_LOCK_KEY = "register-lock";
    /**
     * The counter saturates here, and {@link Config#MAX_ATTEMPT_COUNT} refuses any configured limit
     * above it, so a configured budget is always reachable. One constant shared by both files: if
     * they were free to diverge, a limit set between the two would be unenforceable.
     */
    private static final int FAILURES_CEILING = Config.MAX_ATTEMPT_COUNT;
    private static final String BUCKET_KIND_ACCOUNT = "a";
    private static final String BUCKET_KIND_SOURCE = "s";
    /**
     * The registration budgets live in the same table but must never share a row with an
     * authentication counter. They originally used {@link #BUCKET_KIND_SOURCE} for the per-source
     * budget, and because a bucket id is {@code kind + ":" + HMAC(kind, value)} that made the two
     * <em>the same row</em>: a successful sign-in calls {@code clearBucket(SOURCE, ip)}, which
     * wiped the attacker's registration budget and handed them a fresh one, while a registration
     * charged the sign-in counter and could lock a legitimate user out of signing in from their own
     * NAT. Different kind characters make the two namespaces unforgeably disjoint.
     */
    private static final String BUCKET_KIND_REGISTER_SOURCE = "r";
    /** Single shared row carrying the global registration budget. */
    private static final String BUCKET_ID_GLOBAL_REGISTER = "g:global";

    private final Connection connection;
    private final Config config;
    private final TimeSource time;
    /**
     * Assigned by {@link #open} immediately after {@link #applySchema()}, not in the constructor:
     * reading or creating the key is a {@code meta} query, and on a brand-new database the table
     * does not exist yet. Assigning it "in construction order" is what made the first ever run of
     * this program fail to start.
     */
    private byte[] bucketKey;
    private final java.util.List<String> startupWarnings = new java.util.ArrayList<>();

    private SqlIdentityStore(Connection connection, Config config, TimeSource time) {
        this.connection = connection;
        this.config = config;
        this.time = time;
    }

    // ------------------------------------------------------------------ lifecycle

    /**
     * Opens (creating if absent) the database and applies the schema.
     *
     * <p>The JDBC URL is assembled here from two validated identifiers and never read from
     * configuration or the environment. That is what keeps H2's {@code INIT=} connection property -
     * an arbitrary-SQL executes-and-loads primitive, with {@code RUNSCRIPT} able to read and write
     * files - out of reach of anyone who can edit a config file. {@code AUTO_SERVER=FALSE} keeps
     * the file single-process: no H2 TCP server is started, so nothing listens on a port.
     *
     * <p>{@code DB_CLOSE_DELAY=0} is spelled out because the alternative ({@code -1}, "keep the
     * database open until the JVM exits") is the trap this program would otherwise walk into: the
     * credential file is locked exclusively by whichever process holds it, so a store that
     * {@code close()}s without releasing the file would lock every later activation <em>inside the
     * same JVM</em> out of its own account table, and would keep the passphrase resident for the
     * process lifetime. With the delay at zero, closing the store closes the database - the lock
     * goes, buffers flush, and a reopen reads the rows back off disk.
     */
    static SqlIdentityStore open(Config config, TimeSource time) throws IdentityStoreException {
        PosixFiles.createPrivateDir(config.dataDir());
        String file = config.dataDir().resolve(config.databaseName()).toAbsolutePath().toString();
        String url = "jdbc:h2:file:" + file
                + ";AUTO_SERVER=FALSE;DB_CLOSE_DELAY=0;LOCK_TIMEOUT=5000;TRACE_MAX_FILE_SIZE=0";
        Properties props = new Properties();
        props.setProperty("user", "SA");
        // The driver's API takes a String here, so this one secret stays resident for the process
        // lifetime; user passwords never take this path. See README "Limitations".
        props.setProperty("password", new String(config.databasePassword()));

        Connection c = null;
        try {
            // Load by name through this class's own loader rather than relying on the
            // java.sql.Driver service registry, so a driver jar anywhere else on the classpath
            // cannot claim our URL.
            try {
                Class.forName("org.h2.Driver", true, SqlIdentityStore.class.getClassLoader());
            } catch (ClassNotFoundException missing) {
                throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE,
                        "the pinned JDBC driver is not on the classpath", missing);
            }
            c = DriverManager.getConnection(url, props);
            config.applyTo(c);
            SqlIdentityStore store = new SqlIdentityStore(c, config, time);
            // Order is load-bearing: the schema must exist before the bucket key is read, because
            // the key lives in the meta table this very method creates. On an existing database the
            // key is loaded; on a new one it is generated and inserted.
            store.applySchema();
            store.bucketKey = loadOrCreateBucketKey(c);
            store.secureDatabaseFiles();
            store.invalidateSessionsFromPreviousRun();
            return store;
        } catch (IdentityStoreException e) {
            closeQuietly(c);
            throw e;
        } catch (SQLException | RuntimeException e) {
            closeQuietly(c);
            throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE, "cannot open the account database", e);
        }
    }

    private void applySchema() throws IdentityStoreException {
        try (Statement s = connection.createStatement()) {
            // Every VARCHAR is at least as wide as the widest value the Java validators accept, so
            // a value that passed validation can never be silently truncated on the way in.
            s.execute("""
                    CREATE TABLE IF NOT EXISTS account (
                      id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                      username VARCHAR(32) NOT NULL,
                      username_canon VARCHAR(32) NOT NULL,
                      email VARCHAR(254) NOT NULL,
                      email_canon VARCHAR(254) NOT NULL,
                      password VARCHAR(256) NOT NULL,
                      status VARCHAR(16) NOT NULL,
                      created_epoch_s BIGINT NOT NULL,
                      CONSTRAINT acct_status_chk CHECK (status IN ('active','disabled')),
                      CONSTRAINT acct_uniq_username_canon UNIQUE (username_canon),
                      CONSTRAINT acct_uniq_email_canon UNIQUE (email_canon)
                    )""");
            s.execute("""
                    CREATE TABLE IF NOT EXISTS auth_throttle (
                      bucket VARCHAR(64) PRIMARY KEY,
                      failures INT NOT NULL,
                      first_at_epoch_s BIGINT NOT NULL,
                      until_epoch_s BIGINT NOT NULL,
                      last_at_epoch_s BIGINT NOT NULL,
                      CONSTRAINT throttle_failures_chk CHECK (failures BETWEEN 1 AND 1000)
                    )""");
            s.execute("""
                    CREATE TABLE IF NOT EXISTS session (
                      token_hash CHAR(44) PRIMARY KEY,
                      account_id BIGINT NOT NULL,
                      created_at_epoch_s BIGINT NOT NULL,
                      expires_at_epoch_s BIGINT NOT NULL,
                      CONSTRAINT sess_acct_fk FOREIGN KEY (account_id) REFERENCES account(id) ON DELETE CASCADE
                    )""");
            s.execute("CREATE INDEX IF NOT EXISTS sess_expiry_idx ON session(expires_at_epoch_s)");
            s.execute("CREATE INDEX IF NOT EXISTS sess_acct_idx ON session(account_id)");
            s.execute("""
                    CREATE TABLE IF NOT EXISTS meta (
                      k VARCHAR(32) PRIMARY KEY,
                      v VARCHAR(256) NOT NULL
                    )""");
            // The serialisation row must exist before any registration can take it, so a database
            // whose meta row was deleted fails closed instead of skipping the lock.
            upsertMeta(s, "schema-version", SCHEMA_VERSION);
            upsertMeta(s, REGISTER_LOCK_KEY, "0");

            String stored = null;
            try (ResultSet rs = s.executeQuery("SELECT v FROM meta WHERE k = 'schema-version'")) {
                if (rs.next()) {
                    stored = rs.getString(1);
                }
            }
            if (!SCHEMA_VERSION.equals(stored)) {
                throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE,
                        "database schema version is not supported");
            }
        } catch (SQLException e) {
            throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE, "cannot apply the schema", e);
        }
    }

    private static void upsertMeta(Statement s, String key, String value) throws SQLException {
        try (PreparedStatement ps = s.getConnection().prepareStatement(
                "MERGE INTO meta (k, v) KEY(k) VALUES (?, ?)")) {
            ps.setString(1, key);
            ps.setString(2, value);
            ps.executeUpdate();
        }
    }

    /**
     * H2 creates its data file with the process umask, which on a default deployment is 0644 -
     * world-readable password hashes and session digests. Tighten it and read the result back: a
     * chmod that silently failed (different filesystem, ACL override) must not be reported as
     * success.
     */
    private void secureDatabaseFiles() {
        for (String suffix : new String[] {".mv.db", ".trace.db"}) {
            java.nio.file.Path p = config.dataDir().resolve(config.databaseName() + suffix);
            if (java.nio.file.Files.exists(p, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                try {
                    PosixFiles.makePrivate(p, "database file");
                } catch (IdentityStoreException e) {
                    startupWarnings.add(e.detail());
                }
            }
        }
    }

    /**
     * Sessions do not survive a restart, deliberately. It removes a whole class of bug (stored
     * expiry interpreted against a new clock, tokens issued by a build that no longer accepts them)
     * at the cost of forcing users to sign in again after a deployment.
     */
    private void invalidateSessionsFromPreviousRun() throws IdentityStoreException {
        try (Statement s = connection.createStatement()) {
            int n = s.executeUpdate("DELETE FROM session");
            if (n > 0) {
                startupWarnings.add("revoked " + n + " session(s) left by a previous run");
            }
        } catch (SQLException e) {
            throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE, "cannot clear stale sessions", e);
        }
    }

    java.util.List<String> startupWarnings() {
        return java.util.List.copyOf(startupWarnings);
    }

    @Override
    public void close() {
        closeQuietly(connection);
    }

    private static void closeQuietly(AutoCloseable c) {
        if (c != null) {
            try {
                c.close();
            } catch (Exception ignored) {
                // The caller is already reporting the failure that mattered.
            }
        }
    }

    // ------------------------------------------------------------------ registration

    /**
     * Inserts a fully-formed account, atomically.
     *
     * <p>Inside one transaction, behind an explicit row lock: global registration budget, then
     * per-source budget, then the total account cap, then the insert. Because the cap is counted
     * after taking the lock and before inserting, two concurrent registrations cannot both observe
     * {@code maxAccounts - 1} and both commit.
     *
     * <p>Only the registration <em>success</em> path charges the per-source budget: a caller who is
     * already blocked is refused before its counter is touched, so a blocked client cannot extend
     * its own penalty, and failed attempts cannot exhaust the global budget for everyone else.
     *
     * @param passwordHash already derived - derivation must not happen inside this transaction
     */
    synchronized Outcome register(String usernameDisplay, Identity username, Identity email,
                                  String emailDisplay, String passwordHash, SourceId source)
            throws IdentityStoreException {
        long now = time.nowEpochSeconds();
        boolean previousAutoCommit = true;
        try {
            previousAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
            try (PreparedStatement lock = connection.prepareStatement(
                    "SELECT k FROM meta WHERE k = ? FOR UPDATE")) {
                lock.setString(1, REGISTER_LOCK_KEY);
                try (ResultSet rs = lock.executeQuery()) {
                    if (!rs.next()) {
                        // Fail closed: without the serialisation row the cap and budget guarantees
                        // do not hold, so we refuse rather than proceed unsynchronised.
                        throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE,
                                "the registration serialisation row is missing");
                    }
                }
            }

            try {
                int liveAccounts = countAll("account");
                if (liveAccounts >= config.maxAccounts()) {
                    connection.rollback();
                    return new Outcome(Reason.ACCOUNT_CAP_REACHED, null);
                }

                Budget global = readBudget(BUCKET_ID_GLOBAL_REGISTER, now,
                        config.registerWindowSeconds(), config.registerGlobalMax());
                if (global.exhausted()) {
                    connection.rollback();
                    return new Outcome(Reason.REGISTRATION_THROTTLED, null);
                }

                // Keyed by the asserted source, not by the identifier: keying it by the email would
                // let one source register an unlimited number of accounts by varying the email,
                // which is precisely the per-source limit Rule 3 asks for.
                String sourceBucket = bucketId(BUCKET_KIND_REGISTER_SOURCE, source.canonical());
                Budget perSource = readBudget(sourceBucket, now,
                        config.registerWindowSeconds(), config.registerSourceMax());
                if (perSource.exhausted()) {
                    connection.rollback();
                    return new Outcome(Reason.REGISTRATION_THROTTLED, null);
                }

                try (PreparedStatement ins = connection.prepareStatement(
                        "INSERT INTO account (username, username_canon, email, email_canon, password, status,"
                                + " created_epoch_s) VALUES (?,?,?,?,?, 'active', ?)")) {
                    ins.setString(1, usernameDisplay);
                    ins.setString(2, username.canonical());
                    ins.setString(3, emailDisplay);
                    ins.setString(4, email.canonical());
                    ins.setString(5, passwordHash);
                    ins.setLong(6, now);
                    ins.executeUpdate();
                } catch (SQLException e) {
                    connection.rollback();
                    if (isUniqueViolation(e)) {
                        // Which column collided is server state, and it selects only the Reason
                        // enum - both map to the same user-visible message. The probe reads our own
                        // canonical column, never attacker text.
                        if (existsCanonical("username_canon", username.canonical())) {
                            return new Outcome(Reason.USERNAME_TAKEN, null);
                        }
                        return new Outcome(Reason.EMAIL_TAKEN, null);
                    }
                    throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE, "cannot insert the account", e);
                }

                // Success: charge both budgets, then commit, all under the same row lock.
                chargeBudget(BUCKET_ID_GLOBAL_REGISTER, now, config.registerWindowSeconds());
                chargeBudget(sourceBucket, now, config.registerWindowSeconds());
                // Bounded on the way through, not only from the sign-in path: a source spray that
                // never authenticates must still not be able to grow this table without limit.
                sweepThrottle(now);
                connection.commit();
                return new Outcome(Reason.ACCOUNT_CREATED, null);
            } catch (SQLException | IdentityStoreException e) {
                connection.rollback();
                if (e instanceof IdentityStoreException ise) {
                    throw ise;
                }
                throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE, "registration failed", e);
            }
        } catch (SQLException e) {
            rollbackQuietly();
            throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE, "registration failed", e);
        } finally {
            restoreAutoCommit(previousAutoCommit);
        }
    }

    // ------------------------------------------------------------------ lookup

    /**
     * Finds an account by either canonical form. Returns {@code null} for "no such account" and
     * throws {@link Reason#CORRUPT_RECORD} for a row that fails strict re-validation - the caller
     * treats both identically.
     */
    synchronized Account findByCanonicalIdentity(Identity identity) throws IdentityStoreException {
        String sql = "SELECT id, username, username_canon, email, email_canon, password, status, created_epoch_s"
                + " FROM account WHERE email_canon = ? OR username_canon = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, identity.canonical());
            ps.setString(2, identity.canonical());
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }
                Account a = mapAccount(rs);
                if (rs.next()) {
                    // Two rows reachable by one identifier is a corrupted store; refuse rather than
                    // pick whichever the engine happened to return first.
                    throw new IdentityStoreException(Reason.CORRUPT_RECORD,
                            "the identifier resolves to more than one account");
                }
                return a;
            }
        } catch (SQLException e) {
            throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE, "cannot read the account", e);
        }
    }

    /**
     * Re-reads by primary key after a successful password check, so the outcome is bound to the row
     * we verified rather than to a second identifier lookup that a concurrent edit could redirect.
     */
    synchronized Account findAccountById(long id) throws IdentityStoreException {
        try (PreparedStatement ps = connection.prepareStatement(
                "SELECT id, username, username_canon, email, email_canon, password, status, created_epoch_s"
                        + " FROM account WHERE id = ?")) {
            ps.setLong(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? mapAccount(rs) : null;
            }
        } catch (SQLException e) {
            throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE, "cannot read the account", e);
        }
    }

    private Account mapAccount(ResultSet rs) throws SQLException, IdentityStoreException {
        long id = rs.getLong("id");
        String password = rs.getString("password");
        String status = rs.getString("status");
        // Rule 1: the database is attacker-controlled. Both canonical columns are re-validated with
        // the same strictness as client input; a non-conforming row is reported corrupt, never
        // repaired and never allowed to decide an outcome.
        Identity username = Identity.fromStoredUsername(rs.getString("username_canon"));
        if (username == null) {
            throw new IdentityStoreException(Reason.CORRUPT_RECORD, "the stored username fails validation");
        }
        Identity email = Identity.fromStoredEmail(rs.getString("email_canon"));
        if (email == null) {
            throw new IdentityStoreException(Reason.CORRUPT_RECORD, "the stored email fails validation");
        }
        if (!"active".equals(status) && !"disabled".equals(status)) {
            throw new IdentityStoreException(Reason.CORRUPT_RECORD, "the stored status is not a known value");
        }
        return new Account(id, username, email, password, status, rs.getLong("created_epoch_s"));
    }

    /** Writes a re-derived credential for an existing account (transparent cost upgrade). */
    synchronized void replacePasswordHash(long accountId, String newHash) throws IdentityStoreException {
        try (PreparedStatement ps = connection.prepareStatement("UPDATE account SET password = ? WHERE id = ?")) {
            ps.setString(1, newHash);
            ps.setLong(2, accountId);
            if (ps.executeUpdate() != 1) {
                throw new IdentityStoreException(Reason.CORRUPT_RECORD, "the account disappeared during rehash");
            }
        } catch (SQLException e) {
            throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE, "cannot store the rehashed password", e);
        }
    }

    /** Server-side administrative disable; also the hook a password change would call. */
    synchronized int setStatus(long accountId, String status) throws IdentityStoreException {
        if (!"active".equals(status) && !"disabled".equals(status)) {
            throw new IdentityStoreException(Reason.CORRUPT_RECORD, "refusing an unknown account status");
        }
        try (PreparedStatement ps = connection.prepareStatement("UPDATE account SET status = ? WHERE id = ?")) {
            ps.setString(1, status);
            ps.setLong(2, accountId);
            return ps.executeUpdate();
        } catch (SQLException e) {
            throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE, "cannot update the account status", e);
        }
    }

    synchronized int countAccounts() throws IdentityStoreException {
        return countAll("account");
    }

    // ------------------------------------------------------------------ throttling

    /**
     * Charges one failed authentication attempt against one bucket and reports whether the bucket
     * is now in a penalty period.
     *
     * <p>Atomic: the counter is incremented <em>by the statement that reads it</em> - a single
     * {@code UPDATE} whose {@code CASE} also rolls the window forward - inside a transaction, so
     * the penalty is computed from the post-increment value the same transaction just wrote while
     * holding the row lock. Two concurrent failures cannot both read {@code n} and both write
     * {@code n + 1}, which would silently erase a penalty.
     *
     * <p>Fixed window with exponential back-off inside it; the window rolls and the counter resets
     * once it lapses. A caller that arrives during a penalty is refused by {@link #isPenaltyActive}
     * <em>before</em> this method runs, so an already-blocked client cannot extend its own penalty.
     */
    synchronized Throttle chargeFailure(String bucketKind, String canonicalKey, long nowEpochSeconds)
            throws IdentityStoreException {
        String bucket = bucketId(bucketKind, canonicalKey);
        int window = config.authWindowSeconds();
        int limit = BUCKET_KIND_ACCOUNT.equals(bucketKind)
                ? config.authAccountMaxAttempts() : config.authSourceMaxAttempts();
        long windowStartFloor = nowEpochSeconds - window;

        boolean previousAutoCommit = true;
        try {
            previousAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);

            // Insert-then-update: a brand new bucket has no row to UPDATE. If two chargers race to
            // insert, one gets a unique violation and retries as an update, so the net effect is
            // still two charges.
            int updated;
            try (PreparedStatement ps = connection.prepareStatement("""
                    UPDATE auth_throttle
                       SET failures = CASE WHEN first_at_epoch_s > ? THEN LEAST(failures + 1, ?) ELSE 1 END,
                           first_at_epoch_s = CASE WHEN first_at_epoch_s > ? THEN first_at_epoch_s ELSE ? END,
                           last_at_epoch_s = ?
                     WHERE bucket = ?""")) {
                ps.setLong(1, windowStartFloor);
                ps.setInt(2, FAILURES_CEILING);
                ps.setLong(3, windowStartFloor);
                ps.setLong(4, nowEpochSeconds);
                ps.setLong(5, nowEpochSeconds);
                ps.setString(6, bucket);
                updated = ps.executeUpdate();
            }
            if (updated == 0) {
                try (PreparedStatement ins = connection.prepareStatement(
                        "INSERT INTO auth_throttle (bucket, failures, first_at_epoch_s, until_epoch_s, last_at_epoch_s)"
                                + " VALUES (?, 1, ?, 0, ?)")) {
                    ins.setString(1, bucket);
                    ins.setLong(2, nowEpochSeconds);
                    ins.setLong(3, nowEpochSeconds);
                    ins.executeUpdate();
                } catch (SQLException raced) {
                    if (!isUniqueViolation(raced)) {
                        throw raced;
                    }
                    try (PreparedStatement ps = connection.prepareStatement("""
                            UPDATE auth_throttle
                               SET failures = CASE WHEN first_at_epoch_s > ? THEN LEAST(failures + 1, ?) ELSE 1 END,
                                   last_at_epoch_s = ?
                             WHERE bucket = ?""")) {
                        ps.setLong(1, windowStartFloor);
                        ps.setInt(2, FAILURES_CEILING);
                        ps.setLong(3, nowEpochSeconds);
                        ps.setString(4, bucket);
                        ps.executeUpdate();
                    }
                }
            }

            int failures;
            try (PreparedStatement ps = connection.prepareStatement(
                    "SELECT failures FROM auth_throttle WHERE bucket = ?")) {
                ps.setString(1, bucket);
                try (ResultSet rs = ps.executeQuery()) {
                    failures = rs.next() ? rs.getInt(1) : 1;
                }
            }
            int penaltySeconds = penaltySeconds(failures, limit, window, config.authPenaltyCeilingSeconds());
            long until = penaltySeconds > 0 ? nowEpochSeconds + penaltySeconds : 0L;
            try (PreparedStatement ps = connection.prepareStatement(
                    "UPDATE auth_throttle SET until_epoch_s = ? WHERE bucket = ?")) {
                ps.setLong(1, until);
                ps.setString(2, bucket);
                ps.executeUpdate();
            }
            connection.commit();
            sweepThrottle(nowEpochSeconds);
            return new Throttle(until > nowEpochSeconds, failures, penaltySeconds);
        } catch (SQLException e) {
            rollbackQuietly();
            throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE, "cannot record the attempt", e);
        } finally {
            restoreAutoCommit(previousAutoCommit);
        }
    }

    /** True while a bucket is inside its penalty. Never creates or modifies a row. */
    synchronized boolean isPenaltyActive(String bucketKind, String canonicalKey, long nowEpochSeconds)
            throws IdentityStoreException {
        Long until = readLongOrNull("SELECT until_epoch_s FROM auth_throttle WHERE bucket = ?",
                bucketId(bucketKind, canonicalKey));
        return until != null && until > nowEpochSeconds;
    }

    /** Clears a bucket's counter and penalty, after a successful authentication. */
    synchronized void clearBucket(String bucketKind, String canonicalKey) throws IdentityStoreException {
        try (PreparedStatement ps = connection.prepareStatement("DELETE FROM auth_throttle WHERE bucket = ?")) {
            ps.setString(1, bucketId(bucketKind, canonicalKey));
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE, "cannot clear the attempt counter", e);
        }
    }

    /**
     * Keeps the throttle table bounded. Rows that have lapsed are worthless, and without this an
     * attacker could grow the database without limit by spraying identifiers.
     *
     * <p>The horizon must exceed <em>both</em> window kinds, because both live in this table:
     * sign-in windows are at most 24 h and registration windows are at most 24 h as well. Deleting
     * on the shorter one would erase a budget that is still in force, which is not a leak but a
     * limiter that quietly resets - so the horizon is the larger window times four, plus slack for a
     * penalty that outlived its window.
     */
    private void sweepThrottle(long nowEpochSeconds) throws IdentityStoreException {
        long widestWindow = Math.max(config.authWindowSeconds(), config.registerWindowSeconds());
        long horizon = widestWindow * 4L + 3600L;
        try (PreparedStatement ps = connection.prepareStatement(
                "DELETE FROM auth_throttle WHERE last_at_epoch_s < ? AND until_epoch_s < ?")) {
            ps.setLong(1, nowEpochSeconds - horizon);
            ps.setLong(2, nowEpochSeconds - horizon);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE, "cannot prune attempt counters", e);
        }
    }

    /** Exponential back-off, capped twice: by the configured ceiling and by the window. */
    private static int penaltySeconds(int failures, int limit, int windowSeconds, int ceiling) {
        if (failures < limit) {
            return 0;
        }
        int exponent = Math.min(failures - limit, 20); // keep the shift inside long range
        long penalty = 1L << exponent;
        penalty = Math.min(penalty, Math.min(ceiling, windowSeconds));
        return (int) penalty;
    }

    // ------------------------------------------------------------------ registration budgets

    private record Budget(boolean exhausted, int used) {
    }

    private Budget readBudget(String bucketId, long now, int windowSeconds, int max) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(
                "SELECT failures, first_at_epoch_s FROM auth_throttle WHERE bucket = ?")) {
            ps.setString(1, bucketId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return new Budget(false, 0);
                }
                int failures = rs.getInt("failures");
                long firstAt = rs.getLong("first_at_epoch_s");
                if (firstAt <= now - windowSeconds) {
                    return new Budget(false, 0); // window lapsed: treated as empty
                }
                return new Budget(failures >= max, failures);
            }
        }
    }

    private void chargeBudget(String bucketId, long now, int windowSeconds) throws SQLException {
        long floor = now - windowSeconds;
        try (PreparedStatement ps = connection.prepareStatement("""
                UPDATE auth_throttle
                   SET failures = CASE WHEN first_at_epoch_s > ? THEN LEAST(failures + 1, ?) ELSE 1 END,
                       first_at_epoch_s = CASE WHEN first_at_epoch_s > ? THEN first_at_epoch_s ELSE ? END,
                       last_at_epoch_s = ?
                 WHERE bucket = ?""")) {
            ps.setLong(1, floor);
            ps.setInt(2, FAILURES_CEILING);
            ps.setLong(3, floor);
            ps.setLong(4, now);
            ps.setLong(5, now);
            ps.setString(6, bucketId);
            if (ps.executeUpdate() == 0) {
                try (PreparedStatement ins = connection.prepareStatement(
                        "INSERT INTO auth_throttle (bucket, failures, first_at_epoch_s, until_epoch_s, last_at_epoch_s)"
                                + " VALUES (?, 1, ?, 0, ?)")) {
                    ins.setString(1, bucketId);
                    ins.setLong(2, now);
                    ins.setLong(3, now);
                    ins.executeUpdate();
                }
            }
        }
    }

    // ------------------------------------------------------------------ sessions

    /**
     * Issues a session and enforces the per-account cap in one transaction.
     *
     * <p>The cap is one self-converging {@code DELETE} that keeps the newest N rows, not
     * count-then-truncate: two concurrent logins both leave the table satisfying the cap, and
     * neither can leave {@code N + 1} live sessions behind.
     *
     * <p>The token comes from {@link SessionToken#generate} ({@link SecureRandom}) and is never
     * accepted from the caller; the row is keyed by its SHA-256 digest, so reading this table does
     * not hand over usable credentials.
     */
    synchronized void createSession(long accountId, SessionToken token, long nowEpochSeconds)
            throws IdentityStoreException {
        long expires = nowEpochSeconds + config.sessionTtlSeconds();
        boolean previousAutoCommit = true;
        try {
            previousAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
            try (PreparedStatement ins = connection.prepareStatement(
                    "INSERT INTO session (token_hash, account_id, created_at_epoch_s, expires_at_epoch_s)"
                            + " VALUES (?,?,?,?)")) {
                ins.setString(1, token.tokenHash());
                ins.setLong(2, accountId);
                ins.setLong(3, nowEpochSeconds);
                ins.setLong(4, expires);
                if (ins.executeUpdate() != 1) {
                    throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE, "the session row was not written");
                }
            } catch (SQLException e) {
                connection.rollback();
                if (isUniqueViolation(e)) {
                    // A collision on a 256-bit CSPRNG value means the random source is broken, not
                    // that someone signed in twice. Fail closed; do not paper over it.
                    throw new IdentityStoreException(Reason.CRYPTO_FAILURE,
                            "the generated session token collided with an existing one", e);
                }
                throw e;
            }
            try (PreparedStatement prune = connection.prepareStatement(
                    "DELETE FROM session WHERE account_id = ? AND token_hash NOT IN ("
                            + "SELECT token_hash FROM session WHERE account_id = ?"
                            + " ORDER BY created_at_epoch_s DESC, token_hash DESC FETCH FIRST ? ROWS ONLY)")) {
                prune.setLong(1, accountId);
                prune.setLong(2, accountId);
                prune.setInt(3, config.maxSessionsPerAccount());
                prune.executeUpdate();
            }
            connection.commit();
        } catch (SQLException e) {
            // An IdentityStoreException raised inside the try is not an SQLException, so it does
            // not reach here; the paths that raise it roll back themselves first.
            rollbackQuietly();
            throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE, "cannot create the session", e);
        } finally {
            restoreAutoCommit(previousAutoCommit);
        }
    }

    /**
     * Resolves a submitted token to a session row in one statement, returning the server-side state
     * (expiry, account status) the caller must check. Nothing on the row is trusted as proof of
     * identity beyond the token itself, and the token is never echoed.
     *
     * <p>Every column is read <em>by label</em>, never by position. An earlier version of this method
     * read {@code getString(3)} for the status while {@code username_canon} was third in the
     * projection, so {@code status()} was always the username, never matched {@code "active"}, and
     * the caller's "disabled account" branch <em>deleted the session it had just resolved</em>: every
     * token died on first use, with no error anywhere. A label cannot drift out of sync with the
     * projection it names; an index silently reads a neighbouring column of the same type.
     */
    synchronized SessionRow resolveSession(SessionToken token, long nowEpochSeconds) throws IdentityStoreException {
        String sql = "SELECT s.expires_at_epoch_s, a.id, a.username_canon, a.status"
                + " FROM session s JOIN account a ON a.id = s.account_id WHERE s.token_hash = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, token.tokenHash());
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }
                Identity username = Identity.fromStoredUsername(rs.getString("username_canon"));
                if (username == null) {
                    throw new IdentityStoreException(Reason.CORRUPT_RECORD,
                            "the session points at an account with an invalid username");
                }
                long expires = rs.getLong("expires_at_epoch_s");
                return new SessionRow(rs.getLong("id"), username, rs.getString("status"), expires,
                        expires > nowEpochSeconds);
            }
        } catch (SQLException e) {
            throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE, "cannot read the session", e);
        }
    }

    /**
     * Deletes a session; 1 if it was live, 0 if there was nothing to delete. Both are reported to
     * the caller as {@link Reason#SESSION_REVOKED} - the count is for the audit log only.
     */
    synchronized int revokeSession(SessionToken token) throws IdentityStoreException {
        try (PreparedStatement ps = connection.prepareStatement("DELETE FROM session WHERE token_hash = ?")) {
            ps.setString(1, token.tokenHash());
            return ps.executeUpdate();
        } catch (SQLException e) {
            throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE, "cannot revoke the session", e);
        }
    }

    /** Revokes every session for an account in one statement, so there is no partial window. */
    synchronized int revokeAllSessions(long accountId) throws IdentityStoreException {
        try (PreparedStatement ps = connection.prepareStatement("DELETE FROM session WHERE account_id = ?")) {
            ps.setLong(1, accountId);
            return ps.executeUpdate();
        } catch (SQLException e) {
            throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE, "cannot revoke sessions", e);
        }
    }

    /**
     * Removes sessions whose TTL elapsed. A session row is deleted rather than merely judged dead
     * on read, so a dump of the database overstates nothing - and a revoked token stops being
     * replayable even if a future bug forgets the expiry check.
     */
    synchronized int deleteExpiredSessions(long nowEpochSeconds) throws IdentityStoreException {
        try (PreparedStatement ps = connection.prepareStatement(
                "DELETE FROM session WHERE expires_at_epoch_s <= ?")) {
            ps.setLong(1, nowEpochSeconds);
            return ps.executeUpdate();
        } catch (SQLException e) {
            throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE, "cannot prune sessions", e);
        }
    }

    synchronized int countSessions() throws IdentityStoreException {
        return countAll("session");
    }

    synchronized int countThrottleRows() throws IdentityStoreException {
        return countAll("auth_throttle");
    }

    // ------------------------------------------------------------------ helpers

    /** Immutable row of {@code account}, re-validated. The hash is never printed or compared here. */
    record Account(long id, Identity username, Identity email, String passwordHash, String status,
                   long createdEpochSeconds) {
        @Override
        public String toString() {
            return "Account[id=" + id + ", " + username + ", status=" + status + "]";
        }
    }

    record SessionRow(long accountId, Identity username, String status, long expiresAtEpochSeconds, boolean live) {
        @Override
        public String toString() {
            return "SessionRow[account=" + accountId + ", live=" + live + "]";
        }
    }

    record Throttle(boolean blocked, int failures, int penaltySeconds) {
    }

    /**
     * Result of {@link #register}. {@link #reason()} is the store's specific fact, for the audit log
     * only; {@link #callerReason()} is what an API caller may be given. They differ for a collision -
     * see {@link Reason#forCaller()}.
     */
    record Outcome(Reason reason, SessionToken token) {

        Reason callerReason() {
            return reason.forCaller();
        }
    }

    private int countAll(String table) throws IdentityStoreException {
        // table is a literal at every call site; no caller data reaches this string.
        try (Statement s = connection.createStatement();
             ResultSet rs = s.executeQuery("SELECT COUNT(*) FROM " + table)) {
            return rs.next() ? rs.getInt(1) : 0;
        } catch (SQLException e) {
            throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE, "cannot count rows", e);
        }
    }

    private Long readLongOrNull(String sql, String param) throws IdentityStoreException {
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, param);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getLong(1) : null;
            }
        } catch (SQLException e) {
            throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE, "cannot read the attempt counter", e);
        }
    }

    private boolean existsCanonical(String column, String canonical) throws IdentityStoreException {
        // column is one of two literals chosen in code, never input.
        try (PreparedStatement ps = connection.prepareStatement(
                "SELECT 1 FROM account WHERE " + column + " = ?")) {
            ps.setString(1, canonical);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE, "cannot resolve the collision", e);
        }
    }

    private static boolean isUniqueViolation(SQLException e) {
        // SQLState class 23 is integrity constraint violation. Classified on the state, not on
        // message text: a localised or reworded driver message must not turn a real storage failure
        // into a silently-swallowed "duplicate".
        String state = e.getSQLState();
        return state != null && state.startsWith("23");
    }

    private void rollbackQuietly() {
        try {
            connection.rollback();
        } catch (SQLException ignored) {
            // A failed rollback leaves the transaction to be discarded on close.
        }
    }

    private void restoreAutoCommit(boolean previous) {
        try {
            connection.setAutoCommit(previous);
        } catch (SQLException ignored) {
            // Single-use connection per process; nothing actionable.
        }
    }

    // ------------------------------------------------------------------ bucket keys

    private static byte[] loadOrCreateBucketKey(Connection c) throws SQLException, IdentityStoreException {
        try (PreparedStatement ps = c.prepareStatement("SELECT v FROM meta WHERE k = 'bucket-key'");
             ResultSet rs = ps.executeQuery()) {
            if (rs.next()) {
                String stored = rs.getString(1);
                if (stored != null && stored.length() == 43) {
                    try {
                        byte[] raw = Base64.getUrlDecoder().decode(stored);
                        if (raw.length == 32) {
                            return raw;
                        }
                    } catch (IllegalArgumentException notBase64) {
                        // Replace it below.
                    }
                }
            }
        }
        byte[] fresh = new byte[32];
        new SecureRandom().nextBytes(fresh);
        try (PreparedStatement ps = c.prepareStatement("MERGE INTO meta (k, v) KEY(k) VALUES ('bucket-key', ?)")) {
            ps.setString(1, Base64.getUrlEncoder().withoutPadding().encodeToString(fresh));
            ps.executeUpdate();
        }
        return fresh;
    }

    /** Fixed-width keyed bucket id; no identifier plaintext is stored in the throttle table. */
    private String bucketId(String kind, String canonicalValue) throws IdentityStoreException {
        if (kind == null || kind.isEmpty() || canonicalValue == null) {
            throw new IdentityStoreException(Reason.CORRUPT_RECORD, "refusing an incomplete bucket key");
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            // No wipe attempt: SecretKeySpec copies the key into a private array it does not expose,
            // and destroy() throws UnsupportedOperationException without clearing anything, so a
            // call here would read as hygiene and do nothing. The bucket key must stay resident for
            // buckets to remain stable across the process anyway; it pseudonymises rate-limit keys,
            // and protects no password, token, or passphrase.
            mac.init(new SecretKeySpec(bucketKey, "HmacSHA256"));
            mac.update((byte) kind.charAt(0));
            byte[] digest = mac.doFinal(canonicalValue.getBytes(StandardCharsets.UTF_8));
            return kind + ":" + Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (java.security.GeneralSecurityException e) {
            throw new IdentityStoreException(Reason.CRYPTO_FAILURE, "cannot key the attempt counter", e);
        }
    }

    static String bucketKindAccount() {
        return BUCKET_KIND_ACCOUNT;
    }

    static String bucketKindSource() {
        return BUCKET_KIND_SOURCE;
    }

    /** Exposed so a test can prove the registration and authentication namespaces never collide. */
    static String bucketKindRegisterSource() {
        return BUCKET_KIND_REGISTER_SOURCE;
    }
}
