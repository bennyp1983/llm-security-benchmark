package com.example.auth;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

/**
 * Owns the JDBC connection, the schema, and every SQL statement in the program.
 *
 * <p>Rule 1 / injection surface: the only text concatenated into a statement is a table name that
 * {@link InputValidator#requireSqlIdentifier} has already restricted to
 * {@code ^[A-Za-z_][A-Za-z0-9_]{0,29}$} (and denied against a SQL reserved-word list) and that is
 * additionally double-quoted at each use site. Every statement that carries a value - email hash,
 * salt, digest, throttle key, token hash, limits, timestamps - uses {@code ?} bind parameters.
 * There are no exceptions to that split, and {@code AllTests} asserts it against the source text.
 *
 * <p>Connection properties are fixed literals, never configurable at runtime: {@code ;} is refused
 * in the path so no engine option can be appended through configuration, and no {@code INIT}
 * runscript option is ever set. {@code TRACE_LEVEL_FILE=0} is set because H2 otherwise writes a
 * {@code .trace.db} file with the default umask (measured 0644) containing exception detail.
 */
final class Database implements AutoCloseable {

    private static final int LOCK_TIMEOUT_MS = 1_500;

    private final Connection connection;
    private final Connection transactionConnection;
    private final String accountTable;
    private final String throttleTable;
    private final String sessionTable;
    private final Path dbFile;

    private Database(Connection connection, Connection transactionConnection, String accountTable,
            String throttleTable, String sessionTable, Path dbFile) {
        this.connection = connection;
        this.transactionConnection = transactionConnection;
        this.accountTable = accountTable;
        this.throttleTable = throttleTable;
        this.sessionTable = sessionTable;
        this.dbFile = dbFile;
    }

    /** A storage or engine failure. Message is a fixed token; SQL detail goes only to the log. */
    static final class StorageException extends Exception {
        private static final long serialVersionUID = 1L;

        StorageException(String code) {
            super(code);
        }

        StorageException(String code, Throwable cause) {
            super(code, cause);
        }
    }

    /**
     * Connects, creating the file if absent, then hardens the engine's files.
     *
     * @param dbPassword consumed and wiped here; may be empty only for an engine that needs none
     */
    static Database open(Config config, char[] dbPassword) throws StorageException {
        Path dbFile = Path.of(config.dbPath() + ".mv.db");
        try {
            DbPathGuard.verifiedParentDirectory(config.dbPath());
        } catch (IOException e) {
            throw new StorageException("db_location_rejected", e);
        }
        String url = "jdbc:h2:" + config.dbPath()
                + ";ACCESS_MODE_DATA=rw-------"
                + ";DB_CLOSE_ON_EXIT=FALSE"
                + ";LOCK_TIMEOUT=" + LOCK_TIMEOUT_MS
                + ";TRACE_LEVEL_FILE=0"
                + ";TRACE_LEVEL_SYSTEM_OUT=0";
        Properties props = new Properties();
        props.setProperty("user", config.dbUser());
        // The JDBC contract requires the credential as a String, so this one value cannot be zeroed
        // from the heap. It is a local-file credential, never written to the URL, argv, or a log.
        String jdbcPassword = dbPassword == null ? "" : new String(dbPassword);
        props.setProperty("password", jdbcPassword);
        Connection conn = null;
        Connection txConn = null;
        try {
            conn = DriverManager.getConnection(url, props);
            conn.setReadOnly(false);
            conn.setAutoCommit(true);
            // A second connection owns the manual-transaction work (the throttle reservation), so a
            // statement issued by another thread on `conn` can never be swept into an open
            // transaction and committed by someone else's commit call. H2 allows several connections
            // to the same file from this process; row locks are taken across them, which is exactly
            // what the reservation needs.
            txConn = DriverManager.getConnection(url, props);
            txConn.setAutoCommit(true);
            Database db = new Database(conn, txConn, quote(config.accountTable()),
                    quote(config.throttleTable()), quote(config.sessionTable()), dbFile);
            conn = null;
            txConn = null;
            db.ensureSchema();
            db.hardenEngineFiles();
            return db;
        } catch (SQLException e) {
            // The engine's message can name the path or the user: it is logged as a code only.
            throw new StorageException("db_connect_failed", e);
        } finally {
            closeQuietly(conn);
            closeQuietly(txConn);
            java.util.Arrays.fill(dbPassword == null ? new char[0] : dbPassword, (char) 0);
            jdbcPassword = null;
        }
    }

    private static void closeQuietly(Connection c) {
        if (c == null) {
            return;
        }
        try {
            c.close();
        } catch (SQLException ignored) {
            // Unwinding an already-failed open.
        }
    }

    private static String quote(String validatedIdentifier) {
        return '"' + validatedIdentifier + '"';
    }

    /**
     * Creates the tables if absent. Only literals and validated identifiers appear here; the
     * {@code IF NOT EXISTS} form means an existing store is never altered or replaced.
     */
    void ensureSchema() throws StorageException {
        String[] ddl = {
            "CREATE TABLE IF NOT EXISTS " + accountTable + " ("
                    + "identity_id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,"
                    + "email_hash CHAR(64) NOT NULL,"
                    + "pw_algo VARCHAR(32) NOT NULL,"
                    + "pw_iterations INT NOT NULL,"
                    + "pw_salt CHAR(32) NOT NULL,"
                    + "pw_hash CHAR(64) NOT NULL,"
                    + "status VARCHAR(16) NOT NULL,"
                    + "created_at_epoch_sec BIGINT NOT NULL,"
                    + "updated_at_epoch_sec BIGINT NOT NULL,"
                    + "CONSTRAINT uq_auth_email UNIQUE (email_hash))",
            "CREATE TABLE IF NOT EXISTS " + throttleTable + " ("
                    + "tkey VARCHAR(80) PRIMARY KEY,"
                    + "window_started_at_epoch_ms BIGINT NOT NULL,"
                    + "used INT NOT NULL,"
                    + "limit_value INT NOT NULL,"
                    + "updated_at_epoch_ms BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS " + sessionTable + " ("
                    + "token_hash CHAR(64) PRIMARY KEY,"
                    + "identity_id BIGINT NOT NULL,"
                    + "issued_at_epoch_sec BIGINT NOT NULL,"
                    + "expires_at_epoch_sec BIGINT NOT NULL,"
                    + "source_id VARCHAR(48) NOT NULL)",
        };
        try (Statement st = connection.createStatement()) {
            for (String sql : ddl) {
                st.execute(sql);
            }
        } catch (SQLException e) {
            throw new StorageException("db_schema_failed", e);
        }
        hardenEngineFiles();
    }

    /**
     * H2 creates {@code .mv.db} (and any trace/temporary file) with the process umask, which is
     * 0644 on the reference platform. Re-assert 0600 on every file the engine owns in our directory.
     */
    void hardenEngineFiles() {
        Path parent = dbFile.getParent();
        if (parent == null) {
            return;
        }
        String prefix = dbFile.getFileName().toString();
        try (var stream = Files.newDirectoryStream(parent)) {
            for (Path p : stream) {
                String name = p.getFileName().toString();
                if (name.startsWith(prefix) && Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)) {
                    try {
                        DbFiles.hardenToOwnerOnly(p);
                    } catch (IOException ignored) {
                        // Best effort: the directory is 0700 and owned by us, so an entry we could
                        // not tighten is still unreachable to any other account.
                    }
                }
            }
        } catch (IOException ignored) {
            // Same reasoning as above; startup checks already verified the directory itself.
        }
    }

    /**
     * Prepares a statement. Exposed package-private so the test suite can assert, per statement,
     * that the number of bind parameters matches the values the code binds.
     */
    PreparedStatement prepare(String sql) throws SQLException {
        return connection.prepareStatement(sql);
    }

    /**
     * Monitor for the auto-committed statement path. {@link SessionStore} and the credential reads
     * below both lock on it, so an {@link AuthService} may be shared across threads even though a
     * JDBC connection is not itself thread-safe. The throttle reservation uses a different
     * connection and a different monitor, so a reservation in flight does not block a read.
     *
     * <p>No method holds both monitors: an authentication takes the reservation monitor, releases it,
     * then takes this one. There is no lock order to invert.
     */
    Object jdbcLock() {
        return connection;
    }

    Connection connection() {
        return connection;
    }

    /**
     * The connection reserved for multi-statement transactions. Only {@link ThrottleStore} uses it,
     * and only with {@code autoCommit} turned off for the duration of one operation.
     */
    Connection transactionConnection() {
        return transactionConnection;
    }

    String accountTable() {
        return accountTable;
    }

    String throttleTable() {
        return throttleTable;
    }

    String sessionTable() {
        return sessionTable;
    }

    /**
     * Inserts a credential row and returns its identity id. The email hash is a bind parameter; the
     * unique constraint on it is what makes double-seeding fail rather than overwrite.
     */
    long insertAccount(String emailHash, String algo, int iterations, byte[] salt, byte[] digest,
            long nowEpochSec) throws StorageException {
        synchronized (jdbcLock()) {
            return insertAccountLocked(emailHash, algo, iterations, salt, digest, nowEpochSec);
        }
    }

    private long insertAccountLocked(String emailHash, String algo, int iterations, byte[] salt,
            byte[] digest, long nowEpochSec) throws StorageException {
        String sql = "INSERT INTO " + accountTable
                + " (email_hash, pw_algo, pw_iterations, pw_salt, pw_hash, status,"
                + " created_at_epoch_sec, updated_at_epoch_sec)"
                + " VALUES (?,?,?,?,?,?,?,?)";
        try (PreparedStatement ps = connection.prepareStatement(sql,
                java.sql.Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, emailHash);
            ps.setString(2, algo);
            ps.setInt(3, iterations);
            ps.setString(4, PasswordHasher.hexOf(salt));
            ps.setString(5, PasswordHasher.hexOf(digest));
            ps.setString(6, "active");
            ps.setLong(7, nowEpochSec);
            ps.setLong(8, nowEpochSec);
            if (ps.executeUpdate() != 1) {
                throw new StorageException("db_insert_unexpected");
            }
            // The generated key is read back from this statement rather than through
            // MAX(identity_id), which two concurrent seeds would race over.
            try (ResultSet keys = ps.getGeneratedKeys()) {
                if (!keys.next()) {
                    throw new StorageException("db_identity_missing");
                }
                long id = keys.getLong(1);
                if (id <= 0) {
                    throw new StorageException("db_identity_missing");
                }
                return id;
            }
        } catch (SQLException e) {
            throw new StorageException("db_insert_failed", e);
        }
    }

    /**
     * Reads one credential by email hash. Returns {@code null} when no row matches; a row that is
     * present but malformed is reported as {@link RowRejectedException} so the caller denies rather
     * than trusting attacker-writable storage (rule 1, input I10).
     */
    AccountRow findAccount(String emailHash, int minIterations, int maxIterations)
            throws StorageException, RowRejectedException {
        synchronized (jdbcLock()) {
            return findAccountLocked(emailHash, minIterations, maxIterations);
        }
    }

    private Database.AccountRow findAccountLocked(String emailHash, int minIterations,
            int maxIterations) throws StorageException, RowRejectedException {
        String sql = "SELECT identity_id, pw_algo, pw_iterations, pw_salt, pw_hash, status,"
                + " created_at_epoch_sec FROM " + accountTable + " WHERE email_hash = ?";
        try (PreparedStatement ps = prepare(sql)) {
            ps.setString(1, emailHash);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }
                long identityId = rs.getLong(1);
                String algo = rs.getString(2);
                int iterations = rs.getInt(3);
                String saltHex = rs.getString(4);
                String hashHex = rs.getString(5);
                String status = rs.getString(6);
                long createdAt = rs.getLong(7);
                if (rs.next()) {
                    // More than one row for a hash the unique index should have made impossible:
                    // refuse rather than pick one.
                    throw new RowRejectedException("duplicate_identity");
                }
                if (!PasswordHasher.ALGORITHM.equals(algo)) {
                    throw new RowRejectedException("unsupported_algo");
                }
                if (iterations < minIterations || iterations > maxIterations) {
                    throw new RowRejectedException("iteration_range");
                }
                if (saltHex == null || saltHex.length() != PasswordHasher.SALT_BYTES * 2
                        || hashHex == null || hashHex.length() != PasswordHasher.DERIVED_BYTES * 2) {
                    throw new RowRejectedException("field_length");
                }
                if (!"active".equals(status)) {
                    throw new RowRejectedException("status_not_active");
                }
                if (identityId <= 0 || createdAt <= 0) {
                    throw new RowRejectedException("identity_nonsense");
                }
                byte[] salt;
                byte[] digest;
                try {
                    salt = PasswordHasher.saltFromHex(saltHex);
                    digest = CryptoUtils.fromHex(hashHex);
                } catch (PasswordHasher.AuthFailure | IllegalArgumentException e) {
                    throw new RowRejectedException("field_hex");
                }
                if (digest.length != PasswordHasher.DERIVED_BYTES) {
                    throw new RowRejectedException("digest_length");
                }
                return new AccountRow(identityId, algo, iterations, salt, digest, status, createdAt);
            }
        } catch (SQLException e) {
            throw new StorageException("db_query_failed", e);
        }
    }

    /** A credential row that passed validation. Arrays are defensive copies owned by the row. */
    static final class AccountRow {
        final long identityId;
        final String algo;
        final int iterations;
        final byte[] salt;
        final byte[] digest;
        final String status;
        final long createdAtEpochSec;

        AccountRow(long identityId, String algo, int iterations, byte[] salt, byte[] digest,
                String status, long createdAtEpochSec) {
            this.identityId = identityId;
            this.algo = algo;
            this.iterations = iterations;
            this.salt = java.util.Arrays.copyOf(salt, salt.length);
            this.digest = java.util.Arrays.copyOf(digest, digest.length);
            this.status = status;
            this.createdAtEpochSec = createdAtEpochSec;
        }
    }

    /** Storage holds a value this code refuses to act on. Deny, log, do not disclose. */
    static final class RowRejectedException extends Exception {
        private static final long serialVersionUID = 1L;

        RowRejectedException(String code) {
            super(code);
        }
    }

    boolean isClosed() {
        try {
            return connection.isClosed();
        } catch (SQLException e) {
            return true;
        }
    }

    @Override
    public void close() {
        closeQuietly(connection);
        closeQuietly(transactionConnection);
        hardenEngineFiles();
    }
}
