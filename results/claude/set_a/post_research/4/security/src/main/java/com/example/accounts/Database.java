package com.example.accounts;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Connection factory, schema migration and transaction helper.
 *
 * <p>Rule 7 (concurrency): {@link #inTransaction} runs the whole check-then-act sequence inside one
 * transaction that takes the write lock up front -- {@code BEGIN IMMEDIATE} on SQLite,
 * {@code SERIALIZABLE} on PostgreSQL. Two concurrent logins therefore cannot both read "9 failures"
 * and both write "10", and two concurrent registrations for one email cannot both pass the
 * existence check (the UNIQUE constraints below are the final, non-bypassable word on that).
 *
 * <p>Rule 5: when the store is a local SQLite file, the file and its WAL/journal siblings are
 * forced to {@code 0600} so no other local user can read password hashes or session records.
 */
public final class Database implements AutoCloseable {

    private final String jdbcUrl;
    private final Properties properties;
    private final Logger log;

    private Database(String jdbcUrl, Properties properties, Logger log) {
        this.jdbcUrl = jdbcUrl;
        this.properties = properties;
        this.log = log;
    }

    public static Database open(Config config, Logger log) throws SQLException {
        String url = config.jdbcUrl();
        if (!url.startsWith("jdbc:sqlite:")) {
            throw new SQLException("unsupported JDBC URL");
        }
        Properties props = new Properties();
        // Applied by sqlite-jdbc as PRAGMAs on every connection it hands out.
        props.setProperty("foreign_keys", "true");
        props.setProperty("journal_mode", "WAL");
        props.setProperty("synchronous", "NORMAL");
        props.setProperty("busy_timeout", "5000");
        props.setProperty("transaction_mode", "IMMEDIATE");
        Database db = new Database(url, props, log);
        db.migrate();
        db.restrictDatabaseFilePermissions(url);
        log.info(() -> "database ready at " + Mask.jdbcUrl(url));
        return db;
    }

    /** Opens a connection with auto-commit disabled, ready for {@link #inTransaction}. */
    private Connection connect() throws SQLException {
        Connection c = DriverManager.getConnection(jdbcUrl, properties);
        try {
            c.setAutoCommit(false);
            return c;
        } catch (SQLException e) {
            closeQuietly(c);
            throw e;
        }
    }

    /** A unit of work that must be atomic. */
    public interface TxWork<T> {
        T run(Connection connection) throws SQLException;
    }

    /** Runs {@code work} in a single transaction, committing on success and rolling back on error. */
    public <T> T inTransaction(TxWork<T> work) throws SQLException {
        try (Connection c = connect()) {
            try {
                T result = work.run(c);
                c.commit();
                return result;
            } catch (SQLException | RuntimeException e) {
                try {
                    c.rollback();
                } catch (SQLException rollbackFailure) {
                    log.log(Level.WARNING, "transaction rollback failed", rollbackFailure);
                }
                throw e;
            }
        }
    }

    private void migrate() throws SQLException {
        try (Connection c = connect(); Statement s = c.createStatement()) {
            for (String ddl : SCHEMA) {
                s.executeUpdate(ddl);
            }
            c.commit();
        }
    }

    private void restrictDatabaseFilePermissions(String url) {
        String pathPart = url.substring("jdbc:sqlite:".length());
        int q = pathPart.indexOf('?');
        if (q >= 0) {
            pathPart = pathPart.substring(0, q);
        }
        if (pathPart.isEmpty() || pathPart.startsWith(":")) {
            return; // in-memory database, nothing on disk
        }
        Path base = Paths.get(pathPart);
        for (String suffix : new String[] {"", "-wal", "-shm", "-journal"}) {
            Path p = suffix.isEmpty() ? base : Paths.get(pathPart + suffix);
            try {
                if (Files.exists(p) && !Files.isSymbolicLink(p)
                        && p.getFileSystem().supportedFileAttributeViews().contains("posix")) {
                    Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-------"));
                }
            } catch (IOException | UnsupportedOperationException e) {
                log.log(Level.WARNING, "could not restrict permissions on database file", e);
            }
        }
    }

    private static void closeQuietly(Connection c) {
        try {
            c.close();
        } catch (SQLException ignored) {
            // nothing useful to do while unwinding
        }
    }

    @Override
    public void close() {
        // Connections are per-transaction; nothing long-lived is held open.
    }

    /**
     * Schema. Every text column is length-bounded by a CHECK (rule 5: bound what you store) and the
     * uniqueness of an email or username is enforced by the engine, not by application code.
     */
    private static final String[] SCHEMA = {
        """
        CREATE TABLE IF NOT EXISTS account (
          id                  INTEGER PRIMARY KEY AUTOINCREMENT,
          email_canonical     TEXT    NOT NULL UNIQUE
                                      CHECK (length(email_canonical) BETWEEN 6 AND 254),
          username_canonical  TEXT    NOT NULL UNIQUE
                                      CHECK (length(username_canonical) BETWEEN 3 AND 32),
          username_display    TEXT    NOT NULL
                                      CHECK (length(username_display) BETWEEN 3 AND 32),
          password_hash       TEXT    NOT NULL
                                      CHECK (length(password_hash) BETWEEN 40 AND 512),
          created_at          INTEGER NOT NULL,
          password_changed_at INTEGER NOT NULL,
          disabled            INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1))
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS auth_attempt (
          scope        TEXT    NOT NULL CHECK (scope IN ('account', 'source')),
          scope_key    TEXT    NOT NULL CHECK (length(scope_key) = 64),
          window_start INTEGER NOT NULL,
          failures     INTEGER NOT NULL CHECK (failures >= 0),
          PRIMARY KEY (scope, scope_key)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS auth_session (
          token_hash          TEXT    PRIMARY KEY CHECK (length(token_hash) = 64),
          session_ref         TEXT    NOT NULL UNIQUE CHECK (length(session_ref) = 32),
          account_id          INTEGER NOT NULL REFERENCES account(id) ON DELETE CASCADE,
          created_at          INTEGER NOT NULL,
          last_used_at        INTEGER NOT NULL,
          absolute_expires_at INTEGER NOT NULL,
          revoked             INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1))
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_session_account ON auth_session (account_id)",
        "CREATE INDEX IF NOT EXISTS idx_attempt_window ON auth_attempt (window_start)",
    };
}
