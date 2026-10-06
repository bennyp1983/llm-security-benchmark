package app;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Owns the single JDBC connection and the schema.
 *
 * <p>Autocommit is off for the lifetime of the connection. Every check-then-act path runs
 * inside {@link #inTransaction}, and the throttle additionally takes a row lock, so "count,
 * then allow" and "verify, then grant" are single atomic statements or single locked
 * transactions. A transaction that throws rolls back completely: no partially created account,
 * no half-consumed throttle budget.
 */
public final class Db implements AutoCloseable {

    /** Fail closed rather than queue forever when another writer holds a throttle row. */
    static final int LOCK_TIMEOUT_MILLIS = 2_000;

    private final Connection connection;
    private boolean retired;

    Db(Connection connection) {
        this.connection = connection;
        try {
            connection.setAutoCommit(false);
            try (Statement lockSetup = connection.createStatement()) {
                lockSetup.execute("SET LOCK_TIMEOUT " + LOCK_TIMEOUT_MILLIS);
            }
        } catch (SQLException couldNotConfigure) {
            throw new IllegalStateException("the account store could not be configured", couldNotConfigure);
        }
    }

    public Connection connection() {
        return retired ? null : connection;
    }

    /**
     * The account table, with the credential column sized from the longest hash the key-derivation
     * policy can emit ({@link PasswordHasher#MAX_STORED_HASH_CHARS}) rather than from the width of
     * today's defaults. A fixed 97 fitted the shipped parameters exactly and rejected a legal
     * stronger one - a configured cost must never be refused by storage. The seven {@code %d}
     * placeholders are the only format specifiers; the literal percent signs in the LIKE pattern
     * and in the e-mail character class are written {@code %%}.
     */
    static final String ACCOUNTS_DDL = ("""
        CREATE TABLE IF NOT EXISTS accounts (
          id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          email               VARCHAR(254) NOT NULL,
          username            VARCHAR(32)  NOT NULL,
          password_hash       VARCHAR(%d)  NOT NULL,
          kdf                 VARCHAR(16)  NOT NULL,
          kdf_memory_kib      INT          NOT NULL,
          kdf_iterations      INT          NOT NULL,
          kdf_parallelism     INT          NOT NULL,
          created_at          BIGINT       NOT NULL,
          password_updated_at BIGINT       NOT NULL,
          CONSTRAINT accounts_email_unique UNIQUE (email),
          CONSTRAINT accounts_username_unique UNIQUE (username),
          CONSTRAINT accounts_kdf CHECK (kdf = 'argon2id'),
          CONSTRAINT accounts_kdf_memory CHECK (kdf_memory_kib BETWEEN %d AND %d),
          CONSTRAINT accounts_kdf_iterations CHECK (kdf_iterations BETWEEN %d AND %d),
          CONSTRAINT accounts_kdf_parallelism CHECK (kdf_parallelism BETWEEN %d AND %d),
          CONSTRAINT accounts_hash_matches_kdf CHECK (password_hash LIKE
              '$argon2id$v=19$m=' || CAST(kdf_memory_kib AS VARCHAR)
              || ',t=' || CAST(kdf_iterations AS VARCHAR)
              || ',p=' || CAST(kdf_parallelism AS VARCHAR) || '$%%'),
          CONSTRAINT accounts_email_lower CHECK (email = LOWER(email) AND ASCII(email) <> 32),
          CONSTRAINT accounts_email_shape CHECK (email REGEXP
              '^[A-Za-z0-9._%%+\\-]{1,64}@[A-Za-z0-9.\\-]{1,253}\\z'
              AND INSTR(email, '..') = 0
              AND SUBSTR(email, 1, 1) <> '.'
              AND INSTR(SUBSTR(email, INSTR(email, '@') + 1), '.') > 0),
          CONSTRAINT accounts_username_shape CHECK (username REGEXP
              '^[a-z][a-z0-9\\-]{1,30}[a-z0-9]\\z'),
          CONSTRAINT accounts_hash_shape CHECK (password_hash REGEXP
              '^\\$argon2id\\$v=19\\$m=[0-9]{1,9},t=[0-9]{1,4},p=[0-9]{1,3}\\$[A-Za-z0-9+/]{22}\\$[A-Za-z0-9+/]{43}\\z')
        )""").formatted(PasswordHasher.MAX_STORED_HASH_CHARS,
            PasswordHasher.STORED_MIN_MEMORY_KIB, PasswordHasher.STORED_MAX_MEMORY_KIB,
            PasswordHasher.STORED_MIN_ITERATIONS, PasswordHasher.STORED_MAX_ITERATIONS,
            PasswordHasher.STORED_MIN_PARALLELISM, PasswordHasher.STORED_MAX_PARALLELISM);

    /**
     * Creates the schema if absent. Called once at start-up, before any credential is written.
     *
     * <p>The CHECK constraints repeat, in SQL, the character-class and format rules that
     * {@link InputPolicy} enforces in Java - defence in depth, so a future code path that
     * forgets to validate still cannot persist an email containing a newline, a username with
     * markup, or the same mailbox spelled two different ways. Verified against H2 2.5.252:
     * {@code REGEXP} is usable inside a CHECK constraint, and Java's {@code $} anchor is not
     * acceptable here because Java lets a trailing newline match - SQL {@code \z} is used, which
     * refuses {@code "user@corp.example\n"}.
     *
     * <p>The width and the cost CHECK constraints come from {@link PasswordHasher}, so the storage
     * limit and the accepted-parameter policy are one fact in one place; the exact-shape regex
     * still makes an over-long or padded value a size error rather than a silent truncation. The
     * {@code accounts_hash_matches_kdf} constraint ties the cost parameters embedded in the hash
     * string to their indexed columns, so the two can never disagree and an operator can find
     * every account that needs re-hashing without parsing strings.
     */
    public void applySchema() throws SQLException {
        try (Statement schema = connection.createStatement()) {
            schema.execute(ACCOUNTS_DDL);

            schema.execute("""
                CREATE TABLE IF NOT EXISTS auth_guard (
                  account_id     BIGINT       NOT NULL PRIMARY KEY,
                  failures       INT          NOT NULL DEFAULT 0,
                  window_start   BIGINT       NOT NULL DEFAULT 0,
                  window_seconds INT          NOT NULL,
                  max_failures   INT          NOT NULL,
                  blocked_until  BIGINT       NOT NULL DEFAULT 0,
                  version        BIGINT       NOT NULL DEFAULT 0,
                  CONSTRAINT auth_guard_window CHECK (window_seconds BETWEEN 10 AND 86400),
                  CONSTRAINT auth_guard_max CHECK (max_failures BETWEEN 1 AND 1000),
                  CONSTRAINT auth_guard_failures CHECK (failures BETWEEN 0 AND 1000)
                )""");

            schema.execute("""
                CREATE TABLE IF NOT EXISTS throttle_bucket (
                  bucket_key     VARCHAR(128) NOT NULL PRIMARY KEY,
                  tokens         INT          NOT NULL,
                  window_start   BIGINT       NOT NULL,
                  window_seconds INT          NOT NULL,
                  max_tokens     INT          NOT NULL,
                  CONSTRAINT throttle_window CHECK (window_seconds BETWEEN 10 AND 86400),
                  CONSTRAINT throttle_max CHECK (max_tokens BETWEEN 1 AND 100000),
                  CONSTRAINT throttle_tokens CHECK (tokens BETWEEN 0 AND 100000)
                )""");

            schema.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                  token_hash   CHAR(64)  NOT NULL PRIMARY KEY,
                  account_id   BIGINT    NOT NULL,
                  issued_at    BIGINT    NOT NULL,
                  expires_at   BIGINT    NOT NULL,
                  revoked_at   BIGINT,
                  CONSTRAINT sessions_token_shape CHECK (token_hash REGEXP '^[0-9a-f]{64}\\z'),
                  CONSTRAINT sessions_expiry CHECK (expires_at > issued_at),
                  CONSTRAINT sessions_account_fk FOREIGN KEY (account_id)
                      REFERENCES accounts (id) ON DELETE CASCADE
                )""");
            schema.execute("CREATE INDEX IF NOT EXISTS sessions_account_idx ON sessions (account_id)");
        }
        connection.commit();
    }

    /**
     * Runs {@code body} in one transaction; commits on success, rolls back on any failure.
     *
     * <p>The monitor serialises access: the JDBC connection is confined to one thread at a time
     * and two callers can never interleave work on it. A nested call reuses the open transaction
     * and does not commit early.
     */
    public synchronized <T> T inTransaction(SqlBody<T> body) throws SQLException, AuditLog.AuditException {
        if (retired) {
            throw new SQLException("the account store is closed");
        }
        if (depth > 0) {
            depth++;
            try {
                return body.execute(connection);
            } finally {
                depth--;
            }
        }
        depth = 1;
        try {
            T result = body.execute(connection);
            connection.commit();
            return result;
        } catch (SQLException | AuditLog.AuditException | RuntimeException failed) {
            try {
                connection.rollback();
            } catch (SQLException rollbackFailed) {
                failed.addSuppressed(rollbackFailed);
            }
            throw failed;
        } finally {
            depth = 0;
        }
    }

    private int depth;

    public interface SqlBody<T> {
        /**
         * A body may fail with {@link AuditLog.AuditException} to abort the transaction: a
         * security decision whose audit record could not be written must not be committed, so the
         * rollback is the fail-closed behaviour rather than a partial one.
         */
        T execute(Connection connection) throws SQLException, AuditLog.AuditException;
    }

    public void close() {
        if (retired) {
            return;
        }
        retired = true;
        try {
            connection.rollback();
        } catch (SQLException ignore) {
            // Nothing useful can be done while shutting down; the store is closed below.
        }
        try {
            connection.close();
        } catch (SQLException ignore) {
            // Same as above.
        }
    }
}
