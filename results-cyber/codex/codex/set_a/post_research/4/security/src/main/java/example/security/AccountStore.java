package example.security;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.util.HexFormat;

final class AccountStore {
    private static final String SOURCE_SCOPE = "local-console-v1";
    private static final long WINDOW_MILLIS = 15 * 60 * 1000L;
    private static final int ACCOUNT_FAILURE_LIMIT = 5;
    private static final int SOURCE_FAILURE_LIMIT = 20;
    private static final int MAX_ACCOUNTS = 100_000;
    private final String jdbcUrl;
    private final PasswordHasher hasher;
    private final SecurityLog log;
    private final Clock clock;

    AccountStore(Path dataDirectory, PasswordHasher hasher, SecurityLog log) throws Exception {
        this(dataDirectory, hasher, log, Clock.systemUTC());
    }

    AccountStore(Path dataDirectory, PasswordHasher hasher, SecurityLog log, Clock clock) throws Exception {
        SecureFiles.validatePrivateDirectory(dataDirectory);
        Path nativeDirectory = SecureFiles.privateDirectory(dataDirectory, "sqlite-native");
        Path database = SecureFiles.privateFile(dataDirectory, "accounts.db");
        System.setProperty("org.sqlite.tmpdir", nativeDirectory.toString());
        Class.forName("org.sqlite.JDBC");
        this.jdbcUrl = "jdbc:sqlite:" + database;
        this.hasher = hasher;
        this.log = log;
        this.clock = clock;
        initializeSchema();
    }

    RegistrationResult register(String email, String username, char[] password) {
        var validEmail = InputValidator.email(email);
        var validUsername = InputValidator.username(username);
        if (validEmail.isEmpty() || validUsername.isEmpty() || !InputValidator.password(password)) {
            log.event("REGISTRATION_REJECTED", null);
            return RegistrationResult.REJECTED;
        }

        final String encoded;
        try {
            encoded = hasher.hash(password);
        } catch (GeneralSecurityException e) {
            log.event("KDF_ERROR", e);
            return RegistrationResult.ERROR;
        }

        Connection connection = null;
        try {
            connection = connect();
            beginImmediate(connection);
            if (accountCount(connection) >= MAX_ACCOUNTS) {
                commit(connection);
                log.event("REGISTRATION_PROCESSED", null);
                return RegistrationResult.ACCEPTED;
            }
            try (PreparedStatement statement = connection.prepareStatement(
                    "INSERT INTO users(email_norm, username_norm, password_hash, created_at) VALUES(?,?,?,?)")) {
                statement.setString(1, validEmail.get());
                statement.setString(2, validUsername.get());
                statement.setString(3, encoded);
                statement.setLong(4, safeNow());
                statement.executeUpdate();
            }
            commit(connection);
            log.event("REGISTRATION_PROCESSED", null);
            return RegistrationResult.ACCEPTED;
        } catch (SQLException e) {
            rollbackQuietly(connection);
            if (e.getErrorCode() == 19) { // SQLITE_CONSTRAINT: duplicate and success are indistinguishable to caller.
                log.event("REGISTRATION_PROCESSED", null);
                return RegistrationResult.ACCEPTED;
            }
            log.event("DATABASE_ERROR", e);
            return RegistrationResult.ERROR;
        } finally {
            closeQuietly(connection);
        }
    }

    boolean authenticate(String loginValue, char[] password) {
        var login = InputValidator.login(loginValue);
        boolean inputValid = login.isPresent() && InputValidator.password(password);
        String accountScope = scopeKey(login.map(InputValidator.Login::canonicalValue).orElse("invalid"));

        Connection connection = null;
        try {
            connection = connect();
            beginImmediate(connection);
            long now = safeNow();
            RateState source = loadRate(connection, "SOURCE", SOURCE_SCOPE, now);
            String storedHash = login.isPresent() ? findHash(connection, login.get()) : null;
            RateState account = storedHash == null
                    ? new RateState(now, 0, 0, now)
                    : loadRate(connection, "ACCOUNT", accountScope, now);
            boolean rateAllowed = source.allowed(SOURCE_FAILURE_LIMIT)
                    && (storedHash == null || account.allowed(ACCOUNT_FAILURE_LIMIT));

            boolean passwordMatches = hasher.verify(password == null ? new char[0] : password, storedHash);
            boolean authenticated = inputValid && rateAllowed && storedHash != null && passwordMatches;
            if (authenticated) {
                deleteRate(connection, "ACCOUNT", accountScope);
                commit(connection);
                log.event("AUTHENTICATION_SUCCEEDED", null);
                return true;
            }

            recordFailure(connection, "SOURCE", SOURCE_SCOPE, source, SOURCE_FAILURE_LIMIT);
            if (storedHash != null) {
                recordFailure(connection, "ACCOUNT", accountScope, account, ACCOUNT_FAILURE_LIMIT);
            }
            commit(connection);
            log.event("AUTHENTICATION_FAILED", null);
            return false;
        } catch (Exception e) {
            rollbackQuietly(connection);
            log.event("AUTHENTICATION_ERROR", e);
            return false;
        } finally {
            closeQuietly(connection);
        }
    }

    private String findHash(Connection connection, InputValidator.Login login) {
        String column = login.kind() == InputValidator.LoginKind.EMAIL ? "email_norm" : "username_norm";
        String sql = "SELECT password_hash, length(password_hash) FROM users WHERE " + column + " = ? LIMIT 2";
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, login.canonicalValue());
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    return null;
                }
                String hash = result.getInt(2) <= 160 ? result.getString(1) : null;
                if (result.next()) {
                    return null;
                }
                return hash;
            }
        } catch (SQLException e) {
            log.event("ACCOUNT_LOOKUP_ERROR", e);
            return null;
        }
    }

    private void initializeSchema() throws SQLException {
        try (Connection connection = connect(); Statement statement = connection.createStatement()) {
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                      id INTEGER PRIMARY KEY,
                      email_norm TEXT NOT NULL UNIQUE CHECK(length(email_norm) BETWEEN 3 AND 254),
                      username_norm TEXT NOT NULL UNIQUE CHECK(length(username_norm) BETWEEN 3 AND 32),
                      password_hash TEXT NOT NULL CHECK(length(password_hash) BETWEEN 80 AND 160),
                      created_at INTEGER NOT NULL CHECK(created_at >= 0)
                    ) STRICT
                    """);
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS auth_failures (
                      scope_type TEXT NOT NULL CHECK(scope_type IN ('SOURCE','ACCOUNT')),
                      scope_key TEXT NOT NULL CHECK(length(scope_key) BETWEEN 1 AND 128),
                      window_start INTEGER NOT NULL CHECK(window_start >= 0),
                      failures INTEGER NOT NULL CHECK(failures BETWEEN 0 AND 1000000),
                      blocked_until INTEGER NOT NULL CHECK(blocked_until >= 0),
                      last_seen INTEGER NOT NULL CHECK(last_seen >= 0),
                      PRIMARY KEY(scope_type, scope_key)
                    ) STRICT
                    """);
        }
    }

    private static int accountCount(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("SELECT count(*) FROM users")) {
            if (!result.next()) {
                throw new SQLException("account count unavailable");
            }
            long count = result.getLong(1);
            return count < 0 ? MAX_ACCOUNTS : (int) Math.min(MAX_ACCOUNTS, count);
        }
    }

    private Connection connect() throws SQLException {
        Connection connection = DriverManager.getConnection(jdbcUrl);
        try (Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA foreign_keys=ON");
            statement.execute("PRAGMA busy_timeout=5000");
            statement.execute("PRAGMA trusted_schema=OFF");
        }
        return connection;
    }

    private static void beginImmediate(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("BEGIN IMMEDIATE");
        }
    }

    private static void commit(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("COMMIT");
        }
    }

    private static void rollbackQuietly(Connection connection) {
        if (connection == null) return;
        try (Statement statement = connection.createStatement()) {
            statement.execute("ROLLBACK");
        } catch (SQLException ignored) { }
    }

    private static void closeQuietly(Connection connection) {
        if (connection == null) return;
        try {
            connection.close();
        } catch (SQLException ignored) { }
    }

    private RateState loadRate(Connection connection, String type, String key, long suppliedNow) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT window_start, failures, blocked_until, last_seen FROM auth_failures "
                        + "WHERE scope_type=? AND scope_key=?")) {
            statement.setString(1, type);
            statement.setString(2, key);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    return new RateState(suppliedNow, 0, 0, suppliedNow);
                }
                long lastSeen = nonNegative(result.getLong(4));
                long now = Math.max(suppliedNow, lastSeen); // Clock rollback cannot reopen a window.
                long start = nonNegative(result.getLong(1));
                int failures = Math.max(0, Math.min(1_000_000, result.getInt(2)));
                long blockedUntil = nonNegative(result.getLong(3));
                if (elapsed(now, start) >= WINDOW_MILLIS && now >= blockedUntil) {
                    return new RateState(now, 0, 0, now);
                }
                return new RateState(start, failures, blockedUntil, now);
            }
        }
    }

    private static void recordFailure(Connection connection, String type, String key,
                                      RateState state, int limit) throws SQLException {
        int failures = state.failures();
        long blockedUntil = state.blockedUntil();
        if (state.now() >= blockedUntil) {
            failures = Math.min(1_000_000, failures + 1);
            if (failures >= limit) {
                blockedUntil = saturatingAdd(state.now(), WINDOW_MILLIS);
            }
        }
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO auth_failures(scope_type,scope_key,window_start,failures,blocked_until,last_seen)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(scope_type,scope_key) DO UPDATE SET
                  window_start=excluded.window_start, failures=excluded.failures,
                  blocked_until=excluded.blocked_until, last_seen=excluded.last_seen
                """)) {
            statement.setString(1, type);
            statement.setString(2, key);
            statement.setLong(3, state.windowStart());
            statement.setInt(4, failures);
            statement.setLong(5, blockedUntil);
            statement.setLong(6, state.now());
            statement.executeUpdate();
        }
    }

    private static void deleteRate(Connection connection, String type, String key) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "DELETE FROM auth_failures WHERE scope_type=? AND scope_key=?")) {
            statement.setString(1, type);
            statement.setString(2, key);
            statement.executeUpdate();
        }
    }

    private long safeNow() {
        return Math.max(0, clock.millis());
    }

    private static long nonNegative(long value) {
        return Math.max(0, value);
    }

    private static long elapsed(long later, long earlier) {
        return later >= earlier ? later - earlier : 0;
    }

    private static long saturatingAdd(long left, long right) {
        return left > Long.MAX_VALUE - right ? Long.MAX_VALUE : left + right;
    }

    private static String scopeKey(String canonicalLogin) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(canonicalLogin.getBytes(StandardCharsets.UTF_8));
            try {
                return HexFormat.of().formatHex(digest);
            } finally {
                java.util.Arrays.fill(digest, (byte) 0);
            }
        } catch (GeneralSecurityException impossible) {
            throw new IllegalStateException("required SHA-256 unavailable", impossible);
        }
    }

    enum RegistrationResult { ACCEPTED, REJECTED, ERROR }

    private record RateState(long windowStart, int failures, long blockedUntil, long now) {
        boolean allowed(int limit) {
            return now >= blockedUntil && failures < limit;
        }
    }
}
