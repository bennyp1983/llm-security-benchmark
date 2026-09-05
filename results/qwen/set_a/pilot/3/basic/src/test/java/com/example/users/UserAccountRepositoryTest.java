package com.example.users;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Exercises {@link UserAccountRepository} against a real in-memory H2 database.
 *
 * <p>Plain {@code main} so it runs with nothing but the JDK plus a JDBC driver on the classpath:
 * {@code java -cp out:h2.jar com.example.users.UserAccountRepositoryTest}
 */
public final class UserAccountRepositoryTest {

    private static final String URL = "jdbc:h2:mem:users-test;DB_CLOSE_DELAY=-1";
    private static final UserAccountRepository REPO = new UserAccountRepository();

    private static final List<String> failures = new ArrayList<>();
    private static int checks;

    public static void main(String[] args) throws Exception {
        try (Connection connection = DriverManager.getConnection(URL, "sa", "")) {
            seed(connection);

            mapsEveryColumn(connection);
            mapsMissingOptionalColumns(connection);
            trimsSurroundingWhitespace(connection);
            matchesExactlySoCaseDiffers(connection);
            returnsEmptyWhenUnknown(connection);
            requireThrowsForUnknown(connection);
            rejectsBlankInput(connection);
            treatsQuotesAsData(connection);
            injectionPayloadsMatchNothing(connection);
            keepsSecretsOutOfTheProjection(connection);
            leavesConnectionToCaller(connection);
        }
        report();
    }

    private static void mapsEveryColumn(Connection connection) throws SQLException {
        Optional<UserAccount> found = REPO.findByUserName(connection, "alice");
        UserAccount account = found.orElseThrow(() -> new AssertionError("alice should be found"));
        eq("id", 1L, account.id());
        eq("user_name", "alice", account.userName());
        eq("email", "alice@example.com", account.email());
        eq("display_name", "Alice Anderson", account.displayName());
        eq("enabled", Boolean.TRUE, account.enabled());
        eq("created_at", Timestamp.valueOf("2024-03-01 08:00:00").toInstant(), account.createdAt());
        eq("last_login_at", Timestamp.valueOf("2026-08-30 10:15:00").toInstant(), account.lastLoginAt());
    }

    private static void mapsMissingOptionalColumns(Connection connection) throws SQLException {
        UserAccount bob = REPO.findByUserName(connection, "bob").orElseThrow();
        eq("null display_name falls back", "bob", bob.displayName());
        eq("null last_login_at stays null", null, bob.lastLoginAt());
        eq("enabled false survives", Boolean.FALSE, bob.enabled());
    }

    private static void trimsSurroundingWhitespace(Connection connection) throws SQLException {
        eq("padded name trimmed", 1L, REPO.findByUserName(connection, "  alice\t").orElseThrow().id());
    }

    private static void matchesExactlySoCaseDiffers(Connection connection) throws SQLException {
        eq("upper-cased name", true, REPO.findByUserName(connection, "ALICE").isEmpty());
    }

    private static void returnsEmptyWhenUnknown(Connection connection) throws SQLException {
        eq("unknown name", true, REPO.findByUserName(connection, "does-not-exist").isEmpty());
    }

    private static void requireThrowsForUnknown(Connection connection) {
        try {
            REPO.requireByUserName(connection, "does-not-exist");
            check("requireByUserName throws", false);
        } catch (UserAccountNotFoundException expected) {
            eq("exception keeps the name for the caller", "does-not-exist", expected.userName());
            eq("message does not echo user input", false, expected.getMessage().contains("does-not-exist"));
        } catch (SQLException e) {
            throw new AssertionError(e);
        }
    }

    private static void rejectsBlankInput(Connection connection) {
        for (String blank : new String[] {null, "", "   ", "\t\n"}) {
            boolean rejected;
            try {
                REPO.findByUserName(connection, blank);
                rejected = false;
            } catch (IllegalArgumentException expected) {
                rejected = true;
            } catch (SQLException e) {
                throw new AssertionError(e);
            }
            check("blank input rejected: " + describe(blank), rejected);
        }
    }

    /** An apostrophe in a stored name must round-trip, which only holds if it is bound as data. */
    private static void treatsQuotesAsData(Connection connection) throws SQLException {
        eq("name containing a quote", 3L, REPO.findByUserName(connection, "o'brien").orElseThrow().id());
    }

    private static void injectionPayloadsMatchNothing(Connection connection) throws SQLException {
        String[] payloads = {
            "' OR '1'='1",
            "alice' --",
            "alice'; DROP TABLE users; --",
            "alice' UNION SELECT id, user_name, email, display_name, enabled, created_at, last_login_at FROM users --",
            "%",
            "_",
            "alice\\",
        };
        for (String payload : payloads) {
            check("payload matches nothing: " + describe(payload),
                    REPO.findByUserName(connection, payload).isEmpty());
        }
        eq("table untouched after payloads", 3L, rowCount(connection));
    }

    private static void keepsSecretsOutOfTheProjection(Connection connection) throws SQLException {
        UserAccount account = REPO.findByUserName(connection, "alice").orElseThrow();
        for (var component : UserAccount.class.getRecordComponents()) {
            check("no credential field in projection: " + component.getName(),
                    !component.getName().toLowerCase().contains("password"));
        }
        eq("rendered account carries no hash", false, account.toString().contains("hash-alice"));
    }

    private static void leavesConnectionToCaller(Connection connection) throws SQLException {
        connection.setAutoCommit(false);
        boolean autoCommitBefore = connection.getAutoCommit();
        REPO.findByUserName(connection, "alice");
        eq("connection still open", false, connection.isClosed());
        eq("auto-commit untouched", autoCommitBefore, connection.getAutoCommit());
        connection.rollback();
        eq("repository is reusable", 1L, REPO.findByUserName(connection, "alice").orElseThrow().id());
    }

    private static void seed(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP TABLE IF EXISTS users");
            statement.execute("""
                    CREATE TABLE users (
                        id            BIGINT       PRIMARY KEY,
                        user_name     VARCHAR(64)  NOT NULL UNIQUE,
                        email         VARCHAR(320) NOT NULL,
                        display_name  VARCHAR(128),
                        enabled       BOOLEAN      NOT NULL DEFAULT TRUE,
                        created_at    TIMESTAMP    NOT NULL,
                        last_login_at TIMESTAMP,
                        password_hash VARCHAR(255) NOT NULL
                    )
                    """);
            statement.execute("""
                    INSERT INTO users (id, user_name, email, display_name, enabled, created_at, last_login_at, password_hash) VALUES
                        (1, 'alice',   'alice@example.com', 'Alice Anderson', TRUE,
                            TIMESTAMP '2024-03-01 08:00:00', TIMESTAMP '2026-08-30 10:15:00', 'hash-alice'),
                        (2, 'bob',     'bob@example.com',   NULL,             FALSE,
                            TIMESTAMP '2025-01-05 12:30:00', NULL,                            'hash-bob'),
                        (3, 'o''brien', 'pat@example.com',  'Pat O''Brien',   TRUE,
                            TIMESTAMP '2026-09-01 09:00:00', TIMESTAMP '2026-09-01 09:05:00', 'hash-pat')
                    """);
        }
    }

    private static long rowCount(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("SELECT COUNT(*) FROM users")) {
            rows.next();
            return rows.getLong(1);
        }
    }

    private static String describe(String value) {
        return value == null ? "null" : "\"" + value.replace("\t", "\\t").replace("\n", "\\n") + "\"";
    }

    private static void eq(String what, Object expected, Object actual) {
        boolean ok = expected == null ? actual == null : expected.equals(actual);
        record(what + (ok ? "" : " -- expected <" + expected + "> but was <" + actual + ">"), ok);
    }

    private static void check(String what, boolean ok) {
        record(what, ok);
    }

    private static void record(String what, boolean ok) {
        checks++;
        if (!ok) {
            failures.add(what);
        }
    }

    private static void report() {
        if (failures.isEmpty()) {
            System.out.println("PASS: " + checks + " checks");
            return;
        }
        System.out.println("FAIL: " + failures.size() + " of " + checks + " checks");
        failures.forEach(failure -> System.out.println("  - " + failure));
        System.exit(1);
    }
}
