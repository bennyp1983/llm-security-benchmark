package com.example.security;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Checks for {@link UserRepository}: an exact-match mapping, every rejection rule, the
 * credential redaction, a set of SQL injection payloads that must all resolve to "no such
 * account" against a real database, and a {@link Proxy} double that pins the exact SQL text the
 * repository sends and the fact that the username travels only as a bound parameter.
 *
 * <p>Plain {@code main} with no test framework, so it compiles with nothing but the JDK plus the
 * JDBC driver. Exits non-zero on the first failure.
 */
public final class UserRepositoryTest {

    private static final String MAIN_URL = "jdbc:h2:mem:repo_main;DB_CLOSE_DELAY=-1";
    private static final String DUP_URL = "jdbc:h2:mem:repo_dup;DB_CLOSE_DELAY=-1";
    private static final String EMPTY_URL = "jdbc:h2:mem:repo_empty;DB_CLOSE_DELAY=-1";

    private static int checks;

    public static void main(String[] args) throws Exception {
        Class.forName("org.h2.Driver");

        try (Connection db = DriverManager.getConnection(MAIN_URL, "sa", "")) {
            createUsers(db);
            seed(db);
            UserRepository repo = new UserRepository(db);

            exactMatchMapsEveryColumn(db, repo);
            unknownNameIsEmpty(repo);
            injectionPayloadsMatchNothing(db, repo);
            wildcardCharactersAreNotPatterns(repo);
            storedApostropheRoundTrips(repo);
            surroundingWhitespaceIsTrimmed(repo);
            comparisonIsCaseSensitive(repo);
            invalidInputIsRejected(repo);
            disabledAccountIsReturnedUnfiltered(repo);
            toStringRedactsTheCredential(repo);
        }

        ambiguousMatchIsRefused();
        lookupFailureIsNotSilentlyEmpty();
        statementUsesABoundParameter();

        System.out.println("OK: " + checks + " checks passed");
    }

    // ---------------------------------------------------------------- mapping

    private static void exactMatchMapsEveryColumn(Connection db, UserRepository repo)
            throws SQLException {
        UserAccount alice = require(repo.findByUsername("alice"));
        check(alice.id() == 1L, "id maps");
        check("alice".equals(alice.username()), "username maps");
        check("alice@example.com".equals(alice.email()), "email maps");
        check("Alice Example".equals(alice.fullName()), "full_name maps");
        check("ACTIVE".equals(alice.status()), "status maps");
        check("$2a$10$notarealhashvalue".equals(alice.passwordHash()), "password_hash maps");
        Instant expected = LocalDateTime.of(2024, 1, 2, 3, 4, 5)
                .atZone(ZoneId.systemDefault()).toInstant();
        check(expected.equals(alice.createdAt()), "created_at maps to the right instant");
        check(alice.isActive(), "ACTIVE reports active");

        // NULL created_at must not blow up the mapping.
        UserAccount admin = require(repo.findByUsername("admin"));
        check(admin.createdAt() == null, "NULL created_at maps to null");
        check(rowCount(db) == 4L, "fixture holds four rows");
    }

    private static void unknownNameIsEmpty(UserRepository repo) {
        check(repo.findByUsername("nosuchuser").isEmpty(), "unknown username yields empty");
    }

    /**
     * Each payload is the classic tautology / comment / stacked-query shape. All must behave
     * exactly like an unknown username: no row, and the table untouched.
     */
    private static void injectionPayloadsMatchNothing(Connection db, UserRepository repo)
            throws SQLException {
        String[] payloads = {
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "admin' --",
                "admin' #",
                "' OR 1=1 -- ",
                "' UNION SELECT id, username, email, full_name, status, password_hash, created_at FROM users --",
                "'; DROP TABLE users; --",
                "' OR username IN ('admin','alice') --",
                "1' OR 1=1",
                "%' OR '%'='",
                "_",
                "\\'",
        };
        for (String payload : payloads) {
            Optional<UserAccount> hit = repo.findByUsername(payload);
            check(hit.isEmpty(), "injection payload matches nothing: " + show(payload));
        }
        check(rowCount(db) == 4L, "the table still has four rows after every payload");
        check(tableStillExists(db), "DROP TABLE in a payload did not execute");
    }

    private static void wildcardCharactersAreNotPatterns(UserRepository repo) {
        // Would match everything if the predicate were LIKE instead of equality.
        check(repo.findByUsername("%").isEmpty(), "% is not a wildcard");
        check(repo.findByUsername("li%").isEmpty(), "trailing % is not a wildcard");
        check(repo.findByUsername("a_ice").isEmpty(), "_ is not a wildcard");
    }

    private static void storedApostropheRoundTrips(UserRepository repo) {
        // o'brien is a real username containing a quote. Escaping-by-doubling would turn this
        // into a broken query; binding finds the row.
        UserAccount obrien = require(repo.findByUsername("o'brien"));
        check("o'brien".equals(obrien.username()), "username containing an apostrophe is found");
        check("Sean O'Brien".equals(obrien.fullName()), "apostrophe in a fetched value survives");
    }

    private static void surroundingWhitespaceIsTrimmed(UserRepository repo) {
        check(repo.findByUsername("  alice  ").isPresent(), "surrounding spaces are trimmed");
        check(repo.findByUsername("\talice\n").isPresent(), "surrounding tabs and newlines trim");
    }

    private static void comparisonIsCaseSensitive(UserRepository repo) {
        // Documented behaviour: the comparison is plain equality under the database collation
        // (H2 and PostgreSQL defaults are case sensitive), so no case folding is applied here.
        check(repo.findByUsername("ALICE").isEmpty(), "matching is case sensitive");
        check(repo.findByUsername("Disabled-bot").isEmpty(), "case differs for stored name");
    }

    private static void invalidInputIsRejected(UserRepository repo) {
        checkRejectsNull(repo);
        checkRejects(repo, "", "empty string");
        checkRejects(repo, "   ", "spaces only");
        checkRejects(repo, "\t\n ", "whitespace only");
        checkRejects(repo, "alice\nINFO forged log line", "embedded newline");
        checkRejects(repo, "ali\0ce", "embedded NUL");
        checkRejects(repo, "ali" + (char) 0x1F + "ce", "embedded unit separator");
        checkRejects(repo, "ali" + (char) 0x7F + "ce", "embedded DEL");
        check(repo.findByUsername("alice" + (char) 0x1F).isPresent(),
                "trailing control characters are stripped by the trim");
        checkRejects(repo, "a".repeat(255), "255 characters (over the column width)");
        checkRejects(repo, "a".repeat(5_000), "5000 characters");
        check(repo.findByUsername("a".repeat(254)).isEmpty(),
                "254 characters is accepted (and simply does not match)");
    }

    private static void checkRejectsNull(UserRepository repo) {
        try {
            repo.findByUsername(null);
            fail("null username must be rejected");
        } catch (IllegalArgumentException expected) {
            checks++;
        }
    }

    private static void checkRejects(UserRepository repo, String input, String description) {
        try {
            repo.findByUsername(input);
            fail("expected rejection for " + description);
        } catch (IllegalArgumentException expected) {
            checks++;
        }
    }

    private static void disabledAccountIsReturnedUnfiltered(UserRepository repo) {
        // Status filtering is a caller decision; the repository must not invent policy.
        UserAccount bot = require(repo.findByUsername("DISABLED-bot"));
        check("DISABLED".equals(bot.status()), "disabled account is returned as stored");
        check(!bot.isActive(), "DISABLED reports not active");
    }

    private static void toStringRedactsTheCredential(UserRepository repo) {
        UserAccount alice = require(repo.findByUsername("alice"));
        String text = alice.toString();
        check(text.contains("[redacted]"), "toString redacts the credential");
        check(!text.contains("$2a$10$notarealhashvalue"), "toString does not carry the hash");
    }

    // ------------------------------------------------------- ambiguous match

    /** A username stored twice must not silently resolve to whichever row the engine likes. */
    private static void ambiguousMatchIsRefused() throws SQLException {
        try (Connection db = DriverManager.getConnection(DUP_URL, "sa", "")) {
            createUsers(db);
            seed(db);
            try (Statement st = db.createStatement()) {
                st.execute("INSERT INTO users (id, username, email, full_name, status,"
                        + " password_hash, created_at) VALUES"
                        + " (99, 'alice', 'other@example.com', 'Alice Other', 'ACTIVE',"
                        + " '$2a$10$notarealhashvalue', NULL)");
            }
            try {
                new UserRepository(db).findByUsername("alice");
                fail("duplicate rows must be refused, not guessed between");
            } catch (UserRepositoryException expected) {
                check(expected.getMessage().toLowerCase().contains("ambiguous"),
                        "the ambiguity message explains itself");
                check(expected.getCause() == null, "ambiguity is not reported as a driver error");
            }
        }
    }

    private static void lookupFailureIsNotSilentlyEmpty() throws SQLException {
        try (Connection db = DriverManager.getConnection(EMPTY_URL, "sa", "")) {
            try {
                new UserRepository(db).findByUsername("alice");
                fail("a failed query must not look like an unknown username");
            } catch (UserRepositoryException expected) {
                check(expected.getCause() instanceof SQLException,
                        "the driver failure is kept as the cause for the server log");
                check(!String.valueOf(expected.getMessage()).contains("alice"),
                        "the message does not echo the username");
            }
        }
    }

    // -------------------------------------------------- bound-parameter proof

    /**
     * A {@code users}-agnostic double: it records what the repository asked the driver for and
     * answers with an empty result set. It proves the two structural facts the H2 tests cannot
     * see on their own - the SQL text is the fixed constant and the username is only ever passed
     * to {@code setString}, so a payload can never reach the statement string.
     */
    private static void statementUsesABoundParameter() throws SQLException {
        List<String> sqls = new ArrayList<>();
        List<String> bound = new ArrayList<>();
        Connection spy = recordingConnection(sqls, bound);

        String payload = "' OR '1'='1";
        new UserRepository(spy).findByUsername(payload).ifPresent(a -> {
            throw new IllegalStateException("double always returns no rows");
        });

        check(sqls.size() == 1, "exactly one statement is prepared per lookup");
        check(UserRepository.SELECT_BY_USERNAME.equals(sqls.get(0)),
                "the prepared SQL is the fixed constant, byte for byte");
        check(!sqls.get(0).contains(payload), "the payload is not in the SQL text");
        check(bound.equals(List.of(payload)), "the username was delivered only as parameter 1");
    }

    private static Connection recordingConnection(List<String> sqls, List<String> bound) {
        PreparedStatement statement = (PreparedStatement) Proxy.newProxyInstance(
                UserRepositoryTest.class.getClassLoader(),
                new Class<?>[] {PreparedStatement.class},
                new InvocationHandler() {
                    @Override
                    public Object invoke(Object proxy, Method method, Object[] args) {
                        switch (method.getName()) {
                            case "setString" -> bound.add((String) args[1]);
                            case "executeQuery" -> {
                                return emptyResultSet();
                            }
                            case "toString" -> {
                                return "PreparedStatementProxy";
                            }
                            case "hashCode" -> {
                                return System.identityHashCode(proxy);
                            }
                            case "equals" -> {
                                return proxy == args[0];
                            }
                            default -> {
                                // setMaxRows, close and friends are accepted and ignored.
                            }
                        }
                        return defaultValue(method.getReturnType());
                    }
                });

        return (Connection) Proxy.newProxyInstance(
                UserRepositoryTest.class.getClassLoader(),
                new Class<?>[] {Connection.class},
                (proxy, method, args) -> {
                    if ("prepareStatement".equals(method.getName())) {
                        sqls.add((String) args[0]);
                        return statement;
                    }
                    if ("toString".equals(method.getName())) {
                        return "ConnectionProxy";
                    }
                    if ("hashCode".equals(method.getName())) {
                        return System.identityHashCode(proxy);
                    }
                    if ("equals".equals(method.getName())) {
                        return proxy == args[0];
                    }
                    return defaultValue(method.getReturnType());
                });
    }

    private static ResultSet emptyResultSet() {
        return (ResultSet) Proxy.newProxyInstance(
                UserRepositoryTest.class.getClassLoader(),
                new Class<?>[] {ResultSet.class},
                (proxy, method, args) -> {
                    if ("hashCode".equals(method.getName())) {
                        return System.identityHashCode(proxy);
                    }
                    if ("equals".equals(method.getName())) {
                        return proxy == args[0];
                    }
                    // next() answers false, so the lookup resolves to "no account".
                    return defaultValue(method.getReturnType());
                });
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) {
            return null;
        }
        if (type == boolean.class) {
            return false;
        }
        if (type == void.class) {
            return null;
        }
        return 0;
    }

    // ------------------------------------------------------------- fixtures

    private static void createUsers(Connection db) throws SQLException {
        try (Statement st = db.createStatement()) {
            st.execute("CREATE TABLE users ("
                    + " id BIGINT PRIMARY KEY,"
                    + " username VARCHAR(254) NOT NULL,"
                    + " email VARCHAR(320),"
                    + " full_name VARCHAR(200),"
                    + " status VARCHAR(32) NOT NULL,"
                    + " password_hash VARCHAR(100) NOT NULL,"
                    + " created_at TIMESTAMP)");
        }
    }

    private static void seed(Connection db) throws SQLException {
        try (Statement st = db.createStatement()) {
            st.execute("INSERT INTO users (id, username, email, full_name, status,"
                    + " password_hash, created_at) VALUES"
                    + " (1, 'alice', 'alice@example.com', 'Alice Example', 'ACTIVE',"
                    + " '$2a$10$notarealhashvalue', '2024-01-02 03:04:05'),"
                    + " (2, 'admin', 'admin@example.com', 'Root Admin', 'ACTIVE',"
                    + " '$2a$10$notarealhashvalue', NULL),"
                    + " (3, 'DISABLED-bot', 'bot@example.com', 'Retired Bot', 'DISABLED',"
                    + " '$2a$10$notarealhashvalue', '2025-06-07 08:09:10'),"
                    + " (4, 'o''brien', 'obrien@example.com', 'Sean O''Brien', 'ACTIVE',"
                    + " '$2a$10$notarealhashvalue', '2026-02-03 04:05:06')");
        }
    }

    private static long rowCount(Connection db) throws SQLException {
        try (Statement st = db.createStatement();
             ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM users")) {
            rs.next();
            return rs.getLong(1);
        }
    }

    private static boolean tableStillExists(Connection db) throws SQLException {
        try (Statement st = db.createStatement();
             ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM users WHERE 1 = 0")) {
            rs.next();
            return rs.getLong(1) == 0L;
        }
    }

    // ------------------------------------------------------------ assertion

    private static UserAccount require(Optional<UserAccount> account) {
        return account.orElseThrow(() -> new AssertionError("expected an account, found none"));
    }

    private static void check(boolean condition, String description) {
        if (!condition) {
            fail(description);
        }
        checks++;
    }

    private static String show(String payload) {
        return "'" + payload.replace("\n", "\\n") + "'";
    }

    private static void fail(String description) {
        System.err.println("FAIL: " + description);
        System.exit(1);
    }
}
