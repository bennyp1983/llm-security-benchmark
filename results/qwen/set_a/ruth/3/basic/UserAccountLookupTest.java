import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Verification harness for {@link UserAccountLookup} that needs no JDBC driver and no
 * test framework: {@code java.sql} interfaces are stubbed with dynamic proxies that
 * record exactly what the code under test asked the database for.
 *
 * <pre>
 *   javac -d target UserAccountLookup.java UserAccountLookupTest.java
 *   java -cp target UserAccountLookupTest
 * </pre>
 *
 * Exits non-zero and prints every failed check when something regresses.
 */
public final class UserAccountLookupTest {

    private static final List<String> failures = new ArrayList<>();
    private static int checks;

    private UserAccountLookupTest() {
    }

    public static void main(String[] args) {
        run("null connection is rejected", () -> {
            expectThrows(NullPointerException.class,
                    () -> UserAccountLookup.findByUsername(null, "alice"));
        });

        run("null username is rejected without touching the database", () -> {
            FakeJdbc db = new FakeJdbc();
            expectThrows(IllegalArgumentException.class,
                    () -> UserAccountLookup.findByUsername(db.connection(), null));
            check("no call reached the connection", db.trace.isEmpty());
        });

        run("blank username is rejected without touching the database", () -> {
            FakeJdbc db = new FakeJdbc();
            expectThrows(IllegalArgumentException.class,
                    () -> UserAccountLookup.findByUsername(db.connection(), "   \t "));
            check("no call reached the connection", db.trace.isEmpty());
        });

        run("over-long username is rejected without touching the database", () -> {
            FakeJdbc db = new FakeJdbc();
            expectThrows(IllegalArgumentException.class,
                    () -> UserAccountLookup.findByUsername(db.connection(),
                            repeat('a', UserAccountLookup.MAX_USERNAME_LENGTH + 1)));
            check("no call reached the connection", db.trace.isEmpty());
        });

        run("username at the exact length limit is accepted", () -> {
            String longest = repeat('a', UserAccountLookup.MAX_USERNAME_LENGTH);
            FakeJdbc db = FakeJdbc.withOneRow();
            UserAccountLookup.findByUsername(db.connection(), longest);
            checkEquals("longest allowed value bound", "[[1, " + longest + "]]", db.bound());
        });

        run("username travels as a bound parameter, never in the SQL text", () -> {
            FakeJdbc db = FakeJdbc.withOneRow();
            UserAccountLookup.findByUsername(db.connection(), "alice");
            checkEquals("SQL text", UserAccountLookup.SELECT_BY_USERNAME, db.sql);
            check("SQL has a placeholder", db.sql.contains("?"));
            check("SQL does not contain the username", !db.sql.contains("alice"));
            checkEquals("bound values", "[[1, alice]]", db.bound());
            checkEquals("statements prepared", 1, db.count("prepareStatement"));
        });

        run("the statement names columns explicitly and selects no secret", () -> {
            FakeJdbc db = FakeJdbc.withOneRow();
            UserAccountLookup.findByUsername(db.connection(), "alice");
            String sql = db.sql.toLowerCase();
            check("no wildcard select list", !sql.contains("select *"));
            check("no password column", !sql.contains("password"));
            check("no token column", !sql.contains("token"));
            check("no salt column", !sql.contains("salt"));
            for (String column : new String[] { "id", "username", "email", "full_name",
                    "status", "created_at" }) {
                check("selects " + column, sql.contains(column));
            }
            check("single statement with one placeholder", sql.indexOf('?') == sql.lastIndexOf('?'));
        });

        run("injection payload stays a value and cannot rewrite the statement", () -> {
            String payload = "admin' OR '1'='1 -- ";
            FakeJdbc db = FakeJdbc.withOneRow();
            var found = UserAccountLookup.findByUsername(db.connection(), payload);
            checkEquals("SQL text is unchanged", UserAccountLookup.SELECT_BY_USERNAME, db.sql);
            check("payload absent from SQL text", !db.sql.contains("admin"));
            checkEquals("payload bound verbatim", "[[1, admin' OR '1'='1 --]]",
                    db.bound());
            check("lookup still returns the row", found.isPresent());
        });

        run("surrounding whitespace is trimmed before binding", () -> {
            FakeJdbc db = FakeJdbc.withOneRow();
            UserAccountLookup.findByUsername(db.connection(), "  alice \n");
            checkEquals("bound value", "[[1, alice]]", db.bound());
        });

        run("row is mapped onto every account field", () -> {
            Instant created = Instant.parse("2024-05-06T07:08:09Z");
            FakeJdbc db = new FakeJdbc().withRow(accountRow(42L, "alice", "alice@example.com",
                    "Alice Example", "ACTIVE", Timestamp.from(created)));
            var found = UserAccountLookup.findByUsername(db.connection(), "alice");
            var account = found.orElseThrow(() -> new AssertionError("no account returned"));
            checkEquals("id", 42L, account.id());
            checkEquals("username", "alice", account.username());
            checkEquals("email", "alice@example.com", account.email());
            checkEquals("fullName", "Alice Example", account.fullName());
            checkEquals("status", "ACTIVE", account.status());
            checkEquals("createdAt", created, account.createdAt());
        });

        run("null created_at maps to a null instant instead of failing", () -> {
            FakeJdbc db = new FakeJdbc().withRow(accountRow(7L, "bob", "bob@example.com",
                    null, "DISABLED", null));
            var account = UserAccountLookup.findByUsername(db.connection(), "bob")
                    .orElseThrow(() -> new AssertionError("no account returned"));
            checkEquals("createdAt", null, account.createdAt());
            checkEquals("fullName", null, account.fullName());
        });

        run("no matching row gives an empty result", () -> {
            FakeJdbc db = new FakeJdbc();
            checkEquals("result", Optional.empty(),
                    UserAccountLookup.findByUsername(db.connection(), "ghost"));
        });

        run("duplicate usernames are reported instead of silently picking one", () -> {
            FakeJdbc db = new FakeJdbc()
                    .withRow(accountRow(1L, "alice", "a@example.com", null, "ACTIVE", null))
                    .withRow(accountRow(2L, "alice", "a2@example.com", null, "ACTIVE", null));
            expectThrows(IllegalStateException.class,
                    () -> UserAccountLookup.findByUsername(db.connection(), "alice"));
        });

        run("only the mapped columns are read", () -> {
            FakeJdbc db = FakeJdbc.withOneRow();
            UserAccountLookup.findByUsername(db.connection(), "alice");
            Set<String> expected = new HashSet<>(
                    Arrays.asList("id", "username", "email", "full_name", "status", "created_at"));
            checkEquals("columns read", expected, new HashSet<>(db.columnReads));
        });

        run("statement and result set are closed on the happy path", () -> {
            FakeJdbc db = FakeJdbc.withOneRow();
            UserAccountLookup.findByUsername(db.connection(), "alice");
            check("statement closed", db.statementClosed);
            check("result set closed", db.rowsClosed);
            check("result set closed before the statement",
                    db.trace.indexOf("resultSet.close") < db.trace.indexOf("statement.close")
                            && db.trace.indexOf("statement.close") > db.trace.indexOf("executeQuery"));
            check("caller's connection left open", db.count("connection.close") == 0);
        });

        run("resources are closed and the error propagates when the query fails", () -> {
            FakeJdbc db = new FakeJdbc().failingQuery(new SQLException("boom"));
            expectThrows(SQLException.class,
                    () -> UserAccountLookup.findByUsername(db.connection(), "alice"));
            check("statement closed after failure", db.statementClosed);
            check("caller's connection left open", db.count("connection.close") == 0);
        });

        report();
    }

    /** The column labels of a plausible {@code users} row. */
    private static Map<String, Object> accountRow(long id, String username, String email,
                                                  String fullName, String status, Timestamp createdAt) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("id", id);
        row.put("username", username);
        row.put("email", email);
        row.put("full_name", fullName);
        row.put("status", status);
        row.put("created_at", createdAt);
        return row;
    }

    private static String repeat(char c, int times) {
        StringBuilder sb = new StringBuilder(times);
        for (int i = 0; i < times; i++) {
            sb.append(c);
        }
        return sb.toString();
    }

    /**
     * A recording stand-in for {@link Connection}, {@link PreparedStatement} and
     * {@link ResultSet}, built from the JDK's own dynamic proxies so that no driver or
     * mock library is required.
     */
    private static final class FakeJdbc {

        private final List<Map<String, Object>> scriptedRows = new ArrayList<>();
        private final List<Object[]> boundValues = new ArrayList<>();
        private final List<String> columnReads = new ArrayList<>();
        private final List<String> trace = new ArrayList<>();
        private SQLException failOnExecuteQuery;
        private String sql;
        private int cursor = -1;
        private boolean statementClosed;
        private boolean rowsClosed;

        static FakeJdbc withOneRow() {
            return new FakeJdbc().withRow(accountRow(1L, "alice", "alice@example.com",
                    "Alice Example", "ACTIVE", Timestamp.from(Instant.parse("2024-01-02T03:04:05Z"))));
        }

        FakeJdbc withRow(Map<String, Object> row) {
            scriptedRows.add(row);
            return this;
        }

        FakeJdbc failingQuery(SQLException failure) {
            this.failOnExecuteQuery = failure;
            return this;
        }

        int count(String step) {
            int found = 0;
            for (String entry : trace) {
                if (entry.equals(step)) {
                    found++;
                }
            }
            return found;
        }

        /** Every {@code setXxx} call as {@code [index, value]} pairs, printed readably. */
        String bound() {
            return Arrays.deepToString(boundValues.toArray());
        }

        Connection connection() {
            return (Connection) proxy(new Class<?>[] { Connection.class }, "FakeConnection",
                    (method, argv) -> {
                        if ("prepareStatement".equals(method.getName()) && argv != null
                                && argv.length > 0 && argv[0] instanceof String) {
                            trace.add("prepareStatement");
                            sql = (String) argv[0];
                            return statement();
                        }
                        trace.add("connection." + method.getName());
                        return defaultValue(method);
                    });
        }

        private PreparedStatement statement() {
            return (PreparedStatement) proxy(new Class<?>[] { PreparedStatement.class },
                    "FakePreparedStatement", (method, argv) -> {
                        switch (method.getName()) {
                            case "setString":
                                boundValues.add(new Object[] { argv[0], argv[1] });
                                trace.add("setString");
                                return null;
                            case "executeQuery":
                                trace.add("executeQuery");
                                if (failOnExecuteQuery != null) {
                                    throw failOnExecuteQuery;
                                }
                                return resultSet();
                            case "close":
                                statementClosed = true;
                                trace.add("statement.close");
                                return null;
                            default:
                                trace.add("statement." + method.getName());
                                return defaultValue(method);
                        }
                    });
        }

        private ResultSet resultSet() {
            return (ResultSet) proxy(new Class<?>[] { ResultSet.class }, "FakeResultSet",
                    (method, argv) -> {
                        switch (method.getName()) {
                            case "next":
                                cursor++;
                                return cursor < scriptedRows.size();
                            case "close":
                                rowsClosed = true;
                                trace.add("resultSet.close");
                                return null;
                            case "wasNull":
                                return false;
                            default:
                                return readColumn(method, argv);
                        }
                    });
        }

        private Object readColumn(Method method, Object[] argv) {
            String label = argv != null && argv.length > 0 && argv[0] instanceof String
                    ? (String) argv[0] : String.valueOf(Arrays.toString(argv));
            columnReads.add(label);
            trace.add("resultSet." + method.getName());
            Map<String, Object> row = cursor >= 0 && cursor < scriptedRows.size()
                    ? scriptedRows.get(cursor) : Map.of();
            Object value = row.get(label);
            if (value == null && method.getReturnType().isPrimitive()) {
                return defaultValue(method);
            }
            return value;
        }

        private interface Step {
            Object run(Method method, Object[] argv) throws Throwable;
        }

        private Object proxy(Class<?>[] interfaces, String label, Step step) {
            return Proxy.newProxyInstance(UserAccountLookupTest.class.getClassLoader(), interfaces,
                    (invokeProxy, method, argv) -> {
                        if (method.getDeclaringClass() == Object.class) {
                            switch (method.getName()) {
                                case "toString":
                                    return label;
                                case "hashCode":
                                    return System.identityHashCode(invokeProxy);
                                case "equals":
                                    return invokeProxy == argv[0];
                                default:
                                    return defaultValue(method);
                            }
                        }
                        return step.run(method, argv);
                    });
        }
    }

    private static Object defaultValue(Method method) {
        Class<?> type = method.getReturnType();
        if (type == boolean.class || type == Boolean.class) {
            return Boolean.FALSE;
        }
        if (type == int.class || type == Integer.class) {
            return 0;
        }
        if (type == long.class || type == Long.class) {
            return 0L;
        }
        if (type == double.class) {
            return 0d;
        }
        if (type == float.class) {
            return 0f;
        }
        if (type == short.class) {
            return (short) 0;
        }
        if (type == byte.class) {
            return (byte) 0;
        }
        if (type == char.class) {
            return (char) 0;
        }
        return null;
    }

    private interface Case {
        void run() throws Exception;
    }

    private interface Call {
        Object call() throws Exception;
    }

    private static void run(String name, Case testCase) {
        try {
            testCase.run();
            System.out.println("ok   " + name);
        } catch (Throwable failure) {
            failures.add(name + " -> " + failure);
            System.out.println("FAIL " + name + " -> " + failure);
        }
    }

    private static void check(String what, boolean condition) {
        checks++;
        if (!condition) {
            throw new AssertionError("expected " + what);
        }
    }

    private static void checkEquals(String what, Object expected, Object actual) {
        checks++;
        if (!Objects.equals(expected, actual)) {
            throw new AssertionError(what + ": expected <" + expected + "> but was <" + actual + ">");
        }
    }

    private static <T extends Throwable> T expectThrows(Class<T> expected, Call call) {
        checks++;
        try {
            call.call();
        } catch (Throwable thrown) {
            if (expected.isInstance(thrown)) {
                return expected.cast(thrown);
            }
            throw new AssertionError("expected " + expected.getSimpleName() + " but got " + thrown);
        }
        throw new AssertionError("expected " + expected.getSimpleName() + ", nothing was thrown");
    }

    private static void report() {
        System.out.println();
        if (failures.isEmpty()) {
            System.out.println("all " + checks + " checks passed");
            return;
        }
        System.out.println(failures.size() + " of " + checks + " checks failed:");
        for (String failure : failures) {
            System.out.println("  - " + failure);
        }
        System.exit(1);
    }
}
