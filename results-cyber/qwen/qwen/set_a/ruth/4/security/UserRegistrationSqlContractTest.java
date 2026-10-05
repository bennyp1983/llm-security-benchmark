import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Contract checks for the SQL that {@link UserRegistration} actually sends.
 *
 * <p>No database is involved: {@link Connection}, {@link PreparedStatement},
 * {@link Statement} and {@link ResultSet} are {@link Proxy} doubles that record
 * every statement string and every bound parameter. That is what makes the
 * decisive assertions assertable at all: the test can state that a credential
 * never appears anywhere in the statement text, and can script results the real
 * engine would not hand back (a duplicate-key failure, a corrupt row).</p>
 *
 * <p>The H2 suite ({@code UserRegistrationH2Test}) is the complement: it proves
 * the predicates match exactly the intended row, which a double replaying
 * scripted rows cannot see.</p>
 *
 * Run: {@code java -cp out UserRegistrationSqlContractTest}
 */
public final class UserRegistrationSqlContractTest {

    private static final List<String> failures = new ArrayList<>();
    private static int checks;

    private UserRegistrationSqlContractTest() {
    }

    public static void main(String[] args) throws Exception {
        UserRegistration.PasswordHasher hasher =
                new UserRegistration.PasswordHasher(UserRegistration.PasswordHasher.MIN_ITERATIONS);

        // "admin--" passes the allowlist and is a live SQL comment payload: if
        // any part of it ever reached the statement text, the checks below that
        // look for "--" would fire.
        testInsertBindsEverything("admin--", "hunter2' --DROP TABLE app_users--");
        testInsertBindsEverything("alice", "plain secret");
        testInsertBindsEverything("alice_1", "percent % and underscore _ stay literal");
        testSelectIsKeyedOnOnePlaceholder();
        testAuthenticationSelectBindsTheUsernameVerbatim();
        testUnknownUserQueriesOnceAndStillRunsTheKdf();
        testUniqueViolationBecomesAConflictWithoutASecondAttempt(hasher);
        testUnrelatedConstraintViolationIsRethrown(hasher);
        testCommitFollowsCommitOwnWork(hasher);
        testNoPlainStatementOnTheDataPath(hasher);
        testEveryPreparedStatementIsClosed(hasher);
        testValidationHappensBeforeAnySql(hasher);

        report();
    }

    // ---------------------------------------------------------------- checks

    private static void testInsertBindsEverything(String username, String password) throws Exception {
        FakeConnection fake = new FakeConnection();
        UserRegistration.UserRegistry registry = new UserRegistration.UserRegistry(fake.connection(),
                new UserRegistration.PasswordHasher(UserRegistration.PasswordHasher.MIN_ITERATIONS));

        char[] secret = password.toCharArray();
        UserRegistration.RegistrationOutcome outcome = registry.register(username, secret);
        UserRegistration.PasswordHasher.clear(secret);
        check("register(" + username + ") reports CREATED",
                outcome == UserRegistration.RegistrationOutcome.CREATED);

        FakePreparedStatement insert = fake.firstPrepareMatching("INSERT");
        check("exactly one statement was prepared for the insert",
                fake.preparedStatements.size() == 1);

        String sql = insert.sql();
        check("INSERT targets the fixed table for username " + describe(username),
                sql.startsWith("INSERT INTO app_users"));
        check("INSERT carries three placeholders and no interpolation",
                countChar(sql, '?') == 3 && sql.contains("(username, password_hash, created_at) VALUES (?, ?, ?)"));
        check("statement text does not contain the username", !sql.contains(username));
        check("statement text does not contain the password", !sql.contains(password));
        check("statement text contains no quote character at all", sql.indexOf('\'') < 0);
        check("statement text contains no SQL comment marker", !sql.contains("--") && !sql.contains("/*"));
        check("INSERT does not use LIKE/UPPER/LOWER matching",
                !containsAnyIgnoreCase(sql, "LIKE", "UPPER", "LOWER", "||"));
        check("three parameters were bound, one per placeholder", insert.parameters().size() == 3);
        check("parameter 1 is the username verbatim", username.equals(insert.parameters().get(1)));

        String boundDigest = insert.parameters().get(2);
        check("parameter 2 is a pbkdf2-sha256 digest", boundDigest.startsWith("pbkdf2-sha256$"));
        check("parameter 2 has 4 fields", boundDigest.split("\\$", -1).length == 4);
        check("parameter 2 is not the password", !boundDigest.contains(password));
        check("parameter 2 is at most 200 characters", boundDigest.length() <= 200);
        check("parameter 3 is a timestamp value", insert.rawParameters().get(3) instanceof java.sql.Timestamp);
    }

    private static void testSelectIsKeyedOnOnePlaceholder() throws Exception {
        FakeConnection fake = new FakeConnection();
        fake.queueSelectResult(new String[]{"pbkdf2-sha256$1000$" + SALT + "$" + DIGEST});
        UserRegistration.UserRegistry registry = new UserRegistration.UserRegistry(fake.connection(),
                new UserRegistration.PasswordHasher(UserRegistration.PasswordHasher.MIN_ITERATIONS));

        char[] secret = "anything".toCharArray();
        registry.authenticate("lookup-case", secret);
        UserRegistration.PasswordHasher.clear(secret);

        FakePreparedStatement select = fake.firstPrepareMatching("SELECT");
        check("the lookup prepares exactly one statement",
                fake.preparedStatements.size() == 1);
        String sql = select.sql();
        check("the lookup selects only the digest column",
                sql.startsWith("SELECT password_hash FROM app_users"));
        check("the lookup is keyed on a single placeholder", countChar(sql, '?') == 1);
        check("the lookup compares with =, not LIKE",
                sql.contains("WHERE username = ?") && !sql.toUpperCase().contains("LIKE"));
        check("the lookup text does not contain the username", !sql.contains("lookup-case"));
    }

    private static void testAuthenticationSelectBindsTheUsernameVerbatim() throws Exception {
        FakeConnection fake = new FakeConnection();
        fake.queueSelectResult(new String[]{"pbkdf2-sha256$1000$" + SALT + "$" + DIGEST});
        UserRegistration.UserRegistry registry = new UserRegistration.UserRegistry(fake.connection(),
                new UserRegistration.PasswordHasher(UserRegistration.PasswordHasher.MIN_ITERATIONS));

        String username = "aLiCe_1";
        char[] secret = "does not matter".toCharArray();
        registry.authenticate(username, secret);
        UserRegistration.PasswordHasher.clear(secret);

        FakePreparedStatement select = fake.firstPrepareMatching("SELECT");
        check("the bound lookup key is the username, unchanged",
                username.equals(select.parameters().get(1)));
        check("the bound lookup key was not case-folded",
                !select.parameters().get(1).equals(username.toLowerCase()));
        check("the bound lookup key kept its underscore",
                select.parameters().get(1).contains("_"));
    }

    private static void testUnknownUserQueriesOnceAndStillRunsTheKdf()
            throws Exception {
        // A cost high enough to measure: against a double everything else is
        // free, so elapsed time is a direct read-out of "did the KDF run".
        UserRegistration.PasswordHasher hasher = new UserRegistration.PasswordHasher(GUARDED_ITERATIONS);
        FakeConnection fake = new FakeConnection();
        fake.queueSelectResult(null); // no rows
        UserRegistration.UserRegistry registry = new UserRegistration.UserRegistry(fake.connection(), hasher);

        long start = System.nanoTime();
        char[] secret = "some secret".toCharArray();
        UserRegistration.AuthenticationOutcome outcome = registry.authenticate("ghost", secret);
        long elapsedMillis = (System.nanoTime() - start) / 1_000_000;
        UserRegistration.PasswordHasher.clear(secret);

        check("an unknown username reports NO_SUCH_USER",
                outcome == UserRegistration.AuthenticationOutcome.NO_SUCH_USER);
        check("an unknown username costs exactly one query", fake.preparedStatements.size() == 1);
        // Without this, a guard that silently stopped deriving would still pass
        // every boolean assertion above.
        check("an unknown username still pays for a key derivation (" + elapsedMillis + " ms)",
                elapsedMillis >= MINIMUM_KDF_MILLIS);
    }

    private static void testUniqueViolationBecomesAConflictWithoutASecondAttempt(UserRegistration.PasswordHasher hasher)
            throws Exception {
        FakeConnection fake = new FakeConnection();
        fake.queueInsertFailure(new SQLException("Unique key violation", "23505", 23505));
        fake.queueSelectResult(new String[]{"1"}); // the confirmation probe finds the row
        UserRegistration.UserRegistry registry = new UserRegistration.UserRegistry(fake.connection(), hasher);

        char[] secret = "a secret".toCharArray();
        UserRegistration.RegistrationOutcome outcome = registry.register("taken", secret);
        UserRegistration.PasswordHasher.clear(secret);

        check("a duplicate key is reported as a conflict, not thrown",
                outcome == UserRegistration.RegistrationOutcome.USERNAME_ALREADY_EXISTS);
        check("the insert was attempted once", fake.preparedStatements.size() == 2);
        check("the second statement is the confirmation probe",
                fake.preparedStatements.get(1).sql().startsWith("SELECT 1 FROM app_users"));
        check("the probe is also parameterised",
                countChar(fake.preparedStatements.get(1).sql(), '?') == 1);
        check("no write was retried after the conflict",
                fake.countMatching("INSERT") == 1);
    }

    private static void testUnrelatedConstraintViolationIsRethrown(UserRegistration.PasswordHasher hasher)
            throws Exception {
        FakeConnection fake = new FakeConnection();
        fake.queueInsertFailure(new SQLException("Value too long for column", "22001", 22001));
        UserRegistration.UserRegistry registry = new UserRegistration.UserRegistry(fake.connection(), hasher);

        char[] secret = "a secret".toCharArray();
        boolean rethrown = false;
        try {
            registry.register("toolong", secret);
        } catch (SQLException expected) {
            rethrown = "22001".equals(expected.getSQLState());
        } finally {
            UserRegistration.PasswordHasher.clear(secret);
        }
        check("a non-uniqueness constraint violation is not mistaken for a conflict", rethrown);
        check("a failed insert is not silently retried", fake.countMatching("INSERT") == 1);

        // The hard case: a *different* constraint fails for a username that does
        // already exist. Reporting a friendly "username taken" here would bury a
        // real data fault, so the SQL state, not the mere presence of a row,
        // must decide the outcome.
        FakeConnection withExistingRow = new FakeConnection();
        withExistingRow.queueInsertFailure(new SQLException("Value too long for column", "22001", 22001));
        withExistingRow.queueSelectResult(new String[]{"1"});
        UserRegistration.UserRegistry secondRegistry =
                new UserRegistration.UserRegistry(withExistingRow.connection(), hasher);

        char[] again = "a secret".toCharArray();
        boolean rethrownDespiteExistingRow;
        try {
            UserRegistration.RegistrationOutcome outcome = secondRegistry.register("toolong", again);
            System.out.println("      outcome under a 22001 with an existing row: " + outcome);
            rethrownDespiteExistingRow = false;
        } catch (SQLException expected) {
            rethrownDespiteExistingRow = "22001".equals(expected.getSQLState());
        } finally {
            UserRegistration.PasswordHasher.clear(again);
        }
        check("a 22001 is still rethrown when the username happens to exist", rethrownDespiteExistingRow);
    }

    private static void testCommitFollowsCommitOwnWork(UserRegistration.PasswordHasher hasher) throws Exception {
        for (boolean autoCommit : new boolean[]{true, false}) {
            for (boolean commitOwnWork : new boolean[]{true, false}) {
                FakeConnection fake = new FakeConnection();
                fake.setAutoCommit(autoCommit);
                UserRegistration.UserRegistry registry =
                        new UserRegistration.UserRegistry(fake.connection(), hasher, commitOwnWork);
                char[] secret = "a secret".toCharArray();
                registry.register("commit-case", secret);
                UserRegistration.PasswordHasher.clear(secret);

                boolean expected = commitOwnWork && !autoCommit;
                check("commit called=" + fake.wasCommitCalled() + " matches commitOwnWork=" + commitOwnWork
                                + " autoCommit=" + autoCommit,
                        fake.wasCommitCalled() == expected);
                check("no rollback on the success path", !fake.wasRollbackCalled());
            }
        }
    }

    private static void testNoPlainStatementOnTheDataPath(UserRegistration.PasswordHasher hasher) throws Exception {
        FakeConnection fake = new FakeConnection();
        fake.queueSelectResult(new String[]{"pbkdf2-sha256$1000$" + SALT + "$" + DIGEST});
        UserRegistration.UserRegistry registry = new UserRegistration.UserRegistry(fake.connection(), hasher);

        char[] secret = "a secret".toCharArray();
        registry.register("no-plain-statement", secret);
        registry.authenticate("no-plain-statement", secret);
        registry.exists("no-plain-statement");
        UserRegistration.PasswordHasher.clear(secret);

        check("the data path never uses a plain Statement", fake.plainStatementCount() == 0);
        check("every data-path statement went through prepareStatement",
                fake.preparedStatements.size() >= 3);
    }

    private static void testEveryPreparedStatementIsClosed(UserRegistration.PasswordHasher hasher) throws Exception {
        FakeConnection fake = new FakeConnection();
        fake.queueSelectResult(new String[]{"pbkdf2-sha256$1000$" + SALT + "$" + DIGEST});
        UserRegistration.UserRegistry registry = new UserRegistration.UserRegistry(fake.connection(), hasher);

        char[] secret = "a secret".toCharArray();
        registry.register("leak-case", secret);
        registry.authenticate("leak-case", secret);
        registry.exists("leak-case");
        UserRegistration.PasswordHasher.clear(secret);

        List<String> leaked = new ArrayList<>();
        for (FakePreparedStatement statement : fake.preparedStatements) {
            if (!statement.wasClosed()) {
                leaked.add(statement.sql());
            }
        }
        check("every prepared statement and result set was closed: " + leaked, leaked.isEmpty());
        check("the caller's connection was not closed", !fake.wasCloseCalled());
    }

    private static void testValidationHappensBeforeAnySql(UserRegistration.PasswordHasher hasher) throws Exception {
        FakeConnection fake = new FakeConnection();
        UserRegistration.UserRegistry registry = new UserRegistration.UserRegistry(fake.connection(), hasher);

        char[] secret = "a secret".toCharArray();
        String[] payloads = {"no sql for this one", "admin' OR '1'='1", "ab"};
        for (String username : payloads) {
            try {
                registry.register(username, secret);
                check("[" + describe(username) + "] was accepted as a username", false);
            } catch (IllegalArgumentException expected) {
                check("[" + describe(username) + "] is refused without touching the database",
                        fake.preparedStatements.isEmpty() && fake.plainStatementCount() == 0);
            }

            try {
                registry.authenticate(username, secret);
                check("[" + describe(username) + "] reached the database on lookup", false);
            } catch (IllegalArgumentException expected) {
                check("[" + describe(username) + "] is refused on lookup without a query",
                        fake.preparedStatements.isEmpty());
            }
        }

        try {
            registry.register("valid-name", new char[0]);
            check("an empty password was accepted", false);
        } catch (IllegalArgumentException expected) {
            check("an empty password is refused before any statement",
                    fake.preparedStatements.isEmpty());
        }
        UserRegistration.PasswordHasher.clear(secret);
    }

    // -------------------------------------------------- scripted digest values

    private static final String SALT = "AAAAAAAAAAAAAAAAAAAAAA==";
    private static final String DIGEST = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    /** High enough that the derivation dominates the (free) doubled JDBC calls. */
    private static final int GUARDED_ITERATIONS = 100_000;
    /** Measured floor for {@link #GUARDED_ITERATIONS} on this JVM, with slack. */
    private static final long MINIMUM_KDF_MILLIS = 60;

    // ------------------------------------------------------------- the doubles

    /** Recording doubles for a JDBC {@link Connection} and everything it hands out. */
    private static final class FakeConnection {

        private final List<FakePreparedStatement> preparedStatements = new ArrayList<>();
        private final List<SQLException> queuedInsertFailures = new ArrayList<>();
        private final List<String[]> queuedSelectRows = new ArrayList<>();
        private final List<String> plainStatements = new ArrayList<>();
        private boolean autoCommit = true;
        private boolean commitCalled;
        private boolean rollbackCalled;
        private boolean closeCalled;
        private Connection proxy;

        Connection connection() {
            if (proxy == null) {
                proxy = (Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
                        new Class<?>[]{Connection.class}, new ConnectionHandler());
            }
            return proxy;
        }

        void setAutoCommit(boolean value) {
            autoCommit = value;
        }

        void queueInsertFailure(SQLException failure) {
            queuedInsertFailures.add(failure);
        }

        /** {@code null} means "the query returns no rows". */
        void queueSelectResult(String[] row) {
            queuedSelectRows.add(row);
        }

        boolean wasCommitCalled() {
            return commitCalled;
        }

        boolean wasRollbackCalled() {
            return rollbackCalled;
        }

        boolean wasCloseCalled() {
            return closeCalled;
        }

        int plainStatementCount() {
            return plainStatements.size();
        }

        int countMatching(String fragment) {
            int total = 0;
            for (FakePreparedStatement statement : preparedStatements) {
                if (statement.sql().contains(fragment)) {
                    total++;
                }
            }
            return total;
        }

        FakePreparedStatement firstPrepareMatching(String fragment) {
            for (FakePreparedStatement statement : preparedStatements) {
                if (statement.sql().toUpperCase().contains(fragment.toUpperCase())) {
                    return statement;
                }
            }
            throw new AssertionError("no prepared statement matched [" + fragment + "]; saw "
                    + preparedStatements);
        }

        private final class ConnectionHandler implements InvocationHandler {

            @Override
            public Object invoke(Object proxyObject, Method method, Object[] arguments) throws Throwable {
                switch (method.getName()) {
                    case "prepareStatement":
                        FakePreparedStatement statement = new FakePreparedStatement(
                                (String) arguments[0], FakeConnection.this);
                        preparedStatements.add(statement);
                        return statement.proxy();
                    case "createStatement":
                        plainStatements.add("<createStatement>");
                        return newPlainStatementProxy();
                    case "getAutoCommit":
                        return autoCommit;
                    case "setAutoCommit":
                        autoCommit = (Boolean) arguments[0];
                        return null;
                    case "commit":
                        commitCalled = true;
                        return null;
                    case "rollback":
                        rollbackCalled = true;
                        return null;
                    case "close":
                        closeCalled = true;
                        return null;
                    case "isClosed":
                        return closeCalled;
                    case "toString":
                        return "FakeConnection";
                    case "hashCode":
                        return System.identityHashCode(proxyObject);
                    case "equals":
                        return proxyObject == arguments[0];
                    default:
                        return defaultValueFor(method.getReturnType());
                }
            }
        }

        private Object newPlainStatementProxy() {
            return Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{Statement.class},
                    (proxyObject, method, arguments) -> {
                        if ("close".equals(method.getName())) {
                            return null;
                        }
                        if ("execute".equals(method.getName()) || "executeUpdate".equals(method.getName())
                                || "executeQuery".equals(method.getName())) {
                            plainStatements.add(String.valueOf(arguments[0]));
                            return "executeQuery".equals(method.getName()) ? newResultSetProxy(null) : Integer.valueOf(0);
                        }
                        return defaultValueFor(method.getReturnType());
                    });
        }

        private ResultSet newResultSetProxy(String[] row) {
            return (ResultSet) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[]{ResultSet.class}, new ResultSetHandler(row));
        }

        private final class ResultSetHandler implements InvocationHandler {

            private final String[] row;
            private boolean consumed;

            private ResultSetHandler(String[] row) {
                this.row = row;
            }

            @Override
            public Object invoke(Object proxyObject, Method method, Object[] arguments) throws Throwable {
                switch (method.getName()) {
                    case "next":
                        if (row == null || consumed) {
                            return Boolean.FALSE;
                        }
                        consumed = true;
                        return Boolean.TRUE;
                    case "getString":
                        return row == null ? null : row[((Integer) arguments[0]) - 1];
                    case "getInt":
                        return row == null ? Integer.valueOf(0) : Integer.parseInt(row[((Integer) arguments[0]) - 1]);
                    case "wasNull":
                        return Boolean.FALSE;
                    case "close":
                        return null;
                    default:
                        return defaultValueFor(method.getReturnType());
                }
            }
        }

        private void drainQueuedInsertFailure() throws SQLException {
            if (!queuedInsertFailures.isEmpty()) {
                throw queuedInsertFailures.remove(0);
            }
        }

        private String[] takeQueuedSelectRow() {
            if (queuedSelectRows.isEmpty()) {
                return null;
            }
            return queuedSelectRows.remove(0);
        }
    }

    /** Records the statement text and every bound parameter. */
    private static final class FakePreparedStatement {

        private final String sql;
        private final FakeConnection owner;
        private final Map<Integer, Object> parameters = new LinkedHashMap<>();
        private boolean closed;
        private PreparedStatement proxy;

        private FakePreparedStatement(String sql, FakeConnection owner) {
            this.sql = sql;
            this.owner = owner;
        }

        private String sql() {
            return sql;
        }

        private Map<Integer, String> parameters() {
            Map<Integer, String> asText = new LinkedHashMap<>();
            for (Map.Entry<Integer, Object> entry : parameters.entrySet()) {
                asText.put(entry.getKey(), String.valueOf(entry.getValue()));
            }
            return asText;
        }

        private Map<Integer, Object> rawParameters() {
            return parameters;
        }

        private boolean wasClosed() {
            return closed;
        }

        @Override
        public String toString() {
            return sql + " " + parameters;
        }

        private PreparedStatement proxy() {
            if (proxy == null) {
                proxy = (PreparedStatement) Proxy.newProxyInstance(getClass().getClassLoader(),
                        new Class<?>[]{PreparedStatement.class}, new Handler());
            }
            return proxy;
        }

        private final class Handler implements InvocationHandler {

            @Override
            public Object invoke(Object proxyObject, Method method, Object[] arguments) throws Throwable {
                switch (method.getName()) {
                    case "setString":
                    case "setTimestamp":
                    case "setInt":
                    case "setObject":
                        parameters.put((Integer) arguments[0], arguments[1]);
                        return null;
                    case "close":
                        verifyEveryPlaceholderWasBound();
                        closed = true;
                        return null;
                    case "executeUpdate": {
                        verifyEveryPlaceholderWasBound();
                        owner.drainQueuedInsertFailure();
                        return Integer.valueOf(1);
                    }
                    case "executeQuery": {
                        verifyEveryPlaceholderWasBound();
                        return owner.newResultSetProxy(owner.takeQueuedSelectRow());
                    }
                    case "toString":
                        return "FakePreparedStatement[" + sql + "]";
                    case "hashCode":
                        return System.identityHashCode(proxyObject);
                    case "equals":
                        return proxyObject == arguments[0];
                    default:
                        return defaultValueFor(method.getReturnType());
                }
            }
        }

        private void verifyEveryPlaceholderWasBound() {
            long placeholders = countChar(sql, '?');
            if (placeholders != parameters.size()) {
                throw new AssertionError("statement has " + placeholders + " placeholders but "
                        + parameters.size() + " parameters were bound: " + sql);
            }
        }
    }

    private static Object defaultValueFor(Class<?> type) {
        if (!type.isPrimitive()) {
            return null;
        }
        if (type == boolean.class) {
            return Boolean.FALSE;
        }
        if (type == void.class) {
            return null;
        }
        if (type == int.class) {
            return Integer.valueOf(0);
        }
        if (type == long.class) {
            return Long.valueOf(0L);
        }
        if (type == short.class) {
            return Short.valueOf((short) 0);
        }
        if (type == byte.class) {
            return Byte.valueOf((byte) 0);
        }
        if (type == float.class) {
            return Float.valueOf(0f);
        }
        if (type == double.class) {
            return Double.valueOf(0d);
        }
        if (type == char.class) {
            return Character.valueOf('\0');
        }
        throw new AssertionError("unhandled primitive return type " + type);
    }

    // ----------------------------------------------------------------- helpers

    private static long countChar(String text, char needle) {
        return text.chars().filter(c -> c == needle).count();
    }

    private static boolean containsAnyIgnoreCase(String text, String... needles) {
        String upper = text.toUpperCase();
        for (String needle : needles) {
            if (upper.contains(needle.toUpperCase())) {
                return true;
            }
        }
        return false;
    }

    /** Summary of a value: enough to name a check, never a faithful copy. */
    private static String describe(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length() && i < 24; i++) {
            char c = value.charAt(i);
            if (c >= ' ' && c <= '~') {
                out.append(c);
            } else {
                out.append("(c").append((int) c).append(")");
            }
        }
        return "'" + out + "'(len " + value.length() + ")";
    }

    private static void check(String what, boolean condition) {
        checks++;
        if (!condition) {
            failures.add(what);
            System.out.println("FAIL  " + what);
        } else {
            System.out.println("ok    " + what);
        }
    }

    private static void report() {
        System.out.println("");
        if (failures.isEmpty()) {
            System.out.println(checks + " checks passed.");
            return;
        }
        System.out.println(failures.size() + " of " + checks + " checks FAILED:");
        for (String failure : failures) {
            System.out.println("  - " + failure);
        }
        System.exit(1);
    }
}
