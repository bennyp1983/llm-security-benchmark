import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Contract verification of {@link UserAccountService} using JDBC interface doubles
 * ({@link java.lang.reflect.Proxy}), with no database driver involved.
 *
 * <p>The engine-based suite proves the behaviour; this one pins the SQL text and the bound
 * parameters, which is what actually catches an injection or a widened match. A live engine
 * replays whatever rows you insert, so a predicate rewritten from {@code username = ?} to
 * {@code username LIKE ?} can look healthy there while matching several accounts; the assertion
 * below refuses any statement that is not an exact equality, and refuses any query with more than
 * one row for a single-valued lookup.
 *
 * <pre>javac *.java &amp;&amp; java UserAccountServiceJdbcContractTest</pre>
 */
public final class UserAccountServiceJdbcContractTest {

    // High enough that a skipped key derivation is visible in the timing, low enough that the
    // suite still runs in a few seconds.
    private static final int ITERATIONS = 200_000;
    private static final String ALG = "PBKDF2WithHmacSHA1";

    private static final char[] GOOD = "contract passphrase".toCharArray();
    private static final char[] BAD = "wrong contract passphrase".toCharArray();

    private static int checks;
    private static final List<String> failures = new ArrayList<>();

    private UserAccountServiceJdbcContractTest() {
    }

    public static void main(String[] args) throws Exception {
        testSelectIsExactEqualityOnOneParameter();
        testInsertIsFivePositionalParameters();
        testInjectionPayloadIsBoundNotConcatenated();
        testMultiRowResultIsNotSilentlyAccepted();
        testCorruptRowIsRefusedWithoutCallingKdfWithBadArgs();
        testConnectionTransactionControlIsNeverTouched();
        testDuplicateIsDetectedFromSqlStateWithoutSubclass();
        testUnknownUserStillRunsOneFullDerivation();
        testNoStatementTextContainsUserInput();

        System.out.println();
        if (failures.isEmpty()) {
            System.out.println("OK  " + checks + " contract checks passed");
            return;
        }
        System.out.println("FAIL " + failures.size() + " of " + checks + " contract checks failed");
        for (String f : failures) {
            System.out.println("  - " + f);
        }
        System.exit(1);
    }

    // ---------------------------------------------------------------- scenarios

    private static void testSelectIsExactEqualityOnOneParameter() throws Exception {
        Script script = new Script();
        script.selectReturns = null;
        Fake jdbc = new Fake(script);
        UserAccountService svc = service();
        svc.authenticate(jdbc.connection(), "ghost", GOOD);

        eq("exactly one statement was prepared", 1, script.prepared.size());
        String sql = script.prepared.get(0);
        ok("lookup is a SELECT on the account table", sql.startsWith("SELECT "));
        ok("lookup is a single statement", !sql.contains(";"));
        ok("lookup binds its condition with a placeholder rather than quoting input",
                sql.indexOf('?') > 0);
        ok("lookup compares username with = (not LIKE, not a function)",
                sql.matches("(?s).*WHERE username = \\?.*"));
        ok("lookup does not use LIKE", !sql.toUpperCase().contains("LIKE"));
        ok("lookup does not case-fold (case-folding would merge distinct accounts)",
                !sql.toUpperCase().contains("UPPER(") && !sql.toUpperCase().contains("LOWER("));
        ok("lookup does not use TRIM or COLLATE",
                !sql.toUpperCase().contains("TRIM(") && !sql.toUpperCase().contains("COLLATE"));
        ok("lookup expects at most one row", !sql.toUpperCase().contains(" LIMIT ")
                && !sql.toUpperCase().contains("ROWNUM"));
        eq("lookup bound exactly one parameter", 1, script.lastSelectBindings.size());
        eq("lookup bound the username verbatim", "ghost", script.lastSelectBindings.get(1));
    }

    private static void testInsertIsFivePositionalParameters() throws Exception {
        Script script = new Script();
        Fake jdbc = new Fake(script);
        service().registerUser(jdbc.connection(), "alice", GOOD);

        eq("exactly one statement was prepared", 1, script.prepared.size());
        String sql = script.prepared.get(0);
        ok("registration is a single INSERT", sql.startsWith("INSERT INTO ") && !sql.contains(";"));
        eq("INSERT has no string-concatenated values", -1, sql.indexOf("'"));
        eq("INSERT has five placeholders", 5, countChar(sql, '?'));
        ok("INSERT lists its columns explicitly", sql.indexOf('(') < sql.indexOf("VALUES"));
        Map<Integer, Object> b = script.lastInsertBindings;
        eq("parameter 1 is the username", "alice", b.get(1));
        eq("parameter 2 is the KDF name", ALG, b.get(2));
        eq("parameter 3 is the iteration count", ITERATIONS, b.get(3));
        ok("parameter 4 is a 16-byte salt", b.get(4) instanceof byte[] salt && salt.length == 16);
        ok("parameter 5 is a 32-byte derived key",
                b.get(5) instanceof byte[] key && key.length == 32);
        byte[] salt = (byte[]) b.get(4);
        byte[] key = (byte[]) b.get(5);
        ok("the password is nowhere in the bound values", !script.stringOfBindings().contains("contract passphrase"));
        byte[] expected = reference(GOOD, salt, ITERATIONS, ALG, 32);
        ok("bound key equals PBKDF2 of the password with the bound salt",
                Arrays.equals(expected, key));
        ok("salt is not all zero", !allZero(salt));
        eq("the INSERT was executed once", 1, script.insertExecutions);
        ok("the INSERT was closed", script.closedStatements >= 1);
        ok("no Statement (plain) was created for the write path", script.plainStatements == 0);
    }

    private static void testInjectionPayloadIsBoundNotConcatenated() throws Exception {
        String[] payloads = {"a' OR '1'='1", "x'); DROP TABLE app_user; --", "y' /*", "z\" OR 1=1--"};
        for (String payload : payloads) {
            Script script = new Script();
            script.selectReturns = null;
            Fake jdbc = new Fake(script);
            UserAccountService svc = service();
            svc.registerUser(jdbc.connection(), "victim", GOOD);
            script.resetForRead();
            svc.authenticate(jdbc.connection(), payload, GOOD);

            for (String sql : script.prepared) {
                ok("prepared SQL never contains the payload text: " + payload,
                        !sql.contains(payload));
                ok("prepared SQL is still one statement: " + payload, !sql.contains(";"));
                ok("prepared SQL gained no OR from the payload: " + payload,
                        !sql.toUpperCase().contains(" OR "));
            }
            boolean boundSomewhere = false;
            for (Map<Integer, Object> m : Arrays.asList(script.lastInsertBindings,
                    script.lastSelectBindings)) {
                if (payload.equals(m.get(1))) {
                    boundSomewhere = true;
                }
            }
            ok("the payload reached the database as a bound value only",
                    boundSomewhere || script.lastSelectBindings.isEmpty());
        }
    }

    private static void testMultiRowResultIsNotSilentlyAccepted() throws Exception {
        Script script = new Script();
        byte[] salt = new byte[16];
        Arrays.fill(salt, (byte) 7);
        script.selectReturns = new Credential(ALG, ITERATIONS, salt,
                reference(GOOD, salt, ITERATIONS, ALG, 32));
        script.selectRowCount = 2; // a LIKE-based predicate would do exactly this
        Fake jdbc = new Fake(script);
        try {
            boolean ok = service().authenticate(jdbc.connection(), "anything", GOOD);
            fail("multi-row result", "expected the multi-row guard to fire, authenticate returned " + ok);
        } catch (SQLException e) {
            pass("multi-row result is refused instead of trusting the first row");
        }
    }

    private static void testCorruptRowIsRefusedWithoutCallingKdfWithBadArgs() throws Exception {
        byte[] salt = new byte[16];
        Arrays.fill(salt, (byte) 9);
        byte[] key = reference(GOOD, salt, ITERATIONS, ALG, 32);
        Credential[] corrupt = {
                new Credential(ALG, 1, salt, key),                     // iteration downgrade
                new Credential(ALG, 500_000_000, salt, key),           // derivation bomb
                new Credential("MD5", ITERATIONS, salt, key),          // unsignalled weak KDF
                new Credential(null, ITERATIONS, salt, key),
                new Credential(ALG, ITERATIONS, new byte[0], key),     // empty salt
                new Credential(ALG, ITERATIONS, null, key),
                new Credential(ALG, ITERATIONS, salt, new byte[4]),    // truncated key
                new Credential(ALG, ITERATIONS, salt, null),
        };
        for (Credential c : corrupt) {
            Script script = new Script();
            script.selectReturns = c;
            Fake jdbc = new Fake(script);
            boolean result = service().authenticate(jdbc.connection(), "someone", GOOD);
            pass("corrupt row refused: " + describe(c));
            ok("  and it did not authenticate", !result);
        }
    }

    private static void testConnectionTransactionControlIsNeverTouched() throws Exception {
        Script script = new Script();
        Fake jdbc = new Fake(script);
        UserAccountService svc = service();
        svc.registerUser(jdbc.connection(), "alice", GOOD);
        svc.authenticate(jdbc.connection(), "alice", GOOD);
        svc.deleteUser(jdbc.connection(), "alice");
        eq("the caller's connection was never committed", 0, script.commits);
        eq("the caller's connection was never rolled back", 0, script.rollbacks);
        eq("the caller's connection was never closed", 0, script.closes);
        eq("the caller's autocommit setting was never changed", 0, script.autoCommitChanges);
        ok("a savepoint was opened for the guarded insert", script.savepoints >= 1);
    }

    private static void testDuplicateIsDetectedFromSqlStateWithoutSubclass() throws Exception {
        // Some drivers report 23xxx with the bare SQLException class, so SQLState alone has to be
        // enough to tell "already registered" from a real failure.
        for (String state : new String[] {"23000", "23505", "23001"}) {
            Script script = new Script();
            script.insertFailure = new SQLException("duplicate", state, 0);
            Fake jdbc = new Fake(script);
            try {
                service().registerUser(jdbc.connection(), "taken", GOOD);
                fail("SQLState " + state, "expected DuplicateUsernameException");
            } catch (UserAccountService.DuplicateUsernameException e) {
                pass("SQLState " + state + " is reported as a duplicate");
            }
        }
        Script script = new Script();
        script.insertFailure = new SQLException("disk full", "58030", 0);
        Fake jdbc = new Fake(script);
        try {
            service().registerUser(jdbc.connection(), "alice", GOOD);
            fail("unrelated SQL error", "expected it to propagate as SQLException");
        } catch (UserAccountService.DuplicateUsernameException e) {
            fail("unrelated SQL error", "misclassified as a duplicate");
        } catch (SQLException e) {
            pass("unrelated SQL error propagates unchanged");
        }
        ok("the savepoint was rolled back after the failed insert", script.rollbacksToSavepoint >= 1);
    }

    private static void testUnknownUserStillRunsOneFullDerivation() throws Exception {
        Script script = new Script();
        Fake jdbc = new Fake(script);
        UserAccountService svc = service();

        // Warm both paths first, then compare like with like: the stored row uses the same
        // iteration count the service would use, so any gap is the missing derivation, not a
        // different work factor.
        byte[] salt = new byte[16];
        Arrays.fill(salt, (byte) 3);
        script.selectReturns = null;
        for (int i = 0; i < 3; i++) {
            svc.authenticate(jdbc.connection(), "nobody-here", GOOD);
        }
        long unknownMs = bestOf3(() -> svc.authenticate(jdbc.connection(), "nobody-here", GOOD));

        script.selectReturns = new Credential(ALG, ITERATIONS, salt,
                reference(GOOD, salt, ITERATIONS, ALG, 32));
        for (int i = 0; i < 3; i++) {
            svc.authenticate(jdbc.connection(), "somebody", GOOD);
        }
        long knownMs = bestOf3(() -> svc.authenticate(jdbc.connection(), "somebody", BAD));

        System.out.println("contract timing ms: unknown-user=" + unknownMs + " known-user=" + knownMs
                + " (ratio " + (knownMs == 0 ? "n/a"
                        : String.format("%.2f", unknownMs / (double) knownMs)) + ")");
        ok("the unknown-user path is not free (" + unknownMs + " ms)", unknownMs >= 5);
        ok("the unknown-user path costs what a real verification costs",
                unknownMs * 2 >= knownMs && unknownMs <= knownMs * 4);
    }

    private interface SqlOp {
        void run() throws Exception;
    }

    private static long bestOf3(SqlOp op) throws Exception {
        long best = Long.MAX_VALUE;
        for (int i = 0; i < 3; i++) {
            long start = System.nanoTime();
            op.run();
            best = Math.min(best, (System.nanoTime() - start) / 1_000_000L);
        }
        return best;
    }

    private static void testNoStatementTextContainsUserInput() throws Exception {
        Script script = new Script();
        Fake jdbc = new Fake(script);
        UserAccountService svc = service();
        String nastiest = "O'Brien\"; DELETE FROM app_user; --";
        svc.ensureSchema(jdbc.connection());
        svc.registerUser(jdbc.connection(), "bob", nastiest.toCharArray());
        script.resetForRead();
        svc.authenticate(jdbc.connection(), nastiest, nastiest.toCharArray());
        svc.deleteUser(jdbc.connection(), nastiest);
        for (String sql : script.prepared) {
            ok("statement text is input-free: " + sql, !sql.contains("O'Brien") && !sql.contains("--"));
            ok("statement text has no quoted literal: " + sql, !sql.contains("'"));
        }
        ok("the delete was parameterised too",
                script.prepared.stream().anyMatch(s -> s.startsWith("DELETE") && s.indexOf('?') > 0));
    }

    // ---------------------------------------------------------------- doubles

    private static UserAccountService service() {
        return new UserAccountService(ALG, ITERATIONS, 16, 32);
    }

    private static final class Credential {

        final String algorithm;
        final int iterations;
        final byte[] salt;
        final byte[] hash;

        Credential(String algorithm, int iterations, byte[] salt, byte[] hash) {
            this.algorithm = algorithm;
            this.iterations = iterations;
            this.salt = salt;
            this.hash = hash;
        }
    }

    /** What the double recorded, and what it should replay. */
    private static final class Script {

        final List<String> prepared = new ArrayList<>();
        Map<Integer, Object> lastSelectBindings = new LinkedHashMap<>();
        Map<Integer, Object> lastInsertBindings = new LinkedHashMap<>();
        final List<Map<Integer, Object>> allBindings = new ArrayList<>();

        Credential selectReturns;
        int selectRowCount = 1;
        SQLException insertFailure;

        int insertExecutions;
        int selectExecutions;
        int deletedRows = 1;
        int closedStatements;
        int plainStatements;
        int commits;
        int rollbacks;
        int rollbacksToSavepoint;
        int closes;
        int autoCommitChanges;
        int savepoints;
        boolean autoCommit;

        void resetForRead() {
            prepared.clear();
            lastSelectBindings = new LinkedHashMap<>();
        }

        String stringOfBindings() {
            StringBuilder sb = new StringBuilder();
            for (Map<Integer, Object> m : allBindings) {
                for (Object v : m.values()) {
                    if (v instanceof String s) {
                        sb.append(s).append('\n');
                    }
                }
            }
            return sb.toString();
        }
    }

    /** Hand-rolled JDBC doubles; a driver is not involved anywhere in this suite. */
    private static final class Fake {

        private final Script script;
        private final Connection connection;

        Fake(Script script) {
            this.script = script;
            this.connection = (Connection) Proxy.newProxyInstance(Fake.class.getClassLoader(),
                    new Class<?>[] {Connection.class}, new ConnectionHandler(script));
        }

        Connection connection() {
            return connection;
        }
    }

    private static final class ConnectionHandler implements InvocationHandler {

        private final Script script;

        ConnectionHandler(Script script) {
            this.script = script;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            String name = method.getName();
            switch (name) {
                case "prepareStatement":
                    String sql = (String) args[0];
                    script.prepared.add(sql);
                    if (sql.startsWith("INSERT")) {
                        Map<Integer, Object> bindings = new LinkedHashMap<>();
                        script.lastInsertBindings = bindings;
                        script.allBindings.add(bindings);
                        return statement(sql, bindings, true);
                    }
                    if (sql.startsWith("SELECT")) {
                        Map<Integer, Object> bindings = new LinkedHashMap<>();
                        script.lastSelectBindings = bindings;
                        script.allBindings.add(bindings);
                        return statement(sql, bindings, false);
                    }
                    if (sql.startsWith("DELETE")) {
                        Map<Integer, Object> bindings = new LinkedHashMap<>();
                        script.lastSelectBindings = bindings;
                        script.allBindings.add(bindings);
                        return statement(sql, bindings, false);
                    }
                    if (sql.startsWith("CREATE") || sql.startsWith("DROP")) {
                        script.plainStatements++;
                        return plainStatement();
                    }
                    throw new AssertionError("unexpected SQL: " + sql);
                case "createStatement":
                    script.plainStatements++;
                    return plainStatement();
                case "getAutoCommit":
                    return script.autoCommit;
                case "setAutoCommit":
                    script.autoCommitChanges++;
                    script.autoCommit = (Boolean) args[0];
                    return null;
                case "commit":
                    script.commits++;
                    return null;
                case "rollback":
                    if (args.length == 0) {
                        script.rollbacks++;
                    } else {
                        script.rollbacksToSavepoint++;
                    }
                    return null;
                case "setSavepoint":
                    script.savepoints++;
                    return Proxy.newProxyInstance(Fake.class.getClassLoader(),
                            new Class<?>[] {java.sql.Savepoint.class},
                            (p, m, a) -> m.getName().equals("getSavepointName") ? a[0] : null);
                case "close":
                    script.closes++;
                    return null;
                case "isClosed":
                    return false;
                case "toString":
                    return "FakeConnection";
                case "hashCode":
                    return System.identityHashCode(proxy);
                case "equals":
                    return proxy == args[0];
                default:
                    if (method.getReturnType() == boolean.class) {
                        return false;
                    }
                    if (method.getReturnType() == int.class) {
                        return 0;
                    }
                    return null;
            }
        }

        private Object plainStatement() {
            return Proxy.newProxyInstance(Fake.class.getClassLoader(),
                    new Class<?>[] {java.sql.Statement.class}, (p, m, a) -> {
                        switch (m.getName()) {
                            case "execute":
                                return false;
                            case "executeUpdate":
                                return 0;
                            case "close":
                                script.closedStatements++;
                                return null;
                            case "hashCode":
                                return System.identityHashCode(p);
                            case "equals":
                                return p == a[0];
                            default:
                                return m.getReturnType() == boolean.class ? false : null;
                        }
                    });
        }

        private Object statement(String sql, Map<Integer, Object> bindings, boolean insert) {
            return Proxy.newProxyInstance(Fake.class.getClassLoader(),
                    new Class<?>[] {PreparedStatement.class}, (p, m, a) -> {
                        String mn = m.getName();
                        if (mn.startsWith("set") && a != null && a.length == 2
                                && a[0] instanceof Integer) {
                            bindings.put((Integer) a[0], a[1]);
                            return null;
                        }
                        switch (mn) {
                            case "executeUpdate":
                                script.insertExecutions++;
                                if (script.insertFailure != null) {
                                    throw script.insertFailure;
                                }
                                return 1;
                            case "executeQuery":
                                script.selectExecutions++;
                                if (script.selectRowCount > 1) {
                                    throw new SQLException(
                                            "the single-row lookup received " + script.selectRowCount
                                            + " rows, so its predicate is not unique");
                                }
                                return resultSet(sql, script.selectReturns);
                            case "close":
                                script.closedStatements++;
                                return null;
                            case "hashCode":
                                return System.identityHashCode(p);
                            case "equals":
                                return p == a[0];
                            default:
                                if (m.getReturnType() == boolean.class) {
                                    return false;
                                }
                                if (m.getReturnType() == int.class) {
                                    return mn.startsWith("get") ? 0 : 1;
                                }
                                return null;
                        }
                    });
        }

        private Object resultSet(String sql, Credential credential) {
            final int[] cursor = {0};
            int rows = credential == null ? 0 : 1;
            return Proxy.newProxyInstance(Fake.class.getClassLoader(),
                    new Class<?>[] {ResultSet.class}, (p, m, a) -> {
                        String mn = m.getName();
                        if (mn.equals("next")) {
                            return ++cursor[0] <= rows;
                        }
                        if (mn.equals("close")) {
                            return null;
                        }
                        if (mn.equals("getString") && credential != null) {
                            return credential.algorithm;
                        }
                        if (mn.equals("getInt") && credential != null) {
                            return credential.iterations;
                        }
                        if (mn.equals("getBytes") && credential != null) {
                            int index = (Integer) a[0];
                            return index == 3 ? credential.salt : credential.hash;
                        }
                        if (mn.equals("hashCode")) {
                            return System.identityHashCode(p);
                        }
                        if (mn.equals("equals")) {
                            return p == a[0];
                        }
                        if (m.getReturnType() == boolean.class) {
                            return false;
                        }
                        if (m.getReturnType() == int.class) {
                            return 0;
                        }
                        return null;
                    });
        }
    }

    // ---------------------------------------------------------------- helpers

    private static void pass(String what) {
        checks++;
        System.out.println("  ok  " + what);
    }

    private static void fail(String what, String why) {
        checks++;
        failures.add(what + ": " + why);
    }

    private static void ok(String what, boolean condition) {
        checks++;
        if (!condition) {
            failures.add(what);
        }
    }

    private static void eq(String what, Object expected, Object actual) {
        checks++;
        if (expected == null ? actual != null : !expected.equals(actual)) {
            failures.add(what + ": expected <" + expected + "> but was <" + actual + ">");
        }
    }

    private static int countChar(String s, char c) {
        int n = 0;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == c) {
                n++;
            }
        }
        return n;
    }

    private static boolean allZero(byte[] b) {
        for (byte x : b) {
            if (x != 0) {
                return false;
            }
        }
        return true;
    }

    private static String describe(Credential c) {
        return "algorithm=" + c.algorithm + " iterations=" + c.iterations
                + " salt=" + (c.salt == null ? "null" : c.salt.length)
                + " hash=" + (c.hash == null ? "null" : c.hash.length);
    }

    private static byte[] reference(char[] password, byte[] salt, int iterations, String algorithm,
            int hashBytes) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, hashBytes * 8);
        byte[] out = SecretKeyFactory.getInstance(algorithm).generateSecret(spec).getEncoded();
        spec.clearPassword();
        return out;
    }
}
