import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Verification of {@link UserAccountService} against a real SQL engine (H2, in-memory and
 * file-based). Run with the H2 jar on the classpath:
 *
 * <pre>javac -cp h2.jar *.java &amp;&amp; java -cp h2.jar:. UserAccountServiceTest</pre>
 */
public final class UserAccountServiceTest {

    /** Lower work factor so the suite finishes quickly; the shipped default is much higher. */
    private static final int TEST_ITERATIONS = 50_000;

    private static final char[] GOOD = "correct horse battery".toCharArray();
    private static final char[] BAD = "wrong horse battery".toCharArray();

    private static int checks;
    private static final List<String> failures = new ArrayList<>();

    private UserAccountServiceTest() {
    }

    public static void main(String[] args) throws Exception {
        UserAccountService svc =
                new UserAccountService(UserAccountService.DEFAULT_ALGORITHM, TEST_ITERATIONS, 16, 32);

        try (Connection c = DriverManager.getConnection("jdbc:h2:mem:uit;DB_CLOSE_DELAY=-1")) {
            svc.ensureSchema(c);
            svc.ensureSchema(c); // idempotent
            testHappyPath(svc, c);
            testDistinctSaltsAndNoPlaintext(svc, c);
            testCaseSensitivityAndWildcards(svc, c);
            testPolicyRejections(svc, c);
            testHostileInputsStoredVerbatim(svc, c);
            testMalformedRowsRefused(svc, c);
            testSaltIsFreshEntropyPerRegistration(svc, c);
            testStoredWorkFactorIsHonoured(svc, c);
            testUnrelatedSqlErrorIsNotADuplicate(svc, c);
            testDelete(svc, c);
            testConcurrentDuplicate(svc);
        }
        testUnknownUserCostsWhatKnownUserCosts(svc);
        testTransactionBoundaries(svc);

        try (Connection c = DriverManager.getConnection("jdbc:h2:mem:uit2;DB_CLOSE_DELAY=-1")) {
            svc.ensureSchema(c);
            testUpgradeAdvice(svc, c);
        }

        System.out.println();
        if (failures.isEmpty()) {
            System.out.println("OK  " + checks + " checks passed");
            return;
        }
        System.out.println("FAIL " + failures.size() + " of " + checks + " checks failed");
        for (String f : failures) {
            System.out.println("  - " + f);
        }
        System.exit(1);
    }

    // ---------------------------------------------------------------- scenarios

    private static void testHappyPath(UserAccountService svc, Connection c) throws Exception {
        UserAccountService.Account a = svc.registerUser(c, "alice", GOOD);
        eq("register echoes username", "alice", a.username());
        eq("register reports the KDF", UserAccountService.DEFAULT_ALGORITHM, a.algorithm());
        eq("register reports the work factor", TEST_ITERATIONS, a.iterations());
        eq("account toString carries no secret", -1, a.toString().indexOf("correct"));
        ok("correct password authenticates", svc.authenticate(c, "alice", GOOD));
        ok("wrong password rejected", !svc.authenticate(c, "alice", BAD));
        ok("String overload registers", svc.registerUser(c, "bob", "another passphrase") != null);
        ok("String overload authenticates", svc.authenticate(c, "bob", "another passphrase"));
        ok("unknown user rejected", !svc.authenticate(c, "nobody", GOOD));
        ok("empty username rejected without touching the table", !svc.authenticate(c, "", GOOD));
        ok("null password rejected", !svc.authenticate(c, "alice", (char[]) null));
        ok("empty password rejected", !svc.authenticate(c, "alice", new char[0]));
        eq("one row per account", 2, count(c, "app_user"));
    }

    private static void testDistinctSaltsAndNoPlaintext(UserAccountService svc, Connection c)
            throws Exception {
        svc.registerUser(c, "salt1", GOOD);
        svc.registerUser(c, "salt2", GOOD);
        try (Statement st = c.createStatement();
                ResultSet rs = st.executeQuery(
                        "SELECT salt, password_hash FROM app_user WHERE username IN ('salt1','salt2')")) {
            rs.next();
            byte[] s1 = rs.getBytes(1);
            byte[] h1 = rs.getBytes(2);
            rs.next();
            byte[] s2 = rs.getBytes(1);
            byte[] h2 = rs.getBytes(2);
            eq("salt length", 16, s1.length);
            eq("derived key length", 32, h1.length);
            ok("same password gets a different salt per account", !Arrays.equals(s1, s2));
            ok("same password gets a different key per account", !Arrays.equals(h1, h2));
            ok("salt is random, not a zero fill", !allZeros(s1));
            byte[] utf8 = new String(GOOD).getBytes(StandardCharsets.UTF_8);
            ok("stored salt does not contain the passphrase", !contains(s1, utf8));
            ok("stored key does not contain the passphrase", !contains(h1, utf8));
            ok("stored key is not the passphrase bytes", !Arrays.equals(h1, utf8));
            byte[] sha = MessageDigest.getInstance("SHA-256").digest(utf8);
            ok("stored key is a real KDF output, not a bare SHA-256 of the passphrase",
                    !Arrays.equals(h1, sha));
            byte[] expected = referenceDerive(GOOD, s1, TEST_ITERATIONS,
                    UserAccountService.DEFAULT_ALGORITHM, 32);
            ok("stored key equals an independently computed PBKDF2", Arrays.equals(h1, expected));
        }
    }

    private static void testCaseSensitivityAndWildcards(UserAccountService svc, Connection c)
            throws Exception {
        // Use names that exist nowhere else in this suite, so a hit can only come from the row
        // inserted here.
        svc.registerUser(c, "Carol", GOOD);
        ok("exact username authenticates", svc.authenticate(c, "Carol", GOOD));
        ok("different case is a different account", !svc.authenticate(c, "carol", GOOD));
        ok("LIKE wildcard in a queried username matches nothing",
                !svc.authenticate(c, "Caro_", GOOD));
        ok("SQL comment sequence in a queried username matches nothing",
                !svc.authenticate(c, "Carol' --", GOOD));
        svc.registerUser(c, "a_b", GOOD);
        ok("underscore is an ordinary character in a stored username",
                svc.authenticate(c, "a_b", GOOD));
        ok("a wildcard cannot stand in for the stored underscore",
                !svc.authenticate(c, "aXb", GOOD));
    }

    private static void testPolicyRejections(UserAccountService svc, Connection c) throws Exception {
        String[] badNames = {null, "", "al", "a".repeat(65), " ali", "ali ce", "ali;drop table app_user",
                "ali' or '1'='1", "al!ce", "ali\n", "ali\t", "_leading"};
        for (String n : badNames) {
            expect("username rejected: " + n, UserAccountService.InvalidValueException.class, () -> {
                svc.registerUser(c, n, GOOD);
                return null;
            });
        }
        // "--" and "'" are only dangerous if they reach the SQL text, which the contract suite
        // checks; as a username the pattern above lets "--" through, so it must be inert here.
        ok("a comment-looking username is valid and still requires the right password",
                svc.registerUser(c, "li--", GOOD) != null
                        && !svc.authenticate(c, "li--", BAD)
                        && svc.authenticate(c, "li--", GOOD));
        char[][] badPw = {
                null,
                new char[0],
                "123456789".toCharArray(),                   // 9 chars, one below the minimum
                ("ctrl" + (char) 0x01 + "char1234").toCharArray(),
                ("del" + (char) 0x7F + "char12345").toCharArray(),
                "a".repeat(1025).toCharArray(),              // one above the maximum
        };
        for (char[] p : badPw) {
            expect("weak password rejected", UserAccountService.InvalidValueException.class, () -> {
                svc.registerUser(c, "policyuser", p);
                return null;
            });
        }
        eq("no rejected registration wrote a row", 0,
                count(c, "app_user WHERE username = 'policyuser'"));
        ok("3-character username is the minimum", svc.registerUser(c, "ali", GOOD) != null);
        ok("10-character password is the minimum",
                svc.registerUser(c, "minpw", "0123456789".toCharArray()) != null);
        ok("boundary account authenticates", svc.authenticate(c, "minpw", "0123456789".toCharArray()));
        ok("spaces are legal inside a passphrase",
                svc.registerUser(c, "spaced", "correct horse battery staple".toCharArray()) != null);
        ok("spaced passphrase authenticates",
                svc.authenticate(c, "spaced", "correct horse battery staple".toCharArray()));
    }

    private static void testHostileInputsStoredVerbatim(UserAccountService svc, Connection c)
            throws Exception {
        // Passwords are not validated for syntax, so the classic injection payloads must be inert.
        String[] payloads = {"' or '1'='1' -- ", "x'); DROP TABLE app_user; --", "1\" OR \"1\"=\"1"};
        for (int i = 0; i < payloads.length; i++) {
            String user = "inj" + i;
            svc.registerUser(c, user, payloads[i].toCharArray());
            ok("payload password authenticates: " + payloads[i],
                    svc.authenticate(c, user, payloads[i].toCharArray()));
            ok("a different password is still wrong for that account",
                    !svc.authenticate(c, user, "not the payload"));
        }
        ok("table survived the payloads", count(c, "app_user") > 3);
        ok("another account still authenticates after the payloads",
                svc.authenticate(c, "alice", GOOD));
        // A non-Latin-1 and astral-plane password must round-trip: build from code points so this
        // source file stays ASCII.
        char[] exotic = ("passphrase-" + (char) 0x00C4 + (char) 0x4E2D + "-tail"
                + new String(Character.toChars(0x1F510))).toCharArray();
        svc.registerUser(c, "unicode", exotic);
        ok("unicode password authenticates", svc.authenticate(c, "unicode", exotic));
        exotic[0] = 'X';
        ok("one unicode character off is rejected", !svc.authenticate(c, "unicode", exotic));
    }

    private static void testMalformedRowsRefused(UserAccountService svc, Connection c)
            throws Exception {
        // corrupt_src holds the same password with its own salt, and is the pristine copy that
        // each tamper is undone against. It is never tampered with.
        svc.registerUser(c, "corrupt", GOOD);
        svc.registerUser(c, "corrupt_src", GOOD);
        String restore = "UPDATE app_user SET algorithm = '" + UserAccountService.DEFAULT_ALGORITHM
                + "', iterations = " + TEST_ITERATIONS
                + ", salt = (SELECT salt FROM app_user WHERE username = 'corrupt_src'),"
                + " password_hash = (SELECT password_hash FROM app_user WHERE username = 'corrupt_src')"
                + " WHERE username = 'corrupt'";
        String[][] tamper = {
                {"iteration downgrade", "UPDATE app_user SET iterations = 1 WHERE username = 'corrupt'"},
                {"derivation bomb", "UPDATE app_user SET iterations = 999999999 WHERE username = 'corrupt'"},
                {"one-byte salt", "UPDATE app_user SET salt = X'00' WHERE username = 'corrupt'"},
                {"empty salt", "UPDATE app_user SET salt = X'' WHERE username = 'corrupt'"},
                {"truncated key", "UPDATE app_user SET password_hash = X'0011' WHERE username = 'corrupt'"},
                {"empty key", "UPDATE app_user SET password_hash = X'' WHERE username = 'corrupt'"},
                {"weak KDF named", "UPDATE app_user SET algorithm = 'MD5' WHERE username = 'corrupt'"},
                {"blank algorithm", "UPDATE app_user SET algorithm = '' WHERE username = 'corrupt'"},
                // Someone else's key with this row's own salt: the pair is inconsistent, so the row
                // must authenticate nothing at all.
                {"key copied from another account",
                        "UPDATE app_user SET password_hash = (SELECT password_hash FROM app_user"
                        + " WHERE username = 'alice') WHERE username = 'corrupt'"},
        };
        for (String[] t : tamper) {
            try (Statement st = c.createStatement()) {
                st.executeUpdate(t[1]);
            }
            // Refusal must also be *prompt*: a row that claims 999 999 999 iterations has to be
            // rejected by the bounds check rather than derived, and "it returned false eventually"
            // after minutes of CPU is the failure, not the pass.
            ok("tampered row refused promptly (" + t[0] + "): right password",
                    refusedWithin(svc, c, "corrupt", GOOD, 5_000));
            ok("tampered row refused promptly (" + t[0] + "): wrong password",
                    refusedWithin(svc, c, "corrupt", BAD, 5_000));
            try (Statement st = c.createStatement()) {
                st.executeUpdate(restore);
            }
        }
        ok("row restored to a valid shape authenticates again",
                svc.authenticate(c, "corrupt", GOOD));
        ok("restored row still rejects the wrong password",
                !svc.authenticate(c, "corrupt", BAD));
    }

    /**
     * A salt derived from the username or the password instead of the RNG keeps every functional
     * check green -- the row verifies, the key matches PBKDF2, different usernames still get
     * different salts -- so pin randomness where it is produced.
     */
    private static void testSaltIsFreshEntropyPerRegistration(UserAccountService svc, Connection c)
            throws Exception {
        svc.registerUser(c, "regen", GOOD);
        byte[] first = saltOf(c, "regen");
        ok("first registration has a non-zero salt", !allZeros(first));
        ok("delete the account to re-register the same name", svc.deleteUser(c, "regen"));
        svc.registerUser(c, "regen", GOOD);
        byte[] second = saltOf(c, "regen");
        ok("re-registering the same username with the same password draws a new salt",
                !Arrays.equals(first, second));
        ok("the salt does not encode the username",
                !new String(first, StandardCharsets.ISO_8859_1).contains("regen")
                        && !new String(second, StandardCharsets.ISO_8859_1).contains("regen"));
        ok("the salt does not encode the password",
                !new String(first, StandardCharsets.ISO_8859_1).contains("correct"));
        ok("the re-registered account authenticates", svc.authenticate(c, "regen", GOOD));
    }

    /**
     * Whether {@code authenticate} rejected the credential within the budget. {@code false} means it
     * either accepted the credential or was still deriving when the budget ran out.
     */
    private static boolean refusedWithin(UserAccountService svc, Connection c, String username,
            char[] password, long budgetMillis) throws Exception {
        final java.util.concurrent.CountDownLatch done = new java.util.concurrent.CountDownLatch(1);
        final boolean[] accepted = {true};
        Thread worker = new Thread(() -> {
            try {
                accepted[0] = svc.authenticate(c, username, password);
            } catch (SQLException e) {
                accepted[0] = true;
            } finally {
                done.countDown();
            }
        });
        worker.setDaemon(true);
        worker.start();
        // The latch return value, not Thread.isAlive(): isAlive() can still be true in the window
        // between countDown() and the worker unwinding, which reads as a timeout.
        boolean finished = done.await(budgetMillis, java.util.concurrent.TimeUnit.MILLISECONDS);
        return finished && !accepted[0];
    }

    private static byte[] saltOf(Connection c, String username) throws SQLException {
        try (java.sql.PreparedStatement ps = c.prepareStatement(
                "SELECT salt FROM app_user WHERE username = ?")) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getBytes(1);
            }
        }
    }

    /**
     * Verification must honour the parameters recorded in the row, not the service's current
     * defaults: that is what lets the work factor be raised without locking anyone out.
     */
    private static void testStoredWorkFactorIsHonoured(UserAccountService svc, Connection c)
            throws Exception {
        int legacyIterations = 20_000;
        byte[] legacySalt = new byte[16];
        new java.security.SecureRandom().nextBytes(legacySalt);
        byte[] legacyKey = referenceDerive(GOOD, legacySalt, legacyIterations,
                UserAccountService.DEFAULT_ALGORITHM, 32);
        svc.registerUser(c, "legacy", GOOD);
        try (java.sql.PreparedStatement ps = c.prepareStatement(
                "UPDATE app_user SET iterations = ?, salt = ?, password_hash = ?"
                + " WHERE username = 'legacy'")) {
            ps.setInt(1, legacyIterations);
            ps.setBytes(2, legacySalt);
            ps.setBytes(3, legacyKey);
            ps.executeUpdate();
        }
        ok("an account stored at a cheaper work factor still authenticates",
                svc.authenticate(c, "legacy", GOOD));
        ok("and still rejects the wrong password", !svc.authenticate(c, "legacy", BAD));
        ok("the service reports that the row should be upgraded",
                svc.credentialsNeedUpgrade(legacyIterations));
        ok("re-hashing at the current work factor is what fixes it",
                !svc.credentialsNeedUpgrade(svc.iterations()));
    }

    /**
     * A database failure during the insert must surface as the {@link SQLException} it is, not be
     * laundered into "username already taken". Only a class-23 SQLState is a duplicate.
     */
    private static void testUnrelatedSqlErrorIsNotADuplicate(UserAccountService svc, Connection c)
            throws Exception {
        try (Connection missing = DriverManager.getConnection("jdbc:h2:mem:noSuchTable;DB_CLOSE_DELAY=-1")) {
            Exception thrown = null;
            try {
                svc.registerUser(missing, "anyuser", GOOD);
            } catch (Exception e) {
                thrown = e;
            }
            ok("a failure with no unique constraint involved is reported", thrown != null);
            ok("  and it is not dressed up as a duplicate username",
                    !(thrown instanceof UserAccountService.DuplicateUsernameException));
            ok("  and it is a SQLException carrying a SQLState",
                    thrown instanceof SQLException && ((SQLException) thrown).getSQLState() != null);
            ok("  and that SQLState is not integrity-constraint class 23",
                    thrown instanceof SQLException
                            && !((SQLException) thrown).getSQLState().startsWith("23"));
        }
    }

    private static void testDelete(UserAccountService svc, Connection c) throws Exception {
        svc.registerUser(c, "doomed", GOOD);
        ok("delete removes the account", svc.deleteUser(c, "doomed"));
        ok("account no longer authenticates", !svc.authenticate(c, "doomed", GOOD));
        ok("second delete reports no row", !svc.deleteUser(c, "doomed"));
    }

    private static void testConcurrentDuplicate(UserAccountService svc)
            throws Exception {
        // Two real connections racing on the same username: the unique constraint, not an
        // application-side check, is what has to settle it.
        String url = "jdbc:h2:mem:race;DB_CLOSE_DELAY=-1";
        try (Connection setup = DriverManager.getConnection(url, "sa", "")) {
            svc.ensureSchema(setup);
        }
        final CountDownLatch go = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        Callable<String> racer = () -> {
            try (Connection c = DriverManager.getConnection(url, "sa", "")) {
                go.await();
                svc.registerUser(c, "racer", GOOD);
                return "registered";
            } catch (UserAccountService.DuplicateUsernameException e) {
                return "duplicate";
            }
        };
        Future<String> f1 = pool.submit(racer);
        Future<String> f2 = pool.submit(racer);
        go.countDown();
        List<String> results = Arrays.asList(f1.get(), f2.get());
        pool.shutdown();
        // Which racer wins is nondeterministic; that exactly one of each happened is not.
        List<String> sorted = new ArrayList<>(results);
        java.util.Collections.sort(sorted);
        eq("exactly one insert won and one reported a duplicate " + results,
                "[duplicate, registered]", sorted.toString());
        try (Connection c = DriverManager.getConnection(url, "sa", "")) {
            eq("exactly one row for the contested username", 1,
                    count(c, "app_user WHERE username = 'racer'"));
            ok("contested account authenticates", svc.authenticate(c, "racer", GOOD));
        }
    }

    private static void testUnknownUserCostsWhatKnownUserCosts(UserAccountService svc)
            throws Exception {
        try (Connection c = DriverManager.getConnection("jdbc:h2:mem:timing;DB_CLOSE_DELAY=-1")) {
            svc.ensureSchema(c);
            svc.registerUser(c, "timed", GOOD);
            // Warm both paths, then compare medians: an unknown username must not come back free.
            for (int i = 0; i < 3; i++) {
                svc.authenticate(c, "timed", BAD);
                svc.authenticate(c, "ghost", GOOD);
                svc.authenticate(c, "", GOOD);
            }
            long known = median(() -> svc.authenticate(c, "timed", BAD));
            long unknown = median(() -> svc.authenticate(c, "ghost", GOOD));
            long empty = median(() -> svc.authenticate(c, "", GOOD));
            long bogus = median(() -> svc.authenticate(c, "timed", "x".repeat(40).toCharArray()));
            System.out.printf("timing ms: known=%d unknown=%d empty=%d shortpw=%d%n",
                    known, unknown, empty, bogus);
            ok("known-user path really does the KDF work (" + known + " ms)", known >= 5);
            ok("unknown user costs the same as a known user (" + unknown + " vs " + known + ")",
                    unknown >= known / 2 && unknown <= known * 3);
            ok("empty username costs the same too (" + empty + " vs " + known + ")",
                    empty >= known / 2 && empty <= known * 3);
            ok("short password costs the same too (" + bogus + " vs " + known + ")",
                    bogus >= known / 2 && bogus <= known * 3);
        }
    }

    private static void testTransactionBoundaries(UserAccountService svc) throws Exception {
        Path dir = Files.createTempDirectory("uastx");
        String url = "jdbc:h2:" + dir.resolve("db").toAbsolutePath() + ";";
        try (Connection c = DriverManager.getConnection(url, "sa", "")) {
            c.setAutoCommit(false);
            svc.ensureSchema(c);
            c.commit();

            svc.registerUser(c, "pending", GOOD);
            eq("uncommitted row is visible to its own transaction", 1, count(c, "app_user"));
            ok("the service did not commit it for us: a fresh connection sees nothing",
                    freshRowCount(url) == 0);
            c.rollback();

            try (Connection other = DriverManager.getConnection(url, "sa", "")) {
                ok("rolled-back registration never became a row", count(other, "app_user") == 0);
            }

            svc.registerUser(c, "keep", GOOD);
            UserAccountService.DuplicateUsernameException dup = null;
            try {
                svc.registerUser(c, "keep", GOOD);
            } catch (UserAccountService.DuplicateUsernameException e) {
                dup = e;
            }
            ok("duplicate inside a transaction is reported", dup != null);
            ok("duplicate message names the username",
                    dup != null && dup.getMessage().contains("keep"));
            ok("duplicate is a checked exception, so callers are forced to handle it",
                    dup != null && !RuntimeException.class.isAssignableFrom(dup.getClass())
                            && Exception.class.isAssignableFrom(dup.getClass()));
            // The failed insert must not poison the transaction (PostgreSQL would abort it).
            svc.registerUser(c, "after-dup", GOOD);
            c.commit();

            try (Connection other = DriverManager.getConnection(url, "sa", "")) {
                eq("committed rows survived", 2, count(other, "app_user"));
                ok("committed account authenticates on a fresh connection",
                        svc.authenticate(other, "keep", GOOD));
                ok("post-duplicate account authenticates",
                        svc.authenticate(other, "after-dup", GOOD));
                ok("service never commits for the caller: pending is gone",
                        count(other, "app_user WHERE username = 'pending'") == 0);
            }
            ok("delete inside the transaction is rolled back", svc.deleteUser(c, "keep"));
            c.rollback();
            try (Connection other = DriverManager.getConnection(url, "sa", "")) {
                ok("rolled-back delete left the row", svc.authenticate(other, "keep", GOOD));
            }
        }
    }

    private static void testUpgradeAdvice(UserAccountService svc, Connection c) throws Exception {
        ok("shipped default work factor is current-generation",
                UserAccountService.DEFAULT_ITERATIONS >= 100_000);
        ok("shipped default salt is 128 bits", UserAccountService.DEFAULT_SALT_BYTES == 16);
        ok("shipped default key is 256 bits", UserAccountService.DEFAULT_HASH_BYTES == 32);
        ok("shipped default KDF is PBKDF2-HMAC-SHA256",
                "PBKDF2WithHmacSHA256".equals(UserAccountService.DEFAULT_ALGORITHM));
        ok("current work factor needs no upgrade", !svc.credentialsNeedUpgrade(TEST_ITERATIONS));
        ok("cheaper stored work factor is flagged", svc.credentialsNeedUpgrade(TEST_ITERATIONS - 1));
        ok("more expensive stored work factor is not flagged",
                !svc.credentialsNeedUpgrade(TEST_ITERATIONS * 2));
        expect("rejecting a non-PBKDF2 algorithm", IllegalArgumentException.class,
                () -> new UserAccountService("MD5", TEST_ITERATIONS, 16, 32));
        expect("rejecting an unavailable algorithm", IllegalArgumentException.class,
                () -> new UserAccountService("PBKDF2WithHmacNoSuchThing", TEST_ITERATIONS, 16, 32));
        expect("rejecting a trivial work factor", IllegalArgumentException.class,
                () -> new UserAccountService(UserAccountService.DEFAULT_ALGORITHM, 10, 16, 32));
        expect("rejecting a short salt", IllegalArgumentException.class,
                () -> new UserAccountService(UserAccountService.DEFAULT_ALGORITHM, TEST_ITERATIONS,
                        2, 32));
        ok("a tuned instance works end to end", tuneAndCheck());
    }

    private static boolean tuneAndCheck() throws Exception {
        UserAccountService cheap = new UserAccountService("PBKDF2WithHmacSHA1", 1_000, 8, 20);
        try (Connection c = DriverManager.getConnection("jdbc:h2:mem:tuned;DB_CLOSE_DELAY=-1")) {
            cheap.ensureSchema(c);
            cheap.registerUser(c, "tuned", GOOD);
            return cheap.authenticate(c, "tuned", GOOD) && !cheap.authenticate(c, "tuned", BAD)
                    && cheap.iterations() == 1_000;
        }
    }

    // ---------------------------------------------------------------- helpers

    private interface ThrowingCall<T> {
        T call() throws Exception;
    }

    private static <T> T expect(String what, Class<? extends Throwable> type, ThrowingCall<T> call) {
        checks++;
        try {
            call.call();
            failures.add(what + ": expected " + type.getSimpleName() + ", nothing thrown");
        } catch (Throwable t) {
            if (!type.isInstance(t)) {
                failures.add(what + ": expected " + type.getSimpleName() + ", got " + t);
            }
        }
        return null;
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

    private static int count(Connection c, String from) throws SQLException {
        try (Statement st = c.createStatement();
                ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM " + from)) {
            rs.next();
            return rs.getInt(1);
        }
    }

    /** Row count from a brand-new connection, i.e. what other transactions can see. */
    private static int freshRowCount(String url) throws SQLException {
        try (Connection c = DriverManager.getConnection(url, "sa", "")) {
            return count(c, "app_user");
        }
    }

    private static boolean allZeros(byte[] b) {
        for (byte x : b) {
            if (x != 0) {
                return false;
            }
        }
        return true;
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    /** Independent of the production code path: straight SecretKeyFactory, no shared helpers. */
    private static byte[] referenceDerive(char[] password, byte[] salt, int iterations,
            String algorithm, int hashBytes) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, hashBytes * 8);
        byte[] out = SecretKeyFactory.getInstance(algorithm).generateSecret(spec).getEncoded();
        spec.clearPassword();
        return out;
    }

    private interface Op {
        boolean run() throws Exception;
    }

    private static long median(Op op) throws Exception {
        long[] samples = new long[5];
        for (int i = 0; i < samples.length; i++) {
            long t0 = System.nanoTime();
            op.run();
            samples[i] = (System.nanoTime() - t0) / 1_000_000L;
        }
        Arrays.sort(samples);
        return samples[samples.length / 2];
    }
}
