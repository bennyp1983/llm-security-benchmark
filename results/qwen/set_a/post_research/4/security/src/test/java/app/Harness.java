package app;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

/**
 * Minimal assertion harness: no third-party test framework is pinned, so nothing here depends on
 * a jar that has not been verified against {@code deps.lock}.
 *
 * <p>Scratch directories are named after the process id, never a fixed path. A fixed path passes
 * when one suite runs and fabricates failures the moment two run at once - which is exactly what a
 * mutation battery or CI matrix does - so a "failure" would be misattributed to the code under
 * test. Directories are removed by a shutdown hook rather than at the end of {@code main}, because
 * a run that dies part-way through would otherwise leave one littered directory behind per attempt.
 */
public final class Harness {

    public static final String DB_PASSWORD = "Test-Store-Password-0123456";

    /**
     * Fixture passwords share no substring with any fixture username, so the
     * "password must not contain the account name" rule cannot silently satisfy a different
     * assertion (a fixture that trips an unrelated rule never reaches the guard under test).
     */
    public static final String PW_ONE = "Fresh-Admin-21";
    public static final String PW_TWO = "Another-Admin-7";
    public static final String PW_THREE = "Mobile-Docket-44";
    public static final String PW_WRONG = "Wrong-Invisible-5";

    private static final List<Path> SCRATCH = new ArrayList<>();
    private static final List<String> FAILURES = new ArrayList<>();
    private static final List<String> NOTES = new ArrayList<>();
    private static int checks;

    static {
        Runtime.getRuntime().addShutdownHook(new Thread(Harness::cleanScratch, "harness-cleanup"));
    }

    private Harness() {
    }

    // ------------------------------------------------------------------ assertions

    public static void check(boolean condition, String what) {
        checks++;
        if (!condition) {
            FAILURES.add(what);
            System.out.println("  FAIL  " + what);
        }
    }

    public static void equal(Object actual, Object expected, String what) {
        boolean same = expected == null ? actual == null : expected.equals(actual);
        checks++;
        if (!same) {
            FAILURES.add(what + " (expected <" + expected + "> got <" + actual + ">)");
            System.out.println("  FAIL  " + what + " (expected <" + expected + "> got <" + actual + ">)");
        }
    }

    public static void atLeast(long actual, long floor, String what) {
        checks++;
        if (actual < floor) {
            FAILURES.add(what + " (" + actual + " < " + floor + ")");
            System.out.println("  FAIL  " + what + " (" + actual + " < " + floor + ")");
        }
    }

    public static void atMost(long actual, long ceiling, String what) {
        checks++;
        if (actual > ceiling) {
            FAILURES.add(what + " (" + actual + " > " + ceiling + ")");
            System.out.println("  FAIL  " + what + " (" + actual + " > " + ceiling + ")");
        }
    }

    /** Records a measured value so README prose can be re-derived from the log, not remembered. */
    public static void note(String observation) {
        NOTES.add(observation);
        System.out.println("  NOTE  " + observation);
    }

    public static void section(String name) {
        System.out.println("-- " + name);
    }

    public static List<String> failures() {
        return FAILURES;
    }

    public static int report(String suite) {
        System.out.println("SUITE " + suite + ": " + checks + " checks, " + FAILURES.size() + " failed");
        for (String failure : FAILURES) {
            System.out.println("  FAILED  " + failure);
        }
        for (String note : NOTES) {
            System.out.println("  MEASURED  " + note);
        }
        return FAILURES.isEmpty() ? 0 : 1;
    }

    // ------------------------------------------------------------------ fixtures

    /** A private scratch directory, unique to this process, that the shutdown hook deletes. */
    public static Path scratch(String purpose) {
        try {
            Path base = Paths.get(System.getProperty("java.io.tmpdir"),
                "acctsec-" + ProcessHandle.current().pid() + "-" + purpose);
            if (!Files.exists(base)) {
                Files.createDirectories(base, PosixFilePermissions.asFileAttribute(
                    EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                        PosixFilePermission.OWNER_EXECUTE)));
                SCRATCH.add(base);
            }
            Files.setPosixFilePermissions(base, EnumSet.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE));
            return base;
        } catch (IOException cannotCreate) {
            throw new IllegalStateException("scratch directory unavailable", cannotCreate);
        }
    }

    /** Deletes a scratch directory tree; used when a test needs a clean store mid-suite. */
    public static void remove(Path directory) {
        if (directory == null || !Files.exists(directory)) {
            return;
        }
        try (java.util.stream.Stream<Path> walk = Files.walk(directory)) {
            List<Path> all = new ArrayList<>();
            walk.sorted((a, b) -> b.getNameCount() - a.getNameCount()).forEach(all::add);
            for (Path path : all) {
                try {
                    Files.setPosixFilePermissions(path, EnumSet.of(PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE));
                } catch (IOException | UnsupportedOperationException ignore) {
                    // A file we cannot chmod we also could not have created; try the delete anyway.
                }
                try {
                    Files.deleteIfExists(path);
                } catch (IOException stillThere) {
                    System.out.println("  WARN  could not delete " + path);
                }
            }
        } catch (IOException unreadable) {
            System.out.println("  WARN  could not walk " + directory);
        }
    }

    private static void cleanScratch() {
        for (Path path : SCRATCH) {
            remove(path);
        }
    }

    static void quiet(String message) {
        // Intentionally silent: keeps suite output to checks, failures and measurements.
    }

    // ------------------------------------------------------------------ wiring

    public static final int TEST_MEMORY_KIB = PasswordHasher.STORED_MIN_MEMORY_KIB;
    public static final int TEST_ITERATIONS = PasswordHasher.STORED_MIN_ITERATIONS;
    public static final int TEST_PARALLELISM = 1;

    /** Fixed start time for the controllable clock, so windows are deterministic. */
    public static final long BASE_EPOCH = 1_700_000_000L;

    /**
     * A fixture in a directory of its own. Sections inside a suite must not inherit another
     * section's lockout or budget state, or a passing assertion can be satisfied by leftover
     * throttle rows instead of by the code under test.
     */
    public static Fixture freshFixture(String purpose) {
        Path directory = scratch(purpose);
        remove(directory);
        return fixture(directory, new MutableClock(BASE_EPOCH));
    }

    public static PasswordHasher hasher() {
        try {
            return new PasswordHasher(TEST_MEMORY_KIB, TEST_ITERATIONS, TEST_PARALLELISM);
        } catch (java.security.GeneralSecurityException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    /** Opens a store in the given directory, creating the schema, with the database password erased. */
    public static Fixture fixture(Path dataDir, MutableClock clock) {
        try {
            Config.ensurePrivateDirectory(dataDir);
            Config.ensurePrivateStoreFile(dataDir.resolve("accounts"));
            Properties props = new Properties();
            props.setProperty("user", "app");
            props.setProperty("password", DB_PASSWORD);
            Connection connection = DriverManager.getConnection(
                "jdbc:h2:file:" + dataDir.resolve("accounts")
                    + ";DB_CLOSE_ON_EXIT=FALSE;AUTO_SERVER=FALSE;TRACE_LEVEL_FILE=0", props);
            Db db = new Db(connection);
            db.applySchema();
            PasswordHasher hasher = hasher();
            AuditLog audit = new AuditLog(dataDir.resolve("audit.log"));
            Gate gate = new Gate(audit);
            Throttle throttle = new Throttle(db, clock);
            AccountStore accounts = new AccountStore(db, hasher, throttle, gate, clock);
            SessionStore sessions = new SessionStore(db, gate, clock);
            AuthService auth = new AuthService(accounts, throttle, sessions, hasher, gate, clock);
            return new Fixture(db, audit, gate, throttle, accounts, sessions, auth, hasher, clock, dataDir);
        } catch (SQLException | Config.ConfigException failed) {
            throw new IllegalStateException("fixture could not be built", failed);
        }
    }

    /** Everything a test needs, wired to one store and one controllable clock. */
    public record Fixture(Db db, AuditLog audit, Gate gate, Throttle throttle, AccountStore accounts,
        SessionStore sessions, AuthService auth, PasswordHasher hasher, MutableClock clock, Path dataDir) {

        public void close() {
            db.close();
        }
    }

    /** Clock the test advances, so lockout windows and expiry are exercised without sleeping. */
    public static final class MutableClock extends Clock {
        private Instant now;

        public MutableClock(long epochSeconds) {
            this.now = Instant.ofEpochSecond(epochSeconds);
        }

        public void advanceSeconds(long seconds) {
            now = now.plusSeconds(seconds);
        }

        public void setEpochSeconds(long epochSeconds) {
            now = Instant.ofEpochSecond(epochSeconds);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    // ------------------------------------------------------------------ helpers

    public static Set<PosixFilePermission> permissionsOf(Path path) throws IOException {
        return Files.getPosixFilePermissions(path);
    }

    public static String permissionString(Path path) throws IOException {
        return PosixFilePermissions.toString(Files.getPosixFilePermissions(path));
    }

    public static final Set<PosixFilePermission> OWNER_ONLY = EnumSet.of(
        PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

    public static char[] chars(String value) {
        return value.toCharArray();
    }

    /** Asserts that a password fixture is accepted, then erases it the way the CLI would. */
    public static void password(char[] value) {
        try {
            InputPolicy.password(value);
            check(true, "the password fixture passes the policy");
        } catch (InputPolicy.ValidationException refused) {
            check(false, "the password fixture should have been accepted: " + refused.getMessage());
        } finally {
            java.util.Arrays.fill(value, '\0');
        }
    }

    /** Runs a body, erasing the buffers afterwards, and returns whatever it produced. */
    public static <T> T withSecrets(String password, java.util.function.Supplier<T> body) {
        char[] buffer = chars(password);
        try {
            return body.get();
        } finally {
            java.util.Arrays.fill(buffer, '\0');
        }
    }

    public static String register(Fixture fixture, String email, String username, String password)
        throws SQLException, AuditLog.AuditException, InputPolicy.ValidationException {
        String canonicalEmail = InputPolicy.email(chars(email));
        String canonicalUsername = InputPolicy.username(chars(username));
        char[] buffer = chars(password);
        try {
            return fixture.accounts().register(buffer, canonicalEmail, canonicalUsername, "src-" + username).message();
        } finally {
            java.util.Arrays.fill(buffer, '\0');
        }
    }

    /**
     * Registers with an explicit source key. Rate-limit matrices need one account and many
     * attempts; if every attempt shared a source key the per-source budget would answer first and
     * the guard under test would never run, so those tests spread attempts across sources.
     */
    public static AccountStore.RegisterStatus registerStatus(Fixture fixture, String email, String username,
        String password, String sourceId)
        throws SQLException, AuditLog.AuditException, InputPolicy.ValidationException {
        String canonicalEmail = InputPolicy.email(chars(email));
        String canonicalUsername = InputPolicy.username(chars(username));
        char[] buffer = chars(password);
        try {
            return fixture.accounts().register(buffer, canonicalEmail, canonicalUsername, sourceId).status();
        } finally {
            java.util.Arrays.fill(buffer, '\0');
        }
    }

    public static AuthService.Result login(Fixture fixture, String identifier, String password) {
        char[] identifierBuffer = chars(identifier);
        char[] passwordBuffer = chars(password);
        try {
            return fixture.auth().login(identifierBuffer, passwordBuffer, "src-" + identifier);
        } finally {
            java.util.Arrays.fill(identifierBuffer, '\0');
            java.util.Arrays.fill(passwordBuffer, '\0');
        }
    }

    /** Second argument is the source key, so a test can drive the per-source budget directly. */
    public static AuthService.Result loginFrom(Fixture fixture, String identifier, String password,
        String sourceId) {
        char[] identifierBuffer = chars(identifier);
        char[] passwordBuffer = chars(password);
        try {
            return fixture.auth().login(identifierBuffer, passwordBuffer, sourceId);
        } finally {
            java.util.Arrays.fill(identifierBuffer, '\0');
            java.util.Arrays.fill(passwordBuffer, '\0');
        }
    }

    public static List<String> auditLines(Fixture fixture) throws IOException {
        List<String> lines = fixture.audit().readAll();
        return lines;
    }

    /** Guards against a vacuous pass: an absence assertion over an empty capture proves nothing. */
    public static void requireNotEmpty(List<?> captured, String what) {
        check(!captured.isEmpty(), what + " (capture must not be empty or the check is vacuous)");
    }

    public static void requireNotEmpty(String captured, String what) {
        check(captured != null && !captured.isEmpty(), what + " (capture must not be empty)");
    }
}
