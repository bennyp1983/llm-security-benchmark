package com.example.identity;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Test harness: fixtures, assertions, scratch-space discipline, subprocess execution.
 *
 * <p>Three rules here are load-bearing for the *trustworthiness of the results*, not for the code
 * under test, and each is the residue of a suite that once went green for the wrong reason:
 *
 * <ul>
 *   <li><b>Scratch space is private to the run.</b> Paths are scoped by pid. A fixed
 *     {@code /tmp/portal-test/} path passes alone and fabricates failures the moment two copies run
 *     at once (a mutation battery, a CI matrix): one process bootstraps an account the other deleted,
 *     and the report attributes a real failure to the wrong check. The ancestors must also be
 *     non-world-writable, because {@link Config} refuses a world-writable ancestor and would
 *     otherwise fail every test for a reason unrelated to the one under test.</li>
 *   <li><b>Cleanup runs from a shutdown hook.</b> Suites that fail an assertion or get killed
 *     (mutation runs do both routinely) never reach the last line of {@code main}, so cleanup
 *     registered there would never run and each aborted mutant leaves a littered directory.</li>
 *   <li><b>Absence assertions require a non-empty capture.</b> {@code assertFalse(captured.isEmpty()
 *     || captured.contains("x"))} passes when the capture helper silently captured nothing. Every
 *     "does not contain" check here first asserts the corpus it scanned had content.</li>
 * </ul>
 */
public final class Harness {

    private Harness() {
    }

    // ---------------------------------------------------------------- reporting

    private static final List<String> failures = new ArrayList<>();
    private static final List<String> notes = new ArrayList<>();
    private static int checks;
    private static String section = "(none)";

    public static void section(String name) {
        section = name;
        System.out.println("\n== " + name + " ==");
    }

    public static void check(String what, boolean condition) {
        checks++;
        if (condition) {
            System.out.println("  PASS  " + what);
        } else {
            System.out.println("  FAIL  " + what + "   [" + section + "]");
            failures.add(section + " :: " + what);
        }
    }

    /** Records an expected value with the actual, so a mismatch is diagnosable from the log. */
    public static void checkEquals(String what, Object expected, Object actual) {
        checks++;
        boolean ok = expected == null ? actual == null : expected.equals(actual);
        if (ok) {
            System.out.println("  PASS  " + what);
        } else {
            System.out.println("  FAIL  " + what + "\n          expected: " + expected
                    + "\n          actual:   " + actual + "   [" + section + "]");
            failures.add(section + " :: " + what + " (expected <" + expected + "> got <" + actual + ">)");
        }
    }

    /**
     * Asserts a value is absent from a corpus <em>and</em> that the corpus was actually populated.
     * Without the second half, a broken capture silently turns every leak check into a pass.
     */
    public static void checkAbsent(String what, CharSequence haystack, String needle) {
        check(what + " (corpus is non-empty)", haystack != null && haystack.length() > 0);
        check(what, haystack != null && !haystack.toString().contains(needle));
    }

    public static void note(String n) {
        notes.add(n);
        System.out.println("  NOTE  " + n);
    }

    public static int failureCount() {
        return failures.size();
    }

    public static int checkCount() {
        return checks;
    }

    public static List<String> failures() {
        return List.copyOf(failures);
    }

    public static List<String> notes() {
        return List.copyOf(notes);
    }

    public static void printSummary() {
        System.out.println("\n=================================");
        System.out.println("SUMMARY checks=" + checks + " failures=" + failures.size());
        for (String f : failures) {
            System.out.println("FAILED  " + f);
        }
        System.out.println("=================================");
        for (String n : notes) {
            System.out.println("NOTE  " + n);
        }
    }

    /** Throws so a suite that failed cannot be mistaken for one that passed. */
    public static void requireGreen() {
        if (!failures.isEmpty()) {
            throw new AssertionError(failures.size() + " check(s) failed; see the FAIL lines above");
        }
    }

    // ---------------------------------------------------------------- scratch space

    private static Path scratchRoot;

    /**
     * A per-pid directory whose whole ancestor chain is private. Created 0700 and verified.
     */
    public static synchronized Path scratch(String name) {
        if (scratchRoot == null) {
            scratchRoot = resolvePrivateScratchRoot();
            Path root = scratchRoot;
            Runtime.getRuntime().addShutdownHook(new Thread(() -> deleteRecursively(root), "scratch-cleanup"));
        }
        Path dir = scratchRoot.resolve(name + "-" + ProcessHandle.current().pid());
        deleteRecursively(dir);
        try {
            Files.createDirectories(dir, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                    Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                            PosixFilePermission.OWNER_EXECUTE)));
            Files.setPosixFilePermissions(dir, Set.of(PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE));
        } catch (IOException e) {
            throw new IllegalStateException("cannot create scratch directory " + dir, e);
        }
        return dir;
    }

    private static Path resolvePrivateScratchRoot() {
        String override = System.getProperty("portal.test.scratch");
        List<Path> candidates = new ArrayList<>();
        if (override != null && !override.isBlank()) {
            candidates.add(Path.of(override));
        }
        candidates.add(Path.of(System.getProperty("user.home", "/root"), ".portal-test-scratch"));
        for (Path c : candidates) {
            if (ancestorsPrivate(c)) {
                try {
                    Files.createDirectories(c);
                    Files.setPosixFilePermissions(c, Set.of(PosixFilePermission.OWNER_READ,
                            PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE));
                    return c;
                } catch (IOException ignored) {
                    // try the next candidate
                }
            }
        }
        throw new IllegalStateException("no private scratch root available: the tests need a"
                + " directory whose ancestors are not world-writable, because Config legitimately"
                + " refuses a world-writable ancestor. Pass -Dportal.test.scratch=<path>.");
    }

    /**
     * True when no existing component of the path is world-writable.
     *
     * <p>World-<em>writable</em> is the property {@link Config} refuses, because that is where
     * another account can plant a file we are about to open. World-<em>readable</em> is not a
     * hazard for a directory we are about to create our own 0700 files inside - and refusing it
     * would be unfalsifiable rather than strict: {@code /} is 0755 on every Linux install, so a
     * check on readability rejects every path on the machine and the harness reports "no private
     * scratch root" instead of running the suite.
     */
    private static boolean ancestorsPrivate(Path p) {
        Path absolute = p.toAbsolutePath().normalize();
        Path cursor = absolute.getRoot();
        for (Path seg : absolute) {
            cursor = cursor.resolve(seg);
            if (Files.exists(cursor)) {
                Set<PosixFilePermission> perms;
                try {
                    perms = Files.getPosixFilePermissions(cursor);
                } catch (IOException | UnsupportedOperationException e) {
                    return false;
                }
                if (perms.contains(PosixFilePermission.OTHERS_WRITE)) {
                    return false;
                }
            }
        }
        return true;
    }

    static void deleteRecursively(Path dir) {
        if (dir == null || !Files.exists(dir)) {
            return;
        }
        try {
            Files.walkFileTree(dir, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, java.nio.file.attribute.BasicFileAttributes attrs)
                        throws IOException {
                    try {
                        Files.setPosixFilePermissions(file, Set.of(PosixFilePermission.OWNER_WRITE,
                                PosixFilePermission.OWNER_READ));
                    } catch (IOException | UnsupportedOperationException ignored) {
                        // Best effort: some fixtures are deliberately unwritable.
                    }
                    Files.deleteIfExists(file);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path d, IOException exc) throws IOException {
                    Files.deleteIfExists(d);
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            System.err.println("warning: could not clean scratch directory " + dir);
        }
    }

    // ---------------------------------------------------------------- fixtures

    /**
     * Fixture passwords, from a fixed pool that shares no substring with any fixture username.
     *
     * <p>A strength rule of the form "must not contain the username" (or any future rule keyed on
     * identity) would otherwise reject the fixture before the guard under test ever ran, and the
     * failure would surface as an unrelated check.
     */
    public static final String P1 = "Fresh-Admin-21";
    public static final String P2 = "Another-Admin-7";
    public static final String P3 = "Zephyr-Vector-5";
    public static final String P4 = "Quiet-Lantern-44";
    /** 10 code points, exactly the policy minimum. */
    public static final String P_MIN = "Ab1-defghi";
    /** 9 code points, exactly one below the policy minimum. */
    public static final String P_BELOW_MIN = "Ab1-defgh";

    public static final String U1 = "alice";
    public static final String U2 = "bob";
    public static final String U3 = "carol";
    public static final String U4 = "dave";
    public static final String E1 = "alice@example.com";
    public static final String E2 = "bob@example.com";
    public static final String E3 = "carol@example.com";
    public static final String E4 = "dave@example.com";

    /** Not a credential anywhere in the suite; used for leak assertions. */
    public static final String CANARY = "Canary-9f3c1a7e-Secret";

    public static char[] chars(String s) {
        return s.toCharArray();
    }

    // ---------------------------------------------------------------- config fixtures

    /**
     * Writes a valid, private configuration file for a test, and returns the data directory.
     *
     * <p>Every knob is parameterised because tests of the limiter need different budgets; the
     * defaults are chosen so a <em>functional</em> matrix (many registrations, many failures) does
     * not trip the throttle by accident. A test that wants the throttle to engage says so.
     */
    public static final class Fixture {
        public final Path dir;
        public final Path configFile;
        public final Config config;
        public final TimeSource.Fake clock;

        private Fixture(Path dir, Path configFile, Config config, TimeSource.Fake clock) {
            this.dir = dir;
            this.configFile = configFile;
            this.config = config;
            this.clock = clock;
        }
    }

    public static Fixture fixture(String name) throws Exception {
        return fixture(name, Overrides.defaults());
    }

    public static Overrides overrides() {
        return new Overrides();
    }

    public static final class Overrides {
        public int iterations = 100_000; // the accepted floor; keeps the suite fast
        public int minIterations = 100_000;
        public int maxAccounts = 1000;
        public int sessionTtl = 900;
        public int maxSessions = 3;
        public int authWindow = 900;
        public int authSourceMax = 1000;   // deliberately huge: matrices must not trip it
        public int authAccountMax = 1000;
        public int penaltyCeiling = 300;
        public int regWindow = 3600;
        public int regSourceMax = 1000;
        public int regGlobalMax = 1000;
        public long auditMaxBytes = 8_388_608;

        static Overrides defaults() {
            return new Overrides();
        }
    }

    public static Fixture fixture(String name, Overrides o) throws Exception {
        Path dir = scratch(name);
        Path cfg = dir.resolve("identity.properties");
        Files.writeString(cfg, configText(o, dir), StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(cfg, Set.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE));
        Config config = Config.load(cfg, () -> PASSPHRASE);
        TimeSource.Fake clock = new TimeSource.Fake(1_700_000_000L);
        return new Fixture(dir, cfg, config, clock);
    }

    /** The passphrase every fixture uses; also the value {@link #runCli} passes in the environment. */
    public static final String PASSPHRASE = "Fixture-Passphrase-For-Tests-Only-7f2a";

    /**
     * The full properties text for a fixture, spelled once so {@code ConfigTest} can negate one key
     * at a time out of exactly the text a working fixture is built from.
     */
    public static String configText(Overrides o, Path dir) {
        StringBuilder sb = new StringBuilder();
        sb.append("db.dataDir=").append(dir).append('\n')
          .append("db.name=identity\n")
          .append("security.pbkdf2Iterations=").append(o.iterations).append('\n')
          .append("security.pbkdf2MinIterations=").append(o.minIterations).append('\n')
          .append("limits.maxAccounts=").append(o.maxAccounts).append('\n')
          .append("limits.sessionTtlSeconds=").append(o.sessionTtl).append('\n')
          .append("limits.maxSessionsPerAccount=").append(o.maxSessions).append('\n')
          .append("limits.authWindowSeconds=").append(o.authWindow).append('\n')
          .append("limits.authSourceMaxAttempts=").append(o.authSourceMax).append('\n')
          .append("limits.authAccountMaxAttempts=").append(o.authAccountMax).append('\n')
          .append("limits.authPenaltyCeilingSeconds=").append(o.penaltyCeiling).append('\n')
          .append("limits.registerWindowSeconds=").append(o.regWindow).append('\n')
          .append("limits.registerSourceMax=").append(o.regSourceMax).append('\n')
          .append("limits.registerGlobalMax=").append(o.regGlobalMax).append('\n')
          .append("audit.maxBytes=").append(o.auditMaxBytes).append('\n')
          .append("audit.requirePrivateFile=true\n");
        return sb.toString();
    }

    /**
     * A live API over a fresh database. Closed by the caller; {@link #openApi} registers the store
     * for shutdown cleanup too, so an aborted test does not hold the database file open.
     */
    public static Bundle openApi(Fixture f) throws Exception {
        SqlIdentityStore store = SqlIdentityStore.open(f.config, f.clock);
        AuditLog audit = new AuditLog(f.config);
        PasswordHasher hasher = new PasswordHasher(f.config);
        AuthApi api = new AuthApi(store, hasher, audit, f.config, f.clock);
        return new Bundle(f, store, audit, hasher, api);
    }

    public static final class Bundle implements AutoCloseable {
        public final Fixture fixture;
        public final SqlIdentityStore store;
        public final AuditLog audit;
        public final PasswordHasher hasher;
        public final AuthApi api;

        private Bundle(Fixture f, SqlIdentityStore s, AuditLog a, PasswordHasher h, AuthApi api) {
            this.fixture = f;
            this.store = s;
            this.audit = a;
            this.hasher = h;
            this.api = api;
        }

        @Override
        public void close() {
            api.close();
        }
    }

    /** Registers an account and asserts it succeeded, so later checks are not testing air. */
    public static void register(Bundle b, String email, String username, String password)
            throws IdentityStoreException {
        AuthResult r = b.api.register(email, username, chars(password), SourceId.LOCAL);
        if (!r.isSuccess()) {
            throw new IllegalStateException("fixture registration failed for " + username + ": " + r.reason());
        }
    }

    // ---------------------------------------------------------------- subprocess

    public record ProcResult(int exit, String stdout, String stderr) {
    }

    /**
     * Runs the real CLI in a fresh JVM.
     *
     * <p>Used wherever the property under test <em>is</em> cross-process: a stored credential that
     * reloads wrong, a passphrase that must not appear in {@code /proc/self/cmdline}, an exit code.
     * {@code stdin} is written and closed; a child that is not fed a closed stdin hangs waiting for
     * the third line, and the failure looks like a timeout rather than a bug.
     */
    public static ProcResult runCli(List<String> args, String stdin, Path configPath,
                                    String dbPasswordEnv) throws Exception {
        List<String> cmd = cliCommand(args, configPath);
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.environment().put(Config.ENV_DB_PASSWORD, dbPasswordEnv);
        Process p = pb.start();
        try (PrintStream in = new PrintStream(p.getOutputStream(), true, StandardCharsets.UTF_8)) {
            if (stdin != null) {
                in.print(stdin);
            }
            in.flush();
        }
        String out = readFully(p.getInputStream());
        String err = readFully(p.getErrorStream());
        if (!p.waitFor(180, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            throw new IllegalStateException("child process timed out: " + cmd);
        }
        return new ProcResult(p.exitValue(), out, err);
    }

    private static String classpathForChild() {
        String cp = System.getProperty("java.class.path");
        // The test JVM is launched with lib/h2.jar:bin:build/test-classes already on its classpath;
        // the child needs the same, which is what we forward.
        return cp;
    }

    /**
     * The whole command line for a child JVM: java, classpath, config pointer, {@code mainClass}, then
     * the arguments. The main class is mandatory - without it the JVM takes the first argument as the
     * class name and dies with "Could not find or load main class register", which every child in the
     * cross-process suite would report as exit=1 with empty output.
     */
    private static List<String> childCommand(String mainClass, List<String> args, Path configPath) {
        List<String> cmd = new ArrayList<>();
        cmd.add(System.getProperty("java.home") + "/bin/java");
        cmd.add("-cp");
        cmd.add(classpathForChild());
        cmd.add("-Dportal.config=" + configPath.toAbsolutePath());
        cmd.add(mainClass);
        cmd.addAll(args);
        return cmd;
    }

    private static List<String> cliCommand(List<String> args, Path configPath) {
        return childCommand(PortalCli.class.getName(), args, configPath);
    }

    /**
     * Starts a child JVM and returns it immediately, without waiting.
     *
     * <p>For the claims that need two processes alive <em>at the same time</em> - whether a second
     * writer can reach the same database file while the first one holds it. Reading the child's
     * single-word answer is the caller's job; its output is a line, so the pipe never fills.
     */
    public static Process startChild(String mainClass, Path configPath, String dbPasswordEnv)
            throws java.io.IOException {
        ProcessBuilder pb = new ProcessBuilder(childCommand(mainClass, List.of(), configPath));
        pb.environment().put(Config.ENV_DB_PASSWORD, dbPasswordEnv);
        Process p = pb.start();
        p.getOutputStream().close();
        return p;
    }

    /** What a *live* process exposes to any other local account. */
    public record LiveChild(List<String> argv, Map<String, String> environ, long pid) {
    }

    /**
     * Starts the real CLI, leaves it blocked waiting for input, and reads its {@code /proc/<pid>}
     * entries while it runs.
     *
     * <p>This is the only way to assert the argv discipline rather than merely intend it: once the
     * child exits, {@code /proc/<pid>} is gone and the claim "no secret in the command line" is
     * unfalsifiable. stdin is deliberately left open so the process is still alive when the entries
     * are read, and is closed afterwards so the child sees EOF and finishes.
     */
    public static LiveChild inspectLiveChild(List<String> args, Path configPath, String dbPasswordEnv)
            throws Exception {
        List<String> cmd = cliCommand(args, configPath);
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.environment().put(Config.ENV_DB_PASSWORD, dbPasswordEnv);
        Process p = pb.start();
        try {
            Path pid = Path.of("/proc/" + p.pid());
            long deadline = System.nanoTime() + 20_000_000_000L;
            while (!Files.isDirectory(pid) && System.nanoTime() < deadline) {
                Thread.sleep(20L);
            }
            List<String> argv = readNulList(Path.of("/proc/" + p.pid() + "/cmdline"));
            Map<String, String> environ = new java.util.LinkedHashMap<>();
            for (String entry : readNulList(Path.of("/proc/" + p.pid() + "/environ"))) {
                int eq = entry.indexOf('=');
                if (eq > 0) {
                    environ.put(entry.substring(0, eq), entry.substring(eq + 1));
                }
            }
            return new LiveChild(argv, environ, p.pid());
        } finally {
            p.getOutputStream().close();
            p.getInputStream().transferTo(java.io.OutputStream.nullOutputStream());
            p.getErrorStream().transferTo(java.io.OutputStream.nullOutputStream());
            if (!p.waitFor(60, TimeUnit.SECONDS)) {
                p.destroyForcibly();
            }
        }
    }

    private static List<String> readNulList(Path file) throws IOException {
        byte[] raw = Files.readAllBytes(file);
        List<String> out = new ArrayList<>();
        int start = 0;
        for (int i = 0; i < raw.length; i++) {
            if (raw[i] == 0) {
                if (i > start) {
                    out.add(new String(raw, start, i - start, StandardCharsets.UTF_8));
                }
                start = i + 1;
            }
        }
        if (start < raw.length) {
            out.add(new String(raw, start, raw.length - start, StandardCharsets.UTF_8));
        }
        return out;
    }

    /**
     * Concatenates every text sink under a directory, skipping the database file. Leak assertions
     * need a corpus, and a corpus that silently came back empty turns every absence check into a
     * pass - callers must pair this with a non-empty check.
     */
    public static String scanTextFiles(Path dir) {
        StringBuilder sb = new StringBuilder();
        if (!Files.isDirectory(dir)) {
            return "";
        }
        try {
            Files.walkFileTree(dir, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, java.nio.file.attribute.BasicFileAttributes a) {
                    String name = file.getFileName().toString();
                    // The database legitimately holds salt and digest; the claim under test is about
                    // text sinks - logs, stdout captures, config.
                    if (name.endsWith(".mv.db")) {
                        return FileVisitResult.CONTINUE;
                    }
                    try {
                        sb.append(new String(Files.readAllBytes(file), StandardCharsets.UTF_8));
                    } catch (IOException ignored) {
                        // Unreadable files are not part of the corpus; the caller asserts it is not
                        // empty, so a silent nothing cannot pass a check.
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult preVisitDirectory(Path d, java.nio.file.attribute.BasicFileAttributes a) {
                    if (Files.isSymbolicLink(d)) {
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            return sb.toString();
        }
        return sb.toString();
    }

    /**
     * A second, raw JDBC connection to a fixture's database, for asserting on the <em>stored</em>
     * shape (what a stolen backup would contain) rather than on what the Java accessors choose to
     * expose. Same-process connections share H2's file lock, so this does not conflict with the
     * store the fixture already has open.
     *
     * <p>{@code DB_CLOSE_DELAY=0} so that closing this probe also releases the database. With
     * {@code -1} the probe would leave the engine open in this JVM after the connection was closed -
     * holding the exclusive file lock with nobody attached - and every later CLI child would be
     * refused the store, which reads as "cross-process login is broken" rather than as a harness bug.
     */
    public static java.sql.Connection rawConnection(Fixture f) throws java.sql.SQLException {
        String file = f.config.dataDir().resolve(f.config.databaseName()).toAbsolutePath().toString();
        java.util.Properties p = new java.util.Properties();
        p.setProperty("user", "SA");
        p.setProperty("password", new String(f.config.databasePassword()));
        return java.sql.DriverManager.getConnection(
                "jdbc:h2:file:" + file + ";AUTO_SERVER=FALSE;DB_CLOSE_DELAY=0;LOCK_TIMEOUT=5000", p);
    }

    /** Executes one statement and returns the first column of every row, as text. */
    public static List<String> rawColumn(Fixture f, String sql) throws Exception {
        try (java.sql.Connection c = rawConnection(f);
             java.sql.Statement s = c.createStatement();
             java.sql.ResultSet rs = s.executeQuery(sql)) {
            List<String> out = new ArrayList<>();
            while (rs.next()) {
                out.add(rs.getString(1));
            }
            return out;
        }
    }

    /**
     * Executes one writing statement as a second connection would - i.e. as whoever stole the file
     * or talked their way into a SQL console would. Tests use it to install a row the application's
     * own writers would never produce, which is the only way to exercise the re-validation guards.
     */
    public static int rawExecute(Fixture f, String sql) throws Exception {
        try (java.sql.Connection c = rawConnection(f);
             java.sql.Statement s = c.createStatement()) {
            return s.executeUpdate(sql);
        }
    }

    /** Row count straight from the table, bypassing every accessor in the code under test. */
    public static int rawCount(Fixture f, String table) throws Exception {
        if (!table.matches("[a-z_]+")) {
            throw new IllegalArgumentException("table name must be a plain identifier: " + table);
        }
        try (java.sql.Connection c = rawConnection(f);
             java.sql.Statement s = c.createStatement();
             java.sql.ResultSet rs = s.executeQuery("SELECT COUNT(*) FROM " + table)) {
            return rs.next() ? rs.getInt(1) : -1;
        }
    }

    /**
     * Invokes a private static method and reads its {@code int} result.
     *
     * <p>Reserved for the handful of guards whose dangerous inputs are unreachable through the
     * public API - a counter value the configuration ceiling stops you from ever storing, for
     * instance. Reaching them any other way means the test is asserting something the production
     * path never exercises; using them means it asserts the arithmetic itself. Fails loudly if the
     * method has been renamed or its signature changed, so this cannot rot into a no-op.
     */
    public static int reflectionInt(Class<?> owner, String method, Class<?>[] paramTypes,
                                    Object[] args) throws Exception {
        java.lang.reflect.Method m = owner.getDeclaredMethod(method, paramTypes);
        m.setAccessible(true);
        Object result = m.invoke(null, args);
        if (!(result instanceof Integer)) {
            throw new IllegalStateException(owner.getSimpleName() + "." + method
                    + " did not return an int: " + result);
        }
        return (Integer) result;
    }

    // ---------------------------------------------------------------- source-text guards

    /**
     * Reads a production source file so a check can be made on <em>structure</em> rather than on
     * behaviour that a timed test would only sometimes falsify. Located explicitly by
     * {@code tools/run-tests.sh}; a missing file is a failure, not a skip - a guard that silently
     * stops running is worse than no guard.
     */
    public static String sourceOf(String simpleClassName) {
        Path base = sourceRoot();
        Path file = base.resolve(simpleClassName + ".java");
        if (!Files.isRegularFile(file)) {
            throw new IllegalStateException("cannot read the source of " + simpleClassName + " at " + file
                    + "; structural guards must not silently become skips");
        }
        try {
            String text = Files.readString(file, StandardCharsets.UTF_8);
            if (text.isBlank()) {
                throw new IllegalStateException("source file " + file + " is empty");
            }
            return text;
        } catch (IOException e) {
            throw new IllegalStateException("cannot read " + file, e);
        }
    }

    private static Path sourceRoot() {
        String override = System.getProperty("portal.src");
        if (override != null && !override.isBlank()) {
            return Path.of(override).toAbsolutePath().normalize();
        }
        Path repo = repoRoot();
        return repo.resolve("src/main/java/com/example/identity");
    }

    /**
     * The repository root, located from an anchor file rather than from the working directory, so
     * the suite can be launched from anywhere. Absent is a failure for whoever needs it, never a
     * silent skip.
     */
    public static Path repoFile(String relative) {
        Path p = repoRoot().resolve(relative);
        return Files.isRegularFile(p) ? p : null;
    }

    private static Path repoRoot() {
        String override = System.getProperty("portal.repo");
        if (override != null && !override.isBlank()) {
            return Path.of(override).toAbsolutePath().normalize();
        }
        Path cursor = Path.of(System.getProperty("user.dir", ".")).toAbsolutePath().normalize();
        for (int i = 0; i < 6 && cursor != null; i++) {
            if (Files.isRegularFile(cursor.resolve("deps.lock"))
                    && Files.isDirectory(cursor.resolve("src/main/java/com/example/identity"))) {
                return cursor;
            }
            cursor = cursor.getParent();
        }
        throw new IllegalStateException("cannot locate the repository root (looked for deps.lock);"
                + " run the suite via tools/run-tests.sh or pass -Dportal.repo=<dir>");
    }

    /**
     * Removes <em>comments</em> from Java source and nothing else, so a pattern guard matches code
     * and cannot be satisfied (or defeated) by prose. Literal-aware in both directions: a {@code //}
     * inside a string must not start a comment, and an escaped quote must not end one. String
     * literals are kept verbatim because the SQL shapes the guards look for live inside them.
     */
    public static String stripJavaComments(String source) {
        StringBuilder out = new StringBuilder(source.length());
        int i = 0;
        int n = source.length();
        while (i < n) {
            char c = source.charAt(i);
            if (c == '/' && i + 1 < n && source.charAt(i + 1) == '/') {
                while (i < n && source.charAt(i) != '\n') {
                    i++;
                }
                continue;
            }
            if (c == '/' && i + 1 < n && source.charAt(i + 1) == '*') {
                i += 2;
                while (i + 1 < n && !(source.charAt(i) == '*' && source.charAt(i + 1) == '/')) {
                    i++;
                }
                i += 2;
                out.append(' ');
                continue;
            }
            if (c == '"' && isTextBlockStart(source, i)) {
                int end = i + 3;
                while (end + 2 < n && !(source.charAt(end) == '"' && source.charAt(end + 1) == '"'
                        && source.charAt(end + 2) == '"')) {
                    end++;
                }
                out.append(source, i, Math.min(end + 3, n));
                i = end + 3;
                continue;
            }
            if (c == '"' || c == '\'') {
                char quote = c;
                int end = i + 1;
                while (end < n) {
                    if (source.charAt(end) == '\\') {
                        end += 2;
                        continue;
                    }
                    if (source.charAt(end) == quote) {
                        break;
                    }
                    end++;
                }
                out.append(source, i, Math.min(end + 1, n));
                i = end + 1;
                continue;
            }
            out.append(c);
            i++;
        }
        return out.toString();
    }

    private static boolean isTextBlockStart(String source, int i) {
        return i + 2 < source.length() && source.charAt(i + 1) == '"' && source.charAt(i + 2) == '"';
    }

    /** The body of one method, by name, from comment-stripped source. Best-effort brace matching. */
    public static String methodBody(String strippedSource, String methodName) {
        int decl = strippedSource.indexOf(" " + methodName + "(");
        while (decl >= 0) {
            int open = strippedSource.indexOf('{', decl);
            if (open < 0) {
                return "";
            }
            int depth = 0;
            for (int i = open; i < strippedSource.length(); i++) {
                char c = strippedSource.charAt(i);
                if (c == '{') {
                    depth++;
                } else if (c == '}') {
                    depth--;
                    if (depth == 0) {
                        return strippedSource.substring(decl, i + 1);
                    }
                }
            }
            return "";
        }
        return "";
    }

    private static String readFully(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        in.transferTo(buf);
        return buf.toString(StandardCharsets.UTF_8);
    }

    // ---------------------------------------------------------------- misc

    public static Set<String> distinct(List<String> values) {
        return new LinkedHashSet<>(values);
    }

    public static String repeat(String s, int n) {
        return s.repeat(n);
    }

    public static boolean allZero(char[] a) {
        for (char c : a) {
            if (c != 0) {
                return false;
            }
        }
        return true;
    }

    /** The password fixtures must never appear in an output corpus. */
    public static List<String> secretCanaries() {
        return List.of(P1, P2, P3, P4, P_MIN, P_BELOW_MIN, CANARY);
    }

    public static Set<PosixFilePermission> ownerReadWriteOnly() {
        return Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
    }

    public static Set<PosixFilePermission> ownerOnlyDir() {
        return Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE);
    }

    /** Microseconds, not milliseconds: at 100k iterations every path prints "1 ms" and the ratio is noise. */
    public static double micros(Runnable r) {
        long t0 = System.nanoTime();
        r.run();
        return (System.nanoTime() - t0) / 1000.0;
    }

    public static double median(List<Double> samples) {
        double[] a = samples.stream().mapToDouble(Double::doubleValue).sorted().toArray();
        if (a.length == 0) {
            return 0;
        }
        int mid = a.length / 2;
        return a.length % 2 == 1 ? a[mid] : (a[mid - 1] + a[mid]) / 2.0;
    }

    public static double[] cpuMicros(Runnable r) {
        java.lang.management.ThreadMXBean mx = java.lang.management.ManagementFactory.getThreadMXBean();
        boolean supported = cpuTimeUsable(mx);
        long c0 = supported ? mx.getCurrentThreadCpuTime() : 0L;
        long t0 = System.nanoTime();
        r.run();
        double wall = (System.nanoTime() - t0) / 1000.0;
        long c1 = supported ? mx.getCurrentThreadCpuTime() : 0L;
        return new double[]{wall, supported ? (c1 - c0) / 1000.0 : -1.0};
    }

    /** True only when {@code getCurrentThreadCpuTime()} will return real numbers, not -1. */
    private static boolean cpuTimeUsable(java.lang.management.ThreadMXBean mx) {
        if (!mx.isThreadCpuTimeSupported()) {
            return false;
        }
        try {
            if (!mx.isThreadCpuTimeEnabled()) {
                mx.setThreadCpuTimeEnabled(true);
            }
        } catch (UnsupportedOperationException | SecurityException e) {
            return false;
        }
        return mx.getCurrentThreadCpuTime() >= 0L;
    }

    static {
        // Fail loudly if the JVM cannot report CPU time; a CPU-floor assertion that silently
        // returns -1 is a check that always passes.
        java.lang.management.ThreadMXBean mx = java.lang.management.ManagementFactory.getThreadMXBean();
        if (!cpuTimeUsable(mx)) {
            System.err.println("WARNING: thread CPU time unsupported; CPU-floor checks are vacuous");
        }
    }

    public static String firstLine(String s) {
        int i = s.indexOf('\n');
        return i < 0 ? s : s.substring(0, i);
    }

    public static List<String> lines(String s) {
        return s.isEmpty() ? List.of() : Arrays.asList(s.split("\\R"));
    }

    public static int countOccurrences(String haystack, String needle) {
        int n = 0;
        int i = 0;
        while ((i = haystack.indexOf(needle, i)) >= 0) {
            n++;
            i += needle.length();
        }
        return n;
    }
}
