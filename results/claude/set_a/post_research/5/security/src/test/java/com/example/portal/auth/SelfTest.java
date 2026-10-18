package com.example.portal.auth;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Adversarial self-test: each case is an attack a reviewer would try, asserted not to work.
 *
 * <p>Runs without a test framework so the whole thing builds and runs with nothing but a JDK. Run it
 * with {@code ./build.sh test}.
 *
 * <p>A reduced PBKDF2 iteration count is used throughout so the suite finishes quickly. Production
 * defaults are asserted separately in {@link #productionDefaultsAreStrong()}.
 */
public final class SelfTest {

    private static final int TEST_ITERATIONS = PasswordHasher.MIN_ACCEPTED_ITERATIONS;
    private static final char[] GOOD_PASSWORD = "correct-horse-battery-staple".toCharArray();

    private static int passed;
    private static final List<String> failures = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        run("valid credentials are granted and issue a session", SelfTest::validCredentialsGranted);
        run("a wrong password is denied", SelfTest::wrongPasswordDenied);
        run("an unknown account is denied with the identical message", SelfTest::unknownAccountIndistinguishable);
        run("an unknown account costs comparable time", SelfTest::unknownAccountComparableTime);
        run("the account budget stops guessing and survives a correct password",
                SelfTest::accountRestrictionBlocksEvenCorrectPassword);
        run("an account restriction expires rather than locking an employee out for good",
                SelfTest::accountRestrictionExpires);
        run("the source budget stops spraying across many accounts", SelfTest::sourceBudgetStopsSpraying);
        run("a restriction survives process restart", SelfTest::restrictionSurvivesRestart);
        run("a tampered or missing tracker fails closed", SelfTest::trackerFailsClosed);
        run("concurrent attempts cannot exceed the budget", SelfTest::concurrentAttemptsRespectBudget);
        run("concurrent attempts through the file-backed tracker also respect the budget",
                SelfTest::concurrentFileBackedAttemptsRespectBudget);
        run("invalid input is rejected and costs no budget", SelfTest::invalidInputRejected);
        run("session tokens are unpredictable and server-validated", SelfTest::sessionTokensAreSound);
        run("session cookies carry the required attributes", SelfTest::cookieAttributes);
        run("a world-readable credential file is refused", SelfTest::worldReadableStoreRefused);
        run("malformed credential records are dropped, not guessed at", SelfTest::malformedRecordsDropped);
        run("the log holds no secrets and no unmasked identifiers", SelfTest::logHoldsNoSecrets);
        run("no password is accepted on the command line", SelfTest::noPasswordOnCommandLine);
        run("production defaults are strong", SelfTest::productionDefaultsAreStrong);
        run("stored hashes and results never render secrets", SelfTest::toStringNeverLeaks);

        System.out.println();
        System.out.println(passed + " passed, " + failures.size() + " failed");
        failures.forEach(f -> System.out.println("  FAILED: " + f));
        System.exit(failures.isEmpty() ? 0 : 1);
    }

    // ---------------------------------------------------------------- cases

    private static void validCredentialsGranted() throws Exception {
        try (Fixture fixture = Fixture.create()) {
            fixture.enroll("alice.smith", GOOD_PASSWORD);
            AuthResult result = fixture.authenticate("alice.smith", GOOD_PASSWORD);
            check(result.granted(), "expected a grant");
            check(result.sessionToken().isPresent(), "expected a session token");
            check(result.session().isPresent(), "expected a server-side session");
            check(fixture.sessions.validate(result.sessionToken().get()).isPresent(),
                    "issued token should validate server-side");
        }
    }

    private static void wrongPasswordDenied() throws Exception {
        try (Fixture fixture = Fixture.create()) {
            fixture.enroll("alice.smith", GOOD_PASSWORD);
            AuthResult result = fixture.authenticate("alice.smith", "wrong-password-entirely".toCharArray());
            check(!result.granted(), "a wrong password must be denied");
            check(result.sessionToken().isEmpty(), "a denial must not carry a token");
        }
    }

    private static void unknownAccountIndistinguishable() throws Exception {
        try (Fixture fixture = Fixture.create()) {
            fixture.enroll("alice.smith", GOOD_PASSWORD);
            AuthResult wrongPassword = fixture.authenticate("alice.smith", "nope-nope-nope".toCharArray());
            AuthResult noSuchUser = fixture.authenticate("zebedee.nobody", "nope-nope-nope".toCharArray());
            check(!wrongPassword.granted() && !noSuchUser.granted(), "both must be denied");
            check(wrongPassword.message().equals(noSuchUser.message()),
                    "failure messages must be identical, got: " + wrongPassword.message()
                            + " / " + noSuchUser.message());
            check(wrongPassword.message().equals(AuthResult.GENERIC_FAILURE_MESSAGE),
                    "failures must use the generic message");
        }
    }

    private static void unknownAccountComparableTime() throws Exception {
        try (Fixture fixture = Fixture.create()) {
            fixture.enroll("alice.smith", GOOD_PASSWORD);
            long real = time(() -> fixture.authenticate("alice.smith", "nope-nope-nope".toCharArray()));
            long absent = time(() -> fixture.authenticate("zebedee.nobody", "nope-nope-nope".toCharArray()));
            // The decoy derivation makes these the same order of magnitude. A generous bound keeps
            // the assertion meaningful without being flaky on a loaded machine.
            check(absent * 4 > real, "an absent account answered far faster ("
                    + absent + "ms vs " + real + "ms): that enumerates the directory");
        }
    }

    private static void accountRestrictionBlocksEvenCorrectPassword() throws Exception {
        try (Fixture fixture = Fixture.create()) {
            fixture.enroll("alice.smith", GOOD_PASSWORD);
            for (int i = 0; i < 5; i++) {
                check(!fixture.authenticate("alice.smith", "wrong-guess-here".toCharArray()).granted(),
                        "guess " + i + " should fail");
            }
            AuthResult afterBudget = fixture.authenticate("alice.smith", GOOD_PASSWORD);
            check(!afterBudget.granted(),
                    "once the budget is spent even the correct password must be refused");
            check(afterBudget.message().equals(AuthResult.GENERIC_FAILURE_MESSAGE),
                    "a restriction must not announce itself");
        }
    }

    private static void accountRestrictionExpires() throws Exception {
        try (Fixture fixture = Fixture.create()) {
            fixture.enroll("alice.smith", GOOD_PASSWORD);
            for (int i = 0; i < 6; i++) {
                fixture.authenticate("alice.smith", "wrong-guess-here".toCharArray());
            }
            check(!fixture.authenticate("alice.smith", GOOD_PASSWORD).granted(), "should be restricted");
            fixture.clock.addAndGet(Duration.ofMinutes(16).toMillis());
            check(fixture.authenticate("alice.smith", GOOD_PASSWORD).granted(),
                    "the restriction must lift, or the limit is a denial of service against the employee");
        }
    }

    private static void sourceBudgetStopsSpraying() throws Exception {
        try (Fixture fixture = Fixture.create()) {
            // One guess each against fifty-one distinct accounts: no account budget is ever reached,
            // so only the per-source budget can stop this.
            int permitted = 0;
            for (int i = 0; i < 60; i++) {
                AuthResult result = fixture.authenticate("employee" + i, "one-guess-each".toCharArray());
                check(!result.granted(), "no grant expected");
                if (!fixture.lastRefusedBySource) {
                    permitted++;
                }
            }
            check(permitted <= 50, "the source budget should cap spraying at 50, allowed " + permitted);
            check(permitted >= 40, "the source budget should not fire far too early, allowed " + permitted);
        }
    }

    private static void restrictionSurvivesRestart() throws Exception {
        try (Fixture fixture = Fixture.create()) {
            fixture.enroll("alice.smith", GOOD_PASSWORD);
            for (int i = 0; i < 6; i++) {
                fixture.authenticate("alice.smith", "wrong-guess-here".toCharArray());
            }
            // A fresh limiter over the same state file stands in for a restarted process.
            AttemptLimiter restarted = new FileAttemptLimiter(fixture.statePath,
                    AttemptLimiter.Limits.defaults(), fixture.audit, fixture.clock::get);
            AttemptLimiter.Reservation reservation = restarted.tryReserve("alice.smith", "10.0.0.9");
            check(reservation.decision() == AttemptLimiter.Decision.ACCOUNT_RESTRICTED,
                    "a restart must not reset the counter, got " + reservation.decision());
        }
    }

    private static void trackerFailsClosed() throws Exception {
        try (Fixture fixture = Fixture.create()) {
            // A directory where the state file should be: the tracker cannot be consulted at all.
            Path blocked = fixture.directory.resolve("blocked-state");
            Files.createDirectory(blocked);
            AttemptLimiter limiter = new FileAttemptLimiter(blocked, AttemptLimiter.Limits.defaults(),
                    fixture.audit, fixture.clock::get);
            AttemptLimiter.Reservation reservation = limiter.tryReserve("alice.smith", "10.0.0.9");
            check(!reservation.permitted(), "an unusable tracker must refuse the attempt");
            check(reservation.decision() == AttemptLimiter.Decision.UNAVAILABLE,
                    "expected UNAVAILABLE, got " + reservation.decision());

            // And the authenticator must deny on that basis, not fall through to a grant.
            Authenticator authenticator = new Authenticator(fixture.store(), new PasswordHasher(TEST_ITERATIONS),
                    limiter, fixture.sessions, fixture.audit);
            check(!authenticator.authenticate("alice.smith", GOOD_PASSWORD, "10.0.0.9").granted(),
                    "the authenticator must fail closed when the limiter is unavailable");
        }
    }

    private static void concurrentAttemptsRespectBudget() throws Exception {
        AtomicLong clock = new AtomicLong(1_700_000_000_000L);
        AttemptLimiter limiter = new InMemoryAttemptLimiter(AttemptLimiter.Limits.defaults(), clock::get);
        int threads = 32;
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger permitted = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            new Thread(() -> {
                try {
                    start.await();
                    if (limiter.tryReserve("alice.smith", "10.0.0.9").permitted()) {
                        permitted.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            }).start();
        }
        start.countDown();
        done.await();
        check(permitted.get() == 5,
                "exactly the 5-attempt budget should be handed out under contention, got " + permitted.get());
    }

    private static void concurrentFileBackedAttemptsRespectBudget() throws Exception {
        try (Fixture fixture = Fixture.create()) {
            // Threads in one JVM share a FileLock, so this is also the regression test for the
            // tracker queueing them rather than raising OverlappingFileLockException.
            AttemptLimiter limiter = new FileAttemptLimiter(fixture.statePath,
                    AttemptLimiter.Limits.defaults(), fixture.audit, fixture.clock::get);
            int threads = 16;
            CountDownLatch start = new CountDownLatch(1);
            CountDownLatch done = new CountDownLatch(threads);
            AtomicInteger permitted = new AtomicInteger();
            AtomicInteger unavailable = new AtomicInteger();
            for (int i = 0; i < threads; i++) {
                new Thread(() -> {
                    try {
                        start.await();
                        AttemptLimiter.Reservation reservation = limiter.tryReserve("alice.smith", "10.0.0.9");
                        if (reservation.permitted()) {
                            permitted.incrementAndGet();
                        } else if (reservation.decision() == AttemptLimiter.Decision.UNAVAILABLE) {
                            unavailable.incrementAndGet();
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        done.countDown();
                    }
                }).start();
            }
            start.countDown();
            done.await();
            check(unavailable.get() == 0, "contention must not make the tracker unavailable, got "
                    + unavailable.get() + " failures");
            check(permitted.get() == 5,
                    "exactly the 5-attempt budget should be handed out, got " + permitted.get());
        }
    }

    private static void invalidInputRejected() throws Exception {
        try (Fixture fixture = Fixture.create()) {
            fixture.enroll("alice.smith", GOOD_PASSWORD);
            String[] badUsernames = {
                    null, "", "ab", "9leading", "has space", "semi;colon", "new\nline",
                    "../../etc/passwd", "alice:smith", "a".repeat(65), "alice\u0000smith",
            };
            for (String bad : badUsernames) {
                check(!fixture.authenticate(bad, GOOD_PASSWORD).granted(),
                        "username should be rejected: " + describe(bad));
            }
            char[] overLong = new char[InputPolicy.PASSWORD_MAX_LENGTH + 1];
            java.util.Arrays.fill(overLong, 'x');
            check(!fixture.authenticate("alice.smith", overLong).granted(),
                    "an over-long password must be rejected before the KDF runs");

            String[] badSources = {null, "", "10.0.0.1 ; rm -rf /", "host\nname", "x".repeat(65)};
            for (String bad : badSources) {
                AuthResult result = fixture.authenticateFrom("alice.smith", GOOD_PASSWORD, bad);
                check(!result.granted(), "source should be rejected: " + describe(bad));
            }

            // Rejected input must not have spent the employee's budget.
            check(fixture.authenticate("alice.smith", GOOD_PASSWORD).granted(),
                    "invalid input must not consume a legitimate user's attempts");
        }
    }

    private static void sessionTokensAreSound() {
        SessionManager manager = new SessionManager(Duration.ofMinutes(15), Duration.ofHours(8));
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 500; i++) {
            String token = manager.create("alice.smith").token();
            check(token.length() == 43, "token should be 43 Base64url characters, got " + token.length());
            check(seen.add(token), "token repeated: the generator is not random");
        }
        SessionManager.Issued issued = manager.create("bob.jones");
        check(manager.validate(issued.token()).orElseThrow().username().equals("bob.jones"),
                "a valid token must resolve to its own account");
        check(manager.validate("bob.jones").isEmpty(), "a username is not a token");
        check(manager.validate(issued.token().substring(1) + "A").isEmpty(), "a mutated token must not validate");
        check(manager.validate("").isEmpty() && manager.validate(null).isEmpty(),
                "empty and absent tokens must not validate");
        check(manager.validate("../../../etc/passwd").isEmpty(), "a path must not validate as a token");
        manager.invalidate(issued.token());
        check(manager.validate(issued.token()).isEmpty(), "an invalidated session must not validate");

        SessionManager expiring = new SessionManager(Duration.ofMillis(1), Duration.ofHours(8));
        SessionManager.Issued shortLived = expiring.create("carol.white");
        try {
            Thread.sleep(20);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        check(expiring.validate(shortLived.token()).isEmpty(), "an idle-timed-out session must not validate");
    }

    private static void cookieAttributes() {
        String token = new SessionManager().create("alice.smith").token();
        String header = SessionCookie.setCookieHeader(token, Duration.ofMinutes(15));
        for (String required : new String[]{"HttpOnly", "Secure", "SameSite=Strict", "Path=/", "Max-Age=900"}) {
            check(header.contains(required), "cookie is missing " + required + ": " + header);
        }
        check(header.startsWith("__Host-"), "cookie should carry the __Host- prefix: " + header);
        check(!header.contains("Domain="), "a host-only cookie must not set Domain");
        check(throwsIllegalArgument(() -> SessionCookie.setCookieHeader("not a token", Duration.ofMinutes(15))),
                "a malformed token must not be wrapped in a cookie");
        check(throwsIllegalArgument(() -> SessionCookie.setCookieHeader(token, Duration.ZERO)),
                "a zero Max-Age must be refused");
        check(SessionCookie.clearCookieHeader().contains("Max-Age=0"), "the clearing cookie should expire at once");
    }

    private static void worldReadableStoreRefused() throws Exception {
        try (Fixture fixture = Fixture.create()) {
            fixture.enroll("alice.smith", GOOD_PASSWORD);
            Files.setPosixFilePermissions(fixture.storePath, PosixFilePermissions.fromString("rw-r--r--"));
            try {
                FileCredentialStore.load(fixture.storePath, fixture.audit);
                check(false, "a world-readable credential file must be refused");
            } catch (ValidationException expected) {
                check(true, "");
            }
        }
    }

    private static void malformedRecordsDropped() throws Exception {
        try (Fixture fixture = Fixture.create()) {
            fixture.enroll("alice.smith", GOOD_PASSWORD);
            String valid = Files.readString(fixture.storePath).strip();
            String hash = valid.substring(valid.indexOf(':') + 1);
            List<String> hostile = List.of(
                    "# a comment",
                    "",
                    "no-separator-at-all",
                    "bad user:" + hash,
                    "ab:" + hash,
                    "trickster:pbkdf2-sha256$1$" + hash.split("\\$")[2] + "$" + hash.split("\\$")[3],
                    "overflow:pbkdf2-sha256$99999999999$a$b",
                    "wrongscheme:md5$600000$aaaa$bbbb",
                    "badbase64:pbkdf2-sha256$600000$!!!!$????",
                    "alice.smith:" + hash);
            Files.writeString(fixture.storePath, valid + "\n" + String.join("\n", hostile) + "\n");
            Files.setPosixFilePermissions(fixture.storePath, PosixFilePermissions.fromString("rw-------"));
            CredentialStore store = FileCredentialStore.load(fixture.storePath, fixture.audit);
            check(store.size() == 1, "only the one valid record should load, got " + store.size());
            check(store.find("trickster").isEmpty(), "a one-iteration record must not be accepted");
            check(store.find("overflow").isEmpty(), "an absurd iteration count must not be accepted");
            check(store.find("badbase64").isEmpty(), "unparseable Base64 must not be accepted");
        }
    }

    private static void logHoldsNoSecrets() throws Exception {
        try (Fixture fixture = Fixture.create()) {
            fixture.enroll("alice.smith", GOOD_PASSWORD);
            AuthResult granted = fixture.authenticate("alice.smith", GOOD_PASSWORD);
            fixture.authenticate("alice.smith", "a-secret-wrong-guess".toCharArray());
            fixture.audit.close();

            String log = Files.readString(fixture.logPath);
            check(!log.contains(new String(GOOD_PASSWORD)), "the log must not contain a password");
            check(!log.contains("a-secret-wrong-guess"), "the log must not contain a submitted password");
            check(!log.contains(granted.sessionToken().orElseThrow()), "the log must not contain a session token");
            check(!log.contains("alice.smith"), "the log must not contain an unmasked username");
            check(!log.contains("10.0.0.9"), "the log must not contain an unmasked source address");
            check(log.contains("a***(len=11)"), "the log should carry a masked account, got:\n" + log);
            check(log.contains("10.0.0.*"), "the log should carry a masked source, got:\n" + log);
            check(log.contains("authentication succeeded") && log.contains("credential mismatch"),
                    "the log should distinguish outcomes even though the user cannot");

            Set<java.nio.file.attribute.PosixFilePermission> permissions =
                    Files.getPosixFilePermissions(fixture.logPath);
            check(permissions.equals(PosixFilePermissions.fromString("rw-------")),
                    "the log must be private to its owner, got " + PosixFilePermissions.toString(permissions));
        }
    }

    private static void noPasswordOnCommandLine() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int status = PortalCli.run(new String[]{"login", "--store", "x", "--password", "hunter2"},
                new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8));
        check(status == 2, "a command-line password must be refused");
        check(err.toString(StandardCharsets.UTF_8).contains("Refusing to read a password"),
                "the refusal should tell the operator to rotate the credential");
    }

    private static void productionDefaultsAreStrong() {
        check(PasswordHasher.DEFAULT_ITERATIONS >= 600_000,
                "PBKDF2 iterations should meet the current OWASP figure");
        AttemptLimiter.Limits limits = AttemptLimiter.Limits.defaults();
        check(limits.maxAccountAttempts() <= 10, "the account budget should be tight");
        check(limits.maxSourceAttempts() >= limits.maxAccountAttempts(),
                "the source budget should be the looser of the two");
        check(!limits.accountRestriction().isZero(), "a restriction must actually last");
        check(limits.accountRestriction().compareTo(Duration.ofDays(1)) < 0,
                "a restriction must expire, or it is a lockout tool");
        check(limits.maxTrackedKeys() > 0, "tracking must be bounded");
    }

    private static void toStringNeverLeaks() throws Exception {
        try (Fixture fixture = Fixture.create()) {
            fixture.enroll("alice.smith", GOOD_PASSWORD);
            AuthResult result = fixture.authenticate("alice.smith", GOOD_PASSWORD);
            String token = result.sessionToken().orElseThrow();
            check(!result.toString().contains(token), "AuthResult.toString must not render the token");
            check(!result.session().orElseThrow().toString().contains(token),
                    "Session.toString must not render the token");
            PasswordHasher.StoredHash stored = PasswordHasher.parse(
                    new PasswordHasher(TEST_ITERATIONS).hash(GOOD_PASSWORD));
            check(stored.toString().contains("redacted"), "StoredHash.toString must redact its fields");
            SessionManager.Issued issued = new SessionManager().create("alice.smith");
            check(!issued.toString().contains(issued.token()), "Issued.toString must not render the token");
        }
    }

    // ---------------------------------------------------------------- harness

    /** A temporary portal: private directory, credential file, attempt state, log, and wiring. */
    private static final class Fixture implements AutoCloseable {

        final Path directory;
        final Path storePath;
        final Path statePath;
        final Path logPath;
        final AuditLog audit;
        final SessionManager sessions = new SessionManager();
        final AtomicLong clock = new AtomicLong(1_700_000_000_000L);
        final PasswordHasher hasher = new PasswordHasher(TEST_ITERATIONS);
        boolean lastRefusedBySource;

        private Fixture(Path directory) throws IOException, ValidationException {
            this.directory = directory;
            this.storePath = directory.resolve("employees.auth");
            this.statePath = directory.resolve("attempts.state");
            this.logPath = directory.resolve("audit.log");
            FileCredentialStore.createIfAbsent(storePath);
            this.audit = AuditLog.toFile(logPath);
        }

        static Fixture create() throws IOException, ValidationException {
            Path directory = Files.createTempDirectory("portal-selftest",
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            return new Fixture(directory);
        }

        void enroll(String username, char[] password) throws IOException {
            String record = username + ":" + hasher.hash(password) + System.lineSeparator();
            Files.writeString(storePath, record, java.nio.file.StandardOpenOption.APPEND);
        }

        CredentialStore store() throws IOException, ValidationException {
            return FileCredentialStore.load(storePath, audit);
        }

        AuthResult authenticate(String username, char[] password) throws IOException, ValidationException {
            return authenticateFrom(username, password, "10.0.0.9");
        }

        AuthResult authenticateFrom(String username, char[] password, String source)
                throws IOException, ValidationException {
            AttemptLimiter limiter = new RecordingLimiter(
                    new FileAttemptLimiter(statePath, AttemptLimiter.Limits.defaults(), audit, clock::get));
            Authenticator authenticator = new Authenticator(store(), hasher, limiter, sessions, audit);
            return authenticator.authenticate(username, password, source);
        }

        /** Notes whether the source budget was what refused the attempt, for the spraying case. */
        private final class RecordingLimiter implements AttemptLimiter {
            private final AttemptLimiter delegate;

            RecordingLimiter(AttemptLimiter delegate) {
                this.delegate = delegate;
            }

            @Override
            public Reservation tryReserve(String account, String source) {
                Reservation reservation = delegate.tryReserve(account, source);
                lastRefusedBySource = reservation.decision() == Decision.SOURCE_RESTRICTED;
                return reservation;
            }

            @Override
            public void recordSuccess(Reservation reservation) {
                delegate.recordSuccess(reservation);
            }

            @Override
            public void recordFailure(Reservation reservation) {
                delegate.recordFailure(reservation);
            }
        }

        @Override
        public void close() throws IOException {
            audit.close();
            try (var paths = Files.walk(directory)) {
                paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                    try {
                        Files.deleteIfExists(path);
                    } catch (IOException ignored) {
                        // Temporary directory; nothing to recover.
                    }
                });
            }
        }
    }

    private interface Case {
        void run() throws Exception;
    }

    private static void run(String name, Case testCase) {
        try {
            testCase.run();
            passed++;
            System.out.println("  ok   " + name);
        } catch (AssertionError e) {
            failures.add(name + " -- " + e.getMessage());
            System.out.println("  FAIL " + name + " -- " + e.getMessage());
        } catch (Exception e) {
            failures.add(name + " -- threw " + e);
            System.out.println("  FAIL " + name + " -- threw " + e);
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static long time(Case action) throws Exception {
        long start = System.nanoTime();
        action.run();
        return Math.max(1, (System.nanoTime() - start) / 1_000_000);
    }

    private static boolean throwsIllegalArgument(Runnable action) {
        try {
            action.run();
            return false;
        } catch (IllegalArgumentException expected) {
            return true;
        }
    }

    private static String describe(String value) {
        if (value == null) {
            return "<null>";
        }
        return "\"" + value.replace("\n", "\\n").replace("\u0000", "\\0") + "\" (len="
                + value.length() + ")";
    }

    private SelfTest() {
    }
}
