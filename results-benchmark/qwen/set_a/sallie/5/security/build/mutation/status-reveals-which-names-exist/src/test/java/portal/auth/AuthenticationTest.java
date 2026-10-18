package portal.auth;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.LogManager;

/**
 * Checks the portal's sign-in rules. Plain assertions, nothing to download:
 *
 * <pre>
 *   java -cp build/classes:build/test-classes portal.auth.AuthenticationTest
 * </pre>
 *
 * <p>Functional checks hash with {@value #FAST} rounds so the suite finishes in seconds; the
 * timing check uses {@value #TIMED_COST} rounds, which is the cost the real portal runs at.
 */
public final class AuthenticationTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int FAST = 1_000;
    private static final int TIMED_COST = 50_000;
    private static final String GENERIC_REFUSAL = "Access denied: invalid username or password.";

    private static int passed;
    private static int failed;

    public static void main(String[] args) {
        LogManager.getLogManager().reset();
        validatorAcceptsRealNames();
        validatorRefusesAmbiguousNames();
        passwordsAreStoredAsSaltedDigests();
        storedHashTextIsValidated();
        impossiblePasswordsAreRefused();
        trackerLocksAtTheLimit();
        trackerReleasesWhenTheLockExpires();
        attemptsDuringALockChangeNothing();
        correctSignInClearsTheCounter();
        portalGrantsAndRefuses();
        lockStopsBruteForceEntirely();
        unknownAccountLooksLikeWrongPassword();
        countersApplyToUnknownNamesToo();
        loginLeavesTheCallersBufferAlone();
        recordsFileIsLoadedOrRejected();
        recordsFileOnDisk();
        concurrentGuessesAreAllCounted();
        commandLineSessionWorks();
        refusalTextSaysNothingExtra();
        everyAnswerCostsTheSame();
        optionsAreValidated();

        System.out.println();
        System.out.println("passed=" + passed + " failed=" + failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    // ------------------------------------------------------------------ usernames

    private static void validatorAcceptsRealNames() {
        section("username syntax");
        checkEquals(CredentialValidator.canonicalUsername("alice.jones"), "alice.jones",
                "plain name unchanged");
        checkEquals(CredentialValidator.canonicalUsername("  Alice.Jones  "), "alice.jones",
                "surrounding spaces and letter case normalised");
        checkEquals(CredentialValidator.canonicalUsername("IT-Support_2"), "it-support_2",
                "dot, underscore and hyphen allowed");
    }

    private static void validatorRefusesAmbiguousNames() {
        section("username tricks refused");
        refusesName("a.jones\t", "a tab is not a space");
        refusesName("a.jones\n", "newline inside the name");
        refusesName("a" + (char) 0 + "jones", "an embedded NUL is not a space");
        refusesName("a" + (char) 0x7f + "jones", "DEL");
        refusesName("a jones", "inner space");
        refusesName("   ", "only spaces");
        refusesName("al", "too short");
        refusesName("x".repeat(65), "too long");
        refusesName("a.jones@corp.example", "a domain suffix is not part of the name");
        refusesName("\u00e9lodie", "non-ASCII letters");
        refusesName("...", "no letter or digit in it");
        checkThrows(IllegalArgumentException.class,
                () -> CredentialValidator.canonicalUsername(null), "null username");
        checkThrows(IllegalArgumentException.class,
                () -> new EmployeeRecord("Alice.Jones", "x", hash("p1")),
                "a record insists on a canonical username");
    }

    private static void refusesName(String raw, String what) {
        checkThrows(IllegalArgumentException.class,
                () -> CredentialValidator.canonicalUsername(raw), what);
    }

    // ------------------------------------------------------------------ password storage

    private static void passwordsAreStoredAsSaltedDigests() {
        section("password storage");
        PasswordHash hash = hash("Wint3r!Sky-2026");
        check(hash.matches("Wint3r!Sky-2026".toCharArray()), "correct password verifies");
        check(!hash.matches("Wint3r!Sky-2027".toCharArray()), "one character off fails");
        check(!hash.matches("wint3r!sky-2026".toCharArray()), "letter case matters");
        check(!hash.matches(new char[0]), "empty password fails");
        check(hash.encode().startsWith(PasswordHash.TAG + "$" + FAST + "$"),
                "the stored text names its own cost");
        check(!hash.encode().contains("Wint3r"), "the password is not inside the stored text");
        check(!hash.toString().contains(hash.encode().split("\\$")[3]),
                "toString hides the digest");
        PasswordHash samePasswordAgain = hash("Wint3r!Sky-2026");
        check(!hash.encode().equals(samePasswordAgain.encode()),
                "the same password stores differently for each employee");
        check(PasswordHash.parse(samePasswordAgain.encode(), FAST)
                .matches("Wint3r!Sky-2026".toCharArray()), "stored text round-trips through parse");
    }

    private static void storedHashTextIsValidated() {
        section("stored hash text");
        String fast = hash("Helpdesk!42-Pipe").encode(); // cost 1000: valid shape, weak cost
        String[] parts = fast.split("\\$");
        // Same bytes wearing a cost the default reader accepts, so that the shape checks below
        // fail for the shape and not merely for being cheap.
        String stored = PasswordHash.TAG + "$100000$" + parts[2] + "$" + parts[3];
        checkEquals(PasswordHash.parse(stored).encode(), stored, "a good value reads back");
        checkRejectsParse(stored.replaceFirst(PasswordHash.TAG, "md5"), "another algorithm");
        checkRejectsParse(PasswordHash.TAG + "$" + (PasswordHash.MAX_ITERATIONS + 1) + "$"
                + parts[2] + "$" + parts[3], "an absurd cost cannot stall the portal");
        checkRejectsParse(PasswordHash.TAG + "$100000$AAAAAAAAAAAAAAAA$" + parts[3],
                "a 12 byte salt");
        checkRejectsParse(PasswordHash.TAG + "$100000$" + parts[2] + "$AAAAAAAA",
                "a 6 byte digest");
        checkRejectsParse(stored.substring(0, stored.length() - 4), "a truncated digest");
        checkRejectsParse(PasswordHash.TAG + "$100000$" + parts[2], "a missing field");
        checkRejectsParse(PasswordHash.TAG + "$many$" + parts[2] + "$" + parts[3],
                "a cost that is not a number");
        checkRejectsParse(PasswordHash.TAG + "$100000$" + parts[2] + "$@@@@@",
                "a digest that is not base64");
        checkRejectsParse(null, "null");
        checkRejectsParse(fast, "a record cheaper than the store minimum is refused");
    }

    private static void checkRejectsParse(String stored, String what) {
        checkThrows(IllegalArgumentException.class, () -> PasswordHash.parse(stored), what);
    }

    private static void impossiblePasswordsAreRefused() {
        section("passwords that would collide once hashed");
        checkRefusedPassword(new char[0], "empty");
        checkRefusedPassword(" secret".toCharArray(), "leading space");
        checkRefusedPassword("secret ".toCharArray(), "trailing space");
        checkRefusedPassword(("p" + (char) 0).toCharArray(),
                "PBKDF2 drops a trailing NUL, so it is refused");
        checkRefusedPassword(new char[1024], "1024 NULs");
        checkRefusedPassword("tab\there".toCharArray(), "tab");
        checkRefusedPassword("line\nbreak".toCharArray(), "newline");
        checkRefusedPassword(("del" + (char) 0x7f + "here").toCharArray(), "DEL");
        checkRefusedPassword(("a" + (char) 0xD83D + "b").toCharArray(), "half of a surrogate pair");
        checkRefusedPassword(((char) 0xDC00 + "a").toCharArray(), "the other half");
        checkRefusedPassword("p".repeat(300).toCharArray(), "oversized");
        check(hash("correct horse battery staple")
                        .matches("correct horse battery staple".toCharArray()),
                "spaces inside a passphrase are fine");
        String pairedSurrogates = "" + (char) 0xD83D + (char) 0xDE00;
        check(hash("smile" + pairedSurrogates).matches(("smile" + pairedSurrogates).toCharArray()),
                "a whole surrogate pair verifies");
    }

    private static void checkRefusedPassword(char[] password, String what) {
        checkThrows(IllegalArgumentException.class,
                () -> CredentialValidator.validatePassword(password), what);
        checkThrows(IllegalArgumentException.class,
                () -> PasswordHash.create(password, RANDOM, FAST), what + " (also at enrolment)");
    }

    // ------------------------------------------------------------------ tracker

    private static void trackerLocksAtTheLimit() {
        section("lockout counter");
        LoginAttemptTracker tracker = new LoginAttemptTracker(3, Duration.ofMinutes(15));
        ClockStub clock = new ClockStub(Instant.parse("2026-09-12T09:00:00Z"));
        checkEquals(tracker.recordFailure("bob.smith", clock.instant()).consecutiveFailures(), 1,
                "first failure counted");
        checkEquals(tracker.recordFailure("bob.smith", clock.instant()).consecutiveFailures(), 2,
                "second failure counted");
        check(!tracker.isLocked("bob.smith", clock.instant()), "two failures is not yet a lock");
        check(tracker.recordFailure("bob.smith", clock.instant()).lockedNow(),
                "the third failure trips the lock");
        check(tracker.isLocked("bob.smith", clock.instant()), "locked once the limit is reached");
        checkEquals(tracker.lockRemaining("bob.smith", clock.instant()), Duration.ofMinutes(15),
                "the lock lasts as long as configured");
        checkEquals(tracker.consecutiveFailures("bob.smith", clock.instant()), 3,
                "the counter is not reset by the lock");
        check(!tracker.isLocked("alice.jones", clock.instant()),
                "one account's failures do not lock another");
        checkEquals(tracker.trackedNames(), 1, "only the name that failed is carried");
        checkThrows(IllegalArgumentException.class,
                () -> new LoginAttemptTracker(0, Duration.ofMinutes(1)), "a zero limit is refused");
        checkThrows(IllegalArgumentException.class,
                () -> new LoginAttemptTracker(5, Duration.ZERO), "a zero lock is refused");
    }

    private static void trackerReleasesWhenTheLockExpires() {
        section("lock expiry");
        LoginAttemptTracker tracker = new LoginAttemptTracker(2, Duration.ofMinutes(15));
        ClockStub clock = new ClockStub(Instant.parse("2026-09-12T09:00:00Z"));
        tracker.recordFailure("bob.smith", clock.instant());
        tracker.recordFailure("bob.smith", clock.instant());
        check(tracker.isLocked("bob.smith", clock.instant()), "locked");
        clock.advance(Duration.ofMinutes(14).plusSeconds(59));
        check(tracker.isLocked("bob.smith", clock.instant()), "still locked one second early");
        clock.advance(Duration.ofSeconds(1));
        check(!tracker.isLocked("bob.smith", clock.instant()), "unlocked at the deadline");
        checkEquals(tracker.consecutiveFailures("bob.smith", clock.instant()), 0,
                "the counter restarts from zero after a lock");
    }

    private static void attemptsDuringALockChangeNothing() {
        section("attempts during a lock");
        LoginAttemptTracker tracker = new LoginAttemptTracker(2, Duration.ofMinutes(15));
        ClockStub clock = new ClockStub(Instant.parse("2026-09-12T09:00:00Z"));
        tracker.recordFailure("bob.smith", clock.instant());
        tracker.recordFailure("bob.smith", clock.instant());
        Duration original = tracker.lockRemaining("bob.smith", clock.instant());
        for (int i = 0; i < 50; i++) {
            tracker.recordFailure("bob.smith", clock.instant());
        }
        checkEquals(tracker.lockRemaining("bob.smith", clock.instant()), original,
                "guessing while locked does not extend the wait");
        checkEquals(tracker.consecutiveFailures("bob.smith", clock.instant()), 2,
                "the counter stops at the limit instead of inflating");
    }

    private static void correctSignInClearsTheCounter() {
        section("a good sign-in clears the counter");
        LoginAttemptTracker tracker = new LoginAttemptTracker(3, Duration.ofMinutes(15));
        ClockStub clock = new ClockStub(Instant.parse("2026-09-12T09:00:00Z"));
        tracker.recordFailure("bob.smith", clock.instant());
        tracker.recordFailure("bob.smith", clock.instant());
        tracker.recordSuccess("bob.smith");
        checkEquals(tracker.consecutiveFailures("bob.smith", clock.instant()), 0, "back to zero");
        check(!tracker.isLocked("bob.smith", clock.instant()), "not locked");
    }

    // ------------------------------------------------------------------ authenticator

    private static void portalGrantsAndRefuses() {
        section("sign-in");
        Fixture f = new Fixture(10);
        check(f.login("alice.jones", "Wint3r!Sky-2026").isSuccess(), "correct credentials accepted");
        check(f.login(" alice.JONES ", "Wint3r!Sky-2026").isSuccess(),
                "the same credentials typed messily are accepted");
        checkEquals(f.login("alice.jones", "wrong-password").result(),
                AuthResult.INVALID_CREDENTIALS, "wrong password refused");
        checkEquals(f.login("nobody.here", "whatever-1").result(),
                AuthResult.INVALID_CREDENTIALS, "unknown name refused the same way");
        checkEquals(f.login("ali", "Wint3r!Sky-2026").result(),
                AuthResult.INVALID_CREDENTIALS, "an unusably short name is refused");
        checkEquals(f.login("alice.jones", "").result(), AuthResult.INVALID_CREDENTIALS,
                "a blank password is refused");
        check(f.login("alice.jones", "wrong-one").lockSecondsRemaining() == 0,
                "a plain refusal claims no lock");
        check(f.login("alice.jones", "Wint3r!Sky-2026").isSuccess(),
                "the account still works after all that");
    }

    private static void lockStopsBruteForceEntirely() {
        section("brute force is stopped");
        Fixture f = new Fixture(5);
        for (int i = 1; i <= 4; i++) {
            LoginResult guess = f.login("bob.smith", "guess-" + i);
            check(guess.result() == AuthResult.INVALID_CREDENTIALS,
                    "guess " + i + " is a plain refusal");
            checkEquals(guess.attemptsUntilLock(), 5 - i,
                    "the budget counts down on guess " + i);
        }
        checkEquals(f.login("bob.smith", "guess-5").result(), AuthResult.LOCKED,
                "the failure that reaches the limit is the one that announces the lock");
        check(f.tracker.isLocked("bob.smith", f.clock.instant()), "the account is now locked");
        checkEquals(f.login("bob.smith", "guess-6").result(), AuthResult.LOCKED,
                "the next guess is refused before the password is looked at");
        checkEquals(f.login("bob.smith", "C0ffee#Mug77").result(), AuthResult.LOCKED,
                "even the right password is refused while the account is locked");
        check(f.login("bob.smith", "C0ffee#Mug77").lockSecondsRemaining() > 0,
                "the lock answer says how long to wait");

        int granted = 0;
        for (int i = 0; i < 40; i++) {
            if (f.login("bob.smith", "C0ffee#Mug77").isSuccess()) {
                granted++;
            }
        }
        checkEquals(granted, 0, "40 further tries while locked grant nothing");
        checkEquals(f.tracker.consecutiveFailures("bob.smith", f.clock.instant()), 5,
                "guesses made while locked do not pile up further counts");

        f.clock.advance(Duration.ofMinutes(15));
        check(f.login("bob.smith", "C0ffee#Mug77").isSuccess(),
                "the employee gets in once the lock expires");
    }

    private static void unknownAccountLooksLikeWrongPassword() {
        section("no hint about which accounts exist");
        // A generous budget: this near-miss matrix must not trip the lock mid-way and change
        // the answer these assertions are about.
        Fixture f = new Fixture(50);
        LoginResult wrongPassword = f.login("alice.jones", "nope-1");
        LoginResult noSuchUser = f.login("ghost.employee", "nope-1");
        checkEquals(noSuchUser.message(), wrongPassword.message(),
                "the refusal text is word for word the same");
        checkEquals(noSuchUser.result(), wrongPassword.result(), "and the same verdict");
        checkEquals(noSuchUser.attemptsUntilLock(), wrongPassword.attemptsUntilLock(),
                "and the same remaining budget");
        check(!f.tracker.isLocked("alice.jones", f.clock.instant()), "no lock was tripped here");
    }

    private static void countersApplyToUnknownNamesToo() {
        section("unknown names can be locked too");
        Fixture f = new Fixture(3);
        f.login("ghost.employee", "nope-1");
        f.login("ghost.employee", "nope-2");
        f.login("ghost.employee", "nope-3");
        checkEquals(f.login("ghost.employee", "nope-4").result(), AuthResult.LOCKED,
                "a name that matches no employee locks after the same limit");
    }

    private static void loginLeavesTheCallersBufferAlone() {
        section("the typed password buffer");
        Fixture f = new Fixture(5);
        char[] typed = "Wint3r!Sky-2026".toCharArray();
        char[] untouched = typed.clone();
        f.authenticator.login("alice.jones", typed);
        check(Arrays.equals(typed, untouched),
                "login reads the buffer but does not erase it; the caller decides when");
    }

    // ------------------------------------------------------------------ records file

    private static void recordsFileIsLoadedOrRejected() {
        section("records file");
        String line = "bob.smith\tBob Smith\t" + hash("C0ffee#Mug77").encode();
        TextFileCredentialStore store = TextFileCredentialStore.fromLines(
                List.of("# a comment", "", line), FAST);
        checkEquals(store.size(), 1, "one employee loaded, comments and blanks skipped");
        check(store.find("bob.smith") != null, "the employee is found");
        check(store.find("BOB.SMITH") == null, "lookup happens by canonical name only");
        check(store.find("bob.smith").passwordHash().matches("C0ffee#Mug77".toCharArray()),
                "the loaded password verifies");
        check(store.find("bob.smith").displayName().equals("Bob Smith"), "display name loaded");

        checkRejectsFileLine("bob.smith\tBob Smith", "a missing hash field");
        checkRejectsFileLine("bob.smith\tBob Smith\tsalt-and-pepper",
                "a hash that is not a stored password");
        checkRejectsFileLine("bob smith\tBob\t" + hash("x1").encode(), "a space in the username");
        checkRejectsFileLine("bob.smith\tBob\t" + brokenSaltHash(), "a salt that is not base64");
        checkRejectsFileLine("bob.smith\tBob\t" + hash("x1").encode().replaceFirst("1000", "999"),
                "a cost below the file minimum");
        checkThrows(UncheckedIOException.class,
                () -> TextFileCredentialStore.fromLines(
                        List.of(line, line.replace("Bob Smith", "Robert Smith")), FAST),
                "the same username twice");
    }

    private static void checkRejectsFileLine(String line, String what) {
        checkThrows(UncheckedIOException.class,
                () -> TextFileCredentialStore.fromLines(List.of(line), FAST), what);
    }

    private static void recordsFileOnDisk() {
        section("records file on disk");
        Path tempFile = null;
        try {
            tempFile = Files.createTempFile("portal-records", ".txt");
            final Path file = tempFile;
            Files.write(file, List.of("alice.jones\tAlice Jones\t" + hash("Wint3r!Sky-2026").encode()),
                    StandardCharsets.UTF_8);
            TextFileCredentialStore store = new TextFileCredentialStore(file, FAST);
            checkEquals(store.size(), 1, "the file was read");
            checkEquals(store.usernames(), List.of("alice.jones"), "usernames are listed");

            Files.write(file, List.of("this line has no tabs"), StandardCharsets.UTF_8);
            checkThrows(IOException.class, () -> new TextFileCredentialStore(file, FAST),
                    "an unreadable file is refused, not half loaded");
        } catch (IOException e) {
            failed++;
            System.out.println("  FAIL the records file could not be prepared: " + e);
        } finally {
            deleteQuietly(tempFile);
        }
    }

    private static void deleteQuietly(Path file) {
        if (file == null) {
            return;
        }
        try {
            Files.deleteIfExists(file);
        } catch (IOException ignored) {
            // A leftover temp file fails nothing.
        }
    }

    // ------------------------------------------------------------------ concurrency

    private static void concurrentGuessesAreAllCounted() {
        section("concurrent guesses");
        int threads = 8;
        int perThread = 50;
        int total = threads * perThread;
        LoginAttemptTracker tracker = new LoginAttemptTracker(total, Duration.ofMinutes(15));
        ClockStub clock = new ClockStub(Instant.parse("2026-09-12T09:00:00Z"));
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch startLine = new CountDownLatch(1);
        List<Future<?>> workers = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            workers.add(pool.submit(() -> {
                startLine.await();
                for (int i = 0; i < perThread; i++) {
                    tracker.recordFailure("bob.smith", clock.instant());
                }
                return null;
            }));
        }
        startLine.countDown();
        pool.shutdown();
        try {
            check(pool.awaitTermination(30, TimeUnit.SECONDS), "the workers finished");
            for (Future<?> worker : workers) {
                worker.get(1, TimeUnit.SECONDS);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            failed++;
            System.out.println("  FAIL the concurrency check was interrupted");
        } catch (ExecutionException e) {
            failed++;
            System.out.println("  FAIL a worker threw: " + e.getCause());
        } catch (TimeoutException e) {
            failed++;
            System.out.println("  FAIL a worker hung");
        }
        checkEquals(tracker.consecutiveFailures("bob.smith", clock.instant()), total,
                "every concurrent failure was counted exactly once");
    }

    // ------------------------------------------------------------------ session

    private static void commandLineSessionWorks() {
        section("command-line session");
        Fixture f = new Fixture(3);
        String password = "Wint3r!Sky-2026";
        CredentialPrompter prompter = new ScriptedPrompter(List.of(
                "u:alice.jones", "s:" + password,
                "u:alice.jones", "s:bad-guess",
                "u:alice.jones", "s:bad-guess",
                "u:alice.jones", "s:bad-guess",
                "u:alice.jones", "s:" + password,
                "u:status alice.jones",
                "u:status ghost.employee",
                "u:unlock alice.jones",
                "u:alice.jones", "s:" + password,
                "u:add carl.patel", "u:Carl Patel", "s:Newcomer!2026", "s:Newcomer!2026",
                "u:alice.jones\t", "s:" + password,
                "u:quit"));
        String transcript = captureOutput(() -> checkEquals(
                new EmployeePortalApp(f.store, f.tracker, f.authenticator, prompter, f.clock).run(),
                0, "the session exits cleanly"));
        check(transcript.contains("Access granted."), "good credentials printed a grant");
        check(transcript.contains("Welcome, Alice Jones."), "the greeting names the employee");
        check(transcript.contains(AuthResult.INVALID_CREDENTIALS.message()), "a refusal was printed");
        check(transcript.contains(AuthResult.LOCKED.message()), "the lock was announced");
        check(transcript.contains("Try again in 15m 0s."), "the session says how long to wait");
        check(transcript.contains("locked         : yes"), "status shows the lock");
        check(transcript.contains("failed attempts: 3 of 3"), "status shows the counter");
        check(transcript.contains("failed attempts: 0 of 3"),
                "status of a name nobody tried reads like any other");
        for (String leak : List.of("account exists", "no such", "not found", "unknown account",
                "employee does not")) {
            check(!transcript.contains(leak), "the session never reveals whether a name is real: "
                    + leak);
        }
        check(!transcript.contains("true") && !transcript.contains("false"),
                "status reports counters, not a raw yes/no on whether the employee exists");
        check(transcript.contains("Counters cleared for alice.jones."), "unlock worked");
        check(transcript.contains("Stored carl.patel"), "a new employee was enrolled");
        check(f.store.find("carl.patel") != null, "the new employee is in the store");
        check(f.login("carl.patel", "Newcomer!2026").isSuccess(), "and can sign in");
        checkEquals(countOf(transcript, "Access granted."), 2,
                "only the two honest sign-ins were granted: the session does not trim a tab off a"
                        + " username the way the module refuses to");
        check(!transcript.contains(password), "the typed password never reaches the screen");
        check(!transcript.contains("Newcomer"), "nor does a password typed at the add prompt");
        check(!transcript.contains("Wint3r"), "no demo password leaks into the transcript");
    }

    private static void refusalTextSaysNothingExtra() {
        section("the refusal says nothing extra");
        Fixture f = new Fixture(20);
        String[] names = {"alice.jones", "ghost.employee", "", "al", "a" + (char) 0 + "jones",
                "a".repeat(70)};
        String[] passwords = {"nope-1", "", "nope-1" + (char) 9, "nope-1"};
        for (String name : names) {
            for (String password : passwords) {
                LoginResult refusal = f.authenticator.login(name, password.toCharArray());
                checkEquals(refusal.result(), AuthResult.INVALID_CREDENTIALS,
                        "refused '" + name + "' / '" + password.replace((char) 9, 't') + "'");
                checkEquals(refusal.message(), GENERIC_REFUSAL, "generic wording kept");
                for (String leak : List.of("unknown", "exist", "locked", "disabled", "expired",
                        "unusual", "not found")) {
                    check(!refusal.message().toLowerCase(java.util.Locale.ROOT).contains(leak),
                            "the refusal does not mention " + leak);
                }
            }
        }
    }

    // ------------------------------------------------------------------ timing

    private static void everyAnswerCostsTheSame() {
        section("timing (one hashing round per answer, whatever the reason)");
        Fixture f = new Fixture(5, TIMED_COST);
        for (int i = 0; i < 5; i++) {
            f.login("ghost.employee", "warm-" + i); // this name is the locked one below
        }
        for (int i = 0; i < 2; i++) { // warm every branch up before measuring it
            f.login("alice.jones", "Wint3r!Sky-2026");
            f.login("alice.jones", "wrong-guess");
            f.login("nobody.person", "wrong-guess");
            f.login("ghost.employee", "wrong-guess");
            f.login("al", "wrong-guess");
            f.login("alice.jones", "");
        }
        Duration unknown = medianOf(() -> f.login("nobody.person", "wrong-guess"));
        Duration wrongPassword = medianOf(() -> f.login("bob.smith", "wrong-guess"));
        Duration locked = medianOf(() -> f.login("ghost.employee", "wrong-guess"));
        Duration badName = medianOf(() -> f.login("al", "wrong-guess"));
        Duration badPassword = medianOf(() -> f.login("alice.jones", ""));
        Duration granted = medianOf(() -> f.login("alice.jones", "Wint3r!Sky-2026"));

        long[] answers = {unknown.toNanos(), wrongPassword.toNanos(), locked.toNanos(),
                badName.toNanos(), badPassword.toNanos(), granted.toNanos()};
        String[] names = {"unknown name", "wrong password", "locked", "bad name", "bad password",
                "granted"};
        long fastest = Long.MAX_VALUE;
        long slowest = 0;
        for (long answer : answers) {
            fastest = Math.min(fastest, answer);
            slowest = Math.max(slowest, answer);
        }
        for (int i = 0; i < answers.length; i++) {
            System.out.printf("        %-15s %8d us%n", names[i], answers[i] / 1000);
            check(answers[i] / 1000 > 20_000,
                    names[i] + " paid for a hash too - a free refusal would be a fingerprint");
        }
        double spread = (double) slowest / (double) fastest;
        System.out.printf("        spread %.2fx%n", spread);
        // The lower bound is not decoration: without it a broken max/min computation reports a
        // perfect-looking 0.00x and this check would pass on nothing.
        check(spread >= 1.0 && spread < 3.0, "no answer arrives more than 3x faster than another"
                + " (got " + String.format(java.util.Locale.ROOT, "%.2f", spread) + "x)");
    }

    private static Duration medianOf(Runnable work) {
        long[] samples = new long[3];
        for (int i = 0; i < samples.length; i++) {
            long start = System.nanoTime();
            work.run();
            samples[i] = System.nanoTime() - start;
        }
        Arrays.sort(samples);
        return Duration.ofNanos(samples[1]);
    }

    // ------------------------------------------------------------------ options

    private static void optionsAreValidated() {
        section("command line options");
        try {
            EmployeePortalApp.Options options = EmployeePortalApp.Options.parse(
                    new String[] {"--max-failures", "2", "--lock-minutes", "1",
                            "--iterations", String.valueOf(FAST)});
            checkEquals(options.maxFailures, 2, "--max-failures parsed");
            checkEquals(options.lockMinutes, 1L, "--lock-minutes parsed");
            checkEquals(options.iterations, FAST, "--iterations parsed");
            check(!options.help, "help stays off unless asked for");
            checkThrows(IllegalArgumentException.class,
                    () -> EmployeePortalApp.Options.parse(new String[] {"--records"}),
                    "--records with no file is refused");
        } catch (IllegalArgumentException e) {
            check(false, "valid options were accepted: " + e.getMessage());
        }
        refusesOptions(new String[] {"--nope"}, "an unknown option is refused");
        refusesOptions(new String[] {"--max-failures"}, "--max-failures with no value");
        refusesOptions(new String[] {"--max-failures", "zero"}, "a value that is not a number");
        refusesOptions(new String[] {"--max-failures", "0"}, "a limit below one");
        refusesOptions(new String[] {"--iterations", "10"}, "a cost below the allowed minimum");
    }

    private static void refusesOptions(String[] args, String what) {
        checkThrows(IllegalArgumentException.class, () -> EmployeePortalApp.Options.parse(args),
                what);
    }

    // ------------------------------------------------------------------ helpers

    private static PasswordHash hash(String password) {
        return PasswordHash.create(password.toCharArray(), RANDOM, FAST);
    }

    private static String brokenSaltHash() {
        String[] parts = hash("x1").encode().split("\\$");
        return PasswordHash.TAG + "$" + FAST + "$!!!!$" + parts[3];
    }

    private static int countOf(String text, String needle) {
        int found = 0;
        for (int at = text.indexOf(needle); at >= 0; at = text.indexOf(needle, at + needle.length())) {
            found++;
        }
        return found;
    }

    private static String captureOutput(Runnable work) {
        PrintStream original = System.out;
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        PrintStream capture = new PrintStream(buffer, true, StandardCharsets.UTF_8);
        System.setOut(capture);
        try {
            work.run();
        } finally {
            capture.flush();
            System.setOut(original);
        }
        return buffer.toString(StandardCharsets.UTF_8);
    }

    private static void section(String name) {
        System.out.println("== " + name);
    }

    private static void check(boolean condition, String what) {
        if (condition) {
            passed++;
        } else {
            failed++;
            System.out.println("  FAIL " + what);
        }
    }

    private static void checkEquals(Object actual, Object expected, String what) {
        if (expected.equals(actual)) {
            passed++;
        } else {
            failed++;
            System.out.println("  FAIL " + what + " (expected <" + expected + "> got <" + actual
                    + ">)");
        }
    }

    private static void checkThrows(Class<? extends Exception> expected, ThrowingRunnable body,
                                    String what) {
        try {
            body.run();
            failed++;
            System.out.println("  FAIL " + what + " (expected " + expected.getSimpleName()
                    + ", nothing was thrown)");
        } catch (Exception thrown) {
            if (expected.isInstance(thrown)) {
                passed++;
            } else {
                failed++;
                System.out.println("  FAIL " + what + " (expected " + expected.getSimpleName()
                        + " got " + thrown.getClass().getSimpleName() + ")");
            }
        }
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    /** One store, one tracker, one authenticator, at the limits the caller asks for. */
    private static final class Fixture {

        private final InMemoryCredentialStore store;
        private final LoginAttemptTracker tracker;
        private final Authenticator authenticator;
        private final ClockStub clock;

        Fixture(int maxFailures) {
            this(maxFailures, FAST);
        }

        Fixture(int maxFailures, int iterations) {
            this.store = new InMemoryCredentialStore(RANDOM, iterations);
            this.store.addEmployee("alice.jones", "Alice Jones", "Wint3r!Sky-2026".toCharArray());
            this.store.addEmployee("bob.smith", "Bob Smith", "C0ffee#Mug77".toCharArray());
            this.tracker = new LoginAttemptTracker(maxFailures, Duration.ofMinutes(15));
            this.clock = new ClockStub(Instant.parse("2026-09-12T09:00:00Z"));
            this.authenticator = new Authenticator(store, tracker, clock, iterations);
        }

        /** Types a password and wipes the buffer afterwards, the way the real session does. */
        private LoginResult login(String username, String password) {
            char[] buffer = password.toCharArray();
            try {
                return authenticator.login(username, buffer);
            } finally {
                Arrays.fill(buffer, '\0');
            }
        }
    }

    /** A clock the test moves by hand, so a 15 minute lock is not a 15 minute test. */
    private static final class ClockStub extends Clock {

        private Instant now;

        ClockStub(Instant start) {
            this.now = start;
        }

        void advance(Duration amount) {
            now = now.plus(amount);
        }

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }
    }

    /** Types a prepared script: entries starting with {@code u:} are seen, {@code s:} are secrets. */
    private static final class ScriptedPrompter implements CredentialPrompter {

        private final Deque<String> visible = new ArrayDeque<>();
        private final Deque<String> secrets = new ArrayDeque<>();

        ScriptedPrompter(List<String> script) {
            for (String entry : script) {
                if (entry.startsWith("s:")) {
                    secrets.addLast(entry.substring(2));
                } else if (entry.startsWith("u:")) {
                    visible.addLast(entry.substring(2));
                } else {
                    throw new IllegalArgumentException("script entry needs a u: or s: prefix");
                }
            }
        }

        @Override
        public String readLine(String prompt) {
            System.out.println(prompt + " " + visible.peekFirst());
            return visible.isEmpty() ? null : visible.pollFirst();
        }

        @Override
        public char[] readSecret(String prompt) {
            System.out.println(prompt + " ********");
            return secrets.isEmpty() ? null : secrets.pollFirst().toCharArray();
        }

        @Override
        public boolean hidesSecret() {
            return true;
        }
    }
}
