import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Self-contained test suite for {@link LoginService}: run with
 * {@code java -ea -cp <classes> LoginServiceTest}. Exit code 0 means every check passed.
 *
 * <p>Two conventions keep the results trustworthy. Lockout state is shared mutable
 * state, so anything that loops over candidate passwords uses a tracker that cannot
 * lock, and the lock itself is exercised in its own fixture with a deterministic clock.
 * Timing is asserted per refusal shape rather than as a single known-vs-unknown
 * comparison, because each early return in {@code login} is a separate oracle.
 */
public final class LoginServiceTest {

    private static final AtomicInteger CHECKS = new AtomicInteger();
    private static final List<String> FAILURES = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        long t0 = System.nanoTime();
        correctPasswordGrantsAccess();
        wrongPasswordFailsGenerically();
        unknownUserIsIndistinguishable();
        matchingIsExactNotFoldedOrTrimmed();
        malformedInputRefusedWithoutTouchingStore();
        nonInjectivePasswordsRefused();
        losslessPasswordsStillWork();
        storedRecordShapeAndSaltUniqueness();
        verificationHonoursEmbeddedIterations();
        tamperedRecordsFailWithoutThrowing();
        storedCredentialIsNotThePassword();
        loginDoesNotMutateOrRetainTheCallerArray();
        lockTripsAndIsReportedOnTheNextAttempt();
        successDoesNotLiftALock();
        lockExpiryRestoresAFreshFailureBudget();
        trackerItselfEnforcesTheWindow();
        failuresSpreadOverTimeAreForgotten();
        consecutiveLocksBackOffAndCap();
        operatorCanClearALock();
        unknownUsernameStateIsSwept();
        disabledAccountNeverAuthenticates();
        concurrentFailuresEngageTheLock();
        auditSeesEveryOutcomeAndNoCredentials();
        refusalCostsMatchASuccessfulCheck();

        int checks = CHECKS.get();
        long seconds = (System.nanoTime() - t0) / 1_000_000_000L;
        System.out.println();
        if (FAILURES.isEmpty()) {
            System.out.println("PASS: " + checks + " checks in " + seconds + "s");
            return;
        }
        System.out.println("FAIL: " + FAILURES.size() + " of " + checks + " checks failed in "
                + seconds + "s");
        for (String failure : FAILURES) {
            System.out.println("  - " + failure);
        }
        System.exit(1);
    }

    // -------------------------------------------------------------- happy path

    private static void correctPasswordGrantsAccess() {
        section("correct password grants access");
        Fixture f = fixture("alice", "Corr3ct-Horse-Battery");
        LoginService.LoginOutcome outcome = f.service.login("alice", "Corr3ct-Horse-Battery".toCharArray());
        eq("status", LoginService.LoginStatus.SUCCESS, outcome.status());
        check("granted()", outcome.granted());
        eq("failure counter reset", 0, f.tracker.failureCount("alice"));
    }

    private static void wrongPasswordFailsGenerically() {
        section("wrong password fails");
        Fixture f = fixture("alice", "Corr3ct-Horse-Battery");
        // The tracker must not lock mid-matrix, or the tail of this loop would report
        // ACCOUNT_LOCKED for code that is behaving correctly.
        String[] wrong = {"", "Corr3ct-Horse-Batter", "corr3ct-horse-battery", "x".repeat(80),
                "Corr3ct-Horse-Battery\0", "Corr3ct-Horse-Battery ", "password", "123456",
                "Corr3ct-Horse-Batteries"};
        for (String candidate : wrong) {
            LoginService.LoginOutcome outcome = f.service.login("alice", candidate.toCharArray());
            check("refused '" + describe(candidate) + "'", outcome.status() == LoginService.LoginStatus.INVALID_CREDENTIALS);
            eq("wording '" + describe(candidate) + "'", LoginService.INVALID_MESSAGE, outcome.message());
            check("not granted '" + describe(candidate) + "'", !outcome.granted());
        }
        check("account still usable afterwards",
                f.service.login("alice", "Corr3ct-Horse-Battery".toCharArray()).granted());
    }

    private static void unknownUserIsIndistinguishable() {
        section("unknown user is indistinguishable from a wrong password");
        Fixture f = fixture("alice", "Corr3ct-Horse-Battery");
        LoginService.LoginOutcome unknown = f.service.login("mallory", "whatever-123456".toCharArray());
        LoginService.LoginOutcome wrong = f.service.login("alice", "wrong-password".toCharArray());
        eq("same status", wrong.status(), unknown.status());
        eq("same wording", wrong.message(), unknown.message());
        eq("same retry hint", wrong.retryInSeconds(), unknown.retryInSeconds());
        check("unknown name is still counted for lockout", f.tracker.failureCount("mallory") > 0);
    }

    private static void matchingIsExactNotFoldedOrTrimmed() {
        section("matching is exact, not folded or trimmed");
        Fixture f = fixture("alice", "Corr3ct-Horse-Battery");
        check("Alice is a different key",
                f.service.login("Alice", "Corr3ct-Horse-Battery".toCharArray()).status()
                        == LoginService.LoginStatus.INVALID_CREDENTIALS);
        check("trimming is not applied to the username",
                f.service.login(" alice", "Corr3ct-Horse-Battery".toCharArray()).status()
                        == LoginService.LoginStatus.INVALID_CREDENTIALS);
        check("trailing space in the password is a different secret",
                !f.service.login("alice", "Corr3ct-Horse-Battery ".toCharArray()).granted());
    }

    private static void malformedInputRefusedWithoutTouchingStore() {
        section("malformed input is refused before the store is consulted");
        Fixture f = fixture("alice", "Corr3ct-Horse-Battery");
        int storeBefore = f.store.size();
        String[] names = {null, "", " lead", "trail ", "a b", "-lead", "\u00e9clair",
                "x".repeat(65), "tab\tname", "new\nline", "semi;colon", "quote\"d", "slash/id",
                "' OR '1'='1", "drop table users;--", "%27%20or%201=1", "<script>alert(1)</script>",
                "\u202Eevil", "a".repeat(1000)};
        for (String name : names) {
            LoginService.LoginOutcome outcome = f.service.login(name, "any-password-123".toCharArray());
            check("refused name " + describe(name), outcome.status() == LoginService.LoginStatus.INVALID_CREDENTIALS);
            eq("generic wording for " + describe(name), LoginService.INVALID_MESSAGE, outcome.message());
            check("SQL-ish name not normalised into a key: " + describe(name),
                    !LoginService.isWellFormedUsername(name));
        }
        eq("store untouched", storeBefore, f.store.size());
        eq("no tracker entry created", 0, f.tracker.trackedKeys());

        LoginService.LoginOutcome nullPassword = f.service.login("alice", null);
        eq("null password refused", LoginService.LoginStatus.INVALID_CREDENTIALS, nullPassword.status());
        eq("null password wording", LoginService.INVALID_MESSAGE, nullPassword.message());
    }

    // -------------------------------------------------------------- key derivation

    private static void nonInjectivePasswordsRefused() {
        section("passwords the JCE would silently rewrite are refused");
        Fixture f = fixture("alice", "Corr3ct-Horse-Battery");
        // PBEKeySpec drops trailing NULs, so "secret" and "secret\0" would otherwise
        // derive identically and one person's secret would verify as another's.
        check("trailing NUL is not hashable", !LoginService.PasswordHasher.isHashable("secret\0".toCharArray()));
        check("two trailing NULs are not hashable",
                !LoginService.PasswordHasher.isHashable("secret\0\0".toCharArray()));
        check("trailing NUL cannot log in", !f.service.login("alice", "Corr3ct-Horse-Battery\0".toCharArray()).granted());
        // Every unpaired surrogate maps to '?', so all of these would collide with "q?".
        String[] surrogates = {"q" + (char) 0xD800, "q" + (char) 0xDFFF, "q" + (char) 0xDC00 + "x",
                "" + (char) 0xDEAD, "abc" + (char) 0xD800 + (char) 0xD801};
        for (String candidate : surrogates) {
            check("unpaired surrogate refused: " + describe(candidate),
                    !LoginService.PasswordHasher.isHashable(candidate.toCharArray()));
            check("unpaired surrogate cannot log in: " + describe(candidate),
                    !f.service.login("alice", candidate.toCharArray()).granted());
        }
        LoginService.PasswordHasher hasher = new LoginService.PasswordHasher(2_000);
        String stored = hasher.hash("collide-me".toCharArray());
        check("a refused password cannot be stored either", throwsIAE(() -> hasher.hash("bad\0".toCharArray())));
        check("the collide-me record still rejects an unpaired surrogate",
                !hasher.matches(("collide-me" + (char) 0xD800).toCharArray(), stored));
        // The sharp form of the collision: the JCE drops this candidate's trailing NUL, so
        // verifying it against the record of the password it collides with must be refused by
        // the shape check, not settled by deriving the mangled value.
        check("a trailing NUL cannot borrow the record of the password it collides with",
                !hasher.matches("collide-me\0".toCharArray(), stored));
        check("neither can two trailing NULs", !hasher.matches("collide-me\0\0".toCharArray(), stored));
        check("and the shape check runs before any derivation is trusted",
                !hasher.matches("collide-me\0".toCharArray(), hasher.hash("collide-me".toCharArray())));

        Fixture empty = fixture("bob", "hunter2-hunter2!");
        eq("empty password refused", LoginService.LoginStatus.INVALID_CREDENTIALS,
                empty.service.login("bob", new char[0]).status());
        check("oversized password refused",
                !LoginService.PasswordHasher.isHashable(new char[2_000]));
    }

    private static void losslessPasswordsStillWork() {
        section("passwords that round-trip losslessly keep working");
        LoginService.PasswordHasher hasher = new LoginService.PasswordHasher(2_000);
        String[] ok = {"pa\0ss", "caf\u00e9", "pass phrase with spaces", "tab\tsep",
                "new\nline", "emoji \uD83D\uDE00 rock", "\u4e2d\u6587\u5bc6\u7801", "\u00fc\u00f6\u00e4",
                "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", "a".repeat(1024)};
        for (String password : ok) {
            check("hashable: " + describe(password),
                    LoginService.PasswordHasher.isHashable(password.toCharArray()));
            String stored = hasher.hash(password.toCharArray());
            check("verifies: " + describe(password), hasher.matches(password.toCharArray(), stored));
        }
        check("interior NUL is a distinct secret from the plain value",
                !hasher.matches("pass".toCharArray(), hasher.hash("pa\0ss".toCharArray())));
        check("trailing space is a distinct secret",
                !hasher.matches("caf\u00e9".toCharArray(), hasher.hash("caf\u00e9 ".toCharArray())));

        Fixture f = fixture("carol", "\u4e2d\u6587\u5bc6\u7801");
        check("unicode password logs in", f.service.login("carol", "\u4e2d\u6587\u5bc6\u7801".toCharArray()).granted());
        Fixture emoji = fixture("dave", "emoji \uD83D\uDE00 rock");
        check("astral password logs in", emoji.service.login("dave", "emoji \uD83D\uDE00 rock".toCharArray()).granted());
    }

    private static void storedRecordShapeAndSaltUniqueness() {
        section("stored records are salted PBKDF2 digests");
        LoginService.PasswordHasher hasher = new LoginService.PasswordHasher(2_000);
        char[] password = "same-password-every-time".toCharArray();
        String first = hasher.hash(password);
        String second = hasher.hash(password);
        String[] parts = first.split("\\$", -1);
        eq("four fields", 4, parts.length);
        eq("algorithm prefix", "pbkdf2", parts[0]);
        eq("embedded iterations", "2000", parts[1]);
        byte[] salt = Base64.getDecoder().decode(parts[2]);
        byte[] key = Base64.getDecoder().decode(parts[3]);
        eq("16-byte salt", 16, salt.length);
        eq("32-byte derived key", 32, key.length);
        check("salt is not the password", !first.contains("same-password"));
        check("key is not the password", !new String(key, java.nio.charset.StandardCharsets.US_ASCII)
                .contains("same"));
        check("two registrations of one password differ (fresh salt)", !first.equals(second));
        check("both still verify", hasher.matches(password, first) && hasher.matches(password, second));
        check("iterations are inside the accepted band",
                hasher.iterations() >= LoginService.PasswordHasher.MIN_ITERATIONS
                        && hasher.iterations() <= LoginService.PasswordHasher.MAX_ITERATIONS);
        check("the shipped default is a real cost (>= 100k rounds here)",
                LoginService.PasswordHasher.DEFAULT_ITERATIONS >= 100_000);
        check("the timing-equaliser record is a genuine record",
                parseable(hasher.hash("throwaway-value".toCharArray())));
        check("constructor rejects an absurd cost",
                throwsIAE(() -> new LoginService.PasswordHasher(10)));
        check("constructor rejects an excessive cost",
                throwsIAE(() -> new LoginService.PasswordHasher(50_000_000)));
    }

    private static void verificationHonoursEmbeddedIterations() {
        section("verification honours the stored cost factor");
        LoginService.PasswordHasher legacy = new LoginService.PasswordHasher(2_000);
        LoginService.PasswordHasher current = new LoginService.PasswordHasher(4_000);
        String oldRecord = legacy.hash("legacy-password".toCharArray());
        check("a record hashed at the old cost still verifies",
                current.matches("legacy-password".toCharArray(), oldRecord));
        check("and still rejects a wrong password",
                !current.matches("wrong-password".toCharArray(), oldRecord));
        check("rehashing at the new cost produces a stronger record",
                current.hash("legacy-password".toCharArray()).split("\\$")[1].equals("4000"));
    }

    private static void tamperedRecordsFailWithoutThrowing() {
        section("tampered or corrupt records fail closed");
        LoginService.PasswordHasher hasher = new LoginService.PasswordHasher(2_000);
        char[] password = "record-under-test".toCharArray();
        String stored = hasher.hash(password);
        check("baseline verifies", hasher.matches(password, stored));

        List<String> broken = new ArrayList<>();
        broken.add(null);
        broken.add("");
        broken.add("plaintext-password");
        broken.add(stored.substring(0, stored.length() - 4));
        broken.add("pbkdf2$2000$####$" + stored.split("\\$")[3]);
        broken.add("bcrypt$" + stored.split("\\$")[1] + "$" + stored.split("\\$")[2] + "$"
                + stored.split("\\$")[3]);
        broken.add("pbkdf2$not-a-number$" + stored.split("\\$")[2] + "$" + stored.split("\\$")[3]);
        broken.add("pbkdf2$7$" + stored.split("\\$")[2] + "$" + stored.split("\\$")[3]);
        broken.add("pbkdf2$999999999$" + stored.split("\\$")[2] + "$" + stored.split("\\$")[3]);
        broken.add("pbkdf2$2000$$" + stored.split("\\$")[3]);
        broken.add(stored + "$" + stored.split("\\$")[3]);
        broken.add(flippedDecodedByte(stored, 3));
        broken.add(flippedDecodedByte(stored, 2));
        for (String candidate : broken) {
            check("rejected without throwing: " + describe(candidate),
                    !hasher.matches(password, candidate));
            check("and rejects the right password too: " + describe(candidate),
                    !hasher.matches("another-password".toCharArray(), candidate));
        }
        // A store row that cannot be parsed must not become an open door via an exception.
        LoginService.PasswordHasher corruptHasher = new LoginService.PasswordHasher(2_000);
        LoginService corruptService = new LoginService(
                new CorruptStore("erin", "pbkdf2$2000$Zm9v$not-base64-at-all"), corruptHasher,
                new LoginService.LoginAttemptTracker(1_000, Duration.ofMinutes(15),
                        Duration.ofMinutes(10)));
        eq("corrupt row refuses the good password", LoginService.LoginStatus.INVALID_CREDENTIALS,
                corruptService.login("erin", "good-password".toCharArray()).status());
        eq("corrupt row keeps generic wording", LoginService.INVALID_MESSAGE,
                corruptService.login("erin", "good-password".toCharArray()).message());
    }

    private static void storedCredentialIsNotThePassword() {
        section("the store never holds the password");
        Fixture f = fixture("alice", "Corr3ct-Horse-Battery");
        String stored = f.store.find("alice").orElseThrow().hashedPassword();
        check("stored record does not contain the password", !stored.contains("Corr3ct"));
        check("stored record is a pbkdf2 record", stored.startsWith("pbkdf2$"));
        check("Account.toString does not echo the secret",
                !f.store.find("alice").orElseThrow().toString().contains("Corr3ct"));
    }

    private static void loginDoesNotMutateOrRetainTheCallerArray() {
        section("login leaves the caller's password array alone");
        Fixture f = fixture("alice", "Corr3ct-Horse-Battery");
        char[] candidate = "Corr3ct-Horse-Battery".toCharArray();
        char[] copy = candidate.clone();
        f.service.login("alice", candidate);
        check("array contents unchanged", Arrays.equals(copy, candidate));
        check("a second attempt with the same array still works",
                f.service.login("alice", candidate).granted());
    }

    // ------------------------------------------------------------------ lockout

    private static void lockTripsAndIsReportedOnTheNextAttempt() {
        section("the lock trips on the threshold failure and reports on the next one");
        MutableClock clock = new MutableClock(1_000_000L);
        LoginService.PasswordHasher hasher = new LoginService.PasswordHasher(2_000);
        LoginService.InMemoryAccountStore store = new LoginService.InMemoryAccountStore(hasher);
        enroll(store, "bob", "right-password");
        LoginService.LoginAttemptTracker tracker = tracker(3, 60_000L, 1.0d, 60_000L,
                Duration.ofHours(1), Duration.ofHours(2), clock);
        LoginService service = new LoginService(store, hasher, tracker);

        eq("failure 1", LoginService.LoginStatus.INVALID_CREDENTIALS, attempt(service, "bob", "wrong-1"));
        eq("failure 2", LoginService.LoginStatus.INVALID_CREDENTIALS, attempt(service, "bob", "wrong-2"));
        eq("failure 3 (the one that trips)", LoginService.LoginStatus.INVALID_CREDENTIALS,
                attempt(service, "bob", "wrong-3"));
        eq("counter reset once the lock tripped", 0, tracker.failureCount("bob"));
        LoginService.LoginOutcome locked = service.login("bob", "wrong-4".toCharArray());
        eq("attempt 4 sees the lock", LoginService.LoginStatus.ACCOUNT_LOCKED, locked.status());
        eq("lock wording", LoginService.LOCKED_MESSAGE, locked.message());
        check("retry hint is positive", locked.retryInSeconds() > 0);
        check("retry hint covers the remaining window", locked.retryInSeconds() >= 60);
        check("lock is active", tracker.remainingLockMillis("bob") > 0);

        clock.advance(30_000L);
        eq("still locked halfway through", LoginService.LoginStatus.ACCOUNT_LOCKED, attempt(service, "bob", "wrong-5"));
        clock.advance(31_000L);
        eq("lock has expired", LoginService.LoginStatus.INVALID_CREDENTIALS, attempt(service, "bob", "wrong-6"));

        // While suspended, extra failures must neither be counted twice nor push the
        // release time out: only the timer owns the lock. The clock advances so that a
        // release time silently pushed forward by a stray write is actually observable.
        MutableClock idle = new MutableClock(5_000L);
        LoginService.LoginAttemptTracker quiet = tracker(1, 10_000L, 1.0d, 10_000L,
                Duration.ofHours(1), Duration.ofHours(2), idle);
        check("the only strike trips the lock", quiet.recordFailure("k"));
        eq("the configured lock duration is granted", 10_000L, quiet.remainingLockMillis("k"));
        for (int i = 1; i <= 10; i++) {
            check("a failure during the lock is not itself a new trip", !quiet.recordFailure("k"));
            idle.advance(500L);
        }
        eq("failures during the lock are not counted", 0, quiet.failureCount("k"));
        eq("the release time is owned by the timer alone", 5_000L, quiet.remainingLockMillis("k"));
        idle.advance(5_001L);
        eq("the lock ends when the timer says, not later", 0L, quiet.remainingLockMillis("k"));
    }

    private static void successDoesNotLiftALock() {
        section("a later success cannot lift a lock");
        MutableClock clock = new MutableClock(500L);
        Fixture f = lockedFixture(3, 60_000L, clock);
        lockAccount(f, "bob", 3);
        eq("locked", LoginService.LoginStatus.ACCOUNT_LOCKED, attempt(f.service, "bob", "right-password"));
        f.tracker.recordSuccess("bob");
        eq("success left the lock in place", LoginService.LoginStatus.ACCOUNT_LOCKED,
                attempt(f.service, "bob", "right-password"));
        check("lock still has time left", f.tracker.remainingLockMillis("bob") > 0);
        clock.advance(61_000L);
        eq("the timer, not the success, ends the lock", LoginService.LoginStatus.SUCCESS,
                attempt(f.service, "bob", "right-password"));
    }

    private static void lockExpiryRestoresAFreshFailureBudget() {
        section("a released account gets a fresh failure budget");
        MutableClock clock = new MutableClock(900L);
        Fixture f = lockedFixture(2, 100_000L, clock);
        lockAccount(f, "bob", 2);
        clock.advance(101_000L);
        eq("unlocked again", LoginService.LoginStatus.INVALID_CREDENTIALS, attempt(f.service, "bob", "wrong-a"));
        eq("one failure counted, not three", 1, f.tracker.failureCount("bob"));
        eq("the second failure trips it again", LoginService.LoginStatus.INVALID_CREDENTIALS,
                attempt(f.service, "bob", "wrong-b"));
        eq("locked on the next attempt", LoginService.LoginStatus.ACCOUNT_LOCKED,
                attempt(f.service, "bob", "wrong-c"));
    }

    /**
     * The rolling window is also asserted straight against the tracker. Reaching it only
     * through {@code login} would not prove much: the login path asks for the remaining lock
     * first, and that call prunes the window on its own, so a window rule that only exists in
     * the failure path can survive every service-level check.
     */
    private static void trackerItselfEnforcesTheWindow() {
        section("the tracker enforces the window without help from the login path");
        MutableClock clock = new MutableClock(1_000L);
        LoginService.LoginAttemptTracker tracker = tracker(3, 60_000L, 1.0d, 60_000L,
                Duration.ofSeconds(30), Duration.ofHours(1), clock);

        check("strike 1 is not a trip", !tracker.recordFailure("typed"));
        eq("one counted", 1, tracker.failureCount("typed"));
        clock.advance(20_000L);
        check("strike 2 is not a trip", !tracker.recordFailure("typed"));
        eq("two counted", 2, tracker.failureCount("typed"));

        // Strike 3 lands 45s after strike 1, which is outside the 30s window, so the count
        // has to restart from one rather than reach the threshold of three.
        clock.advance(25_000L);
        check("strike 3 must not trip after the window moved on", !tracker.recordFailure("typed"));
        eq("the stale strike was dropped", 1, tracker.failureCount("typed"));
        eq("so the account is not suspended", 0L, tracker.remainingLockMillis("typed"));

        clock.advance(1_000L);
        check("strike 4", !tracker.recordFailure("typed"));
        clock.advance(1_000L);
        check("strike 5 trips once three land inside one window", tracker.recordFailure("typed"));
        eq("suspended for the configured duration", 60_000L, tracker.remainingLockMillis("typed"));
    }

    private static void failuresSpreadOverTimeAreForgotten() {
        section("failures only count while they fall inside the rolling window");
        MutableClock spreadClock = new MutableClock(10L);
        Fixture spread = new Fixture(new LoginService.PasswordHasher(2_000),
                tracker(3, 60_000L, 1.0d, 60_000L, Duration.ofSeconds(30), Duration.ofMinutes(30), spreadClock));
        enroll(spread.store, "bob", "right-password");
        eq("failure 1", LoginService.LoginStatus.INVALID_CREDENTIALS,
                attempt(spread.service, "bob", "wrong-1"));
        spreadClock.advance(10_000L);
        eq("failure 2", LoginService.LoginStatus.INVALID_CREDENTIALS,
                attempt(spread.service, "bob", "wrong-2"));
        eq("both in-window failures counted", 2, spread.tracker.failureCount("bob"));
        spreadClock.advance(25_000L); // failure 1 is now 35s old, outside the 30s window
        eq("failure 3", LoginService.LoginStatus.INVALID_CREDENTIALS,
                attempt(spread.service, "bob", "wrong-3"));
        eq("the stale failure was forgotten", 1, spread.tracker.failureCount("bob"));
        eq("three spread-out failures did not lock", 0L, spread.tracker.remainingLockMillis("bob"));
        eq("and the account is still usable", LoginService.LoginStatus.SUCCESS,
                attempt(spread.service, "bob", "right-password"));

        // Contrast: the same three failures landing inside the window must lock.
        MutableClock tightClock = new MutableClock(10L);
        Fixture packed = new Fixture(new LoginService.PasswordHasher(2_000),
                tracker(3, 60_000L, 1.0d, 60_000L, Duration.ofSeconds(30), Duration.ofMinutes(30), tightClock));
        enroll(packed.store, "carol", "right-password");
        attempt(packed.service, "carol", "wrong-1");
        tightClock.advance(1_000L);
        attempt(packed.service, "carol", "wrong-2");
        tightClock.advance(1_000L);
        attempt(packed.service, "carol", "wrong-3");
        eq("three failures inside the window engage the lock", LoginService.LoginStatus.ACCOUNT_LOCKED,
                attempt(packed.service, "carol", "right-password"));
    }

    private static void consecutiveLocksBackOffAndCap() {
        section("consecutive locks escalate and stop at the cap");
        MutableClock clock = new MutableClock(1L);
        Fixture f = new Fixture(new LoginService.PasswordHasher(2_000),
                tracker(1, 100L, 2.0d, 800L, Duration.ofMinutes(10), Duration.ofMinutes(10), clock));
        enroll(f.store, "bob", "right-password");
        long[] expected = {100L, 200L, 400L, 800L, 800L};
        for (int i = 0; i < expected.length; i++) {
            f.service.login("bob", ("wrong-" + i).toCharArray());
            long remaining = f.tracker.remainingLockMillis("bob");
            check("lock " + (i + 1) + " lasts about " + expected[i] + "ms (was " + remaining + "ms)",
                    remaining > expected[i] - 20L && remaining <= expected[i]);
            clock.advance(expected[i] + 5L);
            eq("lock " + (i + 1) + " then expires", 0L, f.tracker.remainingLockMillis("bob"));
        }
    }

    private static void operatorCanClearALock() {
        section("an operator can lift a lock");
        MutableClock clock = new MutableClock(77L);
        Fixture f = lockedFixture(2, 600_000L, clock);
        lockAccount(f, "bob", 2);
        eq("locked", LoginService.LoginStatus.ACCOUNT_LOCKED, attempt(f.service, "bob", "right-password"));
        f.tracker.clear("bob");
        eq("cleared", 0L, f.tracker.remainingLockMillis("bob"));
        eq("login works again immediately", LoginService.LoginStatus.SUCCESS,
                attempt(f.service, "bob", "right-password"));
    }

    private static void unknownUsernameStateIsSwept() {
        section("state for usernames that were never real is swept");
        MutableClock clock = new MutableClock(5L);
        LoginService.LoginAttemptTracker tracker = tracker(5, 1_000L, 1.0d, 1_000L,
                Duration.ofSeconds(30), Duration.ofSeconds(5), clock);
        for (int i = 0; i < 200; i++) {
            tracker.recordFailure("guessed-name-" + i);
        }
        eq("every guess is tracked for now", 200, tracker.trackedKeys());

        // The next batch is recorded 6s later, so the first batch is past the 5s retention
        // and the periodic sweep driven by recordFailure must reclaim exactly those 200.
        clock.advance(6_000L);
        for (int i = 200; i < 400; i++) {
            tracker.recordFailure("guessed-name-" + i);
        }
        eq("the periodic sweep reclaimed the stale batch only", 200, tracker.trackedKeys());
        clock.advance(6_000L);
        eq("a later sweep clears the remaining batch", 200, tracker.purgeExpired());
        eq("map is empty", 0, tracker.trackedKeys());

        tracker.recordFailure("guess-again");
        eq("tracking restarts after a sweep", 1, tracker.trackedKeys());
        expiredLockIsReclaimedByTheSweep(clock.getAsLong());
        check("null username is rejected outright",
                throwsIAE(() -> tracker.recordFailure(null)));
        check("empty username is rejected outright",
                throwsIAE(() -> tracker.remainingLockMillis("")));
    }

    /**
     * A suspended entry has to outlive a sweep, and then be reclaimed once its lock
     * expires. The reads are spread right up to the release time because that is what a
     * locked account actually sees: if a read refreshed the idle stamp, the entry would go
     * on looking busy and never be swept.
     */
    private static void expiredLockIsReclaimedByTheSweep(long now) {
        MutableClock own = new MutableClock(now);
        LoginService.LoginAttemptTracker tracker = tracker(1, 60_000L, 1.0d, 60_000L,
                Duration.ofMinutes(10), Duration.ofSeconds(1), own);
        tracker.recordFailure("victim");
        eq("the entry is suspended for the full lock duration", 60_000L,
                tracker.remainingLockMillis("victim"));
        while (tracker.remainingLockMillis("victim") > 500L) {
            own.advance(100L);
        }
        eq("still tracked while suspended", 1, tracker.trackedKeys());
        own.advance(501L);
        eq("idle shortly after the lock expires, so the sweep reclaims it", 1, tracker.purgeExpired());
        eq("map is empty", 0, tracker.trackedKeys());
    }

    private static void disabledAccountNeverAuthenticates() {
        section("a disabled account never authenticates");
        LoginService.PasswordHasher hasher = new LoginService.PasswordHasher(2_000);
        LoginService.InMemoryAccountStore store = new LoginService.InMemoryAccountStore(hasher);
        enroll(store, "svc-batch", "d1sabled-s3cret", false);
        LoginService.LoginAttemptTracker tracker = new LoginService.LoginAttemptTracker(
                1_000, Duration.ofMinutes(15), Duration.ofMinutes(10));
        LoginService service = new LoginService(store, hasher, tracker);
        LoginService.LoginOutcome outcome = service.login("svc-batch", "d1sabled-s3cret".toCharArray());
        eq("disabled account refused", LoginService.LoginStatus.INVALID_CREDENTIALS, outcome.status());
        eq("with generic wording", LoginService.INVALID_MESSAGE, outcome.message());
        check("and the failure still counts", tracker.failureCount("svc-batch") > 0);
    }

    private static void concurrentFailuresEngageTheLock() {
        section("concurrent failures still engage the lock");
        LoginService.PasswordHasher hasher = new LoginService.PasswordHasher(2_000);
        LoginService.InMemoryAccountStore store = new LoginService.InMemoryAccountStore(hasher);
        enroll(store, "race", "right-password");
        LoginService.LoginAttemptTracker tracker = new LoginService.LoginAttemptTracker(
                4, Duration.ofMinutes(15), Duration.ofHours(1));
        LoginService service = new LoginService(store, hasher, tracker);

        final int threads = 24;
        AtomicInteger successes = new AtomicInteger();
        AtomicInteger invalids = new AtomicInteger();
        AtomicInteger locked = new AtomicInteger();
        AtomicInteger odd = new AtomicInteger();
        runConcurrently(threads, index -> {
            LoginService.LoginOutcome outcome = service.login("race", ("wrong-" + index).toCharArray());
            switch (outcome.status()) {
                case SUCCESS -> successes.incrementAndGet();
                case INVALID_CREDENTIALS -> invalids.incrementAndGet();
                case ACCOUNT_LOCKED -> locked.incrementAndGet();
                default -> odd.incrementAndGet();
            }
        });
        eq("every attempt answered", threads, successes.get() + invalids.get() + locked.get() + odd.get());
        eq("nothing succeeded under contention", 0, successes.get());
        eq("only the two expected refusals were returned", 0, odd.get());
        // How the 24 answers split between INVALID_CREDENTIALS and ACCOUNT_LOCKED depends on
        // the interleaving, so only outcomes that must hold for every schedule are asserted
        // here; the exact serialisation invariant is measured at the tracker below.
        check("at least the threshold worth of attempts were answered as plain failures",
                invalids.get() >= 4);
        check("the account is locked once the dust settles",
                tracker.remainingLockMillis("race") > 0);
        eq("the right password is refused while locked", LoginService.LoginStatus.ACCOUNT_LOCKED,
                attempt(service, "race", "right-password"));

        // Serialisation invariant, independent of scheduling: of N concurrent failures
        // against an unlocked account exactly one may report that it tripped the lock.
        // Two means the threshold was crossed twice (lost update), zero means failures
        // were dropped.
        final int strikers = 32;
        LoginService.LoginAttemptTracker raceTracker = new LoginService.LoginAttemptTracker(
                5, Duration.ofMinutes(15), Duration.ofHours(1));
        AtomicInteger trips = new AtomicInteger();
        AtomicInteger counted = new AtomicInteger();
        runConcurrently(strikers, index -> {
            if (raceTracker.recordFailure("shared-key")) {
                trips.incrementAndGet();
            }
            counted.incrementAndGet();
        });
        eq("every concurrent failure was registered", strikers, counted.get());
        eq("exactly one concurrent failure reported tripping the lock", 1, trips.get());
        check("and the lock is actually engaged", raceTracker.remainingLockMillis("shared-key") > 0);

        // Success racing failures must not be able to unlock anybody.
        LoginService.InMemoryAccountStore store2 = new LoginService.InMemoryAccountStore(hasher);
        enroll(store2, "race2", "right-password");
        LoginService.LoginAttemptTracker tracker2 = new LoginService.LoginAttemptTracker(
                3, Duration.ofMinutes(15), Duration.ofHours(1));
        LoginService service2 = new LoginService(store2, hasher, tracker2);
        AtomicInteger race2Successes = new AtomicInteger();
        runConcurrently(18, index -> {
            if (service2.login("race2",
                    (index % 3 == 0 ? "right-password" : "wrong-" + index).toCharArray()).granted()) {
                race2Successes.incrementAndGet();
            }
        });
        check("twelve failures tripped it despite the interleaved successes ("
                        + race2Successes.get() + " grants before the lock engaged)",
                tracker2.remainingLockMillis("race2") > 0);
        eq("a concurrent success did not open the door", LoginService.LoginStatus.ACCOUNT_LOCKED,
                attempt(service2, "race2", "right-password"));
    }

    private static void auditSeesEveryOutcomeAndNoCredentials() {
        section("the audit trail records every outcome and no credential");
        RecordingAudit audit = new RecordingAudit();
        LoginService.PasswordHasher hasher = new LoginService.PasswordHasher(2_000);
        LoginService.InMemoryAccountStore store = new LoginService.InMemoryAccountStore(hasher);
        enroll(store, "alice", "Corr3ct-Horse-Battery");
        LoginService.LoginAttemptTracker tracker = new LoginService.LoginAttemptTracker(
                2, Duration.ofMinutes(15), Duration.ofMinutes(10));
        LoginService service = new LoginService(store, hasher, tracker, audit);

        service.login("alice", "Corr3ct-Horse-Battery".toCharArray());
        service.login("alice", "wrong".toCharArray());
        service.login("nobody", "wrong".toCharArray());
        service.login("bad name", "wrong".toCharArray());
        service.login("alice", "wrong".toCharArray());
        service.login("alice", "Corr3ct-Horse-Battery".toCharArray());

        eq("one event per attempt", 6, audit.statuses.size());
        eq("success first", LoginService.LoginStatus.SUCCESS, audit.statuses.get(0));
        eq("unknown user audited under its own name", "nobody", audit.usernames.get(2));
        eq("malformed name audited without a username", null, audit.usernames.get(3));
        eq("lock audited", LoginService.LoginStatus.ACCOUNT_LOCKED, audit.statuses.get(5));
        check("the locked event carries a retry hint", audit.retries.get(5) > 0);
        check("no event ever mentions a password", !audit.mentions("Corr3ct") && !audit.mentions("wrong"));
    }

    // ------------------------------------------------------------------- timing

    /**
     * Each early return in {@code login} is a separate enumeration oracle, so every
     * refusal shape is timed against a successful check rather than trusting a comment.
     * Lockout state would invalidate later samples, so the shapes that can lock run
     * against a tracker that cannot, and the locked series gets a fresh account per
     * sample from its own one-strike tracker.
     */
    private static void refusalCostsMatchASuccessfulCheck() {
        section("every refusal costs the same work as a successful check");
        int iterations = 30_000;
        LoginService.PasswordHasher hasher = new LoginService.PasswordHasher(iterations);
        LoginService.InMemoryAccountStore store = new LoginService.InMemoryAccountStore(hasher);
        LoginService.LoginAttemptTracker openTracker = new LoginService.LoginAttemptTracker(
                100_000, Duration.ofMinutes(15), Duration.ofHours(12));
        LoginService open = new LoginService(store, hasher, openTracker);
        enroll(store, "timing-known", "timing-secret");
        char[] right = "timing-secret".toCharArray();
        char[] wrong = "timing-wrong".toCharArray();
        char[] unhashable = "timing-secret\0".toCharArray();

        double success = medianMillis(5, () -> requireGranted(open.login("timing-known", right)));
        double knownWrong = medianMillis(4, () -> requireRefused(open.login("timing-known", wrong)));
        double unknown = medianMillis(4, () -> requireRefused(open.login("timing-unknown", wrong)));
        double unhashableCost = medianMillis(4, () -> requireRefused(open.login("timing-known", unhashable)));
        double malformed = medianMillis(4, () -> requireRefused(open.login("not a name", wrong)));

        MutableClock clock = new MutableClock(4_000L);
        LoginService.LoginAttemptTracker strict = tracker(1, 600_000L, 1.0d, 600_000L,
                Duration.ofHours(1), Duration.ofHours(1), clock);
        LoginService lockedService = new LoginService(store, hasher, strict);
        for (int i = 0; i < 4; i++) {
            enroll(store, "tl" + i, "timing-secret");
            lockedService.login("tl" + i, wrong);
            check("sample account " + i + " is locked", strict.remainingLockMillis("tl" + i) > 0);
        }
        double lockedCost = medianMillis(4, new Runnable() {
            private int sample;
            @Override public void run() {
                requireStatus(LoginService.LoginStatus.ACCOUNT_LOCKED,
                        lockedService.login("tl" + (sample++ % 4), wrong));
            }
        });

        System.out.println("      success=" + fmt(success) + "ms known-wrong=" + fmt(knownWrong)
                + "ms unknown=" + fmt(unknown) + "ms unhashable=" + fmt(unhashableCost)
                + "ms malformed=" + fmt(malformed) + "ms locked=" + fmt(lockedCost) + "ms");
        check("the reference check is measurable (" + fmt(success) + "ms)", success >= 5.0d);
        ratio("known wrong password", knownWrong, success);
        ratio("unknown username", unknown, success);
        ratio("unhashable candidate", unhashableCost, success);
        ratio("malformed username", malformed, success);
        ratio("locked account", lockedCost, success);
    }

    private static void ratio(String shape, double observed, double reference) {
        double ratio = observed / reference;
        check(shape + " costs comparable work to a real check (ratio " + fmt(ratio) + ")",
                ratio >= 0.75d && ratio <= 1.35d);
    }

    private static double medianMillis(int samples, Runnable attempt) {
        try {
            attempt.run(); // warm the path
            double[] observed = new double[samples];
            for (int i = 0; i < samples; i++) {
                long start = System.nanoTime();
                attempt.run();
                observed[i] = (System.nanoTime() - start) / 1_000_000.0d;
            }
            Arrays.sort(observed);
            return observed[samples / 2];
        } catch (RuntimeException e) {
            // A timed path that stops returning the expected shape is a defect, but it must
            // be reported as a failed check: letting it escape kills the JVM and hides the
            // reasons from every other check that had already failed.
            fail("timed attempt returned an unexpected outcome: " + e.getMessage());
            return -1.0d;
        }
    }

    private static String fmt(double value) {
        return String.format("%.1f", value);
    }

    // ------------------------------------------------------------------ helpers

    private static final class Fixture {
        final LoginService.PasswordHasher hasher;
        final LoginService.InMemoryAccountStore store;
        final LoginService.LoginAttemptTracker tracker;
        final LoginService service;

        Fixture(LoginService.PasswordHasher hasher) {
            this(hasher, new LoginService.LoginAttemptTracker(
                    100_000, Duration.ofMinutes(15), Duration.ofHours(12)));
        }

        Fixture(LoginService.PasswordHasher hasher, LoginService.LoginAttemptTracker tracker) {
            this.hasher = hasher;
            this.store = new LoginService.InMemoryAccountStore(hasher);
            this.tracker = tracker;
            this.service = new LoginService(store, hasher, tracker);
        }
    }

    /**
     * Store that hands back an unparseable credential, standing in for a corrupt or
     * half-written row: exactly the shape that must fail closed rather than throw.
     */
    private static final class CorruptStore implements LoginService.AccountStore {
        private final String username;
        private final String brokenRecord;

        CorruptStore(String username, String brokenRecord) {
            this.username = username;
            this.brokenRecord = brokenRecord;
        }

        @Override public Optional<LoginService.Account> find(String name) {
            return username.equals(name)
                    ? Optional.of(new LoginService.Account(name, brokenRecord, true))
                    : Optional.empty();
        }
    }

    /**
     * Enrols an account from a literal and wipes the intermediate array, which is the
     * discipline production callers are expected to follow.
     */
    private static void enroll(LoginService.InMemoryAccountStore store, String username,
                               String password) {
        enroll(store, username, password, true);
    }

    private static void enroll(LoginService.InMemoryAccountStore store, String username,
                               String password, boolean enabled) {
        char[] secret = password.toCharArray();
        try {
            store.register(username, secret, enabled);
        } finally {
            java.util.Arrays.fill(secret, '\0');
        }
    }

    private static Fixture fixture(String username, String password) {
        Fixture f = new Fixture(new LoginService.PasswordHasher(2_000));
        enroll(f.store, username, password);
        return f;
    }

    private static Fixture lockedFixture(int maxFailures, long lockMillis, MutableClock clock) {
        Fixture f = new Fixture(new LoginService.PasswordHasher(2_000),
                tracker(maxFailures, lockMillis, 1.0d, lockMillis, Duration.ofHours(1),
                        Duration.ofHours(2), clock));
        enroll(f.store, "bob", "right-password");
        return f;
    }

    private static void lockAccount(Fixture f, String username, int maxFailures) {
        for (int i = 0; i < maxFailures; i++) {
            f.service.login(username, ("strike-" + i).toCharArray());
        }
    }

    private static LoginService.LoginAttemptTracker tracker(int maxFailures, long lockMillis,
                                                           double backoff, long maxLockMillis,
                                                           Duration window, Duration retention,
                                                           java.util.function.LongSupplier clock) {
        return new LoginService.LoginAttemptTracker(maxFailures, Duration.ofMillis(lockMillis),
                backoff, Duration.ofMillis(maxLockMillis), window, retention, clock);
    }

    private static LoginService.LoginStatus attempt(LoginService service, String username, String password) {
        return service.login(username, password.toCharArray()).status();
    }

    private static void requireGranted(LoginService.LoginOutcome outcome) {
        if (!outcome.granted()) {
            throw new IllegalStateException("expected access to be granted, got " + outcome);
        }
    }

    private static void requireRefused(LoginService.LoginOutcome outcome) {
        if (outcome.granted()) {
            throw new IllegalStateException("expected refusal, got " + outcome);
        }
    }

    private static void requireStatus(LoginService.LoginStatus expected, LoginService.LoginOutcome outcome) {
        if (outcome.status() != expected) {
            throw new IllegalStateException("expected " + expected + ", got " + outcome);
        }
    }

    private static void runConcurrently(int threads, java.util.function.IntConsumer body) {
        // One platform thread per worker: a smaller pool would let the barrier wait for
        // queued tasks instead of measuring what happens when the attempts collide.
        ExecutorService pool = Executors.newCachedThreadPool();
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        List<java.util.concurrent.Future<?>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < threads; i++) {
                final int index = i;
                futures.add(pool.submit(() -> {
                    ready.countDown();
                    try {
                        go.await(30, TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                    body.accept(index);
                }));
            }
            try {
                check("workers reached the start gate",
                        ready.await(30, TimeUnit.SECONDS));
                go.countDown();
                for (java.util.concurrent.Future<?> future : futures) {
                    future.get(60, TimeUnit.SECONDS);
                }
            } catch (Exception e) {
                fail("concurrent run failed: " + e);
            }
        } finally {
            pool.shutdownNow();
        }
    }

    private static final class RecordingAudit implements LoginService.AuditSink {
        final List<String> usernames = new ArrayList<>();
        final List<LoginService.LoginStatus> statuses = new ArrayList<>();
        final List<Long> retries = new ArrayList<>();

        @Override public void record(String username, LoginService.LoginStatus status, long retryInSeconds) {
            usernames.add(username);
            statuses.add(status);
            retries.add(retryInSeconds);
        }

        boolean mentions(String needle) {
            for (String username : usernames) {
                if (username != null && username.contains(needle)) {
                    return true;
                }
            }
            return false;
        }
    }

    private static final class MutableClock implements java.util.function.LongSupplier {
        private final AtomicLong now;

        MutableClock(long start) {
            this.now = new AtomicLong(start);
        }

        @Override public long getAsLong() {
            return now.get();
        }

        void advance(long millis) {
            now.addAndGet(millis);
        }
    }

    private static boolean throwsIAE(Runnable body) {
        try {
            body.run();
            return false;
        } catch (IllegalArgumentException expected) {
            return true;
        }
    }

    private static boolean parseable(String record) {
        try {
            String[] parts = record.split("\\$", -1);
            return parts.length == 4 && "pbkdf2".equals(parts[0])
                    && Integer.parseInt(parts[1]) >= LoginService.PasswordHasher.MIN_ITERATIONS
                    && Base64.getDecoder().decode(parts[2]).length == 16
                    && Base64.getDecoder().decode(parts[3]).length == 32;
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * Flips one bit of the decoded field rather than a base64 character, because
     * case-flipping a letter encodes the same bytes and would be a silent no-op.
     */
    private static String flippedDecodedByte(String stored, int field) {
        String[] parts = stored.split("\\$", -1);
        byte[] raw = Base64.getDecoder().decode(parts[field]);
        raw[raw.length / 2] ^= 0x01;
        parts[field] = Base64.getEncoder().encodeToString(raw);
        return String.join("$", parts);
    }

    private static String describe(String value) {
        if (value == null) {
            return "<null>";
        }
        StringBuilder out = new StringBuilder(value.length() + 8).append('\'');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\0') {
                out.append("\\0");
            } else if (c == '\n') {
                out.append("\\n");
            } else if (c == '\t') {
                out.append("\\t");
            } else if (c == '\r') {
                out.append("\\r");
            } else if (Character.isHighSurrogate(c) || Character.isLowSurrogate(c)) {
                out.append(String.format("\\u%04X", (int) c));
            } else if (c < 0x20 || c > 0x7E) {
                out.append(String.format("\\u%04X", (int) c));
            } else if (i >= 24) {
                out.append("...");
                break;
            } else {
                out.append(c);
            }
        }
        return out.append('\'').toString();
    }

    private static void section(String name) {
        System.out.println("== " + name);
    }

    private static void check(String what, boolean condition) {
        CHECKS.incrementAndGet();
        if (!condition) {
            fail(what);
        }
    }

    private static void eq(String what, Object expected, Object actual) {
        CHECKS.incrementAndGet();
        if (!java.util.Objects.equals(expected, actual)) {
            fail(what + ": expected " + expected + " but got " + actual);
        }
    }

    private static void fail(String what) {
        synchronized (FAILURES) {
            FAILURES.add(what);
        }
    }
}
