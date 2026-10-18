import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Checks for {@link LoginService}: credential matching, refusal wording, lockout, the digest
 * format, and the timing equalisation that stops response time from confirming which accounts
 * exist. Plain assertions and a non-zero exit status; no test framework needed.
 *
 * <p>Run: {@code java -cp out LoginServiceTest}
 */
public final class LoginServiceTest {

    private static final AtomicInteger PASSED = new AtomicInteger();
    private static final List<String> FAILURES = new ArrayList<>();

    /** Work factor for functional checks: real algorithm, cheap enough to hash often. */
    private static final int FAST = 1_000;

    private static int checks = 0;

    public static void main(String[] args) throws Exception {
        long start = System.nanoTime();

        correctCredentialsAreAccepted();
        wrongPasswordIsRefused();
        unknownAccountIsRefused();
        caseAndWhitespaceAreSignificant();
        refusalWordingIsIdenticalForEveryFailure();
        cleartextIsNeverStored();
        saltIsFreshPerRegistration();
        digestCarriesItsOwnWorkFactor();
        tamperedDigestsAreUnreadable();
        malformedRecordIsRefusedNotThrown();
        emptyAndNullCandidatesAreRefused();
        lossyPasswordShapesAreRefusedAtTheBoundary();
        registrationRules();
        lockoutAfterRepeatedFailures();
        successClearsFailureState();
        failureWindowAndLockBothExpire();
        sessionTokensAreUniqueAndWellFormed();
        storeIsNotMutatedByFailedLogins();
        countersSurviveConcurrentAttempts();
        measuredTiming();

        long millis = (System.nanoTime() - start) / 1_000_000;
        System.out.printf("%n%d checks, %d failures, %d ms%n", checks, FAILURES.size(), millis);
        if (!FAILURES.isEmpty()) {
            System.out.println("FAILED:");
            for (String failure : FAILURES) {
                System.out.println("  - " + failure);
            }
            System.exit(1);
        }
        System.out.println("ALL CHECKS PASSED");
    }

    // ------------------------------------------------------------------
    // Core login behaviour
    // ------------------------------------------------------------------

    private static void correctCredentialsAreAccepted() {
        Fixture f = new Fixture();
        f.register("alice", "correct horse");
        LoginService.LoginOutcome outcome = f.service.login("alice", "correct horse");
        check("correct credentials grant access", outcome.granted());
        check("grant reports SUCCESS", outcome.status() == LoginService.LoginStatus.SUCCESS);
        check("grant says Authenticated", "Authenticated.".equals(outcome.message()));
        check("grant names the account", "alice".equals(outcome.username()));
    }

    private static void wrongPasswordIsRefused() {
        // A high limit keeps the lockout from short-circuiting later samples in this matrix; the
        // lock itself is exercised in lockoutAfterRepeatedFailures.
        Fixture f = new Fixture(10_000, 60_000L, 600_000L);
        f.register("alice", "correct horse");
        String[] wrong = {
            "Correct horse", "correct horse ", " correct horse", "correcthorse", "correct horses",
            "Correct Horse", "CORRECT HORSE", "correct horss", "correct  horse", "correct", "horse"
        };
        for (String password : wrong) {
            LoginService.LoginOutcome outcome = f.service.login("alice", password);
            check("wrong password refused: [" + showable(password) + "]", !outcome.granted()
                    && outcome.status() == LoginService.LoginStatus.INVALID_CREDENTIALS
                    && outcome.sessionToken() == null);
        }
        LoginService.LoginOutcome empty = f.service.login("alice", "");
        check("empty password refused", !empty.granted() && empty.sessionToken() == null);
    }

    private static void unknownAccountIsRefused() {
        Fixture f = new Fixture();
        f.register("alice", "correct horse");
        LoginService.LoginOutcome outcome = f.service.login("mallory", "correct horse");
        check("unknown account refused even with a valid password", !outcome.granted());
        check("unknown account gets the generic wording",
                "Invalid username or password.".equals(outcome.message()));
        check("unknown account is not created", f.store.find("mallory") == null);
    }

    private static void caseAndWhitespaceAreSignificant() {
        Fixture f = new Fixture();
        f.register("alice", "correct horse");
        check("username lookup is case sensitive", !f.service.login("Alice", "correct horse").granted());
        check("username with trailing space is refused as malformed",
                !f.service.login("alice ", "correct horse").granted());
        check("well-formed usernames are accepted byte for byte",
                LoginService.isWellFormedUsername("ali")
                        && LoginService.isWellFormedUsername("A.b-c_9")
                        && LoginService.isWellFormedUsername("x".repeat(32)));
        check("malformed usernames are rejected outright",
                !LoginService.isWellFormedUsername(null) && !LoginService.isWellFormedUsername("")
                        && !LoginService.isWellFormedUsername("al") && !LoginService.isWellFormedUsername("a ce")
                        && !LoginService.isWellFormedUsername("alice@corp") && !LoginService.isWellFormedUsername("ali\u00e7e")
                        && !LoginService.isWellFormedUsername("x".repeat(33)));

        // Lookalike names must never resolve to a real account. Names are compared byte for byte, so
        // the only way one could alias another is if a guard or the lookup folded case or script.
        String cyrillicAlice = nameWithCyrillic();
        check("a homoglyph name is not well-formed", !LoginService.isWellFormedUsername(cyrillicAlice));
        check("a homoglyph name cannot be registered",
                f.service.register(cyrillicAlice, "correct horse")
                        == LoginService.Registration.INVALID_USERNAME);
        f.store.putIfAbsent(new LoginService.Account(cyrillicAlice, f.hasher.hash("correct horse")));
        check("a homoglyph name cannot log in even when such an account exists",
                !f.service.login(cyrillicAlice, "correct horse").granted());
        check("the real account is untouched by a homoglyph name",
                f.service.login("alice", "correct horse").granted());
        check("mixed-case names are separate accounts, never folded onto an existing one",
                f.service.register("Alice", "different secret") == LoginService.Registration.STORED
                        && !f.service.login("Alice", "correct horse").granted()
                        && f.service.login("Alice", "different secret").granted()
                        && f.service.login("alice", "correct horse").granted());
    }

    /** "alice" with a Cyrillic 'a' and 'e', which ASCII-fold onto the real name. */
    private static String nameWithCyrillic() {
        return new String(new int[] {0x0430, 'l', 'i', 'c', 0x0435}, 0, 5);
    }

    private static void refusalWordingIsIdenticalForEveryFailure() {
        Fixture f = new Fixture();
        f.register("alice", "correct horse");
        f.store.putIfAbsent(new LoginService.Account("broken", "pbkdf2-sha256$1000$no!!base64$no!!base64"));

        Set<String> messages = new LinkedHashSet<>();
        messages.add(f.service.login("alice", "nope").message());
        messages.add(f.service.login("ghost", "nope").message());
        messages.add(f.service.login("broken", "nope").message());
        messages.add(f.service.login("bad name!", "nope").message());
        messages.add(f.service.login("alice", nulTerminated("nope")).message());
        messages.add(f.service.login("alice", null).message());

        check("every failed credential yields one generic message",
                messages.size() == 1 && "Invalid username or password.".equals(messages.iterator().next()));
        check("refusal never echoes the account name", messages.stream().noneMatch(m -> m.contains("alice")));
    }

    private static void cleartextIsNeverStored() {
        Fixture f = new Fixture();
        f.register("alice", "correct horse");
        String stored = f.store.find("alice").passwordHash();
        check("stored value is a digest, not the password", !stored.contains("correct horse"));
        check("stored value is self-describing", stored.startsWith("pbkdf2-sha256$" + FAST + "$"));
        check("stored digest parses", LoginService.PasswordHasher.parse(stored) != null);
        check("account record refuses an empty digest", throwsIllegal(() ->
                new LoginService.Account("x", "")));
    }

    private static void saltIsFreshPerRegistration() {
        LoginService.PasswordHasher hasher = new LoginService.PasswordHasher(FAST);
        String first = hasher.hash("same password");
        String second = hasher.hash("same password");
        check("the same password yields different digests", !first.equals(second));
        check("both digests accept the password",
                hasher.verify("same password", first) == LoginService.PasswordHasher.Verdict.MATCH
                        && hasher.verify("same password", second) == LoginService.PasswordHasher.Verdict.MATCH);
        check("each digest has its own salt", !Arrays.equals(LoginService.PasswordHasher.parse(first).salt(),
                LoginService.PasswordHasher.parse(second).salt()));
        check("the salt is what differs, not the digest length",
                LoginService.PasswordHasher.parse(first).digest().length == 32);
    }

    private static void digestCarriesItsOwnWorkFactor() {
        LoginService.PasswordHasher cheap = new LoginService.PasswordHasher(1_000);
        LoginService.PasswordHasher costly = new LoginService.PasswordHasher(2_000);
        String cheapDigest = cheap.hash("password");
        check("a digest made at a lower work factor still verifies",
                costly.verify("password", cheapDigest) == LoginService.PasswordHasher.Verdict.MATCH);
        check("stored iterations are honoured",
                LoginService.PasswordHasher.parse(cheapDigest).iterations() == 1_000);
        check("work factor below the floor is refused",
                LoginService.PasswordHasher.parse("pbkdf2-sha256$1$" + tailOf(cheapDigest)) == null);
        check("an out-of-range hasher is refused at construction",
                throwsIllegal(() -> new LoginService.PasswordHasher(10)));
    }

    private static void tamperedDigestsAreUnreadable() {
        LoginService.PasswordHasher hasher = new LoginService.PasswordHasher(FAST);
        String digest = hasher.hash("password");
        LoginService.PasswordHasher.Digest parsed = LoginService.PasswordHasher.parse(digest);
        String saltPart = digest.split("\\$")[2];
        String digestPart = digest.split("\\$")[3];

        check("wrong prefix is unreadable", LoginService.PasswordHasher.parse(digest.replaceFirst(
                "pbkdf2-sha256", "md5")) == null);
        check("a truncation is unreadable", LoginService.PasswordHasher.parse(digestPart) == null);
        check("non-numeric work factor is unreadable",
                LoginService.PasswordHasher.parse("pbkdf2-sha256$abc$" + saltPart + "$" + digestPart) == null);
        check("invalid base64 is unreadable",
                LoginService.PasswordHasher.parse("pbkdf2-sha256$" + FAST + "$!!!!$" + digestPart) == null);
        check("a short salt is unreadable", LoginService.PasswordHasher.parse(
                "pbkdf2-sha256$" + FAST + "$aGVsbG8$" + digestPart) == null);
        check("a short digest is unreadable", LoginService.PasswordHasher.parse(
                "pbkdf2-sha256$" + FAST + "$" + saltPart + "$aGVsbG8$") == null);
        check("an extra field is unreadable",
                LoginService.PasswordHasher.parse(digest + "$extra") == null);
        check("a readable digest keeps its bytes", parsed != null && parsed.digest().length == 32
                && parsed.salt().length == 16);
        check("swapping salt and digest does not verify",
                hasher.verify("password", "pbkdf2-sha256$" + FAST + "$" + digestPart + "$" + saltPart)
                        != LoginService.PasswordHasher.Verdict.MATCH);
        check("the password itself is never a valid encoding",
                hasher.verify("password", "password") != LoginService.PasswordHasher.Verdict.MATCH);
    }

    private static void malformedRecordIsRefusedNotThrown() {
        Fixture f = new Fixture();
        f.store.putIfAbsent(new LoginService.Account("broken", "plaintext-secret"));
        f.store.putIfAbsent(new LoginService.Account("short", "pbkdf2-sha256$1000$QQ==$QQ=="));
        LoginService.LoginOutcome broken = f.service.login("broken", "plaintext-secret");
        check("a cleartext record does not grant access", !broken.granted());
        check("a malformed record is refused, not thrown",
                broken.status() == LoginService.LoginStatus.INVALID_CREDENTIALS);
        check("a truncated record is refused", !f.service.login("short", "anything").granted());
        check("malformed records count as failures",
                f.tracker.failures("broken", f.clock.now) == 1);
    }

    private static void emptyAndNullCandidatesAreRefused() {
        Fixture f = new Fixture();
        f.register("alice", "correct horse");
        check("null password refused", !f.service.login("alice", null).granted());
        check("empty password refused", !f.service.login("alice", "").granted());
        check("null username refused", !f.service.login(null, "correct horse").granted());
        check("hash() refuses null", throwsIllegal(() -> f.hasher.hash(null)));
        check("hash() refuses empty", throwsIllegal(() -> f.hasher.hash("")));
        String huge = "p".repeat(4_097);
        check("oversized candidate refused", !f.service.login("alice", huge).granted());
        check("oversized candidate cannot be enrolled",
                f.service.register("big", huge) == LoginService.Registration.PASSWORD_REJECTED);
    }

    // ------------------------------------------------------------------
    // The lossy-conversion guard
    // ------------------------------------------------------------------

    private static void lossyPasswordShapesAreRefusedAtTheBoundary() {
        char[] filler = new char[44];
        Arrays.fill(filler, 'z');
        byte[] salt = new byte[16];
        Arrays.fill(salt, (byte) 7);

        // Pin the reason the guard exists: the raw JCE maps these distinct passwords onto one
        // digest, so accepting them would let one candidate sign in as another.
        String plain = deriveRaw("cafe" + fillerStr(20), salt, FAST);
        String withNul = deriveRaw("cafe" + fillerStr(20) + (char) 0, salt, FAST);
        check("raw JCE collides a password with a trailing NUL", plain.equals(withNul));
        String highSurrogate = deriveRaw("q" + (char) 0xD800, salt, FAST);
        String otherSurrogate = deriveRaw("q" + (char) 0xDC00, salt, FAST);
        String questionMark = deriveRaw("q?", salt, FAST);
        check("raw JCE maps every unpaired surrogate onto one digest",
                highSurrogate.equals(otherSurrogate) && highSurrogate.equals(questionMark));

        Fixture f = new Fixture();
        f.register("alice", "correct horse");
        String trailingNul = "correct horse" + (char) 0;
        String unpaired = "correct horse" + (char) 0xD800;
        check("trailing-NUL candidate cannot log in", !f.service.login("alice", trailingNul).granted());
        check("unpaired-surrogate candidate cannot log in", !f.service.login("alice", unpaired).granted());
        check("trailing-NUL password cannot be enrolled",
                f.service.register("nobody", trailingNul) == LoginService.Registration.PASSWORD_REJECTED);
        check("unpaired surrogate cannot be enrolled",
                f.service.register("nobody2", unpaired) == LoginService.Registration.PASSWORD_REJECTED);
        check("hash() refuses a trailing NUL", throwsIllegal(() -> f.hasher.hash(trailingNul)));
        check("hash() refuses an unpaired surrogate", throwsIllegal(() -> f.hasher.hash(unpaired)));
        check("guard classifies the trailing NUL",
                "trailing-nul".equals(LoginService.PasswordHasher.structuralRejection(trailingNul)));
        check("guard classifies the unpaired surrogate",
                "unpaired-surrogate".equals(LoginService.PasswordHasher.structuralRejection(unpaired)));
        check("guard classifies a lone low surrogate",
                "unpaired-surrogate".equals(LoginService.PasswordHasher.structuralRejection("a" + (char) 0xDC00 + "b")));

        // Only trailing NULs and unpaired surrogates are lossy; legitimate shapes must still work.
        check("interior NUL still hashes distinctly", !f.hasher.hash("a" + (char) 0 + "bbbb").equals(
                f.hasher.hash("a" + (char) 0 + "bbbb" + "c")));
        String astral = "pass" + new String(new int[] {0x1F600}, 0, 1) + "word";
        check("paired surrogates are hashable",
                f.hasher.verify(astral, f.hasher.hash(astral)) == LoginService.PasswordHasher.Verdict.MATCH);
        check("trailing space is not confused with a NUL",
                LoginService.PasswordHasher.structuralRejection("secret ") == null);
    }

    // ------------------------------------------------------------------
    // Registration
    // ------------------------------------------------------------------

    private static void registrationRules() {
        Fixture f = new Fixture();
        check("valid registration stored",
                f.service.register("alice", "correct horse") == LoginService.Registration.STORED);
        check("duplicate username refused",
                f.service.register("alice", "another password") == LoginService.Registration.DUPLICATE_USERNAME);
        check("duplicate does not overwrite the digest",
                f.service.login("alice", "correct horse").granted());
        check("too-short password refused",
                f.service.register("bob", "shorty") == LoginService.Registration.PASSWORD_REJECTED);
        check("boundary-length password accepted",
                f.service.register("carol", "12345678") == LoginService.Registration.STORED);
        check("malformed username refused",
                f.service.register("bad name", "correct horse") == LoginService.Registration.INVALID_USERNAME);
        check("refused registrations store nothing", f.store.count() == 2);
    }

    // ------------------------------------------------------------------
    // Lockout
    // ------------------------------------------------------------------

    private static void lockoutAfterRepeatedFailures() {
        Fixture f = new Fixture(3, 60_000L, 600_000L);
        f.register("alice", "correct horse");
        check("first failure not locked",
                !f.service.login("alice", "nope1").granted() && !f.tracker.isLocked("alice", f.clock.now));
        check("second failure not locked",
                !f.service.login("alice", "nope2").granted() && !f.tracker.isLocked("alice", f.clock.now));
        check("failures accumulate below the limit", f.tracker.failures("alice", f.clock.now) == 2);

        LoginService.LoginOutcome third = f.service.login("alice", "nope3");
        check("the third failure is still refused", !third.granted());
        check("the third failure trips the lock", f.tracker.isLocked("alice", f.clock.now));

        LoginService.LoginOutcome locked = f.service.login("alice", "nope4");
        check("while locked, attempts report LOCKED", locked.status() == LoginService.LoginStatus.LOCKED);
        check("while locked, attempts are refused", !locked.granted());
        LoginService.LoginOutcome right = f.service.login("alice", "correct horse");
        check("correct password is refused while locked", !right.granted());
        check("the LOCKED wording never confirms the password",
                right.message().equals(locked.message()));
        f.tracker.unlock("alice");
        check("operator unlock restores access", f.service.login("alice", "correct horse").granted());
    }

    private static void successClearsFailureState() {
        Fixture f = new Fixture(5, 60_000L, 600_000L);
        f.register("alice", "correct horse");
        f.service.login("alice", "nope");
        f.service.login("alice", "nope");
        check("failures accumulate", f.tracker.failures("alice", f.clock.now) == 2);
        f.service.login("alice", "correct horse");
        check("success clears the counter", f.tracker.failures("alice", f.clock.now) == 0);
        for (int i = 0; i < 4; i++) {
            f.service.login("alice", "nope");
        }
        check("count restarts from zero after a success", f.tracker.failures("alice", f.clock.now) == 4);
    }

    private static void failureWindowAndLockBothExpire() {
        Fixture f = new Fixture(3, 1_000L, 5_000L);
        f.register("alice", "correct horse");
        f.service.login("alice", "nope");
        f.service.login("alice", "nope");
        f.clock.advance(2_000L);
        check("old failures fall out of the window", f.tracker.failures("alice", f.clock.now) == 0);
        f.service.login("alice", "nope");
        check("post-window failure starts a fresh count", f.tracker.failures("alice", f.clock.now) == 1);

        f.service.login("alice", "nope");
        f.service.login("alice", "nope");
        check("lock engaged", f.tracker.isLocked("alice", f.clock.now));
        check("locked while the lock is live", !f.service.login("alice", "correct horse").granted());
        f.clock.advance(5_001L);
        check("lock expires", !f.tracker.isLocked("alice", f.clock.now));
        check("access returns once the lock expires", f.service.login("alice", "correct horse").granted());
    }

    // ------------------------------------------------------------------
    // Sessions and the store
    // ------------------------------------------------------------------

    private static void sessionTokensAreUniqueAndWellFormed() {
        Fixture f = new Fixture();
        f.register("alice", "correct horse");
        Set<String> tokens = new LinkedHashSet<>();
        for (int i = 0; i < 5; i++) {
            LoginService.LoginOutcome outcome = f.service.login("alice", "correct horse");
            tokens.add(outcome.sessionToken());
        }
        check("each grant carries a token", !tokens.contains(null) && tokens.size() == 5);
        String token = tokens.iterator().next();
        check("token is base64url of 32 bytes", token.length() == 43 && !token.contains("="));
        check("token is not derived from the password", !token.contains("correct"));
    }

    private static void storeIsNotMutatedByFailedLogins() {
        Fixture f = new Fixture();
        f.register("alice", "correct horse");
        f.service.login("ghost", "x");
        f.service.login("alice", "x");
        f.service.login("bad name", "x");
        check("failed logins create no accounts", f.store.count() == 1);
        check("failed logins leave the digest alone",
                f.service.login("alice", "correct horse").granted());
        check("store reports an unknown name as null", f.store.find("ghost") == null);
        check("store tolerates a null lookup", f.store.find(null) == null);
    }

    private static void countersSurviveConcurrentAttempts() throws Exception {
        Fixture f = new Fixture(50, 60_000L, 600_000L);
        for (int i = 0; i < 8; i++) {
            f.register("user" + i, "correct horse");
        }
        int threads = 8;
        int perThread = 12;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger granted = new AtomicInteger();
        List<Future<?>> futures = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            int id = t;
            futures.add(pool.submit(() -> {
                ready.countDown();
                go.await();
                for (int i = 0; i < perThread; i++) {
                    if (f.service.login("user" + id, "correct horse").granted()) {
                        granted.incrementAndGet();
                    }
                    f.service.login("user" + id, "wrong");
                }
                return null;
            }));
        }
        ready.await();
        go.countDown();
        for (Future<?> future : futures) {
            future.get();
        }
        pool.shutdown();
        check("every concurrent correct login is granted", granted.get() == threads * perThread);
        check("concurrent failures stay bounded", f.tracker.failures("user0", f.clock.now) <= 50);
        check("the correct password still works under load",
                f.service.login("user3", "correct horse").granted());
    }

    // ------------------------------------------------------------------
    // Timing: the one property no functional test can see
    // ------------------------------------------------------------------

    private static void measuredTiming() {
        int iterations = 60_000;
        LoginService.InMemoryAccountStore store = new LoginService.InMemoryAccountStore();
        // Generous limits: a lockout that short-circuits later attempts would fake the ratio.
        LoginService.LoginAttemptTracker tracker = new LoginService.LoginAttemptTracker(10_000, 1L, 1L);
        MutableClock clock = new MutableClock();
        LoginService service = new LoginService(store, new LoginService.PasswordHasher(iterations), tracker,
                clock::now);
        LoginService.PasswordHasher hasher = new LoginService.PasswordHasher(iterations);

        check("the dummy digest is a real 32-byte digest at this work factor, so a refusal cannot"
                + " short-circuit before the KDF", parseDummyOk(hasher));
        check("a second hasher gets its own dummy", hasher.dummyDigest() != null
                && !Arrays.equals(hasher.dummyDigest().digest(),
                        new LoginService.PasswordHasher(iterations).dummyDigest().digest()));
        check("the dummy accepts no password",
                hasher.verify("anything", reencode(hasher)) != LoginService.PasswordHasher.Verdict.MATCH);

        // Warm both code paths before measuring, then alternate and use a fresh account per sample.
        for (int i = 0; i < 2; i++) {
            warm(service, store, "warm-known-" + i, "warm-unknown-" + i, iterations);
        }

        List<Long> known = new ArrayList<>();
        List<Long> unknown = new ArrayList<>();
        List<Long> refused = new ArrayList<>();
        List<Long> badName = new ArrayList<>();
        List<Long> lockedOut = new ArrayList<>();
        int samples = 7;
        for (int i = 0; i < samples; i++) {
            known.add(timedKnown(service, store, "known-" + i, "the real secret", iterations));
            unknown.add(timedUnknown(service, "nobody-" + i));
            refused.add(timedRefused(service, store, "refused-" + i, "the real secret" + (char) 0, iterations));
            badName.add(timedBadName(service));
            lockedOut.add(timedLockedOut(store, clock, iterations, "locked-" + i, i));
        }

        double knownMean = mean(known);
        double unknownMean = mean(unknown);
        double refusedMean = mean(refused);
        double badNameMean = mean(badName);
        double lockedMean = mean(lockedOut);
        System.out.printf("timing (ms/attempt, %d samples): known=%.1f unknown=%.1f refused=%.1f"
                + " bad-name=%.1f locked=%.1f%n", samples, knownMean, unknownMean, refusedMean, badNameMean,
                lockedMean);

        check("a wrong password costs real work", knownMean > 5.0);
        check("an unknown account costs comparable work (ratio in [0.8, 1.3])",
                ratio(unknownMean, knownMean) >= 0.8 && ratio(unknownMean, knownMean) <= 1.3);
        check("an unhashable candidate costs comparable work (ratio in [0.8, 1.3])",
                ratio(refusedMean, knownMean) >= 0.8 && ratio(refusedMean, knownMean) <= 1.3);
        check("a malformed name costs comparable work (ratio in [0.8, 1.3])",
                ratio(badNameMean, knownMean) >= 0.8 && ratio(badNameMean, knownMean) <= 1.3);
        check("a locked account costs comparable work (ratio in [0.8, 1.3])",
                ratio(lockedMean, knownMean) >= 0.8 && ratio(lockedMean, knownMean) <= 1.3);
        check("no refusal is answered instantly",
                Math.min(Math.min(unknownMean, refusedMean), Math.min(badNameMean, lockedMean))
                        > knownMean * 0.5);
    }

    private static boolean parseDummyOk(LoginService.PasswordHasher hasher) {
        LoginService.PasswordHasher.Digest dummy = hasher.dummyDigest();
        return dummy != null && dummy.iterations() == hasher.iterations() && dummy.digest().length == 32
                && dummy.salt().length >= 8 && LoginService.PasswordHasher.parse(reencode(hasher)) != null;
    }

    /** Re-encodes a hasher's dummy digest in the stored form, to prove it really parses. */
    private static String reencode(LoginService.PasswordHasher hasher) {
        LoginService.PasswordHasher.Digest dummy = hasher.dummyDigest();
        return "pbkdf2-sha256$" + dummy.iterations() + '$'
                + java.util.Base64.getEncoder().encodeToString(dummy.salt()) + '$'
                + java.util.Base64.getEncoder().encodeToString(dummy.digest());
    }

    private static void warm(LoginService service, LoginService.InMemoryAccountStore store, String known,
            String unknown, int iterations) {
        enroll(store, known, "warm secret", iterations);
        service.login(known, "x");
        service.login(unknown, "x");
    }

    private static void enroll(LoginService.InMemoryAccountStore store, String name, String secret,
            int iterations) {
        store.putIfAbsent(new LoginService.Account(name,
                new LoginService.PasswordHasher(iterations).hash(secret)));
    }

    private static long timedKnown(LoginService service, LoginService.InMemoryAccountStore store, String name,
            String secret, int iterations) {
        enroll(store, name, secret, iterations);
        return timed(() -> service.login(name, "wrong " + name));
    }

    private static long timedUnknown(LoginService service, String name) {
        return timed(() -> service.login(name, "wrong " + name));
    }

    private static long timedBadName(LoginService service) {
        return timed(() -> service.login("no such name", "wrong password"));
    }

    /** Times the locked-out branch, which must pay a derivation like every other refusal. */
    private static long timedLockedOut(LoginService.InMemoryAccountStore store, MutableClock clock,
            int iterations, String name, int sample) {
        LoginService.LoginAttemptTracker lockOnce = new LoginService.LoginAttemptTracker(1, 60_000L, 600_000L);
        LoginService service = new LoginService(store, new LoginService.PasswordHasher(iterations), lockOnce,
                clock::now);
        enroll(store, name, "the real secret", iterations);
        boolean tripped = !service.login(name, "wrong once").granted() && lockOnce.isLocked(name, clock.now);
        if (!tripped) {
            throw new IllegalStateException("one-strike lock did not engage for " + name);
        }
        if (sample == 0) {
            check("a locked account still answers with the generic locked notice",
                    service.login(name, "the real secret").status() == LoginService.LoginStatus.LOCKED);
        }
        return timed(() -> service.login(name, "the real secret"));
    }

    private static long timedRefused(LoginService service, LoginService.InMemoryAccountStore store, String name,
            String unhashableSecret, int iterations) {
        enroll(store, name, "the real secret", iterations);
        return timed(() -> service.login(name, unhashableSecret));
    }

    private static long timed(Runnable body) {
        long start = System.nanoTime();
        body.run();
        return (System.nanoTime() - start) / 1_000_000;
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static String deriveRaw(String password, byte[] salt, int rounds) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return Arrays.toString(factory.generateSecret(new PBEKeySpec(password.toCharArray(), salt, rounds,
                    256)).getEncoded());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String fillerStr(int length) {
        char[] filler = new char[length];
        Arrays.fill(filler, 'x');
        return new String(filler);
    }

    private static String nulTerminated(String value) {
        return value + (char) 0;
    }

    private static String tailOf(String digest) {
        String[] parts = digest.split("\\$");
        return parts[2] + "$" + parts[3];
    }

    private static String showable(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == 0) {
                builder.append("\\0");
            } else if (c == ' ') {
                builder.append('_');
            } else {
                builder.append(c);
            }
        }
        return builder.toString();
    }

    private static double mean(List<Long> samples) {
        double total = 0;
        for (long sample : samples) {
            total += sample;
        }
        return total / samples.size();
    }

    private static double ratio(double left, double right) {
        return left / right;
    }

    private static boolean throwsIllegal(Runnable body) {
        try {
            body.run();
            return false;
        } catch (IllegalArgumentException expected) {
            return true;
        }
    }

    private static void check(String what, boolean condition) {
        checks++;
        if (condition) {
            PASSED.incrementAndGet();
            System.out.println("ok   " + what);
        } else {
            FAILURES.add(what);
            System.out.println("FAIL " + what);
        }
    }

    private static final class MutableClock {
        private long now = 1_700_000_000_000L;

        void advance(long millis) {
            now += millis;
        }

        long now() {
            return now;
        }
    }

    /** A service wired to a fake clock and a cheap work factor. */
    private static final class Fixture {
        final LoginService.InMemoryAccountStore store = new LoginService.InMemoryAccountStore();
        final LoginService.PasswordHasher hasher = new LoginService.PasswordHasher(FAST);
        final LoginService.LoginAttemptTracker tracker;
        final MutableClock clock = new MutableClock();
        final LoginService service;

        Fixture() {
            this(5, 60_000L, 600_000L);
        }

        Fixture(int maxFailures, long windowMillis, long lockMillis) {
            this.tracker = new LoginService.LoginAttemptTracker(maxFailures, windowMillis, lockMillis);
            this.service = new LoginService(store, hasher, tracker, clock::now);
        }

        void register(String username, String password) {
            LoginService.Registration result = service.register(username, password);
            if (result != LoginService.Registration.STORED) {
                throw new IllegalStateException("fixture registration failed for " + username + ": " + result);
            }
        }
    }
}
