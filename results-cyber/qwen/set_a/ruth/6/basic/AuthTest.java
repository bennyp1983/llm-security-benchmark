import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Self-contained test harness for {@link UserAuthentication}: {@code java AuthTest}. No test
 * framework, so the whole deliverable compiles with plain javac. Prints one line per check plus a
 * PASS/FAIL summary; exit code 1 on any failure.
 *
 * <p>Lockout policy in this suite: the shared service uses a very large {@code maxFailures} so that
 * a matrix of wrong passwords stays a matrix of independent credential checks. Strike counting and
 * lock expiry are exercised in dedicated fixtures with their own accounts, because per-account
 * failures are shared mutable state: a loop that trips the lock mid-matrix would rewrite the
 * expected outcome of every later assertion against that account.
 */
public final class AuthTest {

    private static final int FAST_ITERATIONS = 2_000;
    private static final int TIMING_ITERATIONS = 30_000;
    private static final int NO_LOCKOUT = 1_000_000;
    private static final int LOCK_ACCOUNTS = 12;
    private static final char[] PW = "winter-Frost-42".toCharArray();
    private static final String EQUAL_WORK_TEXT = "equal-work-placeholder-never-a-real-secret";

    private static final List<String> FAILURES = Collections.synchronizedList(new ArrayList<>());
    private static final AtomicInteger CHECKS = new AtomicInteger();
    private static int sectionNumber;

    public static void main(String[] args) throws Exception {
        long started = System.nanoTime();

        section("username and password validation");
        usernames();
        passwordForms();

        section("password hashing");
        hashing();

        section("credential verification");
        credentials();

        section("lockout policy");
        lockout();
        failureWindowAndExpiry();

        section("account state");
        disabledAndCorrupt();

        section("audit log");
        auditLog();
        logInjection();

        section("equal work against timing enumeration");
        equalWork();

        section("concurrency");
        concurrency();

        section("API contract");
        apiContract();

        System.out.println();
        System.out.println("=== " + CHECKS.get() + " checks, " + FAILURES.size() + " failed, "
            + ((System.nanoTime() - started) / 1_000_000_000L) + "s ===");
        for (String failure : FAILURES) {
            System.out.println("FAILED " + failure);
        }
        System.exit(FAILURES.isEmpty() ? 0 : 1);
    }

    // --------------------------------------------------------------------------------------------
    // Username and password validation
    // --------------------------------------------------------------------------------------------

    private static void usernames() {
        eq("trim and lowercase", "alice", UserAuthentication.normalizeUsername("  Alice "));
        eq("dot underscore hyphen kept", "a.b_c-d1", UserAuthentication.normalizeUsername("A.B_c-D1"));
        eq("full-width A folds to a under NFKC", "abc",
            UserAuthentication.normalizeUsername(String.valueOf((char) 0xFF21) + "bc"));
        eq("non-breaking space trimmed", "abc", UserAuthentication.normalizeUsername("abc" + (char) 0xA0));
        eq("minimum length accepted", "abc", UserAuthentication.normalizeUsername("ABC"));
        eq("maximum length accepted", 64, UserAuthentication.normalizeUsername("u".repeat(64)).length());
        nul("65 characters", UserAuthentication.normalizeUsername("u".repeat(65)));
        nul("too short", UserAuthentication.normalizeUsername("ab"));
        nul("blank", UserAuthentication.normalizeUsername("     "));
        nul("at sign", UserAuthentication.normalizeUsername("alice@example"));
        nul("inner space", UserAuthentication.normalizeUsername("ali ce"));
        nul("path traversal", UserAuthentication.normalizeUsername("../etc/passwd"));
        nul("newline", UserAuthentication.normalizeUsername("alice\nadmin"));
        nul("null input", UserAuthentication.normalizeUsername(null));
    }

    private static void passwordForms() {
        yes("interior NUL is legal", UserAuthentication.isHashablePassword(new char[] {'p', 0, 'w', '1'}));
        yes("well-formed surrogate pair is legal", UserAuthentication.isHashablePassword(
            ("a" + (char) 0xD83D + (char) 0xDE00).toCharArray()));
        no("empty", UserAuthentication.isHashablePassword(new char[0]));
        no("null", UserAuthentication.isHashablePassword(null));
        no("trailing NUL", UserAuthentication.isHashablePassword(new char[] {'a', 'b', 'c', 0}));
        no("lone high surrogate", UserAuthentication.isHashablePassword(new char[] {'a', (char) 0xD800}));
        no("lone low surrogate", UserAuthentication.isHashablePassword(new char[] {'a', (char) 0xDC00}));
        no("high surrogate not followed by a low one",
            UserAuthentication.isHashablePassword(new char[] {(char) 0xD800, 'a'}));
        yes("1024 characters", UserAuthentication.isHashablePassword("p".repeat(1024).toCharArray()));
        no("1025 characters", UserAuthentication.isHashablePassword("p".repeat(1025).toCharArray()));
        no("an all-NUL buffer of any length", UserAuthentication.isHashablePassword(new char[1024]));

        UserAuthentication auth = service(newStore(), fastConfig());
        throwsA("empty password on register", IllegalArgumentException.class,
            () -> auth.register("mallory", new char[0]));
        throwsA("short username on register", IllegalArgumentException.class,
            () -> auth.register("ab", "long-enough-pw".toCharArray()));
        throwsA("null username on register", IllegalArgumentException.class,
            () -> auth.register(null, "long-enough-pw".toCharArray()));
        eq("null username on login is refused, not an NPE", UserAuthentication.Outcome.INVALID_INPUT,
            auth.authenticate(null, "whatever-1".toCharArray()).outcome());
    }

    // --------------------------------------------------------------------------------------------
    // Password hashing
    // --------------------------------------------------------------------------------------------

    private static void hashing() {
        UserAuthentication.PasswordHash first = UserAuthentication.PasswordHash.generate(
            "same-password".toCharArray(), FAST_ITERATIONS, new SecureRandom());
        UserAuthentication.PasswordHash second = UserAuthentication.PasswordHash.generate(
            "same-password".toCharArray(), FAST_ITERATIONS, new SecureRandom());

        eq("same password yields a different encoding (random salt)", false,
            first.encode().equals(second.encode()));
        yes("each record still verifies its own password",
            first.matches(first.deriveKey("same-password".toCharArray())));
        no("and does not accept the other record's derivation",
            first.matches(second.deriveKey("same-password".toCharArray())));

        UserAuthentication.PasswordHash parsed = UserAuthentication.PasswordHash.parse(first.encode());
        eq("encoding round-trips the iteration count", first.iterations(), parsed.iterations());
        yes("encoding round-trips the salt", Arrays.equals(first.salt(), parsed.salt()));
        yes("parsed record verifies the real password",
            parsed.matches(parsed.deriveKey("same-password".toCharArray())));
        no("parsed record rejects a wrong password",
            parsed.matches(parsed.deriveKey("wrong-password".toCharArray())));
        eq("toString redacts the material", "PasswordHash[redacted]", parsed.toString());

        byte[] accessorCopy = first.salt();
        Arrays.fill(accessorCopy, (byte) 0);
        yes("zeroing the array the accessor handed out cannot corrupt the record",
            first.matches(first.deriveKey("same-password".toCharArray())));
        byte[] secondCopy = first.salt();
        yes("the accessor hands out a live copy, not the stored array itself",
            !Arrays.equals(secondCopy, new byte[16]) && secondCopy.length == 16);

        // Build a record from arrays the test keeps a handle on: a record that stored the caller's
        // arrays instead of copying them would be destroyed by the wipe below.
        byte[] ownedSalt = new byte[16];
        new SecureRandom().nextBytes(ownedSalt);
        byte[] ownedKey = rawDerive("constructor-password".toCharArray(), ownedSalt);
        UserAuthentication.PasswordHash borrowed =
            new UserAuthentication.PasswordHash(FAST_ITERATIONS, ownedSalt, ownedKey);
        yes("the record built from caller arrays verifies its password",
            borrowed.matches(borrowed.deriveKey("constructor-password".toCharArray())));
        Arrays.fill(ownedSalt, (byte) 0);
        Arrays.fill(ownedKey, (byte) 0);
        yes("wiping the caller's salt afterwards cannot corrupt the record",
            borrowed.matches(borrowed.deriveKey("constructor-password".toCharArray())));
        no("wiping the caller's key afterwards cannot corrupt the record either",
            borrowed.matches(new byte[32]));
        yes("and a record whose own key was zeroed still rejects a wrong password",
            !borrowed.matches(borrowed.deriveKey("not-it-at-all".toCharArray())));

        List<String> malformed = new ArrayList<>();
        malformed.add(null);
        malformed.add("");
        malformed.add("bcrypt$2000$" + b64(16) + "$" + b64(32));
        malformed.add("pbkdf2-sha256$2000$" + b64(16));
        malformed.add("pbkdf2-sha256$ten$" + b64(16) + "$" + b64(32));
        malformed.add("pbkdf2-sha256$999$" + b64(16) + "$" + b64(32));
        malformed.add("pbkdf2-sha256$2000$" + b64(4) + "$" + b64(32));
        malformed.add("pbkdf2-sha256$2000$" + b64(16) + "$" + b64(8));
        malformed.add("pbkdf2-sha256$2000$" + b64(16) + "X$" + b64(32));
        malformed.add("pbkdf2-sha256$2000$" + b64(16).replace('A', '!') + "$" + b64(32));
        // Case-flipping one Base64 character is still strictly valid and decodes to different
        // bytes, so only a canonical re-encode comparison can catch it.
        malformed.add("pbkdf2-sha256$2000$" + b64(16).replace('A', 'a') + "$" + b64(32));
        malformed.add("pbkdf2-sha256$2000$" + b64(16) + "$" + b64(32).replace('A', 'a'));
        malformed.add("pbkdf2-sha256$2000$" + b64(16) + "$" + b64(32).substring(0, 20) + "A=");
        for (String candidate : malformed) {
            throwsA("malformed stored hash rejected: " + summarize(candidate),
                IllegalArgumentException.class, () -> UserAuthentication.PasswordHash.parse(candidate));
        }

        // The JCE's char[] converter is lossy. Show the collision the guard prevents by deriving
        // with the raw JCE, then confirm the service refuses every collapsing form.
        byte[] salt = first.salt();
        String trailingNul = "password-9";
        yes("raw JCE collapses a trailing NUL onto the shorter password", Arrays.equals(
            rawDerive(trailingNul.toCharArray(), salt),
            rawDerive((trailingNul + (char) 0).toCharArray(), salt)));
        yes("raw JCE collapses two trailing NULs as well", Arrays.equals(
            rawDerive(trailingNul.toCharArray(), salt),
            rawDerive((trailingNul + (char) 0 + (char) 0).toCharArray(), salt)));
        yes("raw JCE collapses an unpaired surrogate onto '?'", Arrays.equals(
            rawDerive(("pw" + (char) 0xD800).toCharArray(), salt), rawDerive("pw?".toCharArray(), salt)));
        no("service accepts the trailing-NUL form",
            UserAuthentication.isHashablePassword((trailingNul + (char) 0).toCharArray()));
        no("service accepts the unpaired-surrogate form",
            UserAuthentication.isHashablePassword(("pw" + (char) 0xD800).toCharArray()));
        yes("interior NUL stays distinct under the raw JCE", !Arrays.equals(
            rawDerive(("pa" + (char) 0 + "ss").toCharArray(), salt),
            rawDerive("pass".toCharArray(), salt)));

        UserAuthentication.PasswordHash astral = UserAuthentication.PasswordHash.generate(
            ("pw" + (char) 0xD83D + (char) 0xDE00).toCharArray(), FAST_ITERATIONS, new SecureRandom());
        yes("astral password round-trips", astral.matches(
            astral.deriveKey(("pw" + (char) 0xD83D + (char) 0xDE00).toCharArray())));
        no("astral password rejects a near miss",
            astral.matches(astral.deriveKey("pw".toCharArray())));
    }

    private static byte[] rawDerive(char[] password, byte[] salt) {
        return rawDerive(password, salt, FAST_ITERATIONS);
    }

    private static byte[] rawDerive(char[] password, byte[] salt, int iterations) {
        try {
            javax.crypto.spec.PBEKeySpec spec =
                new javax.crypto.spec.PBEKeySpec(password, salt, iterations, 32 * 8);
            return javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(spec).getEncoded();
        } catch (java.security.GeneralSecurityException unsupported) {
            throw new IllegalStateException(unsupported);
        }
    }

    private static String b64(int byteLength) {
        return Base64.getEncoder().encodeToString(new byte[byteLength]);
    }

    private static String summarize(String candidate) {
        if (candidate == null) {
            return "null";
        }
        return candidate.length() <= 34 ? "[" + candidate + "]"
            : "[" + candidate.substring(0, 22) + "... (" + candidate.length() + " chars)]";
    }

    // --------------------------------------------------------------------------------------------
    // Credential verification
    // --------------------------------------------------------------------------------------------

    private static void credentials() {
        UserAuthentication.InMemoryAccountStore store = newStore();
        RecordingLog log = new RecordingLog();
        UserAuthentication auth = service(store, fastConfig().withoutLockout(NO_LOCKOUT), log);

        yes("alice registers", auth.register("alice", PW));
        no("duplicate registration is refused", auth.register("alice", "other-password".toCharArray()));
        yes("registration is findable through a different spelling", auth.accountExists(" ALICE "));
        no("unknown account does not exist", auth.accountExists("nobody"));

        UserAuthentication.Result ok = auth.authenticate("alice", PW);
        eq("correct password succeeds", UserAuthentication.Outcome.SUCCESS, ok.outcome());
        eq("success reason", UserAuthentication.Reason.OK, ok.auditReason());
        eq("success reports no failures", 0, ok.failedAttempts());
        yes("success carries a timestamp", ok.timestamp() != null);
        eq("success message", "Login successful.", ok.userMessage());
        yes("isSuccess agrees", ok.isSuccess());

        String[] wrong = {"alice", "Alice1", "winter-Frost-41", "winter-Frost-42 ", " ", "winter",
            "WINTER-FROST-42", "hunter2-nope", "00000000", "password-9", "correct horse"};
        for (String candidate : wrong) {
            eq("wrong password refused [" + candidate.length() + " chars]",
                UserAuthentication.Outcome.INVALID_CREDENTIALS,
                auth.authenticate("alice", candidate.toCharArray()).outcome());
            eq("wrong password reason [" + candidate.length() + " chars]",
                UserAuthentication.Reason.BAD_PASSWORD,
                auth.authenticate("alice", candidate.toCharArray()).auditReason());
        }
        eq("every wrong candidate was counted", wrong.length * 2, store.failuresOf("alice"));

        UserAuthentication.Result unknown = auth.authenticate("carol", "whatever-123".toCharArray());
        eq("unknown user is refused", UserAuthentication.Outcome.INVALID_CREDENTIALS, unknown.outcome());
        eq("unknown user reason", UserAuthentication.Reason.UNKNOWN_USER, unknown.auditReason());
        no("the attempt did not create the account", auth.accountExists("carol"));
        eq("known and unknown users get the same wording",
            auth.authenticate("alice", "nope-nope-nope".toCharArray()).userMessage(), unknown.userMessage());
        eq("wording does not say which half failed", "Invalid username or password.", unknown.userMessage());

        no("password comparison is case sensitive",
            auth.authenticate("alice", "WINTER-FROST-42".toCharArray()).isSuccess());
        eq("trailing-NUL copy of the right password is refused as invalid input",
            UserAuthentication.Outcome.INVALID_INPUT,
            auth.authenticate("alice", (new String(PW) + (char) 0).toCharArray()).outcome());
        eq("unpaired surrogate candidate is refused as invalid input",
            UserAuthentication.Outcome.INVALID_INPUT,
            auth.authenticate("alice", new char[] {'w', (char) 0xD800}).outcome());
        eq("empty password is an input error, not a credential check",
            UserAuthentication.Outcome.INVALID_INPUT, auth.authenticate("alice", new char[0]).outcome());
        eq("oversized password is an input error", UserAuthentication.Outcome.INVALID_INPUT,
            auth.authenticate("alice", new char[4096]).outcome());
        yes("a candidate that merely shares a prefix fails",
            !auth.authenticate("alice", "winter-F".toCharArray()).isSuccess());
        yes("a candidate that is a suffix of the real password fails",
            !auth.authenticate("alice", "rost-42".toCharArray()).isSuccess());

        UserAuthentication.InMemoryAccountStore aliasStore = newStore();
        UserAuthentication aliased = service(aliasStore, fastConfig());
        yes("register through a messy spelling", aliased.register("  Bob.DOE_9  ", "pw-value-1".toCharArray()));
        yes("log in through a different spelling of the same name",
            aliased.authenticate("bob.doe_9", "pw-value-1".toCharArray()).isSuccess());
        yes("both spellings name one account", aliased.accountExists("BOB.DOE_9"));
        eq("the second spelling did not create a second account", 1, aliasStore.size());
    }

    // --------------------------------------------------------------------------------------------
    // Lockout
    // --------------------------------------------------------------------------------------------

    private static void lockout() {
        UserAuthentication.InMemoryAccountStore store = newStore();
        RecordingLog log = new RecordingLog();
        UserAuthentication auth = service(store, fastConfig().withoutLockout(3), log);
        yes("carol registers", auth.register("carol", PW));

        for (int strike = 1; strike <= 2; strike++) {
            UserAuthentication.Result r = auth.authenticate("carol", ("bad-choice-" + strike).toCharArray());
            eq("strike " + strike + " is a credential failure", UserAuthentication.Outcome.INVALID_CREDENTIALS,
                r.outcome());
            eq("strike " + strike + " is counted", strike, r.failedAttempts());
        }

        UserAuthentication.Result tripping = auth.authenticate("carol", "bad-choice-3".toCharArray());
        eq("the strike that trips the lock still reports bad credentials",
            UserAuthentication.Outcome.INVALID_CREDENTIALS, tripping.outcome());
        eq("and reports the full count", 3, tripping.failedAttempts());

        UserAuthentication.Result locked = auth.authenticate("carol", PW);
        eq("the right password is refused while locked", UserAuthentication.Outcome.ACCOUNT_LOCKED,
            locked.outcome());
        eq("locked reason", UserAuthentication.Reason.ACCOUNT_LOCKED, locked.auditReason());
        eq("locked message", "Account temporarily locked. Try again later.", locked.userMessage());
        eq("the counter stops at the threshold", 3, store.failuresOf("carol"));
        eq("the lockout was logged once", 1, log.countOf(UserAuthentication.EventType.ACCOUNT_LOCKED_OUT));
        eq("the locked attempt itself is logged", UserAuthentication.Reason.ACCOUNT_LOCKED,
            log.last(UserAuthentication.EventType.LOGIN_FAILURE).reason);

        yes("an operator can unlock", auth.unlock("carol"));
        eq("unlocking clears the counter", 0, store.failuresOf("carol"));
        yes("login works after an operator unlock", auth.authenticate("carol", PW).isSuccess());
        no("unlocking an unknown account reports false", auth.unlock("nobody"));
        no("locking an unknown account can be unlocked", auth.unlock("no-such-user"));

        UserAuthentication.Result slip = auth.authenticate("carol", "slip-one".toCharArray());
        eq("counting restarts after a verified login", 1, slip.failedAttempts());
        yes("verified login again", auth.authenticate("carol", PW).isSuccess());
        eq("a successful login clears the counter", 0, store.failuresOf("carol"));
        eq("next typo is strike one again", 1,
            auth.authenticate("carol", "slip-two".toCharArray()).failedAttempts());

        int before = log.countOf(UserAuthentication.EventType.LOGIN_SUCCESS);
        auth.authenticate("carol", "slip-three".toCharArray());
        auth.authenticate("carol", PW);
        eq("successes are logged too", before + 1,
            log.countOf(UserAuthentication.EventType.LOGIN_SUCCESS));
    }

    private static void failureWindowAndExpiry() {
        Instant t0 = Instant.parse("2026-09-12T10:00:00Z");
        UserAuthentication.InMemoryAccountStore store = newStore();

        UserAuthentication window = service(store,
            new UserAuthentication.Config(FAST_ITERATIONS, 100, Duration.ofMinutes(15),
                Duration.ofMinutes(60), Clock.fixed(t0, ZoneOffset.UTC)), new RecordingLog());
        yes("window account registers", window.register("win1", PW));
        window.authenticate("win1", "old-failure-1".toCharArray());
        window.authenticate("win1", "old-failure-2".toCharArray());
        eq("two strikes recorded at T0", 2, store.failuresOf("win1"));

        UserAuthentication muchLater = service(store,
            new UserAuthentication.Config(FAST_ITERATIONS, 100, Duration.ofMinutes(15),
                Duration.ofMinutes(60), Clock.fixed(t0.plus(Duration.ofHours(2)), ZoneOffset.UTC)),
            new RecordingLog());
        eq("strikes older than the failure window are forgotten", 1,
            muchLater.authenticate("win1", "fresh-failure".toCharArray()).failedAttempts());

        UserAuthentication inWindow = service(store,
            new UserAuthentication.Config(FAST_ITERATIONS, 100, Duration.ofMinutes(15),
                Duration.ofMinutes(60), Clock.fixed(t0.plus(Duration.ofMinutes(5)), ZoneOffset.UTC)),
            new RecordingLog());
        eq("in-window strikes accumulate", 2,
            inWindow.authenticate("win1", "mid-window".toCharArray()).failedAttempts());

        UserAuthentication locking = service(store,
            new UserAuthentication.Config(FAST_ITERATIONS, 3, Duration.ofMinutes(15),
                Duration.ofMinutes(60), Clock.fixed(t0.plus(Duration.ofHours(3)), ZoneOffset.UTC)),
            new RecordingLog());
        yes("lock account registers", locking.register("lock1", PW));
        for (int i = 1; i <= 3; i++) {
            locking.authenticate("lock1", ("strike-" + i).toCharArray());
        }
        eq("locked 10 minutes into the 15 minute lock", UserAuthentication.Outcome.ACCOUNT_LOCKED,
            service(store, clockAt(t0.plus(Duration.ofMinutes(190)), 3), new RecordingLog())
                .authenticate("lock1", PW).outcome());
        eq("still locked one minute before the deadline", UserAuthentication.Outcome.ACCOUNT_LOCKED,
            service(store, clockAt(t0.plus(Duration.ofMinutes(194)), 3), new RecordingLog())
                .authenticate("lock1", PW).outcome());
        RecordingLog afterExpiryRecording = new RecordingLog();
        UserAuthentication afterExpiry = service(store,
            clockAt(t0.plus(Duration.ofMinutes(196)), 3), afterExpiryRecording);
        yes("auto-unlocked once the lock duration elapsed",
            afterExpiry.authenticate("lock1", PW).isSuccess());
        eq("auto-unlock cleared the counter", 0, store.failuresOf("lock1"));
        eq("the auto-unlock was logged", 1,
            afterExpiryRecording.countOf(UserAuthentication.EventType.ACCOUNT_UNLOCKED));
    }

    private static UserAuthentication.Config clockAt(Instant when, int maxFailures) {
        return new UserAuthentication.Config(FAST_ITERATIONS, maxFailures, Duration.ofMinutes(15),
            Duration.ofMinutes(60), Clock.fixed(when, ZoneOffset.UTC));
    }

    // --------------------------------------------------------------------------------------------
    // Disabled and damaged accounts
    // --------------------------------------------------------------------------------------------

    private static void disabledAndCorrupt() {
        RecordingLog log = new RecordingLog();
        UserAuthentication auth = service(newStore(), fastConfig(), log);
        yes("erin registers", auth.register("erin", PW));
        yes("erin can be disabled", auth.setEnabled("erin", false));
        UserAuthentication.Result off = auth.authenticate("erin", PW);
        eq("disabled account is refused", UserAuthentication.Outcome.ACCOUNT_DISABLED, off.outcome());
        eq("disabled reason", UserAuthentication.Reason.ACCOUNT_DISABLED, off.auditReason());
        eq("a disabled account takes no strike", 0, off.failedAttempts());
        eq("the disabled attempt is logged", UserAuthentication.Reason.ACCOUNT_DISABLED,
            log.last(UserAuthentication.EventType.LOGIN_FAILURE).reason);
        yes("erin can be re-enabled", auth.setEnabled("erin", true));
        yes("erin can log in again", auth.authenticate("erin", PW).isSuccess());
        no("disabling an unknown account reports false", auth.setEnabled("nobody", false));
        no("enabling an unknown account reports false", auth.setEnabled("nobody", true));

        CorruptStore store = new CorruptStore();
        store.inject(UserAuthentication.Account.withCorruptHash("ghost"));
        UserAuthentication corrupt = service(store, fastConfig(), log);
        UserAuthentication.Result broken = corrupt.authenticate("ghost", PW);
        eq("an account whose stored digest is unreadable is refused",
            UserAuthentication.Outcome.INVALID_CREDENTIALS, broken.outcome());
        eq("and is reported internally as a corrupt record", UserAuthentication.Reason.CORRUPT_RECORD,
            broken.auditReason());
        no("a corrupt record is never a match", broken.isSuccess());
    }

    // --------------------------------------------------------------------------------------------
    // Audit log
    // --------------------------------------------------------------------------------------------

    private static void auditLog() throws IOException {
        RecordingLog log = new RecordingLog();
        UserAuthentication auth = service(newStore(),
            fastConfig().withoutLockout(2), log);
        auth.register("frank", PW);

        UserAuthentication.Result ok = auth.authenticate("frank", PW, "203.0.113.7");
        UserAuthentication.Event success = log.last(UserAuthentication.EventType.LOGIN_SUCCESS);
        eq("success records the caller's address", "203.0.113.7", success.remoteAddress);
        eq("success records the normalized username", "frank", success.username);
        eq("success records the outcome", UserAuthentication.Outcome.SUCCESS, success.outcome);
        yes("success records a duration", ok.durationMillis() >= 0);
        eq("success reason is recorded", UserAuthentication.Reason.OK, success.reason);

        auth.authenticate("frank", "wrong-password".toCharArray(), "198.51.100.9");
        UserAuthentication.Event failure = log.last(UserAuthentication.EventType.LOGIN_FAILURE);
        eq("failure records the caller's address", "198.51.100.9", failure.remoteAddress);
        eq("failure records the reason", UserAuthentication.Reason.BAD_PASSWORD, failure.reason);

        auth.authenticate("nobody-here", "whatever-123".toCharArray());
        eq("unknown user is logged as a failure with its reason", UserAuthentication.Reason.UNKNOWN_USER,
            log.last(UserAuthentication.EventType.LOGIN_FAILURE).reason);

        auth.authenticate("bo", "whatever-123".toCharArray());
        eq("a malformed username is logged as a refusal", UserAuthentication.Reason.MALFORMED_USERNAME,
            log.last(UserAuthentication.EventType.LOGIN_REFUSED).reason);

        auth.register("grace", PW);
        eq("both registrations are logged", 2,
            log.countOf(UserAuthentication.EventType.ACCOUNT_REGISTERED));
        no("a repeated username is refused", auth.register("  GRACE ", "different-password".toCharArray()));
        eq("the refused duplicate is logged as well", 3,
            log.countOf(UserAuthentication.EventType.ACCOUNT_REGISTERED));
        eq("and says so", "duplicate", log.last(UserAuthentication.EventType.ACCOUNT_REGISTERED).detail);
        eq("the duplicate did not overwrite the original password", UserAuthentication.Outcome.SUCCESS,
            auth.authenticate("grace", PW).outcome());
        auth.unlock("grace");
        eq("the operator unlock is logged", 1,
            log.countOf(UserAuthentication.EventType.ACCOUNT_UNLOCKED));

        for (UserAuthentication.Event event : log.snapshot()) {
            no("line has no newline (" + event.type + ")", event.format().contains("\n"));
            yes("line parses back (" + event.type + ")",
                UserAuthentication.Event.parseLine(event.format()) != null);
        }
        // One LOGIN_* record for each of the five authenticate calls made above, and no extras.
        eq("exactly one attempt record per authenticate call", 5,
            log.countOf(UserAuthentication.EventType.LOGIN_SUCCESS)
                + log.countOf(UserAuthentication.EventType.LOGIN_FAILURE)
                + log.countOf(UserAuthentication.EventType.LOGIN_REFUSED));

        String rendered = failure.format();
        no("the candidate password is not in the log", rendered.contains("wrong-password"));
        no("the real password is not in the log", rendered.contains(new String(PW)));
        no("no hash material is in the log", rendered.contains("pbkdf2-sha256"));

        UserAuthentication.Event back = UserAuthentication.Event.parseLine(rendered);
        eq("parseLine recovers the type", failure.type, back.type);
        eq("parseLine recovers the username", failure.username, back.username);
        eq("parseLine recovers the reason", failure.reason, back.reason);
        eq("parseLine recovers the address", failure.remoteAddress, back.remoteAddress);
        eq("parseLine recovers the failure count", failure.failedAttempts, back.failedAttempts);
        no("parseLine rejects junk", UserAuthentication.Event.parseLine("not a log line") != null);
        no("parseLine rejects null", UserAuthentication.Event.parseLine(null) != null);

        Path file = Files.createTempFile("auth-audit", ".log");
        try {
            try (UserAuthentication.FileEventLogger fileLogger =
                     new UserAuthentication.FileEventLogger(file, null)) {
                UserAuthentication fileAuth = service(newStore(), fastConfig(), fileLogger);
                fileAuth.register("henry", PW);
                fileAuth.authenticate("henry", PW, "203.0.113.10");
                fileAuth.authenticate("henry", "wrong-password".toCharArray(), "203.0.113.10");
                fileAuth.authenticate("nobody-at-all", "whatever-123".toCharArray(), null);
            }
            List<String> lines = Files.readAllLines(file, StandardCharsets.US_ASCII);
            eq("the file logger wrote one line per event", 4, lines.size());
            yes("every file line is a well formed record", lines.stream()
                .allMatch(line -> line.contains("|event=") && UserAuthentication.Event.parseLine(line) != null));
            yes("the failure reason reached the file", lines.stream()
                .anyMatch(line -> line.contains("reason=BAD_PASSWORD")));
            yes("the success reached the file",
                lines.stream().anyMatch(line -> line.contains("event=LOGIN_SUCCESS")));
            yes("the file is pure ASCII", lines.stream().noneMatch(line -> !isAscii(line)));

            try (UserAuthentication.FileEventLogger reopened =
                     new UserAuthentication.FileEventLogger(file, null)) {
                service(newStore(), fastConfig(), reopened)
                    .authenticate("henry", PW, "203.0.113.11");
            }
            eq("a reopened logger appends instead of truncating", 5,
                Files.readAllLines(file, StandardCharsets.US_ASCII).size());
        } finally {
            Files.deleteIfExists(file);
        }

        PrintStream originalOut = System.out;
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try {
            System.setOut(new PrintStream(buffer, true, StandardCharsets.UTF_8));
            UserAuthentication consoleAuth = service(newStore(), fastConfig(),
                new UserAuthentication.ConsoleEventLogger());
            consoleAuth.register("ivy", PW);
            consoleAuth.authenticate("ivy", PW);
        } finally {
            System.setOut(originalOut);
        }
        String printed = buffer.toString(StandardCharsets.UTF_8);
        yes("the console logger prints the event", printed.contains("event=LOGIN_SUCCESS"));
        no("the console logger never prints the password", printed.contains(new String(PW)));

        UserAuthentication quiet = service(newStore(), fastConfig(),
            UserAuthentication.EventLogger.nullLogger());
        yes("the null logger still authenticates",
            quiet.register("jack", PW) && quiet.authenticate("jack", PW).isSuccess());
    }

    private static void logInjection() {
        RecordingLog log = new RecordingLog();
        UserAuthentication auth = service(newStore(), fastConfig(), log);
        auth.register("peggy", PW);
        String tab = String.valueOf((char) 0x09);
        String[] hostile = {
            "mallory\r\n2026-09-12T00:00:00Z|event=LOGIN_SUCCESS|user=admin|outcome=SUCCESS",
            "bob|event=LOGIN_SUCCESS|user=admin",
            "alice\n|detail=pwned" + tab + "x",
            "a".repeat(200) + "|event=LOGIN_SUCCESS",
            "admin" + (char) 0x00 + "|event=LOGIN_SUCCESS",
            "user" + (char) 0x1B + "[31m"
        };
        for (String name : hostile) {
            UserAuthentication.Result r = auth.authenticate(name, "whatever-123".toCharArray());
            yes("hostile username is refused [" + r.auditReason() + "]",
                r.outcome() == UserAuthentication.Outcome.INVALID_INPUT
                    || r.outcome() == UserAuthentication.Outcome.INVALID_CREDENTIALS);
        }
        UserAuthentication.Result viaPassword =
            auth.authenticate("peggy", ("pass" + (char) 0x0A + "|event=LOGIN_SUCCESS|x=y").toCharArray());
        eq("a newline inside the candidate password cannot forge a record",
            UserAuthentication.Outcome.INVALID_CREDENTIALS, viaPassword.outcome());

        for (UserAuthentication.Event event : log.snapshot()) {
            no("field carries no CR or LF", event.username.contains("\r")
                || event.username.contains("\n") || event.detail.contains("\n"));
            no("field carries no delimiter", event.username.contains("|") || event.detail.contains("|"));
            yes("field is ASCII and bounded", isAscii(event.username) && event.username.length() <= 65);
            eq("record keeps its eight delimiters", 8, countChar(event.format(), '|'));
            eq("record still parses", true, UserAuthentication.Event.parseLine(event.format()) != null);
        }
        eq("sanitizeField neutralizes CRLF", "a..b", UserAuthentication.sanitizeField("a\r\nb"));
        eq("sanitizeField replaces the delimiter", "a.b", UserAuthentication.sanitizeField("a|b"));
        eq("sanitizeField marks truncation", 65, UserAuthentication.sanitizeField("z".repeat(300)).length());
        eq("sanitizeField marks a missing value", "-", UserAuthentication.sanitizeField(null));
        eq("sanitizeField marks an empty value", "-", UserAuthentication.sanitizeField(""));
        eq("sanitizeField keeps ordinary text", "203.0.113.7", UserAuthentication.sanitizeField("203.0.113.7"));
    }

    // --------------------------------------------------------------------------------------------
    // Equal work
    // --------------------------------------------------------------------------------------------

    private static void equalWork() {
        UserAuthentication heavy = service(newStore(),
            new UserAuthentication.Config(TIMING_ITERATIONS, NO_LOCKOUT, Duration.ofMinutes(15),
                Duration.ofMinutes(30), Clock.systemUTC()), new RecordingLog());
        heavy.register("known-user", "known-user-password".toCharArray());

        UserAuthentication.PasswordHash charge = heavy.equalWorkHash();
        eq("the equal-work digest uses the configured rounds", TIMING_ITERATIONS, charge.iterations());
        eq("the equal-work digest has a full salt", 16, charge.salt().length);
        long chargeMillis = timeOnce(() -> charge.deriveKey(EQUAL_WORK_TEXT.toCharArray()));
        yes("the equal-work digest really costs work: " + chargeMillis + "ms", chargeMillis >= 5);
        no("no account accepts the equal-work secret as its password",
            heavy.authenticate("known-user", EQUAL_WORK_TEXT.toCharArray()).isSuccess());
        yes("the equal-work digest verifies its own derivation",
            charge.matches(charge.deriveKey(EQUAL_WORK_TEXT.toCharArray())));

        // One-strike service so each locked sample can be prepared on a fresh account: per-account
        // lockout would otherwise short-circuit later samples and fabricate the ratio.
        UserAuthentication oneStrike = service(newStore(),
            new UserAuthentication.Config(TIMING_ITERATIONS, 1, Duration.ofMinutes(15),
                Duration.ofMinutes(30), Clock.systemUTC()), new RecordingLog());
        for (int i = 0; i < LOCK_ACCOUNTS; i++) {
            oneStrike.register("lock-" + i, ("password-for-lock-" + i).toCharArray());
        }
        double knownWrong = timed(5, () ->
            heavy.authenticate("known-user", "the-wrong-password".toCharArray()));
        double unknown = timed(5, () ->
            heavy.authenticate("no-such-user-x", "the-wrong-password".toCharArray()));
        double badName = timed(5, () ->
            heavy.authenticate("bo", "the-wrong-password".toCharArray()));
        double badPassword = timed(5, () -> heavy.authenticate("known-user", new char[0]));
        double disabledCase = disabledBranchMillis(TIMING_ITERATIONS);
        List<UserAuthentication.Outcome> lockedOutcomes = new ArrayList<>();
        double locked = lockedBranchMillis(oneStrike, lockedOutcomes);
        eq("every locked sample was refused by the lock alone", 5, (int) lockedOutcomes.stream()
            .filter(outcome -> outcome == UserAuthentication.Outcome.ACCOUNT_LOCKED).count());

        yes("a refused credential check costs real work: " + (long) knownWrong + "ms",
            knownWrong >= 8.0);
        ratio("unknown user", unknown, knownWrong);
        ratio("malformed username", badName, knownWrong);
        ratio("unusable password candidate", badPassword, knownWrong);
        ratio("disabled account", disabledCase, knownWrong);
        ratio("locked account", locked, knownWrong);
        System.out.println("    [median ms] known-wrong=" + (long) knownWrong + " unknown="
            + (long) unknown + " bad-name=" + (long) badName + " bad-password=" + (long) badPassword
            + " disabled=" + (long) disabledCase + " locked=" + (long) locked);
    }

    /**
     * Median wall time of the locked-account branch. Each sample trips the lock on a fresh account
     * outside the timed window and then times only the locked refusal, which presents the correct
     * password so that nothing but the lock can refuse it.
     */
    private static double lockedBranchMillis(UserAuthentication oneStrike,
                                             List<UserAuthentication.Outcome> outcomes) {
        for (int i = 0; i < 2; i++) {
            String name = "warm-" + i;
            oneStrike.register(name, ("warm-password-" + i).toCharArray());
            oneStrike.authenticate(name, "the-wrong-password".toCharArray());
            oneStrike.authenticate(name, ("warm-password-" + i).toCharArray());
        }
        long[] observed = new long[5];
        for (int i = 0; i < observed.length; i++) {
            String name = "lock-" + i;
            oneStrike.authenticate(name, "the-wrong-password".toCharArray());
            long begin = System.nanoTime();
            UserAuthentication.Result refusal =
                oneStrike.authenticate(name, ("password-for-lock-" + i).toCharArray());
            observed[i] = (System.nanoTime() - begin) / 1_000_000L;
            outcomes.add(refusal.outcome());
        }
        Arrays.sort(observed);
        return observed[observed.length / 2];
    }

    private static double disabledBranchMillis(int iterations) {
        UserAuthentication service = service(newStore(),
            new UserAuthentication.Config(iterations, NO_LOCKOUT, Duration.ofMinutes(15),
                Duration.ofMinutes(30), Clock.systemUTC()), new RecordingLog());
        service.register("off-user", "off-user-password".toCharArray());
        service.setEnabled("off-user", false);
        return timed(5, () -> service.authenticate("off-user", "anything-at-all".toCharArray()));
    }

    /** Median of {@code samples} calls, after two warm-up calls, timed with the wall clock. */
    private static double timed(int samples, java.util.function.Supplier<?> attempt) {
        for (int i = 0; i < 2; i++) {
            attempt.get();
        }
        long[] observed = new long[samples];
        for (int i = 0; i < samples; i++) {
            long begin = System.nanoTime();
            attempt.get();
            observed[i] = (System.nanoTime() - begin) / 1_000_000L;
        }
        Arrays.sort(observed);
        return observed[observed.length / 2];
    }

    private static void ratio(String label, double measured, double baseline) {
        double value = measured / baseline;
        yes(label + " costs comparable work (ratio " + String.format(Locale.ROOT, "%.2f", value)
            + ", want 0.6-1.7)", value >= 0.6 && value <= 1.7);
    }

    // --------------------------------------------------------------------------------------------
    // Concurrency
    // --------------------------------------------------------------------------------------------

    private static void concurrency() throws Exception {
        final int threads = 8;
        final int trials = 100;
        int lost = 0;
        UserAuthentication.Config config = fastConfig().withoutLockout(threads + 10);
        for (int trial = 0; trial < trials; trial++) {
            UserAuthentication.Account account = UserAuthentication.Account.withCorruptHash("race-" + trial);
            CyclicBarrier barrier = new CyclicBarrier(threads);
            CountDownLatch done = new CountDownLatch(threads);
            for (int t = 0; t < threads; t++) {
                new Thread(() -> {
                    try {
                        barrier.await(10, TimeUnit.SECONDS);
                        account.recordFailure(Instant.now(), config);
                    } catch (Exception failure) {
                        record("strike racer threw " + failure);
                    } finally {
                        done.countDown();
                    }
                }).start();
            }
            done.await(20, TimeUnit.SECONDS);
            if (account.failedAttempts() != threads) {
                lost++;
            }
        }
        eq("the strike counter never loses an update (" + trials + " trials x " + threads + " threads)",
            0, lost);

        UserAuthentication.Account mixed = UserAuthentication.Account.withCorruptHash("mixed");
        UserAuthentication.Config bigWindow = fastConfig().withoutLockout(1000);
        CyclicBarrier barrier = new CyclicBarrier(12);
        CountDownLatch done = new CountDownLatch(12);
        for (int t = 0; t < 8; t++) {
            new Thread(() -> {
                try {
                    barrier.await(10, TimeUnit.SECONDS);
                    mixed.recordFailure(Instant.now(), bigWindow);
                } catch (Exception failure) {
                    record("mixed racer threw " + failure);
                } finally {
                    done.countDown();
                }
            }).start();
        }
        for (int t = 0; t < 4; t++) {
            new Thread(() -> {
                try {
                    barrier.await(10, TimeUnit.SECONDS);
                    mixed.recordSuccess(Instant.now());
                } catch (Exception failure) {
                    record("mixed racer threw " + failure);
                } finally {
                    done.countDown();
                }
            }).start();
        }
        done.await(30, TimeUnit.SECONDS);
        yes("concurrent strikes and successes leave a consistent counter (got "
            + mixed.failedAttempts() + ")", mixed.failedAttempts() <= 8);

        final int writers = 4;
        final int perWriter = 25;
        Path file = Files.createTempFile("auth-audit-concurrent", ".log");
        try (UserAuthentication.FileEventLogger fileLogger =
                 new UserAuthentication.FileEventLogger(file, null)) {
            CyclicBarrier start = new CyclicBarrier(writers);
            CountDownLatch finished = new CountDownLatch(writers);
            for (int w = 0; w < writers; w++) {
                final int id = w;
                new Thread(() -> {
                    try {
                        start.await(10, TimeUnit.SECONDS);
                        for (int i = 0; i < perWriter; i++) {
                            fileLogger.log(newEvent(id, i));
                        }
                    } catch (Exception failure) {
                        record("file logger writer threw " + failure);
                    } finally {
                        finished.countDown();
                    }
                }).start();
            }
            finished.await(30, TimeUnit.SECONDS);
            List<String> lines = Files.readAllLines(file, StandardCharsets.US_ASCII);
            eq("every concurrent log line survived", writers * perWriter, lines.size());
            yes("no interleaved or partial lines", lines.stream()
                .allMatch(line -> UserAuthentication.Event.parseLine(line) != null));
            eq("each writer kept its own lines", writers * perWriter, (int) lines.stream()
                .filter(line -> line.contains("|event=LOGIN_SUCCESS")).count());
        } finally {
            Files.deleteIfExists(file);
        }

        final int racers = 16;
        UserAuthentication.InMemoryAccountStore store = newStore();
        RecordingLog racedLog = new RecordingLog();
        UserAuthentication auth = service(store, fastConfig().withoutLockout(NO_LOCKOUT), racedLog);
        auth.register("racer-target", "raced-password".toCharArray());
        CyclicBarrier loginBarrier = new CyclicBarrier(racers);
        CountDownLatch loginDone = new CountDownLatch(racers);
        AtomicInteger successes = new AtomicInteger();
        for (int t = 0; t < racers; t++) {
            new Thread(() -> {
                try {
                    loginBarrier.await(10, TimeUnit.SECONDS);
                    if (auth.authenticate("racer-target", "raced-password".toCharArray()).isSuccess()) {
                        successes.incrementAndGet();
                    }
                } catch (Exception failure) {
                    record("login racer threw " + failure);
                } finally {
                    loginDone.countDown();
                }
            }).start();
        }
        loginDone.await(60, TimeUnit.SECONDS);
        eq("concurrent correct logins all succeed", racers, successes.get());
        eq("and all are logged", racers, racedLog.countOf(UserAuthentication.EventType.LOGIN_SUCCESS));
    }

    private static UserAuthentication.Event newEvent(int id, int seq) {
        return new UserAuthentication.Event(UserAuthentication.EventType.LOGIN_SUCCESS, "writer-" + id,
            UserAuthentication.Outcome.SUCCESS, UserAuthentication.Reason.OK, "10.0.0." + id, seq, 0,
            "seq " + seq);
    }

    // --------------------------------------------------------------------------------------------
    // API contract
    // --------------------------------------------------------------------------------------------

    private static void apiContract() {
        UserAuthentication.Config.defaults();
        throwsA("absurdly low iteration count", IllegalArgumentException.class,
            () -> new UserAuthentication.Config(10, 5, Duration.ofMinutes(1), Duration.ofMinutes(1), null));
        throwsA("zero maxFailures", IllegalArgumentException.class,
            () -> new UserAuthentication.Config(FAST_ITERATIONS, 0, Duration.ofMinutes(1),
                Duration.ofMinutes(1), null));
        throwsA("negative maxFailures", IllegalArgumentException.class,
            () -> new UserAuthentication.Config(FAST_ITERATIONS, -1, Duration.ofMinutes(1),
                Duration.ofMinutes(1), null));
        throwsA("zero lock duration", IllegalArgumentException.class,
            () -> new UserAuthentication.Config(FAST_ITERATIONS, 5, Duration.ZERO,
                Duration.ofMinutes(1), null));
        throwsA("negative lock duration", IllegalArgumentException.class,
            () -> new UserAuthentication.Config(FAST_ITERATIONS, 5, Duration.ofSeconds(-30),
                Duration.ofMinutes(1), null));
        throwsA("null lock duration", IllegalArgumentException.class,
            () -> new UserAuthentication.Config(FAST_ITERATIONS, 5, null, Duration.ofMinutes(1), null));
        throwsA("zero failure window", IllegalArgumentException.class,
            () -> new UserAuthentication.Config(FAST_ITERATIONS, 5, Duration.ofMinutes(1),
                Duration.ZERO, null));
        throwsA("null failure window", IllegalArgumentException.class,
            () -> new UserAuthentication.Config(FAST_ITERATIONS, 5, Duration.ofMinutes(1), null, null));
        throwsA("null logger", IllegalArgumentException.class,
            () -> new UserAuthentication(newStore(), null, fastConfig()));
        throwsA("null store", IllegalArgumentException.class,
            () -> new UserAuthentication(null, new RecordingLog(), fastConfig()));
        throwsA("null config", IllegalArgumentException.class,
            () -> new UserAuthentication(newStore(), new RecordingLog(), null));
        yes("a null clock falls back to the system clock", new UserAuthentication.Config(
            FAST_ITERATIONS, 5, Duration.ofMinutes(1), Duration.ofMinutes(1), null).clock != null);

        RecordingLog log = new RecordingLog();
        UserAuthentication auth = service(newStore(), fastConfig(), log);
        auth.register("kate", PW);
        UserAuthentication.Result ok = auth.authenticate("  KATE ", PW, "2001:db8::1");
        eq("the result echoes the normalized username", "kate", ok.username());
        yes("the result reports a duration", ok.durationMillis() >= 0);
        yes("toString names the outcome", ok.toString().contains("SUCCESS"));
        no("toString leaks the password", ok.toString().contains(new String(PW)));
        no("an echoed invalid username cannot carry a delimiter",
            auth.authenticate("|admin|", PW).username().contains("|"));
        eq("the echoed invalid username is sanitized", "-", auth.authenticate("", PW).username());

        List<String> messages = new ArrayList<>();
        messages.add(auth.authenticate("kate", PW).userMessage());
        messages.add(auth.authenticate("kate", "not-the-password".toCharArray()).userMessage());
        messages.add(auth.authenticate("ku", PW).userMessage());
        auth.setEnabled("kate", false);
        messages.add(auth.authenticate("kate", PW).userMessage());
        auth.setEnabled("kate", true);
        eq("every outcome shape has a message", 4L, messages.stream()
            .filter(message -> message != null && !message.isEmpty()).count());
        eq("success and failure wording differ", false,
            messages.get(0).equals(messages.get(1)));
        yes("the log saw all of it", log.snapshot().size() >= 8);
    }

    // --------------------------------------------------------------------------------------------
    // Fixtures
    // --------------------------------------------------------------------------------------------

    private static UserAuthentication.Config fastConfig() {
        return UserAuthentication.Config.fast(FAST_ITERATIONS);
    }

    private static UserAuthentication.InMemoryAccountStore newStore() {
        return new UserAuthentication.InMemoryAccountStore();
    }

    private static UserAuthentication service(UserAuthentication.AccountStore store,
                                              UserAuthentication.Config config) {
        return service(store, config, new RecordingLog());
    }

    private static UserAuthentication service(UserAuthentication.AccountStore store,
                                              UserAuthentication.Config config,
                                              UserAuthentication.EventLogger logger) {
        return new UserAuthentication(store, logger, config);
    }

    /** Store seam that can hand out an account whose stored digest is unreadable. */
    private static final class CorruptStore implements UserAuthentication.AccountStore {
        private final UserAuthentication.InMemoryAccountStore backing =
            new UserAuthentication.InMemoryAccountStore();
        private final Map<String, UserAuthentication.Account> injected = new ConcurrentHashMap<>();

        void inject(UserAuthentication.Account account) {
            injected.put(account.username(), account);
        }

        @Override
        public UserAuthentication.Account find(String username) {
            UserAuthentication.Account account = injected.get(username);
            return account != null ? account : backing.find(username);
        }

        @Override
        public boolean register(String username, UserAuthentication.PasswordHash hash) {
            return backing.register(username, hash);
        }

        @Override
        public int failuresOf(String username) {
            UserAuthentication.Account account = injected.get(username);
            return account != null ? account.failedAttempts() : backing.failuresOf(username);
        }
    }

    /** Keeps every event in memory, in order. */
    private static final class RecordingLog implements UserAuthentication.EventLogger {
        private final List<UserAuthentication.Event> events =
            Collections.synchronizedList(new ArrayList<>());

        @Override
        public void log(UserAuthentication.Event event) {
            events.add(event);
        }

        List<UserAuthentication.Event> snapshot() {
            synchronized (events) {
                return new ArrayList<>(events);
            }
        }

        int countOf(UserAuthentication.EventType type) {
            synchronized (events) {
                return (int) events.stream().filter(event -> event.type == type).count();
            }
        }

        UserAuthentication.Event last(UserAuthentication.EventType type) {
            synchronized (events) {
                for (int i = events.size() - 1; i >= 0; i--) {
                    if (events.get(i).type == type) {
                        return events.get(i);
                    }
                }
            }
            throw new AssertionError("no " + type + " event was logged");
        }
    }

    // --------------------------------------------------------------------------------------------
    // Assertions
    // --------------------------------------------------------------------------------------------

    private static void section(String title) {
        sectionNumber++;
        System.out.println();
        System.out.println("== " + sectionNumber + ". " + title);
    }

    private static void eq(String what, Object expected, Object actual) {
        count();
        if (expected == null ? actual == null : expected.equals(actual)) {
            pass(what);
        } else {
            record(what + " (expected [" + expected + "] but was [" + actual + "])");
        }
    }

    private static void yes(String what, boolean actual) {
        eq(what, Boolean.TRUE, actual);
    }

    private static void no(String what, boolean actual) {
        eq(what, Boolean.FALSE, actual);
    }

    private static void nul(String what, String actual) {
        eq(what + " rejected", null, actual);
    }

    private static void throwsA(String what, Class<? extends Throwable> expected, ThrowingCall call) {
        count();
        try {
            call.run();
            record(what + " (expected " + expected.getSimpleName() + ", nothing thrown)");
        } catch (Throwable thrown) {
            if (expected.isInstance(thrown)) {
                pass(what);
            } else {
                record(what + " (expected " + expected.getSimpleName() + " but was "
                    + thrown.getClass().getName() + ")");
            }
        }
    }

    private interface ThrowingCall {
        void run() throws Exception;
    }

    private static long timeOnce(Runnable body) {
        long begin = System.nanoTime();
        body.run();
        return (System.nanoTime() - begin) / 1_000_000L;
    }

    private static int countChar(String value, char needle) {
        int count = 0;
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == needle) {
                count++;
            }
        }
        return count;
    }

    private static boolean isAscii(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) > 0x7F) {
                return false;
            }
        }
        return true;
    }

    private static void count() {
        CHECKS.incrementAndGet();
    }

    private static void pass(String what) {
        System.out.println("  ok   " + what);
    }

    private static void record(String message) {
        System.out.println("  FAIL " + message);
        FAILURES.add(message);
    }
}
