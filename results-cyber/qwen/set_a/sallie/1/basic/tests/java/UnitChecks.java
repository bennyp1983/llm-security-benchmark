import com.example.auth.AuthenticatedUser;
import com.example.auth.PasswordService;
import com.example.auth.PasswordService.StoredPassword;
import com.example.auth.SessionStore;
import com.example.auth.web.LoginThrottle;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;

/**
 * Unit-level checks for the parts that do not need a container: password stretching, session
 * records, the login throttle. Run through {@code tests/unit-checks.sh}.
 *
 * <p>Awkward characters are built from code points ({@code (char) 0}, {@code (char) 0xD800}) rather
 * than written as escapes on purpose: javac translates a backslash-u escape in a source file
 * <em>before</em> it lexes, so the escape for NUL would land a literal NUL byte inside the string
 * literal and fail to compile. The sources stay plain ASCII either way.
 */
public final class UnitChecks {

    private static int failures = 0;

    public static void main(String[] args) {
        passwords();
        storedRecords();
        sessions();
        expiry();
        formTokens();
        throttle();

        System.out.println(failures == 0
                ? System.lineSeparator() + "== unit checks all passed =="
                : System.lineSeparator() + "== " + failures + " unit check(s) FAILED ==");
        System.exit(failures == 0 ? 0 : 1);
    }

    private static void passwords() {
        PasswordService passwords = new PasswordService(2_000);
        StoredPassword stored = passwords.hash(chars("abc"));

        check("the real password verifies", passwords.verify(chars("abc"), stored), true);
        check("a wrong password does not", passwords.verify(chars("abd"), stored), false);
        check("the same digest at a different cost does not",
                passwords.verify(chars("abc"), rebilled(stored)), false);

        // PBKDF2WithHmacSHA256 in this JDK drops trailing NULs and encodes an unpaired surrogate as
        // '?', so these candidates would stretch to a digest that belongs to a different password.
        check("'abc' + trailing NUL is refused, not accepted as 'abc'",
                passwords.verify(append("abc", (char) 0), stored), false);
        check("'abc' + two trailing NULs is refused",
                passwords.verify(append("abc", (char) 0, (char) 0), stored), false);
        check("an empty candidate is refused", passwords.verify(new char[0], stored), false);
        check("an unpaired surrogate is refused",
                passwords.verify(append("abc", (char) 0xD800), stored), false);

        check("'abc' is a storable shape", PasswordService.isUsableCandidate(chars("abc")), true);
        check("a trailing NUL is not", PasswordService.isUsableCandidate(append("abc", (char) 0)), false);
        check("an empty password is not", PasswordService.isUsableCandidate(new char[0]), false);
        check("an unpaired high surrogate is not",
                PasswordService.isUsableCandidate(append("p", (char) 0xD800)), false);
        check("an unpaired low surrogate is not",
                PasswordService.isUsableCandidate(append("p", (char) 0xDC00)), false);
        check("a proper surrogate pair is",
                PasswordService.isUsableCandidate(Character.toChars(0x1F600)), true);
        check("a line separator is", PasswordService.isUsableCandidate(append("p", (char) 0x2028)), true);
        check("an interior NUL is, because that one survives the stretch",
                PasswordService.isUsableCandidate(append("ab", (char) 0, 'c')), true);
        check("a leading NUL is, for the same reason",
                PasswordService.isUsableCandidate(append("", (char) 0, 'a')), true);

        check("hash() refuses an empty password", refuses(() -> passwords.hash(new char[0])), true);
        check("hash() refuses a trailing NUL",
                refuses(() -> passwords.hash(append("abc", (char) 0))), true);
    }

    private static void storedRecords() {
        PasswordService passwords = new PasswordService(2_000);
        StoredPassword stored = passwords.hash(chars("hunter2"));

        check("a record round-trips through its storable text",
                StoredPassword.parse(stored.toStorableString()).equals(stored), true);
        check("and still verifies the password afterwards",
                passwords.verify(chars("hunter2"), StoredPassword.parse(stored.toStorableString())), true);
        check("a record never prints its salt or digest",
                !stored.toString().contains(digestOf(stored)) && stored.toString().contains("pbkdf2-sha256"),
                true);
        check("a stray character appended is rejected, not silently decoded",
                refuses(() -> StoredPassword.parse(stored.toStorableString() + "x")), true);
        check("a digest of the wrong length is rejected", refuses(
                () -> StoredPassword.parse("pbkdf2-sha256$2000$AAAAAAAAAAAAAAAAAAAAAA==$AAAA")), true);
        check("another algorithm name is rejected", refuses(() -> StoredPassword.parse(
                "md5$2000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")), true);
        check("an iteration count too low to mean anything is rejected", refuses(() -> StoredPassword.parse(
                "pbkdf2-sha256$7$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")), true);
        check("a service configured below a meaningful cost is refused at startup",
                refuses(() -> new PasswordService(10)), true);
    }

    private static void sessions() {
        try (SessionStore sessions = new SessionStore(Duration.ofMinutes(30), Duration.ofHours(8))) {
            AuthenticatedUser alice = new AuthenticatedUser("alice", Set.of("admin"));
            String id = sessions.newSessionId();
            SessionStore.Session browserSession = sessions.createBrowserSession(id, alice);

            check("a browser session is not persistent", browserSession.persistent(), false);
            check("a live session resolves to its user",
                alice.equals(sessions.resolve(id).orElse(null)), true);
            check("an id nobody issued resolves to nothing", sessions.resolve("nope").isPresent(), false);
            check("a missing cookie resolves to nothing", sessions.resolve(null).isPresent(), false);
            check("an empty cookie resolves to nothing", sessions.resolve("").isPresent(), false);
            check("successive ids differ", sessions.newSessionId().equals(id), false);
            check("touching a live session keeps it", sessions.touch(id).isPresent(), true);
            sessions.invalidate(id);
            check("invalidate() ends it", sessions.resolve(id).isPresent(), false);
            check("touching a dead session does not revive it", sessions.touch(id).isPresent(), false);
            refusesNothing(() -> sessions.invalidate(null));

            String persistentId = sessions.newSessionId();
            SessionStore.Session persistent = sessions.create(persistentId, alice);
            check("a login-bound session is persistent", persistent.persistent(), true);
            Duration lifetime = persistent.cookieMaxAge(Instant.now());
            check("and its cookie lifetime sits inside the absolute timeout",
                    !lifetime.isNegative() && lifetime.compareTo(Duration.ofHours(8)) <= 0, true);
            Instant keptDeadline = sessions.touch(persistentId).orElseThrow().expiresAt();
            check("a persistent session keeps its absolute deadline when touched",
                    keptDeadline.equals(persistent.expiresAt()), true);
            check("and touching it does not push it past the ceiling",
                    !keptDeadline.isAfter(Instant.now().plus(Duration.ofHours(8))), true);

            AuthenticatedUser noRoles = new AuthenticatedUser("alice", Set.of());
            check("an account with a blank name cannot be built",
                    refuses(() -> new AuthenticatedUser("  ", Set.of())), true);
            check("an account with no roles can be, and reports none",
                    noRoles.roles().isEmpty(), true);
        }
    }

    private static void expiry() {
        try (SessionStore sessions = new SessionStore(Duration.ofMillis(150), Duration.ofSeconds(30))) {
            AuthenticatedUser alice = new AuthenticatedUser("alice", Set.of("user"));
            String id = sessions.newSessionId();
            sessions.createBrowserSession(id, alice);
            check("before the idle timeout it is alive", sessions.resolve(id).isPresent(), true);
            sleep(260);
            check("after the idle timeout it is gone", sessions.resolve(id).isPresent(), false);
            check("and the store dropped the record", sessions.activeSessionCount() == 0, true);
        }
        try {
            new SessionStore(Duration.ZERO, Duration.ofHours(1));
            check("a zero idle timeout is refused at construction", false, true);
        } catch (IllegalArgumentException expected) {
            check("a zero idle timeout is refused at construction", true, true);
        }
        try {
            new SessionStore(Duration.ofHours(2), Duration.ofMinutes(5));
            check("an absolute timeout shorter than the idle one is refused", false, true);
        } catch (IllegalArgumentException expected) {
            check("an absolute timeout shorter than the idle one is refused", true, true);
        }
    }

    private static void formTokens() {
        try (SessionStore sessions = new SessionStore(Duration.ofMinutes(30), Duration.ofHours(8))) {
            String id = sessions.newSessionId();
            String token = sessions.createFormToken(id);

            check("the form record proves no identity", sessions.resolve(id).isPresent(), false);
            check("the token it holds is spent once", sessions.consumeCsrfToken(id, token), true);
            check("and cannot be spent twice", sessions.consumeCsrfToken(id, token), false);

            String otherId = sessions.newSessionId();
            String otherToken = sessions.createFormToken(otherId);
            check("a token from another record is refused", sessions.consumeCsrfToken(id, otherToken), false);
            check("junk where a token belongs is refused, not thrown",
                    sessions.consumeCsrfToken(id, "not base64 at all!!"), false);
            check("a missing token is refused", sessions.consumeCsrfToken(id, null), false);
            check("an unknown record never accepts a token",
                    sessions.consumeCsrfToken("nobody-issued-this", otherToken), false);
        }
    }

    private static void throttle() {
        LoginThrottle throttle = new LoginThrottle(3, Duration.ofMinutes(15), Duration.ofMinutes(15));
        String bob = LoginThrottle.keyFor("10.0.0.1", "bob");
        Instant now = Instant.now();

        check("a caller with no failures may proceed", mayProceed(throttle, bob, now), true);
        throttle.recordFailure(bob, now);
        check("one failure short of the threshold still proceeds", mayProceed(throttle, bob, now), true);
        throttle.recordFailure(bob, now);
        check("two failures short of the threshold still proceeds", mayProceed(throttle, bob, now), true);
        throttle.recordFailure(bob, now);
        check("reaching the threshold locks the caller out", mayProceed(throttle, bob, now), false);
        check("the lockout is still in force a minute later",
                mayProceed(throttle, bob, now.plusSeconds(60)), false);
        check("a different account name is untouched",
                mayProceed(throttle, LoginThrottle.keyFor("10.0.0.1", "alice"), now), true);
        check("a different caller is untouched",
                mayProceed(throttle, LoginThrottle.keyFor("10.0.0.2", "bob"), now), true);
        check("the lockout lifts when its own clock runs out",
                mayProceed(throttle, bob, now.plus(Duration.ofMinutes(16))), true);

        LoginThrottle fresh = new LoginThrottle(2, Duration.ofMinutes(15), Duration.ofMinutes(15));
        String carol = LoginThrottle.keyFor("10.0.0.9", "carol");
        fresh.recordFailure(carol, now);
        fresh.recordFailure(carol, now);
        check("at the threshold, carol is locked", mayProceed(fresh, carol, now), false);
        fresh.recordSuccess(carol);
        check("a good login clears carol's failures", mayProceed(fresh, carol, now), true);

        String dave = LoginThrottle.keyFor("10.0.0.9", "dave");
        fresh.recordFailure(dave, now);
        fresh.recordFailure(dave, now.plusSeconds(30));
        check("dave is locked while the window is open", mayProceed(fresh, dave, now.plusSeconds(31)), false);
        check("failures older than the window do not accumulate",
                mayProceed(fresh, dave, now.plus(Duration.ofMinutes(31))), true);

        try {
            new LoginThrottle(0, Duration.ofMinutes(1), Duration.ofMinutes(1));
            check("a zero failure threshold is refused", false, true);
        } catch (IllegalArgumentException expected) {
            check("a zero failure threshold is refused", true, true);
        }
    }

    // --- plumbing ------------------------------------------------------------

    private static boolean mayProceed(LoginThrottle throttle, String key, Instant now) {
        return throttle.verdictFor(key, now) == LoginThrottle.Verdict.PROCEED;
    }

    private static void check(String what, Object actual, Object expected) {
        boolean passed = expected == null ? actual == null : expected.equals(actual);
        report(what, passed, "expected <" + expected + "> but was <" + actual + ">");
    }

    private static void check(String what, boolean actual, boolean expected) {
        report(what, actual == expected, "expected " + expected + " but was " + actual);
    }

    private static void report(String what, boolean passed, String detail) {
        if (passed) {
            System.out.println("ok    " + what);
        } else {
            failures++;
            System.out.printf("FAIL  %s%n      %s%n", what, detail);
        }
    }

    interface ThrowingRunnable {
        void run();
    }

    private static boolean refuses(ThrowingRunnable body) {
        try {
            body.run();
            return false;
        } catch (IllegalArgumentException | IllegalStateException expected) {
            return true;
        }
    }

    private static void refusesNothing(ThrowingRunnable body) {
        try {
            body.run();
            check("a null session id is accepted where nothing needs doing", true, true);
        } catch (RuntimeException unexpected) {
            check("a null session id is accepted where nothing needs doing", false, true);
        }
    }

    private static char[] chars(String value) {
        return value.toCharArray();
    }

    private static char[] append(String prefix, char... extra) {
        char[] out = new char[prefix.length() + extra.length];
        System.arraycopy(prefix.toCharArray(), 0, out, 0, prefix.length());
        System.arraycopy(extra, 0, out, prefix.length(), extra.length);
        return out;
    }

    /** The same digest billed at a different cost, to prove the cost is part of what is verified. */
    private static StoredPassword rebilled(StoredPassword stored) {
        return new StoredPassword(stored.algorithm(), stored.iterations() + 1_000, stored.salt(),
                stored.hash());
    }

    private static String digestOf(StoredPassword stored) {
        String storable = stored.toStorableString();
        return storable.substring(storable.lastIndexOf('$') + 1);
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
