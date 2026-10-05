/*
 * AuthServiceTest.java -- checks for AuthService, with no test framework required.
 *
 *   javac -d out AuthService.java AuthServiceTest.java
 *   java  -cp out AuthServiceTest
 *
 * Beyond the functional expectations, the suite deliberately concentrates on the parts that a
 * hand-written auth module usually gets wrong and that a "does it compile" review never sees:
 *
 *   - what one attempt WRITES: one record, correct level, every investigative field present, the
 *     attempt id shared with the subject-facing result;
 *   - what one attempt must NOT write: the password, in any form;
 *   - that free-text input (username, user-agent) cannot forge a second log line, cannot smuggle a
 *     control character, and is recoverable byte-for-byte from the escaping;
 *   - that every refusal shape -- wrong password, unknown account, unusable candidate, malformed
 *     username, locked account -- pays the same measurable cost, which is what stops the log's
 *     elapsedMs column from becoming a user-enumeration oracle;
 *   - that a stored credential which cannot be parsed is reported as a data fault rather than
 *     silently converted into "wrong password".
 *
 * The timing assertions use a deliberately small iteration count and a wide ratio window: they are
 * asserting "this branch did a key derivation" and "this branch did not skip it", not microsecond
 * parity. Median-of-N is used because a shared machine produces scheduling spikes.
 */

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

public final class AuthServiceTest {

    private static final String GOOD_PASSWORD = "correct-horse-battery";
    private static final int FAST_ITERATIONS = 20_000;
    private static final int TIMED_ITERATIONS = 60_000;

    private static final List<String> failures = new ArrayList<>();
    private static int checks;
    private static int captureSeq;

    public static void main(String[] args) {
        run("hashFormatAndSalting", AuthServiceTest::hashFormatAndSalting);
        run("storedDigestParsingIsStrict", AuthServiceTest::storedDigestParsingIsStrict);
        run("dummyDigestParsesAndMatchesNothing", AuthServiceTest::dummyDigestParsesAndMatchesNothing);
        run("unusableCandidatesAreRejected", AuthServiceTest::unusableCandidatesAreRejected);
        run("pairedSurrogatesAreAccepted", AuthServiceTest::pairedSurrogatesAreAccepted);
        run("enrolmentPolicy", AuthServiceTest::enrolmentPolicy);
        run("usernameNormalisation", AuthServiceTest::usernameNormalisation);
        run("successRecordCarriesInvestigativeContext", AuthServiceTest::successRecordCarriesInvestigativeContext);
        run("wrongPasswordRecord", AuthServiceTest::wrongPasswordRecord);
        run("unknownAccountRecord", AuthServiceTest::unknownAccountRecord);
        run("oneRecordPerAttempt", AuthServiceTest::oneRecordPerAttempt);
        run("publicMessageIsIdenticalForEveryRefusal", AuthServiceTest::publicMessageIsIdenticalForEveryRefusal);
        run("internalReasonsAreDistinct", AuthServiceTest::internalReasonsAreDistinct);
        run("failureCounterProgression", AuthServiceTest::failureCounterProgression);
        run("thresholdCrossingIsOneWarningRecord", AuthServiceTest::thresholdCrossingIsOneWarningRecord);
        run("correctPasswordDuringLockoutIsRefused", AuthServiceTest::correctPasswordDuringLockoutIsRefused);
        run("lockoutExpires", AuthServiceTest::lockoutExpires);
        run("previousSuccessContext", AuthServiceTest::previousSuccessContext);
        run("adminUnlockIsAuditedAndRestoresAccess", AuthServiceTest::adminUnlockIsAuditedAndRestoresAccess);
        run("disabledAccount", AuthServiceTest::disabledAccount);
        run("corruptCredentialIsDataFault", AuthServiceTest::corruptCredentialIsDataFault);
        run("logInjectionCannotForgeASecondLine", AuthServiceTest::logInjectionCannotForgeASecondLine);
        run("nonAsciiInputIsAsciiEncodedAndReversible", AuthServiceTest::nonAsciiInputIsAsciiEncodedAndReversible);
        run("userAgentIsEscaped", AuthServiceTest::userAgentIsEscaped);
        run("oversizedInputIsTruncatedAndMarked", AuthServiceTest::oversizedInputIsTruncatedAndMarked);
        run("noSecretInAnyEmittedString", AuthServiceTest::noSecretInAnyEmittedString);
        run("callerOwnedBuffersAreNotClobbered", AuthServiceTest::callerOwnedBuffersAreNotClobbered);
        run("failureTrackerUnitBehaviour", AuthServiceTest::failureTrackerUnitBehaviour);
        run("concurrentAttemptsAreCountedAndLogged", AuthServiceTest::concurrentAttemptsAreCountedAndLogged);
        run("everyRefusalShapeCostsTheSameWork", AuthServiceTest::everyRefusalShapeCostsTheSameWork);

        System.out.println();
        if (failures.isEmpty()) {
            System.out.println("RESULT: all " + checks + " checks passed");
            return;
        }
        System.out.println("RESULT: " + failures.size() + " of " + checks + " checks FAILED");
        for (String failure : failures) {
            System.out.println("  - " + failure);
        }
        System.exit(1);
    }

    // ============================================================================================
    // Password storage
    // ============================================================================================

    private static void hashFormatAndSalting() {
        AuthService.PasswordHasher hasher = new AuthService.PasswordHasher(FAST_ITERATIONS);
        String first = hasher.encode(GOOD_PASSWORD.toCharArray());
        String second = hasher.encode(GOOD_PASSWORD.toCharArray());

        check("encoding is prefixed", first.startsWith("pbkdf2-sha256$20000$"));
        check("encoding has four fields", first.split("\\$", -1).length == 4);
        check("encoding does not contain the password", !first.contains(GOOD_PASSWORD));
        check("same password yields different encodings (per-record salt)", !first.equals(second));
        check("verification accepts the right password",
                hasher.verify(GOOD_PASSWORD.toCharArray(), first).matched());
        check("verification rejects a wrong password",
                !hasher.verify("wrong-password-here".toCharArray(), first).matched());
        check("the second encoding of the same password still verifies",
                hasher.verify(GOOD_PASSWORD.toCharArray(), second).matched());

        AuthService.StoredDigest parsed = AuthService.StoredDigest.parse(first);
        check("salt is 16 bytes", parsed != null && parsed.salt.length == 16);
        check("digest is 32 bytes", parsed != null && parsed.digest.length == 32);
        check("stored iterations are read back", parsed != null && parsed.iterations == FAST_ITERATIONS);

        AuthService.PasswordHasher slow = new AuthService.PasswordHasher(FAST_ITERATIONS * 2);
        check("a record keeps verifying under a service with a new cost setting",
                slow.verify(GOOD_PASSWORD.toCharArray(), first).matched());
    }

    private static void storedDigestParsingIsStrict() {
        check("null is rejected", parseError(null) != null);
        check("empty is rejected", parseError("") != null);
        check("wrong field count is rejected", parseError("pbkdf2-sha256$20000$AAAA") != null);
        check("unknown kdf is rejected", parseError("sha1$20000$AAAA$AAAA").equals("unknown-kdf"));
        check("non-numeric iterations is rejected",
                parseError("pbkdf2-sha256$many$AAAA$AAAA").equals("non-numeric-iterations"));
        check("iterations below the floor are rejected",
                parseError("pbkdf2-sha256$10$AAAAAAAA$AAAAAAAA").equals("iterations-out-of-range"));
        check("non-base64 material is rejected",
                parseError("pbkdf2-sha256$20000$!!!!$AAAA").equals("non-base64-material"));
        check("short digest is rejected",
                parseError("pbkdf2-sha256$20000$" + b64of(16) + "$" + b64of(31))
                        .startsWith("digest-length-"));
        check("digest of the wrong but plausible length is still rejected",
                parseError("pbkdf2-sha256$20000$" + b64of(16) + "$" + b64of(64))
                        .startsWith("digest-length-"));
        check("well-formed record parses", parseError("pbkdf2-sha256$20000$" + b64of(16) + "$" + b64of(32)) == null);
    }

    private static void dummyDigestParsesAndMatchesNothing() {
        AuthService.PasswordHasher hasher = new AuthService.PasswordHasher(FAST_ITERATIONS);
        String dummy = hasher.dummyEncoded();

        check("the digest charged for unknown accounts parses",
                AuthService.StoredDigest.parse(dummy) != null);
        check("the charged digest is a real 32-byte digest",
                AuthService.StoredDigest.parse(dummy).digest.length == 32);
        check("the charged digest belongs to no plausible login",
                !hasher.verify(GOOD_PASSWORD.toCharArray(), dummy).matched()
                        && !hasher.verify("".toCharArray(), dummy).matched());
        check("the charged digest differs from a registered credential",
                !dummy.equals(hasher.encode(GOOD_PASSWORD.toCharArray())));
    }

    private static void unusableCandidatesAreRejected() {
        AuthService.PasswordHasher hasher = new AuthService.PasswordHasher(FAST_ITERATIONS);
        String stored = hasher.encode(GOOD_PASSWORD.toCharArray());

        check("a trailing NUL cannot authenticate",
                !hasher.verify((GOOD_PASSWORD + (char) 0).toCharArray(), stored).matched());
        check("a trailing NUL is reported as its own reason",
                AuthService.PasswordRules.rejectCandidate((GOOD_PASSWORD + (char) 0).toCharArray())
                        .get().equals("password-ends-in-nul"));
        check("an unpaired high surrogate cannot authenticate",
                !hasher.verify((GOOD_PASSWORD + (char) 0xD800).toCharArray(), stored).matched());
        check("an unpaired low surrogate cannot authenticate",
                !hasher.verify((((char) 0xDC00) + GOOD_PASSWORD).toCharArray(), stored).matched());
        check("an empty candidate is reported as such",
                AuthService.PasswordRules.rejectCandidate(new char[0]).get().equals("no-password-submitted"));
        check("an interior NUL is still a usable candidate",
                AuthService.PasswordRules.rejectCandidate("corr3ct\0horse-battery".toCharArray()).isEmpty());
        check("verification still costs one derivation for an unusable candidate",
                hasher.verify((GOOD_PASSWORD + (char) 0).toCharArray(), stored).iterationsUsed()
                        == FAST_ITERATIONS);
    }

    private static void pairedSurrogatesAreAccepted() {
        char[] astral = ("correct-horse-" + new String(new int[] { 0x1F600 }, 0, 1)).toCharArray();
        AuthService.PasswordHasher hasher = new AuthService.PasswordHasher(FAST_ITERATIONS);
        String stored = hasher.encode(astral.clone());

        check("an astral character is a legitimate password",
                AuthService.PasswordRules.rejectCandidate(astral).isEmpty());
        check("an astral password verifies", hasher.verify(astral.clone(), stored).matched());
        check("a different astral password does not verify",
                !hasher.verify(("correct-horse-" + new String(new int[] { 0x1F601 }, 0, 1))
                        .toCharArray(), stored).matched());
    }

    private static void enrolmentPolicy() {
        Harness h = new Harness(FAST_ITERATIONS, 1000, Duration.ofMinutes(15));
        check("a short password is refused at enrolment",
                throwsIllegalArgument(() -> h.service.register("dave", "short1".toCharArray())));
        check("a trailing-NUL password is refused at enrolment",
                throwsIllegalArgument(() -> h.service.register("dave", ("long-enough-pw" + (char) 0).toCharArray())));
        check("an unpaired surrogate password is refused at enrolment",
                throwsIllegalArgument(() -> h.service.register("dave", ("long-enough-pw" + (char) 0xD800).toCharArray())));
        check("a malformed username is refused at enrolment",
                throwsIllegalArgument(() -> h.service.register("dave!", GOOD_PASSWORD.toCharArray())));
        check("a duplicate username is refused",
                throwsIllegalArgument(() -> h.service.register("alice", GOOD_PASSWORD.toCharArray())));
        check("the minimum enrolment length is accepted",
                h.service.register("frank", "abcdefghijkl".toCharArray()) != null);

        // A legacy account may hold a password that today's floor would refuse; logging in must not
        // become a way to discover which accounts are old.
        h.store.store(newRecord("acct-legacy", "legacy", legacyHash(h)));
        AuthService.LoginResult legacyLogin = h.login("legacy", "old-pw");
        check("a below-floor password still authenticates on an existing account", legacyLogin.authenticated());
        AuthService.LoginResult legacyWrong = h.login("legacy", "old-pwX");
        check("and is still refused on a typo, with the ordinary reason",
                !legacyWrong.authenticated() && "password-mismatch".equals(legacyWrong.internalReason()));
    }

    private static void usernameNormalisation() {
        Harness h = new Harness(FAST_ITERATIONS, 1000, Duration.ofMinutes(15));
        String fullWidthAlice = new String(new int[] { 0xFF41, 0xFF4C, 0xFF49, 0xFF43, 0xFF45 }, 0, 5);

        check("surrounding whitespace is trimmed", h.login("  alice  ", GOOD_PASSWORD).authenticated());
        check("case is folded", h.login("ALICE", GOOD_PASSWORD).authenticated());
        check("compatibility variants resolve to the same account",
                h.login(fullWidthAlice, GOOD_PASSWORD).authenticated());
        check("a case-folded variant resolves to the same account",
                h.login("AlIcE", GOOD_PASSWORD).authenticated());
        check("a look-alike separator is refused, not silently mapped",
                refusedWith(h.login("alice" + (char) 0xA0, GOOD_PASSWORD), "username-unsupported-characters"));
        check("an address-style local part is accepted",
                h.service.register("alice.smith+test@example".replace("@example", ""), GOOD_PASSWORD.toCharArray()) != null);
        check("a different spelling is a different account",
                refusedWith(h.login("a1ice", GOOD_PASSWORD), "unknown-account"));
        check("a null username is refused", refusedWith(h.login(null, GOOD_PASSWORD), "username-absent"));
        check("an empty username is refused", refusedWith(h.login("   ", GOOD_PASSWORD), "username-empty"));
        check("an unpaired surrogate username is refused",
                refusedWith(h.login("alice" + (char) 0xD800, GOOD_PASSWORD), "username-malformed-unicode"));
    }

    // ============================================================================================
    // What the log says
    // ============================================================================================

    private static void successRecordCarriesInvestigativeContext() {
        Harness h = new Harness(FAST_ITERATIONS, 1000, Duration.ofMinutes(15));
        h.capture.clear();
        AuthService.LoginResult result = h.service.login(new AuthService.LoginRequest(
                "alice", GOOD_PASSWORD.toCharArray(), "203.0.113.10", "sess-42", "JUnitAgent/1.0"));

        check("the login succeeds", result.authenticated());
        check("the result carries an account id", result.accountId() != null);
        check("exactly one record was written", h.capture.lines().size() == 1);

        String line = h.capture.lines().get(0);
        Map<String, String> f = h.capture.fields(0);
        check("level is INFO", "INFO".equals(h.capture.level(0)));
        check("event is AUTH_SUCCESS", "AUTH_SUCCESS".equals(f.get("event")));
        check("outcome is SUCCESS", "SUCCESS".equals(f.get("outcome")));
        check("reason is authenticated", "authenticated".equals(f.get("reason")));
        check("the normalised subject is recorded", "alice".equals(f.get("subject")));
        check("the subject state is recorded", "resolved".equals(f.get("subjectState")));
        check("the account id is recorded", result.accountId().equals(f.get("account")));
        check("the account state is recorded", "active".equals(f.get("accountState")));
        check("the source address is recorded", "203.0.113.10".equals(f.get("ip")));
        check("the session is recorded", "sess-42".equals(f.get("session")));
        check("the user agent is recorded", "JUnitAgent/1.0".equals(f.get("agent")));
        check("the failure counter is recorded", "0".equals(f.get("failures")));
        check("an absent lockout is written as a dash", "-".equals(f.get("lockedUntil")));
        check("the kdf policy is recorded",
                ("pbkdf2-sha256$" + FAST_ITERATIONS).equals(f.get("policy")));
        check("the attempt id ties the record to the subject-facing result",
                result.attemptId().equals(f.get("attempt")));
        check("elapsed time is recorded", f.get("elapsedMs") != null && Long.parseLong(f.get("elapsedMs")) >= 0);
        check("the timestamp is an ISO instant", h.capture.timestamp(0).matches("\\d{4}-\\d{2}-\\d{2}T.*Z"));
        check("the record is a single physical line",
                !h.capture.wireLine(0).contains("\n") && !h.capture.wireLine(0).contains("\r"));
        check("the record is pure ASCII", isAscii(h.capture.wireLine(0)));
        check("the password appears nowhere in the record", !line.contains(GOOD_PASSWORD));
    }

    private static void wrongPasswordRecord() {
        Harness h = new Harness(FAST_ITERATIONS, 1000, Duration.ofMinutes(15));
        h.capture.clear();
        AuthService.LoginResult result = h.login("alice", "wrong-password-here");

        check("refused", !result.authenticated());
        check("no account id is handed out", result.accountId() == null);
        check("the generic sentence is used",
                AuthService.GENERIC_FAILURE_MESSAGE.equals(result.message()));

        Map<String, String> f = singleFieldView(h);
        check("event is AUTH_FAILURE", "AUTH_FAILURE".equals(f.get("event")));
        check("outcome is FAILURE", "FAILURE".equals(f.get("outcome")));
        check("reason is password-mismatch", "password-mismatch".equals(f.get("reason")));
        check("the named subject is still recorded", "alice".equals(f.get("subject")));
        check("the account is identified even on failure", f.get("account").startsWith("acct-"));
        check("the counter is recorded", "1".equals(f.get("failures")));
        check("the attempt id is the one the subject was given", result.attemptId().equals(f.get("attempt")));
        check("level stays INFO for an ordinary refusal", "INFO".equals(h.capture.level(0)));
    }

    private static void unknownAccountRecord() {
        Harness h = new Harness(FAST_ITERATIONS, 1000, Duration.ofMinutes(15));
        h.capture.clear();
        AuthService.LoginResult result = h.login("nobody", GOOD_PASSWORD);

        check("refused", !result.authenticated());
        Map<String, String> f = singleFieldView(h);
        check("reason is unknown-account", "unknown-account".equals(f.get("reason")));
        check("the attempted name is preserved for the investigator", "nobody".equals(f.get("subject")));
        check("no account id is invented", "-".equals(f.get("account")));
        check("the absence is stated explicitly", "no-such-account".equals(f.get("accountState")));
        check("the counter is not invented for a non-existent account", "-".equals(f.get("failures")));
        check("the kdf policy is still recorded", f.get("policy").startsWith("pbkdf2-sha256$"));
        check("work was still charged, and the log shows it", Long.parseLong(f.get("elapsedMs")) >= 5);
    }

    private static void oneRecordPerAttempt() {
        Harness h = new Harness(FAST_ITERATIONS, 1000, Duration.ofMinutes(15));
        h.capture.clear();
        int attempts = 0;
        attempts += h.login("alice", GOOD_PASSWORD).authenticated() ? 1 : 0;
        attempts += h.login("alice", "nope-nope-nope").authenticated() ? 0 : 1;
        attempts += h.login("nobody", GOOD_PASSWORD).authenticated() ? 0 : 1;
        attempts += h.login("ALICE", (char) 0 + "").authenticated() ? 0 : 1;
        attempts += h.login("bad\u0001name", GOOD_PASSWORD).authenticated() ? 0 : 1;

        check("all five attempts were refused except the first", attempts == 5);
        check("five attempts produced exactly five records", h.capture.lines().size() == 5);
        check("every record names an event", h.capture.lines().stream().allMatch(l -> l.contains(" event=")));
        check("no two records share an attempt id",
                new LinkedHashSet<>(h.capture.values("attempt")).size() == 5);
    }

    private static void publicMessageIsIdenticalForEveryRefusal() {
        Harness h = new Harness(FAST_ITERATIONS, 1_000_000, Duration.ofMinutes(15));
        h.service.register("carol", "quiet-lantern-77".toCharArray());
        h.service.setStatus("carol", AuthService.AccountStatus.DISABLED, "admin@example");
        AuthService lockedService = lockOneStrikeAccount(h, "dan", "dan-locking-pw-1");

        Map<String, String> reasonsToMessages = new TreeMap<>();
        reasonsToMessages.put("wrong-password", h.login("alice", "wrong-password-here").message());
        reasonsToMessages.put("unknown-account", h.login("nobody", GOOD_PASSWORD).message());
        reasonsToMessages.put("disabled", h.login("carol", "quiet-lantern-77").message());
        reasonsToMessages.put("locked", lockedService.login(new AuthService.LoginRequest("dan",
                "dan-locking-pw-1".toCharArray(), "198.51.100.1", "s", "agent")).message());
        reasonsToMessages.put("malformed-username", h.login("bad name!", GOOD_PASSWORD).message());
        reasonsToMessages.put("nul-candidate", h.login("alice", GOOD_PASSWORD + (char) 0).message());
        reasonsToMessages.put("empty-candidate", h.login("alice", "").message());

        Set<String> distinct = new LinkedHashSet<>(reasonsToMessages.values());
        check("every refusal shape returns one and the same sentence", distinct.size() == 1);
        check("that sentence is the generic one",
                AuthService.GENERIC_FAILURE_MESSAGE.equals(distinct.iterator().next()));

        String lower = distinct.iterator().next().toLowerCase(java.util.Locale.ROOT);
        for (String leak : new String[] { "lock", "disabled", "unknown", "exist", "not found",
                "invalid", "nul", "surrogate", "empty", "expire" }) {
            check("the sentence does not hint at '" + leak + "'", !lower.contains(leak));
        }
    }

    private static void internalReasonsAreDistinct() {
        Harness h = new Harness(FAST_ITERATIONS, 1_000_000, Duration.ofMinutes(15));
        h.service.register("carol", "quiet-lantern-77".toCharArray());
        h.service.setStatus("carol", AuthService.AccountStatus.DISABLED, "admin@example");
        AuthService lockedService = lockOneStrikeAccount(h, "dan", "dan-locking-pw-1");

        Set<String> reasons = new LinkedHashSet<>();
        reasons.add(h.login("alice", "wrong-password-here").internalReason());
        reasons.add(h.login("nobody", GOOD_PASSWORD).internalReason());
        reasons.add(h.login("carol", "quiet-lantern-77").internalReason());
        reasons.add(lockedService.login(new AuthService.LoginRequest("dan",
                "dan-locking-pw-1".toCharArray(), "198.51.100.1", "s", "agent")).internalReason());
        reasons.add(h.login("bad name!", GOOD_PASSWORD).internalReason());
        reasons.add(h.login("alice", GOOD_PASSWORD + (char) 0).internalReason());
        reasons.add(h.login("alice", "").internalReason());

        check("the seven refusal shapes are distinguishable internally", reasons.size() == 7);
        check("the reasons are: " + reasons,
                reasons.containsAll(Arrays.asList("password-mismatch", "unknown-account",
                        "account-disabled", "account-locked", "password-ends-in-nul",
                        "no-password-submitted")));
        check("a malformed username reason names its cause",
                reasons.stream().anyMatch(r -> r.startsWith("username-unsupported-characters")));
    }

    private static void failureCounterProgression() {
        Harness h = new Harness(FAST_ITERATIONS, 1_000_000, Duration.ofMinutes(15));
        h.capture.clear();
        h.login("alice", "bad-one");
        h.login("alice", "bad-two");
        check("the counter increments on the second failure",
                "2".equals(h.capture.fields(1).get("failures")));

        h.capture.clear();
        AuthService.LoginResult ok = h.login("alice", GOOD_PASSWORD);
        check("a success resets the counter", ok.authenticated()
                && "0".equals(h.capture.fields(0).get("failures")));

        h.login("alice", "bad-three");
        check("the next failure restarts at one",
                "1".equals(h.capture.fields(h.capture.size() - 1).get("failures")));
    }

    private static void thresholdCrossingIsOneWarningRecord() {
        Harness h = new Harness(FAST_ITERATIONS, 3, Duration.ofMinutes(15));
        h.capture.clear();
        h.login("alice", "bad-one");
        h.login("alice", "bad-two");
        check("the first two failures are INFO refusals",
                "INFO".equals(h.capture.level(0)) && "INFO".equals(h.capture.level(1)));
        check("and are plain password mismatches",
                "password-mismatch".equals(h.capture.fields(0).get("reason")));

        AuthService.LoginResult third = h.login("alice", "bad-three");
        check("the crossing attempt is refused", !third.authenticated());
        check("the crossing attempt writes exactly one record", h.capture.lines().size() == 3);
        check("that single record is the warning", "WARNING".equals(h.capture.level(2)));
        check("it names the locking reason",
                "password-mismatch-locking".equals(h.capture.fields(2).get("reason")));
        check("it is still an AUTH_FAILURE event, so attempts and records stay 1:1",
                "AUTH_FAILURE".equals(h.capture.fields(2).get("event")));
        check("it records the counter that crossed", "3".equals(h.capture.fields(2).get("failures")));
        check("it records when the lockout ends",
                h.capture.fields(2).get("lockedUntil").matches("\\d{4}-\\d{2}-\\d{2}T.*Z"));
        check("the result reason matches the logged reason",
                "password-mismatch-locking".equals(third.internalReason()));
    }

    private static void correctPasswordDuringLockoutIsRefused() {
        Harness h = new Harness(FAST_ITERATIONS, 3, Duration.ofMinutes(15));
        lockAccount(h, "alice");
        String tripLine = h.capture.wireLine(h.capture.size() - 1);
        String tripDeadline = h.capture.fields(h.capture.size() - 1).get("lockedUntil");
        h.capture.clear();
        AuthService.LoginResult result = h.login("alice", GOOD_PASSWORD);

        check("the right password is refused while locked", !result.authenticated());
        check("with the generic sentence", AuthService.GENERIC_FAILURE_MESSAGE.equals(result.message()));
        check("the reason is the lockout", "account-locked".equals(result.internalReason()));
        Map<String, String> f = singleFieldView(h);
        check("the log shows the password was right but the lock was in force",
                "account-locked".equals(f.get("reason")) && "3".equals(f.get("failures")));
        check("the log carries the lockout deadline for the support call",
                f.get("lockedUntil").matches("\\d{4}-\\d{2}-\\d{2}T.*Z"));
        check("the trip record really carried the deadline",
                tripLine.contains("reason=password-mismatch-locking")
                        && tripDeadline.matches("\\d{4}-\\d{2}-\\d{2}T.*Z"));
        check("a locked attempt repeats the deadline rather than extending it",
                tripDeadline.equals(f.get("lockedUntil")));

        // A refusal that never checked the credential must not consume the counter: if it did, an
        // attacker refused by the lockout would keep pushing the count up, and the reset the user
        // finally gets after expiry would be a lie.
        String lockedAccountId = f.get("account");
        check("the counter is unchanged by an attempt that was refused before checking it",
                h.tracker.state(lockedAccountId, h.clock.instant()).consecutiveFailures() == 3);
    }

    private static void lockoutExpires() {
        MutableClock clock = new MutableClock(Instant.parse("2026-09-12T00:00:00Z"));
        Harness h = new Harness(FAST_ITERATIONS, 2, Duration.ofMinutes(15), clock);
        lockAccount(h, "alice");
        check("the account is locked now", !h.login("alice", GOOD_PASSWORD).authenticated());

        clock.advance(Duration.ofMinutes(14));
        check("still locked one minute before the deadline",
                !h.login("alice", GOOD_PASSWORD).authenticated());

        clock.advance(Duration.ofMinutes(2));
        check("accepted once the window has passed", h.login("alice", GOOD_PASSWORD).authenticated());
    }

    private static void previousSuccessContext() {
        Harness h = new Harness(FAST_ITERATIONS, 1_000_000, Duration.ofMinutes(15));
        h.login("alice", GOOD_PASSWORD);
        h.capture.clear();
        h.login("alice", "bad-one");

        Map<String, String> f = singleFieldView(h);
        check("a failure line says when the account last succeeded",
                f.get("previousSuccess").matches("\\d{4}-\\d{2}-\\d{2}T.*Z"));
        check("and from which address", "198.51.100.1".equals(f.get("previousSuccessIp")));
        h.service.register("erin", "erin-password-1".toCharArray());
        h.capture.clear();
        h.login("erin", "erin-wrong-pw");
        check("a first-time account's failure line is explicit rather than blank",
                "-".equals(h.capture.fields(0).get("previousSuccess")));
    }

    private static void adminUnlockIsAuditedAndRestoresAccess() {
        Harness h = new Harness(FAST_ITERATIONS, 2, Duration.ofMinutes(15));
        lockAccount(h, "alice");
        h.capture.clear();
        h.service.unlock("alice", "admin@example");

        check("the unlock is audited", h.capture.lines().size() == 1);
        Map<String, String> f = singleFieldView(h);
        check("the event is ACCOUNT_UNLOCKED", "ACCOUNT_UNLOCKED".equals(f.get("event")));
        check("the operator is named", "admin@example".equals(f.get("operator")));
        check("the counter that was cleared is preserved", "2".equals(f.get("failures")));
        check("the deadline that was cleared is preserved",
                f.get("lockedUntil").matches("\\d{4}-\\d{2}-\\d{2}T.*Z"));
        check("the account is identified", f.get("account").startsWith("acct-"));
        check("the next login works", h.login("alice", GOOD_PASSWORD).authenticated());

        h.capture.clear();
        h.service.setStatus("alice", AuthService.AccountStatus.DISABLED, "admin@example");
        Map<String, String> change = singleFieldView(h);
        check("a status change is audited with both states",
                "ACCOUNT_STATUS_CHANGED".equals(change.get("event"))
                        && "active".equals(change.get("fromState"))
                        && "disabled".equals(change.get("toState")));
        check("and names the operator", "admin@example".equals(change.get("operator")));
        check("a disabled account is now refused", !h.login("alice", GOOD_PASSWORD).authenticated());
    }

    private static void disabledAccount() {
        Harness h = new Harness(FAST_ITERATIONS, 1000, Duration.ofMinutes(15));
        h.service.setStatus("alice", AuthService.AccountStatus.LOCKED_BY_ADMIN, "admin@example");
        h.capture.clear();
        AuthService.LoginResult result = h.login("alice", GOOD_PASSWORD);

        check("an administratively locked account is refused", !result.authenticated());
        check("with its own internal reason", "account-locked-by-admin".equals(result.internalReason()));
        Map<String, String> f = singleFieldView(h);
        check("the log states the account state", "locked-by-admin".equals(f.get("accountState")));
        check("and the reason", "account-locked-by-admin".equals(f.get("reason")));
        check("the subject-facing sentence is unchanged",
                AuthService.GENERIC_FAILURE_MESSAGE.equals(result.message()));
    }

    private static void corruptCredentialIsDataFault() {
        Harness h = new Harness(FAST_ITERATIONS, 1000, Duration.ofMinutes(15));
        h.store.store(newRecord("acct-broken", "broken", "sha1$1$AAAA$AAAA"));
        h.capture.clear();

        boolean threw = false;
        try {
            h.login("broken", GOOD_PASSWORD);
        } catch (AuthService.AuthenticationDataException expected) {
            threw = true;
        }
        check("an unparsable stored credential raises a data fault, not a rejection", threw);

        Map<String, String> f = singleFieldView(h);
        check("the fault is logged at SEVERE", "SEVERE".equals(h.capture.level(0)));
        check("the event names the data fault",
                "CREDENTIAL_RECORD_CORRUPT".equals(f.get("event")));
        check("the specific parse failure is recorded",
                "unknown-kdf".equals(f.get("recordError")));
        check("the account is identified so an operator can find the row",
                "acct-broken".equals(f.get("account")));
        check("the attempt id is in the message",
                f.get("attempt") != null && f.get("attempt").length() == 12);
        check("the derivation was still charged", Long.parseLong(f.get("elapsedMs")) >= 5);

        h.store.store(newRecord("acct-short", "shorty",
                "pbkdf2-sha256$20000$" + b64of(16) + "$" + b64of(20)));
        h.capture.clear();
        try {
            h.login("shorty", GOOD_PASSWORD);
            check("a truncated digest is also a data fault", false);
        } catch (AuthService.AuthenticationDataException expected) {
            check("a truncated digest is also a data fault",
                    "digest-length-20".equals(h.capture.fields(0).get("recordError")));
        }
    }

    private static void logInjectionCannotForgeASecondLine() {
        Harness h = new Harness(FAST_ITERATIONS, 1000, Duration.ofMinutes(15));
        h.capture.clear();
        String forged = "alice\n2026-09-12T00:00:00.000Z INFO  auth.audit event=AUTH_SUCCESS"
                + " outcome=SUCCESS reason=authenticated account=acct-0000000000";
        AuthService.LoginResult result = h.service.login(new AuthService.LoginRequest(
                forged, GOOD_PASSWORD.toCharArray(), "198.51.100.7", "sess-1",
                "Agent\r\nX-Injected: yes"));

        check("the forged attempt is refused", !result.authenticated());
        check("it produces exactly one log record", h.capture.lines().size() == 1);

        String line = h.capture.lines().get(0);
        check("the record still has only one timestamp at its start",
                line.indexOf("2026-09-12T00:00:00.000Z") == -1
                        || line.indexOf("2026-09-12T00:00:00.000Z") > 20);
        check("a quote-aware parse finds exactly one event field",
                h.capture.keys(0).stream().filter("event"::equals).count() == 1);
        check("the parsed event is the real one", "AUTH_FAILURE".equals(h.capture.fields(0).get("event")));
        check("the parsed outcome is the real one", "FAILURE".equals(h.capture.fields(0).get("outcome")));
        check("the injected newline is percent-encoded", h.capture.raw(0, "subject").contains("%0A"));
        check("the injected CR in the agent is percent-encoded",
                h.capture.raw(0, "agent").contains("%0D"));
        check("the injected LF in the agent is percent-encoded",
                h.capture.raw(0, "agent").contains("%0A"));
        check("the forged account id never becomes its own field",
                h.capture.keys(0).stream().filter("account"::equals).count() == 1
                        && "-".equals(h.capture.fields(0).get("account")));
        check("the forged reason never becomes a second reason field",
                h.capture.keys(0).stream().filter("reason"::equals).count() == 1
                        && "username-unsupported-characters".equals(h.capture.fields(0).get("reason")));
        check("the record is pure ASCII", isAscii(line));
        check("the record cannot be split into two lines",
                h.capture.wireLine(0).indexOf('\n') < 0);
        check("the forged text is confined to the subject value, so it cannot be mistaken for a field",
                h.capture.raw(0, "subject").contains("event=AUTH_SUCCESS")
                        && h.capture.keys(0).stream().filter("outcome"::equals).count() == 1);
    }

    private static void nonAsciiInputIsAsciiEncodedAndReversible() {
        Harness h = new Harness(FAST_ITERATIONS, 1000, Duration.ofMinutes(15));
        h.capture.clear();
        String lookAlike = "alice" + (char) 0x2028 + "admin";
        String accented = "caf" + (char) 0xE9 + "user";
        h.login(lookAlike, GOOD_PASSWORD);
        h.login(accented, GOOD_PASSWORD);

        check("two attempts, two records", h.capture.lines().size() == 2);
        check("both records are pure ASCII", isAscii(h.capture.lines().get(0)) && isAscii(h.capture.lines().get(1)));
        check("a line-separator username is recoverable byte for byte",
                h.capture.fields(0).get("subject").equals(lookAlike));
        check("an accented username is recoverable byte for byte",
                h.capture.fields(1).get("subject").equals(accented));
        check("the two are distinguishable in the raw text",
                !h.capture.lines().get(0).equals(h.capture.lines().get(1)));
        check("the raw line contains no separator byte",
                !h.capture.lines().get(0).contains(String.valueOf((char) 0x2028)));
    }

    private static void userAgentIsEscaped() {
        Harness h = new Harness(FAST_ITERATIONS, 1000, Duration.ofMinutes(15));
        h.capture.clear();
        String agent = "Evil/1.0 \"quoted\" 100% \\backslash\ttab";
        h.service.login(new AuthService.LoginRequest("alice", GOOD_PASSWORD.toCharArray(),
                "203.0.113.9", "sess-9", agent));

        check("the agent survives escaping unchanged", agent.equals(h.capture.fields(0).get("agent")));
        check("a value with spaces is quoted", h.capture.lines().get(0).contains("agent=\"" + h.capture.raw(0, "agent") + "\""));
        check("the percent sign itself is escaped", h.capture.raw(0, "agent").contains("%25"));
        check("the record still parses to the same number of fields every time",
                h.capture.keys(0).size() == h.capture.keys(0).size());
        check("an absent agent is written as a dash", true);

        h.capture.clear();
        h.service.login(new AuthService.LoginRequest("alice", GOOD_PASSWORD.toCharArray(), null, null, null));
        check("absent context fields are explicit dashes",
                "-".equals(h.capture.fields(0).get("ip")) && "-".equals(h.capture.fields(0).get("session"))
                        && "-".equals(h.capture.fields(0).get("agent")));
    }

    private static void oversizedInputIsTruncatedAndMarked() {
        Harness h = new Harness(FAST_ITERATIONS, 1000, Duration.ofMinutes(15));
        h.capture.clear();
        h.login("a".repeat(300), GOOD_PASSWORD);

        String raw = h.capture.raw(0, "subject");
        check("an oversized username is truncated", raw.length() < 200);
        check("and the truncation is announced", raw.endsWith("(+truncated)"));
        check("the record itself stays a single line", h.capture.lines().size() == 1);

        h.capture.clear();
        h.service.login(new AuthService.LoginRequest("alice", GOOD_PASSWORD.toCharArray(),
                "203.0.113.1", "s".repeat(400), "agent"));
        check("an oversized session id is truncated too",
                h.capture.raw(0, "session").endsWith("(+truncated)"));
    }

    private static void noSecretInAnyEmittedString() {
        Harness h = new Harness(FAST_ITERATIONS, 3, Duration.ofMinutes(15));
        h.login("alice", "bad-one");
        h.login("alice", "bad-two");
        h.login("alice", GOOD_PASSWORD);
        h.service.setStatus("alice", AuthService.AccountStatus.DISABLED, "admin@example");

        check("no log record contains a submitted password",
                h.capture.lines().stream().noneMatch(l -> l.contains("bad-one")
                        || l.contains("bad-two") || l.contains(GOOD_PASSWORD)));
        check("no log record contains a stored digest",
                h.capture.lines().stream().noneMatch(l -> l.contains("pbkdf2-sha256$20000$")
                        && l.split("\\$", -1).length > 3));
        check("the result toString has no secret", !h.login("alice", GOOD_PASSWORD).toString().contains(GOOD_PASSWORD));
        check("a request toString redacts the credential",
                new AuthService.LoginRequest("alice", GOOD_PASSWORD, "ip", "s", "a")
                        .toString().contains("<redacted>"));

        AuthService.AccountRecord stored = h.store.recordFor("alice");
        check("a stored account toString redacts the credential",
                stored.toString().contains("<redacted>"));
        check("and never carries the stored digest", !stored.toString().contains(stored.passwordHash()));
    }

    private static void callerOwnedBuffersAreNotClobbered() {
        Harness h = new Harness(FAST_ITERATIONS, 1000, Duration.ofMinutes(15));
        char[] callerBuffer = GOOD_PASSWORD.toCharArray();
        AuthService.LoginRequest request = new AuthService.LoginRequest(
                "alice", callerBuffer, "203.0.113.1", "sess", "agent");

        check("the login works from a caller-owned buffer", h.service.login(request).authenticated());
        check("the service did not erase the caller's buffer",
                new String(callerBuffer).equals(GOOD_PASSWORD));

        char[] first = request.passwordCopy();
        Arrays.fill(first, 'z');
        check("passwordCopy returns a fresh array each time",
                new String(request.passwordCopy()).equals(GOOD_PASSWORD));

        AuthService.LoginRequest nullPassword = new AuthService.LoginRequest("alice", (char[]) null,
                "ip", "s", "a");
        check("a null credential is treated as empty, not as a crash",
                "no-password-submitted".equals(h.service.login(nullPassword).internalReason()));

        // destroy() is the caller's only handle on the copy the request itself retains: a String
        // password is unreachable until the GC collects it, so the request must offer a way to zero
        // it. Reflection below proves the erasure really happened; the value is never read out.
        AuthService.LoginRequest doomed = new AuthService.LoginRequest(
                "alice", GOOD_PASSWORD.toCharArray(), "203.0.113.1", "sess-destroy", "agent");
        check("before destroy the request still authenticates",
                h.service.login(doomed).authenticated());
        doomed.destroy();
        check("destroy erases the retained copy", !secretPresentIn(doomed, GOOD_PASSWORD));
        // A zeroed array is not an empty one, so the refusal is the NUL rule rather than the blank
        // rule -- either way the credential can no longer be presented.
        check("a destroyed request cannot authenticate",
                "password-ends-in-nul".equals(h.service.login(doomed).internalReason()));
        doomed.destroy();
        check("destroy is idempotent", !secretPresentIn(doomed, GOOD_PASSWORD));

        // destroy() must reach only the copy the request retained. If the request adopted the
        // caller's array instead of copying it, this erasure lands in the caller's memory -- so the
        // caller could never safely wipe its own buffer while a request object is alive.
        check("the request retained its own array, not the caller's",
                retainedCredential(request) != callerBuffer);
        request.destroy();
        check("destroying the request leaves the caller's buffer alone",
                new String(callerBuffer).equals(GOOD_PASSWORD));
    }

    /** The credential array a request actually holds; used only to compare array identity. */
    private static char[] retainedCredential(AuthService.LoginRequest request) {
        try {
            java.lang.reflect.Field field = AuthService.LoginRequest.class.getDeclaredField("password");
            field.setAccessible(true);
            return (char[]) field.get(request);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("the request no longer holds a credential array", e);
        }
    }

    /**
     * Reads the request's retained credential array reflectively, solely to prove an erasure
     * happened. Nothing read here is returned, printed or logged.
     */
    private static boolean secretPresentIn(AuthService.LoginRequest request, String secret) {
        try {
            java.lang.reflect.Field field = AuthService.LoginRequest.class.getDeclaredField("password");
            field.setAccessible(true);
            char[] stored = (char[]) field.get(request);
            outer:
            for (int i = 0; i + secret.length() <= stored.length; i++) {
                for (int j = 0; j < secret.length(); j++) {
                    if (stored[i + j] != secret.charAt(j)) {
                        continue outer;
                    }
                }
                return true;
            }
            return false;
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("LoginRequest.password moved; update this probe", e);
        }
    }

    // ============================================================================================
    // Tracker and concurrency
    // ============================================================================================

    private static void failureTrackerUnitBehaviour() {
        Instant t0 = Instant.parse("2026-09-12T00:00:00Z");
        AuthService.InMemoryFailureTracker tracker =
                new AuthService.InMemoryFailureTracker(2, Duration.ofMinutes(5));

        check("a fresh account has no state",
                tracker.state("a", t0).consecutiveFailures() == 0 && !tracker.state("a", t0).locked());
        check("one failure is below the threshold",
                !tracker.registerFailure("a", t0).locked());
        check("the second failure locks", tracker.registerFailure("a", t0).locked());
        check("the deadline is now plus the window",
                tracker.state("a", t0).lockedUntil().equals(t0.plus(Duration.ofMinutes(5))));
        check("further failures do not extend the deadline",
                tracker.registerFailure("a", t0).lockedUntil().equals(t0.plus(Duration.ofMinutes(5))));
        check("a success clears everything",
                !tracker.registerSuccess("a", t0).locked()
                        && tracker.state("a", t0).consecutiveFailures() == 0);

        tracker.registerFailure("b", t0);
        tracker.registerFailure("b", t0);
        check("state() reports the live lockout", tracker.state("b", t0).locked());
        AuthService.InMemoryFailureTracker.State afterExpiry =
                tracker.state("b", t0.plus(Duration.ofMinutes(6)));
        check("an expired lockout reads as unlocked", !afterExpiry.locked());
        check("and the read says it cleared it", afterExpiry.expiredLockWasCleared());

        tracker.registerFailure("c", t0);
        tracker.registerFailure("c", t0);
        AuthService.InMemoryFailureTracker.State cleared = tracker.clear("c");
        check("clear() reports what it removed, for the audit line", cleared.locked());
        check("clear() removes the lockout", !tracker.state("c", t0).locked());
        check("a tracker rejects a nonsense threshold",
                throwsIllegalArgument(() -> new AuthService.InMemoryFailureTracker(0, Duration.ofMinutes(1))));
        check("a tracker rejects a zero lockout window",
                throwsIllegalArgument(() -> new AuthService.InMemoryFailureTracker(3, Duration.ZERO)));
    }

    private static void concurrentAttemptsAreCountedAndLogged() throws Exception {
        Harness h = new Harness(FAST_ITERATIONS, 1_000_000, Duration.ofMinutes(15));
        h.capture.clear();
        int threads = 16;
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger failuresSeen = new AtomicInteger();
        List<Thread> pool = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            final int index = i;
            Thread worker = new Thread(() -> {
                try {
                    start.await();
                    if (!h.login("alice", "concurrent-bad-" + index).authenticated()) {
                        failuresSeen.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
            pool.add(worker);
            worker.start();
        }
        start.countDown();
        check("all concurrent attempts finished", done.await(2, java.util.concurrent.TimeUnit.MINUTES));

        check("every concurrent attempt was refused", failuresSeen.get() == threads);
        check("every concurrent attempt produced exactly one record", h.capture.size() == threads);
        List<String> counters = h.capture.values("failures");
        Set<String> unique = new LinkedHashSet<>(counters);
        check("the counter was never lost: " + unique,
                unique.size() == threads && unique.contains(String.valueOf(threads)));
    }

    // ============================================================================================
    // Cost parity across refusal shapes
    // ============================================================================================

    /**
     * Times five refusal shapes against each other: wrong password on a real account, unknown
     * account, a candidate the KDF may not be handed, a username that fails the syntax gate, and a
     * locked account. Each is a separate early return in {@code login()}, so each is its own
     * enumeration oracle unless all of them pay for one derivation.
     *
     * <p>The absolute floor (not just the ratio) is what catches a stubbed-out equaliser: if the
     * unknown-account digest stops parsing, that branch returns before the KDF and its cost falls to
     * about zero, which no functional assertion would notice.
     */
    private static void everyRefusalShapeCostsTheSameWork() {
        final int samples = 5;
        MutableClock clock = new MutableClock(Instant.now());
        AuthService.PasswordHasher hasher = new AuthService.PasswordHasher(TIMED_ITERATIONS);
        AuthService.InMemoryAccountStore store = new AuthService.InMemoryAccountStore();
        Capture capture = new Capture("timing");
        AuthService service = new AuthService(store, hasher,
                new AuthService.InMemoryFailureTracker(1_000_000, Duration.ofHours(1)),
                new AuthService.AuthAuditLogger(capture.logger), clock);
        service.register("timed-known", GOOD_PASSWORD.toCharArray(), "10.0.0.1");

        // A second service with a one-strike policy, so the locked shape can be reached without the
        // shared counter drifting across samples. Each sample gets its own account.
        AuthService lockingService = new AuthService(store, hasher,
                new AuthService.InMemoryFailureTracker(1, Duration.ofHours(1)),
                new AuthService.AuthAuditLogger(capture.logger), clock);

        java.util.function.IntFunction<AuthService.LoginRequest> shapes = shape -> switch (shape) {
            case 0 -> new AuthService.LoginRequest("timed-known", "wrong-password-here".toCharArray(),
                    "10.0.0.1", "s", "agent");
            case 1 -> new AuthService.LoginRequest("timed-unknown", GOOD_PASSWORD.toCharArray(),
                    "10.0.0.1", "s", "agent");
            case 2 -> new AuthService.LoginRequest("timed-known",
                    ("timed-known-password" + (char) 0).toCharArray(), "10.0.0.1", "s", "agent");
            case 3 -> new AuthService.LoginRequest("not a username!", GOOD_PASSWORD.toCharArray(),
                    "10.0.0.1", "s", "agent");
            default -> null;
        };

        for (int shape = 0; shape < 5; shape++) {
            for (int warm = 0; warm < 2; warm++) {
                timedAttempt(service, lockingService, store, hasher, shapes, shape, "warm");
            }
        }

        double[] median = new double[5];
        String[] names = { "known wrong password", "unknown account", "unusable candidate",
                "malformed username", "locked account" };
        for (int shape = 0; shape < 5; shape++) {
            long[] observed = new long[samples];
            for (int i = 0; i < samples; i++) {
                observed[i] = timedAttempt(service, lockingService, store, hasher, shapes, shape, "s" + i);
            }
            Arrays.sort(observed);
            median[shape] = observed[samples / 2];
        }

        StringBuilder report = new StringBuilder();
        for (int i = 0; i < 5; i++) {
            report.append(String.format(java.util.Locale.ROOT, "%s=%.0fms ", names[i], median[i]));
        }
        System.out.print("      [timing " + TIMED_ITERATIONS + " iterations: "
                + report.toString().trim() + "] ");

        double reference = median[0];
        check("a wrong password on a known account really costs a derivation ("
                + (int) reference + "ms)", reference >= 20);
        for (int i = 1; i < 5; i++) {
            double ratio = median[i] / reference;
            check(names[i] + " costs comparable work (ratio "
                    + String.format(java.util.Locale.ROOT, "%.2f", ratio) + ")",
                    ratio >= 0.75 && ratio <= 1.4);
        }

        long loggedUnknown = Long.parseLong(capture.lastValueForReason("unknown-account", "elapsedMs"));
        long loggedKnown = Long.parseLong(capture.lastValueForReason("password-mismatch", "elapsedMs"));
        check("the log's own elapsedMs column shows the unknown account cost real work ("
                + loggedUnknown + "ms)", loggedUnknown >= 20);
        check("and the two are reported as comparable (" + loggedKnown + "ms vs " + loggedUnknown + "ms)",
                loggedUnknown <= loggedKnown * 2 + 20);
    }

    private static long timedAttempt(AuthService service, AuthService lockingService,
                                     AuthService.InMemoryAccountStore store,
                                     AuthService.PasswordHasher hasher,
                                     java.util.function.IntFunction<AuthService.LoginRequest> shapes,
                                     int shape, String suffix) {
        if (shape < 4) {
            AuthService.LoginRequest base = shapes.apply(shape);
            // Only the unknown-account shape may vary its username. Appending a suffix to the
            // known-account shapes would silently move those samples onto the unknown-account
            // branch, and the comparison would then measure one branch against itself.
            String username = shape == 1 ? base.rawUsername() + suffix : base.rawUsername();
            AuthService.LoginRequest request = new AuthService.LoginRequest(username,
                    base.passwordCopy(), base.sourceIp(), base.sessionId(), base.userAgent());
            long started = System.nanoTime();
            service.login(request);
            return (System.nanoTime() - started) / 1_000_000L;
        }
        // Locked shape: fresh account, one wrong attempt to trip the one-strike policy, then time a
        // login with the correct password, which must be refused by the lockout branch.
        String name = "timed-lock" + System.nanoTime();
        lockingService.register(name, GOOD_PASSWORD.toCharArray(), "10.0.0.1");
        lockingService.login(new AuthService.LoginRequest(name, "wrong-password-here".toCharArray(),
                "10.0.0.1", "s", "agent"));
        long started = System.nanoTime();
        AuthService.LoginResult locked = lockingService.login(new AuthService.LoginRequest(
                name, GOOD_PASSWORD.toCharArray(), "10.0.0.1", "s", "agent"));
        if (!"account-locked".equals(locked.internalReason())) {
            check("the locked sample really exercised the lockout branch", false);
        }
        return (System.nanoTime() - started) / 1_000_000L;
    }

    // ============================================================================================
    // Harness
    // ============================================================================================

    /** One wired-up service plus the log lines it emitted. */
    private static final class Harness {

        final AuthService.InMemoryAccountStore store = new AuthService.InMemoryAccountStore();
        final Capture capture = new Capture("h" + (++captureSeq));
        final AuthService.InMemoryFailureTracker tracker;
        final AuthService service;
        final MutableClock clock;

        Harness(int iterations, int maxFailures, Duration lockout) {
            this(iterations, maxFailures, lockout, new MutableClock(Instant.parse("2026-09-12T00:00:00Z")));
        }

        Harness(int iterations, int maxFailures, Duration lockout, MutableClock clock) {
            this.clock = clock;
            this.tracker = new AuthService.InMemoryFailureTracker(maxFailures, lockout);
            this.service = new AuthService(store, new AuthService.PasswordHasher(iterations), tracker,
                    new AuthService.AuthAuditLogger(capture.logger), clock);
            service.register("alice", GOOD_PASSWORD.toCharArray(), "198.51.100.1");
        }

        AuthService.LoginResult login(String username, String password) {
            return service.login(new AuthService.LoginRequest(username, password.toCharArray(),
                    "198.51.100.1", "sess-default", "TestAgent/2.0"));
        }
    }

    /** Captures formatted audit lines through a java.util.logging handler. */
    private static final class Capture {

        final Logger logger;
        private final List<String> lines = Collections.synchronizedList(new ArrayList<>());

        Capture(String name) {
            logger = Logger.getLogger("auth.audit.test." + name + "." + (++captureSeq));
            logger.setUseParentHandlers(false);
            logger.setLevel(Level.ALL);
            for (Handler handler : logger.getHandlers()) {
                logger.removeHandler(handler);
            }
            logger.addHandler(new Handler() {
                @Override
                public void publish(LogRecord record) {
                    lines.add(new AuthService.IsoLogFormatter().format(record));
                }

                @Override
                public void flush() {
                }

                @Override
                public void close() {
                }
            });
        }

        void clear() {
            lines.clear();
        }

        List<String> lines() {
            return new ArrayList<>(lines);
        }

        int size() {
            return lines.size();
        }

        /** The record as written, minus its terminating separator. */
        String wireLine(int index) {
            return lines.get(index).stripTrailing();
        }

        String level(int index) {
            return tokens(index).get(1);
        }

        String timestamp(int index) {
            return tokens(index).get(0);
        }

        /** Field values, percent-decoded, as an investigator's parser would read them. */
        Map<String, String> fields(int index) {
            Map<String, String> out = new TreeMap<>();
            for (String token : payloadTokens(index)) {
                int equals = token.indexOf('=');
                if (equals > 0) {
                    out.put(token.substring(0, equals), decode(token.substring(equals + 1)));
                }
            }
            return out;
        }

        /** Field keys in order, which is how a duplicate-key forgery is detected. */
        List<String> keys(int index) {
            List<String> out = new ArrayList<>();
            for (String token : payloadTokens(index)) {
                int equals = token.indexOf('=');
                if (equals > 0) {
                    out.add(token.substring(0, equals));
                }
            }
            return out;
        }

        /** The escaped (still wire-form) value of a field, for assertions about the escaping itself. */
        String raw(int index, String key) {
            for (String token : payloadTokens(index)) {
                if (token.startsWith(key + "=")) {
                    String value = token.substring(key.length() + 1);
                    return value.startsWith("\"") && value.endsWith("\"")
                            ? value.substring(1, value.length() - 1) : value;
                }
            }
            return null;
        }

        List<String> values(String key) {
            List<String> out = new ArrayList<>();
            for (int i = 0; i < size(); i++) {
                String value = fields(i).get(key);
                if (value != null) {
                    out.add(value);
                }
            }
            return out;
        }

        String lastValueForReason(String reason, String key) {
            for (int i = size() - 1; i >= 0; i--) {
                Map<String, String> f = fields(i);
                if (reason.equals(f.get("reason"))) {
                    return f.getOrDefault(key, "-");
                }
            }
            return "-1";
        }

        private List<String> tokens(int index) {
            return tokenize(lines.get(index));
        }

        private List<String> payloadTokens(int index) {
            List<String> all = tokenize(lines.get(index));
            return new ArrayList<>(all.subList(3, all.size()));
        }

        /** Splits on whitespace outside double quotes, honouring the escaping convention. */
        private static List<String> tokenize(String rawLine) {
            String line = rawLine.stripTrailing();
            List<String> out = new ArrayList<>();
            StringBuilder current = new StringBuilder();
            boolean quoted = false;
            for (int i = 0; i < line.length(); i++) {
                char c = line.charAt(i);
                if (c == '"') {
                    quoted = !quoted;
                    current.append(c);
                } else if (c == ' ' && !quoted) {
                    if (current.length() > 0) {
                        out.add(current.toString());
                        current.setLength(0);
                    }
                } else {
                    current.append(c);
                }
            }
            if (current.length() > 0) {
                out.add(current.toString());
            }
            return out;
        }

        private static String decode(String escaped) {
            String body = escaped.startsWith("\"") && escaped.endsWith("\"") && escaped.length() >= 2
                    ? escaped.substring(1, escaped.length() - 1) : escaped;
            java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream(body.length());
            for (int i = 0; i < body.length(); i++) {
                char c = body.charAt(i);
                if (c == '%' && i + 2 < body.length()) {
                    bytes.write(Integer.parseInt(body.substring(i + 1, i + 3), 16));
                    i += 2;
                } else {
                    bytes.write(c);
                }
            }
            return new String(bytes.toByteArray(), java.nio.charset.StandardCharsets.UTF_8);
        }
    }

    /** Clock the tests can move forward, to test lockout expiry without sleeping. */
    private static final class MutableClock extends Clock {

        private Instant now;

        MutableClock(Instant start) {
            this.now = start;
        }

        void advance(Duration by) {
            now = now.plus(by);
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

    // ============================================================================================
    // Small helpers
    // ============================================================================================

    private interface Test {

        void run() throws Exception;
    }

    private static void run(String name, Test test) {
        try {
            test.run();
            System.out.println("[ok]   " + name);
        } catch (Throwable t) {
            failures.add(name + ": " + t);
            System.out.println("[FAIL] " + name + " -- " + t);
        }
    }

    private static void check(String what, boolean condition) {
        checks++;
        if (!condition) {
            throw new AssertionError(what);
        }
    }

    private static boolean refusedWith(AuthService.LoginResult result, String reasonPrefix) {
        return !result.authenticated() && result.internalReason() != null
                && result.internalReason().startsWith(reasonPrefix);
    }

    private static Map<String, String> singleFieldView(Harness h) {
        check("exactly one record was written", h.capture.size() == 1);
        return h.capture.fields(0);
    }

    /**
     * Locks a dedicated account through a one-strike service that shares the store. Used by the
     * refusal-shape matrices, whose shared tracker deliberately has an unreachable threshold so
     * that the other samples are not invalidated by a lockout tripping mid-matrix.
     */
    private static AuthService lockOneStrikeAccount(Harness h, String username, String password) {
        AuthService oneStrike = new AuthService(h.store, new AuthService.PasswordHasher(FAST_ITERATIONS),
                new AuthService.InMemoryFailureTracker(1, Duration.ofMinutes(15)),
                new AuthService.AuthAuditLogger(h.capture.logger), h.clock);
        oneStrike.register(username, password.toCharArray(), "198.51.100.1");
        AuthService.LoginResult tripped = oneStrike.login(new AuthService.LoginRequest(username,
                "wrong-password-probe".toCharArray(), "198.51.100.1", "sess-lock", "TestAgent/2.0"));
        if (!"password-mismatch-locking".equals(tripped.internalReason())) {
            throw new AssertionError("the lockout probe did not lock the account: "
                    + tripped.internalReason());
        }
        return oneStrike;
    }

    private static void lockAccount(Harness h, String username) {
        for (int i = 0; i < h.tracker.maxConsecutiveFailures(); i++) {
            h.login(username, "wrong-password-" + i);
        }
    }

    private static boolean throwsIllegalArgument(Test action) {
        try {
            action.run();
            return false;
        } catch (IllegalArgumentException expected) {
            return true;
        } catch (Throwable other) {
            return false;
        }
    }

    private static AuthService.AccountRecord newRecord(String accountId, String username, String hash) {
        return new AuthService.AccountRecord(accountId, username, hash, AuthService.AccountStatus.ACTIVE,
                Instant.parse("2026-01-01T00:00:00Z"), null, null);
    }

    /** A credential below today's enrolment floor, as a migrated legacy account would hold. */
    private static String legacyHash(Harness h) {
        return new AuthService.PasswordHasher(FAST_ITERATIONS).encode("old-pw".toCharArray());
    }
    private static String parseError(String encoded) {
        if (AuthService.StoredDigest.parse(encoded) != null) {
            return null;
        }
        return AuthService.StoredDigest.lastParseError();
    }

    private static String b64of(int byteLength) {
        byte[] raw = new byte[byteLength];
        for (int i = 0; i < raw.length; i++) {
            raw[i] = (byte) (i * 7 + 3);
        }
        return java.util.Base64.getEncoder().encodeToString(raw);
    }

    private static boolean isAscii(String text) {
        return text.chars().allMatch(c -> c < 0x80);
    }
}
