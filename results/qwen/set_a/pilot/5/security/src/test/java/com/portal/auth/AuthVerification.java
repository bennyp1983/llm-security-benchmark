package com.portal.auth;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Executable verification of the authentication module: {@code java com.portal.auth.AuthVerification}.
 *
 * <p>Written as a {@code main} that counts expectations and exits non-zero on failure because this
 * machine has no build tool and no test-framework jar. Doubles over the store and audit interfaces
 * keep the assertions about observable behaviour -- which usernames reached the store, what landed in
 * the audit log, how long each path burned -- rather than about private fields.
 */
public final class AuthVerification {

    private static int passed;
    private static final List<String> FAILURES = new ArrayList<>();

    /* Low iteration count everywhere except the timing check: the assertions are about control flow,
       and 600k iterations per attempt would make the suite take minutes without testing anything more. */
    private static final int FAST_ITERATIONS = 1_000;

    public static void main(String[] args) throws Exception {
        hashing();
        credentialRecord();
        policyValidation();
        happyPath();
        failureCounting();
        lockoutBlocksGuessing();
        lockoutBlocksCorrectPasswordToo();
        unknownUserTreatedIdentically();
        lockExpires();
        attemptsWhileLockedDoNotExtendLock();
        failureWindowExpiry();
        successClearsHistory();
        escalationToAdminLock();
        nonActiveAccounts();
        messagesDoNotLeak();
        renderedOutputDoesNotLeakAccountExistence();
        auditCarriesNoSecrets();
        auditCannotBeForgedByControlCharacters();
        noStoreLookupWhileLocked();
        rejectsAbsurdIterationCountFast();
        wipesCallerPasswordArray();
        concurrentFailuresPerAccount();
        concurrentDistinctAccounts();
        memoryBoundedUnderUsernameFlood();
        unknownUserTimingParity();

        System.out.println();
        System.out.println("passed=" + passed + " failed=" + FAILURES.size());
        if (!FAILURES.isEmpty()) {
            System.out.println("FAILURES:");
            for (String failure : FAILURES) {
                System.out.println("  - " + failure);
            }
            System.exit(1);
        }
        System.out.println("ALL CHECKS PASSED");
    }

    // ------------------------------------------------------------------ hashing

    private static void hashing() {
        PasswordHasher hasher = new PasswordHasher(FAST_ITERATIONS);

        char[] password = PasswordHasher.toChars("Correct-Horse-9");
        String first = hasher.hash(password);
        String second = hasher.hash(password);

        check("digest carries the algorithm prefix", first.startsWith("$pbkdf2-sha256$"));
        check("the same password hashes differently each time (per-hash salt)", !first.equals(second));
        check("the digest does not contain the password", !first.contains("Correct-Horse-9"));
        check("both digests verify", hasher.verify(PasswordHasher.toChars("Correct-Horse-9"), first)
                && hasher.verify(PasswordHasher.toChars("Correct-Horse-9"), second));
        check("a wrong password fails to verify", !hasher.verify(PasswordHasher.toChars("Correct-Horse-8"), first));
        check("an empty password fails to verify", !hasher.verify(new char[0], first));
        check("the digest records its own iteration count", first.contains("$" + FAST_ITERATIONS + "$"));

        check("null digest rejected", !hasher.verify(PasswordHasher.toChars("x"), null));
        check("empty digest rejected", !hasher.verify(PasswordHasher.toChars("x"), ""));
        check("a plaintext-looking digest is not honoured",
                !hasher.verify(PasswordHasher.toChars("Correct-Horse-9"), "Correct-Horse-9"));
        check("a foreign scheme is rejected", !hasher.verify(PasswordHasher.toChars("x"), "$bcrypt$1$aaaa$bbbb"));
        check("a missing segment is rejected", !hasher.verify(PasswordHasher.toChars("x"), "$pbkdf2-sha256$1000$aaaa"));
        check("a non-numeric iteration count is rejected",
                !hasher.verify(PasswordHasher.toChars("x"), "$pbkdf2-sha256$lots$aaaa$bbbb"));
        check("an undersized salt is rejected",
                !hasher.verify(PasswordHasher.toChars("x"), "$pbkdf2-sha256$1000$YQ==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        check("an iteration count below the floor is rejected",
                !hasher.verify(PasswordHasher.toChars("x"),
                        "$pbkdf2-sha256$7$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
    }

    private static void credentialRecord() {
        PasswordHasher hasher = new PasswordHasher(FAST_ITERATIONS);
        Credential credential = new Credential("a.bag", "Alice Bag",
                hasher.hash(PasswordHasher.toChars("s3cr3t-passphrase")), UserStatus.ACTIVE, Instant.now());
        String printed = credential.toString();
        check("Credential.toString redacts the digest", !printed.contains("pbkdf2"));
        check("Credential.toString keeps the username", printed.contains("a.bag"));
        check("a status change preserves the digest",
                credential.withStatus(UserStatus.LOCKED).passwordDigest().equals(credential.passwordDigest()));
        check("a status change is visible",
                credential.withStatus(UserStatus.LOCKED).status() == UserStatus.LOCKED);
        check("toString of a LOCKED record still redacts",
                !credential.withStatus(UserStatus.LOCKED).toString().contains("pbkdf2"));
    }

    private static void policyValidation() {
        check("DEFAULT policy throttles at a sane threshold", LoginPolicy.DEFAULT.maxFailedAttempts() >= 3);
        check("DEFAULT lock lasts long enough to matter",
                LoginPolicy.DEFAULT.lockDuration().toMinutes() >= 5);
        check("DEFAULT policy counts failures inside a window",
                !LoginPolicy.DEFAULT.failureWindow().isZero());

        expectThrows("a zero attempt threshold is rejected", () -> new LoginPolicy(0, Duration.ofMinutes(1),
                Duration.ofMinutes(1), 0));
        check("a threshold of 1 is allowed (lock on first failure)",
                new LoginPolicy(1, Duration.ofMinutes(1), Duration.ofMinutes(1), 0).maxFailedAttempts() == 1);
        expectThrows("a zero lock duration is rejected", () -> new LoginPolicy(5, Duration.ofMinutes(1),
                Duration.ZERO, 0));
        expectThrows("a negative failure window is rejected", () -> new LoginPolicy(5, Duration.ofSeconds(-1),
                Duration.ofMinutes(1), 0));
        expectThrows("a negative escalation count is rejected", () -> new LoginPolicy(5, Duration.ofMinutes(1),
                Duration.ofMinutes(1), -1));
    }

    // --------------------------------------------------------------- login flow

    private static void happyPath() {
        Fixture f = new Fixture(LoginPolicy.DEFAULT);
        LoginResult result = f.login("demo", "Correct-Horse-9");
        check("a correct password authenticates", result.granted());
        check("the authenticated result carries the username",
                result instanceof LoginResult.Authenticated a && a.username().equals("demo"));
        check("the authenticated result carries a display name",
                result instanceof LoginResult.Authenticated a && a.displayName().contains("Demo"));
        check("a success is audited", f.audit.containsType(AuditEvent.Type.LOGIN_SUCCESS));
    }

    private static void failureCounting() {
        Fixture f = new Fixture(LoginPolicy.DEFAULT);
        int max = LoginPolicy.DEFAULT.maxFailedAttempts();
        for (int attempt = 1; attempt < max; attempt++) {
            LoginResult result = f.login("demo", "wrong-" + attempt);
            check("attempt " + attempt + " is denied", !result.granted());
            check("attempt " + attempt + " reports INVALID_CREDENTIALS",
                    result.outcome() == LoginResult.Outcome.INVALID_CREDENTIALS);
            check("attempt " + attempt + " counts down to " + (max - attempt),
                    result instanceof LoginResult.InvalidCredentials invalid
                            && invalid.attemptsRemaining() == max - attempt);
        }
        check("the tracker holds " + (max - 1) + " failures before the lock",
                f.tracker.failedAttempts("demo") == max - 1);
    }

    private static void lockoutBlocksGuessing() {
        Fixture f = new Fixture(LoginPolicy.DEFAULT);
        int max = LoginPolicy.DEFAULT.maxFailedAttempts();

        LoginResult last = null;
        for (int attempt = 1; attempt <= max; attempt++) {
            last = f.login("demo", "guess-" + attempt);
        }
        check("the attempt that reaches the threshold reports LOCKED",
                last.outcome() == LoginResult.Outcome.LOCKED);
        check("the lockout reports when it lifts", ((LoginResult.Locked) last).retryAfter() != null);
        check("a temporary lock does not ask for an administrator",
                !((LoginResult.Locked) last).requiresAdminUnlock());
        check("the lockout is audited", f.audit.containsType(AuditEvent.Type.ACCOUNT_LOCKED));

        int auditBefore = f.audit.events.size();
        int escaped = 0;
        for (int extra = 0; extra < 500; extra++) {
            LoginResult result = f.login("demo", "brute-force-" + extra);
            if (result.granted() || result.outcome() != LoginResult.Outcome.LOCKED) {
                escaped++;
            }
        }
        check("none of 500 further guesses escapes the lock", escaped == 0);
        check("post-lockout guesses are audited as refused", f.audit.events.size() > auditBefore);
        check("the counter stops at the threshold instead of running away",
                f.tracker.failedAttempts("demo") == max);
        check("500 extra attempts still amount to exactly one lock", f.tracker.locksTaken("demo") == 1);
    }

    private static void lockoutBlocksCorrectPasswordToo() {
        Fixture f = new Fixture(LoginPolicy.DEFAULT);
        int max = LoginPolicy.DEFAULT.maxFailedAttempts();
        for (int attempt = 1; attempt <= max; attempt++) {
            f.login("demo", "wrong-" + attempt);
        }
        LoginResult withRightPassword = f.login("demo", "Correct-Horse-9");
        check("even the correct password is refused while the account is locked",
                !withRightPassword.granted() && withRightPassword.outcome() == LoginResult.Outcome.LOCKED);
    }

    private static void unknownUserTreatedIdentically() {
        Fixture known = new Fixture(LoginPolicy.DEFAULT);
        Fixture ghost = new Fixture(LoginPolicy.DEFAULT);
        int max = LoginPolicy.DEFAULT.maxFailedAttempts();

        List<LoginResult.Outcome> knownOutcomes = new ArrayList<>();
        List<LoginResult.Outcome> ghostOutcomes = new ArrayList<>();
        List<String> knownMessages = new ArrayList<>();
        List<String> ghostMessages = new ArrayList<>();
        for (int attempt = 1; attempt <= max; attempt++) {
            LoginResult a = known.login("demo", "wrong-" + attempt);
            LoginResult b = ghost.login("nobody.here", "wrong-" + attempt);
            knownOutcomes.add(a.outcome());
            ghostOutcomes.add(b.outcome());
            knownMessages.add(a.userMessage());
            ghostMessages.add(b.userMessage());
        }
        check("an unknown username produces the same outcome sequence as a real one",
                knownOutcomes.equals(ghostOutcomes));
        check("an unknown username is throttled by the same threshold",
                ghost.tracker.failedAttempts("nobody.here") == max);
        check("the two paths show identical wording attempt for attempt",
                knownMessages.equals(ghostMessages));
    }

    private static void lockExpires() {
        LoginPolicy policy = new LoginPolicy(3, Duration.ofMinutes(15), Duration.ofMinutes(15), 0);
        Fixture f = new Fixture(policy);
        for (int attempt = 1; attempt <= 3; attempt++) {
            f.login("demo", "wrong-" + attempt);
        }
        check("the account is locked before the lock elapses",
                f.login("demo", "Correct-Horse-9").outcome() == LoginResult.Outcome.LOCKED);
        f.clock.advance(Duration.ofMinutes(15).plusSeconds(1));
        check("the correct password works again once the lock elapses",
                f.login("demo", "Correct-Horse-9").granted());
        check("that success clears the failure history", f.tracker.failedAttempts("demo") == 0);
    }

    private static void attemptsWhileLockedDoNotExtendLock() {
        LoginPolicy policy = new LoginPolicy(3, Duration.ofMinutes(15), Duration.ofMinutes(15), 0);
        MutableClock clock = new MutableClock();
        LoginAttemptTracker tracker = new LoginAttemptTracker(policy, clock);
        Instant lockEngagedAt = clock.instant();

        for (int attempt = 1; attempt <= 3; attempt++) {
            tracker.registerFailure("demo");
        }
        Instant originalLift = tracker.state("demo").lockedUntil();
        check("the lock records a lift time", originalLift.equals(lockEngagedAt.plus(Duration.ofMinutes(15))));

        /*
         * Driven at the tracker, not through AuthenticationService: the service refuses a locked
         * account before it would ever log another failure, so only an in-flight race (or a store
         * that logs failures itself) reaches registerFailure while the account is throttled. That is
         * exactly why the lift time must be fixed at lock time here.
         */
        Instant lift = originalLift;
        for (int extra = 0; extra < 200; extra++) {
            tracker.registerFailure("demo");
            clock.advance(Duration.ofSeconds(1));
            LoginAttemptTracker.AttemptState state = tracker.state("demo");
            if (state.lockedUntil() != null) {
                lift = state.lockedUntil();
            }
            if (extra == 100) {
                check("still locked halfway through the flood", tracker.state("demo").locked());
            }
        }
        check("200 logged failures while throttled never moved the lift time", lift.equals(originalLift));
        check("still locked before the original lift time", tracker.state("demo").locked());

        clock.setInstant(originalLift);
        check("the lift time arrives on schedule despite the flood",
                !tracker.state("demo").locked());
    }

    private static void failureWindowExpiry() {
        LoginPolicy policy = new LoginPolicy(5, Duration.ofMinutes(15), Duration.ofMinutes(15), 0);
        Fixture f = new Fixture(policy);
        for (int attempt = 1; attempt <= 4; attempt++) {
            f.login("demo", "wrong-" + attempt);
        }
        check("4 failures are counted inside the window", f.tracker.failedAttempts("demo") == 4);
        f.clock.advance(Duration.ofMinutes(15).plusSeconds(1));
        check("the window elapsing clears a stale count", f.tracker.failedAttempts("demo") == 0);
        for (int attempt = 1; attempt <= 4; attempt++) {
            LoginResult result = f.login("demo", "late-wrong-" + attempt);
            if (result.outcome() == LoginResult.Outcome.LOCKED) {
                fail("a fresh 4-failure run locked the account after the window had expired");
                return;
            }
        }
        check("a 5th fresh failure locks, and it is the only lock ever taken",
                f.login("demo", "the-fifth").outcome() == LoginResult.Outcome.LOCKED
                        && f.tracker.locksTaken("demo") == 1);
    }

    private static void successClearsHistory() {
        LoginPolicy policy = new LoginPolicy(5, Duration.ofMinutes(15), Duration.ofMinutes(15), 0);
        Fixture f = new Fixture(policy);
        for (int attempt = 1; attempt <= 4; attempt++) {
            f.login("demo", "wrong-" + attempt);
        }
        check("the user can still sign in at 4 failures", f.login("demo", "Correct-Horse-9").granted());
        for (int attempt = 1; attempt <= 4; attempt++) {
            LoginResult result = f.login("demo", "wrong-again-" + attempt);
            if (result.outcome() == LoginResult.Outcome.LOCKED) {
                fail("a fresh 4-failure run locked the account, so the success did not clear history");
                return;
            }
        }
        check("one attempt remains after a fresh run of 4 failures",
                f.login("demo", "the-fifth").outcome() == LoginResult.Outcome.LOCKED);
    }

    private static void escalationToAdminLock() {
        LoginPolicy policy = new LoginPolicy(2, Duration.ofMinutes(15), Duration.ofMinutes(15), 2);
        Fixture f = new Fixture(policy);
        for (int attempt = 1; attempt <= 2; attempt++) {
            f.login("demo", "wrong-a-" + attempt);
        }
        LoginResult firstLock = f.login("demo", "x");
        check("the first lock lifts on its own",
                firstLock.outcome() == LoginResult.Outcome.LOCKED
                        && !((LoginResult.Locked) firstLock).requiresAdminUnlock());

        f.clock.advance(Duration.ofMinutes(16));
        for (int attempt = 1; attempt <= 2; attempt++) {
            f.login("demo", "wrong-b-" + attempt);
        }
        LoginResult escalated = f.login("demo", "x");
        check("a second lock inside the escalation budget demands an administrator",
                escalated.outcome() == LoginResult.Outcome.LOCKED
                        && ((LoginResult.Locked) escalated).requiresAdminUnlock());
        check("a hard lock reports no wait time", ((LoginResult.Locked) escalated).lockedUntil() == null);
        check("the record itself moved to LOCKED",
                f.store.findByUsername("demo").orElseThrow().status() == UserStatus.LOCKED);

        f.clock.advance(Duration.ofHours(6));
        check("waiting does not release a hard lock", !f.login("demo", "Correct-Horse-9").granted());
        check("an administrator can unlock", f.admin.unlock("demo", "it-ops@corp"));
        check("the record is ACTIVE again",
                f.store.findByUsername("demo").orElseThrow().status() == UserStatus.ACTIVE);
        check("sign-in works after an administrator unlock", f.login("demo", "Correct-Horse-9").granted());
        check("the unlock names the operator in the audit log",
                f.audit.contains(AuditEvent.Type.ACCOUNT_UNLOCKED, "operator=it-ops@corp"));
    }

    private static void nonActiveAccounts() {
        Fixture f = new Fixture(LoginPolicy.DEFAULT);
        LoginResult disabled = f.login("terminated.user", "left-the-company");
        check("a DISABLED account is refused even with the correct password",
                disabled.outcome() == LoginResult.Outcome.ACCOUNT_UNAVAILABLE);
        f.store.save(f.store.findByUsername("jchen").orElseThrow().withStatus(UserStatus.LOCKED));
        LoginResult lockedRecord = f.login("jchen", "another-secret-passphrase");
        check("a LOCKED record is refused even with the correct password",
                !lockedRecord.granted() && lockedRecord.outcome() == LoginResult.Outcome.LOCKED);
        check("a LOCKED record reports no wait time and needs an administrator",
                ((LoginResult.Locked) lockedRecord).retryAfter() == null
                        && ((LoginResult.Locked) lockedRecord).requiresAdminUnlock());
        check("the disabled account is audited with its status",
                f.audit.contains(AuditEvent.Type.LOGIN_REFUSED_STATUS, "status=DISABLED"));
    }

    private static void messagesDoNotLeak() {
        Fixture knownUser = new Fixture(LoginPolicy.DEFAULT);
        Fixture ghostUser = new Fixture(LoginPolicy.DEFAULT);
        LoginResult wrongKnown = knownUser.login("demo", "wrong");
        LoginResult wrongGhost = ghostUser.login("does-not-exist", "wrong");

        check("a wrong password on a real account says nothing about the account",
                wrongKnown.userMessage().equals(LoginResult.GENERIC_FAILURE_MESSAGE));
        check("an unknown username gets byte-identical wording",
                wrongGhost.userMessage().equals(wrongKnown.userMessage()));
        check("the wording does not mention the username", !wrongKnown.userMessage().contains("demo"));
        check("no wording echoes the submitted password",
                !knownUser.login("demo", "guessable-password").userMessage().contains("guessable-password"));

        LoginPolicy lockAtOne = new LoginPolicy(1, Duration.ofMinutes(15), Duration.ofMinutes(15), 0);
        Fixture lockedReal = new Fixture(lockAtOne);
        lockedReal.login("demo", "wrong");
        Fixture lockedGhost = new Fixture(lockAtOne);
        lockedGhost.login("does-not-exist", "wrong");
        check("a locked real account and a locked unknown name read identically",
                lockedReal.login("demo", "x").userMessage().equals(lockedGhost.login("does-not-exist", "x").userMessage()));

        Fixture f = new Fixture(LoginPolicy.DEFAULT);
        String disabledMessage = f.login("terminated.user", "whatever").userMessage();
        String lockedMessage = lockedReal.login("demo", "x").userMessage();
        check("a disabled account reads the same as a locked one", disabledMessage.equals(lockedMessage));
        check("the lock wording does not confirm that the account exists",
                !disabledMessage.toLowerCase().contains("exists"));
    }

    private static void renderedOutputDoesNotLeakAccountExistence() {
        Fixture real = new Fixture(LoginPolicy.DEFAULT);
        Fixture ghost = new Fixture(LoginPolicy.DEFAULT);
        LoginResult knownAccount = real.login("demo", "wrong");
        LoginResult unknownName = ghost.login("nobody.here", "wrong");

        check("the result objects do carry the audit-only existence flag",
                ((LoginResult.InvalidCredentials) knownAccount).accountExists()
                        && !((LoginResult.InvalidCredentials) unknownName).accountExists());
        String renderedKnown = PortalAuthApp.render(knownAccount);
        String renderedGhost = PortalAuthApp.render(unknownName);
        check("the rendered terminal output is identical for a real account and an unknown name",
                renderedKnown.equals(renderedGhost));
        check("the countdown is actually printed, so the renderer is not just printing nothing",
                renderedKnown.contains("attempts remaining"));
        check("the rendered output names no username", !renderedKnown.contains("demo"));

        LoginPolicy lockAtOne = new LoginPolicy(1, Duration.ofMinutes(15), Duration.ofMinutes(15), 0);
        Fixture lockedReal = new Fixture(lockAtOne);
        lockedReal.login("demo", "wrong");
        Fixture lockedGhost = new Fixture(lockAtOne);
        lockedGhost.login("nobody.here", "wrong");
        String lockedKnown = PortalAuthApp.render(lockedReal.login("demo", "x"));
        String lockedGhostOut = PortalAuthApp.render(lockedGhost.login("nobody.here", "x"));
        check("locked output is identical too, with no countdown to tell the two apart",
                lockedKnown.equals(lockedGhostOut) && !lockedKnown.contains("attempts remaining"));
    }

    private static void auditCarriesNoSecrets() {
        CapturingAudit audit = new CapturingAudit();
        Fixture f = new Fixture(LoginPolicy.DEFAULT, audit);
        String[] guesses = {"Correct-Horse-9", "s3cr3t-guess", "hunter2", "admin123"};
        for (String guess : guesses) {
            f.login("demo", guess);
        }
        f.login("demo", "Correct-Horse-9");
        f.login("terminated.user", "hunter2");
        f.login("nobody", "admin123");

        String dump = audit.dump();
        for (String guess : guesses) {
            check("the audit log never contains the candidate password '" + guess + "'", !dump.contains(guess));
        }
        check("the audit log never contains a stored digest", !dump.contains("pbkdf2"));
        check("the audit log contains no long base64 run (salt or hash)",
                !dump.matches("(?s).*[A-Za-z0-9+/]{40,}=?.*"));
        check("the audit trail covers every attempt", audit.events.size() >= guesses.length + 3);
    }

    private static void auditCannotBeForgedByControlCharacters() {
        CapturingAudit audit = new CapturingAudit();
        Fixture f = new Fixture(LoginPolicy.DEFAULT, audit);
        f.login("victim\r\nFAKE LOGIN_SUCCESS admin", "wrong");
        f.login("tab\there", "wrong");
        f.login("esc\u001B[31muser", "wrong");
        f.login("victim\" type=LOGIN_SUCCESS admin", "wrong");

        String dump = audit.dump();
        check("no carriage return reaches the log", !dump.contains("\r"));
        check("no escape sequence reaches the log", !dump.contains("\u001B"));
        check("no tab reaches the log", !dump.contains("\t"));
        check("one audit event still means exactly one log line",
                dump.split("\n", -1).length == audit.events.size());
        check("the injected quote is escaped", dump.contains("\\\""));

        /* The real property is field-level: the type field must stay whatever the module recorded,
           however hostile the username is. A naive substring search over the raw line is not the
           guarantee -- quoting is what lets a reader recover the boundary, so assert that instead. */
        boolean fieldsIntact = true;
        for (String line : dump.split("\n")) {
            int at = line.indexOf("type=");
            int end = line.indexOf(' ', at);
            String typeField = line.substring(at + "type=".length(), end < 0 ? line.length() : end);
            if (!isKnownType(typeField)) {
                fieldsIntact = false;
            }
        }
        check("every line's type field is a real event type, never an injected one", fieldsIntact);
        check("no line reports a forged success",
                dump.lines().noneMatch(line -> isTypeField(line, AuditEvent.Type.LOGIN_SUCCESS)));

        StringBuilder huge = new StringBuilder();
        for (int i = 0; i < 5_000; i++) {
            huge.append('x');
        }
        f.login(huge.toString(), "wrong");
        int longest = 0;
        for (String line : audit.dump().split("\n")) {
            longest = Math.max(longest, line.length());
        }
        check("an oversized username cannot produce an oversized log line", longest < 300);
    }

    private static boolean isKnownType(String name) {
        for (AuditEvent.Type type : AuditEvent.Type.values()) {
            if (type.name().equals(name)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isTypeField(String line, AuditEvent.Type type) {
        int at = line.indexOf("type=");
        if (at < 0) {
            return false;
        }
        int end = line.indexOf(' ', at);
        return line.substring(at + "type=".length(), end < 0 ? line.length() : end).equals(type.name());
    }

    private static void noStoreLookupWhileLocked() {
        Fixture f = new Fixture(new LoginPolicy(2, Duration.ofMinutes(15), Duration.ofMinutes(15), 0));
        f.login("demo", "wrong-1");
        f.login("demo", "wrong-2");
        int lookupsBefore = f.store.lookups.get();
        for (int extra = 0; extra < 100; extra++) {
            f.login("demo", "guess-" + extra);
        }
        check("guesses against a locked account never reach the records store",
                f.store.lookups.get() == lookupsBefore);
    }

    private static void rejectsAbsurdIterationCountFast() {
        Fixture f = new Fixture(LoginPolicy.DEFAULT);
        /* A corrupt or tampered record claiming two billion iterations must not turn every later login
           for that account into a hang. */
        f.store.save(new Credential("demo", "Demo Employee",
                "$pbkdf2-sha256$2000000000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                UserStatus.ACTIVE, Instant.now()));
        long start = System.nanoTime();
        LoginResult result = f.login("demo", "Correct-Horse-9");
        long millis = (System.nanoTime() - start) / 1_000_000;
        check("a record with an absurd iteration count is refused rather than honoured",
                result.outcome() == LoginResult.Outcome.INVALID_CREDENTIALS);
        check("refusing it is immediate (took " + millis + "ms)", millis < 2_000);
    }

    private static void wipesCallerPasswordArray() {
        Fixture f = new Fixture(LoginPolicy.DEFAULT);

        char[] wrongGuess = PasswordHasher.toChars("not-the-password");
        check("a failed login is denied", !f.auth.authenticate("demo", wrongGuess).granted());
        check("the candidate password is wiped from the caller's array after a failure",
                isBlank(wrongGuess));

        char[] rightGuess = PasswordHasher.toChars("Correct-Horse-9");
        check("the following correct login succeeds", f.auth.authenticate("demo", rightGuess).granted());
        check("the candidate password is wiped after a success", isBlank(rightGuess));

        char[] empty = new char[0];
        check("a zero-length candidate is denied", !f.auth.authenticate("demo", empty).granted());
        check("a null username is denied", !f.auth.authenticate(null, "Correct-Horse-9").granted());
        check("a blank username is denied", !f.auth.authenticate("   ", "Correct-Horse-9").granted());
    }

    private static boolean isBlank(char[] chars) {
        for (char c : chars) {
            if (c != '\0') {
                return false;
            }
        }
        return true;
    }

    // -------------------------------------------------------------- concurrency

    private static void concurrentFailuresPerAccount() throws Exception {
        LoginPolicy policy = new LoginPolicy(5, Duration.ofMinutes(15), Duration.ofMinutes(15), 0);
        Fixture f = new Fixture(policy);
        int threads = 16;
        int perThread = 25;
        AtomicInteger denials = new AtomicInteger();
        AtomicInteger escapes = new AtomicInteger();
        runConcurrently(threads, t -> {
            for (int i = 0; i < perThread; i++) {
                LoginResult result = f.auth.authenticate("contended", "concurrent-wrong-" + t + '-' + i);
                if (!result.granted()) {
                    denials.incrementAndGet();
                }
                if (result.outcome() == LoginResult.Outcome.INVALID_CREDENTIALS
                        && f.tracker.locksTaken("contended") > 1) {
                    escapes.incrementAndGet();
                }
            }
        });
        check("every concurrent attempt was denied", denials.get() == threads * perThread);
        check("no concurrent attempt ever authenticated",
                !f.audit.containsType(AuditEvent.Type.LOGIN_SUCCESS));
        check("the threshold engaged the lock exactly once under contention",
                f.tracker.locksTaken("contended") == 1);
        check("no attempt was admitted as a plain failure after the lock engaged", escapes.get() == 0);
        int counted = f.tracker.failedAttempts("contended");
        check("the count stopped at the threshold plus at most one late arrival per thread ("
                + counted + ")", counted >= 5 && counted <= 5 + threads);
    }

    private static void concurrentDistinctAccounts() throws Exception {
        Fixture f = new Fixture(LoginPolicy.DEFAULT);
        int threads = 8;
        int perThread = 20;
        runConcurrently(threads, t -> {
            for (int i = 0; i < perThread; i++) {
                f.tracker.registerFailure("user-" + t);
            }
        });
        boolean allExact = true;
        for (int t = 0; t < threads; t++) {
            if (f.tracker.failedAttempts("user-" + t) != perThread) {
                allExact = false;
            }
        }
        check("per-account counters do not lose updates under contention", allExact);
        check("counters stay isolated per account", f.tracker.trackedAccounts() == threads);
    }

    private static void memoryBoundedUnderUsernameFlood() {
        LoginAttemptTracker tracker = new LoginAttemptTracker(
                new LoginPolicy(5, Duration.ofMinutes(15), Duration.ofMinutes(15), 0));
        int flood = LoginAttemptTracker.MAX_TRACKED_ACCOUNTS + 5_000;
        for (int i = 0; i < flood; i++) {
            tracker.registerFailure("spray-" + i);
        }
        check("a username spray does not grow attempt state without bound",
                tracker.trackedAccounts() <= LoginAttemptTracker.MAX_TRACKED_ACCOUNTS);
        check("state is pruned, not silently refused at the cap",
                tracker.trackedAccounts() > 0 && tracker.trackedAccounts() < flood);
    }

    private static void unknownUserTimingParity() throws Exception {
        int iterations = 60_000;
        PasswordHasher hasher = new PasswordHasher(iterations);
        CredentialStore store = InMemoryCredentialStore.of(new Credential("real.user", "Real",
                hasher.hash(PasswordHasher.toChars("a-password-that-is-not-guessed")),
                UserStatus.ACTIVE, Instant.now()));
        LoginAttemptTracker tracker = new LoginAttemptTracker(new LoginPolicy(100_000,
                Duration.ofHours(1), Duration.ofMinutes(15), 0));
        AuthenticationService auth = new AuthenticationService(store, hasher, tracker, AuditLog.none());

        /* Interleaved so that drift in machine load hits both samples equally, and medians so a single
           hiccup cannot decide the verdict. If a real user's failure were markedly slower than a
           non-existent user's, response time alone would name a valid account. */
        List<Long> real = new ArrayList<>();
        List<Long> ghost = new ArrayList<>();
        for (int round = 0; round < 9; round++) {
            real.add(time(auth, "real.user", "wrong-" + round));
            ghost.add(time(auth, "no.such.employee", "wrong-" + round));
        }
        long medianReal = median(real);
        long medianGhost = median(ghost);
        double ratio = (double) medianReal / (double) medianGhost;
        System.out.println("  timing: real-user failure median=" + medianReal + "ms, unknown-user"
                + " failure median=" + medianGhost + "ms, ratio="
                + String.format(Locale.ROOT, "%.2f", ratio));
        check("an unknown username is answered in comparable time to a real one (no user enumeration)",
                ratio > 0.5 && ratio < 2.0);
    }

    private static long time(AuthenticationService auth, String username, String password) {
        long start = System.nanoTime();
        auth.authenticate(username, password);
        return Math.max(1, (System.nanoTime() - start) / 1_000_000);
    }

    private static long median(List<Long> values) {
        List<Long> sorted = new ArrayList<>(values);
        Collections.sort(sorted);
        return sorted.get(sorted.size() / 2);
    }

    private static void runConcurrently(int threads, ThreadBody body) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            final int tid = t;
            futures.add(pool.submit(() -> {
                ready.countDown();
                try {
                    go.await(30, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                body.run(tid);
            }));
        }
        ready.await(30, TimeUnit.SECONDS);
        go.countDown();
        for (Future<?> future : futures) {
            future.get(120, TimeUnit.SECONDS);
        }
        pool.shutdownNow();
    }

    interface ThreadBody {
        void run(int threadId);
    }

    // ------------------------------------------------------------------ fixtures

    static final class MutableClock extends Clock {
        private Instant now = Instant.parse("2026-09-05T09:00:00Z");

        @Override
        public synchronized Instant instant() {
            return now;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        synchronized void advance(Duration amount) {
            now = now.plus(amount);
        }

        synchronized void setInstant(Instant instant) {
            now = instant;
        }
    }

    static final class RecordingStore implements CredentialStore {
        private final InMemoryCredentialStore delegate = new InMemoryCredentialStore();
        final AtomicInteger lookups = new AtomicInteger();

        RecordingStore(Credential... seed) {
            for (Credential credential : seed) {
                delegate.save(credential);
            }
        }

        @Override
        public Optional<Credential> findByUsername(String username) {
            lookups.incrementAndGet();
            return delegate.findByUsername(username);
        }

        @Override
        public void save(Credential credential) {
            delegate.save(credential);
        }

        @Override
        public boolean exists(String username) {
            return delegate.exists(username);
        }
    }

    static final class CapturingAudit implements AuditLog {
        final List<String> events = Collections.synchronizedList(new ArrayList<>());

        @Override
        public void record(AuditEvent event) {
            events.add(event.toString());
        }

        String dump() {
            synchronized (events) {
                return String.join("\n", events);
            }
        }

        boolean containsType(AuditEvent.Type type) {
            return contains(type.name(), null);
        }

        boolean contains(AuditEvent.Type type, String fragment) {
            return contains(type.name(), fragment);
        }

        private boolean contains(String needle, String fragment) {
            synchronized (events) {
                for (String event : events) {
                    if (event.contains(needle) && (fragment == null || event.contains(fragment))) {
                        return true;
                    }
                }
            }
            return false;
        }
    }

    static final class Fixture {
        final MutableClock clock = new MutableClock();
        final RecordingStore store;
        final LoginAttemptTracker tracker;
        final CapturingAudit audit;
        final AuthenticationService auth;
        final AdminService admin;

        Fixture(LoginPolicy policy) {
            this(policy, null);
        }

        Fixture(LoginPolicy policy, CapturingAudit auditSink) {
            PasswordHasher hasher = new PasswordHasher(FAST_ITERATIONS);
            this.store = new RecordingStore(
                    new Credential("demo", "Demo Employee",
                            hasher.hash(PasswordHasher.toChars("Correct-Horse-9")), UserStatus.ACTIVE,
                            clock.instant()),
                    new Credential("jchen", "Jordan Chen",
                            hasher.hash(PasswordHasher.toChars("another-secret-passphrase")), UserStatus.ACTIVE,
                            clock.instant()),
                    new Credential("terminated.user", "Ex Employee",
                            hasher.hash(PasswordHasher.toChars("left-the-company")), UserStatus.DISABLED,
                            clock.instant()));
            this.tracker = new LoginAttemptTracker(policy, clock);
            this.audit = auditSink == null ? new CapturingAudit() : auditSink;
            this.auth = new AuthenticationService(store, hasher, tracker, this.audit);
            this.admin = new AdminService(store, hasher, tracker, this.audit);
        }

        LoginResult login(String username, String password) {
            return auth.authenticate(username, password);
        }
    }

    // --------------------------------------------------------------- assertions

    private static void check(String what, boolean condition) {
        if (condition) {
            passed++;
            System.out.println("ok   " + what);
        } else {
            fail(what);
        }
    }

    private static void fail(String what) {
        FAILURES.add(what);
        System.out.println("FAIL " + what);
    }

    private static void expectThrows(String what, Runnable action) {
        try {
            action.run();
            fail(what + " (nothing thrown)");
        } catch (IllegalArgumentException expected) {
            passed++;
            System.out.println("ok   " + what);
        }
    }

    private AuthVerification() {
    }
}
