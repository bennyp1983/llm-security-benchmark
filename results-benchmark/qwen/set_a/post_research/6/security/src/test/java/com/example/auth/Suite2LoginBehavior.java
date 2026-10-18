package com.example.auth;

import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.UnaryOperator;

/**
 * Suite 2: what an attacker observes from the login endpoint. Every denial must look the same, the
 * per-account lock must not be usable against a legitimate user by someone else's traffic, the
 * per-source budget must actually engage and actually expire, and no denial may leak which field
 * was wrong.
 *
 * <p>Runs with the real iteration count, because a guard that only holds at a fake cost is not a
 * guard. Each attempt costs a derivation plus the latency floor, so the suite is timed in seconds.
 */
public final class Suite2LoginBehavior {

    private static final int ITERATIONS = AuthConfig.MIN_PBKDF2_ITERATIONS;

    private static final String SRC_A = "203.0.113.7";
    private static final String SRC_B = "198.51.100.23";
    private static final String SRC_C = "192.0.2.44";

    /** Smallest legal per-source budget (the configuration bounds reject anything lower). */
    private static final int SOURCE_CAP = 10;

    public static void main(String[] args) throws Exception {
        try (Fixture fx = new Fixture("suite2")) {
            fx.withKeystore(Fixture.PEPPER, AuthTestKeys.STORE_PASSWORD);
            fx.withStandardAccounts(ITERATIONS);
            happyPath(fx);
            uniformDenials(fx);
            accountLockout(fx);
            lockIsolation(fx);
            failureStreakReset(fx);
            sourceBudget(fx);
            missingSource(fx);
            tokenAndCookieShape(fx);
            noOrphanedIdentifierSurvivesADeniedSuccess(fx);
            anAuditOutageNeverLocksOutAGoodPassword(fx);
            aRefusalThatCouldNotBeLoggedChargesTheAccountOnce(fx);
            anAuditOutageStillCostsTheAttackerTheirBudget(fx);
            oversizedNameCostsTheSameAsEveryOtherRefusal(fx);
        }
        Check.summary("suite2-login-behavior");
    }

    private static AuthenticationService build(Fixture fx, UnaryOperator<AuthConfig.Builder> tweak)
            throws Exception {
        AuthConfig.Builder builder = tweak == null ? fx.config(ITERATIONS) : tweak.apply(fx.config(ITERATIONS));
        return AuthenticationService.builder().config(builder.build()).timeSource(fx.time).build();
    }

    // ------------------------------------------------------------------ happy path

    private static void happyPath(Fixture fx) throws Exception {
        try (AuthenticationService service = build(fx, null)) {
            AuthResult good = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC_A);
            Check.ok("known-good credentials succeed", good.isSuccess());
            Check.ok("a session identifier is issued", good.sessionId() != null);
            Check.ok("the session is valid server-side", service.isSessionValid(good.sessionId()));
            Check.eq("no retry hint on success", 0, Integer.valueOf(good.retryAfterSeconds()));

            AuthResult wrongField = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_B, SRC_A);
            Check.ok("a wrong password is denied", !wrongField.isSuccess());

            Check.eq("one event per attempt", 2, Integer.valueOf(fx.logLines().size()));
            Check.eq("persisted count matches the file", 2L, Long.valueOf(service.persistedEventCount()));
            Check.contains("success is logged as login_success", fx.logLines().get(0), "type=login_success");
            Check.contains("failure is logged as login_failure", fx.logLines().get(1), "type=login_failure");
            Check.contains("the account is attributed", fx.logLines().get(0), "account_present=true");
            Check.contains("a wrong password still says the account exists",
                    fx.logLines().get(1), "account_present=true");

            service.revokeSession(good.sessionId());
            Check.ok("revocation takes effect", !service.isSessionValid(good.sessionId()));
            Check.ok("revoking twice is harmless", !service.isSessionValid(good.sessionId()));
            Check.ok("an unknown identifier is never valid",
                    !service.isSessionValid("0123456789abcdef0123456789abcdef"));
            Check.ok("a null identifier is never valid", !service.isSessionValid(null));
        }
    }

    // ------------------------------------------------------------------ uniform denials

    private static void uniformDenials(Fixture fx) throws Exception {
        try (AuthenticationService service = build(fx, null)) {
            int before = fx.logLines().size();
            List<AuthResult> denials = new ArrayList<>();
            denials.add(fx.tryLogin(service, Fixture.USER_ALICE, "Wrong-Password-99", SRC_A));
            denials.add(fx.tryLogin(service, "no-such-account", Fixture.PASSWORD_A, SRC_A));
            denials.add(fx.tryLogin(service, "bad name!", Fixture.PASSWORD_A, SRC_A));
            denials.add(fx.tryLogin(service, "alice\r", Fixture.PASSWORD_A, SRC_A));
            denials.add(fx.tryLogin(service, Fixture.USER_ALICE, "Tiny-1", SRC_A));
            denials.add(fx.tryLogin(service, Fixture.USER_ALICE, "Fresh\tIngress-21", SRC_A));
            denials.add(fx.tryLogin(service, Fixture.USER_ALICE, "Fresh-Ingress-21\u00e9\uDB3D", SRC_A));

            Set<String> texts = new HashSet<>();
            for (int i = 0; i < denials.size(); i++) {
                AuthResult r = denials.get(i);
                Check.ok("denial " + i + " is not a success", !r.isSuccess());
                Check.eq("denial " + i + " carries no retry hint", 0, Integer.valueOf(r.retryAfterSeconds()));
                Check.ok("denial " + i + " issues no session", r.sessionId() == null);
                texts.add(r.message());
            }
            // The whole point of the rule: one text for every way an attempt can fail on credentials.
            Check.eq("every credential failure returns one identical message", 1, Integer.valueOf(texts.size()));
            Check.eq("that message is the generic denial", AuthResult.DENIAL_MESSAGE, denials.get(0).message());
            Check.ok("the denial names neither field's status",
                    !denials.get(0).message().toLowerCase(java.util.Locale.ROOT).contains("exist")
                            && !denials.get(0).message().toLowerCase(java.util.Locale.ROOT).contains("unknown"));

            List<String> wrote = fx.logLines().subList(before, fx.logLines().size());
            Check.eq("one event per denied attempt", denials.size(), Integer.valueOf(wrote.size()));
            for (String line : wrote) {
                Check.contains("a denied attempt is recorded as a failure", line, "type=login_failure");
            }
            // An unknown account must be distinguishable in the log (for review) but not to the caller.
            Check.ok("the log separates an unknown account from a wrong password",
                    fx.logText().contains("account_present=false") && fx.logText().contains("account_present=true"));
        }
    }

    // ------------------------------------------------------------------ lockout

    private static void accountLockout(Fixture fx) throws Exception {
        try (AuthenticationService service = build(fx, b -> b.accountLockAfter(3).sourceMaxAttempts(200))) {
            AuthResult first = fx.tryLogin(service, Fixture.USER_BOB, "Wrong-Password-99", SRC_A);
            AuthResult second = fx.tryLogin(service, Fixture.USER_BOB, "Wrong-Password-99", SRC_A);
            AuthResult third = fx.tryLogin(service, Fixture.USER_BOB, "Wrong-Password-99", SRC_A);
            Check.ok("the first two failures are plain denials",
                    !first.isSuccess() && !second.isSuccess());
            // The failure that trips the lock must be indistinguishable from its predecessors, or the
            // attacker learns the exact threshold.
            Check.eq("the attempt that trips the lock carries no hint", 0, Integer.valueOf(third.retryAfterSeconds()));
            Check.eq("the attempt that trips the lock uses the denial text",
                    AuthResult.DENIAL_MESSAGE, third.message());

            AuthResult inside = fx.tryLogin(service, Fixture.USER_BOB, Fixture.PASSWORD_B, SRC_A);
            Check.ok("the correct password is refused while locked", !inside.isSuccess());
            Check.ok("the locked refusal still carries no session", inside.sessionId() == null);
            Check.ok("the locked refusal carries a retry hint", inside.retryAfterSeconds() > 0);
            Check.eq("a locked attempt uses the same denial text", AuthResult.DENIAL_MESSAGE, inside.message());
            Check.lacks("the locked refusal does not name the account", inside.message(), Fixture.USER_BOB);

            fx.time.advanceMillis(600_001L);
            AuthResult afterWindow = fx.tryLogin(service, Fixture.USER_BOB, Fixture.PASSWORD_B, SRC_A);
            Check.ok("the lock expires and the correct password works", afterWindow.isSuccess());
            Check.ok("a throttled attempt is recorded", fx.logText().contains("type=login_throttled"));
        }
    }

    // ------------------------------------------------------------------ lockout isolation

    private static void lockIsolation(Fixture fx) throws Exception {
        try (AuthenticationService service = build(fx, b -> b.accountLockAfter(3).sourceMaxAttempts(200))) {
            for (int i = 0; i < 6; i++) {
                fx.tryLogin(service, Fixture.USER_BOB, "Wrong-Password-99", SRC_A);
            }
            Check.ok("bob is locked out by his own failures",
                    !fx.tryLogin(service, Fixture.USER_BOB, Fixture.PASSWORD_B, SRC_A).isSuccess());

            // Someone else's failures must not decide this principal's outcome...
            AuthResult other = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC_A);
            Check.ok("another account is unaffected by bob's lock", other.isSuccess());

            // ...and traffic from another source must not be able to exhaust bob's budget faster.
            AuthResult fromElsewhere = fx.tryLogin(service, Fixture.USER_BOB, Fixture.PASSWORD_B, SRC_B);
            Check.ok("the lock follows the account, not the source", !fromElsewhere.isSuccess());

            // Flood of unknown names: they cannot lock a real account and must not stop a real login.
            for (int i = 0; i < 20; i++) {
                AuthResult noise = fx.tryLogin(service, "ghost-" + i, "Wrong-Password-99", SRC_C);
                if (noise.isSuccess()) {
                    Check.ok("an unknown name must never authenticate", false);
                    return;
                }
            }
            AuthResult stillFine = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC_C);
            Check.ok("noise against unknown names does not lock a real account", stillFine.isSuccess());
        }
    }

    private static void failureStreakReset(Fixture fx) throws Exception {
        try (AuthenticationService service = build(fx, b -> b.accountLockAfter(3).sourceMaxAttempts(200))) {
            fx.tryLogin(service, Fixture.USER_BOB, "Wrong-Password-99", SRC_A);
            fx.tryLogin(service, Fixture.USER_BOB, "Wrong-Password-99", SRC_A);
            Check.ok("a success clears the failure streak",
                    fx.tryLogin(service, Fixture.USER_BOB, Fixture.PASSWORD_B, SRC_A).isSuccess());
            for (int i = 0; i < 2; i++) {
                AuthResult again = fx.tryLogin(service, Fixture.USER_BOB, "Wrong-Password-99", SRC_A);
                Check.eq("the streak restarted, so attempt " + (i + 1) + " is not throttled",
                        0, Integer.valueOf(again.retryAfterSeconds()));
            }
            Check.ok("the account is still usable for the real user",
                    fx.tryLogin(service, Fixture.USER_BOB, Fixture.PASSWORD_B, SRC_A).isSuccess());
        }
    }

    // ------------------------------------------------------------------ per-source budget

    private static void sourceBudget(Fixture fx) throws Exception {
        UnaryOperator<AuthConfig.Builder> tight = b -> b.accountLockAfter(3)
                .sourceMaxAttempts(SOURCE_CAP).sourceWindowSeconds(600).sourceBlockSeconds(600);
        try (AuthenticationService service = build(fx, tight)) {
            int before = fx.logLines().size();
            for (int i = 0; i < SOURCE_CAP; i++) {
                AuthResult r = fx.tryLogin(service, "quiet-observer-" + i, "Wrong-Password-99", SRC_B);
                Check.eq("attempt " + (i + 1) + " from the source is within budget",
                        0, Integer.valueOf(r.retryAfterSeconds()));
            }
            // The over-budget attempt carries a real password for a real account: if the budget did
            // not engage, this would succeed, so the assertion below cannot pass vacuously.
            AuthResult over = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC_B);
            Check.ok("the attempt over budget is refused even with a valid password", !over.isSuccess());
            Check.ok("the refusal says how long to wait", over.retryAfterSeconds() > 0);
            Check.eq("a rate-limited attempt uses the same denial text",
                    AuthResult.DENIAL_MESSAGE, over.message());
            Check.lacks("the rate-limit refusal does not name the source", over.message(), SRC_B);
            Check.ok("the refusal is a legitimate user's outcome too: no session",
                    over.sessionId() == null);

            AuthResult elsewhere = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC_C);
            Check.ok("another source keeps its own budget", elsewhere.isSuccess());

            Check.eq("each attempt wrote exactly one event", SOURCE_CAP + 2,
                    Integer.valueOf(fx.logLines().size() - before));
            Check.contains("the blocked attempt is typed as throttled",
                    String.join("\n", fx.logLines().subList(before, fx.logLines().size())), "type=login_throttled");

            // Recovery, not a latch: the block must lift on its own.
            fx.time.advanceMillis(601_000L);
            AuthResult recovered = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC_B);
            Check.ok("the source block expires instead of latching", recovered.isSuccess());
        }
    }

    // ------------------------------------------------------------------ missing source

    private static void missingSource(Fixture fx) throws Exception {
        UnaryOperator<AuthConfig.Builder> tight = b -> b.accountLockAfter(3)
                .sourceMaxAttempts(SOURCE_CAP).sourceWindowSeconds(600).sourceBlockSeconds(600);
        try (AuthenticationService service = build(fx, tight)) {
            int before = fx.logLines().size();
            String[] unusable = {null, "", "not-an-address", "203.0.113.7 ", "localhost"};
            Set<String> texts = new HashSet<>();
            for (int i = 0; i < unusable.length; i++) {
                AuthResult r = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, unusable[i]);
                Check.ok("attempt " + i + " with no usable source is denied", !r.isSuccess());
                Check.ok("attempt " + i + " issues no session", r.sessionId() == null);
                texts.add(r.message());
            }
            Check.eq("every unusable-source attempt says the same thing", 1, Integer.valueOf(texts.size()));
            Check.eq("and that is the source-required text, not the credential denial",
                    AuthResult.SOURCE_REQUIRED_MESSAGE, texts.iterator().next());
            Check.ok("the source text reveals nothing about the account",
                    !texts.iterator().next().toLowerCase(java.util.Locale.ROOT).contains("password"));

            Check.eq("one event per unusable attempt", unusable.length, Integer.valueOf(fx.logLines().size() - before));
            for (String line : fx.logLines().subList(before, fx.logLines().size())) {
                Check.contains("an unusable-source attempt is typed distinctly",
                        line, "type=login_rejected_no_source");
            }
            // Unusable-source attempts are refused before any bookkeeping, so they must not have
            // consumed the budget of a real address or charged anyone's failure streak.
            AuthResult real = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC_C);
            Check.ok("an unusable source neither consumes nor protects a real budget", real.isSuccess());
        }
    }

    // ------------------------------------------------------------------ tokens and cookies

    private static void tokenAndCookieShape(Fixture fx) throws Exception {
        try (AuthenticationService service = build(fx, null)) {
            AuthResult one = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC_A);
            AuthResult two = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC_A);
            String token = one.sessionId();
            Check.eq("token length", 32, Integer.valueOf(token.length()));
            Check.ok("token is lower-case hex", token.matches("[0-9a-f]{32}"));
            Check.ok("successive tokens differ for the same account", !token.equals(two.sessionId()));
            Check.ok("both sessions are independently valid",
                    service.isSessionValid(token) && service.isSessionValid(two.sessionId()));
            Check.lacks("the result's own rendering omits the token", one.toString(), token);
            Check.lacksAllNonEmpty("no event line carries the token", fx.logText(), token,
                    Fixture.PASSWORD_A, Fixture.USER_ALICE);

            String cookie = service.sessionCookieFor(one, "auth-session", "/portal", true);
            Check.ok("a cookie is produced over TLS", cookie != null);
            Check.contains("cookie carries the token", cookie, token);
            Check.contains("cookie is HttpOnly", cookie, "HttpOnly");
            Check.contains("cookie is Secure", cookie, "Secure");
            Check.contains("cookie is SameSite=Strict", cookie, "SameSite=Strict");
            Check.contains("cookie is scoped to the path", cookie, "Path=/portal");
            Check.contains("cookie expires with the session ttl", cookie, "Max-Age=" + service.sessionTtlSeconds());
            Check.ok("no cookie is emitted over plaintext",
                    service.sessionCookieFor(one, "auth-session", "/portal", false) == null);
            Check.ok("a name that cannot be a cookie name is refused",
                    service.sessionCookieFor(one, "bad name", "/portal", true) == null);
            Check.ok("a path that is not a path is refused",
                    service.sessionCookieFor(one, "auth-session", "portal", true) == null);
            Check.ok("a denial yields no cookie",
                    service.sessionCookieFor(fx.tryLogin(service, Fixture.USER_ALICE, "Wrong-Password-99", SRC_A),
                            "auth-session", "/portal", true) == null);
        }
    }

    // ------------------------------------------------------------------ orphaned identifiers

    /**
     * An identifier must never exist in the table unless the caller received it. The failure that
     * creates one is a success whose event could not be persisted: the attempt is refused, so nothing
     * upstream knows to sign it out, and the leftover authenticates as that account until the TTL.
     */
    private static void noOrphanedIdentifierSurvivesADeniedSuccess(Fixture fx) throws Exception {
        try (AuthenticationService service = build(fx, null)) {
            Check.eq("the table starts empty", 0, Integer.valueOf(service.activeSessionCount()));

            AuthResult good = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC_A);
            Check.ok("the control login succeeds", good.isSuccess());
            Check.eq("a granted login leaves exactly one live identifier", 1,
                    Integer.valueOf(service.activeSessionCount()));

            // The log becomes unwritable after the identifier is issued, so the success is denied.
            service.revokeSession(good.sessionId());
            Files.delete(fx.logFile);
            AuthResult denied = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC_A);
            Check.ok("the attempt is refused when its event cannot be persisted", !denied.isSuccess());
            Check.ok("and no identifier is handed to the caller", denied.sessionId() == null);
            Check.eq("the refused attempt left no live identifier behind", 0,
                    Integer.valueOf(service.activeSessionCount()));

            // Recovery, and no accounting drift. The logger never creates the file on reopen, so the
            // operator-shaped recovery is to put a private file back at that name.
            Files.createFile(fx.logFile);
            Fixture.restrict(fx.logFile, Check.OWNER_ONLY);
            AuthResult recovered = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC_A);
            Check.ok("authentication recovers once the log is writable again", recovered.isSuccess());
            Check.eq("exactly the granted identifiers are live", 1,
                    Integer.valueOf(service.activeSessionCount()));
            // selfCheck keeps naming the hole the denied attempt left, which is correct and is what
            // suite 4 pins down. What must not remain is any *other* complaint - a stuck guard, a
            // closed log, a lost credential store.
            List<String> afterRecovery = service.selfCheck();
            Check.eq("only the historical unsaved count is reported", 1, Integer.valueOf(afterRecovery.size()));
            Check.contains("and it names unsaved events, not a stuck condition", afterRecovery.get(0),
                    "could not be persisted");
        } catch (IOException e) {
            Check.note("orphan probe skipped on this filesystem: " + e.getClass().getSimpleName());
        }
    }

    /**
     * An audit outage must cost the operator an audit gap and the user a retry - never the user's
     * account.
     *
     * <p>Every attempt is refused while the log cannot be written, and the intuitive bookkeeping is
     * "a refused attempt is a failed attempt", so charge it to the account. That is the bug: the
     * catch block is reached from the <em>success</em> path, so a full file system converts a
     * correct password into a consecutive failure, and after {@code accountLockAfter} of them the
     * account is locked by the service's own storage failure. The lock then outlives the outage - it
     * is timed, not cleared by recovery - so fixing the disk would leave every legitimate user locked
     * out anyway. Rule 3 forbids exactly this: a limit that locks out a legitimate user.
     *
     * <p>A wrong password is still charged, because the mismatch path charges it before recording;
     * that half is asserted here too, so this guard cannot be satisfied by switching the lock off.
     */
    private static void anAuditOutageNeverLocksOutAGoodPassword(Fixture fx) throws Exception {
        UnaryOperator<AuthConfig.Builder> lockAfterThree =
                b -> b.accountLockAfter(3).sourceMaxAttempts(1000);
        try (AuthenticationService service = build(fx, lockAfterThree)) {
            AuthResult control = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC_A);
            Check.ok("the control login succeeds", control.isSuccess());
            service.revokeSession(control.sessionId());

            Files.delete(fx.logFile);
            for (int i = 0; i < 5; i++) {
                AuthResult duringOutage = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC_A);
                Check.ok("the correct password is refused while the log cannot be written (attempt "
                        + (i + 1) + ")", !duringOutage.isSuccess());
                Check.ok("and no session is handed over", duringOutage.sessionId() == null);
            }
            // The hole is still accounted for - refusing to charge the account must not mean the
            // gap goes unnoticed.
            Check.contains("the deployment check still names the unsaved events",
                    String.join(" | ", service.selfCheck()), "could not be persisted");

            Files.createFile(fx.logFile);
            Fixture.restrict(fx.logFile, Check.OWNER_ONLY);
            AuthResult afterOutage = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC_A);
            Check.ok("the correct password works again the moment the log does, with no lock in between",
                    afterOutage.isSuccess());
            Check.ok("and it carries no retry hint from a lock that was never earned",
                    afterOutage.retryAfterSeconds() == 0);
        } finally {
            if (!Files.exists(fx.logFile)) {
                Files.createFile(fx.logFile);
                Fixture.restrict(fx.logFile, Check.OWNER_ONLY);
            }
        }

        // The other half: the lock must still engage for real failures during the same condition.
        // Three wrong passwords are charged before the record is attempted, so they count.
        try (AuthenticationService service = build(fx, lockAfterThree)) {
            Files.delete(fx.logFile);
            for (int i = 0; i < 3; i++) {
                Check.ok("a wrong password is still refused during the outage (attempt " + (i + 1) + ")",
                        !fx.tryLogin(service, Fixture.USER_BOB, "Wrong-Password-99", SRC_A).isSuccess());
            }
            Files.createFile(fx.logFile);
            Fixture.restrict(fx.logFile, Check.OWNER_ONLY);
            AuthResult locked = fx.tryLogin(service, Fixture.USER_BOB, Fixture.PASSWORD_B, SRC_A);
            Check.ok("three genuine failures during the outage still lock the account", !locked.isSuccess());
            Check.ok("and the lock is real, not merely a refusal", locked.retryAfterSeconds() > 0);
        }
    }

    /**
     * A refusal that could not be written down is charged to the account <em>once</em>, by the path
     * that earned it.
     *
     * <p>{@link #anAuditOutageNeverLocksOutAGoodPassword} proves the outage catch charges nothing to a
     * <em>correct</em> password. It cannot see the opposite defect, because the success path calls
     * {@code resetAccount} before the success event is recorded, so a charge made from the catch is
     * wiped a moment later and the streak never grows. The mismatch path has no such reset: there the
     * failure is charged and <em>then</em> recorded, so a second charge in the catch doubles every
     * streak. The lock then engages at half the configured threshold - and it engages during an audit
     * outage, which is precisely the lock the previous test promises does not exist. This test pins the
     * threshold itself, so both halves of the rule hold: the outage catch charges nothing that the
     * credential path did not already charge.
     */
    private static void aRefusalThatCouldNotBeLoggedChargesTheAccountOnce(Fixture fx) throws Exception {
        final int lockAfter = 4;
        UnaryOperator<AuthConfig.Builder> lockAfterFour =
                b -> b.accountLockAfter(lockAfter).accountLockSeconds(600).sourceMaxAttempts(1000);
        try (AuthenticationService service = build(fx, lockAfterFour)) {
            Files.delete(fx.logFile);
            for (int i = 0; i < lockAfter - 1; i++) {
                AuthResult duringOutage = fx.tryLogin(service, Fixture.USER_BOB, "Wrong-Password-99", SRC_A);
                Check.ok("a genuine mismatch during the outage is refused (attempt " + (i + 1) + ")",
                        !duringOutage.isSuccess());
                Check.ok("and it is still not the attempt that locks the account",
                        duringOutage.retryAfterSeconds() == 0);
            }
            Files.createFile(fx.logFile);
            Fixture.restrict(fx.logFile, Check.OWNER_ONLY);

            // The streak must still be one short of the threshold, so this is the attempt that trips it
            // from a clean mismatch rather than from a lock that was already in force. A double charge
            // during the outage means the account is locked here, and the locked branch answers with a
            // retry hint.
            AuthResult trip = fx.tryLogin(service, Fixture.USER_BOB, "Wrong-Password-99", SRC_A);
            Check.ok("the attempt that reaches the threshold is still refused", !trip.isSuccess());
            Check.eq("and it is a plain denial, not an early lock: the outage attempts counted once each",
                    Integer.valueOf(0), Integer.valueOf(trip.retryAfterSeconds()));

            AuthResult lockedOut = fx.tryLogin(service, Fixture.USER_BOB, Fixture.PASSWORD_B, SRC_A);
            Check.ok("the account is locked now, by failures the user actually committed",
                    !lockedOut.isSuccess());
            Check.ok("so even the correct password is held for the remaining lock window",
                    lockedOut.retryAfterSeconds() > 0);
        } finally {
            if (!Files.exists(fx.logFile)) {
                Files.createFile(fx.logFile);
                Fixture.restrict(fx.logFile, Check.OWNER_ONLY);
            }
        }
    }

    /**
     * Refusing an attempt for lack of a log must not turn into an unthrottled guessing window. The
     * per-source budget is consumed before any credential work, so it is spent whether or not the
     * event lands - the outage removes the record, not the rate limit.
     */
    private static void anAuditOutageStillCostsTheAttackerTheirBudget(Fixture fx) throws Exception {
        UnaryOperator<AuthConfig.Builder> tinyBudget =
                b -> b.accountLockAfter(3).sourceMaxAttempts(SOURCE_CAP);
        try (AuthenticationService service = build(fx, tinyBudget)) {
            Files.delete(fx.logFile);
            for (int i = 0; i < SOURCE_CAP; i++) {
                Check.ok("attempts during the outage are all refused (attempt " + (i + 1) + ")",
                        !fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC_B).isSuccess());
            }
            Files.createFile(fx.logFile);
            Fixture.restrict(fx.logFile, Check.OWNER_ONLY);

            AuthResult exhausted = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC_B);
            Check.ok("the source that spent its budget during the outage is still blocked afterwards",
                    !exhausted.isSuccess());
            Check.ok("and the refusal says why, in the caller's own rate terms",
                    exhausted.retryAfterSeconds() > 0);
            AuthResult elsewhere = fx.tryLogin(service, Fixture.USER_ALICE, Fixture.PASSWORD_A, SRC_C);
            Check.ok("another source is unaffected, so the budget is per source", elsewhere.isSuccess());
        } finally {
            if (!Files.exists(fx.logFile)) {
                Files.createFile(fx.logFile);
                Fixture.restrict(fx.logFile, Check.OWNER_ONLY);
            }
        }
    }

    /**
     * A name longer than the accepted maximum must cost the same as any other refusal. If length were
     * checked after the derivation, the timestamp would be padding and the 65th character would be an
     * account-existence oracle.
     */
    private static void oversizedNameCostsTheSameAsEveryOtherRefusal(Fixture fx) throws Exception {
        try (AuthenticationService service = build(fx, b -> b.accountLockAfter(100).sourceMaxAttempts(1000))) {
            String tooLong = "q".repeat(InputValidator.MAX_USERNAME_CODEPOINTS + 1);
            long[] wall = new long[5];
            long[] cpu = new long[5];
            java.lang.management.ThreadMXBean bean = java.lang.management.ManagementFactory.getThreadMXBean();
            boolean cpuSupported = bean.isThreadCpuTimeSupported() && bean.isCurrentThreadCpuTimeSupported();
            for (int i = 0; i < wall.length; i++) {
                char[] chars = Fixture.PASSWORD_A.toCharArray();
                long start = System.nanoTime();
                long cpuStart = cpuSupported ? bean.getCurrentThreadCpuTime() : 0L;
                AuthResult r = service.authenticate(AuthenticationService.Attempt.of(tooLong, chars, SRC_A));
                Arrays.fill(chars, (char) 0);
                wall[i] = System.nanoTime() - start;
                cpu[i] = cpuSupported ? bean.getCurrentThreadCpuTime() - cpuStart : 0L;
                Check.ok("an oversized name never authenticates", !r.isSuccess());
            }
            Arrays.sort(wall);
            Check.ok("an oversized name takes at least the latency floor (" + wall[2] / 1000L + " us)",
                    wall[2] >= 200_000L);
            if (cpuSupported) {
                Arrays.sort(cpu);
                Check.ok("an oversized name burns derivation CPU (" + cpu[2] / 1000L + " us)",
                        cpu[2] >= 80_000L);
            }
        }
    }

}
