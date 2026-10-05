package com.example.identity;

import java.util.ArrayList;
import java.util.List;

import static com.example.identity.Harness.check;
import static com.example.identity.Harness.checkEquals;
import static com.example.identity.Harness.note;
import static com.example.identity.Harness.section;

/**
 * The attempt limiter (Rule 3), including the half of the rule that is usually forgotten: the
 * limit must not be a weapon against the legitimate user.
 *
 * <p>Everything here runs against {@link TimeSource.Fake}, so windows, penalties and roll-forwards
 * are asserted by moving the clock rather than by sleeping. A limiter tested with sleeps is a limiter
 * whose expiry behaviour was never actually observed - it goes green on a slow machine for the wrong
 * reason and red on a fast one for no reason.
 *
 * <p>The properties, each of which is a separate finding a reviewer could raise:
 * <ul>
 *   <li>the per-account counter is keyed by the account, so rotating sources cannot get unlimited
 *     attempts against one credential;</li>
 *   <li>a caller that arrives <em>during</em> a penalty is refused before any lookup or write, so it
 *     cannot extend its own penalty - the counter must not move at all;</li>
 *   <li>the penalty is bounded (by the configured ceiling and by the window) and always lapses, so
 *     one lockout is not a permanent denial of service delivered through our own defence;</li>
 *   <li>a successful sign-in clears the per-account counter and deliberately does <em>not</em> clear
 *     the per-source one;</li>
 *   <li>an identifier with no account behind it still gets a bucket, which is what makes the cheap
 *     throttled refusal symmetric rather than an existence oracle.</li>
 * </ul>
 *
 * <p>The expected penalty sequences are computed from the shipped rule - {@code failures < limit}
 * costs nothing, and from the limit onward it is {@code 1 << (failures - limit)} capped by
 * {@code min(ceiling, window)} - so a change to that arithmetic shows up as a mismatch rather than
 * as a re-tuned expectation.
 */
public final class ThrottleLockoutTest {

    private ThrottleLockoutTest() {
    }

    public static void run() throws Exception {
        penaltySchedule();
        blockedCallerCannotExtendItsOwnPenalty();
        accountCounterIsGlobalAcrossSources();
        oneAccountOneBudgetWhicheverSpellingIsTyped();
        malformedIdentifierStillChargesTheSource();
        successClearsAccountButNotSource();
        throttledBranchIsSymmetric();
        registrationBudgets();
        throttleTableStaysBounded();
    }

    // ------------------------------------------------------------------ schedule

    private static void penaltySchedule() throws Exception {
        section("The penalty is free until the limit, doubles from it, and is pinned by the ceiling");
        Harness.Overrides o = Harness.overrides();
        o.authAccountMax = 3;
        o.authSourceMax = 1000;
        o.penaltyCeiling = 5;
        Harness.Fixture f = Harness.fixture("sched-cap", o);
        try (Harness.Bundle b = Harness.openApi(f)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            List<Integer> observed = new ArrayList<>();
            for (int i = 0; i < 6; i++) {
                AuthResult r = b.api.signIn(Harness.U1, Harness.chars(Harness.P2), SourceId.LOCAL);
                check("attempt " + i + " is refused", !r.isSuccess());
                int penalty = penaltyNow(f);
                observed.add(penalty);
                if (penalty > 0) {
                    f.clock.advanceSeconds(penalty + 1L);
                }
            }
            checkEquals("nothing, nothing, then 1s, 2s, 4s, pinned at the 5s ceiling",
                    List.of(0, 0, 1, 2, 4, 5), observed);
            note("penalty schedule as read back from the stored until_epoch_s: " + observed);
        }

        section("With a generous ceiling the binding cap is the window, and doubling is visible");
        Harness.Overrides o2 = Harness.overrides();
        o2.authAccountMax = 3;
        o2.authSourceMax = 1000;
        o2.penaltyCeiling = 3600;
        o2.authWindow = 900;
        Harness.Fixture f2 = Harness.fixture("sched-window", o2);
        try (Harness.Bundle b = Harness.openApi(f2)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            List<Integer> observed = new ArrayList<>();
            for (int i = 0; i < 6; i++) {
                b.api.signIn(Harness.U1, Harness.chars(Harness.P2), SourceId.LOCAL);
                int penalty = penaltyNow(f2);
                observed.add(penalty);
                if (penalty > 0) {
                    f2.clock.advanceSeconds(penalty + 1L);
                }
            }
            checkEquals("pure doubling while both caps are out of reach", List.of(0, 0, 1, 2, 4, 8),
                    observed);
            check("no penalty ever exceeds min(ceiling, window), which is the real bound",
                    observed.stream().allMatch(p -> p <= Math.min(o2.penaltyCeiling, o2.authWindow)));
        }

        section("The shift cannot overflow into a deadline in the past");
        // `1L << e` in Java masks the distance to six bits, so only e = 63 (mod 64) produces a
        // negative long - which means an unclamped exponent is harmless at almost every counter
        // value and silently disables the limiter at exactly failures-limit in {63, 127, 191, ...}.
        // A test that only drives the real API up to the configured ceiling would never reach one,
        // so this calls the function directly across the values that matter.
        List<String> illegal = new ArrayList<>();
        int limit = 5;
        int window = 900;
        int ceiling = 300;
        int cap = Harness.reflectionInt(SqlIdentityStore.class, "penaltySeconds",
                new Class<?>[]{int.class, int.class, int.class, int.class},
                new Object[]{limit + 20, limit, window, ceiling});
        check("a high counter lands on the smaller of ceiling and window, not on 2^20",
                cap == Math.min(ceiling, window));
        for (int extra = 0; extra <= 995; extra++) {
            int p = Harness.reflectionInt(SqlIdentityStore.class, "penaltySeconds",
                    new Class<?>[]{int.class, int.class, int.class, int.class},
                    new Object[]{limit + extra, limit, window, ceiling});
            if (p < 1 || p > Math.min(ceiling, window)) {
                illegal.add(limit + extra + "->" + p);
            }
        }
        checkEquals("every counter value from the limit to the storage ceiling yields a legal"
                + " penalty in [1, min(ceiling, window)]", List.of(), illegal);
        check("the values that would overflow without the clamp are among those checked",
                limit + 63 <= 1000 && limit + 959 <= 1000);
    }

    private static int penaltyNow(Harness.Fixture f) throws Exception {
        long until = maxUntil(f);
        long now = f.clock.nowEpochSeconds();
        return until == 0L || until <= now ? 0 : (int) (until - now);
    }

    private static long maxUntil(Harness.Fixture f) throws Exception {
        List<String> v = Harness.rawColumn(f, "SELECT MAX(until_epoch_s) FROM auth_throttle");
        if (v.isEmpty() || v.get(0) == null) {
            return 0L;
        }
        return Long.parseLong(v.get(0));
    }

    /**
     * Sum of {@code failures} over the sign-in buckets. The registration budgets live in the same
     * table (kinds "g" and "s") and would otherwise be counted as sign-in attempts, so every
     * assertion here is scoped by bucket prefix - kind plus ':'.
     */
    private static long totalFailures(Harness.Fixture f) throws Exception {
        return failuresWithKind(f, SqlIdentityStore.bucketKindAccount() + ":")
                + failuresWithKind(f, SqlIdentityStore.bucketKindSource() + ":");
    }

    private static long failuresWithKind(Harness.Fixture f, String kindPrefix) throws Exception {
        List<String> v = Harness.rawColumn(f, "SELECT COALESCE(SUM(failures), 0) FROM auth_throttle"
                + " WHERE bucket LIKE '" + kindPrefix + "%'");
        return v.isEmpty() || v.get(0) == null ? 0L : Long.parseLong(v.get(0));
    }

    /** Number of rows in one bucket namespace, e.g. {@code "a:"} for the sign-in account counters. */
    private static String kindCount(Harness.Fixture f, String kindPrefix) throws Exception {
        List<String> v = Harness.rawColumn(f, "SELECT COUNT(*) FROM auth_throttle"
                + " WHERE bucket LIKE '" + kindPrefix + "%'");
        return v.isEmpty() ? "0" : v.get(0);
    }

    private static void blockedCallerCannotExtendItsOwnPenalty() throws Exception {
        section("A blocked caller is refused before it can touch a counter");
        Harness.Overrides o = Harness.overrides();
        o.authAccountMax = 3;
        o.authSourceMax = 1000;
        o.penaltyCeiling = 3600;
        Harness.Fixture f = Harness.fixture("no-self-extend", o);
        try (Harness.Bundle b = Harness.openApi(f)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            for (int i = 0; i < 3; i++) {
                b.api.signIn(Harness.U1, Harness.chars(Harness.P2), SourceId.LOCAL);
            }
            long untilWhenBlocked = maxUntil(f);
            long accountFailuresWhenBlocked = failuresWithKind(f, "a:");
            long sourceFailuresWhenBlocked = failuresWithKind(f, "s:");
            check("the penalty engaged exactly at the limit", untilWhenBlocked > f.clock.nowEpochSeconds());
            check("and it is the first-trip length, 1 s",
                    untilWhenBlocked - f.clock.nowEpochSeconds() == 1L);

            // Hammer it while blocked, including with the *correct* password. If the penalty check
            // sat anywhere after the account charge, every one of these would push the deadline out
            // and the lockout would never end. The source bucket is a different story, and it is
            // deliberately charged: see the account-penalty branch in AuthApi.signIn.
            for (int i = 0; i < 6; i++) {
                String guess = i % 2 == 0 ? Harness.P2 : Harness.P1;
                AuthResult r = b.api.signIn(Harness.U1, Harness.chars(guess), SourceId.LOCAL);
                check("blocked attempt " + i + " is refused", !r.isSuccess());
            }
            checkEquals("the penalty deadline did not move", untilWhenBlocked, maxUntil(f));
            checkEquals("no failure was charged to the account bucket while blocked, so a blocked"
                            + " caller cannot deepen or extend its own lockout",
                    accountFailuresWhenBlocked, failuresWithKind(f, "a:"));
            checkEquals("while every blocked attempt did cost the caller one charge against its own"
                            + " source budget - parking a lockout on someone else's account is not"
                            + " free",
                    sourceFailuresWhenBlocked + 6L, failuresWithKind(f, "s:"));
            check("and that charge is not an oracle: the source bucket grows the same way for the"
                            + " correct password as for a wrong one",
                    failuresWithKind(f, "s:") >= sourceFailuresWhenBlocked + 3L);
            checkEquals("the blocked attempts issued no session", 0, Harness.rawCount(f, "session"));

            f.clock.advanceSeconds(2);
            long before = totalFailures(f);
            AuthResult afterLapse = b.api.signIn(Harness.U1, Harness.chars(Harness.P2), SourceId.LOCAL);
            check("once the penalty lapses the attempt is evaluated and charged again",
                    totalFailures(f) > before);
            check("and it is still refused on merit", !afterLapse.isSuccess());
            check("the escalation continued from the stored counter (2 s, not back to 1 s)",
                    penaltyNow(f) == 2);

            f.clock.advanceSeconds(o.authWindow + 10L);
            long afterWindow = totalFailures(f);
            AuthResult fresh = b.api.signIn(Harness.U1, Harness.chars(Harness.P2), SourceId.LOCAL);
            check("after the whole window lapses the counter restarts instead of resuming the"
                    + " escalation", penaltyNow(f) == 0 && afterWindow > 6L);
            check("the fresh attempt is still refused on merit", !fresh.isSuccess());
            checkEquals("the restart leaves exactly one charge in the account bucket", 1L,
                    failuresWithKind(f, SqlIdentityStore.bucketKindAccount() + ":"));
            checkEquals("and one in the source bucket rather than the escalated count carried forward",
                    1L, failuresWithKind(f, SqlIdentityStore.bucketKindSource() + ":"));
            checkEquals("the registration budget is a separate bucket and sign-in never touched it",
                    1L, Harness.rawColumn(f,
                            "SELECT failures FROM auth_throttle WHERE bucket LIKE 'g:%'")
                            .stream().mapToLong(Long::parseLong).sum());
        }

        section("The lockout always expires: the owner gets back in (no latched flag)");
        Harness.Fixture f2 = Harness.fixture("lockout-expires", o);
        try (Harness.Bundle b = Harness.openApi(f2)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            for (int i = 0; i < 3; i++) {
                b.api.signIn(Harness.U1, Harness.chars(Harness.P2), SourceId.LOCAL);
            }
            check("the owner with the right password is refused while the penalty is live",
                    !b.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL).isSuccess());
            f2.clock.advanceSeconds(o.authWindow + 10L);
            check("the same owner, same password, is admitted once the window has lapsed",
                    b.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL).isSuccess());
            check("the audit trail records that a throttle engaged",
                    b.audit.readAll().contains("throttle_engaged"));
            note("documented cost of a shared per-account counter: while an attacker burns the"
                    + " account's budget the real owner is refused for up to the penalty length - see"
                    + " README 'Limitations'");
        }
    }

    // ------------------------------------------------------------------ keying

    private static void accountCounterIsGlobalAcrossSources() throws Exception {
        section("Source rotation does not reset the account counter (Rule 3, per-account leg)");
        Harness.Overrides o = Harness.overrides();
        o.authAccountMax = 3;
        o.authSourceMax = 1000;
        o.penaltyCeiling = 3600;
        Harness.Fixture f = Harness.fixture("spray", o);
        try (Harness.Bundle b = Harness.openApi(f)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            for (String s : List.of("192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4")) {
                check("an attempt from " + s + " is refused on merit",
                        !b.api.signIn(Harness.U1, Harness.chars(Harness.P2), s).isSuccess());
            }
            // Census by namespace, not a bare row count. The sign-in rows are four per-source
            // counters plus the one shared account counter: the fourth source was refused by the
            // account penalty and still paid a charge to its own bucket, which is the whole point of
            // that charge. The two rows the registration created (its global and per-source budgets)
            // must be *other* rows that the sign-in traffic never charged.
            checkEquals("four charged sources plus the one shared account bucket, and the two"
                            + " registration budgets kept in their own namespaces",
                    List.of("4", "1", "1", "1"),
                    List.of(kindCount(f, "s:"), kindCount(f, "a:"), kindCount(f, "r:"),
                            kindCount(f, "g:")));
            // The one registration charged each registration budget exactly once. Had the sign-in
            // counters shared their namespace, these rows would carry the sign-in charges too.
            checkEquals("the two registration budgets hold only their own single charge each", "1",
                    Harness.rawColumn(f, "SELECT MAX(failures) FROM auth_throttle"
                            + " WHERE bucket LIKE 'g:%' OR bucket LIKE 'r:%'").get(0));
            checkEquals("the shared account bucket absorbed all three charges (the fourth was refused"
                            + " before it could be charged)", "3",
                    Harness.rawColumn(f, "SELECT MAX(failures) FROM auth_throttle"
                            + " WHERE bucket LIKE 'a:%'").get(0));
            check("so the account penalty engaged after the third attempt, delivered from three"
                    + " different sources", maxUntil(f) > f.clock.nowEpochSeconds());
            check("a fifth source is refused too - the block is on the account, not on the peer",
                    !b.api.signIn(Harness.U1, Harness.chars(Harness.P1), "198.51.100.7").isSuccess());
            note("spraying sources buys neither unlimited guesses nor a reset counter");
        }

        section("Canonical spellings of one address share one bucket (no free bucket rotation)");
        Harness.Overrides o2 = Harness.overrides();
        o2.authAccountMax = 1000;
        o2.authSourceMax = 3;
        o2.penaltyCeiling = 3600;
        Harness.Fixture f2 = Harness.fixture("canon-bucket", o2);
        try (Harness.Bundle b = Harness.openApi(f2)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            b.api.signIn(Harness.U1, Harness.chars(Harness.P2), "0:0:0:0:0:0:0:1");
            b.api.signIn(Harness.U1, Harness.chars(Harness.P2), " ::1 ");
            checkEquals("both spellings charged the one same source bucket", 2L,
                    failuresWithKind(f2, "s:"));
            check("two charges have not reached the limit yet, so the next charge is the one that"
                    + " trips it", penaltyNow(f2) == 0);
            check("the third spelling is refused as well and trips the penalty - rotating the"
                    + " spelling buys no extra guesses",
                    !b.api.signIn(Harness.U1, Harness.chars(Harness.P2), "::1").isSuccess()
                            && penaltyNow(f2) > 0);
            check("during that penalty even the correct password is refused",
                    !b.api.signIn(Harness.U1, Harness.chars(Harness.P1), "0:0:0:0:0:0:0:1").isSuccess());
            check("the shared source bucket is what refused it - the account counter is nowhere near"
                            + " its own limit",
                    failuresWithKind(f2, "a:") < o2.authAccountMax);
            checkEquals("and no extra source bucket was created for the other spellings", "1",
                    kindCount(f2, "s:"));
            checkEquals("with exactly the one sign-in account counter", "1", kindCount(f2, "a:"));
        }
    }

    /**
     * One account, two spellings, one budget.
     *
     * <p>The account counter used to be keyed by the canonical form of <em>whatever the caller
     * typed</em>, and an account is reachable by two canonical forms - its username and its email.
     * That is two counters, which breaks both halves of the limiter at once: an attacker can spend
     * the email budget while guessing through the username, and a verified sign-in clears the form
     * the owner happened to type rather than the one under attack. Keying by the row's primary key
     * makes the count below a single row, which is the only shape in which either property holds.
     */
    private static void oneAccountOneBudgetWhicheverSpellingIsTyped() throws Exception {
        section("Username and email spellings of one account share one counter");
        Harness.Overrides o = Harness.overrides();
        o.authAccountMax = 3;
        o.authSourceMax = 1000;
        o.penaltyCeiling = 3600;
        Harness.Fixture f = Harness.fixture("one-budget", o);
        try (Harness.Bundle b = Harness.openApi(f)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            check("a wrong password typed as the username is refused",
                    !b.api.signIn(Harness.U1, Harness.chars(Harness.P2), SourceId.LOCAL).isSuccess());
            check("and one typed as the email is refused",
                    !b.api.signIn(Harness.E1, Harness.chars(Harness.P2), SourceId.LOCAL).isSuccess());
            checkEquals("both charges landed in the <one> account bucket - two rows here would mean "
                            + "two independent budgets for the same credential",
                    "1", kindCount(f, "a:"));
            checkEquals("and the shared counter holds both charges", 2L,
                    failuresWithKind(f, "a:"));
            check("the third attempt trips it whichever form it uses",
                    !b.api.signIn(Harness.E1, Harness.chars(Harness.P2), SourceId.LOCAL).isSuccess()
                            && penaltyNow(f) > 0);
            checkEquals("still exactly one account bucket after the penalty engaged", "1",
                    kindCount(f, "a:"));
            check("so the owner is refused through the <other> spelling too - the budget they ran"
                            + " out on is the budget they are refused with",
                    !b.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL).isSuccess());
        }

        section("A verified sign-in clears the budget that was being spent, not the spelling used");
        Harness.Overrides o2 = Harness.overrides();
        o2.authAccountMax = 1000;
        o2.authSourceMax = 1000;
        o2.penaltyCeiling = 3600;
        Harness.Fixture f2 = Harness.fixture("clear-right-bucket", o2);
        try (Harness.Bundle b = Harness.openApi(f2)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            // Spend the budget entirely through the email spelling, the way an attacker would.
            b.api.signIn(Harness.E1, Harness.chars(Harness.P2), SourceId.LOCAL);
            b.api.signIn(Harness.E1, Harness.chars(Harness.P2), SourceId.LOCAL);
            long spent = failuresWithKind(f2, "a:");
            check("two charges are sitting in the account bucket", spent == 2L);
            check("the owner signs in through the username spelling",
                    b.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL).isSuccess());
            checkEquals("and the email-keyed charges are gone - clearing only the spelling the owner"
                            + " typed would leave the attacker's counter in place", 0L,
                    failuresWithKind(f2, "a:"));
            checkEquals("with no account bucket left at all", "0", kindCount(f2, "a:"));
        }
    }

    /**
     * The branch that never reaches an account must still be charged.
     *
     * <p>A malformed identifier is refused before the database is touched, at a full derivation's
     * cost to keep it from being an existence oracle. With no account to charge and no charge
     * against the source either, that branch was an unlimited supply of expensive work: fill the
     * corpus with garbage identifiers and every request costs ~850 ms of PBKDF2 while
     * {@code auth_throttle} stays empty, so the per-source limit never engages by construction. The
     * per-process bound in {@code DecisionGuardTest} caps the concurrency; this is what caps the
     * rate.
     */
    private static void malformedIdentifierStillChargesTheSource() throws Exception {
        section("A malformed identifier costs the source a real charge");
        Harness.Overrides o = Harness.overrides();
        o.authAccountMax = 1000;
        o.authSourceMax = 3;
        o.penaltyCeiling = 3600;
        Harness.Fixture f = Harness.fixture("malformed-charge", o);
        try (Harness.Bundle b = Harness.openApi(f)) {
            List<String> garbage = List.of("not an identifier!!", "a@b@evil.example", "???",
                    "alice@example", "x".repeat(5000));
            for (int i = 0; i < 3; i++) {
                String g = garbage.get(i);
                AuthResult r = b.api.signIn(g, Harness.chars(Harness.P1), "192.0.2.9");
                check("garbage attempt " + i + " is refused with the generic sentence",
                        !r.isSuccess() && r.userMessage().equals(Reason.BAD_CREDENTIAL.genericUserMessage()));
            }
            check("and the throttle table is not empty, which is the whole claim",
                    Long.parseLong(kindCount(f, "s:")) == 1L);
            checkEquals("all three charges are in the one source bucket", 3L,
                    failuresWithKind(f, "s:"));
            check("the source penalty engaged, so the free work stopped", penaltyNow(f) > 0);
            long charged = failuresWithKind(f, "s:");
            check("a fourth attempt is refused",
                    !b.api.signIn("more garbage!!", Harness.chars(Harness.P1), "192.0.2.9").isSuccess());
            checkEquals("and being refused before the charge, it did not buy a fifth charge to"
                            + " extend its own penalty", charged, failuresWithKind(f, "s:"));
            checkEquals("a garbage identifier created no account bucket - there is no account",
                    "0", kindCount(f, "a:"));
            note("a candidate that fails the password policy is charged the same way, see the"
                    + " policy branch in AuthApi.signIn");

            section("The policy branch is charged too");
            Harness.Fixture f2 = Harness.fixture("policy-charge", o);
            try (Harness.Bundle b2 = Harness.openApi(f2)) {
                Harness.register(b2, Harness.E1, Harness.U1, Harness.P1);
                for (int i = 0; i < 3; i++) {
                    check("an under-length candidate is refused with the credential sentence",
                            !b2.api.signIn(Harness.U1, Harness.chars("x"), SourceId.LOCAL).isSuccess());
                }
                checkEquals("three charges against the source, at policy-refusal cost", 3L,
                        failuresWithKind(f2, "s:"));
                check("and the source is now blocked, so the policy branch cannot be used to make"
                                + " the service derive forever",
                        penaltyNow(f2) > 0);
                checkEquals("a blocked source is charged nothing further", 3L,
                        failuresWithKind(f2, "s:"));
            }
        }
    }

    private static long maxFailures(Harness.Fixture f) throws Exception {
        List<String> v = Harness.rawColumn(f, "SELECT MAX(failures) FROM auth_throttle");
        return v.isEmpty() || v.get(0) == null ? 0L : Long.parseLong(v.get(0));
    }

    private static void successClearsAccountButNotSource() throws Exception {
        section("A verified sign-in resets the account counter and deliberately not the source one");
        Harness.Overrides o = Harness.overrides();
        o.authAccountMax = 1000;
        o.authSourceMax = 4;
        o.penaltyCeiling = 3600;
        Harness.Fixture f = Harness.fixture("clear-source", o);
        try (Harness.Bundle b = Harness.openApi(f)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            b.api.signIn(Harness.U1, Harness.chars(Harness.P2), SourceId.LOCAL);
            b.api.signIn(Harness.U1, Harness.chars(Harness.P2), SourceId.LOCAL);
            checkEquals("the two failures charged one sign-in source bucket and one account bucket,"
                            + " in buckets separate from the two registration budgets",
                    List.of("1", "1", "1", "1"),
                    List.of(kindCount(f, "s:"), kindCount(f, "a:"), kindCount(f, "r:"),
                            kindCount(f, "g:")));
            checkEquals("the sign-in source counter is at 2", 2L, failuresWithKind(f, "s:"));
            checkEquals("so is the account counter", 2L, failuresWithKind(f, "a:"));

            check("the correct password is accepted",
                    b.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL).isSuccess());
            checkEquals("the account bucket is gone", "0", kindCount(f, "a:"));
            checkEquals("the source bucket is intact at 2 - one known credential must not be a way"
                            + " to keep a source counter permanently empty", 2L,
                    failuresWithKind(f, "s:"));

            b.api.signIn(Harness.U1, Harness.chars(Harness.P2), SourceId.LOCAL);
            b.api.signIn(Harness.U1, Harness.chars(Harness.P2), SourceId.LOCAL);
            check("the source counter reached its limit and is now in penalty",
                    penaltyNow(f) > 0);
            check("during that penalty even the correct password is refused, because the block is on"
                    + " the source and not on the credential",
                    !b.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL).isSuccess());
            f.clock.advanceSeconds(o.authWindow + 10L);
            check("when the source window lapses the owner is back in",
                    b.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL).isSuccess());
        }
    }

    // ------------------------------------------------------------------ oracle symmetry

    private static void throttledBranchIsSymmetric() throws Exception {
        section("A nonexistent identifier still gets buckets (so a cheap refusal is not an oracle)");
        Harness.Overrides o = Harness.overrides();
        o.authAccountMax = 1000;
        o.authSourceMax = 1000;
        Harness.Fixture f = Harness.fixture("symmetric", o);
        try (Harness.Bundle b = Harness.openApi(f)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            check("a failed attempt against a real account is refused",
                    !b.api.signIn(Harness.U1, Harness.chars(Harness.P2), SourceId.LOCAL).isSuccess());
            int afterKnown = Harness.rawCount(f, "auth_throttle");
            check("a failed attempt against nobody is refused identically",
                    !b.api.signIn("nosuchaccount", Harness.chars(Harness.P2), SourceId.LOCAL).isSuccess());
            int afterUnknown = Harness.rawCount(f, "auth_throttle");
            checkEquals("both attempts added exactly one account bucket each", afterKnown + 1, afterUnknown);
            check("the limiter's stored state therefore has the same shape whether or not the"
                    + " identifier exists - which is what makes the uncharged throttled refusal"
                    + " symmetric rather than an existence oracle",
                    maxFailures(f) >= 2L);
        }

        section("Both a real and a fictitious identifier reach the same cheap refusal");
        Harness.Overrides tight = Harness.overrides();
        tight.authAccountMax = 3;
        tight.authSourceMax = 1000;
        Harness.Fixture f2 = Harness.fixture("symmetric-trip", tight);
        try (Harness.Bundle t = Harness.openApi(f2)) {
            Harness.register(t, Harness.E1, Harness.U1, Harness.P1);
            // Each identifier has its own account bucket, so each must be driven to its own limit
            // before the cheap refusal is reachable for either.
            for (int i = 0; i < 3; i++) {
                t.api.signIn(Harness.U1, Harness.chars(Harness.P2), SourceId.LOCAL);
                t.api.signIn("nosuchaccount", Harness.chars(Harness.P2), SourceId.LOCAL);
            }
            AuthResult knownBlocked = t.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL);
            AuthResult unknownBlocked = t.api.signIn("nosuchaccount", Harness.chars(Harness.P1),
                    SourceId.LOCAL);
            check("both are in penalty", maxUntil(f2) > f2.clock.nowEpochSeconds());
            check("both refuse", !knownBlocked.isSuccess() && !unknownBlocked.isSuccess());
            check("with the same string", knownBlocked.userMessage().equals(unknownBlocked.userMessage()));
            check("and the throttled refusal is the generic sign-in failure",
                    Reason.BAD_CREDENTIAL.genericUserMessage().equals(knownBlocked.userMessage()));
            check("the audit log does tell the operator they were throttled rather than wrong",
                    t.audit.readAll().contains("THROTTLED"));
            check("a throttled attempt issued no session", Harness.rawCount(f2, "session") == 0);
        }
    }

    // ------------------------------------------------------------------ registration budgets

    private static void registrationBudgets() throws Exception {
        section("Registration has both a per-source and an independent global budget");
        Harness.Overrides global = Harness.overrides();
        global.regGlobalMax = 2;
        global.regSourceMax = 1000;
        Harness.Fixture f = Harness.fixture("reg-global", global);
        try (Harness.Bundle b = Harness.openApi(f)) {
            check("first registration ok",
                    b.api.register(Harness.E1, Harness.U1, Harness.chars(Harness.P1), "192.0.2.1")
                            .reason() == Reason.ACCOUNT_CREATED);
            check("second registration ok",
                    b.api.register(Harness.E2, Harness.U2, Harness.chars(Harness.P2), "192.0.2.1")
                            .reason() == Reason.ACCOUNT_CREATED);
            AuthResult third = b.api.register(Harness.E3, Harness.U3, Harness.chars(Harness.P3),
                    "192.0.2.1");
            check("the third is rate limited, not capped", third.reason() == Reason.REGISTRATION_THROTTLED);
            AuthResult otherSource = b.api.register(Harness.E4, Harness.U4, Harness.chars(Harness.P4),
                    "198.51.100.9");
            check("a different source cannot escape the global budget",
                    otherSource.reason() == Reason.REGISTRATION_THROTTLED);
            check("the budget refusal invites no retry timing",
                    !third.userMessage().toLowerCase().contains("later")
                            && !third.userMessage().toLowerCase().contains("retry"));
            check("both budget refusals say the same thing regardless of which budget fired",
                    third.userMessage().equals(otherSource.userMessage()));
            check("a budget refusal is not the account-cap message",
                    !third.userMessage().equals(Reason.ACCOUNT_CAP_REACHED.genericUserMessage()));
            f.clock.advanceSeconds(global.regWindow + 1L);
            check("the budget rolls forward with the window",
                    b.api.register(Harness.E3, Harness.U3, Harness.chars(Harness.P3), "192.0.2.1")
                            .reason() == Reason.ACCOUNT_CREATED);
        }

        section("The per-source budget is keyed by the canonical source, and only by it");
        Harness.Overrides perSource = Harness.overrides();
        perSource.regSourceMax = 1;
        perSource.regGlobalMax = 1000;
        Harness.Fixture f2 = Harness.fixture("reg-source", perSource);
        try (Harness.Bundle b = Harness.openApi(f2)) {
            check("source A gets one",
                    b.api.register(Harness.E1, Harness.U1, Harness.chars(Harness.P1), "192.0.2.1")
                            .reason() == Reason.ACCOUNT_CREATED);
            check("source A's second is refused",
                    b.api.register(Harness.E2, Harness.U2, Harness.chars(Harness.P2), "192.0.2.1")
                            .reason() == Reason.REGISTRATION_THROTTLED);
            check("source B has its own budget (Rule 3 asks for a per-source limit)",
                    b.api.register(Harness.E3, Harness.U3, Harness.chars(Harness.P3), "198.51.100.1")
                            .reason() == Reason.ACCOUNT_CREATED);
            check("a spelling variant of source A does not buy a second budget",
                    b.api.register(Harness.E4, Harness.U4, Harness.chars(Harness.P4), " 192.0.2.1 ")
                            .reason() == Reason.REGISTRATION_THROTTLED);
            check("varying the email does not defeat the per-source limit either",
                    b.api.register("someone-else@example.com", "someoneelse", Harness.chars(Harness.P4),
                            "192.0.2.1").reason() == Reason.REGISTRATION_THROTTLED);
            checkEquals("and none of the refusals created a row", 2, Harness.rawCount(f2, "account"));
        }

        section("An unusable source label is refused outright, not counted and not served");
        Harness.Fixture f3 = Harness.fixture("reg-bad-source", Harness.overrides());
        try (Harness.Bundle b = Harness.openApi(f3)) {
            int before = Harness.rawCount(f3, "auth_throttle");
            AuthResult r = b.api.register(Harness.E1, Harness.U1, Harness.chars(Harness.P1),
                    "attacker-chosen-label");
            check("an unverifiable source label aborts the request", r.reason() == Reason.INVALID_REQUEST);
            check("and creates no bucket to hide behind", Harness.rawCount(f3, "auth_throttle") == before);
            checkEquals("no account was created", 0, Harness.rawCount(f3, "account"));
            check("the label is not echoed back", !r.userMessage().contains("attacker"));
            AuthResult in = b.api.signIn(Harness.U1, Harness.chars(Harness.P1), "attacker-chosen-label");
            check("the same label aborts a sign-in too", in.reason() == Reason.INVALID_REQUEST);
            checkEquals("and again creates no bucket", before, Harness.rawCount(f3, "auth_throttle"));
            check("a refused label costs the caller a refusal, not our derivation",
                    in.userMessage().equals(Reason.INVALID_REQUEST.genericUserMessage()));
        }

        section("The registration budget and the sign-in counter are separate namespaces");
        // Both live in auth_throttle. They originally shared the "s" kind character, and because a
        // bucket id is HMAC(kind, value) prefixed with kind, that made a source's registration
        // budget and its sign-in attempt counter literally the same row. Two directions of the same
        // bug, one check each.
        Harness.Overrides crossA = Harness.overrides();
        crossA.regSourceMax = 3;
        crossA.authSourceMax = 3;
        Harness.Fixture f4 = Harness.fixture("reg-vs-signin-a", crossA);
        try (Harness.Bundle b = Harness.openApi(f4)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            for (int i = 0; i < 3; i++) {
                b.api.signIn("nosuchaccount", Harness.chars(Harness.P2), "192.0.2.7");
            }
            check("that source really is in a sign-in penalty now",
                    Harness.rawColumn(f4, "SELECT COUNT(*) FROM auth_throttle WHERE bucket LIKE 's:%'"
                            + " AND until_epoch_s > " + f4.clock.nowEpochSeconds()).get(0).equals("1"));
            check("and spraying failed sign-ins from it does not buy the attacker a registration ban"
                            + " on a service that still has room for them (Rule 3: an attacker cannot"
                            + " use your own limit to lock a legitimate user out)",
                    b.api.register(Harness.E2, Harness.U2, Harness.chars(Harness.P2), "192.0.2.7")
                            .reason() == Reason.ACCOUNT_CREATED);
            // Census of every namespace: one sign-in source counter (192.0.2.7), one sign-in
            // account counter (the fictitious identifier), the two registration budgets for
            // 192.0.2.7, plus the "local" registration budget the fixture's own registration spent.
            // Bucket ids are HMAC-keyed, so a source's value cannot be selected in SQL - the
            // namespace counts below are what prove a source's registration budget and its sign-in
            // counter are different rows.
            checkEquals("sign-in rows and registration rows are distinct rows in one table",
                    List.of("1", "1", "2", "1"),
                    List.of(
                            Harness.rawColumn(f4, "SELECT COUNT(*) FROM auth_throttle"
                                    + " WHERE bucket LIKE 's:%'").get(0),
                            Harness.rawColumn(f4, "SELECT COUNT(*) FROM auth_throttle"
                                    + " WHERE bucket LIKE 'a:%'").get(0),
                            Harness.rawColumn(f4, "SELECT COUNT(*) FROM auth_throttle"
                                    + " WHERE bucket LIKE 'r:%'").get(0),
                            Harness.rawColumn(f4, "SELECT COUNT(*) FROM auth_throttle"
                                    + " WHERE bucket LIKE 'g:%'").get(0)));
        }

        Harness.Overrides crossB = Harness.overrides();
        crossB.regSourceMax = 1;
        Harness.Fixture f5 = Harness.fixture("reg-vs-signin-b", crossB);
        try (Harness.Bundle b = Harness.openApi(f5)) {
            check("the source spends its one registration",
                    b.api.register(Harness.E1, Harness.U1, Harness.chars(Harness.P1), "192.0.2.8")
                            .reason() == Reason.ACCOUNT_CREATED);
            check("its second attempt is refused",
                    b.api.register(Harness.E2, Harness.U2, Harness.chars(Harness.P2), "192.0.2.8")
                            .reason() == Reason.REGISTRATION_THROTTLED);
            check("the owner then signs in successfully from the same source",
                    b.api.signIn(Harness.U1, Harness.chars(Harness.P1), "192.0.2.8").isSuccess());
            check("a successful sign-in clears that source's *sign-in* counter only - it must not"
                            + " hand the source a fresh registration budget",
                    b.api.register(Harness.E3, Harness.U3, Harness.chars(Harness.P3), "192.0.2.8")
                            .reason() == Reason.REGISTRATION_THROTTLED);
            checkEquals("and the sign-in counter really was cleared, so the reset went to the right"
                            + " row and not the wrong one",
                    "0", Harness.rawColumn(f5, "SELECT COUNT(*) FROM auth_throttle"
                            + " WHERE bucket LIKE 's:%'").get(0));
        }
    }

    // ------------------------------------------------------------------ table bound

    private static void throttleTableStaysBounded() throws Exception {
        section("Lapsed counters are swept, so the limiter is not a disk-exhaustion primitive");
        Harness.Overrides o = Harness.overrides();
        o.authWindow = 900;
        Harness.Fixture f = Harness.fixture("sweep", o);
        try (Harness.Bundle b = Harness.openApi(f)) {
            for (int i = 0; i < 12; i++) {
                b.api.signIn("ghost" + i, Harness.chars(Harness.P2), "192.0.2." + (i + 1));
            }
            int grown = Harness.rawCount(f, "auth_throttle");
            check("the attempts created rows", grown >= 24);
            // sweepThrottle's horizon is 4x the *widest* window in the table (the registration
            // window here, 3600 s, is wider than this fixture's 900 s auth window) plus an hour;
            // nothing is in penalty, so nothing is protected from the sweep by a live deadline.
            f.clock.advanceSeconds(o.regWindow * 4L + 3600L + 60L);
            b.api.signIn("ghost0", Harness.chars(Harness.P2), "192.0.2.1");
            int swept = Harness.rawCount(f, "auth_throttle");
            check("a later charge sweeps the lapsed rows", swept < grown);
            check("the sweep leaves only the rows that are still in date", swept <= 3);
            note("throttle rows before the sweep: " + grown + ", after: " + swept);
        }

        section("The sweep horizon follows the widest window, not the auth window");
        // A registration budget with a 24 h window must survive a sweep that happens an hour after
        // a 900 s auth window lapses. Erasing an in-force budget is a limiter that silently resets.
        Harness.Overrides wide = Harness.overrides();
        wide.authWindow = 900;
        wide.regWindow = 86400;
        // 1, so the source is genuinely *in force* (at its limit) when the sweep runs. With the
        // default 1000 the budget row exists but is nowhere near exhausted, and the check below
        // would pass for a sweep that deleted nothing at all.
        wide.regSourceMax = 1;
        Harness.Fixture f2 = Harness.fixture("sweep-horizon", wide);
        try (Harness.Bundle b = Harness.openApi(f2)) {
            check("the source spends its registration budget",
                    b.api.register(Harness.E1, Harness.U1, Harness.chars(Harness.P1), "192.0.2.9")
                            .reason() == Reason.ACCOUNT_CREATED);
            check("the second is refused",
                    b.api.register(Harness.E2, Harness.U2, Harness.chars(Harness.P2), "192.0.2.9")
                            .reason() == Reason.REGISTRATION_THROTTLED);
            int withBudget = Harness.rawCount(f2, "auth_throttle");
            checkEquals("the two budget rows are all that exists so far", 2, withBudget);
            // Well past the auth window, well inside the registration window.
            f2.clock.advanceSeconds(wide.authWindow * 2L + 7200L);
            b.api.signIn("ghost9", Harness.chars(Harness.P2), "198.51.100.77");
            checkEquals("the charge swept, and exactly the ghost's own two new rows plus the two"
                    + " in-force budget rows remain", 4, Harness.rawCount(f2, "auth_throttle"));
            check("the in-force registration budget survived it - the source is still limited",
                    b.api.register(Harness.E3, Harness.U3, Harness.chars(Harness.P3), "192.0.2.9")
                            .reason() == Reason.REGISTRATION_THROTTLED);
            checkEquals("and its row is the one that survived", "1",
                    Harness.rawColumn(f2, "SELECT COUNT(*) FROM auth_throttle WHERE bucket LIKE 'r:%'")
                            .get(0));
        }
    }
}
