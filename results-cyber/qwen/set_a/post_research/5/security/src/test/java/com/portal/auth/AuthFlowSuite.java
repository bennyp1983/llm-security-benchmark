package com.portal.auth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The decision itself: what a caller may learn, what the throttle does under a burst, what
 * the durable counters do across a restart, and whether every refusal really costs the same.
 *
 * <p>Timing assertions are the reason this suite is slow. Each {@code authenticate()} call
 * performs a real 100k-iteration derivation, and the measurements that matter are made
 * twice: once with the latency padding <em>suppressed</em> (to see the paths' true cost
 * spread, which a padded run would hide) and once with the floor <em>raised</em> well above
 * the KDF cost (to prove the padding holds every path up, which a spread-only assertion
 * cannot detect -- deleting the work from every branch leaves a perfect spread).
 */
public final class AuthFlowSuite {

    private static final String SRC_A = "10.0.0.1";
    private static final String SRC_B = "10.0.0.2";
    private static final java.time.Instant T0 = java.time.Instant.parse("2026-03-01T12:00:00Z");

    public static void main(String[] args) {
        TestKit.systemClock();
        grantAndDeny();
        passwordClearing();
        rosterPropagation();
        accountThrottle();
        sourceThrottle();
        concurrency();
        ledgerPersistence();
        sessions();
        csrf();
        timings();
        integrationAudit();
        System.exit(TestKit.report("auth-flow"));
    }

    // --------------------------------------------------------------------- fixtures

    private static final class Rig {
        final Path dir;
        final AuditLog audit;
        final PasswordHasher hasher;
        final EmployeeStore store;
        final Ledger ledger;
        final ThrottleManager throttle;
        final SessionManager sessions;
        final Authenticator auth;

        Rig(String label) throws IOException {
            dir = TestKit.scratchDir(label);
            audit = new AuditLog(dir.resolve("audit.log"));
            hasher = new PasswordHasher(TestKit.FAST_ITERATIONS);
            store = new EmployeeStore(dir.resolve("employees.dat"), hasher, audit);
            store.initialiseEmpty();
            ledger = new Ledger(dir.resolve("throttle.log"));
            throttle = new ThrottleManager(ledger);
            sessions = new SessionManager();
            auth = new Authenticator(store, hasher, throttle, sessions, audit);
        }

        void add(String user, String pw) {
            TestKit.eq("fixture create " + user, EmployeeStore.CreateResult.CREATED,
                    store.create(user, pw.toCharArray()));
        }

        Authenticator.Result login(String user, String pw, String source) {
            return auth.authenticate(user, pw.toCharArray(), source);
        }

        /** Clears both dimensions so a fixture starts from a known-clean budget. */
        void reset(String user, String source) {
            throttle.clearAccountForTesting(Crypto.idRef(user));
            throttle.clearAccountForTesting(SourceRef.ref(source));
        }
    }

    /** A measured call plus the (untimed) setup that must not appear in the sample. */
    private record TimedPath(String name, Runnable prep, Runnable call) {
    }

    // ------------------------------------------------------------- rules 3/6: decisions

    private static void grantAndDeny() {
        TestKit.caseOf("correct credentials grant and mint a usable session", () -> {
            Rig rig = new Rig("flow-grant");
            rig.add("alice", TestKit.PW_ALICE);
            Authenticator.Result r = rig.login("alice", TestKit.PW_ALICE, SRC_A);
            TestKit.ok("granted", r.isSuccess());
            TestKit.eq("reason", "CREDENTIALS_OK", r.reasonForInternalUseOnly());
            TestKit.eq("username", "alice", r.username());
            TestKit.ok("session id well-formed", InputPolicy.isSessionToken(r.sessionId()));
            TestKit.ok("session resolves server-side", rig.sessions.find(r.sessionId()).isPresent());
            TestKit.eq("session names the user", "alice",
                    rig.sessions.find(r.sessionId()).orElseThrow().username);
            TestKit.ok("the id is not the username or a function of it",
                    !r.sessionId().contains("alice"));
        });

        TestKit.caseOf("case-insensitive name, exact password", () -> {
            Rig rig = new Rig("flow-fold");
            rig.add("alice", TestKit.PW_ALICE);
            TestKit.ok("ALICE grants", rig.login("ALICE", TestKit.PW_ALICE, SRC_A).isSuccess());
            TestKit.ok("Alice grants", rig.login("Alice", TestKit.PW_ALICE, SRC_A).isSuccess());
            TestKit.ok("a case-folded wrong password still fails",
                    !rig.login("ALICE", TestKit.PW_WRONG, SRC_A).isSuccess());
        });

        TestKit.caseOf("wrong password denies", () -> {
            Rig rig = new Rig("flow-wrong");
            rig.add("alice", TestKit.PW_ALICE);
            Authenticator.Result r = rig.login("alice", TestKit.PW_WRONG, SRC_A);
            TestKit.ok("denied", !r.isSuccess());
            TestKit.ok("no session issued", r.sessionId() == null);
            TestKit.eq("reason", "BAD_CREDENTIALS", r.reasonForInternalUseOnly());
            rig.reset("alice", SRC_A);
            TestKit.ok("one character different denies", !rig.login("alice",
                    TestKit.PW_ALICE.substring(0, TestKit.PW_ALICE.length() - 1) + "?",
                    SRC_A).isSuccess());
        });

        TestKit.caseOf("an unknown name is refused exactly like a wrong password", () -> {
            Rig rig = new Rig("flow-unknown");
            rig.add("alice", TestKit.PW_ALICE);
            Authenticator.Result known = rig.login("alice", TestKit.PW_WRONG, SRC_A);
            rig.reset("alice", SRC_A);
            Authenticator.Result unknown = rig.login("nobody-here", TestKit.PW_WRONG, SRC_A);
            TestKit.eq("both deny", known.isSuccess(), unknown.isSuccess());
            TestKit.eq("identical internal reason, so identical rendering",
                    known.reasonForInternalUseOnly(), unknown.reasonForInternalUseOnly());
            TestKit.eq("both produce no session", known.sessionId(), unknown.sessionId());
        });

        TestKit.caseOf("a disabled account behaves exactly like a wrong password", () -> {
            Rig rig = new Rig("flow-disabled");
            rig.add("alice", TestKit.PW_ALICE);
            rig.store.disableAccount("alice");
            Authenticator.Result r = rig.login("alice", TestKit.PW_ALICE, SRC_A);
            TestKit.ok("the real password on a disabled account is denied", !r.isSuccess());
            TestKit.eq("indistinguishable from a wrong password", "BAD_CREDENTIALS",
                    r.reasonForInternalUseOnly());
        });

        TestKit.caseOf("malformed input is refused, never defaulted", () -> {
            Rig rig = new Rig("flow-malformed");
            rig.add("alice", TestKit.PW_ALICE);
            String[] names = {"", "ab", "alice ", "alice\t", "a".repeat(40), "a..b", ".alice",
                    "ali\u00e7e", "\uFF41lice", "a=b", "a/b"};
            for (String n : names) {
                Authenticator.Result r = rig.login(n, TestKit.PW_WRONG, SRC_A);
                TestKit.ok("refused name [" + show(n) + "]", !r.isSuccess());
                TestKit.eq("says only 'input invalid' [" + show(n) + "]", "INPUT_INVALID",
                        r.reasonForInternalUseOnly());
            }
            TestKit.ok("null name is denied", !rig.auth
                    .authenticate((String) null, TestKit.PW_ALICE.toCharArray(), SRC_A).isSuccess());
            String[] secrets = {"short1!", "", "x".repeat(200), " has-space-1Aa!",
                    "tabbed\u0009Password1", "nul\u0000Password1Aa", "nonasc\u00e99Password",
                    "trailing-space-1Aa "};
            for (String s : secrets) {
                Authenticator.Result r = rig.login("alice", s, SRC_A);
                TestKit.ok("refused secret len " + s.length(), !r.isSuccess());
                TestKit.eq("never reveals why", "INPUT_INVALID", r.reasonForInternalUseOnly());
            }
        });

        TestKit.caseOf("a trailing invisible character is never folded onto a real account", () -> {
            Rig rig = new Rig("flow-tab");
            rig.add("alice", TestKit.PW_ALICE);
            for (String suffix : List.of("\t", " ", "\u0000", "\n", "\u00a0", "\u200B")) {
                Authenticator.Result r = rig.login("alice" + suffix, TestKit.PW_ALICE, SRC_A);
                TestKit.ok("alice+" + (int) suffix.charAt(0) + " is refused", !r.isSuccess());
                TestKit.eq("and refused as bad input, not as a wrong password", "INPUT_INVALID",
                        r.reasonForInternalUseOnly());
            }
        });

        TestKit.caseOf("the denial vocabulary the client can ever see", () -> {
            Rig rig = new Rig("flow-uniform");
            rig.add("alice", TestKit.PW_ALICE);
            List<String> credentialShaped = new ArrayList<>();
            credentialShaped.add(rig.login("alice", TestKit.PW_WRONG, SRC_A).reasonForInternalUseOnly());
            rig.reset("alice", SRC_A);
            credentialShaped.add(rig.login("ghost", TestKit.PW_WRONG, SRC_A).reasonForInternalUseOnly());
            rig.reset("ghost", SRC_A);
            rig.store.disableAccount("alice");
            credentialShaped.add(rig.login("alice", TestKit.PW_ALICE, SRC_A).reasonForInternalUseOnly());
            TestKit.ok("wrong password, unknown name and disabled account are one token",
                    credentialShaped.stream().distinct().count() == 1);
            Rig empty = new Rig("flow-empty-roster");
            TestKit.ok("an empty roster denies too (fail closed, no default)",
                    !empty.login("anyone", TestKit.PW_ALICE, SRC_A).isSuccess());
        });
    }

    private static void passwordClearing() {
        TestKit.caseOf("the presented password array is cleared on every path", () -> {
            Rig rig = new Rig("flow-wipe");
            rig.add("alice", TestKit.PW_ALICE);
            char[] ok = TestKit.PW_ALICE.toCharArray();
            rig.auth.authenticate("alice", ok, SRC_A);
            TestKit.ok("cleared after success", isBlank(ok));

            char[] wrong = TestKit.PW_WRONG.toCharArray();
            rig.auth.authenticate("alice", wrong, SRC_A);
            TestKit.ok("cleared after a wrong password", isBlank(wrong));

            char[] badName = TestKit.PW_ALICE.toCharArray();
            rig.auth.authenticate("bad name!", badName, SRC_A);
            TestKit.ok("cleared after a refused name", isBlank(badName));

            char[] badSecret = "x".toCharArray();
            rig.auth.authenticate("alice", badSecret, SRC_A);
            TestKit.ok("cleared after a refused secret", isBlank(badSecret));

            for (int i = 0; i < ThrottleManager.ACCOUNT_MAX_FAILURES; i++) {
                rig.login("alice", TestKit.PW_WRONG, SRC_A);
            }
            char[] throttled = TestKit.PW_WRONG.toCharArray();
            rig.auth.authenticate("alice", throttled, SRC_A);
            TestKit.ok("cleared while throttled", isBlank(throttled));

            char[] nullUser = TestKit.PW_ALICE.toCharArray();
            rig.auth.authenticate((String) null, nullUser, SRC_A);
            TestKit.ok("cleared for a null user", isBlank(nullUser));

            char[] emptyUser = TestKit.PW_ALICE.toCharArray();
            rig.auth.authenticate("", emptyUser, SRC_A);
            TestKit.ok("cleared for an empty user", isBlank(emptyUser));

            char[] unknownUser = TestKit.PW_ALICE.toCharArray();
            rig.auth.authenticate("ghost", unknownUser, SRC_A);
            TestKit.ok("cleared for an unknown user", isBlank(unknownUser));
        });
    }

    // ------------------------------------- rules 3/7: another process changes the roster

    private static void rosterPropagation() {
        TestKit.caseOf("a revocation made by another process is adopted by the next decision",
                () -> {
            // The portal is a long-lived process; enrolment, rotation and disablement are
            // short-lived CLI processes against the same file. Verifying against the copy
            // loaded at boot means a revoked employee keeps signing in until restart.
            Rig rig = new Rig("flow-stale-roster");
            rig.add("revoked", TestKit.PW_ALICE);
            Path roster = rig.dir.resolve("employees.dat");
            EmployeeStore cli = new EmployeeStore(roster, rig.hasher, rig.audit);
            TestKit.eq("the second process loads the same roster", 1, cli.load());
            cli.disableAccount("revoked");
            TestKit.ok("the writing process sees it as disabled", cli.isDisabled("revoked"));
            TestKit.ok("the long-lived copy is genuinely stale -- which is what is being fixed",
                    !rig.store.isDisabled("revoked"));
            Authenticator.Result afterDisable = rig.login("revoked", TestKit.PW_ALICE, SRC_A);
            TestKit.ok("the revoked account is denied", !afterDisable.isSuccess());
            TestKit.eq("as an ordinary credential failure, with no new reason to enumerate",
                    "BAD_CREDENTIALS", afterDisable.reasonForInternalUseOnly());

            cli.rotateSecret("revoked", TestKit.PW_BOB.toCharArray());
            TestKit.ok("the superseded password stops working",
                    !rig.login("revoked", TestKit.PW_ALICE, SRC_A).isSuccess());
            TestKit.ok("and the replacement works, so this is not a blanket refusal",
                    rig.login("revoked", TestKit.PW_BOB, SRC_A).isSuccess());

            TestKit.eq("a fresh enrolment lands", EmployeeStore.CreateResult.CREATED,
                    cli.create("newhire", TestKit.PW_CAROL.toCharArray()));
            TestKit.ok("the new account can sign in without restarting the portal",
                    rig.login("newhire", TestKit.PW_CAROL, SRC_A).isSuccess());
        });

        TestKit.caseOf("an unreadable roster fails closed and recovers without latching", () -> {
            Rig rig = new Rig("flow-stale-roster-down");
            rig.add("revoked", TestKit.PW_ALICE);
            Path roster = rig.dir.resolve("employees.dat");
            byte[] good = Files.readAllBytes(roster);
            Files.writeString(roster, EmployeeStore.HEADER + "\nu=revoked r=NOT-A-RECORD\n");
            TestKit.ok("the last known-good copy is not honoured",
                    !rig.login("revoked", TestKit.PW_ALICE, SRC_A).isSuccess());
            TestKit.ok("and the next request is denied too",
                    !rig.login("revoked", TestKit.PW_ALICE, SRC_A).isSuccess());
            long logged = -1;
            try {
                logged = Files.readString(rig.dir.resolve("audit.log")).lines()
                        .filter(l -> l.contains("event=roster-refresh")).count();
            } catch (IOException unreadable) {
                TestKit.ok("the audit log is readable", false);
            }
            TestKit.eq("the corrupt file is parsed once, not re-parsed every request",
                    1L, logged);
            TestKit.ok("failing closed never rewrites the operator's roster",
                    Files.readString(roster).contains("NOT-A-RECORD"));
            rig.reset("revoked", SRC_A);
            Files.write(roster, good);
            TestKit.ok("a valid roster restores access -- the guard must not latch",
                    rig.login("revoked", TestKit.PW_ALICE, SRC_A).isSuccess());
        });
    }

    // ---------------------------------------------------------- rule 3: rate limiting

    private static void accountThrottle() {
        TestKit.caseOf("the account budget is exactly ACCOUNT_MAX_FAILURES", () -> {
            Rig rig = new Rig("flow-acct");
            rig.add("alice", TestKit.PW_ALICE);
            for (int i = 0; i < ThrottleManager.ACCOUNT_MAX_FAILURES; i++) {
                Authenticator.Result r = rig.login("alice", TestKit.PW_WRONG, SRC_A);
                TestKit.ok("attempt " + (i + 1) + " is a credential denial",
                        !r.isSuccess() && r.reasonForInternalUseOnly().equals("BAD_CREDENTIALS"));
            }
            Authenticator.Result after = rig.login("alice", TestKit.PW_WRONG, SRC_A);
            TestKit.ok("the next attempt is still denied", !after.isSuccess());
            TestKit.eq("and is now internally throttled", "THROTTLED",
                    after.reasonForInternalUseOnly());
            TestKit.ok("a back-off was applied",
                    rig.throttle.accountBlockRemaining(Crypto.idRef("alice")) > 0);
        });

        TestKit.caseOf("during the window even the right password is refused", () -> {
            // Stated as a finding, not a surprise: this is the price of any per-account
            // limit. What keeps it from being a lockout weapon is that the window is short,
            // self-clearing and decaying -- asserted in the next two cases.
            Rig rig = new Rig("flow-acct-blocked");
            rig.add("alice", TestKit.PW_ALICE);
            for (int i = 0; i < ThrottleManager.ACCOUNT_MAX_FAILURES; i++) {
                rig.login("alice", TestKit.PW_WRONG, SRC_A);
            }
            Authenticator.Result during = rig.login("alice", TestKit.PW_ALICE, SRC_A);
            TestKit.ok("refused inside the window", !during.isSuccess());
            TestKit.eq("and the client-visible answer is the same generic denial",
                    "THROTTLED", during.reasonForInternalUseOnly());
        });

        TestKit.caseOf("the window lapses and the real user gets in unaided", () -> {
            Rig rig = new Rig("flow-acct-lapse");
            rig.add("alice", TestKit.PW_ALICE);
            TestKit.fixedClockAt(T0);
            for (int i = 0; i < ThrottleManager.ACCOUNT_MAX_FAILURES; i++) {
                rig.login("alice", TestKit.PW_WRONG, SRC_A);
            }
            long blocked = rig.throttle.accountBlockRemaining(Crypto.idRef("alice"));
            TestKit.ok("the first window is the base back-off",
                    blocked == ThrottleManager.BASE_BLOCK_SECONDS);
            TestKit.ok("refused inside it", !rig.login("alice", TestKit.PW_ALICE, SRC_A).isSuccess());
            TestKit.fixedClockAt(T0.plusSeconds(blocked + 2));
            Authenticator.Result recovered = rig.login("alice", TestKit.PW_ALICE, SRC_A);
            TestKit.ok("self-clearing: no administrator needed", recovered.isSuccess());
            TestKit.eq("and a verified success resets the strike count", 0,
                    rig.throttle.failureCountFor(Crypto.idRef("alice")));
            TestKit.systemClock();
        });

        TestKit.caseOf("the window grows while abuse continues, to a bounded ceiling", () -> {
            Rig rig = new Rig("flow-acct-grow");
            rig.add("alice", TestKit.PW_ALICE);
            java.time.Instant t = T0;
            long previous = 0;
            long last = 0;
            for (int round = 0; round < 7; round++) {
                TestKit.fixedClockAt(t);
                for (int i = 0; i < ThrottleManager.ACCOUNT_MAX_FAILURES; i++) {
                    rig.login("alice", TestKit.PW_WRONG, SRC_A);
                }
                long blocked = rig.throttle.accountBlockRemaining(Crypto.idRef("alice"));
                TestKit.measure("account-block-round-" + round, blocked + "s");
                TestKit.ok("round " + round + " did not shrink (" + previous + " -> " + blocked + ")",
                        blocked >= previous);
                TestKit.ok("never past the account ceiling",
                        blocked <= ThrottleManager.MAX_ACCOUNT_BLOCK_SECONDS);
                previous = blocked;
                last = blocked;
                t = t.plusSeconds(blocked + 5);
            }
            // 30, 60, 120, 240, 480, then the ceiling. Asserting the ceiling is reached (and
            // then held) is what pins the documented MAX_ACCOUNT_BLOCK_SECONDS to the code:
            // an exponent cap that stops a step early leaves this green forever otherwise.
            TestKit.eq("the documented ceiling is the one actually enforced",
                    ThrottleManager.MAX_ACCOUNT_BLOCK_SECONDS, last);
            TestKit.ok("and it is held rather than overshot",
                    previous == ThrottleManager.MAX_ACCOUNT_BLOCK_SECONDS);
            TestKit.systemClock();
        });

        TestKit.caseOf("a verified success inside the budget clears the history", () -> {
            Rig rig = new Rig("flow-acct-clear");
            rig.add("alice", TestKit.PW_ALICE);
            for (int i = 0; i < ThrottleManager.ACCOUNT_MAX_FAILURES - 1; i++) {
                rig.login("alice", TestKit.PW_WRONG, SRC_A);
            }
            TestKit.ok("success while there is headroom",
                    rig.login("alice", TestKit.PW_ALICE, SRC_A).isSuccess());
            TestKit.eq("account counters cleared", 0,
                    rig.throttle.failureCountFor(Crypto.idRef("alice")));
            int used = 0;
            while (!rig.throttle.isAccountBlocked(Crypto.idRef("alice"))) {
                rig.login("alice", TestKit.PW_WRONG, SRC_A);
                used++;
                TestKit.ok("no lockout before the budget is spent",
                        used <= ThrottleManager.ACCOUNT_MAX_FAILURES);
            }
            TestKit.eq("a full fresh budget was needed", ThrottleManager.ACCOUNT_MAX_FAILURES, used);
        });

        TestKit.caseOf("the window rolls over and strikes decay", () -> {
            Rig rig = new Rig("flow-acct-window");
            rig.add("alice", TestKit.PW_ALICE);
            TestKit.fixedClockAt(T0);
            for (int i = 0; i < 3; i++) {
                rig.login("alice", TestKit.PW_WRONG, SRC_A);
            }
            TestKit.eq("counted", 3, rig.throttle.failureCountFor(Crypto.idRef("alice")));
            TestKit.fixedClockAt(T0.plusSeconds(ThrottleManager.WINDOW_SECONDS + 60));
            TestKit.eq("rolled over to zero", 0,
                    rig.throttle.failureCountFor(Crypto.idRef("alice")));
            // After a quiet window the back-off must start from the base again, not from
            // wherever the exponent had reached.
            for (int i = 0; i < ThrottleManager.ACCOUNT_MAX_FAILURES; i++) {
                rig.login("alice", TestKit.PW_WRONG, SRC_A);
            }
            TestKit.eq("back-off restarted at the base", ThrottleManager.BASE_BLOCK_SECONDS,
                    rig.throttle.accountBlockRemaining(Crypto.idRef("alice")));
            TestKit.systemClock();
        });
    }

    private static void sourceThrottle() {
        TestKit.caseOf("a spray across many accounts locks none of them", () -> {
            // The arithmetic that makes this true: one source may spend
            // SOURCE_MAX_FAILURES in total, and locking one account costs ACCOUNT_MAX, so a
            // single source can burn at most SOURCE/ACCOUNT (= 6) accounts per window. With
            // more targets than that, no individual account can reach its threshold before
            // the attacker's own address is blocked.
            Rig rig = new Rig("flow-src");
            int victims = 12;
            for (int i = 0; i < victims; i++) {
                rig.add("victim" + i, TestKit.PW_ALICE);
            }
            int sent = 0;
            while (!rig.throttle.isSourceBlocked(SourceRef.ref(SRC_A))) {
                Authenticator.Result r = rig.login("victim" + (sent % victims),
                        TestKit.PW_WRONG, SRC_A);
                TestKit.ok("attempt " + sent + " denied on credentials",
                        !r.isSuccess() && r.reasonForInternalUseOnly().equals("BAD_CREDENTIALS"));
                sent++;
                TestKit.ok("the source ceiling caps the spray",
                        sent <= ThrottleManager.SOURCE_MAX_FAILURES);
            }
            TestKit.eq("the source ceiling was reached", ThrottleManager.SOURCE_MAX_FAILURES, sent);
            TestKit.ok("the attacker's own address is now blocked",
                    rig.throttle.isSourceBlocked(SourceRef.ref(SRC_A)));
            for (int i = 0; i < victims; i++) {
                TestKit.ok("victim" + i + " is not locked",
                        !rig.throttle.isAccountBlocked(Crypto.idRef("victim" + i)));
            }
            rig.throttle.clearAccountForTesting(SourceRef.ref(SRC_A));
            TestKit.ok("and a victim can still sign in from elsewhere",
                    rig.login("victim0", TestKit.PW_ALICE, SRC_B).isSuccess());
        });

        TestKit.caseOf("an unrelated user on another source is unaffected", () -> {
            Rig rig = new Rig("flow-src-b");
            // The spray has to be spread over accounts: hammering one name burns that
            // name's 5-slot budget on request 5, and every later request is refused by
            // the account gate before it can be charged to the source. Only a spread can
            // spend the source budget at all -- which is itself the anti-lockout property.
            int victims = ThrottleManager.SOURCE_MAX_FAILURES / ThrottleManager.ACCOUNT_MAX_FAILURES
                    + 2;
            for (int i = 0; i < victims; i++) {
                rig.add("target" + i, TestKit.PW_ALICE);
            }
            rig.add("carol", TestKit.PW_CAROL);
            for (int i = 0; i < victims * ThrottleManager.ACCOUNT_MAX_FAILURES; i++) {
                rig.login("target" + (i % victims), TestKit.PW_WRONG, SRC_A);
            }
            TestKit.ok("source A is blocked", rig.throttle.isSourceBlocked(SourceRef.ref(SRC_A)));
            TestKit.ok("a refusal from the blocked source is still a plain denial",
                    !rig.login("target0", TestKit.PW_ALICE, SRC_A).isSuccess());
            TestKit.ok("carol from source B is fine",
                    rig.login("carol", TestKit.PW_CAROL, SRC_B).isSuccess());
        });

        TestKit.caseOf("boundary probing is charged to the source budget too", () -> {
            Rig rig = new Rig("flow-src-abuse");
            rig.add("alice", TestKit.PW_ALICE);
            for (int i = 0; i < ThrottleManager.SOURCE_MAX_FAILURES; i++) {
                rig.login("bad name!", TestKit.PW_WRONG, SRC_A);
            }
            TestKit.ok("repeated probing trips the source block",
                    rig.throttle.isSourceBlocked(SourceRef.ref(SRC_A)));
            TestKit.ok("a real login from that source is then refused",
                    !rig.login("alice", TestKit.PW_ALICE, SRC_A).isSuccess());
        });

        TestKit.caseOf("a spray of unknown names arms the source back-off, not just its counter",
                () -> {
            // The reservation counter on its own rolls clean at the next window boundary
            // (see ThrottleManager.beginAttempt): only recordFailure arms the timed block.
            // A denial path that skips it would leave an automated spray throttled for one
            // 300 s window instead of the source ceiling -- and unknown names are the case
            // where nothing else arms it, because no real account is ever touched.
            Rig rig = new Rig("flow-src-unknown-spray");
            rig.add("alice", TestKit.PW_ALICE);
            int targets = ThrottleManager.SOURCE_MAX_FAILURES;
            for (int i = 0; i < targets; i++) {
                Authenticator.Result r = rig.login("ghost" + i, TestKit.PW_WRONG, SRC_A);
                TestKit.ok("unknown attempt " + i + " is a plain credential denial",
                        !r.isSuccess() && r.reasonForInternalUseOnly().equals("BAD_CREDENTIALS"));
            }
            TestKit.ok("the spraying address is blocked, not merely counted",
                    rig.throttle.isSourceBlocked(SourceRef.ref(SRC_A)));
            Map<String, Ledger.Counter> rows = rig.ledger.load(AuditClock.epochSecond(),
                    ThrottleManager.RETENTION_SECONDS);
            Ledger.Counter row = rows.get(Ledger.key('s', SourceRef.ref(SRC_A)));
            TestKit.ok("the armed window runs to the full source ceiling",
                    row != null
                            && row.blockedUntil - AuditClock.epochSecond()
                               >= ThrottleManager.MAX_SOURCE_BLOCK_SECONDS - 1);
            TestKit.ok("the next attempt from that address is refused by the throttle",
                    rig.login("ghost99", TestKit.PW_WRONG, SRC_A).reasonForInternalUseOnly()
                            .equals("THROTTLED"));
            TestKit.ok("no account was locked by spraying names that do not exist",
                    !rig.throttle.isAccountBlocked(Crypto.idRef("alice")));
            TestKit.ok("a real user from another address is unaffected",
                    rig.login("alice", TestKit.PW_ALICE, SRC_B).isSuccess());
        });

        TestKit.caseOf("unparseable sources share one bucket and are still throttled", () -> {
            Rig rig = new Rig("flow-src-unknown");
            rig.add("alice", TestKit.PW_ALICE);
            String[] hostile = {"", "not-an-ip", "999.1.1.1", "1.2.3.4 ", "%20",
                    "x".repeat(300), "fe80::1%eth0", "localhost"};
            for (String h : hostile) {
                rig.login("alice", TestKit.PW_WRONG, h);
                rig.throttle.clearAccountForTesting(Crypto.idRef("alice"));
            }
            String unknown = SourceRef.normalizeForLedger("garbage");
            TestKit.eq("all hostile labels collapse into one bucket", unknown,
                    SourceRef.normalizeForLedger("also garbage"));
            TestKit.ok("the shared bucket accumulated every probe",
                    rig.throttle.failureCountForSource(unknown) >= hostile.length);
            for (int i = 0; i < ThrottleManager.SOURCE_MAX_FAILURES + 5; i++) {
                rig.throttle.consumeSourceBudget(unknown);
            }
            TestKit.ok("and it can be driven to a block",
                    rig.throttle.isSourceBlocked(unknown));
            TestKit.ok("a malformed address cannot opt out of limiting",
                    !unknown.equals(SourceRef.normalizeForLedger("10.0.0.1")));
        });
    }

    // ------------------------------------------------------------------ rule 7: atomic

    private static void concurrency() {
        TestKit.caseOf("a burst cannot exceed the reserved budget", () -> {
            // A race that happens to serialise passes for broken code too, so the
            // assertion is on the exact arithmetic of the reservation rather than on
            // timing: ALLOWED + THROTTLED == threads and ALLOWED == budget, every run.
            Ledger ledger = new Ledger(TestKit.scratchDir("conc-ledger").resolve("t.log"));
            ThrottleManager t = new ThrottleManager(ledger);
            String acct = Crypto.idRef("alice");
            String src = SourceRef.ref(SRC_A);
            int threads = ThrottleManager.ACCOUNT_MAX_FAILURES * 6;
            AtomicInteger allowed = new AtomicInteger();
            AtomicInteger throttled = new AtomicInteger();
            ConcurrentLinkedQueue<String> errors = new ConcurrentLinkedQueue<>();
            CountDownLatch ready = new CountDownLatch(threads);
            CountDownLatch go = new CountDownLatch(1);
            List<Thread> live = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                Thread w = new Thread(() -> {
                    ready.countDown();
                    try {
                        go.await();
                    } catch (InterruptedException gone) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                    try {
                        switch (t.beginAttempt(acct, src)) {
                            case ALLOWED -> allowed.incrementAndGet();
                            case THROTTLED -> throttled.incrementAndGet();
                        }
                    } catch (RuntimeException boom) {
                        errors.add(boom.toString());
                    }
                }, "burst-" + i);
                live.add(w);
                w.start();
            }
            try {
                ready.await();
                go.countDown();
                for (Thread w : live) {
                    w.join(60_000);
                }
            } catch (InterruptedException gone) {
                Thread.currentThread().interrupt();
            }
            TestKit.ok("no worker threw: " + errors, errors.isEmpty());
            TestKit.eq("every thread got a verdict", threads, allowed.get() + throttled.get());
            TestKit.eq("exactly the budget was reserved",
                    ThrottleManager.ACCOUNT_MAX_FAILURES, allowed.get());
            TestKit.eq("the rest were refused",
                    threads - ThrottleManager.ACCOUNT_MAX_FAILURES, throttled.get());
            TestKit.eq("the stored count never overshot",
                    ThrottleManager.ACCOUNT_MAX_FAILURES, t.failureCountFor(acct));
            // A reservation alone is not a failed credential, so it does not arm the timed
            // window (see beginAttempt). What the race must guarantee is that the excess
            // got no slot: THROTTLED is what authenticates as a refusal.
            TestKit.ok("the account is gated once the budget is spent",
                    t.beginAttempt(acct, src) == ThrottleManager.Kind.THROTTLED);
        });

        TestKit.caseOf("concurrent wrong passwords cannot sneak a grant", () -> {
            Rig rig = new Rig("flow-conc-auth");
            rig.add("alice", TestKit.PW_ALICE);
            int threads = 4;
            AtomicInteger granted = new AtomicInteger();
            CountDownLatch go = new CountDownLatch(1);
            List<Thread> live = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                Thread w = new Thread(() -> {
                    try {
                        go.await();
                    } catch (InterruptedException gone) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                    if (rig.login("alice", TestKit.PW_WRONG, SRC_A).isSuccess()) {
                        granted.incrementAndGet();
                    }
                }, "auth-" + i);
                live.add(w);
                w.start();
            }
            try {
                go.countDown();
                for (Thread w : live) {
                    w.join(120_000);
                }
            } catch (InterruptedException gone) {
                Thread.currentThread().interrupt();
            }
            TestKit.eq("nobody is authenticated by a race", 0, granted.get());
            TestKit.ok("the counter stayed within the budget",
                    rig.throttle.failureCountFor(Crypto.idRef("alice"))
                            <= ThrottleManager.ACCOUNT_MAX_FAILURES);
        });

        TestKit.caseOf("concurrent successes each get a distinct session", () -> {
            Rig rig = new Rig("flow-conc-session");
            rig.add("alice", TestKit.PW_ALICE);
            // Four concurrent successes, inside the account budget: a lost put or a
            // duplicated id in SessionManager shows up here as a count below four. The
            // budget interacts with concurrency by design (every attempt reserves a slot,
            // a verified success then clears it), so a burst larger than the budget would
            // make the *number* of grants genuinely nondeterministic -- that is asserted
            // for safety elsewhere, and only the identity of what is issued is asserted
            // here.
            java.util.Set<String> ids = java.util.Collections.synchronizedSet(
                    new java.util.HashSet<>());
            List<Thread> live = new ArrayList<>();
            for (int i = 0; i < 4; i++) {
                Thread w = new Thread(() -> {
                    Authenticator.Result r = rig.login("alice", TestKit.PW_ALICE, SRC_A);
                    if (r.isSuccess()) {
                        ids.add(r.sessionId());
                    }
                });
                live.add(w);
                w.start();
            }
            for (Thread w : live) {
                try {
                    w.join(120_000);
                } catch (InterruptedException gone) {
                    Thread.currentThread().interrupt();
                }
            }
            TestKit.eq("all four were granted", 4, ids.size());
            TestKit.ok("no null session", !ids.contains(null));
            TestKit.eq("every id resolves server-side", 4L,
                    ids.stream().filter(s -> rig.sessions.find(s).isPresent()).count());
            TestKit.eq("the store kept all four", 4, rig.sessions.liveSessionCount());
        });
    }

    // ------------------------------------------------------- rule 7: durable counters

    private static void ledgerPersistence() {
        TestKit.caseOf("throttle state survives a restart", () -> {
            Rig rig = new Rig("flow-ledger");
            rig.add("alice", TestKit.PW_ALICE);
            for (int i = 0; i < ThrottleManager.ACCOUNT_MAX_FAILURES; i++) {
                rig.login("alice", TestKit.PW_WRONG, SRC_A);
            }
            TestKit.ok("blocked before the restart",
                    rig.throttle.isAccountBlocked(Crypto.idRef("alice")));
            TestKit.ok("ledger file exists", rig.ledger.exists());
            TestKit.eq("ledger mode is private", "rw-------",
                    TestKit.mode(rig.dir.resolve("throttle.log")));
            ThrottleManager restarted =
                    new ThrottleManager(new Ledger(rig.dir.resolve("throttle.log")));
            TestKit.ok("blocked after the restart",
                    restarted.isAccountBlocked(Crypto.idRef("alice")));
            // The decision, not just the flag: a restarted process must actually refuse.
            TestKit.ok("a restarted process refuses the attempt",
                    restarted.beginAttempt(Crypto.idRef("alice"), SourceRef.ref(SRC_A))
                            == ThrottleManager.Kind.THROTTLED);
            long remaining = restarted.accountBlockRemaining(Crypto.idRef("alice"));
            TestKit.ok("the back-off window survives with its duration intact",
                    remaining >= 1 && remaining <= ThrottleManager.BASE_BLOCK_SECONDS);
            // What the counter reads while a block is live, pinned precisely because an
            // earlier version of this assertion got it wrong for the right-looking reason.
            // recordFailure restarts the window when it arms the back-off (failures=0,
            // windowStart=now), so the five failures that armed it are spent, not carried.
            // The assertion here used to demand 5, and it passed only because the ledger
            // merged counts with max() and resurrected the value the writer had just
            // cleared -- the same monotonic-merge defect that denied a user their sixth
            // consecutive CORRECT login. Enforcement does not depend on it: beginAttempt
            // gates on blockedUntil, asserted two lines above.
            TestKit.eq("the armed window restarted rather than carrying the spent failures",
                    0, restarted.failureCountFor(Crypto.idRef("alice")));
            // The source dimension needs its own fixture: hammering one account cannot
            // spend the source budget (the account gate refuses first), so drive the
            // non-authentication path that consumes it directly.
            for (int i = 0; i < ThrottleManager.SOURCE_MAX_FAILURES; i++) {
                rig.throttle.consumeSourceBudget(SourceRef.ref(SRC_B));
            }
            TestKit.ok("source blocked before the restart",
                    rig.throttle.isSourceBlocked(SourceRef.ref(SRC_B)));
            ThrottleManager restarted2 =
                    new ThrottleManager(new Ledger(rig.dir.resolve("throttle.log")));
            TestKit.ok("the source block survives too",
                    restarted2.isSourceBlocked(SourceRef.ref(SRC_B)));
            TestKit.ok("the unrelated account block is still there as well",
                    restarted2.isAccountBlocked(Crypto.idRef("alice")));
        });

        TestKit.caseOf("a corrupt ledger resets to the strictest state", () -> {
            Rig rig = new Rig("flow-ledger-corrupt");
            rig.add("alice", TestKit.PW_ALICE);
            for (int i = 0; i < 2; i++) {
                rig.login("alice", TestKit.PW_WRONG, SRC_A);
            }
            Path log = rig.dir.resolve("throttle.log");
            PrivateFiles.writePrivateAtomic(log,
                    "v1|a|garbage line that is not a counter\n".getBytes(StandardCharsets.UTF_8));
            ThrottleManager restarted = new ThrottleManager(new Ledger(log));
            TestKit.eq("the anomaly is reported", 1L, restarted.ledgerLossCount());
            TestKit.eq("counters restart at zero", 0,
                    restarted.failureCountFor(Crypto.idRef("alice")));
            // Zero is the strictest reading: the next attempt is checked rather than
            // trusted, and enforcement simply starts from the top of the budget.
            TestKit.ok("enforcement continues", restarted.beginAttempt(Crypto.idRef("alice"),
                    SourceRef.ref(SRC_A)) == ThrottleManager.Kind.ALLOWED);
            TestKit.eq("and counting resumed", 1, restarted.failureCountFor(Crypto.idRef("alice")));
        });

        TestKit.caseOf("a racing sibling can only raise the danger level", () -> {
            Path dir = TestKit.scratchDir("flow-ledger-merge");
            Ledger ledger = new Ledger(dir.resolve("throttle.log"));
            String subject = Ledger.key('a', Crypto.idRef("alice"));
            long now = AuditClock.epochSecond();
            ledger.persist(Map.of(subject, new Ledger.Counter(now, 9, now + 600)));
            ThrottleManager fresh = new ThrottleManager(ledger);
            fresh.beginAttempt(Crypto.idRef("alice"), SourceRef.ref(SRC_A));
            Map<String, Ledger.Counter> after =
                    ledger.load(now, ThrottleManager.RETENTION_SECONDS);
            TestKit.eq("the higher count survived", 9, after.get(subject).count);
            TestKit.eq("the earlier block survived", now + 600, after.get(subject).blockedUntil);
            TestKit.ok("the reloaded manager still sees the block",
                    fresh.isAccountBlocked(Crypto.idRef("alice")));
        });

        TestKit.caseOf("an unwritable ledger never loosens a decision", () -> {
            Path dir = TestKit.scratchDir("flow-ledger-down");
            Path log = dir.resolve("throttle.log");
            Files.createDirectories(log);  // a directory cannot be replaced by an atomic move
            ThrottleManager t = new ThrottleManager(new Ledger(log));
            String acct = Crypto.idRef("alice");
            int allowed = 0;
            for (int i = 0; i < ThrottleManager.ACCOUNT_MAX_FAILURES + 3; i++) {
                if (t.beginAttempt(acct, SourceRef.ref(SRC_A)) == ThrottleManager.Kind.ALLOWED) {
                    allowed++;
                }
            }
            TestKit.eq("in-memory enforcement held",
                    ThrottleManager.ACCOUNT_MAX_FAILURES, allowed);
            TestKit.ok("the durability failure is recorded for the operator",
                    t.ledgerLossCount() > 0);
            TestKit.ok("and the subject is still gated in memory",
                    t.beginAttempt(acct, SourceRef.ref(SRC_A)) == ThrottleManager.Kind.THROTTLED);
            // The same must hold for a window the caller actually recorded as a failure:
            // the ledger being down cannot downgrade a timed block either.
            t.recordFailure(acct, SourceRef.ref(SRC_A));
            TestKit.ok("a recorded failure still arms the block with the ledger down",
                    t.isAccountBlocked(acct));
        });

        TestKit.caseOf("ledger keys never name an account or an address", () -> {
            Rig rig = new Rig("flow-ledger-keys");
            rig.add("alice", TestKit.PW_ALICE);
            rig.login("alice", TestKit.PW_WRONG, "192.168.7.7");
            String body = Files.readString(rig.dir.resolve("throttle.log"));
            TestKit.ok("no username in the ledger", !body.contains("alice"));
            TestKit.ok("no address in the ledger", !body.contains("192.168.7.7"));
            TestKit.ok("keys are kind + 16 hex", body.lines().allMatch(l -> l.matches(
                    "v2\\|[as]:[0-9a-f]{16}\\|\\d+\\|\\d+\\|\\d+\\|\\d+")));
        });

        TestKit.caseOf("a correct password clears the durable counter, not just memory", () -> {
            Path dir = TestKit.scratchDir("flow-ledger-clear");
            Path log = dir.resolve("throttle.log");
            Ledger ledger = new Ledger(log);
            String acct = Crypto.idRef("alice");
            String src = SourceRef.ref(SRC_A);
            // Four reserved slots spent as failures in one process, then a success in
            // another. Each process must write what it actually decided.
            ThrottleManager first = new ThrottleManager(ledger);
            for (int i = 0; i < 4; i++) {
                first.beginAttempt(acct, src);
                first.recordFailure(acct, src);
            }
            TestKit.eq("four failures are on the ledger", 4,
                    ledger.load(AuditClock.epochSecond(), ThrottleManager.RETENTION_SECONDS)
                            .get(Ledger.key('a', acct)).count);
            ThrottleManager second = new ThrottleManager(ledger);
            second.beginAttempt(acct, src);
            second.recordSuccess(acct, src);
            Map<String, Ledger.Counter> after =
                    ledger.load(AuditClock.epochSecond(), ThrottleManager.RETENTION_SECONDS);
            TestKit.eq("the success cleared it despite the merge", 0,
                    after.get(Ledger.key('a', acct)).count);
            // The regression this pins: with a count-merging-only ledger the file kept
            // re-arming the account at the budget and the sixth correct login of an
            // otherwise quiet day was denied. Assert a full budget-plus-one of clean
            // sign-ins across fresh processes rather than asserting the number once. Each
            // sign-in is settled with recordSuccess, because an unsettled reservation is
            // supposed to spend budget -- the bug was about successes, not reservations.
            int granted = 0;
            for (int i = 0; i < ThrottleManager.ACCOUNT_MAX_FAILURES + 1; i++) {
                ThrottleManager p = new ThrottleManager(ledger);
                if (p.beginAttempt(acct, src) == ThrottleManager.Kind.ALLOWED) {
                    granted++;
                    p.recordSuccess(acct, src);
                }
            }
            TestKit.eq("every clean sign-in is allowed",
                    ThrottleManager.ACCOUNT_MAX_FAILURES + 1, granted);
            TestKit.ok("and a hostile burst still locks it afterwards",
                    lockStillArms(ledger, acct, src));
        });

        TestKit.caseOf("a sibling cannot lower the count inside the same window", () -> {
            Path dir = TestKit.scratchDir("flow-ledger-same-window");
            Path log = dir.resolve("throttle.log");
            Ledger ledger = new Ledger(log);
            String acct = Crypto.idRef("alice");
            String src = SourceRef.ref(SRC_A);
            ThrottleManager a = new ThrottleManager(ledger);
            for (int i = 0; i < 3; i++) {
                a.beginAttempt(acct, src);
                a.recordFailure(acct, src);
            }
            // A second process loaded before those failures existed and clears the account
            // on a success -- same generation as the first writer only because it never
            // replaced the window. Its zero must not erase the other's evidence.
            String key = Ledger.key('a', acct);
            long now = AuditClock.epochSecond();
            ledger.persist(Map.of(key, new Ledger.Counter(now, 0, 0L, 0L)));
            TestKit.eq("the higher same-window count survived", 3,
                    ledger.load(now, ThrottleManager.RETENTION_SECONDS).get(key).count);
        });

        TestKit.caseOf("a v1 ledger line is still read after an upgrade", () -> {
            Path dir = TestKit.scratchDir("flow-ledger-v1");
            Path log = dir.resolve("throttle.log");
            String acct = Crypto.idRef("alice");
            long until = AuditClock.epochSecond() + 600;
            PrivateFiles.writePrivateAtomic(log,
                    ("v1|a:" + acct + "|" + AuditClock.epochSecond() + "|4|" + until + "\n")
                            .getBytes(StandardCharsets.UTF_8));
            ThrottleManager t = new ThrottleManager(new Ledger(log));
            TestKit.ok("the pre-upgrade back-off is honoured", t.isAccountBlocked(acct));
            TestKit.eq("with its count intact", 4, t.failureCountFor(acct));
            TestKit.ok("so a decision against it is refused",
                    t.beginAttempt(acct, SourceRef.ref(SRC_A))
                            == ThrottleManager.Kind.THROTTLED);
            TestKit.ok("and the next write lands in the current version",
                    Files.readString(log).startsWith("v2|a:" + acct));
        });
    }

    /**
     * A budget spent on real failures must still arm a back-off, measured across fresh
     * processes. Paired with the success-clearing assertions so the fix for one cannot be
     * paid for with the other: if the merge stopped honouring counts altogether, clean
     * sign-ins would work and an attack would also stop being restricted.
     */
    private static boolean lockStillArms(Ledger ledger, String acct, String src) {
        for (int i = 0; i < ThrottleManager.ACCOUNT_MAX_FAILURES; i++) {
            ThrottleManager p = new ThrottleManager(ledger);
            if (p.beginAttempt(acct, src) != ThrottleManager.Kind.ALLOWED) {
                return false;
            }
            p.recordFailure(acct, src);
        }
        return new ThrottleManager(ledger).isAccountBlocked(acct);
    }

    // -------------------------------------------------------------- rule 4: sessions

    private static void sessions() {
        TestKit.caseOf("session lifetimes", () -> {
            Rig rig = new Rig("flow-session");
            rig.add("alice", TestKit.PW_ALICE);
            TestKit.fixedClockAt(T0);
            String id = rig.login("alice", TestKit.PW_ALICE, SRC_A).sessionId();
            TestKit.ok("live", rig.sessions.find(id).isPresent());

            // Idle expiry is measured from last use, so the probe below that keeps the
            // session alive is itself part of the fixture -- the expiry has to be asserted
            // from the moment of that last use, not from issue time.
            java.time.Instant lastUse =
                    T0.plusSeconds(SessionManager.IDLE_TIMEOUT.getSeconds() - 60);
            TestKit.fixedClockAt(lastUse);
            TestKit.ok("still live just inside the idle window", rig.sessions.find(id).isPresent());
            TestKit.fixedClockAt(lastUse.plusSeconds(SessionManager.IDLE_TIMEOUT.getSeconds() + 60));
            TestKit.ok("idle-expired", rig.sessions.find(id).isEmpty());

            // Absolute expiry has to be shown while the session is *not* idle, otherwise
            // the same assertion would pass for the idle reason alone. Steady use every
            // few minutes keeps it non-idle for the whole eight hours.
            java.time.Instant issuedAt = AuditClock.instant();
            String fresh = rig.login("alice", TestKit.PW_ALICE, SRC_A).sessionId();
            long keepAliveStep = SessionManager.IDLE_TIMEOUT.getSeconds() - 60;
            java.time.Instant t = issuedAt;
            // 25 hops x 1140s = 28 500s: every hop is inside the 1 200s idle window (so
            // nothing here can expire for idleness) and still under the 28 800s absolute
            // cap, so the whole run demonstrates a session that stays live under steady
            // use right up to the cap. The next jump crosses only the absolute deadline.
            for (int hop = 0; hop < 25; hop++) {
                t = t.plusSeconds(keepAliveStep);
                TestKit.fixedClockAt(t);
                TestKit.ok("hop " + hop + " still live under steady use",
                        rig.sessions.find(fresh).isPresent());
            }
            TestKit.ok("the run stopped just short of the absolute cap",
                    t.isBefore(issuedAt.plusSeconds(SessionManager.ABSOLUTE_TIMEOUT.getSeconds())));
            // Measured from the session's own issue time, and kept inside the idle window,
            // so the only rule that can expire it here is the absolute cap.
            TestKit.fixedClockAt(
                    issuedAt.plusSeconds(SessionManager.ABSOLUTE_TIMEOUT.getSeconds() + 60));
            TestKit.ok("absolute-expired even though it was used a minute ago",
                    rig.sessions.find(fresh).isEmpty());
            TestKit.systemClock();
        });

        TestKit.caseOf("a forged or guessed cookie grants nothing", () -> {
            Rig rig = new Rig("flow-session-forge");
            rig.add("alice", TestKit.PW_ALICE);
            String real = rig.login("alice", TestKit.PW_ALICE, SRC_A).sessionId();
            List<String> hostile = List.of("", "x", real.substring(0, 42), real + "A",
                    Crypto.randomUrlToken(InputPolicy.SESSION_TOKEN_BYTES),
                    "A".repeat(43), real + "=", flipLast(real), "null");
            for (String h : hostile) {
                TestKit.ok("no session for [" + show(h) + "..]", rig.sessions.find(h).isEmpty());
            }
            TestKit.ok("the real one still works", rig.sessions.find(real).isPresent());
            TestKit.ok("a session id for one user is not a capability for another",
                    rig.sessions.find(real).orElseThrow().username.equals("alice"));
        });

        TestKit.caseOf("logout and administrative revocation delete server-side state", () -> {
            Rig rig = new Rig("flow-session-out");
            rig.add("alice", TestKit.PW_ALICE);
            String a = rig.login("alice", TestKit.PW_ALICE, SRC_A).sessionId();
            String b = rig.login("alice", TestKit.PW_ALICE, SRC_A).sessionId();
            TestKit.eq("two live", 2, rig.sessions.liveSessionCount());
            rig.sessions.logout(a);
            TestKit.ok("logged out", rig.sessions.find(a).isEmpty());
            TestKit.ok("the other session survives", rig.sessions.find(b).isPresent());
            rig.sessions.logout("not-a-token");
            TestKit.ok("logging out with junk is a no-op", rig.sessions.find(b).isPresent());
            rig.sessions.revokeAllFor("alice");
            TestKit.eq("all revoked", 0, rig.sessions.liveSessionCount());
            TestKit.ok("the second one is gone too", rig.sessions.find(b).isEmpty());
        });

        TestKit.caseOf("session state is bounded", () -> {
            SessionManager s = new SessionManager();
            for (int i = 0; i < SessionManager.MAX_SESSIONS + 50; i++) {
                s.issue("user" + (i % 997));
            }
            TestKit.eq("hard ceiling", SessionManager.MAX_SESSIONS, s.liveSessionCount());
            TestKit.ok("evictions counted", s.evictedSessionCount() >= 50);
        });

        TestKit.caseOf("a stolen session table would not contain usable ids", () -> {
            SessionManager s = new SessionManager();
            String id = s.issue("alice");
            TestKit.ok("the id is not stored in the clear", !s.liveSubjects().contains(id));
            TestKit.eq("only the username is the payload", List.of("alice"), s.liveSubjects());
        });

        TestKit.caseOf("purgeExpired collects dead sessions", () -> {
            Rig rig = new Rig("flow-session-purge");
            rig.add("alice", TestKit.PW_ALICE);
            TestKit.fixedClockAt(T0);
            rig.login("alice", TestKit.PW_ALICE, SRC_A);
            rig.login("alice", TestKit.PW_ALICE, SRC_A);
            TestKit.eq("two live", 2, rig.sessions.liveSessionCount());
            TestKit.fixedClockAt(T0.plusSeconds(SessionManager.IDLE_TIMEOUT.getSeconds() + 10));
            TestKit.eq("purged", 2, rig.sessions.purgeExpired());
            TestKit.eq("none left", 0, rig.sessions.liveSessionCount());
            TestKit.systemClock();
        });
    }

    private static void csrf() {
        TestKit.caseOf("the csrf pair is single-use and must match", () -> {
            SessionManager s = new SessionManager();
            String token = Crypto.randomUrlToken(InputPolicy.CSRF_TOKEN_BYTES);
            s.issueCsrfToken(token, token);
            TestKit.eq("pending", 1, s.pendingCsrfCount());
            TestKit.ok("consumed once", s.consumeCsrfToken(token, token));
            TestKit.ok("cannot be replayed", !s.consumeCsrfToken(token, token));
            TestKit.eq("pending drained", 0, s.pendingCsrfCount());
            s.issueCsrfToken(token, token);
            TestKit.ok("mismatched halves refused", !s.consumeCsrfToken(token,
                    Crypto.randomUrlToken(InputPolicy.CSRF_TOKEN_BYTES)));
            // Documented behaviour: a caller that does not hold both halves never burns
            // the entry, so junk posted at the endpoint cannot use up a real user's
            // single-use token. Only a *matching* pair is consumed, late or not.
            TestKit.eq("a mismatched attempt leaves the pending entry alone", 1,
                    s.pendingCsrfCount());
            TestKit.ok("the legitimate pair still works afterwards",
                    s.consumeCsrfToken(token, token));
            TestKit.eq("and consuming it empties the store", 0, s.pendingCsrfCount());
            s.issueCsrfToken(token, token);
            TestKit.ok("one half missing refused", !s.consumeCsrfToken(token, null));
            TestKit.ok("both missing refused", !s.consumeCsrfToken(null, null));
            s.issueCsrfToken(token, token);
            TestKit.ok("wrong shape refused", !s.consumeCsrfToken(token + "AA", token + "AA"));
        });

        TestKit.caseOf("csrf tokens expire", () -> {
            SessionManager s = new SessionManager();
            TestKit.fixedClockAt(T0);
            String token = Crypto.randomUrlToken(InputPolicy.CSRF_TOKEN_BYTES);
            s.issueCsrfToken(token, token);
            TestKit.fixedClockAt(T0.plusSeconds(SessionManager.CSRF_TIMEOUT.getSeconds() + 5));
            TestKit.ok("expired token refused", !s.consumeCsrfToken(token, token));
            TestKit.systemClock();
        });

        TestKit.caseOf("issued tokens are unguessable and distinct", () -> {
            java.util.Set<String> seen = new java.util.HashSet<>();
            for (int i = 0; i < 200; i++) {
                seen.add(Crypto.randomUrlToken(InputPolicy.CSRF_TOKEN_BYTES));
            }
            TestKit.eq("all distinct", 200, seen.size());
            TestKit.eq("32 characters = 24 full bytes of entropy", 32,
                    seen.iterator().next().length());
        });
    }

    // ------------------------------------------------- rule 6: comparable work per path

    private static void timings() {
        TestKit.caseOf("every outcome costs the same work", () -> {
            Rig rig = new Rig("flow-timing");
            rig.add("alice", TestKit.PW_ALICE);
            rig.add("carol", TestKit.PW_CAROL);
            rig.store.disableAccount("carol");
            rig.throttle.setTimingControlsForTesting(true, 0);
            try {
                Runnable burnFive = () -> {
                    rig.throttle.clearAccountForTesting(Crypto.idRef("alice"));
                    for (int i = 0; i < ThrottleManager.ACCOUNT_MAX_FAILURES; i++) {
                        rig.login("alice", TestKit.PW_WRONG, SRC_A);
                    }
                };
                List<TimedPath> paths = List.of(
                        new TimedPath("correct",
                                () -> rig.throttle.clearAccountForTesting(Crypto.idRef("alice")),
                                () -> rig.login("alice", TestKit.PW_ALICE, SRC_A)),
                        new TimedPath("wrong-password",
                                () -> rig.throttle.clearAccountForTesting(Crypto.idRef("alice")),
                                () -> rig.login("alice", TestKit.PW_WRONG, SRC_A)),
                        new TimedPath("unknown-name",
                                () -> rig.throttle.clearAccountForTesting(Crypto.idRef("ghost")),
                                () -> rig.login("ghost", TestKit.PW_WRONG, SRC_A)),
                        new TimedPath("malformed-name", () -> {
                        }, () -> rig.login("bad name!", TestKit.PW_WRONG, SRC_A)),
                        new TimedPath("malformed-secret", () -> {
                        }, () -> rig.login("alice", "x", SRC_A)),
                        new TimedPath("throttled", burnFive,
                                () -> rig.login("alice", TestKit.PW_WRONG, SRC_A)),
                        new TimedPath("disabled-account", () -> {
                        }, () -> rig.login("carol", TestKit.PW_WRONG, SRC_A)));

                Map<String, Long> median = new java.util.LinkedHashMap<>();
                for (TimedPath p : paths) {
                    p.prep().run();
                    p.call().run();                       // warm up
                    List<Long> samples = new ArrayList<>();
                    for (int i = 0; i < 3; i++) {
                        p.prep().run();                   // untimed setup
                        long t0 = System.nanoTime();
                        p.call().run();                   // one authenticate, timed alone
                        samples.add((System.nanoTime() - t0) / 1_000_000);
                    }
                    java.util.Collections.sort(samples);
                    median.put(p.name(), samples.get(samples.size() / 2));
                }
                long min = Long.MAX_VALUE;
                long max = 0;
                for (Map.Entry<String, Long> e : median.entrySet()) {
                    TestKit.measure("path-ms-" + e.getKey(), String.valueOf(e.getValue()));
                    min = Math.min(min, e.getValue());
                    max = Math.max(max, e.getValue());
                }
                double spread = (double) max / Math.max(min, 1);
                TestKit.measure("spread-ratio", String.format("%.3f", spread));
                TestKit.ok("no path is materially cheaper than another (ratio "
                        + String.format("%.3f", spread) + ")", spread < 1.35);
                // A deleted decoy derivation would show up as one very small column.
                TestKit.ok("the cheapest path still costs a full derivation", min > 50);
            } finally {
                rig.throttle.setTimingControlsForTesting(false, 0);
            }
        });

        TestKit.caseOf("the padding holds every path up to the floor", () -> {
            Rig rig = new Rig("flow-timing-floor");
            rig.add("alice", TestKit.PW_ALICE);
            long floor = 600_000_000L;  // 600 ms, well above one 100k-iteration derivation
            rig.throttle.setTimingControlsForTesting(false, floor);
            TestKit.ok("the floor ratcheted up", rig.throttle.latencyFloorNanos() >= floor);
            try {
                List<TimedPath> paths = List.of(
                        new TimedPath("correct",
                                () -> rig.throttle.clearAccountForTesting(Crypto.idRef("alice")),
                                () -> rig.login("alice", TestKit.PW_ALICE, SRC_A)),
                        new TimedPath("wrong",
                                () -> rig.throttle.clearAccountForTesting(Crypto.idRef("alice")),
                                () -> rig.login("alice", TestKit.PW_WRONG, SRC_A)),
                        new TimedPath("unknown",
                                () -> rig.throttle.clearAccountForTesting(Crypto.idRef("ghost")),
                                () -> rig.login("ghost", TestKit.PW_WRONG, SRC_A)),
                        new TimedPath("bad-name", () -> {
                        }, () -> rig.login("bad name!", TestKit.PW_WRONG, SRC_A)),
                        new TimedPath("bad-secret", () -> {
                        }, () -> rig.login("alice", "x", SRC_A)));
                for (TimedPath p : paths) {
                    p.prep().run();
                    long t0 = System.nanoTime();
                    p.call().run();
                    long ms = (System.nanoTime() - t0) / 1_000_000;
                    TestKit.measure("floored-ms-" + p.name(), String.valueOf(ms));
                    TestKit.ok(p.name() + " waits for the floor",
                            ms >= floor / 1_000_000 - 5);
                }
                // The ratchet is a max(): the observed 600 ms padding itself becomes the
                // new floor, so assert that a smaller request cannot pull it back down
                // rather than asserting an exact value.
                rig.throttle.setTimingControlsForTesting(false, floor / 2);
                TestKit.ok("a smaller requested floor is ignored",
                        rig.throttle.latencyFloorNanos() >= floor);
                long t1 = System.nanoTime();
                rig.login("ghost", TestKit.PW_WRONG, SRC_A);
                long ms1 = (System.nanoTime() - t1) / 1_000_000;
                TestKit.measure("floored-ms-after-smaller-request", String.valueOf(ms1));
                TestKit.ok("and the refusal still waits for the original floor",
                        ms1 >= floor / 1_000_000 - 5);
            } finally {
                rig.throttle.setTimingControlsForTesting(true, 0);
                rig.throttle.setTimingControlsForTesting(false, 0);
            }
        });
    }

    // --------------------------------------------------------- rule 5: what reaches disk

    private static void integrationAudit() {
        TestKit.caseOf("a full login leaves no secret in the log", () -> {
            Rig rig = new Rig("flow-audit");
            rig.add("alice", TestKit.PW_ALICE);
            rig.login("alice", TestKit.PW_WRONG, "10.9.8.7");
            String sid = rig.login("alice", TestKit.PW_ALICE, "10.9.8.7").sessionId();
            String body = Files.readString(rig.dir.resolve("audit.log"));
            TestKit.ok("granted and denied are both logged",
                    body.contains("granted") && body.contains("bad-credentials"));
            TestKit.ok("password absent", !body.contains(TestKit.PW_ALICE)
                    && !body.contains(TestKit.PW_WRONG));
            TestKit.ok("username absent", !body.contains("alice"));
            TestKit.ok("address absent", !body.contains("10.9.8.7"));
            TestKit.ok("session id absent", !body.contains(sid));
            TestKit.ok("roster and ledger are private",
                    TestKit.mode(rig.dir.resolve("employees.dat")).equals("rw-------")
                            && TestKit.mode(rig.dir.resolve("throttle.log")).equals("rw-------"));
            TestKit.eq("audit log is 0600", 0_600,
                    PrivateFiles.unixMode(rig.dir.resolve("audit.log")) & 0_777);
            TestKit.eq("data directory is 0700", "rwx------", TestKit.mode(rig.dir));
        });
    }

    // ------------------------------------------------------------------------ helpers

    private static boolean isBlank(char[] a) {
        for (char c : a) {
            if (c != '\0') {
                return false;
            }
        }
        return true;
    }

    private static String show(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(s.length(), 14); i++) {
            char c = s.charAt(i);
            sb.append(c < 0x21 || c > 0x7E ? '@' : c);
        }
        return sb.toString();
    }

    /** Deterministically differs from {@code s} while staying inside the token alphabet. */
    private static String flipLast(String s) {
        char last = s.charAt(s.length() - 1);
        return s.substring(0, s.length() - 1) + (last == 'a' ? 'b' : 'a');
    }
}
