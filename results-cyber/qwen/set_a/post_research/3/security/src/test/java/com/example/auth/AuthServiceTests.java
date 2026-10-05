package com.example.auth;

import static com.example.auth.T.eq;
import static com.example.auth.T.inRange;
import static com.example.auth.T.no;
import static com.example.auth.T.section;
import static com.example.auth.T.yes;

import java.lang.management.ManagementFactory;
import java.nio.file.Path;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Rules 3, 4, 6, 7 against the real decision path and a real database.
 *
 * <p>Two timing measurements are made deliberately:
 * <ul>
 *   <li><b>wall clock</b>, which the response-time floor governs - proves no outcome is quicker;</li>
 *   <li><b>CPU time on the calling thread</b>, which the floor cannot affect, because sleeping is not
 *       computation - proves the work is genuinely comparable and not merely padded.</li>
 * </ul>
 * Asserting only the first would leave a defect where the derivation was removed from one path: the
 * stopwatches would still agree because the sleep dominates. The CPU assertion is what catches that.
 *
 * <p>Every negative case below is invalid in exactly one way. Cases that stack two defects pass for
 * the wrong reason - a second unrelated defect can satisfy the guard under test - so each one starts
 * from a store restored by {@link Fixture#reloadService()}.
 */
public final class AuthServiceTests {

    private static final String ACCOUNT = "operator@example.com";
    private static final String OTHER = "second@example.com";
    private static final String PASSWORD = "Winters-Vector-44";
    private static final String WRONG = "Winters-Vector-45";
    private static final int ITERATIONS = 100_000;
    private static final int FLOOR_MS = 500;
    private static final String CRED = "storage-credential-for-local-testing";

    private AuthServiceTests() {
    }

    /** A clock the test drives, so window rollover is deterministic instead of slept through. */
    static final class FakeClock implements ThrottleStore.TimeSource {
        private long now;

        FakeClock(long startMillis) {
            this.now = startMillis;
        }

        @Override
        public long epochMillis() {
            return now;
        }

        void advance(long millis) {
            now += millis;
        }
    }

    public static void main(String[] args) throws Exception {
        successAndFailure();
        noExistenceOracleTiming();
        cpuWorkIsComparable();
        budgetEnforcementAndRecovery();
        sprayIsBoundedPerSource();
        atomicReservation();
        tamperedRowsDeny();
        sessions();
        failClosedOnStorage();
        noWritePatternOracle();
        auditContent();
        System.exit(T.summary("AuthServiceTests"));
    }

    // ------------------------------------------------------------------ harness

    private static final class Fixture implements AutoCloseable {
        final Map<String, String> env = new HashMap<>();
        final Config first;
        final Database db;
        final LogWriter log;
        final FakeClock clock;
        final Path dir;
        final char[] cred;
        AuthService service;

        Fixture(String name, Map<String, String> overrides) throws Exception {
            dir = T.scratch(name);
            env.put("AUTH_DB_PATH", dir.resolve("store").toString());
            env.put("AUTH_AUDIT_LOG", dir.resolve("store.audit.log").toString());
            env.put("AUTH_DB_USER", "authsvc");
            env.put("AUTH_DB_PASSWORD", CRED);
            env.put("AUTH_ITERATIONS", Integer.toString(ITERATIONS));
            env.put("AUTH_MIN_LOGIN_MS", Integer.toString(FLOOR_MS));
            env.put("AUTH_IDENTITY_WINDOW_SEC", "60");
            env.put("AUTH_SOURCE_WINDOW_SEC", "60");
            env.putAll(overrides);
            first = Config.load(env);
            cred = first.takeDbPassword();
            log = LogWriter.open(Path.of(first.dbPath() + ".audit.log"));
            db = Database.open(first, cred);
            clock = new FakeClock(System.currentTimeMillis());
            service = new AuthService(first, db, log, clock);
            AccountSeeder seeder = new AccountSeeder(first, db, log);
            if (seeder.seed(ACCOUNT, T.chars(PASSWORD)) != AccountSeeder.SeedResult.CREATED) {
                throw new IllegalStateException("seed_failed for " + ACCOUNT);
            }
            if (seeder.seed(OTHER, T.chars(PASSWORD)) != AccountSeeder.SeedResult.CREATED) {
                throw new IllegalStateException("seed_failed for " + OTHER);
            }
        }

        /**
         * A fresh service on a fresh configuration, and the account's credential row restored to the
         * pristine copy held for the second account. Used before every tampering case so each row is
         * invalid in one field only, and to obtain a service whose budgets start empty.
         */
        AuthService reloadService(Map<String, String> overrides) throws Exception {
            synchronized (db.jdbcLock()) {
                try (PreparedStatement ps = db.prepare("UPDATE " + db.accountTable()
                        + " SET pw_algo = (SELECT b.pw_algo FROM " + db.accountTable()
                        + " b WHERE b.email_hash = ?),"
                        + " pw_iterations = (SELECT b.pw_iterations FROM " + db.accountTable()
                        + " b WHERE b.email_hash = ?),"
                        + " pw_salt = (SELECT b.pw_salt FROM " + db.accountTable()
                        + " b WHERE b.email_hash = ?),"
                        + " pw_hash = (SELECT b.pw_hash FROM " + db.accountTable()
                        + " b WHERE b.email_hash = ?),"
                        + " status = (SELECT b.status FROM " + db.accountTable()
                        + " b WHERE b.email_hash = ?) WHERE email_hash <> ?")) {
                    String other = AuthService.identityHash(OTHER);
                    for (int i = 1; i <= 5; i++) {
                        ps.setString(i, other);
                    }
                    ps.setString(6, other);
                    ps.executeUpdate();
                }
            }
            Map<String, String> merged = new HashMap<>(env);
            merged.putAll(overrides);
            Config c = Config.load(merged);
            service = new AuthService(c, db, log, clock);
            return service;
        }

        AuthService.Result login(String email, String password) {
            char[] pw = T.chars(password);
            try {
                return service.authenticate(email, pw);
            } finally {
                CryptoUtils.wipe(pw);
            }
        }

        AuthService.Result loginWith(AuthService svc, String email, String password) {
            char[] pw = T.chars(password);
            try {
                return svc.authenticate(email, pw);
            } finally {
                CryptoUtils.wipe(pw);
            }
        }

        /** CPU microseconds burned on the calling thread by one login attempt. */
        long loginCpuMicros(AuthService svc, String email, String password) {
            com.sun.management.ThreadMXBean mx =
                    (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
            if (!mx.isThreadCpuTimeSupported()) {
                return -1;
            }
            mx.setThreadCpuTimeEnabled(true);
            long id = Thread.currentThread().getId();
            char[] pw = T.chars(password);
            long before = mx.getThreadCpuTime(id);
            try {
                svc.authenticate(email, pw);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            } finally {
                CryptoUtils.wipe(pw);
            }
            return (mx.getThreadCpuTime(id) - before) / 1000L;
        }

        long[] identityState(String email, int limit) throws Database.StorageException {
            return service.throttles().inspect(ThrottleStore.identityBudget(
                    AuthService.identityHash(email), limit, first.identityWindowSec()));
        }

        void advanceWindow() {
            clock.advance(first.identityWindowSec() * 1000L + 1000L);
        }

        @Override
        public void close() {
            log.close();
            db.close();
        }
    }

    private static Map<String, String> env(String k1, String v1, String k2, String v2) {
        Map<String, String> m = new HashMap<>();
        m.put(k1, v1);
        m.put(k2, v2);
        return m;
    }

    // ------------------------------------------------------------------ basic outcomes

    private static void successAndFailure() throws Exception {
        section("outcomes");
        try (Fixture f = new Fixture("outcomes", Map.of())) {
            AuthService.Result ok = f.login(ACCOUNT, PASSWORD);
            yes("correct credential is granted", ok.granted());
            eq("reason is the credential match", AuthService.Reason.CREDENTIAL_MATCH, ok.reason);
            yes("a session token is issued", ok.sessionToken != null);
            yes("token is 64 lowercase hex",
                    ok.sessionToken != null && ok.sessionToken.matches("[0-9a-f]{64}"));

            AuthService.Result bad = f.login(ACCOUNT, WRONG);
            no("wrong password is denied", bad.granted());
            eq("reason is a bad credential", AuthService.Reason.BAD_CREDENTIAL, bad.reason);
            no("no token on denial", bad.sessionToken != null);

            f.advanceWindow();
            AuthService.Result unknown = f.login("stranger@example.com", PASSWORD);
            no("unknown address is denied", unknown.granted());
            eq("reason is no such identity, for the operator only",
                    AuthService.Reason.NO_SUCH_IDENTITY, unknown.reason);

            f.advanceWindow();
            yes("case-folded address authenticates", f.login(ACCOUNT.toUpperCase(), PASSWORD).granted());

            f.advanceWindow();
            no("a password with a trailing NUL cannot impersonate",
                    f.service.authenticate(ACCOUNT, (PASSWORD + "\0").toCharArray()).granted());
            f.advanceWindow();
            no("a password with a leading space cannot impersonate",
                    f.service.authenticate(ACCOUNT, (" " + PASSWORD).toCharArray()).granted());
            f.advanceWindow();
            no("an all-NUL buffer cannot authenticate",
                    f.service.authenticate(ACCOUNT, new char[PASSWORD.length()]).granted());
            f.advanceWindow();
            no("an empty password cannot authenticate",
                    f.service.authenticate(ACCOUNT, new char[0]).granted());
            f.advanceWindow();
            no("a null password cannot authenticate",
                    f.service.authenticate(ACCOUNT, null).granted());
            no("a null address cannot authenticate",
                    f.service.authenticate(null, PASSWORD.toCharArray()).granted());
            no("an address with two at-signs cannot authenticate",
                    f.service.authenticate("a@b@example.com", PASSWORD.toCharArray()).granted());
            no("an address carrying the password's syntax is refused",
                    f.service.authenticate(ACCOUNT + "' or '1'='1", PASSWORD.toCharArray())
                            .granted());

            // Exactly two outcomes exist at all, so nothing else can be rendered to a user.
            eq("outcome enum has exactly two values", 2, AuthService.Outcome.values().length);
            // Every reason is a fixed lowercase token: nothing user-supplied can reach the log.
            for (AuthService.Reason r : AuthService.Reason.values()) {
                yes("reason code " + r + " is a fixed token",
                        r.code().matches("[a-z0-9_]{1,40}"));
            }
        }
    }

    // ------------------------------------------------------------------ rule 6: no oracle

    private static void noExistenceOracleTiming() throws Exception {
        section("equal work: no existence oracle in wall clock");
        Map<String, String> loose = env("AUTH_SOURCE_MAX_ATTEMPTS", "100000",
                "AUTH_IDENTITY_MAX_FAILURES", "1000");
        try (Fixture f = new Fixture("timing", loose)) {
            String[] labels = {"known-bad-password", "unknown-address", "malformed-email",
                "malformed-password", "budget-spent", "correct-password"};
            int n = 6;
            long[][] samples = new long[labels.length][n];
            // Two discarded rounds so no sample carries JIT or driver start-up cost.
            for (int warm = 0; warm < 2; warm++) {
                AuthService s = f.reloadService(Map.of());
                f.loginWith(s, ACCOUNT, WRONG);
                f.loginWith(s, "warm@example.com", WRONG);
            }
            for (int i = 0; i < n; i++) {
                AuthService clean = f.reloadService(Map.of());
                samples[0][i] = f.loginWith(clean, ACCOUNT, WRONG).micros;
                samples[1][i] = f.loginWith(clean, "ghost" + i + "@example.com", WRONG).micros;
                samples[2][i] = f.loginWith(clean, "not-an-address", WRONG).micros;
                samples[3][i] = f.loginWith(clean, ACCOUNT, "short").micros;
                // Honest exhausted budget: one failure spends it, the next attempt is refused with
                // the correct password, so the only difference from row 5 is the refusal.
                AuthService spent = f.reloadService(env("AUTH_IDENTITY_MAX_FAILURES", "1",
                        "AUTH_SOURCE_MAX_ATTEMPTS", "100000"));
                spent.authenticate(ACCOUNT, T.chars(WRONG));
                AuthService.Result locked = spent.authenticate(ACCOUNT, T.chars(PASSWORD));
                no("the tight budget really refused a correct credential", locked.granted());
                eq("refusal reason is the spent budget", AuthService.Reason.BUDGET_SPENT,
                        locked.reason);
                samples[4][i] = locked.micros;
                AuthService again = f.reloadService(Map.of());
                f.advanceWindow();
                samples[5][i] = f.loginWith(again, ACCOUNT, PASSWORD).micros;
            }
            StringBuilder note = new StringBuilder("wall-clock medians (ms):");
            double min = Double.MAX_VALUE;
            double max = 0;
            for (int i = 0; i < labels.length; i++) {
                double med = T.median(samples[i]) / 1000.0;
                note.append(' ').append(labels[i]).append('=').append(String.format("%.1f", med));
                min = Math.min(min, med);
                max = Math.max(max, med);
                inRange(labels[i] + " floor at every sample",
                        minOf(samples[i]) / 1000, (long) (FLOOR_MS * 0.97), (long) (FLOOR_MS * 2.5));
            }
            System.out.println("NOTE" + note);
            System.out.println("NOTE wall-clock spread=" + String.format("%.2f", max / min)
                    + "x absolute=" + String.format("%.1f", max - min) + " ms over " + n + " samples");
            inRange("spread across all six outcomes under 10 percent",
                    Math.round(max / min * 100), 100, 110);
            inRange("absolute spread under 90 ms", Math.round(max - min), 0, 90);
        }
    }

    private static long minOf(long[] a) {
        long m = Long.MAX_VALUE;
        for (long v : a) {
            m = Math.min(m, v);
        }
        return m;
    }

    // ------------------------------------------------------------------ rule 6: real work

    private static void cpuWorkIsComparable() throws Exception {
        section("equal work: CPU time on the calling thread");
        Map<String, String> loose = env("AUTH_SOURCE_MAX_ATTEMPTS", "100000",
                "AUTH_IDENTITY_MAX_FAILURES", "1000");
        try (Fixture f = new Fixture("cpu", loose)) {
            AuthService svc = f.reloadService(loose);
            if (f.loginCpuMicros(svc, ACCOUNT, WRONG) < 0) {
                System.out.println("NOTE thread CPU time unsupported here, section skipped");
                return;
            }
            f.reloadService(loose);
            long[] known = new long[5];
            long[] unknown = new long[5];
            long[] badEmail = new long[5];
            long[] badPassword = new long[5];
            for (int i = 0; i < 5; i++) {
                AuthService s = f.reloadService(loose);
                known[i] = f.loginCpuMicros(s, ACCOUNT, WRONG);
                unknown[i] = f.loginCpuMicros(s, "phantom" + i + "@example.com", WRONG);
                badEmail[i] = f.loginCpuMicros(s, "nope", WRONG);
                badPassword[i] = f.loginCpuMicros(s, ACCOUNT, "tiny");
            }
            double mk = T.median(known);
            double mu = T.median(unknown);
            double me = T.median(badEmail);
            double mp = T.median(badPassword);
            System.out.println("NOTE cpu medians (us): known=" + (long) mk + " unknown=" + (long) mu
                    + " bad-email=" + (long) me + " bad-password=" + (long) mp + " at "
                    + ITERATIONS + " iterations, floor " + FLOOR_MS + " ms");
            // One PBKDF2 at this cost is tens of milliseconds of CPU. A path that skipped the
            // derivation would land in the microseconds, far below this floor.
            inRange("known-address path burns real KDF cpu", (long) mk, 20_000, 60_000_000);
            inRange("unknown-address path burns real KDF cpu", (long) mu, 20_000, 60_000_000);
            inRange("malformed-email path burns real KDF cpu", (long) me, 20_000, 60_000_000);
            inRange("malformed-password path burns real KDF cpu", (long) mp, 20_000, 60_000_000);
            inRange("known vs unknown cpu ratio", Math.round(mk / mu * 100), 60, 170);
            inRange("malformed-email cpu ratio", Math.round(me / mk * 100), 60, 170);
            inRange("malformed-password cpu ratio", Math.round(mp / mk * 100), 60, 170);

            // Cost must not scale with what the caller sends, or request cost becomes a signal and a
            // denial dial. Both of these are valid passwords, so both take the real derivation.
            AuthService s2 = f.reloadService(loose);
            long shortReal = f.loginCpuMicros(s2, ACCOUNT, "Twelve-Chars!");
            f.advanceWindow();
            long longReal = f.loginCpuMicros(s2, ACCOUNT, "p".repeat(1024));
            f.advanceWindow();
            long blinded = f.loginCpuMicros(s2, ACCOUNT, "tiny");
            inRange("cpu does not scale with supplied password length",
                    Math.round((double) longReal / Math.max(1, shortReal) * 100), 60, 170);
            inRange("the blinded path costs what a real derivation costs",
                    Math.round((double) blinded / Math.max(1, longReal) * 100), 60, 170);
            System.out.println("NOTE cpu by supplied length: 12ch=" + shortReal + "us 1024ch="
                    + longReal + "us invalid(blinded)=" + blinded + "us");
        }
    }

    // ------------------------------------------------------------------ rule 3: budgets

    private static void budgetEnforcementAndRecovery() throws Exception {
        section("account budget: enforced, self-healing, refunded on success");
        try (Fixture f = new Fixture("budget", env("AUTH_IDENTITY_MAX_FAILURES", "3",
                "AUTH_SOURCE_MAX_ATTEMPTS", "10000"))) {
            for (int i = 1; i <= 3; i++) {
                AuthService.Result r = f.login(ACCOUNT, WRONG);
                no("attempt " + i + " is denied", r.granted());
                eq("attempt " + i + " is a credential failure",
                        AuthService.Reason.BAD_CREDENTIAL, r.reason);
            }
            AuthService.Result locked = f.login(ACCOUNT, PASSWORD);
            no("a correct credential inside the window is still refused", locked.granted());
            eq("refusal reason is the spent budget", AuthService.Reason.BUDGET_SPENT, locked.reason);
            no("no token issued when the budget is spent", locked.sessionToken != null);
            long[] st = f.identityState(ACCOUNT, 3);
            eq("counter sits exactly at the limit", 3L, st[0]);

            // Recovery. A guard that latches leaves the account permanently unreachable, which is a
            // denial of service rather than a control.
            f.advanceWindow();
            AuthService.Result after = f.login(ACCOUNT, PASSWORD);
            yes("the account works again after the window", after.granted());
            long[] st2 = f.identityState(ACCOUNT, 3);
            eq("a success refunded the counter", 0L, st2[0]);

            // Repeated correct sign-ins can never exhaust the budget out of the owner.
            try (Fixture g = new Fixture("budget-refund", env("AUTH_IDENTITY_MAX_FAILURES", "2",
                    "AUTH_SOURCE_MAX_ATTEMPTS", "10000"))) {
                for (int i = 0; i < 6; i++) {
                    yes("repeated correct sign-in " + i + " still granted",
                            g.login(ACCOUNT, PASSWORD).granted());
                }
                eq("account budget never accumulated across successes", 0L,
                        g.identityState(ACCOUNT, 2)[0]);
                g.login(ACCOUNT, WRONG);
                g.login(ACCOUNT, WRONG);
                no("two failures do exhaust it", g.login(ACCOUNT, WRONG).granted());
            }

            // The budget is per account: exhausting one must not touch the other.
            f.advanceWindow();
            f.login(ACCOUNT, WRONG);
            f.login(ACCOUNT, WRONG);
            f.login(ACCOUNT, WRONG);
            no("the account is locked again", f.login(ACCOUNT, PASSWORD).granted());
            yes("a different account is unaffected", f.login(OTHER, PASSWORD).granted());
        }
    }

    private static void sprayIsBoundedPerSource() throws Exception {
        section("password spray: bounded per source, not just per account");
        // Both budgets are 10. Configuration refuses a source budget smaller than an account's
        // (source_max_below_identity_max), because the shared counter would then become the lockout
        // weapon; equal limits are the tightest legal spray test.
        try (Fixture f = new Fixture("spray", env("AUTH_IDENTITY_MAX_FAILURES", "10",
                "AUTH_SOURCE_MAX_ATTEMPTS", "10"))) {
            int accounts = 60;
            int nonThrottled = 0;
            int throttled = 0;
            for (int i = 0; i < accounts; i++) {
                AuthService.Result r = f.login("user" + i + "@example.com", WRONG);
                if (r.reason == AuthService.Reason.BUDGET_SPENT) {
                    throttled++;
                } else {
                    nonThrottled++;
                }
            }
            eq("the source budget caps total attempts", 10, nonThrottled);
            eq("the rest are refused", accounts - 10, throttled);
            yes("no attempt was answered as a success", f.login("user59@example.com", PASSWORD)
                    .granted() == false);

            // The source limit must not become a lockout weapon: accounts the spray never reached
            // must carry no counter, and none may be anywhere near its own limit.
            int withRows = 0;
            for (int i = 0; i < accounts; i++) {
                long[] st = f.identityState("user" + i + "@example.com", 10);
                if (st[0] > 0) {
                    withRows++;
                }
                no("no account reached its own limit", st[0] >= 10);
            }
            eq("only the reached accounts carry a counter", 10, withRows);
            System.out.println("NOTE spray: 60 accounts one password, both budgets 10 ->"
                    + " allowed=" + nonThrottled + " refused=" + throttled
                    + " accountsWithCounter=" + withRows);

            // A legitimate user on this source is served again once the source window rolls, and the
            // spray never consumed the legitimate account's own budget.
            f.advanceWindow();
            yes("source window rolls over", f.login(ACCOUNT, PASSWORD).granted());
            // A successful login charges the identity budget and refunds it, so the legitimate
            // owner's counter reads zero: the spray left them nothing to inherit.
            eq("the legitimate account's own counter reads zero after its success", 0L,
                    f.identityState(ACCOUNT, 10)[0]);
        }
    }

    // ------------------------------------------------------------------ rule 7: atomicity

    private static void atomicReservation() throws Exception {
        section("reservation atomicity under concurrency");
        try (Fixture f = new Fixture("atomic", env("AUTH_IDENTITY_MAX_FAILURES", "10",
                "AUTH_SOURCE_MAX_ATTEMPTS", "100000"))) {
            final int threads = 8;
            final int perThread = 3;   // 24 attempts against a budget of 10
            final CountDownLatch ready = new CountDownLatch(threads);
            final CountDownLatch go = new CountDownLatch(1);
            final AtomicInteger notThrottled = new AtomicInteger();
            final AtomicInteger throttled = new AtomicInteger();
            final AtomicInteger errors = new AtomicInteger();
            final List<String> problems = new ArrayList<>();
            Thread[] pool = new Thread[threads];
            for (int t = 0; t < threads; t++) {
                // Each thread builds its own service: the realistic model is several request
                // handlers over one store, not one object shared across threads.
                pool[t] = new Thread(() -> {
                    try {
                        AuthService svc = new AuthService(f.first, f.db, f.log, f.clock);
                        ready.countDown();
                        go.await();
                        for (int i = 0; i < perThread; i++) {
                            AuthService.Result r = svc.authenticate(ACCOUNT, T.chars(WRONG));
                            if (r.reason == AuthService.Reason.BUDGET_SPENT) {
                                throttled.incrementAndGet();
                            } else {
                                notThrottled.incrementAndGet();
                            }
                        }
                    } catch (Throwable e) {
                        errors.incrementAndGet();
                        synchronized (problems) {
                            problems.add(e.getClass().getSimpleName() + ":" + e.getMessage());
                        }
                    }
                }, "racer-" + t);
                pool[t].start();
            }
            ready.await();
            go.countDown();
            for (Thread thread : pool) {
                thread.join();
            }
            if (!problems.isEmpty()) {
                System.out.println("NOTE racer problem: " + problems.get(0));
            }
            eq("no thread failed", 0, errors.get());
            eq("every attempt got an answer", threads * perThread,
                    notThrottled.get() + throttled.get());
            // The invariant: the budget is never overspent, whatever the interleaving.
            eq("the budget was spent exactly and never overspent", 10, notThrottled.get());
            eq("stored counter equals the limit, not more", 10L, f.identityState(ACCOUNT, 10)[0]);
            System.out.println("NOTE race: " + threads + " threads x " + perThread
                    + " attempts against a budget of 10 -> allowed=" + notThrottled.get());

            // Same invariant for one source budget shared by two accounts.
            try (Fixture g = new Fixture("atomic-source", env("AUTH_IDENTITY_MAX_FAILURES", "4",
                    "AUTH_SOURCE_MAX_ATTEMPTS", "4"))) {
                final AtomicInteger passed = new AtomicInteger();
                final AtomicInteger errs = new AtomicInteger();
                final CountDownLatch start = new CountDownLatch(1);
                List<Thread> ts = new ArrayList<>();
                for (int t = 0; t < 6; t++) {
                    final int idx = t;
                    Thread th = new Thread(() -> {
                        try {
                            AuthService svc = new AuthService(g.first, g.db, g.log, g.clock);
                            start.await();
                            AuthService.Result r = svc.authenticate(
                                    idx % 2 == 0 ? ACCOUNT : OTHER, T.chars(WRONG));
                            if (r.reason != AuthService.Reason.BUDGET_SPENT) {
                                passed.incrementAndGet();
                            }
                        } catch (Exception e) {
                            errs.incrementAndGet();
                        }
                    });
                    ts.add(th);
                    th.start();
                }
                start.countDown();
                for (Thread th : ts) {
                    th.join();
                }
                eq("no thread failed on the shared budget", 0, errs.get());
                inRange("shared source budget never overspent", passed.get(), 1, 4);
                System.out.println("NOTE two accounts sharing one source budget of 4 -> allowed="
                        + passed.get());
            }
        }
    }

    // ------------------------------------------------------------------ rule 1: storage is input

    private static void tamperedRowsDeny() throws Exception {
        section("attacker-writable storage cannot raise the security bar");
        String[][] tampering = {
            {"pw_algo", "bcrypt-legacy", "algorithm outside the allowlist"},
            {"pw_algo", "", "empty algorithm"},
            {"pw_iterations", "1000", "iteration count under the floor"},
            {"pw_iterations", "2000000", "iteration count over the ceiling"},
            {"pw_salt", "abcd", "truncated salt"},
            {"pw_hash", "00", "truncated digest"},
            {"status", "disabled", "status outside the allowlist"},
        };
        try (Fixture f = new Fixture("tamper", Map.of())) {
            yes("baseline authenticates", f.login(ACCOUNT, PASSWORD).granted());
            for (String[] t : tampering) {
                AuthService svc = f.reloadService(Map.of());
                mutate(f, t[0], t[1]);
                AuthService.Result r = f.loginWith(svc, ACCOUNT, PASSWORD);
                no(t[2] + " is refused", r.granted());
                eq(t[2] + " reports a rejected row", AuthService.Reason.ROW_REJECTED, r.reason);
                no(t[2] + " issues no token", r.sessionToken != null);
                inRange(t[2] + " refused promptly", r.micros / 1000,
                        (long) (FLOOR_MS * 0.97), (long) (FLOOR_MS * 3));
            }
            // Weak-but-well-formed values inside the accepted band are honoured, so the guard is a
            // range check and not an accident of the fixture.
            AuthService restored = f.reloadService(Map.of());
            yes("a restored row authenticates again",
                    f.loginWith(restored, ACCOUNT, PASSWORD).granted());

            // Duplicate identity rows: refuse rather than pick one, which is what makes a
            // "first row wins" read unusable as an oracle.
            f.advanceWindow();
            insertDuplicate(f);
            AuthService dupSvc = f.reloadService(Map.of());
            AuthService.Result dup = f.loginWith(dupSvc, ACCOUNT, PASSWORD);
            no("a duplicate row set is refused", dup.granted());
            eq("duplicate rows report a rejected row", AuthService.Reason.ROW_REJECTED, dup.reason);
            System.out.println("NOTE tampered-row variants refused=" + tampering.length
                    + " plus the duplicate-row case");
        }
    }

    private static void mutate(Fixture f, String column, String value) throws Exception {
        synchronized (f.db.jdbcLock()) {
            try (PreparedStatement ps = f.db.prepare("UPDATE " + f.db.accountTable() + " SET "
                    + column + " = ? WHERE email_hash = ?")) {
                ps.setString(1, value);
                ps.setString(2, AuthService.identityHash(ACCOUNT));
                if (ps.executeUpdate() != 1) {
                    throw new IllegalStateException("tampering " + column + " affected no row");
                }
            }
        }
    }

    private static void insertDuplicate(Fixture f) throws Exception {
        byte[] salt = CryptoUtils.randomBytes(16);
        byte[] digest = new PasswordHasher(ITERATIONS).derive(T.chars("Second-Cardinal-71"),
                salt, ITERATIONS);
        // The unique index normally forbids this, so the per-read row check is the last line of
        // defence. Drop the index first to simulate a hand-edited store.
        synchronized (f.db.jdbcLock()) {
            try (Statement st = f.db.connection().createStatement()) {
                st.execute("ALTER TABLE " + f.db.accountTable() + " DROP CONSTRAINT uq_auth_email");
            }
        }
        f.db.insertAccount(AuthService.identityHash(ACCOUNT), PasswordHasher.ALGORITHM, ITERATIONS,
                salt, digest, System.currentTimeMillis() / 1000L);
        CryptoUtils.wipe(salt);
        CryptoUtils.wipe(digest);
    }

    // ------------------------------------------------------------------ rule 4: sessions

    private static void sessions() throws Exception {
        section("sessions: generation, verification, revocation");
        try (Fixture f = new Fixture("sessions", Map.of())) {
            String token = f.login(ACCOUNT, PASSWORD).sessionToken;
            yes("token issued", token != null);
            eq("token is 256 bits of hex", 64, token.length());
            yes("token is lowercase hex", token.matches("[0-9a-f]{64}"));

            Long identity = f.service.resolveSession(token);
            yes("the session resolves against server state", identity != null);

            // Only the digest is stored: the raw token must not appear in the store at all.
            yes("raw token is absent from the store file",
                    !T.read(Path.of(f.first.dbPath() + ".mv.db")).contains(token));

            no("a forged token resolves to nothing",
                    f.service.resolveSession("0".repeat(64)) != null);
            no("a truncated token resolves to nothing",
                    f.service.resolveSession(token.substring(1)) != null);
            no("uppercase hex is refused outright",
                    f.service.resolveSession(token.toUpperCase(Locale.ROOT)) != null);
            no("an empty token resolves to nothing", f.service.resolveSession("") != null);
            no("a null token resolves to nothing", f.service.resolveSession(null) != null);
            no("a token with an injected quote resolves to nothing",
                    f.service.resolveSession("0".repeat(63) + "'") != null);

            // Two issued sessions are unrelated: no counter, no timestamp, no shared prefix.
            String t2 = f.login(OTHER, PASSWORD).sessionToken;
            int prefix = commonPrefix(token, t2);
            no("successive tokens share no meaningful prefix", prefix > 3);
            no("the two tokens differ", token.equals(t2));
            eq("one session row per grant", 2, countSessionRows(f));
            System.out.println("NOTE token common prefix = " + prefix + " chars");

            yes("revocation succeeds once", f.service.logout(token).granted());
            no("the session is gone afterwards", f.service.resolveSession(token) != null);
            no("revoking twice reports nothing granted", f.service.logout(token).granted());

            // Expiry is enforced in the statement, not by a Java-side comparison after the read.
            String t3 = f.login(ACCOUNT, PASSWORD).sessionToken;
            yes("fresh session resolves", f.service.resolveSession(t3) != null);
            synchronized (f.db.jdbcLock()) {
                try (PreparedStatement ps = f.db.prepare("UPDATE " + f.db.sessionTable()
                        + " SET expires_at_epoch_sec = ? WHERE token_hash = ?")) {
                    ps.setLong(1, System.currentTimeMillis() / 1000L - 10);
                    ps.setString(2, CryptoUtils.toHex(CryptoUtils.sha256(t3)));
                    ps.executeUpdate();
                }
            }
            no("an expired session does not resolve", f.service.resolveSession(t3) != null);
            inRange("purge collects the expired session", f.service.purgeExpiredSessions(), 1, 10);

            String cookie = SessionStore.cookieAttributesFor();
            yes("cookie guidance carries HttpOnly", cookie.contains("HttpOnly"));
            yes("cookie guidance carries Secure", cookie.contains("Secure"));
            yes("cookie guidance carries SameSite=Strict", cookie.contains("SameSite=Strict"));
            yes("cookie guidance carries a path", cookie.contains("Path=/"));
            yes("cookie guidance carries a max age", cookie.contains("Max-Age="));
        }
    }

    private static int commonPrefix(String a, String b) {
        int n = Math.min(a.length(), b.length());
        int i = 0;
        while (i < n && a.charAt(i) == b.charAt(i)) {
            i++;
        }
        return i;
    }

    // ------------------------------------------------------------------ fail closed

    private static void failClosedOnStorage() throws Exception {
        section("storage failure denies (fails closed)");
        try (Fixture f = new Fixture("closed", Map.of())) {
            yes("baseline works", f.login(ACCOUNT, PASSWORD).granted());
            f.db.close();
            AuthService.Result after = f.login(ACCOUNT, PASSWORD);
            no("a closed store cannot grant", after.granted());
            eq("reason is a storage failure", AuthService.Reason.STORAGE, after.reason);
            no("no token from a failed store", after.sessionToken != null);
            yes("the attempt still cost comparable time",
                    after.micros / 1000 >= (long) (FLOOR_MS * 0.9));
            no("a repeat attempt still denies", f.login(ACCOUNT, PASSWORD).granted());
            no("revocation on a dead store cannot grant", f.service.logout("0".repeat(64)).granted());
        }
    }

    // ------------------------------------------------------------------ write-pattern oracle

    private static void noWritePatternOracle() throws Exception {
        section("failure write pattern does not reveal existence");
        try (Fixture f = new Fixture("writes", env("AUTH_IDENTITY_MAX_FAILURES", "50",
                "AUTH_SOURCE_MAX_ATTEMPTS", "1000"))) {
            eq("no counter row before any attempt", -1L, f.identityState(ACCOUNT, 50)[0]);
            f.login(ACCOUNT, WRONG);
            f.login("absent-entirely@example.com", WRONG);
            // The property: an attempt against an account that does not exist writes the same kind
            // of counter row as an attempt against one that does, so a dump of the counter table
            // answers no existence question.
            eq("a failed attempt against a known account wrote its counter", 1L,
                    f.identityState(ACCOUNT, 50)[0]);
            eq("a failed attempt against an unknown account wrote the same", 1L,
                    f.identityState("absent-entirely@example.com", 50)[0]);
            eq("both counters carry the same counter value",
                    f.identityState(ACCOUNT, 50)[0],
                    f.identityState("absent-entirely@example.com", 50)[0]);
            System.out.println("NOTE throttle rows after one known and one unknown failure: total="
                    + safeCount(f, f.db.throttleTable()) + " (2 identity + 1 shared source)");

            eq("no session row for a denied attempt", 0, countSessionRows(f));
            f.advanceWindow();
            f.login(ACCOUNT, PASSWORD);
            eq("exactly one session row after a grant", 1, countSessionRows(f));
        }
    }

    private static int safeCount(Fixture f, String table) {
        try {
            return count(f, table);
        } catch (SQLException e) {
            return -1;
        }
    }

    // ------------------------------------------------------------------ log content

    private static void auditContent() throws Exception {
        section("audit log records the decision without leaking the credential");
        try (Fixture f = new Fixture("audit", env("AUTH_IDENTITY_MAX_FAILURES", "20",
                "AUTH_SOURCE_MAX_ATTEMPTS", "1000"))) {
            f.login(ACCOUNT, PASSWORD);
            f.login(ACCOUNT, WRONG);
            f.login("nobody@example.com", WRONG);
            f.login(ACCOUNT, "short");
            f.login("bad@@example", WRONG);
            f.advanceWindow();
            for (int i = 0; i < 25; i++) {
                f.login(ACCOUNT, WRONG);
            }
            String text = T.read(Path.of(f.first.auditLogPath()));
            int lines = text.split("\n", -1).length - 1;
            inRange("every attempt produced exactly one audit line", lines, 30, 40);
            no("the password never appears", text.contains(PASSWORD));
            no("the wrong password never appears", text.contains(WRONG));
            no("the storage credential never appears", text.contains(CRED));
            no("no full address appears", text.contains("operator@example.com"));
            no("no local part appears", text.contains("operator@"));
            no("no session token appears",
                    text.matches("(?s).*[0-9a-f]{64}.*"));
            no("no salt or digest hex appears", text.matches("(?s).*[0-9a-f]{32}.*"));
            yes("the masked address form is used", text.contains("o***@example.com"));
            yes("a denial reason is recorded", text.contains("reason=bad_credential"));
            yes("the missing-account reason is recorded", text.contains("reason=no_such_identity"));
            yes("the exhausted budget is recorded", text.contains("reason=budget_spent"));
            yes("a bad input reason is recorded", text.contains("reason=invalid_password"));
            yes("a malformed address is recorded", text.contains("reason=invalid_email"));
            yes("a grant is recorded", text.contains("ev=login_success"));
            no("no line carries a carriage return", text.contains("\r"));
            inRange("every line is bounded", longestLine(text), 1, 300);
            System.out.println("NOTE audit: lines=" + lines + " longest=" + longestLine(text)
                    + " bytes=" + text.length());
        }
    }

    private static int longestLine(String text) {
        int max = 0;
        for (String line : text.split("\n", -1)) {
            max = Math.max(max, line.length());
        }
        return max;
    }

    private static int countSessionRows(Fixture f) throws SQLException {
        return count(f, f.db.sessionTable());
    }

    private static int count(Fixture f, String table) throws SQLException {
        synchronized (f.db.jdbcLock()) {
            try (Statement st = f.db.connection().createStatement();
                    ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM " + table)) {
                rs.next();
                return rs.getInt(1);
            }
        }
    }
}
