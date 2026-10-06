package app;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.util.ArrayList;
import java.util.List;

/**
 * Sign-in tests. The central claim under test is that every refusal is indistinguishable to the
 * caller - same sentence, same work - while the server still records which branch ran.
 *
 * <p>Rate-limit matrices spread their attempts across distinct source keys on purpose: the
 * per-source budget (10) is smaller than a lockout matrix needs, so attempts that all came from
 * one source would be answered by the source budget and the per-account guard under test would
 * never run.
 */
public final class AuthServiceTest {

    private static final String EMAIL = "signin@corp.example";
    private static final String NAME = "signin-user";

    /** Wall-clock floor for any path that must perform one full derivation, in microseconds. */
    private static final long DERIVATION_FLOOR_MICROS = 30_000L;

    /** How far apart the six timed paths may be, as a ratio of slowest to fastest median. */
    private static final double MAX_SPREAD_RATIO = 3.0;

    /** Samples per path; the median of these is what gets compared. */
    private static final int SAMPLES = 3;

    /** Makes every timed attempt use a source key nobody else has used. */
    private static final java.util.concurrent.atomic.AtomicLong TIMING_KEYS =
        new java.util.concurrent.atomic.AtomicLong();

    public static void main(String[] argv) throws Exception {
        Harness.Fixture happy = Harness.freshFixture("auth-happy");
        Harness.Fixture uniform = Harness.freshFixture("auth-uniform");
        Harness.Fixture accountBudget = Harness.freshFixture("auth-account");
        Harness.Fixture sourceBudget = Harness.freshFixture("auth-source");
        Harness.Fixture recovery = Harness.freshFixture("auth-recovery");
        Harness.Fixture timing = Harness.freshFixture("auth-timing");
        Harness.Fixture upgrade = Harness.freshFixture("auth-upgrade");
        Harness.Fixture malformed = Harness.freshFixture("auth-malformed-budget");

        happyPath(happy);
        uniformFailures(uniform);
        accountLockout(accountBudget);
        sourceBudget(sourceBudget);
        malformedLoginsConsumeBudget(malformed);
        lockoutExpires(recovery);
        equalWork(timing);
        upgradeOnWeakCredential(upgrade);

        System.exit(Harness.report("AuthServiceTest"));
    }

    private static void happyPath(Harness.Fixture fixture) throws Exception {
        Harness.section("a correct credential is verified against stored state and yields a session");
        Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "src-h");
        AuthService.Result result = Harness.login(fixture, EMAIL, Harness.PW_ONE);
        Harness.equal(result.status(), AuthService.Status.AUTHENTICATED, "the correct password signs in");
        Harness.equal(result.message(), "Sign-in complete.", "the success message is the fixed sentence");
        Harness.check(result.session() != null, "a session is returned");
        Harness.equal(result.session().token().length(), SessionStore.TOKEN_CHARS,
            "the token is 64 characters of hex - 32 bytes of entropy");
        Harness.check(SessionStore.isWellFormedToken(result.session().token()),
            "the issued token has the shape the store will accept");
        Harness.equal(Long.valueOf(fixture.accounts().findByEmail(EMAIL).id()),
            fixture.auth().resolveSession(result.session().token()),
            "the token resolves to the account that was authenticated");

        AuthService.Result byName = Harness.login(fixture, NAME, Harness.PW_ONE);
        Harness.check(byName.authenticated(), "sign-in works with the username too");
        AuthService.Result byCaseFoldedEmail = Harness.login(fixture, "SIGNIN@CORP.EXAMPLE", Harness.PW_ONE);
        Harness.check(byCaseFoldedEmail.authenticated(),
            "the mailbox branch reaches the same account through the documented canonical form");

        fixture.close();
    }

    /** Every refusal answers with one sentence, and none of them says which branch fired. */
    private static void uniformFailures(Harness.Fixture fixture) throws Exception {
        Harness.section("every sign-in refusal is the same sentence");
        Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "src-u");

        List<String> messages = new ArrayList<>();
        List<AuthService.Status> statuses = new ArrayList<>();

        // 1. malformed identifier (would previously say "no such account" in a naive design)
        statuses.add(Harness.login(fixture, "not-an-address-or-name", Harness.PW_WRONG).status());
        messages.add(Harness.login(fixture, "not-an-address-or-name", Harness.PW_WRONG).message());
        // 2. identifier that is a valid email shape but no such account
        statuses.add(Harness.login(fixture, "ghost@corp.example", Harness.PW_WRONG).status());
        messages.add(Harness.login(fixture, "ghost@corp.example", Harness.PW_WRONG).message());
        // 3. identifier that is a valid username shape but no such account
        statuses.add(Harness.login(fixture, "ghost-user", Harness.PW_WRONG).status());
        messages.add(Harness.login(fixture, "ghost-user", Harness.PW_WRONG).message());
        // 4. real account, wrong password
        statuses.add(Harness.login(fixture, EMAIL, Harness.PW_WRONG).status());
        messages.add(Harness.login(fixture, EMAIL, Harness.PW_WRONG).message());
        // 5. real username, wrong password
        statuses.add(Harness.login(fixture, NAME, Harness.PW_WRONG).status());
        messages.add(Harness.login(fixture, NAME, Harness.PW_WRONG).message());
        // 6. empty password
        statuses.add(Harness.login(fixture, EMAIL, "").status());
        messages.add(Harness.login(fixture, EMAIL, "").message());
        // 7. oversized password (never allowed to reach the KDF)
        String oversized = "a1" + "z".repeat(600);
        statuses.add(Harness.login(fixture, EMAIL, oversized).status());
        messages.add(Harness.login(fixture, EMAIL, oversized).message());
        // 8. trailing invisible character on a real username - must not fold onto the account
        statuses.add(Harness.login(fixture, NAME + "\t", Harness.PW_ONE).status());
        messages.add(Harness.login(fixture, NAME + "\t", Harness.PW_ONE).message());

        Harness.requireNotEmpty(messages, "the refusal capture");
        Harness.atLeast(messages.size(), 8L, "at least eight distinct refusal paths were exercised");
        for (String message : messages) {
            Harness.equal(message, AuthService.INVALID_MESSAGE,
                "the refusal is the shared invalid-credential sentence");
        }
        Harness.check(messages.stream().distinct().count() == 1,
            "all " + messages.size() + " refusals are byte-identical");
        Harness.check(!AuthService.INVALID_MESSAGE.toLowerCase().contains("exist")
                && !AuthService.INVALID_MESSAGE.toLowerCase().contains("unknown")
                && !AuthService.INVALID_MESSAGE.toLowerCase().contains("lock")
                && !AuthService.INVALID_MESSAGE.toLowerCase().contains("throttl")
                && !AuthService.INVALID_MESSAGE.toLowerCase().contains("attempt")
                && !AuthService.INVALID_MESSAGE.toLowerCase().contains("invalid"),
            "the refusal wording names no branch: " + AuthService.INVALID_MESSAGE);
        Harness.check(!AuthService.INVALID_MESSAGE.contains(EMAIL) && !AuthService.INVALID_MESSAGE.contains(NAME),
            "the refusal does not echo the supplied identifier");
        Harness.check(statuses.contains(AuthService.Status.INVALID_CREDENTIALS),
            "the capture really includes a plain invalid-credential refusal");

        // A trailing tab on a real username must be refused, not silently trimmed onto the account.
        Harness.check(statuses.get(7) != AuthService.Status.AUTHENTICATED,
            "a trailing tab does not sign in as the real account");

        List<String> lines = Harness.auditLines(fixture);
        Harness.requireNotEmpty(lines, "the audit trail for the refusal matrix");
        Harness.check(joined(lines).contains("LOGIN_FAILURE"),
            "the trail distinguishes a credential mismatch even though the client cannot");
        Harness.check(joined(lines).contains("no such account"),
            "the trail records the unknown-account branch server-side");
        Harness.check(joined(lines).contains("LOGIN_REFUSED_INVALID_INPUT"),
            "the trail records the malformed-input branch server-side");
        Harness.check(!joined(lines).contains(EMAIL) && !joined(lines).contains(NAME)
                && !joined(lines).contains(Harness.PW_WRONG),
            "the trail holds tags only, never the identifiers or the candidate password");
        fixture.close();
    }

    private static void accountLockout(Harness.Fixture fixture) throws Exception {
        Harness.section("a wrong-password burst locks the account temporarily, not permanently");
        Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "src-a");

        int refused = 0;
        for (int attempt = 0; attempt < Throttle.ACCOUNT_MAX_FAILURES - 1; attempt++) {
            AuthService.Result result = Harness.loginFrom(fixture, EMAIL, Harness.PW_WRONG,
                "burst-" + attempt);
            Harness.equal(result.message(), AuthService.INVALID_MESSAGE,
                "a strike inside the budget answers with the shared sentence");
            if (result.status() != AuthService.Status.INVALID_CREDENTIALS) {
                refused++;
            }
        }
        Harness.equal(refused, 0, "no earlier attempt was refused by the account budget");

        AuthService.Result lastStrike = Harness.loginFrom(fixture, EMAIL, Harness.PW_WRONG, "burst-final");
        Harness.equal(lastStrike.message(), AuthService.INVALID_MESSAGE,
            "the attempt that trips the lock still answers generically");

        AuthService.Result locked = Harness.loginFrom(fixture, EMAIL, Harness.PW_ONE, "burst-owner");
        Harness.equal(locked.status(), AuthService.Status.THROTTLED,
            "the correct password is refused while the account is in its window - fail closed");
        Harness.equal(locked.message(), AuthService.INVALID_MESSAGE,
            "and the refusal is still the shared sentence, so a lockout is not observable");
        Harness.check(locked.session() == null, "no session is issued while the account is locked");

        List<String> lines = Harness.auditLines(fixture);
        Harness.check(joined(lines).contains("ACCOUNT_LOCKED"),
            "the lockout itself is recorded");
        Harness.check(joined(lines).contains("LOGIN_THROTTLED_ACCOUNT"),
            "the refusal-by-lockout is distinguishable in the trail only");
        Harness.note("the account budget is " + Throttle.ACCOUNT_MAX_FAILURES + " failures inside "
            + Throttle.ACCOUNT_WINDOW_SECONDS + "s, locking for " + Throttle.ACCOUNT_LOCK_SECONDS + "s");
        fixture.close();
    }

    private static void sourceBudget(Harness.Fixture fixture) throws Exception {
        Harness.section("attempts are also limited per source, so one budget cannot starve the other");
        Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "src-s");

        int served = 0;
        int throttled = 0;
        // All attempts come from ONE source against DIFFERENT accounts, so the per-account counter
        // can never be what stops them - only the source budget can.
        for (int attempt = 0; attempt < Throttle.SOURCE_MAX_ATTEMPTS + 3; attempt++) {
            AuthService.Result result = Harness.loginFrom(fixture, "probe" + attempt + "@corp.example",
                Harness.PW_WRONG, "one-source");
            if (result.status() == AuthService.Status.THROTTLED) {
                throttled++;
            } else {
                served++;
            }
            Harness.equal(result.message(), AuthService.INVALID_MESSAGE,
                "a source-throttled refusal is worded like every other refusal");
        }
        Harness.equal(served, Throttle.SOURCE_MAX_ATTEMPTS,
            "exactly the source budget is served before refusal");
        Harness.atLeast(throttled, 1L, "the spent source budget refuses further attempts");

        // The decisive property: a spent source budget must not lock the legitimate owner out,
        // because the two budgets are separate namespaces.
        Harness.Fixture other = Harness.freshFixture("auth-source-other");
        Harness.registerStatus(other, "owner@corp.example", "owner-user", Harness.PW_ONE, "src-o");
        Harness.check(Harness.loginFrom(other, "owner@corp.example", Harness.PW_ONE, "another-source")
            .authenticated(), "a different source is unaffected by the spent budget - the limit is per source");
        other.close();

        fixture.clock().advanceSeconds(Throttle.SOURCE_WINDOW_SECONDS);
        Harness.check(Harness.loginFrom(fixture, "probe-after@corp.example", Harness.PW_WRONG, "one-source")
            .status() != AuthService.Status.THROTTLED, "the source window refills and service resumes");
        fixture.close();
    }

    /**
     * Malformed sign-in attempts must cost the caller the same budget as well-formed ones. Before
     * this, an unusable identifier short-circuited before the source consume - so an attacker could
     * make the server run a full key-derivation and write an audit record an unlimited number of times
     * with input that never touched the limit. The per-source budget is worth nothing if the most
     * expensive path is the one it lets through for free.
     */
    private static void malformedLoginsConsumeBudget(Harness.Fixture fixture) throws Exception {
        Harness.section("malformed sign-in input is rate limited too, so it is not a free work amplifier");
        Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "src-mal");

        int served = 0;
        int throttled = 0;
        // "!!broken!!" carries no '@' and is not a valid username, so it is rejected by the input
        // policy before any credential is compared - the exact path that used to bypass the consume.
        for (int attempt = 0; attempt < Throttle.SOURCE_MAX_ATTEMPTS + 3; attempt++) {
            AuthService.Result result = Harness.loginFrom(fixture, "!!broken!!", Harness.PW_WRONG,
                "bad-source");
            if (result.status() == AuthService.Status.THROTTLED) {
                throttled++;
            } else {
                served++;
                Harness.equal(AuthService.Status.INVALID_CREDENTIALS, result.status(),
                    "while the budget lasts, malformed input gets the ordinary generic refusal");
            }
            Harness.equal(result.message(), AuthService.INVALID_MESSAGE,
                "a malformed refusal, a throttled refusal and a wrong password are worded identically");
        }
        Harness.equal(served, Throttle.SOURCE_MAX_ATTEMPTS,
            "exactly the source budget of malformed attempts is served before refusal - the consume is"
                + " charged on the rejected-input path, not skipped");
        Harness.atLeast((long) throttled, 1L,
            "once spent, malformed attempts are throttled like any other, so the limit bounds the"
                + " expensive derivation path");
        Harness.check(Harness.auditLines(fixture).stream().anyMatch(line -> line.contains("LOGIN_THROTTLED_SOURCE")),
            "the source-denial of a malformed flood is on the record");

        Harness.Fixture other = Harness.freshFixture("auth-malformed-other");
        Harness.registerStatus(other, "owner@corp.example", "owner-user", Harness.PW_ONE, "src-o2");
        Harness.check(Harness.loginFrom(other, "owner@corp.example", Harness.PW_ONE, "clean-source")
            .authenticated(), "a spent source cannot deny a different source - the flood is per source");
        other.close();

        fixture.clock().advanceSeconds(Throttle.SOURCE_WINDOW_SECONDS + 1L);
        Harness.check(Harness.loginFrom(fixture, "!!broken!!", Harness.PW_WRONG, "bad-source").status()
                != AuthService.Status.THROTTLED,
            "after the window malformed input is served again - bounded, never permanent");
        fixture.close();
    }

    private static void lockoutExpires(Harness.Fixture fixture) throws Exception {
        Harness.section("the lockout expires and a success clears the counter - it is not a lock lever");
        Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "src-r");

        for (int attempt = 0; attempt < Throttle.ACCOUNT_MAX_FAILURES; attempt++) {
            Harness.loginFrom(fixture, EMAIL, Harness.PW_WRONG, "strike-" + attempt);
        }
        Harness.equal(Harness.loginFrom(fixture, EMAIL, Harness.PW_ONE, "owner-locked").status(),
            AuthService.Status.THROTTLED, "the account is locked after the burst");

        fixture.clock().advanceSeconds(Throttle.ACCOUNT_LOCK_SECONDS + 1);
        AuthService.Result after = Harness.loginFrom(fixture, EMAIL, Harness.PW_ONE, "owner-after");
        Harness.equal(after.status(), AuthService.Status.AUTHENTICATED,
            "the window is temporary - the owner is served again once it passes");
        Harness.check(after.session() != null, "and the recovered sign-in really issued a session");

        List<String> lines = Harness.auditLines(fixture);
        Harness.check(joined(lines).contains("ACCOUNT_UNLOCKED"),
            "the trail shows the strike window was cleared by a successful sign-in");

        // A success must reset the counter, otherwise four strikes now plus one later would lock
        // the account out on the fifth attempt across an unrelated gap.
        Harness.Fixture clear = Harness.freshFixture("auth-clear");
        Harness.registerStatus(clear, EMAIL, NAME, Harness.PW_ONE, "src-c");
        for (int attempt = 0; attempt < Throttle.ACCOUNT_MAX_FAILURES - 1; attempt++) {
            Harness.loginFrom(clear, EMAIL, Harness.PW_WRONG, "pre-" + attempt);
        }
        Harness.check(Harness.loginFrom(clear, EMAIL, Harness.PW_ONE, "owner-mid").authenticated(),
            "the owner signs in just below the strike threshold");
        for (int attempt = 0; attempt < Throttle.ACCOUNT_MAX_FAILURES - 1; attempt++) {
            Harness.loginFrom(clear, EMAIL, Harness.PW_WRONG, "post-" + attempt);
        }
        Harness.check(Harness.loginFrom(clear, EMAIL, Harness.PW_ONE, "owner-final").authenticated(),
            "a success cleared the counter - strikes do not accumulate across a successful sign-in");
        clear.close();
        fixture.close();
    }

    /**
     * The four refusal paths must cost the same amount of work, or response time tells an attacker
     * whether an account exists. Both wall-clock and process CPU time are checked, and each path is
     * floored absolutely: a ratio alone stays green when the work is deleted from every branch.
     */
    private static void equalWork(Harness.Fixture fixture) throws Exception {
        Harness.section("every sign-in path performs one derivation, so timing cannot name the branch");
        Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "src-t");

        ThreadMXBean cpu = ManagementFactory.getThreadMXBean();
        if (cpu.isThreadCpuTimeSupported() && !cpu.isThreadCpuTimeEnabled()) {
            cpu.setThreadCpuTimeEnabled(true);
        }
        boolean cpuAccounting = cpu.isThreadCpuTimeSupported() && cpu.isThreadCpuTimeEnabled();
        Harness.check(cpuAccounting,
            "thread CPU accounting is available, so key-derivation work cannot be hidden behind I/O");

        // JIT warm-up and first-touch page faults are not what is under test, so two throwaway
        // lookups run before any sample is taken.
        for (int warm = 0; warm < 2; warm++) {
            Harness.loginFrom(fixture, "warm" + warm + "@corp.example", Harness.PW_WRONG, "warm-" + warm);
        }

        List<String> labels = List.of("malformed identifier", "unknown email", "unknown username",
            "wrong password", "locked account", "correct password");
        List<Long> wall = new ArrayList<>();
        List<Long> cpuMicros = new ArrayList<>();

        Harness.equal(measure(fixture, cpu, "!!malformed!!", Harness.PW_WRONG, wall, cpuMicros),
            AuthService.Status.INVALID_CREDENTIALS, "the timed branch really was malformed input");
        Harness.equal(measure(fixture, cpu, "nobody@corp.example", Harness.PW_WRONG, wall, cpuMicros),
            AuthService.Status.INVALID_CREDENTIALS, "the timed branch really was an unknown mailbox");
        Harness.equal(measure(fixture, cpu, "nobody-user", Harness.PW_WRONG, wall, cpuMicros),
            AuthService.Status.INVALID_CREDENTIALS, "the timed branch really was an unknown username");
        Harness.equal(measure(fixture, cpu, NAME, Harness.PW_WRONG, wall, cpuMicros),
            AuthService.Status.INVALID_CREDENTIALS, "the timed branch really was a wrong password");

        // The samples above spent one strike each; burn the rest of the account budget so the next
        // measurement really is the locked branch. Without this the "locked" timing would silently
        // be a second wrong-password measurement and still pass.
        for (int strike = SAMPLES; strike < Throttle.ACCOUNT_MAX_FAILURES; strike++) {
            Harness.loginFrom(fixture, EMAIL, Harness.PW_WRONG, "prime-" + strike);
        }
        Harness.equal(measure(fixture, cpu, NAME, Harness.PW_WRONG, wall, cpuMicros),
            AuthService.Status.THROTTLED, "the timed branch really was a locked account");

        fixture.clock().advanceSeconds(Throttle.ACCOUNT_LOCK_SECONDS + 1);
        Harness.equal(measure(fixture, cpu, NAME, Harness.PW_ONE, wall, cpuMicros),
            AuthService.Status.AUTHENTICATED, "the timed branch really was a successful sign-in");

        for (int i = 0; i < labels.size(); i++) {
            Harness.atLeast(wall.get(i), DERIVATION_FLOOR_MICROS,
                "the " + labels.get(i) + " path is floored by one real derivation (wall)");
            if (cpuAccounting) {
                Harness.atLeast(cpuMicros.get(i), DERIVATION_FLOOR_MICROS / 2,
                    "the " + labels.get(i) + " path burns CPU, not just elapsed time");
            }
        }

        double spread = (double) maxOf(wall) / (double) minOf(wall);
        Harness.check(spread <= MAX_SPREAD_RATIO,
            "all six sign-in paths are within " + MAX_SPREAD_RATIO + "x of each other (saw "
                + String.format("%.2f", spread) + "x)");
        Harness.note("wall medians in microseconds: " + pairUp(labels, wall));
        if (cpuAccounting) {
            Harness.note("cpu medians in microseconds: " + pairUp(labels, cpuMicros));
        }
        Harness.note("slowest/fastest wall ratio across the six paths: " + String.format("%.2f", spread) + "x");
        Harness.note("each derivation used m=" + Harness.TEST_MEMORY_KIB + "KiB,t="
            + Harness.TEST_ITERATIONS + ",p=" + Harness.TEST_PARALLELISM);
        fixture.close();
    }

    /**
     * Takes {@link #SAMPLES} samples of one branch and records the medians. Every attempt uses a
     * source key of its own, so the per-source budget can never be what answers a measurement.
     *
     * @return the status of the last sampled attempt, so the caller can prove which branch it timed
     */
    private static AuthService.Status measure(Harness.Fixture fixture, ThreadMXBean cpu,
        String identifier, String password, List<Long> wall, List<Long> cpuMicros) {
        List<Long> wallSamples = new ArrayList<>();
        List<Long> cpuSamples = new ArrayList<>();
        long key = TIMING_KEYS.incrementAndGet();
        AuthService.Status last = null;
        for (int sample = 0; sample < SAMPLES; sample++) {
            long startedNanos = System.nanoTime();
            long startedCpu = cpu.getCurrentThreadCpuTime();
            last = Harness.loginFrom(fixture, identifier, password, "timing-" + key + '-' + sample).status();
            wallSamples.add((System.nanoTime() - startedNanos) / 1_000L);
            cpuSamples.add((cpu.getCurrentThreadCpuTime() - startedCpu) / 1_000L);
        }
        wall.add(median(wallSamples));
        cpuMicros.add(median(cpuSamples));
        return last;
    }

    /** A credential stored below the current policy is replaced during a successful sign-in. */
    private static void upgradeOnWeakCredential(Harness.Fixture fixture) throws Exception {
        Harness.section("a stored credential below current policy is upgraded on sign-in");
        Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "src-w");
        AccountStore.Account before = fixture.accounts().findByEmail(EMAIL);

        PasswordHasher stronger;
        try {
            stronger = new PasswordHasher(Harness.TEST_MEMORY_KIB * 2, Harness.TEST_ITERATIONS + 1,
                Harness.TEST_PARALLELISM);
        } catch (java.security.GeneralSecurityException impossible) {
            throw new IllegalStateException(impossible);
        }
        // Rewire a second service that demands more work than what is stored, then sign in.
        Gate gate = new Gate(fixture.audit());
        Throttle throttle = new Throttle(fixture.db(), fixture.clock());
        AccountStore accounts = new AccountStore(fixture.db(), stronger, throttle, gate, fixture.clock());
        SessionStore sessions = new SessionStore(fixture.db(), gate, fixture.clock());
        AuthService raised = new AuthService(accounts, throttle, sessions, stronger, gate, fixture.clock());

        Harness.check(stronger.weakerThanPolicy(before.passwordHash()),
            "the stored credential really is below the raised policy");
        char[] identifier = Harness.chars(EMAIL);
        char[] password = Harness.chars(Harness.PW_ONE);
        AuthService.Result result;
        try {
            result = raised.login(identifier, password, "src-upgrade");
        } finally {
            java.util.Arrays.fill(identifier, '\0');
            java.util.Arrays.fill(password, '\0');
        }
        Harness.equal(result.status(), AuthService.Status.AUTHENTICATED,
            "sign-in succeeds with the raised policy in place");

        AccountStore.Account after = fixture.accounts().findByEmail(EMAIL);
        Harness.check(!after.passwordHash().equals(before.passwordHash()),
            "the credential was replaced while the plaintext was legitimately in hand");
        Harness.equal(after.kdfMemoryKib(), Harness.TEST_MEMORY_KIB * 2,
            "the new credential carries the raised memory cost");
        Harness.equal(after.kdfIterations(), Harness.TEST_ITERATIONS + 1,
            "the new credential carries the raised iteration count");
        Harness.check(stronger.verify(Harness.chars(Harness.PW_ONE), after.passwordHash()),
            "the upgraded credential still verifies the same password");
        Harness.check(!stronger.weakerThanPolicy(after.passwordHash()),
            "a second sign-in will not re-hash again - the upgrade converged");

        char[] identifierAgain = Harness.chars(EMAIL);
        char[] passwordAgain = Harness.chars(Harness.PW_ONE);
        try {
            Harness.check(raised.login(identifierAgain, passwordAgain, "src-upgrade-2").authenticated(),
                "sign-in still works after the upgrade");
        } finally {
            java.util.Arrays.fill(identifierAgain, '\0');
            java.util.Arrays.fill(passwordAgain, '\0');
        }
        fixture.close();
    }

    // ------------------------------------------------------------------ helpers

    private static String joined(List<String> lines) {
        return String.join("\n", lines);
    }

    private static long median(List<Long> samples) {
        List<Long> sorted = new ArrayList<>(samples);
        sorted.sort(Long::compare);
        return sorted.get(sorted.size() / 2);
    }

    private static long maxOf(List<Long> values) {
        long max = Long.MIN_VALUE;
        for (long value : values) {
            max = Math.max(max, value);
        }
        return Math.max(max, 1L);
    }

    private static long minOf(List<Long> values) {
        long min = Long.MAX_VALUE;
        for (long value : values) {
            min = Math.min(min, value);
        }
        return Math.max(min, 1L);
    }

    private static String pairUp(List<String> labels, List<Long> values) {
        StringBuilder out = new StringBuilder(256);
        for (int i = 0; i < labels.size(); i++) {
            if (i > 0) {
                out.append("; ");
            }
            out.append(labels.get(i)).append('=').append(values.get(i));
        }
        return out.toString();
    }

}
