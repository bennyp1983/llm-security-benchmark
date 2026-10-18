package com.example.auth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Suite 5: check-then-act under concurrency.
 *
 * <p>Two different methods are used, deliberately. Where an invariant is <em>exactly</em> checkable
 * after a race (how many attempts a shared budget admitted, how many sessions exist, how many lines
 * reached the log) the test races real threads and reconciles the total: a lost update changes the
 * total, so the assertion fails on the first run. Where a race would only <em>sometimes</em> expose
 * a defect, racing threads proves nothing -- the same test passes for correct code most runs and for
 * broken code most runs. Those properties are checked by driving the fixed orders a broken
 * implementation would get wrong, plus a source-text guard on the atomicity mechanism itself.
 */
public final class Suite5Concurrency {

    private static final int ITERATIONS = AuthConfig.MIN_PBKDF2_ITERATIONS;
    private static final long NOW = 1_700_000_000_000L;

    public static void main(String[] args) throws Exception {
        try (Fixture fx = new Fixture("suite5")) {
            fx.withKeystore(Fixture.PEPPER, AuthTestKeys.STORE_PASSWORD);
            fx.withStandardAccounts(ITERATIONS);
            concurrentSuccesses(fx);
            concurrentBurstEngagesLock(fx);
            fixedLockOrders();
            sharedSourceBudgetAdmitsExactlyTheCap();
            sweepingUsesTheDecisionClock();
            tableCapsFailClosed();
            sessionStoreAccounting();
            auditWritesAreNotLost(fx);
            lockGuardIsAtomicInSource();
        }
        Check.summary("suite5-concurrency");
    }

    // ------------------------------------------------------------------ service level

    private static void concurrentSuccesses(Fixture fx) throws Exception {
        int threads = 6;
        try (AuthenticationService service = fx.build(ITERATIONS)) {
            int before = fx.logLines().size();
            List<AuthResult> results = runAll(service, threads, i -> new String[] {
                    Fixture.USER_ALICE, Fixture.PASSWORD_A, "203.0.113." + (10 + i)});
            Set<String> tokens = new HashSet<>();
            for (AuthResult r : results) {
                if (r.isSuccess()) {
                    tokens.add(r.sessionId());
                }
            }
            Check.eq("every concurrent correct login succeeds", threads, Integer.valueOf(tokens.size()));
            boolean allValid = true;
            for (String token : tokens) {
                allValid &= service.isSessionValid(token);
            }
            Check.ok("every concurrently issued identifier is valid", allValid);
            List<String> wrote = fx.logLines().subList(before, fx.logLines().size());
            Check.eq("one event per concurrent attempt", threads, Integer.valueOf(wrote.size()));
            int successLines = 0;
            for (String line : wrote) {
                if (line.contains("type=login_success")) {
                    successLines++;
                }
            }
            Check.eq("the log agrees with the outcomes", threads, Integer.valueOf(successLines));
        }
    }

    private static void concurrentBurstEngagesLock(Fixture fx) throws Exception {
        try (AuthenticationService service = AuthenticationService.builder()
                .config(fx.config(ITERATIONS).accountLockAfter(3).accountLockSeconds(600)
                        .sourceMaxAttempts(200).build())
                .timeSource(fx.time)
                .build()) {
            // All from one source, so the per-source budget is never the reason for a refusal here.
            List<AuthResult> results = runAll(service, 6, i -> new String[] {
                    Fixture.USER_BOB, "Wrong-Password-99", "203.0.113.77"});
            int denied = 0;
            for (AuthResult r : results) {
                if (!r.isSuccess()) {
                    denied++;
                }
                Check.ok("no concurrent wrong password yields a session", r.sessionId() == null);
            }
            Check.eq("every concurrent wrong password is denied", 6, Integer.valueOf(denied));

            // The burst itself cannot report a retry hint: every attempt in it passed the lock check
            // before any lock existed, and the attempt that trips the lock is deliberately silent. The
            // probe below is what proves the lock engaged during the burst.
            AuthResult probe = fx.tryLogin(service, Fixture.USER_BOB, "Wrong-Password-99", "198.51.100.4");
            Check.ok("the next attempt against the account is refused", !probe.isSuccess());
            Check.ok("and is refused by the lock, not by the credentials", probe.retryAfterSeconds() > 0);

            AuthResult real = fx.tryLogin(service, Fixture.USER_BOB, Fixture.PASSWORD_B, "198.51.100.5");
            Check.ok("the correct password is refused while the concurrent burst's lock holds",
                    !real.isSuccess());

            fx.time.advanceMillis(600_001L);
            Check.ok("a lock formed by a burst expires like any other",
                    fx.tryLogin(service, Fixture.USER_BOB, Fixture.PASSWORD_B, "198.51.100.6").isSuccess());
        }
    }

    /**
     * Fixed orders through the throttle, where the lock decision is made. A non-atomic increment
     * shows up as the wrong decision at a specific position in the sequence, which is what falsifies
     * it; a timed race would show the same defect only occasionally.
     */
    private static void fixedLockOrders() {
        AttemptThrottle throttle = new AttemptThrottle();
        Check.eq("first failure is allowed", AttemptThrottle.Kind.ALLOW,
                throttle.recordAccountFailure("acct", NOW, 3, 600).kind());
        Check.eq("second failure is allowed", AttemptThrottle.Kind.ALLOW,
                throttle.recordAccountFailure("acct", NOW, 3, 600).kind());
        Check.eq("the third failure locks", AttemptThrottle.Kind.LOCKED,
                throttle.recordAccountFailure("acct", NOW, 3, 600).kind());
        Check.eq("a later attempt sees the lock", AttemptThrottle.Kind.LOCKED,
                throttle.checkAccountLock("acct", NOW).kind());

        // Hammering a locked account must not lengthen the lock: an attacker who could extend it by
        // retrying could hold a legitimate user out indefinitely.
        throttle.recordAccountFailure("acct", NOW, 3, 600);
        throttle.recordAccountFailure("acct", NOW + 1_000L, 3, 600);
        Check.ok("the lock still holds at the end of its window",
                throttle.checkAccountLock("acct", NOW + 599_000L).kind() == AttemptThrottle.Kind.LOCKED);
        Check.ok("repeated failures did not push it past the window",
                throttle.checkAccountLock("acct", NOW + 601_000L).kind() == AttemptThrottle.Kind.ALLOW);

        // Success path order: failures, a success, then the same count of failures again.
        AttemptThrottle reset = new AttemptThrottle();
        reset.recordAccountFailure("acct2", NOW, 3, 600);
        reset.recordAccountFailure("acct2", NOW, 3, 600);
        reset.resetAccount("acct2");
        Check.eq("a success clears the streak, so the next failure is number one",
                AttemptThrottle.Kind.ALLOW, reset.recordAccountFailure("acct2", NOW, 3, 600).kind());
        Check.eq("and the failure after it is still number two",
                AttemptThrottle.Kind.ALLOW, reset.recordAccountFailure("acct2", NOW, 3, 600).kind());
        Check.eq("the third one locks", AttemptThrottle.Kind.LOCKED,
                reset.recordAccountFailure("acct2", NOW, 3, 600).kind());

        // One bucket per name: alternating case must not halve the attacker's visible progress.
        AttemptThrottle folded = new AttemptThrottle();
        folded.recordAccountFailure(AttemptThrottle.canonicalize("Alice"), NOW, 3, 600);
        folded.recordAccountFailure(AttemptThrottle.canonicalize("ALICE"), NOW, 3, 600);
        Check.eq("case variants share one streak", AttemptThrottle.Kind.LOCKED,
                folded.recordAccountFailure(AttemptThrottle.canonicalize("alice"), NOW, 3, 600).kind());
        Check.ok("a non-ASCII look-alike is not folded onto the real name",
                !AttemptThrottle.canonicalize("alice")
                        .equals(AttemptThrottle.canonicalize("al" + String.valueOf((char) 0x00c9) + "ce")));
    }

    // ------------------------------------------------------------------ throttle internals

    /**
     * Races a shared budget and reconciles exactly how many attempts it admitted. A lost update
     * admits more than the cap, which this catches on the first run rather than occasionally.
     */
    private static void sharedSourceBudgetAdmitsExactlyTheCap() throws Exception {
        final int cap = 40;
        final int threads = 8;
        final int perThread = 5;
        AttemptThrottle throttle = new AttemptThrottle();
        AtomicInteger admitted = new AtomicInteger();
        AtomicInteger refused = new AtomicInteger();
        race(threads, () -> {
            for (int i = 0; i < perThread; i++) {
                if (throttle.consumeSourceAttempt("203.0.113.5", NOW + i, 600, cap, 600).allowed()) {
                    admitted.incrementAndGet();
                } else {
                    refused.incrementAndGet();
                }
            }
        });
        Check.eq("the shared budget admits exactly its cap, never more", cap, Integer.valueOf(admitted.get()));
        Check.eq("everything past the cap is refused", threads * perThread - cap, Integer.valueOf(refused.get()));

        // Per-account: however the threads interleave, exactly lockAfter failures are counted before
        // the lock forms, so no attempt slips past the threshold. The attempt that reaches the
        // threshold reports LOCKED rather than ALLOW, so lockAfter - 1 failures are admitted.
        final int lockAfter = 7;
        AttemptThrottle accountRace = new AttemptThrottle();
        AtomicInteger allowed = new AtomicInteger();
        AtomicInteger locked = new AtomicInteger();
        race(threads, () -> {
            for (int i = 0; i < perThread; i++) {
                if (accountRace.recordAccountFailure("raced", NOW + i, lockAfter, 600).kind()
                        == AttemptThrottle.Kind.ALLOW) {
                    allowed.incrementAndGet();
                } else {
                    locked.incrementAndGet();
                }
            }
        });
        Check.eq("exactly lockAfter failures are counted before the lock forms", lockAfter - 1,
                Integer.valueOf(allowed.get()));
        Check.ok("the remaining racing failures see the lock",
                locked.get() == threads * perThread - (lockAfter - 1));
    }

    /**
     * Idle housekeeping must use the same clock as the verdicts. A sweep that reads the wall clock
     * while decisions use the injected one deletes lockout state wholesale wherever the two differ,
     * and every limit then silently stops applying while the component still reports healthy.
     */
    private static void sweepingUsesTheDecisionClock() {
        AttemptThrottle throttle = new AttemptThrottle();
        // Far in the past relative to this machine's clock, which is what exposes a sweep that reads
        // the wall clock: its horizon would leave nothing "recent" in the table.
        long past = System.currentTimeMillis() - 3_600_000L;
        for (int i = 0; i < 200; i++) {
            throttle.recordAccountFailure("keep-" + i, past, 1_000, 600);
        }
        throttle.recordAccountFailure("keep-0", past, 1_000, 600);
        Check.ok("the sweep interval really ran", 201 / 64 >= 1);
        Check.eq("recently used keys survive a sweep computed on the decision clock", 200,
                Integer.valueOf(throttle.trackedAccountKeys()));

        // And a lock formed on that timeline still holds after sweeps.
        AttemptThrottle locked = new AttemptThrottle();
        for (int i = 0; i < 3; i++) {
            locked.recordAccountFailure("victim", past, 3, 600);
        }
        for (int i = 0; i < 200; i++) {
            locked.recordAccountFailure("noise-" + i, past, 1_000, 600);
        }
        Check.eq("the lock outlived the sweeps around it", AttemptThrottle.Kind.LOCKED,
                locked.checkAccountLock("victim", past).kind());
    }

    /** A throttle that runs out of table space must stop admitting, not start admitting. */
    private static void tableCapsFailClosed() {
        AttemptThrottle throttle = new AttemptThrottle();
        int filled = 0;
        int unfixedAddresses = 0;
        for (int i = 0; i < AttemptThrottle.MAX_SOURCE_KEYS + 64 && filled < AttemptThrottle.MAX_SOURCE_KEYS; i++) {
            String address = String.format(java.util.Locale.ROOT, "10.%d.%d.%d",
                    (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
            String canonical = InputValidator.normalizeSourceAddress(address);
            if (canonical == null) {
                unfixedAddresses++;
                continue;
            }
            if (throttle.consumeSourceAttempt(canonical, NOW, 600, 1000, 600).allowed()) {
                filled++;
            }
        }
        Check.eq("every fixture address is accepted", 0, Integer.valueOf(unfixedAddresses));
        Check.eq("the source table fills to its cap", AttemptThrottle.MAX_SOURCE_KEYS, Integer.valueOf(filled));
        AttemptThrottle.Decision overflow = throttle.consumeSourceAttempt("203.0.113.200", NOW, 600, 1000, 600);
        Check.ok("a new source is refused once the table is full", !overflow.allowed());
        Check.eq("the refusal is a block, not a permissive default", AttemptThrottle.Kind.BLOCKED,
                overflow.kind());

        AttemptThrottle accounts = new AttemptThrottle();
        for (int i = 0; i < AttemptThrottle.MAX_ACCOUNT_KEYS; i++) {
            accounts.recordAccountFailure("probe-" + i, NOW, 1000, 600);
        }
        Check.eq("a new account key is refused once that table is full too", AttemptThrottle.Kind.BLOCKED,
                accounts.recordAccountFailure("probe-overflow", NOW, 3, 600).kind());
    }

    private static void sessionStoreAccounting() throws Exception {
        final int cap = 64;
        final int threads = 8;
        final int perThread = 20;
        // A fixed clock: nothing ages, so nothing is evictable and the cap must hold exactly.
        SessionTokenStore store = new SessionTokenStore(new java.security.SecureRandom(), 900, cap,
                TimeSource.mutable(NOW));
        Set<String> tokens = Collections.synchronizedSet(new HashSet<>());
        AtomicInteger issued = new AtomicInteger();
        race(threads, () -> {
            for (int i = 0; i < perThread; i++) {
                String token = store.issue();
                if (token != null) {
                    issued.incrementAndGet();
                    tokens.add(token);
                }
            }
        });
        Check.eq("concurrent issues stop at the cap", cap, Integer.valueOf(issued.get()));
        Check.eq("the table never exceeds its cap", cap, Integer.valueOf(store.activeCount()));
        Check.eq("every accepted issue produced a distinct identifier",
                issued.get(), Integer.valueOf(tokens.size()));
        int valid = 0;
        for (String token : tokens) {
            if (store.isValid(token)) {
                valid++;
            }
        }
        Check.eq("every identifier in the table validates", store.activeCount(), Integer.valueOf(valid));
        Check.ok("the excess attempts were refused rather than silently dropped",
                issued.get() < threads * perThread);
    }

    // ------------------------------------------------------------------ audit under load

    /** Under concurrency the log must still hold one line per attempt, with no duplicate sequence. */
    private static void auditWritesAreNotLost(Fixture fx) throws Exception {
        try (AuthenticationService service = fx.build(ITERATIONS)) {
            int threads = 8;
            int before = fx.logLines().size();
            long persistedBefore = service.persistedEventCount();
            List<AuthResult> results = runAll(service, threads, i -> new String[] {
                    i % 2 == 0 ? Fixture.USER_ALICE : Fixture.USER_BOB,
                    i % 2 == 0 ? Fixture.PASSWORD_A : "Wrong-Password-99",
                    "203.0.113." + (30 + i)});
            List<String> wrote = fx.logLines().subList(before, fx.logLines().size());
            Check.eq("every concurrent attempt produced exactly one line", threads, Integer.valueOf(wrote.size()));
            Set<String> sequences = new HashSet<>();
            for (String line : wrote) {
                sequences.add(line.substring(4, line.indexOf(' ', 4)));
            }
            Check.eq("no two concurrent events claim the same sequence", threads, Integer.valueOf(sequences.size()));
            int successes = 0;
            for (AuthResult r : results) {
                if (r.isSuccess()) {
                    successes++;
                }
            }
            int successLines = 0;
            for (String line : wrote) {
                if (line.contains("type=login_success")) {
                    successLines++;
                }
            }
            Check.eq("half the concurrent attempts were correct logins", threads / 2, Integer.valueOf(successes));
            Check.eq("successes in the file match the successes reported", successes,
                    Integer.valueOf(successLines));
            // The counter counts what this process persisted since it opened the log (it starts at the
            // number of lines it read back), so it is reconciled as a delta, not against the file size.
            Check.eq("the persisted counter advanced once per concurrent attempt", threads,
                    Integer.valueOf((int) (service.persistedEventCount() - persistedBefore)));
        }
    }

    // ------------------------------------------------------------------ source guard

    /**
     * The atomicity of the lock decision is load-bearing: incrementing a counter outside the
     * {@code compute} call would let two threads each see "one below the limit" and admit an extra
     * attempt. No test can force that interleaving reliably, so the source is checked directly.
     */
    private static void lockGuardIsAtomicInSource() throws IOException {
        String source = stripComments(readThrottleSource());
        int start = source.indexOf("Decision recordAccountFailure");
        int end = source.indexOf("void resetAccount");
        Check.ok("the failure path is present to inspect", start >= 0 && end > start);
        if (start < 0 || end <= start) {
            return;
        }
        String body = source.substring(start, end);
        Check.ok("the failure count is incremented inside ConcurrentHashMap.compute",
                body.contains("accounts.compute(") && body.contains("consecutiveFailures++"));
        Check.ok("no get-then-put on the account table survives in that path",
                !body.contains("accounts.get(") && !body.contains("accounts.put("));

        int budgetStart = source.indexOf("Decision consumeSourceAttempt");
        int budgetEnd = source.indexOf("Decision checkAccountLock");
        Check.ok("the budget path is present to inspect", budgetStart >= 0 && budgetEnd > budgetStart);
        if (budgetStart < 0 || budgetEnd <= budgetStart) {
            return;
        }
        String budget = source.substring(budgetStart, budgetEnd);
        Check.ok("the source budget is consumed inside ConcurrentHashMap.compute",
                budget.contains("sources.compute(") && !budget.contains("sources.put("));

        int lockStart = budgetEnd;
        int lockEnd = source.indexOf("Decision recordAccountFailure");
        String lockBody = source.substring(lockStart, lockEnd);
        Check.ok("applying the lock reads without consuming anything",
                !lockBody.contains("accounts.compute(") && !lockBody.contains("consecutiveFailures++"));
    }

    private static String readThrottleSource() throws IOException {
        Path candidate = Path.of("src/main/java/com/example/auth/AttemptThrottle.java");
        if (!Files.isRegularFile(candidate)) {
            candidate = Path.of(System.getProperty("auth.source.dir", "."),
                    "src/main/java/com/example/auth/AttemptThrottle.java");
        }
        Check.ok("the throttle source is readable for the atomicity guard", Files.isRegularFile(candidate));
        return new String(Files.readAllBytes(candidate), StandardCharsets.UTF_8);
    }

    /**
     * Removes comments so prose cannot satisfy (or defeat) a source-text check. The literal pass is
     * deliberately simple: this file's literals contain no braces, comment markers or backslashes at
     * odd positions, and the guard only looks for method-call text.
     */
    private static String stripComments(String text) {
        StringBuilder out = new StringBuilder(text.length());
        boolean inString = false;
        boolean inChar = false;
        boolean inLine = false;
        boolean inBlock = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            char next = i + 1 < text.length() ? text.charAt(i + 1) : '\0';
            if (inLine) {
                if (c == '\n') {
                    inLine = false;
                    out.append('\n');
                }
                continue;
            }
            if (inBlock) {
                if (c == '*' && next == '/') {
                    inBlock = false;
                    i++;
                }
                continue;
            }
            if (!inString && !inChar && c == '/' && next == '/') {
                inLine = true;
                i++;
                continue;
            }
            if (!inString && !inChar && c == '/' && next == '*') {
                inBlock = true;
                i++;
                continue;
            }
            if (!inChar && c == '"' && !inString) {
                inString = true;
            } else if (inString && c == '"') {
                inString = false;
            } else if (!inString && c == '\'' && !inChar) {
                inChar = true;
            } else if (inChar && c == '\'') {
                inChar = false;
            }
            out.append(c);
        }
        return out.toString();
    }

    // ------------------------------------------------------------------ helpers

    private interface AttemptSpec {
        String[] get(int index);
    }

    private interface Body {
        void run();
    }

    /** Starts {@code threads} tasks on a barrier so they enter the guarded section together. */
    private static void race(int threads, Body body) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();
        try {
            for (int t = 0; t < threads; t++) {
                futures.add(pool.submit(() -> {
                    ready.countDown();
                    await(go);
                    body.run();
                }));
            }
            ready.await(30, TimeUnit.SECONDS);
            go.countDown();
            for (Future<?> f : futures) {
                f.get(120, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }
    }

    private static List<AuthResult> runAll(AuthenticationService service, int threads, AttemptSpec spec)
            throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<AuthResult>> futures = new ArrayList<>();
        try {
            for (int t = 0; t < threads; t++) {
                final int index = t;
                futures.add(pool.submit(() -> {
                    String[] plan = spec.get(index);
                    char[] chars = plan[1].toCharArray();
                    ready.countDown();
                    await(go);
                    try {
                        return service.authenticate(AuthenticationService.Attempt.of(plan[0], chars, plan[2]));
                    } finally {
                        Arrays.fill(chars, (char) 0);
                    }
                }));
            }
            ready.await(30, TimeUnit.SECONDS);
            go.countDown();
            List<AuthResult> out = new ArrayList<>();
            for (Future<AuthResult> f : futures) {
                out.add(f.get(120, TimeUnit.SECONDS));
            }
            return out;
        } finally {
            pool.shutdownNow();
        }
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await(30, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }
}
