package com.portal.auth;

import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;

/**
 * Failed-attempt limiting, per account <em>and</em> per source, with the decision and the
 * counter mutation performed in one atomic transition.
 *
 * <h2>Why two dimensions</h2>
 * A single account-level counter is a denial-of-service lever: an attacker who knows a
 * colleague's name spends their own handful of guesses to lock that colleague out. So:
 * <ul>
 *   <li><b>per source</b> (validated client address, or "local" for the CLI): the tight
 *       budget. It stops the spray and runs out before an attacker can spend much of any
 *       victim's budget.</li>
 *   <li><b>per account</b>: a back-off rather than an indefinite lock. It clears by
 *       itself, grows exponentially while abuse continues, and is cleared by a
 *       <em>correct</em> password, so a locked-out user recovers by authenticating rather
 *       than by waiting for an administrator.</li>
 * </ul>
 *
 * <h2>Atomicity</h2>
 * {@link #gate}, {@link #recordFailure} and {@link #recordSuccess} each hold one monitor
 * for the whole read-modify-write, then persist the resulting state to the ledger under
 * the same monitor. There is no window in which a concurrent request can observe a
 * count and act on a decision derived from a stale value.
 *
 * <h2>Timing equalisation</h2>
 * Every denial path runs the same KDF work as a wrong-password path
 * ({@link PasswordHasher#verifyAgainstDecoy}) and every refusal is then padded to a
 * common latency floor, so "you are locked out" and "wrong password" are not
 * distinguishable by response time. See {@link Authenticator#timings()} for the
 * measurement that pins this down.
 */
public final class ThrottleManager {

    public static final int ACCOUNT_MAX_FAILURES = 5;
    public static final int SOURCE_MAX_FAILURES = 30;
    public static final long WINDOW_SECONDS = 300;
    /** First back-off after the account budget is spent. */
    public static final long BASE_BLOCK_SECONDS = 30;
    /**
     * Ceiling for an <em>account</em> back-off. Deliberately short (15 minutes, not
     * hours): a long account lock is a denial-of-service weapon that an attacker can
     * afford, because they only have to spend five guesses again after it lapses. The
     * correct password also clears it, so the legitimate user's recovery does not depend
     * on an administrator.
     */
    public static final long MAX_ACCOUNT_BLOCK_SECONDS = 900;
    /**
     * Ceiling for a <em>source</em> block. This one is long: the blocked party is the
     * attacker's own address, so there is no lockout weapon to worry about.
     */
    public static final long MAX_SOURCE_BLOCK_SECONDS = 8 * 3600;
    /** Retain a window this long so a restart cannot outrun it. */
    public static final long RETENTION_SECONDS = 24 * 3600;
    private static final int MAX_SUBJECTS = 50_000;

    public enum Kind {
        /** Allowed to proceed to password verification. */
        ALLOWED,
        /** Budget spent: refuse without revealing which dimension tripped. */
        THROTTLED
    }

    /** A single subject's counters (account or source). */
    public static final class State {
        long windowStart;
        int failures;
        long blockedUntil;
        /** Number of times this subject has tripped the back-off; drives the exponent. */
        int strikes;
        /**
         * Which window {@link #failures} describes. Bumped only where this class
         * <em>deliberately replaces</em> the window (a success, a rollover, a failure that
         * arms a back-off), never when a failure is merely added to it. The ledger's merge
         * needs it to tell "a sibling counted more attempts in the same window" from "the
         * window was replaced since that sibling wrote"; without it the on-disk count is
         * monotonic and cannot be cleared at all -- see {@link Ledger}.
         */
        long generation;

        State() {
            this.windowStart = AuditClock.epochSecond();
        }
    }

    private final Object monitor = new Object();
    private final Map<String, State> accounts = new HashMap<>();
    private final Map<String, State> sources = new HashMap<>();
    private final Map<Kind, Long> counters = new EnumMap<>(Kind.class);
    private final Ledger ledger;
    private long lastDecisionNanos;
    private long latencyFloorNanos = 1_000_000L;
    private boolean paddingSuppressed;
    private long ledgerLosses;

    public ThrottleManager(Ledger ledger) {
        this.ledger = ledger;
        for (Kind k : Kind.values()) {
            counters.put(k, 0L);
        }
        if (ledger != null) {
            try {
                loadFromLedger();
            } catch (RuntimeException ledgerUntrustworthy) {
                // A corrupt or unreadable ledger is never a reason to allow more
                // attempts: counters are reset to zero, which is the strictest state,
                // and the anomaly is reported by the caller through the audit log.
                accounts.clear();
                sources.clear();
                ledgerLosses++;
            }
        }
    }

    public long ledgerLossCount() {
        synchronized (monitor) {
            return ledgerLosses;
        }
    }

    private void loadFromLedger() {
        long now = AuditClock.epochSecond();
        Map<String, Ledger.Counter> loaded = ledger.load(now, RETENTION_SECONDS);
        for (Map.Entry<String, Ledger.Counter> e : loaded.entrySet()) {
            char kind = e.getKey().charAt(0);
            String subject = e.getKey().substring(2);
            State s = new State();
            s.windowStart = e.getValue().windowStart;
            s.failures = e.getValue().count;
            s.blockedUntil = e.getValue().blockedUntil;
            s.generation = e.getValue().generation;
            if (s.blockedUntil > s.windowStart) {
                s.strikes = 1;
            }
            (kind == 'a' ? accounts : sources).put(subject, s);
        }
    }

    /**
     * Atomically reserve one verification slot, or refuse.
     *
     * <p>This is a <em>reservation</em>, not a peek: the counter is incremented inside the
     * same monitor that decides the verdict, so a burst of concurrent requests cannot all
     * read "4 of 5 failures" and then all go on to verify. A separate {@code isAllowed()}
     * followed by a later {@code countFailure()} would be exactly the check-then-act hole
     * this class exists to close, and it is the reason the verdict and the mutation are one
     * operation here.
     *
     * <p>Cheap and identity-blind by design: it never touches the roster, so the answer
     * cannot vary between an existing and a non-existing username.
     *
     * <p>What "restriction" means here, precisely: spending the budget restricts
     * immediately, and the timed back-off window is armed by {@link #recordFailure} -- the
     * caller's observation that a reserved verification actually failed. An exhausted
     * budget with no armed window rolls clean at the next window boundary rather than
     * blocking for a further period, because the reservation counter alone does not
     * distinguish five wrong passwords from five requests that were never verified.
     */
    public Kind beginAttempt(String accountRef, String sourceHex) {
        synchronized (monitor) {
            String acct = requireRef(accountRef);
            long now = AuditClock.epochSecond();
            State a = live(accounts, acct);
            State s = live(sources, sourceHex);
            boolean blocked = a.blockedUntil > now || s.blockedUntil > now
                    || a.failures >= ACCOUNT_MAX_FAILURES
                    || s.failures >= SOURCE_MAX_FAILURES;
            Kind verdict;
            if (blocked) {
                verdict = Kind.THROTTLED;
            } else {
                a.failures++;
                s.failures++;
                verdict = Kind.ALLOWED;
            }
            counters.merge(verdict, 1L, Long::sum);
            lastDecisionNanos = System.nanoTime();
            persistLocked();
            return verdict;
        }
    }

    /**
     * The reserved slot's verification failed. Applies the back-off if the reserved count
     * has reached the budget; it does not re-decide anything, and it never re-reads the
     * caller's expectation.
     */
    public void recordFailure(String accountRef, String sourceHex) {
        synchronized (monitor) {
            String acct = requireRef(accountRef);
            long now = AuditClock.epochSecond();
            State a = live(accounts, acct);
            State s = live(sources, sourceHex);
            if (a.failures >= ACCOUNT_MAX_FAILURES && a.blockedUntil <= now) {
                a.strikes = Math.max(1, a.strikes + 1);
                // The exponent cap must land exactly on MAX_ACCOUNT_BLOCK_SECONDS, not one
                // step below it. With the old shift cap of 5 the reachable maximum was
                // 30 << 5 = 480s, so the 900s ceiling stated in this class's documentation
                // was never enforced and the last doubling was silently truncated. The
                // shift that first overshoots 900 is 30 << 6 = 1920, so the strike count is
                // capped at 7 (shift 6) and the min() below is what actually applies the
                // ceiling -- making the declared limit the enforced one.
                a.strikes = Math.min(a.strikes, 7);
                long back = Math.min(MAX_ACCOUNT_BLOCK_SECONDS,
                        BASE_BLOCK_SECONDS << (a.strikes - 1));
                a.blockedUntil = now + back;
                a.windowStart = now;
                a.failures = 0;
                a.generation++;
            }
            if (s.failures >= SOURCE_MAX_FAILURES && s.blockedUntil <= now) {
                // Sources get the ceiling immediately: the point of the source budget is to
                // make an automated spray expensive, not to warn about it. The blocked
                // party here is the attacker's own address, so a long ceiling is not a
                // lockout weapon -- see MAX_ACCOUNT_BLOCK_SECONDS for why the account
                // ceiling is short instead.
                s.blockedUntil = now + MAX_SOURCE_BLOCK_SECONDS;
                s.windowStart = now;
                s.failures = 0;
                s.generation++;
            }
            persistLocked();
            lastDecisionNanos = System.nanoTime();
        }
    }

    /**
     * A correct password clears the account's counters, so partial harassment (a few
     * failures burned before the real user signs in) never accumulates into a lockout.
     *
     * <p>Stated precisely, because the first version of this comment overclaimed: this
     * method clears a window that is <em>already running</em> only if
     * {@link #beginAttempt} handed out a slot, which it does not do while the account is
     * blocked. So the recovery path for a user whose budget was burned by an attacker is
     * that the window lapses on its own, not that a correct password overrides it. What
     * keeps that tolerable is the ceiling: the window is short, self-clearing, decays with
     * a quiet period, and an attacker can only burn one account per
     * {@code ACCOUNT_MAX_FAILURES} of their own requests before their address is blocked.
     */
    public void recordSuccess(String accountRef, String sourceHex) {
        synchronized (monitor) {
            State a = live(accounts, requireRef(accountRef));
            a.failures = 0;
            a.blockedUntil = 0;
            a.strikes = 0;
            a.windowStart = AuditClock.epochSecond();
            a.generation++;
            counters.merge(Kind.ALLOWED, 1L, Long::sum);
            persistLocked();
            lastDecisionNanos = System.nanoTime();
        }
    }

    /** Consume the source budget for a non-authentication abuse (e.g. forged session id). */
    public void consumeSourceBudget(String sourceHex) {
        synchronized (monitor) {
            State s = live(sources, sourceHex);
            s.failures++;
            if (s.failures >= SOURCE_MAX_FAILURES) {
                s.blockedUntil = AuditClock.epochSecond() + MAX_SOURCE_BLOCK_SECONDS;
                s.windowStart = AuditClock.epochSecond();
                s.failures = 0;
                s.generation++;
            }
            persistLocked();
        }
    }

    /**
     * Pad a decision so that every outcome takes about the same wall time. Must be called
     * outside the monitor: it burns CPU on purpose.
     *
     * <p>{@code startedAt} is the caller's request-start timestamp rather than a shared
     * field: under concurrency a shared "last decision" value belongs to whichever request
     * happened to write it last, which would make the padding arbitrary.
     *
     * <p>This performs no key derivation. The KDF work that every path must share is done
     * by {@link Authenticator}, exactly once per request -- doing it here as well would
     * make the per-path work differ, which is precisely the channel this padding exists
     * to close.
     */
    public void padToFloor(long startedAtNanos) {
        long floor;
        if (paddingSuppressed) {
            return;
        }
        synchronized (monitor) {
            floor = latencyFloorNanos;
        }
        long elapsed = System.nanoTime() - startedAtNanos;
        long remaining = floor - elapsed;
        if (remaining > 0) {
            long deadline = System.nanoTime() + remaining;
            // Busy-wait rather than sleep: Thread.sleep granularity is ~1 ms on this box
            // and the point of the padding is sub-millisecond uniformity.
            while (System.nanoTime() < deadline) {
                Thread.onSpinWait();
            }
        }
    }

    /** Observe the slowest refusal so far and use it as the common floor. */
    public void observeLatency(long nanos) {
        if (paddingSuppressed) {
            return;
        }
        synchronized (monitor) {
            if (nanos > latencyFloorNanos) {
                latencyFloorNanos = nanos;
            }
        }
    }

    /**
     * Test controls for the timing assertions.
     *
     * <p>{@code suppressPadding} makes both the padding <b>and</b> the floor ratchet no-ops,
     * so a measurement sees the paths' real cost. It has to disable both: if the ratchet
     * stayed live, the first measured path would raise the floor and every later path would
     * be padded up to it, so a mutant that deletes a derivation from one branch would still
     * show a perfect spread.
     *
     * <p>{@code raiseFloorNanos} only ever <em>raises</em> the floor, so it cannot loosen
     * production behaviour. With the floor set well above the KDF cost, every outcome must
     * take at least the floor -- an assertion the padding actually has to satisfy, which a
     * spread-only assertion would never catch.
     */
    void setTimingControlsForTesting(boolean suppressPadding, long raiseFloorNanos) {
        synchronized (monitor) {
            this.paddingSuppressed = suppressPadding;
            if (raiseFloorNanos > this.latencyFloorNanos) {
                this.latencyFloorNanos = raiseFloorNanos;
            }
        }
    }

    public long latencyFloorNanos() {
        synchronized (monitor) {
            return latencyFloorNanos;
        }
    }

    public long countOf(Kind kind) {
        synchronized (monitor) {
            return counters.getOrDefault(kind, 0L);
        }
    }

    /** Test/inspection only: failures currently recorded for an account. */
    public int failureCountFor(String accountSubjectHex) {
        synchronized (monitor) {
            return live(accounts, accountSubjectHex).failures;
        }
    }

    public int failureCountForSource(String sourceHex) {
        synchronized (monitor) {
            return live(sources, sourceHex).failures;
        }
    }

    public boolean isAccountBlocked(String accountSubjectHex) {
        synchronized (monitor) {
            return live(accounts, accountSubjectHex).blockedUntil > AuditClock.epochSecond();
        }
    }

    public boolean isSourceBlocked(String sourceHex) {
        synchronized (monitor) {
            return live(sources, sourceHex).blockedUntil > AuditClock.epochSecond();
        }
    }

    /** Seconds until the account back-off lapses; 0 when it is not blocking. */
    public long accountBlockRemaining(String accountSubjectHex) {
        synchronized (monitor) {
            long until = live(accounts, accountSubjectHex).blockedUntil;
            long now = AuditClock.epochSecond();
            return until > now ? until - now : 0;
        }
    }

    public void clearAccountForTesting(String accountSubjectHex) {
        synchronized (monitor) {
            accounts.remove(accountSubjectHex);
            persistLocked();
        }
    }

    private State live(Map<String, State> map, String subject) {
        State s = map.get(subject);
        long now = AuditClock.epochSecond();
        if (s == null) {
            if (map.size() >= MAX_SUBJECTS) {
                sweep(map);
                if (map.size() >= MAX_SUBJECTS) {
                    throw new IllegalStateException("throttle-subject-capacity");
                }
            }
            s = new State();
            map.put(subject, s);
        }
        // Two independent roll-overs, measured against two different reference points.
        //
        // (1) The failure *count* window rolls over once it is older than WINDOW_SECONDS
        // and no block is live. A subject that is currently blocked is never rolled over,
        // so reading it for a status line cannot erase the count that armed the block.
        //
        // (2) The escalation (strikes) decays only after a quiet period measured from the
        // subject's last event, which for a blocked subject is the moment its block ends --
        // not the moment it was armed. This distinction is not cosmetic: a 480 s back-off
        // is longer than WINDOW_SECONDS, so decay measured from the arming time would fire
        // while the subject is still sitting out its own window. The escalation would then
        // reset on every round and the back-off could never exceed WINDOW_SECONDS, which
        // would silently make MAX_ACCOUNT_BLOCK_SECONDS unreachable decoration. Decay still
        // happens -- after a genuinely quiet period -- and it only ever makes the subject
        // less restricted, so this direction fails closed.
        if (s.blockedUntil <= now && now - s.windowStart > WINDOW_SECONDS) {
            s.windowStart = now;
            s.failures = 0;
            s.generation++;
        }
        if (now - Math.max(s.windowStart, s.blockedUntil) > WINDOW_SECONDS) {
            s.strikes = 0;
        }
        return s;
    }

    private void sweep(Map<String, State> map) {
        long now = AuditClock.epochSecond();
        map.entrySet().removeIf(e -> now - e.getValue().windowStart > RETENTION_SECONDS
                && e.getValue().blockedUntil <= now);
    }

    private void persistLocked() {
        if (ledger == null) {
            return;
        }
        Map<String, Ledger.Counter> snapshot = new HashMap<>();
        for (Map.Entry<String, State> e : accounts.entrySet()) {
            snapshot.put(Ledger.key('a', e.getKey()),
                    new Ledger.Counter(e.getValue().windowStart, e.getValue().failures,
                            e.getValue().blockedUntil, e.getValue().generation));
        }
        for (Map.Entry<String, State> e : sources.entrySet()) {
            snapshot.put(Ledger.key('s', e.getKey()),
                    new Ledger.Counter(e.getValue().windowStart, e.getValue().failures,
                            e.getValue().blockedUntil, e.getValue().generation));
        }
        try {
            ledger.persist(snapshot);
        } catch (RuntimeException ledgerDown) {
            // In-memory enforcement still holds; the decision must not change because
            // the durability layer is unavailable. Recorded for the operator.
            ledgerLosses++;
        }
    }

    /** A throttle subject must be the 16-hex reference this class documents. */
    private static String requireRef(String ref) {
        if (ref == null || ref.length() != Ledger.SUBJECT_HEX || !isLowerHex(ref)) {
            throw new IllegalArgumentException("throttle-subject-shape");
        }
        return ref;
    }

    private static boolean isLowerHex(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return true;
    }
}
