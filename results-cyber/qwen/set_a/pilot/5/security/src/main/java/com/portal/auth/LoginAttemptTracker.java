package com.portal.auth;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Counts failed logins per account and decides when an account is throttled.
 *
 * <p>This is the guard against password guessing: after
 * {@link LoginPolicy#maxFailedAttempts()} failures inside {@link LoginPolicy#failureWindow()} the
 * account is refused for {@link LoginPolicy#lockDuration()} without the password being checked at
 * all, so attempts stop costing the portal anything and stop telling the caller anything either.
 *
 * <p>Two properties are deliberate and easy to get wrong:
 *
 * <ul>
 *   <li>Attempts arriving <em>while</em> an account is locked do not push the expiry further out. If
 *       they did, an attacker could keep an account permanently shut by arriving continuously,
 *       turning the anti-guessing control into a denial-of-service tool.
 *   <li>State is counted per account, not per source address, because the requirement is to protect
 *       a single account. It is also what makes the counter survive an attacker rotating addresses;
 *       {@link #MAX_TRACKED_ACCOUNTS} bounds the memory that costs.
 * </ul>
 *
 * <p>All methods are {@code synchronized}. Locking is global to the tracker rather than per account
 * for auditability: the critical section is pure in-memory bookkeeping that lasts microseconds, and
 * callers hash the password <em>outside</em> this class (in {@link AuthenticationService}) so no
 * expensive work is ever done while holding the lock.
 */
public final class LoginAttemptTracker {

    /**
     * Ceiling on how many usernames we keep counters for. Without it, a flood of attempts against
     * made-up usernames would grow this map without bound. Past the ceiling the least-recently
     * touched unlocked account is evicted; losing an idle account's history is a far smaller problem
     * than running the process out of memory.
     */
    static final int MAX_TRACKED_ACCOUNTS = 100_000;

    private final Map<String, Counter> counters = new ConcurrentHashMap<>();
    private final LoginPolicy policy;
    private final Clock clock;

    public LoginAttemptTracker(LoginPolicy policy) {
        this(policy, Clock.systemUTC());
    }

    public LoginAttemptTracker(LoginPolicy policy, Clock clock) {
        this.policy = policy;
        this.clock = clock;
    }

    public LoginPolicy policy() {
        return policy;
    }

    /**
     * Current state of an account, after applying any lock that has expired.
     *
     * <p>Callers use this <em>before</em> hashing a candidate password: a locked account is refused
     * without spending the key-derivation cost.
     */
    public synchronized AttemptState state(String username) {
        Counter counter = counters.get(key(username));
        if (counter == null) {
            return new AttemptState(false, null, 0, 0, false, false, null);
        }
        settle(counter, clock.instant());
        return counter.snapshot(clock.instant());
    }

    /**
     * Records a failed credential check and applies the policy.
     *
     * @return the resulting state; {@link AttemptState#justLocked()} tells the caller to log the
     *     lockout event, and {@link AttemptState#requiresAdminUnlock()} tells
     *     {@link AuthenticationService} to move the record to {@link UserStatus#LOCKED}.
     */
    public synchronized AttemptState registerFailure(String username) {
        String key = key(username);
        Instant now = clock.instant();
        Counter counter = counters.computeIfAbsent(key, k -> new Counter(now));
        settle(counter, now);

        if (counter.lockedUntil != null && now.isBefore(counter.lockedUntil)) {
            /*
             * Already throttled. Count the attempt so repeated pressure still escalates, but leave
             * lockedUntil untouched so an attacker cannot extend the lock by continuing to arrive.
             */
            counter.failures++;
            counter.lastTouched = now;
            return counter.snapshot(now);
        }

        boolean outsideWindow = counter.windowStart == null
                || now.isAfter(counter.windowStart.plus(policy.failureWindow()));
        if (outsideWindow) {
            counter.windowStart = now;
            counter.failures = 0;
        }
        counter.failures++;
        counter.lastTouched = now;

        if (counter.failures >= policy.maxFailedAttempts()) {
            counter.locksTaken++;
            counter.lockedUntil = now.plus(policy.lockDuration());
            counter.justLocked = true;
            if (policy.permanentLockAfterLocks() > 0
                    && counter.locksTaken >= policy.permanentLockAfterLocks()) {
                counter.frozen = true;
            }
        }

        AttemptState snapshot = counter.snapshot(now);
        if (counters.size() > MAX_TRACKED_ACCOUNTS) {
            prune(now);
        }
        return snapshot;
    }

    /** A successful login clears the account's failure history. */
    public synchronized void registerSuccess(String username) {
        Counter counter = counters.get(key(username));
        if (counter == null) {
            return;
        }
        counter.failures = 0;
        counter.windowStart = null;
        counter.lockedUntil = null;
        counter.locksTaken = 0;
        counter.justLocked = false;
        /* counter.frozen is intentionally not cleared: an admin freeze survives, and a frozen
           account is refused by AuthenticationService before it could ever reach a success. */
    }

    /** Clears failures <em>and</em> any freeze. For {@link AdminService} and password resets only. */
    public synchronized void reset(String username) {
        counters.remove(key(username));
    }

    /** Number of failures currently counted against an account inside the active window. */
    public synchronized int failedAttempts(String username) {
        return state(username).failedAttempts();
    }

    /** How many times an account has ever been locked. */
    public synchronized int locksTaken(String username) {
        return state(username).locksTaken();
    }

    public synchronized int trackedAccounts() {
        return counters.size();
    }

    /**
     * Drops the lock expiry once elapsed and clears stale windows, so a count from yesterday does
     * not lock someone out today.
     */
    private void settle(Counter counter, Instant now) {
        counter.justLocked = false;
        if (counter.lockedUntil != null && !now.isBefore(counter.lockedUntil)) {
            counter.lockedUntil = null;
        }
        boolean staleWindow = counter.windowStart != null
                && now.isAfter(counter.windowStart.plus(policy.failureWindow()));
        if (staleWindow && !counter.frozen) {
            counter.windowStart = null;
            counter.failures = 0;
        }
    }

    private void prune(Instant now) {
        List<Map.Entry<String, Counter>> evictable = new ArrayList<>();
        for (Map.Entry<String, Counter> entry : counters.entrySet()) {
            Counter counter = entry.getValue();
            boolean protectedEntry = counter.frozen
                    || (counter.lockedUntil != null && now.isBefore(counter.lockedUntil));
            if (!protectedEntry) {
                evictable.add(entry);
            }
        }
        evictable.sort(Comparator.comparing(entry -> entry.getValue().lastTouched));
        int toDrop = counters.size() - MAX_TRACKED_ACCOUNTS / 2;
        for (int i = 0; i < toDrop && i < evictable.size(); i++) {
            counters.remove(evictable.get(i).getKey());
        }
    }

    private static String key(String username) {
        if (username == null) {
            throw new IllegalArgumentException("username must not be null");
        }
        return username;
    }

    /** Mutable only inside the tracker's synchronized methods. */
    private static final class Counter {
        private Instant windowStart;
        private int failures;
        private Instant lockedUntil;
        private int locksTaken;
        private boolean frozen;
        private boolean justLocked;
        private Instant lastTouched;

        Counter(Instant now) {
            this.lastTouched = now;
        }

        AttemptState snapshot(Instant now) {
            boolean frozenNow = frozen;
            boolean temporarilyLocked = lockedUntil != null && now.isBefore(lockedUntil);
            boolean locked = frozenNow || temporarilyLocked;
            Duration remaining = null;
            if (!frozenNow && temporarilyLocked) {
                remaining = Duration.between(now, lockedUntil);
            }
            /* A frozen account reports no lift time: there is no moment at which it opens by itself,
               and handing one back would invite callers to tell users to come back later. */
            return new AttemptState(locked, frozenNow ? null : lockedUntil, failures, locksTaken,
                    frozenNow, justLocked, remaining);
        }
    }

    /**
     * @param locked whether credentials must not be checked for this account
     * @param lockedUntil when a temporary lock lifts; {@code null} when frozen or not locked
     * @param failedAttempts failures counted in the current window
     * @param locksTaken how many locks this account has ever drawn
     * @param requiresAdminUnlock the lock is permanent until an operator resets it
     * @param justLocked this call is the one that engaged a lock
     * @param retryAfter how long until the temporary lock lifts; {@code null} if indefinite
     */
    public record AttemptState(
            boolean locked,
            Instant lockedUntil,
            int failedAttempts,
            int locksTaken,
            boolean requiresAdminUnlock,
            boolean justLocked,
            Duration retryAfter) {
    }
}
