package com.example.portal.auth;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * Per-account throttle that stops unlimited consecutive password guessing.
 *
 * <p>After {@code maxAttempts} consecutive failures an account is locked for
 * {@code lockoutDuration}; further attempts are rejected without even checking the
 * password, so guessing gains nothing. The lock expires on its own - no help-desk call
 * is needed - and any successful sign-in clears the counter.
 *
 * <p>Counters are keyed by account, which is what the requirement asks for. Note the
 * trade-off: an attacker who knows a username can deliberately lock a colleague out
 * (denial of service). A production portal should pair this with per-IP throttling and
 * alerting so the lock is a last resort rather than the first line of defence.
 *
 * <p>Thread-safe: all state changes go through {@link ConcurrentHashMap#compute}, so
 * concurrent attempts on one account cannot lose failures through a read-modify-write race.
 */
public final class LockoutPolicy {

    /** State of one account at a point in time. */
    public record Status(boolean lockedOut, int consecutiveFailures, Duration remaining) {
    }

    private static final class Attempts {
        final int failures;
        final Instant lockedUntil; // null when not locked

        Attempts(int failures, Instant lockedUntil) {
            this.failures = failures;
            this.lockedUntil = lockedUntil;
        }
    }

    private final int maxAttempts;
    private final Duration lockoutDuration;
    private final Supplier<Instant> clock;
    private final Map<String, Attempts> state = new ConcurrentHashMap<>();

    public LockoutPolicy(int maxAttempts, Duration lockoutDuration) {
        this(maxAttempts, lockoutDuration, Instant::now);
    }

    /** Clock-injecting constructor, used by the tests to avoid real waiting. */
    public LockoutPolicy(int maxAttempts, Duration lockoutDuration, Supplier<Instant> clock) {
        if (maxAttempts < 1) {
            throw new IllegalArgumentException("maxAttempts must be at least 1");
        }
        if (lockoutDuration.isNegative() || lockoutDuration.isZero()) {
            throw new IllegalArgumentException("lockoutDuration must be positive");
        }
        this.maxAttempts = maxAttempts;
        this.lockoutDuration = lockoutDuration;
        this.clock = clock;
    }

    public int maxAttempts() {
        return maxAttempts;
    }

    /** Reports whether the account is currently locked, expiring a stale lock if due. */
    public Status check(String account) {
        Instant now = clock.get();
        Attempts a = state.compute(account, (k, cur) -> expireIfDue(cur, now));
        if (a == null) {
            return new Status(false, 0, Duration.ZERO);
        }
        if (a.lockedUntil != null) {
            return new Status(true, a.failures, Duration.between(now, a.lockedUntil));
        }
        return new Status(false, a.failures, Duration.ZERO);
    }

    /** Records a failed attempt and returns the resulting status (locked or not). */
    public Status recordFailure(String account) {
        Instant now = clock.get();
        Attempts a = state.compute(account, (k, cur) -> {
            Attempts base = expireIfDue(cur, now);
            if (base != null && base.lockedUntil != null) {
                return base; // already locked; do not extend the window
            }
            int failures = (base == null ? 0 : base.failures) + 1;
            return failures >= maxAttempts
                    ? new Attempts(failures, now.plus(lockoutDuration))
                    : new Attempts(failures, null);
        });
        return a.lockedUntil != null
                ? new Status(true, a.failures, Duration.between(now, a.lockedUntil))
                : new Status(false, a.failures, Duration.ZERO);
    }

    /** Clears the counter after a successful sign-in. */
    public void recordSuccess(String account) {
        state.remove(account);
    }

    /** Number of guesses left before the account locks. */
    public int remainingAttempts(String account) {
        Status s = check(account);
        return s.lockedOut() ? 0 : Math.max(0, maxAttempts - s.consecutiveFailures());
    }

    /** Drops a lock/counter that has passed its expiry, so state does not go stale. */
    private static Attempts expireIfDue(Attempts cur, Instant now) {
        if (cur == null) {
            return null;
        }
        if (cur.lockedUntil != null && !now.isBefore(cur.lockedUntil)) {
            return null; // lock served: fresh start
        }
        return cur;
    }
}
