package com.example.auth.web;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Counts failed logins per caller and per account name, and refuses further attempts for a while
 * once the threshold is reached. Without it, an unauthenticated caller can try passwords as fast as
 * the server can hash them.
 *
 * <p>The same counter and the same refusal apply whether or not the named account exists, so the
 * refusal cannot be used to find out which usernames are real.
 */
public final class LoginThrottle {

    /** What a login attempt is allowed to do right now. */
    public enum Verdict {
        /** Go ahead and check the credentials. */
        PROCEED,
        /** Too many recent failures; the caller is being made to wait. */
        THROTTLED
    }

    private record Attempt(int failures, Instant firstFailureAt, Instant lockedUntil) {

        static Attempt firstFailure(Instant now) {
            return new Attempt(1, now, null);
        }

        Attempt again(Instant now, Duration window) {
            if (firstFailureAt == null || firstFailureAt.plus(window).isBefore(now)) {
                return firstFailure(now);
            }
            return new Attempt(failures + 1, firstFailureAt, null);
        }

        Attempt lockedUntil(Instant until) {
            return new Attempt(0, null, until);
        }
    }

    private final Map<String, Attempt> attempts = new ConcurrentHashMap<>();
    private final int maxFailures;
    private final Duration window;
    private final Duration lockout;
    private volatile Instant lastPurgeAt = Instant.now();

    public LoginThrottle(int maxFailures, Duration window, Duration lockout) {
        if (maxFailures < 1) {
            throw new IllegalArgumentException("maxFailures must be at least 1");
        }
        if (window == null || window.isZero() || window.isNegative()) {
            throw new IllegalArgumentException("window must be positive");
        }
        if (lockout == null || lockout.isZero() || lockout.isNegative()) {
            throw new IllegalArgumentException("lockout must be positive");
        }
        this.maxFailures = maxFailures;
        this.window = window;
        this.lockout = lockout;
    }

    /** A key that identifies one caller chasing one account name. */
    public static String keyFor(String remoteAddr, String username) {
        return remoteAddr + "\n" + username;
    }

    public Verdict verdictFor(String key, Instant now) {
        purgeStale(now);
        if (key == null) {
            return Verdict.PROCEED;
        }
        Attempt attempt = attempts.get(key);
        if (attempt == null) {
            return Verdict.PROCEED;
        }
        if (attempt.lockedUntil() != null) {
            if (attempt.lockedUntil().isAfter(now)) {
                return Verdict.THROTTLED;
            }
            attempts.remove(key, attempt);
            return Verdict.PROCEED;
        }
        if (attempt.failures() >= maxFailures) {
            attempts.put(key, attempt.lockedUntil(now.plus(lockout)));
            return Verdict.THROTTLED;
        }
        return Verdict.PROCEED;
    }

    /** Records a rejected credential. Reaching the threshold starts the lockout clock. */
    public void recordFailure(String key, Instant now) {
        if (key == null) {
            return;
        }
        attempts.compute(key, (ignored, existing) -> existing == null ? Attempt.firstFailure(now)
                : existing.again(now, window));
    }

    /** A good login clears the slate for that caller and account. */
    public void recordSuccess(String key) {
        if (key != null) {
            attempts.remove(key);
        }
    }

    public int maxFailures() {
        return maxFailures;
    }

    public Duration window() {
        return window;
    }

    public Duration lockout() {
        return lockout;
    }

    /** Drops counters nobody has touched recently, so the map cannot grow without bound. */
    private void purgeStale(Instant now) {
        if (!lastPurgeAt.plus(Duration.ofMinutes(1)).isBefore(now)) {
            return;
        }
        lastPurgeAt = now;
        Instant oldestAllowed = now.minus(window).minus(lockout);
        attempts.entrySet().removeIf(entry -> {
            Instant touched = entry.getValue().lockedUntil() != null ? entry.getValue().lockedUntil()
                    : entry.getValue().firstFailureAt();
            return touched == null || touched.isBefore(oldestAllowed);
        });
    }
}
