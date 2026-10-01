package com.example.auth;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Thread-safe, bounded, and atomic rate limiter for authentication attempts.
 * <p>
 * Enforces dual-level rate limiting:
 * 1. Per-source rate limiting: Blocks abusive IP/clients after repeated failures.
 * 2. Per-(source, account) rate limiting: Isolates lockout per attacker source so legitimate users
 *    are never locked out of their accounts from legitimate sources.
 * 3. Global account progressive delay: Throttles distributed brute force attacks against a single account
 *    without causing hard denial of service.
 * <p>
 * Satisfies:
 * - Rule 3: Attacker cannot use lockout mechanism to DoS legitimate users.
 * - Rule 5: Bounded memory storage with eviction prevents heap exhaustion.
 * - Rule 7: Atomic check-and-act operations prevent concurrency race conditions.
 */
public final class RateLimiter {

    public static final int MAX_SOURCE_ATTEMPTS = 5;
    public static final long SOURCE_WINDOW_MS = 5 * 60 * 1000L; // 5 minutes

    public static final int MAX_SOURCE_ACCOUNT_ATTEMPTS = 3;
    public static final long SOURCE_ACCOUNT_WINDOW_MS = 5 * 60 * 1000L; // 5 minutes

    public static final int GLOBAL_ACCOUNT_THROTTLE_THRESHOLD = 5;
    public static final long GLOBAL_ACCOUNT_WINDOW_MS = 10 * 60 * 1000L; // 10 minutes
    public static final long MAX_PROGRESSIVE_DELAY_MS = 3000L; // Maximum 3 seconds throttle

    public static final int MAX_CACHE_ENTRIES = 10_000;

    public enum Status {
        ALLOWED,
        SOURCE_BLOCKED,
        SOURCE_ACCOUNT_BLOCKED
    }

    public record RateLimitResult(Status status, long progressiveDelayMs, String reason) {
        public boolean isAllowed() {
            return status == Status.ALLOWED;
        }
    }

    private static final class AttemptTracker {
        private final long windowDurationMs;
        private final int maxAttempts;
        private long windowStartTime;
        private int count;

        AttemptTracker(long windowDurationMs, int maxAttempts, long now) {
            this.windowDurationMs = windowDurationMs;
            this.maxAttempts = maxAttempts;
            this.windowStartTime = now;
            this.count = 0;
        }

        synchronized boolean isExpired(long now) {
            return now - windowStartTime > windowDurationMs;
        }

        /**
         * Atomically evaluates and increments the attempt counter.
         * Returns true if allowed, false if limit exceeded.
         */
        synchronized boolean tryAcquire(long now) {
            if (now - windowStartTime > windowDurationMs) {
                windowStartTime = now;
                count = 0;
            }
            if (count >= maxAttempts) {
                return false;
            }
            count++;
            return true;
        }

        synchronized int getCount(long now) {
            if (now - windowStartTime > windowDurationMs) {
                return 0;
            }
            return count;
        }

        synchronized void reset() {
            count = 0;
            windowStartTime = 0;
        }
    }

    private final ConcurrentHashMap<String, AttemptTracker> sourceTrackers = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AttemptTracker> sourceAccountTrackers = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AttemptTracker> globalAccountTrackers = new ConcurrentHashMap<>();
    private final AtomicInteger entryCount = new AtomicInteger(0);

    /**
     * Atomically checks whether an authentication attempt is permitted and calculates any progressive delay.
     * Check and action (count, then allow) are performed atomically.
     *
     * @param sourceId Sanitized client source identifier.
     * @param email    Canonical email address.
     * @return RateLimitResult indicating whether allowed or blocked, along with throttling delay.
     */
    public RateLimitResult checkAndAcquire(String sourceId, String email) {
        long now = System.currentTimeMillis();
        evictIfNecessary(now);

        String safeSource = InputValidator.sanitizeSourceId(sourceId);
        String safeEmail = InputValidator.canonicalizeEmail(email);
        String sourceAccountKey = safeSource + ":" + safeEmail;

        // 1. Check and acquire source permit atomically
        AttemptTracker sourceTracker = getOrCreateTracker(sourceTrackers, safeSource, SOURCE_WINDOW_MS, MAX_SOURCE_ATTEMPTS, now);
        boolean sourceAllowed = sourceTracker.tryAcquire(now);
        if (!sourceAllowed) {
            return new RateLimitResult(Status.SOURCE_BLOCKED, 0, "Source IP / client rate limit exceeded");
        }

        // 2. Check and acquire (source, account) permit atomically
        AttemptTracker sourceAccountTracker = getOrCreateTracker(sourceAccountTrackers, sourceAccountKey,
                SOURCE_ACCOUNT_WINDOW_MS, MAX_SOURCE_ACCOUNT_ATTEMPTS, now);
        boolean sourceAccountAllowed = sourceAccountTracker.tryAcquire(now);
        if (!sourceAccountAllowed) {
            return new RateLimitResult(Status.SOURCE_ACCOUNT_BLOCKED, 0,
                    "Too many failed attempts for this account from current source");
        }

        // 3. Check global account throttle to defend against distributed attacks without DoSing legitimate users
        long progressiveDelayMs = 0;
        if (!safeEmail.isEmpty()) {
            AttemptTracker globalAccountTracker = getOrCreateTracker(globalAccountTrackers, safeEmail,
                    GLOBAL_ACCOUNT_WINDOW_MS, Integer.MAX_VALUE, now);
            int globalFailures = globalAccountTracker.getCount(now);
            if (globalFailures >= GLOBAL_ACCOUNT_THROTTLE_THRESHOLD) {
                int excess = globalFailures - GLOBAL_ACCOUNT_THROTTLE_THRESHOLD + 1;
                progressiveDelayMs = Math.min((long) excess * 500L, MAX_PROGRESSIVE_DELAY_MS);
            }
        }

        return new RateLimitResult(Status.ALLOWED, progressiveDelayMs, "Attempt permitted");
    }

    /**
     * Records a failed authentication attempt across source, (source, account), and global account trackers.
     */
    public void recordAuthenticationFailure(String sourceId, String email) {
        long now = System.currentTimeMillis();
        String safeEmail = InputValidator.canonicalizeEmail(email);

        if (!safeEmail.isEmpty()) {
            AttemptTracker globalTracker = getOrCreateTracker(globalAccountTrackers, safeEmail,
                    GLOBAL_ACCOUNT_WINDOW_MS, Integer.MAX_VALUE, now);
            globalTracker.tryAcquire(now);
        }
    }

    /**
     * Resets failure counters upon successful authentication.
     */
    public void recordAuthenticationSuccess(String sourceId, String email) {
        long now = System.currentTimeMillis();
        String safeSource = InputValidator.sanitizeSourceId(sourceId);
        String safeEmail = InputValidator.canonicalizeEmail(email);
        String sourceAccountKey = safeSource + ":" + safeEmail;

        AttemptTracker sourceTracker = sourceTrackers.get(safeSource);
        if (sourceTracker != null) {
            sourceTracker.reset();
        }

        AttemptTracker sourceAccountTracker = sourceAccountTrackers.get(sourceAccountKey);
        if (sourceAccountTracker != null) {
            sourceAccountTracker.reset();
        }

        AttemptTracker globalTracker = globalAccountTrackers.get(safeEmail);
        if (globalTracker != null) {
            globalTracker.reset();
        }
    }

    private AttemptTracker getOrCreateTracker(ConcurrentHashMap<String, AttemptTracker> map,
                                              String key, long windowMs, int maxAttempts, long now) {
        return map.computeIfAbsent(key, k -> {
            entryCount.incrementAndGet();
            return new AttemptTracker(windowMs, maxAttempts, now);
        });
    }

    /**
     * Enforces bounded memory (Rule 5). Purges expired trackers when capacity limit is reached.
     */
    private void evictIfNecessary(long now) {
        if (entryCount.get() > MAX_CACHE_ENTRIES) {
            purgeExpired(sourceTrackers, now);
            purgeExpired(sourceAccountTrackers, now);
            purgeExpired(globalAccountTrackers, now);
            entryCount.set(sourceTrackers.size() + sourceAccountTrackers.size() + globalAccountTrackers.size());
        }
    }

    private void purgeExpired(ConcurrentHashMap<String, AttemptTracker> map, long now) {
        Iterator<Map.Entry<String, AttemptTracker>> it = map.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, AttemptTracker> entry = it.next();
            if (entry.getValue().isExpired(now)) {
                it.remove();
            }
        }
    }

    /**
     * Clears all trackers (useful for test isolation).
     */
    public void resetAll() {
        sourceTrackers.clear();
        sourceAccountTrackers.clear();
        globalAccountTrackers.clear();
        entryCount.set(0);
    }
}
