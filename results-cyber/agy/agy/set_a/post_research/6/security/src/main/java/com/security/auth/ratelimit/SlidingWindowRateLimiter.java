package com.security.auth.ratelimit;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Sliding-window rate limiter defending against brute-force and lockout DoS (Rules 3, 5, 7).
 * Atomically checks and records attempts (count, then allow) across:
 * 1. Source IP: prevents single-source credential stuffing and brute force.
 * 2. Source IP + Account pair: prevents targeted attacks without locking legitimate users on other IPs out.
 * 3. Global Account: protects accounts against distributed botnet brute force.
 */
public final class SlidingWindowRateLimiter implements RateLimiter {

    public static final int DEFAULT_MAX_SOURCE_ATTEMPTS = 10;
    public static final int DEFAULT_MAX_SOURCE_ACCOUNT_ATTEMPTS = 5;
    public static final int DEFAULT_MAX_GLOBAL_ACCOUNT_ATTEMPTS = 25;
    public static final Duration DEFAULT_WINDOW_DURATION = Duration.ofMinutes(15);
    public static final int DEFAULT_MAX_CACHE_ENTRIES = 10_000;

    private final int maxSourceAttempts;
    private final int maxSourceAccountAttempts;
    private final int maxGlobalAccountAttempts;
    private final Duration windowDuration;
    private final int maxCacheEntries;
    private final Clock clock;

    private final ConcurrentHashMap<String, WindowTracker> trackerMap;
    private final AtomicInteger cleanupCounter = new AtomicInteger(0);

    public SlidingWindowRateLimiter() {
        this(DEFAULT_MAX_SOURCE_ATTEMPTS,
                DEFAULT_MAX_SOURCE_ACCOUNT_ATTEMPTS,
                DEFAULT_MAX_GLOBAL_ACCOUNT_ATTEMPTS,
                DEFAULT_WINDOW_DURATION,
                DEFAULT_MAX_CACHE_ENTRIES,
                Clock.systemUTC());
    }

    public SlidingWindowRateLimiter(int maxSourceAttempts,
                                   int maxSourceAccountAttempts,
                                   int maxGlobalAccountAttempts,
                                   Duration windowDuration,
                                   int maxCacheEntries,
                                   Clock clock) {
        if (maxSourceAttempts <= 0 || maxSourceAccountAttempts <= 0 || maxGlobalAccountAttempts <= 0) {
            throw new IllegalArgumentException("Attempt thresholds must be positive.");
        }
        if (maxCacheEntries <= 0) {
            throw new IllegalArgumentException("Max cache entries must be positive.");
        }
        this.maxSourceAttempts = maxSourceAttempts;
        this.maxSourceAccountAttempts = maxSourceAccountAttempts;
        this.maxGlobalAccountAttempts = maxGlobalAccountAttempts;
        this.windowDuration = Objects.requireNonNull(windowDuration, "Window duration cannot be null.");
        this.maxCacheEntries = maxCacheEntries;
        this.clock = Objects.requireNonNull(clock, "Clock cannot be null.");
        this.trackerMap = new ConcurrentHashMap<>(256);
    }

    @Override
    public synchronized RateLimitStatus acquireAttempt(String clientIp, String username) {
        long now = clock.millis();
        long windowMillis = windowDuration.toMillis();

        maybePruneExpiredEntries(now, windowMillis);

        String sourceKey = (clientIp != null) ? "SRC:" + clientIp : null;
        String sourceAccKey = (clientIp != null && username != null) ? "SRC_ACC:" + clientIp + ":" + username : null;
        String accKey = (username != null) ? "ACC:" + username : null;

        // 1. Check if source IP limit is exceeded
        if (sourceKey != null) {
            WindowTracker tracker = trackerMap.get(sourceKey);
            if (tracker != null && tracker.isBlocked(now, windowMillis, maxSourceAttempts)) {
                return RateLimitStatus.SOURCE_RATE_LIMITED;
            }
        }

        // 2. Check if (source IP, account) limit is exceeded
        if (sourceAccKey != null) {
            WindowTracker tracker = trackerMap.get(sourceAccKey);
            if (tracker != null && tracker.isBlocked(now, windowMillis, maxSourceAccountAttempts)) {
                return RateLimitStatus.SOURCE_RATE_LIMITED;
            }
        }

        // 3. Check if global account limit is exceeded
        if (accKey != null) {
            WindowTracker tracker = trackerMap.get(accKey);
            if (tracker != null && tracker.isBlocked(now, windowMillis, maxGlobalAccountAttempts)) {
                return RateLimitStatus.ACCOUNT_RATE_LIMITED;
            }
        }

        // If all checks pass, ATOMICALLY register this attempt across all trackers (count, then allow - Rule 7)
        if (sourceKey != null) {
            trackerMap.computeIfAbsent(sourceKey, k -> new WindowTracker()).addAttempt(now, windowMillis);
        }
        if (sourceAccKey != null) {
            trackerMap.computeIfAbsent(sourceAccKey, k -> new WindowTracker()).addAttempt(now, windowMillis);
        }
        if (accKey != null) {
            trackerMap.computeIfAbsent(accKey, k -> new WindowTracker()).addAttempt(now, windowMillis);
        }

        return RateLimitStatus.ALLOWED;
    }

    @Override
    public synchronized RateLimitStatus checkRateLimit(String clientIp, String username) {
        long now = clock.millis();
        long windowMillis = windowDuration.toMillis();

        if (clientIp != null) {
            WindowTracker tracker = trackerMap.get("SRC:" + clientIp);
            if (tracker != null && tracker.isBlocked(now, windowMillis, maxSourceAttempts)) {
                return RateLimitStatus.SOURCE_RATE_LIMITED;
            }
        }

        if (clientIp != null && username != null) {
            WindowTracker tracker = trackerMap.get("SRC_ACC:" + clientIp + ":" + username);
            if (tracker != null && tracker.isBlocked(now, windowMillis, maxSourceAccountAttempts)) {
                return RateLimitStatus.SOURCE_RATE_LIMITED;
            }
        }

        if (username != null) {
            WindowTracker tracker = trackerMap.get("ACC:" + username);
            if (tracker != null && tracker.isBlocked(now, windowMillis, maxGlobalAccountAttempts)) {
                return RateLimitStatus.ACCOUNT_RATE_LIMITED;
            }
        }

        return RateLimitStatus.ALLOWED;
    }

    @Override
    public synchronized void recordFailure(String clientIp, String username) {
        long now = clock.millis();
        long windowMillis = windowDuration.toMillis();

        maybePruneExpiredEntries(now, windowMillis);

        if (clientIp != null) {
            trackerMap.computeIfAbsent("SRC:" + clientIp, k -> new WindowTracker()).addAttempt(now, windowMillis);
        }
        if (clientIp != null && username != null) {
            trackerMap.computeIfAbsent("SRC_ACC:" + clientIp + ":" + username, k -> new WindowTracker()).addAttempt(now, windowMillis);
        }
        if (username != null) {
            trackerMap.computeIfAbsent("ACC:" + username, k -> new WindowTracker()).addAttempt(now, windowMillis);
        }
    }

    @Override
    public synchronized void recordSuccess(String clientIp, String username) {
        long now = clock.millis();
        long windowMillis = windowDuration.toMillis();

        // Clear failures specifically for this source IP + account on success (Rule 3)
        if (clientIp != null && username != null) {
            trackerMap.remove("SRC_ACC:" + clientIp + ":" + username);
        }
        // Remove the successful attempt from source and account counters so successful login doesn't penalize user
        if (clientIp != null) {
            WindowTracker sourceTracker = trackerMap.get("SRC:" + clientIp);
            if (sourceTracker != null) {
                sourceTracker.removeLatest(now, windowMillis);
            }
        }
        if (username != null) {
            WindowTracker accTracker = trackerMap.get("ACC:" + username);
            if (accTracker != null) {
                accTracker.removeLatest(now, windowMillis);
            }
        }
    }

    /**
     * Bounded storage cleanup (Rule 5): prunes expired tracking windows to prevent memory exhaustion.
     */
    private void maybePruneExpiredEntries(long now, long windowMillis) {
        if (cleanupCounter.incrementAndGet() % 100 == 0 || trackerMap.size() >= maxCacheEntries) {
            Iterator<Map.Entry<String, WindowTracker>> iterator = trackerMap.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<String, WindowTracker> entry = iterator.next();
                if (entry.getValue().isExpired(now, windowMillis)) {
                    iterator.remove();
                }
            }
            if (trackerMap.size() >= maxCacheEntries) {
                trackerMap.clear();
            }
        }
    }

    /**
     * Thread-safe, bounded timestamp tracker for sliding windows (Rule 7).
     */
    private static final class WindowTracker {
        private final ArrayDeque<Long> timestamps = new ArrayDeque<>();

        public synchronized boolean isBlocked(long now, long windowMillis, int threshold) {
            prune(now, windowMillis);
            return timestamps.size() >= threshold;
        }

        public synchronized void addAttempt(long now, long windowMillis) {
            prune(now, windowMillis);
            timestamps.addLast(now);
        }

        public synchronized void removeLatest(long now, long windowMillis) {
            prune(now, windowMillis);
            if (!timestamps.isEmpty()) {
                timestamps.pollLast();
            }
        }

        public synchronized boolean isExpired(long now, long windowMillis) {
            prune(now, windowMillis);
            return timestamps.isEmpty();
        }

        private void prune(long now, long windowMillis) {
            long cutoff = now - windowMillis;
            while (!timestamps.isEmpty() && timestamps.peekFirst() < cutoff) {
                timestamps.pollFirst();
            }
        }
    }
}
