package com.security.session;

import java.time.Clock;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Bounded, thread-safe, dual-keyed rate limiter.
 * Protects against Denial of Service and brute-force attacks while implementing
 * anti-lockout protection so an attacker cannot lock out a legitimate user.
 */
public class DualKeyBoundedRateLimiter implements RateLimiter {

    public static final int DEFAULT_MAX_ENTRIES = 10_000;
    public static final long DEFAULT_WINDOW_SECONDS = 60L;
    public static final int DEFAULT_IP_LIMIT = 20;
    public static final int DEFAULT_IP_ACCOUNT_LIMIT = 10;
    public static final int DEFAULT_GLOBAL_ACCOUNT_LIMIT = 60;
    public static final int DEFAULT_IP_MAX_CONSECUTIVE_FAILURES = 5;

    private final Clock clock;
    private final int maxEntries;
    private final long windowMillis;
    private final int ipLimit;
    private final int ipAccountLimit;
    private final int globalAccountLimit;
    private final int ipMaxConsecutiveFailures;

    // Bounded ConcurrentHashMaps
    private final ConcurrentHashMap<String, WindowCounter> ipBuckets = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, WindowCounter> ipAccountBuckets = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, WindowCounter> accountBuckets = new ConcurrentHashMap<>();

    public DualKeyBoundedRateLimiter() {
        this(Clock.systemUTC(), DEFAULT_MAX_ENTRIES, DEFAULT_WINDOW_SECONDS,
                DEFAULT_IP_LIMIT, DEFAULT_IP_ACCOUNT_LIMIT, DEFAULT_GLOBAL_ACCOUNT_LIMIT,
                DEFAULT_IP_MAX_CONSECUTIVE_FAILURES);
    }

    public DualKeyBoundedRateLimiter(Clock clock, int maxEntries, long windowSeconds,
                                    int ipLimit, int ipAccountLimit, int globalAccountLimit,
                                    int ipMaxConsecutiveFailures) {
        this.clock = clock;
        this.maxEntries = maxEntries;
        this.windowMillis = windowSeconds * 1000L;
        this.ipLimit = ipLimit;
        this.ipAccountLimit = ipAccountLimit;
        this.globalAccountLimit = globalAccountLimit;
        this.ipMaxConsecutiveFailures = ipMaxConsecutiveFailures;
    }

    private static final class WindowCounter {
        long windowStartMs;
        int count;
        int consecutiveFailures;
        long lastAccessMs;

        WindowCounter(long nowMs) {
            this.windowStartMs = nowMs;
            this.count = 0;
            this.consecutiveFailures = 0;
            this.lastAccessMs = nowMs;
        }

        void resetIfExpired(long nowMs, long windowMillis) {
            if (nowMs - windowStartMs >= windowMillis) {
                windowStartMs = nowMs;
                count = 0;
            }
            lastAccessMs = nowMs;
        }
    }

    private static final class EvaluationResult {
        final boolean allowed;
        final String reason;
        final long retryAfterSeconds;

        EvaluationResult(boolean allowed, String reason, long retryAfterSeconds) {
            this.allowed = allowed;
            this.reason = reason;
            this.retryAfterSeconds = retryAfterSeconds;
        }
    }

    @Override
    public RateLimitResult tryAcquire(String sourceIp, String accountId) {
        String cleanIp = sanitizeKey(sourceIp);
        String cleanAccount = sanitizeKey(accountId);
        String ipAccountKey = cleanIp + "|" + cleanAccount;
        long now = clock.millis();

        ensureCapacity();

        // 1. Check IP bucket atomically
        final EvaluationResult[] ipResult = new EvaluationResult[1];
        ipBuckets.compute(cleanIp, (k, counter) -> {
            if (counter == null) {
                counter = new WindowCounter(now);
            }
            counter.resetIfExpired(now, windowMillis);

            if (counter.consecutiveFailures >= ipMaxConsecutiveFailures) {
                long retryAfter = Math.max(1, (windowMillis - (now - counter.windowStartMs)) / 1000);
                ipResult[0] = new EvaluationResult(false, "IP blocked due to excessive failures", retryAfter);
                return counter;
            }

            if (counter.count >= ipLimit) {
                long retryAfter = Math.max(1, (windowMillis - (now - counter.windowStartMs)) / 1000);
                ipResult[0] = new EvaluationResult(false, "IP rate limit exceeded", retryAfter);
                return counter;
            }

            counter.count++;
            ipResult[0] = new EvaluationResult(true, "OK", 0);
            return counter;
        });

        if (!ipResult[0].allowed) {
            return RateLimitResult.throttle(ipResult[0].reason, ipResult[0].retryAfterSeconds);
        }

        // 2. Check (IP + Account) bucket atomically
        final EvaluationResult[] ipAccountResult = new EvaluationResult[1];
        ipAccountBuckets.compute(ipAccountKey, (k, counter) -> {
            if (counter == null) {
                counter = new WindowCounter(now);
            }
            counter.resetIfExpired(now, windowMillis);

            if (counter.count >= ipAccountLimit) {
                long retryAfter = Math.max(1, (windowMillis - (now - counter.windowStartMs)) / 1000);
                ipAccountResult[0] = new EvaluationResult(false, "IP+Account attempt rate exceeded", retryAfter);
                return counter;
            }

            counter.count++;
            ipAccountResult[0] = new EvaluationResult(true, "OK", 0);
            return counter;
        });

        if (!ipAccountResult[0].allowed) {
            return RateLimitResult.throttle(ipAccountResult[0].reason, ipAccountResult[0].retryAfterSeconds);
        }

        // 3. Check Global Account bucket atomically
        final EvaluationResult[] accountResult = new EvaluationResult[1];
        accountBuckets.compute(cleanAccount, (k, counter) -> {
            if (counter == null) {
                counter = new WindowCounter(now);
            }
            counter.resetIfExpired(now, windowMillis);

            if (counter.count >= globalAccountLimit) {
                long retryAfter = Math.max(1, (windowMillis - (now - counter.windowStartMs)) / 1000);
                accountResult[0] = new EvaluationResult(false, "Account global attempt rate exceeded", retryAfter);
                return counter;
            }

            counter.count++;
            accountResult[0] = new EvaluationResult(true, "OK", 0);
            return counter;
        });

        if (!accountResult[0].allowed) {
            return RateLimitResult.throttle(accountResult[0].reason, accountResult[0].retryAfterSeconds);
        }

        return RateLimitResult.allow();
    }

    @Override
    public void recordOutcome(String sourceIp, String accountId, boolean success) {
        String cleanIp = sanitizeKey(sourceIp);
        long now = clock.millis();

        ipBuckets.computeIfPresent(cleanIp, (k, counter) -> {
            counter.lastAccessMs = now;
            if (success) {
                // Legitimate success resets consecutive failure penalty for this IP
                counter.consecutiveFailures = 0;
            } else {
                // Increment failure penalty for the IP
                counter.consecutiveFailures++;
            }
            return counter;
        });
    }

    private void ensureCapacity() {
        if (ipBuckets.size() > maxEntries || ipAccountBuckets.size() > maxEntries || accountBuckets.size() > maxEntries) {
            cleanupExpired();
            evictIfOverCapacity(ipBuckets);
            evictIfOverCapacity(ipAccountBuckets);
            evictIfOverCapacity(accountBuckets);
        }
    }

    private void cleanupExpired() {
        long now = clock.millis();
        purgeExpiredMap(ipBuckets, now);
        purgeExpiredMap(ipAccountBuckets, now);
        purgeExpiredMap(accountBuckets, now);
    }

    private void purgeExpiredMap(ConcurrentHashMap<String, WindowCounter> map, long now) {
        Iterator<Map.Entry<String, WindowCounter>> iterator = map.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, WindowCounter> entry = iterator.next();
            if (now - entry.getValue().lastAccessMs > windowMillis * 2) {
                iterator.remove();
            }
        }
    }

    private void evictIfOverCapacity(ConcurrentHashMap<String, WindowCounter> map) {
        if (map.size() <= maxEntries) {
            return;
        }
        // Remove oldest entries until under threshold
        int toRemove = map.size() - maxEntries;
        Iterator<String> iterator = map.keySet().iterator();
        while (iterator.hasNext() && toRemove > 0) {
            iterator.next();
            iterator.remove();
            toRemove--;
        }
    }

    private String sanitizeKey(String key) {
        if (key == null || key.isBlank()) {
            return "unknown";
        }
        // Limit key length to prevent memory exhaustion
        if (key.length() > 128) {
            return key.substring(0, 128);
        }
        return key.trim();
    }

    public int getIpBucketCount() {
        return ipBuckets.size();
    }

    public int getAccountBucketCount() {
        return accountBuckets.size();
    }
}
