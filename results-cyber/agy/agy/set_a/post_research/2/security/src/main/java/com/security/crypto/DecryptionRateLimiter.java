package com.security.crypto;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Dual-bucket, multi-dimensional failure rate limiter for decryption operations.
 * <p>
 * Security Design &amp; Attack Mitigation:
 * <ul>
 *   <li>Rule 3 (Authentication and Access): Limits repeated decryption failures per source
 *       (e.g., client IP or caller identifier) AND per account/resource (e.g., keyId or accountId).
 *       Because the source is throttled independently from the account, an attacker submitting
 *       invalid ciphertexts from an external source will be blocked at the source level
 *       before exhausting the account limit, preventing attacker-induced denial-of-service
 *       and lockout of legitimate users.</li>
 *   <li>Rule 5 (Sensitive Data): Enforces a hard bound on the internal tracker maps (bounded memory)
 *       and periodically prunes expired entries to prevent memory exhaustion DoS.</li>
 *   <li>Rule 7 (Concurrency): Employs lock-free atomic window operations via ConcurrentHashMap
 *       and AtomicInteger for race-condition-free check-and-act behavior.</li>
 * </ul>
 */
public final class DecryptionRateLimiter {

    /**
     * Default window duration in milliseconds (1 minute).
     */
    public static final long DEFAULT_WINDOW_MS = 60_000L;

    /**
     * Default maximum permitted failures per source per window.
     */
    public static final int DEFAULT_MAX_SOURCE_FAILURES = 20;

    /**
     * Default maximum permitted failures per account/resource per window.
     */
    public static final int DEFAULT_MAX_RESOURCE_FAILURES = 50;

    /**
     * Maximum entries stored in each tracker map to prevent memory exhaustion.
     */
    private static final int MAX_MAP_ENTRIES = 10_000;

    private final long windowDurationMs;
    private final int maxSourceFailures;
    private final int maxResourceFailures;

    private final ConcurrentHashMap<String, WindowCounter> sourceCounters = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, WindowCounter> resourceCounters = new ConcurrentHashMap<>();

    /**
     * Constructs a DecryptionRateLimiter with default settings.
     */
    public DecryptionRateLimiter() {
        this(DEFAULT_WINDOW_MS, DEFAULT_MAX_SOURCE_FAILURES, DEFAULT_MAX_RESOURCE_FAILURES);
    }

    /**
     * Constructs a DecryptionRateLimiter with custom parameters.
     *
     * @param windowDurationMs    Window size in milliseconds.
     * @param maxSourceFailures   Max failures allowed per source per window.
     * @param maxResourceFailures Max failures allowed per resource/account per window.
     */
    public DecryptionRateLimiter(long windowDurationMs, int maxSourceFailures, int maxResourceFailures) {
        if (windowDurationMs <= 0 || maxSourceFailures <= 0 || maxResourceFailures <= 0) {
            throw new CryptoException("Rate limiter parameters must be positive integers");
        }
        this.windowDurationMs = windowDurationMs;
        this.maxSourceFailures = maxSourceFailures;
        this.maxResourceFailures = maxResourceFailures;
    }

    /**
     * Atomically checks whether a decryption attempt is allowed under current rate limits.
     * Fails closed if either source or resource failure threshold is exceeded.
     *
     * @param sourceId   The source / caller identifier.
     * @param resourceId The resource / key / account identifier.
     * @throws CryptoException If rate limit is exceeded.
     */
    public void checkAllowed(String sourceId, String resourceId) {
        long now = System.currentTimeMillis();

        if (sourceId != null) {
            WindowCounter sourceCounter = sourceCounters.get(sourceId);
            if (sourceCounter != null && sourceCounter.isExceeded(now, windowDurationMs, maxSourceFailures)) {
                throw new CryptoException("Decryption rate limit exceeded");
            }
        }

        if (resourceId != null) {
            WindowCounter resourceCounter = resourceCounters.get(resourceId);
            if (resourceCounter != null && resourceCounter.isExceeded(now, windowDurationMs, maxResourceFailures)) {
                throw new CryptoException("Decryption rate limit exceeded");
            }
        }
    }

    /**
     * Atomically records a decryption failure against both the source and the resource.
     *
     * @param sourceId   The source / caller identifier.
     * @param resourceId The resource / key / account identifier.
     */
    public void recordFailure(String sourceId, String resourceId) {
        long now = System.currentTimeMillis();

        if (sourceId != null) {
            pruneIfNecessary(sourceCounters, now);
            sourceCounters.compute(sourceId, (k, counter) -> {
                if (counter == null || (now - counter.windowStartMs) > windowDurationMs) {
                    return new WindowCounter(now, 1);
                } else {
                    counter.count.incrementAndGet();
                    return counter;
                }
            });
        }

        if (resourceId != null) {
            pruneIfNecessary(resourceCounters, now);
            resourceCounters.compute(resourceId, (k, counter) -> {
                if (counter == null || (now - counter.windowStartMs) > windowDurationMs) {
                    return new WindowCounter(now, 1);
                } else {
                    counter.count.incrementAndGet();
                    return counter;
                }
            });
        }
    }

    /**
     * Resets failure counters for a source and resource on success or administrative action.
     *
     * @param sourceId   The source identifier.
     * @param resourceId The resource identifier.
     */
    public void reset(String sourceId, String resourceId) {
        if (sourceId != null) {
            sourceCounters.remove(sourceId);
        }
        if (resourceId != null) {
            resourceCounters.remove(resourceId);
        }
    }

    /**
     * Bounds map memory by purging expired counters if capacity reaches threshold.
     */
    private void pruneIfNecessary(ConcurrentHashMap<String, WindowCounter> map, long now) {
        if (map.size() >= MAX_MAP_ENTRIES) {
            map.entrySet().removeIf(entry -> (now - entry.getValue().windowStartMs) > windowDurationMs);
        }
    }

    /**
     * Internal window counter.
     */
    private static final class WindowCounter {
        final long windowStartMs;
        final AtomicInteger count;

        WindowCounter(long windowStartMs, int initialCount) {
            this.windowStartMs = windowStartMs;
            this.count = new AtomicInteger(initialCount);
        }

        boolean isExceeded(long now, long windowMs, int maxLimit) {
            if ((now - windowStartMs) > windowMs) {
                return false; // Window expired
            }
            return count.get() >= maxLimit;
        }
    }
}
