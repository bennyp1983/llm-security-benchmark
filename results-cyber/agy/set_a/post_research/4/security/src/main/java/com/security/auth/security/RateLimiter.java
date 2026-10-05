package com.security.auth.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

/**
 * High-concurrency, dual-dimensional rate limiter.
 * Protects against brute-force attacks while preventing Account Lockout Denial-of-Service attacks.
 *
 * Implements Rule 3:
 * "Limit repeated attempts per source as well as per account, so an attacker cannot use your own limit to lock a legitimate user out."
 *
 * Implements Rule 7:
 * "Where you check state and then act on it (verify, then grant; count, then allow), make the check and the action atomic."
 */
public final class RateLimiter {

    private static final Logger log = LoggerFactory.getLogger(RateLimiter.class);

    // Source-level limits (blocks attacker IP)
    public static final int MAX_SOURCE_FAILURES = 5;
    public static final Duration SOURCE_WINDOW = Duration.ofMinutes(5);
    public static final Duration SOURCE_BLOCK_DURATION = Duration.ofMinutes(15);

    // Account-level limits: Progressive throttling rather than hard account denial
    public static final int ACCOUNT_THROTTLE_THRESHOLD = 5;
    public static final Duration ACCOUNT_WINDOW = Duration.ofMinutes(10);
    public static final long BASE_PROGRESSIVE_DELAY_MS = 1000; // 1 second base delay
    public static final long MAX_PROGRESSIVE_DELAY_MS = 5000;  // 5 seconds max delay

    private record AttemptTracker(int failureCount, Instant windowStart, Instant blockedUntil) {
        boolean isBlocked(Instant now) {
            return blockedUntil != null && now.isBefore(blockedUntil);
        }

        boolean isWindowExpired(Instant now, Duration window) {
            return windowStart != null && Duration.between(windowStart, now).compareTo(window) > 0;
        }
    }

    // Source IP -> Tracker
    private final ConcurrentHashMap<String, AttemptTracker> sourceTrackers = new ConcurrentHashMap<>();
    // Account Identifier -> Tracker
    private final ConcurrentHashMap<String, AttemptTracker> accountTrackers = new ConcurrentHashMap<>();

    /**
     * Atomically checks whether a login attempt is permitted based on source and account state.
     *
     * @param sourceIp client source IP
     * @param accountIdentifier account username or email
     * @return CheckResult detailing whether attempt is permitted and any required delay
     */
    public CheckResult checkAllowed(String sourceIp, String accountIdentifier) {
        Instant now = Instant.now();

        // 1. Check Source IP: If source is blocked, reject immediately.
        AttemptTracker sourceTracker = sourceTrackers.get(sourceIp);
        if (sourceTracker != null && sourceTracker.isBlocked(now)) {
            log.warn("Blocked request from source IP due to rate limit: source={}", sourceIp);
            return new CheckResult(false, 0, "Too many failed attempts from this source. Please try again later.");
        }

        // 2. Check Account: Calculate progressive delay without denying legitimate user access.
        // This ensures an attacker spraying bad passwords from various IPs cannot lock the legitimate user out.
        AttemptTracker accountTracker = accountTrackers.get(accountIdentifier.toLowerCase());
        long delayMs = 0;
        if (accountTracker != null && !accountTracker.isWindowExpired(now, ACCOUNT_WINDOW)) {
            if (accountTracker.failureCount() >= ACCOUNT_THROTTLE_THRESHOLD) {
                // Progressive backoff: base * 2^(excess failures), capped at max delay
                int excess = accountTracker.failureCount() - ACCOUNT_THROTTLE_THRESHOLD;
                delayMs = Math.min(MAX_PROGRESSIVE_DELAY_MS, BASE_PROGRESSIVE_DELAY_MS * (1L << Math.min(excess, 3)));
                log.info("Applying progressive delay for account experiencing repeated failures: delayMs={}", delayMs);
            }
        }

        return new CheckResult(true, delayMs, null);
    }

    /**
     * Atomically records a failed authentication attempt for both the source IP and the target account.
     *
     * @param sourceIp client source IP
     * @param accountIdentifier target account identifier
     */
    public void recordFailure(String sourceIp, String accountIdentifier) {
        Instant now = Instant.now();

        // Atomically update Source IP failures
        sourceTrackers.compute(sourceIp, (key, current) -> {
            if (current == null || current.isWindowExpired(now, SOURCE_WINDOW)) {
                return new AttemptTracker(1, now, null);
            }
            int newCount = current.failureCount() + 1;
            Instant blockedUntil = null;
            if (newCount >= MAX_SOURCE_FAILURES) {
                blockedUntil = now.plus(SOURCE_BLOCK_DURATION);
                log.warn("Source IP exceeded failure limit and is blocked: source={}, blockedUntil={}", key, blockedUntil);
            }
            return new AttemptTracker(newCount, current.windowStart(), blockedUntil);
        });

        // Atomically update Account failures
        accountTrackers.compute(accountIdentifier.toLowerCase(), (key, current) -> {
            if (current == null || current.isWindowExpired(now, ACCOUNT_WINDOW)) {
                return new AttemptTracker(1, now, null);
            }
            return new AttemptTracker(current.failureCount() + 1, current.windowStart(), null);
        });

        // Maintenance cleanup to prevent unbounded memory consumption
        cleanupStaleEntries(now);
    }

    /**
     * Atomically clears failure counters on successful authentication.
     *
     * @param sourceIp client source IP
     * @param accountIdentifier target account identifier
     */
    public void recordSuccess(String sourceIp, String accountIdentifier) {
        sourceTrackers.remove(sourceIp);
        accountTrackers.remove(accountIdentifier.toLowerCase());
    }

    public static final int MAX_TRACKER_ENTRIES = 10_000;

    /**
     * Cleans up expired trackers to bound memory usage (Rule 5).
     * If the map exceeds MAX_TRACKER_ENTRIES, forcefully purges oldest entries.
     */
    private void cleanupStaleEntries(Instant now) {
        if (sourceTrackers.size() > 500) {
            sourceTrackers.entrySet().removeIf(entry ->
                    !entry.getValue().isBlocked(now) && entry.getValue().isWindowExpired(now, SOURCE_WINDOW));
        }
        if (sourceTrackers.size() > MAX_TRACKER_ENTRIES) {
            // Evict oldest entries to prevent memory exhaustion
            sourceTrackers.entrySet().stream()
                    .sorted((e1, e2) -> e1.getValue().windowStart().compareTo(e2.getValue().windowStart()))
                    .limit(sourceTrackers.size() - MAX_TRACKER_ENTRIES + 100)
                    .forEach(e -> sourceTrackers.remove(e.getKey()));
        }

        if (accountTrackers.size() > 500) {
            accountTrackers.entrySet().removeIf(entry ->
                    entry.getValue().isWindowExpired(now, ACCOUNT_WINDOW));
        }
        if (accountTrackers.size() > MAX_TRACKER_ENTRIES) {
            accountTrackers.entrySet().stream()
                    .sorted((e1, e2) -> e1.getValue().windowStart().compareTo(e2.getValue().windowStart()))
                    .limit(accountTrackers.size() - MAX_TRACKER_ENTRIES + 100)
                    .forEach(e -> accountTrackers.remove(e.getKey()));
        }
    }

    public record CheckResult(boolean allowed, long delayMs, String reason) {
    }
}
