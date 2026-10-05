package com.employee.portal.security.ratelimit;

import com.employee.portal.security.config.SecurityConfig;

import java.util.Objects;
import java.util.function.LongSupplier;

/**
 * Tracks failed authentication attempts across two independent axes:
 * 1. Source (IP / Client Host)
 * 2. Target Account (Username)
 * 3. Specific Source-Account Pair
 *
 * Implements Rule 3:
 * "Limit repeated attempts per source as well as per account, so an attacker
 * cannot use your own limit to lock a legitimate user out."
 *
 * All operations are bounded (Rule 5) and atomic (Rule 7).
 */
public final class RateLimiter {

    public static final class AttemptRecord {
        private int failureCount;
        private long windowStartTime;
        private long lockedUntil;

        AttemptRecord(long now) {
            this.failureCount = 0;
            this.windowStartTime = now;
            this.lockedUntil = 0;
        }

        public synchronized boolean isLocked(long now) {
            return now < lockedUntil;
        }

        public synchronized long getLockedUntil() {
            return lockedUntil;
        }

        public synchronized int getFailureCount() {
            return failureCount;
        }

        synchronized void recordFailure(long now, long windowMillis, int maxAttempts, long lockoutDurationMillis) {
            if (now < lockedUntil) {
                // Already locked, extend or maintain lockout
                return;
            }
            if (lockedUntil > 0 || (now - windowStartTime > windowMillis)) {
                // Lockout has ended or window has expired: reset window and start fresh
                windowStartTime = now;
                failureCount = 1;
                lockedUntil = 0;
            } else {
                failureCount++;
            }
            if (failureCount >= maxAttempts) {
                lockedUntil = now + lockoutDurationMillis;
            }
        }

        synchronized void reset() {
            failureCount = 0;
            lockedUntil = 0;
        }
    }

    private final BoundedLruCache<String, AttemptRecord> cache;
    private final int maxFailedPerSource;
    private final int maxFailedPerAccount;
    private final long failureWindowMillis;
    private final long lockoutDurationMillis;
    private final LongSupplier clock;

    public RateLimiter(SecurityConfig config) {
        this(config, System::currentTimeMillis);
    }

    public RateLimiter(SecurityConfig config, LongSupplier clock) {
        this.cache = new BoundedLruCache<>(SecurityConfig.MAX_RATE_LIMITER_ENTRIES);
        this.maxFailedPerSource = config.getMaxFailedPerSource();
        this.maxFailedPerAccount = config.getMaxFailedPerAccount();
        this.failureWindowMillis = config.getFailureWindowMillis();
        this.lockoutDurationMillis = config.getLockoutDurationMillis();
        this.clock = Objects.requireNonNull(clock, "clock cannot be null");
    }

    public boolean isSourceRestricted(String sourceIp) {
        if (sourceIp == null) return false;
        AttemptRecord record = cache.get("SRC:" + sourceIp);
        return record != null && record.isLocked(clock.getAsLong());
    }

    public boolean isAccountRestricted(String username) {
        if (username == null) return false;
        AttemptRecord record = cache.get("ACC:" + username);
        return record != null && record.isLocked(clock.getAsLong());
    }

    public boolean isPairRestricted(String sourceIp, String username) {
        if (sourceIp == null || username == null) return false;
        AttemptRecord record = cache.get("PAIR:" + sourceIp + ":" + username);
        return record != null && record.isLocked(clock.getAsLong());
    }

    /**
     * Checks if a login attempt should be restricted.
     * Evaluates source lockout, pair lockout, and global account lockout.
     */
    public boolean isRestricted(String sourceIp, String username) {
        long now = clock.getAsLong();
        if (sourceIp != null) {
            AttemptRecord srcRecord = cache.get("SRC:" + sourceIp);
            if (srcRecord != null && srcRecord.isLocked(now)) {
                return true;
            }
        }
        if (username != null) {
            AttemptRecord accRecord = cache.get("ACC:" + username);
            if (accRecord != null && accRecord.isLocked(now)) {
                return true;
            }
        }
        if (sourceIp != null && username != null) {
            AttemptRecord pairRecord = cache.get("PAIR:" + sourceIp + ":" + username);
            if (pairRecord != null && pairRecord.isLocked(now)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Atomically records a failed authentication attempt across source, account, and pair.
     */
    public void recordFailure(String sourceIp, String username) {
        long now = clock.getAsLong();
        if (sourceIp != null && !sourceIp.isBlank()) {
            cache.compute("SRC:" + sourceIp, (k, existing) -> {
                AttemptRecord rec = (existing != null) ? existing : new AttemptRecord(now);
                rec.recordFailure(now, failureWindowMillis, maxFailedPerSource, lockoutDurationMillis);
                return rec;
            });
        }
        if (username != null && !username.isBlank()) {
            cache.compute("ACC:" + username, (k, existing) -> {
                AttemptRecord rec = (existing != null) ? existing : new AttemptRecord(now);
                rec.recordFailure(now, failureWindowMillis, maxFailedPerAccount, lockoutDurationMillis);
                return rec;
            });
        }
        if (sourceIp != null && !sourceIp.isBlank() && username != null && !username.isBlank()) {
            cache.compute("PAIR:" + sourceIp + ":" + username, (k, existing) -> {
                AttemptRecord rec = (existing != null) ? existing : new AttemptRecord(now);
                rec.recordFailure(now, failureWindowMillis, maxFailedPerSource, lockoutDurationMillis);
                return rec;
            });
        }
    }

    /**
     * Atomically resets failed attempts on successful authentication.
     */
    public void recordSuccess(String sourceIp, String username) {
        if (sourceIp != null) {
            cache.compute("SRC:" + sourceIp, (k, existing) -> {
                if (existing != null) existing.reset();
                return existing;
            });
        }
        if (username != null) {
            cache.compute("ACC:" + username, (k, existing) -> {
                if (existing != null) existing.reset();
                return existing;
            });
        }
        if (sourceIp != null && username != null) {
            cache.compute("PAIR:" + sourceIp + ":" + username, (k, existing) -> {
                if (existing != null) existing.reset();
                return existing;
            });
        }
    }

    public int getSourceFailures(String sourceIp) {
        if (sourceIp == null) return 0;
        AttemptRecord r = cache.get("SRC:" + sourceIp);
        return r != null ? r.getFailureCount() : 0;
    }

    public int getAccountFailures(String username) {
        if (username == null) return 0;
        AttemptRecord r = cache.get("ACC:" + username);
        return r != null ? r.getFailureCount() : 0;
    }

    public void clear() {
        cache.clear();
    }
}
