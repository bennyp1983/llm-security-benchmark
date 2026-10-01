package com.security.auth.ratelimit;

/**
 * Interface for rate limiting authentication attempts (Rule 3 & Rule 7).
 * Defends against brute force, credential stuffing, and account lockout denial-of-service.
 * Enforces atomic "count, then allow" semantics to prevent race conditions.
 */
public interface RateLimiter {

    /**
     * Atomically counts and authorizes an authentication attempt (Rule 7: count, then allow).
     * If within limits, the attempt is atomically registered and ALLOWED is returned.
     * If limits are exceeded, the attempt is rejected without updating attempt counters.
     *
     * @param clientIp client IP address
     * @param username client username
     * @return RateLimitStatus indicating ALLOWED or specific throttling reason
     */
    RateLimitStatus acquireAttempt(String clientIp, String username);

    /**
     * Checks current rate limit status without registering an attempt.
     *
     * @param clientIp client IP address
     * @param username client username
     * @return RateLimitStatus
     */
    RateLimitStatus checkRateLimit(String clientIp, String username);

    /**
     * Atomically records an explicit authentication failure.
     *
     * @param clientIp client IP address
     * @param username client username
     */
    void recordFailure(String clientIp, String username);

    /**
     * Atomically records an authentication success, resetting failed attempt counters
     * for the specific (source IP, account) pair (Rule 3).
     *
     * @param clientIp client IP address
     * @param username client username
     */
    void recordSuccess(String clientIp, String username);

    /**
     * Represents the rate limit evaluation outcome.
     */
    enum RateLimitStatus {
        ALLOWED,
        SOURCE_RATE_LIMITED,
        ACCOUNT_RATE_LIMITED
    }
}
