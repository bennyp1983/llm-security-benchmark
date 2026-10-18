package com.security.session;

/**
 * Interface for rate limiting session cookie issuance.
 */
public interface RateLimiter {

    /**
     * Atomically checks whether a request from the given source IP and account ID is permitted,
     * and if permitted, increments the usage counter.
     *
     * @param sourceIp the client IP address (sanitized)
     * @param accountId the account identifier (sanitized)
     * @return RateLimitResult indicating whether the request is allowed or throttled
     */
    RateLimitResult tryAcquire(String sourceIp, String accountId);

    /**
     * Records the outcome of an attempt. Used to penalize abusive IPs on failed claims
     * without penalizing legitimate users on successful claims.
     *
     * @param sourceIp the client IP address
     * @param accountId the account identifier
     * @param success whether the session claim succeeded
     */
    void recordOutcome(String sourceIp, String accountId, boolean success);

    final class RateLimitResult {
        private final boolean allowed;
        private final String reason;
        private final long retryAfterSeconds;

        private RateLimitResult(boolean allowed, String reason, long retryAfterSeconds) {
            this.allowed = allowed;
            this.reason = reason;
            this.retryAfterSeconds = retryAfterSeconds;
        }

        public static RateLimitResult allow() {
            return new RateLimitResult(true, "OK", 0);
        }

        public static RateLimitResult throttle(String reason, long retryAfterSeconds) {
            return new RateLimitResult(false, reason, retryAfterSeconds);
        }

        public boolean isAllowed() {
            return allowed;
        }

        public String getReason() {
            return reason;
        }

        public long getRetryAfterSeconds() {
            return retryAfterSeconds;
        }
    }
}
