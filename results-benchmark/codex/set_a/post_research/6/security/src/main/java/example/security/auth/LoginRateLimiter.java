package example.security.auth;

import java.time.Instant;

/** Atomic limiter contract. Keys are keyed hashes, never raw account/source identifiers. */
public interface LoginRateLimiter {
    /** Atomically registers and classifies one attempt before credential verification. */
    Decision registerAttempt(String sourceKey, String accountKey, Instant now);
    void recordSuccess(String sourceKey, String accountKey);

    enum Decision { ALLOW, THROTTLED }
}
