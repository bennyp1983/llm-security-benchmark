package com.security.auth.ratelimit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("RateLimiter Anti-Brute-Force & Lockout DoS Defense Tests (Rule 3 & Rule 7)")
class RateLimiterTest {

    @Test
    @DisplayName("Should block source IP after exceeding max source attempts")
    void testSourceRateLimiting() {
        SlidingWindowRateLimiter limiter = new SlidingWindowRateLimiter(
                3, // maxSourceAttempts = 3
                5, // maxSourceAccountAttempts
                10, // maxGlobalAccountAttempts
                Duration.ofMinutes(15),
                1000,
                Clock.systemUTC()
        );

        String ip = "192.168.1.100";
        assertEquals(RateLimiter.RateLimitStatus.ALLOWED, limiter.checkRateLimit(ip, "user1"));

        limiter.recordFailure(ip, "user1");
        limiter.recordFailure(ip, "user2");
        limiter.recordFailure(ip, "user3");

        // 4th attempt from same IP should be blocked
        assertEquals(RateLimiter.RateLimitStatus.SOURCE_RATE_LIMITED, limiter.checkRateLimit(ip, "user4"));
    }

    @Test
    @DisplayName("Account Lockout DoS Defense: Attacker failing repeatedly must NOT lock out legitimate user on different IP (Rule 3)")
    void testAccountLockoutDosDefense() {
        SlidingWindowRateLimiter limiter = new SlidingWindowRateLimiter(
                10, // maxSourceAttempts
                3,  // maxSourceAccountAttempts = 3 per IP for specific account
                20, // maxGlobalAccountAttempts = 20
                Duration.ofMinutes(15),
                1000,
                Clock.systemUTC()
        );

        String attackerIp = "198.51.100.10";
        String legitimateUserIp = "203.0.113.50";
        String targetAccount = "alice";

        // Attacker attempts 3 failed logins against 'alice'
        limiter.recordFailure(attackerIp, targetAccount);
        limiter.recordFailure(attackerIp, targetAccount);
        limiter.recordFailure(attackerIp, targetAccount);

        // Attacker is now blocked from targeting alice
        assertEquals(RateLimiter.RateLimitStatus.SOURCE_RATE_LIMITED, limiter.checkRateLimit(attackerIp, targetAccount));

        // CRITICAL CHECK: Legitimate user connecting from another IP is NOT locked out!
        assertEquals(RateLimiter.RateLimitStatus.ALLOWED, limiter.checkRateLimit(legitimateUserIp, targetAccount));
    }

    @Test
    @DisplayName("Should block account globally when massive distributed attack hits global limit")
    void testGlobalAccountRateLimiting() {
        SlidingWindowRateLimiter limiter = new SlidingWindowRateLimiter(
                10, // maxSourceAttempts
                5,  // maxSourceAccountAttempts
                4,  // maxGlobalAccountAttempts = 4
                Duration.ofMinutes(15),
                1000,
                Clock.systemUTC()
        );

        String targetUser = "victim_admin";

        // 4 different IPs fail once each on victim_admin
        limiter.recordFailure("10.0.0.1", targetUser);
        limiter.recordFailure("10.0.0.2", targetUser);
        limiter.recordFailure("10.0.0.3", targetUser);
        limiter.recordFailure("10.0.0.4", targetUser);

        // Global account threshold reached: protected from distributed attack
        assertEquals(RateLimiter.RateLimitStatus.ACCOUNT_RATE_LIMITED, limiter.checkRateLimit("10.0.0.5", targetUser));
    }

    @Test
    @DisplayName("Successful login should reset source-account failure counter")
    void testSuccessResetsFailureCounter() {
        SlidingWindowRateLimiter limiter = new SlidingWindowRateLimiter(
                10,
                2, // max 2 failures
                10,
                Duration.ofMinutes(15),
                1000,
                Clock.systemUTC()
        );

        String ip = "192.168.1.50";
        String user = "bob";

        limiter.recordFailure(ip, user);
        // 1 failure recorded, still allowed
        assertEquals(RateLimiter.RateLimitStatus.ALLOWED, limiter.checkRateLimit(ip, user));

        // User enters correct password: success recorded
        limiter.recordSuccess(ip, user);

        // Now user can make another failure without hitting limit
        limiter.recordFailure(ip, user);
        assertEquals(RateLimiter.RateLimitStatus.ALLOWED, limiter.checkRateLimit(ip, user));
    }
}
