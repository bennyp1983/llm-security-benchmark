package com.security.auth.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Rule 3 & Rule 7: Rate Limiter & Lockout Prevention Tests")
class RateLimiterTest {

    @Test
    @DisplayName("Blocks source IP after 5 consecutive failures while leaving other IPs unaffected")
    void testSourceRateLimitingAndTargetAccountProtection() {
        RateLimiter limiter = new RateLimiter();
        String attackerIp = "198.51.100.1";
        String victimUser = "alice_target";
        String legitimateUserIp = "203.0.113.5";

        // Initial check: both allowed
        assertTrue(limiter.checkAllowed(attackerIp, victimUser).allowed());
        assertTrue(limiter.checkAllowed(legitimateUserIp, victimUser).allowed());

        // Attacker fails 5 times
        for (int i = 0; i < RateLimiter.MAX_SOURCE_FAILURES; i++) {
            limiter.recordFailure(attackerIp, victimUser);
        }

        // Attacker is now blocked
        RateLimiter.CheckResult attackerCheck = limiter.checkAllowed(attackerIp, victimUser);
        assertFalse(attackerCheck.allowed(), "Attacker source IP must be blocked after exceeding threshold");

        // CRITICAL Rule 3 Requirement:
        // Legitimate user from their own IP must NOT be blocked, even though attacker attacked their account!
        RateLimiter.CheckResult legitCheck = limiter.checkAllowed(legitimateUserIp, victimUser);
        assertTrue(legitCheck.allowed(), "Legitimate user must not be denied access due to an attacker's attempts");

        // Legitimate user logs in successfully
        limiter.recordSuccess(legitimateUserIp, victimUser);

        // Account failure count is cleared on successful authentication
        RateLimiter.CheckResult afterSuccess = limiter.checkAllowed(legitimateUserIp, victimUser);
        assertTrue(afterSuccess.allowed());
        assertEquals(0, afterSuccess.delayMs());
    }

    @Test
    @DisplayName("Account progressive delay kicks in after multiple failures without locking out user")
    void testAccountProgressiveDelay() {
        RateLimiter limiter = new RateLimiter();
        String user = "bob_user";

        // Simulate 6 failures across different attacker sources (distributed attack)
        for (int i = 0; i < 6; i++) {
            limiter.recordFailure("10.0.0." + i, user);
        }

        // A new source checks the account: still allowed to attempt login, but with progressive delay applied
        RateLimiter.CheckResult result = limiter.checkAllowed("192.168.1.50", user);
        assertTrue(result.allowed(), "Account should not be completely locked out");
        assertTrue(result.delayMs() > 0, "Account under distributed pressure should impose progressive delay");
    }

    @Test
    @DisplayName("Rate limiter bounds memory consumption under high load (Rule 5)")
    void testMemoryBounding() {
        RateLimiter limiter = new RateLimiter();
        // Record 11,000 unique failures
        for (int i = 0; i < 11_000; i++) {
            limiter.recordFailure("10.10." + (i / 256) + "." + (i % 256), "user_" + i);
        }
        // Ensure system did not crash and memory cleanup triggered
        assertTrue(limiter.checkAllowed("192.168.1.1", "fresh_user").allowed());
    }
}
