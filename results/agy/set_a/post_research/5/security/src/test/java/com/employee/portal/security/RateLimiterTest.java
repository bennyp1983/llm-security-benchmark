package com.employee.portal.security;

import com.employee.portal.security.config.SecurityConfig;
import com.employee.portal.security.ratelimit.RateLimiter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Paths;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Rule 3 & 7: Rate Limiting, Lockout DoS Protection, and Concurrency Tests")
class RateLimiterTest {

    private AtomicLong mockTime;
    private SecurityConfig config;
    private RateLimiter rateLimiter;

    @BeforeEach
    void setUp() {
        mockTime = new AtomicLong(1000000L);
        // 5 max failed per source, 10 max failed per account, 15 min lockout, 15 min window
        config = new SecurityConfig(
                5, 10,
                15 * 60_000L,
                15 * 60_000L,
                15 * 60_000L,
                480 * 60_000L,
                5, 1000,
                100000,
                Paths.get("./test-data")
        );
        rateLimiter = new RateLimiter(config, mockTime::get);
    }

    @Test
    void testSourceRateLimitingBlocksAttackerSource() {
        String attackerIp = "198.51.100.5";
        String victimUser = "alice";

        // Record 4 failures: not yet restricted
        for (int i = 0; i < 4; i++) {
            rateLimiter.recordFailure(attackerIp, victimUser);
            assertFalse(rateLimiter.isSourceRestricted(attackerIp), "Attempt " + (i + 1) + " should not lock yet");
        }

        // 5th failure: triggers source lockout
        rateLimiter.recordFailure(attackerIp, victimUser);
        assertTrue(rateLimiter.isSourceRestricted(attackerIp), "5th attempt must lock attacker source");
        assertTrue(rateLimiter.isRestricted(attackerIp, victimUser));

        // Other innocent sources are NOT blocked
        String innocentIp = "10.0.0.1";
        assertFalse(rateLimiter.isSourceRestricted(innocentIp));
    }

    @Test
    void testSingleAttackerCannotLockOutLegitimateUserAcrossDistinctSources() {
        String attackerIp = "198.51.100.5";
        String legitimateIp = "10.0.0.1";
        String employeeUser = "alice";

        // Attacker attempts 5 wrong passwords for 'alice'
        for (int i = 0; i < 5; i++) {
            rateLimiter.recordFailure(attackerIp, employeeUser);
        }

        // Attacker source is blocked
        assertTrue(rateLimiter.isSourceRestricted(attackerIp));
        assertTrue(rateLimiter.isRestricted(attackerIp, employeeUser));

        // Rule 3: The legitimate employee attempting from their own IP is NOT locked out!
        assertFalse(rateLimiter.isSourceRestricted(legitimateIp));
        assertFalse(rateLimiter.isAccountRestricted(employeeUser));
        assertFalse(rateLimiter.isRestricted(legitimateIp, employeeUser));
    }

    @Test
    void testDistributedAttackExceedingGlobalAccountThresholdTriggersAccountCooldown() {
        String employeeUser = "alice";

        // 2 distinct attacker IPs each send 5 failures (total 10 distributed failures for alice)
        for (int i = 0; i < 5; i++) {
            rateLimiter.recordFailure("198.51.100.1", employeeUser);
            rateLimiter.recordFailure("198.51.100.2", employeeUser);
        }

        // Both attacker sources are blocked
        assertTrue(rateLimiter.isSourceRestricted("198.51.100.1"));
        assertTrue(rateLimiter.isSourceRestricted("198.51.100.2"));

        // Global account threshold (10) was met
        assertTrue(rateLimiter.isAccountRestricted(employeeUser));
    }

    @Test
    void testLockoutExpiresAfterCooldownWindow() {
        String attackerIp = "198.51.100.5";
        String user = "bob";

        for (int i = 0; i < 5; i++) {
            rateLimiter.recordFailure(attackerIp, user);
        }
        assertTrue(rateLimiter.isSourceRestricted(attackerIp));

        // Advance clock by 14 minutes (within lockout duration of 15 minutes)
        mockTime.addAndGet(14 * 60_000L);
        assertTrue(rateLimiter.isSourceRestricted(attackerIp));

        // Advance clock by 2 more minutes (total 16 minutes > 15 minutes)
        mockTime.addAndGet(2 * 60_000L);
        assertFalse(rateLimiter.isSourceRestricted(attackerIp));
    }

    @Test
    void testRecordSuccessResetsFailureCounts() {
        String sourceIp = "10.0.0.2";
        String user = "charlie";

        rateLimiter.recordFailure(sourceIp, user);
        rateLimiter.recordFailure(sourceIp, user);
        assertEquals(2, rateLimiter.getSourceFailures(sourceIp));
        assertEquals(2, rateLimiter.getAccountFailures(user));

        rateLimiter.recordSuccess(sourceIp, user);
        assertEquals(0, rateLimiter.getSourceFailures(sourceIp));
        assertEquals(0, rateLimiter.getAccountFailures(user));
    }

    @Test
    void testConcurrentFailureRecordingIsAtomic() throws InterruptedException {
        String sourceIp = "172.16.0.10";
        String user = "concurrent_user";
        int threadCount = 20;

        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);

        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    rateLimiter.recordFailure(sourceIp, user);
                } finally {
                    latch.countDown();
                }
            });
        }

        latch.await();
        executor.shutdown();

        // Lockout must have triggered reliably without race condition corruption
        assertTrue(rateLimiter.isSourceRestricted(sourceIp));
        assertTrue(rateLimiter.isAccountRestricted(user));
    }
}
