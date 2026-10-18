package com.example.auth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class RateLimiterTest {

    private RateLimiter rateLimiter;

    @BeforeEach
    void setUp() {
        rateLimiter = new RateLimiter();
    }

    @Test
    void testSourceRateLimiting() {
        String sourceId = "192.168.1.100";
        String email = "alice@example.com";

        // First 3 attempts for this account from this source succeed
        for (int i = 0; i < RateLimiter.MAX_SOURCE_ACCOUNT_ATTEMPTS; i++) {
            RateLimiter.RateLimitResult res = rateLimiter.checkAndAcquire(sourceId, email);
            assertTrue(res.isAllowed(), "Attempt " + i + " should be allowed");
        }

        // 4th attempt for this account from this source is blocked
        RateLimiter.RateLimitResult fourth = rateLimiter.checkAndAcquire(sourceId, email);
        assertFalse(fourth.isAllowed());
        assertEquals(RateLimiter.Status.SOURCE_ACCOUNT_BLOCKED, fourth.status());
    }

    @Test
    void testAttackerCannotLockOutLegitimateUser() {
        // Crucial test for Rule 3: An attacker cannot use lockout mechanism to DoS legitimate users
        String attackerSource = "198.51.100.5";
        String legitimateSource = "203.0.113.42";
        String victimEmail = "victim@company.com";

        // Attacker exhausts attempts from their source against the victim's account
        for (int i = 0; i < RateLimiter.MAX_SOURCE_ACCOUNT_ATTEMPTS; i++) {
            RateLimiter.RateLimitResult res = rateLimiter.checkAndAcquire(attackerSource, victimEmail);
            assertTrue(res.isAllowed());
        }

        // Attacker is now blocked
        RateLimiter.RateLimitResult attackerNext = rateLimiter.checkAndAcquire(attackerSource, victimEmail);
        assertFalse(attackerNext.isAllowed(), "Attacker should be blocked");

        // The legitimate user attempting to log in from their own source is NOT locked out!
        RateLimiter.RateLimitResult legitResult = rateLimiter.checkAndAcquire(legitimateSource, victimEmail);
        assertTrue(legitResult.isAllowed(), "Legitimate user must NOT be locked out by attacker's attempts");
    }

    @Test
    void testAuthenticationSuccessResetsCounters() {
        String sourceId = "192.168.1.50";
        String email = "bob@example.com";

        // Fail 2 attempts
        assertTrue(rateLimiter.checkAndAcquire(sourceId, email).isAllowed());
        assertTrue(rateLimiter.checkAndAcquire(sourceId, email).isAllowed());

        // Successful authentication
        rateLimiter.recordAuthenticationSuccess(sourceId, email);

        // Counter reset allows full attempts again
        for (int i = 0; i < RateLimiter.MAX_SOURCE_ACCOUNT_ATTEMPTS; i++) {
            assertTrue(rateLimiter.checkAndAcquire(sourceId, email).isAllowed());
        }
    }

    @Test
    void testConcurrencyAtomicity() throws InterruptedException, ExecutionException {
        // Tests Rule 7: count, then allow must be atomic under high concurrency
        String sourceId = "10.0.0.99";
        String email = "concurrent@example.com";
        int threadCount = 30;

        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch readyLatch = new CountDownLatch(threadCount);
        CountDownLatch startLatch = new CountDownLatch(1);

        List<Future<Boolean>> futures = new ArrayList<>();

        for (int i = 0; i < threadCount; i++) {
            futures.add(executor.submit((Callable<Boolean>) () -> {
                readyLatch.countDown();
                startLatch.await(); // Synchronize all threads to start at the exact same microsecond
                RateLimiter.RateLimitResult res = rateLimiter.checkAndAcquire(sourceId, email);
                return res.isAllowed();
            }));
        }

        readyLatch.await();
        startLatch.countDown(); // Blast off all threads

        int allowedCount = 0;
        int blockedCount = 0;

        for (Future<Boolean> future : futures) {
            if (future.get()) {
                allowedCount++;
            } else {
                blockedCount++;
            }
        }

        executor.shutdown();

        // Exactly MAX_SOURCE_ACCOUNT_ATTEMPTS must be allowed, no race condition permits leaking through
        assertEquals(RateLimiter.MAX_SOURCE_ACCOUNT_ATTEMPTS, allowedCount,
                "Exactly allowed limit must be acquired under high concurrency");
        assertEquals(threadCount - RateLimiter.MAX_SOURCE_ACCOUNT_ATTEMPTS, blockedCount);
    }
}
