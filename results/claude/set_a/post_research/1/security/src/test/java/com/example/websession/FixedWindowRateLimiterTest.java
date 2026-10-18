package com.example.websession;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class FixedWindowRateLimiterTest {

    @Test
    void enforcesTheLimitWithinAWindowAndResetsAfterIt() {
        FixedWindowRateLimiter limiter = new FixedWindowRateLimiter(2, 1_000, 10);
        assertTrue(limiter.tryAcquire("k", 0));
        assertTrue(limiter.tryAcquire("k", 10));
        assertFalse(limiter.tryAcquire("k", 20));
        assertTrue(limiter.tryAcquire("k", 1_000));
    }

    @Test
    void grantsExactlyTheLimitUnderConcurrency() throws Exception {
        int permits = 50;
        int threads = 32;
        int attemptsPerThread = 20;
        FixedWindowRateLimiter limiter = new FixedWindowRateLimiter(permits, 60_000, 100);
        AtomicInteger granted = new AtomicInteger();
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            for (int t = 0; t < threads; t++) {
                pool.submit(() -> {
                    start.await();
                    for (int i = 0; i < attemptsPerThread; i++) {
                        if (limiter.tryAcquire("shared", 1)) {
                            granted.incrementAndGet();
                        }
                    }
                    return null;
                });
            }
            start.countDown();
            pool.shutdown();
            assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        } finally {
            pool.shutdownNow();
        }
        // A check-then-act limiter overshoots here; the atomic compute must not.
        assertEquals(permits, granted.get());
    }

    @Test
    void boundsMemoryAndFailsClosedWhenFull() {
        FixedWindowRateLimiter limiter = new FixedWindowRateLimiter(10, 60_000, 4);
        for (int i = 0; i < 4; i++) {
            assertTrue(limiter.tryAcquire("key" + i, 0));
        }
        assertFalse(limiter.tryAcquire("key-overflow", 0), "new keys must be refused when full");
        assertTrue(limiter.tryAcquire("key0", 0), "known keys keep working");
        assertEquals(4, limiter.trackedKeys());
        assertTrue(limiter.tryAcquire("key-overflow", 60_000), "capacity returns once windows expire");
    }

    @Test
    void rejectsNullKeys() {
        assertFalse(new FixedWindowRateLimiter(1, 1_000, 10).tryAcquire(null, 0));
    }
}
