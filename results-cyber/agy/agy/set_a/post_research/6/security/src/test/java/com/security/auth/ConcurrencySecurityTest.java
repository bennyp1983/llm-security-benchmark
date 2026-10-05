package com.security.auth;

import com.security.auth.crypto.Pbkdf2PasswordHasher;
import com.security.auth.crypto.TokenGenerator;
import com.security.auth.logging.AuthenticationEvent;
import com.security.auth.logging.SecureFileEventLogger;
import com.security.auth.model.AccountStatus;
import com.security.auth.model.UserRecord;
import com.security.auth.ratelimit.RateLimiter;
import com.security.auth.ratelimit.SlidingWindowRateLimiter;
import com.security.auth.repository.InMemoryUserCredentialRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Concurrency & Atomicity Security Tests (Rule 7)")
class ConcurrencySecurityTest {

    @Test
    @DisplayName("Concurrent login attempts must atomically enforce rate limits without race conditions (Rule 7)")
    void testConcurrentRateLimiting(@TempDir Path tempDir) throws IOException, InterruptedException {
        int threadCount = 20;
        int maxAttempts = 5;

        InMemoryUserCredentialRepository repository = new InMemoryUserCredentialRepository();
        Pbkdf2PasswordHasher hasher = new Pbkdf2PasswordHasher(1000); // Fast iteration for concurrency test
        SlidingWindowRateLimiter rateLimiter = new SlidingWindowRateLimiter(
                maxAttempts,
                maxAttempts,
                50,
                Duration.ofMinutes(15),
                1000,
                java.time.Clock.systemUTC()
        );
        TokenGenerator tokenGenerator = new TokenGenerator();
        SecureFileEventLogger eventLogger = new SecureFileEventLogger(tempDir.resolve("concurrency.log"));

        DefaultAuthenticationService service = new DefaultAuthenticationService(
                repository, hasher, rateLimiter, tokenGenerator, eventLogger
        );

        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch endLatch = new CountDownLatch(threadCount);

        AtomicInteger rateLimitedCount = new AtomicInteger(0);
        AtomicInteger regularFailureCount = new AtomicInteger(0);

        String clientIp = "10.10.10.10";
        String username = "target_user";

        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    AuthenticationRequest request = new AuthenticationRequest(username, "BadPassword123!".toCharArray(), clientIp);
                    AuthenticationResult result = service.authenticate(request);
                    if (result.getInternalErrorCode() == AuthenticationErrorCode.RATE_LIMITED_SOURCE) {
                        rateLimitedCount.incrementAndGet();
                    } else {
                        regularFailureCount.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    endLatch.countDown();
                }
            });
        }

        // Fire all threads simultaneously
        startLatch.countDown();
        assertTrue(endLatch.await(10, TimeUnit.SECONDS));
        executor.shutdown();

        // Exactly 'maxAttempts' regular failures, and the rest were blocked by rate limiting!
        // No race condition allowed exceeding the threshold.
        assertEquals(maxAttempts, regularFailureCount.get(), "Only allowed attempts should reach credential check");
        assertEquals(threadCount - maxAttempts, rateLimitedCount.get(), "All excess concurrent attempts must be throttled");

        // Verify that all events were logged atomically without loss
        List<AuthenticationEvent> events = eventLogger.getRecentEvents(threadCount);
        assertEquals(threadCount, events.size(), "Logger must capture every event without dropping concurrent writes");
    }
}
