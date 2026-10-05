package com.security.auth;

import com.security.auth.crypto.PasswordHasher;
import com.security.auth.crypto.Pbkdf2PasswordHasher;
import com.security.auth.crypto.TokenGenerator;
import com.security.auth.logging.SecureFileEventLogger;
import com.security.auth.model.AccountStatus;
import com.security.auth.model.UserRecord;
import com.security.auth.ratelimit.SlidingWindowRateLimiter;
import com.security.auth.repository.InMemoryUserCredentialRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Timing Attack Resistance Tests (Rule 6)")
class TimingAttackResistanceTest {

    static class InstrumentedPasswordHasher implements PasswordHasher {
        private final PasswordHasher delegate;
        final AtomicInteger dummyVerificationCount = new AtomicInteger(0);
        final AtomicInteger realVerificationCount = new AtomicInteger(0);

        InstrumentedPasswordHasher(PasswordHasher delegate) {
            this.delegate = delegate;
        }

        @Override
        public byte[] hashPassword(char[] password, byte[] salt, int iterations) {
            return delegate.hashPassword(password, salt, iterations);
        }

        @Override
        public boolean verifyPassword(char[] password, UserRecord record) {
            realVerificationCount.incrementAndGet();
            return delegate.verifyPassword(password, record);
        }

        @Override
        public void performDummyVerification(char[] password) {
            dummyVerificationCount.incrementAndGet();
            delegate.performDummyVerification(password);
        }

        @Override
        public byte[] generateSalt(int byteLength) {
            return delegate.generateSalt(byteLength);
        }
    }

    @Test
    @DisplayName("Non-existent user attempt must trigger dummy cryptographic workload to prevent timing enumeration (Rule 6)")
    void testNonExistentUserPerformsDummyWork(@TempDir Path tempDir) throws IOException {
        InMemoryUserCredentialRepository repository = new InMemoryUserCredentialRepository();
        InstrumentedPasswordHasher hasher = new InstrumentedPasswordHasher(new Pbkdf2PasswordHasher(1000));
        DefaultAuthenticationService service = new DefaultAuthenticationService(
                repository, hasher, new SlidingWindowRateLimiter(), new TokenGenerator(),
                new SecureFileEventLogger(tempDir.resolve("timing.log"))
        );

        AuthenticationRequest request = new AuthenticationRequest("missing_user", "SomePassword123!".toCharArray(), "192.168.1.1");
        service.authenticate(request);

        // Verify that dummy cryptographic verification was executed!
        assertEquals(1, hasher.dummyVerificationCount.get(), "Must execute dummy verification when user does not exist");
        assertEquals(0, hasher.realVerificationCount.get());
    }

    @Test
    @DisplayName("Invalid input format must trigger dummy cryptographic workload to prevent timing leaks (Rule 6)")
    void testInvalidInputPerformsDummyWork(@TempDir Path tempDir) throws IOException {
        InMemoryUserCredentialRepository repository = new InMemoryUserCredentialRepository();
        InstrumentedPasswordHasher hasher = new InstrumentedPasswordHasher(new Pbkdf2PasswordHasher(1000));
        DefaultAuthenticationService service = new DefaultAuthenticationService(
                repository, hasher, new SlidingWindowRateLimiter(), new TokenGenerator(),
                new SecureFileEventLogger(tempDir.resolve("timing2.log"))
        );

        AuthenticationRequest request = new AuthenticationRequest("bad@*username", "SomePassword123!".toCharArray(), "192.168.1.1");
        service.authenticate(request);

        assertEquals(1, hasher.dummyVerificationCount.get(), "Must execute dummy verification on validation failure");
    }

    @Test
    @DisplayName("Locked account attempt must trigger dummy cryptographic workload to prevent account status timing leak (Rule 6)")
    void testLockedAccountPerformsDummyWork(@TempDir Path tempDir) throws IOException {
        InMemoryUserCredentialRepository repository = new InMemoryUserCredentialRepository();
        InstrumentedPasswordHasher hasher = new InstrumentedPasswordHasher(new Pbkdf2PasswordHasher(1000));

        byte[] salt = hasher.generateSalt(16);
        byte[] hash = hasher.hashPassword("Password123!".toCharArray(), salt, 1000);
        repository.putUser(new UserRecord("locked_user", hash, salt, 1000, Pbkdf2PasswordHasher.ALGORITHM, AccountStatus.LOCKED));

        DefaultAuthenticationService service = new DefaultAuthenticationService(
                repository, hasher, new SlidingWindowRateLimiter(), new TokenGenerator(),
                new SecureFileEventLogger(tempDir.resolve("timing3.log"))
        );

        AuthenticationRequest request = new AuthenticationRequest("locked_user", "Password123!".toCharArray(), "192.168.1.1");
        service.authenticate(request);

        assertEquals(1, hasher.dummyVerificationCount.get(), "Must execute dummy verification on locked account");
        assertEquals(0, hasher.realVerificationCount.get());
    }
}
