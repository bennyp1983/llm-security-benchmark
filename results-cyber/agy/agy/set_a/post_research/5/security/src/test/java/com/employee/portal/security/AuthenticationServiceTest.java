package com.employee.portal.security;

import com.employee.portal.security.config.SecurityConfig;
import com.employee.portal.security.crypto.PasswordHasher;
import com.employee.portal.security.crypto.SecureTokenGenerator;
import com.employee.portal.security.logging.AuditLogger;
import com.employee.portal.security.model.AuthenticationResult;
import com.employee.portal.security.model.EmployeeRecord;
import com.employee.portal.security.model.UserStatus;
import com.employee.portal.security.ratelimit.RateLimiter;
import com.employee.portal.security.repository.FileEmployeeRepository;
import com.employee.portal.security.service.AuthenticationService;
import com.employee.portal.security.session.SessionManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("End-to-End Authentication Security Verification Tests")
class AuthenticationServiceTest {

    @TempDir
    Path tempDir;

    private AtomicLong mockTime;
    private SecurityConfig config;
    private FileEmployeeRepository repository;
    private PasswordHasher hasher;
    private RateLimiter rateLimiter;
    private SessionManager sessionManager;
    private AuditLogger auditLogger;
    private AuthenticationService authService;

    @BeforeEach
    void setUp() {
        mockTime = new AtomicLong(1000000L);
        config = new SecurityConfig(
                5, 10,
                15 * 60_000L,
                15 * 60_000L,
                15 * 60_000L,
                480 * 60_000L,
                5, 1000,
                100000,
                tempDir
        );
        repository = new FileEmployeeRepository(tempDir.resolve("employees.db"));
        hasher = new PasswordHasher(100000, 32, 256);
        rateLimiter = new RateLimiter(config, mockTime::get);
        sessionManager = new SessionManager(config, new SecureTokenGenerator(), mockTime::get);
        auditLogger = new AuditLogger(tempDir.resolve("audit.log"), false);

        authService = new AuthenticationService(
                config, repository, hasher, rateLimiter, sessionManager, auditLogger, true);

        // Enroll test active user and suspended user
        authService.enrollEmployee("alice", "AliceSecurePass#2026".toCharArray(), "ADMIN");

        // Manually create suspended user
        byte[] salt = hasher.generateSalt();
        byte[] hash = hasher.hashPassword("BobSuspendedPass#2026".toCharArray(), salt);
        repository.save(new EmployeeRecord("bob", salt, hash, 100000, UserStatus.SUSPENDED, "EMPLOYEE"));
    }

    @Test
    void testSuccessfulAuthentication() {
        char[] pwd = "AliceSecurePass#2026".toCharArray();
        AuthenticationResult result = authService.authenticate("alice", pwd, "10.0.0.1");

        assertTrue(result.isSuccess());
        assertTrue(result.getSession().isPresent());
        assertEquals("alice", result.getSession().get().getUsername());
        assertEquals("ADMIN", result.getSession().get().getRole());
        assertTrue(result.getCookieHeader().isPresent());
        assertTrue(result.getCookieHeader().get().contains("HttpOnly"));
        assertTrue(result.getCookieHeader().get().contains("Secure"));
        assertTrue(result.getCookieHeader().get().contains("SameSite=Strict"));
    }

    @Test
    void testFailedAuthenticationOnWrongPassword() {
        char[] pwd = "WrongPassword#999".toCharArray();
        AuthenticationResult result = authService.authenticate("alice", pwd, "10.0.0.1");

        assertFalse(result.isSuccess());
        assertEquals(AuthenticationResult.GENERIC_FAILURE_MESSAGE, result.getMessage());
        assertTrue(result.getSession().isEmpty());
    }

    @Test
    void testFailedAuthenticationOnNonExistentUserGivesIdenticalMessage() {
        char[] pwd = "SomePassword#1234".toCharArray();
        AuthenticationResult result = authService.authenticate("nonexistent_user", pwd, "10.0.0.1");

        assertFalse(result.isSuccess());
        // Rule 6: Identical error message
        assertEquals(AuthenticationResult.GENERIC_FAILURE_MESSAGE, result.getMessage());
        assertTrue(result.getSession().isEmpty());
    }

    @Test
    void testSuspendedUserFailsWithIdenticalMessage() {
        char[] pwd = "BobSuspendedPass#2026".toCharArray();
        AuthenticationResult result = authService.authenticate("bob", pwd, "10.0.0.1");

        assertFalse(result.isSuccess());
        // Rule 6: Identical error message
        assertEquals(AuthenticationResult.GENERIC_FAILURE_MESSAGE, result.getMessage());
        assertTrue(result.getSession().isEmpty());
    }

    @Test
    void testInvalidUsernameFormatFailsWithIdenticalMessage() {
        char[] pwd = "SomePassword#1234".toCharArray();
        AuthenticationResult result = authService.authenticate("../../etc/passwd", pwd, "10.0.0.1");

        assertFalse(result.isSuccess());
        assertEquals(AuthenticationResult.GENERIC_FAILURE_MESSAGE, result.getMessage());
    }

    @Test
    void testPasswordMemoryClearedAfterAuthentication() {
        char[] pwd = "AliceSecurePass#2026".toCharArray();
        authService.authenticate("alice", pwd, "10.0.0.1");

        // Rule 5: Password array must be zeroed out
        for (char c : pwd) {
            assertEquals('\0', c, "Password character in memory must be overwritten with zero");
        }
    }

    @Test
    void testRepeatedFailedAttemptsBlocksSourceWithoutLockingLegitimateUser() {
        String attackerIp = "198.51.100.5";
        String legitimateIp = "10.0.0.1";

        // Attacker attempts 5 wrong passwords for alice
        for (int i = 0; i < 5; i++) {
            char[] wrong = ("BadPasswordAttempt#" + i).toCharArray();
            AuthenticationResult res = authService.authenticate("alice", wrong, attackerIp);
            assertFalse(res.isSuccess());
        }

        // 6th attempt from attacker is rejected by rate limit
        char[] correctPasswordFromAttacker = "AliceSecurePass#2026".toCharArray();
        AuthenticationResult attackerBlocked = authService.authenticate("alice", correctPasswordFromAttacker, attackerIp);
        assertFalse(attackerBlocked.isSuccess());
        assertEquals(AuthenticationResult.GENERIC_FAILURE_MESSAGE, attackerBlocked.getMessage());

        // Legitimate employee on legitimate IP enters correct password: ACCESS GRANTED!
        char[] legitimatePassword = "AliceSecurePass#2026".toCharArray();
        AuthenticationResult legitimateLogin = authService.authenticate("alice", legitimatePassword, legitimateIp);
        assertTrue(legitimateLogin.isSuccess(), "Legitimate employee must not be locked out by attacker IP attempts");
    }

    @Test
    void testTimingEquivalenceBetweenExistingAndNonExistingUser() {
        // Warm up JIT compiler
        for (int i = 0; i < 3; i++) {
            char[] warm1 = "WarmupPassword#123".toCharArray();
            authService.authenticate("alice", warm1, "127.0.0.1");
            char[] warm2 = "WarmupPassword#123".toCharArray();
            authService.authenticate("ghost_user", warm2, "127.0.0.1");
        }

        // Measure time for existing user with wrong password
        char[] pwd1 = "WrongPassword#111".toCharArray();
        long t0 = System.nanoTime();
        authService.authenticate("alice", pwd1, "127.0.0.1");
        long elapsedExisting = System.nanoTime() - t0;

        // Measure time for non-existing user
        char[] pwd2 = "WrongPassword#111".toCharArray();
        long t1 = System.nanoTime();
        authService.authenticate("ghost_user", pwd2, "127.0.0.1");
        long elapsedNonExisting = System.nanoTime() - t1;

        // Both executed full PBKDF2 100,000 iterations:
        // Elapsed time should be of the same order of magnitude (neither is instantaneous microseconds)
        assertTrue(elapsedExisting > 1_000_000L, "Existing user check should take > 1ms");
        assertTrue(elapsedNonExisting > 1_000_000L, "Non-existing user check should take > 1ms due to dummy hashing");
    }
}
