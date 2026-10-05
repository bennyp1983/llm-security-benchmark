package com.example.auth;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class AuthenticationServiceTest {

    private DatabaseManager dbManager;
    private AuthenticationService authService;

    @BeforeEach
    void setUp() {
        String uniqueDbUrl = "jdbc:h2:mem:testdb_" + UUID.randomUUID().toString().replace("-", "") + ";DB_CLOSE_DELAY=-1";
        dbManager = new DatabaseManager(uniqueDbUrl, "sa", "");
        authService = new AuthenticationService(dbManager);
    }

    @AfterEach
    void tearDown() {
        dbManager.close();
    }

    @Test
    void testSuccessfulAuthenticationFlow() {
        String email = "alice@example.com";
        char[] regPassword = "MySecurePassword#123".toCharArray();
        assertTrue(authService.registerUser(email, regPassword));

        char[] loginPassword = "MySecurePassword#123".toCharArray();
        AuthenticationResult result = authService.authenticate(email, loginPassword, "client-1");

        assertTrue(result.isSuccess());
        assertEquals(AuthenticationResult.Status.SUCCESS, result.getStatus());
        assertEquals(AuthenticationResult.MSG_SUCCESS, result.getUserMessage());
        assertTrue(result.getSession().isPresent());
        assertNotNull(result.getSession().get().sessionId());
        assertTrue(result.getSession().get().cookieHeader().contains("__Host-AuthSession="));

        // Memory hygiene verification: caller's password array must be zeroized
        for (char c : loginPassword) {
            assertEquals('\0', c, "Password array must be zeroized in memory");
        }
    }

    @Test
    void testFailedAuthenticationWrongPassword() {
        String email = "bob@example.com";
        assertTrue(authService.registerUser(email, "CorrectPassword#1".toCharArray()));

        char[] wrongPassword = "WrongPassword#2".toCharArray();
        AuthenticationResult result = authService.authenticate(email, wrongPassword, "client-1");

        assertFalse(result.isSuccess());
        assertEquals(AuthenticationResult.Status.INVALID_CREDENTIALS, result.getStatus());
        assertEquals(AuthenticationResult.MSG_INVALID_CREDENTIALS, result.getUserMessage());
        assertTrue(result.getSession().isEmpty());

        // Password array zeroized
        for (char c : wrongPassword) {
            assertEquals('\0', c);
        }
    }

    @Test
    void testFailedAuthenticationNonExistentUserGivesIdenticalGenericMessage() {
        char[] password = "AnyPassword#123".toCharArray();
        AuthenticationResult result = authService.authenticate("nonexistent@example.com", password, "client-1");

        assertFalse(result.isSuccess());
        assertEquals(AuthenticationResult.Status.INVALID_CREDENTIALS, result.getStatus());
        // Generic message identical to wrong password (Rule 6)
        assertEquals(AuthenticationResult.MSG_INVALID_CREDENTIALS, result.getUserMessage());
    }

    @Test
    void testFailedAuthenticationMalformedInputsGiveIdenticalGenericMessage() {
        char[] password = "AnyPassword#123".toCharArray();
        AuthenticationResult result = authService.authenticate("not-an-email", password, "client-1");

        assertFalse(result.isSuccess());
        assertEquals(AuthenticationResult.Status.INVALID_CREDENTIALS, result.getStatus());
        assertEquals(AuthenticationResult.MSG_INVALID_CREDENTIALS, result.getUserMessage());
    }

    @Test
    void testSqlInjectionAttemptsArePrevented() {
        String[] injectionEmails = {
                "' OR 1=1 --",
                "admin'--",
                "' UNION SELECT id, email, password_hash, salt, iterations, algorithm, status FROM users --",
                "victim@example.com'; DROP TABLE users; --"
        };

        for (String maliciousEmail : injectionEmails) {
            char[] password = "Password123!".toCharArray();
            AuthenticationResult result = authService.authenticate(maliciousEmail, password, "test-ip");

            assertFalse(result.isSuccess());
            // Rejection without exposing database error
            assertEquals(AuthenticationResult.MSG_INVALID_CREDENTIALS, result.getUserMessage());
        }
    }

    @Test
    void testRateLimitingEnforcementOnRepeatedFailures() {
        String email = "charlie@example.com";
        assertTrue(authService.registerUser(email, "SecretPassword#1".toCharArray()));

        String sourceId = "192.168.1.200";

        // Fail 3 times from this source
        for (int i = 0; i < RateLimiter.MAX_SOURCE_ACCOUNT_ATTEMPTS; i++) {
            AuthenticationResult res = authService.authenticate(email, "WrongPassword!".toCharArray(), sourceId);
            assertEquals(AuthenticationResult.Status.INVALID_CREDENTIALS, res.getStatus());
        }

        // 4th attempt is rate-limited
        AuthenticationResult rateLimitedRes = authService.authenticate(email, "SecretPassword#1".toCharArray(), sourceId);
        assertFalse(rateLimitedRes.isSuccess());
        assertEquals(AuthenticationResult.Status.RATE_LIMITED, rateLimitedRes.getStatus());
        assertEquals(AuthenticationResult.MSG_RATE_LIMITED, rateLimitedRes.getUserMessage());
    }
}
