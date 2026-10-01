package com.security.auth;

import com.security.auth.crypto.Pbkdf2PasswordHasher;
import com.security.auth.crypto.TokenGenerator;
import com.security.auth.logging.AuthenticationEvent;
import com.security.auth.logging.AuthenticationEventType;
import com.security.auth.logging.SecureFileEventLogger;
import com.security.auth.model.AccountStatus;
import com.security.auth.model.SessionToken;
import com.security.auth.model.UserRecord;
import com.security.auth.ratelimit.SlidingWindowRateLimiter;
import com.security.auth.repository.InMemoryUserCredentialRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("AuthenticationService End-to-End Security Tests (Rules 1-8)")
class AuthenticationServiceTest {

    private InMemoryUserCredentialRepository repository;
    private Pbkdf2PasswordHasher hasher;
    private SlidingWindowRateLimiter rateLimiter;
    private TokenGenerator tokenGenerator;
    private SecureFileEventLogger eventLogger;
    private DefaultAuthenticationService authService;

    private static final String VALID_USER = "valid_user";
    private static final char[] VALID_PASSWORD = "CorrectPassword123!".toCharArray();
    private static final String CLIENT_IP = "192.168.1.10";

    @BeforeEach
    void setUp(@TempDir Path tempDir) throws IOException {
        repository = new InMemoryUserCredentialRepository();
        // 10,000 iterations for test suite performance
        hasher = new Pbkdf2PasswordHasher(10_000);
        rateLimiter = new SlidingWindowRateLimiter();
        tokenGenerator = new TokenGenerator(Duration.ofHours(1));
        eventLogger = new SecureFileEventLogger(tempDir.resolve("auth.log"));

        // Seed repository with a test user (Server-side state)
        byte[] salt = hasher.generateSalt(16);
        byte[] hash = hasher.hashPassword(VALID_PASSWORD, salt, 10_000);
        UserRecord user = new UserRecord(VALID_USER, hash, salt, 10_000, Pbkdf2PasswordHasher.ALGORITHM, AccountStatus.ACTIVE);
        repository.putUser(user);

        // Also add a suspended user
        byte[] salt2 = hasher.generateSalt(16);
        byte[] hash2 = hasher.hashPassword("SuspendedPass123!".toCharArray(), salt2, 10_000);
        UserRecord suspendedUser = new UserRecord("suspended_user", hash2, salt2, 10_000, Pbkdf2PasswordHasher.ALGORITHM, AccountStatus.SUSPENDED);
        repository.putUser(suspendedUser);

        authService = new DefaultAuthenticationService(repository, hasher, rateLimiter, tokenGenerator, eventLogger);
    }

    @Test
    @DisplayName("Successful login should issue secure SessionToken and zeroize credentials from memory (Rules 2, 4, 5)")
    void testSuccessfulAuthentication() {
        char[] passwordCopy = VALID_PASSWORD.clone();
        AuthenticationRequest request = new AuthenticationRequest(VALID_USER, passwordCopy, CLIENT_IP);

        AuthenticationResult result = authService.authenticate(request);

        assertTrue(result.isSuccess());
        assertEquals(AuthenticationResult.SUCCESS_MESSAGE, result.getUserMessage());
        assertTrue(result.getSessionToken().isPresent());

        SessionToken token = result.getSessionToken().get();
        assertEquals(VALID_USER, token.getUsername());
        assertNotNull(token.getValue());
        assertFalse(token.isExpired());

        // Check secure cookie format (Rule 4)
        String cookieHeader = token.toSetCookieHeader("SESSION_ID");
        assertTrue(cookieHeader.contains("HttpOnly"));
        assertTrue(cookieHeader.contains("Secure"));
        assertTrue(cookieHeader.contains("SameSite=Strict"));
        assertTrue(cookieHeader.contains("Path=/"));

        // Check credential memory zeroization (Rule 5)
        assertThrows(IllegalStateException.class, request::getPassword, "Password must be cleared from memory");

        // Verify audit log recorded success
        List<AuthenticationEvent> events = eventLogger.getRecentEvents(1);
        assertEquals(1, events.size());
        assertEquals(AuthenticationEventType.LOGIN_SUCCESS, events.get(0).getEventType());
        assertEquals(token.getAuditFingerprint(), events.get(0).getTokenFingerprint());
    }

    @Test
    @DisplayName("Wrong password should fail, clear memory, and return generic message (Rules 5 & 6)")
    void testWrongPassword() {
        char[] wrongPassword = "WrongPassword999!".toCharArray();
        AuthenticationRequest request = new AuthenticationRequest(VALID_USER, wrongPassword, CLIENT_IP);

        AuthenticationResult result = authService.authenticate(request);

        assertFalse(result.isSuccess());
        assertEquals(AuthenticationResult.GENERIC_FAILURE_MESSAGE, result.getUserMessage());
        assertTrue(result.getSessionToken().isEmpty());

        // Memory zeroized
        assertThrows(IllegalStateException.class, request::getPassword);

        // Verify audit log
        List<AuthenticationEvent> events = eventLogger.getRecentEvents(1);
        assertEquals(1, events.size());
        assertEquals(AuthenticationEventType.LOGIN_FAILURE_INVALID_CREDENTIALS, events.get(0).getEventType());
    }

    @Test
    @DisplayName("User Enumeration Defense: Non-existent user returns IDENTICAL generic message (Rule 6)")
    void testNonExistentUserReturnsGenericMessage() {
        AuthenticationRequest request = new AuthenticationRequest("non_existent_user", "SomePassword123!".toCharArray(), CLIENT_IP);

        AuthenticationResult result = authService.authenticate(request);

        assertFalse(result.isSuccess());
        // Generic message prevents username harvesting (Rule 6)
        assertEquals(AuthenticationResult.GENERIC_FAILURE_MESSAGE, result.getUserMessage());

        List<AuthenticationEvent> events = eventLogger.getRecentEvents(1);
        assertEquals(AuthenticationEventType.LOGIN_FAILURE_USER_NOT_FOUND, events.get(0).getEventType());
    }

    @Test
    @DisplayName("Suspended account returns IDENTICAL generic message to prevent account status enumeration (Rule 6)")
    void testSuspendedAccountReturnsGenericMessage() {
        AuthenticationRequest request = new AuthenticationRequest("suspended_user", "SuspendedPass123!".toCharArray(), CLIENT_IP);

        AuthenticationResult result = authService.authenticate(request);

        assertFalse(result.isSuccess());
        assertEquals(AuthenticationResult.GENERIC_FAILURE_MESSAGE, result.getUserMessage());

        List<AuthenticationEvent> events = eventLogger.getRecentEvents(1);
        assertEquals(AuthenticationEventType.LOGIN_FAILURE_ACCOUNT_LOCKED, events.get(0).getEventType());
    }

    @Test
    @DisplayName("Invalid input format returns IDENTICAL generic message to prevent error leakage (Rule 1 & 6)")
    void testInvalidInputReturnsGenericMessage() {
        // Username with invalid characters
        AuthenticationRequest request = new AuthenticationRequest("bad*user!", "Password123!".toCharArray(), CLIENT_IP);

        AuthenticationResult result = authService.authenticate(request);

        assertFalse(result.isSuccess());
        assertEquals(AuthenticationResult.GENERIC_FAILURE_MESSAGE, result.getUserMessage());

        List<AuthenticationEvent> events = eventLogger.getRecentEvents(1);
        assertEquals(AuthenticationEventType.LOGIN_FAILURE_INVALID_INPUT, events.get(0).getEventType());
    }

    @Test
    @DisplayName("Null authentication request fails closed safely (Rule 3 & 6)")
    void testNullRequestFailsClosed() {
        AuthenticationResult result = authService.authenticate(null);

        assertFalse(result.isSuccess());
        assertEquals(AuthenticationResult.GENERIC_FAILURE_MESSAGE, result.getUserMessage());

        List<AuthenticationEvent> events = eventLogger.getRecentEvents(1);
        assertEquals(AuthenticationEventType.LOGIN_FAILURE_INVALID_INPUT, events.get(0).getEventType());
    }

    @Test
    @DisplayName("Accidental toString on AuthenticationRequest must never reveal password (Rule 2)")
    void testRequestToStringDoesNotLeakPassword() {
        AuthenticationRequest request = new AuthenticationRequest("alice", "SuperSecretPassword123!".toCharArray(), "10.0.0.1");
        String stringRep = request.toString();

        assertFalse(stringRep.contains("SuperSecretPassword123!"));
        assertTrue(stringRep.contains("[PROTECTED]"));
    }
}
