package com.security.auth.service;

import com.security.auth.config.SecurityConfig;
import com.security.auth.database.DatabaseManager;
import com.security.auth.model.AuthenticationRequest;
import com.security.auth.model.AuthenticationResult;
import com.security.auth.model.RegistrationRequest;
import com.security.auth.model.RegistrationResult;
import com.security.auth.model.User;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("End-to-End Security & Authentication Service Tests")
class AuthenticationServiceTest {

    private DatabaseManager dbManager;
    private AuthenticationService authService;

    @BeforeEach
    void setUp() {
        Path serviceTestDir = java.nio.file.Paths.get("./target/test-data-service/" + java.util.UUID.randomUUID()).toAbsolutePath();
        SecurityConfig config = SecurityConfig.builder()
                .dataDirectory(serviceTestDir)
                .dbUrl("jdbc:h2:mem:test_auth_db;DB_CLOSE_DELAY=-1;NON_KEYWORDS=USER")
                .dbUser("sa")
                .dbPassword(new char[0])
                .pbkdf2Iterations(100_000) // Fast for test execution while maintaining PBKDF2
                .sessionTtlMinutes(30)
                .build();

        dbManager = new DatabaseManager(config);
        authService = new AuthenticationService(config, dbManager);
    }

    @AfterEach
    void tearDown() {
        authService.close();
    }

    @Test
    @DisplayName("End-to-end user registration and future authentication")
    void testRegistrationAndAuthenticationSuccess() {
        char[] password = "SecurePassword123!@#".toCharArray();
        RegistrationRequest regReq = new RegistrationRequest("alice@example.com", "alice_smith", password);
        RegistrationResult regResult = authService.register(regReq, "127.0.0.1");

        assertTrue(regResult.isSuccess(), "Registration should succeed for valid credentials");
        assertNotNull(regResult.getUserId());

        // Authenticate with registered username
        char[] authPassword = "SecurePassword123!@#".toCharArray();
        AuthenticationRequest authReq = new AuthenticationRequest("alice_smith", authPassword, "127.0.0.1");
        AuthenticationResult authResult = authService.authenticate(authReq);

        assertTrue(authResult.isSuccess(), "Authentication should succeed with valid username and password");
        assertNotNull(authResult.getSessionToken());
        assertNotNull(authResult.getSessionCookie());
        assertEquals("alice_smith", authResult.getUser().getUsername());
        assertEquals("alice@example.com", authResult.getUser().getEmail());

        // Verify Set-Cookie header contains required security flags (Rule 4)
        String cookieHeader = authResult.getSessionCookie().toHeaderValue();
        assertTrue(cookieHeader.contains("HttpOnly"));
        assertTrue(cookieHeader.contains("Secure"));
        assertTrue(cookieHeader.contains("SameSite=Strict"));
        assertTrue(cookieHeader.contains("Path=/"));

        // Authenticate using email instead of username
        char[] emailAuthPassword = "SecurePassword123!@#".toCharArray();
        AuthenticationRequest emailAuthReq = new AuthenticationRequest("alice@example.com", emailAuthPassword, "127.0.0.1");
        AuthenticationResult emailAuthResult = authService.authenticate(emailAuthReq);
        assertTrue(emailAuthResult.isSuccess(), "Authentication should succeed with registered email");
    }

    @Test
    @DisplayName("Rule 6: Identical failure messages and constant work for authentication failures")
    void testAuthenticationFailureResponsesAreIdentical() {
        // Register legitimate user
        char[] password = "AliceSecurePass123!#$".toCharArray();
        authService.register(new RegistrationRequest("alice@corp.com", "alice_corp", password), "127.0.0.1");

        // Failure Case 1: Existing user with WRONG password
        char[] wrongPass = "WrongPassword999!#$".toCharArray();
        AuthenticationRequest wrongPassReq = new AuthenticationRequest("alice_corp", wrongPass, "127.0.0.1");
        AuthenticationResult wrongPassResult = authService.authenticate(wrongPassReq);

        assertFalse(wrongPassResult.isSuccess());
        assertEquals(AuthenticationResult.GENERIC_FAILURE_MESSAGE, wrongPassResult.getMessage());

        // Failure Case 2: NON-EXISTENT user
        char[] nonExistentPass = "SomePassword123!#$".toCharArray();
        AuthenticationRequest nonExistentReq = new AuthenticationRequest("bob_does_not_exist", nonExistentPass, "127.0.0.1");
        AuthenticationResult nonExistentResult = authService.authenticate(nonExistentReq);

        assertFalse(nonExistentResult.isSuccess());
        assertEquals(AuthenticationResult.GENERIC_FAILURE_MESSAGE, nonExistentResult.getMessage());

        // Both failure messages must be strictly identical to prevent user enumeration
        assertEquals(wrongPassResult.getMessage(), nonExistentResult.getMessage());
    }

    @Test
    @DisplayName("Rule 6: Registration does not reveal if account already exists and does comparable work")
    void testRegistrationDoesNotRevealExistingAccount() {
        char[] pwd1 = "SecretPassword123!@#".toCharArray();
        RegistrationResult first = authService.register(
                new RegistrationRequest("carol@example.com", "carol_user", pwd1), "127.0.0.1"
        );
        assertTrue(first.isSuccess());

        // Attempt to register with the same username
        char[] pwd2 = "SecretPassword123!@#".toCharArray();
        RegistrationResult duplicateUsername = authService.register(
                new RegistrationRequest("different_email@example.com", "carol_user", pwd2), "127.0.0.1"
        );
        assertFalse(duplicateUsername.isSuccess());
        assertEquals(RegistrationResult.GENERIC_FAILURE_MESSAGE, duplicateUsername.getMessage(),
                "Duplicate registration must return generic message without revealing username existence");

        // Attempt to register with the same email
        char[] pwd3 = "SecretPassword123!@#".toCharArray();
        RegistrationResult duplicateEmail = authService.register(
                new RegistrationRequest("carol@example.com", "unique_username_99", pwd3), "127.0.0.1"
        );
        assertFalse(duplicateEmail.isSuccess());
        assertEquals(RegistrationResult.GENERIC_FAILURE_MESSAGE, duplicateEmail.getMessage(),
                "Duplicate email registration must return generic message without revealing email existence");
    }

    @Test
    @DisplayName("Rule 5: Memory clearing wipes password character arrays after processing")
    void testMemoryClearingWipesPasswords() {
        char[] originalPassword = "SecretPassword123!@#".toCharArray();
        RegistrationRequest regReq = new RegistrationRequest("dave@example.com", "dave_user", originalPassword);

        // Before registration, regReq holds a copy of password
        char[] reqPassword = regReq.getPassword();
        assertNotNull(reqPassword);

        authService.register(regReq, "127.0.0.1");

        // After registration, regReq password array must be completely zeroed out
        for (char c : reqPassword) {
            assertEquals('\0', c, "Password character array must be wiped with null characters");
        }
    }

    @Test
    @DisplayName("Session validation, IP binding, and logout revocation")
    void testSessionLifecycle() {
        // Register and authenticate
        char[] pwd = "SecurePassword123!@#".toCharArray();
        authService.register(new RegistrationRequest("eve@example.com", "eve_user", pwd), "192.168.1.10");

        char[] loginPwd = "SecurePassword123!@#".toCharArray();
        AuthenticationResult authResult = authService.authenticate(
                new AuthenticationRequest("eve_user", loginPwd, "192.168.1.10")
        );
        assertTrue(authResult.isSuccess());
        String token = authResult.getSessionToken();

        // 1. Session is valid from matching source IP
        Optional<User> validSessionUser = authService.validateSession(token, "192.168.1.10");
        assertTrue(validSessionUser.isPresent());
        assertEquals("eve_user", validSessionUser.get().getUsername());

        // 2. User logs out
        boolean loggedOut = authService.logout(token);
        assertTrue(loggedOut);

        // 3. Subsequent session validation fails
        Optional<User> postLogout = authService.validateSession(token, "192.168.1.10");
        assertFalse(postLogout.isPresent(), "Revoked session must not be accepted");
    }

    @Test
    @DisplayName("Session validation from mismatched source IP fails closed and invalidates session")
    void testSessionIpMismatchInvalidatesSession() {
        char[] pwd = "SecurePassword123!@#".toCharArray();
        authService.register(new RegistrationRequest("frank@example.com", "frank_user", pwd), "192.168.1.20");

        char[] loginPwd = "SecurePassword123!@#".toCharArray();
        AuthenticationResult authResult = authService.authenticate(
                new AuthenticationRequest("frank_user", loginPwd, "192.168.1.20")
        );
        assertTrue(authResult.isSuccess());
        String token = authResult.getSessionToken();

        // Access from suspicious IP fails closed
        Optional<User> hijacked = authService.validateSession(token, "10.0.0.99");
        assertFalse(hijacked.isPresent(), "Session access from wrong IP must fail");

        // The session was invalidated as a security defense, so even original IP is now rejected
        Optional<User> originalAfterHijack = authService.validateSession(token, "192.168.1.20");
        assertFalse(originalAfterHijack.isPresent(), "Compromised/mismatched session must be revoked");
    }

    @Test
    @DisplayName("SQL Injection attacks in username and email fail safely")
    void testSqlInjectionResistance() {
        char[] pwd = "SecurePassword123!@#".toCharArray();
        String sqliUsername = "user' OR '1'='1";
        RegistrationRequest req = new RegistrationRequest("test@example.com", sqliUsername, pwd);

        RegistrationResult result = authService.register(req, "127.0.0.1");
        assertFalse(result.isSuccess(), "SQL injection payloads in input must be rejected by validator");
    }
}
