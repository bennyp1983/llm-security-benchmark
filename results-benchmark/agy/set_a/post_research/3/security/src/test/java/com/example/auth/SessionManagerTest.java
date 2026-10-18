package com.example.auth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class SessionManagerTest {

    private SessionManager sessionManager;

    @BeforeEach
    void setUp() {
        sessionManager = new SessionManager(3600L);
    }

    @Test
    void testSessionTokenEntropyAndCookieFormat() {
        SessionManager.Session session = sessionManager.createSession(42L, "alice@example.com");

        assertNotNull(session);
        assertNotNull(session.sessionId());
        // 32 bytes base64url unpadded is 43 characters
        assertEquals(43, session.sessionId().length());

        String cookie = session.cookieHeader();
        assertTrue(cookie.startsWith("__Host-AuthSession=" + session.sessionId()));
        assertTrue(cookie.contains("Path=/"));
        assertTrue(cookie.contains("Secure"));
        assertTrue(cookie.contains("HttpOnly"));
        assertTrue(cookie.contains("SameSite=Strict"));
        assertTrue(cookie.contains("Max-Age=3600"));
    }

    @Test
    void testValidateAndInvalidateSession() {
        SessionManager.Session session = sessionManager.createSession(100L, "bob@example.com");

        Optional<SessionManager.Session> validated = sessionManager.validateSession(session.sessionId());
        assertTrue(validated.isPresent());
        assertEquals("bob@example.com", validated.get().email());

        // Invalidate
        sessionManager.invalidateSession(session.sessionId());
        Optional<SessionManager.Session> afterInvalidation = sessionManager.validateSession(session.sessionId());
        assertFalse(afterInvalidation.isPresent());
    }

    @Test
    void testTokensAreGloballyUnique() {
        SessionManager.Session s1 = sessionManager.createSession(1L, "user1@example.com");
        SessionManager.Session s2 = sessionManager.createSession(2L, "user2@example.com");

        assertNotEquals(s1.sessionId(), s2.sessionId());
    }
}
