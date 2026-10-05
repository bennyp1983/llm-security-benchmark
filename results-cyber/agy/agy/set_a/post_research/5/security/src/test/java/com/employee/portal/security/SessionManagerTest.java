package com.employee.portal.security;

import com.employee.portal.security.config.SecurityConfig;
import com.employee.portal.security.crypto.SecureTokenGenerator;
import com.employee.portal.security.model.Session;
import com.employee.portal.security.session.SessionManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Paths;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Rule 4 & 5: Session Management, Token Entropy, and Timeout Tests")
class SessionManagerTest {

    private AtomicLong mockTime;
    private SecurityConfig config;
    private SessionManager sessionManager;

    @BeforeEach
    void setUp() {
        mockTime = new AtomicLong(1000000L);
        config = new SecurityConfig(
                5, 10,
                15 * 60_000L,
                15 * 60_000L,
                15 * 60_000L,  // 15 min idle timeout
                60 * 60_000L,  // 60 min absolute timeout
                2,             // Max 2 concurrent sessions per user
                100,
                100000,
                Paths.get("./test-data")
        );
        sessionManager = new SessionManager(config, new SecureTokenGenerator(), mockTime::get);
    }

    @Test
    void testCreateAndValidateSessionSuccess() {
        Session session = sessionManager.createSession("alice", "EMPLOYEE", "192.168.1.100");
        assertNotNull(session);
        assertNotNull(session.getSessionId());
        assertTrue(session.getSessionId().length() >= 43, "256-bit token in Base64URL should be >= 43 chars");

        Optional<Session> validated = sessionManager.validateSession(session.getSessionId(), "192.168.1.100");
        assertTrue(validated.isPresent());
        assertEquals("alice", validated.get().getUsername());
        assertEquals("EMPLOYEE", validated.get().getRole());
    }

    @Test
    void testSessionFailsClosedOnMissingOrInvalidToken() {
        assertFalse(sessionManager.validateSession("non-existent-token-that-matches-base64url-length-xxxx", "10.0.0.1").isPresent());
        assertFalse(sessionManager.validateSession(null, "10.0.0.1").isPresent());
        assertFalse(sessionManager.validateSession("short", "10.0.0.1").isPresent());
    }

    @Test
    void testSessionFailsAndRevokesOnIpMismatch() {
        Session session = sessionManager.createSession("bob", "EMPLOYEE", "192.168.1.50");

        // Attempting to access session from a different IP indicates session hijacking
        Optional<Session> hijacked = sessionManager.validateSession(session.getSessionId(), "203.0.113.99");
        assertFalse(hijacked.isPresent(), "Session must fail when accessed from unexpected IP");

        // The session must be revoked
        Optional<Session> recheck = sessionManager.validateSession(session.getSessionId(), "192.168.1.50");
        assertFalse(recheck.isPresent(), "Hijacked session must be revoked immediately");
    }

    @Test
    void testIdleTimeoutExpiresSession() {
        Session session = sessionManager.createSession("charlie", "EMPLOYEE", "10.0.0.1");

        // Advance 10 minutes (less than 15 min idle)
        mockTime.addAndGet(10 * 60_000L);
        assertTrue(sessionManager.validateSession(session.getSessionId(), "10.0.0.1").isPresent());

        // Advance another 16 minutes without activity (exceeds 15 min idle timeout)
        mockTime.addAndGet(16 * 60_000L);
        assertFalse(sessionManager.validateSession(session.getSessionId(), "10.0.0.1").isPresent());
    }

    @Test
    void testAbsoluteTimeoutExpiresSessionEvenWithActivity() {
        Session session = sessionManager.createSession("david", "EMPLOYEE", "10.0.0.1");

        // Touch every 10 minutes for 70 minutes (exceeds 60 min absolute timeout)
        for (int i = 0; i < 7; i++) {
            mockTime.addAndGet(10 * 60_000L);
            sessionManager.validateSession(session.getSessionId(), "10.0.0.1");
        }

        // Must be expired because total lifetime exceeded 60 minutes
        assertFalse(sessionManager.validateSession(session.getSessionId(), "10.0.0.1").isPresent());
    }

    @Test
    void testMaxConcurrentSessionsPerUserEvictsOldest() {
        Session s1 = sessionManager.createSession("alice", "EMPLOYEE", "10.0.0.1");
        mockTime.addAndGet(1000L);
        Session s2 = sessionManager.createSession("alice", "EMPLOYEE", "10.0.0.2");
        mockTime.addAndGet(1000L);

        // Max is 2: creating s3 must evict s1 (oldest)
        Session s3 = sessionManager.createSession("alice", "EMPLOYEE", "10.0.0.3");

        assertFalse(sessionManager.validateSession(s1.getSessionId(), "10.0.0.1").isPresent(), "s1 must be evicted");
        assertTrue(sessionManager.validateSession(s2.getSessionId(), "10.0.0.2").isPresent(), "s2 must remain");
        assertTrue(sessionManager.validateSession(s3.getSessionId(), "10.0.0.3").isPresent(), "s3 must remain");
    }

    @Test
    void testSessionToStringDoesNotExposeFullToken() {
        Session session = sessionManager.createSession("alice", "EMPLOYEE", "10.0.0.1");
        String str = session.toString();
        assertFalse(str.contains(session.getSessionId()), "Session.toString() must never expose full token");
        assertTrue(str.contains("..."));
    }
}
