package com.example.auth.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.example.auth.session.InMemorySessionRegistry;
import com.example.auth.session.SessionCookieConfig;
import com.example.auth.session.SessionRegistry;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class LoginServletTest {

    private static final String SUBJECT = "user-42";
    private static final String ID = "Zm9vYmFyLXNlc3Npb24taWRlbnRpZmllcg";

    private InMemorySessionRegistry registry;
    private SessionCookieConfig config;
    private LoginServlet servlet;
    private ServletFakes.ResponseLog log;
    private ServletFakes.RequestStub stub;

    @BeforeEach
    void setUp() {
        registry = new InMemorySessionRegistry();
        config = SessionCookieConfig.DEFAULTS;
        servlet = new LoginServlet(registry, config, Duration.ofMinutes(30));
        log = new ServletFakes.ResponseLog();
        stub = new ServletFakes.RequestStub();
    }

    @Test
    void addsHardenedSessionCookieAfterAuthentication() throws IOException {
        authenticated(ID);

        servlet.doPost(stub.toRequest(), ServletFakes.response(log));

        assertEquals(204, log.status);
        List<Cookie> cookies = log.cookiesNamed(SessionCookieConfig.DEFAULT_NAME);
        assertEquals(1, cookies.size());
        Cookie cookie = cookies.get(0);
        assertEquals(ID, cookie.getValue());
        assertTrue(cookie.isHttpOnly());
        assertTrue(cookie.getSecure());
        assertEquals("/", cookie.getPath());
        assertEquals(-1, cookie.getMaxAge());
        assertNull(cookie.getDomain());
        assertEquals("Lax", cookie.getAttribute("SameSite"));

        assertEquals("no-store", log.headers.get("Cache-Control"));
    }

    @Test
    void recordsTheSessionServerSideUnderTheProvidedIdentifier() throws IOException {
        authenticated(ID);

        servlet.doPost(stub.toRequest(), ServletFakes.response(log));

        SessionRegistry.Session session = registry.find(ID);
        assertNotNull(session, "the cookie has to point at a real server-side session");
        assertEquals(SUBJECT, session.subjectId());
        assertTrue(session.expiresAt().isAfter(Instant.now().plus(Duration.ofMinutes(29))));
    }

    @Test
    void keepsAuthenticatedStateOutOfTheContainerSession() throws IOException {
        authenticated(ID);

        servlet.doPost(stub.toRequest(), ServletFakes.response(log));

        assertFalse(stub.createSessionRequested, "auth state lives in the registry, not in an HttpSession");
    }

    @Test
    void honoursPerSessionLifetimeOverride() throws IOException {
        authenticated(ID);
        stub.attribute(AuthAttributes.SESSION_TTL, Duration.ofMinutes(5));

        servlet.doPost(stub.toRequest(), ServletFakes.response(log));

        Instant expiresAt = registry.find(ID).expiresAt();
        assertTrue(expiresAt.isBefore(Instant.now().plus(Duration.ofMinutes(6))));
        assertTrue(expiresAt.isAfter(Instant.now().plus(Duration.ofMinutes(4))));
    }

    @Test
    void refusesToIssueWhenAuthenticationPublishedNothing() throws IOException {
        servlet.doPost(stub.toRequest(), ServletFakes.response(log));

        assertEquals(401, log.status);
        assertFalse(log.sentActiveSessionCookie(), "only a cleared cookie may be sent");
        assertEquals("", log.cookies.get(0).getValue());
    }

    @Test
    void refusesToAdoptAnIdentifierTheClientAlreadyHad() throws IOException {
        // Session fixation: the attacker's id arrives in a cookie before the victim logs in.
        stub.requestedSessionId = ID;
        authenticated(ID);

        servlet.doPost(stub.toRequest(), ServletFakes.response(log));

        assertEquals(401, log.status);
        assertNull(registry.find(ID));
        assertFalse(log.sentActiveSessionCookie());
    }

    @Test
    void refusesIdentifiersThatArrivedInTheUrl() throws IOException {
        // jsessionid-style URL rewriting leaks identifiers into logs and Referer headers.
        stub.requestedSessionIdFromUrl = true;
        stub.requestedSessionId = ID;
        authenticated(ID);

        servlet.doPost(stub.toRequest(), ServletFakes.response(log));

        assertEquals(401, log.status);
        assertNull(registry.find(ID));
    }

    @Test
    void discardsTheContainerSessionThatPredatedAuthentication() throws IOException {
        ServletFakes.invalidatingSession(stub);
        authenticated(ID);

        servlet.doPost(stub.toRequest(), ServletFakes.response(log));

        assertTrue(stub.sessionInvalidated);
        assertEquals(204, log.status);
        assertEquals(ID, log.cookiesNamed(SessionCookieConfig.DEFAULT_NAME).get(0).getValue());
    }

    @Test
    void rejectsCookieConfigThatOutlivesTheServerSideSession() {
        LoginServlet misconfigured =
                new LoginServlet(registry, config.withMaxAgeSeconds(7200), Duration.ofMinutes(5));

        ServletException e = assertThrows(ServletException.class, misconfigured::init);
        assertTrue(e.getMessage().contains("Max-Age"), e.getMessage());
    }

    @Test
    void loginIsPostOnly() throws IOException {
        servlet.doGet(stub.toRequest(), ServletFakes.response(log));

        assertEquals(405, log.status);
        assertEquals("POST", log.headers.get("Allow"));
    }

    private void authenticated(String sessionId) {
        stub.attribute(AuthAttributes.SUBJECT_ID, SUBJECT);
        stub.attribute(AuthAttributes.SESSION_ID, sessionId);
    }
}
