package com.example.auth.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.example.auth.session.InMemorySessionRegistry;
import com.example.auth.session.SessionCookieConfig;
import jakarta.servlet.http.Cookie;
import java.io.IOException;
import java.time.Duration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class LogoutServletTest {

    private static final String ID = "c2Vzc2lvbi10aGF0LXdpbGwtYmUtZ29uZQ";

    private InMemorySessionRegistry registry;
    private SessionCookieConfig config;
    private LogoutServlet servlet;
    private ServletFakes.ResponseLog log;
    private ServletFakes.RequestStub stub;

    @BeforeEach
    void setUp() {
        registry = new InMemorySessionRegistry();
        config = SessionCookieConfig.DEFAULTS;
        servlet = new LogoutServlet(registry, config);
        log = new ServletFakes.ResponseLog();
        stub = new ServletFakes.RequestStub();
        registry.register(ID, "user-42", Duration.ofMinutes(30));
    }

    @Test
    void dropsTheServerSideSessionAndExpiresTheCookie() throws IOException {
        stub.cookies = new Cookie[] {new Cookie(SessionCookieConfig.DEFAULT_NAME, ID)};

        servlet.doPost(stub.toRequest(), ServletFakes.response(log));

        assertNull(registry.find(ID), "an expired cookie must not leave a live session behind");
        assertEquals(204, log.status);
        Cookie cleared = log.cookiesNamed(SessionCookieConfig.DEFAULT_NAME).get(0);
        assertEquals(0, cleared.getMaxAge());
        assertEquals("/", cleared.getPath());
        assertEquals("no-store", log.headers.get("Cache-Control"));
    }

    @Test
    void stillExpiresTheCookieWhenTheSessionIsAlreadyGone() throws IOException {
        stub.cookies = new Cookie[] {new Cookie(SessionCookieConfig.DEFAULT_NAME, "unknown-id")};

        servlet.doPost(stub.toRequest(), ServletFakes.response(log));

        assertEquals(204, log.status);
        assertNotNull(log.cookiesNamed(SessionCookieConfig.DEFAULT_NAME).get(0));
        assertNotNull(registry.find(ID), "logout must only remove the session it was authenticated as");
    }

    @Test
    void logoutIsPostOnly() throws IOException {
        servlet.doGet(stub.toRequest(), ServletFakes.response(log));

        assertEquals(405, log.status);
        assertEquals("POST", log.headers.get("Allow"));
    }
}
