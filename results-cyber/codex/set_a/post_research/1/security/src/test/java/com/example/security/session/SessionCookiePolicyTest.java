package com.example.security.session;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SessionCookiePolicyTest {
    private static final String VALID = "0123456789abcdefghijklmnopqrstuvwxyz_AB-CDE";

    @Test
    void acceptsOnlyOneExactBase64UrlShape() {
        assertEquals(43, VALID.length());
        assertTrue(SessionCookiePolicy.isValidSessionId(VALID));
        assertFalse(SessionCookiePolicy.isValidSessionId(null));
        assertFalse(SessionCookiePolicy.isValidSessionId("short"));
        assertFalse(SessionCookiePolicy.isValidSessionId(VALID.substring(0, 42) + ";"));
        assertFalse(SessionCookiePolicy.isValidSessionId(SessionCookiePolicy.DUMMY_SESSION_ID));
    }

    @Test
    void validatesOnlyLiteralIpAddressCharactersForSourceKey() {
        assertTrue(SessionCookiePolicy.isValidSourceKey("192.0.2.10"));
        assertTrue(SessionCookiePolicy.isValidSourceKey("2001:db8::1"));
        assertFalse(SessionCookiePolicy.isValidSourceKey("client.example"));
        assertFalse(SessionCookiePolicy.isValidSourceKey("1.2.3.4\r\nforged"));
    }

    @Test
    void createsHostOnlySecureSessionCookie() {
        Cookie cookie = SessionCookiePolicy.sessionCookie(VALID);
        assertEquals("__Host-session", cookie.getName());
        assertEquals(VALID, cookie.getValue());
        assertTrue(cookie.isHttpOnly());
        assertTrue(cookie.getSecure());
        assertEquals("/", cookie.getPath());
        assertNull(cookie.getDomain());
        assertEquals("Strict", cookie.getAttribute("SameSite"));
        assertEquals(-1, cookie.getMaxAge());
    }

    @Test
    void deletionCookieHasIdenticalScopeAndImmediateExpiry() {
        Cookie cookie = SessionCookiePolicy.deletionCookie();
        assertEquals("", cookie.getValue());
        assertEquals(0, cookie.getMaxAge());
        assertTrue(cookie.isHttpOnly());
        assertTrue(cookie.getSecure());
        assertEquals("/", cookie.getPath());
        assertEquals("Strict", cookie.getAttribute("SameSite"));
        assertNull(cookie.getDomain());
    }
}
