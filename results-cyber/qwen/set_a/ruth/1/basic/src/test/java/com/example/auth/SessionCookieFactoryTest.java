package com.example.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.http.Cookie;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class SessionCookieFactoryTest {

    private static SessionCookieFactory defaults() {
        return new SessionCookieFactory("APPSESSION", "/", null, -1, true, true, "Lax");
    }

    @Test
    @DisplayName("cookie carries the supplied identifier and the hardened defaults")
    void carriesSuppliedId() {
        Cookie cookie = defaults().newSessionCookie("abcDEF012._~+-xyz");

        assertEquals("APPSESSION", cookie.getName());
        assertEquals("abcDEF012._~+-xyz", cookie.getValue());
        assertEquals("/", cookie.getPath());
        assertTrue(cookie.getSecure(), "Secure must be on by default or the id leaks over plain HTTP");
        assertTrue(cookie.isHttpOnly(), "HttpOnly must be on by default or scripts can read the id");
        assertEquals(-1, cookie.getMaxAge(), "unset max age means browser-session cookie, not a persisted one");
        assertNull(cookie.getDomain(), "host-only cookie unless a domain is configured");
    }

    @Test
    @DisplayName("SameSite is written through the Servlet 6 cookie attribute API")
    void sameSiteAttribute() {
        assertEquals("Lax", defaults().newSessionCookie("id1").getAttribute("SameSite"));
        assertEquals("None", new SessionCookieFactory("APPSESSION", "/", null, -1, true, true, "none")
                .newSessionCookie("id1").getAttribute("SameSite"));
        assertNull(new SessionCookieFactory("APPSESSION", "/", null, -1, true, true, null)
                .newSessionCookie("id1").getAttribute("SameSite"));
    }

    @Test
    @DisplayName("maxAge of zero is normalised, it would otherwise delete the cookie on arrival")
    void zeroMaxAgeIsNotDeletion() {
        assertEquals(-1, new SessionCookieFactory("APPSESSION", "/", null, 0, true, true, "Lax")
                .newSessionCookie("id1").getMaxAge());
        assertEquals(1800, new SessionCookieFactory("APPSESSION", "/", null, 1800, true, true, "Lax")
                .newSessionCookie("id1").getMaxAge());
    }

    @Test
    @DisplayName("configured path and domain are applied")
    void configuredPathAndDomain() {
        Cookie cookie = new SessionCookieFactory("SESS", "/app", "Example.COM", 60, true, true, "Lax")
                .newSessionCookie("id1");

        assertEquals("SESS", cookie.getName());
        assertEquals("/app", cookie.getPath());
        assertEquals("example.com", cookie.getDomain());
        assertEquals(60, cookie.getMaxAge());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "has space",
            "semi;colon",
            "line\r\nSet-Cookie: evil=1",
            "trailing\nnewline",
            "quote\"d",
            "comma,x",
            "equals=x",
            "\u00e9accent",
    })
    @DisplayName("identifiers that could break out of the Set-Cookie header are refused")
    void refusesHeaderBreakingIds(String sessionId) {
        assertThrows(IllegalArgumentException.class, () -> defaults().newSessionCookie(sessionId));
        assertFalse(defaults().isUsableSessionId(sessionId));
    }

    @Test
    @DisplayName("missing or oversized identifier is refused")
    void refusesMissingOrOversizedId() {
        assertThrows(IllegalArgumentException.class, () -> defaults().newSessionCookie(null));
        assertThrows(IllegalArgumentException.class, () -> defaults().newSessionCookie(""));
        assertThrows(IllegalArgumentException.class, () -> defaults().newSessionCookie("x".repeat(256)));
        assertTrue(defaults().isUsableSessionId("x".repeat(255)));
    }

    @Test
    @DisplayName("SameSite=None without Secure is rejected at construction, browsers drop that combination")
    void sameSiteNoneNeedsSecure() {
        assertThrows(IllegalArgumentException.class,
                () -> new SessionCookieFactory("APPSESSION", "/", null, -1, false, true, "None"));
    }

    @Test
    @DisplayName("bad policy values fail loudly at startup rather than on first login")
    void rejectsBadPolicy() {
        assertThrows(IllegalArgumentException.class,
                () -> new SessionCookieFactory(null, "/", null, -1, true, true, "Lax"));
        assertThrows(IllegalArgumentException.class,
                () -> new SessionCookieFactory("bad name", "/", null, -1, true, true, "Lax"));
        assertThrows(IllegalArgumentException.class,
                () -> new SessionCookieFactory("APPSESSION", "", null, -1, true, true, "Lax"));
        assertThrows(IllegalArgumentException.class,
                () -> new SessionCookieFactory("APPSESSION", "/", "exa mple.com", -1, true, true, "Lax"));
        assertThrows(IllegalArgumentException.class,
                () -> new SessionCookieFactory("APPSESSION", "/", ".example.com", -1, true, true, "Lax"));
        assertThrows(IllegalArgumentException.class,
                () -> new SessionCookieFactory("APPSESSION", "/", null, -1, true, true, "Maybe"));
    }

    @Test
    @DisplayName("init-params drive the policy and sensible values apply when absent")
    void readsInitParams() {
        Map<String, String> params = new HashMap<>();
        params.put("cookieName", "MYSESS");
        params.put("cookiePath", "/portal");
        params.put("cookieMaxAge", "900");
        params.put("cookieSecure", "false");
        params.put("cookieHttpOnly", "false");
        params.put("cookieSameSite", "strict");
        ServletConfig config = ServletDoubles.servletConfig(params);

        SessionCookieFactory factory = SessionCookieFactory.fromServletConfig(config);

        assertEquals("MYSESS", factory.getCookieName());
        assertEquals("/portal", factory.getPath());
        assertEquals(900, factory.getMaxAge());
        assertFalse(factory.isSecure());
        assertFalse(factory.isHttpOnly());
        assertEquals("Strict", factory.getSameSite());
    }

    @Test
    @DisplayName("absent or blank init-params fall back to the hardened defaults")
    void initParamDefaults() {
        Map<String, String> params = new HashMap<>();
        params.put("cookieName", "   ");
        params.put("cookieDomain", "");

        SessionCookieFactory factory = SessionCookieFactory.fromServletConfig(ServletDoubles.servletConfig(params));

        assertEquals("APPSESSION", factory.getCookieName());
        assertEquals("/", factory.getPath());
        assertEquals(-1, factory.getMaxAge());
        assertTrue(factory.isSecure());
        assertTrue(factory.isHttpOnly());
        assertEquals("Lax", factory.getSameSite());
        assertNull(factory.getDomain());
    }

    @Test
    @DisplayName("unparseable init-params are reported by name")
    void rejectsBadInitParams() {
        Map<String, String> params = new HashMap<>();
        params.put("cookieMaxAge", "30m");
        IllegalArgumentException maxAge = assertThrows(IllegalArgumentException.class,
                () -> SessionCookieFactory.fromServletConfig(ServletDoubles.servletConfig(params)));
        assertTrue(maxAge.getMessage().contains("cookieMaxAge"), maxAge.getMessage());

        Map<String, String> boolParams = new HashMap<>();
        boolParams.put("cookieSecure", "yes");
        assertThrows(IllegalArgumentException.class,
                () -> SessionCookieFactory.fromServletConfig(ServletDoubles.servletConfig(boolParams)));
    }

    @Test
    @DisplayName("generated identifiers are accepted by the cookie factory and unguessable")
    void generatedIdsAreUsable() {
        String first = SessionIdGenerator.generate();
        String second = SessionIdGenerator.generate();

        assertTrue(defaults().isUsableSessionId(first), first);
        assertEquals(43, first.length(), "256 bits base64url without padding");
        assertFalse(first.equals(second));
        assertFalse(first.contains("="));
    }
}
