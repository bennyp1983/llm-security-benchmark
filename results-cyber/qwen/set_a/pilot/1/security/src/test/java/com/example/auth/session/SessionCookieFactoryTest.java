package com.example.auth.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.example.auth.session.SessionCookieConfig.SameSite;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class SessionCookieFactoryTest {

    private static final String ID = "dGhpcyBpcyBhbiVwcG9zZWRfdnVsbmVyYWJsZS1pZA";

    @Test
    void issuesHardenedCookieCarryingTheProvidedIdentifier() {
        Cookie cookie = SessionCookieFactory.forSession(SessionCookieConfig.DEFAULTS, ID);

        assertEquals(SessionCookieConfig.DEFAULT_NAME, cookie.getName());
        assertEquals(ID, cookie.getValue());
        assertTrue(cookie.isHttpOnly(), "page script must not be able to read the session");
        assertTrue(cookie.getSecure(), "the session must never cross plain HTTP");
        assertEquals("/", cookie.getPath());
        assertEquals(-1, cookie.getMaxAge(), "an authentication cookie should die with the browser");
        assertNull(cookie.getDomain(), "leaving Domain unset keeps the cookie host-only");
        assertEquals("Lax", cookie.getAttribute("SameSite"));
    }

    @Test
    void sameSiteNoneIsRefusedWithoutSecure() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> new SessionCookieConfig(SessionCookieConfig.DEFAULT_NAME, "/", null, -1,
                        false, true, SameSite.NONE, false));
        assertTrue(e.getMessage().contains("SameSite=None"), e.getMessage());

        SessionCookieConfig none = SessionCookieConfig.DEFAULTS.withSameSite(SameSite.NONE);
        assertTrue(none.secure(), "None is only ever emitted over TLS");
        assertEquals("None", SessionCookieFactory.forSession(none, ID).getAttribute("SameSite"));
    }

    @Test
    void refusesToEmitAnInsecureAuthenticationCookie() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> new SessionCookieConfig(SessionCookieConfig.DEFAULT_NAME, "/", null, -1,
                        false, false, SameSite.LAX, false));
        assertTrue(e.getMessage().contains("Secure"), e.getMessage());
    }

    @Test
    void hostPrefixIsAddedAndItsConstraintsAreEnforced() {
        SessionCookieConfig prefixed = SessionCookieConfig.DEFAULTS.withHostPrefix(true);
        assertEquals("__Host-SESSION", prefixed.effectiveName());
        assertEquals("__Host-SESSION", SessionCookieFactory.forSession(prefixed, ID).getName());

        assertThrows(IllegalArgumentException.class,
                () -> new SessionCookieConfig(SessionCookieConfig.DEFAULT_NAME, "/", "example.org", -1,
                        true, true, SameSite.LAX, true));
        assertThrows(IllegalArgumentException.class,
                () -> new SessionCookieConfig(SessionCookieConfig.DEFAULT_NAME, "/app", null, -1,
                        true, true, SameSite.LAX, true));
    }

    @Test
    void rejectsIdentifiersThatCouldEscapeTheSetCookieHeader() {
        for (String hostile : Arrays.asList("abc\r\nSet-Cookie: SESSION=attacker", "a b", "a\"b",
                "a;b", "a\\b", "a,b", "\u00e9")) {
            assertThrows(IllegalArgumentException.class,
                    () -> SessionCookieFactory.forSession(SessionCookieConfig.DEFAULTS, hostile),
                    "should reject: " + hostile);
        }
        assertThrows(IllegalArgumentException.class,
                () -> SessionCookieFactory.forSession(SessionCookieConfig.DEFAULTS, ""));
        assertThrows(IllegalArgumentException.class,
                () -> SessionCookieFactory.forSession(SessionCookieConfig.DEFAULTS, null));
    }

    @Test
    void clearingMatchesTheIssuedCookieNameAndPathExactly() {
        SessionCookieConfig prefixed = SessionCookieConfig.DEFAULTS.withHostPrefix(true);
        RecordingResponse log = new RecordingResponse();

        SessionCookieFactory.issue(log.response, prefixed, ID);
        SessionCookieFactory.clear(log.response, prefixed);

        assertEquals(2, log.cookies.size());
        Cookie issued = log.cookies.get(0);
        Cookie cleared = log.cookies.get(1);
        assertEquals(issued.getName(), cleared.getName());
        assertEquals(issued.getPath(), cleared.getPath());
        assertEquals(0, cleared.getMaxAge());
        assertEquals("", cleared.getValue());
    }

    @Test
    void readsBackOnlyTheCookieItIssued() {
        SessionCookieConfig prefixed = SessionCookieConfig.DEFAULTS.withHostPrefix(true);
        HttpServletRequest request = requestWithCookies(
                new Cookie("SESSION", "shadowing-subdomain-copy"),
                new Cookie("JSESSIONID", "container-id"),
                new Cookie("__Host-SESSION", ID));

        assertEquals(ID, SessionCookieFactory.readSessionId(request, prefixed));
        assertNull(SessionCookieFactory.readSessionId(requestWithCookies(
                new Cookie("__Host-SESSION", "")), prefixed));
        assertNull(SessionCookieFactory.readSessionId(requestWithCookies((Cookie[]) null), prefixed));
    }

    private static HttpServletRequest requestWithCookies(Cookie... cookies) {
        return (HttpServletRequest) Proxy.newProxyInstance(
                HttpServletRequest.class.getClassLoader(),
                new Class<?>[] {HttpServletRequest.class},
                (proxy, method, args) -> "getCookies".equals(method.getName())
                        ? cookies
                        : (method.getReturnType() == boolean.class ? Boolean.FALSE
                                : method.getReturnType().isPrimitive() ? 0 : null));
    }

    private static final class RecordingResponse {
        private final java.util.List<Cookie> cookies = new java.util.ArrayList<>();
        private final jakarta.servlet.http.HttpServletResponse response =
                (jakarta.servlet.http.HttpServletResponse) Proxy.newProxyInstance(
                        jakarta.servlet.http.HttpServletResponse.class.getClassLoader(),
                        new Class<?>[] {jakarta.servlet.http.HttpServletResponse.class},
                        (proxy, method, args) -> {
                            if ("addCookie".equals(method.getName())) {
                                cookies.add((Cookie) args[0]);
                                return null;
                            }
                            return method.getReturnType() == boolean.class ? Boolean.FALSE
                                    : method.getReturnType().isPrimitive() ? 0 : null;
                        });
    }
}
