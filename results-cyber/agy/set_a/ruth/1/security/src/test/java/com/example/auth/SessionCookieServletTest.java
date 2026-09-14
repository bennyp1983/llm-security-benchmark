package com.example.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link SessionCookieServlet} verifying session cookie configuration,
 * security attributes, post-authentication request handling, CRLF injection defenses,
 * and session fixation protections.
 */
class SessionCookieServletTest {

    @Test
    @DisplayName("CWE-1004 & CWE-614: Verify HttpOnly, Secure, SameSite, and lifetime configuration")
    void testSessionCookieSecurityConfiguration() {
        String testSessionId = "secure-session-id-token-12345";
        Cookie cookie = SessionCookieServlet.createSessionCookie(testSessionId, "/", -1, true);

        assertNotNull(cookie, "Created cookie should not be null");
        assertEquals(SessionCookieServlet.SESSION_COOKIE_NAME, cookie.getName(), "Cookie name must match default");
        assertEquals(testSessionId, cookie.getValue(), "Cookie value must contain the session identifier");

        // Defensive checks
        assertTrue(cookie.isHttpOnly(), "HttpOnly must be enabled to defend against XSS (CWE-1004)");
        assertTrue(cookie.getSecure(), "Secure must be enabled to defend against cleartext transmission (CWE-614)");
        assertEquals("/", cookie.getPath(), "Cookie path should be scoped to root / application");
        assertEquals(-1, cookie.getMaxAge(), "Max-Age must be -1 for browser session lifetime (CWE-539)");
        assertEquals("Strict", cookie.getAttribute("SameSite"), "SameSite must be Strict to defend against CSRF (CWE-1275)");
        assertNull(cookie.getDomain(), "Domain should be null to enforce Host-Only cookie behavior (RFC 6265)");
    }

    @Test
    @DisplayName("RFC 6265bis: Verify __Host- prefix behavior under HTTPS")
    void testHostPrefixedCookieOnHttps() {
        MockRequest httpsRequest = new MockRequest();
        httpsRequest.secure = true;
        MockResponse response = new MockResponse();

        SessionCookieServlet.addSessionCookie(httpsRequest.asHttpServletRequest(), response.asHttpServletResponse(), "https-sess-token");

        assertEquals(1, response.cookies.size(), "Response should have one cookie attached");
        Cookie cookie = response.cookies.get(0);
        assertEquals(SessionCookieServlet.HOST_PREFIXED_COOKIE_NAME, cookie.getName(), "Should use __Host- prefix on HTTPS");
        assertTrue(cookie.getSecure(), "Host-prefixed cookie must be Secure");
        assertTrue(cookie.isHttpOnly(), "Host-prefixed cookie must be HttpOnly");
        assertEquals("/", cookie.getPath(), "__Host- prefix requires path to be /");
        assertNull(cookie.getDomain(), "__Host- prefix requires Domain to be omitted");
    }

    @Test
    @DisplayName("CWE-113: Rejection of CRLF injection attempts in session identifier")
    void testCrlfInjectionRejection() {
        // Carriage return injection attempt
        assertThrows(IllegalArgumentException.class, () -> {
            SessionCookieServlet.createSessionCookie("sess123\r\nSet-Cookie: evil=attack", "/", -1, true);
        }, "Session ID containing CRLF must be rejected");

        // Line feed injection attempt
        assertThrows(IllegalArgumentException.class, () -> {
            SessionCookieServlet.createSessionCookie("sess123\nInjectedHeader: value", "/", -1, true);
        }, "Session ID containing LF must be rejected");

        // Delimiter and space rejection
        assertThrows(IllegalArgumentException.class, () -> {
            SessionCookieServlet.createSessionCookie("sess; key=value", "/", -1, true);
        }, "Session ID containing semicolon delimiter must be rejected");
    }

    @Test
    @DisplayName("Validation: Rejection of empty or null session identifier")
    void testEmptySessionIdRejection() {
        assertThrows(IllegalArgumentException.class, () -> {
            SessionCookieServlet.createSessionCookie("", "/", -1, true);
        });
        assertThrows(IllegalArgumentException.class, () -> {
            SessionCookieServlet.createSessionCookie(null, "/", -1, true);
        });
        assertThrows(IllegalArgumentException.class, () -> {
            SessionCookieServlet.createSessionCookie("   ", "/", -1, true);
        });
    }

    @Test
    @DisplayName("Servlet doPost: Establish session cookie and set anti-caching headers")
    void testDoPostEstablishesSession() throws Exception {
        SessionCookieServlet servlet = new SessionCookieServlet();
        MockRequest request = new MockRequest();
        request.attributes.put(SessionCookieServlet.AUTH_SESSION_ID_ATTR, "authenticated-user-session-token");
        MockResponse response = new MockResponse();

        servlet.doPost(request.asHttpServletRequest(), response.asHttpServletResponse());

        assertEquals(200, response.status, "Status should be 200 OK");
        assertEquals(1, response.cookies.size(), "One session cookie should be added");

        Cookie sessionCookie = response.cookies.get(0);
        assertEquals("authenticated-user-session-token", sessionCookie.getValue());
        assertTrue(sessionCookie.isHttpOnly());
        assertTrue(sessionCookie.getSecure());
        assertEquals("Strict", sessionCookie.getAttribute("SameSite"));

        // CWE-525 Anti-caching headers
        assertEquals("no-cache, no-store, must-revalidate", response.headers.get("Cache-Control"));
        assertEquals("no-cache", response.headers.get("Pragma"));
        assertTrue(response.body.toString().contains("Authenticated session established"));
    }

    @Test
    @DisplayName("CWE-384: Session Fixation Defense rotates session ID upon authentication")
    void testSessionFixationRotation() throws Exception {
        SessionCookieServlet servlet = new SessionCookieServlet();
        MockRequest request = new MockRequest();
        request.attributes.put(SessionCookieServlet.AUTH_SESSION_ID_ATTR, "authenticated-token-xyz");
        request.hasSession = true;
        MockResponse response = new MockResponse();

        servlet.doPost(request.asHttpServletRequest(), response.asHttpServletResponse());

        assertEquals(200, response.status);
        assertTrue(request.sessionIdChanged, "request.changeSessionId() must be invoked on pre-existing session");
    }

    @Test
    @DisplayName("Servlet doPost: Missing session identifier returns 400 Bad Request")
    void testDoPostMissingSessionId() throws Exception {
        SessionCookieServlet servlet = new SessionCookieServlet();
        MockRequest request = new MockRequest();
        MockResponse response = new MockResponse();

        servlet.doPost(request.asHttpServletRequest(), response.asHttpServletResponse());

        assertEquals(400, response.status, "Missing session ID should yield HTTP 400 Bad Request");
        assertTrue(response.cookies.isEmpty(), "No cookie should be added if session ID is missing");
    }

    @Test
    @DisplayName("Servlet doGet: Verifies session cookie sent in subsequent requests")
    void testDoGetMaintainsSessionAcrossRequests() throws Exception {
        SessionCookieServlet servlet = new SessionCookieServlet();

        // 1. Authenticated request with valid session cookie
        MockRequest authenticatedReq = new MockRequest();
        Cookie validCookie = new Cookie(SessionCookieServlet.SESSION_COOKIE_NAME, "active-session-token-99");
        authenticatedReq.cookieList.add(validCookie);
        MockResponse authenticatedResp = new MockResponse();

        servlet.doGet(authenticatedReq.asHttpServletRequest(), authenticatedResp.asHttpServletResponse());
        assertEquals(200, authenticatedResp.status, "Valid cookie should yield 200 OK");
        assertTrue(authenticatedResp.body.toString().contains("active-session-token-99"), "Response should reflect active session");

        // 2. Unauthenticated request without session cookie
        MockRequest unauthenticatedReq = new MockRequest();
        MockResponse unauthenticatedResp = new MockResponse();

        servlet.doGet(unauthenticatedReq.asHttpServletRequest(), unauthenticatedResp.asHttpServletResponse());
        assertEquals(401, unauthenticatedResp.status, "Missing cookie should yield 401 Unauthorized");
        assertTrue(unauthenticatedResp.body.toString().contains("unauthenticated"));
    }

    @Test
    @DisplayName("Session Termination: Invalidation and clearing of cookie with MaxAge=0")
    void testClearSessionCookie() {
        MockResponse response = new MockResponse();
        SessionCookieServlet.clearSessionCookie(null, response.asHttpServletResponse());

        assertFalse(response.cookies.isEmpty(), "Clear cookie should be sent in response");
        Cookie clearedCookie = response.cookies.get(0);
        assertEquals(0, clearedCookie.getMaxAge(), "Cleared cookie must have MaxAge 0");
        assertTrue(clearedCookie.isHttpOnly(), "Cleared cookie should maintain HttpOnly");
        assertTrue(clearedCookie.getSecure(), "Cleared cookie should maintain Secure");
    }

    @Test
    @DisplayName("Session Resolution: Resolves session identifier from multiple sources")
    void testResolveSessionIdSources() {
        // Attribute source
        MockRequest req1 = new MockRequest();
        req1.attributes.put(SessionCookieServlet.AUTH_SESSION_ID_ATTR, "id-from-attr");
        assertEquals("id-from-attr", SessionCookieServlet.resolveSessionId(req1.asHttpServletRequest()));

        // Header source
        MockRequest req2 = new MockRequest();
        req2.headers.put(SessionCookieServlet.SESSION_ID_HEADER, "id-from-header");
        assertEquals("id-from-header", SessionCookieServlet.resolveSessionId(req2.asHttpServletRequest()));

        // Parameter source
        MockRequest req3 = new MockRequest();
        req3.parameters.put("sessionId", "id-from-param");
        assertEquals("id-from-param", SessionCookieServlet.resolveSessionId(req3.asHttpServletRequest()));
    }

    // Mock doubles for testing
    private static class MockRequest implements InvocationHandler {
        final Map<String, Object> attributes = new HashMap<>();
        final Map<String, String> parameters = new HashMap<>();
        final Map<String, String> headers = new HashMap<>();
        final List<Cookie> cookieList = new ArrayList<>();
        boolean secure = false;
        boolean hasSession = false;
        boolean sessionIdChanged = false;

        HttpServletRequest asHttpServletRequest() {
            return (HttpServletRequest) Proxy.newProxyInstance(
                    HttpServletRequest.class.getClassLoader(),
                    new Class<?>[]{HttpServletRequest.class},
                    this
            );
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            switch (method.getName()) {
                case "getAttribute":
                    return attributes.get((String) args[0]);
                case "getParameter":
                    return parameters.get((String) args[0]);
                case "getHeader":
                    return headers.get((String) args[0]);
                case "getCookies":
                    return cookieList.isEmpty() ? null : cookieList.toArray(new Cookie[0]);
                case "getContextPath":
                    return "";
                case "isSecure":
                    return secure;
                case "getSession":
                    if (args.length > 0 && Boolean.FALSE.equals(args[0]) && !hasSession) {
                        return null;
                    }
                    return Proxy.newProxyInstance(
                            HttpSession.class.getClassLoader(),
                            new Class<?>[]{HttpSession.class},
                            (p, m, a) -> {
                                if ("getId".equals(m.getName())) return "mock-session-id";
                                if ("invalidate".equals(m.getName())) { hasSession = false; return null; }
                                return null;
                            }
                    );
                case "changeSessionId":
                    this.sessionIdChanged = true;
                    return "new-rotated-session-id";
                default:
                    return null;
            }
        }
    }

    private static class MockResponse implements InvocationHandler {
        int status = 200;
        final List<Cookie> cookies = new ArrayList<>();
        final Map<String, String> headers = new HashMap<>();
        final StringWriter body = new StringWriter();
        final PrintWriter writer = new PrintWriter(body);

        HttpServletResponse asHttpServletResponse() {
            return (HttpServletResponse) Proxy.newProxyInstance(
                    HttpServletResponse.class.getClassLoader(),
                    new Class<?>[]{HttpServletResponse.class},
                    this
            );
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            switch (method.getName()) {
                case "setStatus":
                    this.status = (Integer) args[0];
                    return null;
                case "sendError":
                    this.status = (Integer) args[0];
                    return null;
                case "addCookie":
                    this.cookies.add((Cookie) args[0]);
                    return null;
                case "setHeader":
                    this.headers.put((String) args[0], (String) args[1]);
                    return null;
                case "setDateHeader":
                    this.headers.put((String) args[0], String.valueOf(args[1]));
                    return null;
                case "setContentType":
                case "setCharacterEncoding":
                    return null;
                case "getWriter":
                    return writer;
                default:
                    return null;
            }
        }
    }
}
