package com.example.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

class SessionCookieIssuanceTest {

    private static final String SESSION_ID = "dG9rZW4tYWJjMTIz";

    @Test
    void isMappedWithoutWebXml() {
        WebServlet mapping = AuthenticatedSessionServlet.class.getAnnotation(WebServlet.class);
        assertNotNull(mapping);
        assertEquals("authenticatedSessionServlet", mapping.name());
        assertEquals("[/auth/session]", java.util.Arrays.toString(mapping.urlPatterns()));
    }

    @Test
    void publishesHardenedCookieAndAnswersWithNoContent() throws Exception {
        Outcome outcome = publish(Map.of(AuthenticatedSessionServlet.SESSION_ID_ATTRIBUTE, SESSION_ID), Map.of());

        assertEquals(204, outcome.status());
        assertFalse(outcome.errorReported());

        Cookie cookie = outcome.cookie();
        assertNotNull(cookie);
        assertEquals("APP_SESSION", cookie.getName());
        assertEquals(SESSION_ID, cookie.getValue());
        assertEquals("/", cookie.getPath());
        assertEquals(-1, cookie.getMaxAge());
        assertTrue(cookie.getSecure());
        assertTrue(cookie.isHttpOnly());
    }

    @Test
    void rejectsRequestWhereAuthenticationSuppliedNothing() throws Exception {
        Outcome absent = publish(Map.of(), Map.of());
        assertNull(absent.cookie());
        assertEquals(401, absent.errorStatus());

        Outcome blank = publish(Map.of(AuthenticatedSessionServlet.SESSION_ID_ATTRIBUTE, "   "), Map.of());
        assertNull(blank.cookie());
        assertEquals(401, blank.errorStatus());
    }

    @ParameterizedTest
    @ValueSource(strings = {"abc; x=admin=1", "abc\r\nSet-Cookie: evil=1", "abc def", "abc\"x\"", " leading-space"})
    void refusesToPublishIdentifierThatIsNotACookieValue(String unusableSessionId) throws Exception {
        Outcome outcome = publish(
                Map.of(AuthenticatedSessionServlet.SESSION_ID_ATTRIBUTE, unusableSessionId), Map.of());
        assertNull(outcome.cookie());
        assertEquals(500, outcome.errorStatus());
    }

    @Test
    void honoursCookieInitParameters() throws Exception {
        Map<String, String> initParams = new HashMap<>();
        initParams.put(AuthenticatedSessionServlet.COOKIE_NAME_PARAM, "MY_SID");
        initParams.put(AuthenticatedSessionServlet.COOKIE_PATH_PARAM, "/api");
        initParams.put(AuthenticatedSessionServlet.COOKIE_MAX_AGE_PARAM, "1800");
        initParams.put(AuthenticatedSessionServlet.COOKIE_SECURE_PARAM, "false");

        Cookie cookie = publish(Map.of(AuthenticatedSessionServlet.SESSION_ID_ATTRIBUTE, SESSION_ID), initParams)
                .cookie();

        assertNotNull(cookie);
        assertEquals("MY_SID", cookie.getName());
        assertEquals(SESSION_ID, cookie.getValue());
        assertEquals("/api", cookie.getPath());
        assertEquals(1800, cookie.getMaxAge());
        assertFalse(cookie.getSecure());
        assertTrue(cookie.isHttpOnly());
    }

    @Test
    void rejectsNonNumericMaxAgeAtInit() {
        assertThrows(ServletException.class, () -> publish(
                Map.of(AuthenticatedSessionServlet.SESSION_ID_ATTRIBUTE, SESSION_ID),
                Map.of(AuthenticatedSessionServlet.COOKIE_MAX_AGE_PARAM, "soon")));
    }

    @Test
    void rejectsCookieConfigurationThatWouldLeakOutsideTheApplication() {
        assertThrows(IllegalArgumentException.class, () -> new SessionCookieFactory("APP_SESSION", "rel", 60, true));
        assertThrows(IllegalArgumentException.class, () -> new SessionCookieFactory("  ", "/", 60, true));
    }

    private static Outcome publish(Map<String, ?> attributes, Map<String, String> initParams) throws Exception {
        AuthenticatedSessionServlet servlet = new AuthenticatedSessionServlet();
        servlet.init(new StubConfig(initParams));
        ResponseDouble response = new ResponseDouble();
        servlet.doPost(requestWith(attributes), response.proxy());
        return new Outcome(response.cookie, response.status, response.errorReported, response.errorStatus);
    }

    private record Outcome(Cookie cookie, int status, boolean errorReported, int errorStatus) {
    }

    private record StubConfig(Map<String, String> initParams) implements ServletConfig {

        @Override
        public String getServletName() {
            return AuthenticatedSessionServlet.SERVLET_NAME;
        }

        @Override
        public String getInitParameter(String name) {
            return initParams.get(name);
        }
    }

    private static HttpServletRequest requestWith(Map<String, ?> attributes) {
        return (HttpServletRequest) Proxy.newProxyInstance(SessionCookieIssuanceTest.class.getClassLoader(),
                new Class<?>[] {HttpServletRequest.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "getAttribute" -> attributes.get((String) args[0]);
                    case "toString" -> "request-double";
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }

    private static final class ResponseDouble {

        private Cookie cookie;
        private int status;
        private boolean errorReported;
        private int errorStatus;

        private HttpServletResponse proxy() {
            return (HttpServletResponse) Proxy.newProxyInstance(SessionCookieIssuanceTest.class.getClassLoader(),
                    new Class<?>[] {HttpServletResponse.class}, (proxy, method, args) -> {
                        switch (method.getName()) {
                            case "addCookie" -> cookie = (Cookie) args[0];
                            case "setStatus" -> status = (Integer) args[0];
                            case "sendError" -> {
                                errorReported = true;
                                errorStatus = (Integer) args[0];
                            }
                            case "toString" -> {
                                return "response-double";
                            }
                            case "hashCode" -> {
                                return System.identityHashCode(proxy);
                            }
                            case "equals" -> {
                                return proxy == args[0];
                            }
                            default -> throw new UnsupportedOperationException(method.getName());
                        }
                        return null;
                    });
        }
    }
}
