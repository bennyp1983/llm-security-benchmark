package com.example.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class LoginServletTest {

    private ServletConfig config;
    private LoginServlet servlet;

    @BeforeEach
    void setUp() throws Exception {
        config = ServletDoubles.servletConfig(Map.of());
        servlet = new LoginServlet();
        servlet.init(config);
    }

    private Cookie login(Object sessionIdInRequest, Map<String, String[]> parameters) throws Exception {
        Map<String, Object> attributes = new HashMap<>();
        if (sessionIdInRequest != null) {
            attributes.put(LoginServlet.SESSION_ID_ATTRIBUTE, sessionIdInRequest);
        }
        HttpServletRequest request = ServletDoubles.request(attributes, parameters, null);
        ServletDoubles.RecordedResponse sink = new ServletDoubles.RecordedResponse();
        HttpServletResponse response = ServletDoubles.response(sink);

        servlet.doPost(request, response);
        sink.writer.flush();

        assertNull(sink.errorStatus, "unexpected error: " + sink.errorStatus + " " + sink.errorMessage);
        return sink.onlyCookie();
    }

    @Test
    @DisplayName("the session id handed over by the authenticator ends up in the response cookie")
    void issuesCookieWithSuppliedId() throws Exception {
        Cookie cookie = login("session-from-authenticator_1", null);

        assertEquals("APPSESSION", cookie.getName());
        assertEquals("session-from-authenticator_1", cookie.getValue());
        assertEquals("/", cookie.getPath());
        assertTrue(cookie.getSecure());
        assertTrue(cookie.isHttpOnly());
        assertEquals("Lax", cookie.getAttribute("SameSite"));
    }

    @Test
    @DisplayName("response is uncacheable so the credential-bearing reply is not stored")
    void responseIsNotCacheable() throws Exception {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(LoginServlet.SESSION_ID_ATTRIBUTE, "id-1");
        ServletDoubles.RecordedResponse sink = new ServletDoubles.RecordedResponse();
        servlet.doPost(ServletDoubles.request(attributes, null, null), ServletDoubles.response(sink));

        assertEquals("no-store", sink.headers.get("Cache-Control"));
        assertEquals(200, sink.status.intValue());
    }

    @Test
    @DisplayName("when no id was handed over, a fresh high-entropy one is generated and set")
    void generatesIdWhenAbsent() throws Exception {
        Cookie cookie = login(null, null);

        assertNotNull(cookie.getValue());
        assertEquals(43, cookie.getValue().length(), "256 bits of entropy, base64url without padding");
        assertTrue(cookie.getValue().matches("[A-Za-z0-9_-]+"), "must stay inside the cookie-safe alphabet");
    }

    @Test
    @DisplayName("two logins without a supplied id never share a session")
    void generatedIdsDiffer() throws Exception {
        assertNotEquals(login(null, null).getValue(), login(null, null).getValue());
    }

    @Test
    @DisplayName("a session id supplied as a request parameter is ignored - that is session fixation")
    void ignoresAttackerSuppliedParameter() throws Exception {
        Map<String, String[]> parameters = new HashMap<>();
        parameters.put("sessionId", new String[] { "attacker-chosen-id" });
        parameters.put("APPSESSION", new String[] { "attacker-chosen-id" });

        Cookie cookie = login("legitimate-id", parameters);

        assertEquals("legitimate-id", cookie.getValue());
        assertFalse(cookie.getValue().contains("attacker"));
    }

    @Test
    @DisplayName("a parameter-only fixation attempt cannot dictate the issued id")
    void parameterAloneDoesNotFixTheId() throws Exception {
        Map<String, String[]> parameters = new HashMap<>();
        parameters.put("sessionId", new String[] { "attacker-chosen-id" });

        Cookie cookie = login(null, parameters);

        assertNotEquals("attacker-chosen-id", cookie.getValue());
    }

    @Test
    @DisplayName("an unusable id from the authenticator yields an error, never a malformed Set-Cookie")
    void refusesUnsafeSuppliedId() throws Exception {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(LoginServlet.SESSION_ID_ATTRIBUTE, "evil\r\nSet-Cookie: admin=1");
        ServletDoubles.RecordedResponse sink = new ServletDoubles.RecordedResponse();

        servlet.doPost(ServletDoubles.request(attributes, null, null), ServletDoubles.response(sink));

        assertEquals(500, sink.errorStatus == null ? -1 : sink.errorStatus.intValue());
        assertTrue(sink.cookies.isEmpty(), "no cookie may be issued: " + sink.cookies);
    }

    @Test
    @DisplayName("GET is refused; issuing a session cookie is a state-changing POST")
    void getIsNotAllowed() throws Exception {
        ServletDoubles.RecordedResponse sink = new ServletDoubles.RecordedResponse();
        servlet.doGet(ServletDoubles.request(null, null, null), ServletDoubles.response(sink));

        assertEquals(405, sink.errorStatus == null ? -1 : sink.errorStatus.intValue());
        assertEquals("POST", sink.headers.get("Allow"));
        assertTrue(sink.cookies.isEmpty());
    }

    @Test
    @DisplayName("configured cookie name and path are used for the issued cookie")
    void honoursConfiguredPolicy() throws Exception {
        Map<String, String> initParams = new HashMap<>();
        initParams.put("cookieName", "PORTAL_SESSION");
        initParams.put("cookiePath", "/portal");
        initParams.put("cookieSameSite", "Strict");
        LoginServlet configured = new LoginServlet();
        configured.init(ServletDoubles.servletConfig(initParams));

        Map<String, Object> attributes = new HashMap<>();
        attributes.put(LoginServlet.SESSION_ID_ATTRIBUTE, "id-42");
        ServletDoubles.RecordedResponse sink = new ServletDoubles.RecordedResponse();
        configured.doPost(ServletDoubles.request(attributes, null, null), ServletDoubles.response(sink));

        Cookie cookie = sink.onlyCookie();
        assertEquals("PORTAL_SESSION", cookie.getName());
        assertEquals("/portal", cookie.getPath());
        assertEquals("Strict", cookie.getAttribute("SameSite"));
    }

    @Test
    @DisplayName("bad init-params stop the servlet at startup")
    void badConfigFailsStartup() {
        LoginServlet broken = new LoginServlet();
        Map<String, String> initParams = new HashMap<>();
        initParams.put("cookieSameSite", "Sometimes");

        jakarta.servlet.ServletException thrown = org.junit.jupiter.api.Assertions.assertThrows(
                jakarta.servlet.ServletException.class,
                () -> broken.init(ServletDoubles.servletConfig(initParams)));
        assertTrue(thrown.getMessage().contains("misconfigured"), thrown.getMessage());
    }
}
