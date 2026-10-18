package com.example.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.servlet.http.Cookie;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class SessionProbeServletTest {

    private String probe(Cookie[] replayed) throws Exception {
        SessionProbeServlet probe = new SessionProbeServlet();
        probe.init(ServletDoubles.servletConfig(Map.of()));
        ServletDoubles.RecordedResponse sink = new ServletDoubles.RecordedResponse();

        probe.doGet(ServletDoubles.request(null, null, replayed), ServletDoubles.response(sink));
        sink.writer.flush();

        assertEquals(200, sink.status.intValue());
        return sink.body.toString();
    }

    @Test
    @DisplayName("a request that carries no session cookie is reported as unauthenticated")
    void noCookieMeansAnonymous() throws Exception {
        assertTrue(probe(null).startsWith("not authenticated"));
        assertTrue(probe(new Cookie[] { new Cookie("other", "value") }).startsWith("not authenticated"));
    }

    @Test
    @DisplayName("replaying the cookie issued at login is recognised on the next request")
    void replayedCookieMeansAuthenticated() throws Exception {
        Cookie issued = new SessionCookieFactory("APPSESSION", "/", null, -1, true, true, "Lax")
                .newSessionCookie("replayed-session-value");

        String report = probe(new Cookie[] { new Cookie(issued.getName(), issued.getValue()) });

        assertTrue(report.startsWith("authenticated"), report);
        assertTrue(report.contains(String.valueOf(issued.getValue().length())), report);
    }

    @Test
    @DisplayName("the identifier itself is never echoed back in the response body")
    void identifierIsNotEchoed() throws Exception {
        String secret = "super-secret-session-value";
        String report = probe(new Cookie[] { new Cookie("APPSESSION", secret) });

        assertTrue(report.startsWith("authenticated"), report);
        assertTrue(!report.contains(secret), "body must not contain the session identifier");
    }

    @Test
    @DisplayName("an empty session cookie value does not count as authenticated")
    void emptyValueMeansAnonymous() throws Exception {
        assertTrue(probe(new Cookie[] { new Cookie("APPSESSION", "") }).startsWith("not authenticated"));
    }

    @Test
    @DisplayName("a renamed session cookie is honoured by the probe")
    void honoursConfiguredCookieName() throws Exception {
        SessionProbeServlet probe = new SessionProbeServlet();
        probe.init(ServletDoubles.servletConfig(Map.of("cookieName", "PORTAL_SESSION")));
        ServletDoubles.RecordedResponse sink = new ServletDoubles.RecordedResponse();

        probe.doGet(ServletDoubles.request(null, null,
                new Cookie[] { new Cookie("PORTAL_SESSION", "abc") }), ServletDoubles.response(sink));
        sink.writer.flush();

        assertTrue(sink.body.toString().startsWith("authenticated"), sink.body.toString());
    }
}
