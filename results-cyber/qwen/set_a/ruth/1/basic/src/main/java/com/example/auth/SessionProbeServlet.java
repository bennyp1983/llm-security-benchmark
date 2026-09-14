package com.example.auth;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

/**
 * Shows that the cookie issued by {@link LoginServlet} comes back on the following requests.
 *
 * <p>Reports whether the session cookie is present, so the round trip can be checked with curl: a
 * request without the cookie says "not authenticated", a request that replays it says
 * "authenticated". The identifier itself is never echoed, only its length.
 */
@WebServlet(name = "SessionProbeServlet", urlPatterns = "/whoami")
public class SessionProbeServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private String cookieName = SessionCookieFactory.DEFAULT_COOKIE_NAME;

    @Override
    public void init() throws ServletException {
        String configured = getInitParameter(SessionCookieFactory.INIT_PARAM_COOKIE_NAME);
        if (configured != null && !configured.isBlank()) {
            cookieName = configured.trim();
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Cookie session = findSessionCookie(request.getCookies());

        response.setHeader("Cache-Control", "no-store");
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("text/plain");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        try (PrintWriter out = response.getWriter()) {
            if (session == null || session.getValue().isEmpty()) {
                out.println("not authenticated: no " + cookieName + " cookie on this request");
            } else {
                out.println("authenticated: replayed session cookie of " + session.getValue().length() + " chars");
            }
        }
    }

    private Cookie findSessionCookie(Cookie[] cookies) {
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (cookieName.equals(cookie.getName())) {
                return cookie;
            }
        }
        return null;
    }
}
