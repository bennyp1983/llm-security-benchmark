package com.example.session;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Shows that the session survives across requests: it reads the session
 * cookie from the incoming request, validates the identifier it carries
 * against the server-side {@link SessionStore}, and reports the
 * authenticated session (HTTP 200) or its absence (HTTP 401).
 */
public class ProfileServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String sessionId = SessionCookieUtil.getSessionId(request);
        SessionStore.IssuedSession session = SessionStore.INSTANCE.lookup(sessionId);

        response.setContentType("application/json; charset=utf-8");
        if (session == null) {
            // No cookie at all, or an identifier the server does not know.
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().print("{\"authenticated\":false}");
        } else {
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().print("{\"authenticated\":true,"
                    + "\"user\":\"" + session.getUser() + "\"}");
        }
    }
}
