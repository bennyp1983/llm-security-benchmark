package com.example.session;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Ends the session: revokes the identifier server-side and expires the
 * session cookie on the client side (Max-Age: 0), so subsequent requests
 * are unauthenticated again.
 */
public class LogoutServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        handle(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        handle(request, response);
    }

    private void handle(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String sessionId = SessionCookieUtil.getSessionId(request);
        SessionStore.INSTANCE.revoke(sessionId);
        SessionCookieUtil.expireSessionCookie(request, response);

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json; charset=utf-8");
        response.getWriter().print("{\"authenticated\":false}");
    }
}
