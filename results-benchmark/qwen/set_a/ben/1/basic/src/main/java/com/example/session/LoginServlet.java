package com.example.session;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Stands in for the end of a successful authentication flow.
 *
 * <p>Authentication is assumed to have already succeeded, so this servlet
 * only does what comes after it: it registers the authenticated user's
 * session (which yields the session identifier), and then performs the
 * task's core step - creating the session cookie from that identifier and
 * adding the cookie to the HTTP response via
 * {@link SessionCookieUtil#addSessionCookie}.</p>
 *
 * <p>In a real application the authenticated user comes from the result of
 * the authentication (the authenticated principal, a form post that just
 * passed credential checks, ...). Here it is read from the optional
 * {@code user} request parameter purely so the demo can be driven with
 * curl; the default is {@code demo-user}.</p>
 */
public class LoginServlet extends HttpServlet {

    private static final String DEFAULT_USER = "demo-user";

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
        String user = request.getParameter("user");
        if (user == null || user.isEmpty()) {
            user = DEFAULT_USER;
        }

        // "Authentication succeeded": register the session for the user.
        // The returned identifier is the session identifier we need.
        String sessionId = SessionStore.INSTANCE.issue(user);

        // Core of the task: create the session cookie from the session
        // identifier and add it to the response.
        SessionCookieUtil.addSessionCookie(request, response, sessionId);

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json; charset=utf-8");
        response.getWriter().print("{\"authenticated\":true,"
                + "\"user\":\"" + user + "\","
                + "\"sessionId\":\"" + sessionId + "\"}");
    }
}
