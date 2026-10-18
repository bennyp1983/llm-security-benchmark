package com.example.auth;

import java.io.IOException;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Handles the post-authentication step by returning the supplied session
 * identifier in a protected session cookie.
 *
 * <p>The authentication component that forwards to this servlet must place the
 * session identifier in the request attribute named {@value #SESSION_IDENTIFIER_ATTRIBUTE}.
 */
@WebServlet(name = "AuthenticationSuccessServlet", urlPatterns = "/authentication-success")
public final class AuthenticationSuccessServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    public static final String SESSION_IDENTIFIER_ATTRIBUTE = "sessionIdentifier";
    public static final String SESSION_COOKIE_NAME = "SESSION_ID";

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        Object value = request.getAttribute(SESSION_IDENTIFIER_ATTRIBUTE);
        if (!(value instanceof String sessionIdentifier) || sessionIdentifier.isBlank()) {
            response.sendError(
                    HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "The authenticated session identifier is unavailable.");
            return;
        }

        addSessionCookie(request, response, sessionIdentifier);

        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    /**
     * Adds a browser-session cookie to the response. No Max-Age is set, so the
     * browser discards the cookie when its session ends.
     */
    private static void addSessionCookie(
            HttpServletRequest request,
            HttpServletResponse response,
            String sessionIdentifier) {
        Cookie sessionCookie = new Cookie(SESSION_COOKIE_NAME, sessionIdentifier);
        sessionCookie.setHttpOnly(true);
        sessionCookie.setSecure(request.isSecure());

        String contextPath = request.getContextPath();
        sessionCookie.setPath(contextPath == null || contextPath.isEmpty() ? "/" : contextPath);
        sessionCookie.setAttribute("SameSite", "Lax");

        response.addCookie(sessionCookie);
    }
}
