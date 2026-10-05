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
 * Issues the session cookie once credentials have been verified.
 *
 * <p>This servlet performs <strong>no credential checking of its own</strong>. It is the step that
 * runs after authentication succeeded, and the caller is responsible for only routing verified
 * requests here. The session identifier is taken from the request attribute the authenticator
 * leaves behind ({@link #SESSION_ID_ATTRIBUTE}, typically set by a filter or by the code that
 * checked the credentials); when that attribute is absent a fresh identifier is generated. The
 * identifier is deliberately never read from request parameters, headers or form fields, because a
 * client-supplied session identifier is session fixation.
 *
 * <p>Configuration is via init-params, see {@link SessionCookieFactory#fromServletConfig}.
 */
@WebServlet(name = "LoginServlet", urlPatterns = "/login")
public class LoginServlet extends HttpServlet {

    /**
     * Request attribute the preceding authentication step stores the session identifier in. Reading
     * it before the servlet is reached keeps storage of the identifier (database, cache, JWT store)
     * out of the web layer.
     */
    public static final String SESSION_ID_ATTRIBUTE = "com.example.auth.sessionId";

    private static final long serialVersionUID = 1L;

    private transient SessionCookieFactory cookieFactory;

    @Override
    public void init() throws ServletException {
        try {
            cookieFactory = SessionCookieFactory.fromServletConfig(getServletConfig());
        } catch (IllegalArgumentException e) {
            throw new ServletException("LoginServlet is misconfigured: " + e.getMessage(), e);
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setHeader("Allow", "POST");
        response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "use POST");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Object supplied = request.getAttribute(SESSION_ID_ATTRIBUTE);
        String sessionId = (supplied instanceof String) ? (String) supplied : SessionIdGenerator.generate();

        Cookie sessionCookie;
        try {
            sessionCookie = cookieFactory.newSessionCookie(sessionId);
        } catch (IllegalArgumentException e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "unusable session identifier");
            return;
        }

        response.addCookie(sessionCookie);
        response.setHeader("Cache-Control", "no-store");
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("text/plain");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        try (PrintWriter out = response.getWriter()) {
            out.println("authenticated; session cookie issued");
        }
    }
}
