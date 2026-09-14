package com.example.auth;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Issues the session cookie for a user who has already been authenticated.
 *
 * <p>The authentication step (password check, SSO callback, etc.) is expected to
 * happen before this servlet runs. That step stores the session identifier in the
 * request attribute {@link #SESSION_ID_ATTRIBUTE} and forwards here, for example:
 *
 * <pre>{@code
 * request.setAttribute(SessionCookieServlet.SESSION_ID_ATTRIBUTE, sessionId);
 * request.getRequestDispatcher("/auth/session").forward(request, response);
 * }</pre>
 *
 * Code that already holds the request and response can instead call
 * {@link #addSessionCookie(HttpServletRequest, HttpServletResponse, String)} directly.
 *
 * <p>Request attributes cannot be set by HTTP clients, so a direct request to this
 * servlet without prior authentication is rejected with {@code 401 Unauthorized}.
 *
 * <p>Requires Jakarta Servlet 6.0 or later (for {@link Cookie#setAttribute}).
 */
@WebServlet(name = "SessionCookieServlet", urlPatterns = "/auth/session")
public class SessionCookieServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    /** Request attribute holding the session identifier of the authenticated user. */
    public static final String SESSION_ID_ATTRIBUTE = "com.example.auth.SESSION_ID";

    /** Name of the cookie that carries the session identifier. */
    public static final String SESSION_COOKIE_NAME = "APP_SESSION";

    /**
     * Characters allowed in the identifier. This is a subset of the RFC 6265 cookie-octet
     * set covering hex, Base64 and Base64URL encodings; it excludes separators such as
     * {@code ;}, {@code ,}, whitespace and control characters, so the value cannot inject
     * additional cookie attributes or headers. The minimum length rejects trivially short
     * (guessable) identifiers.
     */
    private static final Pattern VALID_SESSION_ID = Pattern.compile("[A-Za-z0-9._~+/=-]{16,4096}");

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        issueCookie(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        issueCookie(request, response);
    }

    private void issueCookie(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Object attribute = request.getAttribute(SESSION_ID_ATTRIBUTE);
        if (!(attribute instanceof String sessionId)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        try {
            addSessionCookie(request, response, sessionId);
        } catch (IllegalArgumentException e) {
            log("Refusing to issue session cookie: " + e.getMessage());
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        }

        // Post/Redirect/Get: send the browser to the application root, now carrying the cookie.
        response.setStatus(HttpServletResponse.SC_SEE_OTHER);
        response.setHeader("Location", contextRoot(request));
    }

    /**
     * Creates the session cookie containing {@code sessionId} and adds it to the response.
     *
     * <p>The cookie is:
     * <ul>
     *   <li>{@code HttpOnly} - not readable from JavaScript, limiting theft via XSS;</li>
     *   <li>{@code Secure} - only sent over HTTPS;</li>
     *   <li>{@code SameSite=Lax} - not sent on cross-site subrequests, mitigating CSRF;</li>
     *   <li>scoped to the application's context path;</li>
     *   <li>a browser-session cookie (no {@code Max-Age}/{@code Expires}), discarded when
     *       the browser closes. Server-side expiry of the session is still required.</li>
     * </ul>
     *
     * <p>Must be called before the response is committed.
     *
     * @throws IllegalArgumentException if {@code sessionId} is not a well-formed identifier
     * @throws IllegalStateException    if the response has already been committed
     */
    public static void addSessionCookie(HttpServletRequest request, HttpServletResponse response, String sessionId) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(response, "response");
        if (sessionId == null || !VALID_SESSION_ID.matcher(sessionId).matches()) {
            // Do not include the value itself: it may be a real credential that must not reach logs.
            throw new IllegalArgumentException("session identifier is missing or malformed");
        }
        if (response.isCommitted()) {
            throw new IllegalStateException("response already committed; cannot add session cookie");
        }

        Cookie cookie = new Cookie(SESSION_COOKIE_NAME, sessionId);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath(contextRoot(request));
        cookie.setMaxAge(-1);
        cookie.setAttribute("SameSite", "Lax");
        response.addCookie(cookie);

        // A response that sets a session credential must never be stored by shared caches.
        response.setHeader("Cache-Control", "no-store");
    }

    private static String contextRoot(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        return contextPath == null || contextPath.isEmpty() ? "/" : contextPath + "/";
    }
}
