package com.example.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Builds and attaches the cookie that carries the session identifier of an
 * authenticated user, so the session can be recognised on subsequent requests.
 */
public final class SessionCookieFactory {

    /** Name of the cookie holding the session identifier. */
    public static final String COOKIE_NAME = "SESSIONID";

    /** Lifetime of the session cookie, in seconds (30 minutes). */
    private static final int MAX_AGE_SECONDS = 30 * 60;

    private SessionCookieFactory() {
    }

    /**
     * Creates the session cookie and adds it to the response.
     *
     * @param request   the current request, used to decide whether the cookie
     *                  may be restricted to HTTPS
     * @param response  the response the {@code Set-Cookie} header is added to
     * @param sessionId the session identifier produced after successful
     *                  authentication
     */
    public static void addSessionCookie(HttpServletRequest request,
                                        HttpServletResponse response,
                                        String sessionId) {
        if (sessionId == null || sessionId.isEmpty()) {
            throw new IllegalArgumentException("sessionId must not be empty");
        }

        Cookie cookie = new Cookie(COOKIE_NAME, sessionId);

        // Not readable from JavaScript: blocks session theft via XSS.
        cookie.setHttpOnly(true);

        // Only sent over TLS. Kept in step with the current channel so the
        // cookie is still usable on a plain-HTTP development server.
        cookie.setSecure(request.isSecure());

        // Not sent on cross-site requests: mitigates CSRF.
        cookie.setAttribute("SameSite", "Strict");

        // Valid for the whole application, and only for it.
        String contextPath = request.getContextPath();
        cookie.setPath(contextPath.isEmpty() ? "/" : contextPath);

        cookie.setMaxAge(MAX_AGE_SECONDS);

        response.addCookie(cookie);
    }

    /**
     * Removes the session cookie, e.g. on logout. The replacement cookie must
     * carry the same name, path and domain as the original one.
     */
    public static void clearSessionCookie(HttpServletRequest request,
                                          HttpServletResponse response) {
        Cookie cookie = new Cookie(COOKIE_NAME, "");
        cookie.setHttpOnly(true);
        cookie.setSecure(request.isSecure());
        cookie.setAttribute("SameSite", "Strict");

        String contextPath = request.getContextPath();
        cookie.setPath(contextPath.isEmpty() ? "/" : contextPath);

        cookie.setMaxAge(0);

        response.addCookie(cookie);
    }
}
