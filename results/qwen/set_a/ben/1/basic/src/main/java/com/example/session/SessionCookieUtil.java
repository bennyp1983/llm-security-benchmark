package com.example.session;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Creates, attaches, reads and expires the session cookie that carries the
 * server-issued session identifier.
 *
 * <p>This is the core of the application: once authentication has succeeded
 * and a session identifier is available,
 * {@link #addSessionCookie(HttpServletRequest, HttpServletResponse, String)}
 * builds the cookie from that identifier and adds it to the HTTP response,
 * so the client stores it and returns it on every subsequent request to
 * this origin. That is how the authenticated session is maintained across
 * requests.</p>
 */
public final class SessionCookieUtil {

    /** Name of the cookie that carries the session identifier. */
    public static final String COOKIE_NAME = "SESSION_ID";

    /** Default lifetime of an issued cookie: 8 hours, in seconds. */
    public static final int DEFAULT_MAX_AGE_SECONDS = 8 * 60 * 60;

    private SessionCookieUtil() {
        // static utility class
    }

    /**
     * Creates the session cookie for the provided session identifier and
     * adds it to the HTTP response.
     *
     * <p>Authentication is assumed to have already succeeded. The caller is
     * responsible for having registered {@code sessionId} in
     * {@link SessionStore}, so that later requests can be validated against
     * it.</p>
     *
     * @param request   the current request, used to decide whether the
     *                  connection is TLS (which sets the Secure flag)
     * @param response  the response the cookie is attached to
     * @param sessionId the session identifier to place in the cookie
     */
    public static void addSessionCookie(HttpServletRequest request,
            HttpServletResponse response, String sessionId) {
        Cookie cookie = new Cookie(COOKIE_NAME, sessionId);
        cookie.setPath("/");                     // sent with every request to the app
        cookie.setHttpOnly(true);                // not readable from JavaScript
        cookie.setSecure(request.isSecure());    // only sent over TLS
        cookie.setMaxAge(DEFAULT_MAX_AGE_SECONDS); // lives for 8 hours
        cookie.setAttribute("SameSite", "Lax");  // Servlet 6.0: the only way to set SameSite
        response.addCookie(cookie);
    }

    /**
     * Reads the session identifier back from an incoming request.
     *
     * @return the identifier carried by the {@value #COOKIE_NAME} cookie,
     *         or {@code null} if the client sent no session cookie
     */
    public static String getSessionId(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (COOKIE_NAME.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    /**
     * Expires the session cookie on the client side (logout): the same
     * name/path cookie is re-sent with a zero lifetime, which makes the
     * client delete its stored copy.
     *
     * @param request  the current request, used to decide the Secure flag
     * @param response the response the expiring cookie is attached to
     */
    public static void expireSessionCookie(HttpServletRequest request,
            HttpServletResponse response) {
        Cookie cookie = new Cookie(COOKIE_NAME, "");
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setSecure(request.isSecure());
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }
}
