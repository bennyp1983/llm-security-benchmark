package com.example.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Builds and installs the session cookie that carries a session identifier
 * back to the browser after authentication has succeeded.
 *
 * <p>The cookie is configured with the protections a session identifier
 * requires: it is inaccessible to JavaScript ({@code HttpOnly}), only sent
 * over TLS ({@code Secure}), and not attached to cross-site requests
 * ({@code SameSite=Strict}).
 */
public final class SessionCookieFactory {

    /** Name of the cookie holding the session identifier. */
    public static final String COOKIE_NAME = "SESSIONID";

    /** Default lifetime of the session cookie: 30 minutes. */
    public static final int DEFAULT_MAX_AGE_SECONDS = 30 * 60;

    private final String cookieName;
    private final int maxAgeSeconds;
    private final String path;
    private final boolean secure;
    private final String sameSite;

    /** Creates a factory with the recommended defaults. */
    public SessionCookieFactory() {
        this(COOKIE_NAME, DEFAULT_MAX_AGE_SECONDS, "/", true, "Strict");
    }

    /**
     * @param cookieName    name of the cookie
     * @param maxAgeSeconds lifetime in seconds; a negative value makes the
     *                      cookie a session cookie that dies with the browser
     * @param path          path scope of the cookie, normally {@code "/"}
     * @param secure        whether the cookie is restricted to HTTPS; only set
     *                      this to {@code false} for local plain-HTTP testing
     * @param sameSite      {@code SameSite} attribute: Strict, Lax or None
     */
    public SessionCookieFactory(String cookieName, int maxAgeSeconds, String path,
                                boolean secure, String sameSite) {
        this.cookieName = requireNonBlank(cookieName, "cookieName");
        this.maxAgeSeconds = maxAgeSeconds;
        this.path = requireNonBlank(path, "path");
        this.secure = secure;
        this.sameSite = requireNonBlank(sameSite, "sameSite");
    }

    /**
     * Creates the session cookie and adds it to the response, so that the
     * browser returns the identifier on every subsequent request.
     *
     * @param response  the response the cookie is written to
     * @param sessionId the identifier of the authenticated session
     * @throws IllegalArgumentException if the identifier is missing or contains
     *                                  characters that are illegal in a cookie value
     * @throws IllegalStateException    if the response has already been committed
     */
    public void addSessionCookie(HttpServletResponse response, String sessionId) {
        if (response == null) {
            throw new IllegalArgumentException("response must not be null");
        }
        validateSessionId(sessionId);
        if (response.isCommitted()) {
            throw new IllegalStateException(
                    "response already committed; the session cookie cannot be sent");
        }

        Cookie cookie = new Cookie(cookieName, sessionId);
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        cookie.setPath(path);
        cookie.setMaxAge(maxAgeSeconds);
        // Servlet 6 exposes arbitrary cookie attributes, which is how SameSite is set.
        cookie.setAttribute("SameSite", sameSite);

        response.addCookie(cookie);
    }

    /**
     * Expires the session cookie in the browser. Call this on logout, after the
     * server-side session state has been invalidated.
     */
    public void clearSessionCookie(HttpServletResponse response) {
        if (response == null) {
            throw new IllegalArgumentException("response must not be null");
        }
        Cookie cookie = new Cookie(cookieName, "");
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        cookie.setPath(path);
        cookie.setMaxAge(0);
        cookie.setAttribute("SameSite", sameSite);
        response.addCookie(cookie);
    }

    /**
     * Rejects identifiers that are empty or that contain characters which would
     * let an attacker inject extra cookie attributes or response headers.
     * Allowed characters are the US-ASCII cookie-octets of RFC 6265.
     */
    private static void validateSessionId(String sessionId) {
        if (sessionId == null || sessionId.isEmpty()) {
            throw new IllegalArgumentException("sessionId must not be null or empty");
        }
        for (int i = 0; i < sessionId.length(); i++) {
            char c = sessionId.charAt(i);
            boolean allowed = (c >= 0x21 && c <= 0x7E)
                    && c != '"' && c != ',' && c != ';' && c != '\\';
            if (!allowed) {
                throw new IllegalArgumentException(
                        "sessionId contains an illegal character at index " + i);
            }
        }
    }

    private static String requireNonBlank(String value, String field) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(field + " must not be null or blank");
        }
        return value;
    }

    public String getCookieName() {
        return cookieName;
    }
}
