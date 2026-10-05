package com.example.auth;

import java.util.regex.Pattern;

import jakarta.servlet.http.Cookie;

/**
 * Builds the cookie that carries an already-authenticated session identifier to the client.
 *
 * <p>The identifier is never generated here: authentication happens elsewhere and the resulting
 * value is handed to {@link #forSession(String)}.
 *
 * <p>The cookie is written with {@code HttpOnly} (no script access), {@code Secure} (HTTPS only)
 * and {@code Path=/} so it is sent with every request of the application. {@code SameSite} is not
 * part of the Servlet 6.0 cookie model - configure it at the container, e.g. Tomcat
 * {@code <CookieProcessor sameSiteCookies="Lax"/>}, or use {@code Cookie.setAttribute} once the
 * application runs on Servlet 6.1.
 */
public final class SessionCookieFactory {

    /** Distinct from the container-managed {@code JSESSIONID} so the two never overwrite each other. */
    public static final String DEFAULT_COOKIE_NAME = "APP_SESSION";

    public static final String DEFAULT_PATH = "/";

    /** Negative means no {@code Max-Age} attribute, which makes the cookie a browser-session cookie. */
    public static final int DEFAULT_MAX_AGE_SECONDS = -1;

    /**
     * RFC 6265 cookie-value octets. Rejecting anything else keeps a hostile identifier from
     * breaking out of the {@code Set-Cookie} header and blocks header injection outright.
     */
    private static final Pattern SESSION_ID_PATTERN = Pattern.compile("[\\x21\\x23-\\x2B\\x2D-\\x3A\\x3C-\\x5B\\x5D-\\x7E]+");

    private final String name;
    private final String path;
    private final int maxAgeSeconds;
    private final boolean secure;

    public SessionCookieFactory() {
        this(DEFAULT_COOKIE_NAME, DEFAULT_PATH, DEFAULT_MAX_AGE_SECONDS, true);
    }

    public SessionCookieFactory(String name, String path, int maxAgeSeconds, boolean secure) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("cookie name must not be blank");
        }
        if (path == null || !(path.equals("/") || (path.length() > 1 && path.startsWith("/")))) {
            throw new IllegalArgumentException("cookie path must be absolute: " + path);
        }
        this.name = name;
        this.path = path;
        this.maxAgeSeconds = maxAgeSeconds;
        this.secure = secure;
    }

    /**
     * @param sessionId session identifier produced by the authentication step
     * @return a cookie ready to be passed to {@code HttpServletResponse#addCookie(Cookie)}
     * @throws IllegalArgumentException if {@code sessionId} cannot be represented as a cookie value
     */
    public Cookie forSession(String sessionId) {
        Cookie cookie = new Cookie(name, requireCookieValue(sessionId));
        cookie.setPath(path);
        cookie.setMaxAge(maxAgeSeconds);
        cookie.setSecure(secure);
        cookie.setHttpOnly(true);
        return cookie;
    }

    private static String requireCookieValue(String sessionId) {
        if (sessionId == null || !SESSION_ID_PATTERN.matcher(sessionId).matches()) {
            throw new IllegalArgumentException("session identifier is not a valid cookie value");
        }
        return sessionId;
    }
}
