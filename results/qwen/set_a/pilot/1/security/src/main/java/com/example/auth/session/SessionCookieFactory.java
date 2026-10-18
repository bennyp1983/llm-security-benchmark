package com.example.auth.session;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Objects;

/**
 * Builds and emits the cookie that carries the session identifier handed over by authentication.
 */
public final class SessionCookieFactory {

    /** Plenty for any opaque identifier, while keeping a hostile "provided" value bounded. */
    private static final int MAX_SESSION_ID_LENGTH = 512;

    private SessionCookieFactory() {
    }

    /**
     * @param sessionId opaque identifier produced by the authentication step; it is copied into the
     *                  cookie verbatim, so it is validated here as the boundary that guards the
     *                  {@code Set-Cookie} header
     */
    public static Cookie forSession(SessionCookieConfig config, String sessionId) {
        Objects.requireNonNull(config, "config");
        Cookie cookie = new Cookie(config.effectiveName(), requireValidSessionId(sessionId));
        cookie.setHttpOnly(config.httpOnly());
        cookie.setSecure(config.secure());
        cookie.setPath(config.path());
        cookie.setMaxAge(config.maxAgeSeconds());
        if (config.domain() != null) {
            cookie.setDomain(config.domain());
        }
        // Extension attributes are part of the Servlet 6.0 Cookie API; the container renders them
        // into the Set-Cookie header. Older containers need response.addHeader(...) instead.
        cookie.setAttribute("SameSite", config.sameSite().headerValue());
        return cookie;
    }

    public static void issue(HttpServletResponse response, SessionCookieConfig config, String sessionId) {
        response.addCookie(forSession(config, sessionId));
    }

    /**
     * Removes the cookie. Name, path and domain have to match the issued cookie exactly, otherwise
     * the browser keeps the original copy and deletion silently does nothing.
     */
    public static void clear(HttpServletResponse response, SessionCookieConfig config) {
        Objects.requireNonNull(config, "config");
        Cookie cookie = new Cookie(config.effectiveName(), "");
        cookie.setHttpOnly(config.httpOnly());
        cookie.setSecure(config.secure());
        cookie.setPath(config.path());
        cookie.setMaxAge(0);
        if (config.domain() != null) {
            cookie.setDomain(config.domain());
        }
        cookie.setAttribute("SameSite", config.sameSite().headerValue());
        response.addCookie(cookie);
    }

    /**
     * Reads the session identifier back out of a subsequent request. The lookup is by the exact
     * effective name, so a second cookie that a page managed to plant on a subpath cannot shadow it.
     */
    public static String readSessionId(HttpServletRequest request, SessionCookieConfig config) {
        Objects.requireNonNull(config, "config");
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        String name = config.effectiveName();
        for (Cookie cookie : cookies) {
            if (name.equals(cookie.getName())) {
                String value = cookie.getValue();
                return value == null || value.isEmpty() ? null : value;
            }
        }
        return null;
    }

    private static String requireValidSessionId(String sessionId) {
        if (sessionId == null || sessionId.isEmpty()) {
            throw new IllegalArgumentException("session identifier is required");
        }
        if (sessionId.length() > MAX_SESSION_ID_LENGTH) {
            throw new IllegalArgumentException("session identifier is unreasonably long");
        }
        for (int i = 0; i < sessionId.length(); i++) {
            if (!isValidCookieValueChar(sessionId.charAt(i))) {
                throw new IllegalArgumentException(
                        "session identifier contains a character that is not allowed in a cookie value");
            }
        }
        return sessionId;
    }

    /**
     * RFC 6265 {@code cookie-value} octets. Whitelisting them keeps control characters out of the
     * header, so an identifier that an attacker influenced cannot break out of the cookie and append
     * further response headers.
     */
    private static boolean isValidCookieValueChar(char c) {
        return c == '!'
                || (c >= '#' && c <= '+')
                || (c >= '-' && c <= ':')
                || (c >= '<' && c <= '[')
                || (c >= ']' && c <= '~');
    }
}
