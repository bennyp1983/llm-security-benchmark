package com.example.auth.web;

import java.time.Duration;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Reading and writing the one cookie this application cares about.
 *
 * <p>A cookie value arriving from a browser is untrusted text: it is length- and character-checked
 * before it is ever used as a map key, so a crafted header cannot probe the store with arbitrary
 * content. The written cookie is {@code HttpOnly} (no script can read it), {@code SameSite=Lax}
 * (a cross-site form POST never carries it) and {@code Secure} whenever the request itself was
 * HTTPS.
 */
final class Cookies {

    /** Session ids are Base64url without padding; anything else did not come from us. */
    private static final java.util.regex.Pattern SESSION_ID =
            java.util.regex.Pattern.compile("[A-Za-z0-9_-]{32,128}");

    private Cookies() {
    }

    /** The session id from the request cookie header, or {@code null} if absent or malformed. */
    static String readSessionId(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (!AuthContext.COOKIE_NAME.equals(cookie.getName())) {
                continue;
            }
            String value = cookie.getValue();
            if (value == null) {
                return null;
            }
            String candidate = value.trim();
            return SESSION_ID.matcher(candidate).matches() ? candidate : null;
        }
        return null;
    }

    /**
     * Writes the session cookie. Without {@code maxAge} the cookie gets no expiry attribute and the
     * browser drops it when the browser closes. A {@code maxAge} of zero is the browser's instruction
     * to delete it now; anything larger is the lifetime the server decided.
     */
    static void writeSessionId(HttpServletResponse response, String sessionId, Duration maxAge,
                               boolean secure, String path) {
        Cookie cookie = new Cookie(AuthContext.COOKIE_NAME, sessionId);
        cookie.setPath(path);
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        cookie.setAttribute("SameSite", "Lax");
        if (maxAge != null) {
            long seconds = Math.max(maxAge.getSeconds(), 0L);
            cookie.setMaxAge(seconds > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) seconds);
        }
        response.addCookie(cookie);
    }

    /** Tells the browser to drop the cookie immediately. */
    static void clearSessionId(HttpServletResponse response, boolean secure, String path) {
        writeSessionId(response, "invalid", Duration.ZERO, secure, path);
    }

    static String cookiePath(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        return contextPath == null || contextPath.isEmpty() ? "/" : contextPath;
    }
}
