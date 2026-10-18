package com.example.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Builds and attaches the session cookie that carries the authenticated
 * session identifier on subsequent requests.
 *
 * <p>The cookie is deliberately configured as a hardened, host-scoped session
 * cookie: the browser must never expose it to JavaScript, never send it over
 * cleartext HTTP, and never attach it to cross-site requests.
 */
public final class SessionCookieFactory {

    /**
     * Cookie name. The {@code __Host-} prefix is enforced by browsers: the
     * cookie is only accepted when it is marked {@code Secure}, has
     * {@code Path=/} and carries <em>no</em> {@code Domain} attribute. That
     * pins it to exactly this host, so a compromised or attacker-controlled
     * sibling subdomain cannot overwrite ("cookie tossing") the session.
     */
    public static final String SESSION_COOKIE_NAME = "__Host-SESSIONID";

    private SessionCookieFactory() {
        // utility class
    }

    /**
     * Creates the session cookie for an already-authenticated user.
     *
     * @param sessionId the session identifier to carry; must be a
     *                  high-entropy, server-generated opaque value
     * @return a fully configured session cookie
     */
    public static Cookie create(String sessionId) {
        if (sessionId == null || sessionId.isEmpty()) {
            throw new IllegalArgumentException("sessionId must not be null or empty");
        }
        if (!isCookieValueSafe(sessionId)) {
            // Refuse control characters, ';', ',' and whitespace so a tainted
            // identifier can never inject extra cookie attributes or headers.
            throw new IllegalArgumentException("sessionId contains illegal characters");
        }

        Cookie cookie = new Cookie(SESSION_COOKIE_NAME, sessionId);

        // Not readable by document.cookie -> an XSS bug cannot exfiltrate the session.
        cookie.setHttpOnly(true);

        // Only ever transmitted over TLS. Required by the __Host- prefix.
        cookie.setSecure(true);

        // Sent for every path on this host. Required by the __Host- prefix.
        cookie.setPath("/");

        // No setDomain(...) call: the __Host- prefix forbids a Domain attribute,
        // and omitting it keeps the cookie host-only (no subdomain sharing).

        // Not attached to cross-site requests -> blocks CSRF via the session cookie.
        // Use "Lax" instead only if top-level cross-site navigations must stay logged in.
        cookie.setAttribute("SameSite", "Strict");

        // Negative max-age = a session cookie: discarded when the browser session
        // ends and never written to disk. Server-side expiry remains authoritative.
        cookie.setMaxAge(-1);

        return cookie;
    }

    /**
     * Creates the session cookie and adds it to the response.
     *
     * <p>Call this only after authentication has succeeded and after the old
     * session has been invalidated and a fresh identifier issued, so that a
     * pre-authentication identifier can never be elevated to an authenticated
     * one (session fixation).
     */
    public static void addTo(HttpServletResponse response, String sessionId) {
        response.addCookie(create(sessionId));
    }

    /**
     * Expires the session cookie on logout. The attributes must match those of
     * the cookie that was set, otherwise the browser will keep the original.
     */
    public static void clearFrom(HttpServletResponse response) {
        Cookie cookie = new Cookie(SESSION_COOKIE_NAME, "");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setAttribute("SameSite", "Strict");
        cookie.setMaxAge(0); // delete now
        response.addCookie(cookie);
    }

    /** Reads the session identifier from an incoming request, or {@code null}. */
    public static String readFrom(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (SESSION_COOKIE_NAME.equals(cookie.getName())) {
                String value = cookie.getValue();
                return (value == null || value.isEmpty()) ? null : value;
            }
        }
        return null;
    }

    /** Allows only the RFC 6265 cookie-octet range. */
    private static boolean isCookieValueSafe(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean allowed = (c >= 'A' && c <= 'Z')
                    || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.' || c == '~' || c == '+' || c == '/' || c == '=';
            if (!allowed) {
                return false;
            }
        }
        return true;
    }
}
