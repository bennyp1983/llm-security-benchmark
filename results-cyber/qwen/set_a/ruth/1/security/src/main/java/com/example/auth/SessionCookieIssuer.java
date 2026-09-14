package com.example.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.List;

/**
 * Builds the session cookie that carries an authenticated session identifier and attaches it to the
 * HTTP response, so the browser returns the identifier on every subsequent request.
 *
 * <p>{@link #issue(HttpServletResponse, SessionIdentifier)} is the entry point to call immediately
 * after authentication succeeded. The attributes that matter are set explicitly rather than left to
 * container or framework defaults:
 *
 * <ul>
 *   <li>{@code HttpOnly} - the cookie is invisible to {@code document.cookie}, so an injected script
 *       cannot read the identifier.</li>
 *   <li>{@code Secure} - never sent over plaintext HTTP, hence never exposed to a network observer
 *       or a downgraded link.</li>
 *   <li>{@code SameSite=Lax} - not attached to cross-site POSTs, which blocks the classic
 *       cross-site request forgery against a state-changing endpoint.</li>
 *   <li>No {@code Domain} attribute - the cookie stays host-only, so a sibling subdomain cannot read
 *       or plant it.</li>
 *   <li>{@code Path} pinned to the application root - the identifier is not sent to unrelated paths
 *       or to paths a host also serves for third parties (user-content directories on a UGC host are
 *       the usual way this leaks).</li>
 *   <li>Browser-session lifetime by default: no {@code Max-Age}/{@code Expires}, so the identifier
 *       disappears when the browser closes instead of lingering on a shared machine.</li>
 * </ul>
 *
 * <p>The identifier itself is validated by {@link SessionIdentifier.of(String)} before it reaches
 * the header, so a value that arrived from outside cannot smuggle CR/LF or an extra attribute into
 * {@code Set-Cookie}. The header the container actually produced is then read back and checked
 * (see {@link #assertHeaderIntegrity}) - an assertion, not a filter, so a response is never served
 * with a silently weaker cookie.
 */
public final class SessionCookieIssuer {

    private final SessionCookieConfig config;

    public SessionCookieIssuer(SessionCookieConfig config) {
        if (config == null) {
            throw new IllegalArgumentException("config is null");
        }
        this.config = config;
    }

    public SessionCookieConfig config() {
        return config;
    }

    /**
     * Attaches the session cookie to {@code response}.
     *
     * @param response the response of the request whose principal just authenticated
     * @param sessionId the identifier to carry, taken verbatim as the cookie value
     * @throws IllegalArgumentException if the identifier is not a safe cookie token
     * @throws IllegalStateException if the container produced a header that is malformed or weaker
     *     than requested; nothing usable should have reached the client because the response is
     *     discarded by the container when the servlet throws before the buffer flushes
     */
    public Cookie issue(HttpServletResponse response, SessionIdentifier sessionId) {
        if (response == null) {
            throw new IllegalArgumentException("response is null");
        }
        if (sessionId == null) {
            throw new IllegalArgumentException("session identifier is null");
        }
        return add(response, build(sessionId.toCookieValue(), config));
    }

    /**
     * Overwrite of the live cookie used by logout: same name and {@code Path} as the real cookie -
     * a mismatch means the browser keeps the original - with an empty value and an expiry in the
     * past. The underlying session must also be invalidated server side; clearing the cookie alone
     * does not end anything.
     */
    public Cookie expire(HttpServletResponse response) {
        if (response == null) {
            throw new IllegalArgumentException("response is null");
        }
        SessionCookieConfig expiring = config.toBuilder().maxAgeSeconds(0).build();
        return add(response, build("", expiring));
    }

    /**
     * Builds the cookie without touching a response. Public so the exact attribute set can be
     * asserted in a test, and so a non-servlet caller (a filter that rewrites the header itself) can
     * reuse the same construction.
     */
    public static Cookie build(String cookieValue, SessionCookieConfig config) {
        Cookie cookie = new Cookie(config.name(), cookieValue);
        cookie.setPath(config.path());
        cookie.setSecure(config.secure());
        cookie.setHttpOnly(config.httpOnly());
        cookie.setMaxAge(config.maxAgeSeconds());
        // Servlet 6 exposes SameSite only as a registered attribute; the container's cookie
        // processor is what renders it into the header. Version/Comment are deliberately left alone:
        // both are deprecated for removal and Comment is obsolete under RFC 6265, so emitting it
        // would buy nothing and pin the code to the RFC 2109 header form.
        cookie.setAttribute("SameSite", config.sameSite().headerValue());
        return cookie;
    }

    private Cookie add(HttpServletResponse response, Cookie cookie) {
        response.addCookie(cookie);
        assertHeaderIntegrity(response, cookie);
        return cookie;
    }

    /**
     * Reads the {@code Set-Cookie} header the container produced and fails closed if it is not the
     * cookie we asked for.
     *
     * <p>Two things are checked: the header must contain no CR or LF and no unbalanced quoting (a
     * response-splitting / cookie-injection shape), and it must still carry {@code HttpOnly},
     * {@code Secure} and {@code Path}. Containers that ignore an attribute would otherwise hand out
     * a cookie that looks set but is readable by script or replayable over http.
     */
    public static void assertHeaderIntegrity(HttpServletResponse response, Cookie cookie) {
        // Scan every Set-Cookie header, not just the one named after this cookie: an injected header
        // under another name carries the same CRLF risk, and matching only on the name is what would
        // let it slip past this check.
        List<String> headers = new ArrayList<>();
        for (String header : response.getHeaders("Set-Cookie")) {
            if (header == null) {
                continue;
            }
            for (int i = 0; i < header.length(); i++) {
                char c = header.charAt(i);
                if (c == '\r' || c == '\n') {
                    throw new IllegalStateException(
                            "a Set-Cookie header contains a control character, which would split the response");
                }
            }
            headers.add(header);
        }
        String header = null;
        for (String candidate : headers) {
            if (candidate.startsWith(cookie.getName() + "=")) {
                header = candidate;
                break;
            }
        }
        if (header == null) {
            throw new IllegalStateException("container did not emit a Set-Cookie header for " + cookie.getName());
        }
        if (cookie.getSecure() && !hasBooleanAttribute(header, "Secure")) {
            throw new IllegalStateException("container dropped the Secure attribute for " + cookie.getName());
        }
        if (cookie.isHttpOnly() && !hasBooleanAttribute(header, "HttpOnly")) {
            throw new IllegalStateException("container dropped the HttpOnly attribute for " + cookie.getName());
        }
        if (!hasAttributeWithPrefix(header, "Path=")) {
            throw new IllegalStateException("container dropped the Path attribute for " + cookie.getName());
        }
    }

    /**
     * {@code true} when one of the header's {@code ;}-separated attributes is exactly this
     * boolean attribute, ignoring case. Attributes are compared as trimmed whole tokens rather than
     * as a substring, because containers render {@code "; Secure"} with a space and because a
     * substring test would be satisfied by an attribute name appearing inside a cookie value.
     */
    private static boolean hasBooleanAttribute(String header, String attribute) {
        for (String part : header.split(";")) {
            if (part.trim().equalsIgnoreCase(attribute)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasAttributeWithPrefix(String header, String prefix) {
        for (String part : header.split(";")) {
            if (part.trim().regionMatches(true, 0, prefix, 0, prefix.length())) {
                return true;
            }
        }
        return false;
    }
}
