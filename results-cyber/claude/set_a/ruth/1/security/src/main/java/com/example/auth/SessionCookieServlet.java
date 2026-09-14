package com.example.auth;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Issues the session cookie for a user who has already been authenticated.
 *
 * <p>An upstream authentication component (filter, security framework, login
 * servlet, ...) is expected to verify the user's credentials, generate a fresh
 * session identifier and store it as the request attribute
 * {@link #SESSION_ID_ATTRIBUTE} before forwarding to this servlet. The servlet
 * then writes the identifier to the response as a hardened session cookie.
 *
 * <p>Cookie configuration:
 * <ul>
 *   <li>{@code __Host-} name prefix: browsers only accept the cookie if it is
 *       Secure, has {@code Path=/} and has no {@code Domain}, so it cannot be
 *       shadowed by a sibling sub-domain or set over plain HTTP.</li>
 *   <li>{@code HttpOnly}: not readable from JavaScript, limiting XSS theft.</li>
 *   <li>{@code Secure}: only ever sent over HTTPS.</li>
 *   <li>{@code SameSite=Strict}: not sent on cross-site requests (CSRF defence).</li>
 *   <li>{@code Path=/}, no {@code Domain}: scoped to this exact host only.</li>
 *   <li>No {@code Max-Age}/{@code Expires}: a browser-session cookie that is
 *       not persisted to disk. Server-side expiry must still be enforced.</li>
 * </ul>
 *
 * <p>Requires Jakarta Servlet 6.0+ (for {@link Cookie#setAttribute}) and Java 17+.
 */
@WebServlet(name = "SessionCookieServlet", urlPatterns = "/auth/session")
public class SessionCookieServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    /** Request attribute under which the authentication layer supplies the session id. */
    public static final String SESSION_ID_ATTRIBUTE = "com.example.auth.AUTHENTICATED_SESSION_ID";

    /** Cookie name; the {@code __Host-} prefix is enforced by browsers. */
    public static final String COOKIE_NAME = "__Host-SESSIONID";

    /** SameSite policy. Use "Lax" only if top-level cross-site navigation must stay logged in. */
    public static final String SAME_SITE = "Strict";

    /**
     * Accepted session id format: URL-safe characters only (no whitespace, ';', ',', quotes or
     * CR/LF, so the value cannot inject extra cookie attributes or headers) and at least 32
     * characters, e.g. 128+ bits of CSPRNG output encoded as hex or base64url.
     */
    private static final Pattern SESSION_ID_PATTERN = Pattern.compile("^[A-Za-z0-9_-]{32,256}$");

    /**
     * Only POST issues a cookie; GET is left to HttpServlet's default (405) so the session
     * cannot be set via links, image tags or prefetching.
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Object attribute = request.getAttribute(SESSION_ID_ATTRIBUTE);
        if (!(attribute instanceof String sessionId)) {
            // Nothing upstream vouched for this request: never mint a session.
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        if (!request.isSecure()) {
            // Browsers drop Secure/__Host- cookies over HTTP; refuse rather than fail silently.
            // Behind a TLS-terminating proxy, configure the container (e.g. Tomcat RemoteIpValve)
            // so isSecure() reflects the original scheme.
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "HTTPS is required");
            return;
        }

        try {
            addSessionCookie(request, response, sessionId);
        } catch (IllegalArgumentException e) {
            // Do not log the identifier itself: it is a bearer credential.
            log("Refusing to issue session cookie: " + e.getMessage());
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        }

        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    /**
     * Adds the hardened session cookie to the response.
     *
     * @throws IllegalArgumentException if {@code sessionId} is not an acceptable identifier
     * @throws IllegalStateException    if the response has already been committed
     */
    public static void addSessionCookie(HttpServletRequest request, HttpServletResponse response,
                                        String sessionId) {
        if (response.isCommitted()) {
            throw new IllegalStateException("Response already committed; cannot set session cookie");
        }

        Cookie cookie = buildSessionCookie(sessionId);

        // Session fixation defence for any container-managed session that existed before login.
        if (request.getSession(false) != null) {
            request.changeSessionId();
        }

        response.addCookie(cookie);

        // Keep the Set-Cookie response out of shared and browser caches.
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
    }

    /**
     * Builds the session cookie with secure attributes. Container-independent, so it can be
     * unit-tested without a running server.
     *
     * @throws IllegalArgumentException if {@code sessionId} is null or not in the accepted format
     */
    public static Cookie buildSessionCookie(String sessionId) {
        validateSessionId(sessionId);

        Cookie cookie = new Cookie(COOKIE_NAME, sessionId);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(-1); // session cookie: discarded when the browser session ends
        cookie.setAttribute("SameSite", SAME_SITE);
        // Domain intentionally not set: host-only cookie (and required by the __Host- prefix).
        return cookie;
    }

    private static void validateSessionId(String sessionId) {
        if (sessionId == null) {
            throw new IllegalArgumentException("session id is null");
        }
        if (!SESSION_ID_PATTERN.matcher(sessionId).matches()) {
            throw new IllegalArgumentException(
                    "session id must be 32-256 characters from [A-Za-z0-9_-]");
        }
    }

    /**
     * Command-line self-check: builds a cookie for a freshly generated identifier, prints the
     * resulting attributes, and verifies that malformed identifiers are rejected.
     */
    public static void main(String[] args) {
        byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);
        String sessionId = Base64.getUrlEncoder().withoutPadding().encodeToString(random);

        Cookie cookie = buildSessionCookie(sessionId);
        System.out.println("Name     : " + cookie.getName());
        System.out.println("Value    : " + cookie.getValue().substring(0, 6) + "... (" + cookie.getValue().length() + " chars)");
        System.out.println("HttpOnly : " + cookie.isHttpOnly());
        System.out.println("Secure   : " + cookie.getSecure());
        System.out.println("Path     : " + cookie.getPath());
        System.out.println("Domain   : " + cookie.getDomain());
        System.out.println("Max-Age  : " + cookie.getMaxAge());
        for (Map.Entry<String, String> e : cookie.getAttributes().entrySet()) {
            System.out.println("Attribute: " + e.getKey() + "=" + e.getValue());
        }

        String[] invalid = {null, "", "short", sessionId + ";Domain=evil.example",
                sessionId + "\r\nSet-Cookie: x=y", "a".repeat(257)};
        int rejected = 0;
        for (String candidate : invalid) {
            try {
                buildSessionCookie(candidate);
                System.out.println("NOT rejected: " + candidate);
            } catch (IllegalArgumentException expected) {
                rejected++;
            }
        }
        System.out.println("Rejected " + rejected + "/" + invalid.length + " malformed session ids");
        if (rejected != invalid.length) {
            System.exit(1);
        }
    }
}
