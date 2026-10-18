package com.example.portal.auth;

import java.time.Duration;

/**
 * Builds the {@code Set-Cookie} header for a session token.
 *
 * <p>This console program does not speak HTTP, so nothing here is used on the CLI path. It exists
 * because the portal's web front end wraps exactly this authenticator, and the attributes a session
 * cookie needs are a property of the session, not of the transport -- leaving them to be
 * rediscovered by whoever writes the servlet is how a session cookie ends up without
 * {@code HttpOnly}.
 *
 * <p>Every issued cookie carries:
 * <ul>
 *   <li>{@code HttpOnly} -- page script cannot read the token, so one XSS flaw elsewhere in the
 *       portal does not become session theft.</li>
 *   <li>{@code Secure} -- the token is never sent over plaintext HTTP.</li>
 *   <li>{@code SameSite=Strict} -- the cookie is not attached to cross-site requests, which removes
 *       the ambient authority that cross-site request forgery depends on.</li>
 *   <li>{@code Path=/portal} -- scoped to the application rather than the whole origin, so it is not
 *       offered to unrelated apps sharing the host.</li>
 *   <li>{@code Max-Age} matching the server-side idle timeout, so the browser and the server agree
 *       on when the session is over. The server-side record remains authoritative.</li>
 * </ul>
 *
 * <p>No {@code Domain} attribute is set: omitting it keeps the cookie host-only, where setting it
 * would widen the cookie to subdomains.
 */
public final class SessionCookie {

    /** The cookie name. A {@code __Host-} prefix additionally pins the cookie to this exact host. */
    public static final String NAME = "__Host-portal_session";
    private static final String PATH = "/";

    private SessionCookie() {
    }

    /**
     * Returns the {@code Set-Cookie} value carrying {@code token}.
     *
     * <p>The {@code __Host-} prefix that browsers enforce requires {@code Secure}, no {@code Domain},
     * and {@code Path=/}; those are fixed here rather than parameterised so the prefix cannot be
     * invalidated by a caller.
     *
     * @throws IllegalArgumentException if the token is not one this application issued -- a shape
     *                                 check, so a caller cannot smuggle cookie attributes through
     *                                 the value
     */
    public static String setCookieHeader(String token, Duration maxAge) {
        if (!SessionManager.hasTokenShape(token)) {
            throw new IllegalArgumentException("refusing to build a cookie for a malformed token");
        }
        if (maxAge == null || maxAge.isNegative() || maxAge.isZero()) {
            throw new IllegalArgumentException("cookie Max-Age must be a positive duration");
        }
        return NAME + "=" + token
                + "; Path=" + PATH
                + "; Max-Age=" + maxAge.toSeconds()
                + "; HttpOnly; Secure; SameSite=Strict";
    }

    /** Returns the header value that clears the cookie, for use on sign-out. */
    public static String clearCookieHeader() {
        return NAME + "=; Path=" + PATH + "; Max-Age=0; HttpOnly; Secure; SameSite=Strict";
    }
}
