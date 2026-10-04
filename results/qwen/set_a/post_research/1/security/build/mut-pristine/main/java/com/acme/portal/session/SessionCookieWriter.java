package com.acme.portal.session;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Emits the session cookie on a servlet response. This is the only class in the component that
 * touches a Servlet API type, so the security decision stays testable without a container.
 *
 * <p>The identifier is re-validated immediately before emission. {@link SessionId} already validated
 * it, but the value crosses a trust boundary at this line: a later maintainer could introduce a path
 * that hands this writer an identifier from somewhere else. The response is therefore only mutated
 * after the second check passes, and the check is reject-only (no normalisation), so a rejected value
 * cannot reach the response at all.
 */
public final class SessionCookieWriter {

    private static final String SAME_SITE_ATTRIBUTE = "SameSite";

    /** Any response that can carry session material is uncacheable, without exception. */
    private static final String NO_STORE = "no-store, max-age=0";

    private final SessionCookiePolicy policy;

    public SessionCookieWriter(SessionCookiePolicy policy) {
        if (policy == null) {
            throw new IllegalArgumentException("cookie policy is required");
        }
        this.policy = policy;
    }

    /**
     * Writes the anti-caching headers and then the {@code Set-Cookie} header. Nothing else.
     *
     * <p>{@code no-store} is set first so that if the cookie write below somehow fails, the partial
     * response that reaches the network is already uncacheable. Both must precede the first body byte:
     * a servlet container silently discards headers set afterwards.
     *
     * @param sessionIdentifier identifier already accepted by the trusted session owner
     * @param response          response to mutate
     * @throws InvalidSessionIdentifierException if the identifier is not a well-formed token; the
     *         response then carries the cache headers and no cookie
     */
    public void writeSessionCookie(SessionId sessionIdentifier, HttpServletResponse response)
            throws InvalidSessionIdentifierException {
        if (response == null) {
            throw new IllegalArgumentException("response is required");
        }
        // Unconditional and first: a response that carried, failed to carry, or partially carried
        // session material must never be storable by a browser or an intermediary.
        response.setHeader("Cache-Control", NO_STORE);
        response.setHeader("Pragma", "no-cache");
        if (sessionIdentifier == null) {
            throw new InvalidSessionIdentifierException(SessionId.Rejection.ABSENT);
        }
        String value = sessionIdentifier.value();
        SessionId.Rejection rejection = SessionId.inspect(value);
        if (rejection != SessionId.Rejection.NONE) {
            // The reason class is safe to log. The value is interpolated nowhere below.
            throw new InvalidSessionIdentifierException(rejection);
        }

        Cookie cookie = new Cookie(policy.name(), value);
        cookie.setPath(policy.path());
        cookie.setHttpOnly(policy.httpOnly());
        cookie.setSecure(policy.secure());
        // setMaxAge is deliberately never called. Tomcat renders maxAge == 0 as
        // "Expires=Tue Nov 17 10:15:05 GMT 1995", an already-expired cookie the browser discards, so
        // a session cookie must keep the API default of emitting no expiry attribute at all.
        // Servlet 6.0 has no SameSite setter; the attribute map is the supported extension point and
        // Tomcat 10.1 renders it into Set-Cookie. Host-only by deliberately never calling setDomain.
        cookie.setAttribute(SAME_SITE_ATTRIBUTE, policy.sameSite());
        // addCookie, not setHeader: the container owns header syntax and quoting. One call emits one
        // Set-Cookie, so there is no header-injection surface even if a name were ever wrong.
        response.addCookie(cookie);
    }

    /** The policy in force; for startup logging and for the caller's success page. */
    public SessionCookiePolicy policy() {
        return policy;
    }
}
