package com.example.auth;

/**
 * Renders the {@code Set-Cookie} header for a session identifier.
 *
 * <p>Attributes are fixed in code rather than configured, so no deployment can
 * accidentally weaken them: {@code HttpOnly} (script cannot read the identifier),
 * {@code Secure} (never sent over cleartext), {@code SameSite=Strict} (not
 * attached to cross-site requests), an explicit narrow {@code Path}, and a
 * {@code Max-Age} that matches the server-side absolute timeout. The {@code __Host-}
 * name prefix makes browsers reject the cookie unless it is secure, host-scoped
 * and path {@code /}, which stops a sibling subdomain from planting one.</p>
 */
public final class SessionCookie {

    public static final String NAME = "__Host-session";
    private static final String PATH = "/";

    private SessionCookie() {
    }

    /**
     * @param identifier an identifier produced by {@link SessionRegistry#issue}
     * @param maxAgeSeconds cookie lifetime; must match the session's absolute timeout
     */
    public static String setCookieHeader(String identifier, long maxAgeSeconds) {
        if (!InputPolicy.isWellFormedSessionId(identifier)) {
            // Refuses to emit a header for anything but a well-formed identifier,
            // so no value can smuggle attributes or a header break into the response.
            throw new IllegalArgumentException("identifier is not a valid session identifier");
        }
        if (maxAgeSeconds <= 0 || maxAgeSeconds > 604_800) {
            throw new IllegalArgumentException("maxAgeSeconds must be within (0, 604800]");
        }
        return NAME + "=" + identifier
                + "; Max-Age=" + maxAgeSeconds
                + "; Path=" + PATH
                + "; Secure; HttpOnly; SameSite=Strict";
    }

    /** Header that clears the cookie, for use on sign-out or a rejected session. */
    public static String clearCookieHeader() {
        return NAME + "=; Max-Age=0; Path=" + PATH + "; Secure; HttpOnly; SameSite=Strict";
    }
}
