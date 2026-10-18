package com.example.accounts;

import java.time.Duration;

/**
 * Builds the {@code Set-Cookie} header for an issued session, for when this service is fronted by
 * an HTTP layer.
 *
 * <p>Rule 4 (cookies): the name uses the {@code __Host-} prefix, which a conforming browser accepts
 * only when the cookie is {@code Secure}, has {@code Path=/} and carries no {@code Domain} -- so
 * the browser itself enforces that the cookie cannot be planted by a sibling subdomain over plain
 * HTTP. {@code HttpOnly} keeps it out of reach of script, and {@code SameSite=Strict} means it is
 * not sent on cross-site requests at all, which removes CSRF against state-changing endpoints.
 * {@code Max-Age} matches the server-side idle timeout, but the cookie's own lifetime is never
 * trusted: {@link SessionService#validate} re-checks expiry against the database every time.
 */
public final class SessionCookie {

    /** The {@code __Host-} prefix is load-bearing; do not rename without re-reading rule 4. */
    public static final String NAME = "__Host-session";

    private SessionCookie() {
    }

    /**
     * @param token the session token; must be a well-formed token from
     *              {@link SessionService#issue}
     * @param maxAge how long the browser may keep it, normally the idle timeout
     * @return a {@code Set-Cookie} header value
     */
    public static String setCookieHeader(char[] token, Duration maxAge) {
        if (!SessionService.isWellFormedToken(token)) {
            // Fail closed rather than emit a header with something unexpected in it.
            throw new IllegalArgumentException("token is not a well-formed session token");
        }
        long seconds = Math.max(0, maxAge.getSeconds());
        StringBuilder sb = new StringBuilder(160);
        sb.append(NAME).append('=').append(token, 0, token.length)
                .append("; Path=/")
                .append("; Max-Age=").append(seconds)
                .append("; HttpOnly")
                .append("; Secure")
                .append("; SameSite=Strict");
        return sb.toString();
    }

    /** Header value that clears the cookie; pair it with a server-side revoke, never alone. */
    public static String clearCookieHeader() {
        return NAME + "=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict";
    }
}
