package com.example.identity;

/**
 * The {@code Set-Cookie} shape for a session token, for the deployment shape this program is meant
 * to serve (an HTTP front end in front of {@link AuthApi}).
 *
 * <p>This CLI sets no cookie - it has no transport, and it deliberately never prints the token
 * either - so nothing in the current code path emits a {@code Set-Cookie} line at all. Centralising
 * the attribute string here means the moment someone adds an HTTP layer there is one place that says
 * what the cookie looks like, and one test that pins it.
 *
 * <p>Every attribute is present for a reason:
 * <ul>
 *   <li>{@code HttpOnly} - a cross-site script cannot read the token out of {@code document.cookie}.</li>
 *   <li>{@code Secure} - never sent over plaintext HTTP, so it cannot be captured on the wire or
 *       leaked by a downgrade. Omitting it is the single most damaging cookie omission.</li>
 *   <li>{@code SameSite=Strict} - not attached to cross-site navigations, which is what blocks the
 *       CSRF shape where an attacker's page causes a logged-in browser to act.</li>
 *   <li>{@code Path=/} - stated explicitly rather than inherited from the request URL, so a token
 *       issued at {@code /deep/app/login} is not scoped to a path an attacker's sibling
 *       application cannot be trusted to observe.</li>
 *   <li>{@code Max-Age} - the same TTL the server enforces, so the client never replays a token the
 *       server already considers dead.</li>
 * </ul>
 * No {@code Domain} attribute: that would widen the cookie to every subdomain, and this program
 * never needs the wider scope.
 */
final class CookieSpec {

    static final String NAME = "sid";
    private static final String STATIC_ATTRIBUTES =
            "Path=/; HttpOnly; Secure; SameSite=Strict";

    private CookieSpec() {
    }

    /**
     * @param token      the freshly issued token; never logged by this method
     * @param maxAgeSeconds must be within the TTL range the server itself enforces
     * @throws IdentityStoreException if the token or lifetime is unusable
     */
    static String setCookieHeader(SessionToken token, int maxAgeSeconds) throws IdentityStoreException {
        if (token == null) {
            throw new IdentityStoreException(Reason.INVALID_SESSION, "no token to place in a cookie");
        }
        if (maxAgeSeconds < 1 || maxAgeSeconds > Config.SESSION_TTL_MAX_SECONDS) {
            throw new IdentityStoreException(Reason.CONFIG_INVALID,
                    "cookie Max-Age must be within [1, " + Config.SESSION_TTL_MAX_SECONDS + "]");
        }
        return NAME + "=" + token.value() + "; Max-Age=" + maxAgeSeconds + "; " + STATIC_ATTRIBUTES;
    }

    /** Attribute list without the value, for the README and for the test's equality check. */
    static String attributes() {
        return STATIC_ATTRIBUTES;
    }
}
