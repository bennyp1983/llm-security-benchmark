package com.example.websession;

import java.util.Objects;

/**
 * Builds the {@code Set-Cookie} header value.
 *
 * <p>The Servlet API's {@link jakarta.servlet.http.Cookie} is the platform mechanism and is
 * used for the parts it covers well, but attribute support has varied across containers
 * ({@code SameSite} only became a first-class attribute in Servlet 6.0, and older
 * containers silently dropped unknown attributes). Since a silently dropped {@code SameSite}
 * or {@code HttpOnly} is exactly the kind of defect that is invisible in testing and fatal
 * in production, this component emits one deterministic, fully specified header itself.</p>
 *
 * <p>Injection is prevented structurally, not by escaping: the name comes from
 * {@link SessionCookieSettings} (validated against a character allowlist at startup), the
 * value from {@link SessionIdValidator} (base64url only), and the attributes are chosen
 * from fixed strings and a non-negative long. No caller-supplied text reaches the header
 * unchecked, so no CR/LF can enter it.</p>
 */
final class SetCookieHeaderFactory {

    private SetCookieHeaderFactory() {
    }

    /**
     * @param sessionId a value that has already passed {@link SessionIdValidator#isValid}
     * @param maxAgeSeconds {@code 0} to omit {@code Max-Age} (browser-session cookie)
     */
    static String issue(SessionCookieSettings settings, String sessionId, long maxAgeSeconds) {
        Objects.requireNonNull(settings, "settings");
        if (!SessionIdValidator.isValid(sessionId)) {
            // Defence in depth: this is unreachable through SessionCookieIssuer, and if it
            // ever becomes reachable it must fail rather than emit an unvalidated header.
            throw new IllegalArgumentException("session identifier failed validation");
        }
        if (maxAgeSeconds < 0) {
            throw new IllegalArgumentException("maxAgeSeconds must not be negative");
        }
        return build(settings, sessionId, maxAgeSeconds, maxAgeSeconds > 0);
    }

    /**
     * Header that deletes the cookie. The attributes must match the issued cookie exactly
     * (same name, path, Secure, SameSite) or the browser keeps the original alongside it.
     */
    static String expire(SessionCookieSettings settings) {
        Objects.requireNonNull(settings, "settings");
        return build(settings, "", 0, true);
    }

    private static String build(SessionCookieSettings settings, String value, long maxAge, boolean emitMaxAge) {
        StringBuilder sb = new StringBuilder(160);
        sb.append(settings.cookieName()).append('=').append(value);
        // Path is always set explicitly: without it the browser scopes the cookie to the
        // directory of the issuing URL, which both breaks the session and makes a later
        // overlapping cookie from another path possible.
        sb.append("; Path=").append(settings.path());
        // Deliberately no Domain attribute: a host-only cookie is not shared with sibling
        // subdomains, which is what a __Host- prefixed cookie requires anyway.
        if (emitMaxAge) {
            sb.append("; Max-Age=").append(maxAge);
            if (maxAge == 0) {
                // Expires in the past, for the deletion case, so pre-Max-Age clients also drop it.
                sb.append("; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
            }
        }
        sb.append("; HttpOnly");
        if (settings.secure()) {
            sb.append("; Secure");
        }
        sb.append("; SameSite=").append(settings.sameSite());
        return sb.toString();
    }
}
