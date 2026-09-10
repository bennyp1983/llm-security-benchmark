package com.example.auth.session;

import java.util.Objects;

/**
 * Immutable description of how the authenticated-session cookie is emitted.
 *
 * <p>The defaults are the hardened ones: host-only, {@code Secure}, {@code HttpOnly},
 * {@code SameSite=Lax} and a browser-session lifetime. Every relaxation (a wider domain, a
 * non-secure cookie, {@code SameSite=None}) has to be asked for explicitly and is validated
 * against what the browser will actually accept.
 */
public record SessionCookieConfig(
        String name,
        String path,
        String domain,
        int maxAgeSeconds,
        boolean secure,
        boolean httpOnly,
        SameSite sameSite,
        boolean hostPrefix) {

    public enum SameSite {
        STRICT("Strict"),
        LAX("Lax"),
        NONE("None");

        private final String headerValue;

        SameSite(String headerValue) {
            this.headerValue = headerValue;
        }

        public String headerValue() {
            return headerValue;
        }
    }

    public static final String DEFAULT_NAME = "SESSION";

    public static final SessionCookieConfig DEFAULTS =
            new SessionCookieConfig(DEFAULT_NAME, "/", null, -1, true, true, SameSite.LAX, false);

    /**
     * @param domain        {@code null} keeps the cookie host-only; setting it widens the cookie to
     *                      every subdomain, which widens the blast radius of any XSS there
     * @param maxAgeSeconds {@code -1} for a cookie that dies with the browser, otherwise the
     *                      absolute lifetime of the session cookie
     */
    public SessionCookieConfig {
        Objects.requireNonNull(name, "cookie name");
        Objects.requireNonNull(path, "cookie path");
        Objects.requireNonNull(sameSite, "SameSite");
        if (!isToken(name)) {
            throw new IllegalArgumentException("cookie name must be an RFC 6265 token: " + name);
        }
        if (path.isEmpty() || path.charAt(0) != '/') {
            throw new IllegalArgumentException("cookie path must start with '/': " + path);
        }
        if (maxAgeSeconds < -1) {
            throw new IllegalArgumentException("maxAgeSeconds must be -1 (session cookie) or >= 0");
        }
        if (sameSite == SameSite.NONE && !secure) {
            throw new IllegalArgumentException("SameSite=None is only honoured together with Secure");
        }
        if (sameSite != SameSite.NONE && !secure) {
            throw new IllegalArgumentException("an authentication cookie must be Secure; SameSite="
                    + sameSite.headerValue() + " is downgraded by browsers on plain HTTP anyway");
        }
        if (hostPrefix) {
            if (domain != null) {
                throw new IllegalArgumentException("__Host- prefixed cookies must not carry a Domain");
            }
            if (!"/".equals(path)) {
                throw new IllegalArgumentException("__Host- prefixed cookies must have Path=/");
            }
        }
    }

    /** The name the cookie is actually stored under, including the {@code __Host-} prefix. */
    public String effectiveName() {
        if (!hostPrefix || name.startsWith("__Host-")) {
            return name;
        }
        return "__Host-" + name;
    }

    public SessionCookieConfig withHostPrefix(boolean prefix) {
        return new SessionCookieConfig(name, path, domain, maxAgeSeconds, secure, httpOnly, sameSite, prefix);
    }

    public SessionCookieConfig withSameSite(SameSite site) {
        return new SessionCookieConfig(name, path, domain, maxAgeSeconds, secure, httpOnly, site, hostPrefix);
    }

    public SessionCookieConfig withMaxAgeSeconds(int seconds) {
        return new SessionCookieConfig(name, path, domain, seconds, secure, httpOnly, sameSite, hostPrefix);
    }

    /** Copy of this configuration that expires the cookie instead of establishing it. */
    public SessionCookieConfig expiring() {
        return withMaxAgeSeconds(0);
    }

    private static boolean isToken(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (!isTokenChar(value.charAt(i))) {
                return false;
            }
        }
        return !value.isEmpty();
    }

    private static boolean isTokenChar(char c) {
        return (c >= 'a' && c <= 'z')
                || (c >= 'A' && c <= 'Z')
                || (c >= '0' && c <= '9')
                || "!#$%&'*+-.^_`|~".indexOf(c) >= 0;
    }
}
