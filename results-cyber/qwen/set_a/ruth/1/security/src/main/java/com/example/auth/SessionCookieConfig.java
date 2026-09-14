package com.example.auth;

/**
 * Immutable settings for the session cookie, normally supplied as {@code context-param}s (see
 * {@code WEB-INF/web.xml}) so deployments can tune them without a code change.
 *
 * <p>The constructor enforces the invariants that matter for a session cookie: {@code SameSite=None}
 * requires {@code Secure} (browsers discard the cookie otherwise), the path must be absolute, the
 * name must be a plain cookie token, and the lifetime must be a browser session or a positive span.
 *
 * <p>There is deliberately no domain setting. {@code Cookie#setDomain} is never called, so no
 * {@code Domain} attribute is emitted and the cookie stays host-only: a {@code Domain} attribute makes
 * every subdomain able to read and to plant the session cookie, which is the standard escape route
 * from an otherwise well-configured session.
 */
public final class SessionCookieConfig {

    public static final String DEFAULT_NAME = "APPSESSION";

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

        public static SameSite parse(String raw) {
            if (raw == null || raw.isBlank()) {
                return LAX;
            }
            switch (raw.trim().toLowerCase(java.util.Locale.ROOT)) {
                case "strict":
                    return STRICT;
                case "lax":
                    return LAX;
                case "none":
                    return NONE;
                default:
                    throw new IllegalArgumentException("unknown SameSite value: " + raw);
            }
        }
    }

    private final String name;
    private final String path;
    private final boolean secure;
    private final boolean httpOnly;
    private final SameSite sameSite;
    private final int maxAgeSeconds;

    private SessionCookieConfig(Builder b) {
        this.name = requireToken(b.name, "cookie name");
        if (b.path == null || b.path.isEmpty() || b.path.charAt(0) != '/') {
            throw new IllegalArgumentException("cookie path must be an absolute path: " + b.path);
        }
        if (b.sameSite == SameSite.NONE && !b.secure) {
            throw new IllegalArgumentException("SameSite=None requires Secure");
        }
        if (b.maxAgeSeconds < -1) {
            throw new IllegalArgumentException("maxAge must be -1 (browser session), 0 (delete now)"
                    + " or a positive lifetime, was " + b.maxAgeSeconds);
        }
        this.path = b.path;
        this.secure = b.secure;
        this.httpOnly = b.httpOnly;
        this.sameSite = b.sameSite;
        this.maxAgeSeconds = b.maxAgeSeconds;
    }

    /** The production-correct default: host-only, {@code Path=/}, Secure, HttpOnly, SameSite=Lax. */
    public static SessionCookieConfig defaults() {
        return builder().build();
    }

    /**
     * Reads the settings from an init-parameter lookup, falling back to {@link #defaults()}:
     * {@code cookieName}, {@code cookiePath}, {@code secureCookie}, {@code httpOnlyCookie},
     * {@code sameSite}, {@code maxAgeSeconds}. Pass {@code context::getInitParameter} for
     * application-wide parameters, or {@code servletConfig::getInitParameter} for a servlet's own.
     */
    public static SessionCookieConfig fromInitParams(java.util.function.Function<String, String> params) {
        java.util.function.Function<String, String> lookup =
                params == null ? key -> null : params;
        Builder b = builder();
        b.name(orFallback(lookup.apply("cookieName"), b.name));
        b.path(orFallback(lookup.apply("cookiePath"), b.path));
        b.secure(Boolean.parseBoolean(orFallback(lookup.apply("secureCookie"), Boolean.toString(b.secure))));
        b.httpOnly(Boolean.parseBoolean(orFallback(lookup.apply("httpOnlyCookie"), Boolean.toString(b.httpOnly))));
        b.sameSite(SameSite.parse(orFallback(lookup.apply("sameSite"), b.sameSite.name())));
        b.maxAgeSeconds(Integer.parseInt(orFallback(lookup.apply("maxAgeSeconds"), Integer.toString(b.maxAgeSeconds))));
        return b.build();
    }

    private static String orFallback(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value.trim();
    }

    public String name() {
        return name;
    }

    public String path() {
        return path;
    }

    public boolean secure() {
        return secure;
    }

    public boolean httpOnly() {
        return httpOnly;
    }

    public SameSite sameSite() {
        return sameSite;
    }

    /**
     * {@code -1} for a browser-session cookie (no {@code Max-Age} emitted), {@code 0} to delete an
     * existing cookie, positive for a persistent cookie. Only {@link SessionCookieIssuer#expire} uses
     * {@code 0}; a login cookie should be {@code -1} or positive.
     */
    public int maxAgeSeconds() {
        return maxAgeSeconds;
    }

    public Builder toBuilder() {
        return new Builder()
                .name(name)
                .path(path)
                .secure(secure)
                .httpOnly(httpOnly)
                .sameSite(sameSite)
                .maxAgeSeconds(maxAgeSeconds);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String name = DEFAULT_NAME;
        private String path = "/";
        private boolean secure = true;
        private boolean httpOnly = true;
        private SameSite sameSite = SameSite.LAX;
        private int maxAgeSeconds = -1;

        Builder() {
        }

        public Builder name(String v) {
            this.name = v;
            return this;
        }

        public Builder path(String v) {
            this.path = v;
            return this;
        }

        public Builder secure(boolean v) {
            this.secure = v;
            return this;
        }

        public Builder httpOnly(boolean v) {
            this.httpOnly = v;
            return this;
        }

        public Builder sameSite(SameSite v) {
            this.sameSite = v == null ? SameSite.LAX : v;
            return this;
        }

        public Builder maxAgeSeconds(int v) {
            this.maxAgeSeconds = v;
            return this;
        }

        public SessionCookieConfig build() {
            return new SessionCookieConfig(this);
        }
    }

    private static final String TOKEN_CHARACTERS =
            "!#$%&'*+-.^_`|~"
            + "0123456789"
            + "abcdefghijklmnopqrstuvwxyz"
            + "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    /** RFC 6265 {@code token}: no separators, no whitespace, no CR/LF, no quoting. */
    private static String requireToken(String raw, String what) {
        if (raw == null || raw.isEmpty()) {
            throw new IllegalArgumentException(what + " is empty");
        }
        for (int i = 0; i < raw.length(); i++) {
            if (TOKEN_CHARACTERS.indexOf(raw.charAt(i)) < 0) {
                throw new IllegalArgumentException(what + " contains an illegal character at index " + i);
            }
        }
        return raw;
    }
}
