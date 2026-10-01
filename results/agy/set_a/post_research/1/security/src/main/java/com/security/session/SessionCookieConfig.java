package com.security.session;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Immutable security configuration for post-authentication session cookie creation.
 * Enforces strict cookie prefixes (__Host-), RFC 6265bis compliance, and bounds checking.
 */
public final class SessionCookieConfig {

    private static final Pattern COOKIE_NAME_SAFE_PATTERN = Pattern.compile("^[a-zA-Z0-9_\\-]+$");
    private static final Pattern PATH_SAFE_PATTERN = Pattern.compile("^/[a-zA-Z0-9_\\-/]*$");
    private static final Pattern DOMAIN_SAFE_PATTERN = Pattern.compile("^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\\.[a-zA-Z0-9-]{1,63})*$");

    private final String cookieName;
    private final String path;
    private final String domain;
    private final int maxAgeSeconds;
    private final SameSitePolicy sameSite;
    private final boolean secure;
    private final boolean httpOnly;
    private final boolean partitioned;
    private final boolean requireSecureTransport;
    private final int minSessionIdLength;
    private final int maxSessionIdLength;
    private final Pattern sessionIdPattern;
    private final int maxUserIdLength;
    private final Pattern userIdPattern;
    private final boolean trustForwardedHeaders;
    private final String trustedProxyIpHeader;

    private SessionCookieConfig(Builder builder) {
        this.cookieName = builder.cookieName;
        this.path = builder.path;
        this.domain = builder.domain;
        this.maxAgeSeconds = builder.maxAgeSeconds;
        this.sameSite = builder.sameSite;
        this.secure = builder.secure;
        this.httpOnly = builder.httpOnly;
        this.partitioned = builder.partitioned;
        this.requireSecureTransport = builder.requireSecureTransport;
        this.minSessionIdLength = builder.minSessionIdLength;
        this.maxSessionIdLength = builder.maxSessionIdLength;
        this.sessionIdPattern = builder.sessionIdPattern;
        this.maxUserIdLength = builder.maxUserIdLength;
        this.userIdPattern = builder.userIdPattern;
        this.trustForwardedHeaders = builder.trustForwardedHeaders;
        this.trustedProxyIpHeader = builder.trustedProxyIpHeader;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static SessionCookieConfig createDefault() {
        return builder().build();
    }

    public String getCookieName() {
        return cookieName;
    }

    public String getPath() {
        return path;
    }

    public String getDomain() {
        return domain;
    }

    public int getMaxAgeSeconds() {
        return maxAgeSeconds;
    }

    public SameSitePolicy getSameSite() {
        return sameSite;
    }

    public boolean isSecure() {
        return secure;
    }

    public boolean isHttpOnly() {
        return httpOnly;
    }

    public boolean isPartitioned() {
        return partitioned;
    }

    public boolean isRequireSecureTransport() {
        return requireSecureTransport;
    }

    public int getMinSessionIdLength() {
        return minSessionIdLength;
    }

    public int getMaxSessionIdLength() {
        return maxSessionIdLength;
    }

    public Pattern getSessionIdPattern() {
        return sessionIdPattern;
    }

    public int getMaxUserIdLength() {
        return maxUserIdLength;
    }

    public Pattern getUserIdPattern() {
        return userIdPattern;
    }

    public boolean isTrustForwardedHeaders() {
        return trustForwardedHeaders;
    }

    public String getTrustedProxyIpHeader() {
        return trustedProxyIpHeader;
    }

    public static final class Builder {
        private String cookieName = "__Host-SESSIONID";
        private String path = "/";
        private String domain = null;
        private int maxAgeSeconds = -1; // Default to browser session lifetime
        private SameSitePolicy sameSite = SameSitePolicy.STRICT;
        private boolean secure = true;
        private final boolean httpOnly = true; // Immutable: always true for session cookies
        private boolean partitioned = false;
        private boolean requireSecureTransport = true;
        private int minSessionIdLength = 16;
        private int maxSessionIdLength = 128;
        private Pattern sessionIdPattern = Pattern.compile("^[A-Za-z0-9_-]{16,128}$");
        private int maxUserIdLength = 64;
        private Pattern userIdPattern = Pattern.compile("^[A-Za-z0-9_.@-]{1,64}$");
        private boolean trustForwardedHeaders = false;
        private String trustedProxyIpHeader = "X-Forwarded-For";

        public Builder cookieName(String cookieName) {
            this.cookieName = cookieName;
            return this;
        }

        public Builder path(String path) {
            this.path = path;
            return this;
        }

        public Builder domain(String domain) {
            this.domain = domain;
            return this;
        }

        public Builder maxAgeSeconds(int maxAgeSeconds) {
            this.maxAgeSeconds = maxAgeSeconds;
            return this;
        }

        public Builder sameSite(SameSitePolicy sameSite) {
            this.sameSite = Objects.requireNonNull(sameSite, "sameSite policy cannot be null");
            return this;
        }

        public Builder secure(boolean secure) {
            this.secure = secure;
            return this;
        }

        public Builder partitioned(boolean partitioned) {
            this.partitioned = partitioned;
            return this;
        }

        public Builder requireSecureTransport(boolean requireSecureTransport) {
            this.requireSecureTransport = requireSecureTransport;
            return this;
        }

        public Builder sessionIdConstraints(int minLength, int maxLength, String regexPattern) {
            if (minLength < 16) {
                throw new IllegalArgumentException("Minimum session ID length must be at least 16 characters for security entropy");
            }
            if (maxLength < minLength || maxLength > 512) {
                throw new IllegalArgumentException("Maximum session ID length must be between minLength and 512 characters");
            }
            this.minSessionIdLength = minLength;
            this.maxSessionIdLength = maxLength;
            this.sessionIdPattern = Pattern.compile(regexPattern);
            return this;
        }

        public Builder userIdConstraints(int maxLength, String regexPattern) {
            if (maxLength < 1 || maxLength > 256) {
                throw new IllegalArgumentException("User ID length must be between 1 and 256 characters");
            }
            this.maxUserIdLength = maxLength;
            this.userIdPattern = Pattern.compile(regexPattern);
            return this;
        }

        public Builder trustForwardedHeaders(boolean trustForwardedHeaders, String headerName) {
            this.trustForwardedHeaders = trustForwardedHeaders;
            if (headerName != null && !headerName.isBlank()) {
                this.trustedProxyIpHeader = headerName.trim();
            }
            return this;
        }

        public SessionCookieConfig build() {
            // Validate Cookie Name
            if (cookieName == null || cookieName.isBlank()) {
                throw new SecurityValidationException("Invalid configuration", "Cookie name cannot be null or blank");
            }
            if (cookieName.length() > 64) {
                throw new SecurityValidationException("Invalid configuration", "Cookie name exceeds maximum length of 64 characters");
            }
            if (!COOKIE_NAME_SAFE_PATTERN.matcher(cookieName).matches()) {
                throw new SecurityValidationException("Invalid configuration", "Cookie name contains forbidden characters: " + cookieName);
            }

            // Validate Path
            if (path == null || path.isBlank()) {
                throw new SecurityValidationException("Invalid configuration", "Cookie path cannot be null or blank");
            }
            if (!path.startsWith("/")) {
                throw new SecurityValidationException("Invalid configuration", "Cookie path must start with '/'");
            }
            if (!PATH_SAFE_PATTERN.matcher(path).matches()) {
                throw new SecurityValidationException("Invalid configuration", "Cookie path contains forbidden characters: " + path);
            }

            // Validate Domain
            if (domain != null && !domain.isBlank()) {
                if (domain.length() > 255 || !DOMAIN_SAFE_PATTERN.matcher(domain).matches()) {
                    throw new SecurityValidationException("Invalid configuration", "Invalid cookie domain: " + domain);
                }
            }

            // Validate Max-Age
            if (maxAgeSeconds < -1 || maxAgeSeconds > 2_592_000) { // Max 30 days bounded lifetime
                throw new SecurityValidationException("Invalid configuration", "Cookie maxAge must be -1 or between 0 and 2,592,000 seconds (30 days)");
            }

            // Validate RFC 6265bis prefix: __Host-
            if (cookieName.startsWith("__Host-")) {
                if (!secure) {
                    throw new SecurityValidationException("Invalid configuration", "Cookies with '__Host-' prefix must have the 'Secure' attribute set");
                }
                if (domain != null && !domain.isBlank()) {
                    throw new SecurityValidationException("Invalid configuration", "Cookies with '__Host-' prefix must NOT specify a 'Domain' attribute");
                }
                if (!"/".equals(path)) {
                    throw new SecurityValidationException("Invalid configuration", "Cookies with '__Host-' prefix must specify Path='/'");
                }
            }

            // Validate RFC 6265bis prefix: __Secure-
            if (cookieName.startsWith("__Secure-")) {
                if (!secure) {
                    throw new SecurityValidationException("Invalid configuration", "Cookies with '__Secure-' prefix must have the 'Secure' attribute set");
                }
            }

            // Validate SameSite=None requires Secure
            if (sameSite == SameSitePolicy.NONE && !secure) {
                throw new SecurityValidationException("Invalid configuration", "SameSite=None requires the Secure attribute to be set");
            }

            return new SessionCookieConfig(this);
        }
    }
}
