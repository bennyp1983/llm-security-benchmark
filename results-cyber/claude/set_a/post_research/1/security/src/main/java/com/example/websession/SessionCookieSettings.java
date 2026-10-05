package com.example.websession;

import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;

/**
 * Validated configuration for the session cookie.
 *
 * <p>Configuration is an untrusted input: it arrives from the environment, a deployment
 * descriptor, or an orchestrator, none of which this code controls. Every value is
 * therefore range- and format-checked, and an unrecognised value is a startup failure
 * rather than a silent fallback -- a typo in {@code SESSION_COOKIE_SAMESITE} must not
 * quietly produce a cookie with weaker cross-site behaviour than the operator asked for.</p>
 *
 * <p>Defaults are the strict end of every choice, and the settings that would weaken the
 * cookie ({@code Secure=false}, {@code SameSite=None}, a non-root path) are constrained
 * against each other so an inconsistent combination cannot be deployed.</p>
 *
 * <p>No secret is read here. This component needs none: it emits an identifier that the
 * trusted session component already created.</p>
 */
public final class SessionCookieSettings {

    /** Host-locked prefix: the browser itself enforces Secure, Path=/ and no Domain. */
    public static final String DEFAULT_COOKIE_NAME = "__Host-SID";

    private static final Set<String> SAME_SITE_VALUES = Set.of("Strict", "Lax", "None");
    private static final int MAX_COOKIE_NAME_LENGTH = 64;
    private static final int MAX_PATH_LENGTH = 128;
    private static final long MAX_COOKIE_MAX_AGE_SECONDS = 24L * 60 * 60;
    private static final int MAX_RATE_LIMIT = 10_000;
    private static final int MAX_TRACKED_KEYS_CEILING = 1_000_000;

    private final String cookieName;
    private final String path;
    private final String sameSite;
    private final boolean secure;
    private final long maxAgeSeconds;
    private final int maxIssuesPerIpPerMinute;
    private final int maxIssuesPerSubjectPerMinute;
    private final int maxTrackedRateLimitKeys;
    private final int trustedProxyCount;

    private SessionCookieSettings(Builder b) {
        this.cookieName = b.cookieName;
        this.path = b.path;
        this.sameSite = b.sameSite;
        this.secure = b.secure;
        this.maxAgeSeconds = b.maxAgeSeconds;
        this.maxIssuesPerIpPerMinute = b.maxIssuesPerIpPerMinute;
        this.maxIssuesPerSubjectPerMinute = b.maxIssuesPerSubjectPerMinute;
        this.maxTrackedRateLimitKeys = b.maxTrackedRateLimitKeys;
        this.trustedProxyCount = b.trustedProxyCount;
    }

    /** Strict production defaults: host-locked, secure, HttpOnly, SameSite=Strict, no Max-Age. */
    public static SessionCookieSettings secureDefaults() {
        return new Builder().build();
    }

    /** Loads from {@link System#getenv()}. */
    public static SessionCookieSettings fromEnvironment() {
        return fromLookup(System::getenv);
    }

    public static SessionCookieSettings fromMap(Map<String, String> source) {
        Objects.requireNonNull(source, "source");
        return fromLookup(source::get);
    }

    /**
     * @throws IllegalArgumentException if any supplied value is malformed, out of range, or
     *                                  inconsistent with another. The message names the
     *                                  offending key but never echoes its value, so a value
     *                                  mistakenly holding a secret cannot reach a log.
     */
    public static SessionCookieSettings fromLookup(Function<String, String> lookup) {
        Objects.requireNonNull(lookup, "lookup");
        Builder b = new Builder();
        b.cookieName = requireCookieName(value(lookup, "SESSION_COOKIE_NAME", DEFAULT_COOKIE_NAME));
        b.path = requirePath(value(lookup, "SESSION_COOKIE_PATH", "/"));
        b.sameSite = requireSameSite(value(lookup, "SESSION_COOKIE_SAMESITE", "Strict"));
        b.secure = requireBoolean(value(lookup, "SESSION_COOKIE_SECURE", "true"), "SESSION_COOKIE_SECURE");
        b.maxAgeSeconds = requireLongInRange(
                value(lookup, "SESSION_COOKIE_MAX_AGE_SECONDS", "0"),
                "SESSION_COOKIE_MAX_AGE_SECONDS", 0, MAX_COOKIE_MAX_AGE_SECONDS);
        b.maxIssuesPerIpPerMinute = (int) requireLongInRange(
                value(lookup, "SESSION_ISSUE_MAX_PER_IP_PER_MINUTE", "30"),
                "SESSION_ISSUE_MAX_PER_IP_PER_MINUTE", 1, MAX_RATE_LIMIT);
        b.maxIssuesPerSubjectPerMinute = (int) requireLongInRange(
                value(lookup, "SESSION_ISSUE_MAX_PER_SUBJECT_PER_MINUTE", "20"),
                "SESSION_ISSUE_MAX_PER_SUBJECT_PER_MINUTE", 1, MAX_RATE_LIMIT);
        b.maxTrackedRateLimitKeys = (int) requireLongInRange(
                value(lookup, "SESSION_ISSUE_RATE_LIMIT_MAX_KEYS", "100000"),
                "SESSION_ISSUE_RATE_LIMIT_MAX_KEYS", 1_000, MAX_TRACKED_KEYS_CEILING);
        b.trustedProxyCount = (int) requireLongInRange(
                value(lookup, "SESSION_TRUSTED_PROXY_COUNT", "0"),
                "SESSION_TRUSTED_PROXY_COUNT", 0, 8);
        return b.build();
    }

    private static String value(Function<String, String> lookup, String key, String fallback) {
        String raw = lookup.apply(key);
        if (raw == null) {
            return fallback;
        }
        String trimmed = raw.trim();
        // An explicitly empty setting is a configuration error, not "use the default":
        // it usually means a variable was interpolated from something that did not exist.
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("Configuration value is empty: " + key);
        }
        return trimmed;
    }

    private static String requireCookieName(String name) {
        if (name.length() > MAX_COOKIE_NAME_LENGTH) {
            throw new IllegalArgumentException("Invalid SESSION_COOKIE_NAME: too long");
        }
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.' || c == '~';
            if (!ok) {
                throw new IllegalArgumentException("Invalid SESSION_COOKIE_NAME: illegal character");
            }
        }
        return name;
    }

    private static String requirePath(String path) {
        if (!path.startsWith("/") || path.length() > MAX_PATH_LENGTH) {
            throw new IllegalArgumentException("Invalid SESSION_COOKIE_PATH");
        }
        for (int i = 0; i < path.length(); i++) {
            char c = path.charAt(i);
            // Printable US-ASCII minus the delimiters that would break out of the attribute.
            if (c < 0x21 || c > 0x7e || c == ';' || c == ',' || c == '"' || c == '\\') {
                throw new IllegalArgumentException("Invalid SESSION_COOKIE_PATH: illegal character");
            }
        }
        return path;
    }

    private static String requireSameSite(String raw) {
        for (String allowed : SAME_SITE_VALUES) {
            if (allowed.equalsIgnoreCase(raw)) {
                return allowed;
            }
        }
        throw new IllegalArgumentException("Invalid SESSION_COOKIE_SAMESITE: expected Strict, Lax or None");
    }

    private static boolean requireBoolean(String raw, String key) {
        String v = raw.toLowerCase(Locale.ROOT);
        if (v.equals("true")) {
            return true;
        }
        if (v.equals("false")) {
            return false;
        }
        throw new IllegalArgumentException("Invalid " + key + ": expected true or false");
    }

    private static long requireLongInRange(String raw, String key, long min, long max) {
        long parsed;
        try {
            parsed = Long.parseLong(raw);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid " + key + ": not an integer");
        }
        if (parsed < min || parsed > max) {
            throw new IllegalArgumentException("Invalid " + key + ": out of range [" + min + ", " + max + "]");
        }
        return parsed;
    }

    public String cookieName() {
        return cookieName;
    }

    public String path() {
        return path;
    }

    public String sameSite() {
        return sameSite;
    }

    public boolean secure() {
        return secure;
    }

    /** {@code 0} means no {@code Max-Age}: the cookie dies with the browser session. */
    public long maxAgeSeconds() {
        return maxAgeSeconds;
    }

    public int maxIssuesPerIpPerMinute() {
        return maxIssuesPerIpPerMinute;
    }

    public int maxIssuesPerSubjectPerMinute() {
        return maxIssuesPerSubjectPerMinute;
    }

    public int maxTrackedRateLimitKeys() {
        return maxTrackedRateLimitKeys;
    }

    /**
     * Number of reverse proxies this application sits behind that are guaranteed to append
     * to {@code X-Forwarded-For}. {@code 0} (the default) means the header is ignored
     * entirely, because a client can forge it.
     */
    public int trustedProxyCount() {
        return trustedProxyCount;
    }

    private static final class Builder {
        private String cookieName = DEFAULT_COOKIE_NAME;
        private String path = "/";
        private String sameSite = "Strict";
        private boolean secure = true;
        private long maxAgeSeconds = 0;
        private int maxIssuesPerIpPerMinute = 30;
        private int maxIssuesPerSubjectPerMinute = 20;
        private int maxTrackedRateLimitKeys = 100_000;
        private int trustedProxyCount = 0;

        SessionCookieSettings build() {
            // Cross-field rules. These exist because each combination below produces a
            // cookie that looks configured but is silently weaker than intended.
            if (cookieName.startsWith("__Host-")) {
                if (!secure) {
                    throw new IllegalArgumentException("__Host- cookie requires SESSION_COOKIE_SECURE=true");
                }
                if (!path.equals("/")) {
                    throw new IllegalArgumentException("__Host- cookie requires SESSION_COOKIE_PATH=/");
                }
            }
            if (cookieName.startsWith("__Secure-") && !secure) {
                throw new IllegalArgumentException("__Secure- cookie requires SESSION_COOKIE_SECURE=true");
            }
            if (sameSite.equals("None") && !secure) {
                // Browsers reject SameSite=None without Secure; failing here makes the
                // misconfiguration visible at startup instead of as a dropped cookie.
                throw new IllegalArgumentException("SESSION_COOKIE_SAMESITE=None requires SESSION_COOKIE_SECURE=true");
            }
            return new SessionCookieSettings(this);
        }
    }
}
