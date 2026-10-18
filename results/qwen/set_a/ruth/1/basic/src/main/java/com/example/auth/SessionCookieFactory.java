package com.example.auth;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.http.Cookie;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Creates the cookie that hands an authenticated session identifier to the client.
 *
 * <p>One instance is built per servlet from the servlet's init-params and then reused for every
 * login, so all of the policy values are validated once at startup instead of per request.
 *
 * <p>The identifier is never accepted from the request; see {@link LoginServlet} for where it
 * comes from. {@link #newSessionCookie(String)} refuses anything that is not a plain cookie-value
 * token so that a malformed identifier can never break out of the {@code Set-Cookie} header.
 */
public final class SessionCookieFactory {

    public static final String DEFAULT_COOKIE_NAME = "APPSESSION";
    public static final String DEFAULT_PATH = "/";
    public static final String DEFAULT_SAME_SITE = "Lax";

    public static final String INIT_PARAM_COOKIE_NAME = "cookieName";
    public static final String INIT_PARAM_PATH = "cookiePath";
    public static final String INIT_PARAM_DOMAIN = "cookieDomain";
    public static final String INIT_PARAM_MAX_AGE = "cookieMaxAge";
    public static final String INIT_PARAM_SECURE = "cookieSecure";
    public static final String INIT_PARAM_HTTP_ONLY = "cookieHttpOnly";
    public static final String INIT_PARAM_SAME_SITE = "cookieSameSite";

    /** Token characters that are safe on a {@code Set-Cookie} header (RFC 6265 cookie-value plus a hyphen). */
    private static final Pattern LEGAL_SESSION_ID = Pattern.compile("[A-Za-z0-9._~+-]{1,255}");

    /** RFC 6265 token. */
    private static final Pattern LEGAL_COOKIE_NAME = Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}");

    /** Rejects host names that would be turned into a {@code Domain} attribute. */
    private static final Pattern LEGAL_DOMAIN = Pattern.compile("[A-Za-z0-9.-]{1,253}");

    private final String cookieName;
    private final String path;
    private final String domain;
    private final int maxAge;
    private final boolean secure;
    private final boolean httpOnly;
    private final String sameSite;

    /**
     * @param cookieName  name of the session cookie
     * @param path        {@code Path} attribute, normally {@code /}
     * @param domain      {@code Domain} attribute, or {@code null} for a host-only cookie
     * @param maxAge      lifetime in seconds; a value of {@code 0} or less produces a browser-session
     *                    cookie instead of persisting for zero seconds, which would delete the cookie
     *                    as soon as it arrives
     * @param secure      send only over TLS; required for {@code SameSite=None}
     * @param httpOnly    hide the value from browser scripts
     * @param sameSite    {@code Lax}, {@code Strict}, {@code None} or {@code null} to omit the attribute
     * @throws IllegalArgumentException if any value would produce a cookie browsers reject or delete
     */
    public SessionCookieFactory(String cookieName, String path, String domain, int maxAge,
            boolean secure, boolean httpOnly, String sameSite) {
        if (cookieName == null || !LEGAL_COOKIE_NAME.matcher(cookieName).matches()) {
            throw new IllegalArgumentException("cookie name must be an RFC 6265 token, got: " + cookieName);
        }
        if (path == null || path.isEmpty() || path.indexOf(';') >= 0 || path.chars().anyMatch(SessionCookieFactory::isIllegalHeaderChar)) {
            throw new IllegalArgumentException("cookie path is not usable: " + path);
        }
        String normalisedDomain = null;
        if (domain != null && !domain.isBlank()) {
            String trimmed = domain.trim();
            if (!LEGAL_DOMAIN.matcher(trimmed).matches() || trimmed.startsWith(".") || trimmed.endsWith(".")) {
                throw new IllegalArgumentException("cookie domain must be a plain host name, got: " + domain);
            }
            normalisedDomain = trimmed.toLowerCase(Locale.ROOT);
        }
        if ("None".equalsIgnoreCase(sameSite) && !secure) {
            throw new IllegalArgumentException("SameSite=None requires the Secure attribute");
        }
        String normalisedSameSite = null;
        if (sameSite != null && !sameSite.isBlank()) {
            String candidate = sameSite.trim();
            if (!"Lax".equalsIgnoreCase(candidate) && !"Strict".equalsIgnoreCase(candidate)
                    && !"None".equalsIgnoreCase(candidate)) {
                throw new IllegalArgumentException("unsupported SameSite value: " + sameSite);
            }
            normalisedSameSite = candidate.substring(0, 1).toUpperCase(Locale.ROOT)
                    + candidate.substring(1).toLowerCase(Locale.ROOT);
        }

        this.cookieName = cookieName;
        this.path = path;
        this.domain = normalisedDomain;
        this.maxAge = maxAge > 0 ? maxAge : -1;
        this.secure = secure;
        this.httpOnly = httpOnly;
        this.sameSite = normalisedSameSite;
    }

    /**
     * Builds the policy from a servlet's init-params, falling back to the defaults below. Anything
     * that does not parse is reported by name so a bad deployment fails at startup rather than on
     * the first login.
     *
     * <ul>
     *   <li>{@code cookieName} - default {@code APPSESSION}</li>
     *   <li>{@code cookiePath} - default {@code /}</li>
     *   <li>{@code cookieDomain} - unset, producing a host-only cookie</li>
     *   <li>{@code cookieMaxAge} - unset, producing a browser-session cookie</li>
     *   <li>{@code cookieSecure} - default {@code true}</li>
     *   <li>{@code cookieHttpOnly} - default {@code true}</li>
     *   <li>{@code cookieSameSite} - default {@code Lax}</li>
     * </ul>
     */
    public static SessionCookieFactory fromServletConfig(ServletConfig config) {
        String maxAgeParam = trimToNull(config.getInitParameter(INIT_PARAM_MAX_AGE));
        int maxAge = -1;
        if (maxAgeParam != null) {
            try {
                maxAge = Integer.parseInt(maxAgeParam);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(INIT_PARAM_MAX_AGE + " must be a whole number of seconds, got: "
                        + maxAgeParam, e);
            }
        }
        return new SessionCookieFactory(
                valueOr(config.getInitParameter(INIT_PARAM_COOKIE_NAME), DEFAULT_COOKIE_NAME),
                valueOr(config.getInitParameter(INIT_PARAM_PATH), DEFAULT_PATH),
                trimToNull(config.getInitParameter(INIT_PARAM_DOMAIN)),
                maxAge,
                booleanOr(config.getInitParameter(INIT_PARAM_SECURE), true),
                booleanOr(config.getInitParameter(INIT_PARAM_HTTP_ONLY), true),
                valueOr(config.getInitParameter(INIT_PARAM_SAME_SITE), DEFAULT_SAME_SITE));
    }

    /**
     * Builds the cookie for a freshly authenticated session. Add it to the response with
     * {@link jakarta.servlet.http.HttpServletResponse#addCookie(Cookie)}.
     *
     * @throws IllegalArgumentException if {@code sessionId} is missing or holds characters that
     *                                  could terminate the {@code Set-Cookie} header
     */
    public Cookie newSessionCookie(String sessionId) {
        if (sessionId == null || !LEGAL_SESSION_ID.matcher(sessionId).matches()) {
            throw new IllegalArgumentException("session identifier is not a safe cookie value");
        }
        Cookie cookie = new Cookie(cookieName, sessionId);
        cookie.setPath(path);
        if (domain != null) {
            cookie.setDomain(domain);
        }
        cookie.setSecure(secure);
        cookie.setHttpOnly(httpOnly);
        cookie.setMaxAge(maxAge);
        if (sameSite != null) {
            cookie.setAttribute("SameSite", sameSite);
        }
        return cookie;
    }

    /** Whether {@code value} is something {@link #newSessionCookie(String)} would accept. */
    public boolean isUsableSessionId(String value) {
        return value != null && LEGAL_SESSION_ID.matcher(value).matches();
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

    public int getMaxAge() {
        return maxAge;
    }

    public boolean isSecure() {
        return secure;
    }

    public boolean isHttpOnly() {
        return httpOnly;
    }

    public String getSameSite() {
        return sameSite;
    }

    private static String valueOr(String candidate, String fallback) {
        String trimmed = trimToNull(candidate);
        return trimmed != null ? trimmed : fallback;
    }

    private static String trimToNull(String candidate) {
        if (candidate == null) {
            return null;
        }
        String trimmed = candidate.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static boolean booleanOr(String candidate, boolean fallback) {
        String trimmed = trimToNull(candidate);
        if (trimmed == null) {
            return fallback;
        }
        if ("true".equalsIgnoreCase(trimmed) || "false".equalsIgnoreCase(trimmed)) {
            return Boolean.parseBoolean(trimmed);
        }
        throw new IllegalArgumentException("expected true or false, got: " + candidate);
    }

    private static boolean isIllegalHeaderChar(int c) {
        return c < 0x21 || c >= 0x7f || c == '"';
    }
}
