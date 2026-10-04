package com.acme.portal.session;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Validated, immutable description of the session cookie this component emits.
 *
 * <p>Only three things are operator-selectable: the cookie name, the cookie path and the SameSite
 * mode. {@code Secure} and {@code HttpOnly} are invariants of this class, not configuration, so a
 * mis-deployed property cannot produce a script-readable or transport-unencrypted session cookie.
 * The cookie is always host-only (no {@code Domain}) and always a browser-session cookie (no
 * {@code Max-Age}/{@code Expires}), which bounds session lifetime by the trusted component's own
 * server-side expiry rather than by anything a client could extend or a misconfiguration could
 * stretch.
 *
 * <p>Construction is all-or-nothing. A malformed or unrecognised setting raises
 * {@link IllegalArgumentException} and the component refuses to start: there is no permissive
 * default for a security-relevant attribute and no silent coercion (a typo such as
 * {@code SameSide=Strict} fails loudly at deployment instead of quietly weakening the cookie).
 * Only a genuinely absent or empty value falls back to the hardened default below.
 */
public final class SessionCookiePolicy {

    /**
     * Default name uses the {@code __Host-} cookie prefix, which tells a conforming browser to
     * discard the cookie unless it is Secure, host-only and {@code Path=/}. That is a second,
     * client-enforced layer over the invariants this class already guarantees.
     */
    public static final String DEFAULT_NAME = "__Host-PORTAL_SESSION";

    /** Default path: the application root, so the cookie accompanies every app URL and nothing else. */
    public static final String DEFAULT_PATH = "/";

    public static final String DEFAULT_SAME_SITE = "Strict";

    /** Names this component refuses, so it can never emit a cookie named after a protocol keyword. */
    private static final Set<String> RESERVED_NAMES = new HashSet<>(Arrays.asList(
            "set-cookie", "cookie", "expires", "max-age", "domain", "path", "secure", "httponly",
            "samesite", "version", "comment"));

    private static final int MAX_NAME_LENGTH = 64;
    private static final int MAX_PATH_LENGTH = 128;

    private static final String NAME_FIRST =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_";
    private static final String NAME_REST =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

    private final String name;
    private final String path;
    private final String sameSite;

    /**
     * @param suppliedName     cookie name; {@code null} or empty selects {@link #DEFAULT_NAME}
     * @param suppliedPath     cookie path; {@code null} or empty selects {@link #DEFAULT_PATH}
     * @param suppliedSameSite exactly {@code Strict} or {@code Lax}, any case; {@code null} or
     *                         empty selects {@link #DEFAULT_SAME_SITE}
     * @throws IllegalArgumentException if a value is malformed, or a {@code __Host-} name is paired
     *         with a path the prefix contract forbids
     */
    public static SessionCookiePolicy of(String suppliedName, String suppliedPath, String suppliedSameSite) {
        String name = orDefault(suppliedName, DEFAULT_NAME);
        String path = orDefault(suppliedPath, DEFAULT_PATH);
        String requestedSameSite = orDefault(suppliedSameSite, DEFAULT_SAME_SITE);

        validateName(name);
        validatePath(path);
        String canonicalSameSite = canonicalSameSite(requestedSameSite);

        // A __Host- name is a promise the browser enforces by dropping the cookie. Secure and
        // host-only are unconditional invariants here, so Path is the only one left to check; if
        // an operator pairs the prefix with a subpath the cookie would never be stored, which is a
        // broken deployment rather than a policy we should paper over.
        if (name.startsWith("__Host-") && !"/".equals(path)) {
            throw new IllegalArgumentException(
                    "cookie name uses the __Host- prefix but path is not '/': refusing to start");
        }
        return new SessionCookiePolicy(name, path, canonicalSameSite);
    }

    /**
     * Falls back only on an absent or zero-length value. A whitespace-only setting is a typo and is
     * passed through for validation, where it is refused; values are never trimmed into validity.
     */
    private static String orDefault(String value, String fallback) {
        if (value == null || value.isEmpty()) {
            return fallback;
        }
        return value;
    }

    private static void validateName(String name) {
        if (name.length() > MAX_NAME_LENGTH) {
            throw new IllegalArgumentException("cookie name is longer than " + MAX_NAME_LENGTH + " characters");
        }
        if (NAME_FIRST.indexOf(name.charAt(0)) < 0) {
            throw new IllegalArgumentException("cookie name has an illegal first character");
        }
        for (int i = 1; i < name.length(); i++) {
            if (NAME_REST.indexOf(name.charAt(i)) < 0) {
                throw new IllegalArgumentException("cookie name has an illegal character");
            }
        }
        if (RESERVED_NAMES.contains(name.toLowerCase(Locale.ROOT))) {
            throw new IllegalArgumentException("cookie name collides with a protocol keyword");
        }
    }

    private static void validatePath(String path) {
        if (path.length() > MAX_PATH_LENGTH) {
            throw new IllegalArgumentException("cookie path is longer than " + MAX_PATH_LENGTH + " characters");
        }
        if (path.charAt(0) != '/') {
            throw new IllegalArgumentException("cookie path must start with '/'");
        }
        for (int i = 0; i < path.length(); i++) {
            char c = path.charAt(i);
            boolean allowed = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '/' || c == '_' || c == '-' || c == '.';
            if (!allowed) {
                // Rejects ';', '"', ',', ':', CR, LF, NUL, space and every non-ASCII byte, which is
                // what stops a configured path injecting a cookie attribute or a header line.
                throw new IllegalArgumentException("cookie path has an illegal character");
            }
        }
        if (path.indexOf("//") >= 0 || path.indexOf("/./") >= 0 || path.indexOf("/../") >= 0) {
            throw new IllegalArgumentException(
                    "cookie path must be normalized and must not contain '//' or dot segments");
        }
    }

    private static String canonicalSameSite(String value) {
        if ("strict".equalsIgnoreCase(value)) {
            return "Strict";
        }
        if ("lax".equalsIgnoreCase(value)) {
            return "Lax";
        }
        if ("none".equalsIgnoreCase(value)) {
            // SameSite=None is what a cross-site embed needs. It turns a first-party session cookie
            // into a third-party cookie whose only remaining guard is Secure, and modern browsers
            // increasingly drop it outright. Refused: an operator who really needs cross-site
            // posting should make that call in code review, not in a properties file.
            throw new IllegalArgumentException("SameSite=None is refused; use Strict or Lax");
        }
        throw new IllegalArgumentException("SameSite must be Strict or Lax");
    }

    private SessionCookiePolicy(String name, String path, String sameSite) {
        this.name = name;
        this.path = path;
        this.sameSite = sameSite;
    }

    public String name() {
        return name;
    }

    public String path() {
        return path;
    }

    public String sameSite() {
        return sameSite;
    }

    /** Always true; see the class note on why this is not configuration. */
    public boolean secure() {
        return true;
    }

    /** Always true; see the class note on why this is not configuration. */
    public boolean httpOnly() {
        return true;
    }

    /** Never set: the cookie is host-only, so no other host can read it or shadow it. */
    public String domain() {
        return null;
    }

    /** {@code 0} means "browser session only": no Max-Age/Expires attribute is emitted. */
    public int maxAge() {
        return 0;
    }

    /** Attribute summary only; this type never holds session material. */
    @Override
    public String toString() {
        return "SessionCookiePolicy[name=" + name + ", path=" + path + ", sameSite=" + sameSite
                + ", secure=true, httpOnly=true, hostOnly=true, sessionCookie=true]";
    }
}
