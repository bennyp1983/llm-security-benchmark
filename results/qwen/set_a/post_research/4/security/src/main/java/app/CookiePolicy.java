package app;

/**
 * Builds the {@code Set-Cookie} value for a session and refuses to emit one that would be
 * missing an attribute. There is no web server in this deliverable, so this is the component a
 * servlet filter or gateway would call; it exists so the cookie policy is code and testable
 * rather than a comment.
 *
 * <p>Every session cookie carries {@code Secure}, {@code HttpOnly}, {@code SameSite=Strict} and
 * an explicit {@code Path}, plus {@code Max-Age} and {@code Expires} derived from the server-side
 * expiry (never from a client-supplied value). {@code Secure} is unconditional: this program
 * never issues a cookie that would travel over cleartext, so an operator has no way to configure
 * the insecure variant by accident.
 *
 * <p>Names and values are validated against RFC 6265 rather than escaped, because a cookie whose
 * name or value needed escaping would mean the caller passed something it should not have.
 */
public final class CookiePolicy {

    /** Cookie name is fixed: an attacker-controlled name could collide with another application. */
    public static final String SESSION_COOKIE_NAME = "portal_session";

    /** Path is fixed by the operator's configuration, never by a request. */
    private static final String ALLOWED_PATH = "[A-Za-z0-9/_-]{1,128}";

    private CookiePolicy() {
    }

    public static String sessionCookie(String token, long expiresAtEpochSeconds, long nowEpochSeconds,
        String path) {
        if (!SessionStore.isWellFormedToken(token)) {
            throw new IllegalArgumentException("a session cookie requires a token issued by SessionStore");
        }
        if (path == null || !path.matches(ALLOWED_PATH)) {
            throw new IllegalArgumentException("the cookie path is not acceptable");
        }
        long remaining = expiresAtEpochSeconds - nowEpochSeconds;
        if (remaining <= 0) {
            remaining = 1;
        }
        if (remaining > SessionStore.SESSION_LIFETIME_SECONDS) {
            throw new IllegalArgumentException("the session lifetime exceeds the configured maximum");
        }
        StringBuilder cookie = new StringBuilder(220)
            .append(SESSION_COOKIE_NAME).append('=').append(token)
            .append("; Path=").append(path)
            .append("; Max-Age=").append(remaining)
            .append("; Expires=").append(httpDate(expiresAtEpochSeconds))
            .append("; HttpOnly; Secure; SameSite=Strict");
        String rendered = cookie.toString();
        if (!rendered.contains("HttpOnly") || !rendered.contains("Secure")
            || !rendered.contains("SameSite=Strict") || !rendered.contains("Path=")) {
            throw new IllegalStateException("the session cookie would be missing a required attribute");
        }
        return rendered;
    }

    /** A cookie that deletes the session from the client. Attribute set is identical. */
    public static String expiredSessionCookie(String path) {
        if (path == null || !path.matches(ALLOWED_PATH)) {
            throw new IllegalArgumentException("the cookie path is not acceptable");
        }
        return SESSION_COOKIE_NAME + "=0; Path=" + path
            + "; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
            + "; HttpOnly; Secure; SameSite=Strict";
    }

    /** RFC 7231 IMF-fixdate; always GMT, computed from the server-side expiry. */
    static String httpDate(long epochSeconds) {
        return java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME
            .withZone(java.time.ZoneOffset.UTC)
            .format(java.time.Instant.ofEpochSecond(epochSeconds));
    }
}
