package com.example.auth;

import java.time.Duration;
import java.util.regex.Pattern;

/**
 * Builds the {@code Set-Cookie} header for a session token, for deployments that put an
 * HTTP front end on {@link AuthService}.
 *
 * <p>The attributes are not optional: {@code HttpOnly} keeps the token away from
 * scripts, {@code Secure} keeps it off cleartext connections, {@code SameSite=Strict}
 * blocks cross-site submission, and an explicit narrow {@code Path} keeps it from being
 * sent to unrelated handlers. There is no overload that omits them.
 */
public final class SessionCookie {

    public static final String COOKIE_NAME = "sid";

    private static final Pattern PATH = Pattern.compile("^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,200}$");

    private SessionCookie() {
    }

    /**
     * @param token  a token produced by {@link SessionService#issue}
     * @param path   cookie path, e.g. {@code "/"} or {@code "/app"}
     * @param maxAge session lifetime; must match the server-side expiry
     */
    public static String setCookieHeader(String token, String path, Duration maxAge) {
        if (token == null || !token.matches("^[A-Za-z0-9_-]{43}$")) {
            throw new IllegalArgumentException("token is not a session token issued by this service");
        }
        if (path == null || !PATH.matcher(path).matches()) {
            throw new IllegalArgumentException("cookie path is not acceptable");
        }
        long seconds = maxAge == null ? 0 : maxAge.toSeconds();
        if (seconds < 1 || seconds > 86_400) {
            throw new IllegalArgumentException("cookie Max-Age must be between 1 and 86400 seconds");
        }
        return COOKIE_NAME + "=" + token
                + "; Max-Age=" + seconds
                + "; Path=" + path
                + "; HttpOnly; Secure; SameSite=Strict";
    }

    /** Header that clears the cookie on logout, with the same attributes. */
    public static String clearCookieHeader(String path) {
        if (path == null || !PATH.matcher(path).matches()) {
            throw new IllegalArgumentException("cookie path is not acceptable");
        }
        return COOKIE_NAME + "=; Max-Age=0; Path=" + path + "; HttpOnly; Secure; SameSite=Strict";
    }
}
