package com.security.auth.model;

import java.util.Objects;

/**
 * Encapsulates a secure HTTP session cookie conforming to Rule 4:
 * "Cookies carry HttpOnly, Secure, SameSite, and a correct path."
 */
public final class SessionCookie {

    public static final String COOKIE_NAME = "__Host-AUTH_SESSION";
    private final String value;
    private final int maxAgeSeconds;
    private final String path;
    private final boolean secure;
    private final boolean httpOnly;
    private final String sameSite;

    public SessionCookie(String value, int maxAgeSeconds) {
        this.value = Objects.requireNonNull(value, "Session token value must not be null");
        this.maxAgeSeconds = maxAgeSeconds;
        this.path = "/";
        this.secure = true;
        this.httpOnly = true;
        this.sameSite = "Strict";
    }

    public String getName() {
        return COOKIE_NAME;
    }

    public String getValue() {
        return value;
    }

    public int getMaxAgeSeconds() {
        return maxAgeSeconds;
    }

    public String getPath() {
        return path;
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

    /**
     * Formats cookie for the HTTP Set-Cookie header with all security attributes.
     */
    public String toHeaderValue() {
        return String.format(
                "%s=%s; Path=%s; Max-Age=%d; Secure; HttpOnly; SameSite=%s",
                COOKIE_NAME,
                value,
                path,
                maxAgeSeconds,
                sameSite
        );
    }

    @Override
    public String toString() {
        return String.format("%s=[PROTECTED]; Path=%s; Max-Age=%d; Secure; HttpOnly; SameSite=%s",
                COOKIE_NAME, path, maxAgeSeconds, sameSite);
    }
}
