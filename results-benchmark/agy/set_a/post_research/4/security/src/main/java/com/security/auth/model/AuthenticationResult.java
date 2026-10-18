package com.security.auth.model;

/**
 * Result of an authentication operation.
 * Adheres to Rule 6 by providing identical generic messages for all authentication failures.
 */
public final class AuthenticationResult {

    public static final String GENERIC_FAILURE_MESSAGE = "Invalid credentials.";
    public static final String RATE_LIMITED_MESSAGE = "Too many failed attempts. Please try again later.";
    public static final String SUCCESS_MESSAGE = "Authentication successful.";

    private final boolean success;
    private final String message;
    private final String sessionToken;
    private final SessionCookie sessionCookie;
    private final User user;

    private AuthenticationResult(boolean success, String message, String sessionToken, SessionCookie sessionCookie, User user) {
        this.success = success;
        this.message = message;
        this.sessionToken = sessionToken;
        this.sessionCookie = sessionCookie;
        this.user = user;
    }

    public static AuthenticationResult success(String sessionToken, SessionCookie cookie, User user) {
        return new AuthenticationResult(true, SUCCESS_MESSAGE, sessionToken, cookie, user);
    }

    public static AuthenticationResult failure() {
        return new AuthenticationResult(false, GENERIC_FAILURE_MESSAGE, null, null, null);
    }

    public static AuthenticationResult rateLimited(String reason) {
        return new AuthenticationResult(false, reason != null ? reason : RATE_LIMITED_MESSAGE, null, null, null);
    }

    public boolean isSuccess() {
        return success;
    }

    public String getMessage() {
        return message;
    }

    public String getSessionToken() {
        return sessionToken;
    }

    public SessionCookie getSessionCookie() {
        return sessionCookie;
    }

    public User getUser() {
        return user;
    }

    @Override
    public String toString() {
        return "AuthenticationResult{" +
                "success=" + success +
                ", message='" + message + '\'' +
                ", sessionToken=" + (sessionToken != null ? "[PROTECTED]" : "null") +
                ", sessionCookie=" + (sessionCookie != null ? sessionCookie.toString() : "null") +
                ", user=" + (user != null ? user.toString() : "null") +
                '}';
    }
}
