package com.employee.portal.security.model;

import java.util.Optional;

/**
 * Result of an authentication request.
 * Adheres strictly to Rule 6:
 * Failure messages are generic and indistinguishable across all failure modes
 * (bad credentials, non-existent user, locked account, blocked source, invalid format).
 */
public final class AuthenticationResult {

    public static final String GENERIC_FAILURE_MESSAGE =
            "Invalid username or password or account temporarily restricted. Please try again later.";

    private final boolean success;
    private final String message;
    private final Session session;
    private final String cookieHeader;

    private AuthenticationResult(boolean success, String message, Session session, String cookieHeader) {
        this.success = success;
        this.message = message;
        this.session = session;
        this.cookieHeader = cookieHeader;
    }

    public static AuthenticationResult success(Session session, String cookieHeader) {
        return new AuthenticationResult(true, "Authentication successful.", session, cookieHeader);
    }

    public static AuthenticationResult failure() {
        return new AuthenticationResult(false, GENERIC_FAILURE_MESSAGE, null, null);
    }

    public boolean isSuccess() {
        return success;
    }

    public String getMessage() {
        return message;
    }

    public Optional<Session> getSession() {
        return Optional.ofNullable(session);
    }

    public Optional<String> getCookieHeader() {
        return Optional.ofNullable(cookieHeader);
    }
}
