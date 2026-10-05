package com.example.auth;

import java.util.Optional;

/**
 * Encapsulates the outcome of an authentication request.
 * <p>
 * Satisfies Rule 6:
 * - Emits strictly generic messages to callers so that user existence or credential details are never leaked.
 * - Uniform failure representations prevent enumeration.
 */
public final class AuthenticationResult {

    public enum Status {
        SUCCESS,
        INVALID_CREDENTIALS,
        RATE_LIMITED,
        INTERNAL_ERROR
    }

    public static final String MSG_SUCCESS = "Authentication successful.";
    public static final String MSG_INVALID_CREDENTIALS = "Authentication failed. Invalid email or password.";
    public static final String MSG_RATE_LIMITED = "Authentication failed. Too many attempts, please try again later.";
    public static final String MSG_INTERNAL_ERROR = "Authentication failed. An internal error occurred.";

    private final Status status;
    private final String userMessage;
    private final SessionManager.Session session;

    private AuthenticationResult(Status status, String userMessage, SessionManager.Session session) {
        this.status = status;
        this.userMessage = userMessage;
        this.session = session;
    }

    public static AuthenticationResult success(SessionManager.Session session) {
        if (session == null) {
            throw new IllegalArgumentException("Session cannot be null on success");
        }
        return new AuthenticationResult(Status.SUCCESS, MSG_SUCCESS, session);
    }

    public static AuthenticationResult invalidCredentials() {
        return new AuthenticationResult(Status.INVALID_CREDENTIALS, MSG_INVALID_CREDENTIALS, null);
    }

    public static AuthenticationResult rateLimited() {
        return new AuthenticationResult(Status.RATE_LIMITED, MSG_RATE_LIMITED, null);
    }

    public static AuthenticationResult internalError() {
        return new AuthenticationResult(Status.INTERNAL_ERROR, MSG_INTERNAL_ERROR, null);
    }

    public boolean isSuccess() {
        return status == Status.SUCCESS;
    }

    public Status getStatus() {
        return status;
    }

    public String getUserMessage() {
        return userMessage;
    }

    public Optional<SessionManager.Session> getSession() {
        return Optional.ofNullable(session);
    }
}
