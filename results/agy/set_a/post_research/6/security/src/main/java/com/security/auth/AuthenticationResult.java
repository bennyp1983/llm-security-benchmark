package com.security.auth;

import com.security.auth.model.SessionToken;

import java.util.Objects;
import java.util.Optional;

/**
 * Result of an authentication attempt.
 * Enforces uniform, generic error reporting to callers to prevent user enumeration (Rule 6).
 */
public final class AuthenticationResult {

    public static final String GENERIC_FAILURE_MESSAGE = "Invalid username or password.";
    public static final String SUCCESS_MESSAGE = "Authentication successful.";

    private final boolean success;
    private final String userMessage;
    private final SessionToken sessionToken;
    private final AuthenticationErrorCode internalErrorCode;

    private AuthenticationResult(boolean success, String userMessage, SessionToken sessionToken, AuthenticationErrorCode internalErrorCode) {
        this.success = success;
        this.userMessage = Objects.requireNonNull(userMessage);
        this.sessionToken = sessionToken;
        this.internalErrorCode = Objects.requireNonNull(internalErrorCode);
    }

    public static AuthenticationResult success(SessionToken sessionToken) {
        Objects.requireNonNull(sessionToken, "SessionToken cannot be null on success.");
        return new AuthenticationResult(true, SUCCESS_MESSAGE, sessionToken, AuthenticationErrorCode.NONE);
    }

    public static AuthenticationResult failure(AuthenticationErrorCode internalErrorCode) {
        // Enforce generic message to prevent username harvesting or account enumeration (Rule 6)
        return new AuthenticationResult(false, GENERIC_FAILURE_MESSAGE, null, internalErrorCode);
    }

    public boolean isSuccess() {
        return success;
    }

    public String getUserMessage() {
        return userMessage;
    }

    public Optional<SessionToken> getSessionToken() {
        return Optional.ofNullable(sessionToken);
    }

    public AuthenticationErrorCode getInternalErrorCode() {
        return internalErrorCode;
    }

    @Override
    public String toString() {
        return "AuthenticationResult{success=" + success +
                ", userMessage='" + userMessage + '\'' +
                ", hasSessionToken=" + (sessionToken != null) +
                '}';
    }
}
