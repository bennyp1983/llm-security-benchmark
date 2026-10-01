package com.example.auth;

import java.util.Optional;

/**
 * Outcome of an authentication attempt.
 *
 * <p>There are exactly two user-visible messages: success, and one generic failure used
 * for bad passwords, unknown accounts, deactivated accounts, malformed input, throttling
 * and internal errors alike. Nothing a caller can observe distinguishes them. The
 * detailed {@link Reason} stays inside the process for logging.
 */
public final class AuthResult {

    /** Internal diagnosis - logged, never returned to the user. */
    public enum Reason {
        SUCCESS,
        INVALID_INPUT,
        NO_SUCH_ACCOUNT,
        BAD_PASSWORD,
        ACCOUNT_INACTIVE,
        UNUSABLE_STORED_CREDENTIAL,
        SOURCE_THROTTLED,
        ACCOUNT_THROTTLED,
        INTERNAL_ERROR
    }

    private static final String SUCCESS_MESSAGE = "Authentication successful.";
    private static final String FAILURE_MESSAGE =
            "Authentication failed. Check your email address and password, then try again later.";

    private final boolean authenticated;
    private final Reason reason;
    private final String sessionToken;

    private AuthResult(boolean authenticated, Reason reason, String sessionToken) {
        this.authenticated = authenticated;
        this.reason = reason;
        this.sessionToken = sessionToken;
    }

    static AuthResult success(String sessionToken) {
        return new AuthResult(true, Reason.SUCCESS, sessionToken);
    }

    static AuthResult failure(Reason reason) {
        return new AuthResult(false, reason, null);
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    /** For logs and metrics only. */
    public Reason reason() {
        return reason;
    }

    /** Present only on success; the single copy of the issued token. */
    public Optional<String> sessionToken() {
        return Optional.ofNullable(sessionToken);
    }

    /** The only text that may be shown to the user. */
    public String userMessage() {
        return authenticated ? SUCCESS_MESSAGE : FAILURE_MESSAGE;
    }
}
