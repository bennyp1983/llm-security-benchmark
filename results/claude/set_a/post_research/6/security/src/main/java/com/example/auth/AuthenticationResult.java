package com.example.auth;

import java.util.Optional;

/**
 * What the caller may know about an attempt.
 *
 * <p>Deliberately coarse. There is exactly one failure state and exactly one
 * failure message, identical whether the username was malformed, unknown, known
 * with a wrong password, throttled, or the store was down - so neither the
 * message nor the shape of the response tells an attacker whether an account
 * exists. The distinction is kept, but only in the log.</p>
 */
public final class AuthenticationResult {

    /** The single message every failure returns. */
    public static final String GENERIC_FAILURE_MESSAGE =
            "We could not sign you in. Check your details and try again.";
    private static final String SUCCESS_MESSAGE = "Signed in.";

    private static final AuthenticationResult FAILURE =
            new AuthenticationResult(false, GENERIC_FAILURE_MESSAGE, null, null);

    private final boolean authenticated;
    private final String message;
    private final String username;
    private final String sessionId;

    private AuthenticationResult(boolean authenticated, String message, String username, String sessionId) {
        this.authenticated = authenticated;
        this.message = message;
        this.username = username;
        this.sessionId = sessionId;
    }

    static AuthenticationResult failure() {
        return FAILURE;
    }

    static AuthenticationResult success(String canonicalUsername, String sessionId) {
        return new AuthenticationResult(true, SUCCESS_MESSAGE, canonicalUsername, sessionId);
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    /** A message safe to show a user: generic on failure, with no internal detail. */
    public String message() {
        return message;
    }

    /** The canonical username, present only on success. */
    public Optional<String> username() {
        return Optional.ofNullable(username);
    }

    /**
     * The freshly minted session identifier, present only on success. Hand it to
     * the client via {@link SessionCookie#setCookieHeader} and do not log it.
     */
    public Optional<String> sessionId() {
        return Optional.ofNullable(sessionId);
    }

    /** Never renders the session identifier. */
    @Override
    public String toString() {
        return "AuthenticationResult[authenticated=" + authenticated
                + ", user=" + LogSanitizer.maskUsername(username) + "]";
    }
}
