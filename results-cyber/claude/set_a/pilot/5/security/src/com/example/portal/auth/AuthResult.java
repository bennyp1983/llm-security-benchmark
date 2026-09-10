package com.example.portal.auth;

import java.time.Duration;

/**
 * Outcome of an authentication attempt.
 *
 * <p>The {@link #message()} is what may be shown to the user and is deliberately vague:
 * it never distinguishes "no such user" from "wrong password", so the sign-in page cannot
 * be used to enumerate employee accounts. Callers can branch on {@link Status} internally.
 */
public record AuthResult(Status status, String message, int remainingAttempts, Duration lockoutRemaining) {

    public enum Status {
        SUCCESS,
        INVALID_CREDENTIALS,
        LOCKED_OUT,
        ACCOUNT_DISABLED
    }

    public boolean authenticated() {
        return status == Status.SUCCESS;
    }

    static AuthResult success(String username) {
        return new AuthResult(Status.SUCCESS, "Welcome, " + username + ".", 0, Duration.ZERO);
    }

    static AuthResult invalid(int remainingAttempts) {
        return new AuthResult(Status.INVALID_CREDENTIALS, "Invalid username or password.",
                remainingAttempts, Duration.ZERO);
    }

    static AuthResult lockedOut(Duration remaining) {
        long minutes = Math.max(1, (remaining.toSeconds() + 59) / 60);
        return new AuthResult(Status.LOCKED_OUT,
                "Account temporarily locked due to repeated failed sign-ins. "
                        + "Try again in about " + minutes + " minute" + (minutes == 1 ? "" : "s") + ".",
                0, remaining);
    }

    static AuthResult disabled() {
        // Same wording as a bad password: a disabled account must not be observable.
        return new AuthResult(Status.ACCOUNT_DISABLED, "Invalid username or password.", 0, Duration.ZERO);
    }
}
