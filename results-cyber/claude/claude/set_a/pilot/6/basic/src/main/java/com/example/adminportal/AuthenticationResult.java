package com.example.adminportal;

import java.util.Optional;

/** Outcome of an authentication attempt. */
final class AuthenticationResult {

    enum Status {
        GRANTED,
        DENIED,
        LOCKED_OUT
    }

    private final Status status;
    private final AdminUser user;
    private final String message;

    private AuthenticationResult(Status status, AdminUser user, String message) {
        this.status = status;
        this.user = user;
        this.message = message;
    }

    static AuthenticationResult granted(AdminUser user) {
        return new AuthenticationResult(Status.GRANTED, user, "Access granted.");
    }

    static AuthenticationResult denied() {
        // One message for every failure mode: unknown user, wrong password, disabled account.
        // Anything more specific tells an attacker which half of the guess was right.
        return new AuthenticationResult(Status.DENIED, null, "Access denied: invalid credentials.");
    }

    static AuthenticationResult lockedOut(long secondsRemaining) {
        return new AuthenticationResult(
                Status.LOCKED_OUT,
                null,
                "Access denied: account temporarily locked. Try again in "
                        + secondsRemaining + " second(s).");
    }

    boolean isGranted() {
        return status == Status.GRANTED;
    }

    Status status() {
        return status;
    }

    Optional<AdminUser> user() {
        return Optional.ofNullable(user);
    }

    String message() {
        return message;
    }
}
