package com.example.portal.auth;

import java.time.Duration;
import java.util.Optional;

/**
 * Outcome of a sign-in attempt.
 *
 * <p>{@link #userMessage()} is the only text that should ever be shown to the person
 * signing in: every failure reads the same so an attacker cannot tell a bad password
 * from an unknown username. {@link #status()} carries the real reason, for audit logs.
 */
public final class AuthenticationResult {

    public enum Status {
        /** Credentials matched an active record. */
        GRANTED,
        /** Username unknown, or password wrong. */
        INVALID_CREDENTIALS,
        /** Record exists but the account is deactivated. */
        ACCOUNT_INACTIVE,
        /** Too many recent failures; attempts are being refused for a cooling-off period. */
        LOCKED_OUT
    }

    private static final String GENERIC_FAILURE = "Access denied: invalid username or password.";

    private final Status status;
    private final EmployeeRecord employee;
    private final Duration lockoutRemaining;

    private AuthenticationResult(Status status, EmployeeRecord employee, Duration lockoutRemaining) {
        this.status = status;
        this.employee = employee;
        this.lockoutRemaining = lockoutRemaining;
    }

    static AuthenticationResult granted(EmployeeRecord employee) {
        return new AuthenticationResult(Status.GRANTED, employee, null);
    }

    static AuthenticationResult denied(Status status) {
        return new AuthenticationResult(status, null, null);
    }

    static AuthenticationResult lockedOut(Duration remaining) {
        return new AuthenticationResult(Status.LOCKED_OUT, null, remaining);
    }

    public Status status() {
        return status;
    }

    public boolean granted() {
        return status == Status.GRANTED;
    }

    /** The authenticated employee; empty unless {@link #granted()}. */
    public Optional<EmployeeRecord> employee() {
        return Optional.ofNullable(employee);
    }

    /** Time left on the lockout; empty unless the status is {@code LOCKED_OUT}. */
    public Optional<Duration> lockoutRemaining() {
        return Optional.ofNullable(lockoutRemaining);
    }

    /** Message safe to display to the person at the keyboard. */
    public String userMessage() {
        switch (status) {
            case GRANTED:
                return "Access granted. Welcome, " + employee.displayName() + ".";
            case LOCKED_OUT:
                long seconds = Math.max(1, lockoutRemaining.getSeconds());
                return "Account temporarily locked after repeated failed attempts. "
                        + "Try again in " + seconds + " second(s) or contact the IT service desk.";
            case ACCOUNT_INACTIVE:
            case INVALID_CREDENTIALS:
            default:
                // Inactive accounts deliberately share the generic message.
                return GENERIC_FAILURE;
        }
    }
}
