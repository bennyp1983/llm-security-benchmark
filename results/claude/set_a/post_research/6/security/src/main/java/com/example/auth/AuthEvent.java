package com.example.auth;

import java.time.Instant;
import java.util.Objects;

/**
 * One authentication-activity record, already reduced to what is safe to retain.
 *
 * <p>There is no field for a password, a derived key or a session identifier, so
 * no caller can place one in the log by mistake. The account correlation value is
 * a keyed digest produced by {@link FileAuthEventLog}, which lets an operator
 * group a burst of attempts on one account without the log naming it.</p>
 */
public record AuthEvent(Instant at,
                        Outcome outcome,
                        String maskedUsername,
                        String accountCorrelationId,
                        String maskedSource,
                        String detail) {

    /** What happened. Distinguished in the log only - never in the user's response. */
    public enum Outcome {
        SUCCESS,
        /** Username and password were well formed but did not match. */
        BAD_CREDENTIALS,
        /** No account with that username. */
        UNKNOWN_ACCOUNT,
        /** Input rejected by {@link InputPolicy} before any lookup. */
        INVALID_INPUT,
        /** Refused by {@link LoginThrottle} before any credential work. */
        THROTTLED,
        /** The store, the key-derivation provider or the registry failed; attempt denied. */
        ERROR
    }

    public AuthEvent {
        Objects.requireNonNull(at, "at");
        Objects.requireNonNull(outcome, "outcome");
        maskedUsername = maskedUsername == null ? "-" : maskedUsername;
        accountCorrelationId = accountCorrelationId == null ? "-" : accountCorrelationId;
        maskedSource = maskedSource == null ? "-" : maskedSource;
        detail = detail == null ? "-" : detail;
    }
}
