package com.example.websession;

import java.util.Objects;

/**
 * The server-side facts about a session, as returned by the trusted session component.
 *
 * <p>This record is an input to this component, so its contents are validated on
 * construction rather than trusted. In particular {@code remainingLifetimeSeconds} is
 * bounded, because it is used to compute a cookie {@code Max-Age}: an absurd value from a
 * buggy or compromised provider must not turn a session cookie into a permanent one.</p>
 *
 * @param subjectKey                an opaque, stable, server-side handle for the
 *                                  authenticated principal. Used only as a rate-limiting
 *                                  key and never written to the response or to a log in
 *                                  clear text. Must not be the raw session identifier.
 * @param remainingLifetimeSeconds  how much longer the server will honour the session;
 *                                  must be strictly positive (an expired session is
 *                                  reported by returning no record at all).
 */
public record TrustedSession(String subjectKey, long remainingLifetimeSeconds) {

    /** One year. Anything longer is treated as a provider bug and rejected. */
    public static final long MAX_REMAINING_LIFETIME_SECONDS = 365L * 24 * 60 * 60;

    /** Bound on the subject key so it cannot be used to grow the rate-limiter's memory. */
    public static final int MAX_SUBJECT_KEY_LENGTH = 256;

    public TrustedSession {
        Objects.requireNonNull(subjectKey, "subjectKey");
        if (subjectKey.isBlank() || subjectKey.length() > MAX_SUBJECT_KEY_LENGTH) {
            throw new IllegalArgumentException("subjectKey length out of range");
        }
        if (remainingLifetimeSeconds <= 0 || remainingLifetimeSeconds > MAX_REMAINING_LIFETIME_SECONDS) {
            throw new IllegalArgumentException("remainingLifetimeSeconds out of range");
        }
    }
}
