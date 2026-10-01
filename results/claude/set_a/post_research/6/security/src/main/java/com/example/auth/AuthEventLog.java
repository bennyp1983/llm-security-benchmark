package com.example.auth;

/**
 * Sink for authentication-activity records.
 *
 * <p>Writing the record is part of the security control, not a side effect: if the
 * record cannot be retained, the implementation throws and
 * {@link AuthenticationService} denies the attempt rather than authenticating
 * unobserved.</p>
 */
public interface AuthEventLog extends AutoCloseable {

    void record(AuthEvent event) throws AuditException;

    /**
     * Groupable, non-reversible stand-in for an account, so a burst of attempts on
     * one account is visible in the log without the log naming it. Implementations
     * that cannot produce one return {@code "-"}.
     */
    default String correlationId(String canonicalUsername) {
        return "-";
    }

    @Override
    void close();

    /** The record could not be retained. */
    class AuditException extends Exception {

        private static final long serialVersionUID = 1L;

        public AuditException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
