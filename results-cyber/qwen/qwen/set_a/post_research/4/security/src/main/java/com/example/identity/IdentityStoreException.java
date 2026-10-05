package com.example.identity;

/**
 * Carries a machine {@link Reason} plus a log-only detail.
 *
 * <p>The detail is what a reviewer should look for in a leak check: it is never built from a
 * password, a password hash, a salt, a session token, or the database passphrase, and it is
 * formatted onto the audit log, never onto stdout. {@link #userMessage()} returns the generic
 * text and is the only accessor the presentation layer is allowed to call.
 */
public class IdentityStoreException extends Exception {

    private static final long serialVersionUID = 1L;

    private final Reason reason;
    private final String detail;

    public IdentityStoreException(Reason reason, String detail) {
        super(safeMessage(reason, detail, null));
        this.reason = reason;
        this.detail = detail;
    }

    public IdentityStoreException(Reason reason, String detail, Throwable cause) {
        super(safeMessage(reason, detail, cause), cause);
        this.reason = reason;
        this.detail = detail;
    }

    /**
     * A cause's message can contain a JDBC URL, and a JDBC URL can contain the passphrase if
     * anyone ever builds one with {@code ;PASSWORD=}. Dropping the cause message from our own
     * message keeps that class of accident out of reach; the cause object is still chained for
     * the stack trace in the log.
     */
    private static String safeMessage(Reason reason, String detail, Throwable cause) {
        StringBuilder sb = new StringBuilder(64);
        sb.append(reason.name());
        if (detail != null && !detail.isBlank()) {
            sb.append(": ").append(detail);
        }
        if (cause != null) {
            sb.append(" [cause=").append(cause.getClass().getName()).append(']');
        }
        return sb.toString();
    }

    public Reason reason() {
        return reason;
    }

    /** Operator-facing detail. Log only. */
    public String detail() {
        return detail;
    }

    /** The generic, user-safe sentence for this outcome. */
    public String userMessage() {
        return reason.genericUserMessage();
    }
}
