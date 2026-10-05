package com.security.session;

/**
 * Exception thrown when an input, token, or configuration fails security validation.
 */
public class SecurityValidationException extends RuntimeException {

    private final String clientMessage;
    private final String internalAuditReason;

    public SecurityValidationException(String clientMessage, String internalAuditReason) {
        super(internalAuditReason);
        this.clientMessage = clientMessage;
        this.internalAuditReason = internalAuditReason;
    }

    public SecurityValidationException(String clientMessage, String internalAuditReason, Throwable cause) {
        super(internalAuditReason, cause);
        this.clientMessage = clientMessage;
        this.internalAuditReason = internalAuditReason;
    }

    /**
     * Sanitized generic message safe to return to clients.
     */
    public String getClientMessage() {
        return clientMessage;
    }

    /**
     * Detailed audit reason suitable for server-side security logs only.
     */
    public String getInternalAuditReason() {
        return internalAuditReason;
    }
}
