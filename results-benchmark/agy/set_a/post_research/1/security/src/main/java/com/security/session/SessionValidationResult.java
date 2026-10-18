package com.security.session;

import java.util.Objects;

/**
 * Result of server-side session state validation and claim.
 */
public final class SessionValidationResult {

    private final boolean success;
    private final String errorCode;
    private final String auditMessage;

    private SessionValidationResult(boolean success, String errorCode, String auditMessage) {
        this.success = success;
        this.errorCode = Objects.requireNonNull(errorCode, "errorCode cannot be null");
        this.auditMessage = Objects.requireNonNull(auditMessage, "auditMessage cannot be null");
    }

    public static SessionValidationResult success() {
        return new SessionValidationResult(true, "SUCCESS", "Session validated and claimed successfully");
    }

    public static SessionValidationResult failure(String errorCode, String auditMessage) {
        return new SessionValidationResult(false, errorCode, auditMessage);
    }

    public boolean isSuccess() {
        return success;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public String getAuditMessage() {
        return auditMessage;
    }
}
