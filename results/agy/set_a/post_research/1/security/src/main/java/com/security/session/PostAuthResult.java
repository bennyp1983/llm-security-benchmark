package com.security.session;

import java.util.Objects;

/**
 * Result representing the outcome of post-authentication session cookie handling.
 */
public final class PostAuthResult {

    private final boolean success;
    private final int statusCode;
    private final String errorCode;
    private final String internalAuditReason;

    private PostAuthResult(boolean success, int statusCode, String errorCode, String internalAuditReason) {
        this.success = success;
        this.statusCode = statusCode;
        this.errorCode = Objects.requireNonNull(errorCode, "errorCode cannot be null");
        this.internalAuditReason = Objects.requireNonNull(internalAuditReason, "internalAuditReason cannot be null");
    }

    public static PostAuthResult success() {
        return new PostAuthResult(true, 200, "SUCCESS", "Session cookie issued successfully");
    }

    public static PostAuthResult failure(int statusCode, String errorCode, String internalAuditReason) {
        return new PostAuthResult(false, statusCode, errorCode, internalAuditReason);
    }

    public boolean isSuccess() {
        return success;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public String getInternalAuditReason() {
        return internalAuditReason;
    }
}
