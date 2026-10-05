package com.security.auth.model;

/**
 * Result of a registration operation.
 * Adheres to Rule 6 by providing generic, non-enumerating messages to clients.
 */
public final class RegistrationResult {

    public static final String GENERIC_FAILURE_MESSAGE =
            "Registration request could not be completed. Please verify your details or proceed to login.";
    public static final String SUCCESS_MESSAGE =
            "Account registration completed successfully.";

    private final boolean success;
    private final String message;
    private final String userId;

    private RegistrationResult(boolean success, String message, String userId) {
        this.success = success;
        this.message = message;
        this.userId = userId;
    }

    public static RegistrationResult success(String userId) {
        return new RegistrationResult(true, SUCCESS_MESSAGE, userId);
    }

    public static RegistrationResult failure(String genericMessage) {
        return new RegistrationResult(false, genericMessage, null);
    }

    public static RegistrationResult failure() {
        return failure(GENERIC_FAILURE_MESSAGE);
    }

    public boolean isSuccess() {
        return success;
    }

    public String getMessage() {
        return message;
    }

    public String getUserId() {
        return userId;
    }

    @Override
    public String toString() {
        return "RegistrationResult{" +
                "success=" + success +
                ", message='" + message + '\'' +
                ", userId='" + userId + '\'' +
                '}';
    }
}
