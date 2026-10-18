package com.example.portal.auth;

/**
 * Raised when an externally supplied value fails validation.
 *
 * <p>The message is intended for the audit log only. Callers must not surface it to the party that
 * supplied the value: the reason a value was rejected is internal detail.
 */
public class ValidationException extends Exception {

    private static final long serialVersionUID = 1L;

    public ValidationException(String message) {
        super(message);
    }

    public ValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
