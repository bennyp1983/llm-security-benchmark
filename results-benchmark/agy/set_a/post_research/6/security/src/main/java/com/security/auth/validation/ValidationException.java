package com.security.auth.validation;

/**
 * Exception thrown when user-supplied input violates trust boundary constraints.
 */
public class ValidationException extends Exception {

    private static final long serialVersionUID = 1L;

    public ValidationException(String message) {
        super(message);
    }
}
