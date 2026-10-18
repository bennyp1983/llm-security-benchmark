package com.example.security;

/**
 * Raised when an account lookup cannot be completed.
 *
 * <p>Messages are written to be safe to log and safe to show: they describe the failure without
 * echoing the supplied username, the SQL text, or driver details. The {@link SQLException} cause
 * keeps the database detail for server-side logs.
 */
public class UserRepositoryException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public UserRepositoryException(String message) {
        super(message);
    }

    public UserRepositoryException(String message, Throwable cause) {
        super(message, cause);
    }
}
