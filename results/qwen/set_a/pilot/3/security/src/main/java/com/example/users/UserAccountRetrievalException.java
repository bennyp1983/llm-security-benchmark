package com.example.users;

/**
 * Signals that an account row could not be read.
 *
 * <p>Unchecked so lookup callers are not forced to handle {@link java.sql.SQLException} in the
 * middle of an application flow. The JDBC cause is always preserved for server-side logging;
 * the message itself is generic because driver messages can name tables, columns and query
 * fragments that belong in a log file and not in an API response.
 */
public class UserAccountRetrievalException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public UserAccountRetrievalException(String message, Throwable cause) {
        super(message, cause);
    }
}
