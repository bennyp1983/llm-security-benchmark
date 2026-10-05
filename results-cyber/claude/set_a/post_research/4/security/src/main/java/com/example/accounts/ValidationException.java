package com.example.accounts;

/**
 * A rejected input. The message describes the *format rule* that was broken and never reflects any
 * server-side state, so it is safe to show the user (rule 6) and reveals nothing about which
 * accounts exist.
 */
public class ValidationException extends Exception {

    private static final long serialVersionUID = 1L;

    public ValidationException(String message) {
        super(message);
    }
}
