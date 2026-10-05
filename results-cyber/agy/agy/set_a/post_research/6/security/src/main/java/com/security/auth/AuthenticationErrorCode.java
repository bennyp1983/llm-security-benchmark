package com.security.auth;

/**
 * Internal error codes for logging and audit purposes only (Rule 6).
 * These must NEVER be revealed directly to external clients.
 */
public enum AuthenticationErrorCode {
    NONE,
    INVALID_INPUT,
    USER_NOT_FOUND,
    INVALID_CREDENTIALS,
    ACCOUNT_LOCKED_OR_SUSPENDED,
    RATE_LIMITED_SOURCE,
    RATE_LIMITED_ACCOUNT,
    INTERNAL_ERROR
}
