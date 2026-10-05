package com.security.auth.logging;

/**
 * Types of authentication events recorded for audit and security analysis.
 */
public enum AuthenticationEventType {
    LOGIN_SUCCESS,
    LOGIN_FAILURE_INVALID_CREDENTIALS,
    LOGIN_FAILURE_USER_NOT_FOUND,
    LOGIN_FAILURE_ACCOUNT_LOCKED,
    LOGIN_FAILURE_RATE_LIMITED_SOURCE,
    LOGIN_FAILURE_RATE_LIMITED_ACCOUNT,
    LOGIN_FAILURE_INVALID_INPUT,
    LOGIN_FAILURE_INTERNAL_ERROR
}
