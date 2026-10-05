package com.company.portal.auth;

/** The caller should show the same message for every non-success result. */
public enum AuthenticationResult {
    AUTHENTICATED,
    INVALID_CREDENTIALS,
    ACCOUNT_LOCKED
}
