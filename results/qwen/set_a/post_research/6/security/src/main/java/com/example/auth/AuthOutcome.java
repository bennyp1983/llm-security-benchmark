package com.example.auth;

/** Coarse outcome of an authentication attempt. */
public enum AuthOutcome {

    /** Credentials were verified and a session was issued. */
    SUCCESS,

    /** Credentials were not verified, for any reason. */
    DENIED;

    boolean isSuccess() {
        return this == SUCCESS;
    }
}
