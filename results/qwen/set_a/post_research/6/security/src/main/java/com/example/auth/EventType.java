package com.example.auth;

/** Event categories written to the authentication log. */
enum EventType {

    /** Credentials verified; a session identifier was issued. */
    LOGIN_SUCCESS("login_success"),

    /** Credentials were not verified, for any reason. */
    LOGIN_FAILURE("login_failure"),

    /** Rate limiting stopped the attempt before any credential was checked. */
    LOGIN_THROTTLED("login_throttled"),

    /** The caller supplied no usable source address, so the attempt could not be rate limited. */
    LOGIN_REJECTED_NO_SOURCE("login_rejected_no_source"),

    /**
     * A security-relevant failure that is not a login attempt, for example an event that could not
     * be persisted.
     */
    SECURITY_ALERT("security_alert");

    private final String token;

    EventType(String token) {
        this.token = token;
    }

    /** Stable machine-readable token; contains no attacker-controlled content. */
    String token() {
        return token;
    }

    static EventType fromToken(String token) {
        for (EventType value : values()) {
            if (value.token.equals(token)) {
                return value;
            }
        }
        return null;
    }
}
