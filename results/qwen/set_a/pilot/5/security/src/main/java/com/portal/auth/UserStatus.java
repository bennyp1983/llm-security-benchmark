package com.portal.auth;

/** Lifecycle state of an employee account in the records store. */
public enum UserStatus {

    /** Credentials may be checked. */
    ACTIVE,

    /** A human (or a policy that escalates past temporary lockout) has frozen the account. */
    LOCKED,

    /** The employee has left; no password, correct or not, grants access. */
    DISABLED
}
