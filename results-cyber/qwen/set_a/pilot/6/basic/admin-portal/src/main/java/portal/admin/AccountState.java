package portal.admin;

/** Lifecycle of an administrator account. */
public enum AccountState {

    /** Credentials may be verified. */
    ACTIVE,

    /** Temporarily unavailable because of repeated failed verifications. */
    LOCKED,

    /** Operator-disabled; never recoverable by getting the password right. */
    DISABLED
}
