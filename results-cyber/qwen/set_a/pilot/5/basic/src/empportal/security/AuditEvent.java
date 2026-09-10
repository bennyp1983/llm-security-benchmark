package empportal.security;

/** Sign-in and account-management events worth persisting for review. */
public enum AuditEvent {

    SUCCESS,
    BAD_CREDENTIAL,

    /** A spike of these against many usernames is probing for valid accounts. */
    UNKNOWN_USER,

    LOCKED,

    /** The attempt that tripped the lockout threshold. */
    LOCKOUT_STARTED,
    LOCKOUT_CLEARED,
    DISABLED,
    PENDING_ACTIVATION,

    /** Credential is stored unhashed, so sign-in was refused until it is rotated. */
    UNHASHED_CREDENTIAL,

    /** Verifier re-derived at the current work factor after a successful sign-in. */
    CREDENTIAL_UPGRADED,
    ACCOUNT_ADDED,
    ACCOUNT_UPDATED
}
