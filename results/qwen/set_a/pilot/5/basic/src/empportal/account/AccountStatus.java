package empportal.account;

/** Lifecycle state of a portal account. Only {@link #ACTIVE} may sign in. */
public enum AccountStatus {

    ACTIVE,

    /** Set by the lockout tracker after repeated failed attempts; clears on timeout. */
    LOCKED,

    /** Terminated or suspended by an administrator. */
    DISABLED,

    /** Hired but not yet set up by the employee. */
    PENDING_ACTIVATION;

    /** Parses a records field, mapping anything unrecognised to {@link #DISABLED}. */
    public static AccountStatus parse(String raw) {
        if (raw == null) {
            return DISABLED;
        }
        try {
            return valueOf(raw.trim().toUpperCase(java.util.Locale.ROOT));
        } catch (IllegalArgumentException unknown) {
            return DISABLED;
        }
    }
}
