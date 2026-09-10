package portal.admin;

/** Classification of an audited security event. */
public enum AuditResult {

    SUCCESS,
    FAILURE,
    DENIED,
    LOCKED,
    EXPIRED,
    WARNING,

    /** Non-security operational note. */
    INFO
}
