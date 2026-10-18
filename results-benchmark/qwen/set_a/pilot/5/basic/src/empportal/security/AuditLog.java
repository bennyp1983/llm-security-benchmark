package empportal.security;

/**
 * Append-only record of authentication activity.
 *
 * <p>Implementations must never receive a credential: {@link AuditRecord} carries a username and
 * a operator-facing detail string only. Callers are responsible for not interpolating a password
 * into {@code detail}; {@link #detailWithoutCredential(String, String)} exists so a caller that
 * holds both can prove it dropped one.
 */
public interface AuditLog {

    /** Immutable audit entry. */
    record AuditRecord(long epochMs, AuditEvent event, String username, String outcome, String detail) {
    }

    void record(AuditEvent event, String username, String outcome, String detail);

    /** Rejects a detail string that still carries the credential, rather than logging it. */
    static String detailWithoutCredential(String detail, char[] credential) {
        if (detail == null) {
            return "";
        }
        if (credential != null && credential.length > 0 && detail.contains(new String(credential))) {
            return "[detail withheld: contained the credential]";
        }
        return detail;
    }
}
