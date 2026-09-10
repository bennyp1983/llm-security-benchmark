package empportal.account;

import java.util.Objects;

/**
 * One portal login.
 *
 * <p>{@link #credential()} holds the PBKDF2 verifier for a well-formed record. It is never a
 * value to log or echo; for a legacy record it is the stored plaintext, which is why
 * {@link #legacyPlaintextCredential()} exists and why sign-in refuses such accounts.
 */
public final class EmployeeAccount {

    private final String username;
    private final String displayName;
    private final AccountStatus status;
    private final String credential;
    private final boolean legacyPlaintextCredential;

    private EmployeeAccount(String username, String displayName, AccountStatus status, String credential,
            boolean legacyPlaintextCredential) {
        this.username = Objects.requireNonNull(username, "username");
        this.displayName = displayName == null ? username : displayName;
        this.status = Objects.requireNonNull(status, "status");
        this.credential = Objects.requireNonNull(credential, "credential");
        this.legacyPlaintextCredential = legacyPlaintextCredential;
    }

    /** Builds an account from a credential string that must already be a strong verifier. */
    public static EmployeeAccount create(String username, String displayName, AccountStatus status, String verifier) {
        if (!CredentialRecord.isStrongVerifier(verifier)) {
            throw new IllegalArgumentException("refusing to create an account from a non-hashed credential");
        }
        return new EmployeeAccount(username, displayName, status, verifier, false);
    }

    /** Rebuilds an account from a records row, preserving whatever the row actually contains. */
    public static EmployeeAccount fromRecord(CredentialRecord record) {
        Objects.requireNonNull(record, "record");
        return new EmployeeAccount(record.username(), record.displayName(), AccountStatus.parse(record.status()),
                record.credential(), record.kind() == CredentialRecord.Kind.UNHASHED);
    }

    public CredentialRecord toRecord() {
        return new CredentialRecord(username, displayName, status.name(), credential);
    }

    public EmployeeAccount withStatus(AccountStatus newStatus) {
        return new EmployeeAccount(username, displayName, newStatus, credential, legacyPlaintextCredential);
    }

    public EmployeeAccount withCredential(String verifier) {
        if (!CredentialRecord.isStrongVerifier(verifier)) {
            throw new IllegalArgumentException("refusing to store a non-hashed credential");
        }
        return new EmployeeAccount(username, displayName, status, verifier, false);
    }

    public String username() {
        return username;
    }

    public String displayName() {
        return displayName;
    }

    public AccountStatus status() {
        return status;
    }

    public String credential() {
        return credential;
    }

    public boolean legacyPlaintextCredential() {
        return legacyPlaintextCredential;
    }

    @Override
    public String toString() {
        return "EmployeeAccount[username=" + username + ", name=" + displayName + ", status=" + status + "]";
    }
}
