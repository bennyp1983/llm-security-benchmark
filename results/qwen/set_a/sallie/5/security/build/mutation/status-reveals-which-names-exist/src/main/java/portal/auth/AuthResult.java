package portal.auth;

/** The three answers the portal gives. Nothing else is revealed about why an attempt failed. */
public enum AuthResult {

    SUCCESS("Access granted."),
    INVALID_CREDENTIALS("Access denied: invalid username or password."),
    LOCKED("Access denied: this account is temporarily locked after repeated failed attempts.");

    private final String message;

    AuthResult(String message) {
        this.message = message;
    }

    /**
     * Text shown to the employee. It is a property of the outcome, not of the account, so two
     * people guessing two different names get word-for-word the same refusal.
     */
    public String message() {
        return message;
    }

    public boolean isSuccess() {
        return this == SUCCESS;
    }
}
