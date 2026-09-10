package empportal.security;

/** Outcome of a sign-in attempt. */
public final class AuthResult {

    /**
     * Terminal state of an attempt.
     *
     * <p>{@link #INVALID_CREDENTIAL} covers "unknown username" and "wrong password" alike on
     * purpose: telling them apart hands an attacker a valid-account oracle.
     */
    public enum Status {
        AUTHENTICATED,
        INVALID_CREDENTIAL,
        LOCKED_OUT,
        ACCOUNT_DISABLED,
        PENDING_ACTIVATION,

        /** The stored record is not a PBKDF2 verifier, so it cannot be checked safely. */
        CREDENTIAL_STORAGE_ERROR,

        /** An unexpected store or I/O fault; treated as a denial, never as a grant. */
        INTERNAL_ERROR
    }

    private final Status status;
    private final String message;
    private final int remainingAttempts;
    private final long retryAfterEpochMs;

    private AuthResult(Status status, String message, int remainingAttempts, long retryAfterEpochMs) {
        this.status = status;
        this.message = message;
        this.remainingAttempts = remainingAttempts;
        this.retryAfterEpochMs = retryAfterEpochMs;
    }

    static AuthResult authenticated(String displayName, boolean upgraded) {
        String message = upgraded
                ? "Welcome back, " + displayName + " (password record refreshed)"
                : "Welcome back, " + displayName;
        return new AuthResult(Status.AUTHENTICATED, message, 0, 0L);
    }

    static AuthResult invalidCredential(int remaining) {
        return new AuthResult(Status.INVALID_CREDENTIAL,
                "Invalid username or password." + attemptsSuffix(remaining), Math.max(remaining, 0), 0L);
    }

    static AuthResult lockedOut(long retryAfterEpochMs) {
        return new AuthResult(Status.LOCKED_OUT,
                "This account is temporarily locked after repeated failed sign-ins. Try again later.",
                0, retryAfterEpochMs);
    }

    static AuthResult disabled() {
        return new AuthResult(Status.ACCOUNT_DISABLED,
                "This account is not enabled for portal sign-in. Contact the service desk.", 0, 0L);
    }

    static AuthResult pendingActivation() {
        return new AuthResult(Status.PENDING_ACTIVATION,
                "This account has not been activated yet. Contact the service desk.", 0, 0L);
    }

    static AuthResult credentialStorageError() {
        return new AuthResult(Status.CREDENTIAL_STORAGE_ERROR,
                "This account cannot sign in until its password record is renewed. Contact the service desk.",
                0, 0L);
    }

    static AuthResult internalError() {
        return new AuthResult(Status.INTERNAL_ERROR,
                "Sign-in is temporarily unavailable. Try again shortly.", 0, 0L);
    }

    private static String attemptsSuffix(int remaining) {
        if (remaining <= 2) {
            return " Sign-in is disabled after repeated failures.";
        }
        return "";
    }

    public boolean granted() {
        return status == Status.AUTHENTICATED;
    }

    public Status status() {
        return status;
    }

    /** Wording intended for the sign-in screen; never reveals whether the username exists. */
    public String message() {
        return message;
    }

    public int remainingAttempts() {
        return remainingAttempts;
    }

    public long retryAfterEpochMs() {
        return retryAfterEpochMs;
    }

    @Override
    public String toString() {
        return status + ": " + message;
    }
}
