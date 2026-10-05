package com.example.identity;

/**
 * The outcome of one security operation: a {@link Reason}, and for a successful sign-in the
 * freshly issued {@link SessionToken}.
 *
 * <p>{@code displayName} is server state read back from the account row and re-validated, so it is
 * safe to echo; it is never the raw bytes the caller typed.
 */
public record AuthResult(Reason reason, SessionToken token, String displayName) {

    static AuthResult of(Reason reason) {
        return new AuthResult(reason, null, null);
    }

    static AuthResult success(Reason reason, SessionToken token, String displayName) {
        return new AuthResult(reason, token, displayName);
    }

    /** The only user-facing text this result may produce. */
    public String userMessage() {
        return reason.genericUserMessage();
    }

    public boolean isSuccess() {
        return reason.isSuccess();
    }

    /**
     * A record would otherwise print the token. Refusing to is load-bearing: this object is what
     * gets returned to a caller that might log it.
     */
    @Override
    public String toString() {
        return "AuthResult[" + reason + ", token=" + (token == null ? "none" : "present") + "]";
    }
}
