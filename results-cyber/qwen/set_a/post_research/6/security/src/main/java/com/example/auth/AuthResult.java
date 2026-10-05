package com.example.auth;

/**
 * Result of an authentication attempt.
 *
 * <p>The only field that differs between a denial for an unknown username, a wrong password, an
 * invalid username and an unparseable password is {@code retryAfterSeconds}, and that value is
 * always {@code 0} for those cases. A successful result additionally carries the session identifier
 * issued by {@link SessionTokenStore}.
 */
public final class AuthResult {

    /** Single denial text. It names both fields so a failed attempt cannot indicate which one was wrong. */
    static final String DENIAL_MESSAGE = "Invalid username or password.";

    /**
     * Text returned when the caller did not supply a usable source address. It reveals nothing
     * about any account and is not the denial text, because accepting the attempt would mean
     * authenticating with no way to rate limit it.
     */
    static final String SOURCE_REQUIRED_MESSAGE = "Authentication is not available for this request.";

    private final AuthOutcome outcome;
    private final String message;
    private final String sessionId;
    private final int retryAfterSeconds;

    private AuthResult(AuthOutcome outcome, String message, String sessionId, int retryAfterSeconds) {
        this.outcome = outcome;
        this.message = message;
        this.sessionId = sessionId;
        this.retryAfterSeconds = retryAfterSeconds;
    }

    static AuthResult success(String sessionId) {
        return new AuthResult(AuthOutcome.SUCCESS, "Signed in.", sessionId, 0);
    }

    static AuthResult denied() {
        return new AuthResult(AuthOutcome.DENIED, DENIAL_MESSAGE, null, 0);
    }

    static AuthResult rateLimited(int retryAfterSeconds) {
        return new AuthResult(AuthOutcome.DENIED, DENIAL_MESSAGE, null, retryAfterSeconds);
    }

    static AuthResult sourceUnavailable() {
        return new AuthResult(AuthOutcome.DENIED, SOURCE_REQUIRED_MESSAGE, null, 0);
    }

    public AuthOutcome outcome() {
        return outcome;
    }

    public boolean isSuccess() {
        return outcome.isSuccess();
    }

    /** Generic, user-presentable text. Never contains the username, the address or an internal reason. */
    public String message() {
        return message;
    }

    /**
     * The session identifier, or {@code null} when the attempt did not succeed. The value is
     * produced by {@link SessionTokenStore} from {@link java.security.SecureRandom}; it is never
     * taken from caller input.
     */
    public String sessionId() {
        return sessionId;
    }

    /**
     * Seconds the caller should wait before retrying, suitable for a {@code Retry-After} header.
     * Zero means no throttling was applied.
     */
    public int retryAfterSeconds() {
        return retryAfterSeconds;
    }

    @Override
    public String toString() {
        // The session identifier is a credential: it must never appear in a rendered object.
        return "AuthResult[" + outcome + ", retryAfterSeconds=" + retryAfterSeconds + "]";
    }
}
