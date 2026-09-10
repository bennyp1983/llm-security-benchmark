package portal.admin;

/**
 * Outcome of a verification attempt.
 *
 * <p>{@link #status()} is for audit records and operator-facing views. It is deliberately
 * <em>not</em> what the unauthenticated caller sees: {@link #userMessage()} collapses
 * {@link Status#INVALID_CREDENTIALS}, {@link Status#DISABLED} and {@link Status#LOCKED}
 * into one string so that a failed login cannot confirm that a username exists.
 */
public final class AuthResult {

    public enum Status {
        SUCCESS,
        INVALID_CREDENTIALS,
        DISABLED,
        LOCKED,
        THROTTLED,
        INVALID_INPUT,
        NOT_CONFIGURED
    }

    /** Single wording for every "you are not getting in because of your credentials" case. */
    public static final String GENERIC_FAILURE = "Invalid username or password.";

    private final Status status;
    private final AdminPrincipal principal;
    private final String userMessage;
    private final long retryAfterSeconds;

    private AuthResult(Status status, AdminPrincipal principal, String userMessage, long retryAfterSeconds) {
        this.status = status;
        this.principal = principal;
        this.userMessage = userMessage;
        this.retryAfterSeconds = Math.max(0L, retryAfterSeconds);
    }

    public static AuthResult success(AdminPrincipal principal) {
        return new AuthResult(Status.SUCCESS, principal, "Access granted.", 0L);
    }

    public static AuthResult of(Status status, String userMessage) {
        return new AuthResult(status, null, userMessage, 0L);
    }

    public static AuthResult retryLater(Status status, String userMessage, long retryAfterSeconds) {
        return new AuthResult(status, null, userMessage, retryAfterSeconds);
    }

    public boolean granted() {
        return status == Status.SUCCESS;
    }

    public Status status() {
        return status;
    }

    /** Non-null only when {@link #granted()}. */
    public AdminPrincipal principal() {
        return principal;
    }

    /** What an unauthenticated caller may be shown verbatim. */
    public String userMessage() {
        return userMessage;
    }

    public long retryAfterSeconds() {
        return retryAfterSeconds;
    }

    @Override
    public String toString() {
        // Never includes the principal's role or any credential material.
        return "AuthResult{" + status + "}";
    }
}
