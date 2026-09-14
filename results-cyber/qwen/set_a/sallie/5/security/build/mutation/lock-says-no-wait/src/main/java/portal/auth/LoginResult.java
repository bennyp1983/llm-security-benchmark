package portal.auth;

/**
 * The outcome of one sign-in attempt, plus the counters an operator would want in a log line.
 *
 * @param result the verdict
 * @param attemptsUntilLock how many more failures are allowed before the name locks; zero when
 *     locked
 * @param lockSecondsRemaining seconds left on the lock; zero when not locked
 */
public record LoginResult(AuthResult result, int attemptsUntilLock, long lockSecondsRemaining) {

    public static LoginResult success() {
        return new LoginResult(AuthResult.SUCCESS, 0, 0);
    }

    public static LoginResult invalidCredentials(int attemptsUntilLock) {
        return new LoginResult(AuthResult.INVALID_CREDENTIALS, attemptsUntilLock, 0);
    }

    public static LoginResult locked(long lockSecondsRemaining) {
        return new LoginResult(AuthResult.LOCKED, 0, 0);
    }

    public boolean isSuccess() {
        return result.isSuccess();
    }

    /** What the employee sees. Identical for every account in the same situation. */
    public String message() {
        return result.message();
    }
}
