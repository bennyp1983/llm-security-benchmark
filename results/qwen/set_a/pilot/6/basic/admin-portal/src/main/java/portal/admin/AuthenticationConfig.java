package portal.admin;

/**
 * Tunables for {@link AuthenticationService}. Validated on construction so a
 * misconfiguration (a zero lockout window, a max-attempts value of 0 that would lock
 * everybody out on a good password) fails at startup instead of at first login.
 */
public final class AuthenticationConfig {

    public static final int DEFAULT_MAX_FAILED_ATTEMPTS = 5;
    public static final long DEFAULT_LOCK_MINUTES = 15;
    public static final int DEFAULT_GLOBAL_THROTTLE_THRESHOLD = 25;
    public static final long DEFAULT_THROTTLE_WINDOW_MINUTES = 5;
    public static final long DEFAULT_SESSION_MINUTES = 30;
    public static final long DEFAULT_ABSOLUTE_SESSION_MINUTES = 8 * 60;
    public static final int DEFAULT_MAX_SESSIONS_PER_USER = 3;

    private final int maxFailedAttempts;
    private final long lockDurationMillis;
    private final int globalThrottleThreshold;
    private final long throttleWindowMillis;
    private final long sessionIdleMillis;
    private final long sessionAbsoluteMillis;
    private final int maxSessionsPerUser;

    public AuthenticationConfig(int maxFailedAttempts, long lockDurationMillis,
                                int globalThrottleThreshold, long throttleWindowMillis,
                                long sessionIdleMillis, long sessionAbsoluteMillis,
                                int maxSessionsPerUser) {
        if (maxFailedAttempts < 1) {
            throw new IllegalArgumentException("maxFailedAttempts must be at least 1");
        }
        if (lockDurationMillis < 1_000L) {
            throw new IllegalArgumentException("lock duration must be at least 1 second");
        }
        if (globalThrottleThreshold < 1) {
            throw new IllegalArgumentException("globalThrottleThreshold must be at least 1");
        }
        if (throttleWindowMillis < 1_000L) {
            throw new IllegalArgumentException("throttle window must be at least 1 second");
        }
        if (sessionIdleMillis < 60_000L) {
            throw new IllegalArgumentException("session idle timeout must be at least 1 minute");
        }
        if (sessionAbsoluteMillis < sessionIdleMillis) {
            throw new IllegalArgumentException("absolute session lifetime must be at least the idle timeout");
        }
        if (maxSessionsPerUser < 1) {
            throw new IllegalArgumentException("maxSessionsPerUser must be at least 1");
        }
        this.maxFailedAttempts = maxFailedAttempts;
        this.lockDurationMillis = lockDurationMillis;
        this.globalThrottleThreshold = globalThrottleThreshold;
        this.throttleWindowMillis = throttleWindowMillis;
        this.sessionIdleMillis = sessionIdleMillis;
        this.sessionAbsoluteMillis = sessionAbsoluteMillis;
        this.maxSessionsPerUser = maxSessionsPerUser;
    }

    public static AuthenticationConfig defaults() {
        return new AuthenticationConfig(
                DEFAULT_MAX_FAILED_ATTEMPTS,
                minutesToMillis(DEFAULT_LOCK_MINUTES),
                DEFAULT_GLOBAL_THROTTLE_THRESHOLD,
                minutesToMillis(DEFAULT_THROTTLE_WINDOW_MINUTES),
                minutesToMillis(DEFAULT_SESSION_MINUTES),
                minutesToMillis(DEFAULT_ABSOLUTE_SESSION_MINUTES),
                DEFAULT_MAX_SESSIONS_PER_USER);
    }

    /** Test/tuning-friendly variant with fast clocks so suites do not sleep. */
    public static AuthenticationConfig fast(int maxFailedAttempts, long lockMillis, long sessionMillis) {
        return new AuthenticationConfig(maxFailedAttempts, lockMillis, 1_000, 60_000L,
                sessionMillis, sessionMillis * 10, 3);
    }

    public static long minutesToMillis(long minutes) {
        if (minutes < 1 || minutes > 60 * 24 * 365) {
            throw new IllegalArgumentException("minutes out of range: " + minutes);
        }
        return minutes * 60_000L;
    }

    public int maxFailedAttempts() {
        return maxFailedAttempts;
    }

    public long lockDurationMillis() {
        return lockDurationMillis;
    }

    public int globalThrottleThreshold() {
        return globalThrottleThreshold;
    }

    public long throttleWindowMillis() {
        return throttleWindowMillis;
    }

    public long sessionIdleMillis() {
        return sessionIdleMillis;
    }

    public long sessionAbsoluteMillis() {
        return sessionAbsoluteMillis;
    }

    public int maxSessionsPerUser() {
        return maxSessionsPerUser;
    }
}
