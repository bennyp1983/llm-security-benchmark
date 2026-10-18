package portal.auth;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Counts consecutive failed sign-ins per username and locks a name once the limit is reached.
 *
 * <p>This is the answer to "unlimited consecutive attempts against a single account": after
 * {@code maxConsecutiveFailures} failures in a row the name is locked for {@code lockDuration},
 * and while it is locked the supplied password is not tested at all - correct or not.
 *
 * <p>Details that matter:
 *
 * <ul>
 *   <li>A successful sign-in clears the counter for that name.</li>
 *   <li>Failures are counted for names that do not exist either, so "is this a real account?" is
 *       not answerable by watching which names get locked.</li>
 *   <li>The lock expires by itself. Trying again during the lock window neither extends it nor
 *       spends another of the employee's attempts.</li>
 *   <li>Once a lock expires the counter restarts from zero, so the employee gets a fresh set of
 *       attempts and an attacker gets a fresh, equally small set.</li>
 * </ul>
 *
 * <p>Thread-safe: every transition for one name happens inside a single
 * {@code ConcurrentHashMap.compute}, so concurrent guesses cannot interleave and lose a count.
 * Counters live in memory; a restart clears them (the README says what to change if that matters).
 */
public final class LoginAttemptTracker {

    /** What happened to the counter when a failure was recorded. */
    public record FailureOutcome(int consecutiveFailures, int attemptsUntilLock, boolean lockedNow,
                                 Duration lockRemaining) {
    }

    private record State(int failures, Instant lockedUntil) {

        private static final State CLEAR = new State(0, null);

        private boolean expiredAt(Instant now) {
            return lockedUntil != null && !now.isBefore(lockedUntil);
        }
    }

    private final int maxConsecutiveFailures;
    private final Duration lockDuration;
    private final ConcurrentHashMap<String, State> states = new ConcurrentHashMap<>();

    public LoginAttemptTracker(int maxConsecutiveFailures, Duration lockDuration) {
        if (maxConsecutiveFailures < 1) {
            throw new IllegalArgumentException("maxConsecutiveFailures must be at least 1");
        }
        if (lockDuration == null || lockDuration.isZero() || lockDuration.isNegative()) {
            throw new IllegalArgumentException("lockDuration must be positive");
        }
        this.maxConsecutiveFailures = maxConsecutiveFailures;
        this.lockDuration = lockDuration;
    }

    public int maxConsecutiveFailures() {
        return maxConsecutiveFailures;
    }

    public Duration lockDuration() {
        return lockDuration;
    }

    /** True when {@code username} is inside its lock window at {@code now}. */
    public boolean isLocked(String username, Instant now) {
        return lockedUntil(username, now) != null;
    }

    /** How long is left on the lock; zero when the name is not locked. */
    public Duration lockRemaining(String username, Instant now) {
        Instant until = lockedUntil(username, now);
        return until == null ? Duration.ZERO : clamp(Duration.between(now, until));
    }

    /** Adds a failure for {@code username} and reports the new state. */
    public FailureOutcome recordFailure(String username, Instant now) {
        State[] written = new State[1];
        states.compute(username, (key, previous) -> {
            State base = previous == null || previous.expiredAt(now) ? State.CLEAR : previous;
            int failures = base.failures() + 1;
            State next = failures >= maxConsecutiveFailures
                    ? new State(maxConsecutiveFailures, now.plus(lockDuration))
                    : new State(failures, null);
            written[0] = next;
            return next;
        });
        State next = written[0];
        boolean lockedNow = next.lockedUntil() != null;
        return new FailureOutcome(next.failures(), maxConsecutiveFailures - next.failures(),
                lockedNow,
                lockedNow ? clamp(Duration.between(now, next.lockedUntil())) : Duration.ZERO);
    }

    /** Clears the counter: a proven sign-in cancels the suspicion built up on that name. */
    public void recordSuccess(String username) {
    }

    /** Clears the lock and the counter early, for an administrator. */
    public void unlock(String username) {
        states.remove(username);
    }

    /** Failures currently counted against {@code username}; zero once a lock has expired. */
    public int consecutiveFailures(String username, Instant now) {
        State state = current(username, now);
        return state == null ? 0 : state.failures();
    }

    /** How many names currently carry a counter or a lock; used by tests and status output. */
    public int trackedNames() {
        return states.size();
    }

    private Instant lockedUntil(String username, Instant now) {
        State state = current(username, now);
        return state == null ? null : state.lockedUntil();
    }

    /** Returns the live state for {@code username}, dropping it first if its lock has expired. */
    private State current(String username, Instant now) {
        State[] seen = new State[1];
        states.compute(username, (key, previous) -> {
            State live = previous == null || previous.expiredAt(now) ? null : previous;
            seen[0] = live;
            return live;
        });
        return seen[0];
    }

    private Duration clamp(Duration duration) {
        return duration.isNegative() ? Duration.ZERO : duration;
    }
}
