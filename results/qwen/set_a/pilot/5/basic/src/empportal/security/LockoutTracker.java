package empportal.security;

import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.function.LongSupplier;

/**
 * Sliding-window failure counter that locks an identity after too many misses.
 *
 * <p>Keyed by the sign-in identity rather than a resolved account, so attempts against usernames
 * that do not exist consume the same budget and cannot be probed without limit.
 *
 * <p>Counting is by attempt, not by wall-clock duration: a client that burns CPU to reach the
 * threshold is throttled identically. An {@link AttemptCost} hook lets a deployment add a
 * proof-of-work or IP-reputation cost on top.
 */
public final class LockoutTracker {

    /** Separator used by {@link #exportState()}. */
    private static final String STAMP_SEPARATOR = "=";

    /** Observation hook: report the cost already imposed on this attempt. */
    public interface AttemptCost {
        AttemptCost NONE = identity -> 0;

        int costFor(String identity);
    }

    /**
     * Outcome of registering an attempt.
     *
     * @param locked          whether the identity may not be tried again right now
     * @param remaining       attempts left before the lock trips (never negative)
     * @param retryAfterEpochMs when the lock lifts; {@code 0} when not locked
     * @param justLocked      this very attempt tripped the lock
     */
    public record Decision(boolean locked, int remaining, long retryAfterEpochMs, boolean justLocked) {
    }

    private final int maxFailures;
    private final long windowMillis;
    private final long lockoutMillis;
    private final LongSupplier clock;
    private final AttemptCost cost;
    private final Map<String, Deque<Long>> failures = new ConcurrentHashMap<>();

    public LockoutTracker(int maxFailures, long windowMillis, long lockoutMillis, LongSupplier clock,
            AttemptCost cost) {
        if (maxFailures < 1) {
            throw new IllegalArgumentException("maxFailures must be at least 1");
        }
        if (windowMillis <= 0 || lockoutMillis <= 0) {
            throw new IllegalArgumentException("window and lockout must be positive");
        }
        this.maxFailures = maxFailures;
        this.windowMillis = windowMillis;
        this.lockoutMillis = lockoutMillis;
        this.clock = clock;
        this.cost = cost == null ? AttemptCost.NONE : cost;
    }

    /** Defaults suited to an internal portal: 5 misses in 15 minutes locks for 15 minutes. */
    public static LockoutTracker standard(LongSupplier clock) {
        return new LockoutTracker(5, 15 * 60_000L, 15 * 60_000L, clock, AttemptCost.NONE);
    }

    /** Current lock state, without registering an attempt. */
    public synchronized Decision peek(String identity) {
        long now = clock.getAsLong();
        Deque<Long> hits = failures.get(key(identity));
        if (hits == null || hits.isEmpty()) {
            return new Decision(false, maxFailures, 0L, false);
        }
        if (hits.size() >= maxFailures) {
            long retryAfter = hits.peekLast() + lockoutMillis;
            if (now < retryAfter) {
                return new Decision(true, 0, retryAfter, false);
            }
            failures.remove(key(identity));
            return new Decision(false, maxFailures, 0L, false);
        }
        return new Decision(false, Math.max(0, maxFailures - hits.size()), 0L, false);
    }

    /**
     * Records one attempt.
     *
     * @param succeeded clears the window on a good credential; a failed attempt extends it
     */
    public synchronized Decision record(String identity, boolean succeeded) {
        String key = key(identity);
        long now = clock.getAsLong();
        if (succeeded) {
            failures.remove(key);
            return new Decision(false, maxFailures, 0L, false);
        }

        int weight = 1 + Math.max(0, cost.costFor(key));
        Deque<Long> hits = failures.computeIfAbsent(key, ignored -> new ConcurrentLinkedDeque<>());
        evictStale(hits, now);
        for (int i = 0; i < weight; i++) {
            hits.addLast(now);
        }
        // Trimming the older end (rather than adding at the front) means an expensive attempt
        // trips the threshold without pushing the newest timestamp backwards.
        while (hits.size() > maxFailures) {
            hits.pollFirst();
        }

        if (hits.size() >= maxFailures) {
            return new Decision(true, 0, now + lockoutMillis, true);
        }
        return new Decision(false, maxFailures - hits.size(), 0L, false);
    }

    /** Administrative unlock. */
    public synchronized void clear(String identity) {
        failures.remove(key(identity));
    }

    /**
     * Serialises the failure windows.
     *
     * <p>Needed because a sign-in front end may run one attempt per process: a counter that lives
     * only in the heap resets to zero on every invocation and the lockout never trips.
     */
    public synchronized List<String> exportState() {
        List<String> lines = new ArrayList<>(failures.size());
        for (Map.Entry<String, Deque<Long>> entry : failures.entrySet()) {
            if (entry.getValue().isEmpty()) {
                continue;
            }
            StringBuilder stamps = new StringBuilder();
            for (Long stamp : entry.getValue()) {
                if (stamps.length() > 0) {
                    stamps.append(',');
                }
                stamps.append(stamp.longValue());
            }
            lines.add(entry.getKey() + STAMP_SEPARATOR + stamps);
        }
        return lines;
    }

    /**
     * Restores windows written by {@link #exportState()}.
     *
     * <p>A line that cannot be parsed is skipped rather than fatal: unreadable counters must not
     * lock every account out, and counters throttle attempts rather than authorise them.
     */
    public synchronized void importState(List<String> lines) {
        if (lines == null) {
            return;
        }
        for (String line : lines) {
            if (line == null) {
                continue;
            }
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.charAt(0) == '#') {
                continue;
            }
            String[] halves = trimmed.split(STAMP_SEPARATOR, 2);
            if (halves.length != 2 || halves[0].isEmpty()) {
                continue;
            }
            Deque<Long> stamps = new ConcurrentLinkedDeque<>();
            for (String token : halves[1].split(",")) {
                try {
                    stamps.addLast(Long.parseLong(token.trim()));
                } catch (NumberFormatException corrupt) {
                    stamps.clear();
                    break;
                }
            }
            if (!stamps.isEmpty()) {
                failures.put(key(halves[0]), stamps);
            }
        }
    }

    public int maxFailures() {
        return maxFailures;
    }

    public long lockoutMillis() {
        return lockoutMillis;
    }

    private void evictStale(Deque<Long> hits, long now) {
        Long oldest;
        while ((oldest = hits.peekFirst()) != null && now - oldest > windowMillis) {
            hits.pollFirst();
        }
    }

    private static String key(String identity) {
        return identity == null ? "" : identity.trim().toLowerCase(java.util.Locale.ROOT);
    }
}
