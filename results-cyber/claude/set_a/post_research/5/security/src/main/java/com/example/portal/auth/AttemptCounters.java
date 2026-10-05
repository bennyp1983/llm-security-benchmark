package com.example.portal.auth;

import java.util.Iterator;
import java.util.Map;

/**
 * The counting rules behind every {@link AttemptLimiter}, kept in one place so the in-memory and
 * file-backed trackers cannot drift apart. Both call these methods while holding their own exclusive
 * lock, which is what makes the read-decide-update sequence atomic.
 *
 * <p>Times are epoch milliseconds rather than {@link System#nanoTime()} readings, because the
 * file-backed tracker has to compare timestamps written by an earlier process. That makes the
 * counters sensitive to clock changes, so both directions are defended against:
 *
 * <ul>
 *   <li>A restriction whose stored expiry is further out than one full restriction period -- which
 *       can only happen if the clock moved backwards, or if the file was tampered with -- is clamped
 *       back to one period from now. An attacker cannot turn a 15-minute restriction into a
 *       permanent lockout of an employee that way.</li>
 *   <li>A window whose stored start is in the future is reset to now, so a forward-dated record
 *       cannot park a counter in a window that never elapses.</li>
 * </ul>
 */
final class AttemptCounters {

    /** Result of drawing one slot from one counter. */
    enum Slot { PERMITTED, RESTRICTED, CAPACITY_EXHAUSTED }

    /** Mutable per-key state. Only ever touched under the owning tracker's lock. */
    static final class State {
        int attempts;
        long windowStart;
        long restrictedUntil;
        boolean restricted;

        State(long now) {
            this.windowStart = now;
        }

        State(int attempts, long windowStart, long restrictedUntil, boolean restricted) {
            this.attempts = attempts;
            this.windowStart = windowStart;
            this.restrictedUntil = restrictedUntil;
            this.restricted = restricted;
        }
    }

    private AttemptCounters() {
    }

    /**
     * Draws one attempt slot for {@code key}, applying the restriction when the budget is spent.
     *
     * @param maxKeys upper bound on tracked keys; once reached, expired entries are pruned and, if
     *                the map is still full, the attempt is refused rather than allowed untracked
     */
    static Slot consume(Map<String, State> map,
                        String key,
                        int maxAttempts,
                        long windowMillis,
                        long restrictionMillis,
                        long now,
                        int maxKeys) {
        State state = map.get(key);
        if (state == null) {
            if (map.size() >= maxKeys) {
                prune(map, windowMillis, now);
            }
            if (map.size() >= maxKeys) {
                return Slot.CAPACITY_EXHAUSTED;
            }
            state = new State(now);
            map.put(key, state);
        }

        if (state.windowStart > now) {
            state.windowStart = now;
        }

        if (state.restricted) {
            if (state.restrictedUntil > now + restrictionMillis) {
                state.restrictedUntil = now + restrictionMillis;
            }
            if (state.restrictedUntil > now) {
                return Slot.RESTRICTED;
            }
            // The restriction has served its term. Expiring it is what keeps the limit from being a
            // way to take a legitimate employee offline indefinitely.
            state.restricted = false;
            state.attempts = 0;
            state.windowStart = now;
        }

        if (now - state.windowStart > windowMillis) {
            state.attempts = 0;
            state.windowStart = now;
        }

        if (state.attempts >= maxAttempts) {
            state.restricted = true;
            state.restrictedUntil = now + restrictionMillis;
            return Slot.RESTRICTED;
        }

        state.attempts++;
        return Slot.PERMITTED;
    }

    /** Clears a key's counter outright, used for the account on a successful authentication. */
    static void clear(Map<String, State> map, String key) {
        map.remove(key);
    }

    /**
     * Returns a single consumed slot without clearing the counter, used for the source on a
     * successful authentication: only non-successful attempts should accumulate, but holding one
     * valid credential must not reset an attacker's whole source budget.
     */
    static void giveBack(Map<String, State> map, String key) {
        State state = map.get(key);
        if (state != null && state.attempts > 0) {
            state.attempts--;
        }
    }

    /** Drops counters whose window has elapsed and that are not under an active restriction. */
    static void prune(Map<String, State> map, long windowMillis, long now) {
        for (Iterator<Map.Entry<String, State>> it = map.entrySet().iterator(); it.hasNext(); ) {
            State state = it.next().getValue();
            boolean stillRestricted = state.restricted && state.restrictedUntil > now;
            boolean stale = now - state.windowStart > windowMillis;
            if (!stillRestricted && stale) {
                it.remove();
            }
        }
    }
}
