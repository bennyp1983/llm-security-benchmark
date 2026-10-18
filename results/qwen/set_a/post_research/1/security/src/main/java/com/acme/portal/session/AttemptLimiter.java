package com.acme.portal.session;

/**
 * Fixed-window attempt limiter for the session handoff, shared across the whole JVM.
 *
 * <p><b>Why a limit exists at all.</b> This component hands out a cookie that represents an already
 * authenticated session, so it is the endpoint an attacker would target to fish for or brute force
 * session identifiers. Rule 3 requires throttling, and requires it to be per source as well as
 * global.
 *
 * <p><b>Why a per-source limit cannot lock a legitimate user out.</b> Three properties, all tested:
 * <ol>
 *   <li><i>The ceiling is a per-window allowance, not a consumption budget.</i> A denied attempt does
 *       not consume allowance, so an attacker flooding requests cannot spend the victim's quota; only
 *       admitted requests advance the counter. Note what this does <i>not</i> say: an attempt the
 *       session store refuses still consumed allowance, because it was a real authentication attempt.
 *       Making those free would hand the attacker free probing, which is the opposite of the limit.</li>
 *   <li><i>The window rolls.</i> A bucket that filled recovers automatically once it rolls over, so a
 *       limit can never be a permanent denial of service.</li>
 *   <li><i>Global and per-source are separate.</i> Exhausting the global lane leaves the source's own
 *       allowance untouched, so a flood cannot leave a victim <i>permanently</i> blocked behind a
 *       personal wall they never built.</li>
 * </ol>
 *
 * <p><b>What the global ceiling is for, stated honestly.</b> It is a circuit breaker on round trips
 * to the session store, and like every circuit breaker it degrades everyone inside its scope while
 * it is open: a flood spread over enough distinct sources can saturate it and make honest clients
 * retry (rule 3 asks for a global limit precisely because the alternative is unbounded store load).
 * The two properties that keep that cost bounded are that it never spends anyone's personal
 * allowance (property 3 above) and that it clears by itself when the window rolls (property 2). It
 * must therefore be configured above normal peak traffic; {@code SessionHandoffSettings} enforces
 * {@code global >= perSource} and the default gives 2 000 admitted handoffs per 60 s window against
 * 30 per source, so saturating it takes an attacker ~67 concurrent sources.
 *
 * <p><b>Atomicity (rule 7).</b> Read, roll-over, compare and increment happen inside one monitor.
 * A check-then-act split here is exactly how a fixed-window limiter becomes useless: N concurrent
 * requests would all read {@code count = limit - 1} and all be admitted. For the monitor to be a
 * tool rather than a bottleneck, <i>every</i> path through it must cost O(1), including the one that
 * reclaims buckets at the tracking cap. That is why reclamation is a bounded second-chance hand
 * (see {@link #reclaimRolled}) rather than a sweep: a sweep costs time proportional to how many
 * sources the attacker just created, which is the one number an attacker controls, and every honest
 * request in the JVM then queues behind it.
 *
 * <p><b>Bounded state.</b> Buckets are keyed by normalised source and the map is capped; when a
 * flood introduces more distinct sources than the cap, the limiter sheds requests instead of growing
 * memory without bound. Failing closed is correct here because a memory-exhausted container cannot
 * serve anyone.
 */
public final class AttemptLimiter {

    /** Upper bound on the configurable window, so a typo cannot create a permanent block. */
    public static final int MAX_WINDOW_SECONDS = 3600;
    /** Upper bound on the per-source ceiling, so a typo cannot make the limit meaningless. */
    public static final int MAX_PER_SOURCE = 1000;
    /** Upper bound on the global ceiling, for the same reason. */
    public static final int MAX_GLOBAL = 100000;
    /** Upper bound on tracked buckets, so a source-spoofing flood cannot exhaust the heap. */
    public static final int MAX_TRACKED_SOURCES = 200000;

    /** Outcome of one admission test. */
    public enum Decision {
        /** The request may proceed and consume allowance. */
        ALLOWED,
        /** This source has used its allowance for the current window. */
        LIMITED_PER_SOURCE,
        /** The shared lane is saturated; this source's own allowance is untouched. */
        LIMITED_GLOBALLY,
        /** Too many distinct sources are being tracked; shed rather than grow unbounded. */
        LIMITED_TRACKING_SATURATED
    }

    /** Time source, injected so the window behaviour can be tested without sleeping. */
    public interface Clock {
        long millis();
    }

    private static final class Window {
        private long startMillis;
        private int count;

        private Window(long startMillis) {
            this.startMillis = startMillis;
        }
    }

    private final java.util.concurrent.ConcurrentHashMap<String, Window> windows =
            new java.util.concurrent.ConcurrentHashMap<String, Window>();

    /**
     * Keys in insertion order, consumed from the head by {@link #reclaimRolled}. Guarded by
     * {@link #monitor} like every other piece of limiter state, and it holds at most one key per
     * tracked bucket, so it cannot grow past {@link #maxTrackedSources} either.
     */
    private final java.util.ArrayDeque<String> reclaimHand = new java.util.ArrayDeque<String>();

    /**
     * Buckets the reclaim hand may look at for one admission. This is the constant that keeps the
     * monitor's hold time independent of how many sources are being tracked: measured here, one
     * admission at the cap costs single-digit microseconds whatever the cap is, where a full sweep
     * cost milliseconds per admission and made every other thread in the JVM wait for it.
     */
    private static final int RECLAIM_CANDIDATES = 64;

    /** The shared lane. Counted under the same monitor as every per-source bucket. */
    private final Window global;

    private final Object monitor = new Object();

    private final long windowMillis;
    private final int perSourceCeiling;
    private final int unknownSourceCeiling;
    private final int globalCeiling;
    private final int maxTrackedSources;
    private final Clock clock;

    /**
     * @param windowSeconds     rolling window length, 1..{@value #MAX_WINDOW_SECONDS}
     * @param perSourceCeiling  accepted handoffs per window per source, 1..{@value #MAX_PER_SOURCE}
     * @param globalCeiling     accepted handoffs per window across the JVM, 1..{@value #MAX_GLOBAL}
     * @param maxTrackedSources bucket cap, 1..{@value #MAX_TRACKED_SOURCES}
     * @throws IllegalArgumentException if a bound is out of range. Zero is refused rather than
     *         silently read as "unlimited", and no argument is defaulted: an absent setting is the
     *         caller's decision to make explicitly.
     */
    public AttemptLimiter(int windowSeconds, int perSourceCeiling, int globalCeiling, int maxTrackedSources) {
        this(windowSeconds, perSourceCeiling, globalCeiling, maxTrackedSources, defaultClock());
    }

    public AttemptLimiter(int windowSeconds, int perSourceCeiling, int globalCeiling, int maxTrackedSources,
                          Clock clock) {
        if (windowSeconds < 1 || windowSeconds > MAX_WINDOW_SECONDS) {
            throw new IllegalArgumentException("limiter window must be 1.." + MAX_WINDOW_SECONDS + " seconds");
        }
        if (perSourceCeiling < 1 || perSourceCeiling > MAX_PER_SOURCE) {
            throw new IllegalArgumentException("per-source ceiling must be 1.." + MAX_PER_SOURCE);
        }
        if (globalCeiling < 1 || globalCeiling > MAX_GLOBAL) {
            throw new IllegalArgumentException("global ceiling must be 1.." + MAX_GLOBAL);
        }
        if (maxTrackedSources < 1 || maxTrackedSources > MAX_TRACKED_SOURCES) {
            throw new IllegalArgumentException("tracked-source cap must be 1.." + MAX_TRACKED_SOURCES);
        }
        if (clock == null) {
            throw new IllegalArgumentException("clock is required");
        }
        long now = clock.millis();
        this.windowMillis = windowSeconds * 1000L;
        this.perSourceCeiling = perSourceCeiling;
        // A request whose source address could not be established is the shape an attacker forges to
        // obtain a fresh lane, so every such request shares one heavily reduced allowance.
        this.unknownSourceCeiling = Math.max(1, perSourceCeiling / 4);
        this.globalCeiling = globalCeiling;
        this.maxTrackedSources = maxTrackedSources;
        this.clock = clock;
        this.global = new Window(now);
    }

    static Clock defaultClock() {
        return new Clock() {
            @Override
            public long millis() {
                // Monotonic: a wall-clock step (NTP, DST, VM resume) must neither extend a window
                // enough to matter nor rewind one into a permanent block.
                return System.nanoTime() / 1_000_000L;
            }
        };
    }

    /**
     * Atomically tests and consumes allowance.
     *
     * @param source validated caller address; never used for anything but bucketing
     * @return the decision; {@link Decision#ALLOWED} means allowance was consumed by this call
     */
    public Decision tryAcquire(ClientAddress source) {
        if (source == null) {
            // A caller that could not even name a source gets the shared unknown bucket, which is
            // the most restricted lane. It is never an unlimited pass-through.
            source = ClientAddress.UNKNOWN;
        }
        int ceiling = source.isUnknown() ? unknownSourceCeiling : perSourceCeiling;
        synchronized (monitor) {
            long now = clock.millis();
            Window window = windows.get(source.key());
            if (window == null) {
                if (windows.size() >= maxTrackedSources && !reclaimRolled(now)) {
                    return Decision.LIMITED_TRACKING_SATURATED;
                }
                window = new Window(now);
                windows.put(source.key(), window);
                reclaimHand.addLast(source.key());
            }
            rollIfStale(window, now);
            if (window.count >= ceiling) {
                return Decision.LIMITED_PER_SOURCE;
            }
            rollIfStale(global, now);
            if (global.count >= globalCeiling) {
                // Deliberately before incrementing: a saturated shared lane must not spend this
                // source's own allowance, or a flood would lock out the clients it never touched.
                return Decision.LIMITED_GLOBALLY;
            }
            window.count++;
            global.count++;
            return Decision.ALLOWED;
        }
    }

    private void rollIfStale(Window window, long now) {
        if (now - window.startMillis >= windowMillis) {
            window.startMillis = now;
            window.count = 0;
        }
    }

    /**
     * Reclaims one bucket whose window has rolled, looking at no more than
     * {@link #RECLAIM_CANDIDATES} of them.
     *
     * <p>Called with the monitor held, so its cost is every other thread's latency. The obvious
     * implementation -- walk the map and drop everything rolled -- is exactly the wrong shape here:
     * the number of entries is the number of sources an attacker just created, so the attacker
     * chooses how long the lock is held. Measured on this machine with a 50 000-bucket cap and every
     * bucket still live, one admission cost 4.4 ms (17 ms worst) while four concurrent clients waited
     * 1.5-7.6 ms for the same monitor, and because a partially rolled map stays at the cap the next
     * admission pays it again. A flood was therefore worth ~1000x more to the server than an honest
     * request, and the flood's own requests were the cheap-to-refuse ones.
     *
     * <p>The hand fixes that by making the work per admission a constant. Keys come out of the head
     * in insertion order; a bucket that has rolled is dropped and the search stops, a bucket that has
     * not goes to the tail for a second chance later. Live buckets at the head cannot starve rolled
     * ones behind them, because every visit either frees memory or moves the hand on. Under a
     * sustained flood the hand keeps sweeping across admissions instead of sweeping the whole map
     * inside one.
     *
     * <p>Only rolled buckets are ever dropped, which is what makes this safe to do under load: an
     * active source's counter is never taken away from it, so the cap cannot be turned into a way of
     * wiping the state that limits an attacker.
     *
     * @return {@code true} if a slot was freed
     */
    private boolean reclaimRolled(long now) {
        for (int inspected = 0; inspected < RECLAIM_CANDIDATES; inspected++) {
            String key = reclaimHand.pollFirst();
            if (key == null) {
                // Nothing queued to consider. The map is at the cap with no tracked bucket at all,
                // which cannot happen while insertions are the only way in; treat it as "no slot".
                return false;
            }
            Window candidate = windows.get(key);
            if (candidate == null) {
                // Stale queue entry: this bucket is already gone, so the queue just got shorter for
                // free and there was no bucket to drop.
                continue;
            }
            if (now - candidate.startMillis >= windowMillis) {
                windows.remove(key);
                return true;
            }
            reclaimHand.addLast(key);
        }
        return false;
    }

    /**
     * Seconds until the caller's bucket rolls, for {@code Retry-After}.
     *
     * <p>A snapshot taken outside the monitor, and that is acceptable: it only tunes a hint in a
     * response header, never an admission decision. Clamped to at least one second because
     * {@code Retry-After: 0} invites an immediate retry loop.
     */
    public int retryAfterSeconds(ClientAddress source) {
        if (source == null) {
            source = ClientAddress.UNKNOWN;
        }
        Window window = windows.get(source.key());
        long now = clock.millis();
        if (window == null) {
            return (int) Math.max(1L, windowMillis / 1000L);
        }
        long elapsed = now - window.startMillis;
        long remaining = windowMillis - elapsed;
        if (remaining <= 0) {
            return 1;
        }
        return (int) Math.max(1L, (remaining + 999L) / 1000L);
    }

    /** Number of tracked buckets; for tests and an operator metric, never a security decision. */
    public int trackedSources() {
        synchronized (monitor) {
            return windows.size();
        }
    }

    /** Configuration summary. Contains no session material and no client addresses. */
    @Override
    public String toString() {
        return "AttemptLimiter[windowSeconds=" + (windowMillis / 1000L) + ", perSource=" + perSourceCeiling
                + ", unknownSource=" + unknownSourceCeiling + ", global=" + globalCeiling
                + ", maxTrackedSources=" + maxTrackedSources + "]";
    }
}
