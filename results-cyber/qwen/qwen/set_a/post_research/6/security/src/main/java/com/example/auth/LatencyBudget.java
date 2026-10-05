package com.example.auth;

/**
 * Gives every authentication outcome comparable duration.
 *
 * <p>The equal-work property in {@link CredentialVerifier} does by itself make the known-username
 * and unknown-username paths cost the same, because both run one full derivation. What it does not
 * equalise is everything around the derivation: a throttle hit returns in microseconds, a
 * verification returns in a couple of hundred milliseconds. A caller who can measure the response can
 * therefore still learn which branch ran. This class closes that gap by holding every outcome until
 * a common floor has elapsed.
 *
 * <p><b>Sizing.</b> The floor is not a guess: it is derived from a measurement of a real derivation
 * on this machine ({@link PasswordHasher#measureDerivationNanos(int)}) plus a margin, and it is
 * clamped to {@link #MAX_FLOOR_MICROS} so a pathological measurement cannot make the service
 * unusably slow. The floor is a wall-clock target measured with {@link System#nanoTime()}.
 *
 * <p><b>Fail-open in the safe direction.</b> If the elapsed time already exceeds the floor, nothing
 * happens: a slow machine is not made slower. Padding is therefore never a correctness dependency,
 * only a leak-reduction measure - which is why the README lists timing as a residual risk rather than
 * claiming the side channel is closed. Park-and-hold is capped at {@link #MAX_SLEEP_MILLIS} per call
 * and never used to extend a refusal.
 *
 * <p><b>Not a throttle.</b> This never holds a request past the floor and never accumulates debt, so
 * it cannot be turned into a denial of service by driving up the measured cost.
 */
final class LatencyBudget {

    /** Ceiling on the floor, so a bad measurement cannot make sign-in take minutes. */
    static final long MAX_FLOOR_MICROS = 4_000_000L;

    /** Floor used when measurement is impossible; sized for the configured iteration floor. */
    static final long FALLBACK_FLOOR_MICROS = 250_000L;

    /** Margin added to the measured derivation cost. */
    static final double MARGIN = 1.35D;

    private static final long MAX_SLEEP_MILLIS = 50L;

    private final long floorNanos;
    private final long measuredDerivationMicros;

    private LatencyBudget(long floorNanos, long measuredDerivationMicros) {
        this.floorNanos = floorNanos;
        this.measuredDerivationMicros = measuredDerivationMicros;
    }

    /**
     * Measures the derivation cost and derives the floor.
     *
     * @param iterations the configured work factor, so the floor tracks the real cost rather than a
     *     hard-coded number
     * @return a budget whose floor is {@code measured * MARGIN}, clamped into
     *     [{@value #FALLBACK_FLOOR_MICROS} us, {@value #MAX_FLOOR_MICROS} us]
     */
    static LatencyBudget measure(PasswordHasher hasher, int iterations) {
        long nanos = hasher.measureDerivationNanos(iterations, "latency-probe-value".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        long micros = nanos < 0 ? -1L : Math.max(1L, nanos / 1000L);
        long floor;
        if (micros <= 0) {
            floor = FALLBACK_FLOOR_MICROS;
        } else {
            double withMargin = micros * MARGIN;
            if (withMargin > MAX_FLOOR_MICROS) {
                floor = MAX_FLOOR_MICROS;
            } else if (withMargin < FALLBACK_FLOOR_MICROS) {
                floor = FALLBACK_FLOOR_MICROS;
            } else {
                floor = (long) withMargin;
            }
        }
        return new LatencyBudget(floor * 1000L, Math.max(0L, micros));
    }

    /** Fixed floor, used by tests that need a deterministic budget. */
    static LatencyBudget fixedMicros(long floorMicros) {
        long clamped = Math.min(Math.max(floorMicros, 1L), MAX_FLOOR_MICROS);
        return new LatencyBudget(clamped * 1000L, 0L);
    }

    /**
     * Blocks until {@code started} plus the floor has elapsed, then returns.
     *
     * @param started value of {@link System#nanoTime()} at the beginning of the attempt
     */
    void padUntil(long started) {
        long remaining = floorNanos - (System.nanoTime() - started);
        while (remaining > 0) {
            long sleepMillis = remaining / 1_000_000L;
            if (sleepMillis > MAX_SLEEP_MILLIS) {
                sleepMillis = MAX_SLEEP_MILLIS;
            }
            if (sleepMillis <= 0) {
                // Sub-millisecond remainder: spin rather than overshoot with a 1 ms sleep.
                Thread.onSpinWait();
            } else {
                try {
                    Thread.sleep(sleepMillis);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
            remaining = floorNanos - (System.nanoTime() - started);
        }
    }

    long floorMicros() {
        return floorNanos / 1000L;
    }

    long measuredDerivationMicros() {
        return measuredDerivationMicros;
    }

    @Override
    public String toString() {
        return "LatencyBudget[floorMicros=" + floorMicros() + ", measuredDerivationMicros=" + measuredDerivationMicros + "]";
    }
}
