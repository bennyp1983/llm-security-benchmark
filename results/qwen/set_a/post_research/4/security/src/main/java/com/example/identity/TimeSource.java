package com.example.identity;

/**
 * Time, injectable so expiry and rate-limit windows are testable without sleeping.
 *
 * <p>Two different clocks, deliberately not interchangeable:
 * <ul>
 *   <li>{@link #nowEpochSeconds()} is wall-clock time and is the <b>only</b> clock used for values
 *       that are persisted. It must be wall clock because the point is comparability across
 *       restarts. It is validated on use: a non-monotonic read (NTP step backwards) can extend a
 *       penalty or expire a session early, both of which are fail-safe directions - it can never
 *       extend a session's life beyond its TTL, because expiry is {@code created + ttl} and a
 *       backward step makes {@code now} smaller, which only ever keeps a session live until the
 *       wall clock catches up. That residual is bounded by the NTP offset and is noted in README
 *       "Limitations".</li>
 *   <li>{@link #nowNanos()} is monotonic and used for nothing but measuring elapsed time in tests.
 *       Its origin is an arbitrary per-boot value, so it is never stored, never compared against a
 *       stored value, and never decides whether a credential is live.</li>
 * </ul>
 */
interface TimeSource {

    long nowEpochSeconds();

    long nowNanos();

    /** Production clock. */
    static TimeSource system() {
        return new TimeSource() {
            @Override
            public long nowEpochSeconds() {
                return System.currentTimeMillis() / 1000L;
            }

            @Override
            public long nowNanos() {
                return System.nanoTime();
            }

            @Override
            public String toString() {
                return "TimeSource[system]";
            }
        };
    }

    /**
     * Test clock: epoch seconds advance only when the test says so, so window expiry, penalty
     * growth and session TTL enforcement are asserted deterministically instead of by sleeping -
     * and cannot go green by accident on a fast machine.
     */
    final class Fake implements TimeSource {
        private long epochSeconds;
        private long nanos = 1_000_000L;

        Fake(long startEpochSeconds) {
            this.epochSeconds = startEpochSeconds;
        }

        @Override
        public long nowEpochSeconds() {
            return epochSeconds;
        }

        @Override
        public long nowNanos() {
            return nanos;
        }

        void advanceSeconds(long delta) {
            if (delta < 0) {
                throw new IllegalArgumentException("the fake clock does not go backwards");
            }
            epochSeconds += delta;
            nanos += delta * 1_000_000_000L;
        }

        void tickNanos(long delta) {
            nanos += delta;
        }
    }
}
