package com.example.auth;

import java.time.Clock;
import java.time.Instant;

/**
 * Time source used for lockout windows and session expiry.
 *
 * <p>Injected rather than read inline so the time-based behaviour is testable. The production
 * implementation is {@link Clock#systemUTC()}; the clock is operator-supplied infrastructure, not
 * client input, and {@link AuthConfig} rejects anything but a UTC clock.
 */
public interface TimeSource {

    /** Current time in milliseconds since the epoch. */
    long nowMillis();

    /** Current instant, for log timestamps. */
    Instant now();

    static TimeSource systemUtc() {
        return new SystemTimeSource(Clock.systemUTC());
    }

    static TimeSource of(Clock clock) {
        return new SystemTimeSource(clock);
    }

    /** Fixed clock that the test harness can advance; production uses {@link #systemUtc()}. */
    static Mutable mutable(long epochMillis) {
        return new AdvancingTimeSource(epochMillis);
    }

    interface Mutable extends TimeSource {
        void advanceMillis(long delta);
    }
}

final class SystemTimeSource implements TimeSource {

    private final Clock clock;

    SystemTimeSource(Clock clock) {
        if (clock == null) {
            throw new IllegalArgumentException("clock");
        }
        this.clock = clock;
    }

    @Override
    public long nowMillis() {
        return clock.millis();
    }

    @Override
    public Instant now() {
        return clock.instant();
    }
}

final class AdvancingTimeSource implements TimeSource.Mutable {

    private long millis;

    AdvancingTimeSource(long millis) {
        this.millis = millis;
    }

    @Override
    public synchronized void advanceMillis(long delta) {
        if (delta < 0) {
            throw new IllegalArgumentException("delta");
        }
        millis += delta;
    }

    @Override
    public synchronized long nowMillis() {
        return millis;
    }

    @Override
    public synchronized Instant now() {
        return Instant.ofEpochMilli(nowMillis());
    }
}
