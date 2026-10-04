package com.portal.auth;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

/**
 * Single source of wall-clock readings, so lockout windows and session expiry can be
 * driven deterministically in tests instead of sleeping. Production always uses
 * {@link Clock#systemUTC()}.
 */
public final class AuditClock {

    private static volatile Clock clock = Clock.systemUTC();

    private AuditClock() {
    }

    public static String now() {
        return Instant.now(clock).toString();
    }

    public static long epochSecond() {
        return Instant.now(clock).getEpochSecond();
    }

    public static Instant instant() {
        return Instant.now(clock);
    }

    /** Test hook. Passing {@code null} restores the system clock. */
    public static void useForTesting(Clock replacement) {
        clock = replacement == null ? Clock.systemUTC() : replacement;
    }

    static Clock current() {
        return clock;
    }

    static Clock utcFixed(Instant at) {
        return Clock.fixed(at, ZoneOffset.UTC);
    }
}
