package com.example.portal.auth;

import java.io.PrintStream;
import java.time.Clock;
import java.time.format.DateTimeFormatter;
import java.util.Objects;

/**
 * Records the outcome of every sign-in attempt. Passwords are never passed to this
 * class, so they cannot end up in a log file.
 */
@FunctionalInterface
public interface AuditLog {

    void record(String username, AuthenticationResult.Status status);

    /** Discards all entries; useful in tests. */
    static AuditLog none() {
        return (username, status) -> { };
    }

    /** Writes one timestamped line per attempt to the given stream. */
    static AuditLog toStream(PrintStream out) {
        Objects.requireNonNull(out, "out");
        Clock clock = Clock.systemUTC();
        return (username, status) -> out.println(
                DateTimeFormatter.ISO_INSTANT.format(clock.instant())
                        + " auth " + status + " user=" + (username.isEmpty() ? "<blank>" : username));
    }
}
