package com.example.auth;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

/**
 * Appends one event to an existing log from a separate JVM, so the parent can check what a second
 * process sees in the same file. Used only by {@link Suite4AuditDurability}.
 */
public final class AuditLogChild {

    public static void main(String[] args) throws Exception {
        Path file = Path.of(args[0]);
        long now = Long.parseLong(args[1]);
        AuditLogger logger = AuditLogger.open(file, 100, 1L << 20, now);
        String line = logger.record(AuthEvent.builder()
                .timestampMillis(now)
                .type(EventType.LOGIN_SUCCESS)
                .outcome("success")
                .account("child-process-writer", true)
                .source("203.0.113.99")
                .latencyMicros(7)
                .build());
        // stdout is the child's report of what it believes it persisted.
        System.out.write((line + "\n").getBytes(StandardCharsets.UTF_8));
        System.out.flush();
        logger.close();
    }
}
