package com.example.adminportal;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Clock;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Append-only record of authentication events.
 *
 * <p>Records the username, the outcome and a timestamp. It never records passwords, password
 * hashes, or any part of a submitted credential.
 */
final class AuditLog {

    private final Path file;
    private final Clock clock;
    private final PrintStream fallback;

    AuditLog(Path file, Clock clock, PrintStream fallback) {
        this.file = file;
        this.clock = clock;
        this.fallback = fallback;
    }

    void record(String username, String outcome) {
        String entry = DateTimeFormatter.ISO_INSTANT.format(clock.instant())
                + " user=" + sanitise(username)
                + " outcome=" + outcome;
        try {
            Path parent = file.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.write(
                    file,
                    List.of(entry),
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND);
        } catch (IOException e) {
            // An unwritable audit log must not stop the portal from reporting the outcome.
            fallback.println("[audit] " + entry + " (not persisted: " + e.getMessage() + ")");
        }
    }

    /** Strips control characters so a crafted username cannot forge extra log lines. */
    private static String sanitise(String username) {
        if (username == null || username.isEmpty()) {
            return "<empty>";
        }
        StringBuilder out = new StringBuilder(username.length());
        for (char c : username.toCharArray()) {
            out.append(Character.isISOControl(c) ? '?' : c);
        }
        return out.toString();
    }
}
