package com.example.portal.auth;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.Locale;

/**
 * Append-only audit log for authentication events.
 *
 * <p>The log is the only place failure detail is allowed to go. Users get a generic message; the
 * reason -- unknown account, wrong password, restriction in force, malformed input -- is recorded
 * here instead, where it is useful to an operator and invisible to an attacker.
 *
 * <p>What never reaches this log: passwords, derived keys, salts, stored hashes, and session tokens.
 * Usernames and source addresses are partially masked, so a log that leaks does not hand over a
 * directory of employee accounts, while still leaving enough to correlate events during an
 * investigation.
 *
 * <p>When backed by a file, that file is created with owner-only permissions ({@code rw-------}) and
 * its permissions are re-verified on open, so a pre-created world-readable file is refused rather
 * than written to. Each entry is length-bounded and stripped of control characters, so no input can
 * forge a log line by embedding a newline.
 */
public final class AuditLog implements AutoCloseable {

    /** Maximum characters kept from any single field written to the log. */
    private static final int MAX_FIELD_LENGTH = 200;

    private final PrintStream sink;
    private final boolean ownsSink;

    private AuditLog(PrintStream sink, boolean ownsSink) {
        this.sink = sink;
        this.ownsSink = ownsSink;
    }

    /** An audit log that writes to the process's standard error. */
    public static AuditLog toStandardError() {
        return new AuditLog(System.err, false);
    }

    /**
     * An audit log that appends to {@code path}, creating it owner-only if absent.
     *
     * @throws IOException         if the file cannot be opened for appending
     * @throws ValidationException if the existing file is not a regular file, or is accessible to
     *                             accounts other than its owner
     */
    public static AuditLog toFile(Path path) throws IOException, ValidationException {
        Path resolved = path.toAbsolutePath().normalize();
        PrivateFiles.createPrivateIfAbsent(resolved);
        PrivateFiles.requireOwnerOnly(resolved, "audit log");

        PrintStream stream = new PrintStream(
                Files.newOutputStream(resolved, StandardOpenOption.CREATE, StandardOpenOption.APPEND),
                true, StandardCharsets.UTF_8);
        return new AuditLog(stream, true);
    }

    /** Records a routine operational event. */
    public void info(String event, String detail) {
        write("INFO", event, detail);
    }

    /** Records something that looks wrong but is handled: rejected input, a malformed record. */
    public void warn(String event, String detail) {
        write("WARN", event, detail);
    }

    /** Records a security-relevant decision: a grant, a denial, a restriction taking effect. */
    public void security(String event, String detail) {
        write("SECURITY", event, detail);
    }

    private synchronized void write(String level, String event, String detail) {
        String line = Instant.now() + " " + level + " " + sanitise(event)
                + (detail == null || detail.isEmpty() ? "" : " | " + sanitise(detail));
        sink.println(line);
    }

    /**
     * Collapses control characters and truncates, so no field can inject an extra log line or grow
     * the log without bound. Newline injection matters because a forged line could otherwise make an
     * attacker's failed attempt look like somebody else's successful one.
     */
    private static String sanitise(String value) {
        if (value == null) {
            return "";
        }
        String trimmed = value.length() > MAX_FIELD_LENGTH
                ? value.substring(0, MAX_FIELD_LENGTH) + "...(truncated)"
                : value;
        StringBuilder out = new StringBuilder(trimmed.length());
        for (int i = 0; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            out.append(c < 0x20 || c == 0x7F ? '.' : c);
        }
        return out.toString();
    }

    /**
     * Masks an account identifier for logging: first character, then the length.
     *
     * <p>Enough to tell two accounts apart across entries in an investigation; not enough to recover
     * the directory from a leaked log. Applied to the raw value too, so an invalid username that was
     * rejected is not echoed in full either.
     */
    public static String maskAccount(String username) {
        if (username == null || username.isEmpty()) {
            return "<absent>";
        }
        String safe = sanitise(username);
        return safe.charAt(0) + "***(len=" + safe.length() + ")";
    }

    /**
     * Masks a source address for logging: the network part is kept, the host part dropped.
     *
     * <p>An IPv4 address keeps its first three octets, an IPv6 address its first three groups. That
     * preserves the grouping needed to spot a distributed attempt while not pinning the log to one
     * employee's device.
     */
    public static String maskSource(String source) {
        if (source == null || source.isEmpty()) {
            return "<absent>";
        }
        String safe = sanitise(source).toLowerCase(Locale.ROOT);
        if (safe.indexOf(':') >= 0) {
            String[] groups = safe.split(":", -1);
            StringBuilder out = new StringBuilder();
            for (int i = 0; i < Math.min(3, groups.length); i++) {
                out.append(groups[i]).append(':');
            }
            return out.append("*").toString();
        }
        String[] octets = safe.split("\\.", -1);
        if (octets.length == 4) {
            return octets[0] + "." + octets[1] + "." + octets[2] + ".*";
        }
        return safe.length() <= 4 ? "*" : safe.substring(0, 4) + "*";
    }

    @Override
    public void close() {
        if (ownsSink) {
            sink.flush();
            sink.close();
        } else {
            sink.flush();
        }
    }
}
