package com.example.adminportal;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

/**
 * Append-only audit trail for authentication and administrative events.
 *
 * Every record is chained to its predecessor with a SHA-256 digest, so any
 * deletion or edit of an earlier line breaks verification of every line after
 * it. That makes the log tamper-evident: an attacker who gains write access can
 * still destroy it, but cannot quietly remove the record of their own login.
 *
 * Record format (tab separated, one line each):
 *   timestamp  outcome  username  source  detail  chainDigest
 *
 * Field values are escaped so a hostile username cannot forge extra fields or
 * inject newlines. Passwords are never passed to this class.
 */
public final class AuditLogger {

    /** Digest of the empty chain, used as the predecessor of the first record. */
    private static final String GENESIS = "0".repeat(64);

    private static final Set<PosixFilePermission> OWNER_ONLY_FILE =
            PosixFilePermissions.fromString("rw-------");
    private static final Set<PosixFilePermission> OWNER_ONLY_DIR =
            PosixFilePermissions.fromString("rwx------");

    private final Path logFile;
    private final Object lock = new Object();

    public AuditLogger(Path logFile) throws IOException {
        this.logFile = logFile.toAbsolutePath();
        prepareStorage();
    }

    /** Outcome of an audited event. */
    public enum Outcome {
        AUTH_SUCCESS,
        AUTH_FAILURE,
        AUTH_LOCKED_OUT,
        SESSION_END,
        ADMIN_ACTION,
        ACCESS_DENIED
    }

    /** A parsed audit record. */
    public record Entry(String timestamp, Outcome outcome, String username,
                        String source, String detail, String digest) {
    }

    /**
     * Appends one event to the trail.
     *
     * @param outcome  what happened
     * @param username the submitted username; recorded verbatim so failed attempts
     *                 against unknown accounts are still reviewable
     * @param source   where the attempt came from (host, terminal, address)
     * @param detail   non-sensitive context; must never contain a password
     */
    public void record(Outcome outcome, String username, String source, String detail) {
        String timestamp = Instant.now().toString();
        String line;
        synchronized (lock) {
            String previous = lastDigest();
            String payload = String.join("\t",
                    timestamp,
                    outcome.name(),
                    escape(username),
                    escape(source),
                    escape(detail));
            String digest = sha256(previous + "\n" + payload);
            line = payload + "\t" + digest + System.lineSeparator();
            try {
                Files.writeString(logFile, line, StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            } catch (IOException e) {
                // An unwritable audit trail means events would go unrecorded, so the
                // caller must be able to fail closed rather than continue silently.
                throw new AuditFailureException("Unable to append to audit log " + logFile, e);
            }
        }
    }

    /** Reads the trail in chronological order for later review. */
    public List<Entry> read() throws IOException {
        List<Entry> entries = new ArrayList<>();
        if (!Files.exists(logFile)) {
            return entries;
        }
        synchronized (lock) {
            for (String line : Files.readAllLines(logFile, StandardCharsets.UTF_8)) {
                if (line.isBlank()) {
                    continue;
                }
                String[] f = line.split("\t", -1);
                if (f.length != 6) {
                    throw new IOException("Malformed audit record: " + line);
                }
                entries.add(new Entry(f[0], parseOutcome(f[1]), unescape(f[2]),
                        unescape(f[3]), unescape(f[4]), f[5]));
            }
        }
        return entries;
    }

    /**
     * Recomputes the hash chain over the whole file.
     *
     * @return the 1-based index of the first record that fails verification, or
     *         0 when the trail is intact
     */
    public long verifyIntegrity() throws IOException {
        synchronized (lock) {
            if (!Files.exists(logFile)) {
                return 0;
            }
            String previous = GENESIS;
            long index = 0;
            for (String line : Files.readAllLines(logFile, StandardCharsets.UTF_8)) {
                if (line.isBlank()) {
                    continue;
                }
                index++;
                int cut = line.lastIndexOf('\t');
                if (cut < 0) {
                    return index;
                }
                String payload = line.substring(0, cut);
                String recorded = line.substring(cut + 1);
                String expected = sha256(previous + "\n" + payload);
                if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                        recorded.getBytes(StandardCharsets.UTF_8))) {
                    return index;
                }
                previous = recorded;
            }
            return 0;
        }
    }

    public Path location() {
        return logFile;
    }

    /** Thrown when an event cannot be persisted, so callers can deny access. */
    public static final class AuditFailureException extends RuntimeException {
        AuditFailureException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private String lastDigest() {
        try {
            if (!Files.exists(logFile) || Files.size(logFile) == 0) {
                return GENESIS;
            }
            List<String> lines = Files.readAllLines(logFile, StandardCharsets.UTF_8);
            for (int i = lines.size() - 1; i >= 0; i--) {
                String line = lines.get(i);
                if (!line.isBlank()) {
                    int cut = line.lastIndexOf('\t');
                    return cut < 0 ? GENESIS : line.substring(cut + 1);
                }
            }
            return GENESIS;
        } catch (IOException e) {
            throw new AuditFailureException("Unable to read audit log " + logFile, e);
        }
    }

    private void prepareStorage() throws IOException {
        Path parent = logFile.getParent();
        if (parent != null && !Files.exists(parent)) {
            Files.createDirectories(parent);
            trySetPermissions(parent, OWNER_ONLY_DIR);
        }
        if (!Files.exists(logFile)) {
            Files.createFile(logFile);
        }
        trySetPermissions(logFile, OWNER_ONLY_FILE);
    }

    private static void trySetPermissions(Path path, Set<PosixFilePermission> permissions) {
        try {
            Files.setPosixFilePermissions(path, EnumSet.copyOf(permissions));
        } catch (UnsupportedOperationException | IOException e) {
            // Non-POSIX filesystem; the platform default ACL applies instead.
        }
    }

    private static Outcome parseOutcome(String value) throws IOException {
        try {
            return Outcome.valueOf(value);
        } catch (IllegalArgumentException e) {
            throw new IOException("Unknown audit outcome: " + value);
        }
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    private static String escape(String value) {
        if (value == null || value.isEmpty()) {
            return "-";
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '\t' -> sb.append("\\t");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                default -> {
                    if (c < 0x20 || c == 0x7f) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }

    private static String unescape(String value) {
        if ("-".equals(value)) {
            return "";
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c != '\\' || i + 1 >= value.length()) {
                sb.append(c);
                continue;
            }
            char next = value.charAt(++i);
            switch (next) {
                case '\\' -> sb.append('\\');
                case 't' -> sb.append('\t');
                case 'n' -> sb.append('\n');
                case 'r' -> sb.append('\r');
                case 'u' -> {
                    if (i + 4 < value.length()) {
                        sb.append((char) Integer.parseInt(value.substring(i + 1, i + 5), 16));
                        i += 4;
                    }
                }
                default -> sb.append('\\').append(next);
            }
        }
        return sb.toString();
    }
}
