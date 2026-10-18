package app;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Append-only security audit trail.
 *
 * <p>Every field written here is chosen by this program. No externally supplied string -
 * email, username, password, token, file name - is ever passed to {@link #record}, so log
 * injection and secret leakage through the log are structural properties rather than
 * conventions someone has to remember. Where a value must be correlated across records it
 * appears as a SHA-256 tag, which is not a credential.
 *
 * <p>Writes fail closed: {@link Gate} turns an {@link AuditException} into a denial, so an
 * attacker who replaces the file with a directory or widens its permissions cannot make security
 * events unrecorded. The size budget is the one case that does not deny: see {@link #truncateToFit}
 * for why retiring old records beats refusing the feature.
 */
public final class AuditLog implements AutoCloseable {

    /**
     * Upper bound on the trail. Startup enforces it, and an append that would exceed it retires
     * the oldest records and says so, rather than refusing every later security decision.
     */
    public static final long MAX_BYTES = 64L * 1024 * 1024;

    private static final Set<PosixFilePermission> OWNER_ONLY =
        EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

    /** Event names are a fixed vocabulary - never derived from input. */
    public enum Event {
        REGISTRATION_ATTEMPTED,
        REGISTRATION_ACCEPTED,
        REGISTRATION_DUPLICATE,
        REGISTRATION_THROTTLED,
        REGISTRATION_REFUSED_INVALID_INPUT,
        LOGIN_SUCCESS,
        LOGIN_FAILURE,
        LOGIN_REFUSED_INVALID_INPUT,
        LOGIN_THROTTLED_ACCOUNT,
        LOGIN_THROTTLED_SOURCE,
        LOGIN_STORE_ERROR,
        ACCOUNT_LOCKED,
        ACCOUNT_UNLOCKED,
        ADMIN_REVOKE_REQUESTED,
        ADMIN_REVOKE_REFUSED_INVALID_INPUT,
        MAINTENANCE_RUN,
        TRAIL_RETURED,
        SESSION_ISSUED,
        SESSION_REJECTED,
        SESSION_REVOKED
    }

    private final Path file;
    private final Object writeLock = new Object();
    private long bytes = -1;

    public AuditLog(Path file) {
        this.file = file;
    }

    /** Writes one record; throws if it could not be persisted, so callers can fail closed. */
    public void record(Event event, String... fields) throws AuditException {
        if (event == null) {
            throw new IllegalArgumentException("event is required");
        }
        if (fields.length % 2 != 0) {
            throw new IllegalArgumentException("fields must be key/value pairs");
        }
        StringBuilder line = new StringBuilder(192).append('{');
        field(line, "ts", Instant.now().toString(), true);
        field(line, "event", event.name(), false);
        for (int i = 0; i < fields.length; i += 2) {
            field(line, fields[i], fields[i + 1], false);
        }
        line.append('}').append('\n');
        byte[] encoded = line.toString().getBytes(StandardCharsets.UTF_8);
        synchronized (writeLock) {
            try {
                guardFile();
                if (bytes + encoded.length > MAX_BYTES) {
                    truncateToFit(encoded.length);
                }
                append(encoded);
                bytes += encoded.length;
            } catch (IOException | AuditException failed) {
                throw new AuditException("the audit record could not be written");
            }
        }
    }

    /**
     * Startup bound: if an existing trail has grown past the budget - which can only happen from
     * outside this process - retire it and mark the cut. Called before any command runs.
     */
    public void retireOversizedTrail() throws AuditException {
        synchronized (writeLock) {
            try {
                guardFile();
                if (bytes > MAX_BYTES) {
                    restartTrail(bytes);
                }
            } catch (IOException | AuditException failed) {
                throw new AuditException("the audit trail could not be retired");
            }
        }
    }

    /**
     * Starts a new trail when the budget is full, and says so on the operator's terminal.
     *
     * <p>Retiring the oldest records is the only behaviour that keeps the feature available. A
     * budget that merely refuses would mean that filling the log - which anyone able to trigger
     * refusals can do - turns every later sign-in and registration into a denial: a denial of
     * service against the whole feature, caused by the audit control itself.
     *
     * <p>The cut is marked in two channels, not one. The operator sees a note on the terminal, and a
     * {@link Event#TRAIL_RETURED} record becomes the new trail's first line carrying the retired byte
     * count. The in-trail marker is the load-bearing one: without it, flooding the trail destroys
     * every {@code LOGIN_SUCCESS}, {@code ACCOUNT_LOCKED} and {@code ADMIN_REVOKE_REQUESTED} ever
     * written and leaves a file indistinguishable from one where nothing happened - the erasure would
     * be invisible to anyone who cannot read the terminal. A single record that cannot fit the whole
     * budget still fails closed.
     */
    private void truncateToFit(int incoming) throws IOException, AuditException {
        long retired = Math.max(bytes, 0L);
        restartTrail(retired);
        if (bytes + incoming > MAX_BYTES) {
            throw new AuditException("a single audit record cannot fit the audit budget");
        }
    }

    /**
     * Deletes the trail, recreates it owner-only, and writes the retirement marker as the new first
     * record. Must be called while {@link #writeLock} is held.
     */
    private void restartTrail(long retiredBytes) throws IOException, AuditException {
        Files.delete(file);
        bytes = -1;
        guardFile();
        System.err.println("NOTE the audit log reached its " + MAX_BYTES
            + " byte budget and was restarted; " + retiredBytes
            + " bytes of older trail were retired");
        StringBuilder line = new StringBuilder(160).append('{');
        field(line, "ts", Instant.now().toString(), true);
        field(line, "event", Event.TRAIL_RETURED.name(), false);
        field(line, "retired_bytes", Long.toString(retiredBytes), false);
        field(line, "budget_bytes", Long.toString(MAX_BYTES), false);
        line.append('}').append('\n');
        byte[] marker = line.toString().getBytes(StandardCharsets.UTF_8);
        append(marker);
        bytes += marker.length;
    }

    /**
     * Appends to the trail without ever following a symbolic link and without ever creating one.
     *
     * <p>{@link LinkOption#NOFOLLOW_LINKS} is passed to the open itself, so the kernel - and not a
     * check that completed a few instructions earlier - is what refuses a trail that was swapped for
     * a link or a directory after {@link #guardFile()} looked at it. Without it, {@code guardFile}
     * proves the path is a regular owner-only file and the append then writes wherever the path
     * points at the moment of the open, which is a window anyone able to write in the data
     * directory can reopen at will.
     *
     * <p>{@code CREATE} is deliberately absent: a trail that disappears mid-record must make this
     * record fail closed - the caller denies - rather than have the append quietly re-create it with
     * the process umask, which is typically group- and world-readable. The next record's
     * {@link #guardFile()} re-creates the file owner-only, so one record is lost, not the trail.
     */
    private void append(byte[] encoded) throws IOException {
        Files.write(file, encoded, LinkOption.NOFOLLOW_LINKS,
            StandardOpenOption.WRITE, StandardOpenOption.APPEND);
    }

    private void guardFile() throws IOException, AuditException {
        if (Files.isSymbolicLink(file)) {
            throw new AuditException("the audit log is a symbolic link");
        }
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
            // The mode is passed to the create so a recreated trail cannot exist for even an
            // instant with the umask default; there is no chmod afterwards, because chmod follows
            // links and a create attribute does not.
            Files.createFile(file, PosixFilePermissions.asFileAttribute(OWNER_ONLY));
        }
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            throw new AuditException("the audit log is not a regular file");
        }
        if (!OWNER_ONLY.equals(Files.getPosixFilePermissions(file, LinkOption.NOFOLLOW_LINKS))) {
            throw new AuditException("the audit log is not owner-only");
        }
        // Re-read rather than trust the running total: the budget bounds the file on disk, and a
        // counter that only knows this process's own appends would let anything else that wrote to
        // the trail push it past the guard unnoticed. Attributes are read for this path, never for
        // whatever a link at this path happens to point at.
        bytes = Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS).size();
    }

    private static void field(StringBuilder out, String key, String value, boolean first) {
        if (!first) {
            out.append(',');
        }
        out.append('"').append(safeKey(key)).append("\":\"").append(escape(value)).append('"');
    }

    private static String safeKey(String key) {
        StringBuilder out = new StringBuilder(key.length());
        for (int i = 0; i < key.length(); i++) {
            char c = key.charAt(i);
            out.append(Character.isLetterOrDigit(c) || c == '_' ? c : '_');
        }
        return out.toString();
    }

    /**
     * Values are code-supplied, but they are still escaped and length-bounded so a future caller
     * cannot break out of the JSON string or write a megabyte per event.
     */
    private static String escape(String value) {
        String bounded = value == null ? "" : (value.length() > 256 ? value.substring(0, 256) : value);
        StringBuilder out = new StringBuilder(bounded.length() + 8);
        for (int i = 0; i < bounded.length(); i++) {
            char c = bounded.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20 || c == 0x7f) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.toString();
    }

    /** Reads the trail, for tests and operator inspection. */
    public List<String> readAll() throws IOException {
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
            return new ArrayList<>();
        }
        return Files.readAllLines(file, StandardCharsets.UTF_8);
    }

    public Path path() {
        return file;
    }

    @Override
    public void close() {
        // Records open the file per append so a long-lived handle cannot be redirected or held
        // open by another process; there is nothing to close.
    }

    /** Audit failure. Callers that gate on auditing must treat this as a denial. */
    public static final class AuditException extends Exception {
        private static final long serialVersionUID = 1L;

        AuditException(String safeDescription) {
            super(safeDescription);
        }
    }
}
