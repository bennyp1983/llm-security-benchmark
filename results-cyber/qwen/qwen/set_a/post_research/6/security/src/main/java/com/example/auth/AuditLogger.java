package com.example.auth;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Append-only authentication event log.
 *
 * <p><b>Fail-closed by construction.</b> The factory will not return an instance that silently
 * discards events, and {@link #record(AuthEvent)} verifies the write: if the channel reports fewer
 * bytes than the encoder produced, or the rendered line would be unsafe to write, it throws
 * {@link AuditPersistenceException} and {@link AuthenticationService} refuses the attempt.
 * Authentication therefore cannot proceed with an unrecorded event.
 *
 * <p>Nothing latches. A transient condition (a full file system, a brief write error) refuses the
 * attempts that hit it; once the condition clears, the next attempt authenticates again. Free space
 * is re-checked at most once every {@value #FREE_SPACE_RECHECK_INTERVAL_MILLIS} ms and the interval
 * is re-armed after every failed write, so recovery is automatic and does not need an operator.
 *
 * <p>File handling (all mode checks go through {@link PosixMode} and therefore fail closed):
 * <ul>
 *   <li>the parent directory must exist and must not be writable by group or other users - a
 *       writable directory lets another user replace, delete or pre-create the log at that name;</li>
 *   <li>an existing log file must be a regular file (checked without following symlinks), readable,
 *       writable, and exactly owner-only ({@code 0600});</li>
 *   <li>a new log file is created with the owner-only permission set (equivalent to {@code 0600})
 *       using {@code CREATE_NEW}, so anything already present at that name - including a symlink -
 *       makes creation fail rather than being adopted; the resulting permissions are read back and
 *       verified;</li>
 *   <li>a file whose last record is truncated - the signature of a process that died, or a write
 *       that returned short, mid-line - is repaired before anything is appended to it, see
 *       {@link #discardTornTail(Path)};</li>
 *   <li>the file system must have at least the configured free-space headroom, and the file itself
 *       must be under {@value #MAX_LOG_BYTES} bytes.</li>
 * </ul>
 *
 * <p>Retention: the last {@code maxEvents} rendered lines are kept in a bounded in-memory ring so
 * recent activity can be reviewed without unbounded growth. The file is the durable record; rotation
 * and long-term storage are operator concerns and are noted in the README.
 */
final class AuditLogger {

    /**
     * Ceiling on the log file, enforced at open and before every write. The same bound
     * {@code AuthConfig} applies to a pre-existing file at start-up; without the per-write half, a
     * long-lived process would push the file past that bound and every restart would then refuse to
     * boot, so the operator's only recovery window would be before the first restart.
     */
    static final long MAX_LOG_BYTES = 64L * 1024L * 1024L;

    /** Bytes read per step when scanning backwards for the last record boundary. */
    private static final int TAIL_SCAN_CHUNK = 8 * 1024;

    /** Upper bound on what {@link #readBack()} will read, so review cannot be made to thrash the disk. */
    private static final long MAX_READ_BACK_BYTES = 4L * 1024L * 1024L;

    private static final long FREE_SPACE_RECHECK_INTERVAL_MILLIS = 30_000L;

    private final Path file;
    private final int maxEvents;
    private final long minFreeBytes;
    private final long maxLogBytes;

    private final Deque<String> retained = new ArrayDeque<>();
    private FileChannel channel;
    /**
     * Identity ({@code dev}+{@code ino}) of the inode {@link #channel} was opened against. Compared
     * before every write, see {@link #targetStillOurs()}.
     */
    private Object openedFileKey;
    private long sequence;
    private long totalRecorded;
    private long unsavedEvents;
    /**
     * Lifetime total of bytes discarded while repairing torn tails - what {@link #discardedTornBytes()}
     * reports.
     */
    private long discardedTornBytes;
    /** Bytes discarded since the last {@code log_partial_record} alert, so a repair is reported once. */
    private long pendingTornAlertBytes;
    private long lastFreeSpaceCheckMillis;
    private long lastWriteFailureMillis;
    private boolean closed;
    private boolean alertInFlight;

    private AuditLogger(Path file, int maxEvents, long minFreeBytes, long maxLogBytes, long nowMillis) {
        this.file = file;
        this.maxEvents = maxEvents;
        this.minFreeBytes = minFreeBytes;
        this.maxLogBytes = maxLogBytes;
        this.lastFreeSpaceCheckMillis = nowMillis;
    }

    /**
     * Opens or creates the log file.
     *
     * @throws InvalidConfigException when the location or the permissions would leave the log unsafe
     *     or unwritable. Problems name the condition only, never a client-supplied value.
     */
    static AuditLogger open(Path file, int maxEvents, long minFreeBytes, long nowMillis) throws InvalidConfigException {
        return open(file, maxEvents, minFreeBytes, MAX_LOG_BYTES, nowMillis);
    }

    /**
     * As {@link #open(Path, int, long, long)} with the size ceiling supplied, so the per-write bound
     * in {@link #storageProblem()} can be exercised at a scale a test can reach. The production
     * overload above is the only one the service calls.
     */
    static AuditLogger open(Path file, int maxEvents, long minFreeBytes, long maxLogBytes, long nowMillis)
            throws InvalidConfigException {
        List<String> problems = new ArrayList<>();
        if (file == null || maxEvents < 1 || maxLogBytes < 1L) {
            problems.add("event log configuration is incomplete");
            throw new InvalidConfigException(problems);
        }
        Path parent = file.getParent();
        if (parent == null || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
            problems.add("event log directory does not exist");
            throw new InvalidConfigException(problems);
        }
        if (PosixMode.writableByGroupOrOther(parent)) {
            problems.add("event log directory is writable by group or other users, "
                    + "or its permissions could not be verified");
            throw new InvalidConfigException(problems);
        }
        boolean exists = Files.exists(file, LinkOption.NOFOLLOW_LINKS);
        if (exists) {
            if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
                problems.add("event log path exists but is not a regular file");
                throw new InvalidConfigException(problems);
            }
            if (!Files.isWritable(file)) {
                problems.add("event log file is not writable");
                throw new InvalidConfigException(problems);
            }
        } else {
            try {
                // CREATE_NEW rather than CREATE+APPEND: anything already at the target name,
                // including a symlink another user placed there, must fail the open rather than be
                // adopted and written through.
                Set<? extends OpenOption> createOptions = EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
                // Created empty and closed immediately: the point is the create with the owner-only
                // mode, not a handle to keep.
                FileChannel created = FileChannel.open(file, createOptions, ownerOnlyAttributes());
                created.close();
            } catch (IOException e) {
                problems.add("event log file could not be created");
                throw new InvalidConfigException(problems);
            }
        }
        if (PosixMode.notExactlyOwnerOnly(file)) {
            problems.add("event log file is not exactly owner-only (0600), or its permissions could "
                    + "not be verified");
        }
        if (!problems.isEmpty()) {
            throw new InvalidConfigException(problems);
        }
        long discarded = discardTornTail(file);
        if (discarded < 0L) {
            problems.add("the event log file ends in a partial record that could not be repaired");
            throw new InvalidConfigException(problems);
        }
        AuditLogger logger = new AuditLogger(file, maxEvents, minFreeBytes, maxLogBytes, nowMillis);
        logger.discardedTornBytes = discarded;
        logger.pendingTornAlertBytes = discarded;
        logger.checkFreeSpace(problems);
        if (!problems.isEmpty()) {
            throw new InvalidConfigException(problems);
        }
        try {
            logger.channel = FileChannel.open(file, StandardOpenOption.WRITE, StandardOpenOption.APPEND);
            logger.openedFileKey = fileKeyOf(file);
        } catch (IOException | RuntimeException e) {
            problems.add("event log file could not be opened for append");
            throw new InvalidConfigException(problems);
        }
        if (discarded > 0L) {
            // The repair removes evidence, so it is itself an event. Written after the channel is
            // open, and never in place of the events it made room for. If even that write fails the
            // pending count survives, so the next successful write reports the gap.
            if (logger.recordAlert(Diagnostic.LOG_PARTIAL_RECORD, (String) null, null)) {
                logger.pendingTornAlertBytes = 0L;
            }
        }
        return logger;
    }

    /**
     * Writes one event and the retained copy.
     *
     * @return the line that was persisted
     * @throws AuditPersistenceException when the event could not be persisted. The caller must treat
     *     this as a security failure and refuse the attempt rather than proceed.
     */
    synchronized String record(AuthEvent event) throws AuditPersistenceException {
        if (closed) {
            throw new AuditPersistenceException(Diagnostic.AUDIT_UNAVAILABLE);
        }
        String line = event == null ? null : event.renderOrReject(sequence + 1);
        if (line == null) {
            // An unsafe line is a defect in this process, not a client problem. The unsafe content
            // is never written; the caller records an alert naming the reason instead.
            unsavedEvents++;
            throw new AuditPersistenceException(Diagnostic.LOG_LINE_REJECTED, event);
        }
        if (channel == null) {
            reopenIfPossible();
            if (channel == null) {
                unsavedEvents++;
                throw new AuditPersistenceException(Diagnostic.LOG_WRITE_FAILED, event);
            }
            if (pendingTornAlertBytes > 0L) {
                // Discarding a torn tail removes evidence, so the next event reports the gap instead
                // of leaving the file silently short. recordAlert is re-entrant on this monitor and
                // cannot recurse back into record().
                if (recordAlert(Diagnostic.LOG_PARTIAL_RECORD, (String) null, null)) {
                    pendingTornAlertBytes = 0L;
                }
            }
        }
        if (!targetStillOurs()) {
            unsavedEvents++;
            throw new AuditPersistenceException(Diagnostic.LOG_WRITE_FAILED, event);
        }
        Diagnostic storageProblem = storageProblem();
        if (storageProblem != null) {
            unsavedEvents++;
            throw new AuditPersistenceException(storageProblem, event);
        }
        writeAndRetain(line, event);
        return line;
    }

    /**
     * Writes an alert about a failure, without recursing if that write also fails.
     *
     * @return {@code true} when the alert itself was persisted. When it is {@code false} the
     *     condition is unrecoverable from here and the caller must keep refusing.
     */
    synchronized boolean recordAlert(Diagnostic reason, String submittedUsername, String canonicalSource) {
        AuthEvent fallback = AuthEvent.builder()
                .timestampMillis(System.currentTimeMillis())
                .account(submittedUsername, false)
                .source(canonicalSource)
                .latencyMicros(0L)
                .build();
        return recordAlert(reason, fallback);
    }

    /**
     * Writes an alert about {@code original}, keeping whatever of it was already safe to record.
     *
     * <p>The alert exists because one event could not be written, so the fields of that event are the
     * evidence most worth keeping. Re-deriving them from the caller's arguments instead would report
     * every throttled, wrong-account and locked-out attempt as though it named no account at all,
     * which is precisely the attribution a reviewer needs. Only fields this class would itself have
     * written are carried over - an alert about a rejected line must not try to write it again.
     */
    synchronized boolean recordAlert(Diagnostic reason, AuthEvent original) {
        if (closed || alertInFlight) {
            unsavedEvents++;
            return false;
        }
        alertInFlight = true;
        try {
            if (channel == null) {
                reopenIfPossible();
                if (channel == null) {
                    unsavedEvents++;
                    return false;
                }
            }
            if (!targetStillOurs()) {
                unsavedEvents++;
                return false;
            }
            AuthEvent alert = AuthEvent.builder()
                    .timestampMillis(original == null ? System.currentTimeMillis() : original.timestampMillis())
                    .type(EventType.SECURITY_ALERT)
                    .outcome("error")
                    .accountFieldOf(original == null ? null : original.accountField())
                    .source(original == null ? null : original.sourceIfSafe())
                    .reason(reason)
                    .latencyMicros(original == null ? 0L : original.latencyMicrosIfSafe())
                    .retryAfterSeconds(original == null ? 0 : original.retryAfterSecondsIfSafe())
                    .build();
            String line = alert.renderOrReject(sequence + 1);
            if (line == null) {
                unsavedEvents++;
                return false;
            }
            writeAndRetain(line, alert);
            return true;
        } catch (AuditPersistenceException e) {
            // writeAndRetain already counted the hole, stamped the failure, re-armed the free-space
            // check and closed the channel.
            return false;
        } catch (RuntimeException e) {
            lastWriteFailureMillis = System.currentTimeMillis();
            lastFreeSpaceCheckMillis = 0L;
            closeChannelQuietly();
            unsavedEvents++;
            return false;
        } finally {
            alertInFlight = false;
        }
    }

    /**
     * Appends one already-rendered line, verifies that every byte landed, and only then counts the
     * line as recorded.
     *
     * <p>Both writers go through here so that neither can forget part of the bookkeeping. A failed
     * write closes the channel (so the next attempt re-validates the target instead of appending
     * blind into an inode we no longer trust), stamps the failure, and resets the free-space interval
     * - the claim in the class note above that space is re-checked after a failed write is this line,
     * not an assumption.
     *
     * <p>A short write is not retried against the same channel. The bytes already in the file are a
     * partial record, and the only sound response is to stop writing and let the next attempt
     * re-open, at which point {@link #discardTornTail(Path)} removes the partial record before
     * anything else is appended. {@code APPEND} alone would otherwise splice the next event onto the
     * fragment and produce one line that is a mixture of two attempts.
     */
    private void writeAndRetain(String line, AuthEvent event) throws AuditPersistenceException {
        byte[] bytes = (line + "\n").getBytes(StandardCharsets.UTF_8);
        try {
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) {
                if (channel.write(buffer) <= 0) {
                    throw new IOException("the log channel accepted no further bytes");
                }
            }
            channel.force(false);
        } catch (IOException | RuntimeException e) {
            unsavedEvents++;
            lastWriteFailureMillis = System.currentTimeMillis();
            lastFreeSpaceCheckMillis = 0L;
            closeChannelQuietly();
            throw new AuditPersistenceException(Diagnostic.LOG_WRITE_FAILED, event);
        }
        sequence++;
        totalRecorded++;
        retained.addLast(line);
        while (retained.size() > maxEvents) {
            retained.removeFirst();
        }
    }

    /** Lines currently retained in memory, oldest first. Never contains credentials. */
    synchronized List<String> retained() {
        return Collections.unmodifiableList(new ArrayList<>(retained));
    }

    synchronized long totalRecorded() {
        return totalRecorded;
    }

    /**
     * Events this process tried to write and could not. Every one of those cost the caller a denial,
     * so the number is the size of the hole in the audit trail: without it an operator sees a healthy
     * service producing an empty log, and nobody can tell "no activity" from "activity refused
     * because activity cannot be recorded".
     */
    synchronized long unsavedEvents() {
        return unsavedEvents;
    }

    /**
     * Bytes of a partial trailing record this process discarded while repairing the log. Not counted
     * in {@link #unsavedEvents()} - those bytes were never written by this process - but the hole is
     * real, which is why a repair is itself logged as an alert.
     */
    synchronized long discardedTornBytes() {
        return discardedTornBytes;
    }

    /** {@code true} when the most recent write attempt failed; never used to block forever. */
    synchronized boolean lastWriteFailed() {
        return lastWriteFailureMillis != 0 && channel == null;
    }

    synchronized boolean isClosed() {
        return closed;
    }

    Path file() {
        return file;
    }

    /**
     * Reads the tail of the file back from disk; used by the deployment check and by tests.
     *
     * <p>Bounded to the last {@value #MAX_READ_BACK_BYTES} bytes: the log may legitimately sit at its
     * size ceiling, and a review helper that loads a whole audit file into memory turns a routine
     * status call into a disk-and-heap incident. A leading partial line (the read starting mid-record)
     * is dropped rather than reported as a record.
     */
    List<String> readBack() throws IOException {
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            return Collections.emptyList();
        }
        long size = Files.size(file);
        if (size == 0L) {
            return Collections.emptyList();
        }
        long skip = Math.max(0L, size - MAX_READ_BACK_BYTES);
        int length = (int) (size - skip);
        byte[] raw = new byte[length];
        try (FileChannel probe = FileChannel.open(file, StandardOpenOption.READ)) {
            ByteBuffer target = ByteBuffer.wrap(raw);
            long position = skip;
            int stalls = 0;
            while (target.hasRemaining()) {
                if (probe.read(target, position) < 0L && ++stalls > 8) {
                    throw new IOException("the event log ended before the bytes it reported");
                }
                position = size - target.remaining();
            }
        }
        String text = new String(raw, StandardCharsets.UTF_8);
        List<String> lines = new ArrayList<>();
        int from = skip > 0L ? text.indexOf('\n') + 1 : 0;
        int at = from;
        while (at < text.length()) {
            int nl = text.indexOf('\n', at);
            int end = nl < 0 ? text.length() : nl;
            if (end > at) {
                lines.add(text.substring(at, end));
            }
            if (nl < 0) {
                break;
            }
            at = nl + 1;
        }
        return lines;
    }

    synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        closeChannelQuietly();
    }

    private boolean freeSpaceCheckDue() {
        long now = System.currentTimeMillis();
        if (now - lastFreeSpaceCheckMillis < FREE_SPACE_RECHECK_INTERVAL_MILLIS) {
            return false;
        }
        lastFreeSpaceCheckMillis = now;
        return true;
    }

    /**
     * Checks what the log can still absorb before a write is attempted.
     *
     * @return the reason to refuse, or {@code null} when the write may proceed
     */
    private Diagnostic storageProblem() {
        if (freeSpaceCheckDue()) {
            List<String> problems = new ArrayList<>();
            checkFreeSpace(problems);
            if (!problems.isEmpty()) {
                return Diagnostic.LOG_STORAGE_FULL;
            }
        }
        long size;
        try {
            size = Files.size(file);
        } catch (IOException | RuntimeException e) {
            // The file we were appending to cannot be sized: treat it as untrusted rather than
            // write blind.
            return Diagnostic.LOG_WRITE_FAILED;
        }
        if (size >= maxLogBytes) {
            return Diagnostic.LOG_FILE_LIMIT;
        }
        return null;
    }

    /** Re-opens a channel that a failed write closed, so a transient error does not persist. */
    private void reopenIfPossible() {
        if (closed || channel != null) {
            return;
        }
        try {
            if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
                return;
            }
            if (PosixMode.notExactlyOwnerOnly(file)) {
                return;
            }
            long discarded = discardTornTail(file);
            if (discarded < 0L) {
                // The tail cannot be repaired, so appending would build a corrupted record on top of
                // it. Refuse and keep refusing until the file is dealt with out of band.
                return;
            }
            discardedTornBytes += discarded;
            pendingTornAlertBytes += discarded;
            FileChannel reopened = FileChannel.open(file,
                    EnumSet.of(StandardOpenOption.WRITE, StandardOpenOption.APPEND));
            channel = reopened;
            openedFileKey = fileKeyOf(file);
            lastWriteFailureMillis = 0L;
        } catch (IOException | RuntimeException e) {
            channel = null;
            openedFileKey = null;
        }
    }

    /**
     * Confirms that the name this logger writes to still denotes the file it was opened against, and
     * is still safe to write.
     *
     * <p>An open {@link FileChannel} keeps writing into an inode even after some other process
     * deletes or replaces the path that named it. Without this check the service would keep
     * authenticating while every event went to an unlinked inode that vanishes on close: the audit
     * trail stops existing and nothing reports it. The same check refuses a path that became a
     * symlink, one replaced by a file another user can read or write, and one that was deleted.
     *
     * <p>Runs on every write rather than on a timer. A single unverified write is enough to lose an
     * event, and one {@code getattr} is nothing next to the key derivation every attempt already
     * performs.
     *
     * @return {@code false} when the write must not proceed; the channel is closed so the next
     *     attempt can try to reopen, which keeps recovery automatic
     */
    private boolean targetStillOurs() {
        final java.nio.file.attribute.BasicFileAttributes attrs;
        try {
            attrs = Files.readAttributes(file, java.nio.file.attribute.BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS);
        } catch (IOException | RuntimeException e) {
            // Includes NoSuchFileException: the log name is gone, so the channel can only be
            // writing into an inode nobody will ever read again.
            closeChannelQuietly();
            return false;
        }
        if (!attrs.isRegularFile()) {
            closeChannelQuietly();
            return false;
        }
        Object now = attrs.fileKey();
        if (now != null && openedFileKey != null && !now.equals(openedFileKey)) {
            closeChannelQuietly();
            return false;
        }
        if (PosixMode.notExactlyOwnerOnly(file)) {
            closeChannelQuietly();
            return false;
        }
        return true;
    }

    private static Object fileKeyOf(Path path) {
        try {
            return Files.readAttributes(path, java.nio.file.attribute.BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS).fileKey();
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /**
     * Removes a partial record at the end of the log, so the next append starts on a real boundary.
     *
     * <p>Two things produce a file that does not end in a newline: a process killed mid-write, and a
     * write whose bytes were only partly accepted. Both leave a fragment with no complete record in
     * it, and because the log is opened with {@code APPEND}, nothing in the normal write path would
     * ever notice - the next event is glued to the fragment and the two become one line. A reviewer
     * reading that line sees a mixture of two attempts: the timestamp of one, the account of another.
     * An audit trail that can silently merge records is worse than one with a visible hole in it.
     *
     * <p>The repair truncates to the byte after the last newline (to {@code 0} when the file holds no
     * newline at all) and verifies the resulting size. The discarded bytes are returned so the caller
     * can report the gap; every one of them belonged to a record that was already unreadable as a
     * whole line, so nothing complete is ever removed.
     *
     * @return bytes discarded, {@code 0} when the file already ends on a boundary, or {@code -1}
     *     when the file could not be examined or repaired
     */
    private static long discardTornTail(Path file) {
        try (FileChannel probe = FileChannel.open(file,
                EnumSet.of(StandardOpenOption.READ, StandardOpenOption.WRITE))) {
            long size = probe.size();
            if (size == 0L) {
                return 0L;
            }
            long boundary = offsetAfterLastNewline(probe, size);
            if (boundary == size) {
                return 0L;
            }
            probe.truncate(boundary);
            probe.force(false);
            if (probe.size() != boundary) {
                return -1L;
            }
            return size - boundary;
        } catch (IOException | RuntimeException e) {
            return -1L;
        }
    }

    /**
     * Scans backwards for the last newline, in bounded chunks, and returns the offset just past it
     * (or {@code 0} when the file contains none). Reads only as far back as it must: a log at its
     * size ceiling that ends correctly costs one 8 KiB read.
     */
    private static long offsetAfterLastNewline(FileChannel probe, long size) throws IOException {
        byte[] chunk = new byte[TAIL_SCAN_CHUNK];
        long end = size;
        while (end > 0L) {
            long start = Math.max(0L, end - chunk.length);
            int length = (int) (end - start);
            ByteBuffer buffer = ByteBuffer.wrap(chunk, 0, length);
            int guard = 0;
            while (buffer.hasRemaining()) {
                if (probe.read(buffer, start) < 0L && ++guard > 8) {
                    throw new IOException("the event log could not be read for the tail scan");
                }
            }
            for (int i = length - 1; i >= 0; i--) {
                if (chunk[i] == '\n') {
                    return start + i + 1L;
                }
            }
            end = start;
        }
        return 0L;
    }

    private void closeChannelQuietly() {
        openedFileKey = null;
        if (channel == null) {
            return;
        }
        try {
            channel.close();
        } catch (IOException | RuntimeException e) {
            // Nothing useful to do; the channel is abandoned and reopenIfPossible will retry.
        }
        channel = null;
    }

    private void checkFreeSpace(List<String> problems) {
        Path parent = file.getParent();
        if (parent == null) {
            return;
        }
        long usable;
        try {
            usable = Files.getFileStore(parent).getUsableSpace();
        } catch (IOException | RuntimeException e) {
            problems.add("free space on the event log file system could not be determined");
            return;
        }
        if (usable < minFreeBytes) {
            problems.add("the event log file system is below the configured free-space floor");
        }
    }

    private static FileAttribute<?>[] ownerOnlyAttributes() {
        try {
            return new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(PosixMode.OWNER_ONLY)};
        } catch (UnsupportedOperationException e) {
            return new FileAttribute<?>[0];
        }
    }
}
