package com.example.portal.auth;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongSupplier;

/**
 * An {@link AttemptLimiter} that keeps its counters in a file, so a restriction survives the process
 * that applied it.
 *
 * <p>This is what makes the limit real for a command-line front end. An in-memory tracker in a
 * program that exits after one attempt is no limit at all: the attacker simply runs the program
 * again and starts from zero. Here the counters are read, updated and written back while an
 * exclusive {@link FileLock} is held, so concurrent invocations -- separate processes, with no shared
 * memory between them -- cannot both pass a budget check on the same remaining slot.
 *
 * <p>The state file is created {@code rw-------} and its ownership and permissions are re-verified on
 * every open. That matters more here than it looks: a state file another local account could write
 * is a way to clear one's own restriction, or to forge a permanent one against someone else.
 *
 * <p>Every field read back is parsed and range-checked, and the file is bounded in both size and
 * record count. A line that does not parse is dropped, which costs the attacker nothing it did not
 * already have -- the worst case is a counter resetting to zero, which is the same position as a
 * first attempt -- while a malformed count that was trusted could disable the limit entirely.
 *
 * <p>A {@link FileLock} is held by the whole JVM rather than by a thread, so two threads in one
 * process locking the same file would raise {@link java.nio.channels.OverlappingFileLockException}
 * rather than queue. An in-process lock keyed by the state file's path therefore guards the file
 * lock: threads queue on the first, processes queue on the second.
 *
 * <p>If the file cannot be read or written, {@link Decision#UNAVAILABLE} is returned and the attempt
 * is refused. Failing closed is the only safe choice: the alternative is that deleting, corrupting
 * or locking the state file turns the rate limit off.
 *
 * <p>The lock is released before the password derivation runs, so the expensive work is never
 * serialised behind the bookkeeping.
 */
public final class FileAttemptLimiter implements AttemptLimiter {

    /** Largest state file this tracker will read, in bytes. */
    static final long MAX_FILE_BYTES = 16L * 1024 * 1024;
    /** Largest single record, in characters. */
    private static final int MAX_LINE_LENGTH = 160;

    private static final char ACCOUNT_SCOPE = 'A';
    private static final char SOURCE_SCOPE = 'S';

    /**
     * One in-process lock per state file, shared by every limiter instance pointed at that path.
     * Static because two {@code FileAttemptLimiter} objects over the same file are still one JVM as
     * far as {@link FileLock} is concerned.
     */
    private static final Map<Path, ReentrantLock> PROCESS_LOCKS = new ConcurrentHashMap<>();

    private final Path statePath;
    private final Limits limits;
    private final AuditLog audit;
    private final LongSupplier clockMillis;

    public FileAttemptLimiter(Path statePath, Limits limits, AuditLog audit) {
        this(statePath, limits, audit, System::currentTimeMillis);
    }

    /** Takes an injectable epoch-millisecond clock so the self-test can advance time. */
    public FileAttemptLimiter(Path statePath, Limits limits, AuditLog audit, LongSupplier clockMillis) {
        this.statePath = statePath.toAbsolutePath().normalize();
        this.limits = limits;
        this.audit = audit;
        this.clockMillis = clockMillis;
    }

    @Override
    public Reservation tryReserve(String account, String source) {
        ReentrantLock processLock = PROCESS_LOCKS.computeIfAbsent(statePath, key -> new ReentrantLock());
        processLock.lock();
        try (Transaction transaction = new Transaction()) {
            long now = clockMillis.getAsLong();
            // Source first: see InMemoryAttemptLimiter for why the order matters.
            AttemptCounters.Slot sourceSlot = AttemptCounters.consume(transaction.sources, source,
                    limits.maxSourceAttempts(), limits.sourceWindow().toMillis(),
                    limits.sourceRestriction().toMillis(), now, limits.maxTrackedKeys());
            if (sourceSlot != AttemptCounters.Slot.PERMITTED) {
                transaction.commit();
                return new Reservation(map(sourceSlot, Decision.SOURCE_RESTRICTED), account, source);
            }
            AttemptCounters.Slot accountSlot = AttemptCounters.consume(transaction.accounts, account,
                    limits.maxAccountAttempts(), limits.accountWindow().toMillis(),
                    limits.accountRestriction().toMillis(), now, limits.maxTrackedKeys());
            transaction.commit();
            if (accountSlot != AttemptCounters.Slot.PERMITTED) {
                return new Reservation(map(accountSlot, Decision.ACCOUNT_RESTRICTED), account, source);
            }
            return new Reservation(Decision.PERMITTED, account, source);
        } catch (IOException | ValidationException | RuntimeException e) {
            // Any failure to account for this attempt refuses it. Letting an unaccounted attempt
            // through would make "break the tracker" a way to switch the rate limit off.
            audit.warn("attempt tracker unavailable: " + e.getClass().getSimpleName() + ": " + e.getMessage(), "");
            return new Reservation(Decision.UNAVAILABLE, account, source);
        } finally {
            processLock.unlock();
        }
    }

    @Override
    public void recordSuccess(Reservation reservation) {
        if (!reservation.permitted()) {
            return;
        }
        ReentrantLock processLock = PROCESS_LOCKS.computeIfAbsent(statePath, key -> new ReentrantLock());
        processLock.lock();
        try (Transaction transaction = new Transaction()) {
            AttemptCounters.clear(transaction.accounts, reservation.account());
            AttemptCounters.giveBack(transaction.sources, reservation.source());
            transaction.commit();
        } catch (IOException | ValidationException | RuntimeException e) {
            // The authentication already succeeded, so this cannot be failed closed. Leaving the
            // counter as it stands is the safe direction: it only means the employee's own budget
            // stays drawn down until the window elapses.
            audit.warn("attempt tracker could not be updated after success: "
                    + e.getClass().getSimpleName() + ": " + e.getMessage(), "");
        } finally {
            processLock.unlock();
        }
    }

    @Override
    public void recordFailure(Reservation reservation) {
        // Already counted and persisted by tryReserve().
    }

    private static Decision map(AttemptCounters.Slot slot, Decision restricted) {
        return slot == AttemptCounters.Slot.CAPACITY_EXHAUSTED ? Decision.CAPACITY_EXHAUSTED : restricted;
    }

    /**
     * One read-modify-write cycle over the state file, held under an exclusive lock for its whole
     * lifetime. Closing without {@link #commit()} leaves the file untouched.
     */
    private final class Transaction implements AutoCloseable {

        private final FileChannel channel;
        private final FileLock lock;
        final Map<String, AttemptCounters.State> accounts = new HashMap<>();
        final Map<String, AttemptCounters.State> sources = new HashMap<>();

        Transaction() throws IOException, ValidationException {
            PrivateFiles.createPrivateIfAbsent(statePath);
            PrivateFiles.requireOwnerOnly(statePath, "attempt tracker state file");
            FileChannel opened = FileChannel.open(statePath, StandardOpenOption.READ, StandardOpenOption.WRITE);
            FileLock acquired = null;
            try {
                acquired = opened.lock();
                if (opened.size() > MAX_FILE_BYTES) {
                    throw new ValidationException("attempt tracker state file exceeds the maximum accepted size");
                }
                read(opened);
            } catch (IOException | ValidationException | RuntimeException e) {
                if (acquired != null) {
                    acquired.release();
                }
                opened.close();
                throw e;
            }
            this.channel = opened;
            this.lock = acquired;
        }

        private void read(FileChannel open) throws IOException {
            ByteBuffer buffer = ByteBuffer.allocate((int) open.size());
            open.position(0);
            while (buffer.hasRemaining() && open.read(buffer) >= 0) {
                // Read to end of file.
            }
            String contents = new String(buffer.array(), 0, buffer.position(), StandardCharsets.UTF_8);
            int dropped = 0;
            for (String line : contents.split("\n")) {
                if (line.isBlank()) {
                    continue;
                }
                if (line.length() > MAX_LINE_LENGTH || !parseInto(line.trim())) {
                    dropped++;
                }
            }
            if (dropped > 0) {
                audit.warn("attempt tracker records dropped as unparseable", "records=" + dropped);
            }
        }

        /** Returns false if the record is not well-formed, in which case it is dropped. */
        private boolean parseInto(String line) {
            String[] fields = line.split("\\|", -1);
            if (fields.length != 6 || fields[0].length() != 1) {
                return false;
            }
            Map<String, AttemptCounters.State> target = switch (fields[0].charAt(0)) {
                case ACCOUNT_SCOPE -> accounts;
                case SOURCE_SCOPE -> sources;
                default -> null;
            };
            if (target == null || target.size() >= limits.maxTrackedKeys()) {
                return false;
            }
            if (!"0".equals(fields[5]) && !"1".equals(fields[5])) {
                return false;
            }
            boolean restricted = "1".equals(fields[5]);
            try {
                String key = target == accounts
                        ? InputPolicy.requireValidUsername(fields[1])
                        : InputPolicy.requireValidSource(fields[1]);
                int attempts = Integer.parseInt(fields[2]);
                long windowStart = Long.parseLong(fields[3]);
                long restrictedUntil = Long.parseLong(fields[4]);
                if (attempts < 0 || attempts > 1_000_000 || windowStart < 0 || restrictedUntil < 0) {
                    return false;
                }
                target.put(key, new AttemptCounters.State(attempts, windowStart, restrictedUntil, restricted));
                return true;
            } catch (ValidationException | NumberFormatException e) {
                return false;
            }
        }

        /** Prunes elapsed counters and rewrites the file in place. */
        void commit() throws IOException {
            long now = clockMillis.getAsLong();
            AttemptCounters.prune(accounts, limits.accountWindow().toMillis(), now);
            AttemptCounters.prune(sources, limits.sourceWindow().toMillis(), now);

            StringBuilder out = new StringBuilder();
            append(out, ACCOUNT_SCOPE, accounts);
            append(out, SOURCE_SCOPE, sources);
            byte[] bytes = out.toString().getBytes(StandardCharsets.UTF_8);

            channel.truncate(0);
            channel.position(0);
            channel.write(ByteBuffer.wrap(bytes));
            // Durability matters for a security control: a restriction lost to a crash is a
            // restriction an attacker can provoke by crashing the host.
            channel.force(true);
        }

        private void append(StringBuilder out, char scope, Map<String, AttemptCounters.State> map) {
            for (Map.Entry<String, AttemptCounters.State> entry : map.entrySet()) {
                AttemptCounters.State state = entry.getValue();
                out.append(scope).append('|')
                        .append(entry.getKey()).append('|')
                        .append(state.attempts).append('|')
                        .append(state.windowStart).append('|')
                        .append(state.restrictedUntil).append('|')
                        .append(state.restricted ? '1' : '0').append('\n');
            }
        }

        @Override
        public void close() throws IOException {
            try {
                if (lock != null && lock.isValid()) {
                    lock.release();
                }
            } finally {
                channel.close();
            }
        }
    }
}
