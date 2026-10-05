package com.portal.auth;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * On-disk window counters for {@link ThrottleManager}, so a restart does not reset a
 * throttle state that an attacker is trying to defeat.
 *
 * <p>Format: one line per subject,
 * {@code v2|kind:subject|windowStart|count|blockedUntil|generation}. {@code subject} is a
 * SHA-256 reference, never a username or a raw address: a copied or backed-up ledger must
 * not disclose which account is being hammered.
 *
 * <h2>Why merging needs the generation field</h2>
 * Every mutation takes an exclusive {@link FileLock} on a dedicated lock file (which,
 * unlike the data file, is never replaced) and <em>merges</em> with whatever another
 * process persisted, so a racing sibling can never lower our view of the danger -- the
 * merge fails closed. Merging by {@code max(count)} alone, however, is not merely a
 * fail-closed rule: it makes the count <b>monotonic</b>, and the throttle legitimately
 * <em>reduces</em> a count in three places (a correct password, a window rolling over, a
 * failure that arms a back-off and restarts the window). Measured before the generation
 * field existed, six consecutive <em>correct</em> logins of one account denied the sixth:
 * {@link ThrottleManager#recordSuccess} zeroed the counter, persisted {@code count=0}, and
 * the merge immediately restored the {@code count=5} that the previous process had left
 * behind, because 5 &gt; 0 and the merge could not tell a stale window from a live one.
 * Time cannot make that distinction -- a success two seconds after the last failure opens a
 * window that is genuinely new, not a wider interval -- so each subject carries a
 * generation that is bumped exactly when its window is deliberately replaced.
 *
 * <p>Merge rule: entries of the <b>same</b> generation take the maximum count and the
 * maximum blocked-until (the anti-downgrade property a racing sibling must not defeat);
 * entries of <b>different</b> generations take the count of the higher generation, because
 * that writer is describing a window the other has never seen. {@code blockedUntil} is
 * always the maximum: a back-off is never downgraded by a sibling that happens not to know
 * about it.
 *
 * <p>Residual risk, stated plainly: a writer who can already edit this file can invent a
 * high generation and zero a count. That is not a new escape -- the same writer can delete
 * the file outright, which {@link #load} treats as a clean slate -- so the protection here
 * is the file's owner-only mode and directory, not the merge rule. The merge rule's job is
 * only to stop <em>honest</em> concurrent processes from downgrading each other.
 */
public final class Ledger {

    static final int SUBJECT_HEX = 16;
    private static final String VERSION = "v2";
    private static final int MAX_LINES = 50_000;
    private static final long MAX_EPOCH = 4_102_444_800L; // 2100-01-01
    private static final int MAX_COUNT = 1_000_000;
    private static final long MAX_GENERATION = 1_000_000_000_000_000L;
    private static final long MAX_BYTES = 4L * 1024 * 1024;

    public static final class Counter {
        public long windowStart;
        public int count;
        public long blockedUntil;
        /** Which window {@code count} describes; bumped only when the window is replaced. */
        public long generation;

        Counter(long windowStart, int count, long blockedUntil) {
            this(windowStart, count, blockedUntil, 0L);
        }

        Counter(long windowStart, int count, long blockedUntil, long generation) {
            this.windowStart = windowStart;
            this.count = count;
            this.blockedUntil = blockedUntil;
            this.generation = generation;
        }

        Counter copy() {
            return new Counter(windowStart, count, blockedUntil, generation);
        }
    }

    private final Path file;
    private final Path lockFile;

    public Ledger(Path file) {
        this.file = file;
        this.lockFile = file.resolveSibling(file.getFileName() + ".lock");
    }

    /** Reads the ledger, discarding entries whose block has expired and window rolled over. */
    public synchronized Map<String, Counter> load(long nowEpochSecond, long retentionSeconds) {
        List<String> lines = readLines();
        Map<String, Counter> out = new HashMap<>();
        for (String raw : lines) {
            Counter parsed = parse(raw);
            if (parsed == null) {
                // An unparseable line means somebody edited or truncated the ledger. We
                // refuse to honour a partially parsed security state. The caller starts
                // from a clean slate (which is still fully enforced) and records the
                // anomaly, rather than trusting a file whose integrity is unknown.
                throw new IllegalStateException("ledger-corrupt");
            }
            String key = keyOf(raw);
            boolean stillBlocked = parsed.blockedUntil > nowEpochSecond;
            boolean inWindow = nowEpochSecond - parsed.windowStart <= retentionSeconds
                    && parsed.windowStart <= nowEpochSecond;
            if (stillBlocked || inWindow) {
                out.merge(key, parsed, Ledger::max);
            }
        }
        return out;
    }

    /** Persist, merging with a concurrent writer's view under an exclusive file lock. */
    public synchronized void persist(Map<String, Counter> state) {
        for (Map.Entry<String, Counter> e : state.entrySet()) {
            if (!validKey(e.getKey())) {
                throw new IllegalStateException("ledger-key");
            }
            Counter c = e.getValue();
            if (c.count < 0 || c.count > MAX_COUNT || c.windowStart < 0 || c.windowStart > MAX_EPOCH
                    || c.blockedUntil < 0 || c.blockedUntil > MAX_EPOCH) {
                throw new IllegalStateException("ledger-value");
            }
        }
        FileChannel lockChannel = null;
        try {
            lockChannel = FileChannel.open(lockFile,
                    java.util.EnumSet.of(StandardOpenOption.CREATE, StandardOpenOption.READ,
                            StandardOpenOption.WRITE),
                    PosixFilePermissions.asFileAttribute(PrivateFiles.FILE_MODE));
            FileLock lock = acquire(lockChannel);
            try {
                Map<String, Counter> merged = new HashMap<>();
                for (Map.Entry<String, Counter> e : state.entrySet()) {
                    merged.put(e.getKey(), e.getValue().copy());
                }
                for (Map.Entry<String, Counter> e : readForMerge().entrySet()) {
                    merged.merge(e.getKey(), e.getValue(), Ledger::max);
                }
                PrivateFiles.writePrivateAtomic(file, render(merged));
            } finally {
                try {
                    lock.release();
                } catch (IOException ignored) {
                    // Closing the channel releases it.
                }
            }
        } catch (IOException failure) {
            throw new IllegalStateException("ledger-io", failure);
        } finally {
            if (lockChannel != null) {
                try {
                    lockChannel.close();
                } catch (IOException ignored) {
                    // Nothing further to do.
                }
            }
        }
    }

    private FileLock acquire(FileChannel channel) throws IOException {
        for (int attempt = 0; attempt < 200; attempt++) {
            try {
                FileLock lock = channel.tryLock(0L, Long.MAX_VALUE, false);
                if (lock != null) {
                    return lock;
                }
            } catch (OverlappingFileLockException heldByThisJvm) {
                // Another thread of this JVM holds it; it is also the one writing, and
                // Ledger methods are synchronized, so this is a momentary race only.
            } catch (java.nio.channels.ClosedByInterruptException gone) {
                throw gone;
            } catch (IOException contended) {
                // Fall through to the next attempt.
            }
            try {
                Thread.sleep(25L);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IOException("ledger-interrupted", interrupted);
            }
        }
        throw new IOException("ledger-lock-contended");
    }

    private List<String> readLines() {
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
            return List.of();
        }
        String body = PrivateFiles.readPrivateBounded(file, MAX_BYTES);
        List<String> out = new ArrayList<>();
        for (String raw : body.split("\n")) {
            if (raw.isEmpty()) {
                continue;
            }
            if (out.size() >= MAX_LINES) {
                throw new IllegalStateException("ledger-too-large");
            }
            out.add(raw);
        }
        return out;
    }

    private Map<String, Counter> readForMerge() {
        Map<String, Counter> out = new HashMap<>();
        List<String> lines;
        try {
            lines = readLines();
        } catch (RuntimeException unreadable) {
            return out;
        }
        for (String raw : lines) {
            Counter c = parse(raw);
            if (c != null) {
                out.merge(keyOf(raw), c, Ledger::max);
            }
        }
        return out;
    }

    private static Counter max(Counter a, Counter b) {
        if (a == null) {
            return b.copy();
        }
        if (b == null) {
            return a.copy();
        }
        long blocked = Math.max(a.blockedUntil, b.blockedUntil);
        if (a.generation == b.generation) {
            // Same window: neither writer may lower the other's view of it.
            long windowStart = Math.max(a.windowStart, b.windowStart);
            return new Counter(windowStart, Math.max(a.count, b.count), blocked, a.generation);
        }
        // Different windows: the higher generation is the one that replaced the other, so
        // its count is the current one and the other's is history. Taking the max here is
        // what made a cleared counter un-clearable -- see the class note.
        Counter current = a.generation > b.generation ? a : b;
        return new Counter(current.windowStart, current.count, blocked, current.generation);
    }

    private static byte[] render(Map<String, Counter> state) {
        List<String> lines = new ArrayList<>(state.size());
        for (Map.Entry<String, Counter> e : state.entrySet()) {
            Counter c = e.getValue();
            lines.add(VERSION + "|" + e.getKey() + "|" + c.windowStart + "|" + c.count + "|"
                    + c.blockedUntil + "|" + c.generation);
        }
        Collections.sort(lines);
        return String.join("\n", lines).getBytes(StandardCharsets.UTF_8);
    }

    private static Counter parse(String raw) {
        if (raw.length() > 220) {
            return null;
        }
        String[] parts = raw.split("\\|", -1);
        boolean v2 = VERSION.equals(parts[0]) && parts.length == 6;
        // A v1 line carries no generation. Reading it as generation 0 rather than rejecting
        // it keeps an upgraded deployment's live back-offs intact; the count it carries was
        // written under the old monotonic merge, so it can only be an over-estimate, which
        // is the strict direction.
        boolean v1 = "v1".equals(parts[0]) && parts.length == 5;
        if (!v2 && !v1) {
            return null;
        }
        String key = parts[1];
        if (!validKey(key)) {
            return null;
        }
        try {
            long windowStart = Long.parseLong(parts[2]);
            int count = Integer.parseInt(parts[3]);
            long blockedUntil = Long.parseLong(parts[4]);
            long generation = v2 ? Long.parseLong(parts[5]) : 0L;
            if (windowStart < 0 || windowStart > MAX_EPOCH
                    || blockedUntil < 0 || blockedUntil > MAX_EPOCH
                    || count < 0 || count > MAX_COUNT
                    || generation < 0 || generation > MAX_GENERATION) {
                return null;
            }
            return new Counter(windowStart, count, blockedUntil, generation);
        } catch (NumberFormatException garbage) {
            return null;
        }
    }

    private static boolean validKey(String key) {
        if (key == null || key.length() != SUBJECT_HEX + 2) {
            return false;
        }
        char kind = key.charAt(0);
        if (kind != 'a' && kind != 's') {
            return false;
        }
        if (key.charAt(1) != ':') {
            return false;
        }
        for (int i = 2; i < key.length(); i++) {
            char c = key.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return true;
    }

    private static String keyOf(String rawLine) {
        return rawLine.split("\\|", -1)[1];
    }

    static String key(char kind, String subjectHex) {
        if (subjectHex == null || subjectHex.length() != SUBJECT_HEX) {
            throw new IllegalArgumentException("ledger-subject");
        }
        return kind + ":" + subjectHex;
    }

    /** Test/inspection helper. */
    public synchronized boolean exists() {
        return Files.exists(file, LinkOption.NOFOLLOW_LINKS);
    }
}
