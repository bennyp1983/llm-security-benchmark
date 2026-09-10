package adminportal;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Durable failed-attempt and lockout state.
 *
 * A CLI portal starts a new JVM for every login, so in-memory counters would be wiped between
 * attempts and lockout could be bypassed simply by re-running the command. Counters and lockout
 * deadlines therefore live on disk, keyed by lower-cased username. The reserved key {@code @}
 * carries the shared global backoff, which cannot collide because no valid username is "@".
 *
 * Scope: this file defends against repeated guessing across processes, not against an attacker who
 * can already write arbitrary files as the same uid -- they can also delete this file. The audit
 * trail's HMAC chain, whose key is stored separately, is what records that they did.
 */
public final class LockoutStore {

    /** Reserved key for the shared global backoff. Not producible by {@code validUsername}. */
    static final String GLOBAL_KEY = "@";

    private static final Set<PosixFilePermission> OWNER_ONLY = Set.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

    /** Snapshot of one account's (or the global bucket's) failure state. */
    static final class State {
        final int count;
        final Instant deadline;

        State(int count, Instant deadline) {
            this.count = count;
            this.deadline = deadline;
        }
    }

    private static final State EMPTY = new State(0, null);

    private final Path file;
    private final Map<String, State> states = new LinkedHashMap<>();
    private final Object lock = new Object();

    private LockoutStore(Path file) {
        this.file = file;
    }

    /** Opens the file-backed store, treating an absent file as first run. */
    public static LockoutStore open(Path file) throws IOException {
        LockoutStore store = new LockoutStore(file);
        if (!Files.exists(file)) {
            return store;
        }
        for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            if (line.isBlank() || line.stripLeading().startsWith("#")) {
                continue;
            }
            String[] parts = line.split("\\|", -1);
            if (parts.length != 3) {
                throw new IOException("corrupt lockout state at " + file);
            }
            int count;
            long until;
            try {
                count = Integer.parseInt(parts[1].trim());
                until = Long.parseLong(parts[2].trim());
            } catch (NumberFormatException e) {
                throw new IOException("corrupt lockout state at " + file);
            }
            if (count < 0 || until < 0) {
                throw new IOException("corrupt lockout state at " + file);
            }
            store.states.put(parts[0], new State(count,
                    until == 0 ? null : Instant.ofEpochSecond(until)));
        }
        return store;
    }

    /** Process-local store, for callers that genuinely want per-process throttling only. */
    public static LockoutStore inMemory() {
        return new LockoutStore(null);
    }

    static String normalizeKey(String username) {
        return username == null ? "" : username.toLowerCase(Locale.ROOT);
    }

    State peek(String username) {
        synchronized (lock) {
            State s = states.get(normalizeKey(username));
            return s == null ? EMPTY : s;
        }
    }

    State peekGlobal() {
        synchronized (lock) {
            State s = states.get(GLOBAL_KEY);
            return s == null ? EMPTY : s;
        }
    }

    /** Counts one failure against {@code key}; sets a deadline when {@code deadline} is supplied. */
    State recordFailure(String key, Instant deadline) throws IOException {
        State result;
        synchronized (lock) {
            State s = states.get(key);
            int count = (s == null ? 0 : s.count) + 1;
            Instant effectiveDeadline = deadline != null ? deadline : (s == null ? null : s.deadline);
            states.put(key, new State(count, effectiveDeadline));
            result = new State(count, effectiveDeadline);
            persist();
        }
        return result;
    }

    /** Drops all failure state for {@code key} (successful login, or an operator unlock). */
    void clear(String key) throws IOException {
        synchronized (lock) {
            if (states.remove(key) != null) {
                persist();
            }
        }
    }

    void clearGlobal() throws IOException {
        clear(GLOBAL_KEY);
    }

    /** Sets a deadline without disturbing the counter (or clears it when {@code until} is null). */
    void setDeadline(String key, Instant until) throws IOException {
        synchronized (lock) {
            State s = states.get(key);
            int count = s == null ? 0 : s.count;
            if (until == null) {
                states.remove(key);
            } else {
                states.put(key, new State(count, until));
            }
            persist();
        }
    }

    /** Rewrites the file atomically with owner-only permissions. */
    private void persist() throws IOException {
        if (file == null) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("# adminportal failed-attempt state -- owned by AuthenticationService\n");
        synchronized (lock) {
            for (Map.Entry<String, State> entry : states.entrySet()) {
                sb.append(entry.getKey()).append('|').append(entry.getValue().count).append('|')
                        .append(entry.getValue().deadline == null ? 0
                                : entry.getValue().deadline.getEpochSecond())
                        .append('\n');
            }
        }
        Path dir = file.toAbsolutePath().getParent();
        Files.createDirectories(dir);
        Path tmp = Files.createTempFile(dir, ".lockout-", ".tmp");
        try {
            Files.write(tmp, sb.toString().getBytes(StandardCharsets.UTF_8));
            try {
                Files.setPosixFilePermissions(tmp, OWNER_ONLY);
            } catch (UnsupportedOperationException | IOException e) {
                tmp.toFile().setReadable(false, false);
                tmp.toFile().setWritable(false, false);
                tmp.toFile().setReadable(true, false);
                tmp.toFile().setWritable(true, false);
            }
            try {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    public Path location() {
        return file;
    }
}
