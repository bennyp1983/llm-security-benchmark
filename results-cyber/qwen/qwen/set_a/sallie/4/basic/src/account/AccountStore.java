package account;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * File-backed account registry. One account per line.
 *
 * <p>An adding account is written as a short read-modify-write critical section: the
 * file is re-read under an exclusive lock, merged with any account another process
 * added in the meantime, and rewritten atomically. The lock is therefore held for
 * milliseconds only and never spans a password prompt, so two people registering at
 * the same time cannot lose each other's accounts.</p>
 */
final class AccountStore implements AutoCloseable {

    private static final String HEADER = "# account-store v1";

    private final Path storeFile;
    private final Path lockFile;
    private final FileChannel lockChannel;
    private final Map<String, User> users = new LinkedHashMap<>();

    AccountStore(Path storeFile) {
        this.storeFile = storeFile.toAbsolutePath().normalize();
        this.lockFile = this.storeFile.resolveSibling(this.storeFile.getFileName() + ".lock");
        try {
            Path parent = this.storeFile.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            // READ is required as well as WRITE: a shared lock is only granted on a
            // readable channel, and the load path takes a shared one.
            this.lockChannel = FileChannel.open(this.lockFile,
                    StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE);
        } catch (IOException e) {
            throw new IllegalStateException("cannot open account store: " + e.getMessage(), e);
        }
    }

    Path storeFile() {
        return storeFile;
    }

    /** Takes a shared lock just long enough to read a consistent snapshot. */
    void load() {
        FileLock shared = null;
        try {
            shared = lockChannel.lock(0L, Long.MAX_VALUE, true);
            users.clear();
            users.putAll(readCurrent());
        } catch (IOException e) {
            throw new IllegalStateException("cannot read account store: " + e.getMessage(), e);
        } finally {
            release(shared);
        }
    }

    boolean contains(String username) {
        return users.containsKey(username);
    }

    int size() {
        return users.size();
    }

    Optional<User> find(String username) {
        return Optional.ofNullable(users.get(username));
    }

    /**
     * Registers one account, returning false if the name is already taken - including
     * when it was taken by another process after this store was loaded.
     */
    boolean add(User user) {
        FileLock exclusive = null;
        try {
            exclusive = lockChannel.lock();
            Map<String, User> current = readCurrent();
            User existing = current.get(user.username());
            if (existing != null) {
                users.clear();
                users.putAll(current);
                return false;
            }
            // Keep whatever other processes added while we were working, then add ours.
            users.clear();
            users.putAll(current);
            users.put(user.username(), user);
            writeCurrent();
            return true;
        } catch (IOException e) {
            throw new IllegalStateException("cannot write account store: " + e.getMessage(), e);
        } finally {
            release(exclusive);
        }
    }

    private static void release(FileLock lock) {
        if (lock == null) {
            return;
        }
        try {
            if (lock.isValid()) {
                lock.release();
            }
        } catch (IOException ignored) {
            // A lock the JVM already dropped needs no further action.
        }
    }

    /** Parses the store file from disk. Blank and {@code #} lines are skipped. */
    private Map<String, User> readCurrent() throws IOException {
        Map<String, User> parsed = new LinkedHashMap<>();
        if (!Files.isRegularFile(storeFile)) {
            return parsed;
        }
        int lineNumber = 0;
        for (String line : Files.readAllLines(storeFile, StandardCharsets.UTF_8)) {
            lineNumber++;
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            User user = User.fromLine(line, lineNumber);
            if (parsed.putIfAbsent(user.username(), user) != null) {
                throw new IllegalStateException(
                        "corrupt account store: duplicate account on line " + lineNumber);
            }
        }
        return parsed;
    }

    /** Writes the in-memory map out atomically. Caller must hold the exclusive lock. */
    private void writeCurrent() throws IOException {
        StringBuilder body = new StringBuilder(HEADER).append('\n');
        for (User user : users.values()) {
            body.append(user.toLine()).append('\n');
        }
        byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8);
        Path temp = null;
        try {
            temp = Files.createTempFile(storeFile.getParent(), storeFile.getFileName() + ".", ".tmp");
            Files.write(temp, bytes, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
            try {
                Files.move(temp, storeFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                temp = null;
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, storeFile, StandardCopyOption.REPLACE_EXISTING);
                temp = null;
            }
        } finally {
            if (temp != null) {
                try {
                    Files.deleteIfExists(temp);
                } catch (IOException ignored) {
                    // Best effort only; the store file itself is already consistent.
                }
            }
        }
    }

    @Override
    public void close() {
        try {
            lockChannel.close();
        } catch (IOException ignored) {
            // Nothing useful to do while shutting down.
        }
    }

    static User newUser(String username, String passwordEncoding) {
        return new User(username, passwordEncoding, Instant.now());
    }
}
