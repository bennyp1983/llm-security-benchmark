package empportal.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;

/**
 * Carries a {@link LockoutTracker}'s failure windows across processes.
 *
 * <p>A one-shot sign-in command cannot throttle anything with an in-heap counter: every attempt is
 * a fresh JVM, so the count restarts at zero and the threshold is unreachable. The counter has to
 * live next to the records the same way the records live on disk.
 *
 * <p>A corrupt state file is treated as empty rather than fatal, because this file throttles
 * attempts and does not authorise them: failing to read it must not either lock everyone out or
 * abort sign-in.
 */
public final class LockoutStateFile {

    public static final String SUFFIX = ".lockout";

    private static final String HEADER = "# employee portal failed-attempt windows: identity=epochMs[,...]";

    private final Path file;

    public LockoutStateFile(Path recordsFile) {
        this.file = recordsFile.toAbsolutePath().normalize().resolveSibling(
                recordsFile.getFileName().toString() + SUFFIX);
    }

    public Path path() {
        return file;
    }

    /** Loads any persisted windows into {@code tracker}, ignoring a missing or unreadable file. */
    public void loadInto(LockoutTracker tracker) {
        if (!Files.exists(file)) {
            return;
        }
        try {
            tracker.importState(Files.readAllLines(file, StandardCharsets.UTF_8));
        } catch (IOException | RuntimeException unreadable) {
            // Fail open on the counter only: the credential check above is what grants access.
        }
    }

    /** Rewrites the persisted windows atomically. */
    public void saveFrom(LockoutTracker tracker) {
        List<String> lines = tracker.exportState();
        lines.add(0, HEADER);
        Path temp = null;
        try {
            Path parent = file.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            temp = Files.createTempFile(parent, file.getFileName().toString() + ".", ".tmp");
            Files.write(temp, lines, StandardCharsets.UTF_8);
            try {
                Files.setPosixFilePermissions(temp, PosixFilePermissions.fromString("rw-------"));
            } catch (UnsupportedOperationException notPosix) {
                // Non-POSIX filesystem: rely on the surrounding directory's ACL.
            }
            try {
                Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException noAtomic) {
                Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
            }
            temp = null;
        } catch (IOException failed) {
            // Losing the counter must not lose the sign-in; the next attempt starts unthrottled.
        } finally {
            if (temp != null) {
                try {
                    Files.deleteIfExists(temp);
                } catch (IOException ignored) {
                    // Best effort.
                }
            }
        }
    }
}
