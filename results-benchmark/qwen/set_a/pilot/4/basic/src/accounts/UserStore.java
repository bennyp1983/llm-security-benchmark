package accounts;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Reads and writes the credential file. The file is line-oriented, UTF-8, and replaced
 * in one atomic move rather than appended to, so a crash mid-write cannot leave a
 * half-written store behind.
 *
 * <p>Malformed lines are skipped instead of aborting the load: one corrupt record must
 * not lock every healthy account out of the system. The count is reported through
 * {@link #lastRejectedLines()} so the caller can surface it.
 */
final class UserStore {

    private final Path file;
    private int lastRejectedLines;

    private UserStore(Path file) {
        this.file = file.toAbsolutePath().normalize();
    }

    static UserStore atPath(Path file) {
        if (file == null) {
            throw new IllegalArgumentException("store file path is required");
        }
        return new UserStore(file);
    }

    Path file() {
        return file;
    }

    int lastRejectedLines() {
        return lastRejectedLines;
    }

    /**
     * @return stored credentials in file order; an empty map when the file does not
     *         exist yet, which is the normal state before the first registration
     */
    synchronized Map<String, CredentialRecord> load() throws IOException {
        Map<String, CredentialRecord> records = new LinkedHashMap<>();
        lastRejectedLines = 0;
        if (!Files.isRegularFile(file)) {
            return records;
        }
        List<String> lines;
        try {
            lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IOException("credential store " + file + " could not be read as UTF-8 text: "
                    + e.getMessage(), e);
        }
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            try {
                CredentialRecord record = CredentialRecord.decode(line);
                if (records.containsKey(record.username())) {
                    lastRejectedLines++;
                    continue;
                }
                records.put(record.username(), record);
            } catch (IllegalArgumentException e) {
                lastRejectedLines++;
            }
        }
        return records;
    }

    /** Rewrites the whole file from {@code records}, creating the parent directory if needed. */
    synchronized void replaceAll(Collection<CredentialRecord> records) throws IOException {
        if (isBlocked()) {
            throw new IOException("credential path " + file + " exists but is not a regular file");
        }
        StringBuilder text = new StringBuilder();
        for (CredentialRecord record : records) {
            text.append(record.encode()).append('\n');
        }
        byte[] bytes = text.toString().getBytes(StandardCharsets.UTF_8);

        Path parent = file.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        Path temp = (parent != null ? parent : file.toAbsolutePath().getParent())
                .resolve("accounts-" + System.nanoTime() + ".tmp");
        try {
            Set<PosixFilePermission> ownerOnly = Set.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            try {
                Files.createFile(temp, PosixFilePermissions.asFileAttribute(ownerOnly));
            } catch (UnsupportedOperationException notPosix) {
                Files.createFile(temp);
            }
            try (FileChannel channel = FileChannel.open(temp,
                    StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                while (buffer.hasRemaining()) {
                    channel.write(buffer);
                }
                channel.force(true);
            }
            try {
                Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException | UnsupportedOperationException coarseGrainedFs) {
                // Some filesystems refuse atomic replace outright; a plain move is still
                // correct, just briefly non-atomic. Report failure as an IO problem so
                // callers only ever have to handle IOException.
                try {
                    Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
                } catch (AtomicMoveNotSupportedException | UnsupportedOperationException stillStuck) {
                    throw new IOException("credential store " + file + " could not be replaced: "
                            + stillStuck.getMessage(), stillStuck);
                }
            }
            tightenPermissions();
        } catch (IOException | RuntimeException e) {
            deleteQuietly(temp);
            throw e;
        }
    }

    /** Best effort: hashed credentials are only as private as the file that holds them. */
    private void tightenPermissions() {
        Set<PosixFilePermission> ownerOnly = Set.of(
                PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
        try {
            Files.setPosixFilePermissions(file, ownerOnly);
        } catch (UnsupportedOperationException | IOException notPosix) {
            // No POSIX ACL support (or the file sits on a filesystem that ignores it).
            // Nothing further to do here; the caller still owns the failure to protect it.
        }
    }

    private static void deleteQuietly(Path temp) {
        try {
            Files.deleteIfExists(temp);
        } catch (IOException stillThere) {
            // A leftover temp file is untidy but harmless; the store itself is intact.
        }
    }

    /** True when the store exists but is not a plain readable file, e.g. a directory in its place. */
    boolean isBlocked() {
        return Files.exists(file, LinkOption.NOFOLLOW_LINKS) && !Files.isRegularFile(file);
    }
}
