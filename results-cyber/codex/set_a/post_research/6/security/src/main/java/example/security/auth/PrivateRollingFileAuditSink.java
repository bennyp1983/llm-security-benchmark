package example.security.auth;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.time.format.DateTimeFormatter;
import java.util.Objects;
import java.util.Set;

/** Owner-private, bounded, synchronous authentication event log with bounded rotation. */
public final class PrivateRollingFileAuditSink implements AuditSink {
    private static final String FILE_NAME = "authentication-events.log";
    private static final Set<PosixFilePermission> DIR_PERMS = Set.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE);
    private static final Set<PosixFilePermission> FILE_PERMS = Set.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
    private final Path directory;
    private final Path current;
    private final long maxBytes;
    private final int archives;

    public PrivateRollingFileAuditSink(Path privateDirectory, long maxBytes, int archives) throws IOException {
        Objects.requireNonNull(privateDirectory, "privateDirectory");
        directory = privateDirectory.toAbsolutePath().normalize();
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(directory)) {
            throw new IllegalArgumentException("Audit directory must be an existing real directory");
        }
        try {
            if (!Files.getPosixFilePermissions(directory, LinkOption.NOFOLLOW_LINKS).equals(DIR_PERMS)) {
                throw new IllegalArgumentException("Audit directory permissions must be 0700");
            }
        } catch (UnsupportedOperationException e) {
            throw new IllegalArgumentException("A POSIX file system is required for the private audit log", e);
        }
        if (maxBytes < 65_536 || maxBytes > 1_073_741_824L || archives < 1 || archives > 100) {
            throw new IllegalArgumentException("Invalid audit retention bounds");
        }
        this.maxBytes = maxBytes;
        this.archives = archives;
        this.current = directory.resolve(FILE_NAME);
        ensureFile();
    }

    @Override public synchronized void append(AuthenticationEvent event) throws IOException {
        Objects.requireNonNull(event, "event");
        byte[] record = format(event).getBytes(StandardCharsets.US_ASCII);
        if (record.length > 1024) throw new IllegalArgumentException("Oversized audit event");
        ensureFile();
        if (Files.size(current) + record.length > maxBytes) rotate();
        try (FileChannel channel = FileChannel.open(current, StandardOpenOption.WRITE,
                StandardOpenOption.APPEND, LinkOption.NOFOLLOW_LINKS)) {
            try (var ignored = channel.lock()) {
                ByteBuffer bytes = ByteBuffer.wrap(record);
                while (bytes.hasRemaining()) channel.write(bytes);
                channel.force(true);
            }
        }
    }

    private void ensureFile() throws IOException {
        if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
            if (!Files.isRegularFile(current, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(current)
                    || !Files.getPosixFilePermissions(current, LinkOption.NOFOLLOW_LINKS).equals(FILE_PERMS)) {
                throw new IOException("Unsafe audit log file");
            }
            return;
        }
        Files.createFile(current, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(FILE_PERMS));
    }

    private void rotate() throws IOException {
        for (int i = archives; i >= 1; i--) {
            Path from = i == 1 ? current : directory.resolve(FILE_NAME + "." + (i - 1));
            Path to = directory.resolve(FILE_NAME + "." + i);
            if (Files.exists(from, LinkOption.NOFOLLOW_LINKS)) {
                if (!Files.isRegularFile(from, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(from)
                        || !Files.getPosixFilePermissions(from, LinkOption.NOFOLLOW_LINKS).equals(FILE_PERMS)) {
                    throw new IOException("Unsafe audit archive");
                }
                Files.move(from, to, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            }
        }
        ensureFile();
    }

    private static String format(AuthenticationEvent e) {
        return "event_id=" + e.eventId() + " occurred_at=" + DateTimeFormatter.ISO_INSTANT.format(e.occurredAt())
                + " event=authentication outcome=" + e.outcome() + " reason=" + e.reason()
                + " subject=" + e.subjectKey() + " source=" + e.sourceKey()
                + " session=" + (e.sessionKey() == null ? "-" : e.sessionKey()) + "\n";
    }
}
