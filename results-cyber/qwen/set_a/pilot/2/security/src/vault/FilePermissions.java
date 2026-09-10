package vault;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

/**
 * Tightens permissions on files that hold key material or sealed data.
 *
 * <p>A key that any local user can read is not a secret, so a freshly created keystore is
 * chmod'ed to {@code 0600} before any key is written into it. On non-POSIX filesystems the
 * calls are skipped with a warning path left to the caller, since access control there is
 * handled by ACLs the JDK cannot portably set.
 */
final class FilePermissions {

    private static final Set<PosixFilePermission> OWNER_ONLY =
            Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
    private static final Set<PosixFilePermission> OWNER_ONLY_DIR =
            Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE);

    private FilePermissions() {
    }

    /**
     * Creates (or replaces) {@code path} with owner-only permissions applied at creation time.
     * Setting permissions after a plain create would leave a window where the file is readable
     * by everyone, which matters for recovered plaintext.
     */
    static java.io.OutputStream newOwnerOnlyOutputStream(Path path) throws java.io.IOException {
        java.util.EnumSet<java.nio.file.StandardOpenOption> options =
                java.util.EnumSet.of(java.nio.file.StandardOpenOption.WRITE,
                        java.nio.file.StandardOpenOption.CREATE,
                        java.nio.file.StandardOpenOption.TRUNCATE_EXISTING);
        if (isPosix(path.toAbsolutePath().getParent())) {
            return java.nio.channels.Channels.newOutputStream(Files.newByteChannel(path, options,
                    java.nio.file.attribute.PosixFilePermissions.asFileAttribute(OWNER_ONLY)));
        }
        return java.nio.channels.Channels.newOutputStream(Files.newByteChannel(path, options));
    }

    static boolean isPosix(Path path) {
        return Files.getFileAttributeView(path, java.nio.file.attribute.PosixFileAttributeView.class,
                LinkOption.NOFOLLOW_LINKS) != null;
    }

    static void restrictToOwner(Path path) {
        apply(path, OWNER_ONLY);
    }

    static void restrictDirectoryToOwner(Path path) {
        apply(path, OWNER_ONLY_DIR);
    }

    /** True when the file is readable by group or other, i.e. exposed beyond its owner. */
    static boolean worldOrGroupReadable(Path path) {
        try {
            Set<PosixFilePermission> current = Files.getPosixFilePermissions(path);
            return current.contains(PosixFilePermission.GROUP_READ)
                    || current.contains(PosixFilePermission.OTHERS_READ)
                    || current.contains(PosixFilePermission.GROUP_WRITE)
                    || current.contains(PosixFilePermission.OTHERS_WRITE);
        } catch (UnsupportedOperationException | IOException e) {
            return false;
        }
    }

    private static void apply(Path path, Set<PosixFilePermission> permissions) {
        try {
            Files.setPosixFilePermissions(path, permissions);
        } catch (UnsupportedOperationException | IOException e) {
            // Filesystem has no POSIX permissions; nothing enforceable here.
        }
    }
}
