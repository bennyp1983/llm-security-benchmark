package com.example.auth;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

/**
 * File creation and permission hardening.
 *
 * <p>Measured on the reference platform: H2 creates its {@code .mv.db} (and, when tracing is on, its
 * {@code .trace.db}) with mode 0644 no matter what {@code ACCESS_MODE_DATA} says - that option
 * governs read/write access inside the engine, not the POSIX permission bits. Everything sensitive
 * therefore gets an explicit mode, and the containing directory is 0700 so the mode is not the only
 * line of defence.
 */
final class DbFiles {

    private DbFiles() {
    }

    /**
     * Creates a new file, owner-only, refusing to follow a symlink or clobber an existing file. The
     * requested mode is additionally masked by the process umask, so it is re-asserted and verified
     * rather than trusted.
     */
    static java.nio.channels.FileChannel newPrivateFile(Path file) throws IOException {
        FileAttribute<Set<PosixFilePermission>> attrs =
                PosixFilePermissions.asFileAttribute(PosixPermissions.OWNER_ONLY);
        java.nio.channels.FileChannel ch;
        try {
            ch = java.nio.channels.FileChannel.open(file,
                    Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE,
                            StandardOpenOption.READ), attrs);
        } catch (java.nio.file.FileAlreadyExistsException e) {
            throw new IOException("file_exists", e);
        }
        try {
            hardenToOwnerOnly(file);
        } catch (IOException | RuntimeException e) {
            try {
                ch.close();
            } catch (IOException ignored) {
                // Already unwinding a failed creation.
            }
            throw e;
        }
        return ch;
    }

    /**
     * Forces an existing file to mode 0600 and verifies it took. Verification is by mode, not by
     * attempting to read the file: the reference platform runs as root, and root bypasses permission
     * bits, so an accessibility probe would pass for an insecure file.
     */
    static void hardenToOwnerOnly(Path file) throws IOException {
        PosixFileAttributeView view = Files.getFileAttributeView(file,
                PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            throw new IOException("posix_permissions_unsupported");
        }
        view.setPermissions(PosixPermissions.OWNER_ONLY);
        DbPathGuard.requirePrivateRegularFile(file);
    }

    /** Creates a directory owner-only, or verifies an existing one already is. */
    static Path ensurePrivateDirectory(Path dir) throws IOException {
        if (Files.exists(dir, LinkOption.NOFOLLOW_LINKS)) {
            DbPathGuard.requirePrivateDirectory(dir);
            return dir;
        }
        Files.createDirectory(dir,
                PosixFilePermissions.asFileAttribute(PosixPermissions.OWNER_ONLY_DIR));
        PosixFileAttributeView view = Files.getFileAttributeView(dir,
                PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            throw new IOException("posix_permissions_unsupported");
        }
        // createDirectory's attribute is also umask-masked; set it explicitly and re-verify.
        view.setPermissions(PosixPermissions.OWNER_ONLY_DIR);
        DbPathGuard.requirePrivateDirectory(dir);
        return dir;
    }
}
