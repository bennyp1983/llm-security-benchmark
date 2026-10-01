package com.example.crypto;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.UserPrincipal;
import java.util.EnumSet;
import java.util.Set;

/**
 * Filesystem guard rails for files that hold key material.
 *
 * <p>A key file is only as good as its permissions, so before reading one this
 * component verifies that it is a real file owned by the current user, readable
 * by nobody else, not reached through a symlink, not larger than a sane bound,
 * and not sitting in a world-writable directory (where an attacker could swap
 * it for one of their own). Any failure is fatal: we never fall back to reading
 * it anyway.
 */
final class SecureFiles {

    /** Key/keystore files are small; this bounds how much we will ever read. */
    static final long MAX_KEY_FILE_BYTES = 256 * 1024L;

    private static final Set<PosixFilePermission> FORBIDDEN = EnumSet.of(
            PosixFilePermission.GROUP_READ,
            PosixFilePermission.GROUP_WRITE,
            PosixFilePermission.GROUP_EXECUTE,
            PosixFilePermission.OTHERS_READ,
            PosixFilePermission.OTHERS_WRITE,
            PosixFilePermission.OTHERS_EXECUTE);

    private SecureFiles() {
    }

    /**
     * Validates that {@code path} is safe to read secrets from and returns its
     * contents.
     *
     * @throws IllegalStateException if the file is missing, not a regular file,
     *                               a symlink, too large, or accessible to other users
     */
    static byte[] readPrivateFile(Path path) {
        Path file = path.toAbsolutePath().normalize();
        try {
            // NOFOLLOW_LINKS: a symlink here could redirect us to a file an
            // attacker controls, or be swapped between check and read.
            if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
                throw new IllegalStateException("key file is not a regular file: " + file);
            }
            long size = Files.size(file);
            if (size == 0 || size > MAX_KEY_FILE_BYTES) {
                throw new IllegalStateException("key file size is out of range: " + file);
            }
            requireOwnerOnlyAccess(file);
            requireSafeParent(file.getParent());
            return Files.readAllBytes(file);
        } catch (IOException e) {
            CryptoLog.configProblem("unable to read key file: " + file);
            throw new UncheckedIOException("unable to read key file", e);
        }
    }

    /**
     * Fails unless the file's POSIX mode grants nothing to group or other and
     * the file is owned by the current user. On filesystems without POSIX
     * attributes (where the check cannot be performed) we also fail closed
     * rather than assuming the file is private.
     */
    private static void requireOwnerOnlyAccess(Path file) throws IOException {
        PosixFileAttributeView view =
                Files.getFileAttributeView(file, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            throw new IllegalStateException(
                    "cannot verify permissions of key file (no POSIX attributes): " + file);
        }
        PosixFileAttributes attrs = view.readAttributes();
        for (PosixFilePermission permission : attrs.permissions()) {
            if (FORBIDDEN.contains(permission)) {
                CryptoLog.configProblem("key file is accessible to other users: " + file);
                throw new IllegalStateException(
                        "key file must be readable only by its owner (chmod 600): " + file);
            }
        }
        UserPrincipal me = file.getFileSystem()
                .getUserPrincipalLookupService()
                .lookupPrincipalByName(System.getProperty("user.name", ""));
        if (!attrs.owner().equals(me)) {
            CryptoLog.configProblem("key file is not owned by the current user: " + file);
            throw new IllegalStateException("key file must be owned by the current user: " + file);
        }
    }

    /** A world-writable parent directory lets an attacker replace the key file. */
    private static void requireSafeParent(Path parent) throws IOException {
        if (parent == null) {
            return;
        }
        PosixFileAttributeView view = Files.getFileAttributeView(parent, PosixFileAttributeView.class);
        if (view == null) {
            return; // non-POSIX filesystem; the file check above already failed closed
        }
        Set<PosixFilePermission> permissions = view.readAttributes().permissions();
        if (permissions.contains(PosixFilePermission.OTHERS_WRITE)) {
            CryptoLog.configProblem("key file directory is world-writable: " + parent);
            throw new IllegalStateException("key file directory must not be world-writable: " + parent);
        }
    }
}
