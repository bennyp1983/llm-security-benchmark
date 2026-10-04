package com.example.auth;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

/**
 * The one place that asks what a file's mode is, so that every file holding credentials or audit
 * evidence is asked the same question and gets the same answer when it cannot be asked.
 *
 * <p><b>Every check here fails closed.</b> When a mode cannot be read - a file system with no POSIX
 * permission bits (CIFS, SMB, vfat, some FUSE and container overlay mounts), an entry that vanished
 * between the stat and the read, or an ACL-backed store that refuses the read - the answer is
 * "exposed", never "safe". Rule 2 promises that no credential or audit file is reachable by another
 * user, and a mode nobody can read is a mode nobody can prove is owner-only: reporting success would
 * turn an unreadable file system into the one configuration where the promise is silently dropped,
 * which is worse than refusing to start, because it looks like it passed. A deployment that lands on
 * such a file system must move the files to one that reports a mode, or mount it with an explicit
 * owner-only mask that the platform can actually report.
 *
 * <p>Checks are made without following symlinks, so a symlink planted at the target name is judged
 * on its own bits ({@code lrwxrwxrwx} - group and other execute set) and is refused rather than
 * judged through to whatever it points at.
 */
final class PosixMode {

    /** {@code rw-------}: the only mode any file this component writes or reads may have. */
    static final Set<PosixFilePermission> OWNER_ONLY = Collections.unmodifiableSet(
            EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));

    private PosixMode() {
    }

    /**
     * Reads the mode of {@code path} itself, never the target of a link.
     *
     * @return the permission set, or {@code null} when the file system cannot report one. Callers
     *     must not treat {@code null} as "no exposure" - use the predicates below instead.
     */
    static Set<PosixFilePermission> permissionsOf(Path path) {
        if (path == null) {
            return null;
        }
        try {
            return Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS);
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /**
     * {@code true} when {@code path} is readable, writable or executable by group or other users,
     * or when its mode cannot be verified. Used for the accounts file and the keystore.
     */
    static boolean exposedToGroupOrOther(Path path) {
        Set<PosixFilePermission> permissions = permissionsOf(path);
        if (permissions == null) {
            return true;
        }
        return permissions.contains(PosixFilePermission.GROUP_READ)
                || permissions.contains(PosixFilePermission.GROUP_WRITE)
                || permissions.contains(PosixFilePermission.GROUP_EXECUTE)
                || permissions.contains(PosixFilePermission.OTHERS_READ)
                || permissions.contains(PosixFilePermission.OTHERS_WRITE)
                || permissions.contains(PosixFilePermission.OTHERS_EXECUTE);
    }

    /**
     * {@code true} when group or other users could write {@code path}, or when its mode cannot be
     * verified. Used for the directory holding the event log: a writable directory lets another user
     * delete, replace or pre-create a symlink at the log's name, which defeats every check made
     * against the file itself.
     */
    static boolean writableByGroupOrOther(Path path) {
        Set<PosixFilePermission> permissions = permissionsOf(path);
        if (permissions == null) {
            return true;
        }
        return permissions.contains(PosixFilePermission.OTHERS_WRITE)
                || permissions.contains(PosixFilePermission.GROUP_WRITE);
    }

    /**
     * {@code true} when {@code path} is not exactly {@code rw-------}, or when its mode cannot be
     * verified. Deliberately stricter than "no group/other bits": setuid, group execute on a
     * directory in the chain, or any bit not asked for is a mode this component did not create and
     * cannot explain, so it stops writes rather than being catalogued.
     */
    static boolean notExactlyOwnerOnly(Path path) {
        Set<PosixFilePermission> permissions = permissionsOf(path);
        if (permissions == null) {
            return true;
        }
        return !OWNER_ONLY.equals(permissions);
    }
}
