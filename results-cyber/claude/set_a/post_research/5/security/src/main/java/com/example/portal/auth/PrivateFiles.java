package com.example.portal.auth;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

/**
 * Helpers for the files this application owns -- credential records, the audit log, and the attempt
 * tracker -- all of which must stay private to the account the portal runs as.
 *
 * <p>Centralised so the three call sites cannot disagree about what "private" means, and so a new
 * file added later inherits the same checks.
 */
final class PrivateFiles {

    private static final Set<PosixFilePermission> OWNER_ONLY =
            Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

    private PrivateFiles() {
    }

    /** Whether this filesystem reports POSIX ownership and permissions at all. */
    static boolean posixSupported() {
        return FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
    }

    /**
     * Creates {@code path} with {@code rw-------} if it does not exist.
     *
     * <p>The permissions are passed to {@link Files#createFile} rather than applied afterwards: a
     * create-then-chmod sequence leaves a window in which the file exists with the process umask's
     * permissions, and a credential file that is world-readable for a millisecond is still
     * world-readable.
     */
    static void createPrivateIfAbsent(Path path) throws IOException {
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        if (posixSupported()) {
            Files.createFile(path,
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        } else {
            Files.createFile(path);
        }
    }

    /**
     * Verifies that an existing file is a plain file, owned by this process's user, and reachable by
     * nobody else.
     *
     * <p>Each clause closes a distinct path to compromise: a symlink or FIFO could redirect reads and
     * writes elsewhere; a file owned by another account could have been planted; group or world
     * <em>read</em> on a credential file hands over the hashes; group or world <em>write</em> lets
     * another local account enrol itself as any employee or quietly reset the attempt counters.
     *
     * @param kind short noun used in the exception message, e.g. "credential file"
     * @throws ValidationException if any check fails, including when the platform cannot answer
     */
    static void requireOwnerOnly(Path path, String kind) throws IOException, ValidationException {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new ValidationException(kind + " does not exist");
        }
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new ValidationException(kind + " is not a regular file");
        }
        if (!posixSupported()) {
            throw new ValidationException(kind + " permissions cannot be verified on this filesystem");
        }
        Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS);
        if (!OWNER_ONLY.containsAll(permissions)) {
            throw new ValidationException(kind + " is accessible to accounts other than its owner");
        }
        String fileOwner = Files.getOwner(path, LinkOption.NOFOLLOW_LINKS).getName();
        String processUser = System.getProperty("user.name");
        if (processUser == null || !processUser.equals(fileOwner)) {
            throw new ValidationException(kind + " is not owned by the portal user");
        }
        Path parent = path.getParent();
        if (parent != null && posixSupported()
                && Files.getPosixFilePermissions(parent).contains(PosixFilePermission.OTHERS_WRITE)) {
            // A world-writable directory lets another account replace the file wholesale, which
            // defeats every check above.
            throw new ValidationException(kind + " sits in a world-writable directory");
        }
    }
}
