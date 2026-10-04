package com.example.auth;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

/**
 * Fail-closed checks on filesystem objects that hold the credential store or its audit trail.
 *
 * <p>All checks are on the mode bits and ownership, never on whether a read succeeds: the reference
 * platform runs as root, and root bypasses permission bits, so an accessibility probe would report
 * a world-readable file as safe.
 */
final class DbPathGuard {

    private DbPathGuard() {
    }

    /**
     * The directory must exist, be a real directory (not a symlink), be owned by the running
     * account, and carry no group or world bits. A world-writable directory lets any local account
     * replace or swap the credential file regardless of its own mode.
     */
    static void requirePrivateDirectory(Path dir) throws IOException {
        if (Files.isSymbolicLink(dir)) {
            throw new IOException("dir_is_symlink");
        }
        if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("not_a_directory");
        }
        Set<PosixFilePermission> mode = Files.getPosixFilePermissions(dir, LinkOption.NOFOLLOW_LINKS);
        requireNoForeignAccess(mode);
        requireOwnedByCurrentUser(dir);
        if (!mode.contains(PosixFilePermission.OWNER_WRITE)
                || !mode.contains(PosixFilePermission.OWNER_EXECUTE)) {
            throw new IOException("dir_not_writable_by_owner");
        }
    }

    /** The file must be a regular file (not a symlink), owned by us, and mode 0600 or stricter. */
    static void requirePrivateRegularFile(Path file) throws IOException {
        if (Files.isSymbolicLink(file)) {
            throw new IOException("file_is_symlink");
        }
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("not_a_regular_file");
        }
        Set<PosixFilePermission> mode = Files.getPosixFilePermissions(file, LinkOption.NOFOLLOW_LINKS);
        requireNoForeignAccess(mode);
        requireOwnedByCurrentUser(file);
    }

    private static void requireNoForeignAccess(Set<PosixFilePermission> mode) throws IOException {
        for (PosixFilePermission p : mode) {
            String name = p.name();
            if (name.startsWith("GROUP_") || name.startsWith("OTHERS_")) {
                throw new IOException("path_grants_access_to_others");
            }
        }
    }

    private static void requireOwnedByCurrentUser(Path p) throws IOException {
        java.nio.file.attribute.FileOwnerAttributeView view = Files.getFileAttributeView(p,
                java.nio.file.attribute.FileOwnerAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            throw new IOException("owner_attribute_unsupported");
        }
        String owner = view.getOwner().getName();
        String self = System.getProperty("user.name");
        if (self == null || !owner.equals(self)) {
            throw new IOException("path_not_owned_by_current_user");
        }
    }

    /**
     * Existence plus guard for the parent of the configured database path, performed before the
     * engine is ever contacted. Refuses a symlinked or world-writable storage location.
     */
    static Path verifiedParentDirectory(String canonicalDbPath) throws IOException {
        Path parent = Path.of(canonicalDbPath).getParent();
        if (parent == null) {
            throw new IOException("db_parent_missing");
        }
        requirePrivateDirectory(parent);
        return parent;
    }
}
