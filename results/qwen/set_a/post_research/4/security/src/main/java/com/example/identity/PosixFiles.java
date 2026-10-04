package com.example.identity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.Set;

/**
 * Filesystem permission helpers for anything that may hold a secret.
 *
 * <p>Two things make this more than a {@code chmod} call, and both were measured on this machine:
 * <ul>
 *   <li><b>Creation is not enough.</b> {@code Files.createFile} applies the process umask, and H2
 *       creates its own {@code .mv.db} file, so a database written inside a {@code 0700} directory
 *       still landed on disk as {@code -rw-r--r--} - world-readable credentials and audit trails.
 *       Every path this program touches is therefore chmod-ed <em>after</em> creation and the
 *       result is <em>read back and asserted</em>, never assumed.</li>
 *   <li><b>Root ignores mode bits.</b> Running as uid 0, our own process can read and write a
 *       {@code 000} file. A test that only exercises the happy path as root proves nothing, so
 *       callers assert on the permission <em>set</em>, not on whether an operation succeeded.</li>
 * </ul>
 */
final class PosixFiles {

    /** Owner read/write only: no group, no other, no execute. */
    static final Set<PosixFilePermission> PRIVATE_FILE =
            Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

    /** Owner read/write/execute only. */
    static final Set<PosixFilePermission> PRIVATE_DIR =
            Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE);

    private PosixFiles() {
    }

    static boolean posixSupported(Path p) {
        return Files.getFileAttributeView(p, java.nio.file.attribute.PosixFileAttributeView.class,
                LinkOption.NOFOLLOW_LINKS) != null;
    }

    /**
     * Creates {@code dir} if absent with owner-only permissions, then verifies. A pre-existing
     * directory is tightened rather than trusted.
     *
     * <p>The order matters: create with an explicit mode first (so the window between create and
     * chmod never exposes a wide-open directory), then re-apply, because an inherited default ACL
     * can widen what the mode asks for.
     */
    static void createPrivateDir(Path dir) throws IdentityStoreException {
        assertNotSymbolicLink(dir, "directory");
        try {
            Files.createDirectories(dir, PosixFilePermissions.asFileAttribute(PRIVATE_DIR));
        } catch (UnsupportedOperationException noPosix) {
            throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE,
                    "the filesystem hosting " + dir + " does not support POSIX permissions", noPosix);
        } catch (IOException e) {
            throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE, "cannot create " + dir, e);
        }
        try {
            Files.setPosixFilePermissions(dir, PRIVATE_DIR);
        } catch (IOException e) {
            throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE, "cannot set permissions on " + dir, e);
        }
        assertExactly(dir, PRIVATE_DIR, "data directory");
    }

    /**
     * Tightens an existing file to owner read/write and asserts the result.
     *
     * <p>A symlink is refused <em>first</em>, which is not the same thing as the assert below
     * catching it. Measured on this JDK: {@code setPosixFilePermissions} follows the link, so
     * handing it {@code data/audit.log} pointed at {@code /home/me/.ssh/authorized_keys} chmods
     * that target to 0600 - the damage is done and belongs to somebody else's file - while
     * {@code getPosixFilePermissions(link, NOFOLLOW_LINKS)} reports the link's own
     * {@code rwxrwxrwx}. The assert then throws, and the caller treats it as "nothing happened".
     * Nothing had happened to <em>our</em> path; the victim's file had already been rewritten.
     * Refusing up front is the only order that leaves the target untouched.
     */
    static void makePrivate(Path file, String what) throws IdentityStoreException {
        assertNotSymbolicLink(file, "file");
        try {
            Files.setPosixFilePermissions(file, PRIVATE_FILE);
        } catch (IOException e) {
            throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE, "cannot set permissions on " + file, e);
        }
        assertExactly(file, PRIVATE_FILE, what);
    }

    /**
     * Refuses a symbolic link at the path we are about to secure. {@link Files#isSymbolicLink}
     * does not follow the link, so this is a statement about the path itself, not its target.
     */
    private static void assertNotSymbolicLink(Path p, String kind) throws IdentityStoreException {
        if (Files.isSymbolicLink(p)) {
            throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE,
                    "refusing to secure " + kind + " " + p + ": it is a symbolic link, and the"
                            + " chmod would be applied to whatever it points at");
        }
    }

    private static void assertExactly(Path file, Set<PosixFilePermission> expected, String what)
            throws IdentityStoreException {
        Set<PosixFilePermission> actual = actualPermissions(file);
        if (!actual.equals(expected)) {
            throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE,
                    what + " " + file + " has permissions " + PosixFilePermissions.toString(actual)
                            + ", expected " + PosixFilePermissions.toString(expected));
        }
    }

    static Set<PosixFilePermission> actualPermissions(Path file) throws IdentityStoreException {
        try {
            return Files.getPosixFilePermissions(file, LinkOption.NOFOLLOW_LINKS);
        } catch (UnsupportedOperationException | IOException e) {
            throw new IdentityStoreException(Reason.STORAGE_UNAVAILABLE,
                    "cannot determine permissions of " + file, e);
        }
    }

    /**
     * The value both {@link #isWorldReadable} and {@link #isWorldWritable} answer with when the
     * permission bits cannot be read at all. Named rather than inlined as a bare {@code true} so the
     * test can assert the fail-closed choice from the code instead of from a prose comment: a comment
     * that says "fail closed" is not what makes the code fail closed, and the test that looked for
     * that wording passed while the two methods disagreed about which way was which.
     */
    static final boolean UNREADABLE_ATTRIBUTES_ARE_EXPOSED = true;

    static boolean isWorldReadable(Path p) {
        try {
            return Files.getPosixFilePermissions(p, LinkOption.NOFOLLOW_LINKS)
                    .contains(PosixFilePermission.OTHERS_READ);
        } catch (UnsupportedOperationException | IOException e) {
            return UNREADABLE_ATTRIBUTES_ARE_EXPOSED;
        }
    }

    static boolean isWorldWritable(Path p) {
        try {
            return Files.getPosixFilePermissions(p, LinkOption.NOFOLLOW_LINKS)
                    .contains(PosixFilePermission.OTHERS_WRITE);
        } catch (UnsupportedOperationException | IOException e) {
            return UNREADABLE_ATTRIBUTES_ARE_EXPOSED;
        }
    }

    /**
     * Refuses any file that group or other can write or read. Used for configuration and the audit
     * log, both of which must never be influenced or harvested by another local account.
     */
    static void assertNoGroupOrOtherAccess(Path p, String what) throws IdentityStoreException {
        Set<PosixFilePermission> perms = actualPermissions(p);
        for (PosixFilePermission bad : new PosixFilePermission[] {
                PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE, PosixFilePermission.GROUP_EXECUTE,
                PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_WRITE, PosixFilePermission.OTHERS_EXECUTE }) {
            if (perms.contains(bad)) {
                throw new IdentityStoreException(Reason.CONFIG_INVALID,
                        what + " " + p + " is accessible to others ("
                                + PosixFilePermissions.toString(perms) + ")");
            }
        }
    }

    /** True if the file is a regular file we did not follow through a symlink. */
    static boolean isRegularNoFollow(Path p) {
        return Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(p);
    }

    static String ownerName(Path p) {
        try {
            UserPrincipal owner = Files.getOwner(p, LinkOption.NOFOLLOW_LINKS);
            return owner == null ? "<unknown>" : owner.getName();
        } catch (IOException e) {
            return "<unknown>";
        }
    }

    static String groupName(Path p) {
        try {
            GroupPrincipal owner = Files.getOwner(p, LinkOption.NOFOLLOW_LINKS) instanceof GroupPrincipal g
                    ? g : null;
            return owner == null ? "<none>" : owner.getName();
        } catch (IOException e) {
            return "<unknown>";
        }
    }

    static String describePermissions(Path p) {
        try {
            return PosixFilePermissions.toString(Files.getPosixFilePermissions(p, LinkOption.NOFOLLOW_LINKS));
        } catch (Exception e) {
            return "<unknown>";
        }
    }
}
