package com.portal.auth;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.EnumSet;
import java.util.Set;

/**
 * Every file this program touches is created, read and replaced through here, so that
 * "private to the owner" is one auditable predicate instead of eleven call sites.
 *
 * <p>Invariants:
 * <ul>
 *   <li>Files we create are {@code 0600}, directories {@code 0700}, and the mode is
 *       re-read from the filesystem after creation (a process with an unusual umask or
 *       an ACL default would otherwise silently widen it).</li>
 *   <li>Existing files are opened {@code NOFOLLOW}: a planted symlink out of the data
 *       directory is a refusal, not a write-through.</li>
 *   <li>A pre-existing file with any group/other bit is a refusal. We do not "fix"
 *       somebody else's file, because we cannot know who read it while it was open.</li>
 *   <li>Reads are size-bounded before the bytes are turned into characters.</li>
 * </ul>
 */
public final class PrivateFiles {

    public static final Set<PosixFilePermission> FILE_MODE =
            PosixFilePermissions.fromString("rw-------");
    public static final Set<PosixFilePermission> DIR_MODE =
            PosixFilePermissions.fromString("rwx------");

    private PrivateFiles() {
    }

    /**
     * Prepares (or accepts) the data directory. Returns the same path, canonicalised
     * enough to be trusted for subsequent opens.
     */
    public static Path requireDataDirectory(Path dir) {
        if (!dir.isAbsolute()) {
            throw new IllegalStateException("data-dir-must-be-absolute");
        }
        if (Files.isSymbolicLink(dir)) {
            throw new IllegalStateException("data-dir-must-not-be-symlink");
        }
        rejectWorldWritableAncestors(dir);
        if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) {
            if (Files.exists(dir, LinkOption.NOFOLLOW_LINKS)) {
                throw new IllegalStateException("data-dir-exists-but-not-directory");
            }
            try {
                Files.createDirectories(dir, PosixFilePermissions.asFileAttribute(DIR_MODE));
            } catch (IOException cannotCreate) {
                throw new IllegalStateException("data-dir-uncreatable", cannotCreate);
            }
        }
        requireMode(dir, DIR_MODE);
        requireOwnedProbe(dir);
        return dir;
    }

    /**
     * Ancestors must not be world-writable-and-non-sticky. Readability of an ancestor
     * is not the hazard (our files are 0600 inside a 0700 directory); the hazard is
     * somebody else planting or replacing an entry, which the sticky bit on /tmp also
     * prevents. Demanding "no read bit anywhere" would reject every path on the machine
     * (the root directory is 0755) and turn the check into a crash.
     */
    private static void rejectWorldWritableAncestors(Path dir) {
        Path p = dir.toAbsolutePath();
        for (int depth = 0; p != null && depth < 32; depth++) {
            Integer mode = unixMode(p);
            if (mode != null) {
                boolean worldWritable = (mode & 0_002) != 0;
                boolean sticky = (mode & 0_1000) != 0;
                if (worldWritable && !sticky) {
                    throw new IllegalStateException("data-ancestor-world-writable");
                }
            }
            p = p.getParent();
        }
    }

    /** The raw st_mode, or null when the platform does not expose it. */
    static Integer unixMode(Path p) {
        try {
            Object mode = Files.getAttribute(p, "unix:mode", LinkOption.NOFOLLOW_LINKS);
            return mode instanceof Number n ? n.intValue() : null;
        } catch (IOException | UnsupportedOperationException unavailable) {
            return null;
        }
    }

    /**
     * Proves the directory belongs to whoever can create files in it -- us -- by creating
     * a private probe and comparing unix uid. Comparing {@code user.name} against a
     * resolved owner name is unreliable (uid with no passwd entry, containerised users)
     * and a wrong comparison here means the ownership check silently never fires.
     */
    private static void requireOwnedProbe(Path dir) {
        Path probe = dir.resolve(".ownership-probe-" + Crypto.randomNameSuffix(9));
        try {
            Files.createFile(probe, PosixFilePermissions.asFileAttribute(FILE_MODE));
        } catch (IOException cannotWrite) {
            throw new IllegalStateException("data-dir-not-writable-by-us", cannotWrite);
        }
        try {
            int ours = uidOf(probe);
            int theirs = uidOf(dir);
            if (ours != theirs) {
                throw new IllegalStateException("data-dir-owned-by-someone-else");
            }
        } finally {
            try {
                Files.deleteIfExists(probe);
            } catch (IOException ignored) {
                probe.toFile().delete();
            }
        }
    }

    private static int uidOf(Path p) {
        try {
            Object uid = Files.getAttribute(p, "unix:uid", LinkOption.NOFOLLOW_LINKS);
            if (uid instanceof Number n) {
                return n.intValue();
            }
            throw new IllegalStateException("unix:uid unavailable");
        } catch (IOException | UnsupportedOperationException unavailable) {
            throw new IllegalStateException("cannot-determine-owner", unavailable);
        }
    }

    public static UserPrincipal owner(Path p) {
        try {
            return Files.getOwner(p, LinkOption.NOFOLLOW_LINKS);
        } catch (IOException e) {
            throw new IllegalStateException("cannot-read-owner", e);
        }
    }

    /** Create a new private file, failing if it already exists. */
    public static void createPrivateNew(Path file, byte[] content) {
        refuseSymlink(file);
        if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalStateException("file-already-exists");
        }
        requirePrivateParent(file);
        try {
            writeExactly(file, content, java.nio.file.StandardOpenOption.CREATE_NEW);
        } catch (IOException failure) {
            throw new IllegalStateException("cannot-create-file", failure);
        }
        requireMode(file, FILE_MODE);
    }

    /**
     * Replace the file's contents atomically: write a fresh {@code 0600} temp in the same
     * directory, fsync it, then {@code ATOMIC_MOVE}. A reader therefore sees the old or
     * the new file, never a truncated one, and a crash cannot leave a half-written roster.
     */
    public static void writePrivateAtomic(Path file, byte[] content) {
        refuseSymlink(file);
        requirePrivateParent(file);
        Path temp = file.resolveSibling(file.getFileName() + ".tmp-"
                + Crypto.randomNameSuffix(9));
        try {
            writeExactly(temp, content, java.nio.file.StandardOpenOption.CREATE_NEW);
            sync(temp);
            try {
                Files.move(temp, file,
                        java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (java.nio.file.AtomicMoveNotSupportedException notAtomic) {
                Files.move(temp, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException failure) {
            try {
                Files.deleteIfExists(temp);
            } catch (IOException ignored) {
                temp.toFile().delete();
            }
            throw new IllegalStateException("cannot-replace-file", failure);
        }
        requireMode(file, FILE_MODE);
    }

    /** Append one audit line, creating the file privately on first use. */
    public static void appendPrivateLine(Path file, String line) {
        refuseSymlink(file);
        requirePrivateParent(file);
        boolean fresh = !Files.exists(file, LinkOption.NOFOLLOW_LINKS);
        try {
            if (fresh) {
                writeExactly(file, (line + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8),
                        java.nio.file.StandardOpenOption.CREATE_NEW);
            } else {
                requireMode(file, FILE_MODE);
                try (OutputStream out = Files.newOutputStream(file,
                        java.nio.file.StandardOpenOption.APPEND,
                        LinkOption.NOFOLLOW_LINKS)) {
                    out.write(line.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    out.write('\n');
                    out.flush();
                    if (out instanceof java.io.FileOutputStream fos) {
                        fos.getFD().sync();
                    }
                }
            }
        } catch (IOException failure) {
            throw new IllegalStateException("cannot-append", failure);
        }
        requireMode(file, FILE_MODE);
    }

    /** Read a bounded, private file. Refuses to follow a symlink or exceed {@code maxBytes}. */
    public static String readPrivateBounded(Path file, long maxBytes) {
        refuseSymlink(file);
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalStateException("not-a-regular-file");
        }
        requireMode(file, FILE_MODE);
        long size;
        try {
            size = Files.size(file);
        } catch (IOException unreadable) {
            throw new IllegalStateException("cannot-stat", unreadable);
        }
        if (size > maxBytes) {
            throw new IllegalStateException("file-too-large");
        }
        byte[] raw;
        try {
            raw = Files.readAllBytes(file);
        } catch (IOException unreadable) {
            throw new IllegalStateException("cannot-read", unreadable);
        }
        try {
            if (raw.length > maxBytes) {
                throw new IllegalStateException("file-too-large");
            }
            return new String(raw, java.nio.charset.StandardCharsets.UTF_8);
        } finally {
            Crypto.wipe(raw);
        }
    }

    public static void requireMode(Path file, Set<PosixFilePermission> expected) {
        Set<PosixFilePermission> actual;
        try {
            actual = Files.getPosixFilePermissions(file, LinkOption.NOFOLLOW_LINKS);
        } catch (IOException | UnsupportedOperationException unavailable) {
            throw new IllegalStateException("cannot-read-mode", unavailable);
        }
        Set<PosixFilePermission> extra = EnumSet.copyOf(actual);
        extra.removeAll(expected);
        if (!extra.isEmpty()) {
            throw new IllegalStateException("permissions-too-open: "
                    + PosixFilePermissions.toString(actual));
        }
        if (!actual.equals(expected)) {
            // Narrower than expected is fine for reads, but we created it and must know.
            Set<PosixFilePermission> missing = EnumSet.copyOf(expected);
            missing.removeAll(actual);
            if (missing.contains(PosixFilePermission.OWNER_WRITE)
                    || missing.contains(PosixFilePermission.OWNER_READ)) {
                throw new IllegalStateException("permissions-unusable: "
                        + PosixFilePermissions.toString(actual));
            }
        }
    }

    private static void requirePrivateParent(Path file) {
        Path parent = file.getParent();
        if (parent == null) {
            throw new IllegalStateException("file-needs-a-directory");
        }
        if (!Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalStateException("parent-not-a-directory");
        }
        requireMode(parent, DIR_MODE);
    }

    private static void refuseSymlink(Path file) {
        if (Files.isSymbolicLink(file)) {
            throw new IllegalStateException("symlink-refused");
        }
    }

    /** Create-only write through a channel so the mode can be set atomically at creation. */
    private static void writeExactly(Path file, byte[] content,
                                     java.nio.file.StandardOpenOption createMode) throws IOException {
        // LinkedHashSet rather than EnumSet: StandardOpenOption and LinkOption are
        // different enums, and NOFOLLOW_LINKS in the option set is what stops a symlink
        // that appeared between the refuseSymlink check and this open from being written
        // through.
        java.util.Set<java.nio.file.OpenOption> options = new java.util.LinkedHashSet<>();
        options.add(createMode);
        options.add(java.nio.file.StandardOpenOption.WRITE);
        options.add(LinkOption.NOFOLLOW_LINKS);
        try (java.nio.channels.SeekableByteChannel ch = Files.newByteChannel(file, options,
                PosixFilePermissions.asFileAttribute(FILE_MODE))) {
            java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(content);
            while (buf.hasRemaining()) {
                if (ch.write(buf) == 0) {
                    throw new IOException("short-write");
                }
            }
        }
    }

    /**
     * Predicate for a file we did <em>not</em> create but are about to read (a config
     * file, a keystore). The attack to guard against is another user's eyes on the
     * contents, so the meaningful condition is "no group and no other bits at all".
     *
     * <p>Deliberately not an exact-mode equality: a read-only {@code 0400} file that a
     * deployment tool owns is private and must be accepted, whereas demanding our own
     * {@code 0600} here would reject a correct configuration and teach the operator to
     * switch the check off.
     */
    public static void requireNoGroupOrOtherAccess(Path file) {
        if (Files.isSymbolicLink(file)) {
            throw new IllegalStateException("config-symlink-refused");
        }
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalStateException("config-not-a-regular-file");
        }
        Integer mode = unixMode(file);
        if (mode == null) {
            throw new IllegalStateException("config-mode-unreadable");
        }
        if ((mode & 0_077) != 0) {
            throw new IllegalStateException(
                    "config-readable-by-group-or-other: mode=" + octalText(mode));
        }
        Integer dirMode = file.getParent() == null ? null : unixMode(file.getParent());
        if (dirMode != null && (dirMode & 0_002) != 0 && (dirMode & 0_1000) == 0) {
            throw new IllegalStateException("config-dir-world-writable");
        }
    }

    private static String octalText(int mode) {
        return Integer.toString(mode & 0_7777, 8);
    }

    private static void sync(Path file) throws IOException {
        try (FileChannel ch = FileChannel.open(file,
                java.nio.file.StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
            ch.force(true);
        }
    }

    /** Count of regular files in a directory, used to bound cleanup loops. */
    public static int countEntries(Path dir, int hardMax) {
        int n = 0;
        try (DirectoryStream<Path> it = Files.newDirectoryStream(dir)) {
            for (Path ignored : it) {
                if (++n > hardMax) {
                    throw new IllegalStateException("too-many-entries");
                }
            }
        } catch (IOException unreadable) {
            throw new IllegalStateException("cannot-list", unreadable);
        }
        return n;
    }
}
