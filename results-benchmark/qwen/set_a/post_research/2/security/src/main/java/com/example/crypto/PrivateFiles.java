package com.example.crypto;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.Set;

/**
 * Filesystem checks for anything holding key material or a password.
 *
 * <p>Rule 5 of the brief says secrets go "only to files created private to the owner". Checking the
 * mode after writing does not achieve that - there is a window between creation and the chmod - so
 * every file this component writes is created through {@link FileChannel#open} with its permissions
 * in the creation attributes, which means it never exists in a readable state.
 *
 * <p>Reading is the harder direction, because the file an attacker can influence is the one already
 * on disk. A mode check alone is bypassable: replace the file with a symlink to something else, put
 * it on a filesystem mounted read-only with stale attributes, or leave it in a world-writable
 * directory where anyone can swap it. So a key file must satisfy all of:
 * <ul>
 *   <li>it is a regular file and not a symlink - checked on the same inode the read will use, via
 *       {@code NOFOLLOW_LINKS};</li>
 *   <li>its mode grants nothing to group or other, and no execute or set-id bit is set;</li>
 *   <li>its owner is the user running this process;</li>
 *   <li>every ancestor directory is owned by that user, not writable by group or other, and either
 *       not world-writable or carrying the sticky bit (the {@code /tmp} convention);</li>
 *   <li>if the parent directory is writable by others, the read is re-validated afterwards: the
 *       directory's mode must be unchanged, the file's {@code (st_dev, st_ino)} pair must identify the
 *       same inode that passed the checks above, and its mode and owner must be unchanged - so unlinking
 *       and re-creating the entry while the read is in progress is detected and the bytes discarded.</li>
 * </ul>
 *
 * <p>On a filesystem with no POSIX permissions (Windows without ACL support, FAT, some mounts) the
 * checks cannot be performed and this component refuses rather than assuming the file is private.
 * Configure a hardware-backed store or a secret manager there instead; see {@link KeystoreKeySource}.
 *
 * <p>Residual risk stated plainly: root can read any file this or any other process can read, and an
 * attacker who can already read the process's memory does not need the file. These guards raise the
 * cost against unprivileged local users, service accounts and configuration mistakes - they are not
 * a defence against a compromised host.
 */
public final class PrivateFiles {

    private static final int S_ISUID = 04000;
    private static final int S_ISGID = 02000;
    private static final int S_ISVTX = 01000;
    private static final int PERMS_MASK = 07777;

    /** Owner read/write only: {@code 0600}. */
    public static final Set<PosixFilePermission> OWNER_ONLY =
            EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

    /** Owner read/write/execute: {@code 0700}. Used when this component creates a directory. */
    public static final Set<PosixFilePermission> OWNER_ONLY_DIR = EnumSet.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE);

    private PrivateFiles() {
    }

    /**
     * Creates {@code file} with mode {@code 0600} in one step and writes {@code content}, refusing if
     * it already exists. The parent directory must already satisfy {@link #requireSecureDirectory};
     * that check is deliberately not relaxed for a directory the caller owns but did not create.
     *
     * @throws CryptoException if the file exists, the parent directory is not private, or the
     *     filesystem does not support POSIX permissions
     */
    public static void writeOwnerOnlyFile(Path file, byte[] content) throws CryptoException {
        Limits.requirePayload(content, Limits.MAX_PLAINTEXT_BYTES, "file content");
        Path parent = file.toAbsolutePath().getParent();
        if (parent == null) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                    "key file has no parent directory");
        }
        if (!Files.exists(parent, LinkOption.NOFOLLOW_LINKS)) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                    "key file directory does not exist: refusing to create it implicitly");
        }
        requireSecureDirectory(parent);
        /*
         * No "does it already exist?" check here on purpose. Asking and then opening are two decisions
         * about one fact, and a local attacker can create the file in between, so the answer to the first
         * question would not be the answer that governed the write. CREATE_NEW makes the filesystem
         * decide, in the one operation that also creates the file with its 0600 mode, so there is no
         * window to lose. A caller that wants replacement must delete first, deliberately.
         */
        try {
            Set<StandardOpenOption> opts = EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            try (FileChannel ch = FileChannel.open(file, opts,
                    java.nio.file.attribute.PosixFilePermissions.asFileAttribute(OWNER_ONLY))) {
                java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(content);
                while (buf.hasRemaining()) {
                    ch.write(buf);
                }
                ch.force(true);
            }
        } catch (java.nio.file.FileAlreadyExistsException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                    "key file already exists; refusing to overwrite it", e);
        } catch (java.nio.file.AccessDeniedException | SecurityException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                    "key file could not be created: access denied", e);
        } catch (FileSystemException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                    "key file could not be created", e);
        } catch (IOException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                    "key file could not be created", e);
        }
        /* Belt and braces: confirm the created file really is private before returning. */
        requirePrivateKeyFile(file);
    }

    /**
     * Reads at most {@code maxBytes} from a file that has been proven private to this user.
     *
     * @throws CryptoException if any check in {@link #requirePrivateKeyFile} fails, or the file is
     *     larger than {@code maxBytes}
     */
    public static byte[] readOwnerOnlyFile(Path file, int maxBytes) throws CryptoException {
        Path parent = file.toAbsolutePath().getParent();
        if (parent == null) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                    "key file has no parent directory");
        }
        boolean parentShared = isWritableByOthers(parent);
        int parentModeBefore = unixMode(parent);
        requirePrivateKeyFile(file);
        /*
         * Snapshot what the validation above was actually about - this inode, this mode - so the
         * after-the-fact check can say something true. Comparing the parent directory's mode alone would
         * not notice the attack it claims to notice: an attacker who may write the directory does not
         * chmod it to swap a key out, he unlinks the entry and creates another one.
         */
        long[] inodeBefore = identity(file);
        int modeBefore = unixMode(file);
        byte[] out;
        try {
            long size = Files.size(file);
            if (size > maxBytes) {
                throw new CryptoException(CryptoException.CryptoFailureCode.TOO_LARGE,
                        "key file is larger than " + maxBytes + " bytes");
            }
            out = Files.readAllBytes(file);
        } catch (IOException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE,
                    "key file could not be read", e);
        }
        if (out.length > maxBytes) {
            throw new CryptoException(CryptoException.CryptoFailureCode.TOO_LARGE,
                    "key file is larger than " + maxBytes + " bytes");
        }
        if (parentShared) {
            if (unixMode(parent) != parentModeBefore) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                        "key file directory changed during the read");
            }
            long[] inodeAfter = identity(file);
            if (inodeAfter[0] != inodeBefore[0] || inodeAfter[1] != inodeBefore[1]) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                        "key file was replaced during the read");
            }
            if (unixMode(file) != modeBefore || !stillOwnedByMe(file)) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                        "key file permissions or ownership changed during the read");
            }
        }
        return out;
    }

    /**
     * {@code {st_dev, st_ino}} for {@code p} - enough to tell "the same file" from "a different file
     * that happens to have the same name", which is the distinction that matters here.
     */
    private static long[] identity(Path p) throws CryptoException {
        try {
            Object dev = Files.getAttribute(p, "unix:dev", LinkOption.NOFOLLOW_LINKS);
            Object ino = Files.getAttribute(p, "unix:ino", LinkOption.NOFOLLOW_LINKS);
            if (!(dev instanceof Long d) || !(ino instanceof Long i)) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                        "filesystem does not report inode identity for " + p);
            }
            return new long[] {d, i};
        } catch (UnsupportedOperationException | IllegalArgumentException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                    "inode identity could not be read for " + p, e);
        } catch (IOException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE,
                    "inode identity could not be read for " + p, e);
        }
    }

    /** Ownership re-check that reports rather than throws, for use after the read. */
    private static boolean stillOwnedByMe(Path p) {
        String me = System.getProperty("user.name");
        try {
            return me != null && me.equals(Files.getOwner(p, LinkOption.NOFOLLOW_LINKS).getName());
        } catch (UnsupportedOperationException | IOException e) {
            return false;
        }
    }

    /**
     * Verifies {@code file} is a private, non-symlink, owner-only regular file.
     *
     * @throws CryptoException naming the failed requirement in {@code getTechnicalDetail()}
     */
    public static void requirePrivateKeyFile(Path file) throws CryptoException {
        PosixFileAttributes attrs = readPosix(file);
        if (attrs.isSymbolicLink()) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                    "key file is a symbolic link");
        }
        if (!attrs.isRegularFile()) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                    "key file is not a regular file");
        }
        Set<PosixFilePermission> perms = attrs.permissions();
        for (PosixFilePermission p : perms) {
            switch (p) {
                case OWNER_READ:
                case OWNER_WRITE:
                    break;
                default:
                    /* Group/other access, or any execute bit on a data file: refuse. */
                    throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                            "key file permissions grant more than owner read/write: "
                                    + java.nio.file.attribute.PosixFilePermissions.toString(perms));
            }
        }
        int mode = unixMode(file);
        if ((mode & (S_ISUID | S_ISGID)) != 0) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                    "key file has a set-id bit set");
        }
        requireOwns(file, "key file");
        requireSecureDirectory(file.toAbsolutePath().getParent());
    }

    /**
     * Verifies a directory cannot be written to by anyone but its owner, allowing the sticky-bit
     * convention for shared temporary directories.
     *
     * @throws CryptoException if the directory is writable by group or other without a sticky bit, is not
     *     owned by this user, is not a directory, or is a symlink
     */
    public static void requireSecureDirectory(Path dir) throws CryptoException {
        if (dir == null) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                    "directory is missing");
        }
        Path abs = dir.toAbsolutePath();
        /* Walk from the shortest prefix down: a private file inside an open directory is not private. */
        for (Path component = abs; component != null; ) {
            PosixFileAttributes attrs = readPosix(component);
            if (attrs.isSymbolicLink()) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                        "key file directory path traverses a symbolic link: " + component);
            }
            boolean isRoot = component.getParent() == null;
            if (!isRoot && !attrs.isDirectory()) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                        "key file directory path component is not a directory: " + component);
            }
            int mode = unixMode(component) & PERMS_MASK;
            boolean sticky = (mode & S_ISVTX) != 0;
            /*
             * Group and other write access are treated as one condition, because they are the same
             * threat: somebody else can unlink or replace an entry. The sticky bit is what removes that
             * power - only the owner of an entry may delete or rename it - which is why /tmp is 1777 and
             * why the check is "writable by others without a sticky bit" rather than "world-writable".
             *
             * Rejecting group-writable outright would be stricter, not safer: /tmp is group-writable on
             * every conventional system, so a blanket refusal rejects the standard temporary directory
             * while a 0775 directory with no sticky bit - genuinely unsafe - is refused for a different
             * reason than the one that matters. One rule, applied to both, is the one that can be
             * reasoned about.
             */
            boolean writableByOthers = (mode & 0022) != 0;
            if (writableByOthers && !sticky) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                        "key file directory is writable by others without the sticky bit: " + component);
            }
            if (!isRoot) {
                requireOwns(component, "key file directory");
            }
            component = component.getParent();
        }
    }

    /**
     * Opens a new owner-only ({@code 0600}) output stream, creating the file in the same step that
     * sets its permissions. For callers such as {@code KeyStore.store()} that must write a secret
     * themselves and cannot pass creation attributes: {@code Files.newOutputStream} has no
     * {@code FileAttribute} overload, so a store written that way is born {@code 0644} and stays
     * readable until a later chmod - which is a window, not a fix.
     *
     * @throws CryptoException if the file exists or the parent directory is not private
     */
    public static java.io.OutputStream newOwnerOnlyOutputStream(Path file) throws CryptoException {
        Path parent = file.toAbsolutePath().getParent();
        if (parent == null || !Files.exists(parent, LinkOption.NOFOLLOW_LINKS)) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                    "target directory does not exist");
        }
        requireSecureDirectory(parent);
        /* As in writeOwnerOnlyFile: CREATE_NEW is the decision, so nothing can be swapped in between. */
        try {
            Set<StandardOpenOption> opts = EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            return java.nio.channels.Channels.newOutputStream(
                    FileChannel.open(file, opts,
                            java.nio.file.attribute.PosixFilePermissions.asFileAttribute(OWNER_ONLY)));
        } catch (java.nio.file.FileAlreadyExistsException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                    "file already exists; refusing to overwrite it", e);
        } catch (IOException | SecurityException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                    "private file could not be opened for writing", e);
        }
    }

    /** Creates a directory that only the owner can enter, failing if it already exists. */
    public static Path createOwnerOnlyDirectory(Path dir) throws CryptoException {
        Path parent = dir.toAbsolutePath().getParent();
        requireSecureDirectory(parent);
        try {
            Path created = Files.createDirectory(dir,
                    java.nio.file.attribute.PosixFilePermissions.asFileAttribute(OWNER_ONLY_DIR));
            requireSecureDirectory(created);
            return created;
        } catch (IOException | SecurityException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                    "private directory could not be created", e);
        }
    }

    /** True if users other than the owner may create or unlink entries in {@code dir}. */
    static boolean isWritableByOthers(Path dir) throws CryptoException {
        int mode = unixMode(dir) & PERMS_MASK;
        return (mode & 0022) != 0;
    }

    /**
     * The file's {@code st_mode}. Read directly rather than derived from
     * {@link PosixFilePermission} because that enum cannot represent the set-id or sticky bits -
     * {@code PosixFilePermissions.fromString("rwxrwxrwt")} throws - and those are exactly the bits
     * that matter for a swap attack.
     *
     * @throws CryptoException if the filesystem exposes no unix attributes: no POSIX permissions means
     *     privacy cannot be verified, so this component refuses instead of assuming
     */
    static int unixMode(Path p) throws CryptoException {
        try {
            Object v = Files.getAttribute(p, "unix:mode", LinkOption.NOFOLLOW_LINKS);
            if (!(v instanceof Integer i)) {
                throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                        "filesystem does not report unix permissions for " + p);
            }
            return i;
        } catch (UnsupportedOperationException | IllegalArgumentException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                    "filesystem does not support POSIX permissions, so key-file privacy cannot be "
                            + "verified: " + p, e);
        } catch (IOException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                    "permissions could not be read for " + p, e);
        }
    }

    private static PosixFileAttributes readPosix(Path p) throws CryptoException {
        try {
            return Files.readAttributes(p, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        } catch (UnsupportedOperationException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                    "filesystem does not support POSIX permissions, so key-file privacy cannot be "
                            + "verified: " + p, e);
        } catch (IOException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE,
                    "file status could not be read: " + p, e);
        }
    }

    private static void requireOwns(Path p, String what) throws CryptoException {
        String me = System.getProperty("user.name");
        String owner;
        try {
            owner = Files.getOwner(p, LinkOption.NOFOLLOW_LINKS).getName();
        } catch (UnsupportedOperationException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                    "ownership cannot be verified on this filesystem for " + p, e);
        } catch (IOException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE,
                    "ownership could not be read for " + p, e);
        }
        if (me == null || !me.equals(owner)) {
            /*
             * The owner check is best-effort by design: it stops the common attack (a key file planted
             * by another service account in a shared directory) but an attacker who can set file
             * ownership is already root. Note that this means a process cannot run as one user and read
             * a key file created by another, however legitimately - that is the intended trade.
             */
            throw new CryptoException(CryptoException.CryptoFailureCode.INSECURE_KEY_STORAGE,
                    what + " is owned by " + owner + ", not by the running user " + me);
        }
    }
}
