package com.security.crypto;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.Set;

/**
 * Platform security utility for enforcing strict filesystem trust boundaries
 * and owner-private file permissions.
 * <p>
 * Satisfies:
 * <ul>
 *   <li>Rule 1 (Trust Boundaries): Validates file paths, canonicalization, and regular file status.</li>
 *   <li>Rule 2 (Secrets): Rejects files readable by group or other users.</li>
 *   <li>Rule 5 (Sensitive Data): Ensures files containing sensitive data are created private to the owner (0600).</li>
 *   <li>Rule 8 (Prefer the Platform): Enforces rejection of files located in shared or world-writable locations.</li>
 * </ul>
 */
public final class FileSecurityUtil {

    private static final boolean IS_POSIX = FileSystems.getDefault().supportedFileAttributeViews().contains("posix");

    private FileSecurityUtil() {
        // Utility class
    }

    /**
     * Validates that a file containing cryptographic keys or secrets exists, is a regular file,
     * is not located in an insecure/world-writable location, and is strictly private to the owner.
     *
     * @param path Path to validate.
     * @return Canonical normalized Path.
     * @throws CryptoException If the path fails security or permission validation.
     */
    public static Path validatePrivateFile(Path path) {
        if (path == null) {
            throw new CryptoException("Invalid cryptographic request: file path must not be null");
        }

        Path normalized;
        try {
            normalized = path.toAbsolutePath().normalize();
            if (!Files.exists(normalized, LinkOption.NOFOLLOW_LINKS)) {
                throw new CryptoException("Key file does not exist");
            }
            if (!Files.isRegularFile(normalized, LinkOption.NOFOLLOW_LINKS)) {
                throw new CryptoException("Key file is not a regular file");
            }
        } catch (SecurityException e) {
            throw new CryptoException("Security manager denied access to key file", e);
        }

        // Validate POSIX file permissions and parent directory safety if supported
        if (IS_POSIX) {
            try {
                // Check parent directory is not world-writable
                Path parent = normalized.getParent();
                if (parent != null && Files.exists(parent)) {
                    Set<PosixFilePermission> parentPerms = Files.getPosixFilePermissions(parent);
                    if (parentPerms.contains(PosixFilePermission.OTHERS_WRITE)) {
                        throw new CryptoException("Key file directory is world-writable and unsafe");
                    }
                }

                // Check file owner
                UserPrincipal owner = Files.getOwner(normalized, LinkOption.NOFOLLOW_LINKS);
                String currentUser = System.getProperty("user.name");
                if (owner != null && currentUser != null && !currentUser.equals(owner.getName()) && !"root".equals(owner.getName())) {
                    throw new CryptoException("Key file is not owned by the current application user");
                }

                // Check file permissions: must not be readable/writable by group or others
                Set<PosixFilePermission> perms = Files.getPosixFilePermissions(normalized, LinkOption.NOFOLLOW_LINKS);
                if (perms.contains(PosixFilePermission.GROUP_READ)
                        || perms.contains(PosixFilePermission.GROUP_WRITE)
                        || perms.contains(PosixFilePermission.GROUP_EXECUTE)
                        || perms.contains(PosixFilePermission.OTHERS_READ)
                        || perms.contains(PosixFilePermission.OTHERS_WRITE)
                        || perms.contains(PosixFilePermission.OTHERS_EXECUTE)) {
                    throw new CryptoException("Key file permissions are too open: must be readable only by the owner (mode 0600 or 0400)");
                }
            } catch (IOException e) {
                throw new CryptoException("Failed to verify key file security attributes", e);
            }
        }

        return normalized;
    }

    /**
     * Atomically creates a file strictly private to the owner (mode 0600 on POSIX).
     *
     * @param path The path where the private file should be created.
     * @return Path to the created file.
     * @throws IOException If file creation fails.
     */
    public static Path createPrivateFile(Path path) throws IOException {
        if (path == null) {
            throw new CryptoException("File path must not be null");
        }
        Path normalized = path.toAbsolutePath().normalize();

        if (IS_POSIX) {
            return Files.createFile(normalized,
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        } else {
            Path created = Files.createFile(normalized);
            File file = created.toFile();
            // Restrict on non-POSIX filesystems
            boolean ok = file.setReadable(false, false)
                    && file.setReadable(true, true)
                    && file.setWritable(false, false)
                    && file.setWritable(true, true)
                    && file.setExecutable(false, false);
            if (!ok) {
                // If setting permissions failed, fail closed
                Files.deleteIfExists(created);
                throw new IOException("Failed to restrict file permissions on created file");
            }
            return created;
        }
    }
}
