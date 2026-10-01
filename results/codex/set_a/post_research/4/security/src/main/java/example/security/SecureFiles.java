package example.security;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;
import java.util.regex.Pattern;

final class SecureFiles {
    private static final Set<PosixFilePermission> DIRECTORY_MODE =
            PosixFilePermissions.fromString("rwx------");
    private static final Set<PosixFilePermission> FILE_MODE =
            PosixFilePermissions.fromString("rw-------");
    private static final Pattern SAFE_ABSOLUTE_PATH = Pattern.compile("/[A-Za-z0-9_./-]{1,4095}");

    private SecureFiles() { }

    static Path initializeDataDirectory(String raw) throws IOException {
        if (raw == null || !SAFE_ABSOLUTE_PATH.matcher(raw).matches()) {
            throw new IOException("invalid data directory configuration");
        }
        Path path;
        try {
            path = Path.of(raw);
        } catch (RuntimeException e) {
            throw new IOException("invalid data directory configuration", e);
        }
        if (!path.isAbsolute() || !path.normalize().equals(path)) {
            throw new IOException("data directory must be an absolute normalized path");
        }
        requirePosix(path.getParent());
        rejectSymlinkComponents(path.getParent());
        Set<PosixFilePermission> parentMode = Files.getPosixFilePermissions(
                path.getParent(), LinkOption.NOFOLLOW_LINKS);
        if (parentMode.contains(PosixFilePermission.GROUP_WRITE)
                || parentMode.contains(PosixFilePermission.OTHERS_WRITE)) {
            throw new IOException("data directory parent is writable by other users");
        }
        if (Files.notExists(path, LinkOption.NOFOLLOW_LINKS)) {
            Files.createDirectory(path, PosixFilePermissions.asFileAttribute(DIRECTORY_MODE));
        }
        validatePrivateDirectory(path);
        return path.toRealPath(LinkOption.NOFOLLOW_LINKS);
    }

    static Path privateFile(Path directory, String name) throws IOException {
        Path file = directory.resolve(name);
        if (Files.notExists(file, LinkOption.NOFOLLOW_LINKS)) {
            try {
                Files.createFile(file, PosixFilePermissions.asFileAttribute(FILE_MODE));
            } catch (java.nio.file.FileAlreadyExistsException ignored) {
                // A racing creator is handled by the checks below.
            }
        }
        if (Files.isSymbolicLink(file) || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)
                || !Files.getPosixFilePermissions(file, LinkOption.NOFOLLOW_LINKS).equals(FILE_MODE)) {
            throw new IOException("unsafe private file");
        }
        return file;
    }

    static Path privateDirectory(Path parent, String name) throws IOException {
        Path path = parent.resolve(name);
        if (Files.notExists(path, LinkOption.NOFOLLOW_LINKS)) {
            try {
                Files.createDirectory(path, PosixFilePermissions.asFileAttribute(DIRECTORY_MODE));
            } catch (java.nio.file.FileAlreadyExistsException ignored) {
                // A racing creator is handled by the checks below.
            }
        }
        validatePrivateDirectory(path);
        return path;
    }

    static void validatePrivateDirectory(Path path) throws IOException {
        requirePosix(path);
        if (Files.isSymbolicLink(path) || !Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)
                || !Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS).equals(DIRECTORY_MODE)) {
            throw new IOException("unsafe data directory permissions");
        }
    }

    private static void requirePosix(Path path) throws IOException {
        if (path == null || Files.getFileAttributeView(path, PosixFileAttributeView.class,
                LinkOption.NOFOLLOW_LINKS) == null) {
            throw new IOException("POSIX permissions are required");
        }
    }

    private static void rejectSymlinkComponents(Path path) throws IOException {
        Path current = path.getRoot();
        for (Path part : path) {
            current = current.resolve(part);
            if (Files.isSymbolicLink(current)) {
                throw new IOException("symlink in data path");
            }
        }
    }
}
