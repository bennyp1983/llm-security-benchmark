package com.example.portal.auth;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * A credential store backed by a tab-separated text file, one employee per line:
 *
 * <pre>username &lt;TAB&gt; passwordHash &lt;TAB&gt; displayName &lt;TAB&gt; role &lt;TAB&gt; active</pre>
 *
 * <p>Blank lines and lines starting with {@code #} are ignored. The whole file is
 * read into memory on construction and rewritten atomically on every change, which
 * is appropriate for the few hundred records an internal portal holds. Swap in a
 * database-backed {@link CredentialStore} if that stops being true.
 *
 * <p>This class is not thread-safe on its own; {@link AuthenticationService}
 * synchronizes access to it.
 */
public final class FileCredentialStore implements CredentialStore {

    private static final String DELIMITER = "\t";
    private static final int FIELD_COUNT = 5;

    private final Path file;
    private final Map<String, EmployeeRecord> records = new LinkedHashMap<>();

    public FileCredentialStore(Path file) throws IOException {
        this.file = file.toAbsolutePath();
        load();
    }

    private void load() throws IOException {
        if (!Files.exists(file)) {
            return;
        }
        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.isBlank() || line.startsWith("#")) {
                continue;
            }
            String[] fields = line.split(DELIMITER, -1);
            if (fields.length != FIELD_COUNT) {
                throw new IOException(file + ":" + (i + 1) + ": expected " + FIELD_COUNT
                        + " tab-separated fields but found " + fields.length);
            }
            EmployeeRecord record = new EmployeeRecord(
                    fields[0], fields[1], fields[2], fields[3], Boolean.parseBoolean(fields[4]));
            records.put(record.username(), record);
        }
    }

    @Override
    public Optional<EmployeeRecord> find(String username) {
        if (username == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(records.get(EmployeeRecord.normalizeUsername(username)));
    }

    @Override
    public void save(EmployeeRecord record) {
        records.put(record.username(), record);
        try {
            flush();
        } catch (IOException e) {
            throw new UncheckedIOException("Could not persist credential store " + file, e);
        }
    }

    @Override
    public int size() {
        return records.size();
    }

    /** Writes to a temporary file and renames it, so a crash cannot truncate the store. */
    private void flush() throws IOException {
        Path dir = file.getParent() == null ? Path.of(".") : file.getParent();
        Files.createDirectories(dir);
        List<String> lines = new ArrayList<>(records.size() + 1);
        lines.add("# username\tpasswordHash\tdisplayName\trole\tactive");
        for (EmployeeRecord r : records.values()) {
            lines.add(String.join(DELIMITER, r.username(), r.passwordHash(),
                    r.displayName(), r.role(), Boolean.toString(r.active())));
        }
        Path temp = Files.createTempFile(dir, ".employees", ".tmp");
        try {
            restrictPermissions(temp);
            Files.write(temp, lines, StandardCharsets.UTF_8);
            Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    /** Best-effort owner-only file mode; silently skipped on non-POSIX filesystems. */
    private static void restrictPermissions(Path path) {
        Set<PosixFilePermission> ownerOnly =
                PosixFilePermissions.fromString("rw-------");
        try {
            Files.setPosixFilePermissions(path, ownerOnly);
        } catch (IOException | UnsupportedOperationException e) {
            // Not a POSIX filesystem: leave the platform default in place.
        }
    }
}
