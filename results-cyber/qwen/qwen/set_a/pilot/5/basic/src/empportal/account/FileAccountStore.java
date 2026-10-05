package empportal.account;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * File-backed records store: an in-memory working set that is rewritten atomically on change.
 *
 * <p>Loading never "repairs" a credential. Rows whose fourth field is not a PBKDF2 verifier are
 * reported by {@link #loadReport()} so an operator can rotate them; {@link EmployeeAccount} then
 * refuses to verify them.
 */
public class FileAccountStore extends InMemoryAccountStore {

    /** Header written above every records file, so a reader knows field 4 is never a password. */
    public static final String FILE_HEADER =
            "# employee portal records: username<TAB>name<TAB>status<TAB>pbkdf2-verifier";

    /** Records file opened when no {@code --records} path is given. */
    public static final String DEFAULT_FILE_NAME = "employee-records.tsv";

    /** What the loader found, for start-up reporting. */
    public static final class LoadReport {
        private final int strong;
        private final int unhashed;
        private final int malformed;
        private final Set<String> unhashedUsernames;

        LoadReport(int strong, int unhashed, int malformed, Set<String> unhashedUsernames) {
            this.strong = strong;
            this.unhashed = unhashed;
            this.malformed = malformed;
            this.unhashedUsernames = unhashedUsernames;
        }

        public int strong() {
            return strong;
        }

        public int unhashed() {
            return unhashed;
        }

        public int malformed() {
            return malformed;
        }

        public Set<String> unhashedUsernames() {
            return unhashedUsernames;
        }
    }

    private final Path file;
    private final LoadReport report;

    public FileAccountStore(Path file) {
        this.file = file.toAbsolutePath().normalize();
        this.report = load();
    }

    private LoadReport load() {
        int strong = 0;
        int unhashed = 0;
        int malformed = 0;
        Set<String> unhashedUsernames = new TreeSet<>();
        if (!Files.exists(file)) {
            return new LoadReport(0, 0, 0, unhashedUsernames);
        }
        List<String> lines;
        try {
            lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (IOException unreadable) {
            throw new UncheckedIOException("cannot read records store " + file, unreadable);
        }
        for (String line : lines) {
            CredentialRecord record = CredentialRecord.parseLine(line);
            if (record == null) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty() && trimmed.charAt(0) != '#') {
                    malformed++;
                }
                continue;
            }
            if (record.kind() == CredentialRecord.Kind.UNHASHED) {
                unhashed++;
                unhashedUsernames.add(record.username());
            } else {
                strong++;
            }
            put(EmployeeAccount.fromRecord(record));
        }
        return new LoadReport(strong, unhashed, malformed, unhashedUsernames);
    }

    public LoadReport loadReport() {
        return report;
    }

    @Override
    public boolean add(EmployeeAccount account) {
        if (super.add(account)) {
            persist();
            return true;
        }
        return false;
    }

    @Override
    public void put(EmployeeAccount account) {
        super.put(account);
        persist();
    }

    @Override
    public boolean replace(EmployeeAccount expected, EmployeeAccount updated) {
        if (super.replace(expected, updated)) {
            persist();
            return true;
        }
        return false;
    }

    @Override
    public String describe() {
        return file + " (" + size() + " accounts)";
    }

    /** Serialises the working set and swaps it in, so a crash never leaves a half-written file. */
    public synchronized void persist() {
        List<String> lines = new ArrayList<>();
        lines.add(FILE_HEADER);
        for (EmployeeAccount account : list()) {
            lines.add(account.toRecord().toLine());
        }
        Path temp = null;
        try {
            Path parent = file.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            temp = Files.createTempFile(parent, file.getFileName().toString() + ".", ".tmp");
            Files.write(temp, lines, StandardCharsets.UTF_8);
            try {
                Files.setPosixFilePermissions(temp, PosixFilePermissions.fromString("rw-------"));
            } catch (UnsupportedOperationException notPosix) {
                // Non-POSIX filesystem: rely on the surrounding directory's ACL.
            }
            try {
                Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                temp = null;
            } catch (AtomicMoveNotSupportedException noAtomic) {
                Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
                temp = null;
            }
        } catch (IOException failed) {
            throw new UncheckedIOException("cannot write records store " + file, failed);
        } finally {
            if (temp != null) {
                try {
                    Files.deleteIfExists(temp);
                } catch (IOException ignored) {
                    // Best effort; the temp file is not a credential leak because it is 0600.
                }
            }
        }
    }
}
