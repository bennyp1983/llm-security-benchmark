import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * File backed account store. Each line is {@code username<TAB>storedVerifier}.
 *
 * <p>Only the verifier produced by {@link PasswordHasher} is persisted, never a password.
 * Rewrites go through a temporary file plus an atomic move so a crash cannot leave a
 * half-written store, and the file is narrowed to owner read/write on POSIX filesystems.
 */
public final class AccountStore {

    private static final char FIELD_SEPARATOR = '\t';

    private final Path file;
    private final Map<String, String> records = new LinkedHashMap<>();

    public AccountStore(Path file) {
        this.file = file.toAbsolutePath();
    }

    /** Reads the store from disk if it exists. A missing file simply means an empty store. */
    public AccountStore load() {
        records.clear();
        if (!Files.exists(file)) {
            return this;
        }
        java.util.List<String> lines;
        try {
            lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to read account store " + file, e);
        }
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.isEmpty()) {
                continue;
            }
            int sep = line.indexOf(FIELD_SEPARATOR);
            if (sep <= 0 || sep == line.length() - 1 || line.indexOf(FIELD_SEPARATOR, sep + 1) >= 0) {
                throw new IllegalStateException("Malformed account store " + file + " at line " + (i + 1));
            }
            String user = line.substring(0, sep);
            String verifier = line.substring(sep + 1);
            if (Usernames.normalize(user) == null || PasswordHasher.tryParse(verifier) == null) {
                throw new IllegalStateException("Malformed account store " + file + " at line " + (i + 1));
            }
            if (records.put(user, verifier) != null) {
                throw new IllegalStateException("Duplicate account in store " + file + " at line " + (i + 1));
            }
        }
        return this;
    }

    /** Verifier for {@code username}, or empty when there is no such account. */
    public Optional<String> verifierFor(String username) {
        return Optional.ofNullable(records.get(username));
    }

    public boolean contains(String username) {
        return records.containsKey(username);
    }

    public int size() {
        return records.size();
    }

    /**
     * Adds an account. Returns false without touching the store when the username is taken.
     */
    public boolean add(String username, String verifier) {
        if (PasswordHasher.tryParse(verifier) == null) {
            throw new IllegalArgumentException("refusing to store a malformed verifier");
        }
        if (records.containsKey(username)) {
            return false;
        }
        records.put(username, verifier);
        flush();
        return true;
    }

    /** Serialises the whole store and moves it into place. */
    public void flush() {
        StringBuilder text = new StringBuilder();
        for (Map.Entry<String, String> entry : records.entrySet()) {
            text.append(entry.getKey()).append(FIELD_SEPARATOR).append(entry.getValue()).append('\n');
        }
        Path temp = null;
        try {
            Path dir = file.getParent();
            if (dir != null) {
                Files.createDirectories(dir);
            }
            temp = Files.createTempFile(dir, file.getFileName().toString(), ".tmp");
            Files.write(temp, text.toString().getBytes(StandardCharsets.UTF_8));
            narrowPermissions(temp);
            try {
                Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
            }
            temp = null;
            narrowPermissions(file);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to write account store " + file, e);
        } finally {
            if (temp != null) {
                try {
                    Files.deleteIfExists(temp);
                } catch (IOException ignored) {
                    // Best effort clean-up of the temporary file.
                }
            }
        }
    }

    private static void narrowPermissions(Path path) {
        try {
            Set<PosixFilePermission> only = Set.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(path, only);
        } catch (UnsupportedOperationException | IOException e) {
            // Filesystem without POSIX permissions, or the file vanished: nothing else to do.
        }
    }

    public Path path() {
        return file;
    }

    /** Test hook: raw file text, so a test can prove no plaintext is ever written. */
    public String dumpRaw() {
        try {
            return Files.readString(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to read account store " + file, e);
        }
    }
}
