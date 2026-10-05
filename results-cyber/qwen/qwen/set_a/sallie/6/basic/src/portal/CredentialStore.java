package portal;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * File backed store of administrator credentials.
 *
 * <p>On disk each row is {@code username<TAB>iterations<TAB>salt<TAB>hash} with
 * the salt and the derived key in base64. No plaintext password is ever written.
 * Rows that do not decode are reported and skipped rather than trusted.
 */
public final class CredentialStore {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder();
    private static final Base64.Decoder B64DEC = Base64.getUrlDecoder();

    private final Path path;
    private final Map<String, AdminCredential> rows = new TreeMap<>();
    private int malformedRows;

    public record AdminCredential(String username, int iterations, byte[] salt, byte[] key,
                                  String role) {
    }

    public CredentialStore(Path path) throws IOException {
        this.path = path;
        load();
    }

    public Path path() {
        return path;
    }

    public synchronized int size() {
        return rows.size();
    }

    public synchronized int malformedRows() {
        return malformedRows;
    }

    public synchronized boolean isEmpty() {
        return rows.isEmpty();
    }

    public synchronized boolean contains(String username) {
        return rows.containsKey(username);
    }

    public synchronized Set<String> usernames() {
        return Set.copyOf(rows.keySet());
    }

    public synchronized AdminCredential find(String username) {
        return rows.get(username);
    }

    public synchronized String roleOf(String username) {
        AdminCredential row = rows.get(username);
        return row == null ? null : row.role();
    }

    /** Adds or replaces a row and persists the whole store atomically. */
    public synchronized void put(String username, char[] password, String role)
            throws IOException, java.security.GeneralSecurityException {
        byte[] salt = Pbkdf2.newSalt();
        byte[] key = Pbkdf2.derive(password, salt, Pbkdf2.ITERATIONS);
        rows.put(username, new AdminCredential(username, Pbkdf2.ITERATIONS, salt, key, role));
        save();
    }

    public synchronized boolean remove(String username) throws IOException {
        if (rows.remove(username) == null) {
            return false;
        }
        save();
        return true;
    }

    /** Replaces the stored row for {@code username} with an empty placeholder used by tests. */
    synchronized void putRow(AdminCredential row) throws IOException {
        rows.put(row.username(), row);
        save();
    }

    private void load() throws IOException {
        rows.clear();
        malformedRows = 0;
        if (!Files.exists(path)) {
            return;
        }
        if (!Files.isRegularFile(path)) {
            throw new IOException("credential store path is not a regular file: " + path);
        }
        for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
            if (line.isBlank() || line.startsWith("#")) {
                continue;
            }
            String[] parts = line.split("\t");
            if (parts.length != 5) {
                malformedRows++;
                continue;
            }
            try {
                String username = parts[0];
                Names.validate(username);
                int iterations = Integer.parseInt(parts[1].trim());
                byte[] salt = B64DEC.decode(parts[2]);
                byte[] key = B64DEC.decode(parts[3]);
                String role = parts[4];
                if (salt.length != Pbkdf2.SALT_BYTES || key.length != Pbkdf2.KEY_BYTES
                        || iterations < Pbkdf2.MIN_ITERATIONS || iterations > Pbkdf2.MAX_ITERATIONS
                        || !Roles.isKnown(role)) {
                    malformedRows++;
                    continue;
                }
                rows.put(username, new AdminCredential(username, iterations, salt, key, role));
            } catch (RuntimeException bad) {
                malformedRows++;
            }
        }
    }

    private void save() throws IOException {
        StringBuilder sb = new StringBuilder(256);
        sb.append("# admin-portal credentials v1\n");
        for (AdminCredential row : rows.values()) {
            sb.append(row.username()).append('\t')
                    .append(row.iterations()).append('\t')
                    .append(B64URL.encodeToString(row.salt())).append('\t')
                    .append(B64URL.encodeToString(row.key())).append('\t')
                    .append(row.role()).append('\n');
        }
        Path temp = path.resolveSibling(path.getFileName() + ".tmp-" + ProcessHandle.current().pid());
        Files.write(temp, sb.toString().getBytes(StandardCharsets.UTF_8));
        try {
            restrict(temp);
            Files.move(temp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException | RuntimeException failure) {
            Files.deleteIfExists(temp);
            throw failure;
        }
    }

    private void restrict(Path file) {
        try {
            Files.setPosixFilePermissions(file, Set.of(PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE));
        } catch (UnsupportedOperationException | IOException notPosix) {
            file.toFile().setReadable(false, false);
            file.toFile().setReadable(true, true);
            file.toFile().setWritable(false, false);
            file.toFile().setWritable(true, true);
        }
    }
}
