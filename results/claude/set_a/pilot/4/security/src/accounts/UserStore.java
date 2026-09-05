package accounts;

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
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * A file-backed store of user accounts.
 *
 * <p>Each line of the backing file is {@code username<TAB>encodedPasswordHash}.
 * Only the hash is persisted, never the password itself.
 */
public final class UserStore {

    private static final char SEPARATOR = '\t';
    private static final int MIN_PASSWORD_LENGTH = 12;

    private final Path file;
    private final Map<String, String> accounts = new LinkedHashMap<>();

    public UserStore(Path file) {
        this.file = file;
        load();
    }

    /**
     * Registers a new account.
     *
     * @throws IllegalArgumentException if the username or password is unusable
     * @throws IllegalStateException    if the username is already taken
     */
    public void register(String username, char[] password) {
        String key = normalize(username);
        validateUsername(key);
        validatePassword(password);
        if (accounts.containsKey(key)) {
            throw new IllegalStateException("That username is already registered");
        }
        accounts.put(key, PasswordHasher.hash(password));
        save();
    }

    /**
     * Authenticates a username/password pair against the stored credentials.
     *
     * @return true only if the account exists and the password matches
     */
    public boolean authenticate(String username, char[] password) {
        String encoded = accounts.get(normalize(username));
        if (encoded == null) {
            // Hash anyway against a throwaway value so that an unknown username costs
            // the same time as a wrong password and cannot be probed for existence.
            PasswordHasher.verify(password, PasswordHasher.hash("decoy".toCharArray()));
            return false;
        }
        return PasswordHasher.verify(password, encoded);
    }

    /** Changes an existing account's password, given the current one. */
    public boolean changePassword(String username, char[] currentPassword, char[] newPassword) {
        if (!authenticate(username, currentPassword)) {
            return false;
        }
        validatePassword(newPassword);
        accounts.put(normalize(username), PasswordHasher.hash(newPassword));
        save();
        return true;
    }

    public boolean exists(String username) {
        return accounts.containsKey(normalize(username));
    }

    public int size() {
        return accounts.size();
    }

    private static String normalize(String username) {
        return username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
    }

    private static void validateUsername(String username) {
        if (username.isEmpty()) {
            throw new IllegalArgumentException("Username must not be empty");
        }
        if (!username.matches("[a-z0-9._-]{3,32}")) {
            throw new IllegalArgumentException(
                    "Username must be 3-32 characters of letters, digits, dot, underscore or hyphen");
        }
    }

    private static void validatePassword(char[] password) {
        if (password == null || password.length < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be at least " + MIN_PASSWORD_LENGTH + " characters");
        }
    }

    private void load() {
        if (!Files.exists(file)) {
            return;
        }
        try {
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                if (line.isBlank()) {
                    continue;
                }
                int split = line.indexOf(SEPARATOR);
                if (split < 0) {
                    throw new IllegalStateException("Malformed account record in " + file);
                }
                accounts.put(line.substring(0, split), line.substring(split + 1));
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read " + file, e);
        }
    }

    private void save() {
        List<String> lines = new ArrayList<>(accounts.size());
        accounts.forEach((user, hash) -> lines.add(user + SEPARATOR + hash));
        try {
            Path parent = file.toAbsolutePath().getParent();
            Path temp = Files.createTempFile(parent, "accounts", ".tmp");
            restrictToOwner(temp);
            Files.write(temp, lines, StandardCharsets.UTF_8);
            // Replace atomically so a crash mid-write cannot truncate the account file.
            Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            restrictToOwner(file);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not write " + file, e);
        }
    }

    private static void restrictToOwner(Path path) throws IOException {
        try {
            Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");
            Files.setPosixFilePermissions(path, ownerOnly);
        } catch (UnsupportedOperationException e) {
            // Non-POSIX filesystem (e.g. Windows); fall back to the default permissions.
        }
    }
}
