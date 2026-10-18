package accounts;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * A file-backed store of {@link UserAccount}s.
 *
 * The whole store is small enough to keep in memory; it is loaded once at
 * construction and rewritten atomically on every change so a crash mid-write
 * cannot truncate the credential file.
 */
public final class AccountStore {

    private static final int MIN_USERNAME_LENGTH = 3;
    private static final int MAX_USERNAME_LENGTH = 32;
    private static final int MIN_PASSWORD_LENGTH = 8;

    private final Path file;
    /** Keyed by lower-cased username so logins are case-insensitive. */
    private final Map<String, UserAccount> accounts = new LinkedHashMap<>();

    public AccountStore(Path file) throws IOException {
        this.file = file;
        load();
    }

    private void load() throws IOException {
        if (!Files.exists(file)) {
            return;
        }
        for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            UserAccount account = UserAccount.fromRecord(trimmed);
            accounts.put(key(account.username()), account);
        }
    }

    private void save() {
        List<String> lines = new ArrayList<>(accounts.size());
        for (UserAccount account : accounts.values()) {
            lines.add(account.toRecord());
        }
        try {
            Path parent = file.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Path temp = Files.createTempFile(parent, "accounts", ".tmp");
            Files.write(temp, lines, StandardCharsets.UTF_8);
            restrictPermissions(temp);
            Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not write credential file " + file, e);
        }
    }

    /** Best effort: on POSIX systems the credential file is owner-readable only. */
    private static void restrictPermissions(Path path) {
        try {
            Files.setPosixFilePermissions(path, Set.of(
                    java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                    java.nio.file.attribute.PosixFilePermission.OWNER_WRITE));
        } catch (IOException | UnsupportedOperationException ignored) {
            // Non-POSIX filesystem; nothing else to do.
        }
    }

    private static String key(String username) {
        return username.toLowerCase(Locale.ROOT);
    }

    public boolean exists(String username) {
        return username != null && accounts.containsKey(key(username));
    }

    public int size() {
        return accounts.size();
    }

    /**
     * Registers a new account and persists it.
     *
     * @throws IllegalArgumentException if the credentials fail validation
     * @throws IllegalStateException    if the username is already taken
     */
    public UserAccount register(String username, char[] password) {
        validateUsername(username);
        validatePassword(username, password);
        if (exists(username)) {
            throw new IllegalStateException("Username '" + username + "' is already taken.");
        }
        UserAccount account = UserAccount.create(username, password);
        accounts.put(key(username), account);
        save();
        return account;
    }

    /**
     * Verifies a username/password pair.
     *
     * @return the matching account, or empty if the username is unknown or the
     *         password is wrong (the caller cannot tell the two cases apart)
     */
    public Optional<UserAccount> authenticate(String username, char[] password) {
        if (username == null || password == null) {
            return Optional.empty();
        }
        UserAccount account = accounts.get(key(username));
        if (account == null) {
            // Spend comparable time on unknown users so response timing does not
            // reveal which usernames exist.
            PasswordHasher.hash(password, PasswordHasher.newSalt(), PasswordHasher.DEFAULT_ITERATIONS);
            return Optional.empty();
        }
        return account.verify(password) ? Optional.of(account) : Optional.empty();
    }

    static void validateUsername(String username) {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("Username must not be empty.");
        }
        if (username.length() < MIN_USERNAME_LENGTH || username.length() > MAX_USERNAME_LENGTH) {
            throw new IllegalArgumentException(
                    "Username must be between " + MIN_USERNAME_LENGTH + " and " + MAX_USERNAME_LENGTH + " characters.");
        }
        if (!username.matches("[A-Za-z0-9._-]+")) {
            throw new IllegalArgumentException(
                    "Username may only contain letters, digits, '.', '_' and '-'.");
        }
    }

    static void validatePassword(String username, char[] password) {
        if (password == null || password.length < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be at least " + MIN_PASSWORD_LENGTH + " characters long.");
        }
        String asText = new String(password);
        if (asText.isBlank()) {
            throw new IllegalArgumentException("Password must not be only whitespace.");
        }
        if (username != null && asText.equalsIgnoreCase(username)) {
            throw new IllegalArgumentException("Password must not be the same as the username.");
        }
    }
}
