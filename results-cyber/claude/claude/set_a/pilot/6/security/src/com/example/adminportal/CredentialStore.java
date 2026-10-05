package com.example.adminportal;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * File-backed store of administrator accounts.
 *
 * Only salted PBKDF2 hashes are persisted, and the file is created with
 * owner-only permissions. Usernames are matched case-insensitively but stored
 * as first registered.
 *
 * Line format: username:role:enabled:encodedHash
 */
public final class CredentialStore {

    private static final Set<PosixFilePermission> OWNER_ONLY =
            PosixFilePermissions.fromString("rw-------");

    private final Path file;
    private final Map<String, AdminUser> users = new LinkedHashMap<>();

    public CredentialStore(Path file) throws IOException {
        this.file = file.toAbsolutePath();
        load();
    }

    /** Looks up an account by username, ignoring case. */
    public synchronized Optional<AdminUser> find(String username) {
        if (username == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(users.get(normalize(username)));
    }

    /** Registers a new account. The caller-supplied password is hashed, never stored. */
    public synchronized void addUser(String username, char[] password, AdminUser.Role role)
            throws IOException {
        String key = normalize(username);
        if (key.isEmpty() || !key.matches("[a-z0-9._-]{3,64}")) {
            throw new IllegalArgumentException(
                    "Username must be 3-64 characters of letters, digits, dot, underscore or hyphen");
        }
        if (users.containsKey(key)) {
            throw new IllegalArgumentException("Account already exists");
        }
        PasswordPolicy.requireAcceptable(username, password);
        users.put(key, new AdminUser(username.trim(), PasswordHasher.hash(password), role, true));
        save();
    }

    /** Enables or disables an account without deleting its history. */
    public synchronized boolean setEnabled(String username, boolean enabled) throws IOException {
        AdminUser existing = users.get(normalize(username));
        if (existing == null) {
            return false;
        }
        users.put(normalize(username), new AdminUser(existing.username(),
                existing.passwordHash(), existing.role(), enabled));
        save();
        return true;
    }

    /** Account names and roles, for display. Hashes are deliberately excluded. */
    public synchronized List<AdminUser> list() {
        return new ArrayList<>(users.values());
    }

    public synchronized boolean isEmpty() {
        return users.isEmpty();
    }

    public Path location() {
        return file;
    }

    private void load() throws IOException {
        if (!Files.exists(file)) {
            return;
        }
        int lineNumber = 0;
        for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            lineNumber++;
            if (line.isBlank() || line.startsWith("#")) {
                continue;
            }
            String[] parts = line.split(":", 4);
            if (parts.length != 4) {
                throw new IOException("Malformed credential record at line " + lineNumber);
            }
            AdminUser.Role role;
            try {
                role = AdminUser.Role.valueOf(parts[1].trim().toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException e) {
                throw new IOException("Unknown role at line " + lineNumber + ": " + parts[1]);
            }
            AdminUser user = new AdminUser(parts[0].trim(), parts[3].trim(), role,
                    Boolean.parseBoolean(parts[2].trim()));
            users.put(normalize(user.username()), user);
        }
    }

    private void save() throws IOException {
        StringBuilder sb = new StringBuilder("# username:role:enabled:pbkdf2-hash\n");
        for (AdminUser user : users.values()) {
            sb.append(user.username()).append(':')
              .append(user.role().name()).append(':')
              .append(user.enabled()).append(':')
              .append(user.passwordHash()).append('\n');
        }
        Path parent = file.getParent();
        if (parent != null && !Files.exists(parent)) {
            Files.createDirectories(parent);
        }
        // Write to a temporary file first so a crash cannot leave a truncated store.
        Path temp = file.resolveSibling(file.getFileName() + ".tmp");
        Files.writeString(temp, sb.toString(), StandardCharsets.UTF_8);
        trySetPermissions(temp);
        Files.move(temp, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        trySetPermissions(file);
    }

    private static void trySetPermissions(Path path) {
        try {
            Files.setPosixFilePermissions(path, EnumSet.copyOf(OWNER_ONLY));
        } catch (UnsupportedOperationException | IOException e) {
            // Non-POSIX filesystem; platform defaults apply.
        }
    }

    private static String normalize(String username) {
        return username.trim().toLowerCase(Locale.ROOT);
    }
}
