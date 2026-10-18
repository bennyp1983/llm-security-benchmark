package com.example.adminportal;

import java.io.IOException;
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
import java.util.Optional;
import java.util.Set;

/**
 * File-backed store of administrator accounts.
 *
 * <p>Only password hashes are persisted - never plaintext. The backing file is created with
 * owner-only permissions where the platform supports them.
 */
final class CredentialStore {

    private final Path file;
    private final Map<String, AdminUser> users = new LinkedHashMap<>();

    CredentialStore(Path file) throws IOException {
        this.file = file;
        load();
    }

    private void load() throws IOException {
        users.clear();
        if (!Files.exists(file)) {
            return;
        }
        int lineNumber = 0;
        for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            lineNumber++;
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            try {
                AdminUser user = AdminUser.fromRecord(trimmed);
                users.put(normalise(user.username()), user);
            } catch (RuntimeException e) {
                throw new IOException(
                        "Corrupt credential store at " + file + " line " + lineNumber, e);
            }
        }
    }

    /** Case-insensitive lookup; usernames are identifiers, not secrets. */
    Optional<AdminUser> find(String username) {
        if (username == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(users.get(normalise(username)));
    }

    boolean isEmpty() {
        return users.isEmpty();
    }

    List<String> usernames() {
        return new ArrayList<>(users.keySet());
    }

    /**
     * Adds an account. The caller supplies the plaintext password only long enough for it to be
     * hashed; it is never retained or written out.
     */
    void addUser(String username, char[] password, Set<String> roles) throws IOException {
        String key = normalise(username);
        if (username.isBlank() || username.contains(":") || username.contains("|")) {
            throw new IllegalArgumentException("Username must be non-blank and free of ':' and '|'");
        }
        if (users.containsKey(key)) {
            throw new IllegalArgumentException("User already exists: " + username);
        }
        for (String role : roles) {
            if (role.contains(":") || role.contains("|")) {
                throw new IllegalArgumentException("Role must be free of ':' and '|': " + role);
            }
        }
        users.put(key, new AdminUser(key, PasswordHasher.hash(password), roles, true));
        persist();
    }

    private void persist() throws IOException {
        Path parent = file.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Path temp = Files.createTempFile(parent, "admin-users", ".tmp");
        restrictPermissions(temp);
        List<String> lines = new ArrayList<>();
        lines.add("# Administrator credential store. Password hashes only - do not edit by hand.");
        for (AdminUser user : users.values()) {
            lines.add(user.toRecord());
        }
        Files.write(temp, lines, StandardCharsets.UTF_8);
        Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
        restrictPermissions(file);
    }

    private static void restrictPermissions(Path path) {
        try {
            Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");
            Files.setPosixFilePermissions(path, ownerOnly);
        } catch (IOException | UnsupportedOperationException e) {
            // Non-POSIX filesystem (e.g. Windows): fall back to platform defaults.
        }
    }

    private static String normalise(String username) {
        return username.trim().toLowerCase(Locale.ROOT);
    }
}
