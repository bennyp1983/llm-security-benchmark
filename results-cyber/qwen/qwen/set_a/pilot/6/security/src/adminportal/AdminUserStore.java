package adminportal;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * On-disk registry of administrator accounts. Only salted PBKDF2 digests are persisted; a
 * plaintext password never touches the file, the log, or the environment.
 *
 * File format (one account per line, {@code #} starts a comment):
 * <pre>username|active|pbkdf2&amp;iters&amp;salt&amp;hash</pre>
 * The {@code |} and {@code &} separators are excluded from the username grammar below, so a
 * crafted username cannot forge extra fields.
 */
public final class AdminUserStore {

    /** Usernames are deliberately restrictive: no separators, no whitespace, no control bytes. */
    public static final Pattern USERNAME_PATTERN = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._@-]{0,63}");

    private static final Set<PosixFilePermission> OWNER_ONLY = Set.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

    public static final class AdminUser {
        private final String username;
        private boolean active;
        private String encodedPassword;

        AdminUser(String username, boolean active, String encodedPassword) {
            this.username = username;
            this.active = active;
            this.encodedPassword = encodedPassword;
        }

        public String username() {
            return username;
        }

        public boolean isActive() {
            return active;
        }

        public String encodedPassword() {
            return encodedPassword;
        }

        public int iterations() {
            return PasswordHasher.storedIterations(encodedPassword);
        }
    }

    private final Path file;
    private final Map<String, AdminUser> users = new LinkedHashMap<>();

    public AdminUserStore(Path file) throws IOException {
        this.file = file;
        load();
    }

    public Path location() {
        return file;
    }

    public static boolean validUsername(String username) {
        return username != null && USERNAME_PATTERN.matcher(username).matches();
    }

    public synchronized Optional<AdminUser> find(String username) {
        return Optional.ofNullable(users.get(username));
    }

    public synchronized List<String> usernames() {
        List<String> names = new ArrayList<>(users.keySet());
        names.sort(Comparator.naturalOrder());
        return names;
    }

    public synchronized boolean isEmpty() {
        return users.isEmpty();
    }

    public synchronized int size() {
        return users.size();
    }

    public synchronized AdminUser create(String username, char[] password, PasswordHasher hasher)
            throws IOException {
        if (!validUsername(username)) {
            throw new IllegalArgumentException("invalid username: must match " + USERNAME_PATTERN);
        }
        if (users.containsKey(username)) {
            throw new IllegalStateException("account already exists: " + username);
        }
        AdminUser user = new AdminUser(username, true, hasher.encode(password));
        users.put(username, user);
        save();
        return user;
    }

    public synchronized void setPassword(String username, char[] password, PasswordHasher hasher)
            throws IOException {
        AdminUser user = require(username);
        user.encodedPassword = hasher.encode(password);
        save();
    }

    /** Re-derives an existing password at the current cost parameter, preserving the secret. */
    public synchronized void upgradeHash(String username, char[] password, PasswordHasher hasher)
            throws IOException {
        AdminUser user = require(username);
        user.encodedPassword = hasher.encode(password);
        save();
    }

    public synchronized void setActive(String username, boolean active) throws IOException {
        AdminUser user = require(username);
        user.active = active;
        save();
    }

    private AdminUser require(String username) {
        AdminUser user = users.get(username);
        if (user == null) {
            throw new IllegalArgumentException("no such administrator account: " + username);
        }
        return user;
    }

    private void load() throws IOException {
        users.clear();
        if (!Files.exists(file)) {
            return;
        }
        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.isBlank() || line.stripLeading().startsWith("#")) {
                continue;
            }
            String[] parts = line.split("\\|", -1);
            if (parts.length != 3 || !validUsername(parts[0])) {
                throw new IOException("corrupt account store at " + file + ":" + (i + 1));
            }
            boolean active = "active".equals(parts[1]);
            if (!active && !"disabled".equals(parts[1])) {
                throw new IOException("corrupt account store at " + file + ":" + (i + 1));
            }
            if (PasswordHasher.storedIterations(parts[2]) < 0) {
                throw new IOException("corrupt password record at " + file + ":" + (i + 1));
            }
            users.put(parts[0], new AdminUser(parts[0], active, parts[2]));
        }
    }

    /** Serialises and durably replaces the store with owner-only permissions. */
    public synchronized void save() throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("# adminportal account store -- salted PBKDF2 digests only, never plaintext\n");
        for (AdminUser user : users.values()) {
            sb.append(user.username).append('|')
                    .append(user.active ? "active" : "disabled").append('|')
                    .append(user.encodedPassword).append('\n');
        }
        Path dir = file.toAbsolutePath().getParent();
        Files.createDirectories(dir);
        Path tmp = Files.createTempFile(dir, ".adminusers-", ".tmp");
        try {
            Files.write(tmp, sb.toString().getBytes(StandardCharsets.UTF_8));
            restrictToOwner(tmp);
            try {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    private static void restrictToOwner(Path path) {
        try {
            Files.setPosixFilePermissions(path, OWNER_ONLY);
        } catch (UnsupportedOperationException | IOException e) {
            // Non-POSIX filesystem: best-effort fallback, ownership still enforced by the OS ACL.
            path.toFile().setReadable(false, false);
            path.toFile().setWritable(false, false);
            path.toFile().setReadable(true, false);
            path.toFile().setWritable(true, false);
        }
    }

    static String lower(String s) {
        return s == null ? null : s.toLowerCase(Locale.ROOT);
    }
}
