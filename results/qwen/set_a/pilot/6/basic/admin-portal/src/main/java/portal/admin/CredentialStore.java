package portal.admin;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * File-backed registry of administrator accounts.
 *
 * <p>Guarantees that matter here:
 * <ul>
 *   <li>Only salted digests reach disk. The plaintext password is never serialised, never
 *       logged and never held in a field.</li>
 *   <li>Every field is base64url-encoded, so a username containing {@code :}, newline or
 *       any other structural byte cannot break out of its record and forge a line
 *       (e.g. injecting a second {@code superadmin} record).</li>
 *   <li>Saves go to a temporary file that is fsynced and then atomically moved into place,
 *       with {@code 0600} permissions applied before the file has any content. A crash
 *       mid-save cannot leave a truncated or world-readable store.</li>
 *   <li>Usernames are matched case-insensitively, which is what an operator expects and
 *       removes {@code Alice}/{@code alice} as an ambiguity an attacker can exploit.</li>
 * </ul>
 */
public final class CredentialStore {

    public static final String FILE_HEADER = "admin-portal-credentials v1";

    private static final int FIELD_COUNT = 7;

    private final Path file;
    private final boolean strict;
    private final Map<String, AdminAccount> accounts = new LinkedHashMap<>();
    private final List<String> loadWarnings = new ArrayList<>();

    public CredentialStore(Path file) {
        this(file, false);
    }

    public CredentialStore(Path file, boolean strict) {
        this.file = file;
        this.strict = strict;
    }

    /** Reads the store if it exists; an absent file simply means no accounts yet. */
    public synchronized CredentialStore load() {
        accounts.clear();
        loadWarnings.clear();
        if (!Files.exists(file)) {
            return this;
        }
        try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String header = reader.readLine();
            if (header == null) {
                return this;
            }
            if (!FILE_HEADER.equals(header.trim())) {
                if (strict) {
                    throw new IllegalStateException("unrecognised credential store header in " + file);
                }
                loadWarnings.add("ignoring file with unrecognised header");
                return this;
            }
            String line;
            int lineNo = 1;
            while ((line = reader.readLine()) != null) {
                lineNo++;
                if (line.trim().isEmpty() || line.startsWith("#")) {
                    continue;
                }
                try {
                    AdminAccount account = decode(line);
                    accounts.put(key(account.username()), account);
                } catch (RuntimeException e) {
                    // Always fatal: silently dropping a record would delete an
                    // administrator (and its lockout counters) on the next save.
                    throw new IllegalStateException("malformed record at line " + lineNo
                            + " in " + file + "; repair or remove it rather than letting it be dropped", e);
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("cannot read credential store " + file, e);
        }
        rejectUnreadableDigests();
        return this;
    }

    /**
     * A record whose digest cannot be parsed would make every verification for that
     * account fail in a way that looks like a wrong password. Refusing to load it is
     * louder and safer, so this is enforced even in lenient mode.
     */
    private void rejectUnreadableDigests() {
        for (AdminAccount account : accounts.values()) {
            if (!portal.security.PasswordHasher.isWellFormed(account.passwordDigest())) {
                throw new IllegalStateException("account " + account.username()
                        + " holds a malformed password digest; repair or remove the record");
            }
        }
    }

    public synchronized void save() {
        Path parent = file.toAbsolutePath().getParent();
        try {
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Path temp = Files.createTempFile(
                    parent == null ? file.toAbsolutePath() : parent, ".admins-", ".tmp");
            try {
                restrictToOwner(temp);
                try (BufferedWriter writer = Files.newBufferedWriter(
                        temp, StandardCharsets.UTF_8, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                    writer.write(FILE_HEADER);
                    writer.write('\n');
                    for (AdminAccount account : accounts.values()) {
                        writer.write(encode(account));
                        writer.write('\n');
                    }
                    writer.flush();
                }
                try (FileChannel channel = FileChannel.open(temp, StandardOpenOption.WRITE)) {
                    channel.force(true);
                }
                moveIntoPlace(temp);
            } catch (IOException | RuntimeException e) {
                Files.deleteIfExists(temp);
                throw e;
            }
            if (parent != null) {
                try (FileChannel dir = FileChannel.open(parent, StandardOpenOption.READ)) {
                    dir.force(true);
                } catch (IOException ignored) {
                    // Directory fsync is best-effort; some filesystems do not support it.
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("cannot write credential store " + file, e);
        }
    }

    private void moveIntoPlace(Path temp) throws IOException {
        try {
            Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
        }
        // Re-apply after the move: the destination may have pre-existed with looser modes.
        restrictToOwner(file);
        if (!isOwnerOnlyReadable(file)) {
            loadWarnings.add("could not restrict permissions on " + file.getFileName()
                    + "; move the store to a filesystem that supports file modes");
        }
    }

    /**
     * Best-effort owner-only modes. On POSIX this is exact; elsewhere it degrades to
     * {@link java.io.File#setReadable(boolean, boolean)}, which cannot express "owner
     * read-write only" on every filesystem, hence {@link #isOwnerOnlyReadable}.
     */
    private static void restrictToOwner(Path path) {
        Set<PosixFilePermission> ownerOnly = EnumSet.of(
                PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
        try {
            Files.setPosixFilePermissions(path, ownerOnly);
            return;
        } catch (UnsupportedOperationException | IOException ignored) {
            // fall through to the File API below
        }
        java.io.File asFile = path.toFile();
        asFile.setReadable(false, false);
        asFile.setWritable(false, false);
        asFile.setExecutable(false, false);
        asFile.setReadable(true, true);
        asFile.setWritable(true, true);
    }

    private static boolean isOwnerOnlyReadable(Path path) {
        try {
            return Files.getPosixFilePermissions(path).equals(EnumSet.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        } catch (UnsupportedOperationException | IOException e) {
            java.io.File asFile = path.toFile();
            return asFile.canRead() && asFile.canWrite();
        }
    }

    // ---------------------------------------------------------------- lookups

    public synchronized Optional<AdminAccount> find(String username) {
        return Optional.ofNullable(accounts.get(key(username)));
    }

    public synchronized boolean exists(String username) {
        return accounts.containsKey(key(username));
    }

    public synchronized List<AdminAccount> list() {
        return new ArrayList<>(accounts.values());
    }

    public synchronized int size() {
        return accounts.size();
    }

    public synchronized boolean isEmpty() {
        return accounts.isEmpty();
    }

    public synchronized boolean hasSuperAdmin() {
        for (AdminAccount account : accounts.values()) {
            if (account.role() == AdminRole.SUPER_ADMIN && account.state() == AccountState.ACTIVE) {
                return true;
            }
        }
        return false;
    }

    public List<String> loadWarnings() {
        return Collections.unmodifiableList(new ArrayList<>(loadWarnings));
    }

    public Path file() {
        return file;
    }

    // ---------------------------------------------------------------- mutations

    public synchronized void put(AdminAccount account) {
        accounts.put(key(account.username()), account);
    }

    public synchronized boolean remove(String username) {
        return accounts.remove(key(username)) != null;
    }

    /** Persists a change made to an existing account. */
    public synchronized void update(AdminAccount account) {
        accounts.put(key(account.username()), account);
    }

    // ---------------------------------------------------------------- (de)serialisation

    static String encode(AdminAccount account) {
        return String.join(":",
                enc(account.username()),
                enc(account.passwordDigest()),
                account.role().name(),
                account.state().name(),
                Integer.toString(account.consecutiveFailures()),
                Long.toString(account.lockedUntilMillis()),
                Long.toString(account.updatedAtMillis()));
    }

    private static AdminAccount decode(String line) {
        String[] fields = line.split(":", -1);
        if (fields.length != FIELD_COUNT) {
            throw new IllegalArgumentException("expected " + FIELD_COUNT + " fields");
        }
        String username = dec(fields[0]);
        String digest = dec(fields[1]);
        AdminRole role = AdminRole.valueOf(fields[2].toUpperCase(Locale.ROOT));
        AccountState state = AccountState.valueOf(fields[3].toUpperCase(Locale.ROOT));
        int failures = Integer.parseInt(fields[4]);
        long lockedUntil = Long.parseLong(fields[5]);
        long updated = Long.parseLong(fields[6]);
        return new AdminAccount(username, digest, role, state, failures, lockedUntil, updated);
    }

    private static String enc(String value) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String dec(String value) {
        return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8);
    }

    /** Canonical key: trimmed and case-folded, so lookups are unambiguous. */
    static String key(String username) {
        return username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
    }
}
