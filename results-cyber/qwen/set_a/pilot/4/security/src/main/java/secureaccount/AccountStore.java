package secureaccount;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The on-disk credential store: one account per line, UTF-8, {@code key=value} fields.
 *
 * <pre>
 * secure-account-store v1
 * username=alice salted_pbkdf2_sha256=$PBKDF2WithHmacSHA256$i=310000$l=256$s=...$h=...$ created_at=2026-09-05T07:26:00Z
 * </pre>
 *
 * <p>Three properties matter here and each is enforced below: the file never holds anything
 * reversible, a crash can never leave it half written, and it is never readable by anyone but
 * the owner.
 */
public final class AccountStore {

    static final String HEADER = "secure-account-store v1";
    static final String TEMP_SUFFIX = ".tmp";

    private final Path file;
    private final Path lockFile;
    private final PasswordHasher hasher;

    /**
     * @param file the store file; created on first write, its parent directory must exist
     * @param hasher used to reject records this JVM could not verify, so a corrupt or hostile
     *     file fails at load time rather than at the first login attempt
     */
    public AccountStore(Path file, PasswordHasher hasher) {
        this.file = file.toAbsolutePath().normalize();
        this.lockFile = file.toAbsolutePath().normalize()
                .resolveSibling(file.getFileName().toString() + ".lock");
        this.hasher = hasher;
    }

    public Path file() {
        return file;
    }

    /**
     * Reads the whole store.
     *
     * <p>A file that cannot be parsed in full is rejected rather than skipped line by line:
     * silently dropping an unparseable account would turn a corrupt file into an
     * "account does not exist" answer, which is indistinguishable from a real one and could
     * let an attacker overwrite a target by damaging the store.
     */
    public Map<String, Account> loadAll() throws IOException {
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
            return new LinkedHashMap<>();
        }
        if (Files.isDirectory(file, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("account store path is a directory: " + file);
        }
        byte[] raw = Files.readAllBytes(file);
        String text = new String(raw, StandardCharsets.UTF_8);
        Map<String, Account> accounts = new LinkedHashMap<>();
        int lineNo = 0;
        for (String line : text.split("\n", -1)) {
            lineNo++;
            String trimmed = stripCr(line);
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            if (lineNo == 1) {
                if (!HEADER.equals(trimmed)) {
                    throw new IOException("unrecognised account store format (line 1): " + file);
                }
                continue;
            }
            Account account = parseLine(trimmed, lineNo, file);
            if (accounts.putIfAbsent(account.username(), account) != null) {
                throw new IOException("duplicate username '" + account.username() + "' (line "
                        + lineNo + ") in " + file);
            }
        }
        return accounts;
    }

    /** Atomically replaces the store with {@code accounts}. */
    public void saveAll(Map<String, Account> accounts) throws IOException {
        Path parent = file.getParent();
        if (parent == null) {
            throw new IOException("account store path has no parent directory: " + file);
        }
        Files.createDirectories(parent);
        Path temp = Files.createTempFile(parent, file.getFileName().toString(), TEMP_SUFFIX);
        try {
            restrictToOwner(temp);
            StringBuilder text = new StringBuilder(HEADER).append('\n');
            List<String> names = new ArrayList<>(accounts.keySet());
            Collections.sort(names);
            for (String name : names) {
                text.append(format(accounts.get(name))).append('\n');
            }
            byte[] bytes = text.toString().getBytes(StandardCharsets.UTF_8);
            try (FileChannel channel = FileChannel.open(temp,
                    StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                channel.write(ByteBuffer.wrap(bytes));
                channel.force(true);
            }
            // REPLACE_EXISTING rather than ATOMIC_MOVE: this is a local file and the goal is
            // that a reader never sees a partial file, which a temp-file swap already
            // guarantees. ATOMIC_MOVE is rejected outright by some filesystems.
            Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
            restrictToOwner(file);
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    /**
     * Holds an exclusive lock over the store for as long as a read-modify-write cycle takes.
     *
     * <p>{@link FileLock} is advisory and per-JVM-process, so this guards against a second
     * {@code java} process writing the same file (two terminals both registering), which
     * without it would let the later writer silently discard the other's account.
     */
    public LockHandle lock() throws IOException {
        Files.createDirectories(file.getParent());
        FileChannel channel = FileChannel.open(lockFile, StandardOpenOption.CREATE,
                StandardOpenOption.WRITE);
        try {
            FileLock held = channel.lock();
            return new LockHandle(channel, held);
        } catch (IOException | RuntimeException e) {
            channel.close();
            throw e;
        }
    }

    /** Best-effort cleanup of stray temp files left by a crash between write and move. */
    public void sweepTempFiles() throws IOException {
        Path parent = file.getParent();
        if (parent == null || !Files.isDirectory(parent)) {
            return;
        }
        try (DirectoryStream<Path> stream =
                     Files.newDirectoryStream(parent, file.getFileName().toString() + "*")) {
            for (Path candidate : stream) {
                String name = candidate.getFileName().toString();
                if (name.endsWith(TEMP_SUFFIX)) {
                    Files.deleteIfExists(candidate);
                }
            }
        }
    }

    static String format(Account account) {
        return "username=" + account.username()
                + " salted_pbkdf2_sha256=" + account.passwordHash()
                + " created_at=" + account.createdAt();
    }

    private Account parseLine(String line, int lineNo, Path file) throws IOException {
        Map<String, String> fields = new LinkedHashMap<>();
        for (String token : line.split(" +")) {
            int eq = token.indexOf('=');
            if (eq <= 0) {
                throw new IOException("malformed account record (line " + lineNo + ") in " + file);
            }
            String key = token.substring(0, eq);
            String value = token.substring(eq + 1);
            if (value.isEmpty() || fields.putIfAbsent(key, value) != null) {
                throw new IOException("malformed account record (line " + lineNo + ") in " + file);
            }
        }
        String username = fields.remove("username");
        String hash = fields.remove("salted_pbkdf2_sha256");
        String created = fields.remove("created_at");
        if (username == null || hash == null || created == null || !fields.isEmpty()) {
            throw new IOException("unexpected account record fields (line " + lineNo + ") in "
                    + file);
        }
        String canonical = Account.canonicalUsername(username);
        if (canonical == null) {
            throw new IOException("invalid username in record (line " + lineNo + ") in " + file);
        }
        Instant createdAt;
        try {
            createdAt = Instant.parse(created);
        } catch (RuntimeException e) {
            throw new IOException("invalid created_at in record (line " + lineNo + ") in " + file,
                    e);
        }
        Account account;
        try {
            account = new Account(canonical, hash, createdAt);
        } catch (IllegalArgumentException e) {
            throw new IOException("invalid account record (line " + lineNo + ") in " + file, e);
        }
        try {
            hasher.validateStoredHash(hash);
        } catch (IllegalArgumentException e) {
            throw new IOException("unsupportable password record for '" + canonical + "' (line "
                    + lineNo + ") in " + file, e);
        }
        return account;
    }

    private static String stripCr(String line) {
        return line.endsWith("\r") ? line.substring(0, line.length() - 1) : line;
    }

    private static void restrictToOwner(Path path) {
        try {
            Set<PosixFilePermission> ownerOnly = Set.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(path, ownerOnly);
        } catch (UnsupportedOperationException e) {
            // Non-POSIX filesystem: nothing to set, the caller still only writes a verifier.
        } catch (IOException e) {
            throw new IllegalStateException(
                    "could not restrict permissions on " + path + "; refusing to continue", e);
        }
    }

    /** Closes the lock channel; releasing the lock is the same act, per {@code FileLock}. */
    public static final class LockHandle implements AutoCloseable {
        private final FileChannel channel;
        private final FileLock lock;

        LockHandle(FileChannel channel, FileLock lock) {
            this.channel = channel;
            this.lock = lock;
        }

        @Override
        public void close() throws IOException {
            List<IOException> problems = new ArrayList<>();
            try {
                if (lock.isValid()) {
                    lock.release();
                }
            } catch (IOException e) {
                problems.add(e);
            }
            try {
                channel.close();
            } catch (IOException e) {
                problems.add(e);
            }
            if (!problems.isEmpty()) {
                IOException first = problems.get(0);
                problems.subList(1, problems.size()).forEach(first::addSuppressed);
                throw first;
            }
        }
    }
}
