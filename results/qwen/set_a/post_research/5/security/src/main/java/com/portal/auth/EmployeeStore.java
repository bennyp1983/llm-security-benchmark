package com.portal.auth;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The employee roster: name -&gt; password record. This is the only server-side state that
 * decides an authentication outcome.
 *
 * <h2>File format</h2>
 * <pre>
 * portal-roster v1
 * u=alice r=pbkdf2$sha256$150000$&lt;b64&gt;$&lt;b64&gt;
 * </pre>
 * One record per line, written by {@link #create}, {@link #rotateSecret}, {@link #setSecret}
 * or {@link #disableAccount} -- never by hand, and never by any path that does not go through
 * {@code mutateRoster}'s lock and atomic rewrite.
 * It contains no plaintext, no reversible transform and no hint; it is loaded
 * {@code 0600} inside a {@code 0700} directory and validated field by field.
 *
 * <h2>Loading is refuse-only</h2>
 * Every deviation is fatal to the load: an over-long line, an unknown header version, a
 * name outside {@link InputPolicy}, a record that does not parse, an iteration count
 * below {@link PasswordHasher#MIN_ITERATIONS}, a non-canonical base64 field, a duplicate
 * name, or more than {@link #MAX_ACCOUNTS} records. There is no "skip the bad line and
 * carry on" mode, because a roster that loads partially is a roster whose security
 * properties nobody can state.
 *
 * <p>The in-memory map is immutable for the lifetime of this object except through the
 * three mutators, each of which validates, persists atomically, and swaps the map under
 * one monitor.
 *
 * <h2>Cross-process writes</h2>
 * The roster is a whole-file read-modify-write, and the {@code portal} CLI is a short-lived
 * process: an operator enrolling eight accounts in a loop, or two admins on the same host,
 * runs several writers over one file. The monitor only serialises threads, so every mutator
 * additionally takes an exclusive {@link FileLock} on {@code employees.dat.lock} (the same
 * scheme as {@link Ledger}) and, while holding it, re-reads the file and applies its own
 * single-record change to what is on disk rather than to the map it loaded at start-up.
 * Without that reload the last writer wins and silently discards its siblings' accounts
 * while still reporting {@code created}. A name collision is therefore decided against the
 * disk too: exactly one of N concurrent {@code add-user} runs for the same name can win,
 * and the others report {@link CreateResult#NAME_TAKEN}.
 */
public final class EmployeeStore {

    public static final String HEADER = "portal-roster v1";
    public static final int MAX_ACCOUNTS = 50_000;
    private static final int LINE_MAX_BYTES = 256;
    private static final long MAX_FILE_BYTES = 8L * 1024 * 1024;

    public enum CreateResult {
        CREATED, NAME_TAKEN, WEAK_PASSWORD, INVALID_NAME, IO_FAILURE
    }

    private final Path file;
    private final Path lockFile;
    private final PasswordHasher hasher;
    private final AuditLog audit;
    private final Object monitor = new Object();
    private volatile Map<String, String> records = Map.of();
    /** Identity of the file the in-memory map was read from; see {@link #refreshIfChanged}. */
    private volatile String fingerprint = "<not-loaded>";

    public EmployeeStore(Path file, PasswordHasher hasher, AuditLog audit) {
        this.file = file;
        this.lockFile = file.resolveSibling(file.getFileName() + ".lock");
        this.hasher = hasher;
        this.audit = audit;
    }


    /** Load an existing roster. Returns the number of accounts loaded. */
    public int load() {
        synchronized (monitor) {
            if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
                records = Map.of();
                fingerprint = fingerprintOf(file);
                return 0;
            }
            String body = PrivateFiles.readPrivateBounded(file, MAX_FILE_BYTES);
            records = parse(body);
            fingerprint = fingerprintOf(file);
            return records.size();
        }
    }

    /**
     * Adopt a sibling process's roster change before the next authentication decision.
     *
     * <p>Without this, the long-lived {@code portal} process verifies against the copy it read
     * at start-up while {@code portal disable-user} and {@code portal set-password} -- separate,
     * short-lived processes -- edit the file underneath it. Measured: after {@code disable-user}
     * had written {@code r=disabled$v1} for an account, the running portal went on answering
     * {@code 303} for that account's old password, and after {@code set-password} replaced the
     * credential the <em>superseded</em> password still produced {@code 303}. Both operations are
     * the revocation path an operator believes they just used, so an account an administrator
     * has disabled -- or whose password was rotated after a suspected leak -- keeps signing in
     * until the service is restarted. Rule 3 says a failed credential check must fail closed;
     * checking a stale record is not checking server-side state.
     *
     * <p>The check is one {@code stat}, and it is deliberately not about a name, so its cost is
     * identical whether or not the presented account exists. Change is detected from the file's
     * identity: every sanctioned write goes through {@code ATOMIC_MOVE}, which installs a
     * <em>new inode</em>, so the file key alone distinguishes every write; size and mtime are
     * included to also catch a hand edit that reused the inode. A roster that no longer parses
     * is not treated as empty-and-fine and is not overwritten: the map becomes empty, so every
     * account is refused as an unknown name, and the failure is logged. Refusing everybody is
     * the correct direction; silently writing a roster reconstructed from a partial view would
     * destroy accounts.
     */
    public void refreshIfChanged() {
        String now = fingerprintOf(file);
        if (now.equals(fingerprint)) {
            return;
        }
        synchronized (monitor) {
            if (now.equals(fingerprint)) {
                return;
            }
            fingerprint = now;
            try {
                Map<String, String> reloaded = currentRosterOnDisk();
                for (Map.Entry<String, String> e : reloaded.entrySet()) {
                    hasher.requireValidRecord(e.getValue());
                }
                records = Collections.unmodifiableMap(reloaded);
            } catch (RuntimeException unusable) {
                // Fail closed, and remember the identity we just rejected so a broken file is
                // parsed once rather than on every login.
                records = Map.of();
                audit.systemFailure("roster-refresh", "-", "-", unusable);
            }
        }
    }

    /** Inode + size + mtime of the roster, or {@code absent}. See {@link #refreshIfChanged}. */
    private String fingerprintOf(Path f) {
        try {
            java.nio.file.attribute.BasicFileAttributes a =
                    Files.readAttributes(f, java.nio.file.attribute.BasicFileAttributes.class,
                            LinkOption.NOFOLLOW_LINKS);
            java.time.Instant mtime = a.lastModifiedTime().toInstant();
            return String.valueOf(a.fileKey()) + '|' + a.size() + '|'
                    + mtime.getEpochSecond() + '.' + mtime.getNano();
        } catch (IOException gone) {
            return "absent";
        }
    }

    /** Refuse to run against a roster that is group-/world-readable or not ours. */
    public void requireAcceptableFileMode() {
        if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
            PrivateFiles.requireMode(file, PrivateFiles.FILE_MODE);
        }
    }

    static Map<String, String> parse(String body) {
        String[] lines = body.split("\n", -1);
        Map<String, String> out = new LinkedHashMap<>();
        boolean headerSeen = false;
        int dataLines = 0;
        for (String raw : lines) {
            if (raw.isEmpty()) {
                continue;
            }
            if (raw.length() > LINE_MAX_BYTES) {
                throw new IllegalStateException("roster-line-too-long");
            }
            if (!headerSeen) {
                if (!HEADER.equals(raw)) {
                    throw new IllegalStateException("roster-header-missing");
                }
                headerSeen = true;
                continue;
            }
            if (++dataLines > MAX_ACCOUNTS) {
                throw new IllegalStateException("roster-too-many-accounts");
            }
            if (!raw.startsWith("u=") || raw.charAt(2) == '=') {
                throw new IllegalStateException("roster-line-malformed");
            }
            int sep = raw.indexOf(" r=", 2);
            if (sep < 0) {
                throw new IllegalStateException("roster-line-malformed");
            }
            String name = raw.substring(2, sep);
            String record = raw.substring(sep + 3);
            if (!InputPolicy.isUsername(name)) {
                throw new IllegalStateException("roster-name-invalid");
            }
            // Duplicate keys must be refused: with a permissive parser the last line
            // silently wins, so a write-principled attacker could point "alice" at a
            // record they control.
            if (out.containsKey(name)) {
                throw new IllegalStateException("roster-duplicate-name");
            }
            out.put(name, record);
        }
        if (!headerSeen) {
            throw new IllegalStateException("roster-empty");
        }
        return Collections.unmodifiableMap(out);
    }

    /** Look up a record. Absence is an {@link Optional#empty()}, never a default. */
    public Optional<String> recordFor(String username) {
        if (!InputPolicy.isUsername(username)) {
            return Optional.empty();
        }
        return Optional.ofNullable(records.get(username));
    }

    public boolean exists(String username) {
        return username != null && records.containsKey(username);
    }

    public int size() {
        return records.size();
    }

    public List<String> names() {
        List<String> out = new ArrayList<>(records.keySet());
        Collections.sort(out);
        return out;
    }

    public CreateResult create(String username, char[] secret) {
        if (!InputPolicy.isUsername(username)) {
            return CreateResult.INVALID_NAME;
        }
        String weak = InputPolicy.strengthFailure(secret, username.toCharArray());
        if (weak != null) {
            audit.event("create", Crypto.idRef(username), "-", "denied", "weak-password");
            return CreateResult.WEAK_PASSWORD;
        }
        final CreateResult[] verdict = new CreateResult[1];
        synchronized (monitor) {
            // The in-memory check only saves the KDF for the common case; the decision that
            // is reported is the one taken against the file under the lock below.
            if (records.containsKey(username)) {
                verdict[0] = CreateResult.NAME_TAKEN;
            } else {
                String record = hasher.hashWithCopy(secret, username.toCharArray());
                mutateRoster((Map<String, String> onDisk) -> {
                    if (onDisk.containsKey(username)) {
                        verdict[0] = CreateResult.NAME_TAKEN;
                        return null;
                    }
                    if (onDisk.size() >= MAX_ACCOUNTS) {
                        verdict[0] = CreateResult.IO_FAILURE;
                        return null;
                    }
                    Map<String, String> next = new LinkedHashMap<>(onDisk);
                    next.put(username, record);
                    verdict[0] = CreateResult.CREATED;
                    return next;
                });
            }
        }
        if (verdict[0] == CreateResult.CREATED) {
            audit.event("create", Crypto.idRef(username), "-", "ok", "created");
        }
        return verdict[0];
    }

    /**
     * Enforce the strength policy on an existing record too: a record written by an older
     * build, or by an attacker who edited the file with a low-cost KDF, is refused here
     * and reported, rather than silently accepted.
     */
    public void requirePolicyCompliantRecords() {
        for (Map.Entry<String, String> e : records.entrySet()) {
            try {
                hasher.requireValidRecord(e.getValue());
            } catch (IllegalArgumentException bad) {
                throw new IllegalStateException(
                        "roster-record-invalid reason=" + bad.getMessage(), bad);
            }
        }
    }

    /** Upgrade a record after a successful login (rotation + iteration bump). */
    public void rotateSecret(String username, char[] secret) {
        final String record = hasher.hashWithCopy(secret, username.toCharArray());
        final boolean[] applied = new boolean[1];
        synchronized (monitor) {
            mutateRoster((Map<String, String> onDisk) -> {
                if (!onDisk.containsKey(username)) {
                    return null;
                }
                Map<String, String> next = new LinkedHashMap<>(onDisk);
                next.put(username, record);
                applied[0] = true;
                return next;
            });
        }
        if (!applied[0]) {
            throw new IllegalStateException("roster-name-unknown");
        }
        audit.event("rotate", Crypto.idRef(username), "-", "ok", "kdf-upgraded");
    }

    /** Administrative password set. Validates the same policy as enrolment. */
    public CreateResult setSecret(String username, char[] secret) {
        if (!InputPolicy.isUsername(username)) {
            return CreateResult.INVALID_NAME;
        }
        String weak = InputPolicy.strengthFailure(secret, username.toCharArray());
        if (weak != null) {
            return CreateResult.WEAK_PASSWORD;
        }
        final boolean[] wasDisabled = new boolean[1];
        final CreateResult[] verdict = new CreateResult[1];
        synchronized (monitor) {
            String record = hasher.hashWithCopy(secret, username.toCharArray());
            mutateRoster((Map<String, String> onDisk) -> {
                if (!onDisk.containsKey(username)) {
                    verdict[0] = CreateResult.IO_FAILURE;
                    return null;
                }
                // A disabled account's record is the unusable marker, so writing a real hash
                // over it re-enables the account. There is deliberately no enable-user command,
                // because an operation that turns an account back on must not be something that
                // looks like a password change -- so we perform the reset the operator asked for
                // and record, loudly, that it also lifted the disable.
                wasDisabled[0] = PasswordHasher.DISABLED_RECORD.equals(onDisk.get(username));
                Map<String, String> next = new LinkedHashMap<>(onDisk);
                next.put(username, record);
                verdict[0] = CreateResult.CREATED;
                return next;
            });
        }
        if (verdict[0] == CreateResult.CREATED) {
            audit.event("set-secret", Crypto.idRef(username), "-", "ok",
                    wasDisabled[0] ? "updated-re-enabled" : "updated");
        }
        return verdict[0];
    }

    /**
     * Whether the account is administratively disabled. Exposed so the command line can tell
     * an operator that a password reset is also lifting a disable, rather than leaving them
     * to believe a resettable account was a live one.
     */
    public boolean isDisabled(String username) {
        synchronized (monitor) {
            return PasswordHasher.DISABLED_RECORD.equals(records.get(username));
        }
    }

    /** Lock an account administratively by replacing its record with an unusable one. */
    public void disableAccount(String username) {
        final boolean[] applied = new boolean[1];
        synchronized (monitor) {
            mutateRoster((Map<String, String> onDisk) -> {
                if (!onDisk.containsKey(username)) {
                    return null;
                }
                Map<String, String> next = new LinkedHashMap<>(onDisk);
                // The disabled marker is a recognised record shape that can never verify:
                // PasswordHasher treats it as unparseable, runs the decoy KDF and returns
                // false. It is deliberately NOT an invalid record, because an invalid record
                // would fail the strict load and take the whole roster down with it.
                next.put(username, PasswordHasher.DISABLED_RECORD);
                applied[0] = true;
                return next;
            });
        }
        if (!applied[0]) {
            throw new IllegalStateException("roster-name-unknown");
        }
        audit.event("disable", Crypto.idRef(username), "-", "ok", "administrative");
    }

    /**
     * Applies one record's change to the roster as it exists on disk, under an exclusive
     * cross-process lock, and writes the result atomically. A {@code null} result from
     * {@code edit} means "decide against the disk and do nothing"; either way the in-memory
     * map is replaced by what the disk now holds, so a process never keeps acting on a view
     * that a sibling writer has already invalidated.
     */
    private void mutateRoster(RosterEdit edit) {
        FileChannel lockChannel = null;
        try {
            lockChannel = FileChannel.open(lockFile,
                    java.util.EnumSet.of(java.nio.file.StandardOpenOption.CREATE,
                            java.nio.file.StandardOpenOption.READ,
                            java.nio.file.StandardOpenOption.WRITE),
                    PosixFilePermissions.asFileAttribute(PrivateFiles.FILE_MODE));
            FileLock lock = acquireLock(lockChannel);
            try {
                Map<String, String> onDisk = currentRosterOnDisk();
                Map<String, String> next = edit.apply(onDisk);
                if (next != null) {
                    persistLocked(next);
                    records = Collections.unmodifiableMap(next);
                } else {
                    records = Collections.unmodifiableMap(onDisk);
                }
                // Record the identity of whatever is now on disk (our own write installed a
                // new inode; the refusal path left the file alone). Without this, every
                // process would see a "change" on its next login and re-read every time.
                fingerprint = fingerprintOf(file);
            } finally {
                try {
                    lock.release();
                } catch (IOException ignored) {
                    // Closing the channel releases it.
                }
            }
        } catch (IOException failure) {
            throw new IllegalStateException("roster-io", failure);
        } finally {
            if (lockChannel != null) {
                try {
                    lockChannel.close();
                } catch (IOException ignored) {
                    // Nothing further to do.
                }
            }
        }
    }

    /**
     * Re-read and re-validate the roster from disk. An unparsable file is fatal rather than
     * treated as empty: substituting an empty roster would make the next write erase every
     * account, so a corrupt file must stop the mutator instead of being silently replaced.
     */
    private Map<String, String> currentRosterOnDisk() {
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
            return Map.of();
        }
        return parse(PrivateFiles.readPrivateBounded(file, MAX_FILE_BYTES));
    }

    private FileLock acquireLock(FileChannel channel) throws IOException {
        for (int attempt = 0; attempt < 400; attempt++) {
            try {
                FileLock lock = channel.tryLock(0L, Long.MAX_VALUE, false);
                if (lock != null) {
                    return lock;
                }
            } catch (OverlappingFileLockException heldByThisJvm) {
                // Another thread of this JVM holds it; the monitor above already serialises
                // this path, so this can only be a momentary race with a sibling store.
            } catch (java.nio.channels.ClosedByInterruptException gone) {
                throw gone;
            } catch (IOException contended) {
                // Fall through to the next attempt.
            }
            try {
                Thread.sleep(25L);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IOException("roster-interrupted", interrupted);
            }
        }
        throw new IOException("roster-lock-contended");
    }

    /**
     * The KDF runs before the lock is taken so that concurrent enrolments do not queue
     * behind each other's digests; the record is applied to whatever is on disk once the
     * lock is held.
     */
    private interface RosterEdit {
        /** @return the roster to persist, or {@code null} to leave the file untouched. */
        Map<String, String> apply(Map<String, String> onDisk);
    }

    private void persistLocked(Map<String, String> next) {
        StringBuilder sb = new StringBuilder(next.size() * 96 + 64);
        sb.append(HEADER).append('\n');
        for (Map.Entry<String, String> e : next.entrySet()) {
            sb.append("u=").append(e.getKey()).append(" r=").append(e.getValue()).append('\n');
        }
        PrivateFiles.writePrivateAtomic(file, sb.toString().getBytes(StandardCharsets.US_ASCII));
    }

    /** Write a fresh roster (fails if the file already exists). */
    public void initialiseEmpty() {
        synchronized (monitor) {
            PrivateFiles.createPrivateNew(file, (HEADER + "\n").getBytes(StandardCharsets.US_ASCII));
            records = Map.of();
            fingerprint = fingerprintOf(file);
        }
    }

    public Path path() {
        return file;
    }
}
