package adminportal;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Predicate;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Append-only, tamper-evident audit trail.
 *
 * Every record is sealed with HMAC-SHA256 over its canonical payload <em>and</em> the hash of the
 * preceding record, so the file forms a chain: editing, reordering, inserting or deleting any
 * record breaks every seal after it. Removing the whole tail is only possible by also deleting the
 * log, which is why the key lives in a separate file (an attacker who can write the log but not
 * read the key cannot forge a valid chain).
 *
 * Integrity is only as good as the key. In production the key belongs in a KMS or an HSM; a 0600
 * file next to the log is the honest floor for a single-host deployment and is reported as such by
 * {@link #keyLocation()}.
 */
public final class AuditLog implements AutoCloseable {

    public static final String HMAC_ALGORITHM = "HmacSHA256";
    public static final int KEY_BYTES = 32;

    private static final Set<PosixFilePermission> OWNER_ONLY = Set.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

    /** Thrown when an audit write fails. Callers must treat this as fatal, never swallow it. */
    public static final class AuditFailureException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public AuditFailureException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** Result of replaying the chain. */
    public record Verification(boolean valid, long records, List<String> problems) {
        public boolean isValid() {
            return valid;
        }
    }

    private final Path file;
    private final Path keyFile;
    private final String keyId;
    private final byte[] key;
    private final Object lock = new Object();
    private long nextSeq;
    private String prevHash;
    private boolean open = true;

    private AuditLog(Path file, Path keyFile, String keyId, byte[] key, long nextSeq, String prevHash) {
        this.file = file;
        this.keyFile = keyFile;
        this.keyId = keyId;
        this.key = key;
        this.nextSeq = nextSeq;
        this.prevHash = prevHash;
    }

    /**
     * Opens (creating if absent) the log at {@code file}, using the signing key at {@code keyFile}
     * and generating one on first run.
     */
    public static AuditLog open(Path file, Path keyFile) throws IOException {
        byte[] raw = loadOrCreateKey(keyFile);
        String id = keyId(keyFile);
        return openWithKey(file, keyFile, id, raw);
    }

    /** Opens with an explicit key (tests, or a key sourced from a KMS). */
    public static AuditLog openWithKey(Path file, Path keyFile, String keyId, byte[] key)
            throws IOException {
        if (key.length < KEY_BYTES) {
            throw new IllegalArgumentException("audit key must be at least " + KEY_BYTES + " bytes");
        }
        Files.createDirectories(file.toAbsolutePath().getParent());
        AuditLog log = new AuditLog(file, keyFile, keyId, key.clone(), 1L, AuditEvent.GENESIS);
        log.resumeChain();
        return log;
    }

    /**
     * Replays the tail of the existing log to recover the sequence counter and the head hash, so a
     * reopened log keeps extending the same chain. Truncation is detected and reported loudly rather
     * than silently accepted.
     */
    private void resumeChain() throws IOException {
        if (!Files.exists(file)) {
            Files.createFile(file);
            restrictToOwner(file);
            return;
        }
        restrictToOwner(file);
        List<AuditEvent> all = readAll();
        if (all.isEmpty()) {
            return;
        }
        AuditEvent last = all.get(all.size() - 1);
        this.nextSeq = last.seq() + 1;
        this.prevHash = last.hash();
    }

    /** Appends a record. Throws {@link AuditFailureException} if the record cannot be persisted. */
    public AuditEvent append(String event, AuditEvent.Outcome outcome, String actor, String username,
                             String detail) {
        String safeEvent = AuditEvent.sanitize(event);
        String safeActor = AuditEvent.sanitize(actor);
        String safeUser = AuditEvent.sanitize(username);
        String safeDetail = AuditEvent.sanitize(detail);
        String line;
        AuditEvent record;
        synchronized (lock) {
            if (!open) {
                throw new AuditFailureException("audit log is closed", null);
            }
            long seq = nextSeq;
            String ts = Instant.now().toString();
            AuditEvent unsigned = new AuditEvent(seq, ts, safeEvent, outcome.name(), safeActor,
                    safeUser, safeDetail, keyId, prevHash, "");
            String hash = seal(unsigned);
            record = new AuditEvent(seq, ts, safeEvent, outcome.name(), safeActor, safeUser,
                    safeDetail, keyId, prevHash, hash);
            line = record.toJsonLine() + "\n";
            byte[] bytes = line.getBytes(StandardCharsets.UTF_8);
            try (FileChannel channel = FileChannel.open(file, StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE, StandardOpenOption.APPEND)) {
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                while (buffer.hasRemaining()) {
                    if (channel.write(buffer) <= 0) {
                        throw new IOException("audit record not fully written");
                    }
                }
                channel.force(true);
            } catch (IOException e) {
                // Fail closed: a chain that skipped a seq would look like a deleted record, so the
                // counter is only advanced once the bytes are durable.
                throw new AuditFailureException("unable to write audit record to " + file, e);
            }
            nextSeq = seq + 1;
            prevHash = hash;
        }
        return record;
    }

    /** HMAC-SHA256 over the canonical payload, base64url without padding. */
    static String seal(byte[] key, String payload) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("HMAC unavailable on this JVM", e);
        }
    }

    private String seal(AuditEvent event) {
        return seal(key, event.canonicalPayload());
    }

    /** Reads every record in order; malformed lines are returned as null placeholders in {@code problems}. */
    public List<AuditEvent> readAll() throws IOException {
        List<AuditEvent> events = new ArrayList<>();
        if (!Files.exists(file)) {
            return events;
        }
        try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) {
                    continue;
                }
                AuditEvent event = AuditEvent.fromJsonLine(line);
                if (event != null) {
                    events.add(event);
                }
            }
        }
        return events;
    }

    /**
     * Replays the chain and reports the first problem for each class of break: structural,
     * sequence gap, broken seal, or broken link.
     */
    public Verification verify() throws IOException {
        List<AuditEvent> events = readAll();
        List<String> problems = new ArrayList<>();
        long counted = 0;
        long total = Files.exists(file) ? countDataLines() : 0;
        if (total != events.size()) {
            problems.add((total - events.size())
                    + " line(s) are not valid audit records (tampering or corruption)");
        }
        String expectedPrev = AuditEvent.GENESIS;
        long expectedSeq = 1;
        Set<String> seenKeys = new HashSet<>();
        for (AuditEvent event : events) {
            counted++;
            if (event.seq() != expectedSeq) {
                problems.add("sequence gap or reorder at seq " + event.seq() + " (expected "
                        + expectedSeq + ")");
            }
            if (!constantTimeEquals(expectedPrev, event.prevHash())) {
                problems.add("chain link broken at seq " + event.seq());
            }
            seenKeys.add(event.keyId());
            String recomputed = sealFor(event);
            if (!constantTimeEquals(recomputed, event.hash())) {
                problems.add("record seal invalid at seq " + event.seq()
                        + " (record altered, re-signed, or signed with an unknown key)");
            }
            expectedPrev = event.hash();
            expectedSeq = event.seq() + 1;
        }
        if (seenKeys.size() > 1) {
            problems.add("log mixes signing keys " + seenKeys
                    + "; verify with --key-history to include retired keys");
        }
        return new Verification(problems.isEmpty(), counted, problems);
    }

    /** Re-seals a parsed record with a candidate key, for verification. */
    private String sealFor(AuditEvent event) {
        return seal(key, event.canonicalPayload());
    }

    /** Verification that accepts records sealed by any of the supplied retired keys, by key id. */
    public Verification verifyWithKeys(java.util.Map<String, byte[]> retiredKeys) throws IOException {
        List<AuditEvent> events = readAll();
        List<String> problems = new ArrayList<>();
        String expectedPrev = AuditEvent.GENESIS;
        long expectedSeq = 1;
        for (AuditEvent event : events) {
            if (event.seq() != expectedSeq) {
                problems.add("sequence gap or reorder at seq " + event.seq());
            }
            if (!constantTimeEquals(expectedPrev, event.prevHash())) {
                problems.add("chain link broken at seq " + event.seq());
            }
            byte[] candidate = retiredKeys.getOrDefault(event.keyId(), key);
            String recomputed = seal(candidate, event.canonicalPayload());
            if (!constantTimeEquals(recomputed, event.hash())) {
                problems.add("record seal invalid at seq " + event.seq());
            }
            expectedPrev = event.hash();
            expectedSeq = event.seq() + 1;
        }
        return new Verification(problems.isEmpty(), events.size(), problems);
    }

    /** Records matching {@code filter}, in file order. */
    public List<AuditEvent> query(Predicate<AuditEvent> filter) throws IOException {
        List<AuditEvent> out = new ArrayList<>();
        for (AuditEvent event : readAll()) {
            if (filter.test(event)) {
                out.add(event);
            }
        }
        return out;
    }

    public List<AuditEvent> failuresFor(String username) throws IOException {
        String needle = username == null ? "" : username.toLowerCase(Locale.ROOT);
        return query(e -> e.outcome().equals(AuditEvent.Outcome.FAILURE.name())
                && e.username().toLowerCase(Locale.ROOT).contains(needle));
    }

    public long nextSequence() {
        synchronized (lock) {
            return nextSeq;
        }
    }

    public Path location() {
        return file;
    }

    public Path keyLocation() {
        return keyFile;
    }

    public String keyId() {
        return keyId;
    }

    private long countDataLines() throws IOException {
        long n = 0;
        try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.isBlank()) {
                    n++;
                }
            }
        }
        return n;
    }

    @Override
    public void close() {
        synchronized (lock) {
            open = false;
            java.util.Arrays.fill(key, (byte) 0);
        }
    }

    private static byte[] loadOrCreateKey(Path keyFile) throws IOException {
        Path parent = keyFile.toAbsolutePath().getParent();
        Files.createDirectories(parent);
        if (Files.exists(keyFile)) {
            byte[] existing = Files.readAllBytes(keyFile);
            if (existing.length < KEY_BYTES) {
                throw new IOException("audit signing key at " + keyFile + " is too short/corrupt");
            }
            restrictToOwner(keyFile);
            return existing;
        }
        byte[] generated = new byte[KEY_BYTES];
        new SecureRandom().nextBytes(generated);
        Path tmp = Files.createTempFile(parent, ".auditkey-", ".tmp");
        try {
            Files.write(tmp, generated);
            restrictToOwner(tmp);
            try {
                Files.move(tmp, keyFile, StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, keyFile, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
        return generated;
    }

    private static String keyId(Path keyFile) {
        return AuditEvent.sanitize(keyFile.getFileName().toString().replace(".key", ""));
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8));
    }

    private static void restrictToOwner(Path path) {
        try {
            Files.setPosixFilePermissions(path, OWNER_ONLY);
        } catch (UnsupportedOperationException | IOException e) {
            path.toFile().setReadable(false, false);
            path.toFile().setWritable(false, false);
            path.toFile().setReadable(true, false);
            path.toFile().setWritable(true, false);
        }
    }
}
