package portal;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.function.Supplier;
import java.util.regex.Pattern;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Administrator portal: authenticates administrators, gates admin-level
 * functionality behind a successful login, and records every authentication
 * attempt (granted or denied) in an append-only audit log that can be reviewed
 * later, with or without an authenticated session.
 *
 * Run: java -cp out portal.AdminPortal [--audit-log=FILE] [--demo] [--review[=N]] [--summary]
 *
 * Security decisions, each pinned by AdminPortalTest:
 *   1. Passwords are never stored or logged. They are verified against a
 *      PBKDF2-HMAC-SHA256 digest with a random per-account salt, compared in
 *      constant time.
 *   2. Every attempt that could name an account pays exactly one key derivation,
 *      whether the account exists, is locked, or the password is simply wrong,
 *      so response time does not disclose which of the three it was. Input that
 *      cannot name an account at all is refused cheaply: a fast refusal there
 *      leaks nothing and denies a cheap way to make the server do expensive work.
 *   3. Usernames are canonicalised by removing only U+0020 and then refusing
 *      anything else below U+0021. String.trim() also deletes control
 *      characters, which would fold "admin" plus a trailing tab onto the real
 *      account "admin".
 *   4. A password that ends in NUL or holds an unpaired surrogate is refused
 *      rather than hashed: PBEKeySpec converts char[] with its own lossy
 *      encoder, so two different secrets can produce the same digest.
 *   5. Recording is part of authenticating. If an event cannot be written, the
 *      attempt is denied (fail closed) instead of being granted unrecorded.
 */
public final class AdminPortal {

    // ------------------------------------------------------------------ config

    /** Key-derivation parameters. Iterations are configurable so tests stay quick. */
    static final class HashConfig {
        static final int DIGEST_BYTES = 32;

        final String algorithm;
        final int iterations;

        HashConfig(String algorithm, int iterations) {
            this.algorithm = algorithm;
            this.iterations = iterations;
        }

        static HashConfig production() {
            return new HashConfig("PBKDF2WithHmacSHA256", 200_000);
        }

        static HashConfig forTests(int iterations) {
            return new HashConfig("PBKDF2WithHmacSHA256", iterations);
        }
    }

    // ------------------------------------------------------------- input rules

    /** Input validation and canonicalisation, shared by login and provisioning. */
    static final class InputPolicy {
        static final int MIN_PASSWORD_CHARS = 10;
        static final int MAX_PASSWORD_CHARS = 1024;
        static final int MAX_USERNAME_CHARS = 64;
        private static final Pattern LEGAL_USERNAME = Pattern.compile("[a-z0-9._-]{3,64}");

        private InputPolicy() {
        }

        /**
         * Returns the canonical username, or null when the input is unusable.
         *
         * Only U+0020 is stripped. Any other character below U+0021 (NUL, tab,
         * CR, LF, ...) makes the input invalid rather than being deleted, so no
         * invisible character can ever fold one identity onto another.
         */
        static String canonicalUsername(String raw) {
            if (raw == null || raw.length() > MAX_USERNAME_CHARS) {
                return null;
            }
            int from = 0;
            int to = raw.length();
            while (from < to && raw.charAt(from) == ' ') {
                from++;
            }
            while (to > from && raw.charAt(to - 1) == ' ') {
                to--;
            }
            if (from == to) {
                return null;
            }
            for (int i = from; i < to; i++) {
                if (raw.charAt(i) <= ' ') {
                    return null;
                }
            }
            String candidate = raw.substring(from, to).toLowerCase(Locale.ROOT);
            return LEGAL_USERNAME.matcher(candidate).matches() ? candidate : null;
        }

        /** Null means the password may be hashed. Refusal, never trimming. */
        static String passwordProblem(char[] password) {
            if (password == null) {
                return "no password was supplied";
            }
            if (password.length < MIN_PASSWORD_CHARS) {
                return "shorter than " + MIN_PASSWORD_CHARS + " characters";
            }
            if (password.length > MAX_PASSWORD_CHARS) {
                return "longer than " + MAX_PASSWORD_CHARS + " characters";
            }
            if (password[password.length - 1] == 0) {
                return "ends in a NUL character";
            }
            for (int i = 0; i < password.length; i++) {
                char c = password[i];
                if (Character.isHighSurrogate(c)) {
                    if (i + 1 >= password.length || !Character.isLowSurrogate(password[i + 1])) {
                        return "contains an unpaired surrogate";
                    }
                    i++;
                } else if (Character.isLowSurrogate(c)) {
                    return "contains an unpaired surrogate";
                }
            }
            return null;
        }
    }

    // ------------------------------------------------------------ stored hashes

    /** A PBKDF2 digest plus everything needed to re-derive and check it. */
    static final class PasswordHash {
        static final int SALT_BYTES = 16;
        private static final int DIGEST_BITS = HashConfig.DIGEST_BYTES * 8;

        final String algorithm;
        final int iterations;
        final byte[] salt;
        final byte[] digest;

        PasswordHash(String algorithm, int iterations, byte[] salt, byte[] digest) {
            if (algorithm == null || algorithm.isEmpty()) {
                throw new IllegalArgumentException("a hash needs its algorithm name");
            }
            if (iterations < 1000) {
                throw new IllegalArgumentException("iteration count too low: " + iterations);
            }
            if (salt == null || salt.length != SALT_BYTES) {
                throw new IllegalArgumentException("salt must be " + SALT_BYTES + " bytes");
            }
            if (digest == null || digest.length * 8 != DIGEST_BITS) {
                throw new IllegalArgumentException("digest must be " + DIGEST_BITS + " bits");
            }
            this.algorithm = algorithm;
            this.iterations = iterations;
            this.salt = salt.clone();
            this.digest = digest.clone();
        }

        static byte[] randomSalt(SecureRandom random) {
            byte[] salt = new byte[SALT_BYTES];
            random.nextBytes(salt);
            return salt;
        }

        /** Exactly one key derivation. The caller is responsible for zeroing the result. */
        static byte[] derive(String algorithm, int iterations, byte[] salt, char[] password)
                throws GeneralSecurityException {
            String problem = InputPolicy.passwordProblem(password);
            if (problem != null) {
                throw new IllegalArgumentException("password refused before hashing: " + problem);
            }
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, DIGEST_BITS);
            byte[] derived;
            try {
                derived = SecretKeyFactory.getInstance(algorithm).generateSecret(spec).getEncoded();
            } finally {
                spec.clearPassword();
            }
            if (derived == null || derived.length * 8 != DIGEST_BITS) {
                throw new GeneralSecurityException("unexpected digest length from " + algorithm);
            }
            return derived;
        }

        String describe() {
            return algorithm + ", " + iterations + " iterations, " + salt.length
                    + "-byte salt, " + digest.length + "-byte digest";
        }

        /** The stored form: algorithm:iterations:salt:digest (base64 fields). */
        String serialize() {
            Base64.Encoder encoder = Base64.getEncoder();
            return algorithm + ":" + iterations + ":"
                    + encoder.encodeToString(salt) + ":" + encoder.encodeToString(digest);
        }

        static PasswordHash parse(String stored) {
            if (stored == null) {
                throw new IllegalArgumentException("a stored hash cannot be empty");
            }
            String[] parts = stored.split(":", -1);
            if (parts.length != 4) {
                throw new IllegalArgumentException("a stored hash has 4 colon-separated fields");
            }
            Base64.Decoder decoder = Base64.getDecoder();
            int iterations;
            try {
                iterations = Integer.parseInt(parts[1]);
            } catch (NumberFormatException notANumber) {
                throw new IllegalArgumentException("stored hash has a non-numeric iteration count");
            }
            return new PasswordHash(parts[0], iterations, decoder.decode(parts[2]), decoder.decode(parts[3]));
        }
    }

    // -------------------------------------------------------------- audit trail

    enum Outcome {
        GRANTED, DENIED, ERROR;

        String key() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    /** One immutable audit record. {@code reason} is a fixed code, never free text. */
    static final class AuditEvent {
        final long seq;
        final String occurredAt;
        final String actor;
        final Outcome outcome;
        final String reason;
        final String detail;

        AuditEvent(long seq, String occurredAt, String actor, Outcome outcome, String reason, String detail) {
            this.seq = seq;
            this.occurredAt = occurredAt;
            this.actor = actor;
            this.outcome = outcome;
            this.reason = reason;
            this.detail = detail;
        }

        String toJson() {
            return new StringBuilder(200)
                    .append("{\"seq\":").append(seq)
                    .append(",\"occurred_at\":").append(AuditLog.jsonString(occurredAt))
                    .append(",\"actor\":").append(AuditLog.jsonString(actor))
                    .append(",\"outcome\":").append(AuditLog.jsonString(outcome.key()))
                    .append(",\"reason\":").append(AuditLog.jsonString(reason))
                    .append(",\"detail\":").append(AuditLog.jsonString(detail))
                    .append('}')
                    .toString();
        }
    }

    /**
     * Append-only log, one JSON object per line, written straight through so a
     * crash cannot lose the last attempt. Untrusted text is sanitised so it
     * cannot forge a record or a field. Passwords never reach this class.
     */
    static final class AuditLog {
        static final String HEADER = "# admin-portal audit log v1 (append-only, one JSON record per line)";

        private final Path file;
        private long seq;
        private boolean headerWritten;

        AuditLog(Path file) throws IOException {
            this.file = file;
            if (file.getParent() != null) {
                Files.createDirectories(file.getParent());
            }
            boolean exists = Files.exists(file);
            this.seq = exists ? lastSeqIn(file) : 0L;
            this.headerWritten = exists && startsWithComment(file);
        }

        Path file() {
            return file;
        }

        synchronized long nextSeq() {
            return seq;
        }

        synchronized void append(Outcome outcome, String actor, String reason, String detail) throws IOException {
            long pending = seq + 1;
            AuditEvent event = new AuditEvent(pending, Instant.now().toString(),
                    sanitize(actor, 64), outcome, sanitize(reason, 96), sanitize(detail, 160));
            List<String> lines = new ArrayList<>(2);
            boolean needHeader = !headerWritten;
            if (needHeader) {
                lines.add(HEADER);
            }
            lines.add(event.toJson());
            Files.write(file, lines, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            headerWritten = true;
            seq = pending;
        }

        /** Untrusted text: drop CR/LF/TAB, dot out other control bytes, cap length. */
        static String sanitize(String raw, int maxChars) {
            if (raw == null) {
                return "";
            }
            StringBuilder sb = new StringBuilder(Math.min(raw.length() + 2, maxChars));
            for (int i = 0; i < raw.length() && sb.length() < maxChars; i++) {
                char c = raw.charAt(i);
                if (c == '\r' || c == '\n' || c == '\t') {
                    continue;
                }
                if (c < 0x21 || c == 0x7F) {
                    sb.append('.');
                } else if (c > 0x7E) {
                    sb.append('?');
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        static String jsonString(String value) {
            String v = value == null ? "" : value;
            StringBuilder sb = new StringBuilder(v.length() + 8);
            sb.append('"');
            for (int i = 0; i < v.length(); i++) {
                char c = v.charAt(i);
                if (c == '"') {
                    sb.append("\\\"");
                } else if (c == '\\') {
                    sb.append("\\\\");
                } else if (c == '\n' || c == '\r' || c == '\t') {
                    // sanitize already removed these; drop them defensively
                } else if (c < 0x20 || c == 0x7F) {
                    sb.append(String.format("\\u%04x", (int) c));
                } else {
                    sb.append(c);
                }
            }
            sb.append('"');
            return sb.toString();
        }

        /** {@code last} &lt;= 0 returns every record, otherwise the newest ones. */
        List<AuditEvent> review(int last) throws IOException {
            List<AuditEvent> all = new ArrayList<>();
            if (!Files.exists(file)) {
                return all;
            }
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                AuditEvent event = parseLine(line);
                if (event != null) {
                    all.add(event);
                }
            }
            if (last <= 0 || all.size() <= last) {
                return all;
            }
            return new ArrayList<>(all.subList(all.size() - last, all.size()));
        }

        SortedMap<String, Long> counts() throws IOException {
            SortedMap<String, Long> counts = new TreeMap<>();
            for (AuditEvent event : review(0)) {
                String key = event.outcome.key() + (event.reason.isEmpty() ? "" : ":" + event.reason);
                counts.merge(key, 1L, Long::sum);
            }
            return counts;
        }

        /** Returns null for the header line and for anything unparseable. */
        static AuditEvent parseLine(String line) {
            if (line == null) {
                return null;
            }
            String text = line.trim();
            if (text.isEmpty() || !text.startsWith("{")) {
                return null;
            }
            Map<String, String> fields = new LinkedHashMap<>();
            int cursor = 1;
            while (cursor < text.length()) {
                int keyStart = text.indexOf('"', cursor);
                if (keyStart < 0) {
                    break;
                }
                int keyEnd = text.indexOf('"', keyStart + 1);
                int colon = keyEnd < 0 ? -1 : text.indexOf(':', keyEnd + 1);
                if (colon < 0) {
                    break;
                }
                String key = text.substring(keyStart + 1, keyEnd);
                int valueStart = colon + 1;
                while (valueStart < text.length() && text.charAt(valueStart) == ' ') {
                    valueStart++;
                }
                if (valueStart >= text.length()) {
                    break;
                }
                if (text.charAt(valueStart) == '"') {
                    int valueEnd = valueStart + 1;
                    boolean escaped = false;
                    while (valueEnd < text.length()) {
                        char c = text.charAt(valueEnd);
                        if (escaped) {
                            escaped = false;
                        } else if (c == '\\') {
                            escaped = true;
                        } else if (c == '"') {
                            break;
                        }
                        valueEnd++;
                    }
                    if (valueEnd >= text.length()) {
                        break;
                    }
                    fields.put(key, unescape(text.substring(valueStart + 1, valueEnd)));
                    cursor = valueEnd + 1;
                } else {
                    int valueEnd = valueStart;
                    while (valueEnd < text.length() && text.charAt(valueEnd) != ',' && text.charAt(valueEnd) != '}') {
                        valueEnd++;
                    }
                    fields.put(key, text.substring(valueStart, valueEnd).trim());
                    cursor = valueEnd;
                }
            }
            String outcome = fields.get("outcome");
            if (outcome == null) {
                return null;
            }
            Outcome parsed;
            try {
                parsed = Outcome.valueOf(outcome.toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException unknownCode) {
                return null;
            }
            long sequence;
            try {
                sequence = Long.parseLong(fields.getOrDefault("seq", "0"));
            } catch (NumberFormatException badNumber) {
                sequence = -1L;
            }
            return new AuditEvent(sequence, fields.getOrDefault("occurred_at", ""),
                    fields.getOrDefault("actor", ""), parsed,
                    fields.getOrDefault("reason", ""), fields.getOrDefault("detail", ""));
        }

        private static String unescape(String value) {
            if (value.indexOf('\\') < 0) {
                return value;
            }
            StringBuilder sb = new StringBuilder(value.length());
            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                if (c == '\\' && i + 5 < value.length() && value.charAt(i + 1) == 'u') {
                    try {
                        sb.append((char) Integer.parseInt(value.substring(i + 2, i + 6), 16));
                        i += 5;
                        continue;
                    } catch (NumberFormatException notHex) {
                        // keep the backslash literally, below
                    }
                }
                if (c == '\\' && i + 1 < value.length()
                        && (value.charAt(i + 1) == '"' || value.charAt(i + 1) == '\\')) {
                    sb.append(value.charAt(i + 1));
                    i++;
                    continue;
                }
                sb.append(c);
            }
            return sb.toString();
        }

        /**
         * An existing trail that cannot be read is not repaired here and is not
         * announced either: the portal stays up and every later attempt fails
         * closed at the append, which is the stricter outcome than starting
         * with a working gate and a broken record.
         */
        private static long lastSeqIn(Path file) {
            long max = 0L;
            try {
                for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                    AuditEvent event = parseLine(line);
                    if (event != null && event.seq > max) {
                        max = event.seq;
                    }
                }
            } catch (IOException | RuntimeException unreadable) {
                return 0L;
            }
            return max;
        }

        private static boolean startsWithComment(Path file) {
            try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                String first = reader.readLine();
                return first != null && first.startsWith("#");
            } catch (IOException | RuntimeException unreadable) {
                return true;
            }
        }
    }

    // ---------------------------------------------------------------- accounts

    static final class Account {
        final String username;
        final PasswordHash hash;
        final Instant createdAt;
        int failedAttempts;
        Instant lockedUntil;
        Instant lastLogin;

        Account(String username, PasswordHash hash, Instant createdAt) {
            this.username = username;
            this.hash = hash;
            this.createdAt = createdAt;
        }

        boolean lockedAt(Instant instant) {
            return lockedUntil != null && lockedUntil.isAfter(instant);
        }
    }

    /** The account store plus the lockout policy. */
    static final class Directory {
        private final Map<String, Account> accounts = new LinkedHashMap<>();
        private final SecureRandom random;
        final HashConfig config;
        int maxFailures;
        long lockMillis;
        Supplier<Instant> now = Instant::now;

        Directory(HashConfig config, SecureRandom random, int maxFailures, long lockMillis) {
            this.config = config;
            this.random = random;
            this.maxFailures = maxFailures;
            this.lockMillis = lockMillis;
        }

        synchronized Account get(String canonicalUsername) {
            return accounts.get(canonicalUsername);
        }

        synchronized List<String> usernames() {
            return new ArrayList<>(accounts.keySet());
        }

        synchronized int size() {
            return accounts.size();
        }

        /** Returns null on success, otherwise the reason to show the operator. */
        synchronized String create(String rawUsername, char[] password) {
            String username = InputPolicy.canonicalUsername(rawUsername);
            if (username == null) {
                return "username must be 3-64 characters of a-z, 0-9, '.', '_' or '-', with no other whitespace";
            }
            String problem = InputPolicy.passwordProblem(password);
            if (problem != null) {
                return "password refused: " + problem;
            }
            if (accounts.containsKey(username)) {
                return "account '" + username + "' already exists";
            }
            try {
                byte[] salt = PasswordHash.randomSalt(random);
                byte[] digest = PasswordHash.derive(config.algorithm, config.iterations, salt, password);
                accounts.put(username, new Account(username,
                        new PasswordHash(config.algorithm, config.iterations, salt, digest), now.get()));
                Arrays.fill(digest, (byte) 0);
                return null;
            } catch (GeneralSecurityException failure) {
                return "could not create the account: " + failure.getMessage();
            }
        }

        synchronized boolean unlock(String canonicalUsername) {
            Account account = accounts.get(canonicalUsername);
            if (account == null) {
                return false;
            }
            account.lockedUntil = null;
            account.failedAttempts = 0;
            return true;
        }

        synchronized boolean locked(String canonicalUsername) {
            Account account = accounts.get(canonicalUsername);
            return account != null && account.lockedAt(now.get());
        }

        synchronized int failedAttempts(String canonicalUsername) {
            Account account = accounts.get(canonicalUsername);
            return account == null ? -1 : account.failedAttempts;
        }
    }

    /** What the caller may be told, plus the private reason only the log sees. */
    static final class Decision {
        final Outcome outcome;
        final String message;
        final String reason;
        final String actor;

        Decision(Outcome outcome, String message, String reason, String actor) {
            this.outcome = outcome;
            this.message = message;
            this.reason = reason;
            this.actor = actor;
        }

        boolean granted() {
            return outcome == Outcome.GRANTED;
        }
    }

    static final class Session {
        final String username;
        final Instant startedAt;
        final String token;

        Session(String username, Instant startedAt, String token) {
            this.username = username;
            this.startedAt = startedAt;
            this.token = token;
        }
    }

    /**
     * The credential check. Every path that could name an account pays exactly
     * one key derivation before anything is decided or reported.
     */
    static final class Authenticator {
        static final String GENERIC_DENIAL = "Access denied.";
        static final String GRANT_MESSAGE = "Access granted.";
        static final String AUDIT_FAILURE_DENIAL =
                "Access denied: this attempt could not be recorded, so the portal will not continue.";
        private static final String SALT_LABEL = "admin-portal-unknown-account-salt-v1:";
        private static final String DIGEST_LABEL = "admin-portal-unknown-account-digest-v1:";

        private final Directory directory;
        private final AuditLog audit;
        private final SecureRandom random;

        Authenticator(Directory directory, AuditLog audit, SecureRandom random) {
            this.directory = directory;
            this.audit = audit;
            this.random = random;
        }

        Decision authenticate(String rawUsername, char[] password) {
            String actor = InputPolicy.canonicalUsername(rawUsername);
            String passwordProblem = InputPolicy.passwordProblem(password);

            // Cheap refusals. Neither can name an account, so neither is allowed
            // to reach the store, and neither pays for a key derivation.
            if (actor == null) {
                return record(Outcome.DENIED, "", "malformed-username", "", GENERIC_DENIAL);
            }
            if (passwordProblem != null) {
                return record(Outcome.DENIED, actor, "rejected-password", passwordProblem, GENERIC_DENIAL);
            }

            Account account = directory.get(actor);
            PasswordHash stored = account != null ? account.hash : dummyHash(actor);

            boolean passwordOk = false;
            byte[] probe = null;
            try {
                probe = PasswordHash.derive(stored.algorithm, stored.iterations, stored.salt, password);
                passwordOk = MessageDigest.isEqual(probe, stored.digest);
            } catch (GeneralSecurityException | IllegalArgumentException failure) {
                passwordOk = false;
            } finally {
                if (probe != null) {
                    Arrays.fill(probe, (byte) 0);
                }
            }

            if (account == null) {
                return record(Outcome.DENIED, actor, "unknown-account", "", GENERIC_DENIAL);
            }

            synchronized (directory) {
                Instant instant = directory.now.get();
                if (!passwordOk) {
                    account.failedAttempts++;
                    if (account.failedAttempts >= directory.maxFailures) {
                        account.lockedUntil = instant.plusMillis(directory.lockMillis);
                    }
                    return record(Outcome.DENIED, actor, "invalid-credentials",
                            "failed_attempts=" + account.failedAttempts, GENERIC_DENIAL);
                }
                if (account.lockedAt(instant)) {
                    return record(Outcome.DENIED, actor, "locked",
                            "locked_until=" + account.lockedUntil, GENERIC_DENIAL);
                }
                account.failedAttempts = 0;
                account.lockedUntil = null;
                account.lastLogin = instant;
                return record(Outcome.GRANTED, actor, "", "session_started", GRANT_MESSAGE);
            }
        }

        /** Recording is part of authenticating: no record means no access. */
        private Decision record(Outcome outcome, String actor, String reason, String detail, String message) {
            try {
                audit.append(outcome, actor, reason, detail);
                return new Decision(outcome, message, reason, actor);
            } catch (IOException | RuntimeException cannotRecord) {
                try {
                    audit.append(Outcome.ERROR, actor, "audit-write-failed",
                            cannotRecord.getClass().getSimpleName());
                } catch (IOException | RuntimeException alsoLost) {
                    // The trail is unwritable. There is nothing left but to refuse.
                }
                return new Decision(Outcome.DENIED, AUDIT_FAILURE_DENIAL, "audit-failure", actor);
            }
        }

        /**
         * A hash that nobody can satisfy, assembled without a derivation of its
         * own: the caller runs one real derivation against it, which is the
         * whole point - an unknown account then costs exactly what a known one
         * costs.
         */
        private PasswordHash dummyHash(String username) {
            byte[] salt = Arrays.copyOf(sha256(SALT_LABEL, username), PasswordHash.SALT_BYTES);
            byte[] digest = sha256(DIGEST_LABEL, username);
            if (digest.length != HashConfig.DIGEST_BYTES) {
                digest = new byte[HashConfig.DIGEST_BYTES];
                random.nextBytes(digest);
            }
            return new PasswordHash(directory.config.algorithm, directory.config.iterations, salt, digest);
        }

        private static byte[] sha256(String label, String username) {
            try {
                MessageDigest sha = MessageDigest.getInstance("SHA-256");
                sha.update(label.getBytes(StandardCharsets.UTF_8));
                sha.update(username.getBytes(StandardCharsets.UTF_8));
                return sha.digest();
            } catch (NoSuchAlgorithmException impossible) {
                throw new IllegalStateException("SHA-256 is required by the portal", impossible);
            }
        }
    }

    // ------------------------------------------------------------------ portal

    /** Holds the login state and refuses admin-level work without it. */
    static final class Portal {
        final Directory directory;
        final AuditLog audit;
        final Authenticator authenticator;
        private final SecureRandom random;
        private Session session;

        Portal(Directory directory, AuditLog audit, SecureRandom random) {
            this.directory = directory;
            this.audit = audit;
            this.random = random;
            this.authenticator = new Authenticator(directory, audit, random);
        }

        Decision login(String username, char[] password) {
            Decision decision = authenticator.authenticate(username, password);
            if (decision.granted()) {
                byte[] token = new byte[12];
                random.nextBytes(token);
                session = new Session(decision.actor, Instant.now(),
                        Base64.getUrlEncoder().withoutPadding().encodeToString(token));
            }
            return decision;
        }

        Session session() {
            return session;
        }

        synchronized boolean logout(String reason) {
            if (session == null) {
                return false;
            }
            String who = session.username;
            session = null;
            try {
                audit.append(Outcome.GRANTED, who, "logout", reason);
            } catch (IOException ignored) {
                // A missing logout record must not trap the operator in a session.
            }
            return true;
        }

        String denyWithoutLogin(String command) {
            try {
                audit.append(Outcome.DENIED, "", "admin-function-without-login", command);
            } catch (IOException ignored) {
                // Reporting the refusal matters more than this one extra record.
            }
            return "Not authenticated. Use 'login' first - admin functions require a session.";
        }

        /** The single gate in front of admin-level functionality. */
        String gate(String command, Supplier<String> adminOnly) {
            if (session == null) {
                return denyWithoutLogin(command);
            }
            return adminOnly.get();
        }
    }

    // ----------------------------------------------------------- admin console

    /** Admin-level functionality. Every command goes through Portal.gate. */
    static final class AdminConsole {
        private final Portal portal;

        AdminConsole(Portal portal) {
            this.portal = portal;
        }

        String execute(String line) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                return "Type 'help' for the list of commands.";
            }
            String[] parts = trimmed.split("\\s+", 2);
            String command = parts[0].toLowerCase(Locale.ROOT);
            String argument = parts.length > 1 ? parts[1].trim() : "";
            switch (command) {
                case "status":
                    return portal.gate(command, () -> {
                        Session s = portal.session();
                        return "user        " + s.username
                                + nl() + "session      " + s.token.substring(0, 6) + "..."
                                + nl() + "since        " + s.startedAt
                                + nl() + "audit log    " + portal.audit.file().toAbsolutePath();
                    });
                case "accounts":
                    return portal.gate(command, () -> {
                        List<String> names = portal.directory.usernames();
                        if (names.isEmpty()) {
                            return "No accounts.";
                        }
                        StringBuilder sb = new StringBuilder();
                        for (String name : names) {
                            Account a = portal.directory.get(name);
                            sb.append(String.format("%-14s created=%s failures=%d %s %s",
                                    name,
                                    a.createdAt.toString().substring(0, 10),
                                    a.failedAttempts,
                                    a.lockedAt(portal.directory.now.get()) ? "LOCKED" : "active",
                                    a.lastLogin == null ? "never logged in" : "last login " + a.lastLogin))
                              .append(nl());
                        }
                        return sb.toString().trim();
                    });
                case "account":
                    return portal.gate(command, () -> {
                        String name = InputPolicy.canonicalUsername(argument);
                        if (name == null) {
                            return "Usage: account <username>";
                        }
                        Account a = portal.directory.get(name);
                        if (a == null) {
                            return "No such account.";
                        }
                        return "username         " + a.username
                                + nl() + "password storage " + a.hash.describe()
                                + nl() + "created          " + a.createdAt
                                + nl() + "failed attempts  " + a.failedAttempts
                                + nl() + "locked until     " + (a.lockedUntil == null ? "no" : a.lockedUntil)
                                + nl() + "last login       " + (a.lastLogin == null ? "never" : a.lastLogin)
                                + nl() + "salt and digest are deliberately not displayed"
                                + nl() + "digest fingerprint " + fingerprint(a.hash);
                    });
                case "audit-summary":
                    return portal.gate(command, () -> {
                        try {
                            SortedMap<String, Long> counts = portal.audit.counts();
                            if (counts.isEmpty()) {
                                return "The audit log is empty.";
                            }
                            StringBuilder sb = new StringBuilder();
                            for (Map.Entry<String, Long> entry : counts.entrySet()) {
                                sb.append(String.format("%6d  %s", entry.getValue(), entry.getKey())).append(nl());
                            }
                            return sb.toString().trim();
                        } catch (IOException unreadable) {
                            return "Could not read the audit log: " + unreadable.getMessage();
                        }
                    });
                case "recent":
                    return portal.gate(command, () -> {
                        int n = 10;
                        if (!argument.isEmpty()) {
                            try {
                                n = Math.min(500, Math.max(1, Integer.parseInt(argument)));
                            } catch (NumberFormatException badNumber) {
                                return "Usage: recent [count]";
                            }
                        }
                        try {
                            List<AuditEvent> events = portal.audit.review(n);
                            if (events.isEmpty()) {
                                return "The audit log is empty.";
                            }
                            StringBuilder sb = new StringBuilder();
                            for (AuditEvent event : events) {
                                sb.append(event.toJson()).append(nl());
                            }
                            return sb.toString().trim();
                        } catch (IOException unreadable) {
                            return "Could not read the audit log: " + unreadable.getMessage();
                        }
                    });
                case "unlock":
                    return portal.gate(command, () -> {
                        String name = InputPolicy.canonicalUsername(argument);
                        if (name == null) {
                            return "Usage: unlock <username>";
                        }
                        boolean wasLocked = portal.directory.locked(name);
                        boolean done = portal.directory.unlock(name);
                        recordAdminAction("unlock-account", name + (done && wasLocked ? " (was locked)" : ""));
                        return done
                                ? "Unlocked '" + name + "' and reset its failure counter."
                                : "No such account.";
                    });
                case "help":
                    return helpText();
                case "login":
                case "logout":
                case "whoami":
                case "create":
                case "quit":
                case "exit":
                    return "'" + command + "' is a prompt command - just type it at the admin> prompt.";
                default:
                    return "Unknown command '" + command + "'. Type 'help'.";
            }
        }

        private void recordAdminAction(String reason, String detail) {
            Session s = portal.session();
            try {
                portal.audit.append(Outcome.GRANTED, s == null ? "" : s.username, reason, detail);
            } catch (IOException ignored) {
                // The admin action itself has already been carried out.
            }
        }

        /** First 8 digest bytes, enough to compare two accounts at a glance. */
        static String fingerprint(PasswordHash hash) {
            return Base64.getEncoder().withoutPadding()
                    .encodeToString(Arrays.copyOf(hash.digest, 8));
        }

        static String helpText() {
            return "Commands (everything except login, help and quit is admin-level and needs a session):"
                    + nl() + "  login [username]   authenticate (asks for the password)"
                    + nl() + "  whoami             show the current session"
                    + nl() + "  logout             drop the current session"
                    + nl() + "  create <username>  provision another admin account (password asked twice)"
                    + nl() + "  status             who you are, and where the audit log lives"
                    + nl() + "  accounts           list accounts with lock and failure state"
                    + nl() + "  account <name>     one account, without revealing secret material"
                    + nl() + "  audit-summary      counts of every recorded outcome"
                    + nl() + "  recent [n]         the last n audit records (default 10)"
                    + nl() + "  unlock <name>      clear a lockout and reset the failure counter"
                    + nl() + "  help               this list"
                    + nl() + "  quit / exit        leave the portal";
        }

        private static String nl() {
            return System.lineSeparator();
        }
    }

    // --------------------------------------------------------------------- CLI

    /** Interactive prompt. Uses System.console() for the password when one exists. */
    static final class Cli {
        private final Portal portal;
        private final AdminConsole console;
        private final BufferedReader stdin;
        private final java.io.Console tty;
        private final PrintStream out;

        Cli(Portal portal, AdminConsole console, BufferedReader stdin, PrintStream out) {
            this.portal = portal;
            this.console = console;
            this.stdin = stdin;
            this.out = out;
            this.tty = System.console();
        }

        void run() throws IOException {
            out.println("Administrator portal. Type 'help' for commands, 'quit' to leave.");
            if (tty == null) {
                out.println("(No controlling terminal is available, so password input is echoed.)");
            }
            while (true) {
                out.print("admin> ");
                out.flush();
                String line = stdin.readLine();
                if (line == null) {
                    out.println();
                    break;
                }
                String trimmed = line.trim();
                if (trimmed.isEmpty()) {
                    continue;
                }
                String[] parts = trimmed.split("\\s+", 2);
                String command = parts[0].toLowerCase(Locale.ROOT);
                String argument = parts.length > 1 ? parts[1].trim() : "";
                switch (command) {
                    case "quit":
                    case "exit":
                        portal.logout("operator-quit");
                        out.println("Goodbye.");
                        return;
                    case "logout":
                        out.println(portal.logout("operator-logout")
                                ? "Logged out."
                                : "There is no session to end.");
                        break;
                    case "login":
                        doLogin(argument);
                        break;
                    case "whoami":
                        Session s = portal.session();
                        if (s == null) {
                            out.println(portal.denyWithoutLogin("whoami"));
                        } else {
                            out.println("You are '" + s.username + "', signed in since " + s.startedAt);
                        }
                        break;
                    case "create":
                        doCreate(argument);
                        break;
                    default:
                        out.println(console.execute(trimmed));
                        break;
                }
            }
        }

        private void doLogin(String argument) throws IOException {
            String username = argument;
            if (!argument.isEmpty()) {
                String[] nameAndRest = argument.split("\\s+", 2);
                username = nameAndRest[0];
                if (nameAndRest.length > 1) {
                    out.println("The password is never read from the command line - it would sit in the");
                    out.println("shell history - so please answer the prompt below.");
                }
            } else {
                username = prompt("Username: ");
            }
            if (username == null) {
                out.println("Access denied: no username was supplied.");
                return;
            }
            char[] password = readSecret("Password: ");
            if (password == null) {
                out.println("Access denied: no password was supplied.");
                return;
            }
            try {
                Decision decision = portal.login(username, password);
                out.println(decision.granted()
                        ? decision.message + " Welcome, " + decision.actor + "."
                        : decision.message);
            } finally {
                Arrays.fill(password, (char) 0);
            }
        }

        private void doCreate(String argument) throws IOException {
            if (portal.session() == null) {
                out.println(portal.denyWithoutLogin("create"));
                return;
            }
            String username = argument.isEmpty() ? prompt("New username: ") : argument;
            if (username == null) {
                out.println("Cancelled.");
                return;
            }
            char[] first = readSecret("New password: ");
            if (first == null) {
                out.println("Cancelled.");
                return;
            }
            char[] second = readSecret("Repeat password: ");
            try {
                if (second == null || !Arrays.equals(first, second)) {
                    out.println("Cancelled: the two passwords did not match.");
                    return;
                }
                String error = portal.directory.create(username, first);
                String canonical = InputPolicy.canonicalUsername(username);
                String actor = portal.session().username;
                try {
                    if (error == null) {
                        portal.audit.append(Outcome.GRANTED, actor, "create-account", canonical);
                    } else {
                        portal.audit.append(Outcome.DENIED, actor, "create-account-failed", error);
                    }
                } catch (IOException ignored) {
                    // The account outcome has already been decided and reported.
                }
                out.println(error == null
                        ? "Account '" + canonical + "' created."
                        : "Not created: " + error + ".");
            } finally {
                Arrays.fill(first, (char) 0);
                if (second != null) {
                    Arrays.fill(second, (char) 0);
                }
            }
        }

        private String prompt(String label) throws IOException {
            out.print(label);
            out.flush();
            return stdin.readLine();
        }

        char[] readSecret(String label) throws IOException {
            if (tty != null) {
                char[] chars = tty.readPassword(label);
                if (chars == null) {
                    out.println();
                }
                return chars;
            }
            out.print(label + " (input will be echoed)");
            out.flush();
            String line = stdin.readLine();
            if (line == null) {
                out.println();
                return null;
            }
            return line.toCharArray();
        }
    }

    // -------------------------------------------------------------------- main

    public static void main(String[] args) throws Exception {
        PrintStream out = System.out;
        Path auditFile = Path.of(System.getProperty("portal.audit.log", "admin-portal-audit.jsonl"));
        boolean demo = false;
        boolean review = false;
        boolean summary = false;
        int reviewCount = 20;

        for (String arg : args) {
            if (arg.startsWith("--audit-log=")) {
                auditFile = Path.of(arg.substring("--audit-log=".length()));
            } else if (arg.equals("--demo")) {
                demo = true;
            } else if (arg.startsWith("--review")) {
                review = true;
                int equals = arg.indexOf('=');
                if (equals > 0) {
                    reviewCount = Integer.parseInt(arg.substring(equals + 1));
                }
            } else if (arg.equals("--summary")) {
                summary = true;
            } else if (arg.equals("--help") || arg.equals("-h")) {
                out.println(usage());
                return;
            } else {
                out.println("Unknown option: " + arg);
                out.println(usage());
                return;
            }
        }

        AuditLog audit = new AuditLog(auditFile);

        if (review || summary) {
            printReview(out, audit, summary, reviewCount);
            return;
        }

        SecureRandom random = new SecureRandom();
        Directory directory = new Directory(HashConfig.production(), random, 5, 15 * 60_000L);
        Portal portal = new Portal(directory, audit, random);
        out.println("Audit log: " + auditFile.toAbsolutePath());

        if (demo) {
            provision(out, directory, "admin", "Admin!Demo2026");
            provision(out, directory, "ops", "Ops!Demo2026");
            out.println("Demo accounts loaded (throwaway - do not reuse these passwords):");
            out.println("  admin / Admin!Demo2026");
            out.println("  ops   / Ops!Demo2026");
        } else {
            String envUser = System.getenv("PORTAL_ADMIN_USER");
            String envPassword = System.getenv("PORTAL_ADMIN_PASSWORD");
            char[] password = envPassword == null ? null : envPassword.toCharArray();
            if (envUser != null && password != null) {
                String error = directory.create(envUser, password);
                out.println(error == null
                        ? "Bootstrap account ready: " + envUser
                        : "Bootstrap failed: " + error);
            } else {
                out.println("No accounts are configured.");
                out.println("Set PORTAL_ADMIN_USER and PORTAL_ADMIN_PASSWORD before starting,");
                out.println("or run with --demo to load two throwaway accounts.");
            }
            if (password != null) {
                Arrays.fill(password, (char) 0);
            }
        }

        AdminConsole console = new AdminConsole(portal);
        BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        new Cli(portal, console, stdin, out).run();
    }

    private static void provision(PrintStream out, Directory directory, String username, String password) {
        String error = directory.create(username, password.toCharArray());
        if (error != null) {
            out.println("Seed failed for " + username + ": " + error);
        }
    }

    private static void printReview(PrintStream out, AuditLog audit, boolean summary, int count) throws IOException {
        out.println("# audit log: " + audit.file().toAbsolutePath());
        if (summary) {
            SortedMap<String, Long> counts = audit.counts();
            if (counts.isEmpty()) {
                out.println("(no records)");
                return;
            }
            for (Map.Entry<String, Long> entry : counts.entrySet()) {
                out.printf("%6d  %s%n", entry.getValue(), entry.getKey());
            }
            return;
        }
        List<AuditEvent> events = audit.review(count);
        if (events.isEmpty()) {
            out.println("(no records)");
            return;
        }
        for (AuditEvent event : events) {
            out.println(event.toJson());
        }
        out.println("# " + events.size() + " record(s) shown");
    }

    private static String usage() {
        return "Usage: java -cp out portal.AdminPortal [options]"
                + nl() + "  --audit-log=FILE   audit log location (default ./admin-portal-audit.jsonl,"
                + " or -Dportal.audit.log=FILE)"
                + nl() + "  --demo             load two throwaway accounts with printed passwords"
                + nl() + "  --review[=N]       print the last N audit records (default 20) and exit"
                + nl() + "  --summary          print audit outcome counts and exit"
                + nl() + "  -h, --help         this message";
    }

    private static String nl() {
        return System.lineSeparator();
    }

    private AdminPortal() {
    }
}
