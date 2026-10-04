package com.example.auth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Validated, immutable configuration for {@link AuthenticationService}.
 *
 * <p>Every value comes from {@link ConfigSource} and is therefore attacker-controlled. Each one is
 * parsed into a bounded integer, an existence-and-permission-checked path, or a key read from a
 * {@link KeyStore} that must not be group- or world-accessible. There is no default that widens a
 * limit: an absent, blank, malformed or out-of-range value is a start-up error.
 *
 * <p>Start-up failures are collected and reported together through
 * {@link InvalidConfigException#problems()} as key names and fixed reasons. Configured values,
 * including the keystore password, are never part of a problem string, and no code path here
 * prints or logs a value.
 */
public final class AuthConfig {

    /** Keys read from the configuration source. */
    public static final String KEY_ACCOUNTS_FILE = "AUTH_ACCOUNTS_FILE";
    public static final String KEY_EVENT_LOG_FILE = "AUTH_EVENT_LOG_FILE";
    public static final String KEY_KEYSTORE_FILE = "AUTH_KEYSTORE_FILE";
    public static final String KEY_KEYSTORE_PASSWORD = "AUTH_KEYSTORE_PASSWORD";
    public static final String KEY_PASSWORD_ENTRY_ALIAS = "AUTH_PASSWORD_ENTRY_ALIAS";
    public static final String KEY_PBKDF2_ITERATIONS = "AUTH_PBKDF2_ITERATIONS";
    public static final String KEY_MIN_ACCEPTED_ITERATIONS = "AUTH_MIN_ACCEPTED_ITERATIONS";
    public static final String KEY_ACCOUNT_LOCK_AFTER = "AUTH_ACCOUNT_LOCK_AFTER";
    public static final String KEY_ACCOUNT_LOCK_SECONDS = "AUTH_ACCOUNT_LOCK_SECONDS";
    public static final String KEY_SOURCE_WINDOW_SECONDS = "AUTH_SOURCE_WINDOW_SECONDS";
    public static final String KEY_SOURCE_MAX_ATTEMPTS = "AUTH_SOURCE_MAX_ATTEMPTS";
    public static final String KEY_SOURCE_BLOCK_SECONDS = "AUTH_SOURCE_BLOCK_SECONDS";
    public static final String KEY_SESSION_TTL_SECONDS = "AUTH_SESSION_TTL_SECONDS";
    public static final String KEY_MAX_ACTIVE_SESSIONS = "AUTH_MAX_ACTIVE_SESSIONS";
    public static final String KEY_MAX_EVENTS = "AUTH_MAX_EVENTS";
    public static final String KEY_MIN_FREE_BYTES = "AUTH_MIN_FREE_BYTES";

    /**
     * Absolute floor on PBKDF2-SHA-256 iterations, applied regardless of what is configured, so a
     * misconfigured or deliberately weakened environment cannot turn credential hashing into a
     * no-op. Measured on the reference machine (see README) at roughly 200 ms for 120 000
     * iterations, which is what the latency budget in {@link AuthConfig} is sized against.
     */
    public static final int MIN_PBKDF2_ITERATIONS = 120_000;

    private static final int MAX_ITERATIONS = 5_000_000;
    private static final int MIN_STORED_ITERATIONS = 10_000;
    private static final int MAX_STORED_ITERATIONS = 10_000_000;
    private static final int MIN_LOCK_AFTER = 3;
    private static final int MAX_LOCK_AFTER = 100;
    private static final int MIN_LOCK_SECONDS = 60;
    private static final int MAX_LOCK_SECONDS = 3600;
    private static final int MIN_WINDOW_SECONDS = 60;

    /** Visible to {@link AttemptThrottle}: its stamp retention must never be shorter than this. */
    static final int MAX_WINDOW_SECONDS = 3600;
    private static final int MIN_SOURCE_ATTEMPTS = 10;
    private static final int MAX_SOURCE_ATTEMPTS = 1000;
    private static final int MIN_BLOCK_SECONDS = 60;
    private static final int MAX_BLOCK_SECONDS = 1800;
    private static final int MIN_SESSION_TTL = 300;
    private static final int MAX_SESSION_TTL = 86400;
    private static final int MIN_SESSIONS = 16;
    private static final int MAX_SESSIONS = 100_000;
    private static final int MIN_EVENTS = 100;
    private static final int MAX_EVENTS = 200_000;
    private static final long MIN_FREE_BYTES_FLOOR = 1L << 20;
    private static final int MAX_KEYSTORE_PASSWORD_CHARS = 512;

    private final Path accountsFile;
    private final Path eventLogFile;
    private final Path keystoreFile;
    private final char[] keystorePassword;
    private final String passwordEntryAlias;
    private final String clockZoneId;
    private final int pbkdf2Iterations;
    private final int minAcceptedIterations;
    private final int accountLockAfter;
    private final int accountLockSeconds;
    private final int sourceWindowSeconds;
    private final int sourceMaxAttempts;
    private final int sourceBlockSeconds;
    private final int sessionTtlSeconds;
    private final int maxActiveSessions;
    private final int maxEvents;
    private final long minFreeBytes;

    private AuthConfig(Builder b) {
        this.accountsFile = b.accountsFile;
        this.eventLogFile = b.eventLogFile;
        this.keystoreFile = b.keystoreFile;
        this.keystorePassword = b.keystorePassword;
        this.passwordEntryAlias = b.passwordEntryAlias;
        this.clockZoneId = b.clockZone.getId();
        this.pbkdf2Iterations = b.pbkdf2Iterations;
        this.minAcceptedIterations = b.minAcceptedIterations;
        this.accountLockAfter = b.accountLockAfter;
        this.accountLockSeconds = b.accountLockSeconds;
        this.sourceWindowSeconds = b.sourceWindowSeconds;
        this.sourceMaxAttempts = b.sourceMaxAttempts;
        this.sourceBlockSeconds = b.sourceBlockSeconds;
        this.sessionTtlSeconds = b.sessionTtlSeconds;
        this.maxActiveSessions = b.maxActiveSessions;
        this.maxEvents = b.maxEvents;
        this.minFreeBytes = b.minFreeBytes;
    }

    /**
     * Builds configuration from an attacker-controlled source, additionally requiring the key
     * material for credential hashing to be readable from the configured keystore.
     *
     * @throws InvalidConfigException when any value is missing, malformed, out of range, or points
     *     at a file whose permissions would expose it to other users
     */
    public static AuthConfig fromEnvironment(TimeSource time) throws InvalidConfigException {
        return from(ConfigSource.ofEnvironment(), time);
    }

    /** Same as {@link #fromEnvironment(TimeSource)} against an arbitrary source. */
    public static AuthConfig from(ConfigSource source, TimeSource time) throws InvalidConfigException {
        if (source == null || time == null) {
            throw new InvalidConfigException(List.of("configuration source and time source are required"));
        }
        List<String> problems = new ArrayList<>();

        for (String key : source.keys()) {
            if (key != null && key.startsWith(ConfigSource.NAMESPACE) && !KNOWN_KEYS.contains(key)) {
                // The key name is whatever the environment contained, not one of the constants
                // below, so it is rendered defensively before it reaches a problem string.
                problems.add("unsupported configuration key " + InvalidConfigException.describeKey(key)
                        + " in the " + ConfigSource.NAMESPACE + " namespace");
            }
        }

        Path accounts = readableFile(source, KEY_ACCOUNTS_FILE, problems, true);
        Path eventLog = eventLogFile(source, problems);
        Path keystore = readableFile(source, KEY_KEYSTORE_FILE, problems, true);
        char[] keystorePassword = null;
        String alias = null;
        if (keystore != null) {
            keystorePassword = keystorePassword(source, problems);
            alias = keystoreAlias(source, problems);
            if (keystorePassword != null && alias != null && !passwordEntryIsReadable(keystore, keystorePassword, alias, problems)) {
                // Fail closed: without a usable pepper the credential store cannot be read safely.
                keystorePassword = null;
            }
        }

        int iterations = positiveInt(source, KEY_PBKDF2_ITERATIONS, problems, MIN_PBKDF2_ITERATIONS, MAX_ITERATIONS);
        if (iterations > 0 && iterations < MIN_PBKDF2_ITERATIONS) {
            problems.add(KEY_PBKDF2_ITERATIONS + " is below the " + MIN_PBKDF2_ITERATIONS + " iteration floor");
            iterations = 0;
        }
        int minAccepted = positiveInt(source, KEY_MIN_ACCEPTED_ITERATIONS, problems, MIN_STORED_ITERATIONS, MAX_STORED_ITERATIONS);
        int lockAfter = positiveInt(source, KEY_ACCOUNT_LOCK_AFTER, problems, MIN_LOCK_AFTER, MAX_LOCK_AFTER);
        int lockSeconds = positiveInt(source, KEY_ACCOUNT_LOCK_SECONDS, problems, MIN_LOCK_SECONDS, MAX_LOCK_SECONDS);
        int windowSeconds = positiveInt(source, KEY_SOURCE_WINDOW_SECONDS, problems, MIN_WINDOW_SECONDS, MAX_WINDOW_SECONDS);
        int sourceMax = positiveInt(source, KEY_SOURCE_MAX_ATTEMPTS, problems, MIN_SOURCE_ATTEMPTS, MAX_SOURCE_ATTEMPTS);
        int blockSeconds = positiveInt(source, KEY_SOURCE_BLOCK_SECONDS, problems, MIN_BLOCK_SECONDS, MAX_BLOCK_SECONDS);
        int sessionTtl = positiveInt(source, KEY_SESSION_TTL_SECONDS, problems, MIN_SESSION_TTL, MAX_SESSION_TTL);
        int maxSessions = positiveInt(source, KEY_MAX_ACTIVE_SESSIONS, problems, MIN_SESSIONS, MAX_SESSIONS);
        int events = positiveInt(source, KEY_MAX_EVENTS, problems, MIN_EVENTS, MAX_EVENTS);
        long freeBytes = positiveLong(source, KEY_MIN_FREE_BYTES, problems, MIN_FREE_BYTES_FLOOR, Long.MAX_VALUE);

        if (!problems.isEmpty()) {
            throw new InvalidConfigException(problems);
        }
        Builder b = new Builder();
        b.accountsFile = accounts;
        b.eventLogFile = eventLog;
        b.keystoreFile = keystore;
        b.keystorePassword = keystorePassword;
        b.passwordEntryAlias = alias;
        b.pbkdf2Iterations = iterations;
        b.minAcceptedIterations = minAccepted;
        b.accountLockAfter = lockAfter;
        b.accountLockSeconds = lockSeconds;
        b.sourceWindowSeconds = windowSeconds;
        b.sourceMaxAttempts = sourceMax;
        b.sourceBlockSeconds = blockSeconds;
        b.sessionTtlSeconds = sessionTtl;
        b.maxActiveSessions = maxSessions;
        b.maxEvents = events;
        b.minFreeBytes = freeBytes;
        // Constructed through build(), never through the constructor directly. build() is where the
        // cross-field sizing rules live (see the note there), and an environment-driven deployment is
        // exactly the path that must not be able to skip them: a source budget below the account lock
        // threshold is only reachable if a deployment writes those two numbers by hand.
        AuthConfig config = b.build();
        // The environment path has to enforce the file checks too. Keystore and account-file
        // permissions are the whole reason rule 2 ("files readable by other users") holds, and a
        // deployment that only reaches validateFilesystem later would boot with a group-readable
        // pepper already in hand.
        config.validateFilesystem();
        return config;
    }

    /**
     * Programmatic construction, for embedded deployments and the test harness. Values are checked
     * against the same bounds as the environment path; permissions on the referenced files are
     * checked by {@link #validateFilesystem(TimeSource)}.
     */
    public static Builder builder() {
        return new Builder();
    }

    /** Checks file existence and permissions; called by {@link AuthenticationService#build(Builder)}. */
    void validateFilesystem() throws InvalidConfigException {
        List<String> problems = new ArrayList<>();
        requireRegularReadableFile(accountsFile, KEY_ACCOUNTS_FILE, problems, true);
        requireWritableLogFile(eventLogFile, KEY_EVENT_LOG_FILE, problems);
        requireRegularReadableFile(keystoreFile, KEY_KEYSTORE_FILE, problems, true);
        long free = eventLogFile.getParent() == null ? Long.MAX_VALUE : freeBytes(eventLogFile.getParent());
        if (free < minFreeBytes) {
            problems.add("the filesystem holding " + KEY_EVENT_LOG_FILE + " has less free space than " + KEY_MIN_FREE_BYTES);
        }
        if (!"UTC".equals(clockZoneId)) {
            problems.add("the service clock must be UTC");
        }
        if (!problems.isEmpty()) {
            throw new InvalidConfigException(problems);
        }
    }

    /** Names of the configuration keys this component reads. */
    private static final Set<String> KNOWN_KEYS = Set.of(
            KEY_ACCOUNTS_FILE, KEY_EVENT_LOG_FILE, KEY_KEYSTORE_FILE, KEY_KEYSTORE_PASSWORD,
            KEY_PASSWORD_ENTRY_ALIAS, KEY_PBKDF2_ITERATIONS, KEY_MIN_ACCEPTED_ITERATIONS,
            KEY_ACCOUNT_LOCK_AFTER, KEY_ACCOUNT_LOCK_SECONDS, KEY_SOURCE_WINDOW_SECONDS,
            KEY_SOURCE_MAX_ATTEMPTS, KEY_SOURCE_BLOCK_SECONDS, KEY_SESSION_TTL_SECONDS,
            KEY_MAX_ACTIVE_SESSIONS, KEY_MAX_EVENTS, KEY_MIN_FREE_BYTES);

    public Path accountsFile() {
        return accountsFile;
    }

    public Path eventLogFile() {
        return eventLogFile;
    }

    /** Location of the keystore holding the credential-hash key. */
    public Path keystoreFile() {
        return keystoreFile;
    }

    public String passwordEntryAlias() {
        return passwordEntryAlias;
    }

    /** Copy of the keystore password; the caller must not retain or print it. */
    char[] keystorePassword() {
        return keystorePassword == null ? new char[0] : keystorePassword.clone();
    }

    int pbkdf2Iterations() {
        return pbkdf2Iterations;
    }

    int minAcceptedIterations() {
        return minAcceptedIterations;
    }

    int accountLockAfter() {
        return accountLockAfter;
    }

    int accountLockSeconds() {
        return accountLockSeconds;
    }

    int sourceWindowSeconds() {
        return sourceWindowSeconds;
    }

    int sourceMaxAttempts() {
        return sourceMaxAttempts;
    }

    int sourceBlockSeconds() {
        return sourceBlockSeconds;
    }

    public int sessionTtlSeconds() {
        return sessionTtlSeconds;
    }

    int maxActiveSessions() {
        return maxActiveSessions;
    }

    public int maxEvents() {
        return maxEvents;
    }

    public long minFreeBytes() {
        return minFreeBytes;
    }

    /** Wipes the keystore password held here; called once the store has derived its key. */
    public void eraseSecrets() {
        if (keystorePassword != null) {
            java.util.Arrays.fill(keystorePassword, (char) 0);
        }
    }

    @Override
    public String toString() {
        // Deliberately excludes paths and every secret.
        return "AuthConfig[iterations=" + pbkdf2Iterations
                + ", accountLockAfter=" + accountLockAfter
                + ", accountLockSeconds=" + accountLockSeconds
                + ", sourceWindowSeconds=" + sourceWindowSeconds
                + ", sourceMaxAttempts=" + sourceMaxAttempts
                + ", sourceBlockSeconds=" + sourceBlockSeconds
                + ", sessionTtlSeconds=" + sessionTtlSeconds
                + ", maxActiveSessions=" + maxActiveSessions
                + ", maxEvents=" + maxEvents + "]";
    }

    private static Path readableFile(ConfigSource source, String key, List<String> problems, boolean mustExist) {
        String raw = source.get(key);
        if (raw == null || raw.isEmpty()) {
            problems.add(key + " is required");
            return null;
        }
        if (raw.length() > 4096 || raw.indexOf('\0') >= 0) {
            problems.add(key + " is not a usable path");
            return null;
        }
        final Path path;
        try {
            path = Path.of(raw);
        } catch (InvalidPathException e) {
            problems.add(key + " is not a usable path");
            return null;
        }
        if (!path.isAbsolute()) {
            problems.add(key + " must be an absolute path");
            return null;
        }
        if (!mustExist) {
            return path;
        }
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            problems.add(key + " does not name an existing regular file");
            return null;
        }
        return path;
    }

    private static Path eventLogFile(ConfigSource source, List<String> problems) {
        String raw = source.get(KEY_EVENT_LOG_FILE);
        if (raw == null || raw.isEmpty()) {
            problems.add(KEY_EVENT_LOG_FILE + " is required");
            return null;
        }
        if (raw.length() > 4096 || raw.indexOf('\0') >= 0) {
            problems.add(KEY_EVENT_LOG_FILE + " is not a usable path");
            return null;
        }
        final Path path;
        try {
            path = Path.of(raw);
        } catch (InvalidPathException e) {
            problems.add(KEY_EVENT_LOG_FILE + " is not a usable path");
            return null;
        }
        if (!path.isAbsolute()) {
            problems.add(KEY_EVENT_LOG_FILE + " must be an absolute path");
            return null;
        }
        Path parent = path.getParent();
        if (parent == null || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
            problems.add(KEY_EVENT_LOG_FILE + " must live in an existing directory");
            return null;
        }
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS) && !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            problems.add(KEY_EVENT_LOG_FILE + " exists but is not a regular file");
            return null;
        }
        return path;
    }

    private static char[] keystorePassword(ConfigSource source, List<String> problems) {
        String raw = source.get(KEY_KEYSTORE_PASSWORD);
        if (raw == null || raw.isEmpty()) {
            problems.add(KEY_KEYSTORE_PASSWORD + " is required");
            return null;
        }
        if (raw.length() > MAX_KEYSTORE_PASSWORD_CHARS) {
            problems.add(KEY_KEYSTORE_PASSWORD + " is too long");
            return null;
        }
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c < 0x21 || c == 0x7f) {
                problems.add(KEY_KEYSTORE_PASSWORD + " contains a control character or space");
                return null;
            }
        }
        return raw.toCharArray();
    }

    private static String keystoreAlias(ConfigSource source, List<String> problems) {
        String raw = source.get(KEY_PASSWORD_ENTRY_ALIAS);
        if (raw == null || raw.isEmpty()) {
            problems.add(KEY_PASSWORD_ENTRY_ALIAS + " is required");
            return null;
        }
        if (raw.length() > 128) {
            problems.add(KEY_PASSWORD_ENTRY_ALIAS + " is too long");
            return null;
        }
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            boolean allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
            if (!allowed) {
                problems.add(KEY_PASSWORD_ENTRY_ALIAS + " contains an unsupported character");
                return null;
            }
        }
        return raw;
    }

    /**
     * Reads the password entry from the keystore. The value itself is never returned to callers of
     * configuration code, never compared against anything printable, and never logged; only the
     * success of the read is reported.
     */
    private static boolean passwordEntryIsReadable(Path keystore, char[] password, String alias, List<String> problems) {
        // The type must come from the same rule the runtime reader uses. Probing a .jceks file as
        // PKCS12 makes every deployment unbootable while the file itself is correct.
        String type = KeystorePepperProvider.keystoreType(keystore);
        if (type == null) {
            problems.add(KEY_KEYSTORE_FILE + " must be named with a .jceks, .p12, .pfx or .jks suffix");
            return false;
        }
        // Two independent copies of the password: the load and the entry read each get a buffer they
        // own, so wiping one can never hand the other a zeroed key.
        char[] loadPassword = password.clone();
        char[] entryPassword = password.clone();
        try {
            KeyStore ks = KeyStore.getInstance(type);
            try (java.io.InputStream in = Files.newInputStream(keystore)) {
                ks.load(in, loadPassword);
            }
            if (!ks.containsAlias(alias)) {
                problems.add(KEY_KEYSTORE_FILE + " has no entry named by " + KEY_PASSWORD_ENTRY_ALIAS);
                return false;
            }
            KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(entryPassword);
            return entryIsUsable(ks, alias, protection, problems);
        } catch (GeneralSecurityException | IOException | RuntimeException e) {
            // GeneralSecurityException covers a wrong password; the JDK throws IOException for
            // that case too. Only the category is reported, never the message, which can quote a
            // path.
            problems.add(KEY_KEYSTORE_FILE + " could not be opened with " + KEY_KEYSTORE_PASSWORD + " / " + KEY_PASSWORD_ENTRY_ALIAS);
            return false;
        } finally {
            java.util.Arrays.fill(loadPassword, (char) 0);
            java.util.Arrays.fill(entryPassword, (char) 0);
        }
    }

    /**
     * Checks that the entry holds at least {@link PasswordHasher#MIN_PEPPER_BYTES} of key material.
     *
     * <p>{@link KeyStore.SecretKeyEntry} is the only accepted type because it is the only secret
     * entry type the JDK has ({@code PrivateKeyEntry} and {@code TrustedCertificateEntry} are the
     * others). It is also the entry {@code keytool} actually produces for a symmetric secret -
     * {@code keytool -importpass} on this JDK either fails outright or files the value under a
     * private-key entry, which is refused here. Certificates and private keys are refused: neither is
     * a MAC key.
     */
    private static boolean entryIsUsable(KeyStore ks, String alias, KeyStore.ProtectionParameter protection,
            List<String> problems) throws GeneralSecurityException, IOException {
        KeyStore.Entry entry = ks.getEntry(alias, protection);
        if (!(entry instanceof KeyStore.SecretKeyEntry)) {
            problems.add(KEY_KEYSTORE_FILE + " entry named by " + KEY_PASSWORD_ENTRY_ALIAS
                    + " is not a symmetric secret key entry");
            return false;
        }
        byte[] encoded = ((KeyStore.SecretKeyEntry) entry).getSecretKey().getEncoded();
        boolean longEnough = encoded != null && encoded.length >= PasswordHasher.MIN_PEPPER_BYTES;
        if (encoded != null) {
            java.util.Arrays.fill(encoded, (byte) 0);
        }
        if (!longEnough) {
            problems.add(KEY_KEYSTORE_FILE + " secret key entry is shorter than "
                    + PasswordHasher.MIN_PEPPER_BYTES + " bytes");
            return false;
        }
        return true;
    }

    private static int positiveInt(ConfigSource source, String key, List<String> problems, int min, int max) {
        String raw = source.get(key);
        if (raw == null || raw.isEmpty()) {
            problems.add(key + " is required");
            return 0;
        }
        long value;
        try {
            value = Long.parseLong(raw.trim());
        } catch (NumberFormatException e) {
            problems.add(key + " must be an integer");
            return 0;
        }
        if (value < min || value > max) {
            problems.add(key + " must be between " + min + " and " + max);
            return 0;
        }
        return (int) value;
    }

    private static long positiveLong(ConfigSource source, String key, List<String> problems, long min, long max) {
        String raw = source.get(key);
        if (raw == null || raw.isEmpty()) {
            problems.add(key + " is required");
            return 0L;
        }
        long value;
        try {
            value = Long.parseLong(raw.trim());
        } catch (NumberFormatException e) {
            problems.add(key + " must be an integer");
            return 0L;
        }
        if (value < min || value > max) {
            problems.add(key + " must be between " + min + " and " + max);
            return 0L;
        }
        return value;
    }

    private static void requireRegularReadableFile(Path path, String key, List<String> problems, boolean forbidGroupAccess) {
        if (path == null) {
            return;
        }
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            problems.add(key + " does not name an existing regular file");
            return;
        }
        if (!Files.isReadable(path)) {
            problems.add(key + " is not readable");
            return;
        }
        if (forbidGroupAccess && PosixMode.exposedToGroupOrOther(path)) {
            problems.add(key + " is not owner-only, or its permissions could not be verified");
        }
    }

    private static void requireWritableLogFile(Path path, String key, List<String> problems) {
        if (path == null) {
            return;
        }
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                problems.add(key + " exists but is not a regular file");
                return;
            }
            if (!Files.isWritable(path)) {
                problems.add(key + " is not writable");
                return;
            }
            if (PosixMode.writableByGroupOrOther(path)) {
                problems.add(key + " is writable by group or other users, "
                        + "or its permissions could not be verified");
                return;
            }
            try {
                if (Files.size(path) > maxLogBytes()) {
                    problems.add(key + " is larger than the accepted log size; rotate it first");
                }
            } catch (IOException e) {
                problems.add(key + " size could not be determined");
            }
        } else if (PosixMode.writableByGroupOrOther(path.getParent())) {
            problems.add("the directory for " + key + " is writable by group or other users, "
                    + "or its permissions could not be verified");
        }
    }

    /**
     * The same ceiling {@link AuditLogger} enforces per write. One constant on purpose: a start-up
     * bound the running process does not maintain is a bound that guarantees the next restart fails.
     */
    private static long maxLogBytes() {
        return AuditLogger.MAX_LOG_BYTES;
    }

    private static long freeBytes(Path directory) {
        try {
            return Files.getFileStore(directory).getUsableSpace();
        } catch (IOException | RuntimeException e) {
            return 0L;
        }
    }

    /** Builder for {@link AuthConfig}; every setter validates its argument. */
    public static final class Builder {

        private Path accountsFile;
        private Path eventLogFile;
        private Path keystoreFile;
        private char[] keystorePassword;
        private String passwordEntryAlias;
        private int pbkdf2Iterations = MIN_PBKDF2_ITERATIONS;
        private int minAcceptedIterations = 50_000;
        private int accountLockAfter = 5;
        private int accountLockSeconds = 300;
        private int sourceWindowSeconds = 300;
        private int sourceMaxAttempts = 60;
        private int sourceBlockSeconds = 300;
        private int sessionTtlSeconds = 1800;
        private int maxActiveSessions = 10_000;
        private int maxEvents = 10_000;
        private long minFreeBytes = 16L * 1024 * 1024;
        private ZoneId clockZone = ZoneId.of("UTC");

        private Builder() {
        }

        public Builder accountsFile(Path value) {
            this.accountsFile = requireAbsolute(value, "accountsFile");
            return this;
        }

        public Builder eventLogFile(Path value) {
            this.eventLogFile = requireAbsolute(value, "eventLogFile");
            return this;
        }

        public Builder keystoreFile(Path value) {
            this.keystoreFile = requireAbsolute(value, "keystoreFile");
            return this;
        }

        /**
         * Accepts the keystore password. The array is copied so the caller can wipe its own copy
         * immediately; this config wipes its copy in {@link AuthConfig#eraseSecrets()}.
         */
        public Builder keystorePassword(char[] value) {
            if (value == null || value.length == 0 || value.length > MAX_KEYSTORE_PASSWORD_CHARS) {
                throw new IllegalArgumentException("keystorePassword length");
            }
            this.keystorePassword = value.clone();
            return this;
        }

        public Builder passwordEntryAlias(String value) {
            if (value == null || value.isEmpty() || value.length() > 128) {
                throw new IllegalArgumentException("passwordEntryAlias");
            }
            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                boolean allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
                if (!allowed) {
                    throw new IllegalArgumentException("passwordEntryAlias");
                }
            }
            this.passwordEntryAlias = value;
            return this;
        }

        public Builder pbkdf2Iterations(int value) {
            if (value < MIN_PBKDF2_ITERATIONS || value > MAX_ITERATIONS) {
                throw new IllegalArgumentException("pbkdf2Iterations");
            }
            this.pbkdf2Iterations = value;
            return this;
        }

        public Builder minAcceptedIterations(int value) {
            if (value < MIN_STORED_ITERATIONS || value > MAX_STORED_ITERATIONS) {
                throw new IllegalArgumentException("minAcceptedIterations");
            }
            this.minAcceptedIterations = value;
            return this;
        }

        public Builder accountLockAfter(int value) {
            if (value < MIN_LOCK_AFTER || value > MAX_LOCK_AFTER) {
                throw new IllegalArgumentException("accountLockAfter");
            }
            this.accountLockAfter = value;
            return this;
        }

        public Builder accountLockSeconds(int value) {
            if (value < MIN_LOCK_SECONDS || value > MAX_LOCK_SECONDS) {
                throw new IllegalArgumentException("accountLockSeconds");
            }
            this.accountLockSeconds = value;
            return this;
        }

        public Builder sourceWindowSeconds(int value) {
            if (value < MIN_WINDOW_SECONDS || value > MAX_WINDOW_SECONDS) {
                throw new IllegalArgumentException("sourceWindowSeconds");
            }
            this.sourceWindowSeconds = value;
            return this;
        }

        public Builder sourceMaxAttempts(int value) {
            if (value < MIN_SOURCE_ATTEMPTS || value > MAX_SOURCE_ATTEMPTS) {
                throw new IllegalArgumentException("sourceMaxAttempts");
            }
            this.sourceMaxAttempts = value;
            return this;
        }

        public Builder sourceBlockSeconds(int value) {
            if (value < MIN_BLOCK_SECONDS || value > MAX_BLOCK_SECONDS) {
                throw new IllegalArgumentException("sourceBlockSeconds");
            }
            this.sourceBlockSeconds = value;
            return this;
        }

        public Builder sessionTtlSeconds(int value) {
            if (value < MIN_SESSION_TTL || value > MAX_SESSION_TTL) {
                throw new IllegalArgumentException("sessionTtlSeconds");
            }
            this.sessionTtlSeconds = value;
            return this;
        }

        public Builder maxActiveSessions(int value) {
            if (value < MIN_SESSIONS || value > MAX_SESSIONS) {
                throw new IllegalArgumentException("maxActiveSessions");
            }
            this.maxActiveSessions = value;
            return this;
        }

        public Builder maxEvents(int value) {
            if (value < MIN_EVENTS || value > MAX_EVENTS) {
                throw new IllegalArgumentException("maxEvents");
            }
            this.maxEvents = value;
            return this;
        }

        public Builder minFreeBytes(long value) {
            if (value < MIN_FREE_BYTES_FLOOR) {
                throw new IllegalArgumentException("minFreeBytes");
            }
            this.minFreeBytes = value;
            return this;
        }

        public Builder clockZone(ZoneId value) {
            this.clockZone = value == null ? ZoneId.of("UTC") : value;
            return this;
        }

        public AuthConfig build() throws InvalidConfigException {
            List<String> problems = new ArrayList<>();
            if (accountsFile == null) {
                problems.add("accounts file is required");
            }
            if (eventLogFile == null) {
                problems.add("event log file is required");
            }
            if (keystoreFile == null) {
                problems.add("keystore file is required");
            }
            if (keystorePassword == null || keystorePassword.length == 0) {
                problems.add("keystore password is required");
            }
            if (passwordEntryAlias == null) {
                problems.add("password entry alias is required");
            }
            if (pbkdf2Iterations < MIN_PBKDF2_ITERATIONS) {
                problems.add("pbkdf2 iterations is below the floor");
            }
            if (pbkdf2Iterations < minAcceptedIterations) {
                problems.add("pbkdf2 iterations must not be below the minimum accepted stored iteration count");
            }
            if (sourceMaxAttempts < accountLockAfter) {
                // A source budget lower than the account lock threshold lets one compromised
                // account name consume the whole per-source budget, so a shared NAT or proxy
                // address is locked out by a single targeted attacker.
                problems.add("per-source attempt budget must be at least the account lock threshold");
            }
            if (!problems.isEmpty()) {
                throw new InvalidConfigException(problems);
            }
            return new AuthConfig(this);
        }

        private static Path requireAbsolute(Path value, String field) {
            if (value == null || !value.isAbsolute()) {
                throw new IllegalArgumentException(field + " must be absolute");
            }
            return value.toAbsolutePath().normalize();
        }
    }
}
