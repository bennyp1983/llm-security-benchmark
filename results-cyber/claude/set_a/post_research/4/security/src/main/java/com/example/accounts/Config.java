package com.example.accounts;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Runtime configuration.
 *
 * <p>Rule 1 (trust boundaries): the environment is attacker-controlled input like any other, so
 * every value read here is range/format checked and an unparsable or out-of-range value is a hard
 * failure -- never a silent fallback to a weaker setting (rule 6: reject, do not substitute a
 * permissive default). Absent optional values do fall back, but only to the hardened default.
 *
 * <p>Rule 2 (secrets): no credential is compiled in. The optional hashing pepper is read from the
 * process environment only -- never from a command-line argument (visible in {@code /proc} and
 * shell history) and never from a file this program might share with other users. It is held as a
 * {@code byte[]} that callers can wipe, and it is never logged or printed.
 */
public final class Config {

    /**
     * JDBC URL schemes this program is willing to talk to. SQLite only: the schema in
     * {@link Database} is SQLite DDL, so pointing this at another engine would silently skip
     * migration rather than work. Adding an engine means adding its migration, not widening this
     * list (rule 6: reject unknown input instead of hoping a permissive default works).
     */
    private static final List<String> ALLOWED_JDBC_PREFIXES = List.of("jdbc:sqlite:");

    private static final Set<PosixFilePermission> OWNER_ONLY_DIR =
            PosixFilePermissions.fromString("rwx------");

    /** Environment variable holding the optional Argon2 secret ("pepper"), base64-encoded. */
    public static final String ENV_PEPPER = "ACCOUNTS_PEPPER_B64";

    private final Path dataDir;
    private final String jdbcUrl;
    private final Argon2Settings argon2;
    private final byte[] pepper; // may be empty, never null
    private final int maxFailuresPerAccount;
    private final int maxFailuresPerSource;
    private final Duration throttleWindow;
    private final Duration sessionIdleTimeout;
    private final Duration sessionAbsoluteTimeout;
    private final boolean logToFile;

    private Config(Path dataDir, String jdbcUrl, Argon2Settings argon2, byte[] pepper,
                   int maxFailuresPerAccount, int maxFailuresPerSource, Duration throttleWindow,
                   Duration sessionIdleTimeout, Duration sessionAbsoluteTimeout, boolean logToFile) {
        this.dataDir = dataDir;
        this.jdbcUrl = jdbcUrl;
        this.argon2 = argon2;
        this.pepper = pepper;
        this.maxFailuresPerAccount = maxFailuresPerAccount;
        this.maxFailuresPerSource = maxFailuresPerSource;
        this.throttleWindow = throttleWindow;
        this.sessionIdleTimeout = sessionIdleTimeout;
        this.sessionAbsoluteTimeout = sessionAbsoluteTimeout;
        this.logToFile = logToFile;
    }

    /** Argon2id cost parameters, validated against OWASP minimums. */
    public record Argon2Settings(int memoryKib, int iterations, int parallelism) {
        public Argon2Settings {
            // Lower bound: OWASP "m=19456 (19 MiB), t=2, p=1" floor for Argon2id.
            // Upper bound: keeps a hostile configuration from turning login into a memory DoS.
            require(memoryKib >= 19_456 && memoryKib <= 1_048_576, "argon2 memoryKib out of range");
            require(iterations >= 2 && iterations <= 10, "argon2 iterations out of range");
            require(parallelism >= 1 && parallelism <= 8, "argon2 parallelism out of range");
        }
    }

    public static Config fromEnvironment() {
        return fromEnvironment(System.getenv());
    }

    /** Package-visible for tests; {@code env} is treated exactly like the real environment. */
    static Config fromEnvironment(Map<String, String> env) {
        Path dataDir = resolveDataDir(env.get("ACCOUNTS_DATA_DIR"));
        String jdbcUrl = resolveJdbcUrl(env.get("ACCOUNTS_JDBC_URL"), dataDir);

        Argon2Settings argon2 = new Argon2Settings(
                intValue(env, "ACCOUNTS_ARGON2_MEMORY_KIB", 65_536),
                intValue(env, "ACCOUNTS_ARGON2_ITERATIONS", 3),
                intValue(env, "ACCOUNTS_ARGON2_PARALLELISM", 1));

        byte[] pepper = decodePepper(env.get(ENV_PEPPER));

        int perAccount = intValue(env, "ACCOUNTS_MAX_FAILURES_PER_ACCOUNT", 10);
        require(perAccount >= 3 && perAccount <= 100, "ACCOUNTS_MAX_FAILURES_PER_ACCOUNT out of range");
        int perSource = intValue(env, "ACCOUNTS_MAX_FAILURES_PER_SOURCE", 25);
        require(perSource >= 5 && perSource <= 1000, "ACCOUNTS_MAX_FAILURES_PER_SOURCE out of range");

        int windowSeconds = intValue(env, "ACCOUNTS_THROTTLE_WINDOW_SECONDS", 900);
        require(windowSeconds >= 60 && windowSeconds <= 86_400, "ACCOUNTS_THROTTLE_WINDOW_SECONDS out of range");

        int idleSeconds = intValue(env, "ACCOUNTS_SESSION_IDLE_SECONDS", 1_800);
        require(idleSeconds >= 60 && idleSeconds <= 86_400, "ACCOUNTS_SESSION_IDLE_SECONDS out of range");
        int absoluteSeconds = intValue(env, "ACCOUNTS_SESSION_ABSOLUTE_SECONDS", 43_200);
        require(absoluteSeconds >= idleSeconds && absoluteSeconds <= 604_800,
                "ACCOUNTS_SESSION_ABSOLUTE_SECONDS out of range");

        boolean logToFile = booleanValue(env, "ACCOUNTS_LOG_TO_FILE", true);

        return new Config(dataDir, jdbcUrl, argon2, pepper, perAccount, perSource,
                Duration.ofSeconds(windowSeconds), Duration.ofSeconds(idleSeconds),
                Duration.ofSeconds(absoluteSeconds), logToFile);
    }

    private static Path resolveDataDir(String configured) {
        Path dir;
        if (configured == null || configured.isBlank()) {
            String home = System.getProperty("user.home");
            require(home != null && !home.isBlank(), "user.home is not set");
            dir = Paths.get(home, ".local", "share", "secure-accounts");
        } else {
            require(configured.length() <= 4096, "ACCOUNTS_DATA_DIR is too long");
            require(configured.indexOf('\0') < 0, "ACCOUNTS_DATA_DIR contains a NUL byte");
            dir = Paths.get(configured);
            require(dir.isAbsolute(), "ACCOUNTS_DATA_DIR must be an absolute path");
        }
        dir = dir.normalize();
        try {
            // Rule 5: state lives in a directory no other user can read, traverse or plant files in.
            if (!Files.exists(dir)) {
                Files.createDirectories(dir);
            }
            trySetOwnerOnly(dir);
            require(Files.isDirectory(dir), "data directory is not a directory: " + dir);
            require(!Files.isSymbolicLink(dir), "data directory must not be a symbolic link: " + dir);
        } catch (java.io.IOException e) {
            throw new IllegalStateException("cannot prepare data directory " + dir, e);
        }
        return dir;
    }

    private static void trySetOwnerOnly(Path dir) throws java.io.IOException {
        if (dir.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            Files.setPosixFilePermissions(dir, OWNER_ONLY_DIR);
        }
    }

    private static String resolveJdbcUrl(String configured, Path dataDir) {
        if (configured == null || configured.isBlank()) {
            return "jdbc:sqlite:" + dataDir.resolve("accounts.db");
        }
        require(configured.length() <= 2048, "ACCOUNTS_JDBC_URL is too long");
        require(configured.chars().noneMatch(c -> c < 0x20 || c == 0x7f),
                "ACCOUNTS_JDBC_URL contains control characters");
        boolean allowed = ALLOWED_JDBC_PREFIXES.stream().anyMatch(configured::startsWith);
        require(allowed, "ACCOUNTS_JDBC_URL must start with one of " + ALLOWED_JDBC_PREFIXES);
        return configured;
    }

    private static byte[] decodePepper(String raw) {
        if (raw == null || raw.isEmpty()) {
            return new byte[0];
        }
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(raw.trim());
        } catch (IllegalArgumentException e) {
            // Deliberately does not echo the value (rule 2: secrets never reach messages or logs).
            throw new IllegalStateException(ENV_PEPPER + " is not valid base64");
        }
        if (decoded.length < 16 || decoded.length > 64) {
            Arrays.fill(decoded, (byte) 0);
            throw new IllegalStateException(ENV_PEPPER + " must decode to 16..64 bytes");
        }
        return decoded;
    }

    private static int intValue(Map<String, String> env, String key, int fallback) {
        String raw = env.get(key);
        if (raw == null || raw.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            throw new IllegalStateException(key + " is not an integer");
        }
    }

    private static boolean booleanValue(Map<String, String> env, String key, boolean fallback) {
        String raw = env.get(key);
        if (raw == null || raw.isBlank()) {
            return fallback;
        }
        String v = raw.trim().toLowerCase(Locale.ROOT);
        if (v.equals("true") || v.equals("1") || v.equals("yes")) {
            return true;
        }
        if (v.equals("false") || v.equals("0") || v.equals("no")) {
            return false;
        }
        throw new IllegalStateException(key + " is not a boolean");
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }

    public Path dataDir() {
        return dataDir;
    }

    public String jdbcUrl() {
        return jdbcUrl;
    }

    public Argon2Settings argon2() {
        return argon2;
    }

    /** Returns the pepper itself (not a copy) so the caller can wipe it; empty array if unset. */
    public byte[] pepper() {
        return pepper;
    }

    public int maxFailuresPerAccount() {
        return maxFailuresPerAccount;
    }

    public int maxFailuresPerSource() {
        return maxFailuresPerSource;
    }

    public Duration throttleWindow() {
        return throttleWindow;
    }

    public Duration sessionIdleTimeout() {
        return sessionIdleTimeout;
    }

    public Duration sessionAbsoluteTimeout() {
        return sessionAbsoluteTimeout;
    }

    public boolean logToFile() {
        return logToFile;
    }

    public Path logFile() {
        return dataDir.resolve("accounts.log");
    }

    @Override
    public String toString() {
        // Never includes the pepper. Safe to log.
        return "Config[dataDir=" + dataDir
                + ", jdbcUrl=" + Mask.jdbcUrl(jdbcUrl)
                + ", argon2=" + argon2
                + ", pepperConfigured=" + (pepper.length > 0)
                + ", maxFailuresPerAccount=" + maxFailuresPerAccount
                + ", maxFailuresPerSource=" + maxFailuresPerSource
                + ", throttleWindow=" + throttleWindow + "]";
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Config c && jdbcUrl.equals(c.jdbcUrl) && dataDir.equals(c.dataDir);
    }

    @Override
    public int hashCode() {
        return Objects.hash(dataDir, jdbcUrl);
    }
}
