package com.example.auth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Configuration, loaded from the environment at startup.
 *
 * <p>Every value here crosses a trust boundary (environment, file system), so each
 * one is validated for type, length and allowed characters before use. There are no
 * built-in credentials and no permissive fallbacks: a missing or malformed value is
 * a hard startup failure.
 */
public final class AuthConfig implements AutoCloseable {

    /** Allowed JDBC URL shapes. Anything else is rejected rather than guessed at. */
    private static final Pattern JDBC_URL =
            Pattern.compile("^jdbc:(postgresql|h2):[A-Za-z0-9_:;,.=&/?@\\-]{1,480}$");

    /**
     * JDBC URL sub-options that can make the driver read or execute files, or write
     * trace output. Configuration is normally trusted, but a single mis-set variable
     * should not turn into code execution, so they are refused outright.
     */
    private static final String[] FORBIDDEN_URL_TOKENS = {
            "init=", "runscript", "trace_level", "script_", "shutdown",
            "allowothersettings", "socketfactory", "loggerfile", "sslfactory",
    };

    private static final int MAX_SECRET_FILE_BYTES = 4096;

    private final String jdbcUrl;
    private final String dbUser;
    private final char[] dbPassword;
    private final String sourceId;
    private final int maxAttemptsPerSource;
    private final int maxAttemptsPerAccount;
    private final Duration throttleWindow;
    private final Duration sessionTtl;
    private final Path sessionTokenFile;

    private AuthConfig(String jdbcUrl, String dbUser, char[] dbPassword, String sourceId,
                       int maxAttemptsPerSource, int maxAttemptsPerAccount,
                       Duration throttleWindow, Duration sessionTtl, Path sessionTokenFile) {
        this.jdbcUrl = jdbcUrl;
        this.dbUser = dbUser;
        this.dbPassword = dbPassword;
        this.sourceId = sourceId;
        this.maxAttemptsPerSource = maxAttemptsPerSource;
        this.maxAttemptsPerAccount = maxAttemptsPerAccount;
        this.throttleWindow = throttleWindow;
        this.sessionTtl = sessionTtl;
        this.sessionTokenFile = sessionTokenFile;
    }

    public static AuthConfig fromEnvironment() {
        String url = required("AUTH_DB_URL");
        if (!JDBC_URL.matcher(url).matches()) {
            throw new ConfigException("AUTH_DB_URL is not an accepted jdbc:postgresql: / jdbc:h2: URL");
        }
        String lowered = url.toLowerCase(Locale.ROOT);
        for (String token : FORBIDDEN_URL_TOKENS) {
            if (lowered.contains(token)) {
                throw new ConfigException("AUTH_DB_URL contains a forbidden option");
            }
        }

        String dbUser = optional("AUTH_DB_USER", "");
        if (dbUser.length() > 128 || !dbUser.chars().allMatch(c -> c >= 0x20 && c < 0x7F)) {
            throw new ConfigException("AUTH_DB_USER is too long or contains control characters");
        }

        char[] dbPassword = readDbPassword();

        // Per-source scope key: the caller's network address or client id, supplied by
        // the trusted deployment (not by the remote user) and validated all the same.
        String sourceId = optional("AUTH_SOURCE_ID", "local-cli");
        if (!InputValidator.isValidSourceId(sourceId)) {
            Arrays.fill(dbPassword, '\0');
            throw new ConfigException("AUTH_SOURCE_ID must be 1-64 chars of [A-Za-z0-9.:_-]");
        }

        int perSource = intInRange("AUTH_MAX_ATTEMPTS_PER_SOURCE", 30, 3, 10_000);
        int perAccount = intInRange("AUTH_MAX_ATTEMPTS_PER_ACCOUNT", 10, 3, 1_000);
        Duration window = Duration.ofSeconds(intInRange("AUTH_THROTTLE_WINDOW_SECONDS", 900, 30, 86_400));
        Duration sessionTtl = Duration.ofSeconds(intInRange("AUTH_SESSION_TTL_SECONDS", 1800, 60, 86_400));

        Path tokenFile = null;
        String tokenFileRaw = System.getenv("AUTH_SESSION_FILE");
        if (tokenFileRaw != null && !tokenFileRaw.isBlank()) {
            if (tokenFileRaw.length() > 1024) {
                Arrays.fill(dbPassword, '\0');
                throw new ConfigException("AUTH_SESSION_FILE path is too long");
            }
            tokenFile = Path.of(tokenFileRaw).toAbsolutePath().normalize();
        }

        return new AuthConfig(url, dbUser, dbPassword, sourceId, perSource, perAccount,
                window, sessionTtl, tokenFile);
    }

    /**
     * Database password: preferred from a file that only its owner can read, so the
     * secret never appears in a process listing or in a shared environment dump.
     */
    private static char[] readDbPassword() {
        String file = System.getenv("AUTH_DB_PASSWORD_FILE");
        if (file != null && !file.isBlank()) {
            Path path = Path.of(file).toAbsolutePath().normalize();
            byte[] raw = null;
            try {
                if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                    throw new ConfigException("AUTH_DB_PASSWORD_FILE is not a regular file");
                }
                if (Files.size(path) > MAX_SECRET_FILE_BYTES) {
                    throw new ConfigException("AUTH_DB_PASSWORD_FILE is larger than "
                            + MAX_SECRET_FILE_BYTES + " bytes");
                }
                requireOwnerOnly(path);
                raw = Files.readAllBytes(path);
                String text = new String(raw, StandardCharsets.UTF_8);
                // Strip only a trailing newline; do not alter the secret otherwise.
                if (text.endsWith("\r\n")) {
                    text = text.substring(0, text.length() - 2);
                } else if (text.endsWith("\n") || text.endsWith("\r")) {
                    text = text.substring(0, text.length() - 1);
                }
                if (text.isEmpty()) {
                    throw new ConfigException("AUTH_DB_PASSWORD_FILE is empty");
                }
                return text.toCharArray();
            } catch (IOException e) {
                throw new ConfigException("AUTH_DB_PASSWORD_FILE could not be read");
            } finally {
                if (raw != null) {
                    Arrays.fill(raw, (byte) 0);
                }
            }
        }
        String env = System.getenv("AUTH_DB_PASSWORD");
        if (env != null) {
            if (env.length() > MAX_SECRET_FILE_BYTES) {
                throw new ConfigException("AUTH_DB_PASSWORD is too long");
            }
            return env.toCharArray();
        }
        // Embedded in-memory H2 (demo only) legitimately has no password.
        return new char[0];
    }

    private static void requireOwnerOnly(Path path) throws IOException {
        PosixFileAttributeView view =
                Files.getFileAttributeView(path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            return; // non-POSIX file system; permissions enforced by the platform ACL
        }
        PosixFileAttributes attrs = view.readAttributes();
        Set<PosixFilePermission> perms = attrs.permissions();
        boolean sharedRead = perms.contains(PosixFilePermission.GROUP_READ)
                || perms.contains(PosixFilePermission.OTHERS_READ)
                || perms.contains(PosixFilePermission.GROUP_WRITE)
                || perms.contains(PosixFilePermission.OTHERS_WRITE);
        if (sharedRead) {
            throw new ConfigException("AUTH_DB_PASSWORD_FILE must not be readable or writable "
                    + "by group or others (chmod 600)");
        }
    }

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new ConfigException(name + " is required");
        }
        return value.trim();
    }

    private static String optional(String name, String fallback) {
        String value = System.getenv(name);
        return (value == null || value.isBlank()) ? fallback : value.trim();
    }

    private static int intInRange(String name, int fallback, int min, int max) {
        String raw = System.getenv(name);
        if (raw == null || raw.isBlank()) {
            return fallback;
        }
        int parsed;
        try {
            parsed = Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            throw new ConfigException(name + " must be an integer");
        }
        if (parsed < min || parsed > max) {
            throw new ConfigException(name + " must be between " + min + " and " + max);
        }
        return parsed;
    }

    public String jdbcUrl() { return jdbcUrl; }
    public String dbUser() { return dbUser; }
    /** Caller must not retain or log the returned array. */
    char[] dbPassword() { return dbPassword; }
    public String sourceId() { return sourceId; }
    public int maxAttemptsPerSource() { return maxAttemptsPerSource; }
    public int maxAttemptsPerAccount() { return maxAttemptsPerAccount; }
    public Duration throttleWindow() { return throttleWindow; }
    public Duration sessionTtl() { return sessionTtl; }
    public Path sessionTokenFile() { return sessionTokenFile; }

    /** Clears the database password from memory. */
    @Override
    public void close() {
        Arrays.fill(dbPassword, '\0');
    }

    /** Thrown for invalid configuration. Messages never contain secret values. */
    public static final class ConfigException extends RuntimeException {
        private static final long serialVersionUID = 1L;
        public ConfigException(String message) { super(message); }
    }
}
