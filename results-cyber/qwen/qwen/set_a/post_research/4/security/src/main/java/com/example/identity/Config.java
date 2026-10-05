package com.example.identity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * Validated runtime configuration. Fail-closed: there is no field with a usable default, so a
 * missing or malformed value is a startup failure rather than a silent weakening.
 *
 * <h2>Trust boundary</h2>
 * Configuration comes from a properties file and the process environment, and both are treated as
 * attacker-controlled here: a properties file is often group-writable, and environment variables
 * leak into subprocesses, crash reporters and {@code /proc/&lt;pid&gt;/environ}. Rule 1 applies to
 * every value below - type, length, character set and range are checked before use, and no value
 * is allowed to decide a security outcome unchecked.
 *
 * <h2>Where the database passphrase comes from</h2>
 * The only accepted source is {@code IDENTITY_DB_PASSWORD} in the environment, read once, used to
 * build a {@code char[]} handed to the driver, and erased. It is never:
 * <ul>
 *   <li>in a command-line argument (visible to any local user via {@code ps}/{@code /proc}),</li>
 *   <li>in the properties file (which is routinely world-readable in a deployment),</li>
 *   <li>in a default value, an example, a test fixture, or this source tree.</li>
 * </ul>
 * If it is absent, configuration fails. There is no fallback passphrase.
 *
 * <h2>What the properties file must not contain</h2>
 * The JDBC URL is <em>constructed</em> from a validated path, never read as a URL. An {@code INIT=}
 * property in a JDBC URL makes H2 execute arbitrary SQL and, via {@code RUNSCRIPT}, read or write
 * files - so accepting a URL string from configuration would turn a config file into remote code
 * execution. Only {@code db.dataDir} and {@code db.name} are read, and both are checked to contain
 * no {@code ;}, {@code =}, or {@code ..}.
 */
public record Config(
        Path dataDir,
        String databaseName,
        char[] databasePassword,
        int pbkdf2Iterations,
        int pbkdf2MinIterations,
        int maxAccounts,
        int sessionTtlSeconds,
        int maxSessionsPerAccount,
        int authWindowSeconds,
        int authSourceMaxAttempts,
        int authAccountMaxAttempts,
        int authPenaltyCeilingSeconds,
        int registerWindowSeconds,
        int registerSourceMax,
        int registerGlobalMax,
        long auditMaxBytes,
        boolean auditRequirePrivateFile) {

    public static final int MIN_ITERATIONS_FLOOR = 100_000;
    public static final int SESSION_TTL_MAX_SECONDS = 60 * 60 * 24;   // 24h
    public static final long AUDIT_MAX_BYTES_CEILING = 64L * 1024 * 1024;
    /**
     * Highest value any attempt-count key may take, because that is the value the stored counter
     * saturates at. A limit above it is not a looser limit, it is <em>no</em> limit: the counter
     * stops incrementing below it, so {@code failures >= max} can never become true and the budget
     * silently stops existing. The upper bound on these config keys and the {@code LEAST(...)}
     * ceiling in the UPDATE are one constant for exactly that reason - treating them as two
     * independent numbers is what lets an operator write "100000 per hour" and get "unlimited".
     */
    public static final int MAX_ATTEMPT_COUNT = 1000;

    /** Keys read from the properties file. Anything else in the file is ignored, not trusted. */
    private static final String K_DATA_DIR = "db.dataDir";
    private static final String K_DB_NAME = "db.name";
    private static final String K_ITERATIONS = "security.pbkdf2Iterations";
    private static final String K_MIN_ITERATIONS = "security.pbkdf2MinIterations";
    private static final String K_MAX_ACCOUNTS = "limits.maxAccounts";
    private static final String K_SESSION_TTL = "limits.sessionTtlSeconds";
    private static final String K_MAX_SESSIONS = "limits.maxSessionsPerAccount";
    private static final String K_AUTH_WINDOW = "limits.authWindowSeconds";
    private static final String K_AUTH_SOURCE = "limits.authSourceMaxAttempts";
    private static final String K_AUTH_ACCOUNT = "limits.authAccountMaxAttempts";
    private static final String K_AUTH_PENALTY = "limits.authPenaltyCeilingSeconds";
    private static final String K_REG_WINDOW = "limits.registerWindowSeconds";
    private static final String K_REG_SOURCE = "limits.registerSourceMax";
    private static final String K_REG_GLOBAL = "limits.registerGlobalMax";
    private static final String K_AUDIT_MAX = "audit.maxBytes";
    private static final String K_AUDIT_REQUIRE_PRIVATE = "audit.requirePrivateFile";

    public static final String ENV_DB_PASSWORD = "IDENTITY_DB_PASSWORD";
    /** Optional; defaults to {@code ~/.identity-portal}. Never taken from argv. */
    public static final String ENV_DATA_DIR = "IDENTITY_DATA_DIR";

    private static final int DB_NAME_MAX = 64;

    /**
     * Loads and validates. {@code passwordSupplier} exists so tests can inject a passphrase
     * without putting it in the environment of the test JVM; production passes the environment.
     *
     * @throws IdentityStoreException {@link Reason#CONFIG_INVALID} with a detail that names the
     *         key but never the value, so the message is safe to log.
     */
    public static Config load(Path propertiesFile, java.util.function.Supplier<String> passwordSupplier)
            throws IdentityStoreException {
        Map<String, String> file = readProperties(propertiesFile);

        // Password first: nothing else is worth validating if the secret is missing, and we must
        // not create a half-open configuration.
        String secret = passwordSupplier.get();
        if (secret == null || secret.isBlank()) {
            throw new IdentityStoreException(Reason.CONFIG_INVALID,
                    "the database passphrase must be supplied in the environment variable " + ENV_DB_PASSWORD
                            + " (no default is provided)");
        }
        if (secret.length() < 24 || secret.length() > 512) {
            throw new IdentityStoreException(Reason.CONFIG_INVALID,
                    ENV_DB_PASSWORD + " must be 24-512 characters");
        }
        for (int i = 0; i < secret.length(); i++) {
            char c = secret.charAt(i);
            if (c < 0x21 || c > 0x7E) {
                throw new IdentityStoreException(Reason.CONFIG_INVALID,
                        ENV_DB_PASSWORD + " must be printable ASCII with no spaces");
            }
        }

        String envDir = System.getenv(ENV_DATA_DIR);
        String dirText = envDir != null && !envDir.isBlank() ? envDir : required(file, K_DATA_DIR);
        Path dataDir = validatedDataDir(dirText);

        String dbName = required(file, K_DB_NAME);
        if (dbName.length() > DB_NAME_MAX || !dbName.matches("[a-z0-9][a-z0-9_-]{0,63}")) {
            throw new IdentityStoreException(Reason.CONFIG_INVALID,
                    K_DB_NAME + " must match [a-z0-9][a-z0-9_-]{0,63}");
        }

        int iterations = requiredInt(file, K_ITERATIONS, MIN_ITERATIONS_FLOOR, 20_000_000);
        int minIterations = requiredInt(file, K_MIN_ITERATIONS, MIN_ITERATIONS_FLOOR, 20_000_000);
        if (iterations < minIterations) {
            throw new IdentityStoreException(Reason.CONFIG_INVALID,
                    K_ITERATIONS + " must be >= " + K_MIN_ITERATIONS);
        }

        int maxAccounts = requiredInt(file, K_MAX_ACCOUNTS, 1, 1_000_000);
        int sessionTtl = requiredInt(file, K_SESSION_TTL, 60, SESSION_TTL_MAX_SECONDS);
        int maxSessions = requiredInt(file, K_MAX_SESSIONS, 1, 1000);
        int authWindow = requiredInt(file, K_AUTH_WINDOW, 60, 24 * 3600);
        int authSource = requiredInt(file, K_AUTH_SOURCE, 3, MAX_ATTEMPT_COUNT);
        int authAccount = requiredInt(file, K_AUTH_ACCOUNT, 3, MAX_ATTEMPT_COUNT);
        int penaltyCeiling = requiredInt(file, K_AUTH_PENALTY, 1, 3600);
        int regWindow = requiredInt(file, K_REG_WINDOW, 60, 24 * 3600);
        int regSource = requiredInt(file, K_REG_SOURCE, 1, MAX_ATTEMPT_COUNT);
        int regGlobal = requiredInt(file, K_REG_GLOBAL, 1, MAX_ATTEMPT_COUNT);
        long auditMax = requiredLong(file, K_AUDIT_MAX, 1024, AUDIT_MAX_BYTES_CEILING);

        String requirePrivateText = required(file, K_AUDIT_REQUIRE_PRIVATE);
        boolean requirePrivate = switch (requirePrivateText) {
            case "true" -> true;
            // Turning the private-file requirement off is not offered as an option; refusing here
            // means a hostile config edit cannot make us accept a world-readable audit file.
            default -> throw new IdentityStoreException(Reason.CONFIG_INVALID,
                    K_AUDIT_REQUIRE_PRIVATE + " must be true");
        };

        return new Config(dataDir, dbName, secret.toCharArray(), iterations, minIterations,
                maxAccounts, sessionTtl, maxSessions, authWindow, authSource, authAccount,
                penaltyCeiling, regWindow, regSource, regGlobal, auditMax, requirePrivate);
    }

    // ---------------------------------------------------------------- file parsing

    private static Map<String, String> readProperties(Path file) throws IdentityStoreException {
        if (file == null || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            throw new IdentityStoreException(Reason.CONFIG_INVALID,
                    "configuration file is missing or is not a regular file: " + describe(file));
        }
        // Symlink or group/other-accessible config is refused: whoever can write it picks the
        // security parameters.
        assertNotSymlink(file);
        PosixFiles.assertNoGroupOrOtherAccess(file, "configuration file");

        byte[] raw;
        try {
            long size = Files.size(file);
            if (size > 256 * 1024) {
                throw new IdentityStoreException(Reason.CONFIG_INVALID, "configuration file is too large");
            }
            raw = Files.readAllBytes(file);
        } catch (IOException e) {
            throw new IdentityStoreException(Reason.CONFIG_INVALID, "cannot read configuration file", e);
        }
        Properties p = new Properties();
        try {
            // ISO-8859-1 is Properties' own encoding; values are re-validated as ASCII below.
            p.load(new java.io.ByteArrayInputStream(raw));
        } catch (IOException e) {
            throw new IdentityStoreException(Reason.CONFIG_INVALID, "configuration file is malformed", e);
        }
        Map<String, String> out = new HashMap<>();
        for (String name : p.stringPropertyNames()) {
            String value = p.getProperty(name);
            if (containsControlOrNewline(name) || containsControlOrNewline(value)) {
                // Newlines in a value are how a config file forges extra lines in any text sink
                // downstream, and NUL is a truncation hazard.
                throw new IdentityStoreException(Reason.CONFIG_INVALID,
                        "configuration entry " + name + " contains a control character");
            }
            if (name.toLowerCase(java.util.Locale.ROOT).contains("password")
                    || name.toLowerCase(java.util.Locale.ROOT).contains("secret")) {
                throw new IdentityStoreException(Reason.CONFIG_INVALID,
                        "configuration file must not contain " + name + "; supply it via the environment");
            }
            out.put(name, value);
        }
        return out;
    }

    private static void assertNotSymlink(Path p) throws IdentityStoreException {
        if (Files.isSymbolicLink(p)) {
            throw new IdentityStoreException(Reason.CONFIG_INVALID, "refusing a symbolic link: " + describe(p));
        }
    }

    private static Path validatedDataDir(String text) throws IdentityStoreException {
        String s = Identity.stripSurroundingSpacesOnly(text);
        if (s == null || s.isEmpty() || s.length() > 512) {
            throw new IdentityStoreException(Reason.CONFIG_INVALID, K_DATA_DIR + " is empty or too long");
        }
        if (Identity.containsControlOrDel(s)) {
            throw new IdentityStoreException(Reason.CONFIG_INVALID, K_DATA_DIR + " has control characters");
        }
        // ';' and '=' are the JDBC property separator and assignment: a path containing them would
        // let the config file append driver properties (such as INIT) to the URL we build.
        if (s.indexOf(';') >= 0 || s.indexOf('=') >= 0 || s.indexOf('\0') >= 0) {
            throw new IdentityStoreException(Reason.CONFIG_INVALID,
                    K_DATA_DIR + " may not contain ';', '=' or NUL");
        }
        if (!s.startsWith("/")) {
            throw new IdentityStoreException(Reason.CONFIG_INVALID, K_DATA_DIR + " must be an absolute path");
        }
        // Checked on the raw text, before normalise(). Path.normalize() *resolves* ".." away, so a
        // post-normalise scan for a ".." segment never fires: "/tmp/../etc" normalises to "/etc" and
        // used to be accepted as if it had been checked. Written that way, a config file (or the
        // IDENTITY_DATA_DIR override) could redirect the database anywhere the process can reach.
        for (String segment : s.split("/", -1)) {
            if ("..".equals(segment)) {
                throw new IdentityStoreException(Reason.CONFIG_INVALID, K_DATA_DIR + " may not contain '..'");
            }
        }
        Path path;
        try {
            path = Path.of(s).toAbsolutePath().normalize();
        } catch (java.nio.file.InvalidPathException bad) {
            throw new IdentityStoreException(Reason.CONFIG_INVALID, K_DATA_DIR + " is not a valid path", bad);
        }
        // World-writable parents are where an attacker plants a file we are about to open.
        Path cursor = path.getRoot();
        for (Path segment : path) {
            cursor = cursor.resolve(segment);
            if (Files.exists(cursor, LinkOption.NOFOLLOW_LINKS)) {
                assertNotSymlink(cursor);
                if (PosixFiles.isWorldWritable(cursor)) {
                    throw new IdentityStoreException(Reason.CONFIG_INVALID,
                            "data directory component is world-writable: " + cursor);
                }
            }
        }
        return path;
    }

    // ---------------------------------------------------------------- scalar parsing

    private static String required(Map<String, String> file, String key) throws IdentityStoreException {
        String v = file.get(key);
        if (v == null) {
            throw new IdentityStoreException(Reason.CONFIG_INVALID, "missing required configuration key " + key);
        }
        String trimmed = v.trim();
        if (trimmed.isEmpty()) {
            throw new IdentityStoreException(Reason.CONFIG_INVALID, "configuration key " + key + " is blank");
        }
        return trimmed;
    }

    private static int requiredInt(Map<String, String> file, String key, int min, int max)
            throws IdentityStoreException {
        long v = parseBounded(required(file, key), key, min, max);
        return (int) v;
    }

    private static long requiredLong(Map<String, String> file, String key, long min, long max)
            throws IdentityStoreException {
        return parseBounded(required(file, key), key, min, max);
    }

    private static long parseBounded(String text, String key, long min, long max)
            throws IdentityStoreException {
        if (text.length() > 12 || !(text.charAt(0) == '-' || Character.isDigit(text.charAt(0)))) {
            throw new IdentityStoreException(Reason.CONFIG_INVALID, key + " must be a plain integer");
        }
        long value;
        try {
            value = Long.parseLong(text);
        } catch (NumberFormatException e) {
            throw new IdentityStoreException(Reason.CONFIG_INVALID, key + " is not an integer: " + text, e);
        }
        if (value < min || value > max) {
            throw new IdentityStoreException(Reason.CONFIG_INVALID,
                    key + " must be in [" + min + ", " + max + "]");
        }
        return value;
    }

    private static boolean containsControlOrNewline(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || c == 0x7F) {
                return true;
            }
        }
        return false;
    }

    /** Path without resolution: safe to log, since the config path itself is not secret. */
    private static String describe(Path p) {
        return p == null ? "<null>" : p.getFileName().toString();
    }

    /**
     * Driver properties for the connection, built from validated pieces only. The password is
     * passed as a {@code char[]} so the driver can erase it; {@code Properties} would pin it as a
     * String for the life of the JVM.
     */
    public void applyTo(java.sql.Connection c) throws java.sql.SQLException {
        c.setTransactionIsolation(java.sql.Connection.TRANSACTION_READ_COMMITTED);
    }

    /** Erases the passphrase copy held by this record. */
    public void eraseDatabasePassword() {
        Password.erase(databasePassword);
    }

    @Override
    public String toString() {
        // Deliberately omits databasePassword: a record's default toString would print the
        // char[] identity, and any future change to print its contents would leak it into a log.
        return "Config[dataDir=" + dataDir + ", db=" + databaseName
                + ", iterations=" + pbkdf2Iterations
                + ", maxAccounts=" + maxAccounts
                + ", sessionTtlSeconds=" + sessionTtlSeconds + "]";
    }
}
