package app;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.EnumSet;
import java.util.Properties;
import java.util.Set;

/**
 * Runtime configuration. Every value here comes from the operator's environment or from an
 * out-of-argv command-line option; no credential is ever read from a file that this program
 * created, and no credential has a default value.
 *
 * <p>Consumed inputs (all attacker-reachable if the operator's environment is):
 * <ul>
 *   <li>{@code APP_DATA_DIR} (or {@code --data-dir}, which must be a separate argv element so
 *       the path cannot be confused with a password) - directory holding the database and audit log</li>
 *   <li>{@code APP_DB_PASSWORD} - database password, or</li>
 *   <li>{@code APP_DB_PASSWORD_FILE} - file whose first line is the database password</li>
 *   <li>{@code APP_ARGON2_MEMORY_KIB}, {@code APP_ARGON2_ITERATIONS}, {@code APP_ARGON2_PARALLELISM}
 *       - key-derivation tuning, each bounded below by an OWASP-equivalent minimum work factor</li>
 * </ul>
 * Any of these that is malformed causes a hard stop: there is no permissive default for a
 * security parameter.
 */
public final class Config implements AutoCloseable {

    public static final String ENV_DATA_DIR = "APP_DATA_DIR";
    public static final String ENV_DB_PASSWORD = "APP_DB_PASSWORD";
    public static final String ENV_DB_PASSWORD_FILE = "APP_DB_PASSWORD_FILE";
    public static final String ENV_ARGON2_MEMORY = "APP_ARGON2_MEMORY_KIB";
    public static final String ENV_ARGON2_ITERATIONS = "APP_ARGON2_ITERATIONS";
    public static final String ENV_ARGON2_PARALLELISM = "APP_ARGON2_PARALLELISM";

    /**
     * Key-derivation defaults. 64 MiB with t=3, p=1 is above the OWASP 2024 Argon2id floor
     * (m=19456, t=2, p=1) and measured at roughly 320 ms per hash on this machine, which is
     * cheap enough to apply to every login attempt and expensive enough to matter offline.
     * Spring Security's own default (16 MiB, t=2) is *below* that floor, so it is not used.
     */
    public static final int DEFAULT_MEMORY_KIB = 65_536;
    public static final int DEFAULT_ITERATIONS = 3;
    public static final int DEFAULT_PARALLELISM = 1;

    /**
     * Configuration bounds are the same bounds {@link PasswordHasher} applies to a stored
     * credential, referenced rather than repeated. Two independent numbers for one policy is how a
     * legal configuration ends up refused by the schema later; the hasher is the layer that actually
     * spends the memory, so it decides the range and the environment can only narrow inside it.
     */
    private static final int MIN_MEMORY_KIB = PasswordHasher.STORED_MIN_MEMORY_KIB;
    private static final int MIN_ITERATIONS = PasswordHasher.STORED_MIN_ITERATIONS;
    private static final int MAX_MEMORY_KIB = PasswordHasher.STORED_MAX_MEMORY_KIB;
    private static final int MAX_ITERATIONS = PasswordHasher.STORED_MAX_ITERATIONS;

    private static final int PASSWORD_MAX_BYTES = 1_048_576;

    /** H2 keeps no trace file (which can contain SQL text) and no shutdown hook (we close explicitly). */
    private static final String DB_OPTIONS =
        ";DB_CLOSE_ON_EXIT=FALSE;AUTO_SERVER=FALSE;TRACE_LEVEL_FILE=0";

    private static final Set<PosixFilePermission> OWNER_ONLY =
        EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
    private static final Set<PosixFilePermission> OWNER_ONLY_DIR = EnumSet.of(
        PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE);

    private final Path dataDir;
    private final Path dbBase;
    private final Secrets dbPassword;
    private final int memoryKib;
    private final int iterations;
    private final int parallelism;
    private boolean secretRetired;

    private Config(Path dataDir, Path dbBase, Secrets dbPassword, int memoryKib, int iterations, int parallelism) {
        this.dataDir = dataDir;
        this.dbBase = dbBase;
        this.dbPassword = dbPassword;
        this.memoryKib = memoryKib;
        this.iterations = iterations;
        this.parallelism = parallelism;
    }

    public static Config fromEnvironment(java.util.function.Function<String, String> env, String[] argv)
        throws ConfigException {
        String dirValue = firstOption(argv, "--data-dir");
        if (dirValue == null) {
            dirValue = env.apply(ENV_DATA_DIR);
        }
        if (dirValue == null || dirValue.isEmpty()) {
            throw new ConfigException(ENV_DATA_DIR + " (or --data-dir) must be set");
        }
        Path dataDir = Path.of(dirValue).toAbsolutePath().normalize();
        ensurePrivateDirectory(dataDir);

        Path dbBase = dataDir.resolve("accounts");
        ensurePrivateStoreFile(dbBase);
        ensureAuditLogWithinBudget(dataDir.resolve("audit.log"));

        Secrets password = readDbPassword(env);

        int memory = boundedInt(env, ENV_ARGON2_MEMORY, DEFAULT_MEMORY_KIB, MIN_MEMORY_KIB, MAX_MEMORY_KIB);
        int iterations = boundedInt(env, ENV_ARGON2_ITERATIONS, DEFAULT_ITERATIONS, MIN_ITERATIONS, MAX_ITERATIONS);
        int parallelism = boundedInt(env, ENV_ARGON2_PARALLELISM, DEFAULT_PARALLELISM,
            PasswordHasher.STORED_MIN_PARALLELISM, PasswordHasher.STORED_MAX_PARALLELISM);

        return new Config(dataDir, dbBase, password, memory, iterations, parallelism);
    }

    /**
     * Opens the database. The caller-supplied password is erased from the heap by the returned
     * {@link Db} as soon as the connection is established.
     */
    public Db openDatabase() throws AppConfiguredException {
        Properties props = new Properties();
        props.setProperty("user", "app");
        props.setProperty("password", new String(dbPassword.chars()));
        Connection connection;
        try {
            connection = DriverManager.getConnection(jdbcUrl(), props);
        } catch (SQLException failed) {
            throw new AppConfiguredException("the account store could not be opened", failed);
        }
        retireDatabasePassword();
        return new Db(connection);
    }

    /** Erases the database password; called by {@link Db} once its connection exists. */
    void retireDatabasePassword() {
        if (!secretRetired) {
            dbPassword.close();
            secretRetired = true;
        }
    }

    public String jdbcUrl() {
        return "jdbc:h2:file:" + dbBase + DB_OPTIONS;
    }

    public Path dataDir() {
        return dataDir;
    }

    public Path auditLogFile() {
        return dataDir.resolve("audit.log");
    }

    public int argon2MemoryKib() {
        return memoryKib;
    }

    public int argon2Iterations() {
        return iterations;
    }

    public int argon2Parallelism() {
        return parallelism;
    }

    @Override
    public void close() {
        retireDatabasePassword();
    }

    // ------------------------------------------------------------------ secrets

    private static Secrets readDbPassword(java.util.function.Function<String, String> env) throws ConfigException {
        String inline = env.apply(ENV_DB_PASSWORD);
        String file = env.apply(ENV_DB_PASSWORD_FILE);
        if (inline != null && !inline.isEmpty() && file != null && !file.isEmpty()) {
            throw new ConfigException(ENV_DB_PASSWORD + " and " + ENV_DB_PASSWORD_FILE + " are mutually exclusive");
        }
        if (inline != null && !inline.isEmpty()) {
            if (inline.length() < 16) {
                throw new ConfigException("the database password must be at least 16 characters");
            }
            return Secrets.ofString(inline);
        }
        if (file == null || file.isEmpty()) {
            throw new ConfigException(ENV_DB_PASSWORD + " or " + ENV_DB_PASSWORD_FILE + " must be set");
        }
        Path path = Path.of(file).toAbsolutePath().normalize();
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new ConfigException(ENV_DB_PASSWORD_FILE + " must name a regular file that is not a symlink");
        }
        if (hasGroupOrOtherAccess(path)) {
            throw new ConfigException(ENV_DB_PASSWORD_FILE + " must not be readable by group or other");
        }
        byte[] raw = new byte[PASSWORD_MAX_BYTES + 1];
        int read;
        try (java.io.InputStream in = Files.newInputStream(path)) {
            read = in.readNBytes(raw, 0, raw.length);
        } catch (IOException unreadable) {
            throw new ConfigException(ENV_DB_PASSWORD_FILE + " could not be read");
        }
        if (read > PASSWORD_MAX_BYTES) {
            java.util.Arrays.fill(raw, (byte) 0);
            throw new ConfigException(ENV_DB_PASSWORD_FILE + " is too large to be a password file");
        }
        int lineEnd = indexOf(raw, read, (byte) '\n');
        int length = lineEnd < 0 ? read : lineEnd;
        if (length > 0 && raw[length - 1] == '\r') {
            length--;
        }
        String value;
        try {
            value = new String(raw, 0, length, java.nio.charset.StandardCharsets.UTF_8);
        } finally {
            java.util.Arrays.fill(raw, (byte) 0);
        }
        if (value.length() < 16) {
            throw new ConfigException("the database password must be at least 16 characters");
        }
        return Secrets.ofString(value);
    }

    private static int indexOf(byte[] bytes, int length, byte target) {
        for (int i = 0; i < length; i++) {
            if (bytes[i] == target) {
                return i;
            }
        }
        return -1;
    }

    private static int boundedInt(java.util.function.Function<String, String> env, String name,
        int fallback, int min, int max) throws ConfigException {
        String value = env.apply(name);
        if (value == null || value.isEmpty()) {
            return fallback;
        }
        int parsed;
        try {
            parsed = Integer.parseInt(value.trim());
        } catch (NumberFormatException notANumber) {
            throw new ConfigException(name + " must be an integer between " + min + " and " + max);
        }
        if (parsed < min || parsed > max) {
            throw new ConfigException(name + " must be between " + min + " and " + max
                + "; the minimum keeps the password hashing cost at an approved work factor");
        }
        return parsed;
    }

    /**
     * Reads {@code --data-dir=<path>} as a single argv element. A bare {@code --data-dir} is
     * refused rather than consuming the next token, so an option can never swallow an argument
     * that was meant for something else.
     */
    private static String firstOption(String[] argv, String flag) throws ConfigException {
        String prefix = flag + "=";
        String found = null;
        for (String argument : argv) {
            if (argument.equals(flag) || argument.startsWith(prefix)) {
                if (found != null) {
                    throw new ConfigException(flag + " may be given only once");
                }
                if (!argument.startsWith(prefix) || argument.length() == prefix.length()) {
                    throw new ConfigException(flag + " must be given as one argument, --data-dir=<path>");
                }
                found = argument.substring(prefix.length());
            }
        }
        return found;
    }

    // ------------------------------------------------------------------ directory guards

    /** Creates (or accepts) a data directory that no other user can write into. */
    static void ensurePrivateDirectory(Path dataDir) throws ConfigException {
        rejectSymlinkComponents(dataDir);
        if (Files.exists(dataDir, LinkOption.NOFOLLOW_LINKS)) {
            if (Files.isSymbolicLink(dataDir)) {
                throw new ConfigException("the data directory may not be a symbolic link");
            }
            if (!Files.isDirectory(dataDir, LinkOption.NOFOLLOW_LINKS)) {
                throw new ConfigException("the data directory must be a directory");
            }
            if (isWorldWritable(dataDir)) {
                throw new ConfigException("the data directory may not be writable by other users");
            }
            if (hasGroupOrOtherAccess(dataDir)) {
                try {
                    Files.setPosixFilePermissions(dataDir, OWNER_ONLY_DIR);
                } catch (IOException cannotTighten) {
                    throw new ConfigException("the data directory permissions could not be tightened to 0700");
                }
            }
        } else {
            try {
                Files.createDirectories(dataDir, PosixFilePermissions.asFileAttribute(OWNER_ONLY_DIR));
                Files.setPosixFilePermissions(dataDir, OWNER_ONLY_DIR);
            } catch (IOException cannotCreate) {
                throw new ConfigException("the data directory could not be created");
            }
        }
        if (isWorldWritable(dataDir)) {
            throw new ConfigException("the data directory is writable by other users");
        }
    }

    /**
     * H2 creates a missing store file with the process umask, which is 0644 under this system's
     * default, so the secret-bearing database would be world-readable. Pre-creating the file
     * 0600 makes H2 write into it and preserve that mode (verified against H2 2.5.252); an
     * existing file must already be 0600 or startup stops rather than quietly widening it.
     */
    static void ensurePrivateStoreFile(Path dbBase) throws ConfigException {
        Path store = Paths.get(dbBase + ".mv.db");
        Path parent = store.getParent();
        rejectSymlinkComponents(parent);
        if (Files.exists(store, LinkOption.NOFOLLOW_LINKS)) {
            if (Files.isSymbolicLink(store)) {
                throw new ConfigException("the account store may not be a symbolic link");
            }
            if (!Files.isRegularFile(store, LinkOption.NOFOLLOW_LINKS)) {
                throw new ConfigException("the account store must be a regular file");
            }
            Set<PosixFilePermission> actual = permissions(store);
            if (!OWNER_ONLY.equals(actual)) {
                throw new ConfigException("the account store must have owner-only permissions (0600), found "
                    + PosixFilePermissions.toString(actual));
            }
            return;
        }
        try {
            Files.createFile(store, PosixFilePermissions.asFileAttribute(OWNER_ONLY));
            Files.setPosixFilePermissions(store, OWNER_ONLY);
        } catch (IOException cannotCreate) {
            throw new ConfigException("the account store could not be created");
        }
        if (!OWNER_ONLY.equals(permissions(store))) {
            throw new ConfigException("the account store could not be created with owner-only permissions");
        }
    }

    /** Bounds the audit log so a flood cannot fill the filesystem; truncation is logged. */
    static void ensureAuditLogWithinBudget(Path auditLog) throws ConfigException {
        if (!Files.exists(auditLog, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        if (Files.isSymbolicLink(auditLog)) {
            throw new ConfigException("the audit log may not be a symbolic link");
        }
        if (!Files.isRegularFile(auditLog, LinkOption.NOFOLLOW_LINKS)) {
            throw new ConfigException("the audit log must be a regular file");
        }
        if (!OWNER_ONLY.equals(permissions(auditLog))) {
            throw new ConfigException("the audit log must have owner-only permissions (0600)");
        }
        // The size bound lives in AuditLog, so the startup bound and the append bound are one
        // number, not two that can drift - and the retirement writes its marker inside the trail,
        // not only on the terminal, so an erased history stays detectable from the file alone.
        try {
            new AuditLog(auditLog).retireOversizedTrail();
        } catch (AuditLog.AuditException couldNotInspect) {
            throw new ConfigException("the audit log could not be inspected");
        }
    }

    private static void rejectSymlinkComponents(Path path) throws ConfigException {
        Path absolute = path.toAbsolutePath().normalize();
        for (Path component = absolute; component != null && component.getNameCount() > 0;
             component = component.getParent()) {
            if (Files.isSymbolicLink(component)) {
                throw new ConfigException("the data path may not contain a symbolic link: "
                    + component.getFileName());
            }
        }
    }

    private static Set<PosixFilePermission> permissions(Path path) throws ConfigException {
        try {
            return Files.getPosixFilePermissions(path);
        } catch (IOException | UnsupportedOperationException unreadable) {
            throw new ConfigException("permissions of " + path.getFileName() + " could not be determined");
        }
    }

    private static boolean isWorldWritable(Path path) throws ConfigException {
        return permissions(path).contains(PosixFilePermission.OTHERS_WRITE);
    }

    private static boolean hasGroupOrOtherAccess(Path path) throws ConfigException {
        Set<PosixFilePermission> actual = permissions(path);
        return actual.contains(PosixFilePermission.GROUP_READ)
            || actual.contains(PosixFilePermission.GROUP_WRITE)
            || actual.contains(PosixFilePermission.GROUP_EXECUTE)
            || actual.contains(PosixFilePermission.OTHERS_READ)
            || actual.contains(PosixFilePermission.OTHERS_WRITE)
            || actual.contains(PosixFilePermission.OTHERS_EXECUTE);
    }

    /** Marker so callers can distinguish a bad environment from a runtime failure. */
    public static final class ConfigException extends Exception {
        private static final long serialVersionUID = 1L;

        ConfigException(String safeDescription) {
            super(safeDescription);
        }
    }

    /** A configuration that passed validation but whose store could not be opened. */
    public static final class AppConfiguredException extends Exception {
        private static final long serialVersionUID = 1L;

        AppConfiguredException(String safeDescription, Throwable cause) {
            super(safeDescription, cause);
        }
    }
}
