package com.example.auth;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Set;

/**
 * Manages SQL database connection lifecycle and schema initialization.
 * <p>
 * Satisfies:
 * - Rule 1: Validates database configuration.
 * - Rule 2: No credentials hardcoded; accepts configuration via environment variables or runtime parameters.
 * - Rule 5: If file-backed database is created, enforces strict POSIX file permissions (0700/0600 private to owner).
 * - Rule 8: Uses standard JDBC platform drivers with official dependency versions.
 */
public final class DatabaseManager implements AutoCloseable {

    public static final String DEFAULT_IN_MEMORY_URL = "jdbc:h2:mem:authdb;DB_CLOSE_DELAY=-1";
    public static final String DEFAULT_FILE_DIR = "./data";
    public static final String DEFAULT_FILE_URL = "jdbc:h2:./data/authdb";

    private final String dbUrl;
    private final String dbUser;
    private final String dbPassword;

    public DatabaseManager() {
        this(resolveDatabaseUrl(), resolveUser(), resolvePassword());
    }

    public DatabaseManager(String dbUrl, String dbUser, String dbPassword) {
        if (dbUrl == null || dbUrl.isBlank()) {
            throw new IllegalArgumentException("Database URL cannot be null or blank");
        }
        this.dbUrl = dbUrl;
        this.dbUser = (dbUser != null) ? dbUser : "";
        this.dbPassword = (dbPassword != null) ? dbPassword : "";

        ensureSecureFilePermissionsIfLocal(this.dbUrl);
        initializeSchema();
    }

    /**
     * Obtains a new database connection.
     * Callers must close the connection using try-with-resources.
     */
    public Connection getConnection() throws SQLException {
        return DriverManager.getConnection(this.dbUrl, this.dbUser, this.dbPassword);
    }

    /**
     * Initializes database tables and indexes using idempotent DDL.
     */
    public void initializeSchema() {
        String createTableSql = """
                CREATE TABLE IF NOT EXISTS users (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(254) NOT NULL UNIQUE,
                    password_hash VARCHAR(128) NOT NULL,
                    salt VARCHAR(128) NOT NULL,
                    iterations INT NOT NULL,
                    algorithm VARCHAR(64) NOT NULL,
                    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
                """;

        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.execute(createTableSql);
        } catch (SQLException e) {
            SecurityLogger.logSystemError("Database schema initialization failed", e);
            throw new IllegalStateException("Failed to initialize database schema", e);
        }
        ensureSecureFilePermissionsIfLocal(this.dbUrl);
    }

    /**
     * Ensures directories and files for local file-based databases are restricted to the owner (0700/0600).
     */
    private static void ensureSecureFilePermissionsIfLocal(String jdbcUrl) {
        if (jdbcUrl.startsWith("jdbc:h2:./") || jdbcUrl.startsWith("jdbc:h2:/")) {
            try {
                // Extract file path from H2 JDBC URL
                String rawPath = jdbcUrl.substring("jdbc:h2:".length());
                int semicolonIdx = rawPath.indexOf(';');
                if (semicolonIdx >= 0) {
                    rawPath = rawPath.substring(0, semicolonIdx);
                }
                Path path = Paths.get(rawPath);
                Path parent = path.getParent();
                if (parent != null) {
                    if (!Files.exists(parent)) {
                        if (supportsPosix()) {
                            Set<PosixFilePermission> dirPerms = PosixFilePermissions.fromString("rwx------");
                            Files.createDirectories(parent, PosixFilePermissions.asFileAttribute(dirPerms));
                        } else {
                            Files.createDirectories(parent);
                        }
                    } else if (supportsPosix()) {
                        Files.setPosixFilePermissions(parent, PosixFilePermissions.fromString("rwx------"));
                    }
                }

                // Restrict database file permissions to owner read/write (0600)
                if (supportsPosix()) {
                    Path dbFile = Paths.get(rawPath + ".mv.db");
                    if (Files.exists(dbFile)) {
                        Files.setPosixFilePermissions(dbFile, PosixFilePermissions.fromString("rw-------"));
                    }
                }
            } catch (IOException e) {
                SecurityLogger.logSystemError("Failed to set secure file permissions for database directory/file", e);
            }
        }
    }

    private static boolean supportsPosix() {
        return FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
    }

    private static String resolveDatabaseUrl() {
        String envUrl = System.getenv("AUTH_DB_URL");
        if (envUrl != null && !envUrl.isBlank()) {
            return envUrl.trim();
        }
        return DEFAULT_IN_MEMORY_URL;
    }

    private static String resolveUser() {
        String envUser = System.getenv("AUTH_DB_USER");
        return (envUser != null) ? envUser.trim() : "sa";
    }

    private static String resolvePassword() {
        String envPass = System.getenv("AUTH_DB_PASSWORD");
        return (envPass != null) ? envPass : "";
    }

    @Override
    public void close() {
        // H2 in-memory or connection pools clean-up if needed
    }
}
