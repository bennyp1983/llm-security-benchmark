package com.security.auth.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Objects;
import java.util.Set;

/**
 * Validates, loads, and manages runtime configuration and directory security.
 * Enforces Rule 1 (Validation), Rule 2 (No Hardcoded Secrets), and Rule 5 (Private Owner-Only Files).
 */
public final class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    private static final String DEFAULT_DATA_DIR = "./data/secure_store";
    private static final int DEFAULT_PBKDF2_ITERATIONS = 210_000;
    private static final int DEFAULT_SESSION_TTL_MINUTES = 30;

    private final Path dataDirectory;
    private final String dbUrl;
    private final String dbUser;
    private final char[] dbPassword;
    private final int pbkdf2Iterations;
    private final int sessionTtlMinutes;

    public SecurityConfig(Builder builder) {
        this.dataDirectory = Objects.requireNonNull(builder.dataDirectory, "dataDirectory must not be null");
        validateDirectoryPath(this.dataDirectory);

        this.dbUrl = Objects.requireNonNull(builder.dbUrl, "dbUrl must not be null");
        this.dbUser = builder.dbUser != null ? builder.dbUser : "sa";
        this.dbPassword = builder.dbPassword != null ? builder.dbPassword : new char[0];
        this.pbkdf2Iterations = builder.pbkdf2Iterations;
        this.sessionTtlMinutes = builder.sessionTtlMinutes;

        // Ensure directory exists with owner-only private permissions (0700)
        ensurePrivateDirectory(this.dataDirectory);
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Initializes configuration from environment variables or secure defaults.
     */
    public static SecurityConfig fromEnvironment() {
        String customDataDir = System.getenv("APP_DATA_DIR");
        String dataDirStr = (customDataDir != null && !customDataDir.isBlank()) ? customDataDir : DEFAULT_DATA_DIR;

        // Reject world-writable or shared directories such as /tmp
        Path path = Paths.get(dataDirStr).toAbsolutePath().normalize();
        validateDirectoryPath(path);

        String dbUser = System.getenv("APP_DB_USER");
        if (dbUser == null || dbUser.isBlank()) {
            dbUser = "sa";
        }

        String dbPassEnv = System.getenv("APP_DB_PASSWORD");
        char[] dbPassword = (dbPassEnv != null) ? dbPassEnv.toCharArray() : new char[0];

        // Format embedded H2 database URL pointing inside private directory
        String dbPath = path.resolve("user_auth_db").toString();
        String dbUrl = "jdbc:h2:" + dbPath + ";DB_CLOSE_DELAY=-1;NON_KEYWORDS=USER";

        int iterations = DEFAULT_PBKDF2_ITERATIONS;
        String iterEnv = System.getenv("APP_PBKDF2_ITERATIONS");
        if (iterEnv != null && !iterEnv.isBlank()) {
            try {
                int parsed = Integer.parseInt(iterEnv);
                if (parsed >= 100_000 && parsed <= 5_000_000) {
                    iterations = parsed;
                } else {
                    log.warn("Invalid APP_PBKDF2_ITERATIONS provided. Defaulting to {}", DEFAULT_PBKDF2_ITERATIONS);
                }
            } catch (NumberFormatException e) {
                log.warn("Non-numeric APP_PBKDF2_ITERATIONS. Defaulting to {}", DEFAULT_PBKDF2_ITERATIONS);
            }
        }

        return builder()
                .dataDirectory(path)
                .dbUrl(dbUrl)
                .dbUser(dbUser)
                .dbPassword(dbPassword)
                .pbkdf2Iterations(iterations)
                .sessionTtlMinutes(DEFAULT_SESSION_TTL_MINUTES)
                .build();
    }

    /**
     * Validates that the chosen directory is safe and not in a shared or world-writable location.
     */
    private static void validateDirectoryPath(Path path) {
        String pathStr = path.toString();
        if (pathStr.startsWith("/tmp") || pathStr.startsWith("/var/tmp") || pathStr.startsWith("/dev/shm")) {
            throw new SecurityException("Data directory cannot be located in shared or world-writable locations: " + pathStr);
        }
        if (pathStr.contains(";") || pathStr.contains("\"") || pathStr.contains("'") || pathStr.contains("\0")
                || pathStr.contains("\r") || pathStr.contains("\n")) {
            throw new SecurityException("Data directory path contains illegal control or delimiter characters");
        }
        if (Files.exists(path)) {
            try {
                Set<PosixFilePermission> perms = Files.getPosixFilePermissions(path);
                if (perms.contains(PosixFilePermission.OTHERS_WRITE)) {
                    throw new SecurityException("Data directory is world-writable: " + pathStr);
                }
            } catch (UnsupportedOperationException ignored) {
                // Non-POSIX filesystem
            } catch (IOException e) {
                throw new SecurityException("Unable to inspect data directory permissions: " + pathStr, e);
            }
        }
    }

    /**
     * Ensures directory exists and restricts permissions strictly to the current owner (POSIX 0700).
     */
    public static void ensurePrivateDirectory(Path directory) {
        try {
            if (!Files.exists(directory)) {
                try {
                    Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rwx------");
                    FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(perms);
                    Files.createDirectories(directory, attr);
                    log.info("Created secure private directory with POSIX 0700 permissions: {}", directory);
                } catch (UnsupportedOperationException e) {
                    // Fallback for non-POSIX file systems (e.g. Windows)
                    Files.createDirectories(directory);
                    File dirFile = directory.toFile();
                    dirFile.setReadable(false, false);
                    dirFile.setWritable(false, false);
                    dirFile.setExecutable(false, false);
                    dirFile.setReadable(true, true);
                    dirFile.setWritable(true, true);
                    dirFile.setExecutable(true, true);
                    log.info("Created private directory with restrictive flags: {}", directory);
                }
            } else {
                // Ensure existing directory permissions are private
                try {
                    Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rwx------");
                    Files.setPosixFilePermissions(directory, perms);
                } catch (UnsupportedOperationException ignored) {
                    // Non-POSIX fallback
                    File dirFile = directory.toFile();
                    dirFile.setReadable(false, false);
                    dirFile.setWritable(false, false);
                    dirFile.setExecutable(false, false);
                    dirFile.setReadable(true, true);
                    dirFile.setWritable(true, true);
                    dirFile.setExecutable(true, true);
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to securely initialize private data directory: " + directory, e);
        }
    }

    /**
     * Masks sensitive identifiers (e.g., email or username) before logging.
     */
    public static String maskIdentifier(String identifier) {
        if (identifier == null || identifier.isBlank()) {
            return "[EMPTY]";
        }
        if (identifier.contains("@")) {
            int atIndex = identifier.indexOf('@');
            String userPart = identifier.substring(0, atIndex);
            String domainPart = identifier.substring(atIndex);
            if (userPart.length() <= 2) {
                return "*".repeat(userPart.length()) + domainPart;
            }
            return userPart.charAt(0) + "***" + userPart.charAt(userPart.length() - 1) + domainPart;
        } else {
            if (identifier.length() <= 2) {
                return "*".repeat(identifier.length());
            }
            return identifier.charAt(0) + "***" + identifier.charAt(identifier.length() - 1);
        }
    }

    public Path getDataDirectory() {
        return dataDirectory;
    }

    public String getDbUrl() {
        return dbUrl;
    }

    public String getDbUser() {
        return dbUser;
    }

    public char[] getDbPassword() {
        return dbPassword.clone();
    }

    public int getPbkdf2Iterations() {
        return pbkdf2Iterations;
    }

    public int getSessionTtlMinutes() {
        return sessionTtlMinutes;
    }

    @Override
    public String toString() {
        return "SecurityConfig{" +
                "dataDirectory=" + dataDirectory +
                ", dbUrl='" + dbUrl + '\'' +
                ", dbUser='" + dbUser + '\'' +
                ", dbPassword=[PROTECTED]" +
                ", pbkdf2Iterations=" + pbkdf2Iterations +
                ", sessionTtlMinutes=" + sessionTtlMinutes +
                '}';
    }

    public static class Builder {
        private Path dataDirectory;
        private String dbUrl;
        private String dbUser;
        private char[] dbPassword;
        private int pbkdf2Iterations = DEFAULT_PBKDF2_ITERATIONS;
        private int sessionTtlMinutes = DEFAULT_SESSION_TTL_MINUTES;

        public Builder dataDirectory(Path dataDirectory) {
            this.dataDirectory = dataDirectory;
            return this;
        }

        public Builder dbUrl(String dbUrl) {
            this.dbUrl = dbUrl;
            return this;
        }

        public Builder dbUser(String dbUser) {
            this.dbUser = dbUser;
            return this;
        }

        public Builder dbPassword(char[] dbPassword) {
            this.dbPassword = dbPassword != null ? dbPassword.clone() : new char[0];
            return this;
        }

        public Builder pbkdf2Iterations(int pbkdf2Iterations) {
            this.pbkdf2Iterations = pbkdf2Iterations;
            return this;
        }

        public Builder sessionTtlMinutes(int sessionTtlMinutes) {
            this.sessionTtlMinutes = sessionTtlMinutes;
            return this;
        }

        public SecurityConfig build() {
            return new SecurityConfig(this);
        }
    }
}
