package com.employee.portal.security.config;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Security configuration holding system parameters and security limits.
 * All configurable values are strictly bounded to prevent insecure or denial-of-service settings.
 */
public final class SecurityConfig {

    // Rate Limiting & Lockout limits
    public static final int DEFAULT_MAX_FAILED_PER_SOURCE = 5;
    public static final int DEFAULT_MAX_FAILED_PER_ACCOUNT = 10;
    public static final long DEFAULT_LOCKOUT_DURATION_MINUTES = 15;
    public static final long DEFAULT_FAILURE_WINDOW_MINUTES = 15;

    // Session timeouts
    public static final long DEFAULT_SESSION_IDLE_TIMEOUT_MINUTES = 15;
    public static final long DEFAULT_SESSION_ABSOLUTE_TIMEOUT_MINUTES = 480; // 8 hours
    public static final int DEFAULT_MAX_SESSIONS_PER_USER = 5;
    public static final int DEFAULT_MAX_ACTIVE_SESSIONS = 5000;

    // Cryptography parameters (OWASP / NIST SP 800-63B compliant)
    public static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA512";
    public static final int DEFAULT_PBKDF2_ITERATIONS = 210000;
    public static final int SALT_LENGTH_BYTES = 32;       // 256 bits
    public static final int DERIVED_KEY_LENGTH_BYTES = 32; // 256 bits
    public static final int SESSION_TOKEN_LENGTH_BYTES = 32; // 256 bits

    // Input bounds
    public static final int MIN_USERNAME_LENGTH = 3;
    public static final int MAX_USERNAME_LENGTH = 32;
    public static final int MIN_PASSWORD_LENGTH = 8;
    public static final int MAX_PASSWORD_LENGTH = 128;
    public static final int MAX_SOURCE_IP_LENGTH = 45;

    // Cache / Store bounds
    public static final int MAX_RATE_LIMITER_ENTRIES = 10000;

    // File storage
    public static final String DEFAULT_DATA_DIR = "./data";
    public static final String EMPLOYEE_DB_FILENAME = "employees.db";
    public static final String AUDIT_LOG_FILENAME = "audit.log";

    private final int maxFailedPerSource;
    private final int maxFailedPerAccount;
    private final long lockoutDurationMillis;
    private final long failureWindowMillis;
    private final long sessionIdleTimeoutMillis;
    private final long sessionAbsoluteTimeoutMillis;
    private final int maxSessionsPerUser;
    private final int maxActiveSessions;
    private final int pbkdf2Iterations;
    private final Path dataDirectory;

    public SecurityConfig() {
        this(
            clamp(getIntProp("PORTAL_MAX_FAILED_PER_SOURCE", DEFAULT_MAX_FAILED_PER_SOURCE), 1, 50),
            clamp(getIntProp("PORTAL_MAX_FAILED_PER_ACCOUNT", DEFAULT_MAX_FAILED_PER_ACCOUNT), 1, 20),
            clamp(getLongProp("PORTAL_LOCKOUT_MINUTES", DEFAULT_LOCKOUT_DURATION_MINUTES), 1, 1440) * 60_000L,
            clamp(getLongProp("PORTAL_FAILURE_WINDOW_MINUTES", DEFAULT_FAILURE_WINDOW_MINUTES), 1, 1440) * 60_000L,
            clamp(getLongProp("PORTAL_SESSION_IDLE_MINUTES", DEFAULT_SESSION_IDLE_TIMEOUT_MINUTES), 1, 1440) * 60_000L,
            clamp(getLongProp("PORTAL_SESSION_MAX_MINUTES", DEFAULT_SESSION_ABSOLUTE_TIMEOUT_MINUTES), 1, 1440) * 60_000L,
            clamp(getIntProp("PORTAL_MAX_SESSIONS_PER_USER", DEFAULT_MAX_SESSIONS_PER_USER), 1, 50),
            clamp(getIntProp("PORTAL_MAX_ACTIVE_SESSIONS", DEFAULT_MAX_ACTIVE_SESSIONS), 10, 100000),
            clamp(getIntProp("PORTAL_PBKDF2_ITERATIONS", DEFAULT_PBKDF2_ITERATIONS), 100000, 2000000),
            resolveSafeDataDir(System.getProperty("PORTAL_DATA_DIR", System.getenv().getOrDefault("PORTAL_DATA_DIR", DEFAULT_DATA_DIR)))
        );
    }

    public SecurityConfig(int maxFailedPerSource,
                          int maxFailedPerAccount,
                          long lockoutDurationMillis,
                          long failureWindowMillis,
                          long sessionIdleTimeoutMillis,
                          long sessionAbsoluteTimeoutMillis,
                          int maxSessionsPerUser,
                          int maxActiveSessions,
                          int pbkdf2Iterations,
                          Path dataDirectory) {
        this.maxFailedPerSource = maxFailedPerSource;
        this.maxFailedPerAccount = maxFailedPerAccount;
        this.lockoutDurationMillis = lockoutDurationMillis;
        this.failureWindowMillis = failureWindowMillis;
        this.sessionIdleTimeoutMillis = sessionIdleTimeoutMillis;
        this.sessionAbsoluteTimeoutMillis = sessionAbsoluteTimeoutMillis;
        this.maxSessionsPerUser = maxSessionsPerUser;
        this.maxActiveSessions = maxActiveSessions;
        this.pbkdf2Iterations = pbkdf2Iterations;
        this.dataDirectory = dataDirectory;
    }

    public int getMaxFailedPerSource() {
        return maxFailedPerSource;
    }

    public int getMaxFailedPerAccount() {
        return maxFailedPerAccount;
    }

    public long getLockoutDurationMillis() {
        return lockoutDurationMillis;
    }

    public long getFailureWindowMillis() {
        return failureWindowMillis;
    }

    public long getSessionIdleTimeoutMillis() {
        return sessionIdleTimeoutMillis;
    }

    public long getSessionAbsoluteTimeoutMillis() {
        return sessionAbsoluteTimeoutMillis;
    }

    public int getMaxSessionsPerUser() {
        return maxSessionsPerUser;
    }

    public int getMaxActiveSessions() {
        return maxActiveSessions;
    }

    public int getPbkdf2Iterations() {
        return pbkdf2Iterations;
    }

    public Path getDataDirectory() {
        return dataDirectory;
    }

    public Path getEmployeeDbPath() {
        return dataDirectory.resolve(EMPLOYEE_DB_FILENAME).normalize();
    }

    public Path getAuditLogPath() {
        return dataDirectory.resolve(AUDIT_LOG_FILENAME).normalize();
    }

    private static int clamp(int val, int min, int max) {
        return Math.max(min, Math.min(max, val));
    }

    private static long clamp(long val, long min, long max) {
        return Math.max(min, Math.min(max, val));
    }

    private static int getIntProp(String key, int defaultVal) {
        String val = System.getProperty(key, System.getenv(key));
        if (val == null || val.isBlank()) {
            return defaultVal;
        }
        try {
            return Integer.parseInt(val.trim());
        } catch (NumberFormatException e) {
            return defaultVal;
        }
    }

    private static long getLongProp(String key, long defaultVal) {
        String val = System.getProperty(key, System.getenv(key));
        if (val == null || val.isBlank()) {
            return defaultVal;
        }
        try {
            return Long.parseLong(val.trim());
        } catch (NumberFormatException e) {
            return defaultVal;
        }
    }

    private static Path resolveSafeDataDir(String rawPath) {
        if (rawPath == null || rawPath.isBlank()) {
            return Paths.get(DEFAULT_DATA_DIR).toAbsolutePath().normalize();
        }
        // Validate path does not contain suspicious control characters
        for (char c : rawPath.toCharArray()) {
            if (c < 32 || c == 127) {
                return Paths.get(DEFAULT_DATA_DIR).toAbsolutePath().normalize();
            }
        }
        return Paths.get(rawPath).toAbsolutePath().normalize();
    }
}
