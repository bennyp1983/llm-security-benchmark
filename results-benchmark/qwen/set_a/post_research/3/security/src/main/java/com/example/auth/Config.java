package com.example.auth;

import java.util.Map;

/**
 * Runtime configuration, read from the environment only.
 *
 * <p>Rule 2: no credential in this program is a constant. The database credential is either
 * {@code AUTH_DB_PASSWORD} or a hidden prompt; it is held as {@code char[]}, handed to the JDBC
 * driver exactly once through {@link #takeDbPassword()} (which nulls the field), and wiped by the
 * caller. It is never placed in the JDBC URL string, in an argument vector, in a log line, or in an
 * exception message.
 *
 * <p>Rule 1/6: every value is validated (shape, then range) and an invalid or missing value makes
 * the program refuse to start. There is no default for the database path or user, and no
 * out-of-range value is clamped to a "safe" number - clamping a limit upward would be a permissive
 * default.
 */
final class Config {

    static final String ENV_DB_PATH = "AUTH_DB_PATH";
    static final String ENV_DB_USER = "AUTH_DB_USER";
    static final String ENV_DB_PASSWORD = "AUTH_DB_PASSWORD";
    static final String ENV_ACCOUNT_TABLE = "AUTH_ACCOUNT_TABLE";
    static final String ENV_THROTTLE_TABLE = "AUTH_THROTTLE_TABLE";
    static final String ENV_SESSION_TABLE = "AUTH_SESSION_TABLE";
    static final String ENV_ITERATIONS = "AUTH_ITERATIONS";
    static final String ENV_IDENTITY_MAX = "AUTH_IDENTITY_MAX_FAILURES";
    static final String ENV_IDENTITY_WINDOW = "AUTH_IDENTITY_WINDOW_SEC";
    static final String ENV_SOURCE_MAX = "AUTH_SOURCE_MAX_ATTEMPTS";
    static final String ENV_SOURCE_WINDOW = "AUTH_SOURCE_WINDOW_SEC";
    static final String ENV_SESSION_TTL = "AUTH_SESSION_TTL_SEC";
    static final String ENV_PASSWORD_MIN = "AUTH_PASSWORD_MIN_LENGTH";
    static final String ENV_SOURCE_ID = "AUTH_SOURCE_ID";
    static final String ENV_AUDIT_LOG = "AUTH_AUDIT_LOG";
    static final String ENV_EMIT_SESSION = "AUTH_EMIT_SESSION";
    static final String ENV_MIN_LOGIN_MS = "AUTH_MIN_LOGIN_MS";

    static final int DEFAULT_ITERATIONS = 210_000;
    static final int DEFAULT_IDENTITY_MAX = 8;
    static final int DEFAULT_IDENTITY_WINDOW = 900;
    static final int DEFAULT_SOURCE_MAX = 120;
    static final int DEFAULT_SOURCE_WINDOW = 900;
    static final int DEFAULT_SESSION_TTL = 900;
    static final int DEFAULT_PASSWORD_MIN = 12;
    static final int DEFAULT_MIN_LOGIN_MS = 1_000;
    private static final String DEFAULT_ACCOUNT_TABLE = "auth_accounts";
    private static final String DEFAULT_THROTTLE_TABLE = "auth_throttle";
    private static final String DEFAULT_SESSION_TABLE = "auth_sessions";
    private static final String DEFAULT_SOURCE_ID = "local-cli";

    private final String dbPath;
    private final String dbUser;
    private char[] dbPassword;
    private final String accountTable;
    private final String throttleTable;
    private final String sessionTable;
    private final int iterations;
    private final int identityMaxFailures;
    private final int identityWindowSec;
    private final int sourceMaxAttempts;
    private final int sourceWindowSec;
    private final int sessionTtlSec;
    private final int passwordMinLength;
    private final String sourceId;
    private final String auditLogPath;
    private final boolean emitSession;
    private final int minLoginMs;

    /** Raised at startup. The message is a fixed code token; it never contains a configured value. */
    static final class ConfigException extends Exception {
        private static final long serialVersionUID = 1L;

        ConfigException(String code) {
            super(code);
        }
    }

    private Config(String dbPath, String dbUser, char[] dbPassword, String accountTable,
            String throttleTable, String sessionTable, int iterations, int identityMaxFailures,
            int identityWindowSec, int sourceMaxAttempts, int sourceWindowSec, int sessionTtlSec,
            int passwordMinLength, String sourceId, String auditLogPath, boolean emitSession,
            int minLoginMs) {
        this.dbPath = dbPath;
        this.dbUser = dbUser;
        this.dbPassword = dbPassword;
        this.accountTable = accountTable;
        this.throttleTable = throttleTable;
        this.sessionTable = sessionTable;
        this.iterations = iterations;
        this.identityMaxFailures = identityMaxFailures;
        this.identityWindowSec = identityWindowSec;
        this.sourceMaxAttempts = sourceMaxAttempts;
        this.sourceWindowSec = sourceWindowSec;
        this.sessionTtlSec = sessionTtlSec;
        this.passwordMinLength = passwordMinLength;
        this.sourceId = sourceId;
        this.auditLogPath = auditLogPath;
        this.emitSession = emitSession;
        this.minLoginMs = minLoginMs;
    }

    static Config load(Map<String, String> env) throws ConfigException {
        String dbPath = required(env, ENV_DB_PATH, "dbpath_missing");
        try {
            dbPath = InputValidator.requireDbPath(dbPath);
        } catch (InputValidator.ValidationException e) {
            throw new ConfigException("dbpath_" + e.getMessage());
        }

        String dbUserRaw = required(env, ENV_DB_USER, "dbuser_missing");
        String dbUser;
        try {
            dbUser = InputValidator.requireSqlIdentifier(dbUserRaw);
        } catch (InputValidator.ValidationException e) {
            throw new ConfigException("dbuser_" + e.getMessage());
        }

        char[] dbPassword = env.get(ENV_DB_PASSWORD) == null ? new char[0]
                : env.get(ENV_DB_PASSWORD).toCharArray();

        String accountTable = ident(orDefault(env.get(ENV_ACCOUNT_TABLE), DEFAULT_ACCOUNT_TABLE),
                "account_table");
        String throttleTable = ident(orDefault(env.get(ENV_THROTTLE_TABLE), DEFAULT_THROTTLE_TABLE),
                "throttle_table");
        String sessionTable = ident(orDefault(env.get(ENV_SESSION_TABLE), DEFAULT_SESSION_TABLE),
                "session_table");
        if (accountTable.equalsIgnoreCase(throttleTable)
                || accountTable.equalsIgnoreCase(sessionTable)
                || throttleTable.equalsIgnoreCase(sessionTable)) {
            throw new ConfigException("table_names_must_differ");
        }

        int iterations = integer(env, ENV_ITERATIONS, "iterations", DEFAULT_ITERATIONS,
                PasswordHasher.MIN_ITERATIONS, PasswordHasher.MAX_ITERATIONS);
        int identityMax = integer(env, ENV_IDENTITY_MAX, "identity_max", DEFAULT_IDENTITY_MAX,
                1, 1_000);
        int identityWindow = integer(env, ENV_IDENTITY_WINDOW, "identity_window",
                DEFAULT_IDENTITY_WINDOW, 60, 86_400);
        int sourceMax = integer(env, ENV_SOURCE_MAX, "source_max", DEFAULT_SOURCE_MAX, 1, 100_000);
        int sourceWindow = integer(env, ENV_SOURCE_WINDOW, "source_window", DEFAULT_SOURCE_WINDOW,
                60, 86_400);
        int ttl = integer(env, ENV_SESSION_TTL, "session_ttl", DEFAULT_SESSION_TTL, 60, 86_400);
        int pwMin = integer(env, ENV_PASSWORD_MIN, "password_min", DEFAULT_PASSWORD_MIN, 10, 64);
        int minLoginMs = integer(env, ENV_MIN_LOGIN_MS, "min_login_ms", DEFAULT_MIN_LOGIN_MS,
                500, 15_000);

        // Rule 3: if one source's budget were smaller than one account's budget, the shared
        // per-source counter would itself become the lockout weapon. Refuse the configuration.
        if (sourceMax < identityMax) {
            throw new ConfigException("source_max_below_identity_max");
        }

        String sourceId;
        try {
            sourceId = InputValidator.requireSourceId(
                    orDefault(env.get(ENV_SOURCE_ID), DEFAULT_SOURCE_ID));
        } catch (InputValidator.ValidationException e) {
            throw new ConfigException("source_" + e.getMessage());
        }

        boolean emitSession;
        try {
            // Off unless the operator asks: the emitted value is a bearer credential, and a default
            // of true would put it in every terminal scrollback and CI log by default.
            emitSession = InputValidator.requireBoolean(
                    orDefault(env.get(ENV_EMIT_SESSION), "false"), "emit_session");
        } catch (InputValidator.ValidationException e) {
            throw new ConfigException(e.getMessage());
        }

        String auditLogPath = env.get(ENV_AUDIT_LOG);
        if (auditLogPath != null) {
            try {
                auditLogPath = InputValidator.requireDbPath(auditLogPath);
            } catch (InputValidator.ValidationException e) {
                throw new ConfigException("audit_" + e.getMessage());
            }
        }

        return new Config(dbPath, dbUser, dbPassword, accountTable, throttleTable, sessionTable,
                iterations, identityMax, identityWindow, sourceMax, sourceWindow, ttl, pwMin,
                sourceId, auditLogPath, emitSession, minLoginMs);
    }

    private static String required(Map<String, String> env, String key, String code)
            throws ConfigException {
        String v = env.get(key);
        if (v == null || v.isEmpty()) {
            throw new ConfigException(code);
        }
        return v;
    }

    private static String orDefault(String v, String fallback) {
        return (v == null || v.isEmpty()) ? fallback : v;
    }

    private static String ident(String value, String code) throws ConfigException {
        try {
            return InputValidator.requireSqlIdentifier(value);
        } catch (InputValidator.ValidationException e) {
            throw new ConfigException(code + "_" + e.getMessage());
        }
    }

    private static int integer(Map<String, String> env, String key, String code, int fallback,
            int min, int max) throws ConfigException {
        String raw = env.get(key);
        if (raw == null || raw.isEmpty()) {
            raw = Integer.toString(fallback);
        }
        try {
            return InputValidator.requireInt(raw, code, min, max);
        } catch (InputValidator.ValidationException e) {
            throw new ConfigException(e.getMessage());
        }
    }

    String dbPath() {
        return dbPath;
    }

    String dbUser() {
        return dbUser;
    }

    /** Returns the configured credential once and forgets it; the caller owns and wipes it. */
    char[] takeDbPassword() {
        char[] out = dbPassword;
        dbPassword = new char[0];
        return out;
    }

    boolean hasConfiguredDbPassword() {
        return dbPassword != null && dbPassword.length > 0;
    }

    String accountTable() {
        return accountTable;
    }

    String throttleTable() {
        return throttleTable;
    }

    String sessionTable() {
        return sessionTable;
    }

    int iterations() {
        return iterations;
    }

    int identityMaxFailures() {
        return identityMaxFailures;
    }

    int identityWindowSec() {
        return identityWindowSec;
    }

    int sourceMaxAttempts() {
        return sourceMaxAttempts;
    }

    int sourceWindowSec() {
        return sourceWindowSec;
    }

    int sessionTtlSec() {
        return sessionTtlSec;
    }

    int passwordMinLength() {
        return passwordMinLength;
    }

    String sourceId() {
        return sourceId;
    }

    String auditLogPath() {
        return auditLogPath;
    }

    boolean emitSession() {
        return emitSession;
    }

    int minLoginMs() {
        return minLoginMs;
    }
}
