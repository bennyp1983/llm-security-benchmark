package com.security.auth.database;

import com.security.auth.config.SecurityConfig;
import com.security.auth.model.Session;
import com.security.auth.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Handles database operations using strict parameterized queries, transactions,
 * and owner-private file permissions.
 *
 * Implements:
 * - Rule 1: All DB inputs and outputs strictly typed and validated.
 * - Rule 2: Credentials handled securely without logging.
 * - Rule 5: Bound sizes, enforce owner-only (0600/0700) file permissions.
 * - Rule 7: Atomic operations via transactions and SQL unique constraints.
 */
public final class DatabaseManager implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(DatabaseManager.class);

    private final SecurityConfig config;

    public DatabaseManager(SecurityConfig config) {
        this.config = Objects.requireNonNull(config, "config must not be null");
        initializeDatabase();
    }

    /**
     * Obtains a new database connection.
     */
    public Connection getConnection() throws SQLException {
        char[] pass = config.getDbPassword();
        try {
            return DriverManager.getConnection(config.getDbUrl(), config.getDbUser(), new String(pass));
        } finally {
            // pass is a cloned copy from config, clear it after connection string creation
            java.util.Arrays.fill(pass, '\0');
        }
    }

    /**
     * Initializes the database schema and verifies table constraints.
     */
    private void initializeDatabase() {
        try (Connection conn = getConnection()) {
            conn.setAutoCommit(false);
            try {
                // Table: users
                try (PreparedStatement stmt = conn.prepareStatement(
                        "CREATE TABLE IF NOT EXISTS users (" +
                                "id VARCHAR(36) PRIMARY KEY, " +
                                "username VARCHAR(32) NOT NULL UNIQUE, " +
                                "email VARCHAR(254) NOT NULL UNIQUE, " +
                                "password_hash VARCHAR(256) NOT NULL, " +
                                "salt VARCHAR(64) NOT NULL, " +
                                "iterations INT NOT NULL, " +
                                "created_at TIMESTAMP NOT NULL" +
                                ")"
                )) {
                    stmt.execute();
                }

                // Table: sessions
                try (PreparedStatement stmt = conn.prepareStatement(
                        "CREATE TABLE IF NOT EXISTS sessions (" +
                                "id VARCHAR(36) PRIMARY KEY, " +
                                "user_id VARCHAR(36) NOT NULL, " +
                                "token_hash VARCHAR(64) NOT NULL UNIQUE, " +
                                "created_at TIMESTAMP NOT NULL, " +
                                "expires_at TIMESTAMP NOT NULL, " +
                                "last_active_at TIMESTAMP NOT NULL, " +
                                "source_ip VARCHAR(45) NOT NULL, " +
                                "FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE" +
                                ")"
                )) {
                    stmt.execute();
                }

                // Table: audit_logs
                try (PreparedStatement stmt = conn.prepareStatement(
                        "CREATE TABLE IF NOT EXISTS audit_logs (" +
                                "id VARCHAR(36) PRIMARY KEY, " +
                                "event_type VARCHAR(50) NOT NULL, " +
                                "masked_identifier VARCHAR(100) NOT NULL, " +
                                "source_ip VARCHAR(45) NOT NULL, " +
                                "success BOOLEAN NOT NULL, " +
                                "created_at TIMESTAMP NOT NULL" +
                                ")"
                )) {
                    stmt.execute();
                }

                conn.commit();
                log.info("Database schema initialized and verified successfully.");
            } catch (SQLException e) {
                conn.rollback();
                throw new IllegalStateException("Failed to initialize database schema", e);
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to connect to database for initialization", e);
        }

        // Restrict database file permissions to 0600 on disk
        enforceDbFilePermissions();
    }

    /**
     * Enforces POSIX 0600 (owner read/write only) on any database files created on disk.
     */
    public void enforceDbFilePermissions() {
        Path dataDir = config.getDataDirectory();
        if (dataDir == null || !Files.exists(dataDir)) {
            return;
        }

        try (var stream = Files.newDirectoryStream(dataDir)) {
            for (Path entry : stream) {
                if (Files.isRegularFile(entry)) {
                    try {
                        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
                        Files.setPosixFilePermissions(entry, perms);
                    } catch (UnsupportedOperationException e) {
                        File f = entry.toFile();
                        f.setReadable(false, false);
                        f.setWritable(false, false);
                        f.setExecutable(false, false);
                        f.setReadable(true, true);
                        f.setWritable(true, true);
                    }
                }
            }
        } catch (IOException e) {
            log.warn("Could not enforce strict permissions on all files in data directory: {}", e.getMessage());
        }
    }

    /**
     * Atomically registers a user in the database.
     * Enforces unique constraints and rolls back cleanly on conflict.
     *
     * @param user user entity to store
     * @return true if inserted, false if user or email already exists
     */
    public boolean insertUser(User user) {
        String sql = "INSERT INTO users (id, username, email, password_hash, salt, iterations, created_at) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?)";

        try (Connection conn = getConnection()) {
            conn.setAutoCommit(false);
            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                stmt.setString(1, user.getId());
                stmt.setString(2, user.getUsername());
                stmt.setString(3, user.getEmail());
                stmt.setString(4, user.getPasswordHash());
                stmt.setString(5, user.getSalt());
                stmt.setInt(6, user.getIterations());
                stmt.setTimestamp(7, Timestamp.from(user.getCreatedAt()));

                int rows = stmt.executeUpdate();
                conn.commit();
                enforceDbFilePermissions();
                return rows == 1;
            } catch (SQLException e) {
                conn.rollback();
                // SQLState 23505 is standard ANSI SQL unique violation in H2 and Postgres
                if ("23505".equals(e.getSQLState()) || e.getMessage().toLowerCase().contains("unique")) {
                    log.info("Registration conflict: unique constraint triggered for username or email");
                    return false;
                }
                log.error("Database error while inserting user: {}", e.getMessage());
                return false;
            }
        } catch (SQLException e) {
            log.error("Failed to establish database connection for user insertion: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Checks if a user already exists with the given username or email.
     */
    public boolean userExists(String username, String email) {
        String sql = "SELECT 1 FROM users WHERE username = ? OR email = ?";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, username);
            stmt.setString(2, email);
            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            log.error("Database query failed during userExists check: {}", e.getMessage());
            // Fail closed
            return true;
        }
    }

    /**
     * Retrieves a user by username or email.
     *
     * @param identifier username or email
     * @return Optional containing User if found, empty otherwise
     */
    public Optional<User> findUserByIdentifier(String identifier) {
        String sql = "SELECT id, username, email, password_hash, salt, iterations, created_at FROM users WHERE username = ? OR email = ?";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, identifier);
            stmt.setString(2, identifier);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    User user = new User(
                            rs.getString("id"),
                            rs.getString("username"),
                            rs.getString("email"),
                            rs.getString("password_hash"),
                            rs.getString("salt"),
                            rs.getInt("iterations"),
                            rs.getTimestamp("created_at").toInstant()
                    );
                    return Optional.of(user);
                }
            }
        } catch (SQLException e) {
            log.error("Database error retrieving user by identifier: {}", e.getMessage());
        }
        return Optional.empty();
    }

    /**
     * Retrieves a user by their unique primary key ID.
     *
     * @param id user UUID
     * @return Optional containing User if found, empty otherwise
     */
    public Optional<User> findUserById(String id) {
        String sql = "SELECT id, username, email, password_hash, salt, iterations, created_at FROM users WHERE id = ?";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, id);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    User user = new User(
                            rs.getString("id"),
                            rs.getString("username"),
                            rs.getString("email"),
                            rs.getString("password_hash"),
                            rs.getString("salt"),
                            rs.getInt("iterations"),
                            rs.getTimestamp("created_at").toInstant()
                    );
                    return Optional.of(user);
                }
            }
        } catch (SQLException e) {
            log.error("Database error retrieving user by id: {}", e.getMessage());
        }
        return Optional.empty();
    }

    /**
     * Inserts a new session record atomically.
     */
    public boolean insertSession(Session session) {
        String sql = "INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, last_active_at, source_ip) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?)";
        try (Connection conn = getConnection()) {
            conn.setAutoCommit(false);
            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                stmt.setString(1, session.getId());
                stmt.setString(2, session.getUserId());
                stmt.setString(3, session.getTokenHash());
                stmt.setTimestamp(4, Timestamp.from(session.getCreatedAt()));
                stmt.setTimestamp(5, Timestamp.from(session.getExpiresAt()));
                stmt.setTimestamp(6, Timestamp.from(session.getLastActiveAt()));
                stmt.setString(7, session.getSourceIp());

                int rows = stmt.executeUpdate();
                conn.commit();
                return rows == 1;
            } catch (SQLException e) {
                conn.rollback();
                log.error("Failed to insert session: {}", e.getMessage());
                return false;
            }
        } catch (SQLException e) {
            log.error("Connection failure while inserting session: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Looks up an active session by token hash.
     */
    public Optional<Session> findSessionByTokenHash(String tokenHash) {
        String sql = "SELECT id, user_id, token_hash, created_at, expires_at, last_active_at, source_ip FROM sessions WHERE token_hash = ?";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, tokenHash);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    Session session = new Session(
                            rs.getString("id"),
                            rs.getString("user_id"),
                            rs.getString("token_hash"),
                            rs.getTimestamp("created_at").toInstant(),
                            rs.getTimestamp("expires_at").toInstant(),
                            rs.getTimestamp("last_active_at").toInstant(),
                            rs.getString("source_ip")
                    );
                    return Optional.of(session);
                }
            }
        } catch (SQLException e) {
            log.error("Error finding session by token hash: {}", e.getMessage());
        }
        return Optional.empty();
    }

    /**
     * Updates the last active timestamp of a session.
     */
    public void updateSessionActivity(String sessionId, Instant newLastActive, Instant newExpiresAt) {
        String sql = "UPDATE sessions SET last_active_at = ?, expires_at = ? WHERE id = ?";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setTimestamp(1, Timestamp.from(newLastActive));
            stmt.setTimestamp(2, Timestamp.from(newExpiresAt));
            stmt.setString(3, sessionId);
            stmt.executeUpdate();
        } catch (SQLException e) {
            log.error("Failed to update session activity: {}", e.getMessage());
        }
    }

    /**
     * Deletes a session by token hash (revocation/logout).
     */
    public boolean deleteSessionByTokenHash(String tokenHash) {
        String sql = "DELETE FROM sessions WHERE token_hash = ?";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, tokenHash);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            log.error("Failed to delete session: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Records an audit event in the database.
     */
    public void recordAuditLog(String eventType, String maskedIdentifier, String sourceIp, boolean success) {
        String sql = "INSERT INTO audit_logs (id, event_type, masked_identifier, source_ip, success, created_at) " +
                "VALUES (?, ?, ?, ?, ?, ?)";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, java.util.UUID.randomUUID().toString());
            stmt.setString(2, eventType);
            stmt.setString(3, maskedIdentifier);
            stmt.setString(4, sourceIp);
            stmt.setBoolean(5, success);
            stmt.setTimestamp(6, Timestamp.from(Instant.now()));
            stmt.executeUpdate();
        } catch (SQLException e) {
            log.warn("Failed to write audit log entry: {}", e.getMessage());
        }
    }

    @Override
    public void close() {
        // Enforce permissions one final time before shutdown
        enforceDbFilePermissions();
    }
}
