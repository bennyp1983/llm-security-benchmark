package com.example.auth;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Optional;

/**
 * Repository for user credentials and account state.
 * <p>
 * Satisfies:
 * - Rule 1: Every SQL interaction uses parameterized PreparedStatements. All returned database values
 *   are strictly validated before trusting.
 * - Rule 3: Fails closed on any unexpected or missing database state.
 */
public final class UserRepository {

    private static final String SELECT_USER_BY_EMAIL =
            "SELECT id, email, password_hash, salt, iterations, algorithm, status FROM users WHERE email = ?";

    private static final String INSERT_USER =
            "INSERT INTO users (email, password_hash, salt, iterations, algorithm, status) VALUES (?, ?, ?, ?, ?, ?)";

    private static final String COUNT_USERS =
            "SELECT COUNT(*) FROM users";

    /**
     * Finds a user record by email using a parameterized query.
     * Validates database-stored hash parameters to ensure integrity.
     *
     * @param conn  Active database connection.
     * @param email Canonical email address.
     * @return Optional containing UserRecord if found and valid; empty otherwise.
     */
    public Optional<UserRecord> findByEmail(Connection conn, String email) throws SQLException {
        if (!InputValidator.isValidEmail(email)) {
            return Optional.empty();
        }

        String canonical = InputValidator.canonicalizeEmail(email);

        try (PreparedStatement pstmt = conn.prepareStatement(SELECT_USER_BY_EMAIL)) {
            pstmt.setString(1, canonical);

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    long id = rs.getLong("id");
                    String userEmail = rs.getString("email");
                    String passwordHash = rs.getString("password_hash");
                    String salt = rs.getString("salt");
                    int iterations = rs.getInt("iterations");
                    String algorithm = rs.getString("algorithm");
                    String status = rs.getString("status");

                    // Treat values from database as untrusted until verified (Rule 1)
                    if (passwordHash == null || salt == null || algorithm == null || status == null) {
                        SecurityLogger.logAuthFailure(canonical, "database", "CORRUPTED_USER_ROW_NULL_FIELDS");
                        return Optional.empty();
                    }

                    try {
                        byte[] saltBytes = Base64.getDecoder().decode(salt);
                        byte[] hashBytes = Base64.getDecoder().decode(passwordHash);

                        if (!InputValidator.isValidDatabaseHashParameters(algorithm, iterations, saltBytes, hashBytes)) {
                            SecurityLogger.logAuthFailure(canonical, "database", "CORRUPTED_HASH_PARAMETERS");
                            return Optional.empty();
                        }
                    } catch (IllegalArgumentException e) {
                        SecurityLogger.logAuthFailure(canonical, "database", "INVALID_BASE64_IN_DATABASE");
                        return Optional.empty();
                    }

                    return Optional.of(new UserRecord(id, userEmail, passwordHash, salt, iterations, algorithm, status));
                }
            }
        }

        return Optional.empty();
    }

    /**
     * Persists a new user record using parameterized SQL.
     *
     * @param conn       Active database connection.
     * @param email      Canonical email address.
     * @param hashResult Generated cryptographic hash result.
     * @return true if user successfully persisted; false otherwise.
     */
    public boolean createUser(Connection conn, String email, HashResult hashResult) throws SQLException {
        if (!InputValidator.isValidEmail(email) || hashResult == null) {
            return false;
        }

        String canonical = InputValidator.canonicalizeEmail(email);

        try (PreparedStatement pstmt = conn.prepareStatement(INSERT_USER)) {
            pstmt.setString(1, canonical);
            pstmt.setString(2, hashResult.hashBase64());
            pstmt.setString(3, hashResult.saltBase64());
            pstmt.setInt(4, hashResult.iterations());
            pstmt.setString(5, hashResult.algorithm());
            pstmt.setString(6, "ACTIVE");

            return pstmt.executeUpdate() == 1;
        }
    }

    /**
     * Counts the total number of users in the database.
     */
    public long countUsers(Connection conn) throws SQLException {
        try (PreparedStatement pstmt = conn.prepareStatement(COUNT_USERS);
             ResultSet rs = pstmt.executeQuery()) {
            if (rs.next()) {
                return rs.getLong(1);
            }
            return 0;
        }
    }
}
