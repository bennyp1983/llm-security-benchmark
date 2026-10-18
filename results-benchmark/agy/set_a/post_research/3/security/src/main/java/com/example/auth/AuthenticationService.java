package com.example.auth;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Optional;

/**
 * Core authentication service coordinating trust boundaries, rate limiting,
 * constant-time verification, memory hygiene, and session issuance.
 */
public final class AuthenticationService {

    private final DatabaseManager databaseManager;
    private final UserRepository userRepository;
    private final PasswordHasher passwordHasher;
    private final RateLimiter rateLimiter;
    private final SessionManager sessionManager;

    public AuthenticationService(DatabaseManager databaseManager) {
        this(
                databaseManager,
                new UserRepository(),
                new PasswordHasher(),
                new RateLimiter(),
                new SessionManager()
        );
    }

    public AuthenticationService(DatabaseManager databaseManager,
                                 UserRepository userRepository,
                                 PasswordHasher passwordHasher,
                                 RateLimiter rateLimiter,
                                 SessionManager sessionManager) {
        if (databaseManager == null || userRepository == null || passwordHasher == null
                || rateLimiter == null || sessionManager == null) {
            throw new IllegalArgumentException("Dependencies cannot be null");
        }
        this.databaseManager = databaseManager;
        this.userRepository = userRepository;
        this.passwordHasher = passwordHasher;
        this.rateLimiter = rateLimiter;
        this.sessionManager = sessionManager;
    }

    /**
     * Authenticates a user by email and password.
     * Enforces:
     * - Immediate zeroization of password character array in finally block.
     * - Atomic rate limiting (source and account level).
     * - Constant-work timing attack resistance across missing accounts and format errors.
     * - Generic failure responses to prevent user enumeration.
     *
     * @param email         Candidate email address.
     * @param passwordChars Candidate password characters (zeroized before method returns).
     * @param sourceId      Client / network source identifier.
     * @return AuthenticationResult indicating success or generic failure.
     */
    public AuthenticationResult authenticate(String email, char[] passwordChars, String sourceId) {
        try {
            String safeSource = InputValidator.sanitizeSourceId(sourceId);
            String safeEmail = InputValidator.canonicalizeEmail(email);

            // 1. Concurrency & Rate Limiting Check (Rules 3 & 7)
            RateLimiter.RateLimitResult rateCheck = rateLimiter.checkAndAcquire(safeSource, safeEmail);
            if (!rateCheck.isAllowed()) {
                SecurityLogger.logRateLimitExceeded(safeEmail, safeSource, rateCheck.status().name());
                return AuthenticationResult.rateLimited();
            }

            // Apply progressive delay if account is under distributed brute force pressure
            if (rateCheck.progressiveDelayMs() > 0) {
                try {
                    Thread.sleep(rateCheck.progressiveDelayMs());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    SecurityLogger.logSystemError("Authentication thread interrupted during throttle delay", e);
                    return AuthenticationResult.internalError();
                }
            }

            // 2. Input Validation across Trust Boundaries (Rule 1)
            boolean emailValid = InputValidator.isValidEmail(email);
            boolean passwordValid = InputValidator.isValidPasswordForAuth(passwordChars);

            if (!emailValid || !passwordValid) {
                // Timing defense: perform dummy key derivation so rejection takes standard PBKDF2 time (Rule 6)
                passwordHasher.verifyDummyPassword(passwordChars);
                rateLimiter.recordAuthenticationFailure(safeSource, safeEmail);
                SecurityLogger.logAuthFailure(safeEmail, safeSource, "MALFORMED_INPUT");
                return AuthenticationResult.invalidCredentials();
            }

            // 3. Database State Verification (Rules 1 & 3)
            Optional<UserRecord> userOpt;
            try (Connection conn = databaseManager.getConnection()) {
                userOpt = userRepository.findByEmail(conn, safeEmail);
            } catch (SQLException e) {
                SecurityLogger.logSystemError("Database query failed during authentication", e);
                return AuthenticationResult.internalError();
            }

            // Account not found or inactive -> Fail closed, execute dummy PBKDF2 to prevent timing leakage
            if (userOpt.isEmpty() || !userOpt.get().isActive()) {
                passwordHasher.verifyDummyPassword(passwordChars);
                rateLimiter.recordAuthenticationFailure(safeSource, safeEmail);
                SecurityLogger.logAuthFailure(safeEmail, safeSource,
                        userOpt.isEmpty() ? "ACCOUNT_NOT_FOUND" : "INACTIVE_ACCOUNT");
                return AuthenticationResult.invalidCredentials();
            }

            UserRecord user = userOpt.get();

            // 4. Constant-Time Credential Verification (Rules 3, 6, 8)
            boolean passwordMatches = passwordHasher.verifyPassword(
                    passwordChars,
                    user.salt(),
                    user.iterations(),
                    user.passwordHash()
            );

            if (!passwordMatches) {
                rateLimiter.recordAuthenticationFailure(safeSource, safeEmail);
                SecurityLogger.logAuthFailure(safeEmail, safeSource, "PASSWORD_MISMATCH");
                return AuthenticationResult.invalidCredentials();
            }

            // 5. Authentication Succeeded -> Issue Cryptographic Session Token (Rule 4)
            rateLimiter.recordAuthenticationSuccess(safeSource, safeEmail);
            SessionManager.Session session = sessionManager.createSession(user.id(), user.email());
            SecurityLogger.logAuthSuccess(safeEmail, safeSource);

            return AuthenticationResult.success(session);

        } finally {
            // Memory Hygiene: Zeroize sensitive credentials from memory (Rule 5)
            if (passwordChars != null) {
                Arrays.fill(passwordChars, '\0');
            }
        }
    }

    /**
     * Securely registers a new user with cryptographic salt and PBKDF2 hash.
     * Zeroizes password character array upon completion.
     */
    public boolean registerUser(String email, char[] passwordChars) {
        try {
            if (!InputValidator.isValidEmail(email) || !InputValidator.isValidPasswordForCreation(passwordChars)) {
                return false;
            }

            String canonicalEmail = InputValidator.canonicalizeEmail(email);
            HashResult hashResult = passwordHasher.hashPassword(passwordChars);

            try (Connection conn = databaseManager.getConnection()) {
                conn.setAutoCommit(false);
                try {
                    // Check if already exists
                    if (userRepository.findByEmail(conn, canonicalEmail).isPresent()) {
                        conn.rollback();
                        return false;
                    }
                    boolean created = userRepository.createUser(conn, canonicalEmail, hashResult);
                    if (created) {
                        conn.commit();
                        SecurityLogger.logAuthSuccess(canonicalEmail, "registration");
                        return true;
                    } else {
                        conn.rollback();
                        return false;
                    }
                } catch (SQLException e) {
                    conn.rollback();
                    SecurityLogger.logSystemError("Failed to register user", e);
                    return false;
                }
            } catch (SQLException e) {
                SecurityLogger.logSystemError("Database connection failed during registration", e);
                return false;
            }
        } finally {
            if (passwordChars != null) {
                Arrays.fill(passwordChars, '\0');
            }
        }
    }

    public RateLimiter getRateLimiter() {
        return rateLimiter;
    }

    public SessionManager getSessionManager() {
        return sessionManager;
    }

    public PasswordHasher getPasswordHasher() {
        return passwordHasher;
    }
}
