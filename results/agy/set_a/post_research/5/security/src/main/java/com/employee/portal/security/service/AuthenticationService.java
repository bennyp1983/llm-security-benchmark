package com.employee.portal.security.service;

import com.employee.portal.security.config.SecurityConfig;
import com.employee.portal.security.crypto.PasswordHasher;
import com.employee.portal.security.crypto.SecureTokenGenerator;
import com.employee.portal.security.logging.AuditLogger;
import com.employee.portal.security.model.AuthenticationResult;
import com.employee.portal.security.model.EmployeeRecord;
import com.employee.portal.security.model.Session;
import com.employee.portal.security.model.UserStatus;
import com.employee.portal.security.ratelimit.RateLimiter;
import com.employee.portal.security.repository.EmployeeRepository;
import com.employee.portal.security.session.SessionManager;
import com.employee.portal.security.validation.InputValidator;

import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

/**
 * Core authentication orchestration service.
 * Enforces all security rules:
 * - Rule 1: Validates untrusted input strictly before processing.
 * - Rule 2: Secrets never printed/logged, wiped from memory immediately.
 * - Rule 3: Verifies all authentication against server-side state; fails closed.
 *           Tracks attempts per source and per account to prevent lockout DoS.
 * - Rule 4: Session tokens generated with SecureRandom; cookies carry HttpOnly, Secure, SameSite=Strict.
 * - Rule 5: Password wiped with zeros; tokens masked in logs; storage bounded.
 * - Rule 6: Identical error messages and comparable work (dummy PBKDF2) for all failure outcomes.
 * - Rule 7: State checks and transitions are atomic.
 * - Rule 8: Leverages standard Java Cryptography Architecture (JCA PBKDF2WithHmacSHA512).
 */
public final class AuthenticationService {

    private final SecurityConfig config;
    private final EmployeeRepository repository;
    private final PasswordHasher passwordHasher;
    private final RateLimiter rateLimiter;
    private final SessionManager sessionManager;
    private final AuditLogger auditLogger;
    private final boolean requireSecureCookies;

    public AuthenticationService(SecurityConfig config,
                                 EmployeeRepository repository,
                                 PasswordHasher passwordHasher,
                                 RateLimiter rateLimiter,
                                 SessionManager sessionManager,
                                 AuditLogger auditLogger) {
        this(config, repository, passwordHasher, rateLimiter, sessionManager, auditLogger, true);
    }

    public AuthenticationService(SecurityConfig config,
                                 EmployeeRepository repository,
                                 PasswordHasher passwordHasher,
                                 RateLimiter rateLimiter,
                                 SessionManager sessionManager,
                                 AuditLogger auditLogger,
                                 boolean requireSecureCookies) {
        this.config = Objects.requireNonNull(config);
        this.repository = Objects.requireNonNull(repository);
        this.passwordHasher = Objects.requireNonNull(passwordHasher);
        this.rateLimiter = Objects.requireNonNull(rateLimiter);
        this.sessionManager = Objects.requireNonNull(sessionManager);
        this.auditLogger = Objects.requireNonNull(auditLogger);
        this.requireSecureCookies = requireSecureCookies;
    }

    /**
     * Authenticates an employee with username, password, and source IP.
     * Wipes password memory on completion.
     */
    public AuthenticationResult authenticate(String username, char[] password, String sourceIp) {
        try {
            // Step 1: Input validation across trust boundary (Rule 1)
            boolean validUsername = InputValidator.isValidUsername(username);
            boolean validPassword = InputValidator.isValidPassword(password);
            boolean validSourceIp = InputValidator.isValidSourceIp(sourceIp);

            String safeSource = validSourceIp ? sourceIp.trim() : "unknown-source";

            if (!validUsername || !validPassword || !validSourceIp) {
                // Rule 6: Do comparable work even on invalid inputs to prevent timing analysis
                passwordHasher.dummyVerify(password);
                if (validSourceIp) {
                    rateLimiter.recordFailure(safeSource, null);
                }
                auditLogger.logEvent(AuditLogger.EventType.VALIDATION_ERROR,
                        safeSource,
                        username,
                        "Input format validation failed");
                return AuthenticationResult.failure();
            }

            String normalizedUser = username.trim().toLowerCase();

            // Step 2: Rate limit check per source and per account (Rule 3)
            if (rateLimiter.isRestricted(safeSource, normalizedUser)) {
                // Rule 6: Do comparable PBKDF2 computation so attacker cannot confirm restriction via timing
                passwordHasher.dummyVerify(password);
                auditLogger.logEvent(AuditLogger.EventType.LOGIN_FAILURE,
                        safeSource,
                        normalizedUser,
                        "Login rejected: source or account rate limit reached");
                return AuthenticationResult.failure();
            }

            // Step 3: Lookup employee record against server-side state (Rule 1 & Rule 3)
            Optional<EmployeeRecord> maybeRecord = repository.findByUsername(normalizedUser);

            if (maybeRecord.isEmpty()) {
                // User does not exist: perform dummy hash computation to prevent user enumeration
                passwordHasher.dummyVerify(password);
                rateLimiter.recordFailure(safeSource, normalizedUser);
                auditLogger.logEvent(AuditLogger.EventType.LOGIN_FAILURE,
                        safeSource,
                        normalizedUser,
                        "Authentication failed: credentials rejected");
                return AuthenticationResult.failure();
            }

            EmployeeRecord record = maybeRecord.get();

            // Check account status
            if (!record.isActive()) {
                // Account suspended: perform dummy hash computation to prevent state enumeration
                passwordHasher.dummyVerify(password);
                rateLimiter.recordFailure(safeSource, normalizedUser);
                auditLogger.logEvent(AuditLogger.EventType.LOGIN_FAILURE,
                        safeSource,
                        normalizedUser,
                        "Authentication failed: account suspended");
                return AuthenticationResult.failure();
            }

            // Step 4: Verify supplied credentials using constant-time PBKDF2 comparison
            boolean matches = passwordHasher.verifyPassword(
                    password,
                    record.getSalt(),
                    record.getPasswordHash(),
                    record.getIterations()
            );

            if (!matches) {
                rateLimiter.recordFailure(safeSource, normalizedUser);
                auditLogger.logEvent(AuditLogger.EventType.LOGIN_FAILURE,
                        safeSource,
                        normalizedUser,
                        "Authentication failed: credentials rejected");
                return AuthenticationResult.failure();
            }

            // Step 5: Successful authentication
            // Atomically clear failed attempts for source and account
            rateLimiter.recordSuccess(safeSource, normalizedUser);

            // Create cryptographically random server-side session (Rule 4)
            Session session = sessionManager.createSession(record.getUsername(), record.getRole(), safeSource);

            // Construct secure cookie header (Rule 4)
            long maxAgeSeconds = config.getSessionIdleTimeoutMillis() / 1000L;
            String cookieHeader = SecureTokenGenerator.buildSessionCookieHeader(
                    session.getSessionId(),
                    maxAgeSeconds,
                    requireSecureCookies
            );

            auditLogger.logEvent(AuditLogger.EventType.LOGIN_SUCCESS,
                    safeSource,
                    record.getUsername(),
                    "Authentication successful; session=" + AuditLogger.maskToken(session.getSessionId()));

            return AuthenticationResult.success(session, cookieHeader);

        } catch (Exception e) {
            // Fail closed on any unexpected error (Rule 3)
            auditLogger.logEvent(AuditLogger.EventType.LOGIN_FAILURE,
                    sourceIp,
                    username,
                    "Internal error during authentication: " + e.getClass().getSimpleName());
            return AuthenticationResult.failure();
        } finally {
            // Rule 5: Clear sensitive credentials from memory
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    /**
     * Enrolls an employee into the portal database.
     * Generates a cryptographically strong salt, hashes password with PBKDF2, and wipes memory.
     */
    public boolean enrollEmployee(String username, char[] password, String role) {
        try {
            if (!InputValidator.isValidUsername(username)) {
                return false;
            }
            if (!InputValidator.isValidPassword(password)) {
                return false;
            }
            String normalizedUser = username.trim().toLowerCase();
            if (repository.exists(normalizedUser)) {
                return false;
            }

            byte[] salt = passwordHasher.generateSalt();
            byte[] hash = passwordHasher.hashPassword(password, salt);

            EmployeeRecord record = new EmployeeRecord(
                    username.trim(),
                    salt,
                    hash,
                    passwordHasher.getDefaultIterations(),
                    UserStatus.ACTIVE,
                    (role == null || role.isBlank()) ? "EMPLOYEE" : role.trim().toUpperCase()
            );

            boolean saved = repository.save(record);
            if (saved) {
                auditLogger.logEvent(AuditLogger.EventType.USER_ENROLLED,
                        "127.0.0.1",
                        record.getUsername(),
                        "Employee record registered successfully");
            }
            return saved;
        } finally {
            // Wipe password memory (Rule 5)
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    public SessionManager getSessionManager() {
        return sessionManager;
    }

    public RateLimiter getRateLimiter() {
        return rateLimiter;
    }

    public EmployeeRepository getRepository() {
        return repository;
    }

    public AuditLogger getAuditLogger() {
        return auditLogger;
    }
}
