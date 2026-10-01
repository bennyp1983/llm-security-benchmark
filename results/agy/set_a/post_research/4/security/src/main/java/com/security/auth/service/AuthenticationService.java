package com.security.auth.service;

import com.security.auth.config.SecurityConfig;
import com.security.auth.crypto.CryptoUtils;
import com.security.auth.crypto.PasswordHasher;
import com.security.auth.crypto.TokenGenerator;
import com.security.auth.database.DatabaseManager;
import com.security.auth.model.AuthenticationRequest;
import com.security.auth.model.AuthenticationResult;
import com.security.auth.model.RegistrationRequest;
import com.security.auth.model.RegistrationResult;
import com.security.auth.model.Session;
import com.security.auth.model.SessionCookie;
import com.security.auth.model.User;
import com.security.auth.security.RateLimiter;
import com.security.auth.validation.InputValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Core security service orchestrating registration, authentication, session lifecycle,
 * rate limiting, and side-channel mitigations.
 */
public final class AuthenticationService implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationService.class);

    private final SecurityConfig config;
    private final DatabaseManager databaseManager;
    private final PasswordHasher passwordHasher;
    private final TokenGenerator tokenGenerator;
    private final RateLimiter rateLimiter;

    public AuthenticationService(SecurityConfig config, DatabaseManager databaseManager) {
        this.config = Objects.requireNonNull(config, "config must not be null");
        this.databaseManager = Objects.requireNonNull(databaseManager, "databaseManager must not be null");
        this.passwordHasher = new PasswordHasher(config.getPbkdf2Iterations());
        this.tokenGenerator = new TokenGenerator();
        this.rateLimiter = new RateLimiter();
    }

    /**
     * Registers a new user account.
     * Enforces:
     * - Rule 1: Trust boundary input validation
     * - Rule 5: Credential memory wiping
     * - Rule 6: Identical failure messages and constant work to prevent enumeration
     * - Rule 7: Atomic uniqueness check in database
     *
     * @param request registration input credentials
     * @param sourceIp client source IP
     * @return RegistrationResult
     */
    public RegistrationResult register(RegistrationRequest request, String sourceIp) {
        Objects.requireNonNull(request, "Registration request must not be null");
        String sanitizedSourceIp = InputValidator.validateSourceIp(sourceIp);

        try {
            // 1. Strict Whitelist Input Validation
            String validatedEmail;
            String validatedUsername;
            try {
                validatedEmail = InputValidator.validateAndNormalizeEmail(request.getEmail());
                validatedUsername = InputValidator.validateUsername(request.getUsername());
                InputValidator.validatePassword(request.getPassword());
            } catch (IllegalArgumentException e) {
                log.warn("Registration rejected due to invalid input format: reason={}", e.getMessage());
                // Rule 6: Fail closed with generic message
                return RegistrationResult.failure();
            }

            // 2. Pre-check if user already exists
            boolean alreadyExists = databaseManager.userExists(validatedUsername, validatedEmail);

            // 3. Compute PBKDF2 hash (COMPRABLE WORK)
            // Even if the account already exists, we compute the full PBKDF2 hash
            // to ensure an attacker cannot measure timing differences to enumerate registered users!
            PasswordHasher.HashedPassword hashedPassword = passwordHasher.hash(request.getPassword());

            if (alreadyExists) {
                log.info("Registration aborted: user or email already exists for masked username={}",
                        SecurityConfig.maskIdentifier(validatedUsername));
                databaseManager.recordAuditLog("REGISTRATION_DUPLICATE", SecurityConfig.maskIdentifier(validatedUsername), sanitizedSourceIp, false);
                // Rule 6: Return identical generic message
                return RegistrationResult.failure();
            }

            // 4. Atomic SQL Insertion
            String userId = UUID.randomUUID().toString();
            User newUser = new User(
                    userId,
                    validatedUsername,
                    validatedEmail,
                    hashedPassword.hashBase64(),
                    hashedPassword.saltBase64(),
                    hashedPassword.iterations(),
                    Instant.now()
            );

            boolean inserted = databaseManager.insertUser(newUser);
            if (!inserted) {
                // Caught race condition or DB constraint collision
                log.info("Registration collision during atomic insert for username={}",
                        SecurityConfig.maskIdentifier(validatedUsername));
                databaseManager.recordAuditLog("REGISTRATION_COLLISION", SecurityConfig.maskIdentifier(validatedUsername), sanitizedSourceIp, false);
                return RegistrationResult.failure();
            }

            log.info("New user registered successfully: userId={}, username={}",
                    userId, SecurityConfig.maskIdentifier(validatedUsername));
            databaseManager.recordAuditLog("REGISTRATION_SUCCESS", SecurityConfig.maskIdentifier(validatedUsername), sanitizedSourceIp, true);
            return RegistrationResult.success(userId);

        } finally {
            // Rule 5: Clear credentials from memory immediately when done
            request.wipe();
        }
    }

    /**
     * Authenticates user credentials and issues a secure session token.
     * Enforces:
     * - Rule 1: Trust boundary input validation
     * - Rule 3: Server-side verification, fail-closed, dual-dimensional rate limiting
     * - Rule 4: Cryptographically secure random tokens, secure cookies
     * - Rule 5: Credential memory clearing
     * - Rule 6: Constant work dummy hashing, generic failure messages
     *
     * @param request authentication input
     * @return AuthenticationResult
     */
    public AuthenticationResult authenticate(AuthenticationRequest request) {
        Objects.requireNonNull(request, "Authentication request must not be null");
        String sanitizedSourceIp = InputValidator.validateSourceIp(request.getSourceIp());

        try {
            // 1. Basic format sanity check on identifier and password bounds
            String identifier = request.getIdentifier();
            if (identifier == null || identifier.isBlank() || identifier.length() > InputValidator.EMAIL_MAX_LENGTH) {
                return AuthenticationResult.failure();
            }
            char[] password = request.getPassword();
            if (password == null || password.length < 1 || password.length > InputValidator.PASSWORD_MAX_LENGTH) {
                return AuthenticationResult.failure();
            }

            String normalizedIdentifier = identifier.trim();

            // 2. Dual Rate Limiting Check (Rule 3 & 7)
            RateLimiter.CheckResult checkResult = rateLimiter.checkAllowed(sanitizedSourceIp, normalizedIdentifier);
            if (!checkResult.allowed()) {
                log.warn("Authentication blocked by rate limiter for source={}", sanitizedSourceIp);
                databaseManager.recordAuditLog("AUTH_RATE_LIMITED", SecurityConfig.maskIdentifier(normalizedIdentifier), sanitizedSourceIp, false);
                return AuthenticationResult.rateLimited(checkResult.reason());
            }

            // Apply progressive delay if account is experiencing distributed pressure
            if (checkResult.delayMs() > 0) {
                try {
                    Thread.sleep(checkResult.delayMs());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }

            // 3. Database user lookup
            Optional<User> userOpt = databaseManager.findUserByIdentifier(normalizedIdentifier);

            if (userOpt.isEmpty()) {
                // Rule 6: Constant work timing mitigation!
                // Execute identical dummy PBKDF2 hash computation so response time matches real user verification.
                passwordHasher.verifyDummy(password);

                // Record failure in rate limiter
                rateLimiter.recordFailure(sanitizedSourceIp, normalizedIdentifier);
                databaseManager.recordAuditLog("AUTH_FAILED_NOT_FOUND", SecurityConfig.maskIdentifier(normalizedIdentifier), sanitizedSourceIp, false);
                log.info("Authentication failed: account not found for identifier={}", SecurityConfig.maskIdentifier(normalizedIdentifier));
                return AuthenticationResult.failure();
            }

            User user = userOpt.get();

            // 4. Constant-time password verification
            boolean passwordValid = passwordHasher.verify(
                    password,
                    user.getSalt(),
                    user.getPasswordHash(),
                    user.getIterations()
            );

            if (!passwordValid) {
                rateLimiter.recordFailure(sanitizedSourceIp, normalizedIdentifier);
                databaseManager.recordAuditLog("AUTH_FAILED_BAD_PASSWORD", SecurityConfig.maskIdentifier(normalizedIdentifier), sanitizedSourceIp, false);
                log.info("Authentication failed: invalid password for identifier={}", SecurityConfig.maskIdentifier(normalizedIdentifier));
                return AuthenticationResult.failure();
            }

            // 5. Success: clear failure counters
            rateLimiter.recordSuccess(sanitizedSourceIp, normalizedIdentifier);

            // 6. Generate 256-bit cryptographically secure session token (Rule 4)
            String rawToken = tokenGenerator.generateSecureToken();
            String tokenHash = tokenGenerator.hashToken(rawToken);

            Instant now = Instant.now();
            int ttlMinutes = config.getSessionTtlMinutes();
            Instant expiresAt = now.plus(Duration.ofMinutes(ttlMinutes));

            Session session = new Session(
                    UUID.randomUUID().toString(),
                    user.getId(),
                    tokenHash,
                    now,
                    expiresAt,
                    now,
                    sanitizedSourceIp
            );

            boolean sessionSaved = databaseManager.insertSession(session);
            if (!sessionSaved) {
                log.error("Failed to persist session in database");
                return AuthenticationResult.failure();
            }

            SessionCookie cookie = new SessionCookie(rawToken, ttlMinutes * 60);

            log.info("User authenticated successfully: userId={}, username={}",
                    user.getId(), SecurityConfig.maskIdentifier(user.getUsername()));
            databaseManager.recordAuditLog("AUTH_SUCCESS", SecurityConfig.maskIdentifier(user.getUsername()), sanitizedSourceIp, true);

            return AuthenticationResult.success(rawToken, cookie, user);

        } finally {
            // Rule 5: Clear sensitive password from memory
            request.wipe();
        }
    }

    /**
     * Validates an active session token presented by a client.
     * Enforces:
     * - Rule 1: Strict token format validation
     * - Rule 3: Verified strictly against server-side state, fails closed
     * - Rule 4: Validates against stored SHA-256 token hash
     *
     * @param rawToken session token from client
     * @param sourceIp client source IP
     * @return Optional containing authenticated User if valid; empty otherwise
     */
    public Optional<User> validateSession(String rawToken, String sourceIp) {
        if (!tokenGenerator.isValidTokenFormat(rawToken)) {
            return Optional.empty();
        }
        String sanitizedSourceIp = InputValidator.validateSourceIp(sourceIp);

        String tokenHash = tokenGenerator.hashToken(rawToken);
        Optional<Session> sessionOpt = databaseManager.findSessionByTokenHash(tokenHash);

        if (sessionOpt.isEmpty()) {
            return Optional.empty();
        }

        Session session = sessionOpt.get();
        Instant now = Instant.now();

        // Check expiration
        if (session.isExpired(now)) {
            log.info("Session expired: sessionId={}", session.getId());
            databaseManager.deleteSessionByTokenHash(tokenHash);
            return Optional.empty();
        }

        // Verify source IP binding to prevent token replay from other IPs
        if (!session.getSourceIp().equals(sanitizedSourceIp)) {
            log.warn("Session source IP mismatch detected: sessionIp={}, requestIp={}",
                    session.getSourceIp(), sanitizedSourceIp);
            // Invalidate suspicious session
            databaseManager.deleteSessionByTokenHash(tokenHash);
            return Optional.empty();
        }

        // Check inactivity timeout (e.g. 30 minutes)
        Duration inactiveDuration = Duration.between(session.getLastActiveAt(), now);
        if (inactiveDuration.toMinutes() >= config.getSessionTtlMinutes()) {
            log.info("Session exceeded inactivity timeout: sessionId={}", session.getId());
            databaseManager.deleteSessionByTokenHash(tokenHash);
            return Optional.empty();
        }

        // Slide session expiration and update last active time
        Instant newExpiresAt = now.plus(Duration.ofMinutes(config.getSessionTtlMinutes()));
        databaseManager.updateSessionActivity(session.getId(), now, newExpiresAt);

        // Fetch user from DB
        return databaseManager.findUserById(session.getUserId());
    }

    /**
     * Invalidates a session token (logout).
     */
    public boolean logout(String rawToken) {
        if (!tokenGenerator.isValidTokenFormat(rawToken)) {
            return false;
        }
        String tokenHash = tokenGenerator.hashToken(rawToken);
        return databaseManager.deleteSessionByTokenHash(tokenHash);
    }

    public SecurityConfig getConfig() {
        return config;
    }

    public DatabaseManager getDatabaseManager() {
        return databaseManager;
    }

    public PasswordHasher getPasswordHasher() {
        return passwordHasher;
    }

    public RateLimiter getRateLimiter() {
        return rateLimiter;
    }

    @Override
    public void close() {
        databaseManager.close();
    }
}
