package com.security.auth;

import com.security.auth.crypto.PasswordHasher;
import com.security.auth.crypto.TokenGenerator;
import com.security.auth.logging.AuthenticationEvent;
import com.security.auth.logging.AuthenticationEventLogger;
import com.security.auth.logging.AuthenticationEventType;
import com.security.auth.model.AccountStatus;
import com.security.auth.model.SessionToken;
import com.security.auth.model.UserRecord;
import com.security.auth.ratelimit.RateLimiter;
import com.security.auth.ratelimit.RateLimiter.RateLimitStatus;
import com.security.auth.repository.UserCredentialRepository;
import com.security.auth.validation.InputValidator;
import com.security.auth.validation.ValidationException;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Standard implementation of the authentication component (Rules 1-8).
 * Manages login attempts, failure throttling, timing attack mitigation,
 * generic client error responses, and audit logging.
 */
public final class DefaultAuthenticationService implements AuthenticationService {

    private final UserCredentialRepository userRepository;
    private final PasswordHasher passwordHasher;
    private final RateLimiter rateLimiter;
    private final TokenGenerator tokenGenerator;
    private final AuthenticationEventLogger eventLogger;

    public DefaultAuthenticationService(UserCredentialRepository userRepository,
                                        PasswordHasher passwordHasher,
                                        RateLimiter rateLimiter,
                                        TokenGenerator tokenGenerator,
                                        AuthenticationEventLogger eventLogger) {
        this.userRepository = Objects.requireNonNull(userRepository, "userRepository cannot be null.");
        this.passwordHasher = Objects.requireNonNull(passwordHasher, "passwordHasher cannot be null.");
        this.rateLimiter = Objects.requireNonNull(rateLimiter, "rateLimiter cannot be null.");
        this.tokenGenerator = Objects.requireNonNull(tokenGenerator, "tokenGenerator cannot be null.");
        this.eventLogger = Objects.requireNonNull(eventLogger, "eventLogger cannot be null.");
    }

    @Override
    public AuthenticationResult authenticate(AuthenticationRequest request) {
        if (request == null) {
            // Fail closed on null input (Rule 1 & 6)
            eventLogger.logEvent(new AuthenticationEvent(Instant.now(),
                    AuthenticationEventType.LOGIN_FAILURE_INVALID_INPUT,
                    false,
                    "[NULL_REQUEST]",
                    "[UNKNOWN_IP]",
                    "",
                    "Null authentication request provided"));
            return AuthenticationResult.failure(AuthenticationErrorCode.INVALID_INPUT);
        }

        try {
            String rawUsername = request.getRawUsername();
            char[] rawPassword = request.getPassword();
            String rawClientIp = request.getClientIp();

            // 1. Trust boundary: Validate all client-supplied inputs (Rule 1)
            String validatedUsername;
            String validatedClientIp;
            try {
                validatedUsername = InputValidator.validateUsername(rawUsername);
                InputValidator.validatePassword(rawPassword);
                validatedClientIp = InputValidator.validateClientIp(rawClientIp);
            } catch (ValidationException ve) {
                // Perform dummy cryptographic workload to equalize execution time (Rule 6)
                passwordHasher.performDummyVerification(rawPassword);

                eventLogger.logEvent(new AuthenticationEvent(Instant.now(),
                        AuthenticationEventType.LOGIN_FAILURE_INVALID_INPUT,
                        false,
                        rawUsername,
                        rawClientIp,
                        "",
                        "Input validation failed: " + ve.getMessage()));

                return AuthenticationResult.failure(AuthenticationErrorCode.INVALID_INPUT);
            }

            // 2. Enforce Rate Limiting per source and per account with atomic count-then-allow (Rule 3 & 7)
            RateLimitStatus rateLimitStatus = rateLimiter.acquireAttempt(validatedClientIp, validatedUsername);
            if (rateLimitStatus != RateLimitStatus.ALLOWED) {
                // Perform dummy cryptographic workload to prevent timing enumeration (Rule 6)
                passwordHasher.performDummyVerification(rawPassword);

                AuthenticationEventType eventType = (rateLimitStatus == RateLimitStatus.SOURCE_RATE_LIMITED)
                        ? AuthenticationEventType.LOGIN_FAILURE_RATE_LIMITED_SOURCE
                        : AuthenticationEventType.LOGIN_FAILURE_RATE_LIMITED_ACCOUNT;

                AuthenticationErrorCode errorCode = (rateLimitStatus == RateLimitStatus.SOURCE_RATE_LIMITED)
                        ? AuthenticationErrorCode.RATE_LIMITED_SOURCE
                        : AuthenticationErrorCode.RATE_LIMITED_ACCOUNT;

                eventLogger.logEvent(new AuthenticationEvent(Instant.now(),
                        eventType,
                        false,
                        validatedUsername,
                        validatedClientIp,
                        "",
                        "Authentication throttled due to rate limiting: " + rateLimitStatus.name()));

                return AuthenticationResult.failure(errorCode);
            }

            // 3. Verify against server-side state (Rule 1 & Rule 3)
            Optional<UserRecord> userRecordOpt = userRepository.findByUsername(validatedUsername);

            if (userRecordOpt.isEmpty()) {
                // User does not exist: run dummy verification so timing matches real verification (Rule 6)
                passwordHasher.performDummyVerification(rawPassword);

                eventLogger.logEvent(new AuthenticationEvent(Instant.now(),
                        AuthenticationEventType.LOGIN_FAILURE_USER_NOT_FOUND,
                        false,
                        validatedUsername,
                        validatedClientIp,
                        "",
                        "Authentication failed: user record not found in repository"));

                return AuthenticationResult.failure(AuthenticationErrorCode.USER_NOT_FOUND);
            }

            UserRecord userRecord = userRecordOpt.get();

            // 4. Verify account status (Rule 3)
            if (userRecord.getAccountStatus() != AccountStatus.ACTIVE) {
                passwordHasher.performDummyVerification(rawPassword);

                eventLogger.logEvent(new AuthenticationEvent(Instant.now(),
                        AuthenticationEventType.LOGIN_FAILURE_ACCOUNT_LOCKED,
                        false,
                        validatedUsername,
                        validatedClientIp,
                        "",
                        "Authentication rejected: account status is " + userRecord.getAccountStatus().name()));

                return AuthenticationResult.failure(AuthenticationErrorCode.ACCOUNT_LOCKED_OR_SUSPENDED);
            }

            // 5. Verify credentials in constant time (Rule 6)
            boolean passwordValid = passwordHasher.verifyPassword(rawPassword, userRecord);

            if (!passwordValid) {
                eventLogger.logEvent(new AuthenticationEvent(Instant.now(),
                        AuthenticationEventType.LOGIN_FAILURE_INVALID_CREDENTIALS,
                        false,
                        validatedUsername,
                        validatedClientIp,
                        "",
                        "Authentication failed: password verification failed"));

                return AuthenticationResult.failure(AuthenticationErrorCode.INVALID_CREDENTIALS);
            }

            // 6. Authentication SUCCESS
            rateLimiter.recordSuccess(validatedClientIp, validatedUsername);

            // Generate cryptographically secure session identifier (Rule 4)
            SessionToken sessionToken = tokenGenerator.generateToken(validatedUsername);

            // Record audit event with non-reversible token fingerprint (Rule 2, 4, 5)
            eventLogger.logEvent(new AuthenticationEvent(Instant.now(),
                    AuthenticationEventType.LOGIN_SUCCESS,
                    true,
                    validatedUsername,
                    validatedClientIp,
                    sessionToken.getAuditFingerprint(),
                    "Authentication successful; session token issued"));

            return AuthenticationResult.success(sessionToken);

        } catch (Exception ex) {
            // Fail closed on any unexpected exception (Rule 3 & 6)
            eventLogger.logEvent(new AuthenticationEvent(Instant.now(),
                    AuthenticationEventType.LOGIN_FAILURE_INTERNAL_ERROR,
                    false,
                    (request != null) ? request.getRawUsername() : "[UNKNOWN]",
                    (request != null) ? request.getClientIp() : "[UNKNOWN]",
                    "",
                    "Internal error during authentication: " + ex.getClass().getSimpleName()));

            return AuthenticationResult.failure(AuthenticationErrorCode.INTERNAL_ERROR);
        } finally {
            // Clear credentials from memory immediately after use (Rule 5)
            if (request != null) {
                request.clearCredentials();
            }
        }
    }
}
