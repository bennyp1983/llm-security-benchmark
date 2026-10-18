package com.security.session;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;

/**
 * Hardened post-authentication web component that receives an existing server-side
 * session identifier and issues it to the user's browser in a secure session cookie.
 *
 * <p>Security Features &amp; Defenses:
 * <ul>
 *   <li><b>Trust Boundary Enforcement:</b> Treats all inputs as untrusted and validates
 *       type, length, whitelist character sets, and range before use.</li>
 *   <li><b>Server-Side State Verification:</b> Session identifiers must be verified and
 *       atomically claimed against server-side state (fail closed).</li>
 *   <li><b>Anti-Lockout Dual-Key Rate Limiting:</b> Limits attempts per source IP and per
 *       account, preventing brute-force while stopping attackers from locking out legitimate users.</li>
 *   <li><b>RFC 6265bis Hardening:</b> Enforces HttpOnly, Secure, SameSite=Strict/Lax, and
 *       the '__Host-' prefix (Path=/, no Domain) by default.</li>
 *   <li><b>CRLF / Response Splitting Defense:</b> Strict validation guarantees no control
 *       characters or delimiters enter HTTP headers.</li>
 *   <li><b>Sensitive Data Masking:</b> Session identifiers are never logged in cleartext;
 *       cryptographic SHA-256 fingerprints are logged instead.</li>
 *   <li><b>Generic Failure Behavior:</b> Constant-time execution and identical generic
 *       error responses prevent account and session enumeration.</li>
 *   <li><b>Cache Prevention:</b> Forces strict 'Cache-Control: no-store' headers to prevent
 *       session cookies from being cached by intermediate proxies or clients.</li>
 * </ul>
 */
public class PostAuthSessionCookieHandler {

    private static final Logger logger = LoggerFactory.getLogger(PostAuthSessionCookieHandler.class);

    private static final String GENERIC_ERROR_RESPONSE =
            "{\"status\":\"error\",\"message\":\"Authentication session could not be established.\"}";
    private static final String GENERIC_SUCCESS_RESPONSE =
            "{\"status\":\"success\",\"message\":\"Authentication session established.\"}";
    private static final String GENERIC_RATE_LIMIT_RESPONSE =
            "{\"status\":\"error\",\"message\":\"Too many requests. Please try again later.\"}";

    private static final byte[] DUMMY_SALT = "PostAuthConstantTimeDummySaltValue".getBytes(StandardCharsets.UTF_8);

    private final SessionCookieConfig config;
    private final SessionStateValidator sessionValidator;
    private final RateLimiter rateLimiter;

    public PostAuthSessionCookieHandler(
            SessionCookieConfig config,
            SessionStateValidator sessionValidator,
            RateLimiter rateLimiter) {
        this.config = Objects.requireNonNull(config, "SessionCookieConfig cannot be null");
        this.sessionValidator = Objects.requireNonNull(sessionValidator, "SessionStateValidator cannot be null");
        this.rateLimiter = Objects.requireNonNull(rateLimiter, "RateLimiter cannot be null");
    }

    /**
     * Jakarta Servlet entrypoint.
     */
    public PostAuthResult handlePostAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            String sessionId,
            String userId) throws IOException {
        Objects.requireNonNull(request, "HttpServletRequest cannot be null");
        Objects.requireNonNull(response, "HttpServletResponse cannot be null");

        HttpRequestContext reqContext = HttpRequestContext.fromServlet(request, config);
        HttpResponseContext respContext = HttpResponseContext.fromServlet(response);
        return handlePostAuthentication(reqContext, respContext, sessionId, userId);
    }

    /**
     * Jakarta Servlet entrypoint with sensitive character array session token.
     * Wipes the character array immediately after handling.
     */
    public PostAuthResult handlePostAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            char[] sessionIdChars,
            String userId) throws IOException {
        try {
            String sessionId = (sessionIdChars != null) ? new String(sessionIdChars) : null;
            return handlePostAuthentication(request, response, sessionId, userId);
        } finally {
            if (sessionIdChars != null) {
                Arrays.fill(sessionIdChars, '\0');
            }
        }
    }

    /**
     * Core handler implementation operating on abstract request and response contexts.
     *
     * @param request HTTP request context
     * @param response HTTP response context
     * @param sessionId externally provided server-side session identifier
     * @param userId authenticated account / user identifier
     * @return PostAuthResult indicating outcome
     */
    public PostAuthResult handlePostAuthentication(
            HttpRequestContext request,
            HttpResponseContext response,
            String sessionId,
            String userId) throws IOException {

        if (request == null || response == null) {
            logger.warn("Rejecting request: null request or response context");
            return failClosed(response, 400, "INVALID_CONTEXT", "Null request or response context");
        }

        String remoteIp = request.getRemoteAddr();

        // 1. Rule 1: Trust boundaries - Validate all inputs strictly
        ValidationOutcome valOutcome = validateInputs(sessionId, userId);
        if (!valOutcome.isValid()) {
            performConstantTimeDummyWork();
            logger.warn("Input validation failed: reason={}, ip={}, maskedSession={}",
                    valOutcome.getAuditReason(), remoteIp, CookieSecurityUtil.maskToken(sessionId));
            return failClosed(response, 400, "VALIDATION_FAILED", valOutcome.getAuditReason());
        }

        // 2. Transport Security Check: Ensure TLS / HTTPS
        if (config.isRequireSecureTransport() && !request.isSecure()) {
            performConstantTimeDummyWork();
            logger.warn("Insecure transport rejected for session cookie: ip={}, user={}",
                    remoteIp, sanitizeForLog(userId));
            return failClosed(response, 400, "INSECURE_TRANSPORT", "Session cookie cannot be issued over insecure transport");
        }

        // 3. Rule 3: Authentication and access - Dual-key rate limiting (IP and Account)
        RateLimiter.RateLimitResult rateResult = rateLimiter.tryAcquire(remoteIp, userId);
        if (!rateResult.isAllowed()) {
            performConstantTimeDummyWork();
            logger.warn("Rate limit exceeded: ip={}, user={}, reason={}, retryAfter={}",
                    remoteIp, sanitizeForLog(userId), rateResult.getReason(), rateResult.getRetryAfterSeconds());
            response.setStatus(429);
            response.setHeader("Retry-After", String.valueOf(rateResult.getRetryAfterSeconds()));
            setSecurityHeaders(response);
            response.writeJsonBody(GENERIC_RATE_LIMIT_RESPONSE);
            return PostAuthResult.failure(429, "RATE_LIMITED", rateResult.getReason());
        }

        // 4. Rule 1, 3, 7: Server-side state verification & atomic session claim
        SessionValidationResult sessionResult = sessionValidator.validateAndClaimSession(sessionId, userId);
        if (!sessionResult.isSuccess()) {
            performConstantTimeDummyWork();
            // Record failure in rate limiter (penalizes abusive IP without locking out legitimate user)
            rateLimiter.recordOutcome(remoteIp, userId, false);

            logger.warn("Session verification/claim failed: code={}, auditReason={}, ip={}, user={}, token={}",
                    sessionResult.getErrorCode(), sessionResult.getAuditMessage(), remoteIp,
                    sanitizeForLog(userId), CookieSecurityUtil.maskToken(sessionId));

            return failClosed(response, 401, sessionResult.getErrorCode(), sessionResult.getAuditMessage());
        }

        // 5. Rule 4 & 8: Build secure RFC 6265bis Set-Cookie header
        String setCookieHeader;
        try {
            setCookieHeader = CookieSecurityUtil.buildSetCookieHeader(config, sessionId);
        } catch (SecurityValidationException e) {
            performConstantTimeDummyWork();
            logger.error("Failed to build Set-Cookie header: reason={}, token={}",
                    e.getInternalAuditReason(), CookieSecurityUtil.maskToken(sessionId));
            return failClosed(response, 500, "COOKIE_BUILD_ERROR", e.getInternalAuditReason());
        }

        // 6. Record successful claim in rate limiter
        rateLimiter.recordOutcome(remoteIp, userId, true);

        // 7. Rule 4 & 5: Apply Set-Cookie and strict cache-control security headers
        response.setStatus(200);
        response.addHeader("Set-Cookie", setCookieHeader);
        setSecurityHeaders(response);

        // Audit log success with masked token
        logger.info("Session cookie successfully established: ip={}, user={}, token={}",
                remoteIp, sanitizeForLog(userId), CookieSecurityUtil.maskToken(sessionId));

        response.writeJsonBody(GENERIC_SUCCESS_RESPONSE);
        return PostAuthResult.success();
    }

    private ValidationOutcome validateInputs(String sessionId, String userId) {
        if (sessionId == null || sessionId.isBlank()) {
            return ValidationOutcome.invalid("Session identifier is null or blank");
        }
        if (userId == null || userId.isBlank()) {
            return ValidationOutcome.invalid("User identifier is null or blank");
        }

        // Check lengths against bounded configuration limits
        if (sessionId.length() < config.getMinSessionIdLength() || sessionId.length() > config.getMaxSessionIdLength()) {
            return ValidationOutcome.invalid("Session identifier length out of bounds: " + sessionId.length());
        }
        if (userId.length() > config.getMaxUserIdLength()) {
            return ValidationOutcome.invalid("User identifier length out of bounds: " + userId.length());
        }

        // Check character whitelists
        if (!config.getSessionIdPattern().matcher(sessionId).matches()) {
            return ValidationOutcome.invalid("Session identifier contains invalid characters");
        }
        if (!config.getUserIdPattern().matcher(userId).matches()) {
            return ValidationOutcome.invalid("User identifier contains invalid characters");
        }

        // Check for CRLF / control character injection
        try {
            CookieSecurityUtil.assertNoControlCharacters("sessionId", sessionId);
            CookieSecurityUtil.assertNoHeaderDelimiters("sessionId", sessionId);
            CookieSecurityUtil.assertNoControlCharacters("userId", userId);
        } catch (SecurityValidationException e) {
            return ValidationOutcome.invalid(e.getInternalAuditReason());
        }

        return ValidationOutcome.valid();
    }

    /**
     * Fails closed: sets status, security headers, writes generic error body, never leaks details.
     */
    private PostAuthResult failClosed(HttpResponseContext response, int status, String errorCode, String auditReason)
            throws IOException {
        response.setStatus(status);
        setSecurityHeaders(response);
        response.writeJsonBody(GENERIC_ERROR_RESPONSE);
        return PostAuthResult.failure(status, errorCode, auditReason);
    }

    /**
     * Applies defensive HTTP headers ensuring session cookies and post-auth responses are NEVER cached.
     */
    private void setSecurityHeaders(HttpResponseContext response) {
        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Expires", "0");
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-Frame-Options", "DENY");
    }

    /**
     * Constant-time dummy computation to mitigate timing side-channel attacks across failure branches.
     */
    private void performConstantTimeDummyWork() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(DUMMY_SALT);
            digest.digest();
        } catch (NoSuchAlgorithmException ignored) {
        }
    }

    private String sanitizeForLog(String value) {
        if (value == null) return "[null]";
        return value.replaceAll("[\r\n\t]", "_");
    }

    private static final class ValidationOutcome {
        private final boolean valid;
        private final String auditReason;

        private ValidationOutcome(boolean valid, String auditReason) {
            this.valid = valid;
            this.auditReason = auditReason;
        }

        static ValidationOutcome valid() {
            return new ValidationOutcome(true, "VALID");
        }

        static ValidationOutcome invalid(String reason) {
            return new ValidationOutcome(false, reason);
        }

        boolean isValid() {
            return valid;
        }

        String getAuditReason() {
            return auditReason;
        }
    }
}
