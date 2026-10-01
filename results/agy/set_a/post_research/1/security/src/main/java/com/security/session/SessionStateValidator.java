package com.security.session;

/**
 * Service Provider Interface (SPI) for validating session identifiers against
 * trusted server-side state and atomically binding/claiming the session.
 */
public interface SessionStateValidator {

    /**
     * Atomically validates that the session exists, is currently active, belongs
     * to the specified userId, is not expired, and marks the session as claimed
     * so that it cannot be claimed or fixated again.
     *
     * @param sessionId the externally provided server-side session identifier
     * @param userId the authenticated user claiming the session
     * @return validation result indicating success or failure reason
     */
    SessionValidationResult validateAndClaimSession(String sessionId, String userId);
}
