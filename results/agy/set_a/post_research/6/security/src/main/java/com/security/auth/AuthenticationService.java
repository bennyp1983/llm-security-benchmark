package com.security.auth;

/**
 * Core interface for the user-authentication component.
 * Processes login attempts and records authentication activity in an application log.
 */
public interface AuthenticationService {

    /**
     * Processes a username and password login attempt.
     * Enforces strict trust boundaries, rate-limiting, timing protection,
     * generic failure responses, and secure audit logging.
     *
     * @param request the authentication request containing credentials and client metadata
     * @return AuthenticationResult indicating success or generic failure
     */
    AuthenticationResult authenticate(AuthenticationRequest request);
}
