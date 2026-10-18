package com.example.auth;

import java.time.Instant;

/**
 * Server-side state for one authenticated session.
 *
 * @param identifier the cookie value that names this session
 * @param user the principal that authenticated
 * @param authenticatedAt when authentication succeeded and this identifier was minted
 * @param expiresAt absolute deadline; the session is refused after it regardless of what the cookie
 *     still says, because the cookie's {@code Max-Age} is only advisory to the browser
 */
record AuthenticatedSession(SessionIdentifier identifier, SessionUser user,
                            Instant authenticatedAt, Instant expiresAt) {

    boolean isLive(Instant now) {
        return now.isBefore(expiresAt);
    }
}
