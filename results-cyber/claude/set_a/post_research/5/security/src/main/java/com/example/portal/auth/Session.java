package com.example.portal.auth;

import java.time.Instant;

/**
 * Server-side record of an established session.
 *
 * <p>The session token itself is deliberately absent from this object: the manager stores only a
 * digest of it, so neither this record nor the session table reveals a usable credential.
 *
 * @param username  the authenticated account this session belongs to
 * @param reference a short non-secret handle derived from the token digest, safe to show a user or
 *                  write to a log when correlating a support call with an audit entry
 * @param createdAt when the session was established
 * @param expiresAt the absolute expiry, beyond which the session is invalid regardless of activity
 */
public record Session(String username, String reference, Instant createdAt, Instant expiresAt) {

    /** Never renders anything that could stand in for the token. */
    @Override
    public String toString() {
        return "Session[reference=" + reference + ", expiresAt=" + expiresAt + "]";
    }
}
