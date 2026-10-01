package com.example.websession;

import java.util.Optional;

/**
 * The seam to the trusted component that owns authentication and server-side sessions.
 *
 * <p>This component calls it to answer one question against authoritative server-side
 * state: <em>is this identifier a live session right now?</em> The answer is what decides
 * whether a cookie is emitted; nothing the client sends is allowed to influence it.</p>
 *
 * <p>Implementations must:</p>
 * <ul>
 *   <li>return {@link Optional#empty()} for unknown, expired, revoked, or logged-out
 *       identifiers -- never a partially populated record, and never throw a different
 *       exception type for "unknown" than for "expired", since this component's caller
 *       must not be able to distinguish those cases;</li>
 *   <li>compare identifiers in a way that does not leak them (indexed lookup on a hash of
 *       the identifier is preferred to storing the identifier itself);</li>
 *   <li>be safe for concurrent use and observe the session's state atomically, so a
 *       session revoked concurrently is never reported as live after the fact.</li>
 * </ul>
 */
@FunctionalInterface
public interface TrustedSessionService {

    /**
     * @param sessionId a syntactically validated session identifier
     * @return the live session, or empty if the identifier is not currently valid
     */
    Optional<TrustedSession> lookupActiveSession(String sessionId);
}
