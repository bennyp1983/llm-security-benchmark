package com.example.security.session;

/**
 * Security boundary between cookie delivery and the authoritative session store.
 *
 * <p>The implementation belongs to the trusted session component. The entire operation MUST be
 * one atomic transaction (or one linearizable store operation): apply the source rate limit, look
 * up the session, verify that it is authenticated/active/cookie-eligible, apply the owning
 * account's rate limit, consume its one-time cookie-issuance eligibility, and return the decision.
 * A failed operation must change no session into an authorized state.</p>
 *
 * <p>When {@code candidateWasWellFormed} is false, {@code lookupId} is a fixed dummy value. The
 * implementation must perform comparable lookup/KDF work against a reserved dummy record and
 * apply the source limiter. Unknown, expired, already-consumed, throttled, and unauthorized
 * sessions must all return {@link Decision#DENY}. Rate-limit counters must be bounded and expire;
 * account policy must use short backoff rather than a durable account lockout.</p>
 */
@FunctionalInterface
public interface SessionHandoffStore {
    enum Decision { AUTHORIZE, DENY }

    Decision authorizeAndConsume(String lookupId, boolean candidateWasWellFormed, String sourceKey);
}
