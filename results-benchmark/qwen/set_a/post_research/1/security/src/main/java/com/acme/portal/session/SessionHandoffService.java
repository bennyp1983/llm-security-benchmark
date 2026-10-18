package com.acme.portal.session;

/**
 * The security decision of this component, with no servlet types in it: given what the trusted
 * session owner asserted and what the client sent, may a session cookie be issued?
 *
 * <p>Deliberately free of container and I/O dependencies, so the decision can be exercised directly
 * in tests and the HTTP layer stays a thin adapter that is safe to replace.
 */
public final class SessionHandoffService {

    /** Result of one handoff attempt. */
    public enum Outcome {
        /** A session cookie may be issued; see {@link Decision#sessionIdentifier()}. */
        ISSUED,
        /** The assertion was absent or malformed; nothing was looked up and no allowance consumed. */
        REFUSED_INVALID_ASSERTION,
        /** The identifier is well-formed but not confirmed by the authoritative session store. */
        REFUSED_UNAUTHENTICATED,
        /** This source used up its window allowance. */
        LIMITED_SOURCE,
        /** The shared lane is saturated; this source's own allowance is untouched. */
        LIMITED_GLOBAL,
        /** Too many distinct sources to track; shedding load. */
        LIMITED_TRACKING,
        /** The component is not serving. */
        REFUSED_UNAVAILABLE
    }

    /** The answer, with no session material in its {@code toString()}. */
    public static final class Decision {
        private final Outcome outcome;
        private final SessionId sessionId;
        private final int retryAfterSeconds;
        private final SessionId.Rejection rejection;

        private Decision(Outcome outcome, SessionId sessionId, int retryAfterSeconds) {
            this(outcome, sessionId, retryAfterSeconds, SessionId.Rejection.NONE);
        }

        private Decision(Outcome outcome, SessionId sessionId, int retryAfterSeconds,
                         SessionId.Rejection rejection) {
            this.outcome = outcome;
            this.sessionId = sessionId;
            this.retryAfterSeconds = retryAfterSeconds;
            // A name from a fixed enum, never the value: this is the one detail the caller may log
            // about a rejected assertion, and it is why the reason is carried at all.
            this.rejection = rejection == null ? SessionId.Rejection.NONE : rejection;
        }

        public Outcome outcome() {
            return outcome;
        }

        /**
         * Which validation rule rejected the asserted identifier. Package private on purpose: it
         * exists so the HTTP adapter can write a diagnosable log line, not so an outsider can
         * enumerate why assertions fail. Everything the client can observe stays one generic 403
         * either way (rule 6), so this trades nothing for the operator's ability to tell "the
         * authenticator asserted nothing" apart from "the assertion was 31 characters".
         */
        SessionId.Rejection rejectionReason() {
            return rejection;
        }

        /**
         * The validated identifier to place in the cookie. Non-null only for
         * {@link Outcome#ISSUED}, which is what lets the caller write a cookie without repeating
         * this class's checks.
         */
        public SessionId sessionIdentifier() {
            return sessionId;
        }

        /** Positive for the limited outcomes, zero otherwise; feeds {@code Retry-After}. */
        public int retryAfterSeconds() {
            return retryAfterSeconds;
        }

        /** Names the outcome only: no identifier, no address, no cause message. */
        @Override
        public String toString() {
            return "Decision[" + outcome + "]";
        }
    }

    /**
     * The side channel the trusted session owner must implement.
     *
     * <p>This is what rule 3 means by "verified against server-side state": the component never
     * accepts a session from a request, and never treats an assertion as proof without asking the
     * stateful owner. Implementations should return {@code false} rather than throw for "no"; a throw
     * is still handled as "no" below.
     */
    public interface SessionStateVerifier {
        boolean isSessionValid(String sessionId);
    }

    /** A verifier that confirms nothing, so a missing integration fails closed. */
    public static final SessionStateVerifier DENY_ALL = new SessionStateVerifier() {
        @Override
        public boolean isSessionValid(String sessionId) {
            return false;
        }
    };

    /** Where the assertion comes from. Everything here is attacker-influenced until validated. */
    public static final class Request {
        private final String assertedSessionId;
        private final ClientAddress source;

        public Request(String assertedSessionId, ClientAddress source) {
            this.assertedSessionId = assertedSessionId;
            this.source = source;
        }
    }

    private final SessionCookiePolicy policy;
    private final SessionStateVerifier verifier;
    private final AttemptLimiter limiter;

    public SessionHandoffService(SessionCookiePolicy policy, SessionStateVerifier verifier,
                                 AttemptLimiter limiter) {
        if (policy == null || limiter == null) {
            throw new IllegalArgumentException("cookie policy and limiter are required");
        }
        // A null verifier is not "no verification needed", it is "nothing can be verified", so the
        // only safe behaviour is to refuse every handoff. Failing open here would mean issuing a
        // session cookie for any string a client could invent.
        this.policy = policy;
        this.verifier = verifier == null ? DENY_ALL : verifier;
        this.limiter = limiter;
    }

    /**
     * Ordered so that no cheap unauthenticated check can be used to probe, and no failure path can
     * reach a cookie write.
     *
     * <ol>
     *   <li><b>Validate the asserted identifier.</b> Cheap, no I/O, and it guarantees a malformed
     *       string is never handed to another subsystem as though it were a lookup key.</li>
     *   <li><b>Consume rate-limit allowance.</b> Only well-formed requests pay for it, so an attacker
     *       cannot exhaust a victim's allowance by sending garbage; and the session-store lookup below
     *       sits behind this gate, which is what stops the verifier being used as an amplifier. Two
     *       limits on that claim, stated rather than glossed: an attempt the store then refuses has
     *       still consumed its allowance, because it was a real authentication attempt and making
     *       those free would hand an attacker free probing; and the fixed timing padding charged by
     *       the HTTP adapter runs <i>before</i> this gate, so what this gate sheds is the store round
     *       trip and the cookie write, not every byte of work a request costs.</li>
     *   <li><b>Verify against server-side state.</b> The only step that can authorise a cookie.</li>
     * </ol>
     */
    public Decision handle(Request request) {
        if (request == null) {
            return new Decision(Outcome.REFUSED_UNAVAILABLE, null, 0);
        }
        ClientAddress source = request.source == null ? ClientAddress.UNKNOWN : request.source;

        SessionId sessionId;
        try {
            sessionId = SessionId.fromTrustedComponent(request.assertedSessionId);
        } catch (InvalidSessionIdentifierException rejected) {
            // The reason class is loggable; the value is not. Logging is the caller's job and is
            // deliberately not done here, so a log level cannot become a disclosure path. The reason
            // travels with the decision because "the authenticator asserted nothing" and "the
            // authenticator asserted a 31-character string" are different bugs to fix, and the
            // response the client sees is identical for both either way.
            return new Decision(Outcome.REFUSED_INVALID_ASSERTION, null, 0, rejected.rejection());
        }

        AttemptLimiter.Decision budget = limiter.tryAcquire(source);
        if (budget == AttemptLimiter.Decision.LIMITED_PER_SOURCE) {
            return new Decision(Outcome.LIMITED_SOURCE, null, limiter.retryAfterSeconds(source));
        }
        if (budget == AttemptLimiter.Decision.LIMITED_GLOBALLY) {
            return new Decision(Outcome.LIMITED_GLOBAL, null, limiter.retryAfterSeconds(source));
        }
        if (budget == AttemptLimiter.Decision.LIMITED_TRACKING_SATURATED) {
            return new Decision(Outcome.LIMITED_TRACKING, null, limiter.retryAfterSeconds(source));
        }

        boolean valid;
        try {
            valid = verifier.isSessionValid(sessionId.value());
        } catch (RuntimeException verifierFailed) {
            // A verifier that cannot answer did not confirm anything. Treat it as "no", and let the
            // caller log only the exception type: a cause message from a datastore can carry a
            // connection string, and this component must not put one on the console.
            valid = false;
        }
        if (!valid) {
            return new Decision(Outcome.REFUSED_UNAUTHENTICATED, null, 0);
        }
        return new Decision(Outcome.ISSUED, sessionId, 0);
    }

    /** The policy in force, for startup logging. */
    public SessionCookiePolicy policy() {
        return policy;
    }

    /** Configuration summary; contains no secret and no client address. */
    @Override
    public String toString() {
        return "SessionHandoffService[" + policy + ", " + limiter + "]";
    }
}
