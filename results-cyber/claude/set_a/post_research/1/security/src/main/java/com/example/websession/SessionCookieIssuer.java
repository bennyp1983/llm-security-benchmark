package com.example.websession;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Clock;
import java.util.Objects;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Hands an already-created server-side session identifier to the browser in a cookie.
 *
 * <p>Where the identifier comes from is the security-critical part of this class. It is
 * read from a <strong>request attribute</strong> set by the upstream trusted authentication
 * component. Request attributes live only in server memory for the life of one request and
 * cannot be set by a client through any header, parameter, body, or cookie. The component
 * deliberately exposes no path that accepts an identifier from the request itself: that is
 * what makes session fixation structurally impossible here rather than merely checked for.
 * Even so, the attribute is validated for shape and then checked against authoritative
 * server-side state before any cookie is emitted -- a request attribute is still an input,
 * and an upstream bug must not become a forged session.</p>
 *
 * <p>Instances are thread-safe and intended to be shared; the rate limiters are the only
 * mutable state and are internally synchronised.</p>
 */
public final class SessionCookieIssuer implements AutoCloseable {

    /** Request attribute the trusted authentication component sets. Server-side only. */
    public static final String SESSION_ID_ATTRIBUTE = "com.example.websession.SESSION_ID";

    private static final String ISSUED_MARKER_ATTRIBUTE = "com.example.websession.COOKIE_ISSUED";
    private static final long WINDOW_MILLIS = 60_000L;

    private static final Logger LOG = LoggerFactory.getLogger(SessionCookieIssuer.class);

    private final SessionCookieSettings settings;
    private final TrustedSessionService sessionService;
    private final ClientAddressResolver addressResolver;
    private final FixedWindowRateLimiter perAddressLimiter;
    private final FixedWindowRateLimiter perSubjectLimiter;
    private final LogFingerprint fingerprint;
    private final Clock clock;

    public SessionCookieIssuer(SessionCookieSettings settings, TrustedSessionService sessionService) {
        this(settings, sessionService, Clock.systemUTC());
    }

    public SessionCookieIssuer(SessionCookieSettings settings,
                               TrustedSessionService sessionService,
                               Clock clock) {
        this.settings = Objects.requireNonNull(settings, "settings");
        this.sessionService = Objects.requireNonNull(sessionService, "sessionService");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.addressResolver = new ClientAddressResolver(settings.trustedProxyCount());
        // Two independent budgets. A per-subject budget alone would let an attacker who
        // knows a victim's identity exhaust that budget and lock the victim out; a per-source
        // budget alone would let a distributed attacker hammer one account. Because they are
        // separate counters, exhausting one never consumes the other.
        this.perAddressLimiter = new FixedWindowRateLimiter(
                settings.maxIssuesPerIpPerMinute(), WINDOW_MILLIS, settings.maxTrackedRateLimitKeys());
        this.perSubjectLimiter = new FixedWindowRateLimiter(
                settings.maxIssuesPerSubjectPerMinute(), WINDOW_MILLIS, settings.maxTrackedRateLimitKeys());
        this.fingerprint = new LogFingerprint();
    }

    /**
     * Validates the pending session and, if everything checks out, writes the session cookie
     * and the accompanying response hardening headers.
     *
     * <p>This method never writes a status code or a body -- the servlet translates the
     * returned {@link IssueOutcome} into one of a fixed set of generic responses. Keeping
     * the two apart means an outcome can never be reported as success while the cookie was
     * not actually written.</p>
     */
    public IssueOutcome issue(HttpServletRequest request, HttpServletResponse response) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(response, "response");
        long now = clock.millis();

        if (response.isCommitted()) {
            LOG.warn("Session cookie not issued: response already committed");
            return IssueOutcome.UNAVAILABLE;
        }
        if (settings.secure() && !request.isSecure()) {
            // A Secure cookie sent over cleartext is dropped by the browser, and the
            // identifier would have travelled in the clear to get there. Refuse instead.
            LOG.warn("Session cookie not issued: Secure cookies configured but request is not over TLS");
            return IssueOutcome.UNAVAILABLE;
        }
        if (request.getAttribute(ISSUED_MARKER_ATTRIBUTE) != null) {
            LOG.warn("Session cookie not issued: a cookie was already issued for this request");
            return IssueOutcome.UNAVAILABLE;
        }

        String clientAddress = addressResolver.resolve(request);
        if (!perAddressLimiter.tryAcquire("a|" + clientAddress, now)) {
            LOG.warn("Session cookie issuance throttled for source {}", fingerprint.of(clientAddress));
            return IssueOutcome.RATE_LIMITED;
        }

        String sessionId = request.getAttribute(SESSION_ID_ATTRIBUTE) instanceof String s ? s : null;
        boolean wellFormed = SessionIdValidator.isValid(sessionId);

        Optional<TrustedSession> session;
        try {
            session = wellFormed ? lookup(sessionId) : Optional.empty();
        } catch (RuntimeException e) {
            // Log the type and stack trace, never the identifier.
            LOG.error("Session lookup failed for session {}", fingerprint.of(sessionId), e);
            return IssueOutcome.UNAVAILABLE;
        }

        // The subject budget is charged on every attempt that got this far, including the
        // ones that found nothing, using a source-derived placeholder key. Both branches do
        // one fingerprint and one atomic map update, so the time taken and the state touched
        // do not reveal whether the identifier was real.
        String subjectKey = session.map(TrustedSession::subjectKey).orElse("anon|" + clientAddress);
        boolean withinSubjectBudget = perSubjectLimiter.tryAcquire("s|" + fingerprint.of(subjectKey), now);

        if (session.isEmpty() || !withinSubjectBudget) {
            LOG.info("Session cookie refused for source {} (session {})",
                    fingerprint.of(clientAddress), fingerprint.of(sessionId));
            return IssueOutcome.REJECTED;
        }

        long maxAge = effectiveMaxAge(session.get().remainingLifetimeSeconds());
        String header = SetCookieHeaderFactory.issue(settings, sessionId, maxAge);

        applyResponseHardening(response);
        response.addHeader("Set-Cookie", header);
        request.setAttribute(ISSUED_MARKER_ATTRIBUTE, Boolean.TRUE);

        LOG.info("Session cookie issued for subject {} (session {}, maxAge={}s)",
                fingerprint.of(session.get().subjectKey()), fingerprint.of(sessionId), maxAge);
        return IssueOutcome.ISSUED;
    }

    /**
     * Writes a header that deletes the session cookie, for use by the logout endpoint after
     * the trusted component has invalidated the session server-side. Clearing the cookie is
     * cosmetic on its own -- a copy already taken by an attacker is unaffected -- so it must
     * never be the only step in a logout.
     */
    public void expireSessionCookie(HttpServletResponse response) {
        Objects.requireNonNull(response, "response");
        if (response.isCommitted()) {
            LOG.warn("Session cookie not cleared: response already committed");
            return;
        }
        applyResponseHardening(response);
        response.addHeader("Set-Cookie", SetCookieHeaderFactory.expire(settings));
    }

    private Optional<TrustedSession> lookup(String sessionId) {
        Optional<TrustedSession> found = sessionService.lookupActiveSession(sessionId);
        return found == null ? Optional.empty() : found;
    }

    /**
     * The cookie must never outlive the server-side session: a browser holding a cookie for
     * a session the server has already dropped produces confusing failures and widens the
     * window in which a stolen cookie looks useful.
     */
    private long effectiveMaxAge(long remainingLifetimeSeconds) {
        if (settings.maxAgeSeconds() == 0) {
            return 0; // browser-session cookie, discarded when the browser closes
        }
        return Math.min(settings.maxAgeSeconds(), remainingLifetimeSeconds);
    }

    private static void applyResponseHardening(HttpServletResponse response) {
        // A Set-Cookie carrying a session identifier must never be stored by a shared cache
        // and handed to the next user of that cache.
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Expires", "0");
        response.addHeader("Vary", "Cookie");
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("Referrer-Policy", "same-origin");
    }

    /** Releases the log-masking key. */
    @Override
    public void close() {
        fingerprint.close();
    }
}
