package com.acme.portal.session;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.logging.Level;
import java.util.logging.Logger;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * HTTP adapter for the session-handoff decision.
 *
 * <p><b>It never creates, reads or invalidates a servlet session.</b> No call to
 * {@code getRequestSession} appears in this class, deliberately: a container session would be a
 * second, parallel session mechanism with its own {@code Set-Cookie} and its own cookie name, and the
 * whole point of this component is to emit exactly one session cookie whose attributes it controls.
 * The identifier it issues comes from the trusted component's own store.
 *
 * <p><b>Inputs, all treated as attacker-controlled.</b> The method, the request URI, the source
 * address and {@code If-None-Match} come from the client. The asserted session identifier comes from
 * server-side code upstream in this JVM, and is <i>still</i> validated and re-checked against the
 * authoritative store, because a filter ordering mistake or a compromised upstream must not be able
 * to mint a cookie from a client-chosen string. Cookies, query parameters, body fields and every
 * {@code *-For} header are never read.
 *
 * <p><b>Response shape.</b> Exactly two bodies, both constant. Two status families: a refusal that
 * is an authentication outcome (403) and a refusal that is availability (429/503), which is the
 * smallest distinction that stays honest -- a 403 says "no session was issued to you", which is true
 * and observable from the missing cookie anyway, and never says why.
 *
 * <p>Servlet 6.0 has no {@code SC_TOO_MANY_REQUESTS} constant (it arrived in 6.1), hence the local
 * one.
 */
public final class SessionHandoffServlet extends jakarta.servlet.http.HttpServlet {

    private static final long serialVersionUID = 1L;

    /** Added in Servlet 6.1; declared here so this compiles and runs on 6.0. */
    static final int SC_TOO_MANY_REQUESTS = 429;
    /** Not in the Servlet API constants either. */
    static final int SC_NOT_IMPLEMENTED = 501;

    private static final Logger LOG = Logger.getLogger(SessionHandoffServlet.class.getName());

    /**
     * Collaborators, written by the container's {@code init()} thread and read by every request
     * thread afterwards.
     *
     * <p>All four are {@code volatile}, and {@link #serving} is written <i>last</i> in
     * {@link #configure} and {@code serveNothing()}. That pairing is the point: a request thread that
     * observes {@code serving == true} performs an acquire read of the same field the wiring thread
     * released, so it must also see the three references written before it, and one that observes
     * {@code false} never reads them at all. Without it the container's "init finished before service
     * ran" ordering is a spec promise rather than a happens-before this class can rely on: a worker
     * could see {@code serving == true} next to a {@code null} collaborator, and the NPE that follows
     * is caught and answered as a 503 -- a refusal, so nothing unsafe escapes, but a self-inflicted
     * outage during the first requests after a deploy, which is exactly when an operator is watching.
     * Rule 7 asks for check-and-act atomicity; for a wire-once/read-many object that is visibility,
     * not locking, and volatile gets it without a monitor on the hot path.
     */
    private transient volatile SessionHandoffService service;
    private transient volatile SessionCookieWriter cookieWriter;
    private transient volatile TrustedSessionAssertionSource assertionSource;
    private transient volatile boolean serving;

    /**
     * Wires the component from validated environment settings and the session verifier the
     * application contributes through {@link SessionStateVerifierProvider}.
     *
     * <p>Fail-closed by construction: invalid settings, an absent verifier or unsafe deployment
     * hygiene leave the servlet refusing every request with 503. A servlet that cannot verify a
     * session must never fall back to "assume the authenticator was right".
     */
    @Override
    public void init() {
        SessionHandoffSettings settings;
        try {
            settings = SessionHandoffSettings.fromEnvironment();
        } catch (IllegalArgumentException badSettings) {
            // The message names a setting and a violated bound, never a value read from the
            // environment, so it is safe to log.
            LOG.log(Level.SEVERE, "session handoff is not serving: {0}", badSettings.getMessage());
            serveNothing();
            return;
        }
        String hygieneProblem;
        try {
            // Checked before anything is discovered: this component is about to load a class it does
            // not own, so its own code base and the classpath must already be proven read-only.
            hygieneProblem = DeploymentHygiene.describeProblem(SessionHandoffServlet.class);
        } catch (RuntimeException hygieneCheckFailed) {
            hygieneProblem = "the deployment hygiene check failed: "
                    + hygieneCheckFailed.getClass().getName();
        }
        if (hygieneProblem != null) {
            LOG.log(Level.SEVERE, "session handoff is not serving: {0}", hygieneProblem);
            serveNothing();
            return;
        }
        SessionHandoffService.SessionStateVerifier verifier;
        try {
            verifier = SessionStateVerifierProvider.load();
        } catch (RuntimeException providerFailed) {
            LOG.log(Level.SEVERE, "session handoff is not serving: the session verifier could not be"
                    + " loaded, exceptionType={0}", providerFailed.getClass().getName());
            serveNothing();
            return;
        }
        if (verifier == null) {
            LOG.log(Level.SEVERE, "session handoff is not serving: no session verifier is deployed");
            serveNothing();
            return;
        }
        try {
            // Re-checked with the verifier's own code base in scope, because that class is the
            // authority on whether a session exists.
            hygieneProblem = DeploymentHygiene.describeProblem(SessionHandoffServlet.class, verifier.getClass());
        } catch (RuntimeException hygieneCheckFailed) {
            hygieneProblem = "the deployment hygiene check failed: "
                    + hygieneCheckFailed.getClass().getName();
        }
        if (hygieneProblem != null) {
            LOG.log(Level.SEVERE, "session handoff is not serving: {0}", hygieneProblem);
            serveNothing();
            return;
        }
        SessionCookieWriter writer = new SessionCookieWriter(settings.cookiePolicy());
        configure(new SessionHandoffService(settings.cookiePolicy(), verifier, settings.limiter()),
                writer, new RequestAttributeAssertionSource(settings.assertionAttribute()));
    }

    private void serveNothing() {
        this.service = null;
        this.cookieWriter = null;
        this.assertionSource = null;
        this.serving = false;
    }

    /**
     * Wires the component explicitly. Every argument is required: a partially wired servlet would be
     * an unauthenticated cookie issuer, so a null here means "do not serve" rather than "do less
     * checking".
     */
    public void configure(SessionHandoffService service, SessionCookieWriter cookieWriter,
                          TrustedSessionAssertionSource assertionSource) {
        boolean complete = service != null && cookieWriter != null && assertionSource != null;
        if (!complete) {
            serveNothing();
            LOG.log(Level.SEVERE, "session handoff is not serving: required collaborators are missing");
            return;
        }
        this.service = service;
        this.cookieWriter = cookieWriter;
        this.assertionSource = assertionSource;
        this.serving = true;
        // Policy and limits only. No identifier, no address, no secret.
        LOG.log(Level.INFO, "session handoff ready: {0} wired with {1}",
                new Object[]{service, cookieWriter.policy()});
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        handle(request, response, true);
    }

    @Override
    protected void doHead(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // HEAD takes the same decision path, the same status codes, the same headers and the same
        // fixed work as GET, and writes no body. It is deliberately not a cheaper or freer request: it
        // consumes rate-limit allowance and asks the session store its question, because answering it
        // anywhere earlier would create exactly the cheap probe of session existence that GET is not
        // allowed to be.
        //
        // What it does not do is issue a cookie. A HEAD response body is discarded by definition, so a
        // credential handed to one cannot be used by the client that asked for it, while remaining
        // perfectly visible to the prefetchers, link scanners and proxies that send HEADs and log
        // them. A scanner would also consume a real user's allowance on requests that can never carry
        // the credential away. The 200 that answers a successful HEAD is not a credential and not a
        // quiet channel either: it can only be elicited by a request the authenticator has already
        // asserted a session for, it travels only to the client that made it, and it is logged with
        // the session fingerprint like any other grant.
        handle(request, response, false);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        refuseMethod(response);
    }

    @Override
    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        refuseMethod(response);
    }

    @Override
    protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws IOException {
        refuseMethod(response);
    }

    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response) throws IOException {
        refuseMethod(response);
    }

    @Override
    protected void doTrace(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // TRACE is disabled outright: it echoes request headers back to the caller, which is how
        // cross-site tracing reads a session cookie.
        response.setStatus(SC_NOT_IMPLEMENTED);
        response.setHeader("Allow", "GET, HEAD");
    }

    private void refuseMethod(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        response.setHeader("Allow", "GET, HEAD");
        response.setHeader("Cache-Control", "no-store");
        // No body: the status is the whole answer, and a body would need an escaping decision.
        response.flushBuffer();
    }

    /**
     * The single decision path. {@code writeBody} is false for HEAD.
     *
     * <p>Every header is set before the first body byte, and the body is written last, because a
     * servlet container silently discards headers set afterwards -- a dropped {@code Set-Cookie} or
     * {@code Retry-After} would be invisible.
     */
    private void handle(HttpServletRequest request, HttpServletResponse response, boolean writeBody)
            throws IOException {
        if (response == null) {
            return;
        }
        // Applied once, on every request, before the decision is taken -- including the requests the
        // throttle and the availability check turn away. Padding only the refusal paths is not enough:
        // a path that costs nothing next to a path that costs tens of microseconds is itself the
        // oracle an attacker reads. Equal cost for grant and every refusal alike is what removes the
        // "does this session exist" signal. The cost of that, and why the throttle therefore sheds
        // the session-store round trip rather than this, is written out in WorkEqualizer.
        WorkEqualizer.apply();
        try {
            if (request == null) {
                // Cannot happen through the container; guarded so a direct call cannot NPE into a
                // 200-with-nothing.
                respondUnavailable(response, writeBody);
                return;
            }
            if (!serving) {
                respondUnavailable(response, writeBody);
                return;
            }

            ClientAddress source = ClientAddress.parse(request.getRemoteAddr());
            String assertedId = readAssertion(request);
            SessionHandoffService.Decision decision =
                    service.handle(new SessionHandoffService.Request(assertedId, source));

            switch (decision.outcome()) {
                case ISSUED:
                    respondGranted(response, decision, writeBody);
                    return;
                case LIMITED_SOURCE:
                case LIMITED_GLOBAL:
                case LIMITED_TRACKING:
                    respondLimited(response, decision, writeBody);
                    // Only the outcome and the bucket shape. Never an identifier, never the address.
                    LOG.log(Level.INFO, "session handoff rate limited, outcome={0}, unknownSource={1}",
                            new Object[]{decision.outcome(), Boolean.valueOf(source.isUnknown())});
                    return;
                case REFUSED_INVALID_ASSERTION:
                    respondRefused(response, writeBody);
                    // The reason enum and nothing else: it tells an operator whether the authenticator
                    // asserted nothing at all or asserted something the validator refused, which are
                    // different bugs to chase, while the value itself stays out of the log (rule 5).
                    LOG.log(Level.INFO, "session handoff refused: the authenticator asserted no usable"
                            + " session identifier, reason={0}", decision.rejectionReason().name());
                    return;
                case REFUSED_UNAUTHENTICATED:
                case REFUSED_UNAVAILABLE:
                default:
                    respondRefused(response, writeBody);
                    LOG.log(Level.INFO, "session handoff refused: the session store did not confirm the"
                            + " asserted identifier");
                    return;
            }
        } catch (RuntimeException | IOException unexpected) {
            // Never propagate: the container's error page would disclose class names, paths and
            // versions. Log the exception type only -- a datastore or JDBC message can carry a
            // connection string, and this component must not put one on any log it does not own.
            LOG.log(Level.SEVERE, "session handoff aborted, exceptionType={0}",
                    unexpected.getClass().getName());
            respondUnavailable(response, writeBody);
        }
    }

    /**
     * Reads the assertion through the injected source, which is contractually forbidden from looking
     * at client data. A throw is "no assertion", logged as a type only.
     */
    private String readAssertion(HttpServletRequest request) {
        try {
            return assertionSource.assertedSessionId(request);
        } catch (RuntimeException sourceFailed) {
            LOG.log(Level.WARNING, "assertion source failed, exceptionType={0}",
                    sourceFailed.getClass().getName());
            return null;
        }
    }

    private void respondGranted(HttpServletResponse response, SessionHandoffService.Decision decision,
                                boolean writeBody) throws IOException {
        String body = ResponseBody.granted(cookieWriter.policy());
        // Emitted before the cookie rather than after it: if the write below throws, the half response
        // the client is left holding is already uncacheable.
        applyStandardHeaders(response);
        if (!writeBody) {
            // HEAD is answered from the same decision, through the same header block and the same
            // measure-the-body step as the GET that would answer it, minus the Set-Cookie it never
            // issues. Content-Length reports the body the GET would have produced, which is what a HEAD
            // is for. A method whose responses have a different header shape is a second, quieter way
            // to tell two outcomes apart, so HEAD shares this code rather than imitating it in a second
            // copy that could drift; the harness asserts the equality for the grant and every refusal.
            response.setStatus(HttpServletResponse.SC_OK);
            writeOrMeasure(response, body, false);
            LOG.log(Level.INFO, "session handoff availability check passed for session {0}",
                    decision.sessionIdentifier().fingerprint());
            return;
        }
        try {
            // The writer emits its own Cache-Control/Pragma (same values, set again is a no-op) and
            // then the cookie, so a partial response is uncacheable before the value appears.
            cookieWriter.writeSessionCookie(decision.sessionIdentifier(), response);
        } catch (InvalidSessionIdentifierException rejectedAtWrite) {
            // The writer's independent gate disagreed with the service. That should be impossible,
            // and it is still a refusal rather than a judgement call: no cookie, generic body.
            LOG.log(Level.SEVERE, "session handoff refused at the cookie gate, reason={0}",
                    rejectedAtWrite.rejection().name());
            respondRefused(response, writeBody);
            return;
        }
        response.setStatus(HttpServletResponse.SC_OK);
        writeOrMeasure(response, body, true);
        LOG.log(Level.INFO, "session handoff granted for session {0}",
                decision.sessionIdentifier().fingerprint());
    }

    private void respondRefused(HttpServletResponse response, boolean writeBody) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        applyStandardHeaders(response);
        writeOrMeasure(response, ResponseBody.REFUSAL, writeBody);
    }

    private void respondLimited(HttpServletResponse response, SessionHandoffService.Decision decision,
                                boolean writeBody) throws IOException {
        response.setStatus(SC_TOO_MANY_REQUESTS);
        applyStandardHeaders(response);
        int retryAfter = decision.retryAfterSeconds();
        if (retryAfter > 0) {
            response.setIntHeader("Retry-After", retryAfter);
        }
        writeOrMeasure(response, ResponseBody.REFUSAL, writeBody);
    }

    private void respondUnavailable(HttpServletResponse response, boolean writeBody) throws IOException {
        response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        applyStandardHeaders(response);
        // Short, so a load balancer retries rather than marking the backend down for a long time.
        response.setIntHeader("Retry-After", 5);
        writeOrMeasure(response, ResponseBody.REFUSAL, writeBody);
    }

    /**
     * The header block every response carries, whatever the status and whatever the method.
     *
     * <p>One method rather than four copies: the cache directives, content type and {@code nosniff} are
     * the response's <i>shape</i>, and the shape is what must not encode anything about the decision
     * behind it. Every copy added is another place that can drift, and drift here is exactly the
     * outcome-telling side channel the rest of this class works to remove -- a response that is
     * cacheable, or plain-text, or of a different length class, says which gate answered. The harness
     * asserts the equality across grant, refusal, limit and unavailable, and across GET and HEAD.
     */
    private void applyStandardHeaders(HttpServletResponse response) {
        // Pragma for HTTP/1.0 proxies, max-age=0 for anything that honours Cache-Control strictly.
        response.setHeader("Cache-Control", "no-store, max-age=0");
        response.setHeader("Pragma", "no-cache");
        response.setContentType("text/html;charset=UTF-8");
        response.setHeader("X-Content-Type-Options", "nosniff");
    }

    /**
     * Writes {@code body} for a GET; for a HEAD reports the length that body would have had.
     *
     * <p>Not just RFC tidiness. If the refusals answered a HEAD with no {@code Content-Length} while
     * the grant answered one with a length, the header shape alone would separate the outcomes for a
     * client that sent HEAD instead of GET -- a second, quieter version of the body-tell this class
     * goes out of its way not to have. Both methods now describe the same document.
     */
    private void writeOrMeasure(HttpServletResponse response, String body, boolean writeBody)
            throws IOException {
        if (writeBody) {
            write(response, body);
        } else {
            response.setContentLength(body.getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
            response.flushBuffer();
        }
    }

    private void write(HttpServletResponse response, String body) throws IOException {
        PrintWriter out = response.getWriter();
        out.write(body);
        out.flush();
    }

    /** Configuration summary for an operator endpoint; never contains a secret or an identifier. */
    @Override
    public String toString() {
        return "SessionHandoffServlet[serving=" + serving
                + (cookieWriter == null ? "" : ", " + cookieWriter.policy()) + "]";
    }

    /** Used by the deployment descriptor check and the harness. */
    boolean isServing() {
        return serving;
    }
}
