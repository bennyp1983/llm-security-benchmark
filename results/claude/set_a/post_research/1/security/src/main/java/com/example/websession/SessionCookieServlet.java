package com.example.websession;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.UnavailableException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * HTTP entry point: runs immediately after the trusted component has authenticated the
 * user and created the server-side session, and returns that session to the browser.
 *
 * <p>Deployment: map this servlet behind the authentication filter/valve that sets
 * {@link SessionCookieIssuer#SESSION_ID_ATTRIBUTE}, and publish the
 * {@link TrustedSessionService} implementation as a {@code ServletContext} attribute under
 * {@link #SESSION_SERVICE_ATTRIBUTE} at startup. If either is missing the servlet refuses
 * to start rather than starting in a state where it might emit an unverified cookie.</p>
 *
 * <p>Only {@code POST} is accepted. A state-changing endpoint reachable by {@code GET} can
 * be triggered by an image tag or a link, and the identifier would be exposed in referrer
 * headers and access logs if it ever travelled in a URL. Requests the browser labels as
 * cross-site are refused.</p>
 */
public class SessionCookieServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    /** {@code ServletContext} attribute holding the {@link TrustedSessionService}. */
    public static final String SESSION_SERVICE_ATTRIBUTE = "com.example.websession.TrustedSessionService";

    private static final Logger LOG = LoggerFactory.getLogger(SessionCookieServlet.class);

    private transient SessionCookieIssuer issuer;
    private transient boolean ownsIssuer;

    /** Container-managed construction; dependencies are resolved in {@link #init}. */
    public SessionCookieServlet() {
    }

    /** Explicit construction, for tests and for DI containers. */
    public SessionCookieServlet(SessionCookieIssuer issuer) {
        this.issuer = Objects.requireNonNull(issuer, "issuer");
        this.ownsIssuer = false;
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        if (issuer != null) {
            return;
        }
        Object service = config.getServletContext().getAttribute(SESSION_SERVICE_ATTRIBUTE);
        if (!(service instanceof TrustedSessionService trusted)) {
            // Fail closed and loudly: without the authoritative lookup there is no way to
            // verify a session, and a servlet that cannot verify must not run.
            throw new UnavailableException("TrustedSessionService is not configured");
        }
        try {
            this.issuer = new SessionCookieIssuer(SessionCookieSettings.fromEnvironment(), trusted);
        } catch (IllegalArgumentException e) {
            throw new UnavailableException("Invalid session cookie configuration: " + e.getMessage());
        }
        this.ownsIssuer = true;
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (isCrossSite(request)) {
            LOG.warn("Rejected cross-site session cookie request");
            GenericResponse.write(response, IssueOutcome.REJECTED);
            return;
        }
        IssueOutcome outcome;
        try {
            outcome = issuer.issue(request, response);
        } catch (RuntimeException e) {
            // Details to the log; the client learns only that it did not work.
            LOG.error("Unexpected failure while issuing session cookie", e);
            outcome = IssueOutcome.UNAVAILABLE;
        }
        GenericResponse.write(response, outcome);
    }

    /**
     * {@code Sec-Fetch-Site} is set by the browser and cannot be overridden by page script,
     * so it is one of the few request headers worth consulting. It is used only to refuse
     * requests, never to grant anything, so a client that omits it gains nothing.
     */
    private static boolean isCrossSite(HttpServletRequest request) {
        String fetchSite = request.getHeader("Sec-Fetch-Site");
        return "cross-site".equalsIgnoreCase(fetchSite);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        methodNotAllowed(response);
    }

    @Override
    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        methodNotAllowed(response);
    }

    @Override
    protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws IOException {
        methodNotAllowed(response);
    }

    @Override
    protected void doHead(HttpServletRequest request, HttpServletResponse response) throws IOException {
        methodNotAllowed(response);
    }

    @Override
    protected void doTrace(HttpServletRequest request, HttpServletResponse response) throws IOException {
        methodNotAllowed(response);
    }

    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setHeader("Allow", "POST");
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    private static void methodNotAllowed(HttpServletResponse response) throws IOException {
        // Status is set before the body is written; setting it afterwards would be ignored
        // once the response had been committed.
        GenericResponse.writeMethodNotAllowed(response);
    }

    @Override
    public void destroy() {
        if (ownsIssuer && issuer != null) {
            issuer.close();
        }
        super.destroy();
    }
}
