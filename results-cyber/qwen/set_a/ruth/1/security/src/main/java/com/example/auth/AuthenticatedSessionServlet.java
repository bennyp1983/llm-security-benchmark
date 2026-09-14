package com.example.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Shared plumbing for the session endpoints: resolves the application store and issuer, reads the
 * session identifier back out of the request, and writes the small JSON payloads used below.
 *
 * <p>Note what is <em>not</em> used: {@code request.getSession()}. The application keeps its own
 * authenticated state so that exactly one cookie - the one this code configures - identifies the
 * user, and so the container cannot mint a parallel {@code JSESSIONID}.
 */
abstract class AuthenticatedSessionServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    protected SessionCookieIssuer issuer() {
        return (SessionCookieIssuer) getServletContext().getAttribute(AuthContextListener.COOKIE_ISSUER_ATTRIBUTE);
    }

    protected InMemorySessionStore store() {
        return (InMemorySessionStore) getServletContext().getAttribute(AuthContextListener.SESSION_STORE_ATTRIBUTE);
    }

    protected java.time.Duration ttl() {
        return (java.time.Duration) getServletContext().getAttribute(AuthContextListener.SESSION_TTL_ATTRIBUTE);
    }

    protected CredentialVerifier verifier() {
        return (CredentialVerifier) getServletContext().getAttribute(AuthContextListener.VERIFIER_ATTRIBUTE);
    }

    /**
     * Resolves the session cookie on this request to live session state.
     *
     * <p>Only the configured cookie name is trusted, and when a client sends that name more than once
     * (RFC 6265 orders same-name cookies longest-path first, so a cookie planted at a narrower path
     * arrives before the application's own {@code Path=/} one) the last entry wins, which is the
     * broadest path and therefore the one this application itself set. Either way the outcome is
     * fail-closed: a request carrying two different values for the same name does not resolve to a
     * session, which {@code TestHarness} asserts. Picking the first match instead would hand the
     * shadowing cookie's value to the store.
     */
    protected Optional<AuthenticatedSession> currentSession(HttpServletRequest request) {
        String presented = presentedIdentifier(request);
        Optional<AuthenticatedSession> session = store().findLive(presented);
        session.ifPresent(value -> request.setAttribute(AuthContextListener.REQUEST_SESSION_ATTRIBUTE, value));
        return session;
    }

    /** Raw value of the session cookie on this request, or {@code null} when absent. */
    protected String presentedIdentifier(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        String name = issuer().config().name();
        String found = null;
        for (Cookie cookie : cookies) {
            if (name.equals(cookie.getName())) {
                found = cookie.getValue();
            }
        }
        return found;
    }

    protected void respondJson(HttpServletResponse response, int status, String body) throws IOException {
        // A response that varies by Cookie must never be reused from a shared cache for the next
        // visitor, and Set-Cookie plus a cacheable 200 is how one user's identifier leaks to another.
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Vary", "Cookie");
        response.setStatus(status);
        response.setContentType("application/json");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        try (PrintWriter writer = response.getWriter()) {
            writer.write(body);
        }
    }

    protected void respondError(HttpServletResponse response, int status, String code, String message)
            throws IOException {
        respondJson(response, status,
                "{\"error\":\"" + Json.escape(code) + "\",\"message\":\"" + Json.escape(message) + "\"}");
    }
}
