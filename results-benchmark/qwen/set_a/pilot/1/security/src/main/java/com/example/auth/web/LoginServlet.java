package com.example.auth.web;

import com.example.auth.session.SessionCookieConfig;
import com.example.auth.session.SessionCookieFactory;
import com.example.auth.session.SessionRegistry;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.Objects;

/**
 * Turns a completed authentication into a session the browser can keep using.
 *
 * <p>By the time {@code POST /api/login} gets here the credential check has passed and the
 * authenticating component has published the subject and the identifier that must represent it from
 * now on (see {@link AuthAttributes}). This servlet records that binding server-side and answers with
 * the hardened session cookie; every later request is then recognised by
 * {@link com.example.auth.session.SessionCookieFactory#readSessionId}.
 *
 * <p>Two properties are load-bearing:
 * <ul>
 *   <li>the identifier is only ever read from request <em>attributes</em>, and an identifier the client
 *       already presented is refused -- otherwise an attacker could pre-plant one and have the victim's
 *       new session adopt it (session fixation);</li>
 *   <li>the cookie is emitted through {@link SessionCookieFactory}, i.e. {@code Secure},
 *       {@code HttpOnly}, host-only, {@code SameSite} and an explicit path, because a session cookie
 *       without those is readable by page script and by cross-site requests.</li>
 * </ul>
 */
@WebServlet(name = "loginServlet", urlPatterns = "/api/login")
public class LoginServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private SessionRegistry sessions;
    private SessionCookieConfig cookieConfig;
    private Duration sessionTtl;

    /** Used by the container; collaborators are resolved in {@link #init()}. */
    public LoginServlet() {
    }

    public LoginServlet(SessionRegistry sessions, SessionCookieConfig cookieConfig, Duration sessionTtl) {
        this.sessions = Objects.requireNonNull(sessions, "sessions");
        this.cookieConfig = Objects.requireNonNull(cookieConfig, "cookieConfig");
        this.sessionTtl = Objects.requireNonNull(sessionTtl, "sessionTtl");
    }

    @Override
    public void init() throws ServletException {
        if (sessionTtl == null) {
            var context = getServletContext();
            this.sessions = WebInfrastructure.sessionRegistry(context);
            this.cookieConfig = WebInfrastructure.sessionCookieConfig(context);
            this.sessionTtl = WebInfrastructure.sessionTtl(context);
        }
        long ttlSeconds = sessionTtl.getSeconds();
        int cookieMaxAge = cookieConfig.maxAgeSeconds();
        if (cookieMaxAge >= 0 && cookieMaxAge > ttlSeconds) {
            throw new ServletException("cookie Max-Age " + cookieMaxAge + "s outlives the "
                    + ttlSeconds + "s server-side session; the browser would keep a dead identifier");
        }
    }

    /** Credentials belong in a request body: in a URL they end up in access logs and {@code Referer}. */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        response.setHeader("Allow", "POST");
        AuthResponses.noStore(response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Object subjectId = request.getAttribute(AuthAttributes.SUBJECT_ID);
        Object sessionId = request.getAttribute(AuthAttributes.SESSION_ID);

        if (!(subjectId instanceof String subject) || !(sessionId instanceof String identifier)) {
            // Fail closed: nothing short of a completed authentication populates these attributes.
            AuthResponses.rejectUnauthorized(request, response, cookieConfig);
            return;
        }

        if (presentedByIdClient(request, identifier)) {
            AuthResponses.rejectUnauthorized(request, response, cookieConfig);
            return;
        }

        AuthResponses.discardPreAuthSession(request);

        Duration ttl = request.getAttribute(AuthAttributes.SESSION_TTL) instanceof Duration override
                ? override
                : sessionTtl;
        sessions.register(identifier, subject, ttl);

        AuthResponses.noStore(response);
        SessionCookieFactory.issue(response, cookieConfig, identifier);
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    /**
     * True when the candidate identifier reached us through something the client controls. An
     * identifier that was already in the request cannot be treated as proof of anything: that is
     * exactly how a fixation attack, or a session id that leaked through {@code Referer} via URL
     * rewriting, gets promoted to an authenticated session.
     */
    private boolean presentedByIdClient(HttpServletRequest request, String identifier) {
        if (request.isRequestedSessionIdFromURL()) {
            return true;
        }
        String requested = request.getRequestedSessionId();
        return requested != null && requested.equals(identifier);
    }
}
