package com.example.auth;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

/**
 * Establishes the authenticated session and attaches the session cookie to the response. This is the
 * servlet the task asks for: authentication happens upstream, the session identifier it hands back is
 * what {@link SessionCookieIssuer#issue} puts into {@code Set-Cookie}.
 *
 * <p>What happens on a successful credential check, in order:
 *
 * <ol>
 *   <li>Any session the request already carried is dropped, so the pre-authentication identifier
 *       cannot survive into the authenticated state (session fixation).</li>
 *   <li>A fresh 256-bit identifier is minted and bound to the principal in the store.</li>
 *   <li>The cookie is built with {@code HttpOnly}, {@code Secure}, {@code SameSite=Lax}, host-only
 *       {@code Path=/} and browser-session lifetime, added to the response, and the header the
 *       container emitted is verified before the body is written.</li>
 * </ol>
 *
 * <p>Cookie settings are application-wide {@code context-param}s declared in
 * {@code WEB-INF/web.xml}, which is also where the container's own session cookie is hardened and
 * URL rewriting is switched off.
 */
public final class LoginServlet extends AuthenticatedSessionServlet {

    private static final long serialVersionUID = 1L;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        CredentialVerifier verifier = verifier();
        if (verifier == null) {
            respondError(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "not_configured",
                    "no credential verifier is published by AuthContextListener");
            return;
        }
        if (!verifier.isConfigured()) {
            // A missing verifier must not read as "wrong password": that would hide a broken
            // deployment behind a plausible 401 forever.
            respondError(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "not_configured",
                    "credential verifier has no credentials configured");
            return;
        }

        Optional<SessionUser> principal;
        try {
            principal = verifier.verify(username, password);
        } catch (RuntimeException failure) {
            // Upstream detail stays in the log: a 401 body is a good place to leak why.
            log("credential verification failed", failure);
            respondError(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "verification_error",
                    "credential verification could not be completed");
            return;
        }

        if (principal.isEmpty()) {
            respondError(response, HttpServletResponse.SC_UNAUTHORIZED, "invalid_credentials",
                    "username or password is not correct");
            return;
        }

        // Drop any session this request arrived with before creating the new one, so the identifier
        // presented pre-authentication never names the authenticated session.
        String presented = presentedIdentifier(request);
        if (presented != null) {
            store().remove(presented);
        }

        AuthenticatedSession session = store().create(principal.get(), ttl());

        // The line that matters: the identifier goes into a Set-Cookie header on this response.
        SessionCookieIssuer issuer = issuer();
        issuer.issue(response, session.identifier());

        log("authenticated " + principal.get().username() + " as session " + session.identifier().describe());
        // The body reports a redacted fingerprint, never the identifier itself. Repeating it here
        // would hand the credential to anything that can read the response body - including script
        // running in the page, which is the whole reason the cookie is HttpOnly. Read the real value
        // off the response header when inspecting with curl -D -.
        respondJson(response, HttpServletResponse.SC_OK,
                "{\"authenticated\":true"
                        + ",\"user\":\"" + Json.escape(principal.get().username()) + "\""
                        + ",\"cookie\":{\"name\":\"" + Json.escape(issuer.config().name()) + "\""
                        + ",\"path\":\"" + Json.escape(issuer.config().path()) + "\""
                        + ",\"secure\":" + issuer.config().secure()
                        + ",\"httpOnly\":" + issuer.config().httpOnly()
                        + ",\"sameSite\":\"" + issuer.config().sameSite().headerValue() + "\""
                        + ",\"valueFingerprint\":\"" + Json.escape(session.identifier().fingerprint()) + "\""
                        + "}"
                        + ",\"expiresAt\":\"" + session.expiresAt() + "\"}");
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        respondError(response, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "post_required",
                "POST credentials to this endpoint");
    }
}
