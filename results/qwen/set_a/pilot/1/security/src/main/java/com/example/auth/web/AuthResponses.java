package com.example.auth.web;

import com.example.auth.session.SessionCookieConfig;
import com.example.auth.session.SessionCookieFactory;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/** Response plumbing shared by the auth servlets. */
final class AuthResponses {

    private AuthResponses() {
    }

    /**
     * Authenticated responses carry a fresh credential and often subject data; a cached copy replayed
     * from a proxy or a shared browser profile is a session the original client did not authorise.
     */
    static void noStore(HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
    }

    /**
     * Ends a request that is not entitled to a session. The cookie is actively expired so a leftover
     * from an earlier login cannot linger, and no {@code WWW-Authenticate} is sent: a challenge makes
     * browsers pop a credentials dialog and replay the credentials on every later request.
     */
    static void rejectUnauthorized(HttpServletRequest request,
                                   HttpServletResponse response,
                                   SessionCookieConfig cookieConfig) throws IOException {
        discardPreAuthSession(request);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        noStore(response);
        SessionCookieFactory.clear(response, cookieConfig);
        response.flushBuffer();
    }

    /**
     * A container session that predates authentication has an identifier a fixation attacker may
     * already know, so it is dropped rather than promoted. This application keeps authenticated state
     * in its own cookie plus {@link com.example.auth.session.SessionRegistry} and never needs an
     * {@code HttpSession}.
     */
    static void discardPreAuthSession(HttpServletRequest request) {
        var session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
    }
}
