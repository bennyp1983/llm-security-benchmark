package com.example.auth;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

/**
 * Consumes the cookie: if the session identifier the browser returned resolves to live state, the
 * request is the authenticated user's. This is the round trip the task asks the cookie to enable -
 * nothing is re-authenticated here, the cookie alone carries the session. Mapped in
 * {@code WEB-INF/web.xml}.
 */
public final class WhoAmIServlet extends AuthenticatedSessionServlet {

    private static final long serialVersionUID = 1L;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        Optional<AuthenticatedSession> session = currentSession(request);
        if (session.isEmpty()) {
            respondError(response, HttpServletResponse.SC_UNAUTHORIZED, "anonymous",
                    "no live session for the presented cookie");
            return;
        }
        AuthenticatedSession value = session.get();
        respondJson(response, HttpServletResponse.SC_OK,
                "{\"authenticated\":true"
                        + ",\"user\":\"" + Json.escape(value.user().username()) + "\""
                        + ",\"sessionFingerprint\":\"" + value.identifier().fingerprint() + "\""
                        + ",\"authenticatedAt\":\"" + value.authenticatedAt() + "\""
                        + ",\"expiresAt\":\"" + value.expiresAt() + "\"}");
    }
}
