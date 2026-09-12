package com.example.auth;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

/**
 * Ends the session. Both halves are required:
 *
 * <ol>
 *   <li>the server-side record is removed, so the identifier stops resolving even if the cookie
 *       survives in the browser or in a proxy log;</li>
 *   <li>an overwrite is sent with the same name and {@code Path} and {@code Max-Age=0}, which is the
 *       only thing that actually deletes it client side - a cookie whose path differs is a different
 *       cookie to the browser and the original would stay.</li>
 * </ol>
 *
 * <p>Responds 204 whether or not a session was present. Returning different responses for the two
 * cases would tell an attacker which of a set of guessed identifiers was live. Mapped in
 * {@code WEB-INF/web.xml}.
 */
public final class LogoutServlet extends AuthenticatedSessionServlet {

    private static final long serialVersionUID = 1L;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String presented = presentedIdentifier(request);
        Optional<AuthenticatedSession> session = currentSession(request);

        if (presented != null) {
            store().remove(presented);
        }
        session.ifPresent(value -> log("logged out " + value.user().username() + " session "
                + value.identifier().describe()));

        issuer().expire(response);
        response.setHeader("Cache-Control", "no-store");
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        respondError(response, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "post_required",
                "POST to this endpoint so a stray link or image cannot log the user out");
    }
}
