package com.example.auth;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;

/**
 * Issues the session cookie once authentication has succeeded.
 *
 * <p>Only the post-authentication half is shown here; credential verification
 * is assumed to have already happened and to have produced a session
 * identifier.
 */
@WebServlet("/login")
public class LoginServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // --- Authentication is assumed to have succeeded at this point. ---
        String userId = (String) request.getAttribute("authenticatedUserId");

        // Session fixation defence: drop any session the client arrived with,
        // so the identifier that becomes "authenticated" is one we just minted
        // and the client could not have chosen or pre-seeded.
        HttpSession existing = request.getSession(false);
        if (existing != null) {
            existing.invalidate();
        }

        // The freshly issued identifier for this authenticated session.
        String sessionId = SessionIdGenerator.newSessionId();

        // Bind the identifier to the user in the server-side session store
        // before it is handed to the client.
        SessionStore.create(sessionId, userId);

        // Attach the hardened session cookie to the response.
        SessionCookieFactory.addTo(response, sessionId);

        // Never cache a response that carries a Set-Cookie for a session.
        response.setHeader("Cache-Control", "no-store");

        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
    }
}
