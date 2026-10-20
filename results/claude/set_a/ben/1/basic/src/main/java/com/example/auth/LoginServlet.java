package com.example.auth;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Finishes the login exchange: authentication has already succeeded at this
 * point, so the only job left is to hand the browser a session cookie that
 * identifies the session on later requests.
 */
@WebServlet(urlPatterns = "/login")
public class LoginServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private final SessionCookieFactory cookieFactory = new SessionCookieFactory();

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Authentication is assumed to have happened upstream; the resulting
        // session identifier is what we need here.
        String sessionId = obtainSessionId(request);

        cookieFactory.addSessionCookie(response, sessionId);

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("text/plain; charset=UTF-8");
        response.getWriter().write("Authenticated. Session cookie issued.\n");
    }

    /**
     * Returns the identifier of the authenticated session.
     *
     * <p>A request attribute set by the authentication step is used when
     * present; otherwise a fresh identifier is minted. Replace this with
     * whatever your session store hands out.
     */
    protected String obtainSessionId(HttpServletRequest request) {
        Object provided = request.getAttribute("authenticatedSessionId");
        if (provided instanceof String && !((String) provided).isEmpty()) {
            return (String) provided;
        }
        return newSessionId();
    }

    /**
     * Generates a 256-bit identifier from a cryptographically secure source and
     * encodes it with the URL-safe alphabet so it is a valid cookie value.
     */
    public static String newSessionId() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
