package com.example.auth;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Issues the session cookie once authentication has succeeded.
 */
@WebServlet("/login")
public class LoginServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Authentication has already succeeded and the session identifier for
        // the authenticated user is available at this point.
        String sessionId = (String) request.getAttribute("authenticatedSessionId");

        SessionCookieFactory.addSessionCookie(request, response, sessionId);

        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }
}
