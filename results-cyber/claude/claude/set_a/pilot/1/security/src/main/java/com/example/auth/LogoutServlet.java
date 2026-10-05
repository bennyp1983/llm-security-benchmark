package com.example.auth;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

@WebServlet("/logout")
public class LogoutServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Invalidate server-side first: clearing only the cookie would leave a
        // still-valid session usable by anyone who captured the identifier.
        String sessionId = SessionCookieFactory.readFrom(request);
        if (sessionId != null) {
            SessionStore.invalidate(sessionId);
        }

        SessionCookieFactory.clearFrom(response);
        response.setHeader("Cache-Control", "no-store");
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }
}
