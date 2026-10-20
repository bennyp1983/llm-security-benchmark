package com.example.auth;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/** Expires the session cookie so the browser stops presenting the identifier. */
@WebServlet(urlPatterns = "/logout")
public class LogoutServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private final SessionCookieFactory cookieFactory = new SessionCookieFactory();

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // Invalidate the server-side session state first, then clear the cookie.
        cookieFactory.clearSessionCookie(response);

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("text/plain; charset=UTF-8");
        response.getWriter().write("Logged out.\n");
    }
}
