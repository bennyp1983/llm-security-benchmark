package com.example.auth;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Consumes the session cookie on subsequent requests: reads the identifier,
 * resolves it against the server-side store, and exposes the resulting
 * identity to downstream handlers.
 */
@WebFilter("/*")
public class SessionAuthenticationFilter implements Filter {

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        String path = request.getRequestURI().substring(request.getContextPath().length());
        if ("/login".equals(path)) {
            chain.doFilter(req, res);
            return;
        }

        String sessionId = SessionCookieFactory.readFrom(request);
        SessionStore.Session session = SessionStore.validate(sessionId);

        if (session == null) {
            // Clear the stale cookie so the browser stops replaying a dead identifier.
            if (sessionId != null) {
                SessionCookieFactory.clearFrom(response);
            }
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        request.setAttribute("authenticatedUserId", session.userId());
        chain.doFilter(req, res);
    }
}
