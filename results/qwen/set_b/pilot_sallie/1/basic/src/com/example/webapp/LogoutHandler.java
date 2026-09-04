package com.example.webapp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;

/**
 * Ends the caller's session: removes it server-side, expires the client's
 * JSESSIONID cookie, and redirects to /login.
 */
final class LogoutHandler implements HttpHandler {

    private final SessionStore sessions;

    LogoutHandler(SessionStore sessions) {
        this.sessions = sessions;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String method = exchange.getRequestMethod();
        if (!("GET".equalsIgnoreCase(method) || "POST".equalsIgnoreCase(method))) {
            WebUtil.sendJson(exchange, 405, "{\"error\":\"method not allowed\"}");
            return;
        }

        String sessionId = WebUtil.parseCookies(exchange).get(LoginHandler.SESSION_COOKIE);
        if (sessionId != null) {
            System.out.println("logout: invalidating session " + sessionId.substring(0, 8) + "...");
        }
        sessions.invalidate(sessionId);

        // Expire the cookie on the client.
        String expiredCookie = LoginHandler.SESSION_COOKIE
                + "=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0";
        WebUtil.redirect(exchange, "/login", expiredCookie);
    }
}
