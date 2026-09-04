package com.example.webapp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.util.List;

/**
 * Protected home page. Requires a valid JSESSIONID cookie:
 *
 *   cookie valid   -> 200 personal home page
 *   cookie missing/invalid -> 302 to /login for HTML clients,
 *                             401 JSON for API clients
 */
final class HomeHandler implements HttpHandler {

    private final SessionStore sessions;

    HomeHandler(SessionStore sessions) {
        this.sessions = sessions;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        if (!"/".equals(exchange.getRequestURI().getPath())) {
            WebUtil.sendJson(exchange, 404, "{\"error\":\"not found\"}");
            return;
        }
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            WebUtil.sendJson(exchange, 405, "{\"error\":\"method not allowed\"}");
            return;
        }

        String sessionId = WebUtil.parseCookies(exchange).get(LoginHandler.SESSION_COOKIE);
        SessionStore.Session session = sessions.getSession(sessionId);
        if (session == null) {
            if (wantsHtml(exchange)) {
                WebUtil.redirect(exchange, "/login", null);
            } else {
                WebUtil.sendJson(exchange, 401, "{\"error\":\"Not authenticated\"}");
            }
            return;
        }
        WebUtil.sendHtml(exchange, 200, homePage(session));
    }

    /**
     * Redirect to /login unless the client explicitly prefers a JSON
     * response (i.e. its Accept header names application/json and nothing
     * more specific to HTML). Browsers and plain HTTP clients are therefore
     * treated as HTML clients.
     */
    private static boolean wantsHtml(HttpExchange exchange) {
        List<String> accept = exchange.getRequestHeaders().get("Accept");
        if (accept == null) {
            return true;
        }
        boolean json = accept.stream().anyMatch(h -> h.contains("application/json"));
        boolean html = accept.stream().anyMatch(h -> h.contains("text/html"));
        return !json || html;
    }

    private static String homePage(SessionStore.Session session) {
        String username = WebUtil.escapeHtml(session.username);
        String sessionId = WebUtil.escapeHtml(session.id);
        return """
            <!DOCTYPE html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <title>Home</title>
              <style>
                body { font-family: system-ui, sans-serif; display: grid; place-items: center;
                        min-height: 100vh; margin: 0; background: #f4f5f7; }
                .card { background: #fff; padding: 2rem 2.5rem; border-radius: 12px;
                         box-shadow: 0 4px 16px rgba(0,0,0,.08); width: 400px; }
                h1 { font-size: 1.25rem; margin: 0 0 .5rem; }
                p { color: #444; margin: .35rem 0; line-height: 1.4; }
                code { background: #eef1f5; padding: .1rem .35rem; border-radius: 4px;
                        font-size: .8rem; word-break: break-all; }
                form { margin-top: 1.25rem; }
                button { padding: .6rem 1.25rem; border: 0; border-radius: 6px;
                          background: #dc2626; color: #fff; font-size: 1rem; cursor: pointer; }
                button:hover { background: #b91c1c; }
              </style>
            </head>
            <body>
              <div class="card">
                <h1>Welcome, %s!</h1>
                <p>You are authenticated. This page was served because your
                   browser presented a valid <code>JSESSIONID</code> cookie.</p>
                <p>Session id: <code>%s</code></p>
                <form action="/logout" method="post">
                  <button type="submit">Log out</button>
                </form>
              </div>
            </body>
            </html>
            """.formatted(username, sessionId);
    }
}
