package com.example.webapp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.util.Map;

/**
 * Handles the login page and credential verification.
 *
 *   GET  /login -> HTML login form
 *   POST /login -> verify the submitted username/password:
 *     success -> 302 redirect to / plus
 *                Set-Cookie: JSESSIONID=<id>; Path=/; HttpOnly; SameSite=Lax
 *     failure -> 401 with a JSON error body
 */
final class LoginHandler implements HttpHandler {

    /** Name of the session cookie, mirroring the JSESSIONID convention. */
    static final String SESSION_COOKIE = "JSESSIONID";

    private final SessionStore sessions;
    private final UserService users;

    LoginHandler(SessionStore sessions, UserService users) {
        this.sessions = sessions;
        this.users = users;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String method = exchange.getRequestMethod();
        if ("GET".equalsIgnoreCase(method)) {
            WebUtil.sendHtml(exchange, 200, loginPage());
        } else if ("POST".equalsIgnoreCase(method)) {
            authenticate(exchange);
        } else {
            WebUtil.sendJson(exchange, 405, "{\"error\":\"method not allowed\"}");
        }
    }

    private void authenticate(HttpExchange exchange) throws IOException {
        Map<String, String> form = WebUtil.parseForm(exchange.getRequestBody().readAllBytes());
        String username = form.get("username");
        String password = form.get("password");

        if (username == null || password == null || username.isEmpty() || password.isEmpty()) {
            WebUtil.sendJson(exchange, 400, "{\"error\":\"username and password are required\"}");
            return;
        }

        if (!users.verify(username, password)) {
            System.out.println("login failed: " + username);
            WebUtil.sendJson(exchange, 401, "{\"error\":\"Invalid username or password\"}");
            return;
        }

        // Authentication succeeded: open a server-side session and hand the
        // client its opaque session id in a JSESSIONID cookie.
        SessionStore.Session session = sessions.create(username);
        String cookie = SESSION_COOKIE + "=" + session.id
                + "; Path=/; HttpOnly; SameSite=Lax";
        System.out.println("login succeeded: " + username
                + " (session " + session.id.substring(0, 8) + "..., "
                + sessions.size() + " active session(s))");
        WebUtil.redirect(exchange, "/", cookie);
    }

    private static String loginPage() {
        return """
            <!DOCTYPE html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <title>Login</title>
              <style>
                body { font-family: system-ui, sans-serif; display: grid; place-items: center;
                        min-height: 100vh; margin: 0; background: #f4f5f7; }
                .card { background: #fff; padding: 2rem 2.5rem; border-radius: 12px;
                         box-shadow: 0 4px 16px rgba(0,0,0,.08); width: 320px; }
                h1 { font-size: 1.25rem; margin: 0 0 1rem; }
                label { display: block; font-size: .9rem; margin: .75rem 0 .25rem; color: #444; }
                input { width: 100%; box-sizing: border-box; padding: .5rem .6rem;
                         border: 1px solid #ccc; border-radius: 6px; font-size: 1rem; }
                button { margin-top: 1.25rem; width: 100%; padding: .6rem; border: 0;
                          border-radius: 6px; background: #2563eb; color: #fff;
                          font-size: 1rem; cursor: pointer; }
                button:hover { background: #1d4ed8; }
              </style>
            </head>
            <body>
              <form class="card" action="/login" method="post">
                <h1>Sign in</h1>
                <label for="username">Username</label>
                <input id="username" name="username" type="text"
                       autocomplete="username" required>
                <label for="password">Password</label>
                <input id="password" name="password" type="password"
                       autocomplete="current-password" required>
                <button type="submit">Log in</button>
              </form>
            </body>
            </html>
            """;
    }
}
