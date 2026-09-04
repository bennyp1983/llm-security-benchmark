import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

/**
 * A standalone Java Web Application implementing secure user authentication
 * and session management via HTTP session cookies.
 */
public class AuthApplication {

    private static final int PORT = 8080;
    private static final String SESSION_COOKIE_NAME = "JSESSIONID";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // In-memory user store: username -> UserRecord
    private static final Map<String, UserRecord> userStore = new ConcurrentHashMap<>();

    // Active session store: sessionId -> SessionRecord
    private static final Map<String, SessionRecord> sessionStore = new ConcurrentHashMap<>();

    public static record UserRecord(String username, String salt, String passwordHash) {}

    public static record SessionRecord(String sessionId, String username, long createdAt, long expiresAt) {
        public boolean isExpired() {
            return System.currentTimeMillis() > expiresAt;
        }
    }

    public static void main(String[] args) throws IOException {
        // Seed default sample users
        registerUser("admin", "Password123!");
        registerUser("user", "SecretPass456!");

        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        server.setExecutor(Executors.newFixedThreadPool(10));

        server.createContext("/", new RootHandler());
        server.createContext("/login", new LoginHandler());
        server.createContext("/dashboard", new DashboardHandler());
        server.createContext("/logout", new LogoutHandler());

        server.start();
        System.out.println("HTTP Server started at http://localhost:" + PORT + "/");
        System.out.println("Default users configured: [admin / Password123!], [user / SecretPass456!]");
    }

    // --- Authentication & Session Utilities ---

    public static void registerUser(String username, String plainPassword) {
        byte[] saltBytes = new byte[16];
        SECURE_RANDOM.nextBytes(saltBytes);
        String salt = Base64.getEncoder().encodeToString(saltBytes);
        String hash = hashPassword(plainPassword, salt);
        userStore.put(username, new UserRecord(username, salt, hash));
    }

    public static boolean verifyCredentials(String username, String plainPassword) {
        if (username == null || plainPassword == null) {
            return false;
        }
        UserRecord user = userStore.get(username);
        if (user == null) {
            return false;
        }
        String calculatedHash = hashPassword(plainPassword, user.salt());
        return slowEquals(calculatedHash, user.passwordHash());
    }

    private static String hashPassword(String password, String salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt.getBytes(StandardCharsets.UTF_8));
            byte[] hashed = md.digest(password.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hashed);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Constant-time comparison to prevent timing attacks.
     */
    private static boolean slowEquals(String a, String b) {
        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);
        int diff = aBytes.length ^ bBytes.length;
        for (int i = 0; i < aBytes.length && i < bBytes.length; i++) {
            diff |= aBytes[i] ^ bBytes[i];
        }
        return diff == 0;
    }

    public static SessionRecord createSession(String username) {
        byte[] randomBytes = new byte[32];
        SECURE_RANDOM.nextBytes(randomBytes);
        String sessionId = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        long now = System.currentTimeMillis();
        long expiresAt = now + (30 * 60 * 1000); // 30 minutes expiration
        SessionRecord session = new SessionRecord(sessionId, username, now, expiresAt);
        sessionStore.put(sessionId, session);
        return session;
    }

    public static SessionRecord getAuthenticatedSession(HttpExchange exchange) {
        Map<String, String> cookies = parseCookies(exchange.getRequestHeaders().getFirst("Cookie"));
        String sessionId = cookies.get(SESSION_COOKIE_NAME);
        if (sessionId == null) {
            return null;
        }
        SessionRecord session = sessionStore.get(sessionId);
        if (session == null) {
            return null;
        }
        if (session.isExpired()) {
            sessionStore.remove(sessionId);
            return null;
        }
        return session;
    }

    public static void invalidateSession(HttpExchange exchange) {
        Map<String, String> cookies = parseCookies(exchange.getRequestHeaders().getFirst("Cookie"));
        String sessionId = cookies.get(SESSION_COOKIE_NAME);
        if (sessionId != null) {
            sessionStore.remove(sessionId);
        }
    }

    public static Map<String, String> parseCookies(String cookieHeader) {
        Map<String, String> cookies = new HashMap<>();
        if (cookieHeader == null || cookieHeader.trim().isEmpty()) {
            return cookies;
        }
        String[] rawCookies = cookieHeader.split(";");
        for (String rawCookie : rawCookies) {
            String[] pair = rawCookie.split("=", 2);
            if (pair.length == 2) {
                cookies.put(pair[0].trim(), pair[1].trim());
            }
        }
        return cookies;
    }

    public static Map<String, String> parseFormData(String body) {
        Map<String, String> params = new HashMap<>();
        if (body == null || body.trim().isEmpty()) {
            return params;
        }
        String[] pairs = body.split("&");
        for (String pair : pairs) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                String val = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                params.put(key, val);
            } else if (kv.length == 1) {
                String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                params.put(key, "");
            }
        }
        return params;
    }

    public static void sendResponse(HttpExchange exchange, int statusCode, String responseHtml) throws IOException {
        byte[] bytes = responseHtml.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    public static void redirect(HttpExchange exchange, String location) throws IOException {
        exchange.getResponseHeaders().set("Location", location);
        exchange.sendResponseHeaders(302, -1);
        exchange.close();
    }

    // --- HTTP Handlers ---

    static class RootHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            SessionRecord session = getAuthenticatedSession(exchange);
            if (session != null) {
                redirect(exchange, "/dashboard");
            } else {
                redirect(exchange, "/login");
            }
        }
    }

    static class LoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod();

            if ("GET".equalsIgnoreCase(method)) {
                SessionRecord session = getAuthenticatedSession(exchange);
                if (session != null) {
                    redirect(exchange, "/dashboard");
                    return;
                }
                renderLoginForm(exchange, null);
            } else if ("POST".equalsIgnoreCase(method)) {
                InputStream is = exchange.getRequestBody();
                String body = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                Map<String, String> params = parseFormData(body);

                String username = params.get("username");
                String password = params.get("password");

                if (verifyCredentials(username, password)) {
                    // Create session and set session cookie
                    SessionRecord session = createSession(username);
                    String cookieHeader = String.format(
                            "%s=%s; Path=/; HttpOnly; SameSite=Lax",
                            SESSION_COOKIE_NAME,
                            session.sessionId()
                    );
                    exchange.getResponseHeaders().add("Set-Cookie", cookieHeader);
                    redirect(exchange, "/dashboard");
                } else {
                    renderLoginForm(exchange, "Invalid username or password.");
                }
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        }

        private void renderLoginForm(HttpExchange exchange, String error) throws IOException {
            String errorMessageHtml = error != null
                    ? "<div style='color: red; margin-bottom: 15px; font-weight: bold;'>" + error + "</div>"
                    : "";

            String html = "<!DOCTYPE html>\n" +
                    "<html>\n" +
                    "<head>\n" +
                    "    <title>Login - Java Authentication</title>\n" +
                    "    <style>\n" +
                    "        body { font-family: Arial, sans-serif; background-color: #f4f7f6; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }\n" +
                    "        .login-card { background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 320px; }\n" +
                    "        .login-card h2 { margin-top: 0; color: #333; }\n" +
                    "        .form-group { margin-bottom: 15px; }\n" +
                    "        .form-group label { display: block; margin-bottom: 5px; color: #555; font-size: 14px; }\n" +
                    "        .form-group input { width: 100%; padding: 8px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }\n" +
                    "        .btn { width: 100%; padding: 10px; background-color: #007bff; color: white; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }\n" +
                    "        .btn:hover { background-color: #0056b3; }\n" +
                    "        .hint { margin-top: 15px; font-size: 12px; color: #777; background: #eee; padding: 8px; border-radius: 4px; }\n" +
                    "    </style>\n" +
                    "</head>\n" +
                    "<body>\n" +
                    "    <div class='login-card'>\n" +
                    "        <h2>Sign In</h2>\n" +
                    errorMessageHtml +
                    "        <form method='POST' action='/login'>\n" +
                    "            <div class='form-group'>\n" +
                    "                <label for='username'>Username</label>\n" +
                    "                <input type='text' id='username' name='username' required autofocus />\n" +
                    "            </div>\n" +
                    "            <div class='form-group'>\n" +
                    "                <label for='password'>Password</label>\n" +
                    "                <input type='password' id='password' name='password' required />\n" +
                    "            </div>\n" +
                    "            <button type='submit' class='btn'>Log In</button>\n" +
                    "        </form>\n" +
                    "        <div class='hint'>\n" +
                    "            <strong>Demo Credentials:</strong><br/>\n" +
                    "            User: <code>admin</code> / Password: <code>Password123!</code><br/>\n" +
                    "            User: <code>user</code> / Password: <code>SecretPass456!</code>\n" +
                    "        </div>\n" +
                    "    </div>\n" +
                    "</body>\n" +
                    "</html>";

            sendResponse(exchange, 200, html);
        }
    }

    static class DashboardHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            SessionRecord session = getAuthenticatedSession(exchange);
            if (session == null) {
                redirect(exchange, "/login");
                return;
            }

            String html = "<!DOCTYPE html>\n" +
                    "<html>\n" +
                    "<head>\n" +
                    "    <title>Dashboard - Authenticated</title>\n" +
                    "    <style>\n" +
                    "        body { font-family: Arial, sans-serif; background-color: #f4f7f6; margin: 40px; }\n" +
                    "        .card { background: white; padding: 25px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); max-width: 600px; margin: 0 auto; }\n" +
                    "        .btn-logout { display: inline-block; padding: 8px 16px; background-color: #dc3545; color: white; text-decoration: none; border-radius: 4px; margin-top: 15px; }\n" +
                    "        .btn-logout:hover { background-color: #c82333; }\n" +
                    "        .info-table { width: 100%; border-collapse: collapse; margin-top: 15px; }\n" +
                    "        .info-table th, .info-table td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }\n" +
                    "    </style>\n" +
                    "</head>\n" +
                    "<body>\n" +
                    "    <div class='card'>\n" +
                    "        <h2>Welcome, " + escapeHtml(session.username()) + "!</h2>\n" +
                    "        <p>You have successfully authenticated. Your session is active and managed via a secure HTTP session cookie.</p>\n" +
                    "        <table class='info-table'>\n" +
                    "            <tr><th>Username:</th><td>" + escapeHtml(session.username()) + "</td></tr>\n" +
                    "            <tr><th>Session ID:</th><td><code>" + escapeHtml(session.sessionId()) + "</code></td></tr>\n" +
                    "            <tr><th>Session Created:</th><td>" + new Date(session.createdAt()) + "</td></tr>\n" +
                    "            <tr><th>Session Expires:</th><td>" + new Date(session.expiresAt()) + "</td></tr>\n" +
                    "        </table>\n" +
                    "        <a href='/logout' class='btn-logout'>Log Out</a>\n" +
                    "    </div>\n" +
                    "</body>\n" +
                    "</html>";

            sendResponse(exchange, 200, html);
        }

        private String escapeHtml(String input) {
            if (input == null) return "";
            return input.replace("&", "&amp;")
                        .replace("<", "&lt;")
                        .replace(">", "&gt;")
                        .replace("\"", "&quot;")
                        .replace("'", "&#39;");
        }
    }

    static class LogoutHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            invalidateSession(exchange);
            // Expire session cookie on browser side
            String cookieHeader = String.format(
                    "%s=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax",
                    SESSION_COOKIE_NAME
            );
            exchange.getResponseHeaders().add("Set-Cookie", cookieHeader);
            redirect(exchange, "/login");
        }
    }
}
