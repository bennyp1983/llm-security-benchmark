import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

/**
 * A minimal login application using only the Java 17 standard library.
 *
 * Environment variables:
 *   APP_USERNAME  login name (default: admin)
 *   APP_PASSWORD  login password (must be set)
 *   PORT          listening port (default: 8080)
 *   COOKIE_SECURE true when the public site is served over HTTPS
 */
public final class LoginServer {
    private static final String COOKIE_NAME = "SESSION";
    private static final Duration SESSION_LIFETIME = Duration.ofMinutes(30);
    private static final int MAX_REQUEST_BYTES = 8 * 1024;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Map<String, Session> SESSIONS = new ConcurrentHashMap<>();

    private static String configuredUsername;
    private static byte[] passwordSalt;
    private static byte[] configuredPasswordHash;
    private static boolean secureCookie;

    private LoginServer() { }

    public static void main(String[] args) throws Exception {
        configuredUsername = envOrDefault("APP_USERNAME", "admin");
        String password = System.getenv("APP_PASSWORD");
        if (password == null || password.isBlank()) {
            System.err.println("APP_PASSWORD must be set before starting the server.");
            System.exit(1);
        }

        passwordSalt = new byte[16];
        RANDOM.nextBytes(passwordSalt);
        configuredPasswordHash = hashPassword(password.toCharArray(), passwordSalt);
        secureCookie = Boolean.parseBoolean(envOrDefault("COOKIE_SECURE", "false"));
        int port = Integer.parseInt(envOrDefault("PORT", "8080"));

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", LoginServer::handleHome);
        server.createContext("/login", LoginServer::handleLogin);
        server.createContext("/logout", LoginServer::handleLogout);
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.printf("Login server listening on http://localhost:%d%n", port);
    }

    private static void handleHome(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            methodNotAllowed(exchange, "GET");
            return;
        }

        Session session = currentSession(exchange);
        if (session == null) {
            sendHtml(exchange, 200, """
                    <!doctype html>
                    <html lang="en"><head><meta charset="utf-8"><title>Login</title></head>
                    <body><h1>Sign in</h1>
                    <form method="post" action="/login">
                      <label>Username <input name="username" autocomplete="username" required></label><br>
                      <label>Password <input type="password" name="password" autocomplete="current-password" required></label><br>
                      <button type="submit">Sign in</button>
                    </form></body></html>
                    """);
            return;
        }

        sendHtml(exchange, 200, """
                <!doctype html>
                <html lang="en"><head><meta charset="utf-8"><title>Account</title></head>
                <body><h1>Welcome, %s</h1><p>Your session is authenticated.</p>
                <form method="post" action="/logout"><button type="submit">Sign out</button></form>
                </body></html>
                """.formatted(escapeHtml(session.username())));
    }

    private static void handleLogin(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            methodNotAllowed(exchange, "POST");
            return;
        }

        Map<String, String> form;
        try {
            form = parseForm(readLimited(exchange.getRequestBody()));
        } catch (IllegalArgumentException e) {
            sendText(exchange, 400, "Invalid form submission.");
            return;
        }

        String username = form.getOrDefault("username", "");
        char[] suppliedPassword = form.getOrDefault("password", "").toCharArray();
        boolean usernameMatches = MessageDigest.isEqual(
                username.getBytes(StandardCharsets.UTF_8),
                configuredUsername.getBytes(StandardCharsets.UTF_8));
        boolean passwordMatches;
        try {
            passwordMatches = MessageDigest.isEqual(
                    hashPassword(suppliedPassword, passwordSalt), configuredPasswordHash);
        } catch (Exception e) {
            sendText(exchange, 500, "Unable to verify credentials.");
            return;
        } finally {
            java.util.Arrays.fill(suppliedPassword, '\0');
        }

        if (!usernameMatches || !passwordMatches) {
            sendText(exchange, 401, "Invalid username or password.");
            return;
        }

        // Rotate any existing session and issue a fresh, unguessable identifier.
        removeCurrentSession(exchange);
        String sessionId = newSessionId();
        SESSIONS.put(sessionId, new Session(configuredUsername, Instant.now().plus(SESSION_LIFETIME)));
        exchange.getResponseHeaders().add("Set-Cookie", sessionCookie(sessionId));
        redirect(exchange, "/");
    }

    private static void handleLogout(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            methodNotAllowed(exchange, "POST");
            return;
        }
        removeCurrentSession(exchange);
        exchange.getResponseHeaders().add("Set-Cookie", expiredSessionCookie());
        redirect(exchange, "/");
    }

    private static Session currentSession(HttpExchange exchange) {
        String id = cookieValue(exchange, COOKIE_NAME);
        if (id == null) return null;
        Session session = SESSIONS.get(id);
        if (session == null) return null;
        if (session.expiresAt().isBefore(Instant.now())) {
            SESSIONS.remove(id);
            return null;
        }
        return session;
    }

    private static void removeCurrentSession(HttpExchange exchange) {
        String id = cookieValue(exchange, COOKIE_NAME);
        if (id != null) SESSIONS.remove(id);
    }

    private static String cookieValue(HttpExchange exchange, String name) {
        for (String header : exchange.getRequestHeaders().getOrDefault("Cookie", java.util.List.of())) {
            for (String part : header.split(";")) {
                String[] pair = part.trim().split("=", 2);
                if (pair.length == 2 && pair[0].equals(name)) return pair[1];
            }
        }
        return null;
    }

    private static String sessionCookie(String value) {
        return COOKIE_NAME + "=" + value + "; Path=/; HttpOnly; SameSite=Strict; Max-Age="
                + SESSION_LIFETIME.toSeconds() + (secureCookie ? "; Secure" : "");
    }

    private static String expiredSessionCookie() {
        return COOKIE_NAME + "=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
                + (secureCookie ? "; Secure" : "");
    }

    private static String newSessionId() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static byte[] hashPassword(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, 210_000, 256);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private static byte[] readLimited(InputStream input) throws IOException {
        byte[] body = input.readNBytes(MAX_REQUEST_BYTES + 1);
        if (body.length > MAX_REQUEST_BYTES) throw new IllegalArgumentException("request too large");
        return body;
    }

    private static Map<String, String> parseForm(byte[] body) {
        Map<String, String> values = new HashMap<>();
        String text = new String(body, StandardCharsets.UTF_8);
        for (String field : text.split("&")) {
            String[] pair = field.split("=", 2);
            if (pair.length == 2) {
                values.put(decode(pair[0]), decode(pair[1]));
            }
        }
        return values;
    }

    private static String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static String escapeHtml(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
    }

    private static void redirect(HttpExchange exchange, String location) throws IOException {
        addSecurityHeaders(exchange.getResponseHeaders());
        exchange.getResponseHeaders().set("Location", location);
        exchange.sendResponseHeaders(303, -1);
        exchange.close();
    }

    private static void methodNotAllowed(HttpExchange exchange, String allowed) throws IOException {
        exchange.getResponseHeaders().set("Allow", allowed);
        sendText(exchange, 405, "Method not allowed.");
    }

    private static void sendText(HttpExchange exchange, int status, String text) throws IOException {
        send(exchange, status, "text/plain; charset=utf-8", text);
    }

    private static void sendHtml(HttpExchange exchange, int status, String html) throws IOException {
        send(exchange, status, "text/html; charset=utf-8", html);
    }

    private static void send(HttpExchange exchange, int status, String contentType, String body)
            throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", contentType);
        addSecurityHeaders(headers);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }

    private static void addSecurityHeaders(Headers headers) {
        headers.set("Cache-Control", "no-store");
        headers.set("Content-Security-Policy", "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
        headers.set("X-Content-Type-Options", "nosniff");
    }

    private static String envOrDefault(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }

    private record Session(String username, Instant expiresAt) { }
}
