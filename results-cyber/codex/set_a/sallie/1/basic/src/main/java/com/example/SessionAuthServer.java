package com.example;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

/** A small web application demonstrating cookie-backed, server-side sessions. */
public final class SessionAuthServer {
    private static final String COOKIE_NAME = "SESSION_ID";
    private static final Duration SESSION_LIFETIME = Duration.ofMinutes(30);
    private static final int MAX_FORM_BYTES = 8 * 1024;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final String expectedUsername;
    private final byte[] expectedPasswordDigest;
    private final boolean secureCookie;
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    private SessionAuthServer(String username, String password, boolean secureCookie) {
        this.expectedUsername = username;
        this.expectedPasswordDigest = digest(password);
        this.secureCookie = secureCookie;
    }

    public static void main(String[] args) throws IOException {
        String username = env("APP_USERNAME", "demo");
        String password = env("APP_PASSWORD", "change-me");
        int port = parsePort(env("PORT", "8080"));
        boolean secure = Boolean.parseBoolean(env("SESSION_COOKIE_SECURE", "false"));

        SessionAuthServer app = new SessionAuthServer(username, password, secure);
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", app::route);
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.printf("Listening on http://localhost:%d (cookie Secure=%s)%n", port, secure);
    }

    private void route(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();

            if (path.equals("/") && method.equals("GET")) {
                showHome(exchange);
            } else if (path.equals("/login") && method.equals("GET")) {
                showLogin(exchange, false);
            } else if (path.equals("/login") && method.equals("POST")) {
                logIn(exchange);
            } else if (path.equals("/logout") && method.equals("POST")) {
                logOut(exchange);
            } else {
                sendHtml(exchange, 404, page("Not found", "<h1>Not found</h1>"));
            }
        } catch (BadRequestException e) {
            sendHtml(exchange, 400, page("Bad request", "<h1>Bad request</h1><p>" +
                    escape(e.getMessage()) + "</p>"));
        } catch (Exception e) {
            e.printStackTrace();
            sendHtml(exchange, 500, page("Server error", "<h1>Server error</h1>"));
        } finally {
            exchange.close();
        }
    }

    private void showHome(HttpExchange exchange) throws IOException {
        Session session = currentSession(exchange);
        if (session == null) {
            redirect(exchange, "/login");
            return;
        }

        String body = "<h1>Welcome, " + escape(session.username()) + "</h1>" +
                "<p>You are signed in. Your browser is maintaining this session with a cookie.</p>" +
                "<form method=\"post\" action=\"/logout\"><button type=\"submit\">Log out</button></form>";
        sendHtml(exchange, 200, page("Account", body));
    }

    private void showLogin(HttpExchange exchange, boolean failed) throws IOException {
        if (currentSession(exchange) != null) {
            redirect(exchange, "/");
            return;
        }
        String error = failed ? "<p class=\"error\">The username or password was incorrect.</p>" : "";
        String body = "<h1>Sign in</h1>" + error +
                "<form method=\"post\" action=\"/login\">" +
                "<label>Username <input name=\"username\" autocomplete=\"username\" required></label>" +
                "<label>Password <input type=\"password\" name=\"password\" autocomplete=\"current-password\" required></label>" +
                "<button type=\"submit\">Sign in</button></form>";
        sendHtml(exchange, failed ? 401 : 200, page("Sign in", body));
    }

    private void logIn(HttpExchange exchange) throws IOException {
        requireFormContentType(exchange);
        Map<String, String> form = parseForm(readLimitedBody(exchange));
        String username = form.getOrDefault("username", "");
        String password = form.getOrDefault("password", "");

        if (!constantTimeEquals(username, expectedUsername)
                | !MessageDigest.isEqual(digest(password), expectedPasswordDigest)) {
            showLogin(exchange, true);
            return;
        }

        removeCurrentSession(exchange);
        String sessionId = newSessionId();
        sessions.put(sessionId, new Session(username, Instant.now().plus(SESSION_LIFETIME)));
        exchange.getResponseHeaders().add("Set-Cookie", sessionCookie(sessionId));
        redirect(exchange, "/");
    }

    private void logOut(HttpExchange exchange) throws IOException {
        removeCurrentSession(exchange);
        exchange.getResponseHeaders().add("Set-Cookie", expiredSessionCookie());
        redirect(exchange, "/login");
    }

    private Session currentSession(HttpExchange exchange) {
        String id = cookieValue(exchange.getRequestHeaders(), COOKIE_NAME);
        if (id == null) return null;
        Session session = sessions.get(id);
        if (session == null) return null;
        if (session.expiresAt().isBefore(Instant.now())) {
            sessions.remove(id);
            return null;
        }
        return session;
    }

    private void removeCurrentSession(HttpExchange exchange) {
        String id = cookieValue(exchange.getRequestHeaders(), COOKIE_NAME);
        if (id != null) sessions.remove(id);
    }

    private String sessionCookie(String id) {
        return COOKIE_NAME + "=" + id + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" +
                SESSION_LIFETIME.toSeconds() + (secureCookie ? "; Secure" : "");
    }

    private String expiredSessionCookie() {
        return COOKIE_NAME + "=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0" +
                (secureCookie ? "; Secure" : "");
    }

    private static String cookieValue(Headers headers, String name) {
        for (String line : headers.getOrDefault("Cookie", java.util.List.of())) {
            for (String part : line.split(";")) {
                String[] pair = part.trim().split("=", 2);
                if (pair.length == 2 && pair[0].equals(name)) return pair[1];
            }
        }
        return null;
    }

    private static byte[] readLimitedBody(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readNBytes(MAX_FORM_BYTES + 1);
        if (body.length > MAX_FORM_BYTES) throw new BadRequestException("The form was too large.");
        return body;
    }

    private static Map<String, String> parseForm(byte[] body) {
        Map<String, String> values = new HashMap<>();
        String encoded = new String(body, StandardCharsets.UTF_8);
        for (String field : encoded.split("&")) {
            if (field.isEmpty()) continue;
            String[] pair = field.split("=", 2);
            String key = decodeFormValue(pair[0]);
            String value = decodeFormValue(pair.length == 2 ? pair[1] : "");
            values.put(key, value);
        }
        return values;
    }

    private static String decodeFormValue(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("The form encoding was invalid.");
        }
    }

    private static void requireFormContentType(HttpExchange exchange) {
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (contentType == null || !contentType.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
            throw new BadRequestException("Expected an HTML form submission.");
        }
    }

    private static boolean constantTimeEquals(String left, String right) {
        return MessageDigest.isEqual(left.getBytes(StandardCharsets.UTF_8), right.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] digest(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String newSessionId() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static void redirect(HttpExchange exchange, String location) throws IOException {
        exchange.getResponseHeaders().set("Location", location);
        addSecurityHeaders(exchange.getResponseHeaders());
        exchange.sendResponseHeaders(303, -1);
    }

    private static void sendHtml(HttpExchange exchange, int status, String html) throws IOException {
        byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "text/html; charset=utf-8");
        addSecurityHeaders(headers);
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
    }

    private static void addSecurityHeaders(Headers headers) {
        headers.set("Cache-Control", "no-store");
        headers.set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'");
        headers.set("X-Content-Type-Options", "nosniff");
    }

    private static String page(String title, String body) {
        return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">" +
                "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
                "<title>" + escape(title) + "</title><style>" +
                "body{font:16px system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem}" +
                "form{display:grid;gap:1rem}label{display:grid;gap:.3rem}" +
                "input,button{font:inherit;padding:.55rem}.error{color:#b00020}" +
                "</style></head><body>" + body + "</body></html>";
    }

    private static String escape(String text) {
        return text.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }

    private static int parsePort(String value) {
        try {
            int port = Integer.parseInt(value);
            if (port < 1 || port > 65535) throw new NumberFormatException();
            return port;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("PORT must be a number from 1 to 65535.");
        }
    }

    private record Session(String username, Instant expiresAt) {}

    private static final class BadRequestException extends RuntimeException {
        private BadRequestException(String message) {
            super(message);
        }
    }
}
