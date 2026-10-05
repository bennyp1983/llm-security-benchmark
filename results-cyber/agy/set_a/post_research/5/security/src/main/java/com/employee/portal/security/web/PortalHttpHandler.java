package com.employee.portal.security.web;

import com.employee.portal.security.crypto.SecureTokenGenerator;
import com.employee.portal.security.model.AuthenticationResult;
import com.employee.portal.security.model.Session;
import com.employee.portal.security.service.AuthenticationService;
import com.employee.portal.security.validation.InputValidator;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * HTTP handler for employee portal authentication endpoints.
 * Handles /api/login, /api/dashboard, /api/logout.
 * Strictly adheres to Rule 1 (bound input sizes, validate all headers/body),
 * Rule 4 (HttpOnly, Secure, SameSite=Strict cookies),
 * Rule 5 (wipes password from memory), and Rule 6 (generic error messages).
 */
public final class PortalHttpHandler implements HttpHandler {

    private static final int MAX_REQUEST_BODY_BYTES = 4096; // Bound input size (Rule 1 & 5)

    private final AuthenticationService authService;
    private final boolean requireSecureCookies;

    public PortalHttpHandler(AuthenticationService authService, boolean requireSecureCookies) {
        this.authService = authService;
        this.requireSecureCookies = requireSecureCookies;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        // Enforce strict security headers on all HTTP responses
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.getResponseHeaders().set("X-Frame-Options", "DENY");
        exchange.getResponseHeaders().set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none';");
        exchange.getResponseHeaders().set("Cache-Control", "no-store, no-cache, must-revalidate, private");
        exchange.getResponseHeaders().set("Pragma", "no-cache");
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");

        String path = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod().toUpperCase();
        String clientIp = extractClientIp(exchange);

        try {
            if ("/api/login".equals(path) && "POST".equals(method)) {
                handleLogin(exchange, clientIp);
            } else if ("/api/dashboard".equals(path) && "GET".equals(method)) {
                handleDashboard(exchange, clientIp);
            } else if ("/api/logout".equals(path) && "POST".equals(method)) {
                handleLogout(exchange);
            } else {
                sendJsonResponse(exchange, 404, "{\"error\":\"Not Found\"}");
            }
        } catch (Exception e) {
            sendJsonResponse(exchange, 500, "{\"error\":\"Internal Server Error\"}");
        }
    }

    private void handleLogin(HttpExchange exchange, String clientIp) throws IOException {
        byte[] body = readBoundedBody(exchange.getRequestBody(), MAX_REQUEST_BODY_BYTES);
        if (body == null) {
            sendJsonResponse(exchange, 400, "{\"error\":\"Payload Too Large or Invalid\"}");
            return;
        }

        Map<String, char[]> params = parseFormData(body);
        char[] usernameChars = params.get("username");
        char[] passwordChars = params.get("password");

        try {
            if (usernameChars == null || passwordChars == null) {
                sendJsonResponse(exchange, 400, "{\"error\":\"Missing username or password\"}");
                return;
            }

            String username = new String(usernameChars);
            AuthenticationResult result = authService.authenticate(username, passwordChars, clientIp);

            if (result.isSuccess() && result.getSession().isPresent()) {
                // Rule 4: Attach cookie header
                if (result.getCookieHeader().isPresent()) {
                    exchange.getResponseHeaders().add("Set-Cookie", result.getCookieHeader().get());
                }
                Session session = result.getSession().get();
                String responseJson = String.format(
                        "{\"status\":\"success\",\"message\":\"%s\",\"user\":\"%s\",\"role\":\"%s\"}",
                        InputValidator.escapeHtml(result.getMessage()),
                        InputValidator.escapeHtml(session.getUsername()),
                        InputValidator.escapeHtml(session.getRole())
                );
                sendJsonResponse(exchange, 200, responseJson);
            } else {
                // Rule 6: Generic failure message
                String responseJson = String.format(
                        "{\"status\":\"error\",\"message\":\"%s\"}",
                        InputValidator.escapeHtml(AuthenticationResult.GENERIC_FAILURE_MESSAGE)
                );
                sendJsonResponse(exchange, 401, responseJson);
            }
        } finally {
            // Rule 5: Clear credential characters from memory
            if (usernameChars != null) Arrays.fill(usernameChars, '\0');
            if (passwordChars != null) Arrays.fill(passwordChars, '\0');
            for (char[] val : params.values()) {
                Arrays.fill(val, '\0');
            }
        }
    }

    private void handleDashboard(HttpExchange exchange, String clientIp) throws IOException {
        String sessionToken = extractSessionCookie(exchange);
        if (sessionToken == null) {
            sendJsonResponse(exchange, 401, "{\"error\":\"Unauthorized: No active session\"}");
            return;
        }

        Optional<Session> maybeSession = authService.getSessionManager().validateSession(sessionToken, clientIp);
        if (maybeSession.isEmpty()) {
            sendJsonResponse(exchange, 401, "{\"error\":\"Unauthorized: Session expired or invalid\"}");
            return;
        }

        Session session = maybeSession.get();
        String json = String.format(
                "{\"status\":\"active\",\"username\":\"%s\",\"role\":\"%s\",\"sourceIp\":\"%s\"}",
                InputValidator.escapeHtml(session.getUsername()),
                InputValidator.escapeHtml(session.getRole()),
                InputValidator.escapeHtml(session.getSourceIp())
        );
        sendJsonResponse(exchange, 200, json);
    }

    private void handleLogout(HttpExchange exchange) throws IOException {
        String sessionToken = extractSessionCookie(exchange);
        if (sessionToken != null) {
            authService.getSessionManager().revokeSession(sessionToken);
        }
        // Invalidate cookie header
        String logoutCookie = SecureTokenGenerator.buildLogoutCookieHeader(requireSecureCookies);
        exchange.getResponseHeaders().add("Set-Cookie", logoutCookie);
        sendJsonResponse(exchange, 200, "{\"status\":\"success\",\"message\":\"Logged out successfully\"}");
    }

    private String extractClientIp(HttpExchange exchange) {
        InetSocketAddress remote = exchange.getRemoteAddress();
        if (remote != null && remote.getAddress() != null) {
            return remote.getAddress().getHostAddress();
        }
        return "127.0.0.1";
    }

    private String extractSessionCookie(HttpExchange exchange) {
        String cookieHeader = exchange.getRequestHeaders().getFirst("Cookie");
        if (cookieHeader == null || cookieHeader.isBlank()) {
            return null;
        }
        String cookieName = requireSecureCookies ? "__Host-session" : "portal_session";
        String[] cookies = cookieHeader.split(";");
        for (String c : cookies) {
            String[] parts = c.trim().split("=", 2);
            if (parts.length == 2 && (parts[0].equals(cookieName) || parts[0].equals("__Host-session") || parts[0].equals("portal_session"))) {
                return parts[1].trim();
            }
        }
        return null;
    }

    private byte[] readBoundedBody(InputStream is, int maxBytes) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int totalRead = 0;
        int read;
        while ((read = is.read(buffer)) != -1) {
            totalRead += read;
            if (totalRead > maxBytes) {
                return null; // Bound exceeded
            }
            baos.write(buffer, 0, read);
        }
        return baos.toByteArray();
    }

    private Map<String, char[]> parseFormData(byte[] body) {
        Map<String, char[]> map = new HashMap<>();
        String raw = new String(body, StandardCharsets.UTF_8);
        String[] pairs = raw.split("&");
        for (String pair : pairs) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String val = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    map.put(key, val.toCharArray());
                } catch (Exception ignored) {}
            }
        }
        return map;
    }

    private void sendJsonResponse(HttpExchange exchange, int statusCode, String jsonResponse) throws IOException {
        byte[] responseBytes = jsonResponse.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(statusCode, responseBytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }
}
