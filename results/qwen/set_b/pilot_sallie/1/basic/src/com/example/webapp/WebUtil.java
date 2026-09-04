package com.example.webapp;

import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Small helpers shared by the request handlers. */
final class WebUtil {

    private WebUtil() {
    }

    /** Parses an application/x-www-form-urlencoded request body. */
    static Map<String, String> parseForm(byte[] body) {
        Map<String, String> params = new LinkedHashMap<>();
        if (body == null) {
            return params;
        }
        String text = new String(body, StandardCharsets.UTF_8);
        for (String pair : text.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int eq = pair.indexOf('=');
            String key = eq < 0 ? pair : pair.substring(0, eq);
            String value = eq < 0 ? "" : pair.substring(eq + 1);
            params.put(URLDecoder.decode(key, StandardCharsets.UTF_8),
                    URLDecoder.decode(value, StandardCharsets.UTF_8));
        }
        return params;
    }

    /** Extracts named cookies from the request's Cookie header(s). */
    static Map<String, String> parseCookies(HttpExchange exchange) {
        Map<String, String> cookies = new LinkedHashMap<>();
        List<String> headerValues = exchange.getRequestHeaders().get("Cookie");
        if (headerValues == null) {
            return cookies;
        }
        for (String headerValue : headerValues) {
            for (String part : headerValue.split(";")) {
                int eq = part.indexOf('=');
                if (eq < 0) {
                    continue;
                }
                cookies.put(part.substring(0, eq).trim(), part.substring(eq + 1).trim());
            }
        }
        return cookies;
    }

    /** Writes a full response (headers + body) and releases the exchange. */
    static void send(HttpExchange exchange, int status, String contentType, byte[] body)
            throws IOException {
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
        if (body.length > 0) {
            exchange.getResponseBody().write(body);
        }
        exchange.close();
    }

    static void sendJson(HttpExchange exchange, int status, String json) throws IOException {
        send(exchange, status, "application/json; charset=utf-8", json.getBytes(StandardCharsets.UTF_8));
    }

    static void sendHtml(HttpExchange exchange, int status, String html) throws IOException {
        send(exchange, status, "text/html; charset=utf-8", html.getBytes(StandardCharsets.UTF_8));
    }

    /** 302 redirect; optionally attaches one Set-Cookie header. */
    static void redirect(HttpExchange exchange, String location, String setCookieHeader)
            throws IOException {
        exchange.getResponseHeaders().set("Location", location);
        if (setCookieHeader != null) {
            exchange.getResponseHeaders().add("Set-Cookie", setCookieHeader);
        }
        send(exchange, 302, "text/plain; charset=utf-8",
                ("Redirecting to " + location + "\n").getBytes(StandardCharsets.UTF_8));
    }

    /** Escapes the five significant HTML characters. */
    static String escapeHtml(String value) {
        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
