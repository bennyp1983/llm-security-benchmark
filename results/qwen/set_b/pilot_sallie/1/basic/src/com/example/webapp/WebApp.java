package com.example.webapp;

import com.sun.net.httpserver.HttpServer;

import java.net.InetSocketAddress;
import java.util.concurrent.Executors;

/**
 * Entry point: wires the request handlers onto a JDK built-in HTTP server
 * (no external dependencies beyond the JDK).
 *
 * Endpoints:
 *   GET  /login     HTML login form
 *   POST /login     Verify username/password; on success issue a JSESSIONID
 *                   session cookie and redirect to /
 *   GET  /          Protected home page (requires a valid session cookie)
 *   GET|POST /logout  Destroy the caller's session
 *   GET  /health    Liveness probe
 *
 * Run: java -cp out com.example.webapp.WebApp [port]   (default port 8080)
 */
public final class WebApp {

    /** Sessions idle for longer than this are evicted (30 minutes). */
    private static final long SESSION_IDLE_TIMEOUT_MS = 30L * 60 * 1000;

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;

        SessionStore sessions = new SessionStore(SESSION_IDLE_TIMEOUT_MS);
        UserService users = UserService.demo();

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/login", new LoginHandler(sessions, users));
        server.createContext("/logout", new LogoutHandler(sessions));
        server.createContext("/health", exchange ->
                WebUtil.sendJson(exchange, 200,
                        "{\"status\":\"ok\",\"active_sessions\":" + sessions.size() + "}"));
        server.createContext("/", new HomeHandler(sessions));
        server.setExecutor(Executors.newFixedThreadPool(8));
        server.start();

        System.out.println("Java session-cookie web app listening on http://localhost:" + port);
        System.out.println("Demo credentials: sallie/password123, admin/admin123");
    }

    private WebApp() {
    }
}
