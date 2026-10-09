import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.ConsoleHandler;
import java.util.logging.Formatter;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * AuthApplication - Standalone Java Web Application Demonstrating
 * Secure User Authentication and Session Cookie Management.
 *
 * Requirements addressed:
 * 1. Accepts username and password input.
 * 2. Verifies user credentials using PBKDF2 with salted password hashing.
 * 3. Issues secure session cookies upon successful login (HttpOnly, SameSite=Strict).
 * 4. Maintains authenticated state via session cookies across requests.
 * 5. Provides secure session invalidation on logout.
 */
public class AuthApplication {

    private static final Logger LOGGER = Logger.getLogger(AuthApplication.class.getName());
    public static final String COOKIE_NAME = "SESSIONID";
    public static final int DEFAULT_PORT = 8080;
    public static final int SESSION_MAX_AGE_SECONDS = 1800; // 30 minutes

    private final HttpServer server;
    private final UserManager userManager;
    private final SessionManager sessionManager;
    private final int port;

    public AuthApplication(int port) throws IOException {
        this.port = port;
        this.userManager = new UserManager();
        this.sessionManager = new SessionManager(Duration.ofSeconds(SESSION_MAX_AGE_SECONDS), Duration.ofHours(12));

        // Create HTTP server listening on all network interfaces
        this.server = HttpServer.create(new InetSocketAddress(port), 0);

        // Register HTTP endpoints
        server.createContext("/", new RootHandler());
        server.createContext("/login", new LoginHandler());
        server.createContext("/dashboard", new DashboardHandler());
        server.createContext("/logout", new LogoutHandler());
        server.createContext("/api/login", new ApiLoginHandler());
        server.createContext("/api/session", new ApiSessionHandler());
        server.createContext("/api/logout", new ApiLogoutHandler());

        // Thread pool executor for incoming requests
        server.setExecutor(Executors.newFixedThreadPool(10));
    }

    public void start() {
        server.start();
        LOGGER.info("==================================================================");
        LOGGER.info("  Java Authentication & Session Web Application Started");
        LOGGER.info("  Listening URL: http://localhost:" + port);
        LOGGER.info("  Login Page:    http://localhost:" + port + "/login");
        LOGGER.info("  Dashboard:     http://localhost:" + port + "/dashboard");
        LOGGER.info("  API Login:     POST http://localhost:" + port + "/api/login");
        LOGGER.info("  API Session:   GET  http://localhost:" + port + "/api/session");
        LOGGER.info("  API Logout:    POST http://localhost:" + port + "/api/logout");
        LOGGER.info("==================================================================");
        LOGGER.info("  Preconfigured Demo Credentials:");
        for (User user : userManager.getAllUsers()) {
            LOGGER.info(String.format("   - Username: %-10s | Password: %-16s | Role: %s",
                    user.getUsername(), user.getDemoPassword(), user.getRole()));
        }
        LOGGER.info("==================================================================");
    }

    public void stop() {
        LOGGER.info("Stopping HTTP server and session manager...");
        sessionManager.shutdown();
        server.stop(1);
        LOGGER.info("Server stopped.");
    }

    public static void main(String[] args) {
        setupLogging();

        int port = DEFAULT_PORT;
        if (args.length > 0) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException e) {
                LOGGER.warning("Invalid port argument '" + args[0] + "', defaulting to " + DEFAULT_PORT);
            }
        } else {
            String envPort = System.getenv("PORT");
            if (envPort != null && !envPort.trim().isEmpty()) {
                try {
                    port = Integer.parseInt(envPort.trim());
                } catch (NumberFormatException ignored) {}
            }
        }

        try {
            AuthApplication app = new AuthApplication(port);
            app.start();

            // Register shutdown hook for graceful exit
            Runtime.getRuntime().addShutdownHook(new Thread(app::stop));
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to start server on port " + port, e);
            System.exit(1);
        }
    }

    // ------------------------------------------------------------------------
    // HTTP Handlers
    // ------------------------------------------------------------------------

    /**
     * Root Handler: Redirects authenticated users to /dashboard, otherwise /login.
     */
    private class RootHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod().toUpperCase();
            if (!"GET".equals(method) && !"HEAD".equals(method)) {
                sendMethodNotAllowed(exchange, "GET, HEAD");
                return;
            }

            String sessionId = getSessionIdFromCookie(exchange);
            Optional<Session> session = sessionManager.getValidSession(sessionId);

            if (session.isPresent()) {
                sendRedirect(exchange, "/dashboard");
            } else {
                sendRedirect(exchange, "/login");
            }
        }
    }

    /**
     * Login Handler:
     * - GET: Displays the login HTML form (or redirects to /dashboard if already logged in).
     * - POST: Verifies username and password, sets session cookie on success, redirects to /dashboard.
     */
    private class LoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod().toUpperCase();

            if ("GET".equals(method) || "HEAD".equals(method)) {
                handleGet(exchange);
            } else if ("POST".equals(method)) {
                handlePost(exchange);
            } else {
                sendMethodNotAllowed(exchange, "GET, HEAD, POST");
            }
        }

        private void handleGet(HttpExchange exchange) throws IOException {
            String sessionId = getSessionIdFromCookie(exchange);
            Optional<Session> session = sessionManager.getValidSession(sessionId);

            // If already authenticated, redirect directly to dashboard
            if (session.isPresent()) {
                sendRedirect(exchange, "/dashboard");
                return;
            }

            Map<String, String> queryParams = parseQueryParams(exchange.getRequestURI().getRawQuery());
            String error = queryParams.get("error");
            boolean loggedOut = "true".equalsIgnoreCase(queryParams.get("logout"));

            String html = Views.renderLoginPage(error, loggedOut, userManager.getAllUsers());
            sendHtmlResponse(exchange, 200, html);
        }

        private void handlePost(HttpExchange exchange) throws IOException {
            String requestBody = readRequestBody(exchange);
            Map<String, String> params = parseBodyParams(exchange, requestBody);

            String username = params.getOrDefault("username", "").trim();
            String password = params.getOrDefault("password", "");

            String clientIp = getClientIp(exchange);
            String userAgent = exchange.getRequestHeaders().getFirst("User-Agent");

            LOGGER.info(String.format("[LOGIN ATTEMPT] Username='%s' from IP=%s", username, clientIp));

            Optional<User> user = userManager.authenticate(username, password);

            if (user.isPresent()) {
                // Successful verification: create server session
                Session newSession = sessionManager.createSession(user.get().getUsername(), clientIp, userAgent);
                LOGGER.info(String.format("[AUTH SUCCESS] User '%s' authenticated. Session ID: %s",
                        username, newSession.getId()));

                // Issue secure session cookie
                String cookieHeader = buildSetCookieHeader(newSession.getId(), SESSION_MAX_AGE_SECONDS);
                exchange.getResponseHeaders().add("Set-Cookie", cookieHeader);

                // Redirect to protected dashboard
                sendRedirect(exchange, "/dashboard");
            } else {
                LOGGER.warning(String.format("[AUTH FAILURE] Failed login attempt for username '%s' from IP=%s",
                        username, clientIp));

                // Redirect back to login page with error indicator
                sendRedirect(exchange, "/login?error=invalid_credentials");
            }
        }
    }

    /**
     * Dashboard Handler:
     * - Protected resource requiring valid session cookie.
     * - GET: Validates session cookie, updates access time, renders dashboard with user info.
     */
    private class DashboardHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod().toUpperCase();
            if (!"GET".equals(method) && !"HEAD".equals(method)) {
                sendMethodNotAllowed(exchange, "GET, HEAD");
                return;
            }

            String sessionId = getSessionIdFromCookie(exchange);
            Optional<Session> sessionOpt = sessionManager.getValidSession(sessionId);

            if (sessionOpt.isEmpty()) {
                LOGGER.info("[ACCESS DENIED] Unauthenticated request to /dashboard. Redirecting to /login.");
                // If invalid or missing session cookie, redirect to login
                sendRedirect(exchange, "/login?error=unauthorized");
                return;
            }

            Session session = sessionOpt.get();
            User user = userManager.findByUsername(session.getUsername())
                    .orElse(new User(session.getUsername(), "", "User", "Standard"));

            String html = Views.renderDashboardPage(user, session);
            sendHtmlResponse(exchange, 200, html);
        }
    }

    /**
     * Logout Handler:
     * - Invalidates session in session store.
     * - Clears the session cookie in the browser (Max-Age=0).
     * - Redirects to /login?logout=true.
     */
    private class LogoutHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String sessionId = getSessionIdFromCookie(exchange);
            if (sessionId != null) {
                LOGGER.info("[LOGOUT] Invalidating session ID: " + sessionId);
                sessionManager.invalidateSession(sessionId);
            }

            // Instruct browser to delete the cookie
            String clearCookieHeader = buildClearCookieHeader();
            exchange.getResponseHeaders().add("Set-Cookie", clearCookieHeader);

            sendRedirect(exchange, "/login?logout=true");
        }
    }

    /**
     * API Login Handler: Programmatic JSON login endpoint.
     */
    private class ApiLoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                sendMethodNotAllowed(exchange, "POST");
                return;
            }

            String body = readRequestBody(exchange);
            Map<String, String> params = parseBodyParams(exchange, body);
            String username = params.getOrDefault("username", "").trim();
            String password = params.getOrDefault("password", "");

            String clientIp = getClientIp(exchange);
            String userAgent = exchange.getRequestHeaders().getFirst("User-Agent");

            Optional<User> userOpt = userManager.authenticate(username, password);
            if (userOpt.isPresent()) {
                Session session = sessionManager.createSession(username, clientIp, userAgent);
                String cookieHeader = buildSetCookieHeader(session.getId(), SESSION_MAX_AGE_SECONDS);
                exchange.getResponseHeaders().add("Set-Cookie", cookieHeader);

                String jsonResponse = String.format(
                        "{\"success\":true,\"message\":\"Authentication successful\",\"username\":\"%s\",\"sessionId\":\"%s\"}",
                        escapeJson(username), session.getId());
                sendJsonResponse(exchange, 200, jsonResponse);
            } else {
                String jsonResponse = "{\"success\":false,\"message\":\"Invalid username or password\"}";
                sendJsonResponse(exchange, 401, jsonResponse);
            }
        }
    }

    /**
     * API Session Handler: Returns current authenticated session details.
     */
    private class ApiSessionHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod().toUpperCase();
            if (!"GET".equals(method) && !"HEAD".equals(method)) {
                sendMethodNotAllowed(exchange, "GET, HEAD");
                return;
            }

            String sessionId = getSessionIdFromCookie(exchange);
            Optional<Session> sessionOpt = sessionManager.getValidSession(sessionId);

            if (sessionOpt.isPresent()) {
                Session s = sessionOpt.get();
                User u = userManager.findByUsername(s.getUsername()).orElse(null);
                String role = u != null ? u.getRole() : "User";
                String fullName = u != null ? u.getFullName() : s.getUsername();

                String json = String.format(
                        "{\"authenticated\":true,\"username\":\"%s\",\"fullName\":\"%s\",\"role\":\"%s\",\"sessionId\":\"%s\",\"createdAt\":\"%s\",\"lastAccessedAt\":\"%s\"}",
                        escapeJson(s.getUsername()), escapeJson(fullName), escapeJson(role),
                        s.getId(), s.getCreatedAt().toString(), s.getLastAccessedAt().toString());
                sendJsonResponse(exchange, 200, json);
            } else {
                sendJsonResponse(exchange, 401, "{\"authenticated\":false,\"message\":\"No valid active session found\"}");
            }
        }
    }

    /**
     * API Logout Handler: Programmatic JSON logout endpoint.
     */
    private class ApiLogoutHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                sendMethodNotAllowed(exchange, "POST");
                return;
            }

            String sessionId = getSessionIdFromCookie(exchange);
            if (sessionId != null) {
                sessionManager.invalidateSession(sessionId);
            }

            exchange.getResponseHeaders().add("Set-Cookie", buildClearCookieHeader());
            sendJsonResponse(exchange, 200, "{\"success\":true,\"message\":\"Session invalidated and cookie cleared\"}");
        }
    }

    // ------------------------------------------------------------------------
    // Cookie & Request Utilities
    // ------------------------------------------------------------------------

    public static String getSessionIdFromCookie(HttpExchange exchange) {
        Headers headers = exchange.getRequestHeaders();
        List<String> cookieHeaders = headers.get("Cookie");
        if (cookieHeaders == null || cookieHeaders.isEmpty()) {
            return null;
        }

        for (String cookieLine : cookieHeaders) {
            String[] cookies = cookieLine.split(";");
            for (String cookie : cookies) {
                String[] pair = cookie.trim().split("=", 2);
                if (pair.length == 2 && COOKIE_NAME.equalsIgnoreCase(pair[0].trim())) {
                    return pair[1].trim();
                }
            }
        }
        return null;
    }

    /**
     * Constructs a secure Set-Cookie header string:
     * - HttpOnly: Inaccessible to client JavaScript, mitigating XSS session theft.
     * - SameSite=Strict: Protects against Cross-Site Request Forgery (CSRF).
     * - Path=/: Ensures cookie is sent for all paths in the web application.
     * - Max-Age: Specifies duration in seconds.
     */
    public static String buildSetCookieHeader(String sessionId, int maxAgeSeconds) {
        return String.format("%s=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict",
                COOKIE_NAME, sessionId, maxAgeSeconds);
    }

    public static String buildClearCookieHeader() {
        return String.format("%s=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
                COOKIE_NAME);
    }

    private static String getClientIp(HttpExchange exchange) {
        String xForwardedFor = exchange.getRequestHeaders().getFirst("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.trim().isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return exchange.getRemoteAddress().getAddress().getHostAddress();
    }

    private static String readRequestBody(HttpExchange exchange) throws IOException {
        InputStream is = exchange.getRequestBody();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = is.read(buffer)) != -1) {
            baos.write(buffer, 0, bytesRead);
        }
        return baos.toString(StandardCharsets.UTF_8);
    }

    private static Map<String, String> parseBodyParams(HttpExchange exchange, String body) {
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (contentType != null && contentType.toLowerCase().contains("application/json")) {
            return parseJsonParams(body);
        }
        return parseUrlEncodedParams(body);
    }

    public static Map<String, String> parseUrlEncodedParams(String body) {
        Map<String, String> map = new HashMap<>();
        if (body == null || body.trim().isEmpty()) {
            return map;
        }
        String[] pairs = body.split("&");
        for (String pair : pairs) {
            String[] kv = pair.split("=", 2);
            if (kv.length > 0) {
                String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                String val = kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "";
                map.put(key, val);
            }
        }
        return map;
    }

    public static Map<String, String> parseJsonParams(String json) {
        Map<String, String> map = new HashMap<>();
        if (json == null || json.trim().isEmpty()) {
            return map;
        }
        Pattern pattern = Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"([^\"]*)\"");
        Matcher matcher = pattern.matcher(json);
        while (matcher.find()) {
            map.put(matcher.group(1), matcher.group(2));
        }
        return map;
    }

    public static Map<String, String> parseQueryParams(String query) {
        Map<String, String> map = new HashMap<>();
        if (query == null || query.trim().isEmpty()) {
            return map;
        }
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            String[] kv = pair.split("=", 2);
            if (kv.length > 0) {
                String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                String val = kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "";
                map.put(key, val);
            }
        }
        return map;
    }

    private static void sendRedirect(HttpExchange exchange, String location) throws IOException {
        exchange.getResponseHeaders().set("Location", location);
        exchange.getResponseHeaders().set("Cache-Control", "no-cache, no-store, must-revalidate");
        exchange.sendResponseHeaders(302, -1);
        exchange.close();
    }

    private static void sendHtmlResponse(HttpExchange exchange, int statusCode, String html) throws IOException {
        byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
        exchange.getResponseHeaders().set("Cache-Control", "no-cache, no-store, must-revalidate");
        if ("HEAD".equalsIgnoreCase(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(statusCode, -1);
            exchange.close();
        } else {
            exchange.sendResponseHeaders(statusCode, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }
    }

    private static void sendJsonResponse(HttpExchange exchange, int statusCode, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.getResponseHeaders().set("Cache-Control", "no-cache, no-store, must-revalidate");
        if ("HEAD".equalsIgnoreCase(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(statusCode, -1);
            exchange.close();
        } else {
            exchange.sendResponseHeaders(statusCode, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }
    }

    private static void sendMethodNotAllowed(HttpExchange exchange, String allowed) throws IOException {
        exchange.getResponseHeaders().set("Allow", allowed);
        String msg = "Method Not Allowed. Allowed methods: " + allowed;
        byte[] bytes = msg.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=UTF-8");
        exchange.sendResponseHeaders(405, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String escapeJson(String input) {
        if (input == null) return "";
        return input.replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\b", "\\b")
                    .replace("\f", "\\f")
                    .replace("\n", "\\n")
                    .replace("\r", "\\r")
                    .replace("\t", "\\t");
    }

    private static void setupLogging() {
        Logger rootLogger = Logger.getLogger("");
        rootLogger.setLevel(Level.INFO);
        for (java.util.logging.Handler handler : rootLogger.getHandlers()) {
            rootLogger.removeHandler(handler);
        }
        ConsoleHandler consoleHandler = new ConsoleHandler();
        consoleHandler.setLevel(Level.INFO);
        consoleHandler.setFormatter(new Formatter() {
            private final DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                    .withZone(ZoneId.systemDefault());

            @Override
            public String format(LogRecord record) {
                return String.format("[%s] [%-7s] %s%n",
                        dtf.format(record.getInstant()),
                        record.getLevel().getName(),
                        record.getMessage());
            }
        });
        rootLogger.addHandler(consoleHandler);
    }

    // ------------------------------------------------------------------------
    // Models & Security Service
    // ------------------------------------------------------------------------

    /**
     * User model representing credentials and profile details.
     */
    public static class User {
        private final String username;
        private final byte[] salt;
        private final byte[] passwordHash;
        private final String fullName;
        private final String role;
        private final String demoPassword; // Kept only for UI convenience in demo

        public User(String username, String plainPassword, String fullName, String role) {
            this.username = username;
            this.fullName = fullName;
            this.role = role;
            this.demoPassword = plainPassword;
            this.salt = SecurityUtils.generateSalt(16);
            this.passwordHash = SecurityUtils.hashPassword(plainPassword, this.salt);
        }

        public String getUsername() { return username; }
        public byte[] getSalt() { return salt; }
        public byte[] getPasswordHash() { return passwordHash; }
        public String getFullName() { return fullName; }
        public String getRole() { return role; }
        public String getDemoPassword() { return demoPassword; }
    }

    /**
     * Session model representing an active authenticated session.
     */
    public static class Session {
        private final String id;
        private final String username;
        private final Instant createdAt;
        private volatile Instant lastAccessedAt;
        private final String clientIp;
        private final String userAgent;

        public Session(String id, String username, String clientIp, String userAgent) {
            this.id = id;
            this.username = username;
            this.createdAt = Instant.now();
            this.lastAccessedAt = this.createdAt;
            this.clientIp = clientIp != null ? clientIp : "unknown";
            this.userAgent = userAgent != null ? userAgent : "unknown";
        }

        public String getId() { return id; }
        public String getUsername() { return username; }
        public Instant getCreatedAt() { return createdAt; }
        public Instant getLastAccessedAt() { return lastAccessedAt; }
        public String getClientIp() { return clientIp; }
        public String getUserAgent() { return userAgent; }

        public void touch() {
            this.lastAccessedAt = Instant.now();
        }

        public boolean isExpired(Duration idleTimeout, Duration maxLifetime) {
            Instant now = Instant.now();
            boolean idleExpired = Duration.between(lastAccessedAt, now).compareTo(idleTimeout) > 0;
            boolean maxLifetimeExpired = Duration.between(createdAt, now).compareTo(maxLifetime) > 0;
            return idleExpired || maxLifetimeExpired;
        }
    }

    /**
     * User Repository and Authentication Service.
     */
    public static class UserManager {
        private final Map<String, User> users = new ConcurrentHashMap<>();

        public UserManager() {
            // Seed initial demo users
            addUser(new User("admin", "AdminPassword123!", "System Administrator", "Administrator"));
            addUser(new User("alice", "AlicePass#2026", "Alice Johnson", "Software Engineer"));
            addUser(new User("bob", "BobSecret99!", "Bob Smith", "Security Analyst"));
        }

        public void addUser(User user) {
            users.put(user.getUsername().toLowerCase(), user);
        }

        public Optional<User> findByUsername(String username) {
            if (username == null) return Optional.empty();
            return Optional.ofNullable(users.get(username.trim().toLowerCase()));
        }

        public Collection<User> getAllUsers() {
            return Collections.unmodifiableCollection(users.values());
        }

        /**
         * Verifies input credentials against stored salted hash.
         */
        public Optional<User> authenticate(String username, String password) {
            if (username == null || password == null || username.trim().isEmpty() || password.isEmpty()) {
                return Optional.empty();
            }

            Optional<User> userOpt = findByUsername(username);
            if (userOpt.isEmpty()) {
                // Perform a dummy hash calculation to defend against timing attacks for non-existent users
                SecurityUtils.hashPassword(password, SecurityUtils.DUMMY_SALT);
                return Optional.empty();
            }

            User user = userOpt.get();
            boolean valid = SecurityUtils.verifyPassword(password, user.getSalt(), user.getPasswordHash());
            return valid ? Optional.of(user) : Optional.empty();
        }
    }

    /**
     * Thread-safe Session Management with expiration and background cleanup.
     */
    public static class SessionManager {
        private final ConcurrentMap<String, Session> activeSessions = new ConcurrentHashMap<>();
        private final Duration idleTimeout;
        private final Duration maxLifetime;
        private final ScheduledExecutorService purgeScheduler;

        public SessionManager(Duration idleTimeout, Duration maxLifetime) {
            this.idleTimeout = idleTimeout;
            this.maxLifetime = maxLifetime;
            this.purgeScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "session-purge-thread");
                t.setDaemon(true);
                return t;
            });
            // Purge expired sessions every 60 seconds
            this.purgeScheduler.scheduleAtFixedRate(this::purgeExpired, 1, 1, TimeUnit.MINUTES);
        }

        public Session createSession(String username, String clientIp, String userAgent) {
            String sessionId = SecurityUtils.generateSecureToken(32);
            Session session = new Session(sessionId, username, clientIp, userAgent);
            activeSessions.put(sessionId, session);
            return session;
        }

        public Optional<Session> getValidSession(String sessionId) {
            if (sessionId == null || sessionId.trim().isEmpty()) {
                return Optional.empty();
            }
            Session session = activeSessions.get(sessionId);
            if (session == null) {
                return Optional.empty();
            }
            if (session.isExpired(idleTimeout, maxLifetime)) {
                activeSessions.remove(sessionId);
                return Optional.empty();
            }
            // Sliding session: record activity
            session.touch();
            return Optional.of(session);
        }

        public void invalidateSession(String sessionId) {
            if (sessionId != null) {
                activeSessions.remove(sessionId);
            }
        }

        public int getActiveSessionCount() {
            return activeSessions.size();
        }

        public void purgeExpired() {
            int before = activeSessions.size();
            activeSessions.entrySet().removeIf(entry -> entry.getValue().isExpired(idleTimeout, maxLifetime));
            int purged = before - activeSessions.size();
            if (purged > 0) {
                LOGGER.info("[SESSION PURGE] Cleaned up " + purged + " expired session(s).");
            }
        }

        public void shutdown() {
            purgeScheduler.shutdownNow();
            activeSessions.clear();
        }
    }

    /**
     * Cryptographic and Security Utilities.
     */
    public static class SecurityUtils {
        private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
        private static final int ITERATIONS = 65536;
        private static final int KEY_LENGTH_BITS = 256;
        private static final SecureRandom SECURE_RANDOM = new SecureRandom();
        public static final byte[] DUMMY_SALT = new byte[16];

        static {
            SECURE_RANDOM.nextBytes(DUMMY_SALT);
        }

        public static byte[] generateSalt(int length) {
            byte[] salt = new byte[length];
            SECURE_RANDOM.nextBytes(salt);
            return salt;
        }

        public static byte[] hashPassword(String password, byte[] salt) {
            try {
                KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH_BITS);
                SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
                return factory.generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IllegalStateException("Cryptographic algorithm unavailable", e);
            }
        }

        public static boolean verifyPassword(String providedPassword, byte[] storedSalt, byte[] storedHash) {
            byte[] computedHash = hashPassword(providedPassword, storedSalt);
            // Constant-time comparison to prevent timing attacks
            return MessageDigest.isEqual(storedHash, computedHash);
        }

        public static String generateSecureToken(int byteLength) {
            byte[] randomBytes = new byte[byteLength];
            SECURE_RANDOM.nextBytes(randomBytes);
            return bytesToHex(randomBytes);
        }

        public static String bytesToHex(byte[] bytes) {
            StringBuilder sb = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        }

        public static String escapeHtml(String input) {
            if (input == null) return "";
            return input.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\"", "&quot;")
                    .replace("'", "&#39;");
        }
    }

    // ------------------------------------------------------------------------
    // HTML Views (Embedded CSS & Templates)
    // ------------------------------------------------------------------------

    public static class Views {
        private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                .withZone(ZoneId.systemDefault());

        private static final String COMMON_CSS =
                "*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }\n" +
                "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;\n" +
                "       background: #f0f2f5; color: #1f2937; line-height: 1.5; min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 20px; }\n" +
                ".card { background: #ffffff; border-radius: 12px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.05);\n" +
                "        width: 100%; max-width: 480px; overflow: hidden; border: 1px solid #e5e7eb; }\n" +
                ".card-wide { max-width: 720px; }\n" +
                ".card-header { background: linear-gradient(135deg, #2563eb, #1d4ed8); color: white; padding: 28px 24px; text-align: center; }\n" +
                ".card-header h1 { font-size: 1.5rem; font-weight: 700; margin-bottom: 6px; }\n" +
                ".card-header p { font-size: 0.875rem; opacity: 0.9; }\n" +
                ".card-body { padding: 28px 24px; }\n" +
                ".form-group { margin-bottom: 20px; }\n" +
                "label { display: block; font-size: 0.875rem; font-weight: 600; color: #374151; margin-bottom: 6px; }\n" +
                "input[type='text'], input[type='password'] {\n" +
                "  width: 100%; padding: 12px 14px; font-size: 0.95rem; border: 1.5px solid #d1d5db; border-radius: 8px;\n" +
                "  outline: none; transition: border-color 0.15s ease, box-shadow 0.15s ease; }\n" +
                "input[type='text']:focus, input[type='password']:focus {\n" +
                "  border-color: #2563eb; box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15); }\n" +
                ".btn { display: inline-flex; align-items: center; justify-content: center; width: 100%;\n" +
                "       padding: 12px 18px; font-size: 1rem; font-weight: 600; border-radius: 8px; border: none; cursor: pointer;\n" +
                "       transition: background-color 0.15s ease, transform 0.05s ease; text-decoration: none; }\n" +
                ".btn-primary { background: #2563eb; color: #ffffff; }\n" +
                ".btn-primary:hover { background: #1d4ed8; }\n" +
                ".btn-danger { background: #dc2626; color: #ffffff; }\n" +
                ".btn-danger:hover { background: #b91c1c; }\n" +
                ".btn:active { transform: translateY(1px); }\n" +
                ".alert { padding: 12px 16px; border-radius: 8px; font-size: 0.875rem; margin-bottom: 20px; display: flex; align-items: center; gap: 10px; }\n" +
                ".alert-error { background: #fee2e2; border: 1px solid #fecaca; color: #991b1b; }\n" +
                ".alert-success { background: #dcfce7; border: 1px solid #bbf7d0; color: #166534; }\n" +
                ".alert-warning { background: #fef3c7; border: 1px solid #fde68a; color: #92400e; }\n" +
                ".credentials-box { margin-top: 24px; padding: 16px; background: #f9fafb; border-radius: 8px; border: 1px dashed #d1d5db; font-size: 0.8125rem; }\n" +
                ".credentials-box h4 { font-size: 0.85rem; font-weight: 600; color: #4b5563; margin-bottom: 10px; text-transform: uppercase; letter-spacing: 0.05em; }\n" +
                ".credentials-table { width: 100%; border-collapse: collapse; text-align: left; }\n" +
                ".credentials-table th, .credentials-table td { padding: 6px 8px; border-bottom: 1px solid #e5e7eb; }\n" +
                ".credentials-table th { color: #6b7280; font-weight: 600; }\n" +
                ".badge { display: inline-block; padding: 2px 8px; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }\n" +
                ".badge-admin { background: #fef3c7; color: #92400e; }\n" +
                ".badge-user { background: #e0e7ff; color: #3730a3; }\n" +
                ".info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }\n" +
                "@media (max-width: 600px) { .info-grid { grid-template-columns: 1fr; } }\n" +
                ".info-tile { background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 14px; }\n" +
                ".info-tile .label { font-size: 0.75rem; text-transform: uppercase; color: #6b7280; font-weight: 600; letter-spacing: 0.05em; margin-bottom: 4px; }\n" +
                ".info-tile .value { font-size: 0.95rem; font-weight: 600; color: #111827; word-break: break-all; }\n" +
                ".cookie-pill { font-family: monospace; font-size: 0.85rem; background: #eef2ff; color: #312e81; padding: 8px 12px; border-radius: 6px; word-break: break-all; border: 1px solid #c7d2fe; margin-top: 6px; }\n" +
                ".footer-note { text-align: center; margin-top: 20px; font-size: 0.75rem; color: #6b7280; }";

        public static String renderLoginPage(String error, boolean loggedOut, Collection<User> demoUsers) {
            StringBuilder sb = new StringBuilder();
            sb.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
            sb.append("<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
            sb.append("<title>Sign In - Secure Java Authentication</title>\n");
            sb.append("<style>\n").append(COMMON_CSS).append("</style>\n</head>\n<body>\n");
            sb.append("<div class=\"card\">\n");
            sb.append("  <div class=\"card-header\">\n");
            sb.append("    <h1>Secure Login</h1>\n");
            sb.append("    <p>Authenticate and establish a secure session cookie</p>\n");
            sb.append("  </div>\n");
            sb.append("  <div class=\"card-body\">\n");

            if (loggedOut) {
                sb.append("    <div class=\"alert alert-success\">\n");
                sb.append("      <span>&#10003;</span> <span>You have been successfully logged out. Your session cookie was cleared.</span>\n");
                sb.append("    </div>\n");
            } else if ("invalid_credentials".equalsIgnoreCase(error)) {
                sb.append("    <div class=\"alert alert-error\">\n");
                sb.append("      <span>&#9888;</span> <span>Invalid username or password. Please verify your credentials and try again.</span>\n");
                sb.append("    </div>\n");
            } else if ("unauthorized".equalsIgnoreCase(error)) {
                sb.append("    <div class=\"alert alert-warning\">\n");
                sb.append("      <span>&#128274;</span> <span>Authentication required. Please sign in to access the protected page.</span>\n");
                sb.append("    </div>\n");
            } else if ("expired".equalsIgnoreCase(error)) {
                sb.append("    <div class=\"alert alert-warning\">\n");
                sb.append("      <span>&#9200;</span> <span>Your previous session has expired due to inactivity. Please sign in again.</span>\n");
                sb.append("    </div>\n");
            }

            sb.append("    <form action=\"/login\" method=\"POST\">\n");
            sb.append("      <div class=\"form-group\">\n");
            sb.append("        <label for=\"username\">Username</label>\n");
            sb.append("        <input type=\"text\" id=\"username\" name=\"username\" required placeholder=\"Enter username (e.g. admin)\" autocomplete=\"username\" autofocus>\n");
            sb.append("      </div>\n");
            sb.append("      <div class=\"form-group\">\n");
            sb.append("        <label for=\"password\">Password</label>\n");
            sb.append("        <input type=\"password\" id=\"password\" name=\"password\" required placeholder=\"Enter password\" autocomplete=\"current-password\">\n");
            sb.append("      </div>\n");
            sb.append("      <button type=\"submit\" class=\"btn btn-primary\">Sign In</button>\n");
            sb.append("    </form>\n");

            sb.append("    <div class=\"credentials-box\">\n");
            sb.append("      <h4>Preconfigured Test Accounts</h4>\n");
            sb.append("      <table class=\"credentials-table\">\n");
            sb.append("        <thead><tr><th>Username</th><th>Password</th><th>Role</th></tr></thead>\n");
            sb.append("        <tbody>\n");
            for (User u : demoUsers) {
                sb.append("          <tr>\n");
                sb.append("            <td><code>").append(SecurityUtils.escapeHtml(u.getUsername())).append("</code></td>\n");
                sb.append("            <td><code>").append(SecurityUtils.escapeHtml(u.getDemoPassword())).append("</code></td>\n");
                sb.append("            <td><span class=\"badge ")
                        .append("Administrator".equals(u.getRole()) ? "badge-admin" : "badge-user")
                        .append("\">").append(SecurityUtils.escapeHtml(u.getRole())).append("</span></td>\n");
                sb.append("          </tr>\n");
            }
            sb.append("        </tbody>\n");
            sb.append("      </table>\n");
            sb.append("    </div>\n");

            sb.append("  </div>\n");
            sb.append("</div>\n");
            sb.append("<div class=\"footer-note\">Java Web Application &bull; Session Cookie: HttpOnly & SameSite=Strict</div>\n");
            sb.append("</body>\n</html>");
            return sb.toString();
        }

        public static String renderDashboardPage(User user, Session session) {
            StringBuilder sb = new StringBuilder();
            sb.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
            sb.append("<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
            sb.append("<title>Dashboard - Authenticated Session</title>\n");
            sb.append("<style>\n").append(COMMON_CSS).append("</style>\n</head>\n<body>\n");
            sb.append("<div class=\"card card-wide\">\n");
            sb.append("  <div class=\"card-header\">\n");
            sb.append("    <h1>Welcome, ").append(SecurityUtils.escapeHtml(user.getFullName())).append("!</h1>\n");
            sb.append("    <p>Your session is active and verified via an HTTP session cookie</p>\n");
            sb.append("  </div>\n");
            sb.append("  <div class=\"card-body\">\n");

            sb.append("    <div class=\"alert alert-success\">\n");
            sb.append("      <span>&#10003;</span> <span><strong>Authentication Successful!</strong> The browser is maintaining this session with cookie <code>SESSIONID</code>.</span>\n");
            sb.append("    </div>\n");

            sb.append("    <div class=\"info-grid\">\n");
            sb.append("      <div class=\"info-tile\">\n");
            sb.append("        <div class=\"label\">Username</div>\n");
            sb.append("        <div class=\"value\">").append(SecurityUtils.escapeHtml(user.getUsername())).append("</div>\n");
            sb.append("      </div>\n");
            sb.append("      <div class=\"info-tile\">\n");
            sb.append("        <div class=\"label\">Assigned Role</div>\n");
            sb.append("        <div class=\"value\"><span class=\"badge ")
                    .append("Administrator".equals(user.getRole()) ? "badge-admin" : "badge-user")
                    .append("\">").append(SecurityUtils.escapeHtml(user.getRole())).append("</span></div>\n");
            sb.append("      </div>\n");
            sb.append("      <div class=\"info-tile\">\n");
            sb.append("        <div class=\"label\">Session Created</div>\n");
            sb.append("        <div class=\"value\">").append(DATE_FORMATTER.format(session.getCreatedAt())).append("</div>\n");
            sb.append("      </div>\n");
            sb.append("      <div class=\"info-tile\">\n");
            sb.append("        <div class=\"label\">Last Activity</div>\n");
            sb.append("        <div class=\"value\">").append(DATE_FORMATTER.format(session.getLastAccessedAt())).append("</div>\n");
            sb.append("      </div>\n");
            sb.append("      <div class=\"info-tile\">\n");
            sb.append("        <div class=\"label\">Client IP Address</div>\n");
            sb.append("        <div class=\"value\">").append(SecurityUtils.escapeHtml(session.getClientIp())).append("</div>\n");
            sb.append("      </div>\n");
            sb.append("      <div class=\"info-tile\">\n");
            sb.append("        <div class=\"label\">Idle Session Timeout</div>\n");
            sb.append("        <div class=\"value\">30 minutes (sliding)</div>\n");
            sb.append("      </div>\n");
            sb.append("    </div>\n");

            sb.append("    <div style=\"margin-bottom: 24px;\">\n");
            sb.append("      <label>Active Session Cookie Value (SESSIONID)</label>\n");
            sb.append("      <div class=\"cookie-pill\">").append(SecurityUtils.escapeHtml(session.getId())).append("</div>\n");
            sb.append("    </div>\n");

            sb.append("    <div class=\"credentials-box\" style=\"margin-top: 0; margin-bottom: 24px;\">\n");
            sb.append("      <h4>Security Flags Configured on this Session Cookie</h4>\n");
            sb.append("      <ul style=\"padding-left: 20px; line-height: 1.8;\">\n");
            sb.append("        <li><code>HttpOnly</code>: Prevents client-side scripts (XSS attacks) from reading the cookie via JavaScript.</li>\n");
            sb.append("        <li><code>SameSite=Strict</code>: Protects against Cross-Site Request Forgery (CSRF) attacks by withholding cookie on cross-site requests.</li>\n");
            sb.append("        <li><code>Path=/</code>: Scope covers the entire web application.</li>\n");
            sb.append("        <li><code>Max-Age=1800</code>: Expired automatically after 30 minutes.</li>\n");
            sb.append("      </ul>\n");
            sb.append("    </div>\n");

            sb.append("    <form action=\"/logout\" method=\"POST\">\n");
            sb.append("      <button type=\"submit\" class=\"btn btn-danger\">Sign Out (Invalidate Session)</button>\n");
            sb.append("    </form>\n");

            sb.append("  </div>\n");
            sb.append("</div>\n");
            sb.append("<div class=\"footer-note\">Java Web Application &bull; Protected Resource</div>\n");
            sb.append("</body>\n</html>");
            return sb.toString();
        }
    }
}
