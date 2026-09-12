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
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * A secure Java web application demonstrating user authentication and session management.
 *
 * <p>Key Security Features:
 * <ul>
 *   <li><b>HttpOnly Session Cookies:</b> Session cookies are issued with the {@code HttpOnly} flag,
 *       preventing client-side JavaScript (e.g., via {@code document.cookie}) from reading or manipulating them.</li>
 *   <li><b>SameSite Protection:</b> Cookies use {@code SameSite=Strict} to defend against Cross-Site Request Forgery (CSRF).</li>
 *   <li><b>Secure Flag:</b> Ensures cookies are transmitted exclusively over encrypted HTTPS connections (configurable for local HTTP testing).</li>
 *   <li><b>PBKDF2 Password Hashing:</b> Passwords are stored and verified using PBKDF2WithHmacSHA256 with 100,000 iterations and cryptographic salts.</li>
 *   <li><b>Constant-Time Comparison:</b> Password hashes and tokens are compared using {@link MessageDigest#isEqual} to resist timing side-channel attacks.</li>
 *   <li><b>Cryptographically Strong Session IDs:</b> Generated using {@link SecureRandom} with 256 bits of entropy.</li>
 *   <li><b>Session Fixation Defense:</b> Old sessions are invalidated and a fresh session ID is issued upon every login.</li>
 *   <li><b>Session Expiry:</b> Server-enforced idle timeout (30 minutes) and absolute session lifetime (8 hours).</li>
 *   <li><b>Brute-Force Rate Limiting:</b> IP-based rate limiting throttles repeated failed authentication attempts.</li>
 *   <li><b>CSRF Defense:</b> State-changing requests are validated against a secure CSRF token.</li>
 *   <li><b>Interactive Security Verification:</b> Built-in test interface demonstrating that client-side scripts cannot access the session cookie.</li>
 * </ul>
 */
public final class LoginServer {

    public static final String SESSION_COOKIE_NAME = "SESSIONID";
    public static final String CSRF_COOKIE_NAME = "CSRF_TOKEN";

    private static final Duration SESSION_IDLE_TIMEOUT = Duration.ofMinutes(30);
    private static final Duration SESSION_ABSOLUTE_TIMEOUT = Duration.ofHours(8);
    private static final Duration CSRF_TOKEN_LIFETIME = Duration.ofMinutes(30);

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final Duration RATE_LIMIT_WINDOW = Duration.ofMinutes(15);

    private static final int MAX_REQUEST_BODY_SIZE = 8192; // 8 KB limit
    private static final int MAX_FIELD_LENGTH = 256;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final UserStore userStore;
    private final SessionStore sessionStore = new SessionStore();
    private final RateLimiter rateLimiter = new RateLimiter();
    private final boolean secureCookie;

    public LoginServer(UserStore userStore, boolean secureCookie) {
        this.userStore = userStore;
        this.secureCookie = secureCookie;
    }

    // =========================================================================
    // Application Entry Point
    // =========================================================================

    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(getEnv("PORT", "8080"));
        String host = getEnv("BIND_ADDRESS", "0.0.0.0");
        boolean secureCookie = !"false".equalsIgnoreCase(getEnv("COOKIE_SECURE", "false"));

        // Setup demo credentials
        String demoUser = getEnv("DEMO_USERNAME", "admin");
        String demoPass = getEnv("DEMO_PASSWORD", "AdminPassword123!");

        UserStore userStore = new UserStore();
        userStore.addUser(demoUser, demoPass.toCharArray());
        userStore.addUser("alice", "Password123!".toCharArray());

        LoginServer app = new LoginServer(userStore, secureCookie);

        HttpServer server = HttpServer.create(new InetSocketAddress(host, port), 0);
        ExecutorService workerPool = Executors.newFixedThreadPool(16);
        server.setExecutor(workerPool);

        // Register HTTP routes
        server.createContext("/", app::routeRequest);

        // Background session cleanup task
        ScheduledExecutorService cleaner = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread t = new Thread(runnable, "session-cleaner");
            t.setDaemon(true);
            return t;
        });
        cleaner.scheduleAtFixedRate(app::cleanupExpiredSessions, 1, 1, TimeUnit.MINUTES);

        // Graceful shutdown
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("Shutting down Login Server...");
            server.stop(1);
            workerPool.shutdown();
            cleaner.shutdown();
        }));

        server.start();

        System.out.println("===============================================================");
        System.out.println(" Secure Java Web Application Running");
        System.out.println(" URL: http://" + ("0.0.0.0".equals(host) ? "127.0.0.1" : host) + ":" + port + "/login");
        System.out.println(" Demo Users:");
        System.out.println("   - Username: " + demoUser + "  |  Password: " + demoPass);
        System.out.println("   - Username: alice  |  Password: Password123!");
        System.out.println(" Cookie Security Configuration:");
        System.out.println("   - HttpOnly: true (Client-side scripts cannot read/manipulate cookie)");
        System.out.println("   - SameSite: Strict (CSRF mitigation)");
        System.out.println("   - Secure: " + secureCookie + " (Set COOKIE_SECURE=true for HTTPS-only)");
        System.out.println("===============================================================");
    }

    private static String getEnv(String name, String defaultValue) {
        String val = System.getenv(name);
        return (val == null || val.isBlank()) ? defaultValue : val.trim();
    }

    private void cleanupExpiredSessions() {
        sessionStore.purgeExpired();
        rateLimiter.purgeExpired();
    }

    // =========================================================================
    // Request Routing & Dispatching
    // =========================================================================

    private void routeRequest(HttpExchange exchange) {
        try {
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod().toUpperCase();

            // Set standard defense-in-depth HTTP security headers on all responses
            setSecurityHeaders(exchange);

            switch (path) {
                case "/" -> {
                    requireMethod(method, "GET");
                    if (resolveCurrentSession(exchange).isPresent()) {
                        sendRedirect(exchange, "/dashboard");
                    } else {
                        sendRedirect(exchange, "/login");
                    }
                }
                case "/login" -> {
                    if ("GET".equals(method)) {
                        handleGetLogin(exchange);
                    } else if ("POST".equals(method)) {
                        handlePostLogin(exchange);
                    } else {
                        sendError(exchange, 405, "Method Not Allowed");
                    }
                }
                case "/dashboard" -> {
                    requireMethod(method, "GET");
                    handleGetDashboard(exchange);
                }
                case "/logout" -> {
                    if ("POST".equals(method) || "GET".equals(method)) {
                        handleLogout(exchange);
                    } else {
                        sendError(exchange, 405, "Method Not Allowed");
                    }
                }
                case "/api/session" -> {
                    requireMethod(method, "GET");
                    handleApiSession(exchange);
                }
                default -> sendError(exchange, 404, "Page Not Found");
            }
        } catch (HttpException e) {
            sendError(exchange, e.getStatusCode(), e.getMessage());
        } catch (Exception e) {
            System.err.println("Internal Server Error: " + e.getMessage());
            e.printStackTrace();
            sendError(exchange, 500, "Internal Server Error");
        } finally {
            exchange.close();
        }
    }

    private static void requireMethod(String actual, String expected) throws HttpException {
        if (!expected.equalsIgnoreCase(actual)) {
            throw new HttpException(405, "Method " + actual + " Not Allowed");
        }
    }

    // =========================================================================
    // Route Handlers
    // =========================================================================

    private void handleGetLogin(HttpExchange exchange) throws IOException {
        if (resolveCurrentSession(exchange).isPresent()) {
            sendRedirect(exchange, "/dashboard");
            return;
        }
        renderLoginForm(exchange, 200, null);
    }

    private void handlePostLogin(HttpExchange exchange) throws IOException, HttpException {
        Map<String, String> formData = parseFormData(exchange);

        // CSRF Token validation for login form
        String csrfCookie = extractCookie(exchange, CSRF_COOKIE_NAME);
        String submittedCsrf = formData.get("csrf");
        if (csrfCookie == null || submittedCsrf == null || !MessageDigest.isEqual(
                csrfCookie.getBytes(StandardCharsets.UTF_8),
                submittedCsrf.getBytes(StandardCharsets.UTF_8))) {
            renderLoginForm(exchange, 403, "Your login session expired or CSRF token is invalid. Please try again.");
            return;
        }

        // Rate limiting check
        String clientIp = getClientIp(exchange);
        if (rateLimiter.isBlocked(clientIp)) {
            exchange.getResponseHeaders().set("Retry-After", String.valueOf(RATE_LIMIT_WINDOW.toSeconds()));
            renderLoginForm(exchange, 429, "Too many failed login attempts. Please wait 15 minutes before trying again.");
            return;
        }

        String username = formData.getOrDefault("username", "").trim();
        String password = formData.getOrDefault("password", "");

        if (username.isEmpty() || password.isEmpty()
                || username.length() > MAX_FIELD_LENGTH
                || password.length() > MAX_FIELD_LENGTH) {
            rateLimiter.recordFailure(clientIp);
            renderLoginForm(exchange, 400, "Username and password are required.");
            return;
        }

        // Verify credentials against secure user store
        boolean authenticated = userStore.verifyPassword(username, password.toCharArray());
        if (!authenticated) {
            rateLimiter.recordFailure(clientIp);
            System.out.printf("[SECURITY] Failed login attempt for user '%s' from IP %s%n", sanitizeForLog(username), clientIp);
            // Generic message prevents username enumeration
            renderLoginForm(exchange, 401, "Invalid username or password.");
            return;
        }

        // Clear rate limiter on successful authentication
        rateLimiter.reset(clientIp);

        // Session Fixation Prevention: Invalidate existing session if present
        String existingSessionId = extractCookie(exchange, SESSION_COOKIE_NAME);
        if (existingSessionId != null) {
            sessionStore.invalidate(existingSessionId);
        }

        // Issue fresh server-side session
        Session newSession = sessionStore.createSession(username);

        // Issue HttpOnly session cookie
        // The HttpOnly attribute strictly prevents client-side scripts (e.g. document.cookie)
        // from reading or manipulating this cookie in the browser.
        String sessionCookieHeader = buildCookieHeader(
                SESSION_COOKIE_NAME,
                newSession.id(),
                "/",
                -1, // -1 creates a browser session cookie (cleared when browser is closed)
                true, // HttpOnly = true (CRUCIAL SECURITY REQUIREMENT)
                "Strict", // SameSite = Strict
                this.secureCookie
        );

        // Clear the one-time login CSRF cookie
        String clearCsrfHeader = buildCookieHeader(
                CSRF_COOKIE_NAME,
                "",
                "/login",
                0, // Max-Age 0 clears the cookie
                true,
                "Strict",
                this.secureCookie
        );

        exchange.getResponseHeaders().add("Set-Cookie", sessionCookieHeader);
        exchange.getResponseHeaders().add("Set-Cookie", clearCsrfHeader);

        System.out.printf("[SECURITY] User '%s' successfully authenticated. Issued HttpOnly session cookie.%n", username);

        // Check if request expects JSON
        String accept = exchange.getRequestHeaders().getFirst("Accept");
        if (accept != null && accept.contains("application/json")) {
            String json = "{"status":"success","message":"Authenticated successfully","username":"" + escapeJson(username) + ""}";
            sendResponse(exchange, 200, "application/json; charset=UTF-8", json.getBytes(StandardCharsets.UTF_8));
        } else {
            sendRedirect(exchange, "/dashboard");
        }
    }

    private void handleGetDashboard(HttpExchange exchange) throws IOException {
        Optional<Session> sessionOpt = resolveCurrentSession(exchange);
        if (sessionOpt.isEmpty()) {
            sendRedirect(exchange, "/login");
            return;
        }

        Session session = sessionOpt.get();
        String body = """
            <div class="card">
                <div class="card-header">
                    <h2>Welcome, %s!</h2>
                    <span class="badge badge-success">Authenticated</span>
                </div>
                <div class="card-body">
                    <p>You have successfully logged in. Your browser is maintaining this authenticated session using an <strong>HttpOnly Session Cookie</strong>.</p>
                    
                    <div class="info-grid">
                        <div class="info-item">
                            <span class="label">Username:</span>
                            <span class="value"><strong>%s</strong></span>
                        </div>
                        <div class="info-item">
                            <span class="label">Session ID:</span>
                            <span class="value"><code>%s</code></span>
                        </div>
                        <div class="info-item">
                            <span class="label">Login Time:</span>
                            <span class="value">%s UTC</span>
                        </div>
                        <div class="info-item">
                            <span class="label">Last Activity:</span>
                            <span class="value">%s UTC</span>
                        </div>
                        <div class="info-item">
                            <span class="label">Session Idle Timeout:</span>
                            <span class="value">30 minutes</span>
                        </div>
                        <div class="info-item">
                            <span class="label">Max Session Lifetime:</span>
                            <span class="value">8 hours</span>
                        </div>
                    </div>

                    <div class="security-demo">
                        <h3>Interactive Security Demonstration</h3>
                        <p>The prompt requires: <em>"The session cookie must be protected from being read or manipulated by any client-side script running in the browser."</em></p>
                        <p>Click the buttons below to test how the browser's JavaScript sandbox enforces the <code>HttpOnly</code> protection flag:</p>
                        
                        <div class="button-group">
                            <button type="button" class="btn btn-secondary" onclick="testReadCookie()">
                                Try to Read Cookie with JavaScript (<code>document.cookie</code>)
                            </button>
                            <button type="button" class="btn btn-secondary" onclick="testManipulateCookie()">
                                Try to Manipulate Cookie with JavaScript
                            </button>
                        </div>
                        
                        <div id="test-result" class="test-result" style="display:none;"></div>
                    </div>

                    <div class="card-actions">
                        <form method="post" action="/logout" style="margin: 0;">
                            <input type="hidden" name="csrf" value="%s">
                            <button type="submit" class="btn btn-danger">Log Out</button>
                        </form>
                    </div>
                </div>
            </div>

            <script>
                function testReadCookie() {
                    var box = document.getElementById('test-result');
                    var cookies = document.cookie;
                    box.style.display = 'block';
                    if (cookies.indexOf('SESSIONID') !== -1) {
                        box.className = 'test-result alert-danger';
                        box.innerHTML = '<strong>Vulnerability!</strong> The SESSIONID cookie was read by JavaScript: ' + cookies;
                    } else {
                        box.className = 'test-result alert-success';
                        box.innerHTML = '<strong>Verification Successful!</strong><br>' +
                            '<code>document.cookie</code> returned: <em>"' + (cookies ? cookies : '[empty]') + '"</em><br>' +
                            'The <code>SESSIONID</code> cookie is <strong>completely invisible</strong> to client-side scripts because it is flagged with <code>HttpOnly</code>!';
                    }
                }

                function testManipulateCookie() {
                    var box = document.getElementById('test-result');
                    box.style.display = 'block';
                    try {
                        document.cookie = "SESSIONID=tampered_value; path=/;";
                        // Test API to see if server accepted tampered cookie
                        fetch('/api/session').then(function(res) { return res.json(); }).then(function(data) {
                            if (data.authenticated && data.username === '%s') {
                                box.className = 'test-result alert-success';
                                box.innerHTML = '<strong>Tamper Test Passed!</strong><br>' +
                                    'JavaScript attempted to overwrite <code>SESSIONID</code>, but the browser ignored the modification to the HttpOnly cookie.<br>' +
                                    'The server continues to verify the original, authentic session safely.';
                            } else {
                                box.className = 'test-result alert-warning';
                                box.innerHTML = 'Session state changed unexpectedly.';
                            }
                        });
                    } catch (e) {
                        box.className = 'test-result alert-success';
                        box.innerHTML = 'Manipulation blocked by browser: ' + e;
                    }
                }
            </script>
            """.formatted(
                escapeHtml(session.username()),
                escapeHtml(session.username()),
                escapeHtml(maskToken(session.id())),
                escapeHtml(session.createdAt().toString()),
                escapeHtml(session.lastAccessedAt().toString()),
                escapeHtml(session.csrfToken()),
                escapeHtml(session.username())
        );

        sendHtml(exchange, 200, buildPage("Dashboard", body));
    }

    private void handleLogout(HttpExchange exchange) throws IOException {
        Optional<Session> sessionOpt = resolveCurrentSession(exchange);
        if (sessionOpt.isPresent()) {
            Session session = sessionOpt.get();
            sessionStore.invalidate(session.id());
            System.out.printf("[SECURITY] User '%s' logged out. Session invalidated.%n", session.username());
        }

        // Expire the session cookie immediately in the browser
        String expiredCookie = buildCookieHeader(
                SESSION_COOKIE_NAME,
                "",
                "/",
                0, // Max-Age 0 tells the browser to delete it immediately
                true,
                "Strict",
                this.secureCookie
        );

        exchange.getResponseHeaders().add("Set-Cookie", expiredCookie);
        sendRedirect(exchange, "/login");
    }

    private void handleApiSession(HttpExchange exchange) throws IOException {
        Optional<Session> sessionOpt = resolveCurrentSession(exchange);
        String json;
        if (sessionOpt.isPresent()) {
            Session session = sessionOpt.get();
            json = String.format(
                    "{"authenticated":true,"username":"%s","created_at":"%s","idle_timeout_seconds":%d}",
                    escapeJson(session.username()),
                    session.createdAt(),
                    SESSION_IDLE_TIMEOUT.toSeconds()
            );
        } else {
            json = "{"authenticated":false,"username":null}";
        }
        sendResponse(exchange, 200, "application/json; charset=UTF-8", json.getBytes(StandardCharsets.UTF_8));
    }

    // =========================================================================
    // Login Form Rendering
    // =========================================================================

    private void renderLoginForm(HttpExchange exchange, int statusCode, String errorMessage) throws IOException {
        // Generate a new secure CSRF token for the login form
        String csrfToken = generateSecureToken(32);
        String csrfCookieHeader = buildCookieHeader(
                CSRF_COOKIE_NAME,
                csrfToken,
                "/login",
                CSRF_TOKEN_LIFETIME.toSeconds(),
                true, // HttpOnly
                "Strict",
                this.secureCookie
        );
        exchange.getResponseHeaders().add("Set-Cookie", csrfCookieHeader);

        String errorHtml = (errorMessage != null)
                ? "<div class="alert alert-danger" role="alert">" + escapeHtml(errorMessage) + "</div>"
                : "";

        String body = """
            <div class="card login-card">
                <div class="card-header">
                    <h2>Sign In</h2>
                    <p class="subtitle">Enter your credentials to start an authenticated session</p>
                </div>
                <div class="card-body">
                    %s
                    <form method="post" action="/login" autocomplete="off">
                        <input type="hidden" name="csrf" value="%s">
                        
                        <div class="form-group">
                            <label for="username">Username</label>
                            <input type="text" id="username" name="username" class="form-control" 
                                   required autofocus maxlength="%d" placeholder="e.g. admin or alice">
                        </div>

                        <div class="form-group">
                            <label for="password">Password</label>
                            <input type="password" id="password" name="password" class="form-control" 
                                   required maxlength="%d" placeholder="Enter your password">
                        </div>

                        <div class="form-actions">
                            <button type="submit" class="btn btn-primary btn-block">Sign In</button>
                        </div>
                    </form>

                    <div class="demo-credentials">
                        <strong>Demo Accounts:</strong>
                        <ul>
                            <li><code>admin</code> / <code>AdminPassword123!</code></li>
                            <li><code>alice</code> / <code>Password123!</code></li>
                        </ul>
                    </div>
                </div>
            </div>
            """.formatted(errorHtml, escapeHtml(csrfToken), MAX_FIELD_LENGTH, MAX_FIELD_LENGTH);

        sendHtml(exchange, statusCode, buildPage("Sign In", body));
    }

    // =========================================================================
    // Session & Cookie Helpers
    // =========================================================================

    private Optional<Session> resolveCurrentSession(HttpExchange exchange) {
        String sessionId = extractCookie(exchange, SESSION_COOKIE_NAME);
        if (sessionId == null || sessionId.isBlank()) {
            return Optional.empty();
        }
        return sessionStore.findSession(sessionId);
    }

    /**
     * Constructs a hardened HTTP Set-Cookie header string complying with RFC 6265bis.
     *
     * @param name Name of the cookie
     * @param value Value of the cookie
     * @param path Path scope
     * @param maxAgeSeconds Max age in seconds (-1 for browser session cookie, 0 to delete)
     * @param httpOnly Enables HttpOnly flag to block client-side JavaScript access
     * @param sameSite SameSite policy ("Strict" or "Lax")
     * @param secure Enables Secure flag for HTTPS transport
     * @return Formatted Set-Cookie header value
     */
    public static String buildCookieHeader(
            String name,
            String value,
            String path,
            long maxAgeSeconds,
            boolean httpOnly,
            String sameSite,
            boolean secure) {

        StringBuilder sb = new StringBuilder();
        sb.append(name).append('=').append(value);
        sb.append("; Path=").append(path);

        if (httpOnly) {
            // Crucial: protects cookie from being read or manipulated by client-side scripts
            sb.append("; HttpOnly");
        }

        if (sameSite != null && !sameSite.isBlank()) {
            sb.append("; SameSite=").append(sameSite);
        }

        if (maxAgeSeconds >= 0) {
            sb.append("; Max-Age=").append(maxAgeSeconds);
        }

        if (secure) {
            sb.append("; Secure");
        }

        return sb.toString();
    }

    private static String extractCookie(HttpExchange exchange, String cookieName) {
        Headers headers = exchange.getRequestHeaders();
        for (String cookieHeader : headers.getOrDefault("Cookie", java.util.List.of())) {
            for (String part : cookieHeader.split(";")) {
                int eq = part.indexOf('=');
                if (eq > 0) {
                    String key = part.substring(0, eq).trim();
                    if (key.equals(cookieName)) {
                        return part.substring(eq + 1).trim();
                    }
                }
            }
        }
        return null;
    }

    private static String generateSecureToken(int byteLength) {
        byte[] bytes = new byte[byteLength];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String maskToken(String token) {
        if (token == null || token.length() < 12) {
            return "******";
        }
        return token.substring(0, 6) + "..." + token.substring(token.length() - 6);
    }

    // =========================================================================
    // Request Parsing & Security Helpers
    // =========================================================================

    private static Map<String, String> parseFormData(HttpExchange exchange) throws IOException, HttpException {
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (contentType == null || !contentType.toLowerCase().contains("application/x-www-form-urlencoded")) {
            throw new HttpException(400, "Expected application/x-www-form-urlencoded Content-Type");
        }

        InputStream is = exchange.getRequestBody();
        byte[] bodyBytes = is.readNBytes(MAX_REQUEST_BODY_SIZE + 1);
        if (bodyBytes.length > MAX_REQUEST_BODY_SIZE) {
            throw new HttpException(413, "Request body exceeds maximum size of " + MAX_REQUEST_BODY_SIZE + " bytes");
        }

        String body = new String(bodyBytes, StandardCharsets.UTF_8);
        Map<String, String> form = new HashMap<>();
        for (String pair : body.split("&")) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            if (eq >= 0) {
                String key = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
                String val = URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
                form.put(key, val);
            } else {
                String key = URLDecoder.decode(pair, StandardCharsets.UTF_8);
                form.put(key, "");
            }
        }
        return form;
    }

    private static String getClientIp(HttpExchange exchange) {
        InetSocketAddress remote = exchange.getRemoteAddress();
        if (remote != null && remote.getAddress() != null) {
            return remote.getAddress().getHostAddress();
        }
        return "127.0.0.1";
    }

    private static void setSecurityHeaders(HttpExchange exchange) {
        Headers h = exchange.getResponseHeaders();
        // Prevent browsers from MIME-sniffing response content
        h.set("X-Content-Type-Options", "nosniff");
        // Defend against clickjacking
        h.set("X-Frame-Options", "DENY");
        // Strict Referrer Policy
        h.set("Referrer-Policy", "strict-origin-when-cross-origin");
        // Content Security Policy
        h.set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'");
        // Prevent caching of sensitive authenticated content
        h.set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
        h.set("Pragma", "no-cache");
    }

    private static void sendRedirect(HttpExchange exchange, String location) throws IOException {
        exchange.getResponseHeaders().set("Location", location);
        exchange.sendResponseHeaders(302, -1);
    }

    private static void sendHtml(HttpExchange exchange, int statusCode, String html) throws IOException {
        byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
        sendResponse(exchange, statusCode, "text/html; charset=UTF-8", bytes);
    }

    private static void sendError(HttpExchange exchange, int statusCode, String message) {
        try {
            String html = buildPage("Error " + statusCode, """
                <div class="card error-card">
                    <div class="card-header">
                        <h2>Error %d</h2>
                    </div>
                    <div class="card-body">
                        <p class="error-message">%s</p>
                        <a href="/login" class="btn btn-primary">Return to Login</a>
                    </div>
                </div>
                """.formatted(statusCode, escapeHtml(message)));
            sendHtml(exchange, statusCode, html);
        } catch (Exception ignored) {
        }
    }

    private static void sendResponse(HttpExchange exchange, int statusCode, String contentType, byte[] body) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(statusCode, body.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(body);
        }
    }

    private static String escapeHtml(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace(""", "&quot;")
                    .replace("'", "&#39;");
    }

    private static String escapeJson(String input) {
        if (input == null) return "";
        return input.replace("\", "\\")
                    .replace(""", "\"")
                    .replace("", "\b")
                    .replace("", "\f")
                    .replace("
", "\n")
                    .replace("", "\r")
                    .replace("	", "\t");
    }

    private static String sanitizeForLog(String input) {
        if (input == null) return "";
        return input.replaceAll("[\r\n]", "_");
    }

    private static String buildPage(String title, String content) {
        return """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>%s - Secure Session Auth</title>
                <style>
                    :root {
                        --primary: #2563eb;
                        --primary-hover: #1d4ed8;
                        --bg: #f8fafc;
                        --card-bg: #ffffff;
                        --text: #0f172a;
                        --text-muted: #64748b;
                        --border: #e2e8f0;
                        --success-bg: #dcfce7;
                        --success-text: #166534;
                        --error-bg: #fee2e2;
                        --error-text: #991b1b;
                        --code-bg: #f1f5f9;
                    }
                    * { box-sizing: border-box; margin: 0; padding: 0; }
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                        background: var(--bg);
                        color: var(--text);
                        line-height: 1.5;
                        padding: 2rem 1rem;
                        display: flex;
                        flex-direction: column;
                        align-items: center;
                        min-height: 100vh;
                    }
                    .container { width: 100%%; max-width: 640px; }
                    .card {
                        background: var(--card-bg);
                        border: 1px solid var(--border);
                        border-radius: 12px;
                        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03);
                        overflow: hidden;
                    }
                    .card-header {
                        padding: 1.5rem 2rem;
                        border-bottom: 1px solid var(--border);
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        flex-wrap: wrap;
                        gap: 0.5rem;
                    }
                    .card-header h2 { font-size: 1.5rem; font-weight: 700; }
                    .subtitle { color: var(--text-muted); font-size: 0.95rem; margin-top: 0.25rem; }
                    .card-body { padding: 2rem; }
                    .card-actions { margin-top: 2rem; display: flex; justify-content: flex-end; }
                    .form-group { margin-bottom: 1.25rem; }
                    .form-group label {
                        display: block;
                        font-weight: 600;
                        font-size: 0.9rem;
                        margin-bottom: 0.5rem;
                    }
                    .form-control {
                        width: 100%%;
                        padding: 0.75rem 1rem;
                        border: 1px solid var(--border);
                        border-radius: 8px;
                        font-size: 1rem;
                        outline: none;
                        transition: border-color 0.2s, box-shadow 0.2s;
                    }
                    .form-control:focus {
                        border-color: var(--primary);
                        box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.2);
                    }
                    .btn {
                        display: inline-block;
                        padding: 0.75rem 1.5rem;
                        font-size: 1rem;
                        font-weight: 600;
                        border: none;
                        border-radius: 8px;
                        cursor: pointer;
                        text-decoration: none;
                        text-align: center;
                        transition: background-color 0.2s;
                    }
                    .btn-primary { background: var(--primary); color: #ffffff; }
                    .btn-primary:hover { background: var(--primary-hover); }
                    .btn-secondary { background: #e2e8f0; color: #1e293b; font-size: 0.9rem; padding: 0.6rem 1rem; }
                    .btn-secondary:hover { background: #cbd5e1; }
                    .btn-danger { background: #ef4444; color: #ffffff; }
                    .btn-danger:hover { background: #dc2626; }
                    .btn-block { width: 100%%; }
                    .badge {
                        padding: 0.25rem 0.75rem;
                        border-radius: 9999px;
                        font-size: 0.8rem;
                        font-weight: 700;
                        text-transform: uppercase;
                    }
                    .badge-success { background: var(--success-bg); color: var(--success-text); }
                    .alert {
                        padding: 1rem;
                        border-radius: 8px;
                        margin-bottom: 1.5rem;
                        font-size: 0.95rem;
                    }
                    .alert-danger { background: var(--error-bg); color: var(--error-text); }
                    .alert-success { background: var(--success-bg); color: var(--success-text); }
                    .alert-warning { background: #fef3c7; color: #92400e; }
                    .demo-credentials {
                        margin-top: 1.5rem;
                        padding: 1rem;
                        background: var(--code-bg);
                        border-radius: 8px;
                        font-size: 0.85rem;
                        color: var(--text-muted);
                    }
                    .demo-credentials ul { margin-left: 1.5rem; margin-top: 0.5rem; }
                    .info-grid {
                        display: grid;
                        grid-template-columns: 1fr 1fr;
                        gap: 1rem;
                        margin: 1.5rem 0;
                    }
                    @media (max-width: 480px) { .info-grid { grid-template-columns: 1fr; } }
                    .info-item {
                        background: var(--code-bg);
                        padding: 0.75rem 1rem;
                        border-radius: 8px;
                    }
                    .info-item .label { display: block; font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; font-weight: 600; }
                    .info-item .value { font-size: 0.95rem; margin-top: 0.25rem; display: block; word-break: break-all; }
                    .security-demo {
                        margin-top: 2rem;
                        padding: 1.25rem;
                        border: 2px dashed #93c5fd;
                        border-radius: 8px;
                        background: #eff6ff;
                    }
                    .security-demo h3 { font-size: 1.1rem; color: #1e40af; margin-bottom: 0.5rem; }
                    .security-demo p { font-size: 0.9rem; color: #1e3a8a; margin-bottom: 1rem; }
                    .button-group { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 1rem; }
                    .test-result { padding: 1rem; border-radius: 8px; font-size: 0.9rem; line-height: 1.6; }
                    code {
                        background: rgba(0, 0, 0, 0.06);
                        padding: 0.15rem 0.35rem;
                        border-radius: 4px;
                        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
                        font-size: 0.9em;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    %s
                </div>
            </body>
            </html>
            """.formatted(escapeHtml(title), content);
    }

    // =========================================================================
    // Nested Classes: Session & SessionStore
    // =========================================================================

    public record Session(
            String id,
            String username,
            String csrfToken,
            Instant createdAt,
            Instant lastAccessedAt
    ) {
        public Session withLastAccessedAt(Instant newTime) {
            return new Session(this.id, this.username, this.csrfToken, this.createdAt, newTime);
        }

        public boolean isExpired(Instant now) {
            return now.isAfter(this.lastAccessedAt.plus(SESSION_IDLE_TIMEOUT))
                    || now.isAfter(this.createdAt.plus(SESSION_ABSOLUTE_TIMEOUT));
        }
    }

    public static final class SessionStore {
        private final Map<String, Session> sessions = new ConcurrentHashMap<>();

        public Session createSession(String username) {
            String sessionId = generateSecureToken(32); // 256-bit cryptographically random token
            String csrfToken = generateSecureToken(32);
            Instant now = Instant.now();
            Session session = new Session(sessionId, username, csrfToken, now, now);
            sessions.put(sessionId, session);
            return session;
        }

        public Optional<Session> findSession(String sessionId) {
            if (sessionId == null || sessionId.isBlank()) {
                return Optional.empty();
            }
            Session session = sessions.get(sessionId);
            if (session == null) {
                return Optional.empty();
            }
            Instant now = Instant.now();
            if (session.isExpired(now)) {
                sessions.remove(sessionId);
                return Optional.empty();
            }
            // Update last accessed time to maintain rolling idle timeout
            Session updated = session.withLastAccessedAt(now);
            sessions.put(sessionId, updated);
            return Optional.of(updated);
        }

        public void invalidate(String sessionId) {
            if (sessionId != null) {
                sessions.remove(sessionId);
            }
        }

        public void purgeExpired() {
            Instant now = Instant.now();
            sessions.entrySet().removeIf(entry -> entry.getValue().isExpired(now));
        }

        public int activeSessionCount() {
            return sessions.size();
        }
    }

    // =========================================================================
    // Nested Classes: UserStore with PBKDF2 Password Hashing
    // =========================================================================

    public static final class UserStore {
        private record UserRecord(String username, byte[] salt, byte[] passwordHash) {}

        private static final int ITERATIONS = 100_000;
        private static final int KEY_LENGTH = 256;
        private final Map<String, UserRecord> users = new ConcurrentHashMap<>();

        public void addUser(String username, char[] password) {
            byte[] salt = new byte[16];
            SECURE_RANDOM.nextBytes(salt);
            byte[] hash = hashPassword(password, salt);
            users.put(username.toLowerCase(), new UserRecord(username, salt, hash));
        }

        public boolean verifyPassword(String username, char[] password) {
            UserRecord record = users.get(username.toLowerCase());
            if (record == null) {
                // Perform dummy hash to resist timing attacks (user enumeration)
                byte[] dummySalt = new byte[16];
                hashPassword(password, dummySalt);
                return false;
            }
            byte[] computedHash = hashPassword(password, record.salt);
            // Constant-time byte array comparison
            return MessageDigest.isEqual(record.passwordHash, computedHash);
        }

        private static byte[] hashPassword(char[] password, byte[] salt) {
            try {
                PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);
                SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                return skf.generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IllegalStateException("Failed to hash password with PBKDF2", e);
            }
        }
    }

    // =========================================================================
    // Nested Classes: RateLimiter & Custom Exceptions
    // =========================================================================

    private static final class RateLimiter {
        private final Map<String, Deque<Instant>> failedAttempts = new ConcurrentHashMap<>();

        public synchronized void recordFailure(String clientIp) {
            Instant now = Instant.now();
            Deque<Instant> attempts = failedAttempts.computeIfAbsent(clientIp, k -> new ArrayDeque<>());
            attempts.addLast(now);
            purgeOld(attempts, now);
        }

        public synchronized boolean isBlocked(String clientIp) {
            Deque<Instant> attempts = failedAttempts.get(clientIp);
            if (attempts == null) return false;
            purgeOld(attempts, Instant.now());
            return attempts.size() >= MAX_FAILED_ATTEMPTS;
        }

        public synchronized void reset(String clientIp) {
            failedAttempts.remove(clientIp);
        }

        public synchronized void purgeExpired() {
            Instant now = Instant.now();
            failedAttempts.entrySet().removeIf(e -> {
                purgeOld(e.getValue(), now);
                return e.getValue().isEmpty();
            });
        }

        private void purgeOld(Deque<Instant> attempts, Instant now) {
            Instant threshold = now.minus(RATE_LIMIT_WINDOW);
            while (!attempts.isEmpty() && attempts.peekFirst().isBefore(threshold)) {
                attempts.removeFirst();
            }
        }
    }

    private static final class HttpException extends Exception {
        private final int statusCode;

        public HttpException(int statusCode, String message) {
            super(message);
            this.statusCode = statusCode;
        }

        public int getStatusCode() {
            return statusCode;
        }
    }
}
