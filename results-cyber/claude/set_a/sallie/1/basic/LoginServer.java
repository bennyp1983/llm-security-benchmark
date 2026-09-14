import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
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
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * A small, self-contained web application that logs a user in and keeps them
 * logged in with a session cookie.
 *
 * <p>It uses only the Java standard library (JDK 17+), so it can be started with
 * {@code java LoginServer.java} without any build tool.
 *
 * <p>Routes:
 * <ul>
 *   <li>{@code GET  /}        redirects to the login page or the welcome page</li>
 *   <li>{@code GET  /login}   shows the login form</li>
 *   <li>{@code POST /login}   checks the username and password and issues the session cookie</li>
 *   <li>{@code GET  /welcome} a page that is only visible with a valid session</li>
 *   <li>{@code POST /logout}  ends the session and removes the cookie</li>
 * </ul>
 */
public final class LoginServer {

    private static final String SESSION_COOKIE = "SESSIONID";
    private static final String LOGIN_CSRF_COOKIE = "LOGIN_CSRF";

    private static final Duration SESSION_IDLE_TIMEOUT = Duration.ofMinutes(30);
    private static final Duration SESSION_ABSOLUTE_TIMEOUT = Duration.ofHours(8);
    private static final Duration LOGIN_FORM_LIFETIME = Duration.ofMinutes(30);

    private static final int MAX_FAILED_LOGINS = 5;
    private static final Duration FAILED_LOGIN_WINDOW = Duration.ofMinutes(15);

    private static final int MAX_BODY_BYTES = 4096;
    private static final int MAX_USERNAME_LENGTH = 100;
    private static final int MAX_PASSWORD_LENGTH = 1024;

    private static final SecureRandom RANDOM = new SecureRandom();

    private final UserStore users;
    private final SessionStore sessions = new SessionStore();
    private final LoginRateLimiter rateLimiter = new LoginRateLimiter();
    private final boolean secureCookies;

    LoginServer(UserStore users, boolean secureCookies) {
        this.users = users;
        this.secureCookies = secureCookies;
    }

    // ---------------------------------------------------------------------
    // Startup
    // ---------------------------------------------------------------------

    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(env("PORT", "8080"));
        String bindAddress = env("BIND_ADDRESS", "127.0.0.1");
        boolean secureCookies = !"false".equalsIgnoreCase(env("COOKIE_SECURE", "true"));

        String demoUsername = env("DEMO_USERNAME", "demo");
        String demoPassword = System.getenv("DEMO_PASSWORD");
        boolean passwordGenerated = demoPassword == null || demoPassword.isEmpty();
        if (passwordGenerated) {
            demoPassword = randomToken(12);
        }

        UserStore users = new UserStore();
        users.addUser(demoUsername, demoPassword.toCharArray());

        LoginServer app = new LoginServer(users, secureCookies);

        HttpServer server = HttpServer.create(
                new InetSocketAddress(InetAddress.getByName(bindAddress), port), 0);
        ExecutorService workers = Executors.newFixedThreadPool(16);
        server.setExecutor(workers);
        server.createContext("/", app::handle);

        ScheduledExecutorService janitor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "session-cleanup");
            t.setDaemon(true);
            return t;
        });
        janitor.scheduleAtFixedRate(app::purgeExpiredState, 1, 1, TimeUnit.MINUTES);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            server.stop(1);
            workers.shutdown();
            janitor.shutdown();
        }));

        server.start();

        System.out.println("Login server running at http://" + bindAddress + ":" + port + "/login");
        System.out.println("  Username: " + demoUsername);
        if (passwordGenerated) {
            System.out.println("  Password: " + demoPassword
                    + "   (randomly generated; set DEMO_PASSWORD to choose your own)");
        } else {
            System.out.println("  Password: (taken from the DEMO_PASSWORD environment variable)");
        }
        if (!secureCookies) {
            System.out.println("  WARNING: COOKIE_SECURE=false - cookies will also be sent over plain HTTP.");
        }
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isEmpty() ? fallback : value;
    }

    private void purgeExpiredState() {
        sessions.purgeExpired();
        rateLimiter.purge();
    }

    // ---------------------------------------------------------------------
    // Routing
    // ---------------------------------------------------------------------

    private void handle(HttpExchange exchange) {
        try {
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();

            switch (path) {
                case "/" -> {
                    requireMethod(method, "GET");
                    redirect(exchange, currentSession(exchange).isPresent() ? "/welcome" : "/login");
                }
                case "/login" -> {
                    if ("GET".equals(method)) {
                        showLoginPage(exchange);
                    } else if ("POST".equals(method)) {
                        handleLogin(exchange);
                    } else {
                        throw new HttpError(405, "Method not allowed.");
                    }
                }
                case "/welcome" -> {
                    requireMethod(method, "GET");
                    showWelcomePage(exchange);
                }
                case "/logout" -> {
                    requireMethod(method, "POST");
                    handleLogout(exchange);
                }
                default -> throw new HttpError(404, "Page not found.");
            }
        } catch (HttpError e) {
            sendErrorIfPossible(exchange, e.status, e.getMessage());
        } catch (Exception e) {
            System.err.println("Unexpected error: " + e);
            sendErrorIfPossible(exchange, 500, "Something went wrong.");
        } finally {
            exchange.close();
        }
    }

    private static void requireMethod(String actual, String expected) throws HttpError {
        if (!expected.equals(actual)) {
            throw new HttpError(405, "Method not allowed.");
        }
    }

    // ---------------------------------------------------------------------
    // Pages and actions
    // ---------------------------------------------------------------------

    private void showLoginPage(HttpExchange exchange) throws IOException {
        if (currentSession(exchange).isPresent()) {
            redirect(exchange, "/welcome");
            return;
        }
        renderLoginForm(exchange, 200, null);
    }

    private void handleLogin(HttpExchange exchange) throws IOException, HttpError {
        Map<String, String> form = readForm(exchange);

        // Protect the login form against cross-site request forgery with a
        // double-submit token: the value in the form must match the cookie.
        String csrfCookie = readCookie(exchange, LOGIN_CSRF_COOKIE);
        if (!constantTimeEquals(csrfCookie, form.get("csrf"))) {
            renderLoginForm(exchange, 403, "Your login form expired. Please try again.");
            return;
        }

        String clientKey = exchange.getRemoteAddress().getAddress().getHostAddress();
        if (rateLimiter.isBlocked(clientKey)) {
            exchange.getResponseHeaders().set("Retry-After",
                    String.valueOf(FAILED_LOGIN_WINDOW.toSeconds()));
            renderLoginForm(exchange, 429, "Too many failed attempts. Please wait and try again later.");
            return;
        }

        String username = form.getOrDefault("username", "");
        String password = form.getOrDefault("password", "");
        boolean inputAcceptable = !username.isEmpty() && !password.isEmpty()
                && username.length() <= MAX_USERNAME_LENGTH
                && password.length() <= MAX_PASSWORD_LENGTH;

        if (!inputAcceptable || !users.authenticate(username, password.toCharArray())) {
            rateLimiter.recordFailure(clientKey);
            log("Failed login for '" + username + "' from " + clientKey);
            // Deliberately vague: do not reveal whether the username exists.
            renderLoginForm(exchange, 401, "Invalid username or password.");
            return;
        }

        rateLimiter.reset(clientKey);

        // Throw away any session the browser already had and always issue a
        // brand-new identifier, which prevents session-fixation attacks.
        String oldSessionId = readCookie(exchange, SESSION_COOKIE);
        if (oldSessionId != null) {
            sessions.invalidate(oldSessionId);
        }
        Session session = sessions.create(UserStore.normalize(username));

        Headers headers = exchange.getResponseHeaders();
        headers.add("Set-Cookie", buildCookie(SESSION_COOKIE, session.id, "/", -1));
        headers.add("Set-Cookie", buildCookie(LOGIN_CSRF_COOKIE, "", "/login", 0));
        log("Successful login for '" + session.username + "' from " + clientKey);
        redirect(exchange, "/welcome");
    }

    private void showWelcomePage(HttpExchange exchange) throws IOException {
        Optional<Session> maybeSession = currentSession(exchange);
        if (maybeSession.isEmpty()) {
            redirect(exchange, "/login");
            return;
        }
        Session session = maybeSession.get();
        String body = """
                <h1>Welcome, %s!</h1>
                <p>You are logged in. Your browser is keeping you signed in with a session cookie.</p>
                <p class="muted">Signed in at %s (UTC).</p>
                <form method="post" action="/logout">
                  <input type="hidden" name="csrf" value="%s">
                  <button type="submit">Log out</button>
                </form>
                """.formatted(
                escapeHtml(session.username),
                escapeHtml(session.createdAt.toString()),
                escapeHtml(session.csrfToken));
        sendHtml(exchange, 200, page("Welcome", body));
    }

    private void handleLogout(HttpExchange exchange) throws IOException, HttpError {
        Map<String, String> form = readForm(exchange);
        Optional<Session> session = currentSession(exchange);
        if (session.isPresent()) {
            if (!constantTimeEquals(session.get().csrfToken, form.get("csrf"))) {
                throw new HttpError(403, "Invalid logout request.");
            }
            sessions.invalidate(session.get().id);
            log("Logout for '" + session.get().username + "'");
        }
        exchange.getResponseHeaders().add("Set-Cookie", buildCookie(SESSION_COOKIE, "", "/", 0));
        redirect(exchange, "/login");
    }

    private void renderLoginForm(HttpExchange exchange, int status, String errorMessage) throws IOException {
        String csrfToken = randomToken(32);
        exchange.getResponseHeaders().add("Set-Cookie",
                buildCookie(LOGIN_CSRF_COOKIE, csrfToken, "/login", LOGIN_FORM_LIFETIME.toSeconds()));

        String error = errorMessage == null ? "" : "<p class=\"error\" role=\"alert\">" + escapeHtml(errorMessage) + "</p>";
        String body = """
                <h1>Sign in</h1>
                %s
                <form method="post" action="/login">
                  <input type="hidden" name="csrf" value="%s">
                  <label for="username">Username</label>
                  <input id="username" name="username" type="text" autocomplete="username" maxlength="%d" required autofocus>
                  <label for="password">Password</label>
                  <input id="password" name="password" type="password" autocomplete="current-password" maxlength="%d" required>
                  <button type="submit">Log in</button>
                </form>
                """.formatted(error, escapeHtml(csrfToken), MAX_USERNAME_LENGTH, MAX_PASSWORD_LENGTH);
        sendHtml(exchange, status, page("Sign in", body));
    }

    // ---------------------------------------------------------------------
    // Cookies and sessions
    // ---------------------------------------------------------------------

    private Optional<Session> currentSession(HttpExchange exchange) {
        return sessions.find(readCookie(exchange, SESSION_COOKIE));
    }

    /**
     * Builds a Set-Cookie header value.
     *
     * @param maxAgeSeconds -1 for a browser-session cookie (removed when the
     *                      browser closes), 0 to delete the cookie, or a lifetime
     */
    private String buildCookie(String name, String value, String path, long maxAgeSeconds) {
        StringBuilder cookie = new StringBuilder()
                .append(name).append('=').append(value)
                .append("; Path=").append(path)
                .append("; HttpOnly")          // not readable from JavaScript
                .append("; SameSite=Strict");  // not sent on cross-site requests
        if (maxAgeSeconds >= 0) {
            cookie.append("; Max-Age=").append(maxAgeSeconds);
        }
        if (secureCookies) {
            cookie.append("; Secure");         // only sent over HTTPS (and localhost)
        }
        return cookie.toString();
    }

    private static String readCookie(HttpExchange exchange, String name) {
        for (String header : exchange.getRequestHeaders().getOrDefault("Cookie", java.util.List.of())) {
            for (String part : header.split(";")) {
                int eq = part.indexOf('=');
                if (eq > 0 && part.substring(0, eq).trim().equals(name)) {
                    return part.substring(eq + 1).trim();
                }
            }
        }
        return null;
    }

    static final class Session {
        final String id;
        final String username;
        final String csrfToken;
        final Instant createdAt;
        volatile Instant lastAccessedAt;

        Session(String id, String username, String csrfToken, Instant createdAt) {
            this.id = id;
            this.username = username;
            this.csrfToken = csrfToken;
            this.createdAt = createdAt;
            this.lastAccessedAt = createdAt;
        }

        boolean isExpired(Instant now) {
            return now.isAfter(lastAccessedAt.plus(SESSION_IDLE_TIMEOUT))
                    || now.isAfter(createdAt.plus(SESSION_ABSOLUTE_TIMEOUT));
        }
    }

    /** Keeps active sessions in memory. Sessions are lost when the server restarts. */
    static final class SessionStore {
        private final Map<String, Session> sessions = new ConcurrentHashMap<>();

        Session create(String username) {
            Session session = new Session(randomToken(32), username, randomToken(32), Instant.now());
            sessions.put(session.id, session);
            return session;
        }

        Optional<Session> find(String sessionId) {
            if (sessionId == null || sessionId.isEmpty()) {
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
            session.lastAccessedAt = now;
            return Optional.of(session);
        }

        void invalidate(String sessionId) {
            sessions.remove(sessionId);
        }

        void purgeExpired() {
            Instant now = Instant.now();
            sessions.values().removeIf(session -> session.isExpired(now));
        }
    }

    // ---------------------------------------------------------------------
    // Users and passwords
    // ---------------------------------------------------------------------

    /** Stores users with salted PBKDF2 password hashes; plain-text passwords are never kept. */
    static final class UserStore {
        private final Map<String, PasswordHash> users = new ConcurrentHashMap<>();
        // Checked when the username does not exist, so that response time does
        // not reveal which usernames are valid.
        private final PasswordHash dummyHash = PasswordHasher.hash(randomToken(16).toCharArray());

        void addUser(String username, char[] password) {
            users.put(normalize(username), PasswordHasher.hash(password));
        }

        boolean authenticate(String username, char[] password) {
            PasswordHash stored = users.get(normalize(username));
            boolean matches = PasswordHasher.verify(password, stored != null ? stored : dummyHash);
            return stored != null && matches;
        }

        static String normalize(String username) {
            return username.trim().toLowerCase(Locale.ROOT);
        }
    }

    record PasswordHash(byte[] salt, int iterations, byte[] hash) {
    }

    static final class PasswordHasher {
        private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
        private static final int ITERATIONS = 600_000;
        private static final int SALT_BYTES = 16;
        private static final int KEY_BITS = 256;

        static PasswordHash hash(char[] password) {
            byte[] salt = new byte[SALT_BYTES];
            RANDOM.nextBytes(salt);
            return new PasswordHash(salt, ITERATIONS, derive(password, salt, ITERATIONS));
        }

        static boolean verify(char[] password, PasswordHash stored) {
            byte[] candidate = derive(password, stored.salt(), stored.iterations());
            return MessageDigest.isEqual(candidate, stored.hash());
        }

        private static byte[] derive(char[] password, byte[] salt, int iterations) {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
            try {
                return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IllegalStateException("Password hashing is unavailable", e);
            } finally {
                spec.clearPassword();
                java.util.Arrays.fill(password, '\0');
            }
        }
    }

    // ---------------------------------------------------------------------
    // Brute-force protection
    // ---------------------------------------------------------------------

    /** Blocks a client address after too many failed logins within a time window. */
    static final class LoginRateLimiter {
        private final Map<String, Deque<Instant>> failures = new ConcurrentHashMap<>();

        boolean isBlocked(String clientKey) {
            Instant now = Instant.now();
            boolean[] blocked = {false};
            failures.computeIfPresent(clientKey, (key, attempts) -> {
                prune(attempts, now);
                blocked[0] = attempts.size() >= MAX_FAILED_LOGINS;
                return attempts.isEmpty() ? null : attempts;
            });
            return blocked[0];
        }

        void recordFailure(String clientKey) {
            Instant now = Instant.now();
            failures.compute(clientKey, (key, attempts) -> {
                Deque<Instant> list = attempts == null ? new ArrayDeque<>() : attempts;
                prune(list, now);
                list.addLast(now);
                return list;
            });
        }

        void reset(String clientKey) {
            failures.remove(clientKey);
        }

        void purge() {
            Instant now = Instant.now();
            for (String key : failures.keySet()) {
                failures.computeIfPresent(key, (k, attempts) -> {
                    prune(attempts, now);
                    return attempts.isEmpty() ? null : attempts;
                });
            }
        }

        private static void prune(Deque<Instant> attempts, Instant now) {
            Instant cutoff = now.minus(FAILED_LOGIN_WINDOW);
            while (!attempts.isEmpty() && attempts.peekFirst().isBefore(cutoff)) {
                attempts.removeFirst();
            }
        }
    }

    // ---------------------------------------------------------------------
    // HTTP helpers
    // ---------------------------------------------------------------------

    static final class HttpError extends Exception {
        private static final long serialVersionUID = 1L;
        final int status;

        HttpError(int status, String message) {
            super(message);
            this.status = status;
        }
    }

    private static Map<String, String> readForm(HttpExchange exchange) throws IOException, HttpError {
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (contentType == null || !contentType.toLowerCase(Locale.ROOT).startsWith("application/x-www-form-urlencoded")) {
            throw new HttpError(415, "Expected a submitted HTML form.");
        }

        byte[] raw;
        try (InputStream in = exchange.getRequestBody()) {
            raw = in.readNBytes(MAX_BODY_BYTES + 1);
        }
        if (raw.length > MAX_BODY_BYTES) {
            throw new HttpError(413, "Request is too large.");
        }

        Map<String, String> form = new HashMap<>();
        String body = new String(raw, StandardCharsets.UTF_8);
        try {
            for (String pair : body.split("&")) {
                if (pair.isEmpty()) {
                    continue;
                }
                int eq = pair.indexOf('=');
                String key = URLDecoder.decode(eq < 0 ? pair : pair.substring(0, eq), StandardCharsets.UTF_8);
                String value = eq < 0 ? "" : URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
                form.putIfAbsent(key, value);
            }
        } catch (IllegalArgumentException e) {
            throw new HttpError(400, "Malformed form data.");
        }
        return form;
    }

    private static void addSecurityHeaders(Headers headers) {
        headers.set("Cache-Control", "no-store");
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-Frame-Options", "DENY");
        headers.set("Referrer-Policy", "no-referrer");
        headers.set("Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    }

    private static void sendHtml(HttpExchange exchange, int status, String html) throws IOException {
        byte[] body = html.getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "text/html; charset=utf-8");
        addSecurityHeaders(headers);
        exchange.sendResponseHeaders(status, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    private static void redirect(HttpExchange exchange, String location) throws IOException {
        Headers headers = exchange.getResponseHeaders();
        headers.set("Location", location);
        addSecurityHeaders(headers);
        exchange.sendResponseHeaders(303, -1);
    }

    private static void sendErrorIfPossible(HttpExchange exchange, int status, String message) {
        if (exchange.getResponseCode() != -1) {
            return; // headers were already sent; nothing more we can do
        }
        try {
            sendHtml(exchange, status, page("Error", "<h1>Error " + status + "</h1><p>"
                    + escapeHtml(message) + "</p><p><a href=\"/login\">Back to sign in</a></p>"));
        } catch (IOException ignored) {
            // client went away
        }
    }

    private static String page(String title, String body) {
        return """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                  <meta charset="utf-8">
                  <meta name="viewport" content="width=device-width, initial-scale=1">
                  <title>%s</title>
                  <style>
                    body { font-family: system-ui, sans-serif; background: #f4f5f7; margin: 0; }
                    main { max-width: 360px; margin: 10vh auto; background: #fff; padding: 2rem; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,.1); }
                    label { display: block; margin-top: 1rem; font-weight: 600; }
                    input[type=text], input[type=password] { width: 100%%; box-sizing: border-box; padding: .5rem; margin-top: .25rem; }
                    button { margin-top: 1.5rem; padding: .6rem 1.2rem; }
                    .error { color: #b00020; }
                    .muted { color: #666; font-size: .9rem; }
                  </style>
                </head>
                <body><main>
                %s
                </main></body>
                </html>
                """.formatted(escapeHtml(title), body);
    }

    // ---------------------------------------------------------------------
    // Small utilities
    // ---------------------------------------------------------------------

    static String randomToken(int byteCount) {
        byte[] bytes = new byte[byteCount];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null || a.isEmpty()) {
            return false;
        }
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    static String escapeHtml(String text) {
        StringBuilder out = new StringBuilder(text.length());
        for (char c : text.toCharArray()) {
            switch (c) {
                case '&' -> out.append("&amp;");
                case '<' -> out.append("&lt;");
                case '>' -> out.append("&gt;");
                case '"' -> out.append("&quot;");
                case '\'' -> out.append("&#39;");
                default -> out.append(c);
            }
        }
        return out.toString();
    }

    private static void log(String message) {
        // Strip control characters so user input cannot forge extra log lines.
        System.out.println(Instant.now() + " " + message.replaceAll("\\p{Cntrl}", "?"));
    }
}
