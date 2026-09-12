import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * SecureLoginServer - a small, dependency-free Java web application that
 * authenticates a user with a username and password and keeps them signed in
 * with a hardened session cookie.
 *
 * <p>Session cookie protections:
 * <ul>
 *   <li><b>HttpOnly</b> - the cookie is invisible to JavaScript
 *       ({@code document.cookie}), so scripts cannot read, overwrite or delete it.</li>
 *   <li><b>Secure</b> - the cookie is only sent over HTTPS (browsers also treat
 *       {@code localhost} as secure for local development).</li>
 *   <li><b>SameSite=Strict</b> - the cookie is not sent on cross-site requests.</li>
 *   <li><b>__Host- prefix</b> - the browser rejects the cookie unless it is Secure,
 *       has Path=/ and no Domain, so a sibling sub-domain cannot plant or shadow it.</li>
 *   <li>The value is an unguessable 256-bit random ID that maps to server-side state;
 *       it carries no user data, so editing it only produces an invalid session.</li>
 * </ul>
 *
 * <p>Run with: {@code java SecureLoginServer.java} (Java 17+).
 */
public final class SecureLoginServer {

    // ---- Tunable settings --------------------------------------------------

    static final String SESSION_COOKIE = "__Host-SESSIONID";
    static final Duration IDLE_TIMEOUT = Duration.ofMinutes(15);
    static final Duration ABSOLUTE_TIMEOUT = Duration.ofHours(8);
    static final int MAX_BODY_BYTES = 4096;
    static final int MAX_USERNAME_LENGTH = 64;
    static final int MAX_PASSWORD_LENGTH = 256;
    static final int MAX_FAILED_ATTEMPTS_PER_USER = 5;
    // Higher than the per-user limit because many people can share one IP address (office, NAT).
    static final int MAX_FAILED_ATTEMPTS_PER_IP = 20;
    static final Duration LOCKOUT_DURATION = Duration.ofMinutes(5);

    static final SecureRandom RANDOM = new SecureRandom();
    static final Pattern TOKEN_PATTERN = Pattern.compile("^[A-Za-z0-9_-]{43}$");

    public static void main(String[] args) throws Exception {
        // Bound how long a client may take to send a request (seconds), so slow
        // clients cannot tie up worker threads forever.
        setDefaultProperty("sun.net.httpserver.maxReqTime", "30");
        setDefaultProperty("sun.net.httpserver.maxRspTime", "30");

        String bindAddress = env("APP_BIND_ADDRESS", "127.0.0.1");
        int port = Integer.parseInt(env("APP_PORT", "8080"));
        String keystorePath = System.getenv("APP_KEYSTORE");
        boolean https = keystorePath != null && !keystorePath.isBlank();

        InetSocketAddress address = new InetSocketAddress(bindAddress, port);
        if (address.isUnresolved()) {
            fail("Cannot resolve bind address: " + bindAddress);
        }
        if (!https && !address.getAddress().isLoopbackAddress()) {
            // A Secure cookie is never stored by a browser over plain HTTP on a
            // real network, and credentials would travel in clear text.
            fail("Refusing to start: plain HTTP is only allowed on a loopback address. "
                    + "Set APP_KEYSTORE and APP_KEYSTORE_PASSWORD to enable HTTPS.");
        }

        UserStore users = new UserStore();
        String demoUsername = env("APP_DEMO_USERNAME", "alice");
        String demoPassword = System.getenv("APP_DEMO_PASSWORD");
        boolean generatedPassword = demoPassword == null || demoPassword.isEmpty();
        if (generatedPassword) {
            demoPassword = randomToken().substring(0, 20);
        }
        if (demoUsername.isEmpty() || demoUsername.length() > MAX_USERNAME_LENGTH
                || demoPassword.length() > MAX_PASSWORD_LENGTH) {
            fail("Demo username or password has an invalid length.");
        }
        users.addUser(demoUsername, demoPassword.toCharArray());

        SessionStore sessions = new SessionStore();
        LoginThrottle throttle = new LoginThrottle();

        HttpServer server = https
                ? createHttpsServer(address, keystorePath)
                : HttpServer.create(address, 0);
        ExecutorService workers = Executors.newFixedThreadPool(16);
        server.setExecutor(workers);
        server.createContext("/", new App(users, sessions, throttle, https));

        ScheduledExecutorService janitor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "session-janitor");
            t.setDaemon(true);
            return t;
        });
        janitor.scheduleAtFixedRate(() -> {
            sessions.purgeExpired();
            throttle.purgeStale();
        }, 1, 1, TimeUnit.MINUTES);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            server.stop(1);
            workers.shutdown();
            janitor.shutdown();
        }));

        server.start();
        String scheme = https ? "https" : "http";
        String host = address.getAddress().isLoopbackAddress() ? "localhost" : bindAddress;
        log("Server started at " + scheme + "://" + host + ":" + port + "/");
        if (generatedPassword) {
            log("No APP_DEMO_PASSWORD set. Demo account -> username: " + demoUsername
                    + "  password: " + demoPassword);
        } else {
            log("Demo account '" + demoUsername + "' loaded from environment.");
        }
    }

    // ---- HTTP handling -----------------------------------------------------

    /** Routes requests and implements the login, home and logout pages. */
    static final class App implements HttpHandler {
        private final UserStore users;
        private final SessionStore sessions;
        private final LoginThrottle throttle;
        private final boolean https;

        App(UserStore users, SessionStore sessions, LoginThrottle throttle, boolean https) {
            this.users = users;
            this.sessions = sessions;
            this.throttle = throttle;
            this.https = https;
        }

        @Override
        public void handle(HttpExchange ex) throws IOException {
            try {
                addSecurityHeaders(ex);
                String path = ex.getRequestURI().getPath();
                String method = ex.getRequestMethod();
                switch (path) {
                    case "/" -> {
                        requireMethod(method, "GET");
                        redirect(ex, currentSession(ex).isPresent() ? "/home" : "/login");
                    }
                    case "/login" -> {
                        if (method.equals("GET")) {
                            showLogin(ex);
                        } else {
                            requireMethod(method, "POST");
                            login(ex);
                        }
                    }
                    case "/home" -> {
                        requireMethod(method, "GET");
                        showHome(ex);
                    }
                    case "/logout" -> {
                        requireMethod(method, "POST");
                        logout(ex);
                    }
                    default -> throw new HttpError(404, "Page not found.");
                }
            } catch (HttpError e) {
                if (e.status == 405) {
                    ex.getResponseHeaders().set("Allow", e.allow);
                }
                sendHtml(ex, e.status, page("Error", "<p>" + escapeHtml(e.getMessage()) + "</p>"
                        + "<p><a href=\"/login\">Back to sign in</a></p>"));
            } catch (Exception e) {
                log("Unexpected error: " + e);
                sendHtml(ex, 500, page("Error", "<p>Something went wrong.</p>"));
            } finally {
                ex.close();
            }
        }

        private void showLogin(HttpExchange ex) throws IOException {
            if (currentSession(ex).isPresent()) {
                redirect(ex, "/home");
                return;
            }
            sendLoginPage(ex, 200, null);
        }

        private void login(HttpExchange ex) throws IOException {
            verifySameOrigin(ex);
            Map<String, String> form = readForm(ex);
            String username = form.getOrDefault("username", "");
            String password = form.getOrDefault("password", "");
            String clientIp = ex.getRemoteAddress().getAddress().getHostAddress();
            String userKey = "user:" + username;
            String ipKey = "ip:" + clientIp;

            if (username.isEmpty() || username.length() > MAX_USERNAME_LENGTH
                    || password.isEmpty() || password.length() > MAX_PASSWORD_LENGTH) {
                sendLoginPage(ex, 400, "Please enter a username and password.");
                return;
            }
            if (throttle.isLocked(userKey) || throttle.isLocked(ipKey)) {
                sendLoginPage(ex, 429, "Too many failed attempts. Please wait a few minutes and try again.");
                return;
            }

            char[] passwordChars = password.toCharArray();
            boolean valid;
            try {
                valid = users.verify(username, passwordChars);
            } finally {
                Arrays.fill(passwordChars, '\0');
            }

            if (!valid) {
                throttle.recordFailure(userKey, MAX_FAILED_ATTEMPTS_PER_USER);
                throttle.recordFailure(ipKey, MAX_FAILED_ATTEMPTS_PER_IP);
                log("Failed sign-in for '" + sanitizeForLog(username) + "' from " + clientIp);
                // Same message whether the username or the password was wrong,
                // so the response does not reveal which accounts exist.
                sendLoginPage(ex, 401, "Invalid username or password.");
                return;
            }

            // Only the per-user counter is cleared; the per-IP counter is kept so an
            // attacker cannot reset it by logging in to an account of their own.
            throttle.reset(userKey);

            // Prevent session fixation: throw away any session ID the browser already
            // had and always issue a brand-new one after authentication.
            readSessionCookie(ex).ifPresent(sessions::invalidate);
            String sessionId = sessions.create(username);
            ex.getResponseHeaders().add("Set-Cookie", sessionCookie(sessionId));
            log("Successful sign-in for '" + sanitizeForLog(username) + "' from " + clientIp);
            redirect(ex, "/home");
        }

        private void showHome(HttpExchange ex) throws IOException {
            Optional<Session> session = currentSession(ex);
            if (session.isEmpty()) {
                if (readSessionCookie(ex).isPresent()) {
                    ex.getResponseHeaders().add("Set-Cookie", expiredSessionCookie());
                }
                redirect(ex, "/login");
                return;
            }
            Session s = session.get();
            String body = "<p>Welcome, <strong>" + escapeHtml(s.username) + "</strong>. You are signed in.</p>"
                    + "<p>Signed in at: " + escapeHtml(s.createdAt.toString()) + " (UTC)</p>"
                    + "<p>Your session cookie is HttpOnly, so scripts on this page cannot read it.</p>"
                    + "<form method=\"post\" action=\"/logout\">"
                    + "<input type=\"hidden\" name=\"csrf\" value=\"" + escapeHtml(s.csrfToken) + "\">"
                    + "<button type=\"submit\">Sign out</button>"
                    + "</form>";
            sendHtml(ex, 200, page("Home", body));
        }

        private void logout(HttpExchange ex) throws IOException {
            verifySameOrigin(ex);
            Optional<String> sessionId = readSessionCookie(ex);
            Optional<Session> session = sessionId.flatMap(sessions::find);
            if (session.isPresent()) {
                String submittedToken = readForm(ex).getOrDefault("csrf", "");
                if (!constantTimeEquals(submittedToken, session.get().csrfToken)) {
                    throw new HttpError(403, "Invalid request token.");
                }
                sessions.invalidate(sessionId.get());
            }
            ex.getResponseHeaders().add("Set-Cookie", expiredSessionCookie());
            redirect(ex, "/login");
        }

        private void sendLoginPage(HttpExchange ex, int status, String error) throws IOException {
            String message = error == null ? "" : "<p role=\"alert\"><strong>" + escapeHtml(error) + "</strong></p>";
            String body = message
                    + "<form method=\"post\" action=\"/login\">"
                    + "<p><label>Username<br><input name=\"username\" autocomplete=\"username\" required maxlength=\""
                    + MAX_USERNAME_LENGTH + "\"></label></p>"
                    + "<p><label>Password<br><input name=\"password\" type=\"password\" autocomplete=\"current-password\""
                    + " required maxlength=\"" + MAX_PASSWORD_LENGTH + "\"></label></p>"
                    + "<p><button type=\"submit\">Sign in</button></p>"
                    + "</form>";
            sendHtml(ex, status, page("Sign in", body));
        }

        private Optional<Session> currentSession(HttpExchange ex) {
            return readSessionCookie(ex).flatMap(sessions::find);
        }

        /**
         * Rejects state-changing requests that originate from another site
         * (defence against cross-site request forgery, including login CSRF).
         */
        private void verifySameOrigin(HttpExchange ex) {
            Headers h = ex.getRequestHeaders();
            String fetchSite = h.getFirst("Sec-Fetch-Site");
            if (fetchSite != null && !fetchSite.equals("same-origin") && !fetchSite.equals("none")) {
                throw new HttpError(403, "Cross-site request rejected.");
            }
            String origin = h.getFirst("Origin");
            if (origin != null) {
                String host = h.getFirst("Host");
                String expected = (https ? "https://" : "http://") + host;
                if (host == null || !origin.equalsIgnoreCase(expected)) {
                    throw new HttpError(403, "Cross-site request rejected.");
                }
            }
        }

        private void addSecurityHeaders(HttpExchange ex) {
            Headers h = ex.getResponseHeaders();
            // No scripts are allowed to run at all on these pages.
            h.set("Content-Security-Policy",
                    "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
            h.set("X-Content-Type-Options", "nosniff");
            h.set("X-Frame-Options", "DENY");
            h.set("Referrer-Policy", "no-referrer");
            h.set("Cache-Control", "no-store");
            if (https) {
                h.set("Strict-Transport-Security", "max-age=31536000");
            }
        }
    }

    // ---- Cookies -----------------------------------------------------------

    /**
     * Builds the session cookie. HttpOnly keeps it away from client-side scripts;
     * Secure, SameSite=Strict and the __Host- prefix limit where it is sent and who can set it.
     * No Max-Age is set, so the browser drops it when closed; the server enforces timeouts.
     */
    static String sessionCookie(String sessionId) {
        return SESSION_COOKIE + "=" + sessionId + "; Path=/; Secure; HttpOnly; SameSite=Strict";
    }

    static String expiredSessionCookie() {
        return SESSION_COOKIE + "=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT;"
                + " Secure; HttpOnly; SameSite=Strict";
    }

    static Optional<String> readSessionCookie(HttpExchange ex) {
        List<String> headers = ex.getRequestHeaders().get("Cookie");
        if (headers == null) {
            return Optional.empty();
        }
        for (String header : headers) {
            for (String part : header.split(";")) {
                String pair = part.trim();
                int eq = pair.indexOf('=');
                if (eq > 0 && pair.substring(0, eq).equals(SESSION_COOKIE)) {
                    return Optional.of(pair.substring(eq + 1));
                }
            }
        }
        return Optional.empty();
    }

    // ---- Users and password hashing ---------------------------------------

    /** Stores users with salted PBKDF2 password hashes; plain-text passwords are never kept. */
    static final class UserStore {
        private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
        private static final int ITERATIONS = 600_000;
        private static final int SALT_BYTES = 16;
        private static final int HASH_BITS = 256;

        private record Credential(byte[] salt, byte[] hash) {
        }

        private final Map<String, Credential> users = new ConcurrentHashMap<>();
        // Used when the username does not exist so that the response takes the same
        // time as for a real account, which avoids revealing valid usernames.
        private final Credential dummy = newCredential(randomToken().toCharArray());

        void addUser(String username, char[] password) {
            try {
                users.put(username, newCredential(password));
            } finally {
                Arrays.fill(password, '\0');
            }
        }

        boolean verify(String username, char[] password) {
            Credential stored = users.get(username);
            Credential target = stored != null ? stored : dummy;
            byte[] candidate = pbkdf2(password, target.salt());
            boolean matches = MessageDigest.isEqual(candidate, target.hash());
            Arrays.fill(candidate, (byte) 0);
            return stored != null && matches;
        }

        private static Credential newCredential(char[] password) {
            byte[] salt = new byte[SALT_BYTES];
            RANDOM.nextBytes(salt);
            return new Credential(salt, pbkdf2(password, salt));
        }

        private static byte[] pbkdf2(char[] password, byte[] salt) {
            PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, HASH_BITS);
            try {
                return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("Password hashing is unavailable", e);
            } finally {
                spec.clearPassword();
            }
        }
    }

    // ---- Sessions ----------------------------------------------------------

    static final class Session {
        final String username;
        final String csrfToken;
        final Instant createdAt;
        volatile Instant lastAccess;

        Session(String username, String csrfToken, Instant createdAt) {
            this.username = username;
            this.csrfToken = csrfToken;
            this.createdAt = createdAt;
            this.lastAccess = createdAt;
        }

        boolean isExpired(Instant now) {
            return now.isAfter(lastAccess.plus(IDLE_TIMEOUT)) || now.isAfter(createdAt.plus(ABSOLUTE_TIMEOUT));
        }
    }

    /**
     * Server-side session storage. Sessions are indexed by the SHA-256 hash of the
     * session ID, so the raw IDs are never kept in memory and lookups do not leak
     * timing information about valid IDs.
     */
    static final class SessionStore {
        private final Map<String, Session> sessions = new ConcurrentHashMap<>();

        String create(String username) {
            String sessionId = randomToken();
            Instant now = Instant.now();
            sessions.put(sha256(sessionId), new Session(username, randomToken(), now));
            return sessionId;
        }

        Optional<Session> find(String sessionId) {
            if (!TOKEN_PATTERN.matcher(sessionId).matches()) {
                return Optional.empty();
            }
            String key = sha256(sessionId);
            Session session = sessions.get(key);
            if (session == null) {
                return Optional.empty();
            }
            Instant now = Instant.now();
            if (session.isExpired(now)) {
                sessions.remove(key, session);
                return Optional.empty();
            }
            session.lastAccess = now;
            return Optional.of(session);
        }

        void invalidate(String sessionId) {
            if (TOKEN_PATTERN.matcher(sessionId).matches()) {
                sessions.remove(sha256(sessionId));
            }
        }

        void purgeExpired() {
            Instant now = Instant.now();
            sessions.values().removeIf(s -> s.isExpired(now));
        }
    }

    // ---- Brute-force protection -------------------------------------------

    /** Temporarily blocks a username or client IP after repeated failed sign-ins. */
    static final class LoginThrottle {
        private static final int MAX_TRACKED_KEYS = 100_000;

        private record Entry(int failures, Instant lockedUntil, Instant lastFailure) {
        }

        private final Map<String, Entry> entries = new ConcurrentHashMap<>();

        boolean isLocked(String key) {
            Entry entry = entries.get(key);
            return entry != null && entry.lockedUntil().isAfter(Instant.now());
        }

        void recordFailure(String key, int maxFailures) {
            if (entries.size() >= MAX_TRACKED_KEYS && !entries.containsKey(key)) {
                return; // keep memory bounded under a flood of random usernames
            }
            Instant now = Instant.now();
            entries.compute(key, (k, old) -> {
                // Failures older than the lockout window no longer count.
                int failures = old == null || old.lastFailure().isBefore(now.minus(LOCKOUT_DURATION))
                        ? 1 : old.failures() + 1;
                Instant lockedUntil = old == null ? Instant.EPOCH : old.lockedUntil();
                if (failures >= maxFailures) {
                    return new Entry(0, now.plus(LOCKOUT_DURATION), now);
                }
                return new Entry(failures, lockedUntil, now);
            });
        }

        void reset(String key) {
            entries.remove(key);
        }

        void purgeStale() {
            Instant now = Instant.now();
            Instant cutoff = now.minus(LOCKOUT_DURATION);
            entries.values().removeIf(e -> !e.lockedUntil().isAfter(now) && e.lastFailure().isBefore(cutoff));
        }
    }

    // ---- HTTPS -------------------------------------------------------------

    static HttpServer createHttpsServer(InetSocketAddress address, String keystorePath) throws Exception {
        String keystorePassword = System.getenv("APP_KEYSTORE_PASSWORD");
        if (keystorePassword == null) {
            fail("APP_KEYSTORE_PASSWORD must be set when APP_KEYSTORE is used.");
        }
        char[] password = keystorePassword.toCharArray();
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(Path.of(keystorePath))) {
                keyStore.load(in, password);
            }
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, password);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(kmf.getKeyManagers(), null, RANDOM);

            HttpsServer server = HttpsServer.create(address, 0);
            server.setHttpsConfigurator(new HttpsConfigurator(context) {
                @Override
                public void configure(HttpsParameters params) {
                    SSLParameters sslParams = context.getDefaultSSLParameters();
                    sslParams.setProtocols(new String[] {"TLSv1.3", "TLSv1.2"});
                    params.setSSLParameters(sslParams);
                }
            });
            return server;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    // ---- Helpers -----------------------------------------------------------

    static final class HttpError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        final int status;
        final String allow;

        HttpError(int status, String message) {
            this(status, message, null);
        }

        HttpError(int status, String message, String allow) {
            super(message);
            this.status = status;
            this.allow = allow;
        }
    }

    static void requireMethod(String actual, String expected) {
        if (!actual.equals(expected)) {
            throw new HttpError(405, "Method not allowed.", expected);
        }
    }

    static Map<String, String> readForm(HttpExchange ex) throws IOException {
        String contentType = ex.getRequestHeaders().getFirst("Content-Type");
        if (contentType == null || !contentType.toLowerCase(Locale.ROOT).startsWith("application/x-www-form-urlencoded")) {
            throw new HttpError(415, "Unsupported form encoding.");
        }
        byte[] body;
        try (InputStream in = ex.getRequestBody()) {
            body = in.readNBytes(MAX_BODY_BYTES + 1);
        }
        if (body.length > MAX_BODY_BYTES) {
            throw new HttpError(413, "Request is too large.");
        }
        Map<String, String> form = new HashMap<>();
        String text = new String(body, StandardCharsets.UTF_8);
        try {
            for (String pair : text.split("&")) {
                if (pair.isEmpty()) {
                    continue;
                }
                int eq = pair.indexOf('=');
                String name = URLDecoder.decode(eq < 0 ? pair : pair.substring(0, eq), StandardCharsets.UTF_8);
                String value = eq < 0 ? "" : URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
                form.putIfAbsent(name, value);
            }
        } catch (IllegalArgumentException e) {
            throw new HttpError(400, "Malformed form data.");
        }
        return form;
    }

    static void redirect(HttpExchange ex, String location) throws IOException {
        ex.getResponseHeaders().set("Location", location);
        ex.sendResponseHeaders(303, -1);
    }

    static void sendHtml(HttpExchange ex, int status, String html) throws IOException {
        byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = ex.getResponseBody()) {
            out.write(bytes);
        }
    }

    static String page(String title, String body) {
        return "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                + "<title>" + escapeHtml(title) + "</title></head><body>"
                + "<h1>" + escapeHtml(title) + "</h1>" + body + "</body></html>";
    }

    static String escapeHtml(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (char c : s.toCharArray()) {
            switch (c) {
                case '&' -> sb.append("&amp;");
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '"' -> sb.append("&quot;");
                case '\'' -> sb.append("&#39;");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }

    static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    /** 32 bytes (256 bits) from a cryptographically secure generator, Base64URL-encoded. */
    static String randomToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Strips control characters so user input cannot forge extra log lines. */
    static String sanitizeForLog(String s) {
        return s.replaceAll("[^\\x20-\\x7E]", "?");
    }

    static String env(String name, String defaultValue) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? defaultValue : value;
    }

    static void setDefaultProperty(String name, String value) {
        if (System.getProperty(name) == null) {
            System.setProperty(name, value);
        }
    }

    static void log(String message) {
        System.out.println(Instant.now() + " " + message);
    }

    static void fail(String message) {
        System.err.println(message);
        System.exit(1);
    }
}
