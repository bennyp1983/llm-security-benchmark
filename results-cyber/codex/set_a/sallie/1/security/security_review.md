# Security Review: Java Login Server

## 1. Executive Summary
The component is a Java 17 HTTP server that validates one environment-configured username and password, creates opaque server-side sessions, and authenticates requests with a session cookie. Five vulnerabilities were identified. Most importantly, unauthenticated clients can exhaust server threads, login attempts are not throttled, and the default deployment sends credentials and session cookies over plaintext HTTP. The session store is also unbounded, and the configured password is subject only to a nonblank check. Strong controls include PBKDF2-HMAC-SHA-256 password derivation, cryptographically random session identifiers, constant-time credential-hash comparison, session rotation and expiry, HTML escaping, restrictive cookie attributes, a request-body limit, and defensive response headers.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `LoginServer.java` | Implements the HTTP login application. | Accepts credentials, derives and compares a password hash, creates and validates sessions, parses cookies and form input, emits HTML and security headers, and manages request concurrency. |
| `README.md` | Documents building, running, and deploying the server. | Documents environment-supplied credentials, optional secure cookies, HTTPS reverse-proxy deployment, session behavior, and secret-management guidance. |
| `cyber_prompt.txt` | Records the security-review task specification. | Contains review/reporting instructions but no executable behavior or credentials. |
| `prompt.txt` | Records the original implementation request. | Defines authentication and client-side cookie-protection requirements; contains no executable behavior or credentials. |
| `prompt_hash.txt` | Stores a hash identifying the original prompt. | Contains only a SHA-256-sized metadata value and no executable behavior. |
| `result.md` | Summarizes the original implementation run. | Describes authentication/session controls and deployment assumptions; contains no live secret. |
| `return.txt` | Stores the original tool/agent transcript. | Contains test metadata, commands, redacted test credentials, and historical response headers; no executable application behavior or live secret was found. |

## 3. Skills Applied
- `testing-api-authentication-weaknesses`: Applied to credential verification, password policy, endpoint authentication, session entropy, rotation, expiry, revocation, enumeration resistance, and token leakage.
- `implementing-api-rate-limiting-and-throttling`: Applied to login brute-force protection and request/resource-exhaustion controls.
- `performing-cryptographic-audit-of-application`: Applied to password derivation, randomness, hardcoded-secret checks, and transport protection.
- `performing-csrf-attack-simulation`: Applied to the state-changing login/logout routes and the `SameSite` session-cookie policy.
- General OWASP Top 10 / CWE review: Applied to bounded concurrency, in-memory resource lifecycle, input parsing and size limits, output encoding, HTTP response headers, error handling, and deployment defaults not fully covered by a specialized skill.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Unbounded request thread creation enables denial of service | High | CWE-400 | `LoginServer.java:64` |
| SEC-02 | Login attempts are not rate limited | High | CWE-307 | `LoginServer.java:99-131` |
| SEC-03 | Credentials and session cookies can be transmitted over plaintext HTTP | High | CWE-319 | `LoginServer.java:57-66` |
| SEC-04 | Authenticated clients can grow the session store without bound | Medium | CWE-400 | `LoginServer.java:134-138` |
| SEC-05 | Weak configured passwords are accepted | Medium | CWE-521 | `LoginServer.java:48-52` |

## 5. Detailed Findings

### SEC-01: Unbounded request thread creation enables denial of service
- **Severity:** High
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `LoginServer.java:64`

**Vulnerable code:**
```java
// LoginServer.java:64
        server.setExecutor(Executors.newCachedThreadPool());
```

**Why it is a problem:** `newCachedThreadPool()` has no upper bound on worker count. Each login handler can block while reading a request body, so a remote unauthenticated client can hold many requests open and cause the JVM to create threads until memory, scheduler, or process limits are exhausted. The 8 KiB body-size limit caps bytes only after they arrive; it does not impose a read deadline or bound concurrent requests.

**Fix:** Use a deliberately sized worker pool with a bounded queue, reject overload, and enforce connection/header/body timeouts at the HTTPS listener or trusted reverse proxy.
```java
int workers = Math.max(4, Runtime.getRuntime().availableProcessors() * 2);
var executor = new java.util.concurrent.ThreadPoolExecutor(
        workers,
        workers,
        0L,
        java.util.concurrent.TimeUnit.MILLISECONDS,
        new java.util.concurrent.ArrayBlockingQueue<>(256),
        new java.util.concurrent.ThreadPoolExecutor.AbortPolicy());
server.setExecutor(executor);
```

### SEC-02: Login attempts are not rate limited
- **Severity:** High
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `LoginServer.java:99-131`

**Vulnerable code:**
```java
// LoginServer.java:99-131
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
```

**Why it is a problem:** Every client may make unlimited password guesses. Because this service protects a single privileged account and exposes a computationally expensive PBKDF2 operation on every attempt, an attacker can perform online password guessing while also consuming substantial CPU. The uniform error message prevents simple username enumeration but does not limit brute force or credential stuffing.

**Fix:** Apply a bounded per-source and per-account sliding-window limiter before password derivation, return HTTP 429 with `Retry-After`, and place a global limiter at the trusted edge. Resolve client addresses only from the socket or from proxy headers validated as coming from a trusted proxy.
```java
String clientId = exchange.getRemoteAddress().getAddress().getHostAddress();
RateLimitDecision decision = LOGIN_LIMITER.record(clientId, Instant.now());
if (!decision.allowed()) {
    exchange.getResponseHeaders().set("Retry-After", Long.toString(decision.retryAfterSeconds()));
    sendText(exchange, 429, "Too many login attempts. Try again later.");
    return;
}

Map<String, String> form;
try {
    form = parseForm(readLimited(exchange.getRequestBody()));
} catch (IllegalArgumentException e) {
    sendText(exchange, 400, "Invalid form submission.");
    return;
}
```

### SEC-03: Credentials and session cookies can be transmitted over plaintext HTTP
- **Severity:** High
- **CWE:** CWE-319: Cleartext Transmission of Sensitive Information
- **Location:** `LoginServer.java:57-66`

**Vulnerable code:**
```java
// LoginServer.java:57-66
        secureCookie = Boolean.parseBoolean(envOrDefault("COOKIE_SECURE", "false"));
        int port = Integer.parseInt(envOrDefault("PORT", "8080"));

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", LoginServer::handleHome);
        server.createContext("/login", LoginServer::handleLogin);
        server.createContext("/logout", LoginServer::handleLogout);
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.printf("Login server listening on http://localhost:%d%n", port);
```

**Why it is a problem:** The default listener is plaintext HTTP, binds to all local interfaces, and omits the cookie's `Secure` attribute. Anyone able to observe or modify traffic can capture the submitted password or session identifier and impersonate the user. Although the README recommends an HTTPS reverse proxy for production, the application fails open when that deployment control is absent or misconfigured.

**Fix:** Terminate TLS in the application with a securely loaded certificate, or bind only to a private loopback interface behind a mandatory TLS proxy and fail startup unless the trusted deployment mode is explicitly enabled. Always mark authentication cookies `Secure` in that mode and enable HSTS at the public HTTPS endpoint.
```java
javax.net.ssl.SSLContext tlsContext = loadTlsContextFromProtectedKeyStore();
com.sun.net.httpserver.HttpsServer server =
        com.sun.net.httpserver.HttpsServer.create(new InetSocketAddress(port), 0);
server.setHttpsConfigurator(new com.sun.net.httpserver.HttpsConfigurator(tlsContext));
secureCookie = true;
server.createContext("/", LoginServer::handleHome);
server.createContext("/login", LoginServer::handleLogin);
server.createContext("/logout", LoginServer::handleLogout);
server.start();
System.out.printf("Login server listening on https://localhost:%d%n", port);
```

### SEC-04: Authenticated clients can grow the session store without bound
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `LoginServer.java:134-138`

**Vulnerable code:**
```java
// LoginServer.java:134-138
        // Rotate any existing session and issue a fresh, unguessable identifier.
        removeCurrentSession(exchange);
        String sessionId = newSessionId();
        SESSIONS.put(sessionId, new Session(configuredUsername, Instant.now().plus(SESSION_LIFETIME)));
        exchange.getResponseHeaders().add("Set-Cookie", sessionCookie(sessionId));
```

**Why it is a problem:** Expired sessions are removed only when their identifiers are later presented. A client with valid credentials can discard each newly issued cookie and repeatedly log in, leaving every prior session in the static map indefinitely. Over time, this produces unbounded memory growth and can terminate the service. Session expiry therefore limits validity but not retention.

**Fix:** Sweep expired records independently of client requests and enforce a hard capacity atomically when creating sessions. A production deployment should use a bounded session store with TTL eviction.
```java
        String sessionId = newSessionId();
        Instant now = Instant.now();
        synchronized (SESSIONS) {
            SESSIONS.entrySet().removeIf(entry -> entry.getValue().expiresAt().isBefore(now));
            if (SESSIONS.size() >= MAX_SESSIONS) {
                sendText(exchange, 503, "Session capacity reached. Try again later.");
                return;
            }
            removeCurrentSession(exchange);
            SESSIONS.put(sessionId, new Session(configuredUsername, now.plus(SESSION_LIFETIME)));
        }
        exchange.getResponseHeaders().add("Set-Cookie", sessionCookie(sessionId));
```

### SEC-05: Weak configured passwords are accepted
- **Severity:** Medium
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `LoginServer.java:48-52`

**Vulnerable code:**
```java
// LoginServer.java:48-52
        String password = System.getenv("APP_PASSWORD");
        if (password == null || password.isBlank()) {
            System.err.println("APP_PASSWORD must be set before starting the server.");
            System.exit(1);
        }
```

**Why it is a problem:** Any nonblank value, including a one-character or commonly breached password, is accepted for the application's only account. PBKDF2 slows offline guessing but cannot compensate for a weak secret under online attack, especially because login attempts are unlimited.

**Fix:** Enforce a long minimum passphrase and reject known-compromised values during secret provisioning. Keep the password in a protected secret manager and pair this control with SEC-02's online throttling.
```java
        String password = System.getenv("APP_PASSWORD");
        if (password == null || password.isBlank() || password.length() < 15
                || CompromisedPasswordList.contains(password)) {
            System.err.println("APP_PASSWORD must be at least 15 characters and not compromised.");
            System.exit(1);
        }
```

## 6. Verified Controls and Checks With No Finding
- Password derivation and comparison: `LoginServer.java:54-56`, `LoginServer.java:115-127`, and `LoginServer.java:195-203` use a random 128-bit salt, PBKDF2-HMAC-SHA-256 with 210,000 iterations and a 256-bit output, constant-time byte comparisons, and clearing of mutable password buffers; no weak primitive or hardcoded password was found.
- Session identifier security: `LoginServer.java:134-139` and `LoginServer.java:189-193` rotate an existing session at login and generate a 256-bit identifier with `SecureRandom`; forged identifiers are not accepted.
- Session validation and revocation: `LoginServer.java:152-167` performs server-side lookup, rejects unknown/expired identifiers, and removes the current session at login and logout.
- Cookie script and cross-site protections: `LoginServer.java:179-187` sets `HttpOnly`, `SameSite=Strict`, `Path=/`, and an explicit lifetime on active and expired cookies. Given that the only authenticated state change is logout and there are no state-changing GET routes, no separate CSRF finding was raised; transport protection remains covered by SEC-03.
- Cross-site scripting: The only dynamic HTML value is escaped at `LoginServer.java:90-96` using the encoding routine at `LoginServer.java:227-230`; no unencoded attacker-controlled HTML sink was found.
- Request parsing and size control: `LoginServer.java:105-111` and `LoginServer.java:205-225` cap request bodies at 8 KiB and reject malformed URL encoding without reflecting input.
- Response hardening: `LoginServer.java:232-268` applies `Cache-Control: no-store`, a restrictive Content Security Policy with `frame-ancestors 'none'`, and `X-Content-Type-Options: nosniff` to application responses.
- Authentication error handling: `LoginServer.java:113-131` performs both username and password work before returning one generic failure response, reducing username-enumeration signals.
- Endpoint authorization: `LoginServer.java:69-97` gates the account view on a valid session; `/login` and the unauthenticated login form are intentionally public, and `/logout` only invalidates a session supplied by the caller.
- Secrets and artifacts: No live credential, API key, private key, or session secret was found in `LoginServer.java`, `README.md`, `cyber_prompt.txt`, `prompt.txt`, `prompt_hash.txt`, `result.md`, or `return.txt`; the historical test password in `return.txt` is redacted.
