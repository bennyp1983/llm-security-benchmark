# Security Review: Java Session Authentication Server

## 1. Executive Summary
The component is a Java 17 HTTP server that accepts one configured username and password, creates opaque server-side sessions, authenticates requests with a cookie, renders a protected home page, and supports logout. Seven vulnerabilities were identified: known default credentials and cleartext HTTP are High severity; missing login throttling, fast password hashing, unbounded session retention, and an unbounded request executor are Medium severity; and login CSRF is Low severity. The strongest existing controls are cryptographically random session identifiers, constant-time comparisons, session rotation and revocation, HTML escaping, restrictive response headers, and an 8 KiB form-body limit.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/SessionAuthServer.java` | Complete application source. | Handles network binding and HTTP, credentials, authentication, cookie issuance/parsing, in-memory session lifecycle, request parsing, HTML output, redirects, and security headers. |
| `pom.xml` | Maven build descriptor targeting Java 17. | Pins the compiler plugin and introduces no third-party runtime dependency. |
| `README.md` | Operator and usage documentation. | Documents default credentials, plain-HTTP startup, optional `Secure` cookies, HTTPS expectations, and acknowledged production hardening gaps. |
| `target/classes/com/example/SessionAuthServer.class` | Generated application bytecode. | Compiled form of the reviewed Java source. |
| `target/classes/com/example/SessionAuthServer$Session.class` | Generated session-record bytecode. | Stores a username and absolute session expiry. |
| `target/classes/com/example/SessionAuthServer$BadRequestException.class` | Generated exception bytecode. | Represents malformed request errors. |
| `target/session-auth-demo-1.0.0.jar` | Generated application archive. | Packages the compiled classes and Maven metadata; its executable behaviour derives from the reviewed source. |
| `target/maven-archiver/pom.properties` | Generated artifact metadata. | Contains artifact coordinates only; no secrets or runtime logic. |
| `target/maven-status/maven-compiler-plugin/compile/default-compile/createdFiles.lst` | Generated compiler output manifest. | Lists the three generated class files; no runtime logic. |
| `target/maven-status/maven-compiler-plugin/compile/default-compile/inputFiles.lst` | Generated compiler input manifest. | Identifies the reviewed Java source; exposes only a local build path. |
| `prompt.txt` | Original implementation request. | Non-executable task text; requests username/password authentication and session cookies. |
| `cyber_prompt.txt` | Security-review task specification. | Non-executable review instructions; no application behaviour. |
| `prompt_hash.txt` | Digest of task input. | Non-executable SHA-256 value; not an application credential. |
| `result.md` | Prior run summary. | Non-executable metadata and implementation claims; no active secret. |
| `return.txt` | Prior run transcript. | Non-executable command transcript; the password used in testing is redacted. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: used to inventory the component, identify security behaviours, select specialized reviews, and structure evidence-backed findings.
- `testing-api-authentication-weaknesses`: applied to endpoint protection, credential handling, account-enumeration resistance, session entropy, expiry, rotation, revocation, and authentication abuse.
- `performing-cryptographic-audit-of-application`: applied to password hashing, random session-token generation, hardcoded credential material, and transport cryptography.
- `configuring-tls-1-3-for-secure-communications`: applied to the HTTP listener, credential transport, cookie transport flags, and the absence of TLS/HSTS.
- `implementing-api-rate-limiting-and-throttling`: applied to brute-force protection and request/session resource-exhaustion paths.
- `performing-csrf-attack-simulation`: applied to the state-changing login and logout forms, SameSite behaviour, and the absence of CSRF tokens or Origin validation.
- `testing-for-xss-vulnerabilities`: applied to all request-derived output, HTML contexts, output encoding, CSP, and cookie theft mitigations.
- `implementing-secret-scanning-with-gitleaks`: applied manually to source, configuration, documentation, and recorded transcripts for embedded passwords, keys, and tokens.
- General OWASP Top 10 / CWE knowledge: applied to Java executor bounds, stale-object lifecycle, HTTP parsing, error handling, dependency/build configuration, and attack surfaces for which no narrower matching skill was available.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Known credentials are used when configuration is absent | High | CWE-1392 | `src/main/java/com/example/SessionAuthServer.java:41-42` |
| SEC-02 | Credentials and session cookies can traverse cleartext HTTP | High | CWE-319 | `src/main/java/com/example/SessionAuthServer.java:44-51` |
| SEC-03 | Login attempts are not rate limited | Medium | CWE-307 | `src/main/java/com/example/SessionAuthServer.java:108-116` |
| SEC-04 | Password verification uses a fast, unsalted SHA-256 digest | Medium | CWE-916 | `src/main/java/com/example/SessionAuthServer.java:208-210` |
| SEC-05 | Session storage grows without a hard bound or proactive cleanup | Medium | CWE-400 | `src/main/java/com/example/SessionAuthServer.java:120-123` |
| SEC-06 | The request executor can create an unbounded number of threads | Medium | CWE-400 | `src/main/java/com/example/SessionAuthServer.java:49` |
| SEC-07 | The login action has no CSRF validation | Low | CWE-352 | `src/main/java/com/example/SessionAuthServer.java:100-104` |

## 5. Detailed Findings

### SEC-01: Known credentials are used when configuration is absent
- **Severity:** High
- **CWE:** CWE-1392: Use of Default Credentials
- **Location:** `src/main/java/com/example/SessionAuthServer.java:41-42`

**Vulnerable code:**
```java
// src/main/java/com/example/SessionAuthServer.java:41-42
        String username = env("APP_USERNAME", "demo");
        String password = env("APP_PASSWORD", "change-me");
```

**Why it is a problem:** If either environment variable is missing or blank, the server starts with the publicly documented `demo` / `change-me` credentials. The listener created at line 47 binds by port without a loopback address, so the service can be reachable from other hosts. An attacker who finds such an instance can authenticate without guessing or bypassing any control.

**Fix:** Fail closed when either credential is absent, and provision a unique strong secret through the deployment's secret manager. Do not accept blank values or ship a usable fallback.
```java
        String username = requiredEnv("APP_USERNAME");
        String password = requiredEnv("APP_PASSWORD");

    private static String requiredEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " must be configured");
        }
        return value;
    }
```

### SEC-02: Credentials and session cookies can traverse cleartext HTTP
- **Severity:** High
- **CWE:** CWE-319: Cleartext Transmission of Sensitive Information
- **Location:** `src/main/java/com/example/SessionAuthServer.java:44-51`

**Vulnerable code:**
```java
// src/main/java/com/example/SessionAuthServer.java:44-51
        boolean secure = Boolean.parseBoolean(env("SESSION_COOKIE_SECURE", "false"));

        SessionAuthServer app = new SessionAuthServer(username, password, secure);
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", app::route);
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.printf("Listening on http://localhost:%d (cookie Secure=%s)%n", port, secure);
```

**Why it is a problem:** The application natively serves HTTP, and the session cookie's `Secure` attribute is disabled by default at lines 44 and 152. A user following the default startup path submits the password and later sends the bearer session identifier without transport encryption, allowing an on-path attacker to read or modify them. Documentation recommending an external HTTPS deployment does not enforce that security property in code.

**Fix:** Terminate TLS in the application with an `HttpsServer` (or place the service behind a correctly configured TLS reverse proxy while binding this listener only to loopback), require TLS 1.2 or 1.3, always mark authentication cookies `Secure`, and enable HSTS on externally served HTTPS responses. A direct-TLS configuration should resemble the following, with `loadTlsContext()` loading a deployment-managed certificate and private key.
```java
        boolean secure = true;

        SessionAuthServer app = new SessionAuthServer(username, password, secure);
        SSLContext tlsContext = loadTlsContext();
        HttpsServer server = HttpsServer.create(new InetSocketAddress(port), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(tlsContext));
        server.createContext("/", app::route);
        server.setExecutor(boundedExecutor());
        server.start();
        System.out.printf("Listening on https://localhost:%d%n", port);
```

### SEC-03: Login attempts are not rate limited
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/example/SessionAuthServer.java:108-116`

**Vulnerable code:**
```java
// src/main/java/com/example/SessionAuthServer.java:108-116
    private void logIn(HttpExchange exchange) throws IOException {
        requireFormContentType(exchange);
        Map<String, String> form = parseForm(readLimitedBody(exchange));
        String username = form.getOrDefault("username", "");
        String password = form.getOrDefault("password", "");

        if (!constantTimeEquals(username, expectedUsername)
                | !MessageDigest.isEqual(digest(password), expectedPasswordDigest)) {
            showLogin(exchange, true);
```

**Why it is a problem:** Every caller can make unlimited password guesses. This enables online brute force and credential stuffing and also provides a cheap way to consume CPU, especially once password verification is upgraded to an intentionally expensive KDF. The generic failure response prevents straightforward username enumeration but does not limit guesses.

**Fix:** Enforce bounded attempt rates by both trusted client IP and normalized account identifier, return `429` with `Retry-After`, add progressive backoff, and monitor repeated failures. In a multi-instance deployment, keep counters in a shared atomic store rather than process memory.
```java
    private void logIn(HttpExchange exchange) throws IOException {
        requireFormContentType(exchange);
        Map<String, String> form = parseForm(readLimitedBody(exchange));
        String username = form.getOrDefault("username", "");
        String password = form.getOrDefault("password", "");

        RateLimitDecision decision = loginLimiter.check(
                exchange.getRemoteAddress().getAddress(), username);
        if (!decision.allowed()) {
            exchange.getResponseHeaders().set("Retry-After", Long.toString(decision.retryAfterSeconds()));
            sendHtml(exchange, 429, page("Too many requests", "<h1>Try again later</h1>"));
            return;
        }

        if (!constantTimeEquals(username, expectedUsername)
                | !verifyPassword(password, expectedPasswordHash)) {
            loginLimiter.recordFailure(exchange.getRemoteAddress().getAddress(), username);
            showLogin(exchange, true);
            return;
        }
```

### SEC-04: Password verification uses a fast, unsalted SHA-256 digest
- **Severity:** Medium
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `src/main/java/com/example/SessionAuthServer.java:208-210`

**Vulnerable code:**
```java
// src/main/java/com/example/SessionAuthServer.java:208-210
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
```

**Why it is a problem:** Plain SHA-256 is deliberately fast and the code adds neither a unique salt nor a work factor. The digest retained in application memory is therefore inexpensive to attack offline if exposed through a heap dump, core dump, debugger, or process compromise. Hashing the configured password once does not turn SHA-256 into a password-storage algorithm.

**Fix:** Store a salted password verifier produced by Argon2id, scrypt, bcrypt, or PBKDF2 with a reviewed work factor, ideally provisioned as an encoded verifier rather than receiving the plaintext password at runtime. The JDK-only fallback below illustrates PBKDF2; its iteration count should be performance-tested and periodically increased.
```java
    private static byte[] derivePassword(String value, byte[] salt) {
        char[] password = value.toCharArray();
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, 600_000, 256);
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        } finally {
            Arrays.fill(password, '\0');
        }
    }
```

### SEC-05: Session storage grows without a hard bound or proactive cleanup
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/example/SessionAuthServer.java:120-123`

**Vulnerable code:**
```java
// src/main/java/com/example/SessionAuthServer.java:120-123
        removeCurrentSession(exchange);
        String sessionId = newSessionId();
        sessions.put(sessionId, new Session(username, Instant.now().plus(SESSION_LIFETIME)));
        exchange.getResponseHeaders().add("Set-Cookie", sessionCookie(sessionId));
```

**Why it is a problem:** Each successful login inserts a new entry into an unbounded `ConcurrentHashMap`. Expired entries are removed only when that exact session identifier is presented again at lines 138-140. A user can repeatedly authenticate without returning the prior cookie, leaving both live and expired entries resident indefinitely until the process exhausts memory; the known fallback credential makes exploitation especially easy.

**Fix:** Proactively evict expired sessions, impose a global capacity and a per-account session limit, and reject or evict deterministically when those limits are reached. For multiple instances, use a session store with TTL and capacity controls.
```java
    private static final int MAX_SESSIONS = 10_000;

    private synchronized boolean storeSession(String id, Session session) {
        Instant now = Instant.now();
        sessions.entrySet().removeIf(entry -> !entry.getValue().expiresAt().isAfter(now));
        if (sessions.size() >= MAX_SESSIONS) {
            return false;
        }
        sessions.put(id, session);
        return true;
    }

        removeCurrentSession(exchange);
        String sessionId = newSessionId();
        if (!storeSession(sessionId, new Session(username, Instant.now().plus(SESSION_LIFETIME)))) {
            sendHtml(exchange, 503, page("Unavailable", "<h1>Try again later</h1>"));
            return;
        }
        exchange.getResponseHeaders().add("Set-Cookie", sessionCookie(sessionId));
```

### SEC-06: The request executor can create an unbounded number of threads
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/example/SessionAuthServer.java:49`

**Vulnerable code:**
```java
// src/main/java/com/example/SessionAuthServer.java:49
        server.setExecutor(Executors.newCachedThreadPool());
```

**Why it is a problem:** `newCachedThreadPool()` has no maximum worker count and uses an unbounded handoff strategy. An attacker can hold requests open or create sufficient concurrent work to force continual thread creation, consuming memory and scheduler capacity until legitimate requests fail or the process terminates. The application also sets no request-level read deadline.

**Fix:** Use a measured maximum worker count and bounded queue, reject excess work, and enforce connection/header/body timeouts at the server or a fronting reverse proxy.
```java
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
                8,
                64,
                60L,
                TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(256),
                new ThreadPoolExecutor.AbortPolicy());
        server.setExecutor(executor);
```

### SEC-07: The login action has no CSRF validation
- **Severity:** Low
- **CWE:** CWE-352: Cross-Site Request Forgery (CSRF)
- **Location:** `src/main/java/com/example/SessionAuthServer.java:100-104`

**Vulnerable code:**
```java
// src/main/java/com/example/SessionAuthServer.java:100-104
        String body = "<h1>Sign in</h1>" + error +
                "<form method=\"post\" action=\"/login\">" +
                "<label>Username <input name=\"username\" autocomplete=\"username\" required></label>" +
                "<label>Password <input type=\"password\" name=\"password\" autocomplete=\"current-password\" required></label>" +
                "<button type=\"submit\">Sign in</button></form>";
```

**Why it is a problem:** The login form contains no anti-CSRF token, and `logIn` does not validate `Origin` or `Referer`. A malicious site can submit the attacker's valid credentials to `/login` in a victim's browser, causing a login-CSRF/account-confusion condition in which later activity is associated with the attacker's account. `SameSite=Lax` protects the existing authenticated cookie from ordinary cross-site POST logout requests, but it does not authenticate a pre-login request or prevent the response from creating a new session.

**Fix:** Issue a pre-authentication CSRF value, bind it to the browser, require it in the login POST, and also validate `Origin` against a configured canonical origin. The following double-submit pattern assumes HTTPS and should use a `__Host-` cookie.
```java
        String csrf = newSessionId();
        exchange.getResponseHeaders().add("Set-Cookie",
                "__Host-LOGIN_CSRF=" + csrf + "; Path=/; Secure; HttpOnly; SameSite=Strict");
        String body = "<h1>Sign in</h1>" + error +
                "<form method=\"post\" action=\"/login\">" +
                "<input type=\"hidden\" name=\"csrf\" value=\"" + escape(csrf) + "\">" +
                "<label>Username <input name=\"username\" autocomplete=\"username\" required></label>" +
                "<label>Password <input type=\"password\" name=\"password\" autocomplete=\"current-password\" required></label>" +
                "<button type=\"submit\">Sign in</button></form>";

        String submittedCsrf = form.getOrDefault("csrf", "");
        String cookieCsrf = cookieValue(exchange.getRequestHeaders(), "__Host-LOGIN_CSRF");
        if (cookieCsrf == null || !constantTimeEquals(submittedCsrf, cookieCsrf)) {
            throw new BadRequestException("Invalid form submission.");
        }
```

## 6. Verified Controls and Checks With No Finding
- Authentication boundary: unauthenticated `GET /` requests redirect to `/login`, while only the login form and expected error/not-found pages are public (`SessionAuthServer.java:54-69`, `81-86`).
- Session-token quality: identifiers contain 256 random bits from `SecureRandom` and are URL-safe encoded without predictable input (`SessionAuthServer.java:216-220`).
- Session fixation and revocation: successful login removes any presented session and generates a fresh identifier; logout removes the server-side entry and expires the cookie (`SessionAuthServer.java:120-130`).
- Session validity: unknown and expired identifiers are rejected, with expired entries removed when encountered (`SessionAuthServer.java:133-143`).
- Cookie confidentiality against script access: session cookies are `HttpOnly`; `SameSite=Lax` also blocks cookies on ordinary cross-site POST requests (`SessionAuthServer.java:150-158`). Transport protection remains covered by SEC-02.
- Credential comparison and enumeration: username and password checks both execute, use `MessageDigest.isEqual`, and return the same generic failure page (`SessionAuthServer.java:99`, `114-117`, `204-205`). Password hashing strength remains covered by SEC-04.
- XSS prevention: the only request-derived value rendered after authentication is the username, and it is HTML-escaped; error text is also escaped (`SessionAuthServer.java:71-72`, `88`, `253-256`). No client-side script or DOM sink exists.
- Browser response hardening: HTML has an explicit UTF-8 content type, responses use `Cache-Control: no-store`, CSP denies all sources by default and blocks framing, and `X-Content-Type-Options: nosniff` is set (`SessionAuthServer.java:228-240`). CSP permits inline style only, not inline script.
- Request parsing: login requires a form content type, malformed percent encoding becomes a controlled `400`, and request bodies are limited to 8 KiB (`SessionAuthServer.java:26`, `170-202`).
- Error disclosure: clients receive generic `400`/`500` pages and stack traces are not included in responses (`SessionAuthServer.java:70-75`).
- Injection surfaces: no SQL/database access, OS command execution, file/path access, unsafe deserialization, template interpreter, dynamic redirect target, or outbound network request exists in the application.
- Secret exposure: no private key, API token, or production credential was found in source, configuration, documentation, generated metadata, or transcripts beyond the insecure default credential reported as SEC-01; session identifiers and submitted passwords are not logged by application code.
- Build and dependencies: `pom.xml` declares no third-party runtime dependencies and pins `maven-compiler-plugin` version 3.11.0, so there is no application dependency surface to assess for known vulnerable versions.
