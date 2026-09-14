# Security Review: LoginServer (Java Authentication & Session Management Server)

## 1. Executive Summary
The reviewed codebase comprises `LoginServer.java`, a standalone Java HTTP web application implementing user authentication, PBKDF2 password hashing, secure session management with `HttpOnly` and `SameSite=Strict` cookies, brute-force rate limiting, and an interactive dashboard demonstrating client-side cookie access controls. While the application implements several robust defense-in-depth controls (such as `SecureRandom` session token generation, constant-time hash comparisons, and strict session expiration), multiple security vulnerabilities were identified. The most significant issues include hardcoded credentials in source code (CWE-798), sensitive cookies issued without the `Secure` attribute by default (CWE-614), DOM-based Cross-Site Scripting via `document.cookie` written into `innerHTML` (CWE-79), missing CSRF validation and GET method acceptance on the logout endpoint (CWE-352), empty-token bypass in login CSRF validation (CWE-352), exposure of credentials in standard output logs (CWE-532), context-mismatched output encoding inside JavaScript blocks (CWE-116), an overly permissive Content Security Policy using `'unsafe-inline'` (CWE-1021), IP-only rate limiting susceptible to distributed brute force (CWE-307), and missing HTTP Strict Transport Security (CWE-319).

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `LoginServer.java` | Standalone HTTP web server implementing user authentication, session lifecycle management, and a security demonstration dashboard | Password hashing and verification using PBKDF2WithHmacSHA256; session generation, expiration, and invalidation; cookie attribute configuration (`HttpOnly`, `SameSite`, `Secure`); anti-CSRF token handling and double-submit validation; IP-based rate limiting on authentication; HTTP defense headers and CSP generation; HTML/JSON response generation and client-side JavaScript DOM rendering |

## 3. Skills Applied
- `testing-api-authentication-weaknesses`: Applied to assess credential verification mechanisms, session token entropy, session expiration and invalidation logic, and authentication brute-force protections.
- `performing-cryptographic-audit-of-application`: Applied to audit PBKDF2 hashing parameters, salt generation, constant-time comparison routines, random number generators, and detect hardcoded secrets.
- `performing-csrf-attack-simulation`: Applied to audit anti-CSRF token generation, double-submit cookie validation, request method restrictions, and logout state-change protections.
- `performing-security-headers-audit`: Applied to evaluate HTTP security response headers (`Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Cache-Control`, `Strict-Transport-Security`) and cookie security flags (`HttpOnly`, `SameSite`, `Secure`).
- `testing-for-xss-vulnerabilities`: Applied to inspect server-side HTML/JSON output escaping and client-side DOM sinks (`innerHTML`) consuming client sources (`document.cookie`).
- General OWASP Top 10 / CWE knowledge: Applied to review credential logging in console output (CWE-532), account-level lockout vs. IP-only throttling (CWE-307), and transport layer security enforcement (CWE-319 / CWE-523).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Hardcoded Default and Plaintext User Credentials in Source Code | High | CWE-798 | `LoginServer.java:87-93` |
| SEC-02 | Sensitive Session and CSRF Cookies Issued Without Secure Flag by Default | High | CWE-614 | `LoginServer.java:84` |
| SEC-03 | DOM-Based Cross-Site Scripting (DOM XSS) via `document.cookie` in Dashboard Script | High | CWE-79 | `LoginServer.java:386-390` |
| SEC-04 | Missing CSRF Protection and Insecure GET Method Acceptance on Logout | Medium | CWE-352 | `LoginServer.java:178-184` |
| SEC-05 | Login Anti-CSRF Validation Accepts Empty Form and Cookie Tokens | Medium | CWE-352 | `LoginServer.java:224-231` |
| SEC-06 | Sensitive Authentication Credentials Exposed in Console Logs | Medium | CWE-532 | `LoginServer.java:124-126` |
| SEC-07 | Context-Mismatched HTML Encoding Inside JavaScript String Literal | Medium | CWE-116 | `LoginServer.java:405-406` |
| SEC-08 | Overly Permissive Content Security Policy with `'unsafe-inline'` Directive | Medium | CWE-1021 | `LoginServer.java:675` |
| SEC-09 | Authentication Rate Limiting Restricted to IP Address Without Account-Level Throttling | Medium | CWE-307 | `LoginServer.java:234-239` |
| SEC-10 | Missing HTTP Strict Transport Security (HSTS) Header | Low | CWE-319 | `LoginServer.java:666-680` |

## 5. Detailed Findings

### SEC-01: Hardcoded Default and Plaintext User Credentials in Source Code
- **Severity:** High
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Location:** `LoginServer.java:87-93`

**Vulnerable code:**
```java
// LoginServer.java:87-93
        String demoUser = getEnv("DEMO_USERNAME", "admin");
        String demoPass = getEnv("DEMO_PASSWORD", "AdminPassword123!");

        UserStore userStore = new UserStore();
        userStore.addUser(demoUser, demoPass.toCharArray());
        userStore.addUser("alice", "Password123!".toCharArray());
```

**Why it is a problem:**
The application hardcodes a plaintext password (`"Password123!"`) for user `"alice"` directly into the source code, as well as a default fallback password (`"AdminPassword123!"`) for the `"admin"` account when environment variables are not set. Anyone with access to the source code repository, build artifacts, or decompiled bytecode can extract these credentials and gain unauthorized access to the application.

**Fix:**
Remove hardcoded credentials from the source code. Require credentials to be supplied at runtime via environment variables or an external secrets vault, and fail securely if required credentials are not configured.
```java
        String demoUser = getEnv("DEMO_USERNAME", null);
        String demoPass = getEnv("DEMO_PASSWORD", null);

        UserStore userStore = new UserStore();
        if (demoUser != null && demoPass != null && !demoPass.isBlank()) {
            userStore.addUser(demoUser, demoPass.toCharArray());
        }
```

---

### SEC-02: Sensitive Session and CSRF Cookies Issued Without Secure Flag by Default
- **Severity:** High
- **CWE:** CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
- **Location:** `LoginServer.java:84`

**Vulnerable code:**
```java
// LoginServer.java:84
        boolean secureCookie = !"false".equalsIgnoreCase(getEnv("COOKIE_SECURE", "false"));
```

**Why it is a problem:**
`COOKIE_SECURE` defaults to `"false"`. Consequently, both the session cookie (`SESSIONID`) and the login anti-CSRF cookie (`CSRF_TOKEN`) are issued without the `Secure` flag by default. When the `Secure` attribute is omitted, browsers will transmit session identifiers over unencrypted HTTP connections, allowing adversaries on the same local network or in an active man-in-the-middle (MitM) position to intercept and hijack authenticated user sessions.

**Fix:**
Enforce the `Secure` attribute by default so cookies are restricted to encrypted HTTPS channels unless explicitly disabled for isolated local testing.
```java
        boolean secureCookie = !"false".equalsIgnoreCase(getEnv("COOKIE_SECURE", "true"));
```

---

### SEC-03: DOM-Based Cross-Site Scripting (DOM XSS) via `document.cookie` in Dashboard Script
- **Severity:** High
- **CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- **Location:** `LoginServer.java:386-390`

**Vulnerable code:**
```java
// LoginServer.java:386-390
                    var cookies = document.cookie;
                    box.style.display = 'block';
                    if (cookies.indexOf('SESSIONID') !== -1) {
                        box.className = 'test-result alert-danger';
                        box.innerHTML = '<strong>Vulnerability!</strong> The SESSIONID cookie was read by JavaScript: ' + cookies;
```

**Why it is a problem:**
The `testReadCookie()` function reads `document.cookie` and concatenates it directly into `box.innerHTML` without sanitization or HTML entity escaping. If any non-HttpOnly cookie accessible in the browser context contains HTML markup or malicious script payloads (e.g. from an attacker via cookie injection, subdomain takeover, or cross-site scripting on a related domain), clicking the button will execute arbitrary JavaScript within the authenticated victim's session.

**Fix:**
Use safe DOM manipulation methods such as `textContent` or `innerText` to display raw cookie strings instead of interpolating them directly into `innerHTML`.
```java
                    var cookies = document.cookie;
                    box.style.display = 'block';
                    if (cookies.indexOf('SESSIONID') !== -1) {
                        box.className = 'test-result alert-danger';
                        box.textContent = 'Vulnerability! The SESSIONID cookie was read by JavaScript: ' + cookies;
```

---

### SEC-04: Missing CSRF Protection and Insecure GET Method Acceptance on Logout
- **Severity:** Medium
- **CWE:** CWE-352: Cross-Site Request Forgery (CSRF)
- **Location:** `LoginServer.java:178-184`

**Vulnerable code:**
```java
// LoginServer.java:178-184
                case "/logout" -> {
                    if ("POST".equals(method) || "GET".equals(method)) {
                        handleLogout(exchange);
                    } else {
                        sendError(exchange, 405, "Method Not Allowed");
                    }
                }
```

**Why it is a problem:**
The `/logout` endpoint accepts both `GET` and `POST` requests and immediately invalidates the server session without validating any anti-CSRF token. While the dashboard rendering includes a hidden `csrf` field, `handleLogout` never inspects or verifies this token. Accepting state-changing `GET` requests allows attackers to perform Logout CSRF by embedding `<img src="http://target:8080/logout">` or sending external links, terminating active user sessions without their knowledge or consent.

**Fix:**
Require the `POST` HTTP method for `/logout`, parse the request payload, and validate the submitted CSRF token against the active session's CSRF token before performing session invalidation.
```java
                case "/logout" -> {
                    requireMethod(method, "POST");
                    handleLogout(exchange);
                }
```
and update `handleLogout` to validate the CSRF token:
```java
    private void handleLogout(HttpExchange exchange) throws IOException, HttpException {
        Optional<Session> sessionOpt = resolveCurrentSession(exchange);
        if (sessionOpt.isPresent()) {
            Session session = sessionOpt.get();
            Map<String, String> formData = parseFormData(exchange);
            String submittedCsrf = formData.get("csrf");
            if (submittedCsrf == null || !MessageDigest.isEqual(
                    session.csrfToken().getBytes(StandardCharsets.UTF_8),
                    submittedCsrf.getBytes(StandardCharsets.UTF_8))) {
                throw new HttpException(403, "Invalid CSRF token for logout.");
            }
            sessionStore.invalidate(session.id());
            System.out.printf("[SECURITY] User '%s' logged out. Session invalidated.%n", sanitizeForLog(session.username()));
        }

        String expiredCookie = buildCookieHeader(
                SESSION_COOKIE_NAME,
                "",
                "/",
                0,
                true,
                "Strict",
                this.secureCookie
        );

        exchange.getResponseHeaders().add("Set-Cookie", expiredCookie);
        sendRedirect(exchange, "/login");
    }
```

---

### SEC-05: Login Anti-CSRF Validation Accepts Empty Form and Cookie Tokens
- **Severity:** Medium
- **CWE:** CWE-352: Cross-Site Request Forgery (CSRF)
- **Location:** `LoginServer.java:224-231`

**Vulnerable code:**
```java
// LoginServer.java:224-231
        String csrfCookie = extractCookie(exchange, CSRF_COOKIE_NAME);
        String submittedCsrf = formData.get("csrf");
        if (csrfCookie == null || submittedCsrf == null || !MessageDigest.isEqual(
                csrfCookie.getBytes(StandardCharsets.UTF_8),
                submittedCsrf.getBytes(StandardCharsets.UTF_8))) {
            renderLoginForm(exchange, 403, "Your login session expired or CSRF token is invalid. Please try again.");
            return;
        }
```

**Why it is a problem:**
The validation check checks whether `csrfCookie` or `submittedCsrf` is `null`, but fails to verify that the tokens are non-empty. If a client transmits an empty cookie header (`Cookie: CSRF_TOKEN=`) and an empty form field (`csrf=`), `extractCookie` returns `""` and `formData.get("csrf")` returns `""`. Because neither value is `null` and `MessageDigest.isEqual("".getBytes(), "".getBytes())` evaluates to `true`, the anti-CSRF check succeeds with empty strings, bypassing CSRF validation on login.

**Fix:**
Ensure both the cookie token and submitted token are non-blank in addition to the null check and constant-time comparison.
```java
        String csrfCookie = extractCookie(exchange, CSRF_COOKIE_NAME);
        String submittedCsrf = formData.get("csrf");
        if (csrfCookie == null || submittedCsrf == null || csrfCookie.isBlank() || submittedCsrf.isBlank()
                || !MessageDigest.isEqual(
                csrfCookie.getBytes(StandardCharsets.UTF_8),
                submittedCsrf.getBytes(StandardCharsets.UTF_8))) {
            renderLoginForm(exchange, 403, "Your login session expired or CSRF token is invalid. Please try again.");
            return;
        }
```

---

### SEC-06: Sensitive Authentication Credentials Exposed in Console Logs
- **Severity:** Medium
- **CWE:** CWE-532: Insertion of Sensitive Information into Log File
- **Location:** `LoginServer.java:124-126`

**Vulnerable code:**
```java
// LoginServer.java:124-126
        System.out.println(" Demo Users:");
        System.out.println("   - Username: " + demoUser + "  |  Password: " + demoPass);
        System.out.println("   - Username: alice  |  Password: Password123!");
```

**Why it is a problem:**
During server startup, plaintext passwords and usernames are written directly to standard output. In containerized or production cloud deployments, standard output is aggregated into centralized log storage (e.g. CloudWatch, Elasticsearch, Datadog) or terminal scrollbacks accessible to developers, operators, and monitoring tools, leading to credential leakage.

**Fix:**
Omit passwords entirely from startup logs and console messages.
```java
        System.out.println(" Demo Users configured.");
        System.out.println("   - Username: " + sanitizeForLog(demoUser));
        System.out.println("   - Username: alice");
```

---

### SEC-07: Context-Mismatched HTML Encoding Inside JavaScript String Literal
- **Severity:** Medium
- **CWE:** CWE-116: Improper Encoding or Escaping of Output
- **Location:** `LoginServer.java:405-406`

**Vulnerable code:**
```java
// LoginServer.java:405-406
                        fetch('/api/session').then(function(res) { return res.json(); }).then(function(data) {
                            if (data.authenticated && data.username === '%s') {
```

**Why it is a problem:**
In `handleGetDashboard`, `session.username()` is formatted into a JavaScript single-quoted string literal within a `<script>` tag using `escapeHtml()` (line 429). `escapeHtml()` replaces characters like `'` with HTML numeric entities (`&#39;`). Because browsers do not decode HTML entities inside `<script>` blocks, the JavaScript runtime compares against the literal string `"&#39;"`, causing functional errors. Furthermore, `escapeHtml()` does not escape backslashes (`\`) or line terminators; if a username contains or ends with a backslash, it escapes the enclosing quote and causes JavaScript syntax errors or breaks out of the string literal into the script execution context.

**Fix:**
Use JSON string serialization or dedicated JavaScript string escaping (`escapeJson()`) when interpolating dynamic data into JavaScript string literals, and enclose in double quotes.
```java
                        fetch('/api/session').then(function(res) { return res.json(); }).then(function(data) {
                            if (data.authenticated && data.username === "%s") {
```
and format using `escapeJson`:
```java
                escapeJson(session.username())
```

---

### SEC-08: Overly Permissive Content Security Policy with `'unsafe-inline'` Directive
- **Severity:** Medium
- **CWE:** CWE-1021: Improper Restriction of Rendered UI Layers or Frames / CWE-693: Protection Mechanism Failure
- **Location:** `LoginServer.java:675`

**Vulnerable code:**
```java
// LoginServer.java:675
        h.set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'");
```

**Why it is a problem:**
The `script-src` directive includes `'unsafe-inline'`, which allows the execution of arbitrary inline scripts and inline DOM event handlers. This largely defeats the primary security defense provided by Content Security Policy against Cross-Site Scripting (XSS), as any injected script payload will execute without restriction.

**Fix:**
Eliminate `'unsafe-inline'` from `script-src` by refactoring inline scripts to external JavaScript files or using cryptographic nonces (`'nonce-...'`).
```java
        h.set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'");
```

---

### SEC-09: Authentication Rate Limiting Restricted to IP Address Without Account-Level Throttling
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `LoginServer.java:234-239`

**Vulnerable code:**
```java
// LoginServer.java:234-239
        String clientIp = getClientIp(exchange);
        if (rateLimiter.isBlocked(clientIp)) {
            exchange.getResponseHeaders().set("Retry-After", String.valueOf(RATE_LIMIT_WINDOW.toSeconds()));
            renderLoginForm(exchange, 429, "Too many failed login attempts. Please wait 15 minutes before trying again.");
            return;
        }
```

**Why it is a problem:**
Authentication failures are tracked solely against the client IP address (`clientIp`). An attacker executing a distributed brute-force or credential stuffing attack using rotating proxies, botnets, or mobile IP pools can target a specific account (`admin`) with an unlimited number of login attempts while staying below the 5-attempt threshold per IP. Additionally, a malicious actor can deliberately lock out all legitimate users behind a corporate NAT or shared gateway IP by generating 5 failed attempts from that IP.

**Fix:**
Implement composite rate limiting that tracks and throttles failed authentication attempts by both client IP address and targeted username.
```java
        String clientIp = getClientIp(exchange);
        String username = formData.getOrDefault("username", "").trim().toLowerCase();
        if (rateLimiter.isBlocked(clientIp) || (!username.isEmpty() && rateLimiter.isAccountBlocked(username))) {
            exchange.getResponseHeaders().set("Retry-After", String.valueOf(RATE_LIMIT_WINDOW.toSeconds()));
            renderLoginForm(exchange, 429, "Too many failed login attempts. Please wait 15 minutes before trying again.");
            return;
        }
```

---

### SEC-10: Missing HTTP Strict Transport Security (HSTS) Header
- **Severity:** Low
- **CWE:** CWE-319: Cleartext Transmission of Sensitive Information
- **Location:** `LoginServer.java:666-680`

**Vulnerable code:**
```java
// LoginServer.java:666-680
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
```

**Why it is a problem:**
The security headers omit `Strict-Transport-Security` (HSTS). When running in production over HTTPS, the absence of HSTS allows attackers to perform SSL stripping attacks on initial plaintext HTTP requests, downgrading user connections to unencrypted HTTP.

**Fix:**
Add the `Strict-Transport-Security` header to enforce HTTPS across all browser interactions.
```java
    private static void setSecurityHeaders(HttpExchange exchange) {
        Headers h = exchange.getResponseHeaders();
        // Enforce HTTPS via HSTS
        h.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
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
```

## 6. Verified Controls and Checks With No Finding
- HttpOnly Cookie Flag Enforcement: Verified in `buildCookieHeader` (`LoginServer.java:277-285, 576-579`). The `HttpOnly` flag is strictly appended to `SESSIONID` cookies, successfully preventing client-side scripts (`document.cookie`) from reading or writing the session cookie.
- SameSite Cookie Attribute: Verified in `buildCookieHeader` (`LoginServer.java:283, 581-583`). Cookies are configured with `SameSite=Strict`, preventing cross-site request forgery via ambient cookie transmission.
- Cryptographically Secure Session ID Generation: Verified in `generateSecureToken` and `createSession` (`LoginServer.java:612-616, 931-938`). Session tokens are generated using `java.security.SecureRandom` with 32 bytes (256 bits) of cryptographic entropy and URL-safe Base64 encoding.
- Session Invalidation on Logout: Verified in `handleLogout` (`LoginServer.java:436-455`). Active sessions are purged from the server-side `SessionStore` and an expired cookie header (`Max-Age=0`) is issued.
- Session Fixation Mitigation: Verified in `handlePostLogin` (`LoginServer.java:265-273`). Pre-existing sessions are invalidated upon successful authentication before issuing a fresh session identifier.
- Server-Enforced Session Timeouts: Verified in `Session.isExpired` and `SessionStore.findSession` (`LoginServer.java:922-925, 948-957`). Enforces both a 30-minute rolling idle timeout and an 8-hour maximum absolute session lifetime.
- Background Expiration Purging: Verified in `cleanupExpiredSessions` and the scheduled executor (`LoginServer.java:104-109, 139-142, 965-968, 1042-1048`). Expired sessions and old rate-limiter timestamps are periodically purged, mitigating memory exhaustion denial of service.
- Password Hashing with PBKDF2: Verified in `UserStore.hashPassword` (`LoginServer.java:1006-1014`). Uses `PBKDF2WithHmacSHA256` with 100,000 iterations and a unique 16-byte cryptographically random salt per user.
- Constant-Time Comparison for Hashes and Tokens: Verified in `UserStore.verifyPassword` and `handlePostLogin` (`LoginServer.java:226, 1003`). Employs `MessageDigest.isEqual()` to prevent timing side-channel attacks during credential and token comparisons.
- Timing Side-Channel Protection on Non-Existent Users: Verified in `UserStore.verifyPassword` (`LoginServer.java:995-1000`). Performs a dummy PBKDF2 computation when a queried username is not found, preventing user enumeration via timing discrepancies.
- Generic Authentication Failure Messages: Verified in `handlePostLogin` (`LoginServer.java:258`). Responds with "Invalid username or password" regardless of whether the account exists or the password was incorrect, preventing username enumeration.
- Clickjacking Protection: Verified in `setSecurityHeaders` (`LoginServer.java:671`). Sets `X-Frame-Options: DENY` on all responses to prevent UI redressing attacks.
- MIME Sniffing Prevention: Verified in `setSecurityHeaders` (`LoginServer.java:669`). Employs `X-Content-Type-Options: nosniff` across all responses.
- Browser Cache Prevention for Sensitive Endpoints: Verified in `setSecurityHeaders` (`LoginServer.java:677-678`). Sets `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` and `Pragma: no-cache` to ensure sensitive authenticated pages are not cached.
- Request Body Size Bounds: Verified in `parseFormData` (`LoginServer.java:636-639`). Enforces an 8 KB maximum request body size (`MAX_REQUEST_BODY_SIZE`), preventing denial-of-service through excessive payload transmission.
- Input Length Bounds Validation: Verified in `handlePostLogin` (`LoginServer.java:244-250`). Validates that input fields do not exceed 256 characters (`MAX_FIELD_LENGTH`).
- Log Injection Sanitization: Verified in `sanitizeForLog` (`LoginServer.java:738-741`). Replaces newline characters (`\r`, `\n`) with underscores to prevent log forging and carriage return injection in server logs.
