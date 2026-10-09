# Security Review: Java Authentication and Session Cookie Application

## 1. Executive Summary
This document provides a static application security review of the standalone Java Authentication and Session Cookie Application located in `/data/results/agy/set_a/sallie/1/basic/`. The application provides an embedded HTTP server (`com.sun.net.httpserver.HttpServer`) handling user authentication, session token generation, session lifecycle tracking, and HTML/JSON response rendering. Credential verification utilizes salted PBKDF2-HMAC-SHA256 password hashing with constant-time comparison.

While the core cryptographic verification logic and session token generation mechanisms are implemented securely, the review identified several critical- and high-severity security weaknesses:
1. **Plaintext Secret & Token Logging (High):** Active bearer session tokens are emitted into standard application logs upon login, and demo user passwords are logged during startup.
2. **Hardcoded Credentials & Sensitive Data Exposure (High):** Demo credentials—including the administrator password—are hardcoded and rendered publicly in plaintext on the unauthenticated login web page.
3. **Insecure Session Cookie Transmission (High):** Session cookies omit the `Secure` flag and are served over unencrypted HTTP, allowing session token theft via network eavesdropping.
4. **Denial of Service via Unbounded Request Ingestion (Medium):** Incoming HTTP request bodies are read into memory without size limits, enabling memory exhaustion (`OutOfMemoryError`).
5. **Missing Defensive Security Headers (Medium):** HTTP responses lack standard protective headers (`Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`), leaving clients exposed to clickjacking and MIME sniffing.

Remediation requires removing secrets from logs and views, enforcing the `Secure` attribute over TLS/HTTPS, bounding request streaming sizes, and configuring standard browser protection headers.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `AuthApplication.java` | Core application source containing embedded HTTP server, routing, handlers, user database, PBKDF2 hashing, session management, and view templates | Authentication handling, password hashing and verification, session token generation, cookie creation and parsing, request body reading, HTML/JSON rendering, security logging |
| `pom.xml` | Apache Maven project configuration file | Build specifications, Java compiler version (Java 17), dependency definitions (zero external dependencies), packaging configuration |
| `test_app.sh` | Bash integration test script | Starts application, executes automated HTTP test requests using `curl`, verifies cookie issuance, protected endpoints, and session termination |
| `README.md` | Plain-English documentation | Describes system architecture, security features, setup instructions, credentials, and test workflows |

## 3. Skills Applied
- `testing-api-authentication-weaknesses`: Applied to password authentication routines, session lifecycle management, token revocation on logout, and brute-force vulnerability analysis.
- `testing-for-sensitive-data-exposure`: Applied to credential exposure on login pages, secret leakage in application logs, plaintext session cookies, and in-memory credential retention.
- `performing-security-headers-audit`: Applied to HTTP response headers (Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, HSTS) and session cookie attributes (`HttpOnly`, `SameSite`, `Secure`).
- `performing-cryptographic-audit-of-application`: Applied to PBKDF2 parameters (iterations, salt length, key derivation function), PRNG entropy generation (`SecureRandom`), and timing attack resistance (`MessageDigest.isEqual`).
- `testing-for-xss-vulnerabilities`: Applied to view rendering templates, input reflection, and HTML entity encoding routines.
- General OWASP Top 10 / CWE Knowledge:
  - CWE-400 / CWE-770 (Uncontrolled Resource Consumption / DoS via unbounded stream reading) was evaluated against general OWASP A04:2021 (Insecure Design) as no specialized library skill addressed JVM stream reading constraints.
  - CWE-290 (Client IP Spoofing via unvalidated `X-Forwarded-For` header) was evaluated against general security engineering practices.
  - CWE-377 (Insecure Temporary File in integration scripts) was evaluated against general operating system security best practices.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Active Session Identifier Logged to Application Logs | High | CWE-532 | `AuthApplication.java:216-217` |
| SEC-02 | Hardcoded User Passwords Displayed on Public Login Page | High | CWE-798 | `AuthApplication.java:926-934` |
| SEC-03 | User Passwords Written to Application Logs at Startup | High | CWE-532 | `AuthApplication.java:90-93` |
| SEC-04 | Missing `Secure` Attribute on Session Cookie Over Plaintext Transport | High | CWE-614 | `AuthApplication.java:410-413` |
| SEC-05 | Unbounded Request Body Ingestion Leading to Denial of Service | Medium | CWE-400 | `AuthApplication.java:428-437` |
| SEC-06 | Missing Defensive HTTP Security Headers | Medium | CWE-693 | `AuthApplication.java:501-504` |
| SEC-07 | Client IP Spoofing via Unvalidated `X-Forwarded-For` Header | Medium | CWE-290 | `AuthApplication.java:420-426` |
| SEC-08 | Absence of Authentication Rate Limiting on Login Endpoints | Low | CWE-307 | `AuthApplication.java:209-211` |
| SEC-09 | Insecure Fixed Temporary File in Test Script | Low | CWE-377 | `test_app.sh:6-8` |

## 5. Detailed Findings

### SEC-01: Active Session Identifier Logged to Application Logs
- **Severity:** High
- **CWE:** CWE-532: Insertion of Sensitive Information into Log File
- **Location:** `AuthApplication.java:216-217`

**Vulnerable code:**
```java
// AuthApplication.java:216-217
                LOGGER.info(String.format("[AUTH SUCCESS] User '%s' authenticated. Session ID: %s",
                        username, newSession.getId()));
```

**Why it is a problem:**
When a user logs in successfully, `LoginHandler` writes the newly generated session token (`newSession.getId()`) directly into the application's standard logger output. In production and container environments, log streams are routinely captured by log forwarders, persistent log files, and monitoring dashboards (e.g., CloudWatch, Datadog, ELK). Because session tokens are bearer credentials, anyone with read access to the application logs can extract the active session ID and impersonate the user on `/dashboard` or `/api/session` without providing a password.

**Fix:**
Remove the full session token from the log message. If correlating log entries to session events is required, log only a non-reversible cryptographic hash (e.g. SHA-256 digest) or an internal audit sequence number.
```java
// AuthApplication.java:216-217
                LOGGER.info(String.format("[AUTH SUCCESS] User '%s' authenticated successfully",
                        username));
```

---

### SEC-02: Hardcoded User Passwords Displayed on Public Login Page
- **Severity:** High
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Location:** `AuthApplication.java:926-934`

**Vulnerable code:**
```java
// AuthApplication.java:926-934
            for (User u : demoUsers) {
                sb.append("          <tr>\n");
                sb.append("            <td><code>").append(SecurityUtils.escapeHtml(u.getUsername())).append("</code></td>\n");
                sb.append("            <td><code>").append(SecurityUtils.escapeHtml(u.getDemoPassword())).append("</code></td>\n");
                sb.append("            <td><span class=\"badge ")
                        .append("Administrator".equals(u.getRole()) ? "badge-admin" : "badge-user")
                        .append("\">").append(SecurityUtils.escapeHtml(u.getRole())).append("</span></td>\n");
                sb.append("          </tr>\n");
            }
```

**Why it is a problem:**
The HTML login view generated by `Views.renderLoginPage` contains a "Preconfigured Test Accounts" table that displays the usernames and plaintext passwords for all initialized accounts, including the administrator account (`admin` / `AdminPassword123!`). Because `/login` is accessible without authentication, any remote client or automated scanner can read the administrator credentials directly from the page and log in with full privileges. Furthermore, storing the plaintext password in `User.demoPassword` causes cleartext secrets to reside permanently in JVM heap memory.

**Fix:**
Eliminate plaintext password rendering from the login page, remove `demoPassword` from the `User` model, and initialize credentials from secure external configurations or administrative provisioning workflows.
```java
// AuthApplication.java:926-934
            // Remove the table and do not display user credentials on the login page
```

---

### SEC-03: User Passwords Written to Application Logs at Startup
- **Severity:** High
- **CWE:** CWE-532: Insertion of Sensitive Information into Log File
- **Location:** `AuthApplication.java:90-93`

**Vulnerable code:**
```java
// AuthApplication.java:90-93
        for (User user : userManager.getAllUsers()) {
            LOGGER.info(String.format("   - Username: %-10s | Password: %-16s | Role: %s",
                    user.getUsername(), user.getDemoPassword(), user.getRole()));
        }
```

**Why it is a problem:**
During server startup in `AuthApplication.start()`, the application iterates through all registered users and prints their plaintext passwords to console logs. This causes user authentication secrets to be written to console logs, service stdout files, and systemd journals, completely undermining the confidentiality afforded by the PBKDF2 password hashing mechanism.

**Fix:**
Remove the plaintext password output from startup logging statements. Log only non-sensitive account metadata such as usernames and roles.
```java
// AuthApplication.java:90-93
        for (User user : userManager.getAllUsers()) {
            LOGGER.info(String.format("   - Username: %-10s | Role: %s",
                    user.getUsername(), user.getRole()));
        }
```

---

### SEC-04: Missing `Secure` Attribute on Session Cookie Over Plaintext Transport
- **Severity:** High
- **CWE:** CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
- **Location:** `AuthApplication.java:410-413`

**Vulnerable code:**
```java
// AuthApplication.java:410-413
    public static String buildSetCookieHeader(String sessionId, int maxAgeSeconds) {
        return String.format("%s=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict",
                COOKIE_NAME, sessionId, maxAgeSeconds);
    }
```

**Why it is a problem:**
While `buildSetCookieHeader` correctly specifies `HttpOnly` and `SameSite=Strict`, it omits the `Secure` flag. Concurrently, the application runs on plain HTTP (`HttpServer.create(...)`). Without the `Secure` attribute, browsers will transmit the `SESSIONID` cookie over unencrypted HTTP connections. An adversary positioned on the local network (e.g., shared Wi-Fi, DNS/ARP spoofing) can capture the session cookie in transit via an Adversary-in-the-Middle (MitM) attack and hijack the authenticated session.

**Fix:**
Append the `Secure` flag to the cookie header and deploy the application using TLS/HTTPS (e.g. `HttpsServer` with an SSLContext, or behind a reverse proxy that terminates TLS).
```java
// AuthApplication.java:410-413
    public static String buildSetCookieHeader(String sessionId, int maxAgeSeconds) {
        return String.format("%s=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict; Secure",
                COOKIE_NAME, sessionId, maxAgeSeconds);
    }
```

---

### SEC-05: Unbounded Request Body Ingestion Leading to Denial of Service
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `AuthApplication.java:428-437`

**Vulnerable code:**
```java
// AuthApplication.java:428-437
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
```

**Why it is a problem:**
The `readRequestBody` method reads the entire request body from `exchange.getRequestBody()` into a `ByteArrayOutputStream` until the stream terminates, without checking `Content-Length` or imposing an upper bound on bytes read. An unauthenticated attacker can send an arbitrarily large HTTP POST payload (hundreds of megabytes or gigabytes) to `/login` or `/api/login`. Because this data accumulates in the JVM heap, it can rapidly cause a `java.lang.OutOfMemoryError` (OOM), crashing the process and causing a Denial of Service for all users.

**Fix:**
Enforce an explicit byte limit (e.g., 8 KB for authentication forms). If incoming request data exceeds this threshold, abort processing and return HTTP status 413 (Payload Too Large).
```java
// AuthApplication.java:428-437
    private static final int MAX_BODY_BYTES = 8192; // 8 KB limit

    private static String readRequestBody(HttpExchange exchange) throws IOException {
        InputStream is = exchange.getRequestBody();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int bytesRead;
        int totalBytes = 0;
        while ((bytesRead = is.read(buffer)) != -1) {
            totalBytes += bytesRead;
            if (totalBytes > MAX_BODY_BYTES) {
                throw new IOException("Request body exceeds maximum allowed size (" + MAX_BODY_BYTES + " bytes)");
            }
            baos.write(buffer, 0, bytesRead);
        }
        return baos.toString(StandardCharsets.UTF_8);
    }
```

---

### SEC-06: Missing Defensive HTTP Security Headers
- **Severity:** Medium
- **CWE:** CWE-693: Protection Mechanism Failure
- **Location:** `AuthApplication.java:501-504`

**Vulnerable code:**
```java
// AuthApplication.java:501-504
    private static void sendHtmlResponse(HttpExchange exchange, int statusCode, String html) throws IOException {
        byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
        exchange.getResponseHeaders().set("Cache-Control", "no-cache, no-store, must-revalidate");
```

**Why it is a problem:**
HTTP responses from `sendHtmlResponse` only include `Content-Type` and `Cache-Control`. They omit essential security headers:
- `X-Frame-Options` and `Content-Security-Policy: frame-ancestors 'none'`: Leaves the application vulnerable to clickjacking attacks (CWE-1021) by allowing malicious third-party websites to embed the login and dashboard pages inside an `<iframe>`.
- `X-Content-Type-Options: nosniff`: Leaves browsers open to MIME type sniffing.
- `Content-Security-Policy`: Missing browser-enforced resource and execution boundaries.
- `Referrer-Policy`: Missing explicit control over referrer information leakage.

**Fix:**
Include standard defensive security headers in all HTTP responses.
```java
// AuthApplication.java:501-504
    private static void sendHtmlResponse(HttpExchange exchange, int statusCode, String html) throws IOException {
        byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
        exchange.getResponseHeaders().set("Cache-Control", "no-cache, no-store, must-revalidate");
        exchange.getResponseHeaders().set("X-Frame-Options", "DENY");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.getResponseHeaders().set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'");
        exchange.getResponseHeaders().set("Referrer-Policy", "strict-origin-when-cross-origin");
```

---

### SEC-07: Client IP Spoofing via Unvalidated `X-Forwarded-For` Header
- **Severity:** Medium
- **CWE:** CWE-290: Authentication Bypass by Spoofing
- **Location:** `AuthApplication.java:420-426`

**Vulnerable code:**
```java
// AuthApplication.java:420-426
    private static String getClientIp(HttpExchange exchange) {
        String xForwardedFor = exchange.getRequestHeaders().getFirst("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.trim().isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return exchange.getRemoteAddress().getAddress().getHostAddress();
    }
```

**Why it is a problem:**
`getClientIp` blindly trusts the client-controlled `X-Forwarded-For` HTTP header without verifying that the request originated from a trusted internal reverse proxy. Any client can supply an arbitrary header value (e.g. `X-Forwarded-For: 127.0.0.1` or `X-Forwarded-For: 192.168.1.100`). This spoofed value is recorded in security audit logs (`[LOGIN ATTEMPT] Username='...' from IP=...`), saved into the `Session` object, and displayed on `/dashboard`, falsifying forensic audit trails and subverting any downstream IP-based controls.

**Fix:**
Use the remote socket address directly unless the incoming connection is verified to originate from a designated, trusted reverse proxy CIDR block.
```java
// AuthApplication.java:420-426
    private static String getClientIp(HttpExchange exchange) {
        // Direct socket address cannot be spoofed by HTTP request headers
        return exchange.getRemoteAddress().getAddress().getHostAddress();
    }
```

---

### SEC-08: Absence of Authentication Rate Limiting on Login Endpoints
- **Severity:** Low
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `AuthApplication.java:209-211`

**Vulnerable code:**
```java
// AuthApplication.java:209-211
            LOGGER.info(String.format("[LOGIN ATTEMPT] Username='%s' from IP=%s", username, clientIp));

            Optional<User> user = userManager.authenticate(username, password);
```

**Why it is a problem:**
Neither `/login` nor `/api/login` enforces request rate limiting, failed attempt throttling, or temporary account lockouts. Although PBKDF2 hashing adds computational cost and dummy hashing protects against username enumeration timing differences, attackers can submit rapid, automated brute-force or credential stuffing requests without being throttled or blocked.

**Fix:**
Implement rate limiting or tracking of consecutive failed login attempts keyed by IP address or username, rejecting excessive requests with HTTP 429 (Too Many Requests).
```java
// AuthApplication.java:209-211
            if (isRateLimited(clientIp, username)) {
                sendRedirect(exchange, "/login?error=too_many_attempts");
                return;
            }

            Optional<User> user = userManager.authenticate(username, password);
            if (user.isEmpty()) {
                recordFailedAttempt(clientIp, username);
            } else {
                clearFailedAttempts(clientIp, username);
            }
```

---

### SEC-09: Insecure Fixed Temporary File in Test Script
- **Severity:** Low
- **CWE:** CWE-377: Insecure Temporary File
- **Location:** `test_app.sh:6-8`

**Vulnerable code:**
```bash
# test_app.sh:6-8
COOKIE_JAR="/tmp/test_cookies.txt"

rm -f "${COOKIE_JAR}"
```

**Why it is a problem:**
The automated test script stores authentication cookies containing valid session tokens in `/tmp/test_cookies.txt`. Because `/tmp` is shared among all local users on standard Linux systems and the file path is fixed and predictable, an unprivileged local user could observe or pre-create this file (symlink attack) or read the session cookies during automated test execution.

**Fix:**
Create uniquely named temporary files using `mktemp` with restricted permissions (0600).
```bash
# test_app.sh:6-8
COOKIE_JAR=$(mktemp /tmp/test_cookies.XXXXXX)
chmod 600 "${COOKIE_JAR}"
```

## 6. Verified Controls and Checks With No Finding
- **Password Hashing Implementation (PBKDF2)**: Verified in `AuthApplication.java:768-793`. The application uses standard `PBKDF2WithHmacSHA256` with 65,536 iterations, 128-bit cryptographically secure random salts per user, and 256-bit derived key length. No deprecated or weak algorithms (MD5, SHA-1, plain SHA-256) are used for password storage.
- **Timing Side-Channel Protections**: Verified in `AuthApplication.java:682-685` and `AuthApplication.java:794-798`. Hash verification uses `MessageDigest.isEqual` for constant-time byte comparison, avoiding early termination timing attacks. Additionally, when an unrecognized username is submitted, `UserManager.authenticate` calculates a dummy hash with `SecurityUtils.DUMMY_SALT` to ensure uniform response latency and prevent username enumeration.
- **Session Identifier Entropy**: Verified in `AuthApplication.java:716` and `AuthApplication.java:800-804`. Session tokens are 32 bytes (256 bits) of cryptographic randomness generated via `java.security.SecureRandom`, converted to 64 hexadecimal characters. Tokens are unpredictable and resilient against offline brute force or guessing.
- **Session Lifecycle & Invalidation**: Verified in `AuthApplication.java:639-644`, `AuthApplication.java:703-713`, `AuthApplication.java:730-733`, and `AuthApplication.java:739-743`. Sessions enforce both a 30-minute idle sliding window and a 12-hour absolute lifetime. Expired sessions are removed on access and periodically purged every 60 seconds by a background daemon thread. Both web (`/logout`) and API (`/api/logout`) endpoints immediately invalidate the session server-side and instruct the browser to discard the cookie via `Max-Age=0`.
- **Session Fixation Defense**: Verified in `AuthApplication.java:215` and `AuthApplication.java:312`. Upon successful authentication, a brand-new session token is generated via `sessionManager.createSession(...)`, ensuring no pre-authentication session identifier is adopted or reused.
- **CSRF Defense via Cookie Directive**: Verified in `AuthApplication.java:411`. The session cookie specifies `SameSite=Strict`, instructing modern user agents not to attach the cookie to cross-origin HTTP requests.
- **Client-Side Script Inaccessibility**: Verified in `AuthApplication.java:411`. The `HttpOnly` flag is set on the session cookie, preventing client-side JavaScript (`document.cookie`) from accessing the session token in the event of an XSS vulnerability.
- **HTML Output Encoding**: Verified in `AuthApplication.java:814-821` and `AuthApplication.java:946-995`. User-controlled fields (`username`, `fullName`, `role`, `clientIp`, `sessionId`) are sanitized using `SecurityUtils.escapeHtml()` (encoding `&`, `<`, `>`, `"`, and `'`) before insertion into HTML views.
- **JSON Serialization Safety**: Verified in `AuthApplication.java:542-551` and `AuthApplication.java:348-352`. Output strings rendered in JSON responses are escaped using `escapeJson()` to prevent JSON injection or format breakage.
