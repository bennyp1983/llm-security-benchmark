# Security Review: Secure Employee Portal Authentication

## 1. Executive Summary
This report presents the security review of the **Secure Employee Portal Authentication** system (`secure-employee-auth`), a Java-based authentication service providing credential verification, rate limiting, session management, file-based persistence, audit logging, and an embedded HTTP service.

While the codebase exhibits thoughtful defensive engineering—including standard PBKDF2WithHmacSHA512 hashing with 210,000 iterations, constant-time hash comparisons, timing-neutral dummy verification, CSPRNG session token generation, bounded LRU caches, and strict HTTP security response headers—several security vulnerabilities were identified:
1. A **Time-of-Check to Time-of-Use (TOCTOU) race condition** between the rate limit pre-check and the delayed failure recording allows attackers to bypass attempt restrictions using concurrent request bursts and exhaust CPU resources via parallel PBKDF2 computations.
2. An **account lockout denial-of-service vulnerability** allows an attacker rotating across as few as two IP addresses to lock out legitimate employees globally.
3. The server runs over **unencrypted HTTP** by default and explicitly disables the `Secure` cookie flag in the CLI application, exposing passwords and session tokens in cleartext over the network.
4. An **insecure cookie fallback** accepts un-prefixed session cookies even when `__Host-` cookies are enforced, defeating cookie prefix protections against cookie tossing and subdomain session hijacking.
5. In-memory **plaintext password retention** occurs during HTTP form decoding due to immutable `String` allocations, undermining memory zeroing routines.
6. **File permission checks** fail to enforce restrictive POSIX permissions on pre-existing database and log files.
7. **Storage failure during enrollment** causes in-memory cache corruption without rollback.
8. **Improper output encoding** applies HTML entity escaping instead of RFC 8259 JSON escaping to JSON API responses.

Remediations for each finding are detailed in Section 5.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `pom.xml` | Maven build definition and project dependencies | Defines compiler target (Java 17) and testing dependencies (JUnit 5); no vulnerable third-party dependencies imported |
| `src/main/java/com/employee/portal/security/config/SecurityConfig.java` | Central security parameter configuration | Clamps configurable environment/system properties (timeouts, bounds, iterations) and resolves base storage paths |
| `src/main/java/com/employee/portal/security/validation/InputValidator.java` | Whitelist input validation and output sanitization | Regex validation for usernames, IPs, tokens; CRLF log sanitization; HTML escaping |
| `src/main/java/com/employee/portal/security/crypto/PasswordHasher.java` | PBKDF2 hashing, verification, and timing defense | Generates salts via `SecureRandom`; computes PBKDF2WithHmacSHA512; constant-time comparison via `MessageDigest.isEqual`; dummy verification for non-existent users |
| `src/main/java/com/employee/portal/security/crypto/SecureTokenGenerator.java` | Session token generation and cookie header formatting | Generates 256-bit CSPRNG tokens; formats `Set-Cookie` headers with `HttpOnly`, `SameSite=Strict`, `Path=/`, and optional `Secure` / `__Host-` prefix |
| `src/main/java/com/employee/portal/security/model/UserStatus.java` | Account lifecycle status enumeration | Defines `ACTIVE` and `SUSPENDED` states evaluated during authentication authorization |
| `src/main/java/com/employee/portal/security/model/EmployeeRecord.java` | Immutable credential model | Defensively copies salt and hash byte arrays; validates username and role formats; masks secrets in `toString()` |
| `src/main/java/com/employee/portal/security/model/Session.java` | Server-side active session representation | Tracks session creation, idle timeout, absolute expiry, client IP binding; masks session token in `toString()` |
| `src/main/java/com/employee/portal/security/model/AuthenticationResult.java` | Authentication outcome value object | Provides uniform generic failure messages across all failure modes to prevent account enumeration |
| `src/main/java/com/employee/portal/security/repository/EmployeeRepository.java` | Persistence interface contract | Defines lookup, existence, save, and count operations for employee records |
| `src/main/java/com/employee/portal/security/repository/FileEmployeeRepository.java` | Colon-delimited flat-file storage implementation | Sets POSIX file permissions (0600 file, 0700 dir); atomic write via temp file and `ATOMIC_MOVE`; read-write locking |
| `src/main/java/com/employee/portal/security/ratelimit/BoundedLruCache.java` | Memory-bounded LRU cache with concurrency control | Prevents memory exhaustion via `LinkedHashMap` bounded eviction and `ReentrantLock` synchronization |
| `src/main/java/com/employee/portal/security/ratelimit/RateLimiter.java` | Multi-axis failed attempt tracker and lockout manager | Tracks failure counters across source IP, target username, and IP-username pair; manages lockout windows |
| `src/main/java/com/employee/portal/security/session/SessionManager.java` | Server-side session lifecycle orchestrator | Generates session tokens; bounds concurrent sessions per user; validates expiration and IP binding; session revocation |
| `src/main/java/com/employee/portal/security/service/AuthenticationService.java` | Core authentication orchestrator | Coordinates validation, rate limiting, constant-time verification, timing padding, memory wiping, and audit logging |
| `src/main/java/com/employee/portal/security/logging/AuditLogger.java` | Audit event logging facility | Writes structured security events to console and private disk file (0600); token masking; CRLF sanitization |
| `src/main/java/com/employee/portal/security/web/PortalServer.java` | Embedded HTTP server wrapper | Instantiates `com.sun.net.httpserver.HttpServer` with thread pool executor and registers `/api/` handler |
| `src/main/java/com/employee/portal/security/web/PortalHttpHandler.java` | HTTP handler for authentication endpoints | Enforces HTTP security headers (`nosniff`, `DENY`, `CSP`); bounds request body; form parsing; cookie extraction; session validation |
| `src/main/java/com/employee/portal/security/cli/EmployeePortalApp.java` | Interactive CLI and entrypoint | Secure password entry via `Console.readPassword()`; user enrollment; server startup; zeroing password memory |

## 3. Skills Applied
- `performing-api-rate-limiting-bypass`: Applied to evaluate rate limit mechanisms, attempt tracking across source and account axes, concurrent request handling, lockout window resets, and bypass opportunities via parallel requests and rotating sources.
- `testing-api-authentication-weaknesses`: Applied to assess endpoint authentication, session token generation and entropy, cookie configuration, session lifecycle/revocation, timing discrepancies, and user enumeration defenses.
- `performing-security-headers-audit`: Applied to verify browser-level protections including Content-Security-Policy (CSP), X-Frame-Options, X-Content-Type-Options, Cache-Control, and cookie flags (`HttpOnly`, `Secure`, `SameSite`, and prefix enforcement).
- `performing-cryptographic-audit-of-application`: Applied to audit password hashing algorithms (PBKDF2WithHmacSHA512), iteration counts (210,000), salt length (32 bytes), CSPRNG implementation (`SecureRandom`), and constant-time equality comparisons (`MessageDigest.isEqual`).
- `testing-for-broken-access-control`: Applied to evaluate session binding against client source IP, session expiration enforcement, and role access controls across `/api/` endpoints.
- General OWASP Top 10 / CWE knowledge: Applied to audit file system access permissions and atomic file operations (CWE-732 / CWE-276), sensitive data memory management and string immutability (CWE-244 / CWE-316), output encoding and escaping (CWE-116 / CWE-75), error handling and state consistency (CWE-665 / CWE-703), and transport layer security (CWE-319).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | TOCTOU Race Condition in Authentication Rate Limiting | High | CWE-367 | `src/main/java/com/employee/portal/security/service/AuthenticationService.java:97` |
| SEC-02 | Denial of Service via Global Account Lockout Abuse | High | CWE-645 | `src/main/java/com/employee/portal/security/ratelimit/RateLimiter.java:119` |
| SEC-03 | Insecure Cleartext HTTP Transmission & Disabled Cookie Security | High | CWE-319 | `src/main/java/com/employee/portal/security/cli/EmployeePortalApp.java:48` |
| SEC-04 | Insecure Cookie Prefix Fallback Permitting Cookie Tossing / Session Injection | Medium | CWE-384 | `src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:173` |
| SEC-05 | Sensitive Password String Retention in Heap via Form Decoding | Medium | CWE-244 | `src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:197` |
| SEC-06 | Missing Permission Verification on Pre-Existing Database and Audit Log Files | Medium | CWE-732 | `src/main/java/com/employee/portal/security/repository/FileEmployeeRepository.java:65` |
| SEC-07 | Inconsistent In-Memory State on Storage Failure During Employee Enrollment | Medium | CWE-665 | `src/main/java/com/employee/portal/security/repository/FileEmployeeRepository.java:168` |
| SEC-08 | Improper Output Encoding: HTML Escaping Applied to JSON Responses | Low | CWE-116 | `src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:98` |

## 5. Detailed Findings

### SEC-01: TOCTOU Race Condition in Authentication Rate Limiting
- **Severity:** High
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `src/main/java/com/employee/portal/security/service/AuthenticationService.java:97-105, 136-150`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/service/AuthenticationService.java:97-105, 136-150
            // Step 2: Rate limit check per source and per account (Rule 3)
            if (rateLimiter.isRestricted(safeSource, normalizedUser)) {
                // Rule 6: Do comparable PBKDF2 computation so attacker cannot confirm restriction via timing
                passwordHasher.dummyVerify(password);
                auditLogger.logEvent(AuditLogger.EventType.LOGIN_FAILURE,
                        safeSource,
                        normalizedUser,
                        "Login rejected: source or account rate limit reached");
                return AuthenticationResult.failure();
            }
...
            // Step 4: Verify supplied credentials using constant-time PBKDF2 comparison
            boolean matches = passwordHasher.verifyPassword(
                    password,
                    record.getSalt(),
                    record.getPasswordHash(),
                    record.getIterations()
            );

            if (!matches) {
                rateLimiter.recordFailure(safeSource, normalizedUser);
                auditLogger.logEvent(AuditLogger.EventType.LOGIN_FAILURE,
                        safeSource,
                        normalizedUser,
                        "Authentication failed: credentials rejected");
                return AuthenticationResult.failure();
            }
```

**Why it is a problem:**
In `AuthenticationService.authenticate`, the rate limit status is checked at line 97 before the slow cryptographic PBKDF2 verification (~100–200 ms for 210,000 iterations). However, the failure is only recorded at line 144 *after* password verification completes.

Because the check (`rateLimiter.isRestricted`) and the state modification (`rateLimiter.recordFailure`) are non-atomic and separated by a high-latency computation, an attacker sending a burst of concurrent HTTP authentication requests will have all requests pass the `isRestricted` check simultaneously while the failure counter is still zero. An attacker can execute dozens of simultaneous password guesses in parallel, bypassing the defined 5-attempt limit and triggering server-side CPU exhaustion through parallel PBKDF2 executions (CWE-400).

**Fix:**
Atomically reserve an attempt permit (or increment an active attempt counter) in `RateLimiter` prior to executing the expensive cryptographic verification, and finalize or decrement upon success:
```java
            // Atomically check and acquire an attempt slot before beginning verification
            if (!rateLimiter.tryAcquireAttempt(safeSource, normalizedUser)) {
                passwordHasher.dummyVerify(password);
                auditLogger.logEvent(AuditLogger.EventType.LOGIN_FAILURE,
                        safeSource,
                        normalizedUser,
                        "Login rejected: source or account rate limit reached");
                return AuthenticationResult.failure();
            }

            // Perform verification
            boolean matches = passwordHasher.verifyPassword(
                    password,
                    record.getSalt(),
                    record.getPasswordHash(),
                    record.getIterations()
            );

            if (!matches) {
                // Attempt failed; rate limit counter was already pre-incremented
                auditLogger.logEvent(AuditLogger.EventType.LOGIN_FAILURE,
                        safeSource,
                        normalizedUser,
                        "Authentication failed: credentials rejected");
                return AuthenticationResult.failure();
            }

            // On success, reset the failure counters
            rateLimiter.recordSuccess(safeSource, normalizedUser);
```

---

### SEC-02: Denial of Service via Global Account Lockout Abuse
- **Severity:** High
- **CWE:** CWE-645: Overly Restrictive Account Lockout Mechanism
- **Location:** `src/main/java/com/employee/portal/security/ratelimit/RateLimiter.java:119-124`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/ratelimit/RateLimiter.java:119-124
        if (username != null) {
            AttemptRecord accRecord = cache.get("ACC:" + username);
            if (accRecord != null && accRecord.isLocked(now)) {
                return true;
            }
        }
```

**Why it is a problem:**
When `maxFailedPerAccount` (default 10) failed attempts occur for a given username across all sources, `RateLimiter.isRestricted` flags the account as locked globally. Consequently, all authentication attempts for that username—including attempts from the legitimate employee's trusted workstation IP—are rejected.

Although source IP tracking halts a single IP after 5 attempts, an attacker rotating across as few as two IP addresses (or using public proxies, IPv6 addresses, or cloud functions) can submit 5 failed attempts from IP A and 5 failed attempts from IP B. This locks the target account globally for 15 minutes. An attacker can repeatedly trigger this lockout, permanently denying legitimate employees access to their accounts. This directly violates the prompt specification: *"Limit repeated attempts per source as well as per account, so an attacker cannot use your own limit to lock a legitimate user out."*

**Fix:**
Enforce rate limiting on the specific source or source-account pair (`PAIR:source:username`, which is already recorded), or require step-up authentication (e.g. out-of-band challenge or progressive exponential backoff per IP) rather than blocking all authentications globally across independent IP addresses:
```java
    public boolean isRestricted(String sourceIp, String username) {
        long now = clock.getAsLong();
        if (sourceIp != null) {
            AttemptRecord srcRecord = cache.get("SRC:" + sourceIp);
            if (srcRecord != null && srcRecord.isLocked(now)) {
                return true;
            }
        }
        if (sourceIp != null && username != null) {
            // Restrict only the specific source-account pair to prevent an attacker from locking out the legitimate user from other IPs
            AttemptRecord pairRecord = cache.get("PAIR:" + sourceIp + ":" + username);
            if (pairRecord != null && pairRecord.isLocked(now)) {
                return true;
            }
        }
        return false;
    }
```

---

### SEC-03: Insecure Cleartext HTTP Transmission & Disabled Cookie Security
- **Severity:** High
- **CWE:** CWE-319: Cleartext Transmission of Sensitive Information
- **Location:** `src/main/java/com/employee/portal/security/cli/EmployeePortalApp.java:48-50, 246, 270` and `src/main/java/com/employee/portal/security/web/PortalServer.java:20-27`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/cli/EmployeePortalApp.java:48-50
        this.authService = new AuthenticationService(
                config, repository, passwordHasher, rateLimiter, sessionManager, auditLogger, false);
```
and
```java
// src/main/java/com/employee/portal/security/web/PortalServer.java:20-27
    public PortalServer(int port, AuthenticationService authService, boolean requireSecureCookies) throws IOException {
        this.server = HttpServer.create(new InetSocketAddress(port), 0);
        this.executor = Executors.newFixedThreadPool(8);
        this.server.setExecutor(executor);

        PortalHttpHandler handler = new PortalHttpHandler(authService, requireSecureCookies);
        this.server.createContext("/api/", handler);
    }
```

**Why it is a problem:**
`PortalServer` instantiates a plaintext `HttpServer` rather than an `HttpsServer` configured with TLS (`SSLContext`), and `EmployeePortalApp` passes `requireSecureCookies = false` during server and service instantiation. 

As a result:
1. All employee credentials (usernames and passwords in POST bodies) and session identifiers are transmitted across the local network in plaintext without cryptographic protection, vulnerable to interception by network eavesdroppers or Adversary-in-the-Middle (MitM) attacks (CWE-319).
2. When `requireSecureCookies` is `false`, `SecureTokenGenerator.buildSessionCookieHeader` omits the `Secure` flag on `Set-Cookie` (CWE-614), violating Rule 4: *"Cookies carry HttpOnly, Secure, SameSite, and a correct path."*

**Fix:**
Require TLS on the server using `HttpsServer` and enforce `requireSecureCookies = true`:
```java
// Configure HttpsServer with TLS SSLContext and enforce secure cookies
    public static HttpsServer createSecureServer(int port, AuthenticationService authService, SSLContext sslContext) throws IOException {
        HttpsServer httpsServer = HttpsServer.create(new InetSocketAddress(port), 0);
        httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext));
        httpsServer.setExecutor(Executors.newFixedThreadPool(8));
        PortalHttpHandler handler = new PortalHttpHandler(authService, true);
        httpsServer.createContext("/api/", handler);
        return httpsServer;
    }
```

---

### SEC-04: Insecure Cookie Prefix Fallback Permitting Cookie Tossing / Session Injection
- **Severity:** Medium
- **CWE:** CWE-384: Session Fixation
- **Location:** `src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:172-176`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:172-176
        for (String c : cookies) {
            String[] parts = c.trim().split("=", 2);
            if (parts.length == 2 && (parts[0].equals(cookieName) || parts[0].equals("__Host-session") || parts[0].equals("portal_session"))) {
                return parts[1].trim();
            }
        }
```

**Why it is a problem:**
Under RFC 6265bis, the `__Host-` prefix protects against cookie tossing and subdomain attacks because cookies with this prefix can only be set from the origin host over HTTPS with `Path=/` and `Secure`. 

However, line 173 checks `|| parts[0].equals("portal_session")` regardless of whether `requireSecureCookies` is enabled. An attacker on an insecure sibling subdomain or network who cannot set `__Host-session` cookies can toss an un-prefixed `portal_session=attacker_session` cookie into the victim's browser. Because `PortalHttpHandler` processes cookies in order and accepts `portal_session`, this fallback completely defeats the security guarantees of the `__Host-` cookie prefix, allowing session injection or fixation.

**Fix:**
Strictly accept only the expected `cookieName` based on the active security configuration:
```java
        for (String c : cookies) {
            String[] parts = c.trim().split("=", 2);
            if (parts.length == 2 && parts[0].equals(cookieName)) {
                return parts[1].trim();
            }
        }
```

---

### SEC-05: Sensitive Password String Retention in Heap via Form Decoding
- **Severity:** Medium
- **CWE:** CWE-244: Improper Clearing of Heap Memory Before Release ('Memory Scumming')
- **Location:** `src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:195-210`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:195-210
    private Map<String, char[]> parseFormData(byte[] body) {
        Map<String, char[]> map = new HashMap<>();
        String raw = new String(body, StandardCharsets.UTF_8);
        String[] pairs = raw.split("&");
        for (String pair : pairs) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String val = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    map.put(key, val.toCharArray());
                } catch (Exception ignored) {}
            }
        }
        return map;
    }
```

**Why it is a problem:**
The system attempts to follow Rule 5 (*"clear credentials from memory when done"*) by passing passwords as `char[]` and invoking `Arrays.fill(..., '\0')` in `finally` blocks. 

However, `parseFormData` converts the entire HTTP request body (including the plaintext password) into an immutable `java.lang.String` (`raw`), splits it into substrings, and calls `URLDecoder.decode` to create another immutable `String` (`val`). Because `java.lang.String` objects are immutable in Java, their underlying character buffers cannot be wiped or zeroed out. The plaintext password persists in the JVM heap and garbage collection survivors indefinitely, exposed to process memory dumps, core dumps, and heap inspection (CWE-316).

**Fix:**
Decode form fields using byte buffers or character arrays directly without creating intermediate `String` instances containing sensitive parameters, and wipe byte buffers after decoding:
```java
    private Map<String, char[]> parseFormData(byte[] body) {
        Map<String, char[]> map = new HashMap<>();
        try {
            int start = 0;
            for (int i = 0; i <= body.length; i++) {
                if (i == body.length || body[i] == '&') {
                    parseParamPair(body, start, i, map);
                    start = i + 1;
                }
            }
        } finally {
            Arrays.fill(body, (byte) 0);
        }
        return map;
    }
```

---

### SEC-06: Missing Permission Verification on Pre-Existing Database and Audit Log Files
- **Severity:** Medium
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `src/main/java/com/employee/portal/security/repository/FileEmployeeRepository.java:65-77` and `src/main/java/com/employee/portal/security/logging/AuditLogger.java:72-84`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/repository/FileEmployeeRepository.java:65-77
            if (!Files.exists(dbFile)) {
                try {
                    Set<PosixFilePermission> filePerms = PosixFilePermissions.fromString("rw-------");
                    FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(filePerms);
                    Files.createFile(dbFile, attr);
                } catch (UnsupportedOperationException e) {
                    Files.createFile(dbFile);
                    dbFile.toFile().setReadable(false, false);
                    dbFile.toFile().setReadable(true, true);
                    dbFile.toFile().setWritable(false, false);
                    dbFile.toFile().setWritable(true, true);
                }
            }
```

**Why it is a problem:**
Both `FileEmployeeRepository.ensureSecureFileExists` and `AuditLogger.ensureSecureLogFile` only assign POSIX `0600` permissions (`rw-------`) when creating a non-existent file (`if (!Files.exists(dbFile))`). 

If `employees.db` or `audit.log` already exists prior to startup (e.g. provisioned by IT, deployed by automated tooling, or created with a default `umask` such as `0644` or `0666`), the existing permissions are never inspected or hardened. Unprivileged local users on the same operating system can read password salts, PBKDF2 hashes, usernames, and audit log entries (CWE-276 / CWE-732).

**Fix:**
Enforce restrictive POSIX permissions unconditionally on existing files as well as newly created files:
```java
            if (!Files.exists(dbFile)) {
                Set<PosixFilePermission> filePerms = PosixFilePermissions.fromString("rw-------");
                try {
                    Files.createFile(dbFile, PosixFilePermissions.asFileAttribute(filePerms));
                } catch (UnsupportedOperationException e) {
                    Files.createFile(dbFile);
                }
            }
            // Unconditionally restrict permissions on existing file
            try {
                Files.setPosixFilePermissions(dbFile, PosixFilePermissions.fromString("rw-------"));
            } catch (UnsupportedOperationException e) {
                dbFile.toFile().setReadable(false, false);
                dbFile.toFile().setReadable(true, true);
                dbFile.toFile().setWritable(false, false);
                dbFile.toFile().setWritable(true, true);
            }
```

---

### SEC-07: Inconsistent In-Memory State on Storage Failure During Employee Enrollment
- **Severity:** Medium
- **CWE:** CWE-665: Improper Initialization
- **Location:** `src/main/java/com/employee/portal/security/repository/FileEmployeeRepository.java:163-173`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/repository/FileEmployeeRepository.java:163-173
    @Override
    public boolean save(EmployeeRecord record) {
        Objects.requireNonNull(record, "record cannot be null");
        rwLock.writeLock().lock();
        try {
            cache.put(record.getUsername().toLowerCase(), record);
            return persistToDisk();
        } finally {
            rwLock.writeLock().unlock();
        }
    }
```

**Why it is a problem:**
`FileEmployeeRepository.save` inserts the new `EmployeeRecord` into the in-memory `cache` *before* attempting `persistToDisk()`. If disk persistence fails (due to disk full, file permission denial, or `AtomicMoveNotSupportedException`), `save()` returns `false`, but the in-memory cache is never rolled back. 

This leaves the application in an inconsistent state: the user exists in memory and can authenticate until the application is restarted, but does not exist on disk. Furthermore, subsequent enrollment requests for the same username fail because `repository.exists()` reads from the unpersisted in-memory cache.

**Fix:**
Roll back the in-memory cache if `persistToDisk()` fails:
```java
    @Override
    public boolean save(EmployeeRecord record) {
        Objects.requireNonNull(record, "record cannot be null");
        rwLock.writeLock().lock();
        String key = record.getUsername().toLowerCase();
        EmployeeRecord previous = cache.get(key);
        try {
            cache.put(key, record);
            boolean success = persistToDisk();
            if (!success) {
                // Roll back cache to prior state
                if (previous != null) {
                    cache.put(key, previous);
                } else {
                    cache.remove(key);
                }
            }
            return success;
        } finally {
            rwLock.writeLock().unlock();
        }
    }
```

---

### SEC-08: Improper Output Encoding: HTML Escaping Applied to JSON Responses
- **Severity:** Low
- **CWE:** CWE-116: Improper Encoding or Escaping of Output
- **Location:** `src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:97-103, 106-110, 136-141`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:97-103
                Session session = result.getSession().get();
                String responseJson = String.format(
                        "{\"status\":\"success\",\"message\":\"%s\",\"user\":\"%s\",\"role\":\"%s\"}",
                        InputValidator.escapeHtml(result.getMessage()),
                        InputValidator.escapeHtml(session.getUsername()),
                        InputValidator.escapeHtml(session.getRole())
                );
                sendJsonResponse(exchange, 200, responseJson);
```

**Why it is a problem:**
The HTTP handler returns responses with `Content-Type: application/json; charset=UTF-8`, but formats string values using `InputValidator.escapeHtml()` instead of standard JSON string escaping.

`escapeHtml` translates characters into HTML entities (such as `&quot;`, `&lt;`, `&gt;`, `&#x27;`). In a JSON context:
1. JSON clients receive corrupted data containing HTML entities rather than literal characters.
2. `escapeHtml` leaves backslashes (`\`) unescaped and permits control characters (`\t`, `\n`, `\r`, which line 125 of `InputValidator` explicitly skips), which violates the RFC 8259 JSON specification and causes JSON parsing failures in clients.

**Fix:**
Implement standard RFC 8259 JSON string escaping (`escapeJson`) for all JSON serialized values:
```java
    public static String escapeJson(String text) {
        if (text == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 32) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }
```

## 6. Verified Controls and Checks With No Finding
- **Password Hashing Algorithm & Iterations**: Verified that `PasswordHasher.java` uses `PBKDF2WithHmacSHA512` with 210,000 iterations and a 256-bit derived key length, complying with OWASP Password Storage and NIST SP 800-63B guidelines.
- **Cryptographic Salt Generation**: Verified that `PasswordHasher.generateSalt()` uses `SecureRandom` to generate unique 256-bit (32-byte) salts for each credential record.
- **Constant-Time Hash Comparison**: Verified that `PasswordHasher.verifyPassword()` utilizes `MessageDigest.isEqual()` to compare password hashes in constant time, preventing side-channel timing leaks.
- **Timing Parity on Failure**: Verified that `PasswordHasher.dummyVerify()` performs a full PBKDF2 hash computation on non-existent accounts, suspended users, and restricted requests, preventing user enumeration via timing discrepancies.
- **Session Token Entropy**: Verified that `SecureTokenGenerator.generateToken()` generates 256 bits of cryptographic entropy via `SecureRandom` encoded as unguessable URL-safe Base64 strings.
- **Session Identifier Masking**: Verified that `AuditLogger.maskToken()` and `Session.toString()` mask tokens to reveal only the first and last 4 characters, preventing session token leakage in logs.
- **Log Injection Defense (CRLF)**: Verified that `InputValidator.sanitizeForLog()` strips `\r` and `\n` characters (replacing them with `_`) and bounds log entry lengths to mitigate CWE-117 log injection.
- **Path Traversal Defense**: Verified that `InputValidator.isValidUsername()` rejects traversal sequences (`..`) and restricts usernames to `^[a-zA-Z0-9._-]{3,32}$`, preventing directory traversal during file resolution.
- **Defensive Copying of Sensitive Byte Arrays**: Verified that `EmployeeRecord` defensively copies `salt` and `passwordHash` arrays in its constructor and accessors to preserve immutability.
- **Atomic File Persistence**: Verified that `FileEmployeeRepository.persistToDisk()` writes new state to a temporary file before performing an atomic replacement via `Files.move(..., StandardCopyOption.ATOMIC_MOVE)`, preventing database corruption.
- **HTTP Security Headers**: Verified that `PortalHttpHandler.handle()` applies `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, and `Cache-Control: no-store, no-cache, must-revalidate, private` to all HTTP responses.
- **Bounded Request Processing**: Verified that `PortalHttpHandler.readBoundedBody()` enforces a 4,096-byte limit on incoming HTTP request bodies, preventing buffer exhaustion and resource consumption attacks.
- **Generic Failure Feedback**: Verified that `AuthenticationResult.failure()` returns an identical, uniform error message across all authentication failure modes, mitigating account enumeration.
- **Bounded In-Memory Caches**: Verified that `BoundedLruCache` enforces capacity limits (10,000 for rate limiting, 5,000 for active sessions) with LRU eviction to prevent heap exhaustion DoS (CWE-400).
