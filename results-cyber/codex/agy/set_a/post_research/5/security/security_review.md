# Security Review: Secure Employee Portal Authentication System

## 1. Executive Summary
The component is a Java 17 employee-authentication application with CLI enrollment and login, an embedded HTTP API, PBKDF2 password hashing, file-backed credential storage, audit logging, rate limiting, and server-side sessions. The review found two high-severity issues: the production entry point exposes credentials and session tokens over plaintext HTTP with non-`Secure` cookies, and the CLI permits unauthenticated creation of accounts with an attacker-selected `ADMIN` role. Medium-severity findings affect concurrent rate-limit enforcement, rate-limit reset and eviction, request-time resource limits, sensitive-file permissions, password strength, and timing consistency. Low-severity findings concern echoed fallback password input, immutable heap copies of HTTP passwords, and a failed-persistence state inconsistency. Review was static only; no source code, classes, JARs, builds, tests, or dependencies were executed or imported.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `pom.xml` | Maven build definition for Java 17 and JUnit. | Pins build/test plugins and the sole third-party test dependency. |
| `src/main/java/com/employee/portal/security/cli/EmployeePortalApp.java` | Application entry point and interactive CLI. | Accepts credentials, enrolls users and roles, exposes session tokens, and launches the HTTP server. |
| `src/main/java/com/employee/portal/security/config/SecurityConfig.java` | Loads and bounds security settings. | Controls lockouts, session lifetimes, KDF cost, cache sizes, and sensitive file locations. |
| `src/main/java/com/employee/portal/security/crypto/PasswordHasher.java` | Hashes and verifies passwords with PBKDF2. | Uses random salts, configurable work factors, constant-time comparison, and dummy verification. |
| `src/main/java/com/employee/portal/security/crypto/SecureTokenGenerator.java` | Generates session tokens and cookie headers. | Uses `SecureRandom`; conditionally adds `Secure` and the `__Host-` prefix. |
| `src/main/java/com/employee/portal/security/logging/AuditLogger.java` | Writes authentication audit events. | Sanitizes untrusted fields, masks tokens, and creates an audit file with intended owner-only access. |
| `src/main/java/com/employee/portal/security/model/AuthenticationResult.java` | Represents authentication outcomes. | Provides a uniform public failure message and returns sessions/cookies on success. |
| `src/main/java/com/employee/portal/security/model/EmployeeRecord.java` | Represents a stored credential and role. | Validates salt/hash/work-factor ranges and accepts persisted authorization roles. |
| `src/main/java/com/employee/portal/security/model/Session.java` | Represents server-side session state. | Stores identity, role, source IP, and idle/absolute expiry timestamps. |
| `src/main/java/com/employee/portal/security/model/UserStatus.java` | Defines account status values. | Controls whether an account is eligible to authenticate. |
| `src/main/java/com/employee/portal/security/ratelimit/BoundedLruCache.java` | Thread-safe bounded LRU map. | Evicts least-recently-used rate-limit or session state when capacity is reached. |
| `src/main/java/com/employee/portal/security/ratelimit/RateLimiter.java` | Tracks source, account, and source/account failures. | Enforces temporary authentication restrictions and clears counters after success. |
| `src/main/java/com/employee/portal/security/repository/EmployeeRepository.java` | Credential repository interface. | Defines lookup, existence, persistence, and reload operations. |
| `src/main/java/com/employee/portal/security/repository/FileEmployeeRepository.java` | File-backed credential repository. | Parses untrusted records, stores password hashes and roles, and atomically replaces the database file. |
| `src/main/java/com/employee/portal/security/service/AuthenticationService.java` | Orchestrates authentication and enrollment. | Performs validation, rate checks, password verification, role assignment, session creation, and password clearing. |
| `src/main/java/com/employee/portal/security/session/SessionManager.java` | Creates, validates, expires, and revokes sessions. | Uses random tokens, server-side state, IP binding, timeouts, and per-user/global bounds. |
| `src/main/java/com/employee/portal/security/validation/InputValidator.java` | Validates identifiers and encodes output. | Allowlists usernames, IPs, and tokens; bounds passwords; sanitizes logs; escapes HTML. |
| `src/main/java/com/employee/portal/security/web/PortalHttpHandler.java` | Implements login, dashboard, and logout endpoints. | Reads credentials, sets cookies/security headers, validates sessions, and processes untrusted HTTP bodies/cookies. |
| `src/main/java/com/employee/portal/security/web/PortalServer.java` | Configures the embedded HTTP server. | Binds a plaintext listener and serves authentication traffic with a fixed worker pool. |
| `src/test/java/com/employee/portal/security/AuthenticationServiceTest.java` | Authentication service tests. | Exercises generic failures, password clearing, lockouts, sessions, and timing behavior. |
| `src/test/java/com/employee/portal/security/FileEmployeeRepositoryTest.java` | Repository tests. | Exercises permissions, record parsing, persistence, and defensive copies. |
| `src/test/java/com/employee/portal/security/InputValidatorTest.java` | Validation tests. | Exercises allowlists, bounds, log sanitization, and HTML escaping. |
| `src/test/java/com/employee/portal/security/PasswordHasherTest.java` | Password hashing tests. | Exercises salt uniqueness, verification, and dummy hashing. |
| `src/test/java/com/employee/portal/security/PortalHttpHandlerTest.java` | HTTP endpoint tests. | Uses plaintext HTTP and checks endpoint, header, cookie, and logout behavior. |
| `src/test/java/com/employee/portal/security/RateLimiterTest.java` | Rate limiter tests. | Exercises source/account thresholds and atomic counter increments, but not check/verify/update races or eviction. |
| `src/test/java/com/employee/portal/security/SessionManagerTest.java` | Session tests. | Exercises token format, IP binding, expiry, revocation, and session caps. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Used as the router workflow to inventory every source file, identify security-relevant behavior, select specialized skills, and require CWE/file:line evidence.
- `testing-api-authentication-weaknesses`: Applied to login behavior, password policy, account enumeration resistance, session issuance, validation, expiry, revocation, and cookie handling.
- `testing-for-broken-access-control`: Applied to CLI enrollment, role assignment, protected API endpoints, and server-side authorization decisions.
- `testing-for-sensitive-data-exposure`: Applied to credentials and tokens in transit, responses, logs, process memory, terminal input, and files at rest.
- `performing-cryptographic-audit-of-application`: Applied to PBKDF2 parameters, salts, constant-time comparison, CSPRNG token generation, hardcoded secrets, and transport cryptography.
- `performing-api-rate-limiting-bypass`: Applied to source/account/pair identifiers, counter reset behavior, cache capacity, and brute-force bypass paths.
- `exploiting-race-condition-vulnerabilities`: Applied statically to authentication check/verify/update sequences, repository updates, session lifecycle, and concurrent counters.
- General OWASP Top 10 / CWE knowledge: Applied to request timeouts/resource exhaustion, file permissions and symlinks, log injection, CSRF, output encoding, path handling, error behavior, and dependency/build configuration where no closer skill matched.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Login credentials and sessions are exposed over plaintext HTTP | High | CWE-319 | `src/main/java/com/employee/portal/security/web/PortalServer.java:20-26` |
| SEC-02 | Unauthenticated CLI enrollment can grant an arbitrary administrative role | High | CWE-862 | `src/main/java/com/employee/portal/security/cli/EmployeePortalApp.java:185-191` |
| SEC-03 | Authentication rate-limit check and update are not atomic | Medium | CWE-362 | `src/main/java/com/employee/portal/security/service/AuthenticationService.java:96-154` |
| SEC-04 | Any successful login resets the source-wide failure counter | Medium | CWE-307 | `src/main/java/com/employee/portal/security/ratelimit/RateLimiter.java:165-183` |
| SEC-05 | LRU eviction silently discards live rate-limit state | Medium | CWE-307 | `src/main/java/com/employee/portal/security/ratelimit/BoundedLruCache.java:26-30` |
| SEC-06 | Slow request bodies can exhaust all HTTP worker threads | Medium | CWE-400 | `src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:180-191` |
| SEC-07 | Existing credential and audit files are used without enforcing private permissions | Medium | CWE-732 | `src/main/java/com/employee/portal/security/repository/FileEmployeeRepository.java:65-77` |
| SEC-08 | Password policy accepts trivial and commonly compromised passwords | Medium | CWE-521 | `src/main/java/com/employee/portal/security/validation/InputValidator.java:51-56` |
| SEC-09 | Per-record PBKDF2 costs reintroduce account-enumeration timing differences | Medium | CWE-208 | `src/main/java/com/employee/portal/security/service/AuthenticationService.java:110-140` |
| SEC-10 | Password fallback input is visibly echoed | Low | CWE-200 | `src/main/java/com/employee/portal/security/cli/EmployeePortalApp.java:283-291` |
| SEC-11 | HTTP password parsing leaves immutable plaintext strings in heap memory | Low | CWE-316 | `src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:195-205` |
| SEC-12 | Failed disk persistence leaves an active in-memory credential | Low | CWE-703 | `src/main/java/com/employee/portal/security/repository/FileEmployeeRepository.java:163-169` |

## 5. Detailed Findings

### SEC-01: Login credentials and sessions are exposed over plaintext HTTP
- **Severity:** High
- **CWE:** CWE-319: Cleartext Transmission of Sensitive Information
- **Location:** `src/main/java/com/employee/portal/security/web/PortalServer.java:20-26`; `src/main/java/com/employee/portal/security/cli/EmployeePortalApp.java:269-271`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/web/PortalServer.java:20-26
    public PortalServer(int port, AuthenticationService authService, boolean requireSecureCookies) throws IOException {
        this.server = HttpServer.create(new InetSocketAddress(port), 0);
        this.executor = Executors.newFixedThreadPool(8);
        this.server.setExecutor(executor);

        PortalHttpHandler handler = new PortalHttpHandler(authService, requireSecureCookies);
        this.server.createContext("/api/", handler);
```
```java
// src/main/java/com/employee/portal/security/cli/EmployeePortalApp.java:269-271
        try {
            PortalServer server = new PortalServer(port, authService, false);
            server.start();
```

**Why it is a problem:** The server uses `HttpServer`, not `HttpsServer`, and the production entry point explicitly disables secure-cookie behavior. The listener binds to the wildcard address by default, so a network observer can capture employee passwords, session tokens, and authenticated responses. The resulting `portal_session` cookie lacks `Secure` and the `__Host-` prefix. Response headers such as CSP and `HttpOnly` do not protect data in transit.

**Fix:** Serve the API only through TLS, use a configured certificate/trust policy, bind only to the intended interface, reject or redirect plaintext traffic before credentials are accepted, and make secure cookies unconditional in production.
```java
SSLContext sslContext = loadServerTlsContext();
HttpsServer httpsServer = HttpsServer.create(new InetSocketAddress(bindAddress, port), 0);
httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext));
httpsServer.setExecutor(executor);
httpsServer.createContext("/api/", new PortalHttpHandler(authService, true));
```

### SEC-02: Unauthenticated CLI enrollment can grant an arbitrary administrative role
- **Severity:** High
- **CWE:** CWE-862: Missing Authorization
- **Location:** `src/main/java/com/employee/portal/security/cli/EmployeePortalApp.java:185-191`; `src/main/java/com/employee/portal/security/service/AuthenticationService.java:193-216`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/cli/EmployeePortalApp.java:185-191
                    System.out.print("Enter role [EMPLOYEE / ADMIN]: ");
                    String role = reader.readLine();
                    if (role == null || role.isBlank()) {
                        role = "EMPLOYEE";
                    }

                    boolean enrolled = authService.enrollEmployee(username, password, role);
```

**Why it is a problem:** Enrollment is a top-level unauthenticated menu option, and the caller directly chooses the persisted role. Neither the CLI nor `enrollEmployee` requires a validated administrator session or another trusted provisioning credential. A person with access to the running CLI and its data store can create a new `ADMIN` identity without proving authorization.

**Fix:** Remove enrollment from the unauthenticated user menu. Require a server-validated administrator session (or a separate, tightly controlled bootstrap workflow), enforce the allowed role set server-side, and audit the authorizing identity.
```java
Optional<Session> actor = sessionManager.validateSession(adminToken, sourceIp);
if (actor.isEmpty() || !"ADMIN".equals(actor.get().getRole())) {
    throw new SecurityException("Enrollment requires an authenticated administrator");
}
String assignedRole = "ADMIN".equals(requestedRole) ? "ADMIN" : "EMPLOYEE";
authService.enrollEmployee(actor.get(), username, password, assignedRole);
```

### SEC-03: Authentication rate-limit check and update are not atomic
- **Severity:** Medium
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
- **Location:** `src/main/java/com/employee/portal/security/service/AuthenticationService.java:96-154`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/service/AuthenticationService.java:96-105
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
```
```java
// src/main/java/com/employee/portal/security/service/AuthenticationService.java:143-154
            if (!matches) {
                rateLimiter.recordFailure(safeSource, normalizedUser);
                auditLogger.logEvent(AuditLogger.EventType.LOGIN_FAILURE,
                        safeSource,
                        normalizedUser,
                        "Authentication failed: credentials rejected");
                return AuthenticationResult.failure();
            }

            // Step 5: Successful authentication
            // Atomically clear failed attempts for source and account
            rateLimiter.recordSuccess(safeSource, normalizedUser);
```

**Why it is a problem:** Individual cache operations are locked, but the security decision spans `isRestricted`, an expensive PBKDF2 computation, and a later `recordFailure` or `recordSuccess`. Concurrent requests can all observe an unrestricted counter before any request updates it, allowing more password guesses than the configured threshold and letting a successful concurrent request clear failures. The concurrency test covers increments only, not this check-to-update sequence.

**Fix:** Introduce an atomic attempt reservation keyed consistently by source, account, and pair. The reservation must reject attempts once capacity is reached and commit success/failure under the same coordinated state transition. For multiple processes, use a shared atomic store or script rather than JVM-local locks.
```java
try (RateLimiter.AttemptPermit permit = rateLimiter.beginAttempt(safeSource, normalizedUser)) {
    if (!permit.isAllowed()) {
        passwordHasher.dummyVerify(password);
        return AuthenticationResult.failure();
    }
    boolean matches = passwordHasher.verifyPassword(
            password, record.getSalt(), record.getPasswordHash(), record.getIterations());
    permit.complete(matches);
    if (!matches) {
        return AuthenticationResult.failure();
    }
}
```

### SEC-04: Any successful login resets the source-wide failure counter
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/employee/portal/security/ratelimit/RateLimiter.java:165-183`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/ratelimit/RateLimiter.java:165-183
    public void recordSuccess(String sourceIp, String username) {
        if (sourceIp != null) {
            cache.compute("SRC:" + sourceIp, (k, existing) -> {
                if (existing != null) existing.reset();
                return existing;
            });
        }
        if (username != null) {
            cache.compute("ACC:" + username, (k, existing) -> {
                if (existing != null) existing.reset();
                return existing;
            });
        }
        if (sourceIp != null && username != null) {
            cache.compute("PAIR:" + sourceIp + ":" + username, (k, existing) -> {
                if (existing != null) existing.reset();
                return existing;
            });
        }
    }
```

**Why it is a problem:** A success for any account resets the shared `SRC:<ip>` record. An attacker who controls or has valid credentials for one account can alternate unsuccessful guesses against victims with successful logins to the controlled account, repeatedly clearing the per-source defense. Account-level limits remain, but the advertised independent source limit no longer constrains credential stuffing across accounts.

**Fix:** Do not clear an aggregate source-abuse counter because one account authenticated successfully. Clear only the relevant account/pair state, or decay source failures by time while maintaining a separate request-rate limit.
```java
public void recordSuccess(String sourceIp, String username) {
    if (username != null) {
        cache.remove("ACC:" + username);
    }
    if (sourceIp != null && username != null) {
        cache.remove("PAIR:" + sourceIp + ":" + username);
    }
    // Preserve SRC:<ip>; expire or decay it according to the configured window.
}
```

### SEC-05: LRU eviction silently discards live rate-limit state
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/employee/portal/security/ratelimit/BoundedLruCache.java:26-30`; `src/main/java/com/employee/portal/security/ratelimit/RateLimiter.java:81`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/ratelimit/BoundedLruCache.java:26-30
        this.map = new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
                return size() > BoundedLruCache.this.maxCapacity;
            }
        };
```
```java
// src/main/java/com/employee/portal/security/ratelimit/RateLimiter.java:80-82
    public RateLimiter(SecurityConfig config, LongSupplier clock) {
        this.cache = new BoundedLruCache<>(SecurityConfig.MAX_RATE_LIMITER_ENTRIES);
        this.maxFailedPerSource = config.getMaxFailedPerSource();
```

**Why it is a problem:** Source, account, and pair records share one attacker-influenced LRU cache. Generating enough distinct valid identifiers silently evicts older entries even when they represent an active lockout. An attacker with distributed sources can churn the cache, discard a target restriction, and resume guesses. The same generic cache also evicts active sessions, turning capacity pressure into forced logout. Bounding memory is necessary, but silently dropping live security state fails open.

**Fix:** Store rate-limit axes separately in an atomic TTL-backed store, delete only expired records, reserve capacity for active restrictions, and fail closed or shed requests when tracking capacity is unavailable. Do not use ordinary LRU eviction for live lockout state.
```java
AttemptRecord existing = attempts.get(key);
if (existing == null && attempts.size() >= maxCapacity) {
    purgeExpiredAttempts(now);
    if (attempts.size() >= maxCapacity) {
        throw new RateLimitCapacityException("Authentication tracking unavailable");
    }
}
attempts.compute(key, (k, record) -> updateAttempt(record, now));
```

### SEC-06: Slow request bodies can exhaust all HTTP worker threads
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:180-191`; `src/main/java/com/employee/portal/security/web/PortalServer.java:21-23`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:180-191
    private byte[] readBoundedBody(InputStream is, int maxBytes) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int totalRead = 0;
        int read;
        while ((read = is.read(buffer)) != -1) {
            totalRead += read;
            if (totalRead > maxBytes) {
                return null; // Bound exceeded
            }
            baos.write(buffer, 0, read);
        }
```

**Why it is a problem:** The byte count is bounded, but read duration is not. A client can send a few bytes very slowly and keep a worker blocked in `InputStream.read`. Eight such connections can occupy the fixed eight-thread executor and prevent legitimate logins. The executor is also created without a bounded rejection policy visible at the application layer.

**Fix:** Use a production HTTP/TLS server or trusted reverse proxy that enforces header, body, idle, and total request deadlines before dispatching to the application; also use bounded concurrency and request queues. A byte limit must remain in place.
```java
Server server = new Server();
ServerConnector connector = new ServerConnector(server, sslConnectionFactory, httpConnectionFactory);
connector.setIdleTimeout(Duration.ofSeconds(10).toMillis());
connector.setAcceptQueueSize(64);
server.addConnector(connector);
// Retain the 4096-byte application body limit as defense in depth.
```

### SEC-07: Existing credential and audit files are used without enforcing private permissions
- **Severity:** Medium
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `src/main/java/com/employee/portal/security/repository/FileEmployeeRepository.java:65-77`; `src/main/java/com/employee/portal/security/logging/AuditLogger.java:72-84`

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

**Why it is a problem:** Owner-only permissions are applied only when the file is newly created. A pre-existing database or audit log with group/world access is accepted unchanged. `Files.exists` follows symbolic links, and the fallback ignores the boolean results from `File.setReadable`/`setWritable`, so the promised privacy is not verified. Password hashes, account status/roles, usernames, source addresses, and audit details can therefore be exposed or redirected under unsafe deployment permissions.

**Fix:** Reject symbolic links, create/open files without following links, enforce permissions even for existing files, verify the resulting owner and mode, and abort initialization if private access cannot be guaranteed.
```java
if (Files.isSymbolicLink(dbFile)) {
    throw new SecurityException("Credential database must not be a symbolic link");
}
if (Files.notExists(dbFile, LinkOption.NOFOLLOW_LINKS)) {
    Files.createFile(dbFile, PosixFilePermissions.asFileAttribute(
            PosixFilePermissions.fromString("rw-------")));
}
Files.setPosixFilePermissions(dbFile, PosixFilePermissions.fromString("rw-------"));
if (!Files.getPosixFilePermissions(dbFile).equals(
        PosixFilePermissions.fromString("rw-------"))) {
    throw new SecurityException("Credential database permissions are not private");
}
```

### SEC-08: Password policy accepts trivial and commonly compromised passwords
- **Severity:** Medium
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `src/main/java/com/employee/portal/security/validation/InputValidator.java:51-56`; `src/main/java/com/employee/portal/security/config/SecurityConfig.java:34-35`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/validation/InputValidator.java:51-56
    public static boolean isValidPassword(char[] password) {
        if (password == null) {
            return false;
        }
        return password.length >= SecurityConfig.MIN_PASSWORD_LENGTH &&
               password.length <= SecurityConfig.MAX_PASSWORD_LENGTH;
```

**Why it is a problem:** The only strength check is an eight-character minimum, and the tests explicitly treat `12345678` as valid. PBKDF2 slows offline guessing but does not make a known or low-entropy password safe. For a password-only employee portal, this permits credentials that are readily guessed or present in breach corpora.

**Fix:** Require a longer password/passphrase appropriate to the authentication context, reject known-compromised values with a local privacy-preserving blocklist, permit long passphrases, and add MFA for privileged accounts. Do not rely on composition rules alone.
```java
public static boolean isValidPassword(char[] password) {
    if (password == null || password.length < 15 || password.length > 128) {
        return false;
    }
    return !CompromisedPasswordBlocklist.contains(password);
}
```

### SEC-09: Per-record PBKDF2 costs reintroduce account-enumeration timing differences
- **Severity:** Medium
- **CWE:** CWE-208: Observable Timing Discrepancy
- **Location:** `src/main/java/com/employee/portal/security/service/AuthenticationService.java:110-140`; `src/main/java/com/employee/portal/security/model/EmployeeRecord.java:40-41`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/service/AuthenticationService.java:110-140
            if (maybeRecord.isEmpty()) {
                // User does not exist: perform dummy hash computation to prevent user enumeration
                passwordHasher.dummyVerify(password);
                rateLimiter.recordFailure(safeSource, normalizedUser);
                auditLogger.logEvent(AuditLogger.EventType.LOGIN_FAILURE,
                        safeSource,
                        normalizedUser,
                        "Authentication failed: credentials rejected");
                return AuthenticationResult.failure();
            }

            EmployeeRecord record = maybeRecord.get();

            // Check account status
            if (!record.isActive()) {
                // Account suspended: perform dummy hash computation to prevent state enumeration
                passwordHasher.dummyVerify(password);
                rateLimiter.recordFailure(safeSource, normalizedUser);
                auditLogger.logEvent(AuditLogger.EventType.LOGIN_FAILURE,
                        safeSource,
                        normalizedUser,
                        "Authentication failed: account suspended");
                return AuthenticationResult.failure();
            }

            // Step 4: Verify supplied credentials using constant-time PBKDF2 comparison
            boolean matches = passwordHasher.verifyPassword(
                    password,
                    record.getSalt(),
                    record.getPasswordHash(),
                    record.getIterations()
            );
```

**Why it is a problem:** Missing and suspended users always incur the hasher's current default iteration count, while active users incur the iteration count stored in their record. Records permit values from 100,000 to 2,000,000, and configuration changes naturally create mixed-cost records. An attacker can distinguish active existing users, suspended users, and missing users from response-time clusters despite uniform messages and constant-time hash comparison.

**Fix:** Normalize all stored credentials to one current KDF policy through an offline migration or controlled rehash-on-login strategy, and do not serve authentication while records have distinguishable work factors. Dummy verification must use the same effective cost as every served credential class.
```java
int iterations = Integer.parseInt(iterStr);
if (iterations != configuredPbkdf2Iterations) {
    throw new IllegalStateException("Credential store requires KDF migration");
}
EmployeeRecord record = new EmployeeRecord(
        username, salt, hash, configuredPbkdf2Iterations, status, role);
```

### SEC-10: Password fallback input is visibly echoed
- **Severity:** Low
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **Location:** `src/main/java/com/employee/portal/security/cli/EmployeePortalApp.java:283-291`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/cli/EmployeePortalApp.java:283-291
    public static char[] readPasswordSecurely(String prompt, BufferedReader fallbackReader) {
        Console console = System.console();
        if (console != null) {
            return console.readPassword(prompt);
        } else {
            System.out.print(prompt);
            try {
                String line = fallbackReader.readLine();
                return line != null ? line.toCharArray() : null;
```

**Why it is a problem:** When `System.console()` is unavailable—as in many IDEs, redirected sessions, containers, or service wrappers—the fallback reads an ordinary line with terminal echo enabled. The password may be visible to observers or captured in terminal/session logs; it also exists as an immutable `String`.

**Fix:** Fail closed for interactive password entry when hidden input is unavailable, or use a vetted terminal library that disables echo and restores terminal state reliably. Provisioning automation should accept secrets through a protected secret channel, not ordinary stdin.
```java
public static char[] readPasswordSecurely(String prompt) {
    Console console = System.console();
    if (console == null) {
        throw new IllegalStateException("A protected console is required for password input");
    }
    return console.readPassword(prompt);
}
```

### SEC-11: HTTP password parsing leaves immutable plaintext strings in heap memory
- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:195-205`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:195-205
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
```

**Why it is a problem:** Clearing the resulting `char[]` does not clear `body`, `raw`, `pairs`, `kv`, or the decoded `val` strings. The plaintext password can remain in immutable heap objects until garbage collection and can appear in heap dumps or memory-forensics output. This contradicts the component's stated memory-clearing control.

**Fix:** Use a form parser designed to deliver sensitive values into mutable buffers, avoid whole-body/string copies, and clear both the original body bytes and mutable decoded buffers in `finally`. Also disable or tightly protect heap dumps and process debugging as defense in depth.
```java
byte[] body = readBoundedBody(exchange.getRequestBody(), MAX_REQUEST_BODY_BYTES);
try {
    MutableForm form = MutableForm.parseUtf8(body);
    char[] password = form.removeChars("password");
    authenticateAndClear(password);
    form.clear();
} finally {
    Arrays.fill(body, (byte) 0);
}
```

### SEC-12: Failed disk persistence leaves an active in-memory credential
- **Severity:** Low
- **CWE:** CWE-703: Improper Check or Handling of Exceptional Conditions
- **Location:** `src/main/java/com/employee/portal/security/repository/FileEmployeeRepository.java:163-169`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/repository/FileEmployeeRepository.java:163-169
    public boolean save(EmployeeRecord record) {
        Objects.requireNonNull(record, "record cannot be null");
        rwLock.writeLock().lock();
        try {
            cache.put(record.getUsername().toLowerCase(), record);
            return persistToDisk();
        } finally {
```

**Why it is a problem:** The cache is modified before persistence. If the atomic file write/move fails, `save` returns `false`, but authentication immediately sees the new or replaced credential in memory. The caller reports enrollment failure while the account is active until restart, and an attempted overwrite can replace the running credential without a durable commit.

**Fix:** Stage the change, persist the staged snapshot first, and publish it to the live cache only after a successful atomic move. Alternatively, roll back the exact previous value on failure while still holding the write lock.
```java
String key = record.getUsername().toLowerCase();
Map<String, EmployeeRecord> staged = new HashMap<>(cache);
staged.put(key, record);
if (!persistToDisk(staged)) {
    return false;
}
cache.clear();
cache.putAll(staged);
return true;
```

## 6. Verified Controls and Checks With No Finding
- Password hashing primitives: Verified PBKDF2-HMAC-SHA-512, 32-byte random salts, 256-bit derived keys, bounded work factors, and `MessageDigest.isEqual` in `PasswordHasher.java`; no weak hash, fixed salt, predictable RNG, or direct password comparison was found.
- Session token generation: Verified 32 bytes from `SecureRandom`, Base64URL encoding, server-side lookup, idle and absolute expiry, and logout revocation in `SecureTokenGenerator.java` and `SessionManager.java`; no caller-selected or predictable token was found.
- Authentication responses: Verified the same public failure message across malformed input, nonexistent users, suspended users, wrong passwords, and restrictions in `AuthenticationResult.java` and `AuthenticationService.java`; detailed internal exceptions are not returned by the HTTP handler.
- Server-side session authorization: Verified `/api/dashboard` rejects missing, malformed, unknown, expired, and source-IP-mismatched tokens in `PortalHttpHandler.java:122-142` and `SessionManager.java:90-117`.
- Cookie attributes when secure mode is enabled: Verified `__Host-session`, `Path=/`, `Secure`, `HttpOnly`, `SameSite=Strict`, and bounded `Max-Age` in `SecureTokenGenerator.java:53-64`; SEC-01 concerns production disabling that mode and omitting TLS.
- HTTP response hardening: Verified `X-Content-Type-Options`, `X-Frame-Options`, restrictive CSP, and no-store cache directives on responses in `PortalHttpHandler.java:44-50`.
- Output injection: Verified values reaching JSON are constrained by username/role/IP allowlists or static messages, and HTML metacharacters are escaped. No exploitable XSS or JSON injection was identified in the current response fields.
- Log injection and secret logging: Verified CR/LF/control-character sanitization, input length truncation, generic audit details, and token masking in `InputValidator.java:90-105` and `AuditLogger.java:90-123`; no full password or session token logging was found.
- File-record parsing: Verified bounds and allowlists for usernames, salt/hash lengths, iteration count, status enum, and role in `FileEmployeeRepository.java` and `EmployeeRecord.java`; malformed records fail closed.
- Path traversal: Verified fixed database/log filenames, normalized configured directories, and strict username allowlisting; usernames do not influence filesystem paths.
- Memory bounds: Verified request bodies, session counts, password lengths, and in-memory maps have numeric limits. SEC-05 and SEC-06 concern the fail-open/availability behavior of particular bounding choices, not unbounded allocation.
- CSRF: Verified state-changing HTTP operations use POST and cookies use `SameSite=Strict`. No high-confidence cross-site state-change exploit was established for the current API, which exposes only login/logout and a read-only dashboard.
- Hardcoded secrets and dependency surface: No production credentials, signing keys, API keys, default accounts, native command execution, deserialization, SQL construction, or runtime third-party dependencies were found. Maven versions are pinned in `pom.xml`.
