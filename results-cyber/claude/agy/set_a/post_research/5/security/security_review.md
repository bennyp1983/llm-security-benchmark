# Security Review: Secure Employee Portal Authentication (Java)

## 1. Executive Summary

The component is a self-contained Java 17 authentication system for an internal employee portal. It offers a CLI (`EmployeePortalApp`) and an embedded `com.sun.net.httpserver` HTTP API (`/api/login`, `/api/dashboard`, `/api/logout`). Credentials are stored in a flat file (`employees.db`) as PBKDF2WithHmacSHA512 hashes (210,000 iterations, 32-byte salt), sessions are opaque 256-bit `SecureRandom` tokens held in a bounded in-memory LRU map, and failed logins are counted per source IP, per account, and per source+account pair.

The cryptographic core is genuinely strong: modern KDF with sound parameters, `SecureRandom.getInstanceStrong()`, constant-time hash comparison via `MessageDigest.isEqual`, dummy PBKDF2 work on every failure path, a single generic failure message, strict allow-list input validation, log CRLF sanitisation, 0600 file creation, and atomic file replacement. No working hardcoded credentials or keys exist anywhere in the tree.

The important findings are in the state and transport layers rather than the crypto:

- **The brute-force/lockout control can be reset at will.** All lockout state lives in a 10,000-entry access-ordered LRU cache; an attacker who generates traffic with ~10k distinct usernames evicts the `ACC:`/`SRC:` lockout records of the account they are attacking, so the lockout silently disappears (SEC-01).
- **In the CLI the source IP used for rate limiting is typed in by the caller**, so the per-source axis of the "dual-axis" limiter is attacker-controlled (SEC-02).
- **The HTTP server is always started in plaintext mode with `requireSecureCookies = false`**, so session cookies are issued without `Secure`, there is no HSTS, and passwords and tokens cross the network in the clear (SEC-03).
- **Full session tokens are printed to the console** by the CLI success path, contradicting the system's own masking policy (SEC-04).
- Session IP binding **fails open** when either IP is `null` (SEC-05), the rate-limit gate is a non-atomic check-then-act (SEC-06), the `__Host-` cookie prefix protection is defeated by also accepting a non-prefixed cookie name (SEC-07), and pre-existing database/log files are used without verifying their permissions (SEC-08).

Four lower-severity issues (passwords materialised in immutable `String`s, no CSRF/Content-Type defence on state-changing endpoints, sessions surviving account suspension, and a length-only password policy) complete the picture. No SQL, no deserialization, no command execution and no template rendering exist in this code base, so those classes do not apply.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/employee/portal/security/config/SecurityConfig.java` | Central tunables and limits | Reads system properties / environment variables, clamps numeric values to safe ranges, canonicalises the data directory path |
| `src/main/java/com/employee/portal/security/validation/InputValidator.java` | Allow-list validation + output sanitisation | Username/password/IP/token regexes, log CRLF sanitisation, HTML escaping; password policy is length-only |
| `src/main/java/com/employee/portal/security/crypto/PasswordHasher.java` | Password hashing/verification | PBKDF2WithHmacSHA512, 210k iterations, `SecureRandom.getInstanceStrong()`, `MessageDigest.isEqual`, dummy-verify for timing neutrality, array zeroing |
| `src/main/java/com/employee/portal/security/crypto/SecureTokenGenerator.java` | Session token + cookie construction | 256-bit CSPRNG URL-safe tokens; builds `Set-Cookie` with `HttpOnly`, `SameSite=Strict`, conditional `Secure`/`__Host-` prefix |
| `src/main/java/com/employee/portal/security/model/EmployeeRecord.java` | Stored credential record | Re-validates username, salt/hash lengths, iteration range, role format; defensive array copies; `toString` omits secrets |
| `src/main/java/com/employee/portal/security/model/Session.java` | Server-side session state | Idle + absolute expiry logic, IP binding field, masked `toString` |
| `src/main/java/com/employee/portal/security/model/AuthenticationResult.java` | Auth outcome | Single generic failure message for all failure modes |
| `src/main/java/com/employee/portal/security/model/UserStatus.java` | Account status enum | `ACTIVE` / `SUSPENDED` |
| `src/main/java/com/employee/portal/security/repository/EmployeeRepository.java` | Persistence contract | Lookup/save/exists/reload surface |
| `src/main/java/com/employee/portal/security/repository/FileEmployeeRepository.java` | Flat-file credential store | Creates files 0600 / dirs 0700, parses and re-validates every stored field, atomic temp-file replace, `ReentrantReadWriteLock` |
| `src/main/java/com/employee/portal/security/ratelimit/RateLimiter.java` | Failed-attempt tracking | Per-source, per-account and per-pair counters with windows and lockouts; all state in a bounded LRU |
| `src/main/java/com/employee/portal/security/ratelimit/BoundedLruCache.java` | Bounded LRU store | Access-ordered `LinkedHashMap` with eviction, `ReentrantLock`, atomic `compute` |
| `src/main/java/com/employee/portal/security/logging/AuditLogger.java` | Security audit log | Sanitises all fields, masks tokens, creates log 0600, appends under a lock, mirrors to stdout |
| `src/main/java/com/employee/portal/security/session/SessionManager.java` | Session lifecycle | Token issuance, server-side validation, idle/absolute expiry, per-user session cap, IP binding, revocation |
| `src/main/java/com/employee/portal/security/service/AuthenticationService.java` | Authentication orchestration | Validation → rate-limit gate → record lookup → status check → PBKDF2 verify → session creation; dummy hashing on every failure path; password zeroing |
| `src/main/java/com/employee/portal/security/web/PortalHttpHandler.java` | HTTP endpoints | Body size bound, form parsing, cookie extraction, security response headers, generic JSON errors |
| `src/main/java/com/employee/portal/security/web/PortalServer.java` | Embedded HTTP server | Plain `HttpServer.create` (no TLS), fixed 8-thread pool, `/api/` context |
| `src/main/java/com/employee/portal/security/cli/EmployeePortalApp.java` | CLI entry point | Interactive login/enrol/session-verify/server-start; reads passwords via `Console.readPassword`; supplies the source IP and prints session data |
| `pom.xml` | Build definition | Pinned plugin and JUnit 5.10.2 versions, no third-party runtime dependencies |
| `src/test/java/.../*.java` (7 files) | JUnit tests | Exercise validator, hasher, rate limiter, sessions, repository, service, HTTP handler; not part of the attack surface |

## 3. Skills Applied

- `review-code-for-security-vulnerabilities`: router skill — drove file-by-file comprehension, keyword extraction (password storage, session tokens, rate limiting, cookies, file permissions, logging, HTTP input handling) and selection of the specialised skills below.
- `performing-cryptographic-audit-of-application`: applied to `PasswordHasher`, `SecureTokenGenerator` and `SecurityConfig` — checked KDF choice and iteration count, salt length and generation, RNG source, constant-time comparison, key sizes, hardcoded key/secret material and transport crypto. Only the transport leg failed (SEC-03); the primitives themselves are sound.
- `testing-api-authentication-weaknesses`: applied to `AuthenticationService`, `SessionManager` and `PortalHttpHandler` — token entropy, server-side validation, revocation on logout and on account state change, token leakage into logs/output, password policy, account enumeration via differing responses. Produced SEC-04, SEC-05, SEC-11, SEC-12, SEC-13.
- `performing-api-rate-limiting-bypass`: applied to `RateLimiter`, `BoundedLruCache`, `PortalHttpHandler.extractClientIp` and `EmployeePortalApp.handleLogin` — IP-spoofing headers, account rotation, path/method/case variation, parameter pollution and concurrent-burst bypass. Produced SEC-01, SEC-02 and SEC-06; confirmed `X-Forwarded-For` is correctly ignored.
- `performing-security-headers-audit`: applied to `PortalHttpHandler.handle` and the `Set-Cookie` builders — CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Cache-Control`, HSTS, and cookie `Secure`/`HttpOnly`/`SameSite`/prefix attributes. Produced SEC-03 and SEC-07.
- `testing-for-sensitive-data-exposure`: applied to `AuditLogger`, `Session.toString`, `EmployeeRecord.toString`, `FileEmployeeRepository`, and CLI output — secret masking, data at rest file permissions, data in transit, information leakage in errors. Produced SEC-04, SEC-08 and SEC-10.
- `performing-csrf-attack-simulation`: applied to the state-changing `POST /api/login` and `POST /api/logout` handlers — origin/referer checks, anti-CSRF tokens, Content-Type enforcement, cookie `SameSite` reliance. Produced SEC-11.
- `testing-for-broken-access-control`: applied to `handleDashboard` and `SessionManager.validateSession` — whether authorisation is re-derived from server-side state, and whether role/status changes take effect. Produced SEC-12; confirmed no IDOR surface exists (no object identifiers are accepted).
- Behaviours reviewed against general OWASP Top 10 / CWE knowledge because no library skill matched: concurrency / TOCTOU on the lockout counters (CWE-367, informing SEC-06), local file-store hardening and symlink/permission handling for `employees.db` and `audit.log` (CWE-732, SEC-08), in-memory credential lifetime in immutable `String` objects (CWE-316, SEC-09), configuration intake from environment and system properties (CWE-15/CWE-20 — found adequately clamped), log injection handling (CWE-117 — found correctly sanitised), and build/dependency hygiene in `pom.xml` (CWE-1104 — all versions pinned, no third-party runtime code). There is no SQL, ORM, XML parser, deserialization, reflection, or `Runtime.exec` anywhere in the tree, so CWE-89, CWE-502, CWE-611 and CWE-78 are structurally inapplicable.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Lockout state is evictable: brute-force protection reset by flooding the LRU cache | High | CWE-307 | `src/main/java/com/employee/portal/security/ratelimit/RateLimiter.java:81` |
| SEC-02 | CLI takes the rate-limiting source IP from the user, defeating the per-source limit | High | CWE-807 | `src/main/java/com/employee/portal/security/cli/EmployeePortalApp.java:116` |
| SEC-03 | Credentials and session cookies are served over plaintext HTTP with `Secure` hardcoded off | High | CWE-319 | `src/main/java/com/employee/portal/security/cli/EmployeePortalApp.java:246` |
| SEC-04 | Full session token printed to console and included in CLI output | Medium | CWE-532 | `src/main/java/com/employee/portal/security/cli/EmployeePortalApp.java:130` |
| SEC-05 | Session IP binding fails open when either IP is null | Medium | CWE-636 | `src/main/java/com/employee/portal/security/session/SessionManager.java:107` |
| SEC-06 | Non-atomic check-then-act on the lockout gate allows a concurrent-burst bypass | Medium | CWE-367 | `src/main/java/com/employee/portal/security/service/AuthenticationService.java:97` |
| SEC-07 | `__Host-` cookie-prefix protection defeated by accepting the unprefixed cookie name | Medium | CWE-565 | `src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:173` |
| SEC-08 | Pre-existing credential database and audit log are used without verifying permissions | Medium | CWE-732 | `src/main/java/com/employee/portal/security/repository/FileEmployeeRepository.java:65` |
| SEC-09 | Submitted passwords are materialised in immutable `String` objects, defeating zeroing | Low | CWE-316 | `src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:204` |
| SEC-10 | Audit log re-created with default (world-readable) permissions if removed | Low | CWE-532 | `src/main/java/com/employee/portal/security/logging/AuditLogger.java:106` |
| SEC-11 | No CSRF or Content-Type defence on `POST /api/login` and `POST /api/logout` | Low | CWE-352 | `src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:57` |
| SEC-12 | Sessions survive account suspension; authorisation state never re-checked | Low | CWE-613 | `src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:129` |
| SEC-13 | Password policy is length-only; no complexity or breached-password screening | Low | CWE-521 | `src/main/java/com/employee/portal/security/validation/InputValidator.java:55` |

## 5. Detailed Findings

### SEC-01: Lockout state is evictable: brute-force protection reset by flooding the LRU cache
- **Severity:** High
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/employee/portal/security/ratelimit/RateLimiter.java:81` (with `src/main/java/com/employee/portal/security/ratelimit/BoundedLruCache.java:26-31`)

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/ratelimit/RateLimiter.java:80-87
    public RateLimiter(SecurityConfig config, LongSupplier clock) {
        this.cache = new BoundedLruCache<>(SecurityConfig.MAX_RATE_LIMITER_ENTRIES);
        this.maxFailedPerSource = config.getMaxFailedPerSource();
        this.maxFailedPerAccount = config.getMaxFailedPerAccount();
        this.failureWindowMillis = config.getFailureWindowMillis();
        this.lockoutDurationMillis = config.getLockoutDurationMillis();
        this.clock = Objects.requireNonNull(clock, "clock cannot be null");
    }
```
```java
// src/main/java/com/employee/portal/security/ratelimit/BoundedLruCache.java:26-31
        this.map = new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
                return size() > BoundedLruCache.this.maxCapacity;
            }
        };
```

**Why it is a problem:** Every lockout decision in the system is read out of this single 10,000-entry, access-ordered LRU map (`isRestricted` at `RateLimiter.java:111-132` returns `false` whenever the key is absent — absence means "not restricted"). The map silently discards its least-recently-used entry once it exceeds capacity, and a failed login attempt inserts up to three attacker-chosen keys (`SRC:<ip>`, `ACC:<username>`, `PAIR:<ip>:<username>`). An attacker who has burned the 10-failure budget on `ACC:ceo` simply issues further login attempts against ~5,000 distinct non-existent usernames; each one inserts two fresh entries (`ACC:` and `PAIR:`) and pushes the now-idle `ACC:ceo` record off the end of the map. The next guess against `ceo` sees no record at all, so the lockout — and the accumulated failure count — is gone, and password guessing can continue indefinitely in 10-attempt bursts. The same trick clears the `SRC:` record for the attacker's own IP. This is the exact "account rotation" bypass the `performing-api-rate-limiting-bypass` skill tests for (Step 5), and it nullifies the feature the task is built around. Note also that nothing evicts expired entries deliberately, so the cache stays full of attacker-chosen keys, keeping eviction pressure on legitimate records.

**Fix:** Lockout state must not be stored in a structure that can discard it. Keep locked records in a non-evictable store and evict only records that are both unlocked and outside the failure window; bound memory by expiry (and, if needed, by refusing new *unlocked* entries rather than dropping existing locked ones). Persisting lockouts would additionally survive a restart.

```java
// RateLimiter.java - keep locked entries; expire by time, not by LRU pressure
private final ConcurrentHashMap<String, AttemptRecord> records = new ConcurrentHashMap<>();

private AttemptRecord recordFor(String key, long now) {
    // Opportunistic time-based cleanup: only drop records that are neither
    // locked nor inside their failure window, so a lockout can never be evicted.
    if (records.size() > SecurityConfig.MAX_RATE_LIMITER_ENTRIES) {
        records.values().removeIf(r -> !r.isLocked(now) && r.isWindowExpired(now, failureWindowMillis));
    }
    return records.computeIfAbsent(key, k -> new AttemptRecord(now));
}

public void recordFailure(String sourceIp, String username) {
    long now = clock.getAsLong();
    if (sourceIp != null && !sourceIp.isBlank()) {
        recordFor("SRC:" + sourceIp, now)
            .recordFailure(now, failureWindowMillis, maxFailedPerSource, lockoutDurationMillis);
    }
    if (username != null && !username.isBlank()) {
        recordFor("ACC:" + username, now)
            .recordFailure(now, failureWindowMillis, maxFailedPerAccount, lockoutDurationMillis);
    }
    if (sourceIp != null && !sourceIp.isBlank() && username != null && !username.isBlank()) {
        recordFor("PAIR:" + sourceIp + ":" + username, now)
            .recordFailure(now, failureWindowMillis, maxFailedPerSource, lockoutDurationMillis);
    }
}
```

### SEC-02: CLI takes the rate-limiting source IP from the user, defeating the per-source limit
- **Severity:** High
- **CWE:** CWE-807: Reliance on Untrusted Inputs in a Security Decision
- **Location:** `src/main/java/com/employee/portal/security/cli/EmployeePortalApp.java:116-123`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/cli/EmployeePortalApp.java:116-123
                System.out.print("Enter client IP [leave empty for 127.0.0.1]: ");
                String clientIp = reader.readLine();
                if (clientIp == null || clientIp.isBlank()) {
                    clientIp = "127.0.0.1";
                }

                System.out.println("Authenticating...");
                AuthenticationResult result = authService.authenticate(username, password, clientIp.trim());
```

**Why it is a problem:** `sourceIp` is the key for the per-source and per-pair lockout axes (`RateLimiter.java:140,154`) and is also the value a session is bound to (`SessionManager.java:58`). Here it is typed in by the caller and only format-checked — never derived from the connection. An attacker driving the CLI (the documented interactive login path) supplies a different well-formed IP on every attempt, so `SRC:` and `PAIR:` counters never accumulate and the entire "dual-axis" defence collapses to the per-account counter. Combined with SEC-01 that leaves no effective limit at all. It also lets the attacker bind a stolen session to an arbitrary "IP", and poisons the audit trail with forged source addresses (`AuthenticationService.java:87-90`). The HTTP path does this correctly (`PortalHttpHandler.java:156-162` reads the real socket address), which shows the intended design.

**Fix:** Never accept the source identifier from the authenticating party. In the CLI the request genuinely originates locally, so derive it from the process context and remove the prompt entirely; if an operator-supplied value is ever needed, gate it behind a separate trusted-admin path and document it.

```java
// EmployeePortalApp.handleLogin - derive the source, never prompt for it
                // The CLI request always originates from this host; the source is not
                // caller-supplied, so per-source rate limiting cannot be rotated away.
                String clientIp = InetAddress.getLoopbackAddress().getHostAddress();

                System.out.println("Authenticating...");
                AuthenticationResult result = authService.authenticate(username, password, clientIp);
```

### SEC-03: Credentials and session cookies are served over plaintext HTTP with `Secure` hardcoded off
- **Severity:** High
- **CWE:** CWE-319: Cleartext Transmission of Sensitive Information
- **Location:** `src/main/java/com/employee/portal/security/cli/EmployeePortalApp.java:246` and `:270`; `src/main/java/com/employee/portal/security/web/PortalServer.java:21`; `src/main/java/com/employee/portal/security/cli/EmployeePortalApp.java:49`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/cli/EmployeePortalApp.java:246-247
            PortalServer server = new PortalServer(port, authService, false);
            server.start();
```
```java
// src/main/java/com/employee/portal/security/web/PortalServer.java:20-23
    public PortalServer(int port, AuthenticationService authService, boolean requireSecureCookies) throws IOException {
        this.server = HttpServer.create(new InetSocketAddress(port), 0);
        this.executor = Executors.newFixedThreadPool(8);
        this.server.setExecutor(executor);
```

**Why it is a problem:** `HttpServer.create` is the plaintext server (`HttpsServer.create` with an `HttpsConfigurator` is the TLS variant), and every construction site passes `requireSecureCookies = false` — `EmployeePortalApp.java:49`, `:246` and `:270` — with no configuration switch to turn it on. The consequences compound: form-encoded usernames and passwords traverse the network in clear text; `SecureTokenGenerator.buildSessionCookieHeader` (`:53-64`) therefore emits `portal_session=<token>; Path=/; HttpOnly; SameSite=Strict` with **no `Secure` flag**, so the session token is replayable by any passive observer on the path and is sent over future plaintext requests; and no `Strict-Transport-Security` header is set anywhere in `PortalHttpHandler.handle` (`:45-50`), so there is no downgrade protection even if TLS were added at a proxy. All the care taken over 210k-iteration PBKDF2 and 256-bit tokens is undone by handing both the password and the token to the network in the clear. "Internal portal" is not a mitigation — this is precisely the adversary-in-the-middle position (ATT&CK T1557) the crypto-audit skill flags.

**Fix:** Serve the API over TLS using `HttpsServer` with a keystore supplied by configuration, always issue `Secure` cookies, and add HSTS. Refuse to start in plaintext unless an explicit, clearly named development flag is set.

```java
// PortalServer - TLS by default, plaintext only on an explicit dev opt-in
public PortalServer(int port, AuthenticationService authService,
                    SSLContext sslContext, boolean allowInsecureDevMode) throws IOException {
    if (sslContext != null) {
        HttpsServer https = HttpsServer.create(new InetSocketAddress(port), 0);
        https.setHttpsConfigurator(new HttpsConfigurator(sslContext));
        this.server = https;
    } else if (allowInsecureDevMode) {
        this.server = HttpServer.create(new InetSocketAddress(port), 0);
    } else {
        throw new IllegalStateException("TLS keystore not configured; refusing to serve credentials in cleartext");
    }
    this.executor = Executors.newFixedThreadPool(8);
    this.server.setExecutor(executor);
    // requireSecureCookies is true whenever TLS is in use
    this.server.createContext("/api/", new PortalHttpHandler(authService, sslContext != null));
}
```
```java
// PortalHttpHandler.handle - add transport downgrade protection
exchange.getResponseHeaders().set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
```

### SEC-04: Full session token printed to console and included in CLI output
- **Severity:** Medium
- **CWE:** CWE-532: Insertion of Sensitive Information into Log File
- **Location:** `src/main/java/com/employee/portal/security/cli/EmployeePortalApp.java:130-131`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/cli/EmployeePortalApp.java:127-131
                    System.out.println("\n[+] ACCESS GRANTED");
                    System.out.println("    Welcome, " + InputValidator.escapeHtml(session.getUsername()));
                    System.out.println("    Role: " + session.getRole());
                    System.out.println("    Session ID: " + session.getSessionId());
                    result.getCookieHeader().ifPresent(c -> System.out.println("    Cookie Header: " + c));
```

**Why it is a problem:** The session identifier is a bearer credential: anyone holding it can authenticate as the user until it expires (up to 8 hours). Everywhere else the system is careful — `Session.toString` masks it (`Session.java:76`), `AuditLogger.maskToken` masks it (`AuditLogger.java:119-123`), and the success audit entry logs only the masked form (`AuthenticationService.java:170`). These two lines print it in full, twice (the cookie header contains it as well), to stdout. Console output is routinely captured in terminal scrollback, `screen`/`tmux` logs, CI job logs, systemd journals and shoulder-surfing range, and the `AuditLogger` is constructed with `consoleOutput = true` (`AuditLogger.java:48`) so the same stream is already treated as a log sink. This directly violates the system's own stated masking policy.

**Fix:** Print only the masked token, and never the raw cookie header.

```java
                    System.out.println("\n[+] ACCESS GRANTED");
                    System.out.println("    Welcome, " + session.getUsername());
                    System.out.println("    Role: " + session.getRole());
                    // Bearer credential: show only a correlation prefix, never the full token
                    System.out.println("    Session ID: " + AuditLogger.maskToken(session.getSessionId()));
                    System.out.println("    Session cookie issued (value withheld).");
```

### SEC-05: Session IP binding fails open when either IP is null
- **Severity:** Medium
- **CWE:** CWE-636: Not Failing Securely ('Failing Open')
- **Location:** `src/main/java/com/employee/portal/security/session/SessionManager.java:107-113`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/session/SessionManager.java:106-113
        // Validate client IP binding if source IP is available (prevents session hijacking)
        if (currentSourceIp != null && session.getSourceIp() != null) {
            if (!session.getSourceIp().equals(currentSourceIp)) {
                // Suspicious IP change for active session: invalidate
                sessionCache.remove(token);
                return Optional.empty();
            }
        }
```

**Why it is a problem:** A missing value skips the check instead of rejecting the request, which is the opposite of the "a missing or failed check fails closed" requirement. `Session.getSourceIp()` is explicitly nullable (`Session.java:28` assigns it without a null check, unlike the other fields), and callers can pass `currentSourceIp == null`: `EmployeePortalApp.handleVerifySession` (`:214-220`) advertises "leave empty to skip IP check" and converts blank input to `null`, so anyone holding a token can validate it with the binding disabled. Any future caller that forgets to thread the client address through silently loses the control too. The anti-hijacking guarantee claimed in the README is therefore optional at the attacker's discretion on the CLI path.

**Fix:** Make the binding mandatory. Require a non-null, validated source IP on both sides and reject when either is absent.

```java
    public Optional<Session> validateSession(String token, String currentSourceIp) {
        if (!InputValidator.isValidSessionToken(token)) {
            return Optional.empty();
        }
        // Fail closed: a session with no recorded binding, or a request with no
        // identifiable source, cannot be validated.
        if (!InputValidator.isValidSourceIp(currentSourceIp)) {
            return Optional.empty();
        }

        Session session = sessionCache.get(token);
        if (session == null || session.getSourceIp() == null) {
            return Optional.empty();
        }

        long now = clock.getAsLong();
        if (session.isExpired(now, idleTimeoutMillis)) {
            sessionCache.remove(token);
            return Optional.empty();
        }

        if (!session.getSourceIp().equals(currentSourceIp.trim())) {
            sessionCache.remove(token);
            return Optional.empty();
        }

        session.touch(now);
        return Optional.of(session);
    }
```

### SEC-06: Non-atomic check-then-act on the lockout gate allows a concurrent-burst bypass
- **Severity:** Medium
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `src/main/java/com/employee/portal/security/service/AuthenticationService.java:97-105` and `:144`

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

**Why it is a problem:** The counter is read at line 97 and only incremented much later, at line 144, after a deliberately slow 210,000-iteration PBKDF2 verification. Individually `isRestricted` and `recordFailure` are atomic, but the composite "count, then allow" sequence is not — exactly the pattern the task's concurrency rule targets. With the server's 8-thread pool (`PortalServer.java:22`), eight simultaneous `POST /api/login` requests all pass the gate before any of them records a failure, so each burst yields up to 8 guesses regardless of the configured limit of 10; because the window is wide (15 minutes) and the hash is slow, the gap between check and update is hundreds of milliseconds, making the race trivially winnable rather than theoretical. Repeated bursts therefore overshoot the lockout threshold, and the overshoot grows with the thread pool size.

**Fix:** Make the gate atomically reserve an attempt slot before doing the expensive work, and settle it afterwards — so concurrent requests cannot all claim the same remaining budget.

```java
// RateLimiter - atomic reserve/settle instead of read-then-later-write
/** Atomically consumes one attempt slot; false means the caller is restricted. */
public boolean tryAcquireAttempt(String sourceIp, String username) {
    long now = clock.getAsLong();
    boolean allowed = reserve("SRC:" + sourceIp, now, maxFailedPerSource)
            && reserve("ACC:" + username, now, maxFailedPerAccount)
            && reserve("PAIR:" + sourceIp + ":" + username, now, maxFailedPerSource);
    return allowed;
}

private boolean reserve(String key, long now, int maxAttempts) {
    AttemptRecord rec = recordFor(key, now);
    // in-flight attempts count towards the budget until released on success
    return rec.tryReserve(now, failureWindowMillis, maxAttempts, lockoutDurationMillis);
}

// AuthenticationService.authenticate - Step 2
            if (!rateLimiter.tryAcquireAttempt(safeSource, normalizedUser)) {
                passwordHasher.dummyVerify(password);
                auditLogger.logEvent(AuditLogger.EventType.LOGIN_FAILURE,
                        safeSource, normalizedUser,
                        "Login rejected: source or account rate limit reached");
                return AuthenticationResult.failure();
            }
```

### SEC-07: `__Host-` cookie-prefix protection defeated by accepting the unprefixed cookie name
- **Severity:** Medium
- **CWE:** CWE-565: Reliance on Cookies without Validation and Integrity Checking
- **Location:** `src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:169-176`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:169-176
        String cookieName = requireSecureCookies ? "__Host-session" : "portal_session";
        String[] cookies = cookieHeader.split(";");
        for (String c : cookies) {
            String[] parts = c.trim().split("=", 2);
            if (parts.length == 2 && (parts[0].equals(cookieName) || parts[0].equals("__Host-session") || parts[0].equals("portal_session"))) {
                return parts[1].trim();
            }
        }
        return null;
```

**Why it is a problem:** The whole point of the `__Host-` prefix is that browsers refuse to store such a cookie unless it was set with `Secure`, `Path=/` and no `Domain` — i.e. it cannot be injected by a sibling subdomain or over a plaintext hop. By also accepting `portal_session` unconditionally, the server throws that guarantee away in secure mode: an attacker with a foothold on any sibling subdomain (or a network position on a plaintext request) can set a plain `portal_session` cookie, and the server will happily consume it as the session token. The extra name also makes the first clause redundant and is a session-fixation primitive — a victim can be made to carry an attacker-chosen session value. The ordering is non-deterministic too: whichever matching cookie appears first in the header wins, so an injected cookie can shadow the legitimate one.

**Fix:** Accept exactly the cookie name the current mode issues, and nothing else. Also re-validate the token format before use (it is validated downstream in `SessionManager`, but failing fast here prevents malformed values reaching the cache lookup).

```java
        String cookieName = requireSecureCookies ? "__Host-session" : "portal_session";
        for (String c : cookieHeader.split(";")) {
            String[] parts = c.trim().split("=", 2);
            // Only the name issued in the current mode is honoured, so the __Host-
            // prefix guarantee cannot be bypassed with an unprefixed cookie.
            if (parts.length == 2 && parts[0].equals(cookieName)) {
                String value = parts[1].trim();
                return InputValidator.isValidSessionToken(value) ? value : null;
            }
        }
        return null;
```

### SEC-08: Pre-existing credential database and audit log are used without verifying permissions
- **Severity:** Medium
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `src/main/java/com/employee/portal/security/repository/FileEmployeeRepository.java:65-77` (same pattern at `src/main/java/com/employee/portal/security/logging/AuditLogger.java:72-84`)

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

**Why it is a problem:** The 0600 permissions are applied only on the *creation* path. If the file already exists — the normal case on every run after the first, after a restore from backup, after an operator `touch`, or because an attacker pre-created it — its mode, owner and type are never examined. The data directory itself is whatever `PORTAL_DATA_DIR` or the relative `./data` default resolves to (`SecurityConfig.java:174-185` validates only control characters, not whether the location is shared or world-writable), so the store can legitimately end up in a directory such as `/tmp`. A local unprivileged user can then pre-create a world-readable `employees.db`, or a symlink pointing at it, and read every salt and PBKDF2 hash for offline cracking; a pre-created *writable* file lets them inject an attacker-controlled record and authenticate as any role, since the loader accepts any schema-valid line (`:112-123`). `AuditLogger.ensureSecureLogFile` has the identical gap, allowing the audit trail to be read or tampered with.

**Fix:** On startup, verify the resolved path is a regular file (not a symlink), owned by the current user, and with no group/other bits; tighten or refuse otherwise. Reject data directories that are world- or group-writable.

```java
    private void ensureSecureFileExists() {
        try {
            // ... directory creation as before ...
            if (!Files.exists(dbFile)) {
                // ... creation with 0600 as before ...
            } else {
                assertPrivateRegularFile(dbFile);
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to initialize secure storage at " + dbFile, e);
        }
    }

    private static void assertPrivateRegularFile(Path file) throws IOException {
        if (Files.isSymbolicLink(file) || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalStateException("Credential store is not a regular file: " + file);
        }
        PosixFileAttributeView view = Files.getFileAttributeView(file, PosixFileAttributeView.class,
                LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            return; // non-POSIX platform: nothing further to assert
        }
        PosixFileAttributes attrs = view.readAttributes();
        if (!attrs.owner().equals(Files.getOwner(Paths.get(System.getProperty("user.home"))))) {
            throw new IllegalStateException("Credential store not owned by this user: " + file);
        }
        Set<PosixFilePermission> perms = EnumSet.copyOf(attrs.permissions());
        perms.retainAll(EnumSet.of(
                PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE,
                PosixFilePermission.GROUP_EXECUTE, PosixFilePermission.OTHERS_READ,
                PosixFilePermission.OTHERS_WRITE, PosixFilePermission.OTHERS_EXECUTE));
        if (!perms.isEmpty()) {
            // Fail closed rather than silently serving a world-readable hash store.
            throw new IllegalStateException("Credential store has unsafe permissions: " + file);
        }
    }
```

### SEC-09: Submitted passwords are materialised in immutable `String` objects, defeating zeroing
- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:195-209` (same pattern at `src/main/java/com/employee/portal/security/cli/EmployeePortalApp.java:290-291`)

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:195-209
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

**Why it is a problem:** The `char[]` discipline enforced elsewhere (`AuthenticationService.java:183-185`, `PortalHttpHandler.java:114-118`) exists so the plaintext password can be zeroed immediately. Here the password passes through at least three immutable `String`s before reaching that `char[]`: `raw` (the whole body), the `kv[1]` substring, and the `URLDecoder.decode` result. Strings cannot be wiped; they persist on the heap until garbage collection, which means a heap dump, core dump, or swap file taken minutes later can still yield cleartext passwords. The raw `body` byte array is likewise never cleared. `EmployeePortalApp.readPasswordSecurely` has the same flaw on its fallback path (`:290-291`: `fallbackReader.readLine()` returns a `String`), which is the path taken whenever the program runs without a TTY. The residual exposure is the same memory-scraping threat the README claims to have eliminated.

**Fix:** Decode form fields straight into a `char[]` without an intermediate `String`, and clear the raw body buffer when done.

```java
    private Map<String, char[]> parseFormData(byte[] body) {
        Map<String, char[]> map = new HashMap<>();
        try {
            int start = 0;
            while (start <= body.length) {
                int amp = indexOf(body, (byte) '&', start);
                int end = (amp < 0) ? body.length : amp;
                int eq = indexOf(body, (byte) '=', start, end);
                if (eq > start) {
                    String key = urlDecodeToString(body, start, eq);          // names are not secret
                    char[] value = urlDecodeToChars(body, eq + 1, end);       // never becomes a String
                    char[] previous = map.put(key, value);
                    if (previous != null) {
                        Arrays.fill(previous, '\0');
                    }
                }
                if (amp < 0) break;
                start = amp + 1;
            }
        } finally {
            Arrays.fill(body, (byte) 0); // drop the cleartext request buffer
        }
        return map;
    }
```

### SEC-10: Audit log re-created with default (world-readable) permissions if removed
- **Severity:** Low
- **CWE:** CWE-532: Insertion of Sensitive Information into Log File
- **Location:** `src/main/java/com/employee/portal/security/logging/AuditLogger.java:106-107`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/logging/AuditLogger.java:103-112
        if (logFilePath != null) {
            fileLock.lock();
            try {
                Files.writeString(logFilePath, entry, StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            } catch (IOException e) {
                System.err.println("[LOGGING_ERROR] Failed writing to secure audit log");
            } finally {
                fileLock.unlock();
            }
        }
```

**Why it is a problem:** `StandardOpenOption.CREATE` recreates the file if it has disappeared since construction time — after log rotation, a cleanup job, a `/tmp` reaper, or deliberate deletion by a local attacker. `Files.writeString` supplies no file attributes, so the new file gets the process umask, typically `rw-r--r--` (0644). The audit log records usernames, source IPs, account-state hints ("account suspended") and masked session prefixes; world-readable it becomes a reconnaissance aid listing valid employee usernames and their login patterns, and the 0600 guarantee the component advertises no longer holds for the rest of the process lifetime.

**Fix:** Open the log with explicit private permissions on creation, so a recreated file is private too.

```java
            try {
                // CREATE_NEW with explicit 0600 on the create path; plain APPEND otherwise,
                // so a recreated log can never inherit a permissive umask.
                if (!Files.exists(logFilePath)) {
                    ensureSecureLogFile();
                }
                try (OutputStream out = Files.newOutputStream(logFilePath,
                        StandardOpenOption.WRITE, StandardOpenOption.APPEND)) {
                    out.write(entry.getBytes(StandardCharsets.UTF_8));
                }
            } catch (IOException e) {
                System.err.println("[LOGGING_ERROR] Failed writing to secure audit log");
            } finally {
                fileLock.unlock();
            }
```

### SEC-11: No CSRF or Content-Type defence on `POST /api/login` and `POST /api/logout`
- **Severity:** Low
- **CWE:** CWE-352: Cross-Site Request Forgery
- **Location:** `src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:57-62` and `:145-154`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:57-62
            if ("/api/login".equals(path) && "POST".equals(method)) {
                handleLogin(exchange, clientIp);
            } else if ("/api/dashboard".equals(path) && "GET".equals(method)) {
                handleDashboard(exchange, clientIp);
            } else if ("/api/logout".equals(path) && "POST".equals(method)) {
                handleLogout(exchange);
            } else {
```

**Why it is a problem:** Both state-changing endpoints accept `application/x-www-form-urlencoded` bodies with no anti-CSRF token, no `Origin`/`Referer` validation and no `Content-Type` check — the handler never inspects the request's content type at all (`parseFormData` at `:195` just decodes whatever arrived). A simple cross-origin auto-submitting HTML form therefore reaches them. `SameSite=Strict` on the session cookie blunts the logout case in modern browsers but is not a substitute: the login endpoint needs no cookie to be driven cross-site, giving a *login CSRF* primitive (an attacker silently authenticates the victim's browser as an attacker-controlled employee account, so subsequent actions and data entry occur under that identity), and it also lets a third-party page burn a victim's rate-limit budget against a chosen account. Accepting an unchecked content type additionally forfeits the CORS preflight that a JSON-only API would get for free.

**Fix:** Require `Content-Type: application/x-www-form-urlencoded` (or JSON), validate `Origin` against an allow-list on every state-changing request, and issue/verify a double-submit CSRF token for the login form.

```java
    private static final Set<String> ALLOWED_ORIGINS = Set.of("https://portal.internal.example.com");

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        // ... security headers ...
        String method = exchange.getRequestMethod().toUpperCase();
        if (!"GET".equals(method) && !isTrustedOrigin(exchange)) {
            sendJsonResponse(exchange, 403, "{\"error\":\"Forbidden\"}");
            return;
        }
        // ... routing ...
    }

    private boolean isTrustedOrigin(HttpExchange exchange) {
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (contentType == null || !contentType.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
            return false;
        }
        String origin = exchange.getRequestHeaders().getFirst("Origin");
        // Fail closed: a state-changing request with no verifiable origin is rejected.
        return origin != null && ALLOWED_ORIGINS.contains(origin);
    }
```

### SEC-12: Sessions survive account suspension; authorisation state never re-checked
- **Severity:** Low
- **CWE:** CWE-613: Insufficient Session Expiration
- **Location:** `src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:129-141`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/web/PortalHttpHandler.java:129-141
        Optional<Session> maybeSession = authService.getSessionManager().validateSession(sessionToken, clientIp);
        if (maybeSession.isEmpty()) {
            sendJsonResponse(exchange, 401, "{\"error\":\"Unauthorized: Session expired or invalid\"}");
            return;
        }

        Session session = maybeSession.get();
        String json = String.format(
                "{\"status\":\"active\",\"username\":\"%s\",\"role\":\"%s\",\"sourceIp\":\"%s\"}",
                InputValidator.escapeHtml(session.getUsername()),
                InputValidator.escapeHtml(session.getRole()),
                InputValidator.escapeHtml(session.getSourceIp())
        );
```

**Why it is a problem:** Username and role are read from the `Session` snapshot taken at login and never re-derived from the repository. `SessionManager.revokeAllForUser` exists (`SessionManager.java:132-148`) but no caller ever invokes it, and nothing in the repository save path revokes sessions. So when an employee is suspended (`UserStatus.SUSPENDED`), has their role reduced, or has their password reset, every session they already hold keeps working for up to the 8-hour absolute timeout — the login path's status check at `AuthenticationService.java:124` is the *only* place status is consulted. Offboarding and incident response ("lock this account now") therefore do not take effect, which is the classic insufficient-session-expiration gap.

**Fix:** Re-validate the account against server-side state on every authenticated request, and revoke all of a user's sessions whenever their record changes.

```java
        Session session = maybeSession.get();
        // Re-derive authorisation from server-side state: a suspended, deleted or
        // re-roled account must lose access immediately, not at session expiry.
        Optional<EmployeeRecord> current = authService.getRepository().findByUsername(session.getUsername());
        if (current.isEmpty() || !current.get().isActive()
                || !current.get().getRole().equals(session.getRole())) {
            authService.getSessionManager().revokeAllForUser(session.getUsername());
            sendJsonResponse(exchange, 401, "{\"error\":\"Unauthorized: Session expired or invalid\"}");
            return;
        }
```

### SEC-13: Password policy is length-only; no complexity or breached-password screening
- **Severity:** Low
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `src/main/java/com/employee/portal/security/validation/InputValidator.java:51-57`

**Vulnerable code:**
```java
// src/main/java/com/employee/portal/security/validation/InputValidator.java:51-57
    public static boolean isValidPassword(char[] password) {
        if (password == null) {
            return false;
        }
        return password.length >= SecurityConfig.MIN_PASSWORD_LENGTH &&
               password.length <= SecurityConfig.MAX_PASSWORD_LENGTH;
    }
```

**Why it is a problem:** This is the only gate on enrolment (`AuthenticationService.enrollEmployee` at `:198`), so `password`, `12345678`, `employee`, or the user's own username are all accepted. The strong KDF raises the cost per guess but does not help against the handful of passwords an attacker tries first, and with the lockout bypasses above (SEC-01, SEC-02, SEC-06) an online guessing attack becomes realistic. NIST SP 800-63B — which the file's own comments cite for the KDF parameters — requires screening candidate passwords against a blocklist of common, breached and context-specific values.

**Fix:** Keep the length bounds (the upper bound is a sound DoS control) and add blocklist screening plus a context check against the username.

```java
    /** Length bounds plus NIST SP 800-63B style blocklist screening. */
    public static boolean isValidPassword(char[] password, String username) {
        if (password == null) {
            return false;
        }
        if (password.length < SecurityConfig.MIN_PASSWORD_LENGTH
                || password.length > SecurityConfig.MAX_PASSWORD_LENGTH) {
            return false;
        }
        // Compared in place; no String copy of the secret is retained.
        if (username != null && containsIgnoreCase(password, username)) {
            return false;
        }
        return !CommonPasswordBlocklist.contains(password);
    }
```

## 6. Verified Controls and Checks With No Finding

- **Password hashing algorithm and parameters:** PBKDF2WithHmacSHA512 with 210,000 iterations, a 32-byte salt and a 32-byte derived key (`config/SecurityConfig.java:25-28`, `crypto/PasswordHasher.java:89-93`). Meets current OWASP guidance; no MD5/SHA-1/unsalted hashing anywhere. Iterations are clamped to 100,000–2,000,000 (`config/SecurityConfig.java:67`) and re-validated on load (`model/EmployeeRecord.java:40-42`), so a tampered database cannot downgrade the KDF to 1 iteration.
- **Per-record salting:** A fresh CSPRNG salt is generated per enrolment (`crypto/PasswordHasher.java:67-71`, `service/AuthenticationService.java:206`); no shared or static salt.
- **Random number generation:** `SecureRandom.getInstanceStrong()` with a `SecureRandom` fallback for both tokens and salts (`crypto/SecureTokenGenerator.java:26-29`, `crypto/PasswordHasher.java:37-41`). No `java.util.Random`, no time-based seeding.
- **Session token entropy and origin:** 256-bit tokens, URL-safe Base64 without padding, generated server-side only; never accepted or derived from caller input (`crypto/SecureTokenGenerator.java:38-42`, `session/SessionManager.java:56`).
- **Constant-time secret comparison:** `MessageDigest.isEqual` for hash comparison (`crypto/PasswordHasher.java:111`), and `Arrays.equals` is used only on the two locally entered passwords during enrolment confirmation (`cli/EmployeePortalApp.java:180`), where no secret is being compared against stored state.
- **Timing-neutral failure paths:** A full dummy PBKDF2 computation runs on invalid input, rate-limited, unknown-user and suspended-account paths (`service/AuthenticationService.java:83,99,112,126`), with a pre-computed dummy salt and hash (`crypto/PasswordHasher.java:48-61`). Residual difference: `dummyVerify` always uses `defaultIterations` while the real path uses the per-record count (`crypto/PasswordHasher.java:130` vs `:110`), so a measurable gap would appear only if records were ever stored with a non-default iteration count — not the case in this code.
- **Uniform failure responses:** One shared `GENERIC_FAILURE_MESSAGE` for every authentication failure mode, with no account-existence or lockout detail (`model/AuthenticationResult.java:13-14,32-34`), and HTTP 401 with the same body for all of them (`web/PortalHttpHandler.java:104-111`). Note the separate 400 for a structurally absent username/password field (`web/PortalHttpHandler.java:83-86`) — this reveals nothing about accounts, but it also bypasses rate-limit accounting, so malformed requests are not metered.
- **Allow-list input validation:** Username `^[a-zA-Z0-9._-]{3,32}$` with an extra `..` rejection, password length bounds, strict IPv4/IPv6 patterns with a 45-character cap, and session tokens restricted to `^[a-zA-Z0-9_-]{43,64}$` (`validation/InputValidator.java:14-22,32-84`). Applied at every boundary including re-validation of data read back from the database (`repository/FileEmployeeRepository.java:112`, `model/EmployeeRecord.java:28-51`).
- **No injection sinks:** No SQL/JPA/ORM, no `Runtime.exec`/`ProcessBuilder`, no deserialization (`ObjectInputStream`), no XML/YAML parsing, no reflection on untrusted names, and no template engine anywhere in `src/main`. CWE-89, CWE-78, CWE-502 and CWE-611 are structurally inapplicable rather than merely unobserved.
- **Path traversal:** Usernames never reach the filesystem — records live in a single flat file keyed in memory (`repository/FileEmployeeRepository.java:123,143`) — and the data directory is canonicalised with control characters rejected (`config/SecurityConfig.java:174-185`), with `normalize()` applied to both derived file paths (`config/SecurityConfig.java:135,139`).
- **Log injection (CWE-117):** Every logged field passes through `sanitizeForLog`, which replaces CR/LF and other control characters and truncates to 80 characters (`validation/InputValidator.java:90-106`, applied at `logging/AuditLogger.java:92-94`). Audit entries cannot be forged or unbounded.
- **Secret handling in logs and `toString`:** Passwords are never logged; session tokens are masked to first-4/last-4 (`logging/AuditLogger.java:119-123`) and `Session.toString` masks the identifier (`model/Session.java:76`); `EmployeeRecord.toString` deliberately omits salt and hash (`model/EmployeeRecord.java:104-107`). The caught-exception path logs only the exception class name, never a message or stack trace (`service/AuthenticationService.java:179`). The only violation of this otherwise consistent policy is SEC-04.
- **No working hardcoded credentials or keys:** No default accounts, API keys or secret keys exist. The two literal strings in `PasswordHasher` (`:50`, `:127`) are dummy inputs for timing-equalisation work whose output is discarded — they authenticate nothing and are not stored; passwords are never passed as command-line arguments, and enrolment reads them via `Console.readPassword` when a TTY is present (`cli/EmployeePortalApp.java:284-286`).
- **Memory hygiene for credentials:** Passwords are handled as `char[]` and zeroed in `finally` blocks on every path (`service/AuthenticationService.java:181-186,226-231`, `web/PortalHttpHandler.java:112-119`, `cli/EmployeePortalApp.java:136-139,197-202`), and `PBEKeySpec.clearPassword()` plus zeroing of computed hashes is performed in `PasswordHasher` (`:96-98,114-118`). The residual `String` exposure is SEC-09.
- **Rate limiting covers both axes and cannot be header-spoofed:** Failures are recorded per source, per account and per source+account pair, with distinct thresholds (5 source / 10 account) so an attacker's own IP is cut off before the victim's account locks (`ratelimit/RateLimiter.java:137-160`). The HTTP handler derives the client IP from the TCP socket and ignores `X-Forwarded-For`, `X-Real-IP` and friends entirely (`web/PortalHttpHandler.java:156-162`) — the primary bypass the rate-limit-bypass skill tests for. Path, method and letter-case variations are also covered: routing uses exact path/method equality (`web/PortalHttpHandler.java:52-62`) and usernames are normalised to lower case before keying (`service/AuthenticationService.java:94`). The residual bypasses are SEC-01, SEC-02 and SEC-06.
- **Lockout window and reset semantics:** Failure windows expire, lockouts clear correctly after their duration, and a successful login resets all three counters atomically (`ratelimit/RateLimiter.java:45-66,165-184`), so a legitimate user is not permanently penalised.
- **Session lifecycle:** Idle (15 min) and absolute (8 h) timeouts are both enforced server-side (`model/Session.java:66-71`, `session/SessionManager.java:101-104`), expired sessions are removed on access, logout revokes server-side (`web/PortalHttpHandler.java:145-153`) rather than merely clearing the cookie, and per-user concurrent sessions are capped with oldest-first eviction under a lock (`session/SessionManager.java:60-81`). All validation is against server-side state; a missing or unknown token returns empty (`session/SessionManager.java:91-98`).
- **Cookie attributes:** `HttpOnly`, `SameSite=Strict`, `Path=/` and an explicit `Max-Age` are always set, with `Secure` and the `__Host-` prefix applied in secure mode, and logout sends `Max-Age=0` (`crypto/SecureTokenGenerator.java:53-82`). The gaps are that secure mode is never switched on (SEC-03) and the prefix is undermined on the read path (SEC-07).
- **HTTP response hardening:** `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `Cache-Control: no-store, …, private`, `Pragma: no-cache` and an explicit JSON content type are set on every response, including errors (`web/PortalHttpHandler.java:45-50`). Only HSTS is missing, covered by SEC-03.
- **Output encoding / XSS:** Responses are `application/json` with `nosniff`, and all interpolated values are escaped (`validation/InputValidator.java:111-134`, applied at `web/PortalHttpHandler.java:99-101,138-140`). The interpolated values are additionally constrained by the username/role/IP allow-lists, so neither JSON nor HTML breakout is reachable; the quote-escaping also prevents JSON structure injection.
- **Request size bounding:** Request bodies are capped at 4096 bytes with the connection abandoned past the limit (`web/PortalHttpHandler.java:180-193`), the password length cap bounds PBKDF2 work (`validation/InputValidator.java:55-56`), and both the session store and rate-limiter store are capacity-bounded (`session/SessionManager.java:37`, `ratelimit/RateLimiter.java:81`). Memory-exhaustion DoS is addressed — though the rate-limiter bound is what SEC-01 abuses.
- **Concurrency primitives:** `BoundedLruCache` guards every operation including `compute` with a `ReentrantLock` (`ratelimit/BoundedLruCache.java:34-105`), `AttemptRecord` mutators and accessors are `synchronized` (`ratelimit/RateLimiter.java:33-66`), the repository uses a `ReentrantReadWriteLock` (`repository/FileEmployeeRepository.java:141-182`), the audit log append is lock-guarded (`logging/AuditLogger.java:104-112`), and session enumeration/eviction runs under a dedicated lock (`session/SessionManager.java:60-81`). Only the service-level composite sequence is unsafe (SEC-06).
- **Fail-closed error handling:** Unexpected exceptions in `authenticate` return the generic failure (`service/AuthenticationService.java:174-180`); malformed or corrupted database lines are skipped rather than partially trusted (`repository/FileEmployeeRepository.java:100-126`); an unreadable database leaves an empty cache so every login fails (`repository/FileEmployeeRepository.java:128-130`); unknown routes return 404 and unhandled exceptions a bodyless generic 500 (`web/PortalHttpHandler.java:63-68`). No permissive defaults were found on any security path except the two fail-open cases reported as SEC-05 and SEC-07.
- **Configuration intake:** All numeric settings are parsed defensively and clamped to safe minimum/maximum ranges, with unparseable values falling back to safe defaults rather than to permissive ones (`config/SecurityConfig.java:59-67,150-172`). Environment and system-property input cannot weaken iteration counts, timeouts or thresholds.
- **Atomic persistence:** Records are written to a 0600 temp file in the same directory and moved into place with `ATOMIC_MOVE` + `REPLACE_EXISTING`, with temp-file cleanup on failure (`repository/FileEmployeeRepository.java:193-233`); a crash cannot leave a truncated credential store.
- **Platform primitives preferred over hand-rolled code:** JCA `SecretKeyFactory`/`PBEKeySpec` for the KDF, `SecureRandom` for randomness, `MessageDigest.isEqual` for comparison, `java.util.HexFormat` for encoding, `java.util.Base64` for tokens, and the JDK's own HTTP server — no custom cryptography anywhere.
- **Dependency and build hygiene:** No third-party runtime dependencies; the only dependency is JUnit 5.10.2 at `test` scope, and all Maven plugins are version-pinned to specific releases from Maven Central (`pom.xml:24-28,33-57`). No remote code is downloaded or executed at runtime, and nothing is loaded from a shared or world-writable location.
