# Security Review: Secure Employee Portal Authentication (`secure-employee-auth` 1.0.0)

## 1. Executive Summary

This is a Java 17 / Maven authentication component (`com.employee.portal.security`) that provides PBKDF2 password hashing, a flat-file employee store, a dual-axis rate limiter, server-side session management, input validation, an audit logger, a console CLI, and a small `com.sun.net.httpserver` HTTP API.

The **crypto and credential-handling core is genuinely well built**: PBKDF2-HMAC-SHA512 at 210,000 iterations with per-record 32-byte salts and 32-byte keys, constant-time comparison, dummy-hash work on every early-return path to defeat timing oracles, `char[]` passwords wiped via `PBEKeySpec.clearPassword()`, whitelist (not blacklist) validation regexes, POSIX `0600`/`0700` file permissions, and atomic file replacement. Most of the obvious mistakes are absent, and 18 main source files show consistent security intent.

**The problems are in the wiring and the trust boundaries, not the primitives.** The single most important finding is that the hardened cookie path is *dead code as shipped*: every launch path in the application passes `requireSecureCookies = false` (`EmployeePortalApp.java:49`, `:246`, `:270`), while `PortalServer` serves **plaintext HTTP bound to all interfaces** (`PortalServer.java:21`). The result is that employee passwords and 256-bit session tokens cross the network unencrypted and the session cookie carries no `Secure` flag and no `__Host-` prefix — so the session is trivially hijacked by anyone on the network path. `README.md` claims Rule 3/Rule 4 controls (including the `__Host-`/`Secure` cookie) as satisfied and reports "zero findings"; **that claim is not supported by the delivered code**, and the existing 913 lines of tests do not cover the CLI/default wiring where the gap lives.

Below are 14 findings: 1 Critical, 2 High, 4 Medium, 7 Low. Two are availability/DoS-class and one is a data-integrity bug that can silently destroy the entire credential store.

**Immediate priorities:** (1) terminate TLS and default secure cookies to `true`, (2) match the session cookie name strictly, (3) require an authenticated administrator and a role allowlist before `enrollEmployee` writes an account.

## 2. Scope

Reviewed read-only at `/data/results/agy/set_a/post_research/5/security/`. Paths in this report are relative to `src/main/java/com/employee/portal/security/` unless written in full. Static review only — nothing was executed, built, installed, or imported.

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `cli/EmployeePortalApp.java` | CLI menu, object graph wiring, entry point | Constructs `AuthenticationService` and `PortalServer` with `requireSecureCookies = false`; prompts operator for a "client IP" used as the rate-limit identity and session-binding value; prompts for role at enrollment; `readPasswordSecurely` falls back to echoed stdin when no console |
| `web/PortalServer.java` | HTTP listener bootstrap | `HttpServer.create(new InetSocketAddress(port), 0)` — cleartext HTTP on all interfaces; fixed 8-thread pool; routes `/api/` |
| `web/PortalHttpHandler.java` | HTTP API (`/api/login`, `/api/dashboard`, `/api/logout`) | Sets `nosniff`, `X-Frame-Options: DENY`, CSP `default-src 'none'`, `no-store`; 4096-byte body cap; derives client IP from the socket (does not trust `X-Forwarded-For`); hand-built JSON via `String.format` + `escapeHtml`; cookie extraction accepts both cookie names |
| `service/AuthenticationService.java` | Login orchestration, enrollment | Rate-limit checks, dummy-hash timing parity, generic failure message, session creation, cookie header assembly; `enrollEmployee` has no authentication/authorization and accepts an arbitrary role |
| `crypto/PasswordHasher.java` | PBKDF2 hashing/verification | PBKDF2WithHmacSHA512, 32-byte salt, 256-bit key, `MessageDigest.isEqual`, dummy verify for timing parity, `clearPassword()`; `SecureRandom.getInstanceStrong()` in constructor |
| `crypto/SecureTokenGenerator.java` | Session token + cookie headers | 256-bit base64url tokens; `__Host-session`/`Secure` only when `requireSecure`; `HttpOnly`, `SameSite=Strict`, `Max-Age` always |
| `session/SessionManager.java` | In-memory session lifecycle | Bounded LRU store, idle + absolute timeouts, per-user session cap, session rotation, IP binding by string equality that is skipped when either side is null |
| `ratelimit/RateLimiter.java` | Dual-axis (source / account / pair) throttling and lockout | All three key axes share one bounded LRU; `compute`-based atomic increment |
| `ratelimit/BoundedLruCache.java` | Capacity-bounded concurrent map | `accessOrder` `LinkedHashMap` with `removeEldestEntry`; every operation lock-wrapped; `get()` mutates recency order |
| `repository/FileEmployeeRepository.java` | Flat-file credential store | `:`-separated hex records, per-record skip on corruption, read failure swallowed leaving an empty cache, whole-cache rewrite via `ATOMIC_MOVE` |
| `config/SecurityConfig.java` | Env/sysprop configuration with clamping | Iterations clamped to 100000–2000000, all numeric knobs clamped; `PORTAL_DATA_DIR` resolved with only a control-character scan |
| `validation/InputValidator.java` | Whitelist validation + sanitizers | Username/IPv4/IPv6/session-token regexes, `..` rejection, password length-only check, `sanitizeForLog` (80-char cap), `escapeHtml` |
| `logging/AuditLogger.java` | Security audit trail | Dir `0700` / file `0600`, token masking, sanitised fields; `details` emitted inside unescaped quotes; creation failure swallowed |
| `model/EmployeeRecord.java` | Immutable credential record | Length/range validation, defensive copies, `toString()` omits salt/hash; role validated by character shape only, not an allowlist |
| `model/AuthenticationResult.java` | Login outcome | Single `GENERIC_FAILURE_MESSAGE` — no user enumeration through messages |
| `model/Session.java` | Session record | `volatile lastAccessedAt`, masked `toString()` |
| `model/UserStatus.java`, `repository/EmployeeRepository.java` | Enum / repository interface | No security-relevant behaviour found |
| `pom.xml` | Build | Java 17; only dependency is JUnit Jupiter 5.10.2 (test scope) — no runtime third-party supply chain |
| `src/test/java/...` (7 files, 913 lines) | Unit tests | 39 tests, no `@Disabled`; covers hashing, repository, validator, rate limiter, sessions, handler — does not cover the CLI default wiring |

## 3. Skills Applied

The router skill `review-code-for-security-vulnerabilities` drove the workflow: first establish what each file actually does, then search the sibling skill library for skills matching the observed behaviour, then apply them. Keyword search over the 819-entry `/root/.qwen/skills` library confirmed the following matching skills, which were applied to this code:

- **`performing-cryptographic-audit-of-application`** — audited PBKDF2 algorithm choice, iteration count, salt length/uniqueness, derived-key length, PRNG seeding, and comparison constant-time properties.
- **`testing-api-authentication-weaknesses`** — evaluated token entropy, session fixation/rotation, idle and absolute timeouts, cookie attributes, timing side channels, and user-enumeration resistance.
- **`testing-for-broken-access-control`** — traced every state-changing operation (`enrollEmployee`, `/api/dashboard`, `/api/logout`) back to an authentication/authorization decision point.
- **`testing-for-sensitive-data-exposure`** — reviewed transport encryption, credential storage permissions, log masking, `toString()` leakage, and secret echo to console.
- **`configuring-tls-1-3-for-secure-communications`** and **`performing-ssl-tls-security-assessment`** — assessed the listener's transport security and what `Secure`/`__Host-` cookie semantics actually require.
- **`implementing-api-rate-limiting-and-throttling`** — evaluated the dual-axis limiter's key space, state-store lifetime, eviction behaviour, and bypass paths.
- **`performing-content-security-policy-bypass`** — reviewed the CSP/`X-Frame-Options`/`nosniff` header set and whether escaping is applied at the right output context.
- **`testing-for-xss-vulnerabilities`** — checked the encoder used for the JSON response context versus the HTML context `escapeHtml` targets.
- **`performing-csrf-attack-simulation`** — checked for anti-CSRF tokens on state-changing `POST` endpoints and the strength of `SameSite` as the sole control.
- **`testing-oauth2-implementation-flaws`** — searched for token/session leakage in URLs, logs, and error responses (no OAuth flow present; used for token-handling review).
- **`implementing-secret-scanning-with-gitleaks`** — swept all sources, `pom.xml`, and `README.md` for hardcoded credentials, keys, and default accounts (none found).
- **`performing-web-application-vulnerability-triage`** — used to confirm true/false positives and assign severity for the handler-level findings.

Reviewed against general OWASP Top 10 / CWE knowledge, because the skill library contains no skill covering these behaviours in this codebase: **log injection and audit-integrity field forging** (CWE-117, `AuditLogger.java:96`), **external control of a filesystem path** for the credential store (CWE-73, `SecurityConfig.java:174-185`), **fail-open persistence integrity** where a swallowed `IOException` combines with a whole-cache atomic rewrite (CWE-390/CWE-254, `FileEmployeeRepository.java:128` + `:223`), and **uncontrolled resource consumption through access-order cache eviction** (CWE-770/CWE-400, `RateLimiter.java:81`).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Secure cookies disabled on every launch path over a cleartext HTTP server bound to all interfaces | Critical | CWE-319 | `cli/EmployeePortalApp.java:49` |
| SEC-02 | Session cookie accepted under either name, defeating the `__Host-` prefix | High | CWE-565 | `web/PortalHttpHandler.java:173` |
| SEC-03 | Unauthenticated account enrollment with caller-supplied role enables privilege assignment | High | CWE-862 | `service/AuthenticationService.java:193` |
| SEC-04 | Lockout and rate-limit state lives in one shared bounded LRU and can be evicted by an attacker | Medium | CWE-770 | `ratelimit/RateLimiter.java:81` |
| SEC-05 | Client identity is operator-supplied text; session IP binding is optional and string-compared | Medium | CWE-290 | `cli/EmployeePortalApp.java:117` |
| SEC-06 | Swallowed read failure leaves an empty cache that the next save writes over the credential store | Medium | CWE-390 | `repository/FileEmployeeRepository.java:128` |
| SEC-07 | `PORTAL_DATA_DIR` controls where the credential store and audit log are written | Medium | CWE-73 | `config/SecurityConfig.java:184` |
| SEC-08 | Audit record fields can be forged because `details` is quoted without escaping | Low | CWE-117 | `logging/AuditLogger.java:96` |
| SEC-09 | JSON responses are escaped with an HTML encoder, the wrong encoder for the context | Low | CWE-116 | `web/PortalHttpHandler.java:97` |
| SEC-10 | `SecureRandom.getInstanceStrong()` in constructors can block indefinitely on a starved entropy pool | Low | CWE-400 | `crypto/SecureTokenGenerator.java:26` |
| SEC-11 | Fixed thread pool with no request/read timeouts allows cheap connection-exhaustion DoS | Low | CWE-400 | `web/PortalServer.java:22` |
| SEC-12 | Password is echoed to the terminal when no console is available | Low | CWE-522 | `cli/EmployeePortalApp.java:288` |
| SEC-13 | Password policy enforces length only, with no complexity or compromise screening | Low | CWE-521 | `validation/InputValidator.java:55` |
| SEC-14 | No anti-CSRF token on state-changing `POST /api/login` and `/api/logout` | Low | CWE-352 | `web/PortalHttpHandler.java:145` |

## 5. Detailed Findings

### SEC-01: Secure cookies disabled on every launch path over a cleartext HTTP server bound to all interfaces

- **Severity:** Critical
- **CWE:** CWE-319: Cleartext Transmission of Sensitive Information
- **Location:** `cli/EmployeePortalApp.java:49`

**Vulnerable code:**

```java
// cli/EmployeePortalApp.java:48-49
        this.authService = new AuthenticationService(
                config, repository, passwordHasher, rateLimiter, sessionManager, auditLogger, false);
```

```java
// cli/EmployeePortalApp.java:246
            PortalServer server = new PortalServer(port, authService, false);
```

```java
// cli/EmployeePortalApp.java:270
            PortalServer server = new PortalServer(port, authService, false);
```

```java
// web/PortalServer.java:20-26
    public PortalServer(int port, AuthenticationService authService, boolean requireSecureCookies) throws IOException {
        this.server = HttpServer.create(new InetSocketAddress(port), 0);
        this.executor = Executors.newFixedThreadPool(8);
        this.server.setExecutor(executor);

        PortalHttpHandler handler = new PortalHttpHandler(authService, requireSecureCookies);
        this.server.createContext("/api/", handler);
```

```java
// crypto/SecureTokenGenerator.java:53-59
    public static String buildSessionCookieHeader(String token, long maxAgeSeconds, boolean requireSecure) {
        String cookieName = requireSecure ? "__Host-session" : "portal_session";
        StringBuilder sb = new StringBuilder();
        sb.append(cookieName).append("=").append(token).append("; ");
        sb.append("Path=/; ");
        if (requireSecure) {
            sb.append("Secure; ");
```

**Why it is a problem:**

The `requireSecure` branch — the one that emits `__Host-session` and the `Secure` attribute — is unreachable in the shipped application. `EmployeePortalApp`'s constructor hardcodes `false` at line 49, and both server launch paths hardcode `false` at lines 246 and 270. So every user of this program gets the insecure branch.

What that combination means concretely:

1. `HttpServer.create(new InetSocketAddress(port), 0)` binds to the **wildcard address** (all interfaces) and `HttpServer` is **plain HTTP** — there is no `HttpsServer`, no `SSLContext`, no `HttpsConfigurator` anywhere in the project. Anyone on the network path (ARP-spoofable LAN, rogue Wi-Fi, compromised router, passive tap, or an `sslstrip`-style downgrade) reads the `POST /api/login` body containing the employee's **plaintext password**, and reads the `Set-Cookie` response containing a **256-bit session token**.
2. Because the emitted cookie is `portal_session` with **no `Secure` attribute**, the browser will re-send the stolen-in-transit session token over cleartext HTTP forever, so a single passive sniff yields a persistent hijack rather than a one-time credential capture.
3. Because the cookie is not `__Host-`-prefixed and not `Secure`, it is scope-shared: any subdomain, or any attacker who gets a script onto any origin that can set a cookie for this host, can fix or overwrite the session cookie.

The `README.md` asserts Rule 4 (`__Host-`-prefixed, `Secure`-flagged cookies with IP binding) as implemented and reports "zero findings." As delivered, that assertion is false. The `__Host-` prefix machinery exists but no code path turns it on, and there is no configuration knob to enable it — the flag is a hardcoded literal at three call sites, so an operator cannot opt in without recompiling. This is a transport-layer defect: no amount of hashing strength downstream compensates, because the password is captured before it ever reaches `PasswordHasher`.

Severity is Critical because the attacker needs only a network position — no authentication, no user interaction, and no local access — and the payoff is both plaintext credentials and an immediately usable session.

**Fix:**

Make TLS the only supported transport and make secure cookies the default that must be explicitly overridden, so the hardened path is the one that actually runs:

```java
// web/PortalServer.java — require TLS and bind explicitly
    public PortalServer(int port, SSLContext sslContext, String bindHost,
                        AuthenticationService authService, boolean requireSecureCookies) throws IOException {
        if (sslContext == null) {
            throw new IOException("TLS is required: refuse to start without an SSLContext");
        }
        this.server = HttpsServer.create(new InetSocketAddress(bindHost, port), 0);
        ((HttpsServer) this.server).setHttpsConfigurator(new HttpsConfigurator(sslContext));
        this.executor = Executors.newFixedThreadPool(8);
        this.server.setExecutor(executor);

        PortalHttpHandler handler = new PortalHttpHandler(authService, requireSecureCookies);
        this.server.createContext("/api/", handler);
    }
```

```java
// cli/EmployeePortalApp.java:48-49 — default to secure; insecure only by explicit, loud opt-out
        boolean requireSecureCookies =
                !SecurityProperties.isTruthy(System.getenv("PORTAL_ALLOW_INSECURE_COOKIES"));
        if (!requireSecureCookies) {
            System.err.println("[!] INSECURE COOKIES ENABLED - credentials and session tokens are sent in cleartext.");
        }
        this.authService = new AuthenticationService(
                config, repository, passwordHasher, rateLimiter, sessionManager, auditLogger,
                requireSecureCookies);
```

and change both launch sites to pass `requireSecureCookies` instead of the literal `false`:

```java
// cli/EmployeePortalApp.java:246 and :270
            PortalServer server = new PortalServer(port, sslContext, "127.0.0.1",
                    authService, requireSecureCookies);
```

If a cleartext local-CLI-only demo mode must remain, gate it behind the same explicit opt-out flag, bind it to `127.0.0.1` rather than the wildcard, and stop claiming Rule 4 compliance in `README.md` when the flag is set.

### SEC-02: Session cookie accepted under either name, defeating the `__Host-` prefix

- **Severity:** High
- **CWE:** CWE-565: Reliance on Cookies without Validation and Integrity Checking in Security Decisions
- **Location:** `web/PortalHttpHandler.java:173`

**Vulnerable code:**

```java
// web/PortalHttpHandler.java:164-178
    private String extractSessionCookie(HttpExchange exchange) {
        String cookieHeader = exchange.getRequestHeaders().getFirst("Cookie");
        if (cookieHeader == null || cookieHeader.isBlank()) {
            return null;
        }
        String cookieName = requireSecureCookies ? "__Host-session" : "portal_session";
        String[] cookies = cookieHeader.split(";");
        for (String c : cookies) {
            String[] parts = c.trim().split("=", 2);
            if (parts.length == 2 && (parts[0].equals(cookieName) || parts[0].equals("__Host-session") || parts[0].equals("portal_session"))) {
                return parts[1].trim();
            }
        }
        return null;
    }
```

**Why it is a problem:**

Line 169 computes the one cookie name appropriate for the current mode, then line 173 throws that decision away by accepting `__Host-session` **or** `portal_session` regardless of mode. The `cookieName` variable is effectively dead.

The `__Host-` prefix is not decoration — RFC 6265bis gives it three enforcement properties (secure-context only, no `Domain` attribute so it is host-only, path `/`), and the security value comes entirely from the server *refusing anything else*. Once the server accepts `portal_session` as an equal alternative, all three properties collapse:

- **Cookie-tossing downgrade.** A `Secure` cookie cannot be set by a non-secure context, but a `portal_session` cookie **can** be set by any `http://` interaction with the host (and, absent host-only scoping, by a subdomain). An attacker who plants `portal_session=<token>` and then gets the victim to hit the plaintext origin has the server accept the attacker-influenced name, even after the deployment later enables `requireSecureCookies`.
- **Ambiguous precedence.** Because the loop returns the *first* match in header order, and the attacker controls the order and content of `portal_session` while the `__Host-session` cookie is attacker-unsettable, the attacker can win which of two identities the server acts on when both are present.
- **Fixation persists across the hardening switch.** Turning secure cookies on does not retire the old name, so any pre-switch fixation or injection still resolves.

The result is that the mode flag changes only how cookies are *written*, never how they are *read* — so the read path is always the weaker of the two, and SEC-01's weakness cannot be closed merely by flipping the flag.

**Fix:**

Accept exactly the name the current mode issues, and treat any other cookie as unrelated:

```java
// web/PortalHttpHandler.java
        String cookieName = requireSecureCookies ? "__Host-session" : "portal_session";
        String found = null;
        for (String c : cookieHeader.split(";")) {
            String[] parts = c.trim().split("=", 2);
            if (parts.length == 2 && parts[0].equals(cookieName)) {
                if (found != null) {
                    return null; // duplicate session cookie: ambiguous, reject
                }
                found = parts[1].trim();
            }
        }
        return found;
```

Additionally, validate the extracted value against `InputValidator.SESSION_TOKEN_PATTERN` before it reaches `SessionManager`, and — for the secure mode — verify on the server side that the request arrived over TLS so a plaintext request can never satisfy a `__Host-`-named cookie.

### SEC-03: Unauthenticated account enrollment with caller-supplied role enables privilege assignment

- **Severity:** High
- **CWE:** CWE-862: Missing Authorization
- **Location:** `service/AuthenticationService.java:193`

**Vulnerable code:**

```java
// service/AuthenticationService.java:193-216
    public boolean enrollEmployee(String username, char[] password, String role) {
        try {
            if (!InputValidator.isValidUsername(username)) {
                return false;
            }
            if (!InputValidator.isValidPassword(password)) {
                return false;
            }
            String normalizedUser = username.trim().toLowerCase();
            if (repository.exists(normalizedUser)) {
                return false;
            }

            byte[] salt = passwordHasher.generateSalt();
            byte[] hash = passwordHasher.hashPassword(password, salt);

            EmployeeRecord record = new EmployeeRecord(
                    username.trim(),
                    salt,
                    hash,
                    passwordHasher.getDefaultIterations(),
                    UserStatus.ACTIVE,
                    (role == null || role.isBlank()) ? "EMPLOYEE" : role.trim().toUpperCase()
            );
```

```java
// cli/EmployeePortalApp.java:185-191
                    System.out.print("Enter role [EMPLOYEE / ADMIN]: ");
                    String role = reader.readLine();
                    if (role == null || role.isBlank()) {
                        role = "EMPLOYEE";
                    }

                    boolean enrolled = authService.enrollEmployee(username, password, role);
```

```java
// model/EmployeeRecord.java:48-51
        String cleanedRole = (role == null || role.isBlank()) ? "EMPLOYEE" : role.trim().toUpperCase();
        if (!cleanedRole.matches("^[A-Z0-9_-]{1,32}$")) {
            throw new IllegalArgumentException("Invalid role format");
        }
```

**Why it is a problem:**

`enrollEmployee` is a privilege-assigning write: it creates an `ACTIVE` credential record and stores an arbitrary role string. It performs *only* input-shape validation and a duplicate-name check. There is no authentication check, no authorization check, no caller identity, and no confirmation step anywhere in the method or its call site — contrast `authenticate`, which enforces rate limits, does dummy-hash parity work, and audits.

The role is never checked against an allowlist. `EmployeeRecord.java:49` validates the role's **character shape** (`^[A-Z0-9_-]{1,32}$`) and nothing about its **meaning**, so `ADMIN`, `SUPERADMIN`, `OWNER`, or any other token is accepted verbatim. The CLI prompt at line 185 literally advertises `ADMIN` as a valid answer. Anyone able to reach the enrollment path therefore self-assigns any privilege level they choose, and the new account is immediately usable for login. Because enrollment is the *bootstrap* operation, this also means the very first account created is attacker-chosen if the attacker is first.

Two secondary weaknesses in the same block: the audit entry for enrollment records a hardcoded `"127.0.0.1"` source, so a mass-enrollment event leaves no attributable origin; and the method returns a bare `boolean`, so the caller cannot distinguish "duplicate" from "rejected" and cannot log a meaningful failure.

This is High rather than Critical because exploiting it requires reaching the enrollment surface (the CLI, or a future caller that exposes it), rather than being reachable anonymously over the network today. Any HTTP exposure of enrollment would make it Critical.

**Fix:**

Require an authenticated administrative principal, resolve the role against a fixed allowlist, and audit the real caller:

```java
// service/AuthenticationService.java
    public static final Set<String> ASSIGNABLE_ROLES = Set.of("EMPLOYEE", "ADMIN");

    public boolean enrollEmployee(String username, char[] password, String role, Session caller) {
        String normalizedRole = (role == null || role.isBlank()) ? "EMPLOYEE" : role.trim().toUpperCase();

        if (caller == null || !"ADMIN".equals(caller.getRole())) {
            auditLogger.logEvent(AuditLogger.EventType.SUSPICIOUS_ACTIVITY,
                    "unknown-source", "unauthenticated", "Enrollment denied: caller lacks ADMIN role");
            return false;
        }
        if (!ASSIGNABLE_ROLES.contains(normalizedRole)) {
            auditLogger.logEvent(AuditLogger.EventType.VALIDATION_ERROR,
                    caller.getSourceIp(), caller.getUsername(), "Enrollment rejected: unknown role");
            return false;
        }
        // ... existing validation, then:
        EmployeeRecord record = new EmployeeRecord(
                username.trim(), salt, hash, passwordHasher.getDefaultIterations(),
                UserStatus.ACTIVE, normalizedRole);
```

Apply the same allowlist in `EmployeeRecord` (`Set` membership rather than a character-class regex) so the model cannot be bypassed by any future caller, and record the real source IP instead of `127.0.0.1`.

### SEC-04: Lockout and rate-limit state lives in one shared bounded LRU and can be evicted by an attacker

- **Severity:** Medium
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `ratelimit/RateLimiter.java:81`

**Vulnerable code:**

```java
// ratelimit/RateLimiter.java:80-84
    public RateLimiter(SecurityConfig config, LongSupplier clock) {
        this.cache = new BoundedLruCache<>(SecurityConfig.MAX_RATE_LIMITER_ENTRIES);
        this.maxFailedPerSource = config.getMaxFailedPerSource();
        this.maxFailedPerAccount = config.getMaxFailedPerAccount();
        this.failureWindowMillis = config.getFailureWindowMillis();
```

```java
// config/SecurityConfig.java:39
    public static final int MAX_RATE_LIMITER_ENTRIES = 10000;
```

```java
// ratelimit/BoundedLruCache.java:20-32
    public BoundedLruCache(int maxCapacity) {
        if (maxCapacity <= 0) {
            throw new IllegalArgumentException("maxCapacity must be > 0");
        }
        this.maxCapacity = maxCapacity;
        this.lock = new ReentrantLock();
        this.map = new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
                return size() > BoundedLruCache.this.maxCapacity;
            }
        };
    }
```

**Why it is a problem:**

One cache holds all three limiter axes — the `SRC:`, `ACC:`, and `PAIR:` key families — and it is bounded to 10,000 entries with **`accessOrder = true`**, meaning it evicts the least-recently-*used* entry. Boundedness is the right instinct (an unbounded map keyed on attacker-chosen strings is a memory-exhaustion bug), but the eviction policy is attacker-steerable, which converts a memory guard into an auth-control bypass:

1. **Lockout erasure by key churn.** Source and account keys are attacker-chosen. Spraying failures across ~10,001 distinct usernames (or distinct source IPs from a botnet) pushes the map past capacity, and `removeEldestEntry` discards exactly the entries that have not been touched recently — which are precisely the *legitimate* users' accumulated failure counts and in-progress lockouts. A victim account under active lockout can be silently reset to zero attempts by evicting it, so `maxFailedPerAccount` and the lockout window stop being a guarantee. Because each key is independent, the attacker's own counters never need to survive.
2. **Read amplification accelerates it.** The map is access-ordered and `get()` mutates that order (`BoundedLruCache.java:34-42`), and `isRestricted` performs up to three separate `cache.get(...)` lookups per check. Ordinary read traffic therefore reshuffles recency and pushes genuine defenders' entries toward the eviction end even without deliberate spraying — eviction is driven partly by traffic volume, not only by attack.
3. **Cost asymmetry.** Forgetting a key is free for the attacker and costs the defender their lockout protection; maintaining 10,001 keys is trivially cheap compared with what an unthrottled credential-guessing budget buys.

This is a Medium rather than High because it *degrades* an existing layered control (per-source and per-account limits plus a pair axis still constrain a low-volume attacker) rather than bypassing authentication outright, and exploitation still requires the guesses themselves to succeed.

**Fix:**

Separate the identity namespaces and make lockout state non-evictable under load — evict expired records first, and fail closed (or offload to an eviction-free store) when capacity is genuinely exhausted:

```java
// ratelimit/BoundedLruCache.java — insert-order eviction of *expired* entries, never LRU of live counters
    public BoundedLruCache(int maxCapacity, LongFunction<Boolean> isExpired) {
        this.maxCapacity = maxCapacity;
        this.isExpired = isExpired;
        this.lock = new ReentrantLock();
        this.map = new LinkedHashMap<>(16, 0.75f, false); // no access-order reshuffling on read
    }

    /** Called with the lock held: reclaim expired entries, then oldest entries; true = must shed load. */
    private boolean evictIfNeeded() {
        if (map.size() <= maxCapacity) {
            return false;
        }
        Iterator<Map.Entry<K, V>> it = map.entrySet().iterator();
        while (it.hasNext() && map.size() > maxCapacity) {
            if (Boolean.TRUE.equals(isExpired.apply((Long) it.next().getKey()))) {
                it.remove();
            }
        }
        return map.size() > maxCapacity; // still full of live counters -> caller decides
    }
```

and in `RateLimiter`, use distinct caches per axis (or a key-partitioned cache with a per-axis quota) so spraying the account axis cannot evict the source axis, treat "cache full of live counters" as an explicit **throttle-everything** condition rather than silently dropping state, and raise or externalise the cap for lockout records so the number of simultaneously locked-out principals is not an attacker-chosen budget.

### SEC-05: Client identity is operator-supplied text; session IP binding is optional and string-compared

- **Severity:** Medium
- **CWE:** CWE-290: Authentication Bypass by Spoofing
- **Location:** `cli/EmployeePortalApp.java:117`

**Vulnerable code:**

```java
// cli/EmployeePortalApp.java:115-123
            try {
                System.out.print("Enter client IP [leave empty for 127.0.0.1]: ");
                String clientIp = reader.readLine();
                if (clientIp == null || clientIp.isBlank()) {
                    clientIp = "127.0.0.1";
                }

                System.out.println("Authenticating...");
                AuthenticationResult result = authService.authenticate(username, password, clientIp.trim());
```

```java
// cli/EmployeePortalApp.java:214-220
            System.out.print("Enter source IP [leave empty to skip IP check]: ");
            String sourceIp = reader.readLine();
            if (sourceIp != null && sourceIp.isBlank()) {
                sourceIp = null;
            }

            Optional<Session> maybeSession = sessionManager.validateSession(token.trim(), sourceIp != null ? sourceIp.trim() : null);
```

```java
// session/SessionManager.java:106-113
        // Validate client IP binding if source IP is available (prevents session hijacking)
        if (currentSourceIp != null && session.getSourceIp() != null) {
            if (!session.getSourceIp().equals(currentSourceIp)) {
                // Suspicious IP change for active session: invalidate
                sessionCache.remove(token);
                return Optional.empty();
            }
        }
```

**Why it is a problem:**

`sourceIp` is the security-relevant identity that the dual-axis rate limiter keys on (`SRC:`), that lockouts are recorded against, and that sessions bind to. Here it is free-form text typed by whoever is sitting at the terminal, and the design treats that as authoritative.

The concrete bypasses:

1. **Rate-limit and lockout evasion.** A caller rotating through distinct valid-looking IP strings on each attempt gets a fresh `SRC:` bucket every time, so `maxFailedPerSource` never accumulates. `InputValidator` accepts any well-formed IPv4/IPv6 literal, so the key space for spoofed "sources" is effectively the entire address space.
2. **Binding is opt-out by design.** `handleVerifySession` explicitly invites the operator to "leave empty to skip IP check", passing `null`. `SessionManager.java:107` then *skips* the comparison when **either** side is null. So the control that `README.md` advertises as session-hijack protection is disabled by default on this path, and a session stolen from a bound login validates fine with a blank IP.
3. **Binding is textual, not semantic.** `String.equals` on the address string means `1.2.3.4` and `001.002.003.004` (or differing IPv6 text forms of one address) do not match, while legitimately renumbered clients (DHCP, mobile, NAT-pool drift, any proxy or VPN egress pool) do get their sessions destroyed at line 110. The control simultaneously misfires against real users and does nothing against an adversary who simply types the bound address.

This is Medium: the CLI is a local operator tool today, and the HTTP handler does the right thing (deriving the IP from the socket, see §6). The risk is that this pattern — trusting a caller-supplied identity string and allowing it to be omitted — is the template a future proxy- or API-fronted deployment will follow, at which point the same null-skip makes the binding bypassable by any client behind a shared egress or by simply omitting the value.

**Fix:**

Bind validation to the presence of binding information (never to an operator's choice), compare parsed addresses, and label untrusted input as such rather than treating it as a source identity:

```java
// session/SessionManager.java — binding is mandatory when the session has one
        String boundIp = session.getSourceIp();
        if (boundIp != null) {
            if (currentSourceIp == null || !IpEquality.sameAddress(boundIp, currentSourceIp)) {
                sessionCache.remove(token);
                return Optional.empty();
            }
        }
```

```java
// cli/EmployeePortalApp.java:214-215 — no "skip" affordance
            System.out.print("Enter source IP (required for bound sessions): ");
```

where `IpEquality.sameAddress` normalises via `InetAddress`/`IpValidator` parsing (rejecting unparseable input) instead of string equality. For the login path, derive the identity from the transport socket as `PortalHttpHandler.extractClientIp` already does, and if a genuinely unattributable actor is unavoidable, key the limiter on a per-connection nonce rather than on spoofable text.

### SEC-06: Swallowed read failure leaves an empty cache that the next save writes over the credential store

- **Severity:** Medium
- **CWE:** CWE-390: Detection of Error Condition Without Action
- **Location:** `repository/FileEmployeeRepository.java:128`

**Vulnerable code:**

```java
// repository/FileEmployeeRepository.java:83-90
    private void loadRecords() {
        rwLock.writeLock().lock();
        try {
            cache.clear();
            if (!Files.exists(dbFile)) {
                return;
            }
            try (BufferedReader reader = Files.newBufferedReader(dbFile, StandardCharsets.UTF_8)) {
```

```java
// repository/FileEmployeeRepository.java:126-133
                    }
                }
            } catch (IOException e) {
                // If database read fails, fail closed
            }
        } finally {
            rwLock.writeLock().unlock();
        }
```

```java
// repository/FileEmployeeRepository.java:162-170
    @Override
    public boolean save(EmployeeRecord record) {
        Objects.requireNonNull(record, "record cannot be null");
        rwLock.writeLock().lock();
        try {
            cache.put(record.getUsername().toLowerCase(), record);
            return persistToDisk();
```

```java
// repository/FileEmployeeRepository.java:209-223
            try (BufferedWriter writer = Files.newBufferedWriter(tempFile, StandardCharsets.UTF_8)) {
                for (EmployeeRecord rec : cache.values()) {
                    String line = String.format("%s:%s:%s:%d:%s:%s%n",
                            rec.getUsername(),
                            hexFormat.formatHex(rec.getSalt()),
                            hexFormat.formatHex(rec.getPasswordHash()),
                            rec.getIterations(),
                            rec.getStatus().name(),
                            rec.getRole());
                    writer.write(line);
                }
            }

            // Atomic move replaces target file atomically
            Files.move(tempFile, dbFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
```

**Why it is a problem:**

The comment at line 129 says "fail closed", but the catch body is empty and the surrounding `finally` releases the write lock normally. Control flow shows the opposite: `loadRecords()` already executed `cache.clear()` at line 86, so if any `IOException` interrupts the read — a transient I/O error, a permission change, a file system going read-only, a disk full mid-read, a concurrent backup holding the file — the method returns **successfully with an empty cache**. The process now believes there are zero employees, with no flag, no exception, and no log entry recording that its identity store failed to load.

`save()` at line 163 then compounds it. It writes one record into that empty cache and calls `persistToDisk()`, which serialises **`cache.values()`** — the entire store, as currently believed — to a temp file and installs it with `ATOMIC_MOVE` + `REPLACE_EXISTING` at line 223. The result is that a single enrollment after a transient read error **replaces the whole credential database with a one-line file**. The move is atomic, so there is no partially-written file to recover from and no torn-write signature; the destruction is clean, silent, and irreversible.

Two aggravating factors:

- **Nothing surfaces it.** There is no read-error counter, no `loadedSuccessfully` flag, and no audit event, so the first signal is legitimate users reporting they can no longer log in — with a `0600` file that now contains one record.
- **The per-record skip at line 124 is a milder instance of the same shape.** Individual corrupted records are silently dropped from the cache, so any subsequent `save()` also silently deletes those employees' credentials from disk. Skipping a malformed *line* is defensible; letting that omission propagate into a whole-file rewrite is not.

This is availability/integrity rather than confidentiality — an attacker cannot read hashes through it, and reaching it needs an I/O fault or file tampering. It is Medium because the damage is total loss of the authentication database and it converts a recoverable transient error into unrecoverable data loss.

**Fix:**

Make load failure loud and sticky, and never persist from an unverified snapshot:

```java
// repository/FileEmployeeRepository.java
    private volatile boolean loaded = false;   // false until a full successful read

    private void loadRecords() throws IOException {
        rwLock.writeLock().lock();
        try {
            Map<String, EmployeeRecord> next = new HashMap<>(); // build aside; do not clear live cache first
            if (Files.exists(dbFile)) {
                try (BufferedReader reader = Files.newBufferedReader(dbFile, StandardCharsets.UTF_8)) {
                    // ... parse into next, counting skipped malformed records
                }
            }
            cache.clear();
            cache.putAll(next);
            loaded = true;
        } catch (IOException e) {
            loaded = false;                      // refuse to treat the store as "empty"
            throw e;                             // propagate: do not start serving an empty identity set
        } finally {
            rwLock.writeLock().unlock();
        }
    }

    private boolean persistToDisk() throws IOException {
        if (!loaded) {
            throw new IOException("Refusing to persist: credential store was not fully loaded");
        }
        // ... existing temp-file + ATOMIC_MOVE write
    }
```

Additionally, keep a dated `.bak` of the previous file before each `REPLACE_EXISTING` move, and log the count of skipped malformed records at load so partial loss is visible rather than silent.

### SEC-07: `PORTAL_DATA_DIR` controls where the credential store and audit log are written

- **Severity:** Medium
- **CWE:** CWE-73: External Control of File Name or Path
- **Location:** `config/SecurityConfig.java:184`

**Vulnerable code:**

```java
// config/SecurityConfig.java:68
            resolveSafeDataDir(System.getProperty("PORTAL_DATA_DIR", System.getenv().getOrDefault("PORTAL_DATA_DIR", DEFAULT_DATA_DIR)))
```

```java
// config/SecurityConfig.java:174-185
    private static Path resolveSafeDataDir(String rawPath) {
        if (rawPath == null || rawPath.isBlank()) {
            return Paths.get(DEFAULT_DATA_DIR).toAbsolutePath().normalize();
        }
        // Validate path does not contain suspicious control characters
        for (char c : rawPath.toCharArray()) {
            if (c < 32 || c == 127) {
                return Paths.get(DEFAULT_DATA_DIR).toAbsolutePath().normalize();
            }
        }
        return Paths.get(rawPath).toAbsolutePath().normalize();
    }
```

**Why it is a problem:**

The name `resolveSafeDataDir` and the comment "Validate path does not contain suspicious control characters" overstate what this function does. The loop rejects only bytes below `0x20` and `0x7F` — characters that essentially never appear in path-injection payloads. Everything that actually matters passes: `/`, `..`, and absolute paths. Line 184 then happily resolves the attacker- or operator-controlled string to any absolute path on the system, with no allowlist, no canonical containment check against a permitted root, and no check that the resolved location is not a symlink.

The consequences follow from what gets written there: this directory receives the **credential database** (username, salt, PBKDF2 hash, iterations, status, role) and the **audit log**. The application creates them with `0600`/`0700` permissions, which is good but does not constrain *location*. So a configuration-influencing principal — a compromised sidecar or CI job that can set environment variables, a shared-host `systemd` drop-in, or a `-DPORTAL_DATA_DIR` injected through a wrapper script — can redirect the credential store and audit trail to any path the process can write, for example a world-readable staging directory, a directory later served or archived, or a location where the `0600` file is then group-readable through a parent ACL. Redirecting the audit log is separately damaging: it makes the trail the deployment relies on for detection disappear from where defenders look, while the app keeps reporting successful audit writes.

There is also a write-anything failure mode: if the target path collides with an existing file the process can write, `persistToDisk()`'s `ATOMIC_MOVE` + `REPLACE_EXISTING` (see SEC-06) **destroys that file**. Note the clamping applied to every numeric knob here is careful and correct — the string path is simply the one input class that skipped the same treatment.

Severity is Medium because exploiting it requires the ability to influence the process's environment or system properties (i.e. it is not remotely reachable), but the impact — credential exposure plus audit-trail suppression or arbitrary file displacement — is disproportionate to how casually the input is accepted.

**Fix:**

Constrain the resolved path to a permitted root and reject anything that escapes it, applying the same rigour already used for the numeric bounds:

```java
// config/SecurityConfig.java
    private static final Path DATA_DIR_ROOT =
            Paths.get(System.getProperty("PORTAL_DATA_DIR_ROOT", "/var/lib/employee-portal"))
                 .toAbsolutePath().normalize();

    private static Path resolveSafeDataDir(String rawPath) {
        if (rawPath == null || rawPath.isBlank()) {
            return DATA_DIR_ROOT;
        }
        Path candidate = Paths.get(rawPath).toAbsolutePath().normalize();
        if (!candidate.startsWith(DATA_DIR_ROOT)) {
            System.err.println("[!] PORTAL_DATA_DIR outside permitted root, using default: " + candidate);
            return DATA_DIR_ROOT;
        }
        // Reject symlinked/ancestor swaps after the fact: verify real location matches the request
        try {
            return DATA_DIR_ROOT.relativize(candidate)
                    .toString()
                    .matches("[A-Za-z0-9._/-]*") ? candidate : DATA_DIR_ROOT;
        } catch (IllegalArgumentException e) {
            return DATA_DIR_ROOT;
        }
    }
```

For defence in depth, resolve with `toRealPath()` where the directory already exists so a symlink swap is caught, refuse to start if the resolved directory is not owned by the service user, and treat the audit-log path as a **separate, non-overridable** setting so an operator who legitimately relocates the data directory cannot also relocate the audit trail.

### SEC-08: Audit record fields can be forged because `details` is quoted without escaping

- **Severity:** Low
- **CWE:** CWE-117: Improper Output Neutralization for Logs
- **Location:** `logging/AuditLogger.java:96`

**Vulnerable code:**

```java
// logging/AuditLogger.java:90-97
    public void logEvent(EventType type, String sourceIp, String username, String details) {
        String timestamp = ISO_FORMATTER.format(Instant.now());
        String cleanSource = InputValidator.sanitizeForLog(sourceIp);
        String cleanUser = InputValidator.sanitizeForLog(username);
        String cleanDetails = InputValidator.sanitizeForLog(details);

        String entry = String.format("[%s] [SECURITY_AUDIT] event=%s source=%s user=%s details=\"%s\"%n",
                timestamp, type.name(), cleanSource, cleanUser, cleanDetails);
```

```java
// validation/InputValidator.java:90-104
    public static String sanitizeForLog(String input) {
        if (input == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(Math.min(input.length(), 80));
        for (int i = 0; i < input.length() && i < 80; i++) {
            char c = input.charAt(i);
            if (c == '\r' || c == '\n') {
                sb.append('_');
            } else if (c < 32 || c == 127) {
                sb.append('?');
            } else {
                sb.append(c);
            }
        }
```

**Why it is a problem:**

The CRLF half of log injection is handled correctly — `\r`/`\n` become `_` and other control bytes become `?`, so an attacker cannot inject a newline and forge a whole additional audit line. That part is a genuine control (credited in §6). What is missing is the **quote and delimiter** half, and it matters because the record is not plain text: it is a `key=value` structure whose final field is delimited by double quotes that the sanitizer never escapes (`InputValidator.java:101` passes `"` through untouched).

Given input containing `"`, an attacker closes the `details` field early and appends fabricated `key=value` pairs to the same line. Because `AuditLogger` uses space-separated parsing on the way out and most log shippers parse `key=value` positionally, trailing injected pairs are absorbed as new fields — so a single `LOGIN_FAILURE` event can be made to carry an invented `event=LOGIN_SUCCESS`-style attribute, a bogus `user=`, or a spoofed `source=`. The real event is still present; the forged attributes are appended to it, which is exactly what makes this insidious during an investigation: the record is not obviously corrupt, it is *plausible*.

The 80-character cap compounds this in the opposite direction. Truncation is silent, so on the paths where attacker-controlled text is logged the tail of the evidence disappears — and where the truncation happens determines what survives. Combined, the two properties let an attacker both add fields at will and, by padding the prefix, control which part of the string the audit trail retains. In the current code the most exposed input is the **raw `username`** on the validation-error path (`AuthenticationService.java:89`), which is logged precisely *because* it failed the whitelist regex — i.e. by definition it may contain characters that validated input never can.

Low severity: it does not bypass authentication or expose data, and exploiting it requires an input that already failed validation. Impact is on the integrity and completeness of the evidence that incident response depends on.

**Fix:**

Escape the field delimiters and make truncation explicit rather than silent:

```java
// validation/InputValidator.java
    public static String sanitizeForLog(String input) {
        if (input == null) {
            return "null";
        }
        int limit = Math.min(input.length(), 80);
        StringBuilder sb = new StringBuilder(limit + 8);
        for (int i = 0; i < limit; i++) {
            char c = input.charAt(i);
            if (c == '\r' || c == '\n') {
                sb.append('_');
            } else if (c < 32 || c == 127) {
                sb.append('?');
            } else if (c == '"' || c == '\\') {
                sb.append('\\').append(c);   // neutralise the field delimiter
            } else if (c == ' ') {
                sb.append("\\s");            // neutralise the key=value separator
            } else {
                sb.append(c);
            }
        }
        if (input.length() > limit) {
            sb.append("...[truncated]");     // truncation is visible in the record
        }
        return sb.toString();
    }
```

Prefer emitting the audit record as single-line JSON via a real encoder, which removes the hand-rolled quoting entirely, and log a normalised `username` placeholder rather than raw invalid input on the validation-error path.

### SEC-09: JSON responses are escaped with an HTML encoder, the wrong encoder for the context

- **Severity:** Low
- **CWE:** CWE-116: Improper Encoding or Escaping of Output
- **Location:** `web/PortalHttpHandler.java:97`

**Vulnerable code:**

```java
// web/PortalHttpHandler.java:97-102
                String responseJson = String.format(
                        "{\"status\":\"success\",\"message\":\"%s\",\"user\":\"%s\",\"role\":\"%s\"}",
                        InputValidator.escapeHtml(result.getMessage()),
                        InputValidator.escapeHtml(session.getUsername()),
                        InputValidator.escapeHtml(session.getRole())
                );
```

```java
// web/PortalHttpHandler.java:136-141
        String json = String.format(
                "{\"status\":\"active\",\"username\":\"%s\",\"role\":\"%s\",\"sourceIp\":\"%s\"}",
                InputValidator.escapeHtml(session.getUsername()),
                InputValidator.escapeHtml(session.getRole()),
                InputValidator.escapeHtml(session.getSourceIp())
        );
```

```java
// validation/InputValidator.java:118-131
            switch (c) {
                case '<' -> out.append("&lt;");
                case '>' -> out.append("&gt;");
                case '&' -> out.append("&amp;");
                case '"' -> out.append("&quot;");
                case '\'' -> out.append("&#x27;");
                default -> {
                    if (c < 32 && c != '\t' && c != '\n' && c != '\r') {
                        out.append('?');
                    } else {
                        out.append(c);
                    }
                }
            }
```

**Why it is a problem:**

The intent here is right — every interpolated value passes through an encoder, and the author clearly had XSS (CWE-79) in mind. The encoder is the wrong one for the output context, which means the protection is largely inapplicable to the format actually being produced.

`escapeHtml` is an HTML entity encoder: it turns `"` into `&quot;` and `<` into `&lt;`. Those are the correct outputs for an HTML text node. In JSON they are **not** the required escapes — JSON string boundaries need a backslash escape (`\"`), and the characters that break JSON are `"` and the raw control range. But `escapeHtml` leaves `"` escaped as the six-character sequence `&quot;` (harmless but wrong for JSON) while letting **`\n`, `\r`, and `\t` through verbatim** (lines 125-126 explicitly exempt them). A raw newline inside a JSON string literal is invalid JSON: the client's parser rejects the whole response. So the one character class that genuinely corrupts this output format is precisely the one the chosen encoder deliberately preserves, while the character class it does encode is not a JSON hazard.

There is also a correctness inversion worth flagging: HTML-encoding values inside a JSON body double-encodes for any client that then renders the string in HTML (`&amp;lt;` reaches the DOM as literal `&lt;`), and produces mojibake in non-browser consumers. Encoding at the wrong layer tends to cause both under-protection and data corruption simultaneously, which is what is happening here.

This is **not currently exploitable**, and that is why the severity is Low: every interpolated value is whitelist-constrained upstream — `username` matches `^[a-zA-Z0-9._-]{3,32}$`, `role` matches `^[A-Z0-9_-]{1,32}$`, and `sourceIp` is either a validated IP literal or the fixed string `unknown-source`. None of those alphabets contains `"`, `<`, `&`, or a control character. The vulnerability is latent: it becomes live the moment any interpolated value stops being regex-constrained — a display name, a free-text message field, or an operator-supplied IP (see SEC-05) — and nobody reviewing `escapeHtml` at that point would think to revisit the JSON assembly.

**Fix:**

Encode for the output context — use a JSON encoder and let it handle escaping:

```java
// web/PortalHttpHandler.java — context-correct encoding
    private static String jsonResponse(Object... kvPairs) {
        if (kvPairs.length % 2 != 0) {
            throw new IllegalArgumentException("expected key/value pairs");
        }
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < kvPairs.length; i += 2) {
            if (i > 0) sb.append(',');
            sb.append(JsonEncoder.quote(String.valueOf(kvPairs[i])))
              .append(':')
              .append(JsonEncoder.quote(String.valueOf(kvPairs[i + 1])));
        }
        return sb.append('}').toString();
    }

    // usage
    String json = jsonResponse(
            "status", "active",
            "username", session.getUsername(),
            "role", session.getRole(),
            "sourceIp", session.getSourceIp());
```

where `JsonEncoder.quote` escapes `"` and `\`, maps control characters to `\u00XX` (notably `\n` → `\n`, `\r` → `\r`), and optionally escapes `/` and U+2028/U+2029. Since `pom.xml` deliberately carries no runtime dependencies, either add a vetted JSON library or implement the encoder above and unit-test the control-character cases. Keep `escapeHtml` only for any genuine HTML output, which this component does not currently produce.

### SEC-10: `SecureRandom.getInstanceStrong()` in constructors can block indefinitely on a starved entropy pool

- **Severity:** Low
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `crypto/SecureTokenGenerator.java:26`

**Vulnerable code:**

```java
// crypto/SecureTokenGenerator.java:23-30
    public SecureTokenGenerator(int tokenLengthBytes) {
        SecureRandom rng;
        try {
            rng = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            rng = new SecureRandom();
        }
        this.secureRandom = rng;
```

```java
// crypto/PasswordHasher.java:35-42
    public PasswordHasher(int iterations, int saltLengthBytes, int keyLengthBits) {
        SecureRandom rng;
        try {
            rng = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            rng = new SecureRandom();
        }
        this.secureRandom = rng;
```

**Why it is a problem:**

`SecureRandom.getInstanceStrong()` returns the platform's strongest-seeded instance, which on Linux is `/dev/random` semantics: it **blocks** until the kernel entropy accounting says enough true entropy is available. That blocking behaviour is the entire point of the API for long-term key generation, but it is the wrong choice here, for two reasons.

First, the placement makes the block unbounded and unsurfaced. Both calls sit in a **constructor**, so a container scheduled onto a host with a starved pool — the common case for a fresh pod at boot, on a VM with no hardware RNG or virtio-rng, in a `chroot`/CI runner, or during a startup thundering herd — stalls the constructing thread with no timeout, no progress signal, and no exception. The application does not fail, it hangs, which is a worse operational outcome because health checks report a live process and the operator gets no diagnostic pointing at entropy. `PasswordHasher`'s constructor additionally performs a full 210,000-iteration dummy hash (line 50 onward), so it compounds a CPU cost onto a possibly-blocking wait.

Second, the strength buys nothing that a non-blocking CSPRNG would not. Both consumers use the generator for **session tokens** (`generateToken`, already 256 bits of output) and **per-record salts** — both are *public* values whose security requires unpredictability, not perfect forward-seeded true randomness. Java's default `new SecureRandom()` (NativePRNG, backed by `/dev/urandom` on Linux) is already a properly-seeded CSPRNG and is non-blocking; after the JVM's initial seeding it provides the same cryptographic guarantee for these two use cases. So the availability cost is real and the security benefit is essentially nil for these call sites. Note the `catch (NoSuchAlgorithmException)` fallback already picks `new SecureRandom()`, which quietly concedes that the non-blocking instance is an acceptable choice — the blocking path is the only one that needs justifying.

Low severity: availability-only, requires an entropy-starved environment, and does not weaken any credential or session value.

**Fix:**

Use the non-blocking CSPRNG for token/salt generation, and reserve a blocking instance for any long-term key generation:

```java
// crypto/SecureTokenGenerator.java (and identically in PasswordHasher)
    public SecureTokenGenerator(int tokenLengthBytes) {
        // Non-blocking CSPRNG: tokens and salts are public, high-volume, unpredictable-by-design values.
        // Never use getInstanceStrong() here - it blocks on a starved /dev/random pool.
        this.secureRandom = new SecureRandom();
        this.tokenLengthBytes = tokenLengthBytes;
    }
```

If the deployment standard insists on a strong-seeded instance, obtain it once at startup on a dedicated bootstrap thread **with a bounded wait**, fail fast with a clear "insufficient entropy" error rather than hanging, document `securerandom.strongAlgorithms=NativePRNGNonBlocking:SUN` as the container default, and add a startup self-test that reads 32 bytes within a timeout so entropy starvation becomes a visible crash rather than a silent stall.

### SEC-11: Fixed thread pool with no request/read timeouts allows cheap connection-exhaustion DoS

- **Severity:** Low
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `web/PortalServer.java:22`

**Vulnerable code:**

```java
// web/PortalServer.java:20-26
    public PortalServer(int port, AuthenticationService authService, boolean requireSecureCookies) throws IOException {
        this.server = HttpServer.create(new InetSocketAddress(port), 0);
        this.executor = Executors.newFixedThreadPool(8);
        this.server.setExecutor(executor);

        PortalHttpHandler handler = new PortalHttpHandler(authService, requireSecureCookies);
        this.server.createContext("/api/", handler);
```

```java
// web/PortalHttpHandler.java:180-193
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
        return baos.toByteArray();
    }
```

**Why it is a problem:**

The capacity ceiling is eight concurrent requests — `newFixedThreadPool(8)` — and nothing bounds how long a worker may be occupied by one request. `HttpServer` exposes no request-timeout or read-timeout setting, and `readBoundedBody` loops on `is.read(buffer)` with no deadline: the 4,096-byte cap limits *volume*, not *duration*. A client that sends 1 byte every few seconds keeps a worker parked in that blocking `read` for as long as it likes.

The cost asymmetry makes this cheap to exploit: **eight** slow connections — eight sockets, eight trickle streams, negligible bandwidth — occupy every worker, and the queue in front of the fixed pool then grows unbounded (`Executors.newFixedThreadPool` uses an unbounded `LinkedBlockingQueue`), so legitimate logins wait behind stalled requests indefinitely. The attacker never trips the size limit, so `Payload Too Large` never fires, and never sends anything malformed, so the `catch (Exception)` → 500 path never fires either. This is the classic slowloris shape, and it is reachable by any host that can open a TCP connection to the port — which, per SEC-01, is every host that can route to the machine, since the socket is bound to the wildcard address.

Two aggravating factors. PBKDF2 at 210,000 iterations makes each login genuinely CPU-expensive, so the pool is the correct thing to bound — but eight workers handling slow reads means the same eight slots that would absorb a legitimate burst are held by attackers. And because the request queue is unbounded, backlog growth eventually manifests as memory pressure and latency collapse rather than a clean rejection, so the failure mode degrades into something worse than a fast 503.

Low severity as a standalone finding (availability only, and an embedded demo server would normally sit behind a real front end), but it should be read together with SEC-01: the same wildcard plaintext exposure that makes credential theft remote also makes this DoS remote.

**Fix:**

Bound worker occupancy with a read deadline and bound the queue so overload sheds load explicitly:

```java
// web/PortalServer.java — bounded queue + explicit rejection when saturated
        this.executor = new ThreadPoolExecutor(
                8, 8, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(64),
                new ThreadPoolExecutor.AbortPolicy());   // fail fast instead of queueing forever
        this.server.setExecutor(this.executor);
```

```java
// web/PortalHttpHandler.java — wall-clock deadline on the body read
    private byte[] readBoundedBody(InputStream is, int maxBytes, long deadlineMillis) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int totalRead = 0;
        long deadline = System.currentTimeMillis() + deadlineMillis;
        int read;
        while ((read = is.read(buffer)) != -1) {
            totalRead += read;
            if (totalRead > maxBytes) {
                return null; // Bound exceeded
            }
            if (System.currentTimeMillis() > deadline) {
                throw new IOException("Request body read timed out"); // slow client
            }
            baos.write(buffer, 0, read);
        }
        return baos.toByteArray();
    }
```

`com.sun.net.httpserver` cannot set a socket read timeout directly, so for any deployment exposed beyond localhost, front it with a reverse proxy that enforces client body and idle timeouts (or replace it with a server that supports them natively: keep `ServerSocket` timeouts under your control via `HttpsConfigurator`-backed `HttpsServer` plus a hardened front end). Also set `server.stop(...)`-friendly lifecycle handling so a stalled worker cannot block shutdown.

### SEC-12: Password is echoed to the terminal when no console is available

- **Severity:** Low
- **CWE:** CWE-522: Insufficiently Protected Credentials
- **Location:** `cli/EmployeePortalApp.java:288`

**Vulnerable code:**

```java
// cli/EmployeePortalApp.java:283-292
    public static char[] readPasswordSecurely(String prompt, BufferedReader fallbackReader) {
        Console console = System.console();
        if (console != null) {
            return console.readPassword(prompt);
        } else {
            System.out.print(prompt);
            try {
                String line = fallbackReader.readLine();
                return line != null ? line.toCharArray() : null;
            } catch (Exception e) {
```

**Why it is a problem:**

`console.readPassword()` exists precisely to suppress terminal echo, and the code uses it correctly when a console is present. The `else` branch discards that protection entirely: `System.out.print(prompt)` followed by `BufferedReader.readLine()` reads from an ordinary line reader, and **nothing disables echo**, so every character the user types is echoed by the terminal driver. The method name `readPasswordSecurely` and its surrounding comment promise the opposite of what the fallback does, so a caller has no reason to suspect the difference.

When does `System.console()` return null? Under an IDE runner, inside a CI job, through `ssh host cmd`, in a container `exec`, when stdin is piped or redirected, and in most process-wrapper scenarios — which is to say, in exactly the environments where this component is likely to be run. So the fallback is not a rare corner; it is plausibly the common path, and on that path the **plaintext password is rendered on screen and into anything that captures terminal output**: CI logs, `script`/`tee` captures, asciinema recordings, `screen`/`tmux` scrollback, and IDE console history. A single enrollment or login in a CI job therefore writes an employee password into a build log that typically has far broader read access than the credential store.

Compounding this, `line.toCharArray()` creates a `String` that the JVM pools and cannot wipe — the intermediate `String` retains the password in heap memory past the `catch`/`finally` wiping that the rest of the codebase carefully performs (`PBEKeySpec.clearPassword()`, `Arrays.fill` zeroing). So the fallback leaks the credential both to the output stream and to non-wipeable heap memory, undermining the hygiene the surrounding code deliberately maintains.

Low severity: requires a no-console invocation, the exposure is local/operational rather than remotely reachable, and it does not weaken authentication. It is still a credential-disclosure defect in a component whose stated rules forbid logging or echoing secrets.

**Fix:**

Never read a secret where echo cannot be suppressed — fail loudly instead of degrading silently:

```java
// cli/EmployeePortalApp.java
    public static char[] readPasswordSecurely(String prompt, BufferedReader fallbackReader) {
        Console console = System.console();
        if (console != null) {
            return console.readPassword(prompt);
        }
        // No tty: echo cannot be suppressed, so the secret would land on stdout/logs.
        // Accept it from a protected channel instead of an echoed stream.
        String fromEnv = System.getenv("PORTAL_PASSWORD_FILE");
        if (fromEnv != null && !fromEnv.isBlank()) {
            Path p = Paths.get(fromEnv);
            try {
                List<String> lines = Files.readAllLines(p, StandardCharsets.UTF_8);
                return lines.isEmpty() ? null : lines.get(0).toCharArray();
            } catch (IOException e) {
                throw new IllegalStateException("Cannot read password file securely", e);
            }
        }
        throw new IllegalStateException(
                "No interactive console: refusing to read a password from echoed stdin. "
              + "Run on a tty or set PORTAL_PASSWORD_FILE to a 0600 file.");
    }
```

If interactive-echo suppression in a piped context is genuinely required, do it by invoking `stty -echo` around the read and restoring it in a `finally` — never by reading through an echoing `BufferedReader`. Do not route the secret through an intermediate `String`, and document in `README.md` that headless enrollment requires the file-based path.

### SEC-13: Password policy enforces length only, with no complexity or compromise screening

- **Severity:** Low
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `validation/InputValidator.java:55`

**Vulnerable code:**

```java
// validation/InputValidator.java:52-58
    public static boolean isValidPassword(char[] password) {
        if (password == null || password.length < MIN_PASSWORD_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
            return false;
        }
        return true;
    }
```

```java
// validation/InputValidator.java:12-17
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9._-]{3,32}$");
```

**Why it is a problem:**

`isValidPassword` checks `length >= 8 && length <= 128` and nothing else. Length-only policies are a legitimate modern design (NIST SP 800-63B explicitly prefers length and screening over composition rules), so the *absence of complexity rules* is not by itself a defect — and the 128-character ceiling, which permits long passphrases, is a deliberate and correct choice. The finding is about what is missing from the rest of a length-only policy, not about missing character-class mandates.

Specifically, the policy has **no compromise screening**. `isValidPassword` never compares against a breached-password or common-password list, so `password`, `12345678`, `qwerty12`, and any credential in a public breach corpus are accepted as valid on their 8-character length alone. Under NIST 800-63B, a length-only rule is defensible **only when paired with** blocked-password screening; adopting half of the guidance while omitting the half that does the work yields a policy that looks modern and is not.

This matters more here than in a typical application because of the surrounding design. The store holds a salted PBKDF2 hash that any network-adjacent or local attacker can capture, and the rate limiter protects the *online* path only. Once the flat file leaks, defence reduces entirely to per-password strength against offline cracking at 210,000 iterations — a rate an attacker with GPU or ASIC capacity will find productive against 8-character dictionary words. The design also does not reject a password equal to the username (or the reversed/uppercased username), which is the single most common weak-password pattern in an employee-portal context where the username is known and often the person's name. And `enrollEmployee` calls `isValidPassword` and then stores the result with `UserStatus.ACTIVE` unconditionally, so there is no administrative strength review at enrollment either.

Low severity: this is a hardening/defence-in-depth weakness that raises the blast radius of another compromise rather than a directly exploitable defect.

**Fix:**

Add the screening half of a length-only policy, and raise the floor:

```java
// validation/InputValidator.java
    public static boolean isValidPassword(char[] password, String username) {
        if (password == null || password.length < MIN_PASSWORD_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
            return false;
        }
        String candidate = new String(password).toLowerCase(Locale.ROOT);

        // NIST SP 800-63B s5.1.1.2: screen against breached/common passwords.
        if (CompromisedPasswordList.contains(candidate)) {
            return false;
        }
        // Reject the obvious username-derived variants.
        if (username != null && !username.isBlank()) {
            String user = username.toLowerCase(Locale.ROOT);
            if (candidate.equals(user)
                    || candidate.equals(new StringBuilder(user).reverse().toString())
                    || candidate.startsWith(user) || candidate.endsWith(user)) {
                return false;
            }
        }
        return true;
    }
```

Set `MIN_PASSWORD_LENGTH` to 12 or higher to reflect the offline-cracking threat this component actually faces, keep the 128-character ceiling, and load the denylist as a sorted/bloom-filtered structure so the check stays O(1) and preserves the timing parity that `authenticate` works to maintain. Wipe the intermediate `String` concern by keeping the check on `char[]` where feasible, and apply the same rule at enrollment and password change.

### SEC-14: No anti-CSRF token on state-changing `POST /api/login` and `/api/logout`

- **Severity:** Low
- **CWE:** CWE-352: Cross-Site Request Forgery (CSRF)
- **Location:** `web/PortalHttpHandler.java:145`

**Vulnerable code:**

```java
// web/PortalHttpHandler.java:145-153
    private void handleLogout(HttpExchange exchange) throws IOException {
        String sessionToken = extractSessionCookie(exchange);
        if (sessionToken != null) {
            authService.getSessionManager().revokeSession(sessionToken);
        }
        // Invalidate cookie header
        String logoutCookie = SecureTokenGenerator.buildLogoutCookieHeader(requireSecureCookies);
        exchange.getResponseHeaders().add("Set-Cookie", logoutCookie);
        sendJsonResponse(exchange, 200, "{\"status\":\"success\",\"message\":\"Logged out successfully\"}");
    }
```

```java
// crypto/SecureTokenGenerator.java:56-63 (cookie attributes on the login response)
        sb.append(cookieName).append("=").append(token).append("; ");
        sb.append("Path=/; ");
        if (requireSecure) {
            sb.append("Secure; ");
        }
        sb.append("HttpOnly; ");
        sb.append("SameSite=Strict; ");
        sb.append("Max-Age=").append(maxAgeSeconds);
```

**Why it is a problem:**

Neither `POST /api/login` nor `POST /api/logout` checks an anti-CSRF token, an `Origin`/`Sec-Fetch-Site` header, or any custom request header that a cross-site form cannot set. The only defence is the cookie attribute `SameSite=Strict` on the session cookie, and `SameSite` is a mitigation, not a control: it is a browser-policy default that varies with browser version and is bypassable in older engines, is not applied to requests the browser classifies as same-site (subdomains, some redirect shapes), and does nothing for endpoints that authenticate by means other than a cookie.

The two endpoints differ sharply in impact, and the honest framing matters:

- **`/api/logout` is genuinely low-risk.** Forced logout is a nuisance attack, and it can be issued cross-site today via a simple form POST because it reads the session cookie and needs no attacker knowledge. Its worst case is user disruption — repeatedly evicting a session to mask activity or to harass.
- **`/api/login` is the interesting one, and it is session *fixation*, not logout.** A cross-site form can submit an attacker-supplied `username`/`password` pair — meaning an attacker who holds any weak credential (see SEC-13) can log the victim into a session the attacker already knows the identity of. `SameSite=Strict` is what blocks this today, and it happens to block it well, since a top-level cross-site form POST carries no cookies and this endpoint reads credentials from the body rather than from a cookie — so Strict is not even the relevant gate on the request itself. The protection here is therefore *incidental*: it depends on the absence of any cookie-authenticated login path and on browser `SameSite` semantics holding, rather than on an explicit check.

The design does get several things right that limit this finding's severity: CSP `default-src 'none'; frame-ancestors 'none'` plus `X-Frame-Options: DENY` (lines 46-47) prevent framing-based clickjacking into these POSTs, and the JSON content type with `nosniff` blocks naive cross-origin form navigation from being read back. It is Low because there is no realistic data-theft CSRF today — but the missing control is an explicit one, and relying on `SameSite` plus the accident of body-based authentication means any change to the authentication mechanism silently reintroduces a CSRF hole.

**Fix:**

Require a proof-of-origin on state-changing requests, in addition to keeping `SameSite=Strict`:

```java
// web/PortalHttpHandler.java
    private static final Set<String> ALLOWED_ORIGINS = Set.of("https://portal.internal.example");

    private boolean sameOrigin(HttpExchange exchange) {
        String origin = exchange.getRequestHeaders().getFirst("Origin");
        String fetchSite = exchange.getRequestHeaders().getFirst("Sec-Fetch-Site");
        if ("same-origin".equalsIgnoreCase(fetchSite) || "none".equalsIgnoreCase(fetchSite)) {
            return true;
        }
        String host = exchange.getRequestHeaders().getFirst("Host");
        if (origin == null) {
            return false;                       // POSTs from non-browsers must still be explicit
        }
        return ALLOWED_ORIGINS.contains(origin)
                || ("https://" + host).equalsIgnoreCase(origin);
    }

    // in handle(), before dispatching any POST:
            if ("POST".equals(method) && !sameOrigin(exchange)) {
                sendJsonResponse(exchange, 403, "{\"error\":\"Cross-origin request rejected\"}");
                return;
            }
```

For login specifically, add a per-session anti-CSRF token issued alongside the session cookie and require it as a header (e.g. `X-CSRF-Token`) that a cross-site form cannot set, and verify `Origin`/`Sec-Fetch-Site` on logout as well. Keep CSP framing denial in place as the second layer rather than the primary one.

## 6. Verified Controls and Checks With No Finding

The following were examined and found correct. Several are non-trivial and were deliberately implemented; they are recorded so they are not regressed.

**Credential storage and cryptography**

- `PBKDF2WithHmacSHA512` at 210,000 default iterations (`SecurityConfig.java`), inside the accepted modern range; all overrides clamped to `100000..2000000` (`SecurityConfig.java:67`), so the KDF cost cannot be silently weakened by configuration.
- Per-record 32-byte salt from `SecureRandom` (`PasswordHasher.generateSalt`), no salt reuse across records; 32-byte (256-bit) derived key.
- `MessageDigest.isEqual(computedHash, expectedHash)` for hash comparison — constant-time, no early-exit byte comparison.
- `dummyVerify(char[])` (`PasswordHasher.java:124`) performs a real PBKDF2 pass against a stored dummy hash, and `authenticate` invokes it on **every** early-return path (invalid input, rate-limited, unknown user, suspended account), so response time does not reveal whether a username exists. Timing-parity discipline here is genuinely good.
- Passwords held in `char[]` rather than `String` on the internal paths, with `PBEKeySpec.clearPassword()` in a `finally` and `Arrays.fill` zeroing of computed hashes.
- `EmployeeRecord` performs defensive copies of salt and hash in both constructor and getters (`EmployeeRecord.java:44-45`, `:59-60`), and its `toString()` omits salt and hash entirely.
- `pom.xml` declares no runtime third-party dependencies (only JUnit Jupiter 5.10.2, test scope), so the crypto path has no transitive supply-chain surface.

**Authentication and session management**

- A single `AuthenticationResult.GENERIC_FAILURE_MESSAGE` for all failure reasons; no user enumeration through response text, and `PortalHttpHandler.java:106-109` emits the same message for every login failure.
- Session tokens are 256-bit, base64url-encoded, from `SecureRandom`; validated against `^[a-zA-Z0-9_-]{43,64}$` before use.
- Session rotation on successful login (new token issued per authentication) and per-user active-session cap from `SecurityConfig`, mitigating fixation on the login path itself.
- Both idle and absolute timeouts enforced, with expiry removal on validation; `Session.lastAccessedAt` is `volatile` and `Session.toString()` masks the session ID.
- `HttpOnly` and `SameSite=Strict` are appended **unconditionally** in `SecureTokenGenerator.java:61-62`, independent of the `requireSecure` branch — so the two attributes that matter most for script-based theft are always present.
- `extractClientIp` (`PortalHttpHandler.java:156-162`) derives the client address from `exchange.getRemoteAddress()` and **does not** consult `X-Forwarded-For` or `X-Real-IP`, so header-based rate-limit identity spoofing is not possible on the HTTP path. (Compare SEC-05, where the CLI path does trust operator text.)
- `AuditLogger.maskToken` renders only first-4/last-4 characters; no full session token appears in any log record.

**Input validation and output handling**

- Whitelist (allowlist) validation throughout: `^[a-zA-Z0-9._-]{3,32}$` for usernames (`InputValidator.java:14`), structured IPv4/IPv6 patterns plus `localhost`, and the session-token pattern. No blacklist-style filtering found.
- Path-traversal sequences (`..`) explicitly rejected in validation; the flat-file store derives no path from user input (SEC-07 concerns only the environment-supplied data directory).
- `sanitizeForLog` neutralises CR/LF and all other control characters, which does prevent line-based audit-record forgery — the residual gap is only the unescaped quote and silent truncation reported in SEC-08.
- Response headers set on every response (`PortalHttpHandler.java:45-50`): `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `Cache-Control: no-store, no-cache, must-revalidate, private`, `Pragma: no-cache`, and an explicit `application/json; charset=UTF-8`. CSP is maximally restrictive and there is no HTML output, so stored/reflected XSS has no sink; the CSP/framing denial is effective as defence in depth.
- Request bodies are bounded to `MAX_REQUEST_BODY_BYTES = 4096` (`PortalHttpHandler.java:32`, enforced at `:72-76`), rejecting oversized payloads before parsing.
- Unknown routes return a generic 404 and the top-level `catch (Exception)` (`PortalHttpHandler.java:66-67`) returns a static 500 body — no stack traces or internal detail reach the client.

**Data store and configuration integrity**

- Credential file written to a temp file with `0600` permissions then installed via `Files.move(..., ATOMIC_MOVE, REPLACE_EXISTING)` (`FileEmployeeRepository.java:223`), so readers never observe a partially-written database; temp file deleted on failure.
- Directory `0700` / files `0600` established at creation for both the data directory and the audit log (`AuditLogger.ensureSecureLogFile`, `FileEmployeeRepository` init), with POSIX permission attributes rather than best-effort `chmod`.
- Flat-file records are `:`-separated with `split(":", -1)`, requiring at least 6 fields, and each candidate record is re-validated through `InputValidator.isValidUsername` and the `EmployeeRecord` constructor before entering the cache (`FileEmployeeRepository.java:99-122`) — so a tampered file cannot inject an out-of-range iteration count or malformed role.
- All numeric configuration values pass through `clamp(...)`, bounding sessions, timeouts, windows, and KDF iterations against both absurd and weakened settings.
- No hardcoded credentials, default/service accounts, keys, or tokens anywhere in the sources, `pom.xml`, or `README.md`.

**Concurrency and injection surfaces**

- `BoundedLruCache` wraps every operation (`get`, `put`, `remove`, `compute`, `forEach`) in a `ReentrantLock`, and rejects non-positive capacity — no unsynchronised `LinkedHashMap` access despite `accessOrder` mutation on read. The eviction *policy* is the finding (SEC-04); its thread-safety is sound.
- `RateLimiter` increments counters via `cache.compute(...)`, so check-and-increment is atomic rather than a read-then-write race; `AttemptRecord` state is `synchronized`.
- `FileEmployeeRepository` uses a `ReentrantReadWriteLock` for read/write separation over the record cache; `SessionManager` uses a `ReadWriteLock` plus a per-user lock for the session cache.
- No SQL or NoSQL anywhere (flat file only) — injection surface absent by construction.
- No Java deserialization of untrusted data: hex parsing goes through `HexFormat.parseHex`, which is strict and rejects malformed input; no `ObjectInputStream`, no `readObject`.
- No OS command execution (`Runtime.exec`/`ProcessBuilder`), no reflection on user-supplied class or method names, no `eval`-equivalent, no URL fetching from user input (SSRF absent).
- Passwords are never written to the audit log or stdout; audit fields are sanitised and token material is masked (see above).
- No `@Disabled`, `assertTrue(true)`, or no-op assertions found in the 7 test files (39 tests, 913 lines) — the suite is not silently weakened, and it does exercise hashing, validation, repository load/save, rate limiting, and session expiry. It does **not** cover the CLI/default wiring where SEC-01 lives, which is why the "zero findings" claim in `README.md` was not caught by the existing tests.
