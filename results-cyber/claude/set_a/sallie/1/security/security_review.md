# Security Review: SecureLoginServer

## 1. Executive Summary
`SecureLoginServer.java` is a single-file Java 17 web app with no dependencies, built on `com.sun.net.httpserver`. It serves a sign-in form, checks a username and password against PBKDF2-SHA256 hashes kept in memory, and issues a `__Host-SESSIONID` cookie (`Secure; HttpOnly; SameSite=Strict`). That cookie maps to a session stored on the server. It also serves a home page for signed-in users and a sign-out endpoint protected by a CSRF token. Optional HTTPS uses a PKCS12 keystore.

The core controls are sound: password storage, session ID generation and storage, cookie attributes, session-fixation handling, output encoding and security headers. No injection, XSS, session hijacking or authentication-bypass flaw was found. The findings are about abuse resistance and hardening:

- **Medium:** any unauthenticated client can lock a known username out of sign-in for as long as it likes (SEC-01).
- **Medium:** a handful of slow connections can use up the fixed pool of 16 worker threads, and each login runs a 600,000-iteration PBKDF2 hash (SEC-02).
- **Medium:** the per-IP limit counts every IPv6 address separately, so rotating addresses defeats it (SEC-03).
- **Low:** the lockout check and the failure count are not atomic (SEC-04).
- **Low:** the same-origin check compares `Origin` with the request's own `Host` header and allows requests that send neither header, so it can be passed via DNS rebinding and gives no login-CSRF protection to browsers without `Origin` (SEC-05).
- **Low:** the generated demo password is written to stdout (SEC-06).
- **Low:** a configured password can be as short as one character (SEC-07).

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `SecureLoginServer.java` | The whole application: HTTP/HTTPS server, routing, login, home and logout pages, user store, session store, login throttle, helpers | Password hashing (PBKDF2), `SecureRandom` tokens, session cookie creation and parsing, session timeouts and invalidation, CSRF defences (Origin/Sec-Fetch-Site checks and a synchronizer token), brute-force throttling by username and IP, HTML output encoding, security headers, TLS setup, form parsing and body size limits, logging of usernames and IPs, a secret (the demo password) read from the environment and printed |
| `README.md` | Plain-English guide to running and configuring the app | Documents defaults (loopback bind, HTTPS via keystore), environment variables, a `curl` example and production caveats. No executable code. |
| `prompt.txt`, `cyber_prompt.txt` | The task prompts used to generate the app and this review | None (text only) |
| `result.md`, `return.txt`, `prompt_hash.txt` | Run metadata and summary from the generation step (`prompt_hash.txt` is empty) | None (text/JSON only) |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: the router workflow. It was used to understand the code, pick specialised skills by keyword and structure this report.
- `testing-api-authentication-weaknesses`: login flow, account-enumeration resistance, session lifecycle (fixation, logout revocation, expiry), token entropy, tokens in URLs or logs, and password policy (SEC-01, SEC-07).
- `implementing-api-rate-limiting-and-throttling`: `LoginThrottle` and how it is used in `login()`. Checked atomic check-and-increment, client identification, X-Forwarded-For trust and resource exhaustion (SEC-02, SEC-03, SEC-04).
- `performing-csrf-attack-simulation`: `verifySameOrigin()`, the logout CSRF token, SameSite settings and login CSRF (SEC-05).
- `performing-cryptographic-audit-of-application`: PBKDF2 parameters, salt, constant-time comparison, `SecureRandom` usage, SHA-256 session-ID indexing, TLS protocol versions and keystore secret handling (no finding).
- `performing-security-headers-audit`: CSP, X-Frame-Options/frame-ancestors, nosniff, Referrer-Policy, Cache-Control, HSTS and cookie attributes (no finding; one hardening note in section 6).
- `testing-for-sensitive-data-exposure`: logging of credentials, error-message leakage, caching of authenticated pages and credentials in URLs (SEC-06).
- `testing-for-xss-vulnerabilities`: every place untrusted data reaches HTML (HTML body and attribute contexts) and the CSP (no finding).
- General OWASP Top 10 / CWE knowledge, used where no library skill closely matched:
  - thread-pool and slow-request exhaustion in the JDK HTTP server (CWE-400)
  - trusting the `Host` header and DNS rebinding against a server bound to loopback (CWE-346)
  - overly restrictive account lockout (CWE-645)
  - log injection (CWE-117)
  - open redirect (CWE-601)
  - HTTP response splitting (CWE-113)
  - path traversal, deserialization and command/SQL injection (confirmed absent)

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Any client can lock a user out by sending five wrong passwords for that username | Medium | CWE-645 | `SecureLoginServer.java:235` |
| SEC-02 | A few slow connections and costly unauthenticated hashing can use up the 16-thread worker pool | Medium | CWE-400 | `SecureLoginServer.java:122` |
| SEC-03 | Per-IP login limit is keyed on the full IPv6 address, so rotating addresses bypasses it | Medium | CWE-307 | `SecureLoginServer.java:226` |
| SEC-04 | Lockout check and failure recording are not atomic, so parallel guesses exceed the limit | Low | CWE-367 | `SecureLoginServer.java:235` |
| SEC-05 | Same-origin check trusts the request's own Host header and passes when Origin/Sec-Fetch-Site are absent | Low | CWE-346 | `SecureLoginServer.java:327` |
| SEC-06 | Generated demo password is written to stdout/log output | Low | CWE-532 | `SecureLoginServer.java:146` |
| SEC-07 | No minimum strength for the configured account password | Low | CWE-521 | `SecureLoginServer.java:110` |

## 5. Detailed Findings

### SEC-01: Any client can lock a user out by sending five wrong passwords for that username
- **Severity:** Medium
- **CWE:** CWE-645: Overly Restrictive Account Lockout Mechanism
- **Location:** `SecureLoginServer.java:235-237`, `SecureLoginServer.java:534-536` (limit defined at line 73)

**Vulnerable code:**
```java
// SecureLoginServer.java:235-237
            if (throttle.isLocked(userKey) || throttle.isLocked(ipKey)) {
                sendLoginPage(ex, 429, "Too many failed attempts. Please wait a few minutes and try again.");
                return;
// SecureLoginServer.java:534-536
                if (failures >= maxFailures) {
                    return new Entry(0, now.plus(LOCKOUT_DURATION), now);
                }
```

**Why it is a problem:** The per-user lock applies to the username everywhere, no matter who caused the failures. Once `user:alice` is locked, the check runs before the password is verified, so the real owner gets `429` even with the correct password. Anyone who can reach `/login` can send five wrong passwords for `alice` every five minutes and keep the account locked forever. That costs 5 requests per 5 minutes, and each attempt adds only 1 to the attacker's per-IP counter (limit 20). A single IPv4 address can therefore keep four accounts locked indefinitely, and IPv6 rotation (SEC-03) removes even that limit. Usernames are easy to guess (the default is `alice`), so this is a practical denial of service against sign-in.

**Fix:** Apply the hard lock to the pair of username and client, so an attacker only locks themselves out. Keep a per-username counter with a much higher threshold to stop distributed guessing. Let that username-wide lock be bypassed only by clients the account has already trusted, for example a signed "device cookie" issued after a successful login (OWASP device-cookie pattern).
```java
static final int MAX_FAILED_ATTEMPTS_PER_USER_AND_CLIENT = 5;
static final int MAX_FAILED_ATTEMPTS_PER_USER_GLOBAL = 50;

// in login()
String userKey = "user:" + username;
String pairKey = "user+client:" + username + "|" + ipKey;

if (throttle.isLocked(pairKey) || throttle.isLocked(ipKey)) {
    sendLoginPage(ex, 429, "Too many failed attempts. Please wait a few minutes and try again.");
    return;
}
// A username-wide lock only stops clients the account has never successfully used.
if (throttle.isLocked(userKey) && !hasValidDeviceCookie(ex, username)) {
    sendLoginPage(ex, 429, "Too many failed attempts. Please wait a few minutes and try again.");
    return;
}
...
if (!valid) {
    throttle.recordFailure(pairKey, MAX_FAILED_ATTEMPTS_PER_USER_AND_CLIENT);
    throttle.recordFailure(userKey, MAX_FAILED_ATTEMPTS_PER_USER_GLOBAL);
    throttle.recordFailure(ipKey, MAX_FAILED_ATTEMPTS_PER_IP);
    ...
}
throttle.reset(pairKey);
throttle.reset(userKey);
issueDeviceCookie(ex, username); // HMAC-signed, HttpOnly, Secure, SameSite=Strict
```

### SEC-02: A few slow connections and costly unauthenticated hashing can use up the 16-thread worker pool
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `SecureLoginServer.java:84-85`, `SecureLoginServer.java:122-123` (hash cost at line 396)

**Vulnerable code:**
```java
// SecureLoginServer.java:84-85
        setDefaultProperty("sun.net.httpserver.maxReqTime", "30");
        setDefaultProperty("sun.net.httpserver.maxRspTime", "30");
// SecureLoginServer.java:122-123
        ExecutorService workers = Executors.newFixedThreadPool(16);
        server.setExecutor(workers);
```

**Why it is a problem:** The JDK `HttpServer` reads each request's line, headers and body (and, for `HttpsServer`, runs the TLS handshake) on the executor thread. Only 16 threads exist, and a request may take up to 30 seconds to arrive. An attacker who opens 16 connections and sends bytes slowly, reopening them every ~30 seconds, holds every worker. Other requests then sit in the executor's unbounded queue, and the site, including sign-in, stops responding. Separately, every unauthenticated `POST /login` with a well-formed body runs PBKDF2 with 600,000 iterations (line 396), which uses roughly a CPU core for a noticeable fraction of a second. The throttles only kick in after failures, and SEC-03 lets an attacker avoid the per-IP throttle entirely. Sustained login attempts can therefore saturate the CPU and the pool. Nothing limits concurrent connections or concurrent hashes.

**Fix:** Stop slow clients from pinning scarce platform threads by using virtual threads on Java 21+ or a much larger bounded pool behind a reverse proxy with slow-request protection. Shorten the request timeout, and cap concurrent PBKDF2 work with a semaphore that fails fast with `503`.
```java
setDefaultProperty("sun.net.httpserver.maxReqTime", "10");
setDefaultProperty("sun.net.httpserver.maxRspTime", "10");

// Java 21+: a blocked slow client costs a cheap virtual thread, not one of 16 workers.
ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
server.setExecutor(workers);

// Bound CPU spent on unauthenticated password hashing.
static final Semaphore HASH_PERMITS =
        new Semaphore(Math.max(2, Runtime.getRuntime().availableProcessors() / 2));

// in login(), around users.verify(...)
boolean acquired;
try {
    acquired = HASH_PERMITS.tryAcquire(2, TimeUnit.SECONDS);
} catch (InterruptedException e) {
    Thread.currentThread().interrupt();
    acquired = false;
}
if (!acquired) {
    sendLoginPage(ex, 503, "The server is busy. Please try again shortly.");
    return;
}
char[] passwordChars = password.toCharArray();
boolean valid;
try {
    valid = users.verify(username, passwordChars);
} finally {
    Arrays.fill(passwordChars, '\0');
    HASH_PERMITS.release();
}
```

### SEC-03: Per-IP login limit is keyed on the full IPv6 address, so rotating addresses bypasses it
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `SecureLoginServer.java:226-228`

**Vulnerable code:**
```java
// SecureLoginServer.java:226-228
            String clientIp = ex.getRemoteAddress().getAddress().getHostAddress();
            String userKey = "user:" + username;
            String ipKey = "ip:" + clientIp;
```

**Why it is a problem:** The per-IP counter uses the full textual address. On an IPv6-reachable deployment (for example, binding to `::` with HTTPS), a single attacker usually controls at least a /64, which is 2^64 source addresses. Using a new address for each attempt means `ip:` never reaches 20 failures. That removes the only control against password spraying (one or two guesses against many usernames) and against the lockout abuse in SEC-01. It also removes the per-client limit on how many PBKDF2 hashes a client can trigger (SEC-02). Each new address also adds an entry to the throttle map.

**Fix:** Group IPv6 clients by their /64 prefix (IPv4 stays per address). Optionally add a global failed-login budget that triggers extra friction such as a CAPTCHA or delay when exceeded.
```java
static String clientKey(InetAddress address) {
    if (address instanceof Inet6Address) {
        // An end site normally owns a whole /64, so count the prefix as one client.
        return "ip6:" + HexFormat.of().formatHex(address.getAddress(), 0, 8);
    }
    return "ip4:" + address.getHostAddress();
}

// in login()
InetAddress clientAddress = ex.getRemoteAddress().getAddress();
String clientIp = clientAddress.getHostAddress();
String userKey = "user:" + username;
String ipKey = clientKey(clientAddress);
```

### SEC-04: Lockout check and failure recording are not atomic, so parallel guesses exceed the limit
- **Severity:** Low
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `SecureLoginServer.java:235-250`

**Vulnerable code:**
```java
// SecureLoginServer.java:235-250
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
```

**Why it is a problem:** The lock is checked, then a slow PBKDF2 verification runs, and only afterwards is the failure recorded. Requests arriving in parallel all pass `isLocked()` before any of them records a failure. With 16 workers, an attacker can fit up to about 15 extra guesses into each lockout window, roughly four times the documented limit of 5 per user. The per-IP limit is weakened the same way. The rate-limiting skill specifically calls for an atomic check-and-increment.

**Fix:** Reserve the attempt atomically before hashing (inside `ConcurrentHashMap.compute`) and clear the per-user counter on success.
```java
/** Atomically counts an attempt; returns false if the key is already locked. */
boolean tryAcquire(String key, int maxAttempts) {
    Instant now = Instant.now();
    boolean[] allowed = {false};
    entries.compute(key, (k, old) -> {
        if (old != null && old.lockedUntil().isAfter(now)) {
            return old;
        }
        int attempts = old == null || old.lastFailure().isBefore(now.minus(LOCKOUT_DURATION))
                ? 1 : old.failures() + 1;
        allowed[0] = true;
        return attempts >= maxAttempts
                ? new Entry(0, now.plus(LOCKOUT_DURATION), now)
                : new Entry(attempts, Instant.EPOCH, now);
    });
    return allowed[0];
}

// in login(): count the attempt before hashing
if (!throttle.tryAcquire(userKey, MAX_FAILED_ATTEMPTS_PER_USER)
        || !throttle.tryAcquire(ipKey, MAX_FAILED_ATTEMPTS_PER_IP)) {
    sendLoginPage(ex, 429, "Too many failed attempts. Please wait a few minutes and try again.");
    return;
}
... verify ...
if (valid) {
    throttle.reset(userKey);
}
```

### SEC-05: Same-origin check trusts the request's own Host header and passes when Origin/Sec-Fetch-Site are absent
- **Severity:** Low
- **CWE:** CWE-346: Origin Validation Error
- **Location:** `SecureLoginServer.java:327-341`

**Vulnerable code:**
```java
// SecureLoginServer.java:327-341
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
```

**Why it is a problem:** There are two weaknesses.

1. **The expected origin comes from the request's own `Host` header.** The check therefore only confirms `Origin == Host`, not that the request is for this application's real origin, and no Host allow-list exists anywhere. In the default plain-HTTP mode the server listens on `127.0.0.1:8080`. A malicious website can use DNS rebinding to point `evil.example` at `127.0.0.1`. The victim's browser then sends `Origin: http://evil.example:8080` with `Host: evil.example:8080`, which passes the check, and the attacker's script can read the responses. From the victim's machine it can:
   - guess passwords (the responses act as an oracle);
   - lock the local account (SEC-01);
   - use up the shared `127.0.0.1` per-IP budget, which blocks every local user.
2. **The check allows requests that carry neither `Sec-Fetch-Site` nor `Origin`.** The login form has no CSRF token, so login CSRF protection depends entirely on these headers. Browsers that omit them get no protection.

HTTPS mode limits the first issue, because rebinding breaks certificate name validation.

**Fix:** Validate `Host` against a configured allow-list on every request. Compare `Origin` with the configured public origin, and reject state-changing requests that carry neither header. Command-line clients such as the README's `curl` example then need `-H 'Origin: http://localhost:8080'`.
```java
// configured once, e.g. from APP_PUBLIC_ORIGIN (default "http://localhost:" + port)
private final String publicOrigin;
private final Set<String> allowedHosts; // e.g. Set.of("localhost:8080", "127.0.0.1:8080")

// at the start of handle(), before routing
String host = ex.getRequestHeaders().getFirst("Host");
if (host == null || !allowedHosts.contains(host.toLowerCase(Locale.ROOT))) {
    throw new HttpError(400, "Unknown host.");
}

private void verifySameOrigin(HttpExchange ex) {
    Headers h = ex.getRequestHeaders();
    String fetchSite = h.getFirst("Sec-Fetch-Site");
    if (fetchSite != null && !fetchSite.equals("same-origin") && !fetchSite.equals("none")) {
        throw new HttpError(403, "Cross-site request rejected.");
    }
    String origin = h.getFirst("Origin");
    if (origin == null && fetchSite == null) {
        // Fail closed: without either header the request's origin cannot be established.
        throw new HttpError(403, "Cross-site request rejected.");
    }
    if (origin != null && !origin.equalsIgnoreCase(publicOrigin)) {
        throw new HttpError(403, "Cross-site request rejected.");
    }
}
```

### SEC-06: Generated demo password is written to stdout/log output
- **Severity:** Low
- **CWE:** CWE-532: Insertion of Sensitive Information into Log File
- **Location:** `SecureLoginServer.java:146-148`

**Vulnerable code:**
```java
// SecureLoginServer.java:146-148
        if (generatedPassword) {
            log("No APP_DEMO_PASSWORD set. Demo account -> username: " + demoUsername
                    + "  password: " + demoPassword);
```

**Why it is a problem:** When `APP_DEMO_PASSWORD` is not set, the working password is printed through the normal `log()` channel on stdout. When the app runs under systemd, Docker, Kubernetes or a CI runner, stdout is captured and kept by log collectors that are often readable by many more people than the host. Anyone with log access can then sign in. The README warns against doing this "with real accounts", but the code does it by default without checking where stdout goes.

**Fix:** Don't send the secret through the logging channel. Show it only on an interactive terminal, and otherwise require the operator to set `APP_DEMO_PASSWORD`. On JDK 22+ also check `Console.isTerminal()`, because `System.console()` may return a non-null console when output is redirected.
```java
if (generatedPassword) {
    java.io.Console console = System.console();
    if (console != null) {
        // Shown once on the interactive terminal only; never written through log().
        console.printf("Demo account -> username: %s  password: %s%n", demoUsername, demoPassword);
    } else {
        fail("No interactive terminal: set APP_DEMO_PASSWORD instead of relying on a generated password.");
    }
} else {
    log("Demo account '" + demoUsername + "' loaded from environment.");
}
```

### SEC-07: No minimum strength for the configured account password
- **Severity:** Low
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `SecureLoginServer.java:105-113`

**Vulnerable code:**
```java
// SecureLoginServer.java:105-113
        String demoPassword = System.getenv("APP_DEMO_PASSWORD");
        boolean generatedPassword = demoPassword == null || demoPassword.isEmpty();
        if (generatedPassword) {
            demoPassword = randomToken().substring(0, 20);
        }
        if (demoUsername.isEmpty() || demoUsername.length() > MAX_USERNAME_LENGTH
                || demoPassword.length() > MAX_PASSWORD_LENGTH) {
            fail("Demo username or password has an invalid length.");
        }
```

**Why it is a problem:** Only a maximum length is enforced. `APP_DEMO_PASSWORD=a` or `APP_DEMO_PASSWORD=password` is accepted and becomes the account's password. Combined with the default username `alice` and the throttle weaknesses above (SEC-03, SEC-04), a weak password can be guessed within a few lockout windows. `addUser()` is the template for loading real users, and it has no policy hook either.

**Fix:** Enforce a minimum length (NIST SP 800-63B recommends at least 15 characters for single-factor passwords) and reject known-common passwords before hashing.
```java
static final int MIN_PASSWORD_LENGTH = 15;

String demoPassword = System.getenv("APP_DEMO_PASSWORD");
boolean generatedPassword = demoPassword == null || demoPassword.isEmpty();
if (generatedPassword) {
    demoPassword = randomToken().substring(0, 20);
}
if (demoUsername.isEmpty() || demoUsername.length() > MAX_USERNAME_LENGTH
        || demoPassword.length() < MIN_PASSWORD_LENGTH
        || demoPassword.length() > MAX_PASSWORD_LENGTH
        || CommonPasswords.contains(demoPassword)) {
    fail("Demo username or password is invalid: the password needs at least "
            + MIN_PASSWORD_LENGTH + " characters and must not be a common password.");
}
```

## 6. Verified Controls and Checks With No Finding
- **Password storage:** PBKDF2WithHmacSHA256 with 600,000 iterations, a 16-byte per-user salt from `SecureRandom` and a 256-bit output (lines 395-398, 425-440). This meets OWASP 2023 guidance. The password spec is cleared after use (line 438), and password char arrays are wiped (lines 245, 412).
- **Constant-time comparison:** the password hash (line 420) and the CSRF token (lines 297, 675-677) are compared with `MessageDigest.isEqual`.
- **Account enumeration:** unknown usernames are hashed against a dummy credential, so timing matches real accounts (lines 404-406, 416-423). Wrong username and wrong password both give the same `401` message (line 254). The lockout response does not reveal whether an account exists.
- **Session ID entropy and storage:** 256-bit `SecureRandom` tokens encoded as Base64URL (lines 680-684). IDs are stored only as SHA-256 hashes (lines 471-476), and incoming values must match a strict format before lookup (lines 79, 479, 497).
- **Session fixation:** any existing session is invalidated and a new ID issued on successful login (lines 264-266).
- **Session expiry and revocation:** 15-minute idle and 8-hour absolute timeouts are enforced on every lookup (lines 458-460, 488-491). Logout removes the server-side session and expires the cookie (lines 300-303). A background job purges expired sessions (lines 131-134).
- **Cookie attributes:** `__Host-` prefix, `Path=/`, `Secure`, `HttpOnly`, `SameSite=Strict`, no `Domain`, and no persistent expiry (lines 67, 365-372). The session value holds no user data. Cookie parsing matches the exact name (lines 374-389).
- **CSRF on authenticated actions:** logout requires POST (line 194), a per-session 256-bit token checked in constant time (lines 285, 296-299) and the Sec-Fetch-Site/Origin checks. `SameSite=Strict` stops the cookie being sent cross-site. Login CSRF residual risk is covered in SEC-05.
- **XSS / output encoding:** every dynamic value put into HTML goes through `escapeHtml`, which encodes `& < > " '` (lines 660-673). This covers:
  - error messages (line 203)
  - the username and timestamp (lines 281-282)
  - the CSRF token in an attribute (line 285)
  - login errors (line 307)
  - page titles (lines 656-657)

  No input is reflected without encoding. The CSP `default-src 'none'` blocks all script (lines 346-347).
- **Security headers:** CSP with `frame-ancestors 'none'`, `form-action 'self'` and `base-uri 'none'`, plus `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and `Cache-Control: no-store` on every response (lines 343-351). HSTS is sent in HTTPS mode (lines 352-354). Hardening note, not a finding: HSTS lacks `includeSubDomains`, but the `__Host-` prefix already stops cookies being planted from subdomains.
- **Transport security:** plain HTTP is refused on non-loopback addresses (lines 96-101). TLS is limited to TLSv1.3 and TLSv1.2 with JDK default cipher suites (line 575). The keystore password comes from the environment, not source, and is wiped after use (lines 555-581). No certificate validation is disabled (no custom TrustManager).
- **Hardcoded secrets:** none in source. Credentials come from environment variables or are generated randomly (lines 105-108, 555).
- **Client IP trust:** the per-IP key uses the socket address, not `X-Forwarded-For`, so it cannot be spoofed with headers (line 226). The README notes the proxy caveat.
- **Log injection:** usernames are reduced to printable ASCII before logging (lines 251, 267, 696-698). IPs come from the socket. The unexpected-exception log (line 206) does not echo request data to the client.
- **Error handling:** clients receive only generic messages, with no stack traces (lines 199-207).
- **Input handling and limits:** body limited to 4096 bytes (lines 614-620). The `application/x-www-form-urlencoded` Content-Type is required (lines 610-613). Malformed percent-encoding returns `400` (lines 633-635). Username and password lengths are bounded (lines 230-233). Duplicate parameters keep the first value (line 631). HTTP methods are enforced per route (lines 603-607).
- **Throttle memory bound:** the map is capped at 100,000 keys, and stale entries are purged every minute (lines 512, 525-527, 545-549). Once full, `recordFailure` stops recording new keys, which fails open. At the current PBKDF2 cost, the ~5-minute retention window cannot realistically reach the cap, so this is not reported as a finding, but it becomes relevant if hashing cost or limits change.
- **Open redirect / response splitting:** every `Location` value is a hard-coded constant (lines 179, 215, 268, 277, 303, 639-642). No user data reaches response headers.
- **Injection classes not present:** no SQL, LDAP, OS command execution, deserialization, XML parsing, templates or outbound network calls (no SSRF). The only file access is the operator-supplied keystore path from the environment (line 562), which clients cannot reach.
- **Non-code files:** `README.md`, `prompt.txt`, `cyber_prompt.txt`, `result.md`, `return.txt` and `prompt_hash.txt` contain no executable code or live secrets. The README's `change-me` keystore password appears only in a self-signed test-certificate example.
