# Security Review: LoginServer (Java session-cookie login web application)

## 1. Executive Summary
`LoginServer.java` is a self-contained JDK 17 web application built on `com.sun.net.httpserver.HttpServer`. It serves a login form, checks a username/password against an in-memory PBKDF2 hash store, issues a random `SESSIONID` cookie, protects a `/welcome` page and supports CSRF-protected logout. The other files in the folder are documentation and run metadata; they contain no executable code.

The code is well built for a demo. Passwords are hashed with PBKDF2-HMAC-SHA256 at 600,000 iterations. Session IDs have 256 bits of entropy. The session ID is replaced at each login, sessions have idle and absolute timeouts, and cookies are `HttpOnly`, `SameSite=Strict` and `Secure` by default. Output is HTML-escaped everywhere, a strict CSP is sent, and both forms carry CSRF tokens. No injection, XSS, broken session, or weak cryptography was found.

The weaknesses are in availability and abuse resistance, plus some deployment hardening:
- **Medium:**
  - The brute-force limiter counts failures only per exact client IP. It can be bypassed by rotating IPv6 addresses or using many hosts, and it has a check-then-act race (SEC-01).
  - Behind the TLS reverse proxy that the README recommends, every visitor shares one IP. Five failed logins by anyone then lock everyone out (SEC-02).
  - Anyone without an account can tie up the 16-thread worker pool with slow request bodies or 600k-iteration PBKDF2 requests (SEC-03).
- **Low:**
  - The app only speaks plain HTTP and sends no HSTS (SEC-04).
  - A generated password is printed to stdout, which often ends up in log files (SEC-05).
  - Security cookies have no `__Host-` prefix and duplicate cookie names are not detected (SEC-06).
  - Log sanitisation misses Unicode line-break and bidi characters (SEC-07).

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `LoginServer.java` | Entire application: HTTP routing, login and logout handlers, session store, PBKDF2 user store, brute-force limiter, form parsing, HTML rendering, security headers, logging | Authentication, password hashing (PBKDF2, salt, `SecureRandom`), session ID generation and expiry, cookie attributes, double-submit and per-session CSRF tokens, IP-based rate limiting, request body parsing and size limits, HTML output encoding, CSP and security headers, console logging of user input and the generated password, bind address and `COOKIE_SECURE` configuration |
| `README.md` | Plain-English guide to running and configuring the server | Documents the security defaults (`BIND_ADDRESS=127.0.0.1`, `COOKIE_SECURE`), recommends running behind a TLS reverse proxy (lines 141-149), and notes the shared-IP limiter problem |
| `result.md` | Run metadata and a summary of the generating session | None (documentation only) |
| `return.txt` | JSON metadata of the generating session | None (no secrets or credentials found) |
| `prompt.txt` | The original task prompt that produced the application | None |
| `cyber_prompt.txt` | The instructions for this security review | None |
| `prompt_hash.txt` | Empty file | None |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: the router workflow. It covered understanding each file, finding matching skills by name and description, applying them, and reporting.
- `testing-api-authentication-weaknesses`: applied to the whole login flow:
  - unauthenticated route exposure (`/welcome`),
  - session token entropy and server-side revocation on logout (lines 282, 377),
  - account enumeration through messages and timing (lines 228-232, 418-427),
  - credentials leaking into logs (lines 119-126, 230),
  - brute-force and credential-stuffing resistance (SEC-01, SEC-05, SEC-07).
- `performing-api-rate-limiting-bypass`: applied to `LoginRateLimiter` and how it picks a client key (lines 214-236, 473-517). Checks: IP rotation, whether spoofed `X-Forwarded-For` is trusted (it is not), path variations (exact `switch` match, so no bypass), and concurrency (SEC-01, SEC-02).
- `implementing-api-rate-limiting-and-throttling`: used as the reference for fixing SEC-01, SEC-02 and SEC-03. It covers per-account and per-IP keys, atomic sliding windows, and `Retry-After`.
- `performing-cryptographic-audit-of-application`: applied to:
  - `PasswordHasher`: algorithm, iterations, salt size, key length, constant-time compare (lines 438-466),
  - `SecureRandom` token generation (lines 65, 633-637),
  - hardcoded-secret search.
  No weaknesses found.
- `performing-csrf-attack-simulation`: applied to:
  - the double-submit token on the login form (lines 208-212, 289-292),
  - the per-session token on logout (lines 275-281),
  - `SameSite` attributes,
  - token removal, empty-token and cross-session token cases (`constantTimeEquals` rejects null or empty values, line 640).
  Led to SEC-06.
- `performing-security-headers-audit`: applied to `addSecurityHeaders` (CSP, X-Frame-Options, nosniff, Referrer-Policy, Cache-Control) and to `buildCookie`'s attributes and prefixes (lines 324-337, 565-572). Led to SEC-04 (no HSTS or TLS) and SEC-06 (no `__Host-` prefix).
- `testing-for-xss-vulnerabilities`: applied to every place data is written into HTML:
  - the username in the welcome page's HTML body context,
  - tokens in HTML attribute context,
  - error messages and the title,
  - the `escapeHtml` implementation and the CSP.
  No XSS found.
- `performing-clickjacking-attack-test`: applied to the frame-protection headers (`X-Frame-Options: DENY`, `frame-ancestors 'none'`). No finding.
- `testing-for-sensitive-data-exposure`: applied to:
  - cleartext transport (SEC-04),
  - credentials in console output and logs (SEC-05),
  - error-response detail (line 178 goes to stderr only, and the client gets a generic message),
  - caching of authenticated pages (`Cache-Control: no-store`).
- General OWASP Top 10 / CWE knowledge was used where no library skill matched:
  - how the JDK `HttpServer` worker pool behaves under slow clients (CWE-400, SEC-03),
  - lockout behaviour behind a shared proxy address (CWE-645, SEC-02),
  - Unicode log neutralisation (CWE-117, SEC-07),
  - form parsing: parameter pollution, body size cap, content type,
  - HTTP method enforcement and open-redirect review.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Brute-force protection is per exact IP only, can be reset, and can be raced | Medium | CWE-307 | `LoginServer.java:214` |
| SEC-02 | Behind the recommended reverse proxy, all clients share one lockout counter | Medium | CWE-645 | `LoginServer.java:214` |
| SEC-03 | Anyone without an account can exhaust the 16-thread worker pool (slow bodies, costly PBKDF2) | Medium | CWE-400 | `LoginServer.java:100` |
| SEC-04 | Credentials and session cookies can travel over cleartext HTTP; no HSTS | Low | CWE-319 | `LoginServer.java:84` |
| SEC-05 | Generated account password is written to stdout | Low | CWE-532 | `LoginServer.java:122` |
| SEC-06 | Security cookies have no `__Host-` prefix and duplicates are not detected (cookie injection) | Low | CWE-565 | `LoginServer.java:339` |
| SEC-07 | Log neutralisation misses Unicode line separators and bidi controls | Low | CWE-117 | `LoginServer.java:663` |

## 5. Detailed Findings

### SEC-01: Brute-force protection is per exact IP only, can be reset, and can be raced
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `LoginServer.java:214-236`, `LoginServer.java:476-499`

**Vulnerable code:**
```java
// LoginServer.java:214-236
        String clientKey = exchange.getRemoteAddress().getAddress().getHostAddress();
        if (rateLimiter.isBlocked(clientKey)) {
            exchange.getResponseHeaders().set("Retry-After",
                    String.valueOf(FAILED_LOGIN_WINDOW.toSeconds()));
            renderLoginForm(exchange, 429, "Too many failed attempts. Please wait and try again later.");
            return;
        }

        String username = form.getOrDefault("username", "");
        String password = form.getOrDefault("password", "");
        boolean inputAcceptable = !username.isEmpty() && !password.isEmpty()
                && username.length() <= MAX_USERNAME_LENGTH
                && password.length() <= MAX_PASSWORD_LENGTH;

        if (!inputAcceptable || !users.authenticate(username, password.toCharArray())) {
            rateLimiter.recordFailure(clientKey);
            log("Failed login for '" + username + "' from " + clientKey);
            // Deliberately vague: do not reveal whether the username exists.
            renderLoginForm(exchange, 401, "Invalid username or password.");
            return;
        }

        rateLimiter.reset(clientKey);
```

**Why it is a problem:** The only brute-force control is a counter keyed on the exact textual peer address. It can be bypassed in three ways.
1. **No per-account limit.** An attacker using many source addresses gets 5 guesses per address per 15 minutes against the same account. One IPv6 host normally controls a whole /64, which is 2^64 distinct keys. A botnet can spray passwords the same way.
2. **The check and the record are separate steps.** `isBlocked` runs first, then a PBKDF2 verification that takes hundreds of milliseconds, and only then `recordFailure`. Parallel requests from one IP all pass `isBlocked` before any failure is recorded, so one address can make far more than 5 guesses per window (up to the worker pool size in each burst).
3. **A success clears everything.** `rateLimiter.reset(clientKey)` wipes the whole failure history for that IP after any successful login. Once more users are added (the README explains how), an attacker with their own account can log in after every 4 guesses against a victim and never be blocked.

A generated demo password has 96 bits of entropy and resists guessing. A password chosen through `DEMO_PASSWORD`, or added users with human-chosen passwords, can be brute-forced.

**Fix:**
- Reserve each attempt atomically before the expensive check.
- Throttle both the client network (a /64 for IPv6) and the target account.
- On success, clear only the account counter, never the IP counter.
- To keep per-account limits from becoming a lockout DoS, prefer progressive delays or a CAPTCHA over a hard lock.

```java
// In handleLogin: parse the username first, then reserve attempts atomically
String username = form.getOrDefault("username", "");
String password = form.getOrDefault("password", "");
String clientKey = LoginRateLimiter.clientKey(exchange.getRemoteAddress().getAddress());
String accountKey = "user:" + UserStore.normalize(username);
if (!rateLimiter.tryAcquire(clientKey) || !rateLimiter.tryAcquire(accountKey)) {
    exchange.getResponseHeaders().set("Retry-After",
            String.valueOf(FAILED_LOGIN_WINDOW.toSeconds()));
    renderLoginForm(exchange, 429, "Too many failed attempts. Please wait and try again later.");
    return;
}
// ... authenticate as before; on failure do NOT record again (already counted) ...
rateLimiter.reset(accountKey); // on success: never clear the per-client counter

// In LoginRateLimiter
boolean tryAcquire(String key) {
    Instant now = Instant.now();
    boolean[] allowed = {false};
    failures.compute(key, (k, attempts) -> {
        Deque<Instant> list = attempts == null ? new ArrayDeque<>() : attempts;
        prune(list, now);
        if (list.size() < MAX_FAILED_LOGINS) {
            list.addLast(now); // counted before the slow hash, so parallel requests cannot race past it
            allowed[0] = true;
        }
        return list.isEmpty() ? null : list;
    });
    return allowed[0];
}

static String clientKey(InetAddress address) {
    byte[] bytes = address.getAddress();
    if (bytes.length == 16) { // IPv6: one subscriber usually owns the whole /64
        return "net:" + java.util.HexFormat.of().formatHex(bytes, 0, 8);
    }
    return "ip:" + address.getHostAddress();
}
```

### SEC-02: Behind the recommended reverse proxy, all clients share one lockout counter
- **Severity:** Medium
- **CWE:** CWE-645: Overly Restrictive Account Lockout Mechanism
- **Location:** `LoginServer.java:214-220` (deployment guidance in `README.md:141-149`)

**Vulnerable code:**
```java
// LoginServer.java:214-215
        String clientKey = exchange.getRemoteAddress().getAddress().getHostAddress();
        if (rateLimiter.isBlocked(clientKey)) {
```

**Why it is a problem:** The server has no TLS, so the README tells operators to put it behind nginx, Caddy or a cloud load balancer. In that setup the TCP peer of every request is the proxy. One anonymous attacker can then send five wrong passwords, which takes under a second and needs no knowledge of any account. After that, `isBlocked` returns true for every visitor, and nobody can log in for 15 minutes. Repeating this keeps the login page permanently unavailable. The README notes the effect but the code does nothing about it, and the recommended secure deployment is exactly the one that triggers it.

**Fix:** Derive the client address from a forwarding header only when the TCP peer is a configured trusted proxy. Use the right-most hop that the trusted proxy added, never client-supplied values. Combine this with the per-account throttling from SEC-01.
```java
private static final java.util.Set<String> TRUSTED_PROXIES =
        java.util.Set.of(env("TRUSTED_PROXIES", "").split(","));

static InetAddress clientAddress(HttpExchange exchange) throws java.net.UnknownHostException {
    InetAddress peer = exchange.getRemoteAddress().getAddress();
    if (!TRUSTED_PROXIES.contains(peer.getHostAddress())) {
        return peer; // direct connection: never trust forwarding headers
    }
    String xff = exchange.getRequestHeaders().getFirst("X-Forwarded-For");
    if (xff == null || xff.isBlank()) {
        return peer;
    }
    String[] hops = xff.split(",");
    String last = hops[hops.length - 1].trim(); // appended by our own proxy, not forgeable by the client
    if (!last.matches("[0-9A-Fa-f:.]+")) {
        return peer; // only accept IP literals, never hostnames
    }
    return InetAddress.getByName(last);
}

// in handleLogin
String clientKey = LoginRateLimiter.clientKey(clientAddress(exchange));
```

### SEC-03: Anyone without an account can exhaust the 16-thread worker pool (slow bodies, costly PBKDF2)
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `LoginServer.java:98-101`, `LoginServer.java:203-204`, `LoginServer.java:539-542`, `LoginServer.java:440`

**Vulnerable code:**
```java
// LoginServer.java:98-101
        HttpServer server = HttpServer.create(
                new InetSocketAddress(InetAddress.getByName(bindAddress), port), 0);
        ExecutorService workers = Executors.newFixedThreadPool(16);
        server.setExecutor(workers);
// LoginServer.java:203-204
    private void handleLogin(HttpExchange exchange) throws IOException, HttpError {
        Map<String, String> form = readForm(exchange);
// LoginServer.java:539-542
        byte[] raw;
        try (InputStream in = exchange.getRequestBody()) {
            raw = in.readNBytes(MAX_BODY_BYTES + 1);
        }
// LoginServer.java:440
        private static final int ITERATIONS = 600_000;
```

**Why it is a problem:** Every request runs on one of 16 worker threads. `handleLogin` reads the body first, before the CSRF check or the rate limiter, with a blocking `readNBytes`. The JDK `HttpServer` sets no per-request read timeout by default (`sun.net.httpserver.maxReqTime` is disabled). So 16 connections that each announce `Content-Length: 4096` and then send one byte every few seconds hold every worker indefinitely. That is a Slowloris-style outage of the whole site from a single client.

Separately, anyone can make the server run a 600,000-iteration PBKDF2 (hundreds of milliseconds of CPU) per request. Getting past the double-submit check only requires sending matching `LOGIN_CSRF` cookie and `csrf` field values of the attacker's choosing. Because the limiter only counts per IP (SEC-01), a distributed client can keep all workers busy hashing.

The default loopback bind reduces exposure, but any network deployment is affected.

**Fix:**
- Bound how long a client may take to send a request.
- Limit how many password hashes run at once and shed extra load with 503 instead of queueing.
- In production, also enforce client header and body timeouts at the reverse proxy.
```java
// In main, before HttpServer.create(...)
System.setProperty("sun.net.httpserver.maxReqTime", "10"); // seconds to receive a full request
System.setProperty("sun.net.httpserver.maxRspTime", "10"); // seconds to send the response

// In LoginServer
private static final java.util.concurrent.Semaphore HASH_PERMITS = new java.util.concurrent.Semaphore(4);

// In handleLogin, replacing the direct authenticate call
if (!HASH_PERMITS.tryAcquire()) {
    exchange.getResponseHeaders().set("Retry-After", "5");
    renderLoginForm(exchange, 503, "The server is busy. Please try again shortly.");
    return;
}
boolean authenticated;
try {
    authenticated = inputAcceptable && users.authenticate(username, password.toCharArray());
} finally {
    HASH_PERMITS.release();
}
```

### SEC-04: Credentials and session cookies can travel over cleartext HTTP; no HSTS
- **Severity:** Low
- **CWE:** CWE-319: Cleartext Transmission of Sensitive Information
- **Location:** `LoginServer.java:83-84`, `LoginServer.java:98-99`, `LoginServer.java:565-572`

**Vulnerable code:**
```java
// LoginServer.java:83-84
        String bindAddress = env("BIND_ADDRESS", "127.0.0.1");
        boolean secureCookies = !"false".equalsIgnoreCase(env("COOKIE_SECURE", "true"));
// LoginServer.java:565-572
    private static void addSecurityHeaders(Headers headers) {
        headers.set("Cache-Control", "no-store");
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-Frame-Options", "DENY");
        headers.set("Referrer-Policy", "no-referrer");
        headers.set("Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    }
```

**Why it is a problem:** The server only implements plain HTTP.
- If `BIND_ADDRESS` is set to a routable address (for example `0.0.0.0`), the login form sends usernames and passwords in cleartext, and anyone on the network can read them.
- `COOKIE_SECURE=false` is accepted for any bind address, not just loopback, and only prints a warning. The session cookie then goes over HTTP and can be stolen and replayed.
- No `Strict-Transport-Security` header is ever sent. Even behind a TLS proxy, a first visit or a typed `http://` URL can be SSL-stripped.

The secure default (`127.0.0.1`, `Secure` cookies) keeps this Low, but nothing stops an unsafe configuration.

**Fix:** Refuse unsafe combinations at startup, and send HSTS (browsers ignore it over plain HTTP, so it is safe to send always).
```java
// In main, before creating the server
InetAddress bind = InetAddress.getByName(bindAddress);
boolean behindTlsProxy = "true".equalsIgnoreCase(env("BEHIND_TLS_PROXY", "false"));
if (!bind.isLoopbackAddress() && !behindTlsProxy) {
    throw new IllegalStateException("Refusing to accept passwords over plain HTTP on " + bindAddress
            + "; terminate TLS in front of the server and set BEHIND_TLS_PROXY=true");
}
if (!secureCookies && !bind.isLoopbackAddress()) {
    throw new IllegalStateException("COOKIE_SECURE=false is only allowed on a loopback address");
}

// In addSecurityHeaders
headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
```

### SEC-05: Generated account password is written to stdout
- **Severity:** Low
- **CWE:** CWE-532: Insertion of Sensitive Information into Log File
- **Location:** `LoginServer.java:121-123`

**Vulnerable code:**
```java
// LoginServer.java:121-123
        if (passwordGenerated) {
            System.out.println("  Password: " + demoPassword
                    + "   (randomly generated; set DEMO_PASSWORD to choose your own)");
```

**Why it is a problem:** The plaintext password of the only account is printed to standard output. The same stream carries the application log (the `log()` method at line 663). When the server runs under systemd, Docker, Kubernetes, `nohup`, or a CI job, stdout is saved to the journal, container logs or a log aggregator. Anyone with read access to those logs, often a much wider group than the server's administrators, gets working credentials. The rest of the code avoids keeping plaintext passwords, so this undoes that effort.

**Fix:** Show a generated password only on an interactive terminal, never on redirected stdout. Otherwise require `DEMO_PASSWORD`. Run this check before `server.start()`.
```java
if (passwordGenerated) {
    java.io.Console console = System.console(); // on JDK 22+ also require console.isTerminal()
    if (console == null) {
        throw new IllegalStateException(
                "No interactive terminal: set DEMO_PASSWORD instead of relying on a generated password");
    }
    // Written to the terminal only, so it never lands in redirected stdout or log files.
    console.printf("  Password: %s   (randomly generated; shown once)%n", demoPassword);
}
```

### SEC-06: Security cookies have no `__Host-` prefix and duplicates are not detected (cookie injection)
- **Severity:** Low
- **CWE:** CWE-565: Reliance on Cookies without Validation and Integrity Checking
- **Location:** `LoginServer.java:51-52`, `LoginServer.java:208-209`, `LoginServer.java:339-349`

**Vulnerable code:**
```java
// LoginServer.java:51-52
    private static final String SESSION_COOKIE = "SESSIONID";
    private static final String LOGIN_CSRF_COOKIE = "LOGIN_CSRF";
// LoginServer.java:339-349
    private static String readCookie(HttpExchange exchange, String name) {
        for (String header : exchange.getRequestHeaders().getOrDefault("Cookie", java.util.List.of())) {
            for (String part : header.split(";")) {
                int eq = part.indexOf('=');
                if (eq > 0 && part.substring(0, eq).trim().equals(name)) {
                    return part.substring(eq + 1).trim();
                }
            }
        }
        return null;
    }
```

**Why it is a problem:** The login CSRF check is a plain double-submit: any cookie value that matches the form field is accepted (line 209). The cookies have no `__Host-` prefix, so they can be planted by:
- a sibling subdomain (`Domain=.example.com`),
- a network attacker injecting `Set-Cookie` into a plain-HTTP response for the host.

Such an attacker can:
- plant `LOGIN_CSRF=x; SameSite=None` and submit a cross-site form with `csrf=x`, logging the victim into the attacker's account (login CSRF), or
- plant `SESSIONID=<attacker session>; Path=/welcome`. When several cookies share a name, browsers send the one with the more specific path first. `readCookie` returns the first match, so the victim silently uses the attacker's session even after logging in themselves.

The app currently stores no user data, so the impact is limited, but either trick undermines the CSRF and session-fixation defences.

**Fix:** When cookies are secure, use the `__Host-` prefix so browsers only accept the cookie from a secure origin with `Path=/` and no `Domain`. Move the login CSRF cookie to `Path=/`, and treat duplicate cookie names as hostile.
```java
private final String sessionCookie;
private final String loginCsrfCookie;

LoginServer(UserStore users, boolean secureCookies) {
    this.users = users;
    this.secureCookies = secureCookies;
    // __Host- cookies can only be set by a secure origin, for Path=/ and without Domain,
    // so a sibling subdomain or a plain-HTTP attacker cannot plant or shadow them.
    String prefix = secureCookies ? "__Host-" : "";
    this.sessionCookie = prefix + "SESSIONID";
    this.loginCsrfCookie = prefix + "LOGIN_CSRF";
}

// renderLoginForm / handleLogin: the __Host- prefix requires Path=/
exchange.getResponseHeaders().add("Set-Cookie",
        buildCookie(loginCsrfCookie, csrfToken, "/", LOGIN_FORM_LIFETIME.toSeconds()));

private static String readCookie(HttpExchange exchange, String name) {
    String found = null;
    for (String header : exchange.getRequestHeaders().getOrDefault("Cookie", java.util.List.of())) {
        for (String part : header.split(";")) {
            int eq = part.indexOf('=');
            if (eq > 0 && part.substring(0, eq).trim().equals(name)) {
                if (found != null) {
                    return null; // duplicate names indicate cookie injection: trust neither value
                }
                found = part.substring(eq + 1).trim();
            }
        }
    }
    return found;
}
```

### SEC-07: Log neutralisation misses Unicode line separators and bidi controls
- **Severity:** Low
- **CWE:** CWE-117: Improper Output Neutralization for Logs
- **Location:** `LoginServer.java:230`, `LoginServer.java:661-664`

**Vulnerable code:**
```java
// LoginServer.java:230
            log("Failed login for '" + username + "' from " + clientKey);
// LoginServer.java:661-664
    private static void log(String message) {
        // Strip control characters so user input cannot forge extra log lines.
        System.out.println(Instant.now() + " " + message.replaceAll("\\p{Cntrl}", "?"));
    }
```

**Why it is a problem:** In `java.util.regex`, `\p{Cntrl}` is the POSIX class `[\x00-\x1F\x7F]` and only covers ASCII. The username is URL-decoded as UTF-8, so an attacker can submit `%C2%85` (U+0085 NEL), `%E2%80%A8` (U+2028 LINE SEPARATOR), or bidi overrides such as U+202E. These pass through unchanged. Many log viewers, SIEM parsers and line-splitting tools (for example Python's `splitlines`, and JSON/JavaScript-based viewers) treat NEL, LS and PS as line breaks. That lets an attacker forge entries such as a fake `Successful login for 'admin'` line, or visually reorder text to mislead investigators. Also, users often type their password into the username field by mistake, and the failed-login log records it verbatim.

**Fix:** Neutralise all Unicode control (`Cc`), format (`Cf`, which includes bidi overrides) and line or paragraph separator characters.
```java
private static void log(String message) {
    // Replace ASCII/C1 controls, Unicode format chars (bidi overrides) and line/paragraph separators,
    // so user input cannot forge or visually disguise log lines.
    String safe = message.replaceAll("[\\p{Cc}\\p{Cf}\\u2028\\u2029]", "?");
    System.out.println(Instant.now() + " " + safe);
}
```

## 6. Verified Controls and Checks With No Finding
- **Password storage:**
  - `PasswordHasher` uses PBKDF2WithHmacSHA256 with 600,000 iterations, which meets OWASP's 2023 minimum (lines 439-442).
  - Each password gets a 16-byte random salt from `SecureRandom` (lines 445-446) and a 256-bit derived key.
  - Hashes are compared in constant time with `MessageDigest.isEqual` (line 452).
  - Password `char[]` buffers are zeroed after use (lines 462-463).
  - No plaintext passwords are kept (line 421).
- **Randomness:**
  - A single `SecureRandom` is used for every token (line 65).
  - Session IDs and per-session CSRF tokens are 32 random bytes each (256 bits), URL-safe Base64 (lines 377, 633-637).
  - No `java.util.Random`, `Math.random` or time-based seeds.
- **Hardcoded secrets:** none. The demo password is random or taken from the environment (lines 87-91). `return.txt` and `result.md` contain no credentials.
- **Account enumeration:**
  - Unknown usernames and wrong passwords get the same message and status code (line 232).
  - A dummy hash is checked when the user does not exist, so response time is the same (lines 418, 424-427).
  - The input-length short-circuit (lines 224-226) does not depend on whether the account exists.
- **Session management:**
  - A new session ID is issued and any old one invalidated at each login, which prevents session fixation (lines 240-244).
  - Logout invalidates the session on the server (line 282).
  - Sessions have a 30-minute idle timeout and an 8-hour absolute timeout, both enforced on each lookup and by the scheduled purge (lines 54-55, 366-369, 391-394, 403-406).
  - The session cookie has no `Max-Age`, so it is a true browser-session cookie (line 247).
  - One observation with no finding: sessions per user are not capped. Only authenticated users can create sessions, so this is not exploitable without credentials.
- **Cookie attributes:** every cookie gets `HttpOnly`, `SameSite=Strict`, and `Secure` by default (lines 324-337). Cookie values are server-generated Base64url, so no header injection is possible through them.
- **CSRF:**
  - The login form uses a double-submit token (lines 208-212).
  - Logout requires the per-session token, compared in constant time (lines 279-281).
  - `constantTimeEquals` rejects null or empty values, so the cleared cookie (`LOGIN_CSRF=`) cannot be matched by an empty field (line 640).
  - State changes only happen on POST (lines 159-160, 170).
  - The remaining weakness is under SEC-06.
- **XSS and output encoding:**
  - Every value placed into HTML goes through `escapeHtml`, which encodes `& < > " '` (lines 646-659). That covers the username (line 269), timestamps, CSRF tokens in attributes (lines 271, 306), error messages (lines 294, 598) and the title (line 626).
  - User data is only passed as `formatted` arguments, never as the format string.
  - The CSP is `default-src 'none'` with no script source (line 571), which gives defence in depth.
- **Clickjacking:** `X-Frame-Options: DENY` and `frame-ancestors 'none'` are sent on HTML responses and redirects (lines 568, 571, 578, 588).
- **Caching and referrer leaks:** `Cache-Control: no-store` and `Referrer-Policy: no-referrer` are set on every HTML and redirect response (lines 566, 569). Tokens are never placed in URLs.
- **Open redirect and Host header:** `redirect` is only ever called with constant relative paths (`/welcome`, `/login`). The `Host` header and request URLs are never reflected.
- **Rate-limit bypass through headers or paths:**
  - `X-Forwarded-For`-style headers are not trusted, so spoofing them does nothing (line 214).
  - Routing uses an exact `switch` on the path (line 151), so variants such as `/login/` or `/LOGIN` get 404 instead of skipping the limiter.
- **Request parsing:**
  - `Content-Type` must be `application/x-www-form-urlencoded` (line 535).
  - The body is capped at 4096 bytes (lines 541-544).
  - Malformed percent-encoding returns 400 (lines 559-560).
  - Duplicate parameters keep the first value (line 557), so there is no parameter pollution.
  - Username and password lengths are bounded (lines 224-226).
- **Error handling:**
  - Unexpected exceptions are logged to stderr, and the client gets a generic message with no stack trace (lines 177-179).
  - `sendErrorIfPossible` avoids writing twice (line 593).
- **HTTP methods:** each route enforces its allowed methods and returns 405 otherwise (lines 153, 157-163, 166, 170, 185-189).
- **Network exposure default:** the server binds to `127.0.0.1` by default (line 83).
- **Categories not present in the code:** no SQL or NoSQL queries, OS command execution, file-system path handling, deserialization, XML parsing, outbound network calls (SSRF), JWTs or third-party dependencies, so injection, XXE, deserialization, SSRF and supply-chain checks do not apply.
- **Non-code files:** `README.md`, `result.md`, `return.txt`, `prompt.txt`, `cyber_prompt.txt` and `prompt_hash.txt` were read. They are documentation, prompts or metadata with no executable content and no secrets.
