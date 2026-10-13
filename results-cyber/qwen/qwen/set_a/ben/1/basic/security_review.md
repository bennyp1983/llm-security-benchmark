# Security Review: session-cookie-demo

## 1. Executive Summary

The code under review is a Java 17 / Servlet 6.0 web application (`session-cookie-demo`, WAR packaging) that demonstrates server-side session management: a `LoginServlet` "completes" an assumed-successful authentication by issuing a 256-bit `SecureRandom` session identifier and attaching it to an `SESSION_ID` cookie; `ProfileServlet` validates the cookie against an in-memory `ConcurrentHashMap`-backed `SessionStore`; `LogoutServlet` revokes the session server-side and expires the cookie client-side. Cookie hygiene is largely good (HttpOnly, SameSite=Lax, Secure-on-TLS, 8h lifetime, high-entropy tokens, server-side validation, no session fixation). The most important findings are: (1) the "login" endpoint is completely unauthenticated and issues a valid session for **any** user name taken from a request parameter, allowing impersonation of any account; (2) unescaped user input is concatenated into JSON responses (JSON injection / broken output encoding); (3) the unauthenticated login endpoint feeds an unbounded, never-expiring in-memory session store, enabling memory-exhaustion DoS and indefinite replay of stolen session IDs; (4) state-changing endpoints (`/login`, `/logout`) are reachable via GET and unauthenticated, enabling CSRF-style drive-by logout/login; (5) nothing enforces TLS, so over plain HTTP the session token is transmitted in cleartext.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/session/SessionCookieUtil.java` | Builds, reads, and expires the `SESSION_ID` session cookie | Cookie attribute setting (HttpOnly/Secure/SameSite/Path/Max-Age); extraction of session ID from client-supplied cookies |
| `src/main/java/com/example/session/LoginServlet.java` | Stands in for the end of a successful authentication; issues the session | Reads untrusted `user` request parameter and registers a session for it with **no credential check**; concatenates unescaped user input into a JSON response; accepts both GET and POST |
| `src/main/java/com/example/session/SessionStore.java` | In-memory thread-safe registry of issued sessions | 256-bit `SecureRandom` identifier generation; unbounded `ConcurrentHashMap` with no server-side expiry or cleanup |
| `src/main/java/com/example/session/ProfileServlet.java` | Reports the authenticated session (200) or its absence (401) | Validates session ID against the server-side store (server-side session validation); reflects stored user into JSON |
| `src/main/java/com/example/session/LogoutServlet.java` | Ends the session | Revokes session server-side, expires cookie client-side; reachable via GET |
| `src/main/webapp/index.html` | Static demo landing page with links to the three endpoints | None (static markup, no scripts or user input) |
| `src/main/webapp/WEB-INF/web.xml` | Servlet mappings; restricts container session tracking to cookies | No `<security-constraint>` or HTTPS enforcement for any endpoint |
| `pom.xml` | Maven build; only dependency is `jakarta.servlet-api` (provided scope) | No third-party runtime dependencies |

## 3. Skills Applied

- No specialised skill in the library clearly matched a **static** review of a Java servlet session-management codebase. The closest candidates (`performing-web-application-penetration-test`, `testing-for-xss-vulnerabilities`, `testing-api-authentication-weaknesses`, `exploiting-api-injection-vulnerabilities`, `exploiting-oauth-misconfiguration`) are all dynamic testing/pentest skills requiring a running target and were therefore not applicable to a read-only static review.
- All security-relevant behaviours were therefore reviewed against general OWASP Top 10 / CWE knowledge: A07 (Identification and Authentication Failures), A03 (Injection), A05 (Security Misconfiguration), A04 (Insecure Design), A10 (Cryptographic Failures), A08 (Software and Data Integrity Issues), and the session-management guidance in OWASP A01/A07.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Unauthenticated login issues a valid session for any user name | High | CWE-287 | `src/main/java/com/example/session/LoginServlet.java:43` |
| SEC-02 | JSON injection / broken output encoding of user-supplied value | Medium | CWE-116 | `src/main/java/com/example/session/LoginServlet.java:58` |
| SEC-03 | Unbounded, never-expiring in-memory session store behind unauthenticated endpoint | Medium | CWE-770 | `src/main/java/com/example/session/SessionStore.java:64` |
| SEC-04 | State-changing endpoints reachable via unauthenticated GET (CSRF / drive-by) | Low | CWE-352 | `src/main/java/com/example/session/LogoutServlet.java:17` |
| SEC-05 | No TLS enforcement; session token transmitted in cleartext over HTTP | Low | CWE-319 | `src/main/java/com/example/session/SessionCookieUtil.java:50` |

## 5. Detailed Findings

### SEC-01: Unauthenticated login issues a valid session for any user name
- **Severity:** High
- **CWE:** CWE-287: Improper Authentication (see also CWE-306: Missing Authentication for Critical Function)
- **Location:** `src/main/java/com/example/session/LoginServlet.java:43-50`

**Vulnerable code:**
```java
// src/main/java/com/example/session/LoginServlet.java:41-50
    private void handle(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String user = request.getParameter("user");
        if (user == null || user.isEmpty()) {
            user = DEFAULT_USER;
        }

        // "Authentication succeeded": register the session for the user.
        // The returned identifier is the session identifier we need.
        String sessionId = SessionStore.INSTANCE.issue(user);
```

**Why it is a problem:** The endpoint assumes authentication has succeeded and takes the authenticated identity from a client-supplied request parameter with no credential verification, no rate limiting, and no distinction between anonymous and authenticated callers. Any unauthenticated client can call `GET /login?user=<victim>` and receive a fully valid session (and its 256-bit session ID) impersonating any user name they choose (e.g. an administrator or another customer), who then passes the `ProfileServlet` validation at `ProfileServlet.java:21` exactly as if they had authenticated. This is a complete authentication bypass and, combined with SEC-03, also doubles as the unauthenticated DoS trigger.

**Fix:** Move identity assignment behind a real authentication step: the user must come from verified credentials (an authenticated principal, a validated form post, an IdP assertion), never from a client parameter; and reject (401/403) any session issuance without it.
```java
private void handle(HttpServletRequest request, HttpServletResponse response)
        throws IOException {
    // Identity must come from a verified authentication step, e.g.
    // request.getUserPrincipal() after a real credential check, or a
    // validated, signed assertion. Never trust a client-supplied name.
    Principal principal = request.getUserPrincipal();
    if (principal == null) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().print("{\"authenticated\":false}");
        return;
    }
    String user = principal.getName();
    String sessionId = SessionStore.INSTANCE.issue(user);
    SessionCookieUtil.addSessionCookie(request, response, sessionId);
    response.setStatus(HttpServletResponse.SC_OK);
    // ...
}
```

### SEC-02: JSON injection / broken output encoding of user-supplied value
- **Severity:** Medium
- **CWE:** CWE-116: Improper Encoding or Escape of Output
- **Location:** `src/main/java/com/example/session/LoginServlet.java:58-60` (and `src/main/java/com/example/session/ProfileServlet.java:30-31`)

**Vulnerable code:**
```java
// src/main/java/com/example/session/LoginServlet.java:58-60
        response.getWriter().print("{\"authenticated\":true,"
                + "\"user\":\"" + user + "\","
                + "\"sessionId\":\"" + sessionId + "\"}");
```

**Why it is a problem:** `user` is taken directly from `request.getParameter("user")` (`LoginServlet.java:43`) and concatenated into a JSON document without escaping. A value such as `x","role":"admin","user":"` closes the `user` string and injects arbitrary JSON fields, while a bare `"` or control character produces malformed JSON that breaks downstream clients. Because the same unescaped value is stored in the session and reflected again by `ProfileServlet` (`ProfileServlet.java:30-31`), an attacker can persist a crafted payload on the server: `GET /login?user=%22%2C%22admin%22%3Atrue%2C%22user%22%3A%22x` makes `/profile` answer `{"authenticated":true,"admin":true,...}`, which can escalate privileges in any client that authorizes on JSON fields or reflects them into HTML (downstream XSS).

**Fix:** Serialize JSON with a library (e.g. Jackson) instead of string concatenation, or at minimum escape quotes, backslashes, and control characters in every interpolated value.
```java
// Using Jackson (add com.fasterxml.jackson.core:jackson-databind):
ObjectNode body = ObjectNodeFactory... // simplified:
Map<String, Object> payload = Map.of(
        "authenticated", true,
        "user", user,
        "sessionId", sessionId);
response.getWriter().print(new ObjectMapper().writeValueAsString(payload));
```

### SEC-03: Unbounded, never-expiring in-memory session store behind unauthenticated endpoint
- **Severity:** Medium
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `src/main/java/com/example/session/SessionStore.java:60-66` (with `LoginServlet.java:50`)

**Vulnerable code:**
```java
// src/main/java/com/example/session/SessionStore.java:60-66
    public String issue(String user) {
        byte[] raw = new byte[IDENTIFIER_BYTES];
        RANDOM.nextBytes(raw);
        String sessionId = ENCODER.encodeToString(raw);
        sessions.put(sessionId, new IssuedSession(user, Instant.now()));
        return sessionId;
    }
```

**Why it is a problem:** `issue()` is called from the unauthenticated, GET-reachable `LoginServlet` (`LoginServlet.java:50`), and each call inserts an entry that is only ever removed by an explicit `revoke()` on logout. There is no server-side absolute or idle timeout, no maximum session count, and no cleanup task, so (a) an attacker can exhaust JVM heap by repeatedly calling `/login`, and (b) every issued session ID stays valid indefinitely — a stolen identifier can be replayed far beyond the client cookie's 8-hour `Max-Age` (the client stops sending it, but the server still accepts it), which also defeats the expectation that "lives for 8 hours" (`SessionCookieUtil.java:25`) is honored server-side.

**Fix:** Enforce server-side lifetimes and bounds: store an expiry, evict on lookup, and cap store size (or move to a bounded store such as Redis with TTL).
```java
private static final long MAX_LIFETIME_SECONDS = 8 * 60 * 60;

public String issue(String user) {
    byte[] raw = new byte[IDENTIFIER_BYTES];
    RANDOM.nextBytes(raw);
    String sessionId = ENCODER.encodeToString(raw);
    sessions.put(sessionId, new IssuedSession(user, Instant.now()));
    evictExpired(); // also run periodically
    return sessionId;
}

public IssuedSession lookup(String sessionId) {
    if (sessionId == null) {
        return null;
    }
    IssuedSession s = sessions.get(sessionId);
    if (s == null
            || Duration.between(s.getIssuedAt(), Instant.now())
                    .compareTo(Duration.ofSeconds(MAX_LIFETIME_SECONDS)) > 0) {
        sessions.remove(sessionId);
        return null;
    }
    return s;
}
```

### SEC-04: State-changing endpoints reachable via unauthenticated GET (CSRF / drive-by)
- **Severity:** Low
- **CWE:** CWE-352: Cross-Site Request Forgery
- **Location:** `src/main/java/com/example/session/LogoutServlet.java:17-20` (and `LoginServlet.java:29-33`)

**Vulnerable code:**
```java
// src/main/java/com/example/session/LogoutServlet.java:16-20
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        handle(request, response);
    }
```

**Why it is a problem:** Logout revokes a server-side session (a state-changing operation) but is triggered by a plain GET with no CSRF token, no SameSite-relying check, and no authentication requirement; `/login` is the same. An attacker can drive-by these endpoints: an `<img src="https://victim.example/logout">` tag or a link on a malicious page logs the victim out (session DoS) or — because `/login` is GET-reachable — forces a fresh session for an attacker-controlled `user` value into the victim's browser. The SameSite=Lax cookie attribute only partially mitigates this (Lax still sends the cookie on top-level navigations), and the underlying design flaw is that a non-idempotent action sits on a simple GET.

**Fix:** Require POST (with a CSRF token) for state-changing endpoints, and remove the GET handler; for `/logout` at least restrict it to POST.
```java
@Override
protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws IOException {
    response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
}

@Override
protected void doPost(HttpServletRequest request, HttpServletResponse response)
        throws IOException {
    // Verify a site-bound, per-session CSRF token before proceeding.
    if (!isValidCsrfToken(request)) {
        response.sendError(HttpServletResponse.SC_FORBIDDEN);
        return;
    }
    handle(request, response);
}
```

### SEC-05: No TLS enforcement; session token transmitted in cleartext over HTTP
- **Severity:** Low
- **CWE:** CWE-319: Cleartext Transmission of Sensitive Information
- **Location:** `src/main/java/com/example/session/SessionCookieUtil.java:50` (with `src/main/webapp/WEB-INF/web.xml` lacking any `<security-constraint>`)

**Vulnerable code:**
```java
// src/main/java/com/example/session/SessionCookieUtil.java:50
        cookie.setSecure(request.isSecure());    // only sent over TLS
```

**Why it is a problem:** The `Secure` attribute is set conditionally on whether the *current* request happened to be TLS. Nothing in the application enforces HTTPS — `web.xml` declares no `<security-constraint>` with `transport-guarantee=CONFIDENTIAL` and no redirect from HTTP to HTTPS. If the WAR is ever deployed (or proxied) on plain HTTP, the session identifier is set and sent without the `Secure` flag, travelling in cleartext in Cookie headers where it can be captured on the network or by an on-path MITM, giving full session takeover.

**Fix:** Enforce TLS at the application (and/or container) level and always set `Secure` for the session cookie.
```java
// web.xml:
<security-constraint>
    <web-resource-collection>
        <web-resource-name>Session endpoints</web-resource-name>
        <url-pattern>/*</url-pattern>
    </web-resource-collection>
    <user-data-constraint>
        <transport-guarantee>CONFIDENTIAL</transport-guarantee>
    </user-data-constraint>
</security-constraint>
```
```java
// SessionCookieUtil.addSessionCookie():
cookie.setSecure(true); // session cookies are always Secure in this app
```

## 6. Verified Controls and Checks With No Finding

- **Session identifier entropy and generation:** 32 bytes from `java.security.SecureRandom`, URL-safe Base64 without padding (`SessionStore.java:20-24, 60-63`) — 256 bits of CSPRNG output; no predictable or time-based IDs (no CWE-330/640 concern).
- **Server-side session validation:** `ProfileServlet` treats the cookie as an opaque token and rejects any identifier the server does not know with HTTP 401 (`ProfileServlet.java:20-27`) — the session is not a client-side claim.
- **Session fixation resistance:** a fresh, random identifier is issued on every login call and no pre-authentication session identifier is ever reused or carried over (`LoginServlet.java:50`).
- **HttpOnly flag:** set on both the issued and the expiring cookie, so JavaScript cannot read the session ID (`SessionCookieUtil.java:49, 87`).
- **SameSite=Lax:** set via the Servlet 6.0 cookie attribute, reducing cross-site request cookie sending (`SessionCookieUtil.java:52`).
- **Cookie scoping and expiry on logout:** `Path=/` limits the cookie to the application; logout revokes the session server-side (`LogoutServlet.java:31`) *and* expires the client cookie with matching name/path/Max-Age 0 (`LogoutServlet.java:32`, `SessionCookieUtil.java:83-91`).
- **Container session tracking:** `web.xml` restricts tracking mode to `COOKIE`, preventing `;jsessionid=` URL rewriting (`WEB-INF/web.xml:37-39`).
- **No other attack surface:** no SQL or query construction, no OS command execution, no deserialization, no file/path handling, no outbound network calls, no hardcoded secrets or credentials in any file; `index.html` is static markup with no scripts; the only dependency is the provided-scope `jakarta.servlet-api` (`pom.xml`).
