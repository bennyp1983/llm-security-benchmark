# Security Review: Jakarta Servlet Session Cookie Component

## 1. Executive Summary
The codebase under review implements an authenticated session management component for Java web applications using the Jakarta Servlet API 6.0 (Jakarta EE 10). Its primary responsibilities include issuing hardened session cookies following successful authentication (`doPost`), verifying active sessions across requests (`doGet`), and invalidating sessions and purging cookies on logout (`doDelete`). It provides defense-in-depth cookie attributes (`HttpOnly`, `Secure`, `SameSite=Strict`, `__Host-` prefixing, host-only scoping), anti-caching HTTP response headers, and session ID octet validation to prevent CRLF injection.

However, several significant security vulnerabilities were identified in the session management and lifecycle handling:
1. **Session Fixation via Untrusted Client Input (CWE-384 / CWE-20)**: The session resolver reads session identifiers directly from unauthenticated client-controlled HTTP headers and query/POST parameters.
2. **Defective Session Fixation Rotation (CWE-384 / CWE-670)**: When an existing session is rotated via `request.changeSessionId()`, the return value is discarded, causing the servlet to issue the pre-rotation session identifier in the `Set-Cookie` header.
3. **Session Identifier Exposure Bypassing HttpOnly (CWE-200 / CWE-1004)**: The `GET /auth/session` endpoint reflects the full session identifier in the JSON response body, enabling any client-side script running in the application origin (via XSS) to retrieve the token via a simple `fetch()` call.
4. **Missing Server-Side Session Validation (CWE-287)**: `doGet` determines authentication status solely based on cookie syntax validation without checking active session state in the servlet container.
5. **Missing Anti-Caching Headers on Session Verification (CWE-525)**: The `doGet` endpoint omits anti-caching headers, allowing intermediate proxies or browser caches to store responses containing session status and tokens.
6. **Incomplete Cookie Purging on Logout (CWE-613)**: The cookie clearing logic hardcodes `Path="/"`, failing to remove cookies scoped to context paths in non-root servlet deployments.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `SessionCookieServlet.java` / `src/main/java/com/example/auth/SessionCookieServlet.java` | Jakarta Servlet 6.0 implementation managing session cookie creation, verification, and termination. | Resolves session IDs from attributes/headers/parameters; rotates sessions via `changeSessionId()`; configures cookie security flags (`HttpOnly`, `Secure`, `SameSite`, `Path`, `__Host-`); validates session ID regex against CRLF; applies anti-caching headers; handles `POST`, `GET`, and `DELETE` requests. |
| `src/main/webapp/WEB-INF/web.xml` | Jakarta EE 10 deployment descriptor configuring servlet mappings and container session parameters. | Maps `SessionCookieServlet` to `/auth/session` and `/login`; enforces `<tracking-mode>COOKIE</tracking-mode>` to prevent URL rewriting session leakage (CWE-598); configures container-level `<cookie-config>` (`http-only`, `secure`, `path`); defines 30-minute session timeout. |
| `pom.xml` | Maven project build configuration file. | Declares dependencies on `jakarta.servlet:jakarta.servlet-api:6.0.0` (provided scope) and `org.junit.jupiter:junit-jupiter:5.10.2` (test scope); configures Java 17 compiler and WAR packaging. |
| `src/test/java/com/example/auth/SessionCookieServletTest.java` | JUnit 5 unit test suite for `SessionCookieServlet`. | Tests cookie attribute configuration, `__Host-` prefix on HTTPS, CRLF injection rejection, session fixation rotation invocation, subsequent session retrieval, and cookie deletion. |

## 3. Skills Applied
- `testing-api-authentication-weaknesses`: Applied to audit session token acquisition, session fixation defenses, session rotation, token transmission in parameters/headers, and token invalidation lifecycles.
- `performing-security-headers-audit`: Applied to audit cookie security attributes (`HttpOnly`, `Secure`, `SameSite`, `Domain`, `Path`, `__Host-` prefix) and anti-caching response headers (`Cache-Control`, `Pragma`, `Expires`).
- `performing-csrf-attack-simulation`: Applied to verify Cross-Site Request Forgery defenses, specifically `SameSite=Strict` cookie policy enforcement on session cookies.
- `testing-for-xss-vulnerabilities`: Applied to inspect protection of session tokens against XSS exfiltration (`HttpOnly` flag effectiveness and JSON body reflection).
- General OWASP Top 10 / CWE Knowledge:
  - Input validation and CRLF injection / HTTP response splitting defense reviewed against CWE-113 and RFC 6265 octet specifications.
  - Session tracking mode reviewed against CWE-598 (Information Exposure Through Query Strings in GET Request) and CWE-200.
  - Web deployment configuration reviewed against Jakarta EE 10 / OWASP session management best practices.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Session Fixation via Untrusted Client Input Acceptance | High | CWE-384 | `SessionCookieServlet.java:487-503` |
| SEC-02 | Flawed Session Rotation Discards New Session ID and Emits Pre-Rotation ID | High | CWE-384 | `SessionCookieServlet.java:125-144` |
| SEC-03 | Sensitive Session Identifier Reflected in Response Body Bypassing HttpOnly | High | CWE-200 | `SessionCookieServlet.java:184-187` |
| SEC-04 | Missing Server-Side Session Validation in Verification Endpoint | Medium | CWE-287 | `SessionCookieServlet.java:178-191` |
| SEC-05 | Missing Anti-Caching Headers on Session Verification Endpoint | Medium | CWE-525 | `SessionCookieServlet.java:174-192` |
| SEC-06 | Cookie Path Mismatch During Invalidation Leaves Active Session in Sub-Contexts | Medium | CWE-613 | `SessionCookieServlet.java:418-430` |

## 5. Detailed Findings

### SEC-01: Session Fixation via Untrusted Client Input Acceptance
- **Severity:** High
- **CWE:** CWE-384: Session Fixation
- **Location:** `SessionCookieServlet.java:487-503`

**Vulnerable code:**
```java
// SessionCookieServlet.java:487-503
        // 4. Check request header
        String headerVal = request.getHeader(SESSION_ID_HEADER);
        if (headerVal != null && !headerVal.trim().isEmpty()) {
            return headerVal.trim();
        }

        // 5. Check request parameter
        String param = request.getParameter("sessionId");
        if (param != null && !param.trim().isEmpty()) {
            return param.trim();
        }

        String altParam = request.getParameter("session_id");
        if (altParam != null && !altParam.trim().isEmpty()) {
            return altParam.trim();
        }

        return null;
```

**Why it is a problem:**
In `resolveSessionId`, if no trusted server-side request attribute (`AUTH_SESSION_ID_ATTR` or `SESSION_ID_ATTR`) or active session exists, the method falls back to resolving the session identifier from unauthenticated client-supplied input (the `X-Session-ID` HTTP header or the `sessionId`/`session_id` request parameters). An attacker can construct a phishing link or trigger a POST request that supplies an attacker-selected session ID. When `doPost` runs, it issues a `Set-Cookie` header establishing the session under the attacker's chosen identifier without calling `changeSessionId()` (because `existingSession` is null). The attacker can subsequently use the pre-seeded session token to hijack the victim's authenticated session. Furthermore, accepting session identifiers from query parameters causes sensitive tokens to be exposed in browser history, proxy access logs, and HTTP `Referer` headers (CWE-598 / CWE-200).

**Fix:**
Remove resolution of session identifiers from client-controlled request parameters and headers. Session identifiers must originate strictly from trusted server-side request attributes populated by upstream authentication filters, or from the existing container session:
```java
        // Do not accept session identifiers from untrusted client headers or request parameters.
        // Session identifiers must originate strictly from trusted server-side attributes or active sessions.
        return null;
```

---

### SEC-02: Flawed Session Rotation Discards New Session ID and Emits Pre-Rotation ID
- **Severity:** High
- **CWE:** CWE-384: Session Fixation
- **Location:** `SessionCookieServlet.java:125-144`

**Vulnerable code:**
```java
// SessionCookieServlet.java:125-144
        String sessionId = resolveSessionId(request);

        if (sessionId == null || sessionId.trim().isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    "Authentication required: no valid session identifier provided.");
            return;
        }

        // 1. Session Fixation Defense (CWE-384):
        // Invalidate or rotate any existing pre-authentication session so an attacker
        // cannot fixate a pre-login session ID onto the authenticated user.
        HttpSession existingSession = request.getSession(false);
        if (existingSession != null) {
            // Jakarta Servlet 3.1+ provides changeSessionId() to securely rotate session IDs
            request.changeSessionId();
        }

        // 2. Attach the hardened session cookie to the response
        try {
            addSessionCookie(request, response, sessionId);
```

**Why it is a problem:**
On line 125, `resolveSessionId(request)` resolves `sessionId` *before* the session rotation occurs. If the session ID is derived from `existingSession.getId()`, `sessionId` holds the pre-authentication session identifier. On line 139, `request.changeSessionId()` rotates the session identifier in the servlet container and returns the newly generated identifier. However, the return value of `changeSessionId()` is discarded, and the `sessionId` variable is never updated. Consequently, on line 144, `addSessionCookie` attaches the *old, pre-rotation* session ID into the `Set-Cookie` header. This completely negates the session fixation defense (CWE-384) and desynchronizes the client cookie from the container session manager (CWE-670), causing subsequent authenticated requests using the cookie to fail.

**Fix:**
Rotate the session first, capture the new session identifier returned by `request.changeSessionId()`, and use that updated identifier when constructing the cookie:
```java
        HttpSession existingSession = request.getSession(false);
        String sessionId;
        if (existingSession != null) {
            // Securely rotate session identifier and capture the newly generated ID
            sessionId = request.changeSessionId();
        } else {
            sessionId = resolveSessionId(request);
        }

        if (sessionId == null || sessionId.trim().isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    "Authentication required: no valid session identifier provided.");
            return;
        }

        // Attach the hardened session cookie with the rotated identifier
        try {
            addSessionCookie(request, response, sessionId);
```

---

### SEC-03: Sensitive Session Identifier Reflected in Response Body Bypassing HttpOnly
- **Severity:** High
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **Location:** `SessionCookieServlet.java:184-187`

**Vulnerable code:**
```java
// SessionCookieServlet.java:184-187
        if (sessionId != null) {
            response.setStatus(HttpServletResponse.SC_OK);
            writer.write("{\"status\":\"authenticated\",\"sessionId\":\"" + escapeJson(sessionId) + "\"}");
        } else {
```

**Why it is a problem:**
The servlet configures `cookie.setHttpOnly(true)` to prevent client-side scripts from reading session tokens, mitigating session hijacking via Cross-Site Scripting (CWE-1004). However, in `doGet`, when a valid session cookie is presented, the servlet prints the full session identifier into the JSON response body (`{"status":"authenticated","sessionId":"..."}`). Because browsers automatically attach cookies (including `HttpOnly` cookies) to same-origin `fetch()` or `XMLHttpRequest` calls, any injected JavaScript from a Cross-Site Scripting (XSS) vulnerability can execute `fetch('/auth/session')` and parse `sessionId` from the JSON payload. This completely circumvents and nullifies the protection provided by the `HttpOnly` flag.

**Fix:**
Do not reflect session credentials or identifiers in HTTP response bodies. Return only non-sensitive verification status:
```java
        if (sessionId != null) {
            response.setStatus(HttpServletResponse.SC_OK);
            writer.write("{\"status\":\"authenticated\"}");
        } else {
```

---

### SEC-04: Missing Server-Side Session Validation in Verification Endpoint
- **Severity:** Medium
- **CWE:** CWE-287: Improper Authentication
- **Location:** `SessionCookieServlet.java:178-191`

**Vulnerable code:**
```java
// SessionCookieServlet.java:178-191
        String sessionId = getSessionIdFromCookie(request);

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        PrintWriter writer = response.getWriter();

        if (sessionId != null) {
            response.setStatus(HttpServletResponse.SC_OK);
            writer.write("{\"status\":\"authenticated\",\"sessionId\":\"" + escapeJson(sessionId) + "\"}");
        } else {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            writer.write("{\"status\":\"unauthenticated\",\"message\":\"No active session cookie found.\"}");
        }
        writer.flush();
```

**Why it is a problem:**
`doGet` evaluates whether a client is authenticated solely by calling `getSessionIdFromCookie(request)`, which merely verifies that the cookie name matches `JSESSIONID` (or `__Host-JSESSIONID`) and that the value conforms to the regular expression `isValidSessionId()`. It never verifies whether the session identifier corresponds to an existing, valid session in the servlet container via `request.getSession(false)` or a persistent session store. Consequently, an unauthenticated attacker can supply any arbitrary string matching the regex (e.g., `Cookie: JSESSIONID=unauthenticated_test_token_123`) and the servlet will falsely respond with `HTTP 200 OK` and `status: authenticated`.

**Fix:**
Validate the cookie's session identifier against the server-side session registry before confirming authentication:
```java
        String cookieSessionId = getSessionIdFromCookie(request);
        HttpSession activeSession = request.getSession(false);

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        PrintWriter writer = response.getWriter();

        boolean isAuthenticated = cookieSessionId != null
                && activeSession != null
                && cookieSessionId.equals(activeSession.getId());

        if (isAuthenticated) {
            response.setStatus(HttpServletResponse.SC_OK);
            writer.write("{\"status\":\"authenticated\"}");
        } else {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            writer.write("{\"status\":\"unauthenticated\",\"message\":\"No active session found.\"}");
        }
        writer.flush();
```

---

### SEC-05: Missing Anti-Caching Headers on Session Verification Endpoint
- **Severity:** Medium
- **CWE:** CWE-525: Use of Web Browser Cache Containing Sensitive Information
- **Location:** `SessionCookieServlet.java:174-192`

**Vulnerable code:**
```java
// SessionCookieServlet.java:174-192
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String sessionId = getSessionIdFromCookie(request);

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        PrintWriter writer = response.getWriter();

        if (sessionId != null) {
            response.setStatus(HttpServletResponse.SC_OK);
            writer.write("{\"status\":\"authenticated\",\"sessionId\":\"" + escapeJson(sessionId) + "\"}");
        } else {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            writer.write("{\"status\":\"unauthenticated\",\"message\":\"No active session cookie found.\"}");
        }
        writer.flush();
    }
```

**Why it is a problem:**
While `doPost` (line 153) and `doDelete` (line 212) correctly invoke `applyAntiCachingHeaders(response)`, `doGet` omits anti-caching headers entirely. Because `doGet` processes HTTP `GET` requests that convey sensitive session state and authentication verification results, the responses are eligible for caching by intermediate proxies, content delivery networks (CDNs), shared corporate gateways, and local browser caches. This exposes sensitive user authentication status to other users on shared machines or via proxy cache inspection.

**Fix:**
Call `applyAntiCachingHeaders(response)` at the beginning of `doGet`:
```java
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        applyAntiCachingHeaders(response);

        String sessionId = getSessionIdFromCookie(request);
```

---

### SEC-06: Cookie Path Mismatch During Invalidation Leaves Active Session in Sub-Contexts
- **Severity:** Medium
- **CWE:** CWE-613: Insufficient Session Expiration
- **Location:** `SessionCookieServlet.java:418-430`

**Vulnerable code:**
```java
// SessionCookieServlet.java:418-430
        for (String name : cookieNamesToClear) {
            Cookie cookie = new Cookie(name, "");
            cookie.setHttpOnly(true);
            cookie.setSecure(true);
            cookie.setPath(DEFAULT_COOKIE_PATH);
            cookie.setMaxAge(0); // Max-Age=0 instructs the browser to immediately delete the cookie
            try {
                cookie.setAttribute("SameSite", DEFAULT_SAME_SITE);
            } catch (NoSuchMethodError | UnsupportedOperationException ignored) {
                // Backward-compatibility fallback
            }
            response.addCookie(cookie);
        }
```

**Why it is a problem:**
In `addSessionCookie` (lines 360-365), when standard cookie names are used (non-`__Host-`), the cookie path is scoped to `request.getContextPath()` (e.g., `/app`). However, `clearSessionCookie` unconditionally hardcodes the deletion cookie path to `DEFAULT_COOKIE_PATH` (`"/"`). Under RFC 6265 Section 5.2.4, a browser only deletes a cookie if the `name`, `domain`, and `path` of the `Set-Cookie` deletion header match the path of the existing cookie. In any deployment with a non-root context path, the deletion cookie with `Path="/"` fails to match or clear the cookie stored with `Path="/app"`. The browser retains the session cookie, leaving the user with an uncleared cookie after logout.

**Fix:**
Determine the effective path from the request context and issue clearance cookies matching both the context path and root path:
```java
        String contextPath = (request != null && request.getContextPath() != null && !request.getContextPath().isEmpty())
                ? request.getContextPath()
                : DEFAULT_COOKIE_PATH;

        Set<String> pathsToClear = new HashSet<>(Arrays.asList(DEFAULT_COOKIE_PATH, contextPath));

        for (String name : cookieNamesToClear) {
            for (String path : pathsToClear) {
                Cookie cookie = new Cookie(name, "");
                cookie.setHttpOnly(true);
                cookie.setSecure(true);
                cookie.setPath(path);
                cookie.setMaxAge(0);
                try {
                    cookie.setAttribute("SameSite", DEFAULT_SAME_SITE);
                } catch (NoSuchMethodError | UnsupportedOperationException ignored) {
                }
                response.addCookie(cookie);
            }
        }
```

## 6. Verified Controls and Checks With No Finding
- **HttpOnly Cookie Flag Enforcement (CWE-1004)**: Verified in `SessionCookieServlet.createSessionCookie` (line 292) and `web.xml` (line 30). The servlet explicitly sets `cookie.setHttpOnly(true)` on all created session cookies, and `web.xml` enforces `<http-only>true</http-only>` at the container level.
- **Secure Cookie Flag Enforcement (CWE-614)**: Verified in `SessionCookieServlet.createSessionCookie` (line 296), `addSessionCookie` (line 368), and `web.xml` (line 31). Cookies are strictly marked `Secure`, requiring HTTPS transmission.
- **SameSite Cookie Attribute Enforcement (CWE-1275)**: Verified in `SessionCookieServlet.createSessionCookie` (line 314) and `clearSessionCookie` (line 425). Session cookies have `SameSite=Strict` configured via `cookie.setAttribute("SameSite", "Strict")`, defending against cross-site request forgery.
- **Host-Only Domain Scoping (RFC 6265 Section 4.1.2.3)**: Verified in `SessionCookieServlet.createSessionCookie` (lines 305-309). The `Domain` attribute is intentionally omitted, scoping the cookie strictly to the host origin and preventing subdomain cookie tossing.
- **RFC 6265bis Cookie Prefixing (`__Host-`)**: Verified in `SessionCookieServlet.addSessionCookie` (lines 352-368). When HTTPS is detected (`request.isSecure()`), the cookie adopts the `__Host-JSESSIONID` prefix, ensuring root path scope, HTTPS-only transport, and host binding at the browser level.
- **CRLF Injection & HTTP Response Splitting Defense (CWE-113 / CWE-20)**: Verified in `SessionCookieServlet.validateSessionId` (lines 508-526) and `VALID_COOKIE_VALUE_PATTERN` (lines 103-104). Session identifiers are strictly checked for `\r` and `\n` control characters and validated against an RFC 6265 visible octet regex (`^[a-zA-Z0-9_\\-\\.~+=/]{1,256}$`).
- **URL Rewriting Session Tracking Disabled (CWE-598 / CWE-200)**: Verified in `web.xml` (line 35). `<tracking-mode>COOKIE</tracking-mode>` is explicitly declared, preventing servlet containers from falling back to URL rewriting or embedding session IDs in query strings.
- **Container Session Inactivity Timeout (CWE-613)**: Verified in `web.xml` (line 27). `<session-timeout>30</session-timeout>` is configured, bounding idle session lifetime to 30 minutes.
- **Anti-Caching Headers on Session Creation and Destruction (CWE-525)**: Verified in `SessionCookieServlet.applyAntiCachingHeaders` (lines 439-445), called in `doPost` (line 153) and `doDelete` (line 212). Sets `Cache-Control: no-cache, no-store, must-revalidate`, `Pragma: no-cache`, and `Expires: 0`.
- **Server-Side Session Invalidation on Logout (CWE-613)**: Verified in `SessionCookieServlet.doDelete` (lines 206-209). Active sessions are explicitly invalidated on the server via `session.invalidate()`.
