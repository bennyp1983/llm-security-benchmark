# Security Vulnerability Review Report

## Executive Summary

A comprehensive security review was conducted on the source code and configuration files located in this project:
- `SessionCookieServlet.java` (and its mirrored Maven source tree location `src/main/java/com/example/auth/SessionCookieServlet.java`)
- `pom.xml`

The application implements a Jakarta Servlet (`SessionCookieServlet`) responsible for creating, configuring, and clearing HTTP session cookies following user authentication. While the implementation incorporates several defense-in-depth browser controls (such as `HttpOnly`, `Secure`, `SameSite=Strict`, RFC 6265 octet validation, and anti-caching headers), the audit identified critical and medium-severity security flaws in session lifecycle handling, authentication enforcement, session fixation resistance, and session termination scoping.

---

## Scope & Code Understanding

| File | Primary Function | Security-Relevant Behaviours Identified |
|---|---|---|
| `SessionCookieServlet.java` / `src/main/java/com/example/auth/SessionCookieServlet.java` | Jakarta Servlet handling post-authentication session cookie creation and cookie clearing. | - Acceptance of session identifiers from HTTP request attributes and parameters (`request.getParameter("sessionId")`).<br>- Session fixation defense via container session rotation (`request.changeSessionId()`).<br>- Cookie attribute configuration (`HttpOnly`, `Secure`, `SameSite`, `Path`, `MaxAge`, `__Host-` prefix).<br>- HTTP response splitting / CRLF input validation via regex.<br>- Response cache-control headers (`Cache-Control`, `Pragma`, `Expires`).<br>- Session clearing on logout (`clearSessionCookie`). |
| `pom.xml` | Maven configuration for WAR deployment targeting Java 17 and Jakarta EE 10 (Servlet API 6.0.0). | - Dependency scope and versioning. |

---

## Skills Applied

In accordance with the security review workflow, the following specialised skills from the library were matched and applied:
1. `testing-api-authentication-weaknesses` - Assessed session token lifecycle, session identifier handling, authentication enforcement, and token exposure risks.
2. `performing-security-headers-audit` - Evaluated cookie security attributes (`HttpOnly`, `Secure`, `SameSite`, `Path`, `__Host-` prefix) and anti-caching response headers.
3. `testing-for-broken-access-control` - Audited endpoint access control, unauthenticated entry points, and missing function-level authentication checks.
4. `performing-csrf-attack-simulation` - Evaluated cross-site request forgery risks, state-changing POST handlers, and Login CSRF vectors.

---

## Findings Summary Table

| Finding ID | Severity | CWE ID | Title | Location |
|---|---|---|---|---|
| **SEC-01** | High | CWE-384 | Untrusted Session ID Parameter Acceptance Leading to Session Fixation | `SessionCookieServlet.java:65-67` |
| **SEC-02** | High | CWE-306 | Missing Authentication Enforcement on Session Cookie Issuance Endpoint | `SessionCookieServlet.java:29`, `58-72` |
| **SEC-03** | Medium | CWE-384 / CWE-653 | Container Session Rotation Desynchronization with Issued Cookie | `SessionCookieServlet.java:77-85` |
| **SEC-04** | Medium | CWE-613 | Ineffective Cookie Clearing Due to Path Mismatch on Context Deployments | `SessionCookieServlet.java:170-176`, `213` |
| **SEC-05** | Medium | CWE-352 | Missing CSRF Protection on Session Establishment Endpoint (Login CSRF) | `SessionCookieServlet.java:58-102` |
| **SEC-06** | Low | CWE-598 / CWE-200 | Exposure of Sensitive Session Identifier via URL Query String | `SessionCookieServlet.java:66` |
| **SEC-07** | Low | CWE-614 / CWE-613 | Inconsistent `__Host-` Prefix and Cookie Clearing Across Transport Contexts | `SessionCookieServlet.java:146-148`, `205-207` |
| **SEC-08** | Low | CWE-209 | Internal Exception Message Exposure in Error Response | `SessionCookieServlet.java:87` |

---

## Detailed Findings

### Finding SEC-01: Untrusted Session ID Parameter Acceptance Leading to Session Fixation

- **Severity**: High
- **CWE ID**: [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html) (also [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html))
- **File & Line**: `SessionCookieServlet.java:65-67` (and `src/main/java/com/example/auth/SessionCookieServlet.java:65-67`)
```java
64:         String sessionId = (String) request.getAttribute("authenticatedSessionId");
65:         if (sessionId == null || sessionId.trim().isEmpty()) {
66:             sessionId = request.getParameter("sessionId");
67:         }
```

#### Why it is a problem
The servlet retrieves the session identifier from request attributes (`authenticatedSessionId`), but if not present, falls back to `request.getParameter("sessionId")`. 
`request.getParameter()` retrieves user-supplied input from the HTTP request query string or POST body. 

An attacker can force or pre-select a known session identifier (e.g., by tricking a victim into submitting a request with `sessionId=ATTACKER_KNOWN_ID` or submitting it prior to login). The servlet accepts this untrusted input and directly packages it into the response's `JSESSIONID` or `__Host-JSESSIONID` cookie. Once the victim's session is established under that token, the attacker uses the pre-set token to access the victim's authenticated account.

#### Fix / Remediation
Session identifiers must **never** be accepted from client-supplied HTTP request parameters. Session identifiers should always be generated server-side by the servlet container using a cryptographically secure random number generator. If an upstream authentication filter or service has authenticated the user, pass the session identifier exclusively via secure server-side request attributes and reject any request where the attribute is absent:

```java
// Retrieve established session identifier strictly from trusted server-side attribute
String sessionId = (String) request.getAttribute("authenticatedSessionId");
if (sessionId == null || sessionId.trim().isEmpty()) {
    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthenticated request.");
    return;
}
```

---

### Finding SEC-02: Missing Authentication Enforcement on Session Cookie Issuance Endpoint

- **Severity**: High
- **CWE ID**: [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html) (also [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html))
- **File & Line**: `SessionCookieServlet.java:29`, `SessionCookieServlet.java:58-72`
```java
29: @WebServlet(name = "SessionCookieServlet", urlPatterns = {"/auth/session", "/login"})
...
59:     protected void doPost(HttpServletRequest request, HttpServletResponse response)
...
62:         // Assumption: User authentication has already succeeded prior to this step.
```

#### Why it is a problem
The servlet is exposed at public URL patterns (`/auth/session`, `/login`). Line 62 states an assumption: *"Assumption: User authentication has already succeeded prior to this step."* However, there is no validation verifying that authentication has actually occurred. The code does not check `request.getUserPrincipal()`, does not check `request.getRemoteUser()`, and does not check any cryptographic token or authentication filter assertion.

Because of this missing check combined with SEC-01, an unauthenticated client can invoke `POST /auth/session?sessionId=arbitrary_token` and receive an HTTP 200 response with `Set-Cookie` establishing a session and a response payload claiming `{"status":"success","message":"Authenticated session established."}`.

#### Fix / Remediation
Enforce explicit authentication checks before executing session establishment logic. Verify the caller's principal or enforce role-based security in the deployment descriptor / `@ServletSecurity`:

```java
if (request.getUserPrincipal() == null && request.getAttribute("authenticatedUser") == null) {
    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication required.");
    return;
}
```

---

### Finding SEC-03: Container Session Rotation Desynchronization with Issued Cookie

- **Severity**: Medium
- **CWE ID**: [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html) (also [CWE-653: Improper Isolation or Compartmentalization](https://cwe.mitre.org/data/definitions/653.html))
- **File & Line**: `SessionCookieServlet.java:77-85`
```java
77:         HttpSession existingSession = request.getSession(false);
78:         if (existingSession != null) {
79:             // Jakarta Servlet 3.1+ provides changeSessionId() to rotate session IDs securely
80:             request.changeSessionId();
81:         }
82: 
83:         // 2. Attach the hardened session cookie to the response
84:         try {
85:             addSessionCookie(request, response, sessionId);
```

#### Why it is a problem
On lines 77–81, the servlet detects if an existing pre-authentication session exists and calls `request.changeSessionId()`. In Jakarta Servlet, `HttpServletRequest.changeSessionId()` rotates the internal ID of the container-managed `HttpSession` and returns the new session ID string.

However, line 85 completely ignores the new session ID returned by `request.changeSessionId()` (or `existingSession.getId()`) and instead calls `addSessionCookie(request, response, sessionId)` using the original `sessionId` variable. This introduces two serious security and functional flaws:
1. If an attacker attempted session fixation, rotating the container session ID is rendered completely useless because the client's cookie is still set to the old/untrusted `sessionId`.
2. The servlet container's internal session ID and the client's cookie value become desynchronized. Future HTTP requests carrying the cookie will not match the container's active session.

#### Fix / Remediation
Assign the result of `changeSessionId()` to `sessionId`, or obtain the new ID from `existingSession.getId()`, ensuring the issued cookie matches the rotated container session:

```java
HttpSession session = request.getSession(false);
if (session != null) {
    // changeSessionId() rotates the ID and returns the new ID string
    sessionId = request.changeSessionId();
} else {
    session = request.getSession(true);
    sessionId = session.getId();
}

addSessionCookie(request, response, sessionId);
```

---

### Finding SEC-04: Ineffective Cookie Clearing Due to Path Mismatch on Context Deployments

- **Severity**: Medium
- **CWE ID**: [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)
- **File & Line**: `SessionCookieServlet.java:170-176`, `SessionCookieServlet.java:213`
```java
// In addSessionCookie (lines 170-176):
170:         String cookiePath = DEFAULT_COOKIE_PATH;
171:         if (request != null && !cookieName.startsWith("__Host-")) {
172:             String contextPath = request.getContextPath();
173:             if (contextPath != null && !contextPath.isEmpty()) {
174:                 cookiePath = contextPath;
175:             }
176:         }
177:         sessionCookie.setPath(cookiePath);
...
// In clearSessionCookie (line 213):
213:         cookie.setPath(DEFAULT_COOKIE_PATH);
214:         cookie.setMaxAge(0);
```

#### Why it is a problem
When `addSessionCookie` sets a session cookie named `JSESSIONID` in an application deployed under a context path (e.g. `/app`), the cookie path is set to `/app`. 

However, `clearSessionCookie` unconditionally sets `cookie.setPath(DEFAULT_COOKIE_PATH)` (`"/"`). According to RFC 6265, a `Set-Cookie` directive with `Path=/` and `Max-Age=0` will **not** match or delete a cookie scoped to `Path=/app`. As a result, when a user logs out, the browser retains the authenticated session cookie scoped to `/app`. If the device is shared or accessed subsequently, the session token remains active in the browser.

Furthermore, `clearSessionCookie` does not call `session.invalidate()` on the server-side container session, leaving the session active on the server.

#### Fix / Remediation
Ensure the cookie path used in `clearSessionCookie` mirrors the exact path resolution logic used in `addSessionCookie`. Also, invalidate the server session:

```java
public static void clearSessionCookie(HttpServletRequest request, HttpServletResponse response) {
    if (response == null) {
        return;
    }

    if (request != null) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
    }

    // Clear both potential cookie names across paths
    String[] cookieNames = {HOST_PREFIXED_COOKIE_NAME, SESSION_COOKIE_NAME};
    String contextPath = (request != null && request.getContextPath() != null && !request.getContextPath().isEmpty())
            ? request.getContextPath()
            : DEFAULT_COOKIE_PATH;
    String[] paths = {DEFAULT_COOKIE_PATH, contextPath};

    for (String name : cookieNames) {
        for (String path : paths) {
            Cookie cookie = new Cookie(name, "");
            cookie.setHttpOnly(true);
            cookie.setSecure(true);
            cookie.setAttribute("SameSite", "Strict");
            cookie.setPath(path);
            cookie.setMaxAge(0);
            response.addCookie(cookie);
        }
    }
}
```

---

### Finding SEC-05: Missing CSRF Protection on Session Establishment Endpoint (Login CSRF)

- **Severity**: Medium
- **CWE ID**: [CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)
- **File & Line**: `SessionCookieServlet.java:58-102`
```java
58:     @Override
59:     protected void doPost(HttpServletRequest request, HttpServletResponse response)
60:             throws ServletException, IOException {
```

#### Why it is a problem
The servlet handles state-changing POST requests that establish user sessions. Although the newly created cookie has `SameSite=Strict`, the `doPost` endpoint itself lacks anti-CSRF token verification and origin header validation.

Because the endpoint accepts `sessionId` via request parameters (SEC-01), an attacker can perform a Login CSRF attack: an attacker tricks a victim's browser into submitting a cross-site POST request to `/login` or `/auth/session` containing the attacker's pre-authenticated or fixated session identifier. The victim's browser establishes the session under the attacker's account, allowing the attacker to monitor or capture sensitive user activity performed on the site.

#### Fix / Remediation
1. Validate an unpredictable anti-CSRF token (synchronizer token) in `doPost`.
2. Inspect `Origin` and `Fetch Metadata` headers (`Sec-Fetch-Site: same-origin`) to reject cross-origin POST requests.

---

### Finding SEC-06: Exposure of Sensitive Session Identifier via URL Query String

- **Severity**: Low
- **CWE ID**: [CWE-598: Use of GET Request Method with Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html) (also [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html))
- **File & Line**: `SessionCookieServlet.java:66`
```java
66:             sessionId = request.getParameter("sessionId");
```

#### Why it is a problem
In Java Servlets, `request.getParameter("sessionId")` extracts parameters from both the HTTP request body and the URL query string (`request.getQueryString()`). If a client or upstream service submits a request like `POST /auth/session?sessionId=abc123xyz`, the sensitive session identifier is transmitted in the URL query string.

Query string parameters are frequently logged in plain text in web server access logs, reverse proxies (Nginx, Apache, AWS ALB), browser histories, and outgoing `Referer` headers, leading to unauthorized exposure of session credentials.

#### Fix / Remediation
Ensure sensitive session tokens are never read from or accepted via query parameters. If request parameters are processed, verify that `request.getQueryString()` does not contain `sessionId`.

---

### Finding SEC-07: Inconsistent `__Host-` Prefix and Cookie Clearing Across Transport Contexts

- **Severity**: Low
- **CWE ID**: [CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html) (also [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html))
- **File & Line**: `SessionCookieServlet.java:146-148`, `SessionCookieServlet.java:205-207`
```java
146:         String cookieName = (request != null && request.isSecure())
147:                 ? HOST_PREFIXED_COOKIE_NAME
148:                 : SESSION_COOKIE_NAME;
...
205:         String cookieName = (request != null && request.isSecure())
206:                 ? HOST_PREFIXED_COOKIE_NAME
207:                 : SESSION_COOKIE_NAME;
```

#### Why it is a problem
1. **Reverse Proxy TLS Termination**: If the application operates behind a reverse proxy or load balancer that terminates TLS without configuring the servlet container to respect `X-Forwarded-Proto`, `request.isSecure()` evaluates to `false`. As a result, the application falls back to `JSESSIONID` and disables the `__Host-` prefix protection, allowing subdomains to overwrite or spoof the session cookie.
2. **Asymmetric Cookie Clearing**: If a session cookie was established with `__Host-JSESSIONID` over HTTPS, but a subsequent logout request arrives over an insecure connection or behind an unconfigured reverse proxy where `request.isSecure()` is `false`, `clearSessionCookie` will send a deletion cookie for `JSESSIONID` instead of `__Host-JSESSIONID`. The original session cookie will remain intact in the browser.

#### Fix / Remediation
1. Configure container reverse proxy support (e.g. `RemoteIpValve` in Tomcat) to accurately detect HTTPS via standard forwarding headers.
2. In `clearSessionCookie`, proactively expire both `__Host-JSESSIONID` and `JSESSIONID`.

---

### Finding SEC-08: Internal Exception Message Exposure in Error Response

- **Severity**: Low
- **CWE ID**: [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
- **File & Line**: `SessionCookieServlet.java:87`
```java
86:         } catch (IllegalArgumentException e) {
87:             response.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
88:             return;
89:         }
```

#### Why it is a problem
The servlet passes `e.getMessage()` directly to `response.sendError()`. Depending on the servlet container configuration, this raw error string may be reflected in server-generated HTML error pages or API responses. While currently limited to input validation messages, exposing raw exception messages aids attackers in reconnaissance and testing input boundary constraints.

#### Fix / Remediation
Log the detailed exception internally and return a standardized, client-safe error response:

```java
} catch (IllegalArgumentException e) {
    // Log exception details to internal logging framework
    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid session identifier format.");
    return;
}
```

---

## Review of Security-Relevant Behaviours Against General OWASP / CWE Knowledge

The following security-relevant behaviours and controls were evaluated against general OWASP Top 10 and CWE standards:

1. **CRLF Injection / HTTP Response Splitting ([CWE-113](https://cwe.mitre.org/data/definitions/113.html))**:
   - Evaluated `VALID_COOKIE_VALUE_PATTERN` (`^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]+$`) and explicit checks for `\r` and `\n` in `SessionCookieServlet.java:137-142`.
   - **Assessment**: The regex strictly enforces RFC 6265 compliant cookie-octet characters and excludes delimiters (`;`, `,`, `"`, `\`) and control characters. This effectively prevents header injection and response splitting via the cookie value.

2. **Sensitive Information Caching ([CWE-525](https://cwe.mitre.org/data/definitions/525.html))**:
   - Evaluated cache prevention headers set on `SessionCookieServlet.java:93-95`:
     ```java
     response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
     response.setHeader("Pragma", "no-cache");
     response.setDateHeader("Expires", 0);
     ```
   - **Assessment**: The headers comply with OWASP session management best practices, preventing shared proxies and browser caches from storing session response data.

3. **Session Cookie Security Flags ([CWE-1004](https://cwe.mitre.org/data/definitions/1004.html), [CWE-614](https://cwe.mitre.org/data/definitions/614.html), [CWE-1275](https://cwe.mitre.org/data/definitions/1275.html))**:
   - Evaluated `sessionCookie.setHttpOnly(true)` (mitigates XSS token exfiltration).
   - Evaluated `sessionCookie.setSecure(true)` (mitigates plaintext transport).
   - Evaluated `sessionCookie.setAttribute("SameSite", "Strict")` (mitigates cross-site cookie transmission).
   - Evaluated `sessionCookie.setMaxAge(-1)` (configures non-persistent browser-session lifetime).
   - **Assessment**: These attributes are correctly applied to the outgoing cookie object.

4. **Build and Dependencies (`pom.xml`)**:
   - Evaluated Maven dependencies in `pom.xml`. The project depends solely on `jakarta.servlet:jakarta.servlet-api:6.0.0` with `provided` scope, targeting Java 17.
   - **Assessment**: No third-party vulnerable dependencies or misconfigured repositories were detected.
