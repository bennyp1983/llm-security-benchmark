# Secure Authenticated Session Cookie Implementation

A complete Java web application implementation using the **Jakarta Servlet API** for establishing, configuring, and maintaining secure session cookies following successful user authentication.

---

## 1. Overview

In web applications, managing user sessions after authentication requires careful configuration of HTTP cookies. If session cookies lack proper security attributes, attackers can steal or manipulate session identifiers via Cross-Site Scripting (XSS), network eavesdropping, Cross-Site Request Forgery (CSRF), or subdomain cookie tossing.

This application provides a production-grade implementation compliant with the **Jakarta Servlet API (Jakarta EE 10 / Servlet 6.0)** that:
1. Receives an authenticated session identifier from upstream authentication logic.
2. Defends against session fixation (CWE-384) by rotating the pre-authentication session ID.
3. Configures all essential defense-in-depth cookie attributes (`HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, Host-Only domain).
4. Employs RFC 6265bis cookie prefixing (`__Host-JSESSIONID`) when operating over TLS/HTTPS.
5. Emits strict anti-caching HTTP headers (CWE-525) to prevent caching of session tokens.
6. Maintains the authenticated session across subsequent HTTP requests.
7. Provides clean session termination and cookie invalidation (`Max-Age=0`).

---

## 2. Security Controls & Cookie Configuration

| Security Control | Attribute / Method | Target CWE / RFC | Threat Mitigated |
|---|---|---|---|
| **Script Inaccessibility** | `cookie.setHttpOnly(true)` | **CWE-1004** | Blocks client-side JavaScript (`document.cookie`) from accessing session tokens, defeating XSS-based session hijacking. |
| **Encrypted-Only Transmission** | `cookie.setSecure(true)` | **CWE-614** | Restricts cookie transmission strictly to encrypted TLS/HTTPS connections, preventing cleartext network eavesdropping and MITM interception. |
| **Cross-Site Request Forgery Defense** | `cookie.setAttribute("SameSite", "Strict")` | **CWE-1275** | Prohibits browsers from sending the session cookie on cross-site requests, neutralizing CSRF attacks. |
| **Host-Only Domain Scoping** | *Omit `cookie.setDomain(...)`* | **RFC 6265 Section 4.1.2.3** | Omitting the `Domain` attribute scopes the cookie strictly to the origin host. Subdomains cannot read or overwrite the cookie (prevents cookie tossing). |
| **Origin Binding Prefix** | `__Host-JSESSIONID` | **RFC 6265bis** | Under HTTPS, prefixes enforce that the browser requires the `Secure` flag, forbids the `Domain` attribute, and scopes path to `/`. |
| **Session Fixation Defense** | `request.changeSessionId()` | **CWE-384** | Rotates existing session IDs upon authentication so an attacker cannot fixate a pre-authentication session ID onto a victim. |
| **CRLF Injection / Splitting Defense** | RFC 6265 octet regex validation | **CWE-113, CWE-20** | Enforces strict validation of session tokens, rejecting carriage return (`\r`), line feed (`\n`), semicolons, and control characters. |
| **Anti-Caching Protection** | `Cache-Control: no-cache, no-store, must-revalidate` | **CWE-525** | Prevents proxy caches, intermediate gateways, and local browser histories from storing sensitive session credentials. |
| **Controlled Lifetime** | `cookie.setMaxAge(-1)` | **CWE-539** | Default `-1` produces a transient session cookie that is destroyed when the browser session terminates. |
| **Cookie-Only Tracking** | `<tracking-mode>COOKIE</tracking-mode>` | **CWE-598, CWE-200** | Prevents servlet containers from appending session IDs to URLs (URL rewriting / URL parameter leakage). |

---

## 3. Project Structure

```text
.
├── pom.xml                                          # Maven project configuration (Jakarta Servlet 6.0, JUnit 5)
├── README.md                                        # Technical and security documentation
├── README                                           # Plaintext copy of documentation
├── SessionCookieServlet.java                        # Complete standalone Java implementation & verification suite
├── src
│   ├── main
│   │   ├── java
│   │   │   └── com/example/auth
│   │   │       └── SessionCookieServlet.java       # Standard Maven package source
│   │   └── webapp
│   │       └── WEB-INF
│   │           └── web.xml                         # Deployment descriptor with container-level security config
│   └── test
│       └── java
│           └── com/example/auth
│               └── SessionCookieServletTest.java   # Comprehensive JUnit 5 test suite (10 test cases)
└── target/                                          # Compiled classes and packaged WAR
```

---

## 4. Endpoints & API Reference

### 1. `POST /auth/session` (or `POST /login`)
Establishes an authenticated session cookie following successful authentication.

- **Upstream Input Sources** (checked in order):
  1. Request attribute `authenticatedSessionId`
  2. Request attribute `sessionId`
  3. Active `HttpSession.getId()`
  4. Header `X-Session-ID`
  5. Form / Query parameter `sessionId`
- **Actions Performed**:
  - Validates session identifier against CRLF and invalid octets.
  - Calls `request.changeSessionId()` if a pre-authentication session exists.
  - Instantiates `Cookie` with `HttpOnly=true`, `Secure=true`, `Path="/"`, `SameSite=Strict`, `Max-Age=-1`.
  - Attaches cookie to `HttpServletResponse` via `response.addCookie(cookie)`.
  - Adds `Cache-Control: no-cache, no-store, must-revalidate`.
- **Response**: `200 OK` with JSON payload `{"status":"success","message":"Authenticated session established."}`.

### 2. `GET /auth/session`
Maintains and verifies the active authenticated session across subsequent requests.

- **Actions Performed**:
  - Inspects incoming `Cookie` headers via `request.getCookies()`.
  - Locates `JSESSIONID` or `__Host-JSESSIONID` and validates format.
- **Response**:
  - If valid cookie present: `200 OK` with `{"status":"authenticated","sessionId":"<session-id>"}`.
  - If cookie missing or invalid: `401 Unauthorized` with `{"status":"unauthenticated","message":"No active session cookie found."}`.

### 3. `DELETE /auth/session`
Invalidates the server-side session and purges the client cookie.

- **Actions Performed**:
  - Invalidates server session via `session.invalidate()`.
  - Sends expired cookie (`Max-Age=0`) with identical security attributes (`HttpOnly`, `Secure`, `Path=/`).
- **Response**: `200 OK` with `{"status":"success","message":"Session invalidated and cookie cleared."}`.

---

## 5. How to Compile and Run

### Prerequisites
- **JDK 17** or newer (`java -version`, `javac -version`)
- **Apache Maven 3.8+** (`mvn -version`)

---

### Option A: Standalone CLI Compilation & Built-In Verification Suite

The implementation includes a self-contained test harness in its `main` method that verifies all security attributes using dynamic proxies—no external servlet container or mocking framework is required:

1. **Compile with `javac`**:
   ```bash
   javac -cp /root/.m2/repository/jakarta/servlet/jakarta.servlet-api/6.0.0/jakarta.servlet-api-6.0.0.jar -d . SessionCookieServlet.java
   ```

2. **Run Standalone Test Suite**:
   ```bash
   java -ea -cp .:/root/.m2/repository/jakarta/servlet/jakarta.servlet-api/6.0.0/jakarta.servlet-api-6.0.0.jar com.example.auth.SessionCookieServlet
   ```

   **Output**:
   ```text
   =================================================================
    SessionCookieServlet - Verification & Security Test Suite
   =================================================================
   [TEST 1/7] Testing createSessionCookie security configuration... PASSED
   [TEST 2/7] Testing __Host- prefixed cookie on HTTPS... PASSED
   [TEST 3/7] Testing doPost handling & cookie attachment... PASSED
   [TEST 4/7] Testing doGet subsequent session retrieval... PASSED
   [TEST 5/7] Testing CRLF / Header Injection prevention... PASSED
   [TEST 6/7] Testing session termination and cookie clearing... PASSED
   [TEST 7/7] Testing session fixation mitigation... PASSED
   =================================================================
   All 7/7 tests PASSED successfully!
   ```

---

### Option B: Apache Maven Build & JUnit 5 Testing

1. **Compile**:
   ```bash
   mvn compile
   ```

2. **Run JUnit 5 Test Suite**:
   ```bash
   mvn test
   ```
   Runs 10 unit test cases covering:
   - HttpOnly and Secure flag enforcement (CWE-1004, CWE-614)
   - SameSite=Strict configuration (CWE-1275)
   - Host-Only domain omission (RFC 6265)
   - RFC 6265bis `__Host-` prefix on HTTPS
   - CRLF injection rejection (CWE-113)
   - Null / empty session ID validation
   - Anti-caching header application (CWE-525)
   - Session fixation rotation via `changeSessionId` (CWE-384)
   - Subsequent session retrieval across requests (`doGet`)
   - Session clearance via `Max-Age=0` (`doDelete`)

3. **Package Deployable WAR**:
   ```bash
   mvn package
   ```
   Outputs `target/auth-session-cookie-1.0.0.war`, ready to deploy onto any Jakarta EE 10 compatible container (Apache Tomcat 10.1+, Eclipse Jetty 12+, WildFly 27+).

---

## 6. Programmatic Java API Usage Example

If integrating this functionality into an existing authentication filter or servlet:

```java
import com.example.auth.SessionCookieServlet;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, String authenticatedSessionId) {
    // 1. Rotate pre-authentication session ID to defend against Session Fixation (CWE-384)
    if (request.getSession(false) != null) {
        request.changeSessionId();
    }

    // 2. Add hardened session cookie to HTTP response
    // Configures HttpOnly=true, Secure=true, SameSite=Strict, Path="/", Max-Age=-1
    SessionCookieServlet.addSessionCookie(request, response, authenticatedSessionId);

    // 3. Apply anti-caching headers (CWE-525)
    SessionCookieServlet.applyAntiCachingHeaders(response);
}
```
