# Authenticated Session Cookie Management (Jakarta Servlet API)

This project provides a complete, production-grade Java web application implementation using the **Jakarta Servlet API (v6.0)** to securely create, configure, and issue an HTTP session cookie after successful user authentication, and maintain that authenticated session across subsequent HTTP requests.

---

## 1. Overview & Functionality

In modern web applications, establishing a session post-authentication requires creating a secure session cookie that binds the client to the server-side authenticated state. This implementation assumes that authentication has already succeeded upstream (e.g., via credential verification filter, identity provider, or authentication realm) and that an authenticated session identifier is available.

The core implementation is encapsulated in [`SessionCookieServlet.java`](SessionCookieServlet.java), mapped to endpoints `/auth/session` and `/login`:

- **Session Cookie Creation (`POST /auth/session` / `POST /login`)**: Accepts the authenticated session identifier (via request attribute `authenticatedSessionId` or parameter `sessionId`), rotates existing sessions to prevent session fixation, applies comprehensive defensive cookie attributes, adds anti-caching headers, and attaches the cookie to the HTTP response (`HttpServletResponse.addCookie`).
- **Session Maintenance Across Requests (`GET /auth/session`)**: Extracts the session cookie from incoming request cookies (`HttpServletRequest.getCookies()`), validates its structure, and verifies that the authenticated session is maintained across requests.
- **Session Termination / Logout (`DELETE /auth/session`)**: Invalidates the server-side session and issues an expired cookie (`Max-Age=0`) to instruct the client browser to immediately purge the cookie.
- **Built-in Self-Test Suite (`main` method)**: Enables instant standalone verification of all security controls and HTTP flows directly from the command line without needing external servlet container setup.

---

## 2. Post-Authentication Session Cookie Configuration

The session cookie is configured using defense-in-depth security best practices to protect against common web application vulnerabilities:

| Security Attribute / Control | Value / Mechanism | Vulnerability Addressed | Rationale & Protection |
| :--- | :--- | :--- | :--- |
| **`HttpOnly` Flag** | `cookie.setHttpOnly(true)` | **CWE-1004** (Sensitive Cookie Without 'HttpOnly' Flag) / **XSS** | Prevents client-side scripts (e.g., `document.cookie`) from accessing the session identifier. In the event of a Cross-Site Scripting (XSS) flaw, attackers cannot directly exfiltrate the session token. |
| **`Secure` Flag** | `cookie.setSecure(true)` | **CWE-614** (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute) | Restricts cookie transmission exclusively to encrypted TLS/HTTPS connections. Prevents eavesdropping and Man-in-the-Middle (MITM) session sniffing over plaintext HTTP. |
| **`SameSite` Attribute** | `cookie.setAttribute("SameSite", "Strict")` | **CWE-1275** (Sensitive Cookie with Improper 'SameSite' Attribute) / **CSRF** | Guarantees that the session cookie will not be attached to cross-site requests initiated by third-party origins, preventing Cross-Site Request Forgery attacks. |
| **Host-Only Scoping** | Omits `cookie.setDomain(...)` | Subdomain Takeover & Cookie Tossing Attacks | By intentionally omitting the `Domain` attribute, the browser scopes the cookie strictly to the origin host. Subdomains cannot access or tamper with the session cookie. |
| **RFC 6265bis Cookie Prefix** | `__Host-JSESSIONID` (under HTTPS) | Origin Spoofing & Subdomain Injection | Under HTTPS, prefixes enforce browser-level validation: the cookie must be `Secure`, have `Path=/`, and must NOT specify a `Domain`. |
| **Session Fixation Defense** | `request.changeSessionId()` | **CWE-384** (Session Fixation) | When authentication succeeds, any existing unauthenticated session is rotated or invalidated so attackers cannot pre-set a session identifier that persists past login. |
| **CRLF Injection Protection** | Strict regex validation (`VALID_COOKIE_VALUE_PATTERN`) | **CWE-113** (HTTP Response Splitting / Header Injection) | Validates that the provided session identifier contains only valid RFC 6265 cookie octets and strictly rejects carriage return (`\r`) and line feed (`\n`) characters. |
| **Session Lifetime** | `cookie.setMaxAge(-1)` | **CWE-539** (Improper Handling of Cookie Expiration) | Sets `-1` to designate a transient browser session cookie that is automatically purged when the user terminates their browser session. |
| **Anti-Caching Headers** | `Cache-Control: no-cache, no-store, must-revalidate` | **CWE-525** (Web Browser Cache Storing Sensitive Information) | Prevents intermediate proxies and browser caches from storing HTTP responses containing sensitive `Set-Cookie` headers. |

---

## 3. Project File Structure

```
.
├── pom.xml                                           # Maven build configuration
├── README.md                                         # Documentation (this file)
├── README                                            # Plain-text documentation mirror
├── SessionCookieServlet.java                         # Standalone Java source file
├── src
│   ├── main
│   │   ├── java
│   │   │   └── com
│   │   │       └── example
│   │   │           └── auth
│   │   │               └── SessionCookieServlet.java # Maven-standard source file
│   │   └── webapp
│   │       └── WEB-INF
│   │           └── web.xml                           # Web application deployment descriptor
│   └── test
│       └── java
│           └── com
│               └── example
│                   └── auth
│                       └── SessionCookieServletTest.java # JUnit 5 test suite
```

---

## 4. Prerequisites

- **Java Development Kit (JDK)**: Java 17 or higher
- **Maven**: Version 3.8+ (optional, for Maven lifecycle builds)
- **Jakarta Servlet API**: Version 6.0.0 (included in Maven POM and local repository)

---

## 5. How to Compile and Run

### Method 1: Direct CLI Compilation & Execution (No Build Tools Required)

You can compile and run the standalone source file directly using `javac` and `java`:

1. **Compile**:
   ```bash
   javac -cp /root/.m2/repository/jakarta/servlet/jakarta.servlet-api/6.0.0/jakarta.servlet-api-6.0.0.jar -d . SessionCookieServlet.java
   ```

2. **Execute Built-In Verification Suite**:
   ```bash
   java -ea -cp .:/root/.m2/repository/jakarta/servlet/jakarta.servlet-api/6.0.0/jakarta.servlet-api-6.0.0.jar com.example.auth.SessionCookieServlet
   ```

   **Sample Output:**
   ```
   =================================================================
    SessionCookieServlet - Verification & Security Test Suite
   =================================================================
   [TEST 1/5] Testing createSessionCookie security configuration... PASSED
   [TEST 2/5] Testing doPost handling & cookie attachment... PASSED
   [TEST 3/5] Testing doGet subsequent session retrieval... PASSED
   [TEST 4/5] Testing CRLF / Header Injection prevention... PASSED
   [TEST 5/5] Testing session termination and cookie clearing... PASSED
   =================================================================
   All 5/5 tests PASSED successfully!
   Security controls verified: HttpOnly, Secure, SameSite=Strict,
   Path=/, Host-Only domain scoping, Anti-caching, CRLF rejection.
   =================================================================
   ```

---

### Method 2: Build and Test Using Apache Maven

1. **Compile the project**:
   ```bash
   mvn compile
   ```

2. **Execute unit tests**:
   ```bash
   mvn test
   ```
   Runs 8 automated JUnit 5 tests covering cookie generation, security flag verification, CRLF rejection, and HTTP request flows.

3. **Package as WAR for Servlet Container**:
   ```bash
   mvn package
   ```
   Produces `target/auth-session-cookie-1.0.0.war` ready to deploy into any Jakarta EE 10 servlet container (Apache Tomcat 10.1+, Eclipse Jetty 12+, WildFly 27+).

---

## 6. HTTP API Endpoint Reference

### 1. Create Session Cookie (Post-Authentication)
- **Endpoint**: `POST /auth/session` or `POST /login`
- **Request Parameters / Attributes**:
  - `sessionId`: The session identifier established by authentication (e.g. `sess_abc12345`)
  - Alternatively provided upstream as `request.setAttribute("authenticatedSessionId", "...")`
- **Response**:
  - HTTP `200 OK`
  - `Set-Cookie: JSESSIONID=sess_abc12345; Path=/; Secure; HttpOnly; SameSite=Strict`
  - Headers: `Cache-Control: no-cache, no-store, must-revalidate`
  - JSON Body: `{"status":"success","message":"Authenticated session established."}`

```bash
# Example cURL request:
curl -i -X POST -d "sessionId=sess_authenticated_token_12345" http://localhost:8080/auth/session
```

### 2. Maintain Session Across Subsequent Requests
- **Endpoint**: `GET /auth/session`
- **Request Header**:
  - `Cookie: JSESSIONID=sess_authenticated_token_12345`
- **Response**:
  - HTTP `200 OK`
  - JSON Body: `{"status":"authenticated","sessionId":"sess_authenticated_token_12345"}`

```bash
# Example cURL request:
curl -i -X GET --cookie "JSESSIONID=sess_authenticated_token_12345" http://localhost:8080/auth/session
```

### 3. Terminate Session & Clear Cookie
- **Endpoint**: `DELETE /auth/session`
- **Response**:
  - HTTP `200 OK`
  - `Set-Cookie: JSESSIONID=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict`
  - JSON Body: `{"status":"success","message":"Session invalidated and cookie cleared."}`

```bash
# Example cURL request:
curl -i -X DELETE http://localhost:8080/auth/session
```
