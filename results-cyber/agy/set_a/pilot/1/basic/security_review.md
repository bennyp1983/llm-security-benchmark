# Security Review Report: Session Cookie Servlet

**Target Directory:** `/data/results-cyber/agy/set_a/pilot/1/basic`  
**Target File:** [`SessionCookieServlet.java`](file:///data/results-cyber/agy/set_a/pilot/1/basic/SessionCookieServlet.java)  
**Date of Audit:** 2026-09-09  
**Review Standard:** OWASP Top 10 / CWE / OWASP ASVS / WSTG  

---

## 1. Executive Summary

A comprehensive security review was conducted on the source code in this directory, focusing on [`SessionCookieServlet.java`](file:///data/results-cyber/agy/set_a/pilot/1/basic/SessionCookieServlet.java). The servlet is written using the Jakarta Servlet API and is designed to establish and attach a session cookie (`JSESSIONID`) to the HTTP response following successful user authentication.

While the servlet implements several good defensive cookie attributes (`HttpOnly`, `Secure`, `SameSite=Strict`, transient lifetime), critical architectural and implementation vulnerabilities were discovered:
1. **Session Fixation (CWE-384)**: The servlet accepts user-supplied session identifiers via HTTP request parameters (`request.getParameter("sessionId")`), allowing an attacker to fix a victim's session identifier.
2. **Missing Authentication for Critical Function (CWE-306)**: The servlet exposes public endpoints (`/auth/session`, `/login`) without verifying whether the caller has actually authenticated.
3. **Incomplete Input Validation / Delimiter Injection (CWE-20 / CWE-113)**: Input validation on `sessionId` relies on an incomplete blacklist checking only for `\r` and `\n`, failing to restrict delimiters like semicolons (`;`) or enforce allowlist formatting.
4. **Potential Sensitive Token Leakage via URL Query String (CWE-598 / CWE-532)**: `request.getParameter("sessionId")` allows session tokens to be passed in URL query strings, exposing them in logs and Referer headers.
5. **Insufficient Entropy / Lack of Server-Side CSPRNG Generation (CWE-330)**: The application does not enforce that session identifiers are generated server-side using a Cryptographically Secure Pseudo-Random Number Generator.

---

## 2. Methodology & Skills Applied

### 2.1 Code Understanding & Security Behaviours (Step 1)
- **File in Scope**: [`SessionCookieServlet.java`](file:///data/results-cyber/agy/set_a/pilot/1/basic/SessionCookieServlet.java)
- **Functionality**: A Jakarta EE servlet mapped to `/auth/session` and `/login` that retrieves a session ID and sets a `JSESSIONID` cookie on the HTTP response.
- **Security-Relevant Behaviours Identified**:
  - Session identifier acquisition from client-controlled request parameters.
  - Endpoint exposure and absence of authentication verification.
  - Cookie attribute configuration (`HttpOnly`, `Secure`, `Path`, `MaxAge`, `SameSite`).
  - Character validation and HTTP response splitting mitigation (`\r`, `\n`).
  - Transmission of sensitive session credentials over HTTP parameters.

### 2.2 Skills Applied (Steps 2 & 3)
In accordance with the security review workflow, the following specialised skills from the skill library were identified, loaded, and applied to audit the codebase:

1. **`testing-api-authentication-weaknesses`**
   - *Focus*: Unauthenticated endpoint discovery, session management flaws, token lifecycle, and token leakage in URL parameters.
2. **`performing-web-application-penetration-test`**
   - *Focus*: Session fixation assessment, cookie security flags (`Secure`, `HttpOnly`, `SameSite`), and input validation testing.
3. **`testing-for-broken-access-control`**
   - *Focus*: Missing function-level access control on session-issuance endpoints and unauthenticated access checks.
4. **`performing-security-headers-audit`**
   - *Focus*: Audit of cookie security attributes, transport security, and response headers.

*Note on General Knowledge*: Security-relevant behaviours not exclusively covered by a single specialised skill (such as CRLF/cookie injection via incomplete character blacklists and session entropy generation) were evaluated against general OWASP Top 10 (A03:2021 Injection, A02:2021 Cryptographic Failures) and MITRE CWE specifications.

---

## 3. Detailed Security Findings

### Finding 1: Session Fixation via Client-Controlled Session Parameter
- **Severity**: **High** (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N — Base Score: 8.1)
- **CWE ID**: [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html) (also [CWE-472: External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html))
- **File & Lines**: [`SessionCookieServlet.java:28-36`](file:///data/results-cyber/agy/set_a/pilot/1/basic/SessionCookieServlet.java#L28-L36), specifically Line 30.
- **Vulnerable Code**:
  ```java
  // SessionCookieServlet.java:28-31
  String sessionId = (String) request.getAttribute("authenticatedSessionId");
  if (sessionId == null || sessionId.trim().isEmpty()) {
      sessionId = request.getParameter("sessionId");
  }
  ```
- **Why It Is a Problem**:
  When `authenticatedSessionId` is not present in the internal request attributes, the servlet falls back to reading `sessionId` directly from the client HTTP request (`request.getParameter("sessionId")`). 
  In a session fixation attack, an adversary pre-determines or obtains a known session identifier and tricks a victim into authenticating or establishing a session with that identifier (e.g., via a crafted phishing link or cross-site form submission). Because this servlet adopts whatever `sessionId` the client supplies and writes it directly to the victim's `JSESSIONID` cookie, the attacker can use their pre-determined session identifier to hijack the victim's authenticated session.
- **The Fix**:
  Never accept session identifiers from untrusted client parameters. Session identifiers must always be generated server-side upon successful authentication. If the standard Jakarta Servlet container session mechanism is used, invoke `request.changeSessionId()` or `request.getSession(true)`:
  ```java
  // Secure remediation: Never read sessionId from request.getParameter()
  String sessionId = (String) request.getAttribute("authenticatedSessionId");
  if (sessionId == null || sessionId.trim().isEmpty()) {
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthenticated session creation attempt.");
      return;
  }
  ```

---

### Finding 2: Missing Authentication for Critical Session Cookie Issuance Endpoint
- **Severity**: **High** (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N — Base Score: 7.5)
- **CWE ID**: [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html) (also [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html))
- **File & Lines**: [`SessionCookieServlet.java:15`](file:///data/results-cyber/agy/set_a/pilot/1/basic/SessionCookieServlet.java#L15), [`SessionCookieServlet.java:23-50`](file:///data/results-cyber/agy/set_a/pilot/1/basic/SessionCookieServlet.java#L23-L50)
- **Vulnerable Code**:
  ```java
  // SessionCookieServlet.java:15
  @WebServlet(name = "SessionCookieServlet", urlPatterns = {"/auth/session", "/login"})
  public class SessionCookieServlet extends HttpServlet {
      ...
      @Override
      protected void doPost(HttpServletRequest request, HttpServletResponse response)
              throws ServletException, IOException {
          // Assumption: User authentication has already succeeded prior to this step.
          String sessionId = (String) request.getAttribute("authenticatedSessionId");
          if (sessionId == null || sessionId.trim().isEmpty()) {
              sessionId = request.getParameter("sessionId");
          }
  ```
- **Why It Is a Problem**:
  The servlet is mapped to public endpoint routes (`/auth/session` and `/login`). While the source code states the comment `// Assumption: User authentication has already succeeded prior to this step`, there is zero code enforcing or validating this assumption. There is no credential verification, no check of `request.getUserPrincipal()`, no security filter check, and no validation that the request originated from an authenticated internal dispatch.
  An unauthenticated remote attacker can issue an HTTP POST directly to `/login` or `/auth/session` specifying any arbitrary `sessionId`, receiving an HTTP 200 OK and a valid `JSESSIONID` cookie without supplying any credentials.
- **The Fix**:
  Enforce authentication checks before issuing a session cookie. Verify that a valid authenticated principal or security context exists. If this servlet is strictly an internal component meant to be forwarded to from an authentication handler, verify internal dispatch markers or restrict URL mapping so it cannot be invoked directly by external unauthenticated clients:
  ```java
  Principal principal = request.getUserPrincipal();
  if (principal == null && request.getAttribute("authenticatedSessionId") == null) {
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication required.");
      return;
  }
  ```

---

### Finding 3: Incomplete Blacklist Validation of Session Identifier (Cookie Injection / Delimiter Injection)
- **Severity**: **Medium** (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N — Base Score: 5.3)
- **CWE ID**: [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) (also [CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers](https://cwe.mitre.org/data/definitions/113.html), [CWE-1286: Improper Validation of Syntactic Integrity of Input](https://cwe.mitre.org/data/definitions/1286.html))
- **File & Lines**: [`SessionCookieServlet.java:69-71`](file:///data/results-cyber/agy/set_a/pilot/1/basic/SessionCookieServlet.java#L69-L71), [`SessionCookieServlet.java:74`](file:///data/results-cyber/agy/set_a/pilot/1/basic/SessionCookieServlet.java#L74)
- **Vulnerable Code**:
  ```java
  // SessionCookieServlet.java:68-74
  // Prevent HTTP Response Splitting / CRLF Injection attacks
  if (sessionId.contains("\r") || sessionId.contains("\n")) {
      throw new IllegalArgumentException("Session ID contains invalid control characters.");
  }

  // 1. Create the cookie containing the session identifier
  Cookie sessionCookie = new Cookie(SESSION_COOKIE_NAME, sessionId.trim());
  ```
- **Why It Is a Problem**:
  The validation in `addSessionCookie` uses a blacklist approach that checks only for carriage return (`\r`) and newline (`\n`) characters. However, HTTP `Set-Cookie` headers use semicolons (`;`) as delimiters separating the cookie value from attributes (`Path`, `Domain`, `SameSite`, `Max-Age`). If an unvalidated `sessionId` contains semicolons, spaces, quotes, or non-ASCII characters, an attacker might inject arbitrary cookie directives or additional cookies depending on the servlet container's cookie header serialization. Furthermore, blacklist filtering is inherently fragile compared to strict allowlist regex validation.
- **The Fix**:
  Enforce strict allowlist pattern matching on the session identifier format (e.g. hex or base64url characters only, with length bounds):
  ```java
  private static final Pattern SESSION_ID_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{16,128}$");

  if (!SESSION_ID_PATTERN.matcher(sessionId).matches()) {
      throw new IllegalArgumentException("Invalid session ID format.");
  }
  ```

---

### Finding 4: Exposure of Sensitive Session Identifier via HTTP Request Parameters
- **Severity**: **Medium** (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N — Base Score: 4.3)
- **CWE ID**: [CWE-598: Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html) (also [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html), [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html))
- **File & Lines**: [`SessionCookieServlet.java:30`](file:///data/results-cyber/agy/set_a/pilot/1/basic/SessionCookieServlet.java#L30)
- **Vulnerable Code**:
  ```java
  // SessionCookieServlet.java:30
  sessionId = request.getParameter("sessionId");
  ```
- **Why It Is a Problem**:
  In the Jakarta Servlet API, `request.getParameter("sessionId")` parses both application/x-www-form-urlencoded POST bodies AND the URL query string (e.g. `POST /login?sessionId=secret123`). When session identifiers are passed in URL query strings, they become exposed in multiple unencrypted or semi-public logs:
  - Reverse proxy and web server access logs (Nginx, Apache, CloudFront, ALB)
  - Browser history and caching proxies
  - HTTP `Referer` headers when navigating to external resources
  Session tokens are sensitive authentication secrets and must never be transmissible via URL parameters.
- **The Fix**:
  Remove `request.getParameter("sessionId")`. Session state must remain purely internal or be transferred via secure request bodies or headers intended for authentication payloads.

---

### Finding 5: Lack of Server-Side Cryptographically Secure Random Session ID Generation
- **Severity**: **Medium** (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N — Base Score: 5.3)
- **CWE ID**: [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html) (also [CWE-340: Generation of Predictable Numbers or Identifiers](https://cwe.mitre.org/data/definitions/340.html))
- **File & Lines**: [`SessionCookieServlet.java:28-36`](file:///data/results-cyber/agy/set_a/pilot/1/basic/SessionCookieServlet.java#L28-L36), [`SessionCookieServlet.java:74`](file:///data/results-cyber/agy/set_a/pilot/1/basic/SessionCookieServlet.java#L74)
- **Vulnerable Code**:
  ```java
  // The servlet assumes an ID is provided and sets whatever string was passed:
  Cookie sessionCookie = new Cookie(SESSION_COOKIE_NAME, sessionId.trim());
  ```
- **Why It Is a Problem**:
  The servlet relies on an external entity to supply the `sessionId` and does not generate or verify the entropy of the identifier. If the caller provides low-entropy, sequential, or predictable strings (e.g. `sessionId=123`), the session cookie becomes susceptible to brute-force guessing and hijacking attacks. Session identifiers must contain at least 128 bits of entropy generated by a CSPRNG (`java.security.SecureRandom`).
- **The Fix**:
  Generate session IDs using `java.security.SecureRandom` or rely on the container's standard session management via `request.getSession(true).getId()`.

---

## 4. Positive Security Controls Present in the Code

During the review against `performing-security-headers-audit` and `performing-web-application-penetration-test`, several positive defensive mechanisms were verified:

| Security Control | Code Location | Standard / Mitigation | Status |
|---|---|---|---|
| **HttpOnly Flag** | `SessionCookieServlet.java:77` | Mitigates XSS-based cookie theft ([CWE-1004](https://cwe.mitre.org/data/definitions/1004.html)) | **PASS** |
| **Secure Flag** | `SessionCookieServlet.java:80` | Restricts cookie to HTTPS/TLS ([CWE-614](https://cwe.mitre.org/data/definitions/614.html)) | **PASS** |
| **SameSite Attribute** | `SessionCookieServlet.java:90` | Set to `Strict` to mitigate CSRF ([CWE-1275](https://cwe.mitre.org/data/definitions/1275.html)) | **PASS** |
| **Scoped Cookie Path** | `SessionCookieServlet.java:83` | Restricts path to `/` | **PASS** |
| **Transient Max-Age** | `SessionCookieServlet.java:86` | Set to `-1` (expires when browser session ends) | **PASS** |
| **Basic CRLF Check** | `SessionCookieServlet.java:69` | Rejects `\r` and `\n` to prevent HTTP response splitting | **PARTIAL** (Blacklist only; needs allowlist) |

---

## 5. Remediation Recommendations & Secure Implementation

### Recommended Refactored Implementation
Below is a refactored implementation illustrating how to address all identified findings:

```java
package com.example.auth;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.regex.Pattern;

@WebServlet(name = "SessionCookieServlet", urlPatterns = {"/auth/session"})
public class SessionCookieServlet extends HttpServlet {

    public static final String SESSION_COOKIE_NAME = "JSESSIONID";
    public static final String COOKIE_PATH = "/";
    public static final int SESSION_COOKIE_MAX_AGE = -1;
    
    // Strict allowlist: 32+ characters of base64url or hex
    private static final Pattern VALID_SESSION_ID_PATTERN = 
            Pattern.compile("^[a-zA-Z0-9_-]{22,128}$");

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
        // 1. Verify that user authentication has succeeded
        if (request.getUserPrincipal() == null && request.getAttribute("authenticatedUser") == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication required.");
            return;
        }

        // 2. Obtain session ID securely: NEVER from request.getParameter()
        // Preferred: Use container-managed session with session fixation protection
        HttpSession currentSession = request.getSession(false);
        if (currentSession != null) {
            // Prevent Session Fixation by changing session ID upon authentication
            request.changeSessionId();
        } else {
            currentSession = request.getSession(true);
        }

        String sessionId = currentSession.getId();

        // 3. Attach secure cookie
        try {
            addSessionCookie(response, sessionId);
        } catch (IllegalArgumentException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid session token.");
            return;
        }

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"status\":\"success\",\"message\":\"Session established successfully.\"}");
    }

    public static void addSessionCookie(HttpServletResponse response, String sessionId) {
        if (response == null) {
            throw new IllegalArgumentException("HttpServletResponse must not be null.");
        }
        if (sessionId == null || !VALID_SESSION_ID_PATTERN.matcher(sessionId).matches()) {
            throw new IllegalArgumentException("Invalid session ID format.");
        }

        Cookie sessionCookie = new Cookie(SESSION_COOKIE_NAME, sessionId);
        sessionCookie.setHttpOnly(true);
        sessionCookie.setSecure(true);
        sessionCookie.setPath(COOKIE_PATH);
        sessionCookie.setMaxAge(SESSION_COOKIE_MAX_AGE);
        sessionCookie.setAttribute("SameSite", "Strict");

        response.addCookie(sessionCookie);
    }
}
```

---

## 6. Summary of Findings Table

| ID | Finding Title | Severity | CWE ID | Affected Location |
|---|---|---|---|---|
| **SEC-01** | Session Fixation via Client-Controlled Parameter | **High** | [CWE-384](https://cwe.mitre.org/data/definitions/384.html), [CWE-472](https://cwe.mitre.org/data/definitions/472.html) | [`SessionCookieServlet.java:29-31`](file:///data/results-cyber/agy/set_a/pilot/1/basic/SessionCookieServlet.java#L29-L31) |
| **SEC-02** | Missing Authentication for Session Issuance Endpoint | **High** | [CWE-306](https://cwe.mitre.org/data/definitions/306.html), [CWE-287](https://cwe.mitre.org/data/definitions/287.html) | [`SessionCookieServlet.java:15`](file:///data/results-cyber/agy/set_a/pilot/1/basic/SessionCookieServlet.java#L15), [`SessionCookieServlet.java:23-50`](file:///data/results-cyber/agy/set_a/pilot/1/basic/SessionCookieServlet.java#L23-L50) |
| **SEC-03** | Incomplete Blacklist Validation (Cookie Injection Risk) | **Medium** | [CWE-20](https://cwe.mitre.org/data/definitions/20.html), [CWE-113](https://cwe.mitre.org/data/definitions/113.html), [CWE-1286](https://cwe.mitre.org/data/definitions/1286.html) | [`SessionCookieServlet.java:69-71`](file:///data/results-cyber/agy/set_a/pilot/1/basic/SessionCookieServlet.java#L69-L71), [`SessionCookieServlet.java:74`](file:///data/results-cyber/agy/set_a/pilot/1/basic/SessionCookieServlet.java#L74) |
| **SEC-04** | Session Identifier Exposure via Query Parameter | **Medium** | [CWE-598](https://cwe.mitre.org/data/definitions/598.html), [CWE-532](https://cwe.mitre.org/data/definitions/532.html), [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [`SessionCookieServlet.java:30`](file:///data/results-cyber/agy/set_a/pilot/1/basic/SessionCookieServlet.java#L30) |
| **SEC-05** | Insufficient Session Identifier Randomness / Entropy | **Medium** | [CWE-330](https://cwe.mitre.org/data/definitions/330.html), [CWE-340](https://cwe.mitre.org/data/definitions/340.html) | [`SessionCookieServlet.java:28-36`](file:///data/results-cyber/agy/set_a/pilot/1/basic/SessionCookieServlet.java#L28-L36), [`SessionCookieServlet.java:74`](file:///data/results-cyber/agy/set_a/pilot/1/basic/SessionCookieServlet.java#L74) |
