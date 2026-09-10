# Security Code Review — Session Cookie Issuance (Jakarta Servlet)

**Scope:** `src/main/java/com/example/auth/LoginServlet.java`, `src/main/java/com/example/auth/SessionCookieFactory.java`
**Date:** 2026-09-09
**Method:** `review-code-for-security-vulnerabilities` router skill — understand the code, select matching specialised skills from the library, apply each against the source, report with CWE ids and `file:line` evidence.

---

## 1. What the code does

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `LoginServlet.java` | `@WebServlet("/login")` endpoint. On POST it reads a session identifier from the request attribute `authenticatedSessionId`, hands it to `SessionCookieFactory`, and returns `204 No Content`. | Authentication boundary (assumed upstream), session-token handling, HTTP response construction. |
| `SessionCookieFactory.java` | Static factory that builds the `SESSIONID` cookie (`addSessionCookie`) and an expiring replacement for logout (`clearSessionCookie`). | Cookie security attributes (`Secure`, `HttpOnly`, `SameSite`, `Path`, `Max-Age`), session lifetime, session termination. |

**Keywords derived:** session management, session cookie attributes, session fixation, CSRF, XSS-driven session theft, cleartext transmission / TLS downgrade, session expiration and revocation, caching of sensitive responses, error handling.

**What the code gets right (verified, no finding):**
- `HttpOnly` is set on both cookies — `SessionCookieFactory.java:41`, `:66` — blocking `document.cookie` theft via XSS.
- `SameSite=Strict` is set on both cookies — `SessionCookieFactory.java:48`, `:68` — a correct browser-level CSRF mitigation (`performing-csrf-attack-simulation` Step 3: `Strict` is the strongest value and is not subject to the `Lax` top-level-GET bypass).
- No `Domain` attribute is set, so the cookie is host-only rather than being widened to sibling subdomains — `SessionCookieFactory.java:38`.
- `clearSessionCookie` correctly reuses the same name and path as the original cookie — `SessionCookieFactory.java:65`, `:71` — so the deletion actually matches (a common logout bug that is *absent* here).
- No hardcoded secrets, no SQL, no deserialization, no OS command execution, no file/path handling, and no outbound network calls anywhere in scope — those weakness classes do not apply.

---

## 2. Findings

### F-1 — HIGH — Session cookie's `Secure` flag is conditional on the current request's scheme
**CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute** (also **CWE-319: Cleartext Transmission of Sensitive Information**)
**Evidence:** `src/main/java/com/example/auth/SessionCookieFactory.java:45`
```java
cookie.setSecure(request.isSecure());
```
Same defect in the logout path: `src/main/java/com/example/auth/SessionCookieFactory.java:67`.

**Why it is a problem.** The `Secure` attribute is derived from the transport of the request that happened to create the session, not from a deployment policy. Any request that reaches the servlet over plain HTTP causes the session identifier to be issued *without* `Secure`, after which the browser will attach it to every future `http://` request to the host in cleartext. This is `performing-security-headers-audit` Scenario 3 ("Session Cookie Without Secure Flag") verbatim. Three realistic paths make this reachable in production, not just on the intended dev server:

- A TLS-terminating reverse proxy / load balancer that forwards to the container over HTTP makes `request.isSecure()` return `false` for *every* request unless the container is explicitly configured to honour `X-Forwarded-Proto` (`RemoteIpValve`, `server.forward-headers-strategy`). This is the default failure mode and it silently strips `Secure` from all production cookies.
- An attacker who can reach the victim's traffic triggers a single plain-HTTP request to `/login` (SSL stripping — see `performing-ssl-stripping-attack` Step 4). The application itself cooperates by issuing a non-`Secure` cookie.
- Once a non-`Secure` cookie exists in the jar, an attacker only has to induce *any* `http://` sub-resource request to the host to harvest the full session identifier — no server compromise required.

The in-code justification ("Kept in step with the current channel so the cookie is still usable on a plain-HTTP development server") trades a production security control for developer convenience, which is the wrong place to make that trade.

**Fix.** Set the flag unconditionally and make HTTP a deployment problem, not a code branch:
```java
cookie.setSecure(true);
```
If a plain-HTTP local dev loop is genuinely required, gate it on an explicit, fail-closed configuration flag that defaults to secure (e.g. `!"dev".equals(System.getProperty("app.profile"))`), never on a per-request property an attacker can influence. Pair with an HSTS header (see F-6) and configure the container to trust `X-Forwarded-Proto` behind the proxy.

---

### F-2 — MEDIUM — Session identifier is written to a persistent (on-disk) cookie, and lifetime is enforced only client-side
**CWE-539: Use of Persistent Cookies Containing Sensitive Information** (also **CWE-613: Insufficient Session Expiration**)
**Evidence:** `src/main/java/com/example/auth/SessionCookieFactory.java:17` and `:54`
```java
private static final int MAX_AGE_SECONDS = 30 * 60;
...
cookie.setMaxAge(MAX_AGE_SECONDS);
```

**Why it is a problem.** A positive `Max-Age` turns this into a *persistent* cookie: the browser serialises the live session identifier to disk (e.g. the Chrome `Cookies` SQLite database) instead of holding it in memory only. Consequences:

- The token survives browser close and is recoverable by any local malware, backup, forensic image, or another user of a shared/kiosk machine — the exact class of artefact that credential-stealer malware harvests first.
- `Max-Age` is a *client-side* hint. It is trivially removed by an attacker who has already captured the cookie value (they simply replay the raw `SESSIONID` string). Nothing in this code establishes a server-side idle timeout or absolute timeout, so the 30-minute window is a comfort, not a control. `performing-web-application-penetration-test` Step 5 explicitly requires verifying that sessions expire server-side by replaying a captured token after the timeout — this code offers no such enforcement.

**Fix.** Make the cookie a browser-session cookie and enforce lifetime where it counts:
```java
cookie.setMaxAge(-1); // session cookie: not persisted to disk
```
and independently enforce both an idle timeout (~30 min) and an absolute timeout on the server-side session record, rejecting identifiers past either bound regardless of what the client sends.

---

### F-3 — MEDIUM — Logout deletes the client-side cookie but never invalidates the session server-side
**CWE-613: Insufficient Session Expiration** (also **CWE-772/CWE-384 class: session remains usable after intended termination**)
**Evidence:** `src/main/java/com/example/auth/SessionCookieFactory.java:63-76` — the entire `clearSessionCookie` method only calls `response.addCookie(...)` with `setMaxAge(0)`; there is no call to `HttpSession.invalidate()`, no session-store revocation, and no token blacklisting anywhere in scope.

**Why it is a problem.** Deleting the cookie is a request to the *victim's own browser* to forget the token. It does nothing to the identifier itself. An attacker who obtained the session ID beforehand — via F-1 cleartext interception, via the on-disk artefact from F-2, or from a proxy/CDN cache per F-4 — keeps a fully valid session after the user clicks "log out", for the full server-side lifetime of that session. `testing-api-authentication-weaknesses` Step 5 flags precisely this ("Token still valid after logout — no server-side revocation") as a HIGH-severity condition. It also means the user's own remediation action ("I think I was phished, let me log out") is ineffective.

**Fix.** Revoke first, then clear the cookie:
```java
HttpSession session = request.getSession(false);
if (session != null) {
    session.invalidate();   // or: sessionStore.revoke(sessionId)
}
// then add the Max-Age=0 replacement cookie
```
Also revoke all of a user's sessions on password change and on privilege change.

---

### F-4 — MEDIUM — The `Set-Cookie` response carries no `Cache-Control: no-store`
**CWE-525: Use of Web Browser Cache Containing Sensitive Information** (also **CWE-524: Use of Cache Containing Sensitive Information**)
**Evidence:** `src/main/java/com/example/auth/LoginServlet.java:27-29`
```java
SessionCookieFactory.addSessionCookie(request, response, sessionId);
response.setStatus(HttpServletResponse.SC_NO_CONTENT);
```
No `response.setHeader("Cache-Control", ...)` is set on this or any other path in scope.

**Why it is a problem.** `performing-security-headers-audit` Step 6 requires `Cache-Control: no-store, no-cache, must-revalidate` on responses carrying sensitive data. This response body is empty, but the *headers* contain the session identifier. Without an explicit directive, the caching behaviour of any intermediary — a corporate proxy, a CDN, a debug/logging tier, or the browser's own back-forward cache — is left to heuristics. A shared cache that stores and later replays this response hands the session identifier to a different user. Because `/login` is a `POST`, most well-behaved caches will skip it, which is why this is MEDIUM rather than HIGH — but "most caches usually behave" is not a control.

**Fix.** Set the directives explicitly on every authentication response:
```java
response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
response.setHeader("Pragma", "no-cache");
```

---

### F-5 — LOW/MEDIUM — Cookie is not protected against being overwritten by a related host (no `__Host-` prefix)
**CWE-384: Session Fixation** (also **CWE-565: Reliance on Cookies without Validation and Integrity Checking**)
**Evidence:** `src/main/java/com/example/auth/SessionCookieFactory.java:14` and `:52`
```java
public static final String COOKIE_NAME = "SESSIONID";
...
cookie.setPath(contextPath.isEmpty() ? "/" : contextPath);
```

**Why it is a problem.** Cookies are not origin-isolated. Any content controlled by an attacker on a sibling subdomain — a compromised `blog.example.com`, an XSS on a marketing host, a subdomain-takeover of a dangling DNS record, or even a plain-HTTP host per F-1 — can issue `Set-Cookie: SESSIONID=<attacker_value>; Domain=example.com; Path=/`. The browser then sends both cookies to the application with no attribute distinguishing which one the application itself set, and the server has no way to tell them apart. If the injected value wins, the victim authenticates into a session the attacker knows: classic session fixation. `performing-security-headers-audit` Step 5 explicitly calls for `__Host-` / `__Secure-` prefix checks for this reason.

**Fix.** Adopt the `__Host-` prefix, which browsers enforce (cookie must be `Secure`, `Path=/`, and carry no `Domain` — and, critically, cannot be set over plain HTTP):
```java
public static final String COOKIE_NAME = "__Host-SESSIONID";
// requires: setSecure(true) (F-1) and setPath("/")
```
Note the `__Host-` prefix mandates `Path=/`, which conflicts with the current context-path scoping at `:52`; path scoping is not a security boundary between origins anyway (any same-origin script can read any path), so this is a safe trade. Independently, always issue a *fresh* session identifier at the moment of authentication and discard any identifier presented by the client beforehand.

---

### F-6 — LOW — No HSTS header is emitted, leaving the HTTPS-only guarantee unenforced
**CWE-319: Cleartext Transmission of Sensitive Information**
**Evidence:** `src/main/java/com/example/auth/LoginServlet.java:20-30` — the authentication response sets only a status code; no `Strict-Transport-Security` header is set here or anywhere in scope.

**Why it is a problem.** This is `performing-security-headers-audit` Scenario 4 ("Missing HSTS Enabling SSL Stripping"). Without HSTS, a network-positioned attacker downgrades the victim's connection to HTTP (`performing-ssl-stripping-attack` Step 3-4); the application then cooperates by issuing a non-`Secure` session cookie (F-1) which is readable on the wire. F-1 and F-6 compound each other: HSTS is the control that makes `setSecure(true)` reliable from the very first visit.

**Fix.** Emit HSTS from a security filter or at the reverse proxy for all HTTPS responses, and redirect HTTP to HTTPS:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

---

### F-7 — LOW — The endpoint trusts an unverified request attribute as proof of authentication, and fails open-ended on absence
**CWE-306: Missing Authentication for Critical Function** (also **CWE-248: Uncaught Exception**, **CWE-209: Information Exposure Through an Error Message**)
**Evidence:** `src/main/java/com/example/auth/LoginServlet.java:25-27`
```java
String sessionId = (String) request.getAttribute("authenticatedSessionId");
SessionCookieFactory.addSessionCookie(request, response, sessionId);
```

**Why it is a problem.** The servlet is mapped at `/login` and is directly reachable, yet it performs no authentication itself and no check that an upstream filter ran — the guarantee lives entirely in a code comment at `:23-24`. Request attributes are server-side, so they are not directly attacker-settable over HTTP, which keeps this LOW; but the design is fragile: if the filter is unmapped, misordered, reordered by a `web.xml` change, or bypassed by an alternative mapping/forward, `/login` still executes and the failure is silent. When the attribute is absent, `SessionCookieFactory.addSessionCookie` throws `IllegalArgumentException` (`SessionCookieFactory.java:34-36`), which escapes `doPost` uncaught and produces a container error page — on a default Tomcat configuration that page includes the stack trace and version banner, leaking internal class names and the technology stack.

Secondary concern on the same lines: the identifier is passed straight into the cookie value with only an emptiness check (`SessionCookieFactory.java:34`). If a future upstream component ever derives that attribute from user input, control characters in the value become a header-injection vector (**CWE-113: HTTP Response Splitting**). Modern Tomcat's cookie processor rejects invalid characters, so this is defence-in-depth rather than an exploitable path today.

**Fix.** Make the precondition explicit and fail closed with a clean status:
```java
Object attr = request.getAttribute("authenticatedSessionId");
if (!(attr instanceof String sessionId) || sessionId.isEmpty()) {
    response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    return;
}
```
Enforce the authentication filter via a container-level constraint rather than convention, validate the identifier against the expected charset/length before it reaches a header, and configure a custom error page so stack traces are never rendered to clients.

---

## 3. Summary

| ID | Severity | CWE | Location | Issue |
|---|---|---|---|---|
| F-1 | HIGH | CWE-614 / CWE-319 | `SessionCookieFactory.java:45`, `:67` | `Secure` flag conditional on `request.isSecure()` |
| F-2 | MEDIUM | CWE-539 / CWE-613 | `SessionCookieFactory.java:17`, `:54` | Session ID in a persistent on-disk cookie; client-side-only lifetime |
| F-3 | MEDIUM | CWE-613 | `SessionCookieFactory.java:63-76` | Logout clears cookie but does not invalidate the session server-side |
| F-4 | MEDIUM | CWE-525 / CWE-524 | `LoginServlet.java:27-29` | `Set-Cookie` response lacks `Cache-Control: no-store` |
| F-5 | LOW/MED | CWE-384 / CWE-565 | `SessionCookieFactory.java:14`, `:52` | No `__Host-` prefix; cookie overwritable by a related host |
| F-6 | LOW | CWE-319 | `LoginServlet.java:20-30` | No HSTS header; enables SSL-stripping downgrade |
| F-7 | LOW | CWE-306 / CWE-248 / CWE-209 | `LoginServlet.java:25-27` | Unverified authentication precondition; uncaught exception on absence |

**Highest-value single change:** `cookie.setSecure(true)` unconditionally (F-1), paired with HSTS (F-6). Together they close the cleartext-interception path that makes F-2, F-3 and F-4 exploitable in practice.

---

## 4. Skills applied

Selected by grepping the skill-library directory names for the Step 1 keywords, then skimming candidate `description` frontmatter; read and applied in priority order:

1. **`performing-security-headers-audit`** — Step 5 (cookie security attributes: `Secure`/`HttpOnly`/`SameSite`/`Path`/`Max-Age`, `__Host-`/`__Secure-` prefixes), Step 6 (`Cache-Control` on sensitive responses), Step 2 (HSTS), Scenarios 3 and 4. → F-1, F-4, F-5, F-6.
2. **`testing-api-authentication-weaknesses`** — Step 5 session-management checks (token revocation on logout, expiration, server-side invalidation). → F-3, F-2.
3. **`performing-web-application-penetration-test`** — Step 5 Session Management Testing (cookie flags, server-side idle/absolute expiration, session-token handling) and Step 4 session-fixation guidance. → F-2, F-5.
4. **`performing-csrf-attack-simulation`** — Step 3 SameSite/browser-level CSRF defences. → verified as correctly implemented; no finding.
5. **`performing-ssl-stripping-attack`** — Step 3-4 HSTS enforcement and HTTPS-downgrade attack path. → F-1, F-6.
6. **`testing-for-sensitive-data-exposure`** — Step 3 data-transmission security (cleartext endpoints, unprotected transmission of secrets). → F-1.

**Behaviours reviewed against general OWASP Top 10 / CWE knowledge where no library skill matched:** Jakarta Servlet-specific concerns — servlet lifecycle and thread-safety (no mutable shared state; `SessionCookieFactory` is a stateless final class with a private constructor — no finding), `@WebServlet` reachability and filter-ordering assumptions, exception propagation out of `doPost` and container error-page disclosure, and cookie-value character validation / HTTP response splitting. These informed F-7. No library skill covers Java/Jakarta servlet internals directly.
