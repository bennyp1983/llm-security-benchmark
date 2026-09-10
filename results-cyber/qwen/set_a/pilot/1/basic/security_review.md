# Security Review Report

**Project:** `auth-session-cookie` (Maven WAR, Java 17, Jakarta Servlet 6.0)
**Date:** 2026-09-09
**Method:** Workflow of the `review-code-for-security-vulnerabilities` router skill — (1) read every source file, (2) pull in matching specialised skills from the library, (3) apply each skill's checklist to the code, (4) report findings with CWE ids and `file:line` evidence.

---

## 1. What each file does

| File | Purpose |
|---|---|
| `pom.xml` | Maven build for a WAR. Dependencies: `jakarta.servlet-api` 6.0.0 (`provided`), JUnit Jupiter 5.10.2 (`test`), maven-war-plugin 3.4.0, surefire 3.2.5. No credentials, no suspect dependencies. |
| `src/main/java/com/example/auth/AuthenticatedSessionServlet.java` | `HttpServlet` mapped to `POST /auth/session`. Reads the **server-side request attribute** `com.example.auth.sessionId` (set by an upstream authentication step), and if present publishes it as a cookie via `SessionCookieFactory`, answering `204`; `401` if no identifier, `500` if the identifier is not a representable cookie value. Cookie name/path/max-age/Secure are configurable through servlet init parameters with safe defaults (`Secure=true`). |
| `src/main/java/com/example/auth/SessionCookieFactory.java` | Builds the session `Cookie`: `HttpOnly=true` always, `Secure` configurable (default on), absolute `Path` (default `/`), `Max-Age` (default `-1` = browser-session cookie). Validates the session identifier against the exact RFC 6265 cookie-octet set before use (header-injection guard). |
| `src/test/java/com/example/auth/SessionCookieIssuanceTest.java` | Unit tests: hardened cookie flags, 401 on missing/blank identifier, rejection of CRLF/semicolon/quote/space identifiers (parameterized), init-parameter handling, config validation. Uses JDK dynamic proxies as request/response stubs; no secrets. |

Security-relevant behaviours flagged in Step 1: session-cookie issuance and cookie security attributes (Secure/HttpOnly/SameSite/Path/Max-Age), Set-Cookie **header injection** (CRLF), session identifier **entropy**, session **expiration**, endpoint **authentication enforcement**, secrets in source, response-body output (XSS).

---

## 2. Findings

### F1 — Sensitive session cookie issued without a `SameSite` attribute

- **Severity:** Medium
- **CWE:** CWE-1275 (Sensitive Cookie Without SameSite Attribute)
- **Location:** `src/main/java/com/example/auth/SessionCookieFactory.java:62-69` (`forSession`); acknowledged in Javadoc `SessionCookieFactory.java:13-16`
- **Problem:** The factory sets `Path` (line 64), `Max-Age` (line 65), `Secure` (line 66) and `HttpOnly` (line 67), but no `SameSite` attribute is ever set. In the Servlet 6.0 typed `Cookie` API there is no dedicated setter, and the code explicitly defers this to *external container configuration* ("configure it at the container, e.g. Tomcat `<CookieProcessor sameSiteCookies=...>`"). Nothing in the code, the WAR, or the test suite enforces that configuration, so if the container is left at defaults or misconfigured, the browser falls back to the implicit `Lax`-ish legacy behavior that still sends the cookie on many cross-site requests (e.g. cross-site form `POST`s, `img`/`fetch` with `credentials`). Because this cookie is the application's session bearer, the missing attribute re-exposes every state-changing endpoint in the host application to CSRF. Note that the attribute *can* be set in the Servlet 6.0 API via `Cookie.setAttribute("SameSite", "Lax")` (present since Servlet 4.0 and honoured by Tomcat), so the gap is addressable in this component rather than only in deployment config.
- **Fix:** In `forSession`, add `cookie.setAttribute("SameSite", "Lax");` (or `"Strict"` if the app has no legitimate cross-site request flows), and assert the attribute in `SessionCookieIssuanceTest` so the guarantee does not depend on undocumented container configuration.

### F2 — Unbounded session lifetime: `cookieMaxAgeSeconds` has no validation or upper bound

- **Severity:** Low
- **CWE:** CWE-613 (Insufficient Session Expiration)
- **Location:** `src/main/java/com/example/auth/AuthenticatedSessionServlet.java:44` (parsed via `intInitParameter`) and `src/main/java/com/example/auth/SessionCookieFactory.java:65` (`cookie.setMaxAge(maxAgeSeconds)`), with the factory constructor at `SessionCookieFactory.java:44-55` accepting any `int`
- **Problem:** The init parameter is parsed with `Integer.parseInt` and passed straight to `Cookie.setMaxAge` with no range check. A deployment value such as `2147483647` produces an `Expires` date of roughly the year 5685 — a session cookie that effectively never expires server-side, defeating session-expiration controls (the factory's own `DEFAULT_MAX_AGE_SECONDS = -1` is at least a sane browser-session default). The same constructor path (used directly by any in-app caller, `SessionCookieFactory.java:40-42`) accepts the same unbounded value.
- **Fix:** Validate `maxAgeSeconds` in the factory constructor (e.g. reject values above a policy maximum such as 30 days = 2 592 000, and document the `-1` session-cookie semantics), throwing `IllegalArgumentException` on violation, and add a test.

### F3 — No minimum length / entropy backstop on the session identifier

- **Severity:** Low
- **CWE:** CWE-330 (Use of Insufficiently Random Values)
- **Location:** `src/main/java/com/example/auth/SessionCookieFactory.java:71-75` (`requireCookieValue`), called from `SessionCookieFactory.java:63`
- **Problem:** Validation only checks the *character set* (RFC 6265 cookie octets). Any non-empty value that matches — including a single character such as `"a"` — is published as the session cookie. Identifier entropy is delegated entirely to the upstream authentication component; this layer provides no backstop that would reject an implausibly weak/short identifier before it becomes a live session bearer. If the upstream generator is ever weakened, misconfigured, or replaced, nothing here would catch it.
- **Fix:** Enforce a minimum length (e.g. ≥ 16 characters) and, where feasible, a character-set/entropy check consistent with what the authentication component actually generates; fail with the existing `IllegalArgumentException` path.

---

## 3. Verified mitigations (checked and confirmed sound)

- **Set-Cookie header / CRLF injection — mitigated.** `SessionCookieFactory.java:33` compiles `[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]+`, which is byte-for-byte the RFC 6265 `cookie-octet` set (verified programmatically: the sets are identical). CR (0x0D), LF (0x0A), NUL, tab, space (0x20), DQUOTE (0x22), SEMI (0x3B — also blocks `; Path=…` attribute injection), and backslash (0x5C) are all excluded. `requireCookieValue` (`SessionCookieFactory.java:71-75`) rejects anything else before `Cookie` construction, and `AuthenticatedSessionServlet.java:59-64` maps the rejection to a generic `500` without echoing the value. The container's `Cookie.setValue` validation is a second layer. Covered by tests in `SessionCookieIssuanceTest.java` (parameterized cases `"abc\r\nSet-Cookie: evil=1"`, `"abc; x=admin=1"`, `"abc\"x\""`, `" leading-space"`).
- **HttpOnly — always set.** `SessionCookieFactory.java:67` `cookie.setHttpOnly(true)`, unconditionally; asserted in tests.
- **Secure — safe default.** `AuthenticatedSessionServlet.java:45` defaults the `cookieSecure` init parameter to `true`; applied at `SessionCookieFactory.java:66`. (See O2 for the config affordable override.)
- **Cookie path breakout — prevented.** Constructor rejects relative or empty paths: `SessionCookieFactory.java:48-50` (must be `/` or start with `/`); name must be non-blank (`SessionCookieFactory.java:45-47`). Both tested.
- **Authentication enforcement on the endpoint.** `AuthenticatedSessionServlet.java:50-55`: a request without the server-side attribute gets `401` and **no cookie**. Request attributes cannot be set by a client (they are not headers/parameters), so forced-browsing `POST /auth/session` unauthenticated cannot obtain a session cookie. Only `doPost` exists, so other HTTP methods get `405` with no cookie issuance.
- **No information disclosure.** Error bodies are fixed strings (`AuthenticatedSessionServlet.java:53-54`, `61-62`); the session identifier is never echoed, logged, or included in any exception message (the only interpolated message is an init-time config error, `AuthenticatedSessionServlet.java:88-90`, visible only to container logs).
- **No secrets in source.** No credentials, keys, or tokens in any source file, `pom.xml`, or test fixtures (the test's `dG9rZW4tYWJjMTIz` is an inert base64-style fixture, `SessionCookieIssuanceTest.java:23`).
- **No XSS surface.** The only user-adjacent value (the session ID) flows solely into the validated cookie value; the response body contains only static error strings and a `204` status.

## 4. Observations (contextual, not scored findings)

- **O1 — Security depends on who sets `SESSION_ID_ATTRIBUTE`.** The design is sound only because `resolveSessionId` (`AuthenticatedSessionServlet.java:76-78`) reads a *server-side* attribute that clients cannot forge. If any other code path (a filter, another servlet, a JSP) ever sets `com.example.auth.sessionId` from client-controlled input, the entire authentication boundary collapses. Ensure only the trusted authentication filter writes this attribute; consider making the constant package-private or adding a javadoc warning.
- **O2 — `cookieSecure=false` is a deployable escape hatch** (`AuthenticatedSessionServlet.java:45, 98-104`). The default is safe, but a misconfigured deployment could publish the session cookie over plain HTTP. If the application will always run behind TLS, consider removing the parameter entirely.
- **O3 — Cookie name not validated against the RFC 6265 token charset** (`SessionCookieFactory.java:45-47` accepts any non-blank name). The name comes from trusted deployment config, so this is a self-inflicted-misconfiguration risk only (e.g. an operator setting a name that collides with `JSESSIONID`, which the Javadoc at `SessionCookieFactory.java:25` warns about).
- **O4 — Session rotation and revocation are out of this component's scope.** Session-fixation defense (rotating the identifier at login) and logout invalidation live in the upstream authentication component and cannot be verified from these files; the default `Max-Age=-1` (browser-session cookie) does at least bound lifetime to the browser session.

---

## 5. Skills applied

| Skill (in `/root/.qwen/skills/`) | Applied to |
|---|---|
| `performing-security-headers-audit` | Step 5 cookie-attribute audit: Secure / HttpOnly / SameSite / Path / Max-Age of the issued session cookie → findings F1, F2; confirmed HttpOnly/Secure/Path mitigations. |
| `testing-api-authentication-weaknesses` | OWASP API2 session-management checks: unauthenticated endpoint access, token leakage in logs/URLs, session expiration, token entropy → findings F2, F3; confirmed 401 behavior and absence of leakage. |
| `testing-for-email-header-injection` | CRLF/header-injection *knowledge* applied to the Set-Cookie surface: verified the `Session_ID_PATTERN` regex (`SessionCookieFactory.java:33`) exactly covers the RFC 6265 cookie-octet set and blocks CR/LF/SEMI/DQUOTE → injection mitigated, no finding. |
| `bypassing-authentication-with-forced-browsing` | Forced access to `POST /auth/session` without upstream auth (401, no cookie), HTTP-method-based bypass (only `doPost` exists), no exposed admin/debug/backup resources in the WAR. |
| `performing-web-application-penetration-test` | WSTG Step 5 (session management): token analysis, expiration, cookie flags, CSRF interplay with SameSite; WSTG Steps 2–4 cross-checked (no SQLi/XSS/SSRF/command-injection input sinks exist). |
| `performing-cryptographic-audit-of-application` | Full-code scan for weak algorithms (MD5/SHA-1/DES/RC4/ECB), hardcoded secrets, weak RNG/KDF: none present — no `java.security`/`javax.crypto` usage anywhere in scope. |

## 6. Behaviours reviewed against general OWASP Top 10 / CWE knowledge (no matching library skill)

- **XSS (A03:2021 / CWE-79):** reviewed response-body construction — no user data reflected; not applicable.
- **Injection beyond headers (A03:2021 / CWE-89, CWE-78, CWE-918):** no SQL, command, SSRF, or template sinks exist in this code; only the Set-Cookie sink, covered by the header-injection skill.
- **Supply chain / dependencies (A06:2021 / CWE-506):** `pom.xml` dependency set reviewed — servlet API in `provided` scope, JUnit in `test` scope; no vulnerable or suspicious artifacts identified.
- **Insecure configuration (A05:2021 / CWE-16):** init-parameter defaults audited (all fail-safe: `Secure=true`, `Path=/`, session-cookie lifetime); residual config risks recorded as F2 and O2/O3.

**Bottom line:** the component is well hardened — header injection is provably blocked and HttpOnly/Secure/Path defaults are correct. The residual issues are the missing `SameSite` guarantee (F1), the unbounded `Max-Age` configuration (F2), and the absence of an identifier-strength backstop (F3), all low-to-medium severity and straightforward to fix in `SessionCookieFactory`.
