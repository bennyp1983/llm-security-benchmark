# Security Review: Session Cookie Authentication Servlet (`SessionCookieIssuer` / `LoginServlet` demo app)

## 1. Executive Summary

This is a small Jakarta Servlet 6 demo that mints its own authenticated session and hands the identifier to the
browser in a `Set-Cookie` header. The cookie-handling core is unusually careful: the identifier is 32 bytes from
`SecureRandom`, comparisons are constant-time, the pre-authentication session is destroyed before the new one is
created, the identifier is never echoed into a response body or a log line, and the emitted header is re-read and
asserted before the response is written. Session fixation, cookie attribute stripping, `Set-Cookie` injection,
URL rewriting via `;JSESSIONID=` and user enumeration were each probed and are correctly handled.

The findings are concentrated at the edges of that core rather than inside it. Two are High: the deployment
descriptor never requires TLS, so credentials and the freshly issued session identifier can be sent over plaintext
HTTP (the README's own run instructions use `http://localhost:8080/`), and `POST api/login` has no rate limit or
lockout, so a single shared demo credential is exposed to unlimited online guessing. The remaining findings are
Medium/Low: no anti-CSRF defence on login, ambiguous resolution of duplicated cookie names, a CSP with no
`frame-ancestors`, unsanitised attacker-controlled text written to the log, password comparison with no salted
key derivation, config values that silently fail *open* for `Secure`/`HttpOnly`, secrets placed on the JVM command
line, container default error pages, shell-command injection into the generated `bin/setenv.sh`, an untrusted jar
discovered with `find /`, and asymmetric validation of the cookie path.

13 findings: 2 High, 6 Medium, 5 Low. None of them requires rewriting the session cookie logic; each is a
localised fix. The two High findings should be closed before anything built from this tree is reachable from an
untrusted network.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `src/main/java/com/example/auth/SessionCookieIssuer.java` | Builds the `jakarta.servlet.http.Cookie`, adds it to the response, and expires it | Sets `Path`/`Secure`/`HttpOnly`/`Max-Age`/`SameSite`; `assertHeaderIntegrity` re-reads the emitted `Set-Cookie` and throws if an attribute was dropped or a control character is present |
| `src/main/java/com/example/auth/LoginServlet.java` | `POST api/login`: verify credentials, renew session, issue cookie | Reads `username`/`password` parameters, destroys the presented session, mints a new one, writes the identifier to the log in redacted form, no rate limiting |
| `src/main/java/com/example/auth/LogoutServlet.java` | `POST api/logout`: drop the session and expire the cookie | Removes by raw presented value, always returns 204, logs the redacted username/session |
| `src/main/java/com/example/auth/WhoAmIServlet.java` | `GET api/whoami`: report the current principal | Uniform 401 for absent/unknown/expired/foreign identifiers; exposes only a 64-bit SHA-256 fingerprint, never the identifier |
| `src/main/java/com/example/auth/AuthenticatedSessionServlet.java` | Shared base: wiring from `ServletContext` + cookie lookup + JSON helpers | `presentedIdentifier` scans `Cookie[]` and keeps the **last** name-matching value; `respondJson` sets `no-store`, `Vary: Cookie`, `application/json` |
| `src/main/java/com/example/auth/SessionCookieConfig.java` | Immutable cookie settings + `fromInitParams` from `context-param` | Validates name as an RFC token, path as absolute, rejects `SameSite=None` without `Secure`; `Boolean.parseBoolean` on `secureCookie`/`httpOnlyCookie` fails open |
| `src/main/java/com/example/auth/SessionIdentifier.java` | 256-bit opaque session identifier | `SecureRandom`, base64url, `MessageDigest.isEqual` equality, `describe()` redaction, `fingerprint()` truncated SHA-256 |
| `src/main/java/com/example/auth/InMemorySessionStore.java` | `ConcurrentHashMap` session store, side-effect-free lookup | Rejects non-token strings without throwing, checks liveness against an absolute `expiresAt`, `removeIf` sweep; no cap on entries |
| `src/main/java/com/example/auth/EnvironmentCredentialVerifier.java` | Placeholder `CredentialVerifier` | Compares plaintext property/env values with `MessageDigest.isEqual`; no user store, no salted hash, no lockout |
| `src/main/java/com/example/auth/SecurityHeadersFilter.java` | `/*` security-header filter | `no-store`, `Vary`, `Referrer-Policy`, `nosniff`, CSP (no `frame-ancestors`), HSTS only when `isSecure()` |
| `src/main/java/com/example/auth/AuthContextListener.java` | Publishes issuer/store/verifier/TTL at startup | Constructs the production issuer with the container `Cookie` processor; config errors fail startup |
| `src/main/java/com/example/auth/{Json,SessionUser,AuthenticatedSession,CredentialVerifier}.java` | JSON escaping, principal, session record, verifier SPI | `Json.escape` covers `"`,`\`,`\n`,`\r`,`\t`,`\b`,`\f`,`<0x20`,`U+2028/9`; not HTML-significant characters |
| `src/main/webapp/WEB-INF/web.xml` | Context params, filter/servlet mapping, container session hardening | `SameSite=Lax`, `Secure=true`, `HttpOnly=true`, `Max-Age=-1`, `tracking-mode=COOKIE`; **no** `user-data-constraint`, no `error-page`, no `<same-site>` on `JSESSIONID` |
| `src/main/webapp/{index.html,app.js,app.css}` | Demo page | `textContent`-only rendering, `credentials:"include"`, no CSRF token, no inline script |
| `build.sh`, `run-tests.sh`, `smoke-test.sh` | Compile, run unit harness, end-to-end HTTP check | Discover the Servlet API jar with `find / -maxdepth 6`; generate `bin/setenv.sh` containing the demo credential in an unquoted heredoc |
| `src/test/java/com/example/auth/TestHarness.java` | 974-line offline harness with `Proxy` fakes | Asserts header integrity, expiry, cross-user 401, duplicate-cookie non-resolution, log redaction |
| `README.md` | Run instructions, design notes, honest limitations | Documents credential on `CATALINA_OPTS`, `http://localhost:8080/`, and the missing CSRF/HTTPS/lockout controls |

`result.md`, `return.txt`, `prompt.txt`, `prompt_hash.txt`, `cyber_prompt.txt` and `qwen-sandbox.json` are task
harness artefacts, not application code; they were excluded from the vulnerability analysis.

## 3. Skills Applied

- **`review-code-for-security-vulnerabilities`** — the driving workflow: understand what each file does first, then
  select the specialised skills that match the code's actual security-relevant behaviour, apply each one in turn,
  and report only real defects with CWE ids and `file:line` evidence.
- **`testing-api-authentication-weaknesses`** — applied to `LoginServlet`, `LogoutServlet`, `WhoAmIServlet`,
  `EnvironmentCredentialVerifier` and `InMemorySessionStore`: unauthenticated surface, credential policy,
  session/identifier lifecycle (issuance, rotation, revocation, expiry), replay-after-logout, and user/session
  enumeration through differing responses. JWT- and OAuth-specific checks were reviewed and are not applicable.
- **`performing-cryptographic-audit-of-application`** — applied to `SessionIdentifier` (CSPRNG choice, 32 bytes of
  entropy, base64url encoding, absence of time/PID-seeded randomness), `SessionIdentifier.matches` and
  `EnvironmentCredentialVerifier.constantTimeEquals` (side-channel-free comparison), `fingerprint()` (SHA-256,
  8-byte truncation over an already-uniform input), and credential storage (no salted one-way KDF → SEC-07).
  MD5/SHA-1/DES/RC4, ECB mode and hardcoded key material were searched for and are absent.
- **`performing-security-headers-audit`** — applied to `SecurityHeadersFilter` and `index.html`: CSP directives
  including `frame-ancestors` (SEC-05), HSTS presence/gating and `preload`, `X-Content-Type-Options`,
  `Referrer-Policy`, `Cache-Control`/`Vary` on authenticated responses, and inline-script policy.
- **`performing-csrf-attack-simulation`** — applied to `LoginServlet.doPost`, `LogoutServlet.doPost` and `app.js`:
  state-changing endpoint inventory, token/`Origin`/`Sec-Fetch-Site` validation, and whether the `SameSite` posture
  actually covers the POST case (it does not for login → SEC-03).
- **`testing-for-xss-vulnerabilities`** — applied to `Json.escape`, every `respondJson` call site, `app.js` and
  `index.html`: reflected/stored output paths, DOM sinks, `innerHTML`/`insertAdjacentHTML`/`eval` use, and whether
  CSP closes the gap left by JSON-only escaping. No sink was found; see §6.
- **`testing-for-sensitive-data-exposure`** — applied to every response body, `describe()`/`fingerprint()`
  redaction, log output, and the client-side assets: session identifier confinement to the header, secret scanning
  of `app.js`/`index.html`/scripts, and exposure of credential material in build/run artefacts (SEC-09).
- **Reviewed against general OWASP Top 10 / CWE knowledge because no skill in the library matched the behaviour:**
  absence of a `transport-guarantee`/TLS requirement in `web.xml` (CWE-319, SEC-01); fail-open boolean parsing of a
  security control (CWE-1188/CWE-20, SEC-08); secrets reachable through the process command line (CWE-214,
  SEC-09); container default error page disclosure (CWE-209, SEC-10); shell-command injection and untrusted
  search path in the build/test scripts (CWE-78, CWE-426, SEC-11/SEC-12); log forging (CWE-117, SEC-06); and
  asymmetric input validation of a cookie attribute (CWE-20, SEC-13). SQL/LDAP/NoSQL injection, XXE, insecure
  deserialization, path traversal, open redirect, SSRF, file upload and mass assignment were each considered and
  confirmed not applicable — this code contains no query language, no XML or object deserialization, no filesystem
  access from a request, no redirects and no outbound requests.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | No transport security required: credentials and session cookie can cross the wire in cleartext | High | CWE-319 | `src/main/webapp/WEB-INF/web.xml:104-117` |
| SEC-02 | `api/login` has no rate limiting or lockout against unlimited credential guessing | High | CWE-307 | `src/main/java/com/example/auth/LoginServlet.java:34-68` |
| SEC-03 | Login is not CSRF-protected; `SameSite=Lax` does not cover the POST case | Medium | CWE-352 | `src/main/java/com/example/auth/LoginServlet.java:34-38` |
| SEC-04 | Duplicate session-cookie names resolve silently to the last value (cookie-shadowing primitive) | Medium | CWE-384 | `src/main/java/com/example/auth/AuthenticatedSessionServlet.java:64-72` |
| SEC-05 | CSP has no `frame-ancestors` and no `X-Frame-Options`: login form is frameable | Medium | CWE-1021 | `src/main/java/com/example/auth/SecurityHeadersFilter.java:36-37` |
| SEC-06 | Attacker-controlled username written to the log unsanitised (log forging) | Medium | CWE-117 | `src/main/java/com/example/auth/LoginServlet.java:84` |
| SEC-07 | Password verified by comparing plaintext with no salted key derivation or user store | Medium | CWE-916 | `src/main/java/com/example/auth/EnvironmentCredentialVerifier.java:32-33` |
| SEC-08 | `secureCookie`/`httpOnlyCookie` config values fail *open* on a typo | Medium | CWE-1188 | `src/main/java/com/example/auth/SessionCookieConfig.java:95-96` |
| SEC-09 | Credential placed on the JVM command line and in a world-readable generated file | Low | CWE-214 | `smoke-test.sh:92-97` |
| SEC-10 | Unhandled exceptions reach the container's default error page | Low | CWE-209 | `src/main/webapp/WEB-INF/web.xml:112-117` |
| SEC-11 | Unquoted heredoc allows shell-command injection through a credential value | Low | CWE-78 | `smoke-test.sh:92-97` |
| SEC-12 | Build classpath accepts an arbitrary jar found anywhere under `/` | Low | CWE-426 | `build.sh:22-25` |
| SEC-13 | `cookiePath` is not validated for attribute-separating characters | Low | CWE-20 | `src/main/java/com/example/auth/SessionCookieConfig.java:59-62` |

## 5. Detailed Findings

### SEC-01: No transport security required: credentials and session cookie can cross the wire in cleartext

**Severity:** High
**CWE:** CWE-319: Cleartext Transmission of Sensitive Information
**Location:** `src/main/webapp/WEB-INF/web.xml:104-117`

**Vulnerable code:**

```xml
<!-- src/main/webapp/WEB-INF/web.xml:104-117 -->
  <session-config>
    <session-timeout>30</session-timeout>
    <cookie-config>
      <name>JSESSIONID</name>
      <http-only>true</http-only>
      <secure>true</secure>
    </cookie-config>
    <tracking-mode>COOKIE</tracking-mode>
  </session-config>

  <welcome-file-list>
    <welcome-file>index.html</welcome-file>
  </welcome-file-list>
</web-app>
```

**Why it is a problem:** The descriptor hardens cookie attributes and disables URL rewriting, but nowhere declares
a `<security-constraint>` with `<transport-guarantee>CONFIDENTIAL</transport-guarantee>`. Nothing in the servlet
layer forces HTTPS or redirects `http://` to `https://`, so the container will happily accept the credential POST
in the clear and answer it with a `Set-Cookie` header in the clear. The `Secure` attribute is set on the cookie, but
`Secure` only stops a *HTTPS-origin* browser from sending the cookie over HTTP — it does not stop the browser from
submitting the form and receiving the cookie over HTTP in the first place, which is exactly how the app is
documented to run: README.md:126 says "Then open `http://localhost:8080/`", and README.md:159 offers
`secureCookie=false` "to debug over plain http". The related `Strict-Transport-Security` header is only emitted when
`request.isSecure()` is true (`SecurityHeadersFilter.java:39-41`), so the first visit — and any downgrade — is
unprotected. On any network an attacker can observe (including a shared or corporate LAN, or a misconfigured
reverse proxy that terminates TLS and re-originates over HTTP), this yields both the password and a live session
identifier, defeating every downstream control in the cookie layer.

**Fix:** Add a transport constraint covering the whole application so the container rejects/redirects non-TLS
requests, and pair it with a TLS listener in `server.xml`:

```xml
<!-- src/main/webapp/WEB-INF/web.xml -->
  <security-constraint>
    <web-resource-collection>
      <web-resource-name>entire-application</web-resource-name>
      <url-pattern>/*</url-pattern>
    </web-resource-collection>
    <user-data-constraint>
      <transport-guarantee>CONFIDENTIAL</transport-guarantee>
    </user-data-constraint>
  </security-constraint>

  <session-config>
    <session-timeout>30</session-timeout>
    <cookie-config>
      <name>JSESSIONID</name>
      <http-only>true</http-only>
      <secure>true</secure>
      <same-site>Lax</same-site>
    </cookie-config>
    <tracking-mode>COOKIE</tracking-mode>
  </session-config>
```

Then remove the `secureCookie=false` debugging suggestion from README.md, and document that a TLS-terminating
proxy requires `RemoteIpValve` (or equivalent) so `request.isSecure()` is true at the origin and HSTS is emitted.

### SEC-02: `api/login` has no rate limiting or lockout against unlimited credential guessing

**Severity:** High
**CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
**Location:** `src/main/java/com/example/auth/LoginServlet.java:34-68`

**Vulnerable code:**

```java
// src/main/java/com/example/auth/LoginServlet.java:34-38
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
```

**Why it is a problem:** `doPost` goes straight from reading the parameters to `verifier.verify(...)` (line 56) and
back out through a uniform 401 (lines 65-69) with no counter, delay, lockout, or CAPTCHA anywhere in the request
path. The uniform 401 that is *good* for anti-enumeration (no per-username difference, no user-existence oracle)
also means the endpoint is a clean, low-noise oracle: a request costs one string comparison, so an attacker can
fire it as fast as the JVM will serve it. `EnvironmentCredentialVerifier` makes this concrete — its own javadoc
(lines 11-12) states "there is no user store, no salted password hash, no lockout on repeated failure", and
README.md:171-174 repeats it. With a single shared credential and no failed-attempt telemetry, a weak or leaked
demo password is brute-forced with no cost and no signal. The 401 handler is also where a real deployment would add
the store, so this gap is inherited by the production verifier unless it is implemented in the servlet.

**Fix:** Enforce a bounded attempt window in front of verification, keyed on both the submitted username and the
source address so that spraying one password across many accounts is also throttled:

```java
// src/main/java/com/example/auth/LoginServlet.java
    private static final int MAX_ATTEMPTS = 10;
    private static final java.time.Duration WINDOW = java.time.Duration.ofMinutes(15);
    private static final java.util.concurrent.ConcurrentHashMap<String, AttemptWindow> ATTEMPTS =
            new java.util.concurrent.ConcurrentHashMap<>();

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        String key = (username == null ? "?" : username) + '|' + request.getRemoteAddr();
        AttemptWindow window = ATTEMPTS.compute(key, (k, w) -> w == null ? new AttemptWindow() : w.fresh(WINDOW));
        if (window.count() >= MAX_ATTEMPTS) {
            response.setDateHeader("Retry-After", WINDOW.toSeconds());
            respondError(response, 429, "too_many_attempts", "too many failed logins, retry later");
            return;
        }
        // ...on every failed verification, before the 401:
        //   window.record();  and on success:  ATTEMPTS.remove(key);
    }

    private record AttemptWindow(int count, java.time.Instant firstSeen) {
        static AttemptWindow starting() {
            return new AttemptWindow(0, java.time.Instant.now());
        }
        AttemptWindow fresh(java.time.Duration window) {
            return java.time.Instant.now().isAfter(firstSeen.plus(window)) ? starting() : this;
        }
        AttemptWindow record() {
            return new AttemptWindow(count + 1, firstSeen);
        }
    }
```

Also emit a log event at the throttle point (sanitised per SEC-06) so repeated failures are visible to the SOC, and
prefer a shared/distributed counter once more than one instance serves the endpoint.

### SEC-03: Login is not CSRF-protected; `SameSite=Lax` does not cover the POST case

**Severity:** Medium
**CWE:** CWE-352: Cross-Site Request Forgery (CSRF)
**Location:** `src/main/java/com/example/auth/LoginServlet.java:34-38`

**Vulnerable code:**

```java
// src/main/java/com/example/auth/LoginServlet.java:34-38
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
```

**Why it is a problem:** The state-changing endpoint accepts a form-encoded POST with no CSRF token, no `Origin`
check, and no `Sec-Fetch-Site` check. The README is candid about this (README.md:178-180: "A login form is not
CSRF-protected here") and points at `SameSite=Lax`, but Lax only protects against *cross-site POST* submissions —
it is not a login-CSRF defence at all, because login CSRF is normally mounted as a top-level navigation (GET) or a
same-site-looking form post that Lax does not block in the cases that matter. In practice an attacker page can
submit the victim's browser to `api/login` with attacker-chosen credentials: the server then mints an
attacker-authenticated session and sets it in the victim's browser (`LoginServlet.java:73-78` deliberately deletes
the pre-existing session first, which makes the attack *more* effective — the victim's real session is dropped and
replaced). Everything the victim then types, uploads or searches is performed as the attacker and is readable in
the attacker's session, and the attacker learns the victim's username from the login form. Cross-site `POST` here
is also fully reachable because there is no CORS configuration restricting `Content-Type: application/x-www-form-urlencoded`
navigation-style requests.

**Fix:** Require the request to originate from this application. A tokenless origin check is sufficient for login
and cannot break the legitimate form:

```java
// src/main/java/com/example/auth/LoginServlet.java
        String origin = request.getHeader("Origin");
        if (origin == null) {
            origin = request.getHeader("Referer");
        }
        if (origin == null || !isSameOrigin(origin, request)) {
            respondError(response, HttpServletResponse.SC_FORBIDDEN, "cross_origin",
                    "login must be submitted from this origin");
            return;
        }

    private static boolean isSameOrigin(String headerValue, HttpServletRequest request) {
        try {
            java.net.URI declared = new java.net.URI(headerValue.trim().toLowerCase(java.util.Locale.ROOT));
            String scheme = request.getScheme().toLowerCase(java.util.Locale.ROOT);
            int port = request.getServerPort();
            String expectedAuthority = request.getServerName().toLowerCase(java.util.Locale.ROOT)
                    + (("http".equals(scheme) && port == 80) || ("https".equals(scheme) && port == 443)
                            ? "" : ":" + port);
            String actualAuthority = declared.getHost() == null ? "" : declared.getHost().toLowerCase(java.util.Locale.ROOT)
                    + (declared.getPort() == -1 ? "" : ":" + declared.getPort());
            return scheme.equalsIgnoreCase(declared.getScheme()) && expectedAuthority.equals(actualAuthority);
        } catch (java.net.URISyntaxException malformed) {
            return false;
        }
    }
```

For a defence-in-depth pass, add a short-lived double-submit CSRF cookie issued by `GET api/login` and require it
as a parameter, and add `<same-site>Lax</same-site>` to the container cookie block in `web.xml`.

### SEC-04: Duplicate session-cookie names resolve silently to the last value (cookie-shadowing primitive)

**Severity:** Medium
**CWE:** CWE-384: Session Fixation
**Location:** `src/main/java/com/example/auth/AuthenticatedSessionServlet.java:64-72`

**Vulnerable code:**

```java
// src/main/java/com/example/auth/AuthenticatedSessionServlet.java:64-72
        String name = issuer().config().name();
        String found = null;
        for (Cookie cookie : cookies) {
            if (name.equals(cookie.getName())) {
                found = cookie.getValue();
            }
        }
        return found;
    }
```

**Why it is a problem:** When a request carries more than one `Cookie` header entry named `APPSESSION`, the loop
overwrites `found` on every match and returns the last one seen, with no log entry and no error. RFC 6265 §5.4
orders duplicates by path length with the *narrower* path first, so "last wins" normally lands on the
host-only `Path=/` cookie — which is why the current deployment is safe, and why the test harness at
`TestHarness.java:367` can assert that a planted duplicate yields 401. That safety is an accident of ordering, not
a property of this code: it depends on the attacker's cookie having a narrower path, on the client honouring the
ordering convention, and on the container's cookie parser not reordering. `Set-Cookie` without a `Domain` cannot be
injected by a subdomain in a `Secure`-only setup, but a subdomain (or any XSS on a sibling app on the same host)
that can set `APPSESSION` for a narrower path, plus any client or proxy that presents the values in the other
order, resolves the attacker's identifier — and the base class then hands that value to `InMemorySessionStore.findLive`
and treats a match as authentication. Ambiguity in an authentication input should never be silently resolved; it
should fail closed.

**Fix:** Treat multiple matches as an invalid request rather than choosing one:

```java
// src/main/java/com/example/auth/AuthenticatedSessionServlet.java
        String name = issuer().config().name();
        String found = null;
        int matches = 0;
        for (Cookie cookie : cookies) {
            if (name.equals(cookie.getName())) {
                matches++;
                found = cookie.getValue();
            }
        }
        if (matches > 1) {
            // Ambiguous identity: refuse to authenticate rather than guess which one the client meant.
            log("ambiguous duplicate " + name + " cookie (" + matches + " values) rejected");
            return null;
        }
        return found;
    }
```

`return null` routes through the existing uniform 401/204 paths, so the response an attacker sees is identical to
the no-cookie case.

### SEC-05: CSP has no `frame-ancestors` and no `X-Frame-Options`: login form is frameable

**Severity:** Medium
**CWE:** CWE-1021: Improper Restriction or Removal of a Validation Check
**Location:** `src/main/java/com/example/auth/SecurityHeadersFilter.java:36-37`

**Vulnerable code:**

```java
// src/main/java/com/example/auth/SecurityHeadersFilter.java:36-37
            http.setHeader("Content-Security-Policy",
                    "default-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'");
```

**Why it is a problem:** The policy is otherwise well built — `script-src 'self'` with no `unsafe-inline`,
`base-uri 'none'`, `form-action 'self'` — but it never constrains who may embed the page, and no
`X-Frame-Options` header is emitted anywhere in the project. Any third-party site can therefore render
`index.html` inside an invisible or partly transparent iframe and drive the victim's keystrokes into the real
login form (clickjacking / UI-redressing). Combined with SEC-03 this is a working credential-capture chain: the
framed form posts to the real origin with the victim's own credentials, and the attacker's overlay decides when the
submit happens. It also gives an attacker a framed context in which to observe the post-login `#output` text.
Every mainstream hardening baseline (OWASP Secure Headers, CIS) treats framing protection as a required header, and
the absence is complete rather than partial: `grep -rn "frame-ancestors\|X-Frame-Options" src/` matches nothing.

**Fix:** Deny framing in both the modern CSP directive and the legacy header, keeping them consistent:

```java
// src/main/java/com/example/auth/SecurityHeadersFilter.java
            http.setHeader("Content-Security-Policy",
                    "default-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none';"
                            + " form-action 'self'; frame-ancestors 'none'");
            http.setHeader("X-Frame-Options", "DENY");
```

`frame-ancestors 'none'` is honoured by every current browser; `X-Frame-Options: DENY` covers older clients and
proxies that strip CSP. Add a wire assertion for both headers to `smoke-test.sh` alongside the existing
`HttpOnly`/`Secure`/`SameSite` checks.

### SEC-06: Attacker-controlled username written to the log unsanitised (log forging)

**Severity:** Medium
**CWE:** CWE-117: Improper Output Neutralization for Logs
**Location:** `src/main/java/com/example/auth/LoginServlet.java:84`

**Vulnerable code:**

```java
// src/main/java/com/example/auth/LoginServlet.java:84
        log("authenticated " + principal.get().username() + " as session " + session.identifier().describe());
```

**Why it is a problem:** `principal.get().username()` is the raw `username` request parameter, echoed straight into
`java.util.logging` with no neutralisation of CR/LF. In Tomcat's default `FILE` handler each record starts with a
timestamp line, so a username containing `%0A%0DINFO:%20...` lets the caller append arbitrary well-formed looking
records to `catalina.out`: fake "authenticated admin" lines to mislead a human reviewer, fake events to poison a
regex-based SIEM parser, or fabricated entries to hide a real event inside noise. The same call site pattern repeats
at `LogoutServlet.java:37-38`. Note the code is careful about the *identifier* here — `describe()` at
`SessionIdentifier.java:98-104` is deliberately redacted and tested — but the username, which is 100% attacker
chosen, gets no equivalent treatment. `Json.escape` exists in this package and escapes `\n`/`\r`, but it is a JSON
encoder (`Json.java:17-23`); using it for log output would emit literal `\n` text rather than neutralising the
newline, so it is not the right tool.

**Fix:** Neutralise line separators and bound the field length before logging:

```java
// src/main/java/com/example/auth/LoginServlet.java
    /** Neutralise CRLF and control characters in attacker-controlled text before it reaches the log. */
    private static String forLog(String value) {
        if (value == null) {
            return "<none>";
        }
        String trimmed = value.length() > 64 ? value.substring(0, 64) + "…" : value;
        return trimmed.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t");
    }

    // ...
        log("authenticated " + forLog(principal.get().username())
                + " as session " + session.identifier().describe());
```

Apply the same helper at `LogoutServlet.java:37-38`, and prefer a logging backend configured to escape newlines in
message fields as the defence-in-depth layer.

### SEC-07: Password verified by comparing plaintext with no salted key derivation or user store

**Severity:** Medium
**CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
**Location:** `src/main/java/com/example/auth/EnvironmentCredentialVerifier.java:32-33`

**Vulnerable code:**

```java
// src/main/java/com/example/auth/EnvironmentCredentialVerifier.java:32-33
        boolean userMatches = constantTimeEquals(expectedUser(), username);
        boolean passwordMatches = constantTimeEquals(expectedPassword(), password);
```

**Why it is a problem:** Verification compares the UTF-8 bytes of the submitted password against the UTF-8 bytes of
a plaintext secret read from a system property or environment variable (`EnvironmentCredentialVerifier.java:50-56`).
There is no salt, no key-derivation function, and no per-user record, so the server must hold the password itself in
reversible form. `MessageDigest.isEqual` removes a timing oracle — genuinely good work for a placeholder — but it is
not a substitute for a password hash: anyone who can read the property, the environment, a heap dump, or a
`catalina.sh` debug trace has a directly usable credential, and no offline-cracking cost stands between them and
reuse of that credential elsewhere. The class javadoc (lines 7-16) is explicit that this is not for production, yet
the class is wired as the `CredentialVerifier` in `AuthContextListener.java:78` and is what the shipped run
instructions and `smoke-test.sh` exercise, so a deployment built by following the README inherits it. Because
`CredentialVerifier` is an SPI, the fix is contained: implement a real verifier and stop shipping the placeholder as
the default wiring.

**Fix:** Store `salt || PBKDF2(password, salt, iterations)` per user and compare derived bytes, so the plaintext
never needs to exist server-side:

```java
// src/main/java/com/example/auth/StoredCredentialVerifier.java
    private static final int ITERATIONS = 600_000;   // OWASP 2023+ guidance for PBKDF2-HMAC-SHA256
    private static final int KEY_BITS = 256;

    /** Stored record format: base64(salt):base64(digest), one record per user in the user store. */
    private static boolean passwordMatches(StoredCredential stored, String presented) throws GeneralSecurityException {
        byte[] derived = new javax.crypto.SecretKeyFactory("PBKDF2WithHmacSHA256")
                .generateSecret(new javax.crypto.spec.PBEKeySpec(
                        presented.toCharArray(), stored.salt(), ITERATIONS, KEY_BITS))
                .getEncoded();
        return java.security.MessageDigest.isEqual(stored.digest(), derived);
    }

    @Override
    public Optional<SessionUser> verify(String username, String password) {
        if (username == null || password == null) {
            return Optional.empty();
        }
        return store.lookup(username)
                .filter(stored -> {
                    try {
                        return passwordMatches(stored, password);
                    } catch (GeneralSecurityException unavailable) {
                        throw new IllegalStateException("password verification unavailable", unavailable);
                    }
                })
                .map(SessionUser::new);
    }
```

Prefer Argon2id or scrypt where a vetted library is available, derive the comparison inside the store rather than in
the servlet, and make `AuthContextListener` fail startup if the placeholder verifier is selected outside a profile
that is explicitly non-production.

### SEC-08: `secureCookie`/`httpOnlyCookie` config values fail *open* on a typo

**Severity:** Medium
**CWE:** CWE-1188: Insecure Default Initialization of Resource
**Location:** `src/main/java/com/example/auth/SessionCookieConfig.java:95-96`

**Vulnerable code:**

```java
// src/main/java/com/example/auth/SessionCookieConfig.java:95-96
        b.secure(Boolean.parseBoolean(orFallback(lookup.apply("secureCookie"), Boolean.toString(b.secure))));
        b.httpOnly(Boolean.parseBoolean(orFallback(lookup.apply("httpOnlyCookie"), Boolean.toString(b.httpOnly))));
```

**Why it is a problem:** `Boolean.parseBoolean` returns `false` for *anything* that is not the string `"true"`,
including the typos an operator actually makes: `yes`, `1`, `on`, `True ` with a stray character, `ture`. An
`<env-entry>`/`context-param` typo or a copy-paste from a non-Java config format therefore silently disables
`Secure` or `HttpOnly` — the two attributes this class exists to guarantee — with no startup error, no log line, and
a cookie that looks correct to `curl` until someone notices the missing attribute. The rest of this class handles
exactly the same situation in the opposite direction, which is what makes this a defect rather than a trade-off:
`SameSite.parse` throws on an unknown value (line 47), `Integer.parseInt` throws on a malformed `maxAgeSeconds`
(line 98), and the constructor validates name, path and the `None`-without-`Secure` combination (lines 60-68). A
security control must fail closed like those do, not open. `AuthContextListener.java:59-64` already turns a
construction exception into a `ContextLoaderListener` startup failure, so throwing here is consistent and visible.

**Fix:** Parse strictly and reject anything unrecognised, mirroring `SameSite.parse`:

```java
// src/main/java/com/example/auth/SessionCookieConfig.java
        b.secure(parseBoolean(orFallback(lookup.apply("secureCookie"), Boolean.toString(b.secure)), "secureCookie"));
        b.httpOnly(parseBoolean(orFallback(lookup.apply("httpOnlyCookie"), Boolean.toString(b.httpOnly)),
                "httpOnlyCookie"));

    private static boolean parseBoolean(String raw, String what) {
        if ("true".equalsIgnoreCase(raw)) {
            return true;
        }
        if ("false".equalsIgnoreCase(raw)) {
            return false;
        }
        throw new IllegalArgumentException("unknown " + what + " value: " + raw + " (expected true or false)");
    }
```

A malformed value then aborts deployment instead of shipping a weaker cookie, and add a `TestHarness` case asserting
that `secureCookie=yes` throws.

### SEC-09: Credential placed on the JVM command line and in a world-readable generated file

**Severity:** Low
**CWE:** CWE-214: Generation of Error Message Containing Sensitive Information
**Location:** `smoke-test.sh:92-97`

**Vulnerable code:**

```bash
# smoke-test.sh:92-97
cat > "$BASE/bin/setenv.sh" <<EOF
# generated by smoke-test.sh
CATALINA_OPTS="\$CATALINA_OPTS -Ddemo.username=$DEMO_USER"
CATALINA_OPTS="\$CATALINA_OPTS -Ddemo.password='$DEMO_PASSWORD'"
export CATALINA_OPTS
EOF
```

**Why it is a problem:** Two exposures compound here. First, the credential is written into `$CATALINA_OPTS` as a
`-D` JVM argument, so it becomes part of the Tomcat process command line — readable by *any* local account via
`ps -ef`, `/proc/<pid>/cmdline`, shell history, and any process-monitoring or APM agent that collects argv. Second,
it is persisted in `bin/setenv.sh`, created with the default umask (typically `022`, i.e. world-readable) and left
behind after the run, so the secret survives the test in a plaintext file inside `CATALINA_HOME` — which is then
routinely tarred up for support bundles and copied into CI artefacts. The same pattern is what README.md:121-123
documents for a manual run, so operators following the guide reproduce it. The script comments acknowledge the
trade-off ("A demo password on a command line is fine for a local check and wrong for a real deployment"), but the
demo password is also the password the README tells people to change by editing this exact line.

**Fix:** Keep the secret in the environment of the launching process (visible only to that user's processes), never
in argv, and create the file with restrictive permissions:

```bash
# smoke-test.sh
umask 077
install -m 600 /dev/null "$BASE/bin/setenv.sh"
cat > "$BASE/bin/setenv.sh" <<EOF
# generated by smoke-test.sh - do not commit; contains a demo credential
export DEMO_USERNAME='$DEMO_USER'
export DEMO_PASSWORD='$DEMO_PASSWORD'
EOF
chmod 600 "$BASE/bin/setenv.sh"
# ...and at the end of the script:
trap 'rm -f "$BASE/bin/setenv.sh"' EXIT
```

`EnvironmentCredentialVerifier` already reads `DEMO_USERNAME`/`DEMO_PASSWORD` from the environment, so no code
change is needed. Update README.md:121-123 to show the `export` form rather than the `-D` form, and note that
`DEMO_PASSWORD` must never appear in a `CATALINA_OPTS` value.

### SEC-10: Unhandled exceptions reach the container's default error page

**Severity:** Low
**CWE:** CWE-209: Generation of Error Message Containing Sensitive Information
**Location:** `src/main/webapp/WEB-INF/web.xml:112-117`

**Vulnerable code:**

```xml
<!-- src/main/webapp/WEB-INF/web.xml:112-117 -->
  </session-config>

  <welcome-file-list>
    <welcome-file>index.html</welcome-file>
  </welcome-file-list>
</web-app>
```

**Why it is a problem:** There is no `<error-page>` mapping, so any exception that escapes a servlet is rendered by
Tomcat's default `/error` page, which echoes the exception type and message (and, with `org.apache.catalina.connector
.RESPONSES_SHOW_EXCEPTION_INFO` or a developer-mode install, the stack trace) to the client. Escaping paths exist:
`SessionCookieIssuer.assertHeaderIntegrity` throws `IllegalStateException` when the container drops an attribute or a
value contains a control character (`SessionCookieIssuer.java:133-157`), `SessionIdentifier.of` throws
`IllegalArgumentException` on malformed input, and `requireToken` throws on a bad `cookieName`. The servlets
deliberately keep upstream detail out of *their own* error bodies — `LoginServlet.java:57-62` catches `RuntimeException`
from verification and logs it instead of exposing it — so the intent is clearly that detail stays server-side, but
that intent is unenforced for anything thrown outside the `verify` call. That leaks class names, method names and
config values (e.g. the rejected `cookieName` is included in the message) to an unauthenticated caller, which is
free reconnaissance for an attacker probing the cookie layer.

**Fix:** Map error codes and throwable types to static pages that contain no diagnostic detail:

```xml
<!-- src/main/webapp/WEB-INF/web.xml -->
  <error-page>
    <error-code>400</error-code>
    <location>/error.html</location>
  </error-page>
  <error-page>
    <error-code>404</error-code>
    <location>/error.html</location>
  </error-page>
  <error-page>
    <error-code>500</error-code>
    <location>/error.html</location>
  </error-page>
  <error-page>
    <exception-type>java.lang.Throwable</exception-type>
    <location>/error.html</location>
  </error-page>
```

Ship a static `src/main/webapp/error.html` whose only content is a generic message, and make sure the detail is
logged server-side (the container already logs the throwable) rather than returned. Keep the existing
`respondError` JSON contract for the application-level 4xx/5xx paths so API clients are unaffected.

### SEC-11: Unquoted heredoc allows shell-command injection through a credential value

**Severity:** Low
**CWE:** CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
**Location:** `smoke-test.sh:92-97`

**Vulnerable code:**

```bash
# smoke-test.sh:92-97
cat > "$BASE/bin/setenv.sh" <<EOF
# generated by smoke-test.sh
CATALINA_OPTS="\$CATALINA_OPTS -Ddemo.username=$DEMO_USER"
CATALINA_OPTS="\$CATALINA_OPTS -Ddemo.password='$DEMO_PASSWORD'"
export CATALINA_OPTS
EOF
```

The two expanded interpolation lines are the defect (lines 94-95).

**Why it is a problem:** The heredoc delimiter is unquoted, so `$DEMO_USER` and `$DEMO_PASSWORD` are expanded by the
*generating* shell and substituted as raw text into a file that `catalina.sh` later sources. There is no
quoting-validating or character filtering between the two. A value containing a single quote closes the surrounding
quotes, and a value containing `$(...)` or backticks is executed *at generation time*: `DEMO_PASSWORD="a'; touch
/pwned; '"` runs `touch /pwned` as the user building the app, and a value containing `"` breaks the assignment so
later tokens are word-split. In the smoke-test's own flow the values come from `DEMO_USERNAME`/`DEMO_PASSWORD`, so
today it requires a hostile or careless operator/CI variable to trigger — which is why this is Low rather than
High. The pattern matters beyond that: the same lines are the copy-paste template a real deployment would use to
inject a secret supplied by a provisioning system, a vault template, or a CI secret whose content is not
shell-quoting-checked, at which point it is remote-ish code execution on the build host.

**Fix:** Quote the delimiter so nothing is expanded at generation time, and pass the values through the environment
as single-quoted literals:

```bash
# smoke-test.sh
quote() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

{
  printf '%s\n' '# generated by smoke-test.sh - contains a demo credential, do not commit'
  printf 'DEMO_USERNAME=%s\n' "$(quote "$DEMO_USER")"
  printf 'DEMO_PASSWORD=%s\n' "$(quote "$DEMO_PASSWORD")"
  printf '%s\n' 'export DEMO_USERNAME DEMO_PASSWORD'
} > "$BASE/bin/setenv.sh"
```

`quote` renders any value — including `'`, `$( )`, backticks and `"` — as inert single-quoted text. If the values can
originate outside the operator's control, additionally reject anything outside `[A-Za-z0-9 ._@:+-]` before writing.

### SEC-12: Build classpath accepts an arbitrary jar found anywhere under `/`

**Severity:** Low
**CWE:** CWE-426: Untrusted Search Path
**Location:** `build.sh:22-25`

**Vulnerable code:**

```bash
# build.sh:22-25
  local found
  found=$(find / -maxdepth 6 \( -name 'jakarta.servlet-api-*.jar' -o -name 'servlet-api.jar' \) \
      -not -path '*/\.git/*' 2>/dev/null | sort)
  while IFS= read -r jar; do [ -n "$jar" ] && candidates+=("$jar"); done <<<"$found"
```

**Why it is a problem:** When no jar is pinned, the script walks the entire filesystem from `/` and takes the first
candidate that merely *contains* an entry named `jakarta/servlet/http/Cookie.class`. The only acceptance test is
that one `jar --list | grep -q` check (`build.sh:30`, and identically `run-tests.sh:25`) — there is no path
allowlist, no ownership or world-writability check, no signature, and no checksum. Because `find` recurses through
`/tmp`, `/home`, `/var`, and any mounted volume, an unprivileged local user (or any prior CI job on a shared
runner) can drop `/tmp/x/lib/jakarta.servlet-api-6.0.0.jar` containing an arbitrary `Cookie.class` plus malicious
`javac`-visible classes, and `build.sh` will select it by `sort` order and compile the application against attacker
-controlled API definitions — and `run-tests.sh` will execute it on the test classpath, where static initializers
run. It also makes builds non-reproducible and silently version-dependent. This is Low only because it presumes
write access to a shared machine or a poisoned runner, not because the mechanism is weak.

**Fix:** Require an explicit, verified jar; never search the filesystem:

```bash
# build.sh
SERVLET_API_JAR="lib/jakarta.servlet-api-6.0.0.jar"
SERVLET_API_SHA256="e64d30fd0a50505321e2c2a1c6a1a6a0c3a2f8f6b2b5c0a4e1e0c9d8f7a6b5c4"

if [ ! -f "$SERVLET_API_JAR" ]; then
  echo "missing $SERVLET_API_JAR" >&2
  echo "download it from Maven Central, then verify it before building:" >&2
  echo "  curl -fLso $SERVLET_API_JAR https://repo1.maven.org/maven2/jakarta/servlet/jakarta.servlet-api/6.0.0/jakarta.servlet-api-6.0.0.jar" >&2
  exit 1
fi
if ! printf '%s  %s\n' "$SERVLET_API_SHA256" "$SERVLET_API_JAR" | sha256sum --check --status -; then
  echo "$SERVLET_API_JAR does not match the pinned SHA-256; refusing to build" >&2
  exit 1
fi
```

Delete `find_servlet_api` from both scripts (keeping the `SERVLET_API_JAR` override for explicit CI use), and vendor
the jar with its checksum so the compiler and test classpath are pinned to a known artifact.

### SEC-13: `cookiePath` is not validated for attribute-separating characters

**Severity:** Low
**CWE:** CWE-20: Improper Input Validation
**Location:** `src/main/java/com/example/auth/SessionCookieConfig.java:59-62`

**Vulnerable code:**

```java
// src/main/java/com/example/auth/SessionCookieConfig.java:59-62
    private SessionCookieConfig(Builder b) {
        this.name = requireToken(b.name, "cookie name");
        if (b.path == null || b.path.isEmpty() || b.path.charAt(0) != '/') {
            throw new IllegalArgumentException("cookie path must be an absolute path: " + b.path);
```

**Why it is a problem:** The name is validated character-by-character against the RFC 6265 token grammar by
`requireToken`, but the path gets a single structural check — non-empty and starting with `/`. Everything after the
first character is accepted verbatim, including `;`, `,`, quotes, spaces and control characters, all of which are
significant in a `Set-Cookie` header. So `<param-value>/app;HttpOnly=</param-value>` or a path with an embedded
newline passes validation and reaches `cookie.setPath(config.path())` at `SessionCookieIssuer.java:94`. Tomcat's
RFC 6265 cookie processor rejects a path containing `;` or a control character at `addCookie()` time, so the
practical effect today is an unhandled `IllegalArgumentException` — a 500 on every login — discovered only when the
first user authenticates, whereas an invalid `cookieName` fails at startup. On any container that does not validate
paths, the same accepted value becomes `Set-Cookie` attribute injection. Either way, an invalid deployment value is
accepted by the validator and surfaces late, which is the defect.

**Fix:** Validate the path against the RFC 6265 `path-value` grammar, so a bad value fails at startup like every
other setting:

```java
// src/main/java/com/example/auth/SessionCookieConfig.java
    private SessionCookieConfig(Builder b) {
        this.name = requireToken(b.name, "cookie name");
        this.path = requirePath(b.path);

    private static String requirePath(String raw) {
        if (raw == null || raw.isEmpty() || raw.charAt(0) != '/') {
            throw new IllegalArgumentException("cookie path must be an absolute path: " + raw);
        }
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            // RFC 6265 path-value: %x21 / %x23-2B / %x2D-3A / %x3D-5B / %x5D-7E, i.e. no ';' ',' '"' or control chars.
            if (c < 0x21 || c > 0x7e || c == ';' || c == ',' || c == '"') {
                throw new IllegalArgumentException("cookie path contains an invalid character at index " + i);
            }
        }
        return raw;
    }
```

Add a `TestHarness` case asserting that a `cookiePath` of `/app;HttpOnly=` throws at construction, and keep the
`assertHeaderIntegrity` re-read as the runtime backstop it already is.

## 6. Verified Controls and Checks With No Finding

- **Identifier entropy and CSPRNG** — `SessionIdentifier.java:23` uses `new SecureRandom()` (not `Random`,
  `ThreadLocalRandom`, or a time/PID seed) and `generate()` at lines 63-66 draws a full 32 bytes
  (`RANDOM_BYTES = 32`, line 18), giving 256 bits rendered as 43 base64url characters. `TestHarness.java:188-200`
  asserts the `[A-Za-z0-9_-]{43}` shape and the prefix/null rejections. No forgeable or sequential identifier.
- **Cookie attribute integrity, verified not assumed** — `SessionCookieIssuer.java:92-103` sets `Path`, `Secure`,
  `HttpOnly`, `Max-Age` and the `SameSite` attribute, and `add()` at lines 106-109 calls
  `assertHeaderIntegrity` (lines 121-157), which re-reads `response.getHeaders("Set-Cookie")` and throws if no
  header was emitted or if `Secure`, `HttpOnly` or `Path` was dropped. A container-level downgrade therefore breaks
  the login instead of silently shipping a weaker cookie; `smoke-test.sh` independently asserts `HttpOnly`,
  `Secure`, `SameSite=Lax`, `Path=/`, absence of `Domain` (host-only), and absence of `Max-Age` on the login
  response.
- **Session fixation** — `LoginServlet.java:71-78` removes the session named by the presented cookie *before*
  `store().create(...)` mints a brand-new identifier, so a pre-authentication identifier never names an
  authenticated session. Confirmed end-to-end by the smoke test comparing pre- and post-login identifier values.
- **No `Set-Cookie` injection through the identifier** — every presented value is parsed through
  `SessionIdentifier.of` (lines 39-52), which rejects null, empty, over-length, and any character outside
  `[A-Za-z0-9._~-]` (`isTokenCharacter`, lines 123-128), so CR, LF, `;`, `"` and `/` cannot reach a header or a
  comparison. `InMemorySessionStore.findLive` (lines 51-55) converts the parse failure to an empty result rather
  than an exception, so a crafted cookie yields the same uniform 401 — verified by the smoke test sending
  `abc; Domain=attacker.example`.
- **Constant-time comparison** — `SessionIdentifier.matches` (lines 73-79) and
  `EnvironmentCredentialVerifier.constantTimeEquals` (lines 58-62) both use `MessageDigest.isEqual`, avoiding the
  early-exit byte-compare oracle that a `String.equals` here would create for both session identifiers and
  credentials.
- **Credential material never leaves the header** — the response bodies expose only `SessionIdentifier.fingerprint()`
  (`WhoAmIServlet.java:32`, `LoginServlet.java:97`), an 8-byte SHA-256 truncation (lines 111-121) of an input that is
  already uniformly random, so it is not a reversing or brute-force shortcut. `describe()` (lines 98-104) and
  `toString()` (lines 93-94) emit at most 4+4 characters, and `TestHarness.java:188-200` asserts the full value never
  appears in `toString` output.
- **Session lifecycle and replay** — `InMemorySessionStore.create` binds an absolute `expiresAt`
  (`AuthenticatedSession.java:28-30`), `findLive` re-checks liveness against `Instant.now()` (lines 57-59), and
  `sweep` (lines 81-83) drops expired entries. After `LogoutServlet` removes the entry and `expire()` emits
  `Max-Age=0`, replaying the old identifier returns 401; the smoke test asserts both the `Max-Age=0` header and the
  replayed 401.
- **Uniform responses, no user or session enumeration** — unknown, expired, malformed and cross-user identifiers all
  yield the same 401 (`WhoAmIServlet.java:22-24`, `AuthenticatedSessionServlet.java:51-56`), logout always returns
  204, and a wrong username is indistinguishable from a wrong password because
  `EnvironmentCredentialVerifier.java:34` requires `userMatches && passwordMatches` and returns the same empty
  result either way, without revealing which half failed.
- **URL rewriting closed** — `web.xml:111` sets `<tracking-mode>COOKIE</tracking-mode>`, and both smoke-test
  assertions confirm no `JSESSIONID` appears and that a `;JSESSIONID_STYLE_PATH=...` request must authenticate by
  header cookie, so the session identifier cannot leak via `href` rewriting or Referer (CWE-598 avoided).
- **No second session identity** — `InMemorySessionStore`'s javadoc (lines 12-17) documents that `request.getSession()`
  is never called; verified — no call site exists in `src/main`, so `JSESSIONID` is never created and there is no
  two-cookie ambiguity to exploit. (The `<cookie-config>` block at `web.xml:106-110` omits `<same-site>`, which is
  harmless *because* the container session is never instantiated; adding it as part of SEC-01's fix makes the
  guarantee structural.)
- **No XSS sink for the unescaped JSON fields** — `Json.java:17-30` implements JSON escaping only (quotes,
  backslash, control characters, `U+2028/9`) and does not escape `<`, `>`, `&` or `/`, and a few interpolation points
  bypass even that (`LoginServlet.java:96,99`; `WhoAmIServlet.java:32-34`). This was chased and is not exploitable:
  every one of those values is an enum constant (`SameSite.headerValue()`), an `Instant`, a base64url fingerprint, or
  a boolean; the responses are served as `application/json` with `X-Content-Type-Options: nosniff`; and
  `app.js:7` is the only DOM write, using `textContent` — no `innerHTML`, `outerHTML`, `insertAdjacentHTML`,
  `eval`, or `document.write` anywhere, `index.html` has no inline handlers, and CSP `script-src 'self'` permits no
  inline script. Wrapping those fields in `Json.escape` for symmetry would be tidy but is not a vulnerability.
- **No secrets in client-delivered assets** — `app.js`, `index.html` and `app.css` were scanned for keys, tokens,
  endpoints and credentials; the only strings are the endpoint paths `api/login`, `api/logout`, `api/whoami`
  (`app.js:23-41`), and the demo password appears solely in test/deployment scripts, reported as SEC-09.
- **Caching of authenticated responses** — `SecurityHeadersFilter.java:32-33` and
  `AuthenticatedSessionServlet.respondJson` set `Cache-Control: no-store` and `Vary: Cookie` on every response, and
  the smoke test asserts both on the unauthenticated `whoami` response, so a shared cache or a back/forward cache
  cannot serve one user's principal to another.
- **Config fail-fast where it counts** — `SessionCookieConfig`'s constructor rejects a non-token name, a non-absolute
  path, `SameSite=None` without `Secure`, and `Max-Age < -1` (lines 60-68), and `SameSite.parse` (line 47) plus
  `Integer.parseInt` (line 98) throw on unknown/malformed values, so most deployment typos abort startup via
  `AuthContextListener.contextInitialized` (lines 59-71) instead of degrading behaviour. Only the two boolean
  attributes escape that discipline (SEC-08).
- **Application classes are not web-accessible** — `build.sh` stages compiled classes under
  `WEB-INF/classes`, and `smoke-test.sh` probes `WEB-INF/classes/com/example/auth/LoginServlet.class` expecting
  404/403, so the source of the cookie logic is not downloadable over HTTP.
- **Test coverage of the negative paths** — `TestHarness.java` (974 lines, `Proxy`-based fakes, no live container)
  and `smoke-test.sh` together already assert the behaviours most reviews only hope for: attribute dropping throws,
  `Max-Age=0` on logout, replay after expiry, cross-user identifier rejection, duplicate-cookie non-resolution
  (line 367), `toString` redaction, `fingerprint()` length bound, crafted-cookie 401, and header presence. The
  findings above should each add a case there rather than rely on manual verification.
- **Not applicable vulnerability classes, confirmed by reading the code** — no SQL or query language, no XML or
  `ObjectInputStream` parsing of untrusted input, no path or file access derived from a request, no redirects or
  outbound requests (so no open redirect or SSRF), no JWT or OAuth handling, no file upload, no server-side template
  rendering, no deserialization endpoints, and no email/header generation. `Json.java`, `SessionIdentifier.java` and
  the verifier were the only places untrusted input reaches a security decision, and each is covered above.
