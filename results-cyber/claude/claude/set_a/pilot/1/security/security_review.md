# Security Code Review — `session-cookie-auth`

**Scope:** every source file in this folder
(`src/main/java/com/example/auth/*.java`, `src/main/webapp/WEB-INF/web.xml`, `pom.xml`).
**Method:** the `review-code-for-security-vulnerabilities` router skill — understand each
file, derive security-relevant behaviours, select and apply the matching specialised
skills from the library, report with CWE ids and `file:line` evidence.

---

## 1. What the code does

| File | Purpose | Security-relevant behaviour |
|------|---------|-----------------------------|
| `LoginServlet.java` | `POST /login` endpoint that mints a session and sets the cookie | Authentication entry point, session issuance, session-fixation handling, cache control |
| `LogoutServlet.java` | `POST /logout` — server-side invalidation + cookie deletion | Session termination, revocation |
| `SessionAuthenticationFilter.java` | `@WebFilter("/*")` — resolves the cookie to an identity for every request | Access control, path-based exemption, identity propagation |
| `SessionStore.java` | In-memory registry: id → (userId, createdAt, lastSeenAt) with idle + absolute timeouts | Session state, expiry, concurrency, revocation |
| `SessionCookieFactory.java` | Builds/reads/clears the `__Host-SESSIONID` cookie | Cookie attributes (HttpOnly, Secure, SameSite, Path, host-only), header-injection filtering |
| `SessionIdGenerator.java` | 256-bit `SecureRandom` id, URL-safe Base64 | CSPRNG, token entropy |
| `WEB-INF/web.xml` | Container session hardening + `CONFIDENTIAL` transport constraint | TLS enforcement, container cookie config |
| `pom.xml` | Jakarta Servlet 6.0 (`provided`), Java 17, WAR packaging | Dependency surface (single, current, no known-vulnerable libs) |

**Keywords derived:** authentication, session management, session fixation, access
control / forced browsing, CSRF, cookie security headers, race condition (TOCTOU),
CSPRNG / entropy, resource exhaustion, TLS transport.

---

## 2. Findings

### F-01 — Critical — `/login` issues a valid authenticated session to anyone (authentication bypass)
**CWE-306: Missing Authentication for Critical Function** (also **CWE-287: Improper Authentication**)
**Evidence:** `LoginServlet.java:29`, `LoginServlet.java:40-47`; `SessionAuthenticationFilter.java:30-33`

`SessionAuthenticationFilter` explicitly exempts `/login` from all authentication
(`SessionAuthenticationFilter.java:30-33`), and `LoginServlet.doPost` performs **no**
credential verification — it reads the identity from a request attribute that nothing
in this application ever sets:

```java
String userId = (String) request.getAttribute("authenticatedUserId");   // LoginServlet.java:29
...
SessionStore.create(sessionId, userId);                                  // LoginServlet.java:44
SessionCookieFactory.addTo(response, sessionId);                         // LoginServlet.java:47
```

The only code that sets `authenticatedUserId` is the filter itself
(`SessionAuthenticationFilter.java:47`) — and that line is unreachable for `/login`
because of the exemption above. The result is that on the request path as written,
`userId` is **always `null`**.

**Attack:** `curl -X POST https://host/login` (no credentials, no cookie) returns
`204` with `Set-Cookie: __Host-SESSIONID=<valid id>`. That id is a live entry in
`SESSIONS`, so `SessionStore.validate` returns non-null and the filter admits every
subsequent request to every protected resource — an unauthenticated attacker obtains
a fully valid session. Downstream handlers additionally receive `authenticatedUserId == null`,
which either NPEs or is silently treated as an anonymous/default principal.

The comment at `LoginServlet.java:28` states authentication is "assumed to have
succeeded", but no component in scope enforces that assumption and the filter
actively disables it for this path, so the deployed artifact is exploitable as-is.

**Fix:**
1. Verify credentials inside `LoginServlet.doPost` (or in a dedicated authentication
   filter mapped to `/login` and ordered *before* this servlet) against a store using a
   memory-hard password hash (Argon2id/bcrypt/scrypt), with constant-time comparison,
   rate limiting and lockout.
2. Reject the request (`401`) and issue no cookie when `userId` is `null` or blank —
   add an explicit guard before `SessionStore.create`.
3. Stop reusing the name `authenticatedUserId` for both an *input* to login and an
   *output* of the filter; request attributes are the wrong carrier for a credential
   verification result across two independent components.

---

### F-02 — High — Race between `validate()` and `invalidate()` resurrects a logged-out session
**CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization (TOCTOU)**
(consequence: **CWE-613: Insufficient Session Expiration**)
**Evidence:** `SessionStore.java:46-59` (get → compute → put), `SessionStore.java:62-66` (remove)

`validate()` is a non-atomic read-modify-write on the shared map:

```java
Session session = SESSIONS.get(sessionId);   // SessionStore.java:46
...
Session refreshed = new Session(session.userId(), session.createdAt(), now);
SESSIONS.put(sessionId, refreshed);           // SessionStore.java:58
```

`ConcurrentHashMap` makes each individual call atomic, but not the sequence.

**Failure scenario:** thread A (any authenticated request) executes line 46 and is
descheduled; thread B runs `LogoutServlet` → `SessionStore.invalidate` →
`SESSIONS.remove` (`SessionStore.java:64`); thread A then resumes and executes the
`put` at line 58, **re-inserting the session that logout just destroyed**, with a
freshly refreshed idle timer. The user believes they are logged out; the captured
session id keeps working for another 30 minutes of idle time (up to the 8-hour
absolute cap). The identical race also defeats the expiry `remove` at line 54.

**Fix:** make the check-and-refresh a single atomic operation, e.g.

```java
return SESSIONS.computeIfPresent(sessionId, (id, s) -> expired(s) ? null : s.withLastSeen(now));
```

(returning `null` from `computeIfPresent` removes the entry), and have `invalidate()`
remain a plain `remove` — the atomic remapping function then cannot interleave with it.

---

### F-03 — Medium — Login invalidates the wrong session store; the pre-existing application session survives re-authentication
**CWE-384: Session Fixation** / **CWE-613: Insufficient Session Expiration**
**Evidence:** `LoginServlet.java:34-37` vs. `SessionStore.java:24`, `SessionCookieFactory.java:24`

```java
HttpSession existing = request.getSession(false);   // LoginServlet.java:34
if (existing != null) { existing.invalidate(); }    // LoginServlet.java:36
```

This invalidates the *container's* `HttpSession` (`JSESSIONID`), which this application
never creates or reads — all authentication state lives in the custom `SESSIONS` map
keyed by `__Host-SESSIONID`. The session the client actually arrived with is therefore
**not** invalidated: whatever id was in the incoming `__Host-SESSIONID` cookie remains a
live, usable entry in `SessionStore` after login, until it times out on its own.

Consequences: an id captured before login (e.g. from a shared/kiosk browser, or one the
attacker previously obtained via F-01) stays valid in parallel with the new one; and
re-authentication does not clean up abandoned sessions. Minting a fresh id
(`LoginServlet.java:40`) does block classic fixation, so the impact is bounded — but the
stated defence at `LoginServlet.java:31-33` does not do what the comment claims.

**Fix:** read the incoming cookie and invalidate the *application* session before
issuing the new one:

```java
String previous = SessionCookieFactory.readFrom(request);
if (previous != null) { SessionStore.invalidate(previous); }
```

Keep the `HttpSession` invalidation only if the container session is genuinely used
elsewhere; otherwise delete it as misleading dead code.

---

### F-04 — Medium — No anti-CSRF token on the state-changing endpoints; protection rests entirely on `SameSite=Strict`
**CWE-352: Cross-Site Request Forgery**
**Evidence:** `LoginServlet.java:25-53`, `LogoutServlet.java:17-30`, `SessionCookieFactory.java:63`

Neither `POST /login` nor `POST /logout` validates a synchronizer token, an `Origin`
header, or a `Referer`. The sole control is `SameSite=Strict` on the session cookie
(`SessionCookieFactory.java:63`), which is a good *defence in depth* but is a single
point of failure and does not cover both directions:

* **Login CSRF:** `POST /login` requires no cookie at all (F-01), so `SameSite` is
  irrelevant to it. A cross-site form post to `/login` still receives a `Set-Cookie` —
  `SameSite` restricts when a cookie is *sent*, not whether a cross-site response may
  *set* one. The attacker can therefore silently plant **their own** session in the
  victim's browser; the victim's subsequent activity is recorded under the attacker's
  account.
* **Logout CSRF:** a nuisance-level denial of service if `SameSite` is ever relaxed to
  `Lax`/`None` (the comment at `SessionCookieFactory.java:62` invites exactly that
  relaxation) or on a client that does not enforce it.

**Fix:** validate the `Origin` header (falling back to `Referer`) against an allowlist on
every state-changing request, and add a per-session synchronizer token (or double-submit
cookie) to `/logout` and to the login form. Keep `SameSite=Strict` as an additional layer.

---

### F-05 — Medium — Unbounded, never-reaped session map: memory exhaustion
**CWE-400: Uncontrolled Resource Consumption** (also **CWE-772: Missing Release of Resource after Effective Lifetime**)
**Evidence:** `SessionStore.java:24`, `SessionStore.java:32-35`, `SessionStore.java:42-56`

`SESSIONS` grows without limit and entries are removed **only** when someone presents the
id again (`SessionStore.java:54`) or calls logout (`SessionStore.java:64`). There is no
background reaper, no cap, and no eviction policy. A session that is created and never
used again — the normal case for an abandoned browser, and the guaranteed case for
sessions minted by the anonymous `/login` of F-01 — is retained forever.

**Attack:** a loop of unauthenticated `POST /login` requests (F-01) adds ~200 bytes of
permanently-retained heap per request with no credential cost, driving the JVM to
`OutOfMemoryError`. Even without F-01, ordinary abandoned sessions leak monotonically.

**Fix:** use a store with built-in expiry (Caffeine with `expireAfterAccess(30m)` +
`expireAfterWrite(8h)`, or Redis with a TTL), or run a scheduled sweep over
`SESSIONS.values()`; add a hard maximum entry count. The class javadoc
(`SessionStore.java:12-14`) already anticipates the Redis swap — a TTL there solves this.

---

### F-06 — Low — HTTPS is required but never pinned: no HSTS header
**CWE-319: Cleartext Transmission of Sensitive Information** (via downgrade) / **CWE-523: Unprotected Transport of Credentials**
**Evidence:** `web.xml:27-35` (transport guarantee), no `Strict-Transport-Security` anywhere in the codebase

`<transport-guarantee>CONFIDENTIAL</transport-guarantee>` makes the container *redirect*
cleartext requests to HTTPS, but that redirect is itself sent over HTTP and is trivially
stripped by a network attacker (sslstrip). Nothing in the application emits
`Strict-Transport-Security`. The session cookie is `Secure` + `__Host-` so it will not
leak, but the login POST body and any first-visit navigation can be intercepted or
downgraded.

**Fix:** emit `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
on every HTTPS response (a filter or the reverse proxy), and submit the domain to the
HSTS preload list.

---

### F-07 — Low — Filter path exemption uses raw-URI exact match and only the `REQUEST` dispatcher
**CWE-1173: Improper Use of Validation Framework** / **CWE-289: Authentication Bypass by Alternate Name** (hardening)
**Evidence:** `SessionAuthenticationFilter.java:29-33`, `@WebFilter("/*")` at `SessionAuthenticationFilter.java:19`

```java
String path = request.getRequestURI().substring(request.getContextPath().length());
if ("/login".equals(path)) { chain.doFilter(req, res); return; }
```

`getRequestURI()` returns the **raw, undecoded** URI including path parameters, and is
compared by exact string equality, while the container maps the servlet using the
*decoded and normalised* path. The two parsers disagree: `/login;x=y`, `/lo%67in`, and
`//login` all reach `LoginServlet` while failing the `equals` test. I verified the
direction of the mismatch: it fails **closed** (such requests are forced through
authentication and get `401`), so it is not exploitable as a bypass today — but the
pattern is fragile and inverts into a bypass the moment the allowlist grows or the
comparison is loosened (`startsWith`, `contains`, `equalsIgnoreCase`).

Separately, `@WebFilter` defaults to `DispatcherType.REQUEST` only; `FORWARD`, `INCLUDE`,
`ASYNC` and `ERROR` dispatches are not filtered. Only server-initiated dispatches can
reach those paths, so there is no direct external attack, but any future
`RequestDispatcher.forward` to a protected resource would be unauthenticated.

**Fix:** compare `request.getServletPath()` (container-normalised) rather than
`getRequestURI()`, and declare the filter with
`dispatcherTypes = {REQUEST, FORWARD, INCLUDE, ASYNC, ERROR}`. Prefer an allowlist of
exempt paths held in a `Set<String>` so the deny-by-default property stays explicit.

---

### F-08 — Low — No authentication or session-lifecycle logging
**CWE-778: Insufficient Logging**
**Evidence:** no logging statements in any of the six Java files — `LoginServlet.java:44`
(session created), `SessionAuthenticationFilter.java:43` (401 rejection),
`LogoutServlet.java:24` (session destroyed) all pass silently

Session creation, rejected session ids, expiry and logout produce no audit record, so
credential stuffing, session-id guessing, and the mass-session-creation abuse in F-05
are invisible to detection tooling and unreconstructable during incident response.

**Fix:** log (at INFO/WARN) session creation, validation failure with source IP and
user-agent, expiry and explicit logout. Never log the session id itself — log a
truncated SHA-256 of it so records can be correlated without becoming a credential store.

---

## 3. Controls verified as correct

These were checked against the same skills and found sound — recorded so the report is
not read as a blanket condemnation of the cookie layer, which is largely well built:

* **Session id entropy and RNG** — `SessionIdGenerator.java:15-25`: a single shared
  `SecureRandom` (CSPRNG, correctly *not* seeded manually), 32 bytes = 256 bits, URL-safe
  unpadded Base64. Not guessable or enumerable; no `java.util.Random`, no
  timestamp/counter/userId material in the token. No CWE-330/CWE-338 issue.
* **Cookie attributes** — `SessionCookieFactory.java:50-67`: `HttpOnly`, `Secure`,
  `Path=/`, no `Domain`, `SameSite=Strict`, `Max-Age=-1` (browser-session cookie, never
  written to disk), and the `__Host-` prefix (`SessionCookieFactory.java:24`), which
  browsers enforce and which blocks cookie-tossing from a sibling subdomain. This is the
  correct hardened configuration; no CWE-1004/CWE-614/CWE-1275 issue.
* **Cookie header injection** — `SessionCookieFactory.java:41-45,114-126`: the value is
  charset-restricted before use, so control characters, `;` and `,` cannot inject extra
  attributes or split headers (CWE-113 not present).
* **Cookie deletion parity** — `SessionCookieFactory.java:88-96`: `clearFrom` reproduces
  the exact attribute set of the issued cookie, so browsers actually overwrite it.
* **Opaque, server-side session state** — `SessionStore.java:29-35`: the client holds a
  lookup key only; identity and expiry are server-authoritative and untamperable. No
  client-side trust boundary violation (CWE-565), no deserialization of client data
  (CWE-502), and no self-contained token to forge (the JWT `alg:none`, key-confusion and
  weak-HMAC-secret checks from the API-auth skill are all inapplicable — there is no JWT).
* **Both timeouts present** — `SessionStore.java:19-22,51-52`: 30-minute idle **and**
  8-hour absolute; the absolute cap is the one usually missing (CWE-613).
* **Logout order** — `LogoutServlet.java:22-27`: server-side invalidation happens before
  the cookie is cleared, so a captured id is genuinely revoked rather than merely hidden
  from the browser (subject to F-02).
* **Stale-cookie cleanup** — `SessionAuthenticationFilter.java:39-42`: a dead id causes
  the cookie to be expired rather than replayed indefinitely.
* **Deny-by-default access control** — `SessionAuthenticationFilter.java:19,38-44`: the
  filter is mapped to `/*` with a single explicit exemption, and every unresolved session
  terminates the chain with `401` (the forced-browsing skill's core check — no protected
  handler is reachable without passing the filter, subject to F-07).
* **Cache control on credential-bearing responses** — `LoginServlet.java:50` and
  `LogoutServlet.java:28` set `Cache-Control: no-store`, so `Set-Cookie` is not stored by
  shared caches (CWE-525).
* **Method hygiene** — `LoginServlet.java:56-59` rejects `GET` on the login endpoint with
  `405`, preventing session issuance via a link or `<img>` tag.
* **Container hardening** — `web.xml:13-24`: `tracking-mode COOKIE` (no `jsessionid` in
  URLs → no CWE-598 token-in-URL leakage via `Referer`/logs/shared links), `http-only`,
  `secure`, no `<domain>`.
* **Dependencies** — `pom.xml:20-25`: one dependency, `jakarta.servlet-api:6.0.0`, scope
  `provided` (API only, not shipped in the WAR). No known-vulnerable or unmaintained
  components; nothing to flag under CWE-1395/A06:2021.
* **No hardcoded secrets** — grepped all files: no keys, passwords, tokens or connection
  strings (CWE-798 not present). No SQL, no OS command execution, no file-path handling,
  no XML/object deserialization, no outbound network calls, and no HTML/response body
  rendering anywhere in scope, so injection classes (CWE-89, CWE-78, CWE-22, CWE-611,
  CWE-79, CWE-918) have no reachable sink.

## 4. Behaviours reviewed against general OWASP/CWE knowledge

The library had no skill dedicated to Java servlet-filter chain ordering,
`@WebFilter` dispatcher-type coverage, `ConcurrentHashMap` atomicity, or JVM heap
exhaustion via unbounded collections. F-02, F-05 and F-07 were therefore assessed
directly against general OWASP Top 10 (A01 Broken Access Control, A04 Insecure Design,
A07 Identification and Authentication Failures) and CWE knowledge rather than a
specialised skill checklist.

## 5. Skills applied

1. `testing-api-authentication-weaknesses` — missing authentication on endpoints, token
   entropy, token revocation/lifecycle, session-management flaws → F-01, F-02, F-03
2. `bypassing-authentication-with-forced-browsing` — unprotected endpoints, path
   normalisation and method-based bypass, defence in depth → F-01, F-07
3. `testing-for-broken-access-control` — missing function-level checks, deny-by-default
   verification → F-01, F-07
4. `performing-csrf-attack-simulation` — SameSite assessment, anti-CSRF token and
   Origin/Referer validation on state-changing requests → F-04
5. `exploiting-race-condition-vulnerabilities` — TOCTOU on shared session state → F-02
6. `performing-security-headers-audit` — HSTS, cookie attributes, transport security → F-06, §3
7. `performing-cryptographic-audit-of-application` — CSPRNG selection, token entropy,
   absence of hardcoded key material → §3
8. `testing-for-sensitive-data-exposure` — token leakage in URLs/logs/caches, insecure
   transport of the session credential → F-06, F-08, §3

## 6. Summary

| ID | Severity | CWE | Location |
|----|----------|-----|----------|
| F-01 | Critical | CWE-306 / CWE-287 | `LoginServlet.java:29,40-47`; `SessionAuthenticationFilter.java:30-33` |
| F-02 | High | CWE-362 / CWE-613 | `SessionStore.java:46-59,62-66` |
| F-03 | Medium | CWE-384 / CWE-613 | `LoginServlet.java:34-37` |
| F-04 | Medium | CWE-352 | `LoginServlet.java:25-53`; `LogoutServlet.java:17-30` |
| F-05 | Medium | CWE-400 / CWE-772 | `SessionStore.java:24,32-35,42-56` |
| F-06 | Low | CWE-319 / CWE-523 | `web.xml:27-35` |
| F-07 | Low | CWE-1173 / CWE-289 | `SessionAuthenticationFilter.java:19,29-33` |
| F-08 | Low | CWE-778 | `LoginServlet.java:44`; `SessionAuthenticationFilter.java:43`; `LogoutServlet.java:24` |

The cookie-handling layer (`SessionCookieFactory`, `SessionIdGenerator`) is genuinely
well engineered and needs no changes. The defects are concentrated in the
*authentication decision* and *session lifecycle*: `/login` hands out valid sessions to
anonymous callers (F-01), the store's refresh is not atomic against revocation (F-02),
and the session-fixation defence targets a session store the application does not use
(F-03). Fix F-01 first — it is remotely exploitable with a single unauthenticated
request and it also supplies the free session-creation primitive that makes F-05
practical.
