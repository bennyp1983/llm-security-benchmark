# Security Review — `auth-session-cookie`

**Scope:** all source under `src/main/` and `src/test/`, plus `web.xml` and `pom.xml`.
**Framework:** Java 17, Jakarta Servlet API 6.0.0 (WAR), Maven.
**Overall verdict:** The code is heavily hardened. No high/critical vulnerabilities were found.
There is **1 low** finding (CSRF defense-in-depth) and **2 informational** findings
(session-cookie lifetime management; no HSTS emitted by the WAR). The remainder of the report
documents the controls that were verified to be *present and correct*, plus non-vulnerability
deployment constraints.

All `file:line` references are relative to the project root.

---

## Findings

### F1 — LOW — CWE-352 (Cross-Site Request Forgery)
**No anti-CSRF token and no Origin/Referer validation; CSRF protection rests entirely on the
session cookie's `SameSite` attribute plus POST-only handlers.**

- `src/main/java/com/example/auth/web/LogoutServlet.java:54-64` — the state change
  (`sessions.remove(identifier)`, `:58`) performs no CSRF token, `Origin`, or `Referer` check.
- `src/main/java/com/example/auth/web/LoginServlet.java:78-103` — the login POST is likewise
  unprotected by a token, though see the mitigation below.

**Why it matters:** A cross-site attacker who can trick a victim's browser into submitting a
`POST /api/logout` form could force the victim's session to be revoked (annoyance / log-out
DoS). Whether that request actually carries the session cookie depends solely on
`SameSite`. The shipped config uses `Strict` (`src/main/webapp/WEB-INF/web.xml:24-26`), so the
cookie is *not* sent cross-site and the attack is currently blocked; both endpoints also return
`405` on `GET` (`LoginServlet.java:72-74`, `LogoutServlet.java:49-51`), which blocks the trivial
`<img>`-tag trigger.

**Residual risk:** `SessionCookieConfig` *permits* `SameSite=None` (it only validates that
`None` is paired with `Secure`, `src/main/java/com/example/auth/session/SessionCookieConfig.java:63-64`).
If an operator ever sets `auth.cookie.sameSite=None`, the cookie is sent on cross-site requests
and logout CSRF becomes exploitable — the design has no independent CSRF control to fall back on.

**Mitigations already present:** `SameSite=Strict` in `web.xml`; `405` on `GET`; and login
itself is CSRF-resistant *by design* because identity is read from server-set request attributes,
never from client input (`LoginServlet.java:79-86`) — a cross-site form POST has no attributes and
fails closed with `401`.

**Recommendation:** Add an independent CSRF control on state-changing POSTs — validate
`Origin`/`Referer` or the `Sec-Fetch-Site` header (reject `cross-site`), or issue a per-session
anti-CSRF token. Additionally, either forbid `SameSite=None` for this app or document that doing
so re-enables CSRF.

---

### F2 — Informational — CWE-613 (Insufficient Session Expiration)
**The client cookie is a browser-session cookie (no `Max-Age`/`Expires`) while the server-side
session has a 1800 s TTL; there is no idle/sliding expiration.**

- `src/main/java/com/example/auth/session/SessionCookieConfig.java:41-42` — `DEFAULTS` uses
  `maxAgeSeconds = -1`; `:60-61` explicitly allows `-1` ("a cookie that dies with the browser").
- `src/main/webapp/WEB-INF/web.xml:28-30` — `auth.session.ttlSeconds = 1800`; `web.xml` does not
  set a cookie `Max-Age`, so the `-1` default applies.
- `src/main/java/com/example/auth/web/LoginServlet.java:63-66` — the guard only rejects the
  `Max-Age >= 0` case that outlives the server TTL; the `-1` case is intentionally allowed.

**Why it matters (low impact):** After 1800 s the server discards the session, but the browser
keeps the cookie until it is closed. This is **fail-closed, not a confidentiality defect**: the
server is authoritative and rejects expired identifiers on every lookup
(`src/main/java/com/example/auth/session/InMemorySessionRegistry.java:30-44`), so a stale cookie
grants nothing. The practical consequence is a cookie-lifetime-management / usability note (a
long-idle user is hard-logged-out at the TTL with no sliding extension), not an exploitable flaw.

**Recommendation (optional):** If a long-lived-but-active session is desired, add idle/sliding
expiration; otherwise leave as-is and document that the server TTL is authoritative.

---

### F3 — Informational — CWE-319 (Cleartext Transmission of Sensitive Information)
**No `Strict-Transport-Security` header is emitted by the WAR; HTTPS enforcement is delegated to
an edge / TLS terminator.**

- `src/main/webapp/WEB-INF/web.xml:14-15` — comment assumes HTTPS is enforced by the deployment.
- `src/main/webapp/WEB-INF/web.xml:39-40` and `src/main/java/com/example/auth/session/SessionCookieFactory.java:28-31`
  — the `Secure` + `HttpOnly` cookie flags are the primary control.

**Why it matters (low impact):** If the app is ever directly reachable over plain HTTP, the
`Secure`/`__Host-` cookie simply is not sent (fail-closed), but the *first* pre-HSTS contact is
exposed to SSL-stripping / downgrade. HSTS is not set here because it is a deployment/edge
concern, but the WAR does not emit it either.

**Recommendation:** Ensure the load balancer / reverse proxy sets HSTS
(`max-age` + `includeSubDomains`, ideally `preload`); for Tomcat this is the
`StrictTransportSecurityHeaderValve` plus `RemoteIpValve` behind TLS.

---

## Non-vulnerability deployment constraints (not scored)

- **Single-node, in-memory session store** — `src/main/java/com/example/auth/session/InMemorySessionRegistry.java:12,20`.
  Sessions are lost on process restart and are not shared across a cluster. Documented in the
  README; this is an availability/usability constraint, not a confidentiality flaw. (CWE-613-adjacent.)
- **`SameSite` emitted via a Servlet 6.0 extension attribute** — `src/main/java/com/example/auth/session/SessionCookieFactory.java:36,58`
  uses `Cookie.setAttribute("SameSite", ...)`, which requires a Servlet 6.0 container
  (Tomcat 10.1+ / Jetty 11+ / WildFly 27+, per `pom.xml:21-26`). A container that drops the
  extension attribute would silently downgrade CSRF protection to the browser default (`Lax`).
  Pin/test the target container. (CWE-352-adjacent.)
- **Container `JSESSIONID` SameSite is out of `web.xml`** — `src/main/webapp/WEB-INF/web.xml:32-35`
  notes Tomcat renders the *container* session cookie's `SameSite` via `context.xml`
  (`Rfc6265CookieProcessor`), which this WAR does not control. The `JSESSIONID` `SameSite=Strict`
  hardening therefore depends on the deployment's `context.xml`, not this artifact.

---

## Controls verified to be present and correct (no finding)

- **Unpredictable, claim-free session id** — 256 bits from the platform CSPRNG
  (`src/main/java/com/example/auth/session/SessionIdentifiers.java:17-18`), encoded
  `base64url` without padding (`:23-27`). CWE-330 mitigated.
- **`Set-Cookie` header injection prevented** — `requireValidSessionId` bounds length (512) and
  whitelists exactly the RFC 6265 `cookie-value` octets
  (`src/main/java/com/example/auth/session/SessionCookieFactory.java:82-96,103-110`), so an
  attacker-influenced identifier cannot break out of the cookie and append response headers.
  CWE-113 / CWE-444 mitigated.
- **Cookie hardening** — `HttpOnly`, `Secure`, `Path=/`, host-only (no `Domain`), `__Host-`
  prefix, and `SameSite` are all set on issue and on clear
  (`src/main/java/com/example/auth/session/SessionCookieFactory.java:26-36`); `__Host-` is only
  valid with no `Domain` and `Path=/` (`SessionCookieConfig.java:70-76`). CWE-1004 / CWE-1021 mitigated.
- **Config cannot weaken `Secure`/`HttpOnly`** — any `SameSite` requires `Secure`
  (`SessionCookieConfig.java:63-68`); the `WebInfrastructure` fallback hardcodes
  `secure=true`/`httpOnly=true`, so context params can only *narrow* the cookie.
- **Session-fixation defense** — the identifier is read only from server-set request attributes
  (fail-closed `401`, `LoginServlet.java:79-86`); an identifier the client already presented is
  refused (`LoginServlet.java:88-91,111-116`); a URL-derived identifier is refused
  (`LoginServlet.java:112-113`); the pre-auth `HttpSession` is discarded (`LoginServlet.java:93`).
  CWE-384 mitigated.
- **Logout revokes the server-side record before expiring the cookie** —
  `src/main/java/com/example/auth/web/LogoutServlet.java:56-58` (remove first) then `:64`
  (clear). A copy of the id stolen before logout stops working.
- **POST-only endpoints** — both handlers return `405` + `Allow: POST` on `GET`
  (`LoginServlet.java:72-74`, `LogoutServlet.java:49-51`), preventing GET-based CSRF and
  log-out-via-`<img>` DoS.
- **No identifier in URLs / `Referer`** — `<tracking-mode>COOKIE</tracking-mode>` only
  (`src/main/webapp/WEB-INF/web.xml:44`).
- **No response caching** — `Cache-Control: no-store` on all responses (`AuthResponses.noStore`).
- **Absence of classic sink classes** — no SQL, no unsafe deserialization, no OS command
  execution, no hardcoded secrets/keys, and no weak or legacy cryptographic primitives anywhere
  in `src/main` or `src/test` (verified by targeted searches across the tree).

---

## Skills applied

- `testing-api-authentication-weaknesses`
- `performing-security-headers-audit`
- `performing-cryptographic-audit-of-application`
- `performing-csrf-attack-simulation`
- `testing-for-broken-access-control`
- `implementing-secret-scanning-with-gitleaks` (considered; targeted search for keys/credentials/secrets — none found)
- `exploiting-insecure-deserialization` (considered; no deserialization sinks in scope — N/A)

## Note on behaviors with no matching library skill

Session-fixation specifics and secure session-cookie attribute enforcement have **no dedicated
library skill** in this library. Those behaviors were reviewed against general OWASP Top 10
(A01 Broken Access Control, A02 Cryptographic Failures, A05 Security Misconfiguration) and CWE
knowledge (CWE-384 Session Fixation, CWE-613 Insufficient Session Expiration, CWE-1004
Sensitive Cookie Without Secure Flag, CWE-113 / CWE-444 header injection, CWE-352 CSRF).
