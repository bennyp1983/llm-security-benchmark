# Security Review: session-cookie-demo (`com.example.auth` session-cookie issuance and probe)

## 1. Executive Summary

`session-cookie-demo` is a Jakarta Servlet 6 / Tomcat 10 web application that demonstrates issuing a session
identifier in a hardened cookie and reading it back. It ships two mapped endpoints — `POST /login`
(`LoginServlet`) and `GET /whoami` (`SessionProbeServlet`) — plus a cookie-policy class
(`SessionCookieFactory`) and a `SecureRandom` identifier generator (`SessionIdGenerator`). The built artifact
contains no `web.xml`, so both `@WebServlet` annotations are live mappings.

The cookie layer is genuinely well hardened: `Secure` and `HttpOnly` default to on, `SameSite` defaults to
`Lax`, `SameSite=None` is refused without `Secure`, the identifier is never read from a request parameter
(session-fixation safe), and a `Set-Cookie` allow-list regex makes header injection through the cookie value
impossible. `Cache-Control: no-store` is set and the identifier is never echoed.

The problems are all in what the cookie layer is *not* backed by: **there is no authentication and no session
state at all**. `SessionProbeServlet` reports a caller as `authenticated` purely because a non-empty cookie of
the right name is present — any value an attacker types works (`SEC-01`, the most severe finding). `LoginServlet`
issues a valid session cookie to any anonymous `POST /login` with no credential check (`SEC-02`). Sessions are
never recorded, expired or revocable, and the shipped API cannot even express "delete this cookie" (`SEC-03`).
Secondary findings: a supplied session identifier is only checked for *legal characters*, not for entropy, so a
three-character session id is accepted (`SEC-04`); both cookie-protection flags can be switched off by init-param
with no acknowledgement (`SEC-05`); `POST /login` has no anti-CSRF control and the CSRF-relevant `SameSite`
default is operator-overridable (`SEC-06`); one Low response-splitting gap and one Low missing-headers gap
(`SEC-07`, `SEC-08`).

Eight findings: 1 Critical, 1 High, 4 Medium, 2 Low. `SEC-01`–`SEC-03` should be closed before this package is
deployed anywhere reachable; the README describes them as out of scope for the demo, but the code as shipped
grants "authenticated" to anyone who asks, and the sample is the thing other developers will copy.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `src/main/java/com/example/auth/LoginServlet.java` | `POST /login`; issues the session cookie | No credential check: mints an identifier and returns 200 + cookie for any anonymous POST (`:56-76`); accepts an identifier from a server-side request attribute without an entropy check (`:57-58`); `doGet` rejected with 405 (`:50-53`); sets `Cache-Control: no-store` (`:69`) |
| `src/main/java/com/example/auth/SessionCookieFactory.java` | Cookie policy: name, path, domain, max-age, `Secure`, `HttpOnly`, `SameSite` | `Secure`/`HttpOnly` default on but are switchable off by init-param (`:131-132`, `:95-96`); value allow-list blocks `Set-Cookie` injection (`:33`, `:144`); `Max-Age <= 0` normalised to `-1`, so no delete-cookie can be produced and max-age is unbounded above (`:94`, `:117-125`); `SameSite=None` allowed with `Secure` (`:77-79`) |
| `src/main/java/com/example/auth/SessionIdGenerator.java` | Generates session identifiers | Correct: 256 bits from `SecureRandom`, Base64-URL unpadded, 43 chars, thread-safe static instance (`:15-16`, `:21-25`) |
| `src/main/java/com/example/auth/SessionProbeServlet.java` | `GET /whoami`; proves the cookie replays | Declares a caller authenticated from cookie presence alone — no session lookup, no validation of the value (`:36-50`); `cookieName` init-param is used unvalidated in a response header and the body (`:29-32`, `:45`) |
| `src/test/java/com/example/auth/LoginServletTest.java` | 12 tests for `/login` | Confirms fixation attempts via parameters are ignored and CRLF identifiers yield 500; also confirms the anonymous happy path (`generatesIdWhenAbsent`) |
| `src/test/java/com/example/auth/SessionCookieFactoryTest.java` | 11 tests for the cookie policy | Asserts the hardened defaults and the 8 header-breaking identifiers; also asserts `cookieSecure=false`/`cookieHttpOnly=false` are accepted and that `"id1"` is a usable id |
| `src/test/java/com/example/auth/SessionProbeServletTest.java` | 5 tests for `/whoami` | `honoursConfiguredCookieName` demonstrates the defect: value `"abc"` yields `authenticated`; `identifierIsNotEchoed` confirms the id is not reflected |
| `src/test/java/com/example/auth/ServletDoubles.java` | `java.lang.reflect.Proxy` doubles for `HttpServletRequest/Response/ServletConfig` | Test-only; no production impact. Unstubbed methods return type defaults rather than throwing, which can mask unexpected calls in assertions |
| `pom.xml` | WAR build, `jakarta.servlet-api` 6.0.0 (provided), JUnit 5.10.2 (test), release 17 | No vulnerable pinned dependency was identified from the declarations themselves; no live CVE/dependency lookup was performed (see §6) |
| `README.md` | Design notes, configuration table, verified results | Documents the security intent and the demo's scope; the `curl -i -X POST .../login` example is the reproduction for `SEC-02`; the logout note is the reproduction for `SEC-03` |
| `target/` (build output) | `session-cookie-demo.war`, exploded webapp | Contains **no** `web.xml` → the two `@WebServlet` annotations are the only mappings and both endpoints are deployed by default |

Not reviewed as code: `prompt.txt`, `cyber_prompt.txt`, `prompt_hash.txt`, `return.txt`, `result.md` (task-harness
files, no executable content).

## 3. Skills Applied

- `review-code-for-security-vulnerabilities`: entry point. Established what each file actually does first, then
  selected the specialised skills below by name/description match rather than reporting from general knowledge.
- `testing-api-authentication-weaknesses`: applied to `LoginServlet.doPost` (`:56-76`) and
  `SessionProbeServlet.doGet` (`:36-50`) — token/identifier validation, where the credential comes from, and
  whether possession of a token is ever verified server-side. Source of `SEC-01`, `SEC-02`, `SEC-04`.
- `testing-for-broken-access-control`: applied to the two mapped endpoints — no `web.xml`, no `security-constraint`,
  no filter, no container realm, so `/login` and `/whoami` are reachable unauthenticated and `/whoami` performs no
  authorization decision at all.
- `performing-cryptographic-audit-of-application`: applied to `SessionIdGenerator.java:14-25` (PRNG choice, seed
  source, output length) and to the length/entropy floor applied to *externally supplied* identifiers, i.e.
  `SessionCookieFactory.java:33`. Source of `SEC-04`.
- `performing-security-headers-audit`: applied to every response built in `LoginServlet.java:68-72` and
  `SessionProbeServlet.java:39-42` and to the resulting cookie attributes. Source of `SEC-05`, `SEC-08`.
- `performing-csrf-attack-simulation`: applied to the state-changing `POST /login` (no synchroniser token, no
  `Origin`/`Referer` check) and to how far `SameSite=Lax` actually protects a *login* endpoint. Source of `SEC-06`.
- `testing-for-xss-vulnerabilities`: applied to both response bodies — every value written to the writer was traced
  to see whether request data reaches it. Result: no XSS; one response-splitting gap (`SEC-07`).
- `implementing-secret-scanning-with-gitleaks`: applied to `src/`, `pom.xml` and `README.md` for hardcoded
  credentials, keys and tokens. No real secret found (the only hit, `super-secret-session-value` at
  `src/test/java/com/example/auth/SessionProbeServletTest.java:47`, is a test fixture).

Session-lifecycle behaviour — server-side session recording, idle/absolute expiration, revocation and logout
(`SEC-03`) — plus the cookie attribute policy itself (`SEC-05`) had no matching skill in the library and were
reviewed against general OWASP Top 10 / CWE knowledge (OWASP Session Management Cheat Sheet; CWE-384, CWE-613,
CWE-614, CWE-1004).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | `/whoami` treats any non-empty session cookie value as proof of authentication | Critical | CWE-287 | `SessionProbeServlet.java:44-48` |
| SEC-02 | `POST /login` issues a session cookie without checking any credential | High | CWE-306 | `LoginServlet.java:56-68` |
| SEC-03 | No server-side session state: identifiers never expire, cannot be revoked, no logout | Medium | CWE-613 | `LoginServlet.java:56-76`, `SessionCookieFactory.java:94` |
| SEC-04 | Supplied session identifier is checked for characters only, not entropy | Medium | CWE-330 | `SessionCookieFactory.java:33`, `LoginServlet.java:57-58` |
| SEC-05 | `cookieSecure=false` / `cookieHttpOnly=false` accepted silently | Medium | CWE-614 | `SessionCookieFactory.java:126-133` |
| SEC-06 | No CSRF control on the state-changing `POST /login` | Medium | CWE-352 | `LoginServlet.java:56-68` |
| SEC-07 | Unvalidated `cookieName` init-param reaches `Set-Cookie` and the response body | Low | CWE-20 | `SessionProbeServlet.java:29-32` |
| SEC-08 | Missing response hardening headers (HSTS, `X-Content-Type-Options`, frame protections) | Low | CWE-693 | `LoginServlet.java:69-72` |

## 5. Detailed Findings

### SEC-01: `/whoami` treats any non-empty session cookie value as proof of authentication

- **Severity:** Critical
- **CWE:** CWE-287: Improper Authentication (also CWE-306 for the endpoint behind it)
- **Location:** `SessionProbeServlet.java:36-50`, decision at `44-48`

**Vulnerable code:**

```java
// src/main/java/com/example/auth/SessionProbeServlet.java:36-49
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Cookie session = findSessionCookie(request.getCookies());

        response.setHeader("Cache-Control", "no-store");
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("text/plain");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        try (PrintWriter out = response.getWriter()) {
            if (session == null || session.getValue().isEmpty()) {
                out.println("not authenticated: no " + cookieName + " cookie on this request");
            } else {
                out.println("authenticated: replayed session cookie of " + session.getValue().length() + " chars");
            }
        }
```

**Why it is a problem:** The only gate is "a cookie named `APPSESSION` exists and its value is not empty". The
value is never validated, never looked up, and never compared with anything the server issued — not even with
`SessionCookieFactory.isUsableSessionId`, which exists in this same package. The cookie is the one piece of
session state a client writes freely, so the check authenticates nobody:

```bash
curl -i -H 'Cookie: APPSESSION=anything' http://localhost:8080/session-cookie-demo/whoami
  # HTTP/1.1 200
  # authenticated: replayed session cookie of 7 chars
```

The repository's own test suite encodes this as expected behaviour — `SessionProbeServletTest.java:62-72` feeds a
hand-written value `"abc"` and asserts the response starts with `authenticated`. Any attacker chooses their own
credential, and any application built by lifting this pattern (a very likely use of a package named *session
cookie demo*) grants access on a client-supplied value. Severity is Critical because authentication is the
function being performed and it is fully bypassed by design.

**Fix:** The identifier must resolve to state the server created. Issue sessions from a store, look the presented
value up on every request, and answer 401 when it is unknown, malformed or expired:

```java
// SessionStore is the missing piece: an in-memory map in the demo, a DB/cache table in production.
public interface SessionStore {
    record Principal(String sessionId, Instant issuedAt) { }

    Principal create();

    /** Empty unless the id was issued by this server and is inside its idle and absolute timeout. */
    Optional<Principal> find(String sessionId);

    void remove(String sessionId);
}
```

```java
// SessionProbeServlet.java — authenticated probe built on the store
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Cookie session = findSessionCookie(request.getCookies());

        response.setHeader("Cache-Control", "no-store");
        response.setContentType("text/plain");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());

        Optional<SessionStore.Principal> principal =
                (session == null || !cookiePolicy.isUsableSessionId(session.getValue()))
                        ? Optional.empty()
                        : sessionStore.find(session.getValue());
        if (principal.isEmpty()) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            try (PrintWriter out = response.getWriter()) {
                out.println("not authenticated");
            }
            return;
        }

        response.setStatus(HttpServletResponse.SC_OK);
        try (PrintWriter out = response.getWriter()) {
            out.println("authenticated");
        }
    }
```

Note the fix also stops reporting the identifier's length to an anonymous caller and returns a real status code
instead of 200 for unauthenticated requests, which the current code never does.

### SEC-02: `POST /login` issues a session cookie without checking any credential

- **Severity:** High
- **CWE:** CWE-306: Missing Authentication for Critical Function
- **Location:** `LoginServlet.java:56-68` (mapping at `:26`)

**Vulnerable code:**

```java
// src/main/java/com/example/auth/LoginServlet.java:56-68
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Object supplied = request.getAttribute(SESSION_ID_ATTRIBUTE);
        String sessionId = (supplied instanceof String) ? (String) supplied : SessionIdGenerator.generate();

        Cookie sessionCookie;
        try {
            sessionCookie = cookieFactory.newSessionCookie(sessionId);
        } catch (IllegalArgumentException e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "unusable session identifier");
            return;
        }

        response.addCookie(sessionCookie);
```

**Why it is a problem:** `/login` is the authentication endpoint, and it authenticates nothing. No credential is
read (`no getParameter`, no header, no realm), and no check is made that an authentication step actually ran:
`request.getAttribute(SESSION_ID_ATTRIBUTE)` is `null` for every request that is not the product of a documented
internal forward, so the `null` branch silently *succeeds* by generating a fresh 256-bit identifier and handing
back a hardened, `Secure`, `HttpOnly` session cookie with HTTP 200. There is no `web.xml` in the built WAR and no
filter in the project, so nothing in front of the servlet enforces the precondition the comment assumes. Anyone
on the network becomes "authenticated" with one unauthenticated request — this is the endpoint's documented
behaviour and its own test asserts it (`LoginServletTest.java:74-82`) — and it is exactly what the README's
`curl -i -X POST http://localhost:8080/session-cookie-demo/login` example demonstrates. The class javadoc is
honest about the assumption ("performs no credential checking of its own"), but a missing precondition on a
mapped, deployed endpoint is a vulnerability in the artifact, not in its documentation: fail-open on
"authentication did not happen" turns an integration mistake into an access grant.

**Fix:** Absence of an authenticated principal must be a refusal, never a fallback to generating an identifier:

```java
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!(request.getAttribute(SESSION_ID_ATTRIBUTE) instanceof String sessionId)) {
            // No preceding authentication step ran: this is an anonymous login attempt.
            response.setHeader("Cache-Control", "no-store");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "not authenticated");
            return;
        }

        Cookie sessionCookie;
        try {
            sessionCookie = cookieFactory.newSessionCookie(sessionId);
        } catch (IllegalArgumentException e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "unusable session identifier");
            return;
        }

        response.addCookie(sessionCookie);
```

If this servlet is meant to *own* credential verification instead, then read the credential here, verify it
against a real identity store with a constant-time comparison and an Argon2id/bcrypt password hash, rate-limit
the endpoint, and only then mint the identifier. Either way the `SessionIdGenerator.generate()` fallback on an
unauthenticated request has to go. `LoginServletTest.java:74-82` then becomes an assertion that an anonymous POST
yields 401 and no cookie.

### SEC-03: No server-side session state: identifiers never expire, cannot be revoked, no logout

- **Severity:** Medium
- **CWE:** CWE-613: Insufficient Session Expiration (with CWE-1071 for the unusable normalisation)
- **Location:** `LoginServlet.java:56-76`, `SessionCookieFactory.java:94`, `SessionCookieFactory.java:117-125`

**Vulnerable code:**

```java
// src/main/java/com/example/auth/SessionCookieFactory.java:91-97
        this.cookieName = cookieName;
        this.path = path;
        this.domain = normalisedDomain;
        this.maxAge = maxAge > 0 ? maxAge : -1;
        this.secure = secure;
        this.httpOnly = httpOnly;
        this.sameSite = normalisedSameSite;
```

**Why it is a problem:** Nothing anywhere records a session. `LoginServlet.doPost` (`:56-76`) mints an identifier,
puts it in a cookie and forgets it; there is no store, no idle timeout, no absolute lifetime, no logout endpoint
and no revocation path. A session identifier is therefore valid forever, and "forever" is literally the default:
`cookieMaxAge` is unset, `maxAge` becomes `-1`, and the identifier outlives the browser session as far as the
server is concerned. Combined with `SEC-01`, which accepts any value anyway, there is no server-side notion of a
session at all — logging out, firing an employee or rotating a compromised credential has no meaning.

Two concrete sub-problems in the policy class itself:

1. `maxAge` has no upper bound. `Integer.parseInt` at `:120` happily accepts `cookieMaxAge=2147483647`, which
   `newSessionCookie` writes as a ~68-year persistent session cookie on every login.
2. `maxAge > 0 ? maxAge : -1` (`:94`) means the class *cannot produce* a `Max-Age=0` cookie — yet the README's own
   security note says logout must "expire the cookie with `Max-Age=0`". No API in this package can do it, so a
   developer following the README cannot implement the half of logout that clears the cookie. (The normalisation
   itself is correct for the *login* cookie, where a literal `Max-Age=0` would delete it on arrival; the gap is
   that no separate expiry cookie exists.)

**Fix:** Bind every issued identifier to server-side state with both an idle and an absolute timeout, revoke it on
logout, and give the factory an explicit expire-cookie so the README's logout recipe is implementable:

```java
// SessionCookieFactory.java — bounded lifetime
        if (maxAge > MAX_AGE_SECONDS) {
            throw new IllegalArgumentException("cookieMaxAge must be at most " + MAX_AGE_SECONDS
                    + " seconds, got: " + maxAge);
        }
        this.maxAge = maxAge > 0 ? maxAge : DEFAULT_SESSION_MAX_AGE; // e.g. 1800, not -1
```

```java
// SessionCookieFactory.java — the delete-cookie the logout flow needs
    /** Tells the browser to drop the session cookie immediately. For logout only. */
    public Cookie expireSessionCookie() {
        Cookie cookie = new Cookie(cookieName, "expired");
        cookie.setPath(path);
        if (domain != null) {
            cookie.setDomain(domain);
        }
        cookie.setSecure(secure);
        cookie.setHttpOnly(httpOnly);
        cookie.setMaxAge(0);                 // literal 0: this cookie is meant to die
        if (sameSite != null) {
            cookie.setAttribute("SameSite", sameSite);
        }
        return cookie;
    }
```

```java
// LogoutServlet.java — both halves of logout, as the README requires
        sessionStore.remove(presentedSessionId);                     // server side
        response.addCookie(cookiePolicy.expireSessionCookie());      // client side
        response.setHeader("Cache-Control", "no-store");
```

The store must also enforce an absolute ceiling (e.g. 8–12 hours) in addition to an idle timeout, and
`SessionStore.find(...)` — used by `SEC-01`'s fix — is where both timeouts are applied.

### SEC-04: Supplied session identifier is checked for characters only, not entropy

- **Severity:** Medium
- **CWE:** CWE-330: Use of Insufficiently Random Values (CWE-331 insufficient entropy, CWE-20 missing validation)
- **Location:** `SessionCookieFactory.java:33` (validator), `LoginServlet.java:57-58` (trusted caller)

**Vulnerable code:**

```java
// src/main/java/com/example/auth/SessionCookieFactory.java:32-33
    /** Token characters that are safe on a {@code Set-Cookie} header (RFC 6265 cookie-value plus a hyphen). */
    private static final Pattern LEGAL_SESSION_ID = Pattern.compile("[A-Za-z0-9._~+-]{1,255}");
```

**Why it is a problem:** `{1,255}` is a *transport* safety rule, not a strength rule — a one-character identifier
passes. The only length-1..3 identifiers this package ever puts in a cookie are attacker-supplied ones, and the
trust boundary that matters is `LoginServlet.java:57-58`, where a request attribute from an upstream authenticator
is taken verbatim as the session identifier. That is the documented integration point for third-party
authentication code, and if it stores anything guessable there — a sequence number, a user id, a short ticket, a
`UUID.randomUUID()`-free counter — this package will deliver it as a session cookie and `SEC-01` will accept it
back, giving a fully guessable session. `SessionCookieFactory.java:161-163` (`isUsableSessionId`) exposes that same
character-only rule as a public "is this usable?" check, so a caller can satisfy the package's only stated
requirement with `"1"`, which is exactly the problem: the security-critical strength
check is delegated to a caller that is never constrained, tested or even identified. The repository's own tests
prove short ids flow through: `SessionCookieFactoryTest` builds cookies with `"id1"` and
`"abcDEF012._~+-xyz"`, and `LoginServletTest.java:49-54` asserts `"session-from-authenticator_1"` is accepted.
There is also a silent collision risk: `newSessionCookie` cannot detect that the supplied identifier was already
issued to a different principal, so a caller-generated identifier silently hijacks an existing session.

**Fix:** Refuse identifiers that do not carry at least 128 bits of entropy, as the OWASP Session Management
Cheat Sheet requires, and restrict the alphabet to the one `SessionIdGenerator` emits:

```java
// SessionCookieFactory.java
    /**
     * 22 base64url characters is ~132 bits, the OWASP floor for a session identifier. Anything the
     * caller supplies must already look like the output of SessionIdGenerator.
     */
    private static final Pattern LEGAL_SESSION_ID = Pattern.compile("[A-Za-z0-9_-]{22,255}");
```

```java
// LoginServlet.java:57-58 — generate here, or reject; never trust the caller's entropy
        Object supplied = request.getAttribute(SESSION_ID_ATTRIBUTE);
        if (!(supplied instanceof String sessionId)) {
            response.setHeader("Cache-Control", "no-store");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "not authenticated");
            return;                       // no generate()-on-behalf-of-an-anonymous-caller fallback
        }
        if (!cookieFactory.isUsableSessionId(sessionId)) {
            response.setHeader("Cache-Control", "no-store");
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "unusable session identifier");
            return;                       // caller supplied "1": refuse rather than ship a guessable id
        }
```

The existing tests that use `"id1"` / `"abcDEF012._~+-xyz"` (`carriesSuppliedId` at
`SessionCookieFactoryTest.java:26-36` and `sameSiteAttribute` at `:40-46`) must be updated to a 43-character value,
and a test asserting that a short identifier is
refused should be added. If the caller must keep ownership of identifier generation, make it explicit: have the
caller ask `SessionIdGenerator` for the value and record the collision check against `SessionStore`.

### SEC-05: `cookieSecure=false` / `cookieHttpOnly=false` accepted silently

- **Severity:** Medium
- **CWE:** CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute (also CWE-1004: HTTPOnly not set)
- **Location:** `SessionCookieFactory.java:126-133` (policy read), `:95-96` (policy applied)

**Vulnerable code:**

```java
// src/main/java/com/example/auth/SessionCookieFactory.java:126-133
        return new SessionCookieFactory(
                valueOr(config.getInitParameter(INIT_PARAM_COOKIE_NAME), DEFAULT_COOKIE_NAME),
                valueOr(config.getInitParameter(INIT_PARAM_PATH), DEFAULT_PATH),
                trimToNull(config.getInitParameter(INIT_PARAM_DOMAIN)),
                maxAge,
                booleanOr(config.getInitParameter(INIT_PARAM_SECURE), true),
                booleanOr(config.getInitParameter(INIT_PARAM_HTTP_ONLY), true),
                valueOr(config.getInitParameter(INIT_PARAM_SAME_SITE), DEFAULT_SAME_SITE));
```

**Why it is a problem:** The defaults are correct, but both protections are one unprefixed, unremarkable init-param
away from being off, and the class accepts that outcome the same way it accepts a typo — no warning, no log, no
acknowledgement, and nothing binds the flag to an actual plaintext dev environment. `web.xml` init-params are
routinely copied between environments, and `cookieHttpOnly=false` is precisely the value a developer picks when a
page script needs to "just read the session cookie" — a decision that turns any XSS in the application into a full
session theft, and which is invisible to a reviewer afterwards. `SessionCookieFactoryTest.java:121-139` asserts
this acceptance (`assertFalse(factory.isSecure())`, `assertFalse(factory.isHttpOnly())`), so the behaviour is
pinned. This is especially cheap to fix given the class already refuses `SameSite=None` without `Secure`
(`:77-79`) and already fails startup on unparseable values (`cookieSecure=yes` throws) — the inconsistency is that
a *parseable* weakening is waved through. `Secure` is also the only thing standing between this application's
session cookie and the plain-HTTP deployment the README describes, and nothing verifies it is present.

**Fix:** Keep the secure defaults, but make weakening them require a second, explicit acknowledgement, and keep the
localhost escape hatch documented in `README.md`:

```java
// SessionCookieFactory.java
    public static final String INIT_PARAM_ALLOW_PLAINTEXT = "allowPlaintextSessionCookie";

    public static SessionCookieFactory fromServletConfig(ServletConfig config) {
        // ... existing maxAge parsing ...
        boolean secure = booleanOr(config.getInitParameter(INIT_PARAM_SECURE), true);
        boolean httpOnly = booleanOr(config.getInitParameter(INIT_PARAM_HTTP_ONLY), true);
        if (!secure || !httpOnly) {
            if (!"true".equalsIgnoreCase(trimToNull(config.getInitParameter(INIT_PARAM_ALLOW_PLAINTEXT)))) {
                throw new IllegalArgumentException(INIT_PARAM_SECURE + "/" + INIT_PARAM_HTTP_ONLY
                        + " may only be weakened together with " + INIT_PARAM_ALLOW_PLAINTEXT
                        + "=true, which must never be set outside a local development run");
            }
            System.getLogger(SessionCookieFactory.class.getName()).log(Level.WARNING,
                    "session cookie issued with Secure={0} HttpOnly={1}", secure, httpOnly);
        }
        return new SessionCookieFactory(
                valueOr(config.getInitParameter(INIT_PARAM_COOKIE_NAME), DEFAULT_COOKIE_NAME),
                valueOr(config.getInitParameter(INIT_PARAM_PATH), DEFAULT_PATH),
                trimToNull(config.getInitParameter(INIT_PARAM_DOMAIN)),
                maxAge, secure, httpOnly,
                valueOr(config.getInitParameter(INIT_PARAM_SAME_SITE), DEFAULT_SAME_SITE));
    }
```

Stronger still, drop the flags entirely and always emit `Secure` + `HttpOnly`: `HttpOnly` has no functional
purpose for a session cookie in a `text/plain` API, and Tomcat can serve the localhost demo over TLS.

### SEC-06: No CSRF control on the state-changing `POST /login`

- **Severity:** Medium
- **CWE:** CWE-352: Cross-Site Request Forgery (CSRF)
- **Location:** `LoginServlet.java:56-68`, `SessionCookieFactory.java:133`

**Vulnerable code:**

```java
// src/main/java/com/example/auth/LoginServlet.java:55-68
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Object supplied = request.getAttribute(SESSION_ID_ATTRIBUTE);
        String sessionId = (supplied instanceof String) ? (String) supplied : SessionIdGenerator.generate();

        Cookie sessionCookie;
        try {
            sessionCookie = cookieFactory.newSessionCookie(sessionId);
        } catch (IllegalArgumentException e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "unusable session identifier");
            return;
        }

        response.addCookie(sessionCookie);
```

**Why it is a problem:** `POST /login` changes the caller's session state and carries no anti-CSRF token, no
double-submit cookie, and no `Origin`/`Referer` check. The `405` on `GET` (`:50-53`) narrows the attack but does not
remove it: a cross-site `<form method="post">` reaches `doPost`, and `SameSite=Lax` — which is what protects the
*sending* of cookies — does not stop the browser from *storing* the `Set-Cookie` returned for that cross-site POST.
The attacker's page can therefore establish a session in the victim's browser at will (login CSRF). Today the
payload is small because the session has no identity behind it (`SEC-02`); it becomes a real attack the moment
either documented extension lands — credentials verified from the POST body, or `SEC-04`'s caller-supplied
identifier, where a forced login with an attacker-known id is direct session planting. The remaining mitigation is
also operator-removable: `cookieSameSite=None` is accepted (only `None` without `Secure` is refused at `:77-79`),
and `None` is exactly the value needed for embedded/cross-site framing, so a single init-param silently drops the
cross-site protection this endpoint depends on. A login endpoint should not depend on a configurable cookie
attribute for its CSRF resistance.

**Fix:** Validate the origin of every state-changing request, and refuse a `SameSite` value that would leave the
session cookie sendable cross-site:

```java
// LoginServlet.java — Origin check before any session state changes
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String origin = request.getHeader("Origin");
        if (origin != null && !origin.isBlank() && !isSameOrigin(origin, request)) {
            response.setHeader("Cache-Control", "no-store");
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "cross-origin login");
            return;
        }
        // ... existing authentication + cookie issue path ...
    }

    private static boolean isSameOrigin(String origin, HttpServletRequest request) {
        String expected = request.getScheme() + "://" + request.getServerName()
                + (isDefaultPort(request) ? "" : ":" + request.getServerPort());
        return expected.equalsIgnoreCase(origin.trim());
    }
```

For the credential-verifying login that this package is meant to become, add the synchroniser-token /
double-submit-cookie step as well, and pin `SameSite=Lax` for the session cookie at startup:

```java
// SessionCookieFactory.fromServletConfig — do not let the CSRF-relevant default be weakened
        String sameSite = valueOr(config.getInitParameter(INIT_PARAM_SAME_SITE), DEFAULT_SAME_SITE);
        if ("None".equalsIgnoreCase(sameSite)) {
            throw new IllegalArgumentException(INIT_PARAM_SAME_SITE + "=None is not allowed for a session cookie");
        }
```

### SEC-07: Unvalidated `cookieName` init-param reaches `Set-Cookie` and the response body

- **Severity:** Low
- **CWE:** CWE-20: Improper Input Validation (response splitting; different validator on the same field, CWE-116)
- **Location:** `SessionProbeServlet.java:29-32`, used at `:45`

**Vulnerable code:**

```java
// src/main/java/com/example/auth/SessionProbeServlet.java:28-33
    public void init() throws ServletException {
        String configured = getInitParameter(SessionCookieFactory.INIT_PARAM_COOKIE_NAME);
        if (configured != null && !configured.isBlank()) {
            cookieName = configured.trim();
        }
    }
```

**Why it is a problem:** `SessionProbeServlet` re-reads the `cookieName` init-param on its own and stores it with
only a blank check. `SessionCookieFactory` validates the identical value with the RFC 6265 token pattern
`LEGAL_COOKIE_NAME` (`:36`) and rejects spaces, semicolons, quotes, control and non-ASCII characters — and `LoginServlet`
fails startup on such a value (`:41-47`). The probe applies none of that, so the same deployment can contain a
`cookieName` that `LoginServlet` would have rejected. `cookieName` is then concatenated into the response body at
`:45` and into the `Set-Cookie` header for the lookup name, so a value containing CR/LF is an HTTP response-splitting
primitive, and a value containing a quote breaks the response framing. The servlet still calls
`cookieName.equals(cookie.getName())` at `:57`, so a malformed name simply never matches and the endpoint reports
"not authenticated" forever — the inconsistency is silent, not loud. Impact is Low because the input is a
container-admin `web.xml` value, not remote input (no `getParameter`/`getHeader` use anywhere in `src/main`), but
it is a genuine validation gap in a security-relevant field and it defeats the fail-at-startup design the rest of
the package commits to.

**Fix:** Do not re-parse the policy; build the one validated `SessionCookieFactory` and read the name back from it,
so a bad value fails `init()` like it does in `LoginServlet`:

```java
// SessionProbeServlet.java
    private transient SessionCookieFactory cookiePolicy;

    @Override
    public void init() throws ServletException {
        try {
            cookiePolicy = SessionCookieFactory.fromServletConfig(getServletConfig());
        } catch (IllegalArgumentException e) {
            throw new ServletException("SessionProbeServlet is misconfigured: " + e.getMessage(), e);
        }
    }
```

and in `doGet`/`findSessionCookie` use `cookiePolicy.getCookieName()` (guaranteed to be an RFC 6265 token) instead
of the raw `cookieName` field. If the field is kept for any reason, validate it the same way the factory does:

```java
        String configured = getInitParameter(SessionCookieFactory.INIT_PARAM_COOKIE_NAME);
        if (configured != null && !configured.isBlank()
                && !SessionCookieFactory.isLegalCookieName(configured.trim())) {
            throw new ServletException("cookieName is not an RFC 6265 token: " + configured);
        }
```

### SEC-08: Missing response hardening headers (HSTS, `X-Content-Type-Options`, frame protections)

- **Severity:** Low
- **CWE:** CWE-693: Protection Mechanism Failure (CWE-319 for the TLS-enforcement gap)
- **Location:** `LoginServlet.java:69-72`, `SessionProbeServlet.java:39-42`

**Vulnerable code:**

```java
// src/main/java/com/example/auth/LoginServlet.java:68-72
        response.addCookie(sessionCookie);
        response.setHeader("Cache-Control", "no-store");
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("text/plain");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
```

**Why it is a problem:** `Cache-Control: no-store` is set — correctly, and it is the most important of the set — but
it is the only protection header either endpoint emits. Two gaps matter given this application's own choices:

1. No `Strict-Transport-Security`. The session cookie's `Secure` attribute is what keeps it off the wire, and the
   README states plainly that "this example is plain HTTP". Nothing tells a browser that the host is TLS-only, so a
   first visit over `http:` or a downgrade strips the protection the cookie attribute assumes. `Secure` on the
   cookie and HSTS on the host are two halves of one control, and only one half is implemented.
2. No `X-Content-Type-Options: nosniff` on responses whose body is assembled from values that are not fully under
   the application's control (`cookieName` per `SEC-07`). With a `text/plain` content type and no `nosniff`, a
   user-agent that honours legacy MIME sniffing can be pushed toward rendering that body as something else.
   There is also no frame protection (`X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`) and no
   `Referrer-Policy`, which matters precisely because `SessionCookieFactory` accepts `SameSite=None` — the
   embedded-iframe scenario — with nothing forbidding the framing itself.

Severity is Low because the bodies are static text, `Content-Type` is explicit and there is no HTML/XSS sink
anywhere; these are defense-in-depth headers on a session-issuing endpoint rather than an directly exploitable
flaw.

**Fix:** Emit the hardening set from one place on every response, on both endpoints:

```java
// SessionResponseHeaders.java — call first in every doGet/doPost, before any body is written
    static void harden(HttpServletRequest request, HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
        response.setHeader("Referrer-Policy", "no-referrer");
        // HSTS over cleartext must not be sent: browsers ignore it, and a preload listing
        // would assert TLS for a host that is not actually serving it.
        if (request.isSecure()) {
            response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        }
        response.setContentType("text/plain");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
    }
```

Gate `Strict-Transport-Security` on `request.isSecure()` — or, behind a TLS-terminating proxy, on a validated
`Forwarded` header, never on an `X-Forwarded-Proto` value taken at face value. Note that the header is also pointless
unless the deployment actually serves TLS on the default port, which the README lists as out of the demo's scope;
pair this fix with that configuration change.

## 6. Verified Controls and Checks With No Finding

Cookie and identifier handling (verified by reading the code and by the existing tests):

- **Cookie value injection / response splitting through the session id — blocked.** `LEGAL_SESSION_ID`
  (`SessionCookieFactory.java:33`) plus the check in `newSessionCookie` (`:143-146`) reject CR, LF, space, `;`,
  `"`, `,`, `=` and non-ASCII before the value can reach `Set-Cookie`. `SessionCookieFactoryTest` proves all eight
  classes are refused, and `LoginServletTest.java:114-125` proves a CRLF identifier yields 500 with **no** cookie
  written. This is the single strongest control in the package.
- **Session fixation (CWE-384) — prevented.** The identifier is never read from a request parameter, query string,
  header or form field. The only server-side read in `src/main` is `request.getCookies()` at
  `SessionProbeServlet.java:37`; `LoginServlet.java:57` reads a server-set request attribute, and the `null` case
  generates a fresh identifier instead of honouring a client-suggested one. `LoginServletTest` covers `?sessionId=`
  and `APPSESSION=` attempts.
- **Cookie attribute defaults — correct.** `Secure` and `HttpOnly` default `true` (`:131-132`), `SameSite=Lax`,
  host-only `Path=/` with no `Domain` (`:149-151`), `SameSite=None` refused without `Secure` (`:77-79`). Note the
  configurable weakening is `SEC-05`, not a defect in the defaults.
- **Cookie name, path and domain — validated at startup.** `LEGAL_COOKIE_NAME` (`:36`), the path check at `:66-68`
  with `isIllegalHeaderChar`, and `LEGAL_DOMAIN` (`:39`, `:72`) reject non-tokens, `;`-bearing and control-character
  paths, and leading/trailing-dot domains; unparseable init-params fail `init()` (`LoginServlet.java:41-47`). The
  `Domain` attribute widens to subdomains when configured — an opt-in, documented deployment choice, not a finding.
- **Identifier strength when *this* code generates it — correct.** `SessionIdGenerator.java:14-25`: 256 bits from
  a shared `SecureRandom` (thread-safe, not `java.util.Random`, no time-based seeding, no `Math.random()`),
  Base64-URL unpadded, 43 chars, inside the cookie-safe alphabet. The weakness in `SEC-04` is about *caller-supplied*
  values only.
- **`Max-Age=0` normalisation — correct for the login cookie.** `:94` avoids the "cookie deleted on arrival" bug;
  the missing counterpart for logout is `SEC-03`.

Authentication, authorization and session state:

- **No XSS sink.** Every byte written to a response writer is a literal string (`LoginServlet.java:74`,
  `SessionProbeServlet.java:45`/`:47`) except the `cookieName` concatenation of `SEC-07`. The session identifier
  length is emitted as an `int`, and no request value is ever reflected. `SessionProbeServletTest`
  (`identifierIsNotEchoed`, line 47) enforces that the identifier itself never appears in the body, which also keeps
  it out of caches, proxy logs and history.
- **No SQL, LDAP, OS command, path, deserialization, expression-language or template execution anywhere in
  `src/main/java`.** There is no database, no file I/O, no `Runtime.exec`, no `ObjectInputStream`, no JSP/EL
  rendering. The only external interface is the response writer.
- **`GET` cannot mutate state.** `LoginServlet.doGet` (`:50-53`) advertises `Allow: POST` and returns 405.
- **Secrets scan — clean.** Reviewed `src/`, `pom.xml` and `README.md` for credentials, private keys, API tokens and
  connection strings. The only hit is the test fixture `super-secret-session-value` at
  `SessionProbeServletTest.java:47`. No `.env`, key material or credential file exists in the project.
- **Test doubles reviewed.** `src/test/java/com/example/auth/ServletDoubles.java` is reflection-`Proxy`-based test
  scaffolding with no production reachability. One caveat worth recording rather than reporting: unstubbed methods
  return type defaults instead of throwing, so assertions can pass while an unexpected production call is silently
  swallowed.
- **Build configuration reviewed, no injected risk.** `pom.xml` declares only `jakarta.servlet-api` 6.0.0
  (`provided`) and `junit-jupiter` 5.10.2 (`test`), plus compiler/surefire/war plugins; `release` 17, no `exec`
  plugins, no repository overrides. **Limitation:** no live CVE/dependency lookup was performed (no
  network-fed `dependency-check`/OSV query run here), so "no vulnerable dependency" means "none identifiable from
  the declarations", not a verified scan result.
- **Deployment surface confirmed.** The built `target/session-cookie-demo/` and the WAR contain no `WEB-INF/web.xml`
  (`failOnMissingWebXml` is `false`), so the two `@WebServlet` annotations are the only mappings. That is what makes
  `SEC-01` and `SEC-02` reachable in the artifact as shipped rather than hypothetical, and it also means the
  servlet-spec `transport-guarantee CONFIDENTIAL` constraint that would enforce TLS is absent — folded into `SEC-08`.
