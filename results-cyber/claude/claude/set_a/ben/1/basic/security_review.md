# Security Review: Jakarta Servlet Session Cookie Issuer (`com.example.auth`)

## 1. Executive Summary

The component is a small Jakarta Servlet 6.0 web application whose only job is
to issue and clear a session cookie. `SessionCookieFactory` builds a
`SESSIONID` cookie (`HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`,
`Max-Age=1800`) and adds it to the response; `LoginServlet` (`POST /login`)
obtains a session identifier and issues the cookie; `LogoutServlet`
(`POST /logout`) re-sends the cookie with `Max-Age=0`. There is no database, no
cryptography beyond `SecureRandom`, no deserialization, no file or OS access,
and no hardcoded secrets.

The cookie-construction code itself is well done: all three protective
attributes are set, and the identifier is validated against the RFC 6265
cookie-octet set, which closes the usual `Set-Cookie`/response-header injection
path (CWE-113). The real weaknesses are in the session *lifecycle* around that
cookie:

- `POST /login` performs no authentication or authorization of any kind and
  still mints and issues a fresh 256-bit session identifier to any anonymous
  caller (`LoginServlet.java:26-38`, `47-53`) — a missing-authentication
  fail-open design (CWE-306).
- `POST /logout` only expires the browser cookie; the comment promising
  server-side invalidation is not backed by any code, so a captured identifier
  survives logout (`LogoutServlet.java:22-23`) (CWE-613).
- The identifier may be taken from an upstream-supplied value and is never
  rotated or proven fresh, so the design permits session fixation
  (`LoginServlet.java:47-53`) (CWE-384).
- Both state-changing endpoints rely solely on `SameSite=Strict` for CSRF
  protection, with no token or `Origin`/`Referer` check (CWE-352).

Lower-severity issues: the session identifier is placed in a *persistent*
cookie (CWE-539), the constructor accepts `secure=false` and `SameSite=None`
without validation (CWE-614 / CWE-1275), and no authentication events are
logged (CWE-778). Nothing in the reviewed code is remotely exploitable for code
execution, and no injection sink exists.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/auth/SessionCookieFactory.java` | Builds the `SESSIONID` cookie and adds/expires it on an `HttpServletResponse`. | Cookie attribute configuration (`HttpOnly`, `Secure`, `SameSite`, `Path`, `Max-Age`); session-identifier character validation (header-injection defence); configurable-insecure constructor; committed-response check. |
| `src/main/java/com/example/auth/LoginServlet.java` | `POST /login` endpoint that issues the session cookie after "assumed successful" authentication. | Unauthenticated state-changing endpoint; session-identifier sourcing from a request attribute; `SecureRandom`-based identifier generation; no CSRF defence; no logging. |
| `src/main/java/com/example/auth/LogoutServlet.java` | `POST /logout` endpoint that expires the session cookie. | Session termination (client-side only); no server-side invalidation; no CSRF defence; no logging. |
| `pom.xml` | Maven WAR build against `jakarta.servlet-api` 6.0.0 (`provided`), Java 17. | Dependency surface (single provided-scope API dependency, no third-party runtime libraries); `failOnMissingWebXml=false` with annotation-driven servlet mapping. |
| `README.md` | Documentation of behaviour, cookie attributes, build and run steps. | Documents the `secure=false` local-testing escape hatch and acknowledges (but does not fix) session fixation and missing server-side session state. |

## 3. Skills Applied

- `review-code-for-security-vulnerabilities`: router skill — drove the
  understand-code / select-skills / apply / report workflow over the five files
  above.
- `performing-security-headers-audit`: applied to the `Set-Cookie` attributes
  produced by `SessionCookieFactory.addSessionCookie`
  (`SessionCookieFactory.java:72-80`) and `clearSessionCookie`
  (`SessionCookieFactory.java:91-97`) — checked `Secure`, `HttpOnly`,
  `SameSite`, `Path`, `Domain`, `Max-Age`/`Expires`, and transport expectations
  (HSTS is out of this code's control but relevant to the `Secure` flag).
- `performing-csrf-attack-simulation`: applied to the two state-changing
  endpoints `POST /login` (`LoginServlet.java:26`) and `POST /logout`
  (`LogoutServlet.java:20`) — checked for anti-CSRF tokens, `Origin`/`Referer`
  validation, and the strength of `SameSite` as the sole control.
- `testing-api-authentication-weaknesses`: applied to the session lifecycle —
  token entropy (`LoginServlet.java:59-63`), missing authentication on
  endpoints (`LoginServlet.java:26-38`), token reuse after logout
  (`LogoutServlet.java:22-23`), and session identifier sourcing
  (`LoginServlet.java:47-53`).
- `bypassing-authentication-with-forced-browsing`: applied to the
  annotation-declared URL patterns `/login` and `/logout`
  (`LoginServlet.java:18`, `LogoutServlet.java:12`) — confirmed both are
  reachable without any declared security constraint (no `web.xml`,
  `failOnMissingWebXml` is `false` in `pom.xml:35`, and no
  `@ServletSecurity`/`@HttpConstraint` annotations are present).
- `testing-for-sensitive-data-exposure`: applied to the handling and storage of
  the session identifier — persistence in a disk-backed cookie
  (`SessionCookieFactory.java:76`), absence of the identifier from response
  bodies (`LoginServlet.java:37`), and absence of hardcoded credentials across
  all files.
- Reviewed against general OWASP Top 10 / CWE knowledge, with no library skill
  matched: response-header / `Set-Cookie` injection via the cookie value
  (CWE-113, `SessionCookieFactory.java:105-118`); insufficient session
  expiration and idle timeout (CWE-613); security logging and monitoring
  failures (OWASP A09:2021, CWE-778); cookie-prefix and scope hardening
  (`__Host-` prefix, `Path`/`Domain` breadth); and error-handling behaviour of
  the unchecked `IllegalArgumentException`/`IllegalStateException` paths
  (CWE-209/CWE-248 — judged non-exploitable here, see section 6).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | `POST /login` issues a valid session cookie to unauthenticated callers (fail-open) | High | CWE-306 | `src/main/java/com/example/auth/LoginServlet.java:26-38` |
| SEC-02 | Logout only clears the browser cookie; the session identifier is never invalidated server-side | Medium | CWE-613 | `src/main/java/com/example/auth/LogoutServlet.java:22-23` |
| SEC-03 | Session identifier accepted from an externally supplied value and never rotated (session fixation) | Medium | CWE-384 | `src/main/java/com/example/auth/LoginServlet.java:47-53` |
| SEC-04 | State-changing `/login` and `/logout` endpoints have no CSRF token or `Origin`/`Referer` validation | Medium | CWE-352 | `src/main/java/com/example/auth/LoginServlet.java:26-33` |
| SEC-05 | Session identifier stored in a persistent cookie with a fixed absolute lifetime and no idle timeout | Low | CWE-539 | `src/main/java/com/example/auth/SessionCookieFactory.java:76` |
| SEC-06 | Constructor accepts `secure=false` and an unvalidated `SameSite` value, allowing a silently insecure cookie | Low | CWE-614 | `src/main/java/com/example/auth/SessionCookieFactory.java:43-50` |
| SEC-07 | No audit logging of session issuance or termination | Low | CWE-778 | `src/main/java/com/example/auth/LoginServlet.java:26-38` |

## 5. Detailed Findings

### SEC-01: `POST /login` issues a valid session cookie to unauthenticated callers (fail-open)

- **Severity:** High
- **CWE:** CWE-306: Missing Authentication for Critical Function
- **Location:** `src/main/java/com/example/auth/LoginServlet.java:26-38` (and `47-53`, `18`)

**Vulnerable code:**
```java
// src/main/java/com/example/auth/LoginServlet.java:25-38
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Authentication is assumed to have happened upstream; the resulting
        // session identifier is what we need here.
        String sessionId = obtainSessionId(request);

        cookieFactory.addSessionCookie(response, sessionId);

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("text/plain; charset=UTF-8");
        response.getWriter().write("Authenticated. Session cookie issued.\n");
    }
```

**Why it is a problem:** The servlet is mapped at `/login`
(`LoginServlet.java:18`) with no `@ServletSecurity` constraint and no `web.xml`
(`pom.xml:35` sets `failOnMissingWebXml=false`), so it is reachable
anonymously. It never verifies that authentication actually happened: it does
not check a credential, a principal (`request.getUserPrincipal()`), or even
that the upstream step set the `authenticatedSessionId` attribute. When that
attribute is absent — which is exactly the state for a direct, unauthenticated
request — `obtainSessionId` *fails open* and mints a fresh identifier
(`LoginServlet.java:52`), and the response then tells the caller
"Authenticated." Any anonymous client gets a well-formed `SESSIONID` cookie.

Whether that cookie grants access depends on the session store the integrator
plugs in, but the failure mode is dangerous in both directions: if the store
trusts identifiers presented by the client, this is an outright authentication
bypass; if it does not, the attacker can still pre-seed a victim's browser with
a chosen identifier (see SEC-03). Worse, a developer reading the "Authenticated.
Session cookie issued." response reasonably concludes the endpoint enforces
authentication when it enforces nothing. Security-relevant code must fail
closed, not substitute a plausible-looking value for a missing precondition.

**Fix:** Require positive evidence of authentication and reject the request
when it is absent, instead of minting a substitute identifier. Also declare a
container-level constraint on the endpoint so it cannot be reached anonymously
even if the code path changes.

```java
// src/main/java/com/example/auth/LoginServlet.java
@WebServlet(urlPatterns = "/login")
@ServletSecurity(@HttpConstraint(rolesAllowed = {"USER"}))
public class LoginServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private final SessionCookieFactory cookieFactory = new SessionCookieFactory();

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Fail closed: only an authenticated request may be issued a session cookie.
        if (request.getUserPrincipal() == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        // The session store mints the identifier; it is never taken from the client.
        String sessionId = sessionStore.createSession(request.getUserPrincipal().getName());

        cookieFactory.addSessionCookie(response, sessionId);

        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }
}
```

### SEC-02: Logout only clears the browser cookie; the session identifier is never invalidated server-side

- **Severity:** Medium
- **CWE:** CWE-613: Insufficient Session Expiration
- **Location:** `src/main/java/com/example/auth/LogoutServlet.java:22-23`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/LogoutServlet.java:19-28
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // Invalidate the server-side session state first, then clear the cookie.
        cookieFactory.clearSessionCookie(response);

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("text/plain; charset=UTF-8");
        response.getWriter().write("Logged out.\n");
    }
```

**Why it is a problem:** The comment on line 22 states that server-side session
state is invalidated first, but no such call exists — `clearSessionCookie` only
emits `Set-Cookie: SESSIONID=; Max-Age=0`, a purely client-side instruction.
Logout therefore removes the cookie from the cooperating browser and nothing
else. An attacker who already captured the identifier (shared machine, proxy
log, prior XSS, backup of the cookie jar) keeps a fully valid session after the
user "logs out" and can continue to replay it until the 30-minute
`Max-Age`-independent server-side expiry — which also does not exist here. The
misleading comment makes the gap likely to survive code review: a reader sees
the stated invariant and not the missing code. `request.getSession()` is never
touched either, so any container-managed session created by a filter or JSP
also survives logout.

**Fix:** Invalidate the server-side record for the presented identifier (and
the container session) before clearing the cookie, so the token is dead
regardless of who holds a copy.

```java
// src/main/java/com/example/auth/LogoutServlet.java
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Invalidate server-side state FIRST so a captured identifier is dead
        // even if the browser never receives or honours the cookie deletion.
        String presented = readSessionCookie(request, cookieFactory.getCookieName());
        if (presented != null) {
            sessionStore.invalidate(presented);
        }
        HttpSession containerSession = request.getSession(false);
        if (containerSession != null) {
            containerSession.invalidate();
        }

        cookieFactory.clearSessionCookie(response);
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    private static String readSessionCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie c : cookies) {
            if (name.equals(c.getName()) && !c.getValue().isEmpty()) {
                return c.getValue();
            }
        }
        return null;
    }
```

### SEC-03: Session identifier accepted from an externally supplied value and never rotated (session fixation)

- **Severity:** Medium
- **CWE:** CWE-384: Session Fixation
- **Location:** `src/main/java/com/example/auth/LoginServlet.java:47-53`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/LoginServlet.java:47-53
    protected String obtainSessionId(HttpServletRequest request) {
        Object provided = request.getAttribute("authenticatedSessionId");
        if (provided instanceof String && !((String) provided).isEmpty()) {
            return (String) provided;
        }
        return newSessionId();
    }
```

**Why it is a problem:** The identifier that will authenticate every later
request is whatever value happens to sit in the `authenticatedSessionId`
request attribute, used verbatim with no check that it is fresh, that it was
generated server-side, or that it is not already bound to a different (possibly
anonymous, pre-login) session. Request attributes are server-set rather than
client-set, so this is not directly client-controlled — but any upstream filter
or `RequestDispatcher.forward` that populates the attribute from a parameter,
header, or the inbound cookie (a very common "carry the existing session
forward" pattern) turns this into textbook session fixation: the attacker plants
an identifier in the victim's browser, the victim authenticates, the same
identifier is re-issued, and the attacker's copy is now an authenticated
session. The `README.md:106-107` production notes acknowledge exactly this risk
but the code does not implement the mitigation, and because `obtainSessionId` is
`protected` it is explicitly designed to be overridden by integrators who may
feed it a client-derived value. Privilege transitions must always be
accompanied by a new identifier.

**Fix:** Always mint a new identifier at the authentication boundary. Accept an
externally supplied identifier only from a trusted session store that itself
guarantees freshness, and reject anything that was already presented by the
client.

```java
// src/main/java/com/example/auth/LoginServlet.java
    /**
     * Returns a freshly minted identifier for the newly authenticated session.
     * The identifier is never carried over from the request: rotating it at the
     * privilege transition is what prevents session fixation.
     */
    private String newAuthenticatedSessionId(HttpServletRequest request) {
        // Drop any pre-login session so its identifier can never be reused.
        HttpSession existing = request.getSession(false);
        if (existing != null) {
            existing.invalidate();
        }
        return sessionStore.createSession(request.getUserPrincipal().getName());
    }

    /** Generates a 256-bit identifier from a cryptographically secure source. */
    public static String newSessionId() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
```

### SEC-04: State-changing `/login` and `/logout` endpoints have no CSRF token or `Origin`/`Referer` validation

- **Severity:** Medium
- **CWE:** CWE-352: Cross-Site Request Forgery (CSRF)
- **Location:** `src/main/java/com/example/auth/LoginServlet.java:26-33`, `src/main/java/com/example/auth/LogoutServlet.java:20-23`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/LoginServlet.java:26-33
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Authentication is assumed to have happened upstream; the resulting
        // session identifier is what we need here.
        String sessionId = obtainSessionId(request);

        cookieFactory.addSessionCookie(response, sessionId);
```

**Why it is a problem:** Both endpoints change state — one installs a session
cookie, the other destroys the session — and neither validates an anti-CSRF
token, nor the `Origin` or `Referer` header, nor a custom header such as
`X-Requested-With`. The only control is `SameSite=Strict` on the cookie
(`SessionCookieFactory.java:78`), which is incomplete as a sole defence: it
protects requests that *depend on the existing cookie being sent*, but
`POST /login` does not — a cross-site form post reaches it with no cookie
needed and returns a `Set-Cookie` that the browser stores, which is the
login-CSRF / cookie-forcing primitive behind SEC-03. `SameSite` is also a
browser-side attribute, so non-browser clients, older browsers, and any future
relaxation of the attribute to `Lax`/`None` (permitted by the constructor, see
SEC-06) silently remove the protection. The `README.md` makes the stronger claim
that `SameSite=Strict` "blocks CSRF against the authenticated session", which
overstates the guarantee.

**Fix:** Validate the request origin server-side on every state-changing
endpoint and require a synchronizer token, keeping `SameSite=Strict` as
defence-in-depth rather than the only layer.

```java
// src/main/java/com/example/auth/LoginServlet.java
    private static final Set<String> ALLOWED_ORIGINS =
            Set.of("https://app.example.com");

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        if (!originAllowed(request) || !csrfTokenValid(request)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        // ... issue the cookie only after the request is proven same-site ...
    }

    private static boolean originAllowed(HttpServletRequest request) {
        String origin = request.getHeader("Origin");
        if (origin != null) {
            return ALLOWED_ORIGINS.contains(origin);
        }
        String referer = request.getHeader("Referer");
        // No Origin and no Referer: reject rather than assume same-site.
        return referer != null
                && ALLOWED_ORIGINS.stream().anyMatch(o -> referer.startsWith(o + "/"));
    }
```

### SEC-05: Session identifier stored in a persistent cookie with a fixed absolute lifetime and no idle timeout

- **Severity:** Low
- **CWE:** CWE-539: Use of Persistent Cookies Containing Sensitive Information
- **Location:** `src/main/java/com/example/auth/SessionCookieFactory.java:76` (default from `21`, `31`)

**Vulnerable code:**
```java
// src/main/java/com/example/auth/SessionCookieFactory.java:76
        cookie.setMaxAge(maxAgeSeconds);
```

**Why it is a problem:** `DEFAULT_MAX_AGE_SECONDS` is `30 * 60`
(`SessionCookieFactory.java:21`) and the default constructor applies it
(`SessionCookieFactory.java:31`), so the default `Set-Cookie` carries
`Max-Age=1800` and the browser writes the session identifier to its on-disk
cookie store rather than keeping it in memory for the tab's lifetime. The
credential then outlives the browser process and is recoverable from the
profile directory or a machine backup by anyone with filesystem access —
exactly the exposure a session cookie should avoid. The lifetime is also purely
absolute and purely client-side: there is no server-side idle timeout, no
re-issue on activity, and (per SEC-02) no server-side expiry at all, so a
captured identifier is bounded only by whatever the integrator later builds.

**Fix:** Make the browser cookie a non-persistent session cookie
(`setMaxAge(-1)`), and enforce both an idle and an absolute timeout
server-side, where the attacker cannot influence it.

```java
// src/main/java/com/example/auth/SessionCookieFactory.java
    /**
     * Default lifetime: -1, a non-persistent cookie that is held in memory only
     * and discarded when the browser closes. Session expiry is enforced
     * server-side by the session store, not by this attribute.
     */
    public static final int DEFAULT_MAX_AGE_SECONDS = -1;

    /** Creates a factory with the recommended defaults. */
    public SessionCookieFactory() {
        this(COOKIE_NAME, DEFAULT_MAX_AGE_SECONDS, "/", true, "Strict");
    }
```

### SEC-06: Constructor accepts `secure=false` and an unvalidated `SameSite` value, allowing a silently insecure cookie

- **Severity:** Low
- **CWE:** CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute (also CWE-1275: Sensitive Cookie with Improper SameSite Attribute)
- **Location:** `src/main/java/com/example/auth/SessionCookieFactory.java:43-50` (effect at `74`, `78`)

**Vulnerable code:**
```java
// src/main/java/com/example/auth/SessionCookieFactory.java:43-50
    public SessionCookieFactory(String cookieName, int maxAgeSeconds, String path,
                                boolean secure, String sameSite) {
        this.cookieName = requireNonBlank(cookieName, "cookieName");
        this.maxAgeSeconds = maxAgeSeconds;
        this.path = requireNonBlank(path, "path");
        this.secure = secure;
        this.sameSite = requireNonBlank(sameSite, "sameSite");
    }
```

**Why it is a problem:** The defaults are correct, but the configuration
surface lets the single most important protections be switched off with no
guard rail and no runtime signal. `secure=false` (documented as a local-testing
convenience in `README.md:100-102`) produces a session cookie that the browser
will transmit over plaintext HTTP, where it can be sniffed or stripped — the
classic mistake is that this setting reaches production. `sameSite` is only
checked for blankness by `requireNonBlank`
(`SessionCookieFactory.java:120-125`), so `"None"` is accepted (removing the
sole CSRF control of SEC-04) and so is a typo such as `"Stict"`, which the
browser discards as an unknown attribute value — silently degrading to the
default. A single misconfiguration therefore removes a protection with no error.

**Fix:** Validate the `SameSite` value against the three legal tokens, refuse
the illegal `SameSite=None` without `Secure` combination outright, and make a
non-secure cookie an explicit, loudly named development-only choice rather than
an ordinary constructor argument.

```java
// src/main/java/com/example/auth/SessionCookieFactory.java
    private static final Set<String> VALID_SAME_SITE = Set.of("Strict", "Lax", "None");

    public SessionCookieFactory(String cookieName, int maxAgeSeconds, String path,
                                boolean secure, String sameSite) {
        this.cookieName = requireNonBlank(cookieName, "cookieName");
        this.maxAgeSeconds = maxAgeSeconds;
        this.path = requireNonBlank(path, "path");
        this.sameSite = requireNonBlank(sameSite, "sameSite");
        if (!VALID_SAME_SITE.contains(this.sameSite)) {
            throw new IllegalArgumentException(
                    "sameSite must be one of Strict, Lax or None");
        }
        if ("None".equals(this.sameSite) && !secure) {
            throw new IllegalArgumentException("SameSite=None requires Secure");
        }
        if (!secure && !Boolean.getBoolean("com.example.auth.allowInsecureCookie")) {
            throw new IllegalArgumentException("a session cookie must be Secure; "
                    + "set -Dcom.example.auth.allowInsecureCookie=true for local "
                    + "plain-HTTP testing only");
        }
        this.secure = secure;
    }
```

### SEC-07: No audit logging of session issuance or termination

- **Severity:** Low
- **CWE:** CWE-778: Insufficient Logging
- **Location:** `src/main/java/com/example/auth/LoginServlet.java:26-38`, `src/main/java/com/example/auth/LogoutServlet.java:20-28`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/LoginServlet.java:31-37
        String sessionId = obtainSessionId(request);

        cookieFactory.addSessionCookie(response, sessionId);

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("text/plain; charset=UTF-8");
        response.getWriter().write("Authenticated. Session cookie issued.\n");
```

**Why it is a problem:** Session issuance and termination are the security
events most needed for detecting credential abuse, yet neither servlet emits
any log record — not even for the rejection paths, where
`addSessionCookie` throws `IllegalArgumentException` on a malformed identifier
(`SessionCookieFactory.java:105-118`). An uncaught exception there surfaces
only as a container-level 500, so bursts of invalid identifiers — the signature
of someone probing the cookie-value validator or of a broken upstream — produce
no attributable signal. Combined with SEC-01, an attacker harvesting session
cookies from the unauthenticated `/login` endpoint leaves no application-level
trace at all (OWASP A09:2021).

**Fix:** Log issuance, termination, and rejection with the subject and request
metadata, never the identifier itself (logging the identifier would turn the log
into a credential store).

```java
// src/main/java/com/example/auth/LoginServlet.java
    private static final Logger LOG = System.getLogger(LoginServlet.class.getName());

    // ... inside doPost, after the authentication check ...
    try {
        cookieFactory.addSessionCookie(response, sessionId);
        // Log the subject and context, never the session identifier itself.
        LOG.log(Logger.Level.INFO, "session issued for subject={0} from ip={1}",
                request.getUserPrincipal().getName(), request.getRemoteAddr());
    } catch (IllegalArgumentException e) {
        LOG.log(Logger.Level.WARNING, "rejected malformed session identifier from ip={0}",
                request.getRemoteAddr());
        response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        return;
    }
```

## 6. Verified Controls and Checks With No Finding

- **`Set-Cookie` / response-header injection (CWE-113, CWE-93)**: `validateSessionId`
  (`SessionCookieFactory.java:105-118`) rejects null/empty identifiers and
  permits only US-ASCII `0x21`–`0x7E` minus `"`, `,`, `;` and `\` — the RFC 6265
  cookie-octet set. CR (`0x0D`), LF (`0x0A`), NUL, space and all other control
  characters fall outside the allowed range, so an identifier cannot inject
  extra cookie attributes (`; Domain=`, `; SameSite=None`) or split the response
  into additional headers. Validation runs before the `Cookie` object is
  constructed (`SessionCookieFactory.java:66` precedes `72`). This is the one
  input-handling control in the code and it is implemented correctly.
- **`HttpOnly` on both cookies**: set unconditionally and not configurable —
  `SessionCookieFactory.java:73` (issue) and `:92` (clear) — so an XSS flaw
  elsewhere cannot read the identifier via `document.cookie`.
- **`Secure` by default**: the no-arg constructor passes `true`
  (`SessionCookieFactory.java:31`), applied at `SessionCookieFactory.java:74`
  and `:93`; both servlets use that constructor (`LoginServlet.java:23`,
  `LogoutServlet.java:17`), so the shipped configuration is HTTPS-only. The
  configurability of this flag is reported separately as SEC-06.
- **`SameSite=Strict` by default**: `SessionCookieFactory.java:31` and `:78`,
  via the Servlet 6 `Cookie.setAttribute` API; the required API version is
  correctly pinned in `pom.xml:21`. Reported as insufficient *on its own* under
  SEC-04, but present and correctly spelled by default.
- **Session identifier entropy (CWE-330, CWE-331, CWE-338)**: `newSessionId`
  (`LoginServlet.java:59-63`) draws 32 bytes (256 bits) from `SecureRandom` —
  a CSPRNG, not `java.util.Random`/`Math.random` — and encodes them with the
  URL-safe Base64 alphabet, which is a subset of the allowed cookie-octets. No
  timestamp, counter, username or other predictable material is mixed in, and
  the value is not truncated. Entropy and generation are sound.
- **No identifier leakage into URLs, bodies or logs**: the login response writes
  only a fixed string (`LoginServlet.java:37`) and the logout response likewise
  (`LogoutServlet.java:27`); the identifier is never placed in a query string,
  redirect `Location`, or log statement anywhere in the three source files.
- **Cookie deletion correctness**: `clearSessionCookie`
  (`SessionCookieFactory.java:91-97`) re-sends the same name, `Path` and
  `Secure`/`SameSite` attributes with `Max-Age=0`, which is required for the
  browser to match and evict the original cookie. The client-side mechanics are
  right; what is missing is the server-side half, reported as SEC-02.
- **Committed-response check**: `SessionCookieFactory.java:67-70` throws
  `IllegalStateException` rather than silently dropping the `Set-Cookie` header
  when the response is already committed, so a session can never appear to be
  established when the cookie was in fact never sent.
- **Cookie scope**: `Path=/` (`SessionCookieFactory.java:31`, `:75`) is
  appropriate for an application-wide session, and no `Domain` attribute is set,
  so the cookie stays host-only and is not shared with sibling subdomains —
  the correct choice. (A `__Host-` name prefix would harden this further but its
  absence is not a vulnerability.)
- **No hardcoded secrets (CWE-798)**: grepped all five files; the only constants
  are the cookie name `"SESSIONID"`, the `1800`-second lifetime, `"/"` and
  `"Strict"` (`SessionCookieFactory.java:18-21`, `:31`). No keys, passwords,
  tokens or connection strings.
- **No cryptographic misuse**: the code performs no hashing, encryption,
  signing or JWT handling — the session identifier is an opaque random value, so
  there is no cipher mode, key, IV, salt or algorithm choice to get wrong. The
  `performing-cryptographic-audit-of-application` and JWT skills were considered
  and found not applicable for this reason.
- **No injection sinks**: no SQL or other database query construction, no OS
  command execution (`Runtime.exec`/`ProcessBuilder`), no file or path handling,
  no XML/XSLT parsing, no deserialization (`readObject`/`ObjectInputStream`), no
  reflection on request-controlled names, no outbound HTTP requests, and no
  template or HTML rendering. CWE-89, CWE-78, CWE-22, CWE-611, CWE-502, CWE-918
  and CWE-79 have no reachable sink in this codebase. The only response bodies
  are fixed `text/plain` strings with an explicit `charset=UTF-8`
  (`LoginServlet.java:36`, `LogoutServlet.java:26`), so there is no reflected
  output to escape.
- **Error handling / information disclosure (CWE-209)**: the exception messages
  thrown by `SessionCookieFactory` (`:64`, `:69`, `:107`, `:115`, `:122`)
  disclose only the offending field name and a character index — no identifier
  value, no internal path or stack-derived detail — so even the default
  container error page would not leak session material. The unchecked
  exceptions do mean a malformed identifier surfaces as a 500 rather than a
  handled error; that is a robustness and logging gap rather than a disclosure
  one, and the logging aspect is reported as SEC-07.
- **Immutability / thread safety of the shared factory**: all five
  `SessionCookieFactory` fields are `final` and only `String`/primitive
  (`SessionCookieFactory.java:23-27`), and `validateSessionId` holds no state,
  so the single instance shared across concurrent requests by each servlet
  (`LoginServlet.java:23`, `LogoutServlet.java:17`) cannot be mutated or raced
  into issuing another request's identifier — the usual servlet
  shared-mutable-state flaw (CWE-362, CWE-567) is absent.
- **Dependency surface (CWE-1104, CWE-1395)**: `pom.xml:17-24` declares exactly
  one dependency, `jakarta.servlet-api:6.0.0`, at `provided` scope, so no
  third-party code is bundled into the WAR and there is no transitive
  vulnerable-component exposure. The build targets Java 17 (`pom.xml:13`), a
  supported LTS release.
- **Endpoint inventory**: the only declared routes are `POST /login`
  (`LoginServlet.java:18`) and `POST /logout` (`LogoutServlet.java:12`); no
  `doGet`, `doPut`, `doDelete` or `service` override exists, so the state
  changes cannot be triggered by a simple GET navigation (which would bypass
  `SameSite=Lax` were it configured). No debug, admin or status endpoint is
  exposed.
