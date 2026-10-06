# Security Review: Session Cookie Handoff Component (`com.example.security.session`)

## 1. Executive Summary

The component is a small Jakarta Servlet 6.1 module that takes an already-created server-side
session identifier from a trusted upstream authentication component (passed as a request
attribute), re-authorizes it against an authoritative store, and returns it to the browser in a
`__Host-session` cookie. It consists of a POST-only servlet (`SessionCookieEndpoint`), a cookie/
validation policy holder (`SessionCookiePolicy`), and a one-method store contract
(`SessionHandoffStore`).

The core cookie-issuance logic is unusually well hardened: the identifier is never read from a
client-controlled parameter, header, URL or cookie; it is strictly allowlisted (43 base64url
characters) before use, which also closes CRLF response-splitting; the cookie carries `Secure`,
`HttpOnly`, `SameSite=Strict`, `Path=/`, no `Domain`, and the `__Host-` prefix; the response is
`no-store`; failures are generic, identical, and fail closed (including `null` and exception
returns from the store); and every local prerequisite is folded into the single atomic
`authorizeAndConsume` call so an ineligible request cannot burn a valid one-time handoff. No
secrets, no cryptography, no SQL, no deserialization, no file or command execution are present.

The findings that remain are around the edges of that core:

- **SEC-01 (Medium)** – the state-changing POST has no CSRF/Origin/Referer or custom-header check.
  A cross-site form POST reaches `doPost`, takes the failure path, and emits a `__Host-session`
  deletion cookie with `Path=/`, logging the victim out (session denial of service). `SameSite=Strict`
  protects the cookie being *sent*, not the cookie being *overwritten*.
- **SEC-02 (Medium)** – the rate-limit key is the raw `getRemoteAddr()`. Behind the TLS-terminating
  reverse proxy the design mandates, every user shares one key, so one attacker's attempts can
  throttle all legitimate handoffs; the component itself enforces no attempt limit at all.
- **SEC-03/04/05 (Low)** – inherited `HttpServlet.doTrace` reflects request headers, security
  decisions are not logged at all (no detection signal for handoff abuse), and the cookie-issuing
  response omits `Strict-Transport-Security`.

No Critical or High issues were found in the code as written; the largest residual risks are
structural (the externally supplied identifier and the unenforceable store contract) and are
documented by the author in `README.md`.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/security/session/SessionCookieEndpoint.java` | POST-only servlet performing the session-cookie handoff | Reads the candidate identifier from a request attribute; validates it and the remote address; requires `isSecure()`; calls the store's atomic authorize-and-consume; issues the session cookie or a generic 401 plus a deletion cookie; sets anti-cache headers; logging; exception handling |
| `src/main/java/com/example/security/session/SessionCookiePolicy.java` | Validation allowlists and cookie construction | Session-id charset/length allowlist, remote-address allowlist, dummy constants, `__Host-` cookie with `Secure`/`HttpOnly`/`SameSite=Strict`/`Path=/`, browser-session vs deletion cookie |
| `src/main/java/com/example/security/session/SessionHandoffStore.java` | Trust boundary to the authoritative session store | Declares (but cannot enforce) atomic rate limiting, session validation, one-time consume, and the `AUTHORIZE`/`DENY` decision |
| `pom.xml`, `.mvn/maven.config` | Build configuration | Pinned dependency and plugin versions, `provided` servlet API, `--strict-checksums` for artifact integrity |
| `src/test/java/.../SessionCookieEndpointTest.java`, `SessionCookiePolicyTest.java` | Unit tests | Assert fail-closed behaviour, dummy-work path, and cookie attributes; no credentials or network access |
| `README.md` | Design and security rationale | Documents deployment requirements (TLS termination, store contract) that the code depends on |

## 3. Skills Applied

- `review-code-for-security-vulnerabilities`: router skill; drove the file-by-file behaviour
  inventory (session cookie issuance, input validation, authorization delegation, logging, failure
  handling) and the keyword set used to select the skills below.
- `performing-csrf-attack-simulation`: applied to `SessionCookieEndpoint.doPost` as a
  state-changing POST — checked for anti-CSRF tokens, `Origin`/`Referer` validation, custom-header
  requirements, and the limits of `SameSite=Strict`. Produced SEC-01.
- `performing-security-headers-audit`: applied to `addNonCacheableHeaders` and
  `SessionCookiePolicy.baseCookie` — verified `Secure`/`HttpOnly`/`SameSite`/`__Host-` prefix rules
  and cache headers, and checked for HSTS. Produced SEC-05.
- `testing-api-authentication-weaknesses`: applied to the identifier handling and the
  `SessionHandoffStore` boundary — token source, token entropy assumptions, token leakage into URLs
  and logs, session-fixation and fail-open behaviour. Fed SEC-02 and the controls in section 6.
- `implementing-api-rate-limiting-and-throttling`: applied to the per-source / per-account limiting
  delegated via `authorizeAndConsume` — checked keying strategy, bucket sharing, and bypass.
  Produced SEC-02.
- `testing-for-sensitive-data-exposure`: applied to the response bodies, headers, and log statements
  in `SessionCookieEndpoint` — verified the session identifier never reaches logs, error messages,
  URLs, or disk. Produced SEC-03 (header reflection) and the no-finding controls.
- Reviewed against general OWASP Top 10 / CWE knowledge, because no library skill matched: HTTP
  response splitting / header injection via the cookie value (CWE-113); unoverridden
  `HttpServlet.doTrace` and HTTP method handling (CWE-200, produced SEC-03); security-decision
  logging adequacy (CWE-778, produced SEC-04); exception-path fail-closed behaviour (CWE-636);
  check-then-act / TOCTOU around the one-time consume (CWE-367); build and dependency integrity in
  `pom.xml` / `.mvn/maven.config` (CWE-1104, CWE-494).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | State-changing handoff POST has no CSRF/origin check; failure path deletes the victim's session cookie cross-site | Medium | CWE-352 | `src/main/java/com/example/security/session/SessionCookieEndpoint.java:36-85` (cookie emitted at `:83`) |
| SEC-02 | Rate-limit key is the raw `getRemoteAddr()` and is shared behind the mandated reverse proxy; no attempt limiting in this component | Medium | CWE-770 | `src/main/java/com/example/security/session/SessionCookieEndpoint.java:51-66` |
| SEC-03 | Inherited `HttpServlet.doTrace` reflects request headers (including `Cookie`) in the response | Low | CWE-200 | `src/main/java/com/example/security/session/SessionCookieEndpoint.java:18` |
| SEC-04 | Security decisions are not logged; the store-failure log line carries no identifying context | Low | CWE-778 | `src/main/java/com/example/security/session/SessionCookieEndpoint.java:70-84` |
| SEC-05 | Cookie-issuing response omits `Strict-Transport-Security` | Low | CWE-319 | `src/main/java/com/example/security/session/SessionCookieEndpoint.java:87-91` |

## 5. Detailed Findings

### SEC-01: State-changing handoff POST has no CSRF/origin check; failure path deletes the victim's session cookie cross-site

- **Severity:** Medium
- **CWE:** CWE-352: Cross-Site Request Forgery (CSRF)
- **Location:** `src/main/java/com/example/security/session/SessionCookieEndpoint.java:36-85` (specifically `:83`)

**Vulnerable code:**
```java
// src/main/java/com/example/security/session/SessionCookieEndpoint.java:36-61
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(response, "response");

        // This endpoint owns an uncommitted response. Reset prevents an upstream stale Set-Cookie.
        if (response.isCommitted()) {
            logger.log(System.Logger.Level.ERROR, "session handoff called after response commit");
            return; // the container can no longer produce a safe generic response
        }
        response.reset();
        addNonCacheableHeaders(response);

        Object supplied = request.getAttribute(SessionCookiePolicy.REQUEST_ATTRIBUTE);
        String candidate = supplied instanceof String string ? string : null;
        String remoteAddress = request.getRemoteAddr();
```
```java
// src/main/java/com/example/security/session/SessionCookieEndpoint.java:82-84
        // Remove any pre-existing session to prevent a failed login from retaining another user.
        response.addCookie(SessionCookiePolicy.deletionCookie());
        writeGenericFailure(response);
```

**Why it is a problem:** `doPost` is a state-changing request (it consumes a one-time handoff in the
store and it writes a `Set-Cookie` for `__Host-session` with `Path=/`), yet it performs no
anti-CSRF verification: there is no CSRF token, no `Origin`/`Referer`/`Sec-Fetch-Site` check, and no
required custom header such as `X-Requested-With`. A plain cross-site HTML form POST
(`enctype=text/plain` or `application/x-www-form-urlencoded`) is a "simple request", needs no CORS
preflight, and reaches this method from any attacker-controlled page while the victim is browsing.

With no upstream attribute set, `locallyEligible` is false, so execution reaches line 83 and the
response contains `Set-Cookie: __Host-session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict`.
A `Set-Cookie` in a response is applied by the browser regardless of the `SameSite` attribute —
`SameSite=Strict` governs whether a cookie is *sent* on a cross-site request, not whether a
cross-site response may *overwrite* it. The result is a reliable cross-site forced logout of the
victim's live session (session denial of service), repeatable in a hidden iframe, which also wipes
any CSRF-protection state bound to that session. If the endpoint is instead reachable in a context
where the upstream filter does populate the attribute for an in-flight authenticated request, the
same cross-site POST burns the one-time handoff eligibility, denying the legitimate handoff. The
`README` claims login CSRF and cookie tossing were reviewed, but no code enforces an origin check.

**Fix:** Require an unguessable, per-session CSRF token (or, minimally, strict same-origin
validation of `Sec-Fetch-Site`/`Origin`) before the method does anything that affects state, and in
particular before emitting any cookie. Fail closed with the same generic response when the check
fails, and do not emit the deletion cookie on requests that were not proven same-origin. Compare the
token with a constant-time comparison. Because this is an internal handoff endpoint, also restrict
it at the deployment boundary (internal listener / `<security-constraint>`) so it is not reachable
from the public internet at all.

```java
// src/main/java/com/example/security/session/SessionCookieEndpoint.java
    private static final String SAME_ORIGIN_HEADER = "Sec-Fetch-Site";

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(response, "response");

        if (response.isCommitted()) {
            logger.log(System.Logger.Level.ERROR, "session handoff called after response commit");
            return;
        }
        response.reset();
        addNonCacheableHeaders(response);

        // Reject anything that is not provably a same-origin request from this application
        // before touching cookies or the store. Unknown/absent values are rejected, not defaulted.
        if (!isSameOriginRequest(request)) {
            writeGenericFailure(response); // no Set-Cookie at all on a cross-site attempt
            return;
        }
        // ... unchanged handoff logic ...
    }

    private static boolean isSameOriginRequest(HttpServletRequest request) {
        // Fetch metadata: browsers that support it label the request's initiator.
        String fetchSite = request.getHeader(SAME_ORIGIN_HEADER);
        if (fetchSite != null) {
            return "same-origin".equals(fetchSite) || "none".equals(fetchSite);
        }
        // Fallback for clients without fetch metadata: Origin must match this host exactly.
        String origin = request.getHeader("Origin");
        if (origin == null) {
            return false; // fail closed; no permissive default
        }
        String expected = request.getScheme() + "://" + request.getServerName()
                + (isDefaultPort(request) ? "" : ":" + request.getServerPort());
        return origin.equals(expected);
    }

    private static boolean isDefaultPort(HttpServletRequest request) {
        int port = request.getServerPort();
        return ("https".equals(request.getScheme()) && port == 443)
                || ("http".equals(request.getScheme()) && port == 80);
    }
```

### SEC-02: Rate-limit key is the raw `getRemoteAddr()` and is shared behind the mandated reverse proxy; no attempt limiting in this component

- **Severity:** Medium
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling (related: CWE-307,
  Improper Restriction of Excessive Authentication Attempts)
- **Location:** `src/main/java/com/example/security/session/SessionCookieEndpoint.java:51-66`

**Vulnerable code:**
```java
// src/main/java/com/example/security/session/SessionCookieEndpoint.java:51-66
        String remoteAddress = request.getRemoteAddr();

        boolean validCandidate = SessionCookiePolicy.isValidSessionId(candidate);
        boolean validSource = SessionCookiePolicy.isValidSourceKey(remoteAddress);
        boolean secureTransport = request.isSecure();

        // Include every local prerequisite in the flag passed to the atomic consume operation.
        // Otherwise an HTTP request could burn a valid one-time handoff and then be denied here.
        boolean locallyEligible = validCandidate && validSource && secureTransport;
        String lookupId = locallyEligible ? candidate : SessionCookiePolicy.DUMMY_SESSION_ID;
        String sourceKey = validSource ? remoteAddress : SessionCookiePolicy.DUMMY_SOURCE_KEY;

        try {
            SessionHandoffStore.Decision returned =
                    store.authorizeAndConsume(lookupId, locallyEligible, sourceKey);
```

**Why it is a problem:** The only throttling in this design is the per-source bucket keyed by
`sourceKey`, and `sourceKey` is `request.getRemoteAddr()`. The component's own deployment
requirement is that TLS is terminated by a proxy so `isSecure()` is trustworthy, and the design
deliberately ignores `Forwarded` / `X-Forwarded-*` (`README.md:12-13`). Under that mandated
topology `getRemoteAddr()` is the *proxy's* address for every request, so all users collapse into a
single rate-limit bucket: one attacker hammering this endpoint exhausts the shared source budget and
every legitimate user's handoff is throttled — exactly the "attacker uses your own limit to lock out
legitimate users" failure mode. The same effect is reachable deliberately by sending malformed
input, since every invalid attempt still calls the store and still consumes bucket budget
(line 61 maps *all* invalid sources onto the single `DUMMY_SOURCE_KEY` bucket, a second shared
choke point). Independently, this class enforces no limit of its own: if the injected
`SessionHandoffStore` implementation omits or mis-implements rate limiting — the interface is a
`@FunctionalInterface`, so any lambda satisfies it — there is no throttling anywhere in the request
path and the omission is silent.

**Fix:** Derive the throttling key from a trustworthy client identity rather than the raw peer
address: accept a forwarded address only when the peer is in an explicitly configured list of
trusted proxies, and otherwise use the peer address. Keep per-source and per-account limits in the
atomic store call, but also make the key space explicit so a shared-proxy deployment cannot be
collapsed into one bucket, and add a local defence-in-depth limiter so a non-conforming store
cannot leave the endpoint completely unthrottled.

```java
// src/main/java/com/example/security/session/SessionCookieEndpoint.java
    // Injected from configuration; empty means "no proxy is trusted".
    private final Set<String> trustedProxies;

    private String throttlingKey(HttpServletRequest request) {
        String peer = request.getRemoteAddr();
        if (!SessionCookiePolicy.isValidSourceKey(peer)) {
            return SessionCookiePolicy.DUMMY_SOURCE_KEY;
        }
        if (!trustedProxies.contains(peer)) {
            return peer; // direct client: peer address is authoritative
        }
        // Peer is a configured, trusted terminator: take the single client address it asserts,
        // and validate it with the same allowlist before using it as a key.
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null) {
            String client = forwarded.split(",", 2)[0].trim();
            if (SessionCookiePolicy.isValidSourceKey(client)) {
                return client;
            }
        }
        return SessionCookiePolicy.DUMMY_SOURCE_KEY; // unknown input is rejected, not defaulted
    }
```

### SEC-03: Inherited `HttpServlet.doTrace` reflects request headers (including `Cookie`) in the response

- **Severity:** Low
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **Location:** `src/main/java/com/example/security/session/SessionCookieEndpoint.java:18`

**Vulnerable code:**
```java
// src/main/java/com/example/security/session/SessionCookieEndpoint.java:18-19
public final class SessionCookieEndpoint extends HttpServlet {
    private static final long serialVersionUID = 1L;
```

**Why it is a problem:** The class overrides only `doPost`. `HttpServlet`'s default `doTrace`
implementation echoes the full request line and every request header back to the client as a
`message/http` body. On a session-cookie endpoint that reflected body includes the victim's
`Cookie: __Host-session=...` header, defeating the `HttpOnly` protection that
`SessionCookiePolicy.baseCookie` carefully sets if any request-forwarding primitive
(an XSS-driven plugin, a vulnerable intermediary, or a misconfigured proxy that forwards TRACE)
can reach the endpoint with the victim's cookies attached. The endpoint also advertises itself
through the default `doOptions`. Many containers reject TRACE at the connector by default
(Tomcat's `allowTrace=false`), which is why this is Low rather than higher — but the servlet should
not rely on an external default it does not control, and the `README`'s "POST-only endpoint" claim
is not actually enforced in code.

**Fix:** Override `doTrace` (and, for a strictly POST-only endpoint, `doOptions`) so that every
method other than POST returns the same generic `405`/`401` without reflecting any request data.

```java
// src/main/java/com/example/security/session/SessionCookieEndpoint.java
    @Override
    protected void doTrace(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        // Never reflect request headers: they carry the session cookie.
        rejectMethod(response);
    }

    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        rejectMethod(response);
    }

    private static void rejectMethod(HttpServletResponse response) throws IOException {
        if (response.isCommitted()) {
            return;
        }
        response.reset();
        addNonCacheableHeaders(response);
        response.setHeader("Allow", "POST");
        response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        response.setContentLength(0);
    }
```

### SEC-04: Security decisions are not logged; the store-failure log line carries no identifying context

- **Severity:** Low
- **CWE:** CWE-778: Insufficient Logging
- **Location:** `src/main/java/com/example/security/session/SessionCookieEndpoint.java:70-84`

**Vulnerable code:**
```java
// src/main/java/com/example/security/session/SessionCookieEndpoint.java:70-84
        } catch (RuntimeException failure) {
            // Exception messages may contain secrets supplied by a backing store; never log them.
            logger.log(System.Logger.Level.ERROR, "session handoff store failure");
        }

        if (locallyEligible
                && decision == SessionHandoffStore.Decision.AUTHORIZE) {
            response.addCookie(SessionCookiePolicy.sessionCookie(candidate));
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            return;
        }

        // Remove any pre-existing session to prevent a failed login from retaining another user.
        response.addCookie(SessionCookiePolicy.deletionCookie());
        writeGenericFailure(response);
```

**Why it is a problem:** No denial is ever recorded: malformed identifiers, insecure transport,
`null`/`DENY` store decisions, replayed one-time handoffs, and the post-commit abort path (the one
`ERROR` at line 43) all leave either nothing or an unattributable message. Nothing distinguishes a
single misconfiguration from a sustained attack against the handoff endpoint, so the attacks the
`README` says were considered (replay races, enumeration, cookie tossing, the SEC-01 forced-logout
loop) are invisible to monitoring and un-investigable after the fact. The one log statement that
does fire on backend failure has no timestamp-correlatable context — no event type, no outcome, no
throttling key, no exception class — so an operator cannot even tell which requests failed. The
author's reasoning (avoiding log flooding and never logging secrets) is sound but the remedy
overshoots: structured, rate-limited, non-sensitive event logging achieves both goals.

**Fix:** Emit one structured, non-sensitive security event per outcome — event name, outcome, a
coarse denial reason, and the throttling key — never the candidate identifier or the store's
exception message. Log the exception *class* (not its message) so backend faults are diagnosable,
and sample/aggregate denial events so the log cannot be flooded.

```java
// src/main/java/com/example/security/session/SessionCookieEndpoint.java
        } catch (RuntimeException failure) {
            // Log the type only: a store exception *message* may embed secrets.
            logger.log(System.Logger.Level.ERROR,
                    "event=session_handoff outcome=error cause={0} source={1}",
                    failure.getClass().getName(), sourceKey);
        }

        if (locallyEligible && decision == SessionHandoffStore.Decision.AUTHORIZE) {
            response.addCookie(SessionCookiePolicy.sessionCookie(candidate));
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            logger.log(System.Logger.Level.INFO,
                    "event=session_handoff outcome=issued source={0}", sourceKey);
            return;
        }

        // Denials are logged at DEBUG with a coarse reason and no supplied value, so that
        // monitoring can alert on rates without an attacker being able to flood the log.
        logger.log(System.Logger.Level.DEBUG,
                "event=session_handoff outcome=denied reason={0} source={1}",
                denialReason(validCandidate, validSource, secureTransport), sourceKey);
        response.addCookie(SessionCookiePolicy.deletionCookie());
        writeGenericFailure(response);
```

### SEC-05: Cookie-issuing response omits `Strict-Transport-Security`

- **Severity:** Low
- **CWE:** CWE-319: Cleartext Transmission of Sensitive Information
- **Location:** `src/main/java/com/example/security/session/SessionCookieEndpoint.java:87-91`

**Vulnerable code:**
```java
// src/main/java/com/example/security/session/SessionCookieEndpoint.java:87-91
    private static void addNonCacheableHeaders(HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store, max-age=0");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("X-Content-Type-Options", "nosniff");
    }
```

**Why it is a problem:** This is the response that establishes the browser's session cookie, and it
asserts no HSTS policy. Without `Strict-Transport-Security`, a victim's first or subsequent
plaintext navigation to the host is not upgraded by the browser, so an active network attacker can
strip TLS on later requests and attempt downgrade/`Secure`-cookie-eviction tricks against the
session this very response created. The `__Host-` prefix and `Secure` attribute prevent the cookie
being read or overwritten over plain HTTP, which keeps this Low, but the strongest available
browser-level transport commitment is missing at exactly the moment it matters most. The
`README` asserts that cache leakage and spoofed-forwarding attacks were reviewed but does not
address transport pinning.

**Fix:** Send a long-lived HSTS header (ideally `includeSubDomains`, with `preload` once the domain
qualifies) on the cookie-issuing response, in addition to configuring it at the TLS-terminating
edge.

```java
// src/main/java/com/example/security/session/SessionCookieEndpoint.java
    private static void addNonCacheableHeaders(HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store, max-age=0");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("X-Content-Type-Options", "nosniff");
        // Pin HTTPS for the host that is being given a session cookie.
        response.setHeader("Strict-Transport-Security",
                "max-age=63072000; includeSubDomains");
        response.setHeader("Referrer-Policy", "no-referrer");
    }
```

## 6. Verified Controls and Checks With No Finding

- **Session identifier never taken from client-controlled input**: the candidate comes only from the
  server-side request attribute `com.example.security.session.authenticatedSessionId`
  (`SessionCookieEndpoint.java:49`); no `getParameter`, `getHeader`, `getCookies`, query string, or
  request body is read anywhere in the component (verified across all three main source files).
- **Strict type and value validation of the attribute**: the value must be a `String`
  (`SessionCookieEndpoint.java:50`) of exactly 43 characters from the base64url alphabet, and may not
  be the reserved dummy value (`SessionCookiePolicy.java:16-28`) — a type-, length-, and
  charset-based allowlist, not a denylist.
- **HTTP response splitting / header injection (CWE-113)**: the cookie value is constrained to
  `[A-Za-z0-9-_]` before `new Cookie(...)` (`SessionCookiePolicy.java:20-27`, used at
  `SessionCookieEndpoint.java:77`), so CR, LF, `;`, `"` and `=` cannot reach the `Set-Cookie`
  header; the deletion cookie uses a constant empty value (`SessionCookiePolicy.java:51`).
- **Cookie attributes**: `HttpOnly`, `Secure`, `Path=/`, no `Domain`, `SameSite=Strict`, and the
  `__Host-` name prefix are all set in one place (`SessionCookiePolicy.java:56-64`) and satisfy the
  `__Host-` prefix requirements; `setMaxAge(-1)` makes it a browser-session cookie
  (`SessionCookiePolicy.java:46`), and the deletion cookie uses an identically scoped `setMaxAge(0)`
  (`SessionCookiePolicy.java:50-53`), so it reliably evicts the real cookie. Platform cookie
  serialization is used rather than a hand-built header, per the "prefer the platform" rule. One
  residual deployment dependency: `SameSite` is set via `Cookie.setAttribute`
  (`SessionCookiePolicy.java:62`), which silently has no effect on a container that does not honour
  the Servlet 6.1 attribute — worth asserting in an integration test rather than only a unit test.
- **Fail-closed authorization**: `decision` is initialised to `DENY`
  (`SessionCookieEndpoint.java:63`), a `null` return is ignored (`:67-69`), a `RuntimeException` leaves
  it `DENY` (`:70-73`), and the cookie is issued only when `locallyEligible && decision == AUTHORIZE`
  (`:75-76`). No path substitutes a permissive default.
- **TOCTOU / check-then-act (CWE-367)**: every local prerequisite (identifier validity, source
  validity, `isSecure()`) is folded into the single `locallyEligible` flag passed to one
  `authorizeAndConsume` call (`SessionCookieEndpoint.java:59-66`), so a request that will be denied
  locally cannot first consume a valid one-time handoff, and the validate/consume/decide step is a
  single store operation by contract (`SessionHandoffStore.java:6-16`).
- **Transport enforcement**: issuance requires `request.isSecure()`
  (`SessionCookieEndpoint.java:55,59`), and spoofable `Forwarded` / `X-Forwarded-*` headers are
  deliberately not consulted (confirmed by grep: no `getHeader` call exists in the component).
- **Uniform failure responses / no enumeration (CWE-203)**: all denial causes converge on the same
  `401`, the same fixed-length `text/plain` body, and the same deletion cookie
  (`SessionCookieEndpoint.java:82-99`); malformed input still performs a dummy store lookup with the
  reserved `DUMMY_SESSION_ID` so the backend can do comparable work
  (`SessionCookieEndpoint.java:60`, `SessionCookiePolicy.java:11`).
- **No secrets in source**: no keys, passwords, tokens, or connection strings appear in any source
  file, `pom.xml`, or `.mvn/maven.config`; the only constants are a cookie name, an attribute name,
  and non-secret dummy placeholders (`SessionCookiePolicy.java:6-12`).
- **Sensitive data not leaked to logs, URLs, disk, or errors**: both log statements are fixed strings
  with no supplied value and no exception message (`SessionCookieEndpoint.java:43,72`); the
  identifier is never written to a file, a command line, a redirect, or an error body; the failure
  body is a compile-time constant (`SessionCookieEndpoint.java:20-21`).
- **Caching and sniffing**: `Cache-Control: no-store, max-age=0`, `Pragma: no-cache`, and
  `X-Content-Type-Options: nosniff` are set before any output, and `response.reset()` clears any
  upstream stale `Set-Cookie` while correctly guarding against an already-committed response
  (`SessionCookieEndpoint.java:42-47,87-91`).
- **Stale-session retention**: a failed handoff actively deletes any pre-existing
  `__Host-session` cookie (`SessionCookieEndpoint.java:83`), so a failed exchange cannot leave the
  browser holding another user's session. (The cross-site reachability of that same code path is
  SEC-01.)
- **No injection sinks present**: the component contains no SQL or other query construction, no
  deserialization (`readObject`, XML, JSON), no reflection on untrusted input, no file or path
  handling, no `Runtime.exec`/`ProcessBuilder`, no outbound network calls, and no HTML/template
  rendering — so SQLi, XXE, insecure deserialization, path traversal, command injection, SSRF, and
  XSS have no applicable sink. `serialVersionUID` is declared but the servlet is never deserialized
  from untrusted bytes.
- **Cryptography**: the component performs no hashing, encryption, or random generation; identifier
  entropy is the upstream component's responsibility, and the dependence on the creator using a
  CSPRNG for 256 bits is explicitly documented as residual risk (`README.md:43-49`). Because the
  identifier is supplied rather than generated here, session-fixation resistance also rests on that
  upstream contract.
- **Build and dependency integrity**: all dependencies and plugins are pinned to exact versions from
  official coordinates, the servlet API is `provided` (`pom.xml:19-30,35-59`), and Maven runs with
  `--strict-checksums` (`.mvn/maven.config:1`). No remote scripts are fetched and no code is loaded
  from shared or world-writable locations.
- **Tests contain no credentials or live network/database access**: `SessionCookieEndpointTest.java`
  and `SessionCookiePolicyTest.java` use in-memory `java.lang.reflect.Proxy` stubs only, and
  `SessionCookieEndpointTest.java:46-60` explicitly verifies that a store returning `AUTHORIZE` for
  malformed input still fails closed.
- **Unenforceable store contract (reviewed, documented, not scored as a separate finding)**:
  `SessionHandoffStore` is a `@FunctionalInterface` whose atomicity, one-time consume, dummy-record
  work, and rate-limit requirements exist only as Javadoc (`SessionHandoffStore.java:3-22`). The
  endpoint cannot detect a non-conforming implementation; the security of this feature therefore
  depends on reviewing the store implementation too, which is outside this scope. The throttling
  consequence of that gap is captured in SEC-02.
