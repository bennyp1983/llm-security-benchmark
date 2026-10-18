# Post-authentication session cookie component

Takes a session identifier that a **separate, trusted component** has already created and
validated server-side, and returns it to the browser in a hardened `Set-Cookie`, so the
authenticated session survives subsequent requests.

This component does **not** authenticate users, create sessions, or validate credentials.
Its whole job is the cookie and the response that carries it.

Java 17 - Jakarta Servlet 6.0 (Tomcat 10.1+, Jetty 12 EE10) - no runtime dependency
beyond the servlet API and the SLF4J facade. `mvn test` -> 40 tests, all green.

---

## How it is wired up

```
[ trusted authenticator ]  authenticates, creates server-side session
          |
          |  request.setAttribute("com.example.websession.SESSION_ID", id)   <- server-side only
          v
[ SessionCookieServlet ]   POST /session/establish   <- this component
          |
          +-- SessionCookieIssuer: validate shape -> verify against server state -> rate limit
          +-- SetCookieHeaderFactory: Set-Cookie: __Host-SID=...; Path=/; HttpOnly; Secure; SameSite=Strict
          +-- GenericResponse: one of four fixed bodies
```

Startup, in a `ServletContextListener`:

```java
context.setAttribute(SessionCookieServlet.SESSION_SERVICE_ATTRIBUTE, myTrustedSessionService);
```

If that attribute is missing, or configuration is invalid, the servlet throws
`UnavailableException` and never serves a request.

### Configuration (environment; all optional, all validated, all strict by default)

| Variable | Default | Range |
|---|---|---|
| `SESSION_COOKIE_NAME` | `__Host-SID` | cookie-token chars, <= 64 |
| `SESSION_COOKIE_PATH` | `/` | must start with `/`, no delimiters |
| `SESSION_COOKIE_SAMESITE` | `Strict` | `Strict` \| `Lax` \| `None` |
| `SESSION_COOKIE_SECURE` | `true` | `true` \| `false` |
| `SESSION_COOKIE_MAX_AGE_SECONDS` | `0` (browser-session cookie) | 0 - 86400 |
| `SESSION_ISSUE_MAX_PER_IP_PER_MINUTE` | `30` | 1 - 10000 |
| `SESSION_ISSUE_MAX_PER_SUBJECT_PER_MINUTE` | `20` | 1 - 10000 |
| `SESSION_ISSUE_RATE_LIMIT_MAX_KEYS` | `100000` | 1000 - 1000000 |
| `SESSION_TRUSTED_PROXY_COUNT` | `0` (ignore `X-Forwarded-For`) | 0 - 8 |

Inconsistent combinations are rejected at startup, not silently downgraded: a `__Host-`
name forces `Secure` and `Path=/`, and `SameSite=None` forces `Secure`.

---

## How each rule is satisfied

### 1. Trust boundaries

Every input, enumerated, and what is done with it:

| Input | Source | Treatment |
|---|---|---|
| Session identifier | request attribute set by the trusted authenticator | length 22-128 **and** base64url-only (`SessionIdValidator`), then looked up in authoritative server-side state before anything is emitted |
| `TrustedSession.subjectKey` | trusted session component | non-blank, <= 256 chars (`TrustedSession` compact constructor); used only as a hashed rate-limit key |
| `TrustedSession.remainingLifetimeSeconds` | trusted session component | must be `> 0` and <= 1 year; clamps the cookie `Max-Age` |
| `X-Forwarded-For` | **client** | ignored unless `SESSION_TRUSTED_PROXY_COUNT > 0`; only the hop the trusted proxy wrote is read; validated as an IP literal; no DNS lookup; header > 1 KiB ignored |
| `Sec-Fetch-Site` | browser | used only to *refuse* (`cross-site`), never to grant |
| `getRemoteAddr()` | container | validated as an IP literal before becoming a map key |
| HTTP method | client | allowlist of exactly `POST` (plus a fixed `OPTIONS`) |
| `Cookie`, query string, body, any other header | **client** | **never read** |
| All 9 configuration variables | environment | type/format/range checked; unknown or empty value is a startup failure |

The decisive security check -- "is this a live session?" -- is answered only by
`TrustedSessionService.lookupActiveSession`, i.e. by server-side state. No client-supplied
value participates in it.

### 2. Secrets

There are no credentials, keys, or passwords in this code or in its configuration: it
emits an identifier the trusted component already minted, so it needs none. The one piece
of key material that exists -- the HMAC key used to mask log values -- is generated at
startup from `SecureRandom`, held in a `byte[]`, never written to a file, log, command
line, or response, and zeroed by `LogFingerprint.close()` (called from `Servlet.destroy()`).
Configuration error messages name the offending key but never echo its value, in case a
variable was mistakenly populated with a secret.

### 3. Authentication and access

Authentication itself belongs to the upstream component. What this code enforces is that a
cookie is issued **only** after a positive answer from server-side state. Every path that
cannot reach that answer fails closed and emits no cookie: missing attribute, wrong
attribute type, malformed identifier, empty lookup result, an exception from the lookup,
an uncommitted-response violation, a non-TLS request while `Secure` is configured, a
second issuance in one request, and a missing `TrustedSessionService` at startup.

Repeated attempts are limited on **two independent axes**:

* per source address - `SESSION_ISSUE_MAX_PER_IP_PER_MINUTE`, answered with `429`;
* per subject - `SESSION_ISSUE_MAX_PER_SUBJECT_PER_MINUTE`, answered with the same generic `401` as any other refusal.

They are separate counters, so exhausting one does not consume the other. That is the point:
an attacker who knows a victim's identity can only spend the victim's subject budget, and
only if they already hold a live identifier for that subject -- they cannot consume it by
guessing, because guesses never resolve to the victim's subject (they are charged to a
source-derived placeholder key instead). Conversely, a flood from one address cannot
affect another user's source budget.

### 4. Identifiers and tokens

The task specifies an externally provided identifier, so this component does **not**
generate one; it validates strictly and documents the residual risk below. It is never
accepted from the caller: the only accepted source is a request attribute, which lives in
server memory for one request and cannot be set through any header, parameter, cookie, or
body. A test (`neverReadsTheIdentifierFromTheClient`) pins this by sending the identifier
in both a header and a cookie and asserting it is ignored.

Cookie attributes, always, on both issuance and deletion:

`__Host-SID=<id>; Path=/; HttpOnly; Secure; SameSite=Strict` and no `Domain`.

* `__Host-` - the browser itself refuses the cookie unless it is `Secure`, `Path=/`, and host-only; it also blocks a subdomain from overwriting it.
* `HttpOnly` - out of reach of `document.cookie`, so an XSS does not hand over the session.
* `Secure` - never sent over cleartext; the component additionally refuses to issue over a non-TLS connection rather than emitting a cookie the browser will drop.
* `SameSite=Strict` - not attached to cross-site requests; CSRF against session-authenticated endpoints loses its ambient credential.
* `Path=/` - explicit, so the cookie is not scoped to the issuing directory and no second cookie of the same name can appear on a narrower path.
* `Max-Age` - omitted by default (dies with the browser); when configured, clamped to `min(configured, remaining server-side lifetime)` so the cookie never outlives the session.

**Residual risk, since the identifier is not generated here.** This component cannot
verify that the identifier is unpredictable, unique, or freshly rotated. It enforces a
>= 22-character base64url shape as a weak proxy for entropy, and nothing more. The trusted
component therefore remains responsible for:

1. generating the identifier from a CSPRNG with >= 128 bits of entropy;
2. **rotating it at the moment of privilege change** -- if the identifier handed to this
   component is the same one the browser held before authenticating, session fixation is
   live and nothing here can detect it, because the value is valid server-side either way;
3. idle and absolute expiry, and server-side invalidation on logout.

`expireSessionCookie()` is provided for logout, with attributes matching the issued cookie
so the browser actually drops it; it is cosmetic unless the trusted component invalidates
the session server-side first, which the Javadoc says explicitly.

### 5. Sensitive data

No session identifier, subject key, or source address is ever logged in clear text. Each is
replaced by a 12-hex-character HMAC tag under a per-process random key (`LogFingerprint`),
which permits correlating one request's log lines but not confirming a guessed identifier
from log access -- a plain hash would allow exactly that. Nothing is written to disk, so
there are no file permissions to get wrong. Every input is length-bounded before it is
stored (identifier <= 128, subject key <= 256, address <= 45, `X-Forwarded-For` <= 1 KiB),
and the rate-limiter key space is capped, so no attacker-controlled value can grow memory
without bound. The HMAC key is zeroed on shutdown; the identifier arrives as an immutable
`String` from the container and cannot be wiped, so it is simply never copied or retained
beyond the request.

### 6. Failure behaviour

Four fixed responses, chosen from constants, with no field for a reason and nothing echoed
back from the request:

| Outcome | Status | Body |
|---|---|---|
| issued | 200 | `{"status":"ok"}` |
| **every** refusal | 401 | `{"error":"authentication_required"}` |
| source throttled | 429 | `{"error":"too_many_requests"}` |
| refused to act | 503 | `{"error":"service_unavailable"}` |

"Missing identifier", "malformed identifier", "no such session", "expired session",
"revoked session", and "subject throttled" all produce byte-for-byte the same 401, with the
same `Content-Length`; a test asserts the equality directly. Each of those paths also does
the same work -- one lookup attempt, one fingerprint, one atomic counter update -- using a
placeholder subject key when the lookup found nothing, so the response time does not
separate them either. Exception detail and stack traces go to the log only. Unrecognised
configuration is rejected at startup rather than replaced with a permissive default, and an
explicitly empty variable is an error rather than "use the default".

### 7. Concurrency

The only check-then-act in the component is the rate limiter, and its window roll, counter
increment, and decision all happen inside a single `ConcurrentHashMap.compute` -- atomic
per key -- with the verdict taken from the value that call returned, never from a second
read. `grantsExactlyTheLimitUnderConcurrency` hammers one key with 32 threads x 20 attempts
against a 50-permit budget and asserts exactly 50 grants; a naive implementation overshoots.
Counters saturate instead of overflowing into a negative count that would reopen the gate.
Double issuance within one request is blocked by a marker attribute on the request, which is
single-threaded by definition. The atomicity of the session lookup itself is the trusted
component's responsibility and is stated in the `TrustedSessionService` contract.

### 8. Prefer the platform

The Servlet API is used for everything it does well: `HttpServlet` method dispatch,
`ServletContext` wiring, `UnavailableException` for fail-closed startup, container TLS
detection via `isSecure()`, `SecureRandom` and `javax.crypto.Mac` from the JDK for masking.
Browser-enforced platform mechanisms are preferred over anything hand-rolled: the `__Host-`
prefix, `SameSite`, `HttpOnly`, and `Secure` are all enforced by the user agent, not by
this code.

The one deliberate exception is the `Set-Cookie` header itself, which is built as a string
rather than through `jakarta.servlet.http.Cookie`. `SameSite` only became a first-class
attribute in Servlet 6.0, and containers have historically dropped attributes they did not
recognise -- a silently missing `SameSite` is invisible in testing and serious in
production. Emitting one deterministic header makes the output exactly what the tests
assert. Injection is prevented structurally rather than by escaping: the name comes from a
startup-validated allowlist, the value is base64url-only, and the attributes are fixed
strings plus a non-negative `long`, so no CR/LF can enter the header by any route.

Dependencies are pinned to specific released versions from Maven Central, the official
distribution point (`jakarta.servlet-api` 6.0.0 `provided`, `slf4j-api` 2.0.16,
`junit-jupiter` 5.10.2). Snapshots are disabled, `checksumPolicy` is `fail`, and no mirror,
shared directory, or world-writable location is referenced. Nothing is downloaded or
executed at runtime.

---

## What this component deliberately does not do

* Authenticate, create, rotate, or invalidate sessions - the trusted component owns all of it.
* Bind the session to a client fingerprint or address - that belongs with session validation.
* Serve as CSRF defence on its own. `SameSite=Strict` plus POST-only plus the `Sec-Fetch-Site`
  refusal cover this endpoint; application endpoints that act on the session still need their
  own token-based protection for browsers where `SameSite` cannot be relied on.
* Terminate TLS or set HSTS - deploy behind HTTPS with HSTS at the edge, or the `Secure`
  attribute protects only the cookie and not the first request.
