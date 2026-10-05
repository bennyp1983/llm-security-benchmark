# Security Review: `com.example.websession` post-authentication session-cookie component

## 1. Executive Summary

This Maven/Java 17 component (Jakarta Servlet 6.0) takes a server-side session identifier that a
separate trusted authenticator has already created, verifies it against authoritative server-side
state, and returns it to the browser in a hardened `Set-Cookie`. It does not authenticate users and
does not mint identifiers.

The code is defensively written and most of the classic failure modes for this feature are genuinely
closed: the identifier is read from a request attribute (never from a client-controllable header,
parameter, or cookie), it is syntactically validated against a base64url allowlist before it reaches
the header builder, it is then confirmed live via `TrustedSessionService`, failures collapse into
four fixed generic responses, the rate-limiter's check-and-increment is atomic inside a single
`ConcurrentHashMap.compute`, no secret is hardcoded, and sensitive values are HMAC-fingerprinted
before logging. Session fixation and `Set-Cookie` header injection are structurally prevented rather
than filtered.

The findings are therefore all in the supporting controls rather than in the cookie itself, and none
of them allows forging or stealing a session directly. The most important are:

- **Source-address trust (SEC-01):** `X-Forwarded-For` is read with `getHeader()`, which returns only
  the *first* header instance. In any deployment whose proxy appends a *second* `X-Forwarded-For`
  header line rather than extending the existing one, the hop the code selects is attacker-supplied,
  defeating the per-source rate limit and poisoning the source attribution in logs.
- **Rate-limiter key-space exhaustion (SEC-02):** the limiter's bounded key map fails *closed* for
  unseen keys, so any attacker with a large source-address range (a single IPv6 /64 suffices) can fill
  the map and cause every new legitimate client to be throttled, while also forcing an O(n) purge scan
  over up to one million entries on each subsequent request.
- **Missing HSTS (SEC-03)** on the very response that delivers a `Secure` session cookie.
- **CSRF defence rests on one optional browser header (SEC-04)**, which is absent on older browsers
  and on non-browser clients, and which treats every `same-site` origin as trusted.

Four further low-severity issues cover an insecure-by-configuration `Secure=false` path, the
fixed-window burst allowance, a 48-bit truncated fingerprint used as a throttle bucket key, and a
shared `"unknown"` rate-limit bucket.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/websession/SessionCookieServlet.java` | HTTP entry point; `POST` only, resolves dependencies in `init` | Cross-site rejection via `Sec-Fetch-Site`; method allowlisting (405 for all other verbs); fail-closed startup (`UnavailableException`); exception swallowing so no stack trace reaches the client |
| `src/main/java/com/example/websession/SessionCookieIssuer.java` | Orchestrates validation, server-side verification, throttling, and header emission | Reads session id from a request attribute; TLS precondition check; per-source and per-subject rate limiting; response hardening headers; fingerprinted logging; `Max-Age` clamped to remaining session lifetime |
| `src/main/java/com/example/websession/SessionIdValidator.java` | Syntactic validation of the externally supplied identifier | Length bounds (22–128) and base64url character allowlist — the control that makes CR/LF and cookie-attribute injection impossible |
| `src/main/java/com/example/websession/SetCookieHeaderFactory.java` | Builds the `Set-Cookie` value by hand | Emits `HttpOnly`, conditional `Secure`, `SameSite`, explicit `Path`, no `Domain`; re-validates the identifier as defence in depth; builds the deletion header |
| `src/main/java/com/example/websession/SessionCookieSettings.java` | Validated configuration from environment variables | Treats configuration as untrusted input: type/format/range checks, strict defaults, cross-field consistency rules for `__Host-`/`__Secure-`/`SameSite=None`; error messages never echo values |
| `src/main/java/com/example/websession/ClientAddressResolver.java` | Derives the per-source rate-limit key | Parses `X-Forwarded-For` only when trusted proxies are declared; validates IP literals; no DNS resolution; bounded lengths |
| `src/main/java/com/example/websession/FixedWindowRateLimiter.java` | Bounded, thread-safe fixed-window counter | Atomic check-then-act via `ConcurrentHashMap.compute`; counter saturation instead of overflow; bounded key space with expiry purge and fail-closed admission |
| `src/main/java/com/example/websession/LogFingerprint.java` | Masks sensitive values for logging | `SecureRandom` 256-bit HMAC-SHA256 key generated at startup, never persisted; output truncated to 12 hex chars; key zeroed on `close()` |
| `src/main/java/com/example/websession/GenericResponse.java` | The only thing a client learns about failure | Four fixed pre-encoded bodies with fixed `Content-Length`; `no-store`; `nosniff`; `Retry-After` on 429 |
| `src/main/java/com/example/websession/IssueOutcome.java` | Coarse outcome enum | Collapses missing/malformed/unknown identifier and per-subject throttle into one `REJECTED` to avoid an existence oracle |
| `src/main/java/com/example/websession/TrustedSession.java` | Record of server-side session facts | Validates provider output: bounded `subjectKey` length, strictly positive and bounded `remainingLifetimeSeconds` |
| `src/main/java/com/example/websession/TrustedSessionService.java` | Seam to the trusted session owner | Documents the authoritative "is this session live now?" contract, including indistinguishable unknown/expired answers and atomic observation |
| `src/main/java/com/example/websession/package-info.java` | Package documentation | States the trust model (every inbound value attacker-controlled) |
| `pom.xml` | Build definition | Dependency provenance and versions: `jakarta.servlet-api` and `slf4j-api` (provided/compile), JUnit 5 test-scoped |
| `src/test/java/com/example/websession/*.java` | Unit tests (40) and a servlet API test double | Not production code; reviewed only to confirm the asserted behaviour of the controls above |
| `README.md`, `prompt.txt`, `cyber_prompt.txt`, `result.md`, `return.txt`, `prompt_hash.txt`, `target/` | Documentation, task artefacts, build output | No executable application code; checked for embedded secrets (none found) |

## 3. Skills Applied

- `review-code-for-security-vulnerabilities`: router skill — drove the whole review (understand the
  code, select specialised skills, apply them, report with CWE ids and `file:line` evidence).
- `performing-api-rate-limiting-bypass`: applied to `ClientAddressResolver` and
  `FixedWindowRateLimiter` — IP-spoofing-header bypass, per-account vs per-source budget separation,
  counter race conditions, fixed-window vs sliding-window burst behaviour, and HTTP method/endpoint
  variation bypass. Produced SEC-01, SEC-02, SEC-06, SEC-08.
- `performing-security-headers-audit`: applied to `SetCookieHeaderFactory.build`,
  `SessionCookieIssuer.applyResponseHardening`, and `GenericResponse.send` — `Secure`/`HttpOnly`/
  `SameSite`/`Path`/`Domain` cookie attributes, `__Host-` prefix requirements, HSTS, `nosniff`,
  `Referrer-Policy`, caching headers. Produced SEC-03 and SEC-05.
- `performing-csrf-attack-simulation`: applied to `SessionCookieServlet.doPost`/`isCrossSite` —
  synchronizer-token absence, `Origin`/`Referer` validation, `SameSite` reliance, and header-based
  defences that fail open. Produced SEC-04.
- `testing-for-sensitive-data-exposure`: applied to every `LOG.*` call site, to `GenericResponse`,
  and to `SessionCookieSettings` error messages — identifier/PII leakage into logs, stack traces and
  internal detail in responses, cache headers, secrets in source. No finding.
- `performing-cryptographic-audit-of-application`: applied to `LogFingerprint` — RNG quality,
  algorithm and key length, hardcoded keys, key storage/rotation, output truncation, memory zeroing.
  Produced SEC-07.
- `testing-for-broken-access-control`: applied to `SessionCookieIssuer.issue` and the servlet's
  method handlers — server-side verification of the security decision, fail-closed behaviour on a
  missing or failed check, HTTP verb and method-override bypass, forced browsing. No finding.
- Reviewed against general OWASP Top 10 / CWE knowledge, because no library skill matched these
  behaviours directly: session fixation and cookie-identifier provenance (CWE-384); HTTP response
  splitting / `Set-Cookie` attribute injection via the cookie name, path, value, and `Max-Age`
  (CWE-113, CWE-1004); configuration-as-untrusted-input parsing and integer range handling in
  `SessionCookieSettings` (CWE-20, CWE-1284); counter overflow in the rate limiter (CWE-190);
  servlet lifecycle and `transient` field initialisation on an unavailable servlet (CWE-636);
  dependency provenance and version pinning in `pom.xml` (CWE-1104); timing differences between
  failure branches in `issue()` (CWE-208).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Only the first `X-Forwarded-For` header is read, so the selected hop can be attacker-supplied | Medium | CWE-348 | `src/main/java/com/example/websession/ClientAddressResolver.java:40` |
| SEC-02 | Rate-limiter key space can be exhausted, denying service to all new clients | Medium | CWE-770 | `src/main/java/com/example/websession/FixedWindowRateLimiter.java:49` |
| SEC-03 | No `Strict-Transport-Security` on the response that delivers the session cookie | Medium | CWE-319 | `src/main/java/com/example/websession/SessionCookieIssuer.java:172` |
| SEC-04 | CSRF defence relies solely on an optional browser header and trusts all same-site origins | Medium | CWE-352 | `src/main/java/com/example/websession/SessionCookieServlet.java:94` |
| SEC-05 | Configuration permits a session cookie without the `Secure` attribute | Low | CWE-614 | `src/main/java/com/example/websession/SessionCookieSettings.java:86` |
| SEC-06 | Fixed-window counter permits a 2x burst across the window boundary | Low | CWE-307 | `src/main/java/com/example/websession/FixedWindowRateLimiter.java:55` |
| SEC-07 | 48-bit truncated fingerprint used as the per-subject throttle key | Low | CWE-328 | `src/main/java/com/example/websession/LogFingerprint.java:26` |
| SEC-08 | Unparseable client addresses collapse into one shared `"unknown"` rate-limit bucket | Low | CWE-770 | `src/main/java/com/example/websession/ClientAddressResolver.java:57` |

## 5. Detailed Findings

### SEC-01: Only the first `X-Forwarded-For` header is read, so the selected hop can be attacker-supplied
- **Severity:** Medium
- **CWE:** CWE-348: Use of Less Trusted Source
- **Location:** `src/main/java/com/example/websession/ClientAddressResolver.java:40-52`

**Vulnerable code:**
```java
// src/main/java/com/example/websession/ClientAddressResolver.java:40-52
        String header = request.getHeader(FORWARDED_FOR);
        if (header == null || header.length() > MAX_HEADER_LENGTH) {
            return direct;
        }
        String[] hops = header.split(",", -1);
        int index = hops.length - trustedProxyCount;
        if (index < 0 || index >= hops.length) {
            // Fewer hops than the deployment promises: the chain is not what we were told
            // it would be, so fall back to the only address we observed ourselves.
            return direct;
        }
        String candidate = sanitize(hops[index].trim());
        return candidate.equals(UNKNOWN) ? direct : candidate;
```

**Why it is a problem:** The "count from the right" strategy is correct, but it is applied to the
wrong string. Per the Servlet specification, `HttpServletRequest.getHeader(String)` returns **only the
first** header instance when a request carries the same field name more than once. Not every reverse
proxy extends an existing `X-Forwarded-For` field; several (for example HAProxy's `option forwardfor`
without `if-none`, and assorted ingress configurations that use an add-header rather than an
append-to-existing directive) emit a *new* `X-Forwarded-For` header line instead, leaving the client's
forged header as the first one in the request.

With `SESSION_TRUSTED_PROXY_COUNT=1` in such a deployment, a client sending
`X-Forwarded-For: 203.0.113.9` makes `getHeader` return `"203.0.113.9"`, so `hops.length == 1`,
`index == 0`, and the fully attacker-chosen value becomes the rate-limit bucket key. Because the
value is only required to parse as an IP literal, the attacker can cycle through a fresh literal on
every request and obtain an unlimited number of 30-per-minute buckets, defeating
`perAddressLimiter` at `SessionCookieIssuer.java:97` entirely and simultaneously feeding each one as
a new key into the bounded map described in SEC-02. The same forged value is what gets fingerprinted
into the throttling and refusal log lines (`SessionCookieIssuer.java:98`, `122`), so source
attribution during an incident is attacker-controlled too.

The class's own Javadoc states that entries left of the trusted ones are "skipped", which is the
intended design; reading a single header instance silently breaks that guarantee without any visible
symptom.

**Fix:** Flatten *all* `X-Forwarded-For` header instances into one hop list before indexing, so the
trusted-proxy count is applied to the complete chain the request actually carried. Keep the existing
total-length bound, applied to the concatenation rather than to one instance.

```java
    /** @return a validated address literal, or {@code "unknown"} -- never a client-supplied string. */
    String resolve(HttpServletRequest request) {
        String direct = sanitize(request.getRemoteAddr());
        if (trustedProxyCount == 0) {
            return direct;
        }
        // getHeader() returns only the first instance; a proxy that adds a second
        // X-Forwarded-For header line would otherwise leave us indexing into the
        // client's forged header. Concatenate every instance, in request order.
        List<String> hops = new ArrayList<>();
        int totalLength = 0;
        Enumeration<String> instances = request.getHeaders(FORWARDED_FOR);
        if (instances == null) {
            return direct;
        }
        while (instances.hasMoreElements()) {
            String instance = instances.nextElement();
            if (instance == null) {
                continue;
            }
            totalLength += instance.length();
            if (totalLength > MAX_HEADER_LENGTH) {
                return direct;
            }
            for (String hop : instance.split(",", -1)) {
                hops.add(hop);
            }
        }
        int index = hops.size() - trustedProxyCount;
        if (index < 0 || index >= hops.size()) {
            // Fewer hops than the deployment promises: the chain is not what we were told
            // it would be, so fall back to the only address we observed ourselves.
            return direct;
        }
        String candidate = sanitize(hops.get(index).trim());
        return candidate.equals(UNKNOWN) ? direct : candidate;
    }
```

### SEC-02: Rate-limiter key space can be exhausted, denying service to all new clients
- **Severity:** Medium
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `src/main/java/com/example/websession/FixedWindowRateLimiter.java:49-53`, `66-72`

**Vulnerable code:**
```java
// src/main/java/com/example/websession/FixedWindowRateLimiter.java:49-53
        if (windows.size() >= maxTrackedKeys && !windows.containsKey(key)) {
            purgeExpired(nowMillis);
            if (windows.size() >= maxTrackedKeys && !windows.containsKey(key)) {
                return false;
            }
        }
```

**Why it is a problem:** Bounding the key space is the right instinct — an unbounded map would be a
heap-exhaustion vector — but the chosen failure mode converts a memory problem into an availability
problem for *everyone else*. Once the map holds `maxTrackedKeys` entries whose windows have not yet
expired, every key the limiter has not seen before is refused, and `SessionCookieIssuer.java:97-100`
turns that refusal into `RATE_LIMITED` for a brand-new, entirely legitimate client.

Filling the map does not require the spoofing of SEC-01. The default ceiling is 100 000 keys and the
default window is 60 seconds, and an attacker with a routed IPv6 /64 has 2^64 distinct source
addresses, so 100 000 requests inside one minute — well within reach of a single host — locks out
every user whose address is not already tracked, for as long as the attacker keeps the window alive.
A second, compounding effect: from that point on, every request for an untracked key triggers
`purgeExpired`, which iterates the entire map (up to the 1 000 000 configurable ceiling) while
finding nothing to remove, turning each request into a full-map scan.

**Fix:** Keep the hard bound, but evict rather than refuse, so admission failure is never the
attacker's lever. Bounding the map with an eviction policy (approximate LRU, or the oldest window
first) preserves the memory guarantee and degrades the limiter's accuracy under flood instead of
degrading availability. Rate-limit the purge scan so it cannot be driven once per request, and
account for the fact that under eviction a flooding attacker loses their own counters first.

```java
    boolean tryAcquire(String key, long nowMillis) {
        if (key == null) {
            return false;
        }
        if (windows.size() >= maxTrackedKeys && !windows.containsKey(key)) {
            // Purge at most once per window, so a flood of unseen keys cannot drive a
            // full-map scan on every request.
            long lastPurge = lastPurgeMillis;
            if (nowMillis - lastPurge >= windowMillis
                    && LAST_PURGE.compareAndSet(this, lastPurge, nowMillis)) {
                purgeExpired(nowMillis);
            }
            // Still full: evict the entry with the oldest window rather than refusing the
            // new key. Refusing would let an attacker who can vary the key deny service to
            // every client the limiter has not seen yet.
            while (windows.size() >= maxTrackedKeys && !windows.containsKey(key)) {
                Map.Entry<String, Window> oldest = null;
                for (Map.Entry<String, Window> entry : windows.entrySet()) {
                    if (oldest == null || entry.getValue().startMillis() < oldest.getValue().startMillis()) {
                        oldest = entry;
                    }
                }
                if (oldest == null || !windows.remove(oldest.getKey(), oldest.getValue())) {
                    break;
                }
            }
        }
        Window updated = windows.compute(key, (k, existing) -> {
            if (existing == null || nowMillis - existing.startMillis() >= windowMillis) {
                return new Window(nowMillis, 1);
            }
            // Saturate rather than overflow into a negative count, which would reopen the gate.
            int next = existing.count() == Integer.MAX_VALUE ? existing.count() : existing.count() + 1;
            return new Window(existing.startMillis(), next);
        });
        return updated.count() <= permitsPerWindow;
    }
```

### SEC-03: No `Strict-Transport-Security` on the response that delivers the session cookie
- **Severity:** Medium
- **CWE:** CWE-319: Cleartext Transmission of Sensitive Information
- **Location:** `src/main/java/com/example/websession/SessionCookieIssuer.java:172-181`

**Vulnerable code:**
```java
// src/main/java/com/example/websession/SessionCookieIssuer.java:172-181
    private static void applyResponseHardening(HttpServletResponse response) {
        // A Set-Cookie carrying a session identifier must never be stored by a shared cache
        // and handed to the next user of that cache.
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Expires", "0");
        response.addHeader("Vary", "Cookie");
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("Referrer-Policy", "same-origin");
    }
```

**Why it is a problem:** This is the one response in the whole application that hands the browser a
session identifier, and it is emitted over TLS by construction (`SessionCookieIssuer.java:85-89`
refuses to issue a `Secure` cookie on a non-TLS request). That makes it the single best place to pin
the origin to HTTPS, and `Strict-Transport-Security` is absent.

Without HSTS, a network attacker can SSL-strip the victim's *next* navigation to the origin: the
browser is willing to issue a plaintext `http://` request, and although the `Secure` attribute stops
the `__Host-SID` cookie from being attached to it, the user is now transacting over a
attacker-controlled cleartext channel against an origin they believe is authenticated, and any
non-`Secure` cookie or form post on that origin is exposed. The first visit to the origin is
similarly unprotected. The response already carries five other hardening headers, so the omission
reads as an oversight rather than a deliberate delegation.

**Fix:** Emit HSTS alongside the other hardening headers, but only when the request actually arrived
over TLS — sending `Strict-Transport-Security` over plaintext is ignored by browsers and, in a
deliberate `SESSION_COOKIE_SECURE=false` development deployment, would be actively unhelpful. Note
that `includeSubDomains` and `preload` are origin-wide commitments; if the edge terminator already
sets the header, `setHeader` here keeps a single consistent value rather than duplicating it.

```java
    private static void applyResponseHardening(HttpServletRequest request, HttpServletResponse response) {
        // A Set-Cookie carrying a session identifier must never be stored by a shared cache
        // and handed to the next user of that cache.
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Expires", "0");
        response.addHeader("Vary", "Cookie");
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("Referrer-Policy", "same-origin");
        if (request.isSecure()) {
            // Pin the origin to HTTPS so the next navigation cannot be SSL-stripped. Only
            // meaningful over TLS; browsers ignore it on a cleartext response.
            response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        }
    }
```

### SEC-04: CSRF defence relies solely on an optional browser header and trusts all same-site origins
- **Severity:** Medium
- **CWE:** CWE-352: Cross-Site Request Forgery (CSRF)
- **Location:** `src/main/java/com/example/websession/SessionCookieServlet.java:94-97`

**Vulnerable code:**
```java
// src/main/java/com/example/websession/SessionCookieServlet.java:94-97
    private static boolean isCrossSite(HttpServletRequest request) {
        String fetchSite = request.getHeader("Sec-Fetch-Site");
        return "cross-site".equalsIgnoreCase(fetchSite);
    }
```

**Why it is a problem:** `Sec-Fetch-Site` is a good signal — it is browser-set and script cannot
forge it — but it is the *only* CSRF control on a state-changing `POST`, and the check is a denylist
of exactly one value, so it fails open in three ways:

1. **Header absent.** Fetch metadata is not universally sent (notably by older Safari and by any
   non-browser HTTP client), and `equalsIgnoreCase` on a `null` simply returns `false`, so the
   request proceeds. The Javadoc's claim that "a client that omits it gains nothing" holds only for
   the identifier itself; see point 3 for what is still reachable.
2. **`same-site` is fully trusted.** Any sibling subdomain — including one that is third-party
   hosted, or one with an XSS — counts as `same-site`, not `cross-site`, and can drive this endpoint
   at will.
3. **There is something to gain.** A forged request still consumes the victim's budget in *both*
   limiters (`SessionCookieIssuer.java:97` keyed on the victim's source address, and
   `SessionCookieIssuer.java:119` keyed on the victim's subject). A hostile page that fires 30
   requests in a minute leaves the victim's own legitimate re-establishment attempts rejected,
   which is precisely the attacker-induced lockout that the two-budget design elsewhere in this
   class is meant to prevent. The `cross-site` branch is checked before the limiters, but the
   header-absent and `same-site` cases are not.

The cookie itself defaults to `SameSite=Strict`, which mitigates (1) for cross-site navigations, but
`SESSION_COOKIE_SAMESITE` is configurable down to `Lax` or `None`, so that mitigation cannot be
relied on.

**Fix:** Treat an unknown fetch-site as untrusted and fall back to explicit `Origin` validation
against the request's own host. Keep the allowlist positive (`same-origin` / `none`, meaning a
user-initiated navigation) rather than denying one known-bad value, so an unrecognised or missing
value fails closed. For a browser-driven endpoint, pairing this with a synchronizer token issued by
the upstream authenticator remains the stronger control.

```java
    /**
     * {@code Sec-Fetch-Site} is set by the browser and cannot be overridden by page script,
     * so it is the preferred signal. It is an allowlist, not a denylist: an unrecognised or
     * absent value falls through to Origin validation and is refused if that is inconclusive
     * too, so the check cannot fail open on a client that omits fetch metadata.
     */
    private static boolean isCrossSite(HttpServletRequest request) {
        String fetchSite = request.getHeader("Sec-Fetch-Site");
        if (fetchSite != null) {
            // "same-site" is deliberately NOT accepted: a sibling subdomain is not this origin.
            return !("same-origin".equalsIgnoreCase(fetchSite) || "none".equalsIgnoreCase(fetchSite));
        }
        String origin = request.getHeader("Origin");
        if (origin == null) {
            // No fetch metadata and no Origin: cannot establish the request is same-origin.
            return true;
        }
        StringBuffer self = request.getRequestURL();
        String expected = self == null ? null : self.substring(0, self.indexOf("/", self.indexOf("//") + 2));
        return expected == null || !origin.equals(expected);
    }
```

### SEC-05: Configuration permits a session cookie without the `Secure` attribute
- **Severity:** Low
- **CWE:** CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
- **Location:** `src/main/java/com/example/websession/SessionCookieSettings.java:86`, enforced at `src/main/java/com/example/websession/SetCookieHeaderFactory.java:69-71`

**Vulnerable code:**
```java
// src/main/java/com/example/websession/SessionCookieSettings.java:86
        b.secure = requireBoolean(value(lookup, "SESSION_COOKIE_SECURE", "true"), "SESSION_COOKIE_SECURE");
```

**Why it is a problem:** The default is `true` and the cross-field rules at
`SessionCookieSettings.java:237-252` force `Secure` for `__Host-`/`__Secure-` prefixed names and for
`SameSite=None`, so the common paths are safe. But a deployment that sets both
`SESSION_COOKIE_NAME=SID` and `SESSION_COOKIE_SECURE=false` passes validation, and
`SetCookieHeaderFactory.build` then omits the attribute entirely — the session identifier is written
to a cookie the browser will attach to any future `http://` request to the origin. The TLS
precondition in `SessionCookieIssuer.java:85-89` is conditioned on `settings.secure()`, so turning
`Secure` off also turns that guard off: the identifier is now permitted to travel over cleartext in
both directions. A single environment variable, plausibly set during local development and carried
into a deployment, silently removes the component's main transport protection with no startup
warning.

**Fix:** Keep the escape hatch for local development, but make it explicit and loud rather than a
bare boolean: require a separate, deliberately awkward acknowledgement variable before accepting
`SESSION_COOKIE_SECURE=false`, so the insecure combination cannot be reached by flipping one flag.

```java
        b.secure = requireBoolean(value(lookup, "SESSION_COOKIE_SECURE", "true"), "SESSION_COOKIE_SECURE");
        if (!b.secure) {
            // Dropping Secure puts the session identifier on the wire in cleartext and also
            // disables the TLS precondition in SessionCookieIssuer. It must not be reachable
            // by flipping a single flag.
            if (!"i-accept-cleartext-sessions".equals(
                    value(lookup, "SESSION_COOKIE_INSECURE_ACKNOWLEDGED", ""))) {
                throw new IllegalArgumentException(
                        "SESSION_COOKIE_SECURE=false requires SESSION_COOKIE_INSECURE_ACKNOWLEDGED");
            }
        }
```

### SEC-06: Fixed-window counter permits a 2x burst across the window boundary
- **Severity:** Low
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/example/websession/FixedWindowRateLimiter.java:55-63`

**Vulnerable code:**
```java
// src/main/java/com/example/websession/FixedWindowRateLimiter.java:55-63
        Window updated = windows.compute(key, (k, existing) -> {
            if (existing == null || nowMillis - existing.startMillis() >= windowMillis) {
                return new Window(nowMillis, 1);
            }
            // Saturate rather than overflow into a negative count, which would reopen the gate.
            int next = existing.count() == Integer.MAX_VALUE ? existing.count() : existing.count() + 1;
            return new Window(existing.startMillis(), next);
        });
        return updated.count() <= permitsPerWindow;
```

**Why it is a problem:** The window start is anchored to the first request in the window, and the
counter resets wholesale when the window elapses. An attacker who spends the full budget in the last
instant of one window and the full budget again in the first instant of the next sends
`2 * permitsPerWindow` requests — 60 issuance attempts against the default of 30 — within a span
that can be milliseconds wide. The documented intent of the two budgets at
`SessionCookieIssuer.java:56-59` is to cap attempts per source and per subject, and the effective
short-term cap is twice what the operator configured. The window roll is otherwise correct and the
check-and-increment is atomic, so this is a precision limitation of the algorithm rather than a
logic error; it matters here only because the limiter is the component's sole anti-brute-force and
anti-lockout control.

**Fix:** Keep two adjacent counters and weight the previous window by how much of it still overlaps
the current instant (the standard sliding-window approximation). The state stays O(1) per key and
the update stays inside the single atomic `compute`, so the concurrency property is preserved.

```java
    private record Window(long startMillis, int count, int previousCount) {
    }

    // ...

        Window updated = windows.compute(key, (k, existing) -> {
            if (existing == null || nowMillis - existing.startMillis() >= 2 * windowMillis) {
                return new Window(nowMillis, 1, 0);
            }
            if (nowMillis - existing.startMillis() >= windowMillis) {
                // Roll: the window that just ended becomes the weighted predecessor rather
                // than being discarded, so a burst straddling the boundary still counts.
                return new Window(existing.startMillis() + windowMillis, 1, existing.count());
            }
            int next = existing.count() == Integer.MAX_VALUE ? existing.count() : existing.count() + 1;
            return new Window(existing.startMillis(), next, existing.previousCount());
        });
        long elapsed = nowMillis - updated.startMillis();
        double carryOver = updated.previousCount() * (1.0d - (double) elapsed / windowMillis);
        return updated.count() + carryOver <= permitsPerWindow;
```

### SEC-07: 48-bit truncated fingerprint used as the per-subject throttle key
- **Severity:** Low
- **CWE:** CWE-328: Use of Weak Hash
- **Location:** `src/main/java/com/example/websession/LogFingerprint.java:26`, consumed at `src/main/java/com/example/websession/SessionCookieIssuer.java:119`

**Vulnerable code:**
```java
// src/main/java/com/example/websession/LogFingerprint.java:26
    private static final int TAG_HEX_CHARS = 12;
```

**Why it is a problem:** 12 hex characters is 48 bits, which is an entirely reasonable length for a
log correlation tag — the class's stated purpose. The problem is that the same truncated tag is
reused as a security-relevant map key:

```java
// src/main/java/com/example/websession/SessionCookieIssuer.java:119
        boolean withinSubjectBudget = perSubjectLimiter.tryAcquire("s|" + fingerprint.of(subjectKey), now);
```

Two distinct subjects whose tags collide share one 20-per-minute bucket, so one principal's attempts
throttle the other's — the cross-tenant lockout the two-budget design is explicitly meant to avoid.
At the configurable ceiling of 1 000 000 tracked keys the birthday probability of at least one
collision is roughly 0.4 % per process lifetime, which is small but is a real and silent
availability coupling between unrelated accounts. The HMAC key is per-process and unexported, so an
attacker cannot *target* a collision offline; this is an accidental-collision issue, not a forgeable
one.

**Fix:** Separate the two uses. Keep the short tag for logs, and add a full-length (or at least
128-bit) tag for keying, so the rate-limiter's bucket identity is collision-free in practice while
log lines stay short. The `subjectKey` is already length-bounded at
`TrustedSession.java:27`, so key length is not a memory concern.

```java
    private static final int TAG_HEX_CHARS = 12;
    /** Keying needs collision resistance, not brevity: 128 bits, not 48. */
    private static final int KEY_HEX_CHARS = 32;

    /** Short tag for logs. Never use as a map key -- see {@link #keyFor}. */
    public String of(String value) {
        return tag(value, TAG_HEX_CHARS);
    }

    /** Full-width tag for use as a security-relevant key, e.g. a rate-limit bucket. */
    public String keyFor(String value) {
        return tag(value, KEY_HEX_CHARS);
    }
```

with the call site becoming:

```java
        boolean withinSubjectBudget = perSubjectLimiter.tryAcquire("s|" + fingerprint.keyFor(subjectKey), now);
```

### SEC-08: Unparseable client addresses collapse into one shared `"unknown"` rate-limit bucket
- **Severity:** Low
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `src/main/java/com/example/websession/ClientAddressResolver.java:57` and `73`, consumed at `src/main/java/com/example/websession/SessionCookieIssuer.java:97`

**Vulnerable code:**
```java
// src/main/java/com/example/websession/ClientAddressResolver.java:55-58
    private static String sanitize(String raw) {
        if (raw == null || raw.isEmpty() || raw.length() > MAX_ADDRESS_LENGTH) {
            return UNKNOWN;
        }
```

**Why it is a problem:** Refusing to let a hostile string become a map key is right, but the
replacement is a single shared constant. Every request whose source address does not parse — an
IPv6 literal carrying a `%` zone identifier, a Unix-domain or `AF_UNIX` front-end where the
container reports a non-IP `getRemoteAddr()`, or an address longer than the 45-character bound —
lands in the same `"a|unknown"` bucket and competes for one 30-per-minute budget. In a deployment
where that path is reached routinely, legitimate users throttle each other; where it is reached
rarely, a client that can induce it has found a cheap way to deny the endpoint to every other such
client. Note also that `resolve` only falls back from a bad forwarded entry to the direct address
(line 52) — a bad *direct* address has no further fallback.

**Fix:** Distinguish "no usable address" from "throttle everyone together". Fail closed for the
address-less case rather than pooling it: the component cannot enforce a per-source limit on a
request whose source it cannot identify, and pooling such requests is strictly worse than refusing
them. Expose the condition so the operator can see it, and log it.

```java
    /** Sentinel meaning "no per-source key could be derived"; callers must fail closed. */
    static final String UNRESOLVED = "unknown";
```

with the issuer refusing rather than pooling:

```java
        String clientAddress = addressResolver.resolve(request);
        if (ClientAddressResolver.UNRESOLVED.equals(clientAddress)) {
            // No per-source budget can be enforced for a request whose source cannot be
            // identified. Refuse rather than pooling every such request into one bucket.
            LOG.warn("Session cookie not issued: client address could not be resolved");
            return IssueOutcome.UNAVAILABLE;
        }
        if (!perAddressLimiter.tryAcquire("a|" + clientAddress, now)) {
            LOG.warn("Session cookie issuance throttled for source {}", fingerprint.of(clientAddress));
            return IssueOutcome.RATE_LIMITED;
        }
```

## 6. Verified Controls and Checks With No Finding

- **Session fixation (CWE-384) — structurally prevented.** The identifier is read only from the
  server-side request attribute `com.example.websession.SESSION_ID`
  (`SessionCookieIssuer.java:102`), which no client can set through a header, parameter, body, or
  cookie. Grepped the whole package: there is no `getParameter`, no `getCookies`, and no request-body
  read anywhere, so no code path accepts a caller-supplied identifier.
- **`Set-Cookie` header injection / HTTP response splitting (CWE-113).** Every segment of the header
  built at `SetCookieHeaderFactory.java:52-73` is constrained: the value passes
  `SessionIdValidator.isValid` (base64url only, 22–128 chars, `SessionIdValidator.java:37-51`), the
  name passes a character allowlist (`SessionCookieSettings.java:119-132`), the path rejects
  non-printables and `; , " \` (`SessionCookieSettings.java:134-146`), `SameSite` is one of three
  fixed strings (`SessionCookieSettings.java:148-155`), and `Max-Age` is a non-negative `long`.
  Confirmed CR, LF, NUL, space, quote, comma, semicolon, and backslash cannot enter the header.
- **Defence-in-depth re-validation.** `SetCookieHeaderFactory.issue` re-runs
  `SessionIdValidator.isValid` and throws rather than emitting an unvalidated header
  (`SetCookieHeaderFactory.java:32-36`), so a future caller that bypasses the issuer still fails
  closed.
- **Cookie attributes (`performing-security-headers-audit`).** `HttpOnly` is unconditional
  (`SetCookieHeaderFactory.java:68`), `SameSite` is always emitted and defaults to `Strict`
  (`SetCookieHeaderFactory.java:72`, `SessionCookieSettings.java:85`), `Path` is always explicit
  (`SetCookieHeaderFactory.java:58`), and no `Domain` attribute is ever emitted — verified by
  grepping the factory. The default name `__Host-SID` therefore satisfies the browser's `__Host-`
  prefix requirements, and `SessionCookieSettings.java:237-247` enforces them at startup.
- **Authorisation decided by server-side state (`testing-for-broken-access-control`).** The cookie is
  emitted only when `TrustedSessionService.lookupActiveSession` returns a present `Optional`
  (`SessionCookieIssuer.java:102-135`); a `null` return is normalised to empty
  (`SessionCookieIssuer.java:155-158`), a thrown exception returns `UNAVAILABLE`
  (`SessionCookieIssuer.java:108-112`), and a malformed identifier skips the lookup and is rejected.
  Every branch fails closed.
- **Fail-closed startup (CWE-636).** A missing or wrongly typed `TrustedSessionService`, or invalid
  configuration, throws `UnavailableException` from `init` (`SessionCookieServlet.java:57-67`), so
  the servlet never serves a request in a state where it could emit an unverified cookie.
- **HTTP method restriction and method-override bypass.** `doGet`, `doPut`, `doDelete`, `doHead`, and
  `doTrace` all return a fixed 405 with `Allow: POST`
  (`SessionCookieServlet.java:100-128`, `GenericResponse.java:36-42`); `doOptions` returns 204 with
  `Allow: POST`. Tested the override vector conceptually: `HttpServlet.service` dispatches on the
  real request method, and nothing in the package reads `X-HTTP-Method-Override`, so an override
  header cannot reach `doPost`.
- **Atomic check-then-act (CWE-367).** The read, window roll, increment, and decision all happen
  inside one `ConcurrentHashMap.compute` and the verdict is taken from the returned value, never
  from a second lookup (`FixedWindowRateLimiter.java:55-63`). The counter saturates at
  `Integer.MAX_VALUE` instead of overflowing negative, which would have reopened the gate
  (`FixedWindowRateLimiter.java:59-60`) — the CWE-190 case is explicitly handled.
- **Separate per-source and per-subject budgets.** Two independent limiter instances with
  independent counters (`SessionCookieIssuer.java:56-63`) and disjoint key prefixes `"a|"` and `"s|"`
  (`SessionCookieIssuer.java:97`, `119`), so exhausting one never consumes the other and an attacker
  who knows a victim's identity cannot lock them out through the source budget. Subject-budget
  exhaustion is reported as the generic `REJECTED`, not as 429, so it is not an existence oracle.
- **Double-issuance guard.** A per-request marker attribute prevents two `Set-Cookie` headers for one
  request (`SessionCookieIssuer.java:91-94`, set at `SessionCookieIssuer.java:132`).
- **TLS precondition.** When `Secure` cookies are configured, a non-TLS request is refused rather
  than having the identifier travel in cleartext to a cookie the browser would discard anyway
  (`SessionCookieIssuer.java:85-89`).
- **Committed-response handling.** `issue`, `expireSessionCookie`, `GenericResponse.write`, and
  `GenericResponse.writeMethodNotAllowed` all check `isCommitted()` first
  (`SessionCookieIssuer.java:81`, `147`, `GenericResponse.java:37`, `45`), and status is always set
  before the body is written (`GenericResponse.java:59-65`), so no outcome can be misreported.
- **Cookie lifetime bounded by the session's.** `Max-Age` is `min(configured, remaining server-side
  lifetime)` (`SessionCookieIssuer.java:165-170`), the configured value is capped at 24 hours
  (`SessionCookieSettings.java:33`), the provider's `remainingLifetimeSeconds` is validated as
  strictly positive and at most one year (`TrustedSession.java:34-36`), and the default of `0`
  yields a browser-session cookie with no `Max-Age` at all.
- **Sensitive data in logs (`testing-for-sensitive-data-exposure`).** Reviewed all ten `LOG.*`
  call sites. The session identifier and subject key appear only through `fingerprint.of(...)`
  (`SessionCookieIssuer.java:98`, `110`, `119`, `122-123`, `134-135`); no log statement carries a raw
  identifier, cookie value, or header value. The stack trace from a lookup failure goes to the log
  only (`SessionCookieIssuer.java:110`), never to the response.
- **Generic failure responses and response-size uniformity.** Four pre-encoded constant bodies with a
  fixed `Content-Length` (`GenericResponse.java:23-26`, `62`); "no such session", "expired", and
  "per-subject throttle" all collapse into one `REJECTED`/401 before anything leaves the process
  (`IssueOutcome.java:16-21`, `SessionCookieIssuer.java:121-124`). No exception message, reason code,
  or echoed identifier is ever returned.
- **Configuration error messages.** `SessionCookieSettings` names the offending key but never echoes
  its value (`SessionCookieSettings.java:114`, `121`, `128`, `136`, `142`, `154`, `165`, `173`,
  `176`), so a variable mistakenly holding a secret cannot reach a log. An explicitly empty value is
  a startup error rather than a silent fall back to the default
  (`SessionCookieSettings.java:110-116`) — the "reject, never substitute a permissive default" rule
  holds throughout.
- **Cryptography (`performing-cryptographic-audit-of-application`).** `LogFingerprint` uses
  HMAC-SHA256 with a 256-bit key generated by `SecureRandom` at construction
  (`LogFingerprint.java:29`, `32-34`); the key is never persisted, logged, exported, or read from
  configuration, and is zeroed in `close()` (`LogFingerprint.java:66-69`), which the servlet invokes
  from `destroy()` (`SessionCookieServlet.java:137-142`). The `GeneralSecurityException` path returns
  `"-"` and never surfaces the input (`LogFingerprint.java:50-53`). Intermediate buffers are zeroed
  (`LogFingerprint.java:54`, `60`). No weak algorithm, no ECB, no static IV, no hardcoded key.
  Verified the hex loop at `LogFingerprint.java:56-59` cannot read past the 32-byte MAC: it appends
  two characters per iteration up to 12, so it touches `mac[0..5]` only.
- **Hardcoded secrets (CWE-798).** Grepped the package and `pom.xml` for credentials, keys, tokens,
  and passwords. The only constants are attribute names, header names, configuration keys, JSON
  bodies, and the `0123456789abcdef` hex alphabet. Nothing in the repository would authenticate
  anywhere if someone ran it.
- **No injection sinks.** There is no SQL, no ORM, no command execution, no deserialization, no file
  or path access, no template rendering, no reflection, no outbound network call, and no XML or JSON
  parsing of untrusted input anywhere in the package — confirmed by grepping for the corresponding
  APIs. The whole OWASP A03 injection family and A08 deserialization family are therefore not
  reachable here. `ClientAddressResolver` deliberately performs no name resolution
  (`ClientAddressResolver.java:76-94` rejects anything that is not an IP literal), so the header
  cannot be turned into a DNS or SSRF primitive.
- **XSS (CWE-79).** The only response bodies are four fixed JSON constants served as
  `application/json;charset=UTF-8` with `X-Content-Type-Options: nosniff`
  (`GenericResponse.java:21`, `61`, `63`); no request data is reflected into any response body or
  header.
- **Caching of the identifier-bearing response.** `Cache-Control: no-store`, `Pragma: no-cache`,
  `Expires: 0`, and `Vary: Cookie` on the issuing response (`SessionCookieIssuer.java:175-178`), and
  `no-store` on every generic response including the 405 (`GenericResponse.java:64`), so a shared
  cache cannot hand the `Set-Cookie` to the next user.
- **Cookie deletion correctness.** `SetCookieHeaderFactory.expire` reuses the same name, path,
  `Secure`, and `SameSite` as the issued cookie and emits both `Max-Age=0` and a 1970 `Expires`
  (`SetCookieHeaderFactory.java:47-49`, `61-67`), so the browser actually drops the cookie instead of
  keeping the original alongside it. The Javadoc correctly warns that clearing the cookie must never
  be the only step in a logout.
- **Provider output treated as untrusted.** `TrustedSession` validates its own constructor arguments
  (`TrustedSession.java:29-37`), bounding `subjectKey` to 256 characters so it cannot be used to
  grow the rate-limiter's memory, and rejecting absurd lifetimes from a buggy or compromised
  provider.
- **Dependency provenance (CWE-1104).** `pom.xml` pins `jakarta.servlet-api` and `slf4j-api` to
  explicit versions from Maven Central with no snapshot, range, or remote-script dependency, and
  JUnit is test-scoped. No code is loaded from a shared or world-writable location.
- **Timing differences between failure branches (CWE-208) — reviewed, no finding.** The malformed
  branch skips the `TrustedSessionService` call (`SessionCookieIssuer.java:125`), so a malformed
  identifier is measurably faster than a well-formed unknown one. This is not exploitable here
  because the identifier is not client-suppliable: an attacker cannot submit candidate values to
  time. Noted rather than reported, but worth preserving if a future change ever makes the
  identifier caller-provided.
- **`LogFingerprint` close/use race — reviewed, no finding.** `of()` reads the `volatile closed` flag
  before computing (`LogFingerprint.java:41`), so a concurrent `close()` could in principle produce a
  tag over a partially zeroed key. This only occurs during shutdown and only affects log tag
  stability, not any security decision that outlives the process.
