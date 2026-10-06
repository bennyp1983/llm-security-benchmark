# Security Review: Post-Authentication Session Cookie Component (`com.security.session`)

## 1. Executive Summary

The component under review is a Java 17 / Jakarta Servlet 6 library that takes an
already-created server-side session identifier plus an authenticated user identifier and
returns that identifier to the browser in a hardened `Set-Cookie` header. It consists of a
handler (`PostAuthSessionCookieHandler`), an immutable cookie configuration with builder
validation (`SessionCookieConfig`), a `Set-Cookie` builder with CRLF/delimiter rejection and
token masking (`CookieSecurityUtil`), request/response abstractions with servlet adapters, a
dual-key in-memory rate limiter (`DualKeyBoundedRateLimiter`), and a reference server-side
session-state validator that performs an atomic single-claim (`InMemorySessionStateValidator`).

The baseline posture is good: defaults are `__Host-SESSIONID`, `Secure`, `HttpOnly`,
`SameSite=Strict`, `Path=/`, no `Domain`, session-lifetime cookie, `Cache-Control: no-store`,
strict allow-list validation of the session identifier, header-injection rejection, masked
logging, generic client error bodies, and a compare-and-set session claim. No hardcoded
secrets, no SQL/OS command/deserialization/file I/O, and no hand-rolled cryptography for
anything security-bearing were found.

The findings are therefore concentrated in the availability and configuration layers rather
than in the cookie-writing path itself. The most important are: a per-IP consecutive-failure
block that is never cleared when the rate-limit window rolls over, which turns the
anti-brute-force control into a permanent block for every user behind a shared NAT or proxy
(SEC-01); unauthenticated trust of `X-Forwarded-For` / `X-Forwarded-Proto` with no
trusted-proxy check, which lets a client both forge its rate-limit key and claim HTTPS on a
cleartext connection (SEC-02); and a builder that still permits a session cookie with
`Secure=false` and `requireSecureTransport=false` whenever the cookie name lacks a
`__Host-`/`__Secure-` prefix (SEC-03). Six lower-severity issues (rate-limiter eviction
bypass, caller-supplied regex, internal audit detail leaving the trust boundary, the
`char[]` wipe that cannot work, session consumed on a late failure, and the inherent
no-rotation session-fixation residue) are also reported.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/security/session/PostAuthSessionCookieHandler.java` | Core handler: validate inputs, check transport, rate-limit, claim session, emit cookie | Input validation, fail-closed error handling, dummy "constant time" work, masked logging, security headers, status codes |
| `src/main/java/com/security/session/CookieSecurityUtil.java` | Builds the `Set-Cookie` header; masking and constant-time compare helpers | Control-character/CRLF and delimiter rejection, attribute assembly, SHA-256 token fingerprinting, `MessageDigest.isEqual` |
| `src/main/java/com/security/session/SessionCookieConfig.java` | Immutable config + validating builder | Cookie name/path/domain/Max-Age validation, `__Host-`/`__Secure-` prefix rules, `Secure`/`HttpOnly`/`SameSite` flags, session/user-ID length and regex bounds, forwarded-header trust switch |
| `src/main/java/com/security/session/SameSitePolicy.java` | `SameSite` attribute enum | Emits `Strict`/`Lax`/`None` attribute values |
| `src/main/java/com/security/session/HttpRequestContext.java` | Request abstraction + servlet adapter | Client IP derivation (optionally from `X-Forwarded-For`), TLS determination (optionally from `X-Forwarded-Proto`), loose IP syntax check |
| `src/main/java/com/security/session/SimpleHttpRequestContext.java` | In-memory request stub | Header storage, no security decision of its own |
| `src/main/java/com/security/session/HttpResponseContext.java` | Response abstraction + servlet adapter | Header set/add (`Set-Cookie`), status, JSON body writing with explicit charset |
| `src/main/java/com/security/session/SimpleHttpResponseContext.java` | In-memory response stub | Captures headers/body for tests |
| `src/main/java/com/security/session/RateLimiter.java` | Rate-limiter SPI and result type | Contract for atomic acquire and outcome recording, `Retry-After` value |
| `src/main/java/com/security/session/DualKeyBoundedRateLimiter.java` | Per-IP, per-IP+account and per-account fixed-window limiter | Attacker-controlled map keys, bounded maps with eviction, consecutive-failure blocking, `ConcurrentHashMap.compute` atomicity |
| `src/main/java/com/security/session/SessionStateValidator.java` | SPI for server-side session verification and claim | Contract: verify existence, ownership, expiry; claim once |
| `src/main/java/com/security/session/InMemorySessionStateValidator.java` | Reference validator | Session registry bounded at 50k, revocation/expiry checks, constant-time user compare, `AtomicBoolean` single claim |
| `src/main/java/com/security/session/SessionValidationResult.java` | Validation outcome value object | Carries error code and internal audit message |
| `src/main/java/com/security/session/PostAuthResult.java` | Handler outcome value object | Carries HTTP status, error code and internal audit reason to the caller |
| `src/main/java/com/security/session/SecurityValidationException.java` | Validation exception | Separates client message from internal audit reason |
| `pom.xml` | Build definition | Pinned dependency versions (jakarta.servlet-api 6.0.0, slf4j 2.0.9, JUnit 5.10.0) from official coordinates, no custom/remote repositories |

Reviewed statically only; nothing in the source tree was executed, built, or imported. The
compiled artefacts under `target/` were not analysed (they are build output of the same
sources).

## 3. Skills Applied

- `review-code-for-security-vulnerabilities`: router skill — drove the per-file behaviour
  inventory in section 2 and the keyword set (cookies, session fixation, rate limiting,
  header injection, logging of secrets, trust boundaries, concurrency) used to select the
  skills below.
- `performing-security-headers-audit`: applied to `CookieSecurityUtil.buildSetCookieHeader`
  and `SessionCookieConfig.Builder.build`, specifically the skill's cookie-attribute
  checklist (`Secure`, `HttpOnly`, `SameSite`, `Path`, `Domain`, `Max-Age`) and its
  `__Host-`/`__Secure-` prefix rules, plus `PostAuthSessionCookieHandler.setSecurityHeaders`
  for `Cache-Control: no-store` on an authentication response (SEC-03).
- `testing-for-sensitive-data-exposure`: applied to every log statement in
  `PostAuthSessionCookieHandler`, to `CookieSecurityUtil.maskToken`, to the `char[]`
  overload's in-memory handling of the session token (SEC-07), and to the data crossing back
  to the caller in `PostAuthResult` / `SecurityValidationException` (SEC-06).
- `implementing-api-rate-limiting-and-throttling`: applied to `DualKeyBoundedRateLimiter` —
  window algorithm correctness, counter/penalty expiry, key derivation from client-controlled
  values, per-IP vs per-account key separation, bounded state, and `429` + `Retry-After`
  behaviour (SEC-01, SEC-02, SEC-04).
- `testing-api-authentication-weaknesses`: applied to the session-identifier trust boundary —
  `validateInputs`, `InMemorySessionStateValidator.validateAndClaimSession`, token entropy
  assumptions, fail-closed ordering, and token leakage into logs (SEC-09, and the verified
  controls in section 6).
- `testing-for-broken-access-control`: applied to
  `InMemorySessionStateValidator.validateAndClaimSession` to confirm the session→user binding
  is re-verified against server-side state and that a mismatch fails closed, so a caller
  cannot bind another user's session to its own cookie.
- `performing-csrf-attack-simulation`: applied to the `SameSite` configuration surface and
  the absence of a request-method check on the handler entrypoint (`SameSite=Strict` default
  verified in section 6; `SameSite=None` reachability noted under SEC-03).
- `testing-for-host-header-injection`: applied to `HttpRequestContext.fromServlet`, the only
  place where client-supplied headers influence a security decision (SEC-02); no `Host`-derived
  value reaches the cookie `Domain`, which is config-only.
- `performing-cryptographic-audit-of-application`: applied to `MessageDigest` use in
  `CookieSecurityUtil.maskToken` / `constantTimeEquals`,
  `InMemorySessionStateValidator`'s `MessageDigest.isEqual` user comparison, and the
  `performConstantTimeDummyWork` SHA-256 padding; no key material, cipher, or RNG is handled
  by this component (identifier generation is explicitly upstream).
- Behaviour reviewed against general OWASP Top 10 / CWE knowledge because no library skill
  matched: the `SessionCookieConfig.Builder` configuration trust boundary including the
  caller-supplied `Pattern.compile` input (CWE-20/CWE-1333, SEC-05); the check-then-act
  ordering between the session claim and cookie construction and the non-atomic sequencing
  across the three rate-limiter buckets (CWE-459/CWE-367, SEC-08); the `pom.xml` dependency
  pinning and repository hygiene (A06:2021); and the generic-response/identical-failure
  requirement (CWE-203/CWE-209, SEC-06).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Per-IP failure block never expires, permanently locking out every user behind a shared address | Medium | CWE-645 | `DualKeyBoundedRateLimiter.java:66-72` |
| SEC-02 | `X-Forwarded-For` / `X-Forwarded-Proto` trusted without a trusted-proxy check, forging rate-limit identity and TLS status | Medium | CWE-348 | `HttpRequestContext.java:42-68` |
| SEC-03 | Builder still permits a session cookie without `Secure` and over cleartext transport | Medium | CWE-614 | `SessionCookieConfig.java:167-180` |
| SEC-04 | Rate-limit state evicted in arbitrary order by attacker-driven growth, clearing the attacker's own penalties | Medium | CWE-770 | `DualKeyBoundedRateLimiter.java:192-230` |
| SEC-05 | Caller-supplied session-ID regex compiled without restriction (permissive pattern / catastrophic backtracking) | Low | CWE-1333 | `SessionCookieConfig.java:182-193` |
| SEC-06 | Internal audit details, including input lengths and configuration values, cross back to the caller | Low | CWE-209 | `PostAuthSessionCookieHandler.java:203-207` |
| SEC-07 | `char[]` entrypoint copies the session token into an immutable `String`, so the wipe is ineffective | Low | CWE-316 | `PostAuthSessionCookieHandler.java:90-98` |
| SEC-08 | Session is claimed before the cookie header is built; a later failure consumes the session with no rollback | Low | CWE-459 | `PostAuthSessionCookieHandler.java:153-178` |
| SEC-09 | Externally supplied identifier is issued verbatim with no post-authentication rotation (documented residual risk) | Low | CWE-384 | `CookieSecurityUtil.java:39` |

## 5. Detailed Findings

### SEC-01: Per-IP failure block never expires, permanently locking out every user behind a shared address

- **Severity:** Medium
- **CWE:** CWE-645: Overly Restrictive Account Lockout Mechanism
- **Location:** `src/main/java/com/security/session/DualKeyBoundedRateLimiter.java:66-72` (reset), `:104-108` (enforcement), `:179-189` (increment)

**Vulnerable code:**
```java
// DualKeyBoundedRateLimiter.java:66-72
        void resetIfExpired(long nowMs, long windowMillis) {
            if (nowMs - windowStartMs >= windowMillis) {
                windowStartMs = nowMs;
                count = 0;
            }
            lastAccessMs = nowMs;
        }
```
```java
// DualKeyBoundedRateLimiter.java:104-108
            if (counter.consecutiveFailures >= ipMaxConsecutiveFailures) {
                long retryAfter = Math.max(1, (windowMillis - (now - counter.windowStartMs)) / 1000);
                ipResult[0] = new EvaluationResult(false, "IP blocked due to excessive failures", retryAfter);
                return counter;
            }
```

**Why it is a problem:** `resetIfExpired` clears `count` when the fixed window rolls over but
never clears `consecutiveFailures`, and `recordOutcome` only resets it on a *successful*
claim (`DualKeyBoundedRateLimiter.java:181-183`) — which the blocked IP can no longer reach,
because `tryAcquire` returns `false` before the session claim is ever attempted
(`PostAuthSessionCookieHandler.java:140-150`). Once five failed attempts accumulate for an IP,
that IP is blocked forever as far as this limiter is concerned. The only escape is the
`purgeExpiredMap` sweep, which requires `now - lastAccessMs > windowMillis * 2`
(`:212`) — but `resetIfExpired` and `recordOutcome` refresh `lastAccessMs` on every attempt
(`:71`, `:180`), so a client that keeps retrying keeps its own block alive, and the sweep
only runs at all once a map exceeds `maxEntries` (`:193`). Because the key is the source IP,
an attacker who sends five bad session identifiers from a CGNAT address, corporate egress
proxy, VPN exit, or cloud load balancer permanently denies session-cookie issuance to every
legitimate user sharing that address. The `Retry-After` value returned to the client is also
misleading: it is computed from the rate-limit window even though the block does not expire
with that window. This directly defeats the component's stated anti-lockout goal
(`PostAuthSessionCookieHandler.java:25-26`).

**Fix:** Give the failure penalty its own expiring timestamp so the block decays, and reset
the penalty counter when the window rolls over. Keep the penalty keyed per IP+account as well
if a stronger per-source brake is needed, but never let a per-IP block become permanent.

```java
    private static final class WindowCounter {
        long windowStartMs;
        int count;
        int consecutiveFailures;
        long failureBlockUntilMs;   // new: explicit, expiring block
        long lastAccessMs;

        WindowCounter(long nowMs) {
            this.windowStartMs = nowMs;
            this.count = 0;
            this.consecutiveFailures = 0;
            this.failureBlockUntilMs = 0L;
            this.lastAccessMs = nowMs;
        }

        void resetIfExpired(long nowMs, long windowMillis) {
            if (nowMs - windowStartMs >= windowMillis) {
                windowStartMs = nowMs;
                count = 0;
                // Failure penalties decay with the window so a shared source IP
                // can never be locked out permanently.
                consecutiveFailures = 0;
            }
            if (failureBlockUntilMs != 0L && nowMs >= failureBlockUntilMs) {
                failureBlockUntilMs = 0L;
                consecutiveFailures = 0;
            }
            lastAccessMs = nowMs;
        }
    }

    // in tryAcquire, replacing the consecutiveFailures check:
            if (counter.failureBlockUntilMs > now) {
                long retryAfter = Math.max(1, (counter.failureBlockUntilMs - now) / 1000);
                ipResult[0] = new EvaluationResult(false, "IP temporarily blocked due to excessive failures", retryAfter);
                return counter;
            }

    // in recordOutcome, when !success:
                counter.consecutiveFailures++;
                if (counter.consecutiveFailures >= ipMaxConsecutiveFailures) {
                    counter.failureBlockUntilMs = now + failureBlockMillis; // e.g. 60_000L, bounded
                }
```

### SEC-02: `X-Forwarded-For` / `X-Forwarded-Proto` trusted without a trusted-proxy check, forging rate-limit identity and TLS status

- **Severity:** Medium
- **CWE:** CWE-348: Use of Less Trusted Source
- **Location:** `src/main/java/com/security/session/HttpRequestContext.java:42-68`

**Vulnerable code:**
```java
// HttpRequestContext.java:42-68
                if (config.isTrustForwardedHeaders()) {
                    String forwarded = request.getHeader(config.getTrustedProxyIpHeader());
                    if (forwarded != null && !forwarded.isBlank()) {
                        // Take the leftmost IP from forwarded header and sanitize
                        String firstIp = forwarded.split(",")[0].trim();
                        if (isValidIp(firstIp)) {
                            return firstIp;
                        }
                    }
                }
                String remoteAddr = request.getRemoteAddr();
                return (remoteAddr != null && !remoteAddr.isBlank()) ? remoteAddr : "0.0.0.0";
            }

            @Override
            public boolean isSecure() {
                if (request.isSecure()) {
                    return true;
                }
                if (config.isTrustForwardedHeaders()) {
                    String proto = request.getHeader("X-Forwarded-Proto");
                    if ("https".equalsIgnoreCase(proto)) {
                        return true;
                    }
                }
                return false;
            }
```

**Why it is a problem:** When `trustForwardedHeaders` is enabled — which is exactly the
configuration a deployment behind a load balancer will choose — the adapter accepts the
forwarded headers from *any* peer. It never checks that `request.getRemoteAddr()` is one of a
configured set of trusted proxies, and it takes the **leftmost** `X-Forwarded-For` element,
which is the element a client can inject outright. Two security decisions then run on
attacker-controlled data: (1) the rate-limiter key (`PostAuthSessionCookieHandler.java:120`,
`:140`), so an attacker rotating a forged header gets a fresh per-IP bucket and fresh failure
budget for every request, nullifying SEC-01's brake and the per-IP limit entirely — and can
also deliberately poison another user's IP bucket; and (2) the "is this request on TLS"
decision (`PostAuthSessionCookieHandler.java:132`), so sending `X-Forwarded-Proto: https`
over a plaintext HTTP connection passes the transport gate and the session cookie is written
into a cleartext response. The hardcoded `"X-Forwarded-Proto"` on line 62 also ignores the
configurable header name, so an operator who configures a different trusted header still gets
the stock one honoured for the protocol decision.

**Fix:** Require an explicit allow-list of trusted proxy addresses, verify the *direct* peer
against it before reading any forwarded header, parse `X-Forwarded-For` right-to-left past
trusted hops, and make the protocol header name configurable alongside the IP header.

```java
            @Override
            public String getRemoteAddr() {
                String peer = request.getRemoteAddr();
                String safePeer = (peer != null && !peer.isBlank()) ? peer : "0.0.0.0";
                if (!config.isTrustForwardedHeaders() || !config.isTrustedProxy(safePeer)) {
                    return safePeer;   // fail closed: ignore forwarded headers from untrusted peers
                }
                String forwarded = request.getHeader(config.getTrustedProxyIpHeader());
                if (forwarded == null || forwarded.isBlank()) {
                    return safePeer;
                }
                // Walk right-to-left, skipping hops we trust; the first untrusted hop is the client.
                String[] hops = forwarded.split(",");
                for (int i = hops.length - 1; i >= 0; i--) {
                    String hop = hops[i].trim();
                    if (!isValidIp(hop)) {
                        return safePeer;          // malformed chain -> do not guess
                    }
                    if (!config.isTrustedProxy(hop)) {
                        return hop;
                    }
                }
                return safePeer;
            }

            @Override
            public boolean isSecure() {
                if (request.isSecure()) {
                    return true;
                }
                String peer = request.getRemoteAddr();
                if (config.isTrustForwardedHeaders() && peer != null && config.isTrustedProxy(peer)) {
                    return "https".equalsIgnoreCase(request.getHeader(config.getTrustedProtoHeader()));
                }
                return false;
            }
```

### SEC-03: Builder still permits a session cookie without `Secure` and over cleartext transport

- **Severity:** Medium
- **CWE:** CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
- **Location:** `src/main/java/com/security/session/SessionCookieConfig.java:167-180`, enforcement gap at `:248-270`

**Vulnerable code:**
```java
// SessionCookieConfig.java:167-180
        public Builder secure(boolean secure) {
            this.secure = secure;
            return this;
        }

        public Builder partitioned(boolean partitioned) {
            this.partitioned = partitioned;
            return this;
        }

        public Builder requireSecureTransport(boolean requireSecureTransport) {
            this.requireSecureTransport = requireSecureTransport;
            return this;
        }
```

**Why it is a problem:** `build()` only enforces `Secure` when the cookie name carries a
`__Host-` or `__Secure-` prefix (`SessionCookieConfig.java:248-265`). A configuration such as
`SessionCookieConfig.builder().cookieName("SESSIONID").secure(false).requireSecureTransport(false).build()`
validates successfully, and `CookieSecurityUtil.buildSetCookieHeader` then omits the `Secure`
attribute because of the `if (config.isSecure())` guard (`CookieSecurityUtil.java:53-55`),
while `PostAuthSessionCookieHandler.java:132` skips the transport gate entirely. The session
identifier is then emitted in a plaintext response and replayed by the browser on every
subsequent `http://` request, where a network attacker can read it and hijack the session —
precisely scenario 3 of the security-headers checklist. The same gap lets a non-prefixed
cookie be scoped to a parent `Domain` (`:236-240`, `CookieSecurityUtil.java:68-71`), sharing
the session with every sibling subdomain, and lets a session cookie be built with
`SameSitePolicy.NONE` (`:268-270` only couples `None` to `Secure`, never rejects it), which
re-exposes the cookie to cross-site requests and removes the component's CSRF defence
(CWE-1275). Because `HttpOnly` is deliberately hardcoded (`:131`), the inconsistency is
clearly unintended: the component keeps one non-negotiable flag but leaves the other two
negotiable.

**Fix:** Treat this as a session-cookie-only configuration object and make `Secure`,
secure transport, and a non-`None` `SameSite` non-negotiable, as `HttpOnly` already is. If a
test/loopback escape hatch is genuinely needed, gate it behind an explicitly named insecure
factory that no production path uses.

```java
        private final boolean secure = true;                  // non-negotiable for session cookies
        private final boolean requireSecureTransport = true;  // non-negotiable for session cookies

        // secure(boolean) and requireSecureTransport(boolean) setters removed.

        public Builder sameSite(SameSitePolicy sameSite) {
            Objects.requireNonNull(sameSite, "sameSite policy cannot be null");
            if (sameSite == SameSitePolicy.NONE) {
                throw new SecurityValidationException("Invalid configuration",
                        "SameSite=None is not permitted for session cookies");
            }
            this.sameSite = sameSite;
            return this;
        }

        public SessionCookieConfig build() {
            // ... existing name / path / Max-Age validation ...

            // A session cookie must never be host-unbound.
            if (domain != null && !domain.isBlank()) {
                throw new SecurityValidationException("Invalid configuration",
                        "Session cookies must not specify a Domain attribute (host-only scope required)");
            }
            if (!"/".equals(path)) {
                throw new SecurityValidationException("Invalid configuration",
                        "Session cookies must specify Path='/'");
            }
            // ... existing prefix checks (now always satisfied) ...
            return new SessionCookieConfig(this);
        }
```

### SEC-04: Rate-limit state evicted in arbitrary order by attacker-driven growth, clearing the attacker's own penalties

- **Severity:** Medium
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `src/main/java/com/security/session/DualKeyBoundedRateLimiter.java:192-230`

**Vulnerable code:**
```java
// DualKeyBoundedRateLimiter.java:192-230
    private void ensureCapacity() {
        if (ipBuckets.size() > maxEntries || ipAccountBuckets.size() > maxEntries || accountBuckets.size() > maxEntries) {
            cleanupExpired();
            evictIfOverCapacity(ipBuckets);
            evictIfOverCapacity(ipAccountBuckets);
            evictIfOverCapacity(accountBuckets);
        }
    }

    private void cleanupExpired() {
        long now = clock.millis();
        purgeExpiredMap(ipBuckets, now);
        purgeExpiredMap(ipAccountBuckets, now);
        purgeExpiredMap(accountBuckets, now);
    }

    private void purgeExpiredMap(ConcurrentHashMap<String, WindowCounter> map, long now) {
        Iterator<Map.Entry<String, WindowCounter>> iterator = map.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, WindowCounter> entry = iterator.next();
            if (now - entry.getValue().lastAccessMs > windowMillis * 2) {
                iterator.remove();
            }
        }
    }

    private void evictIfOverCapacity(ConcurrentHashMap<String, WindowCounter> map) {
        if (map.size() <= maxEntries) {
            return;
        }
        // Remove oldest entries until under threshold
        int toRemove = map.size() - maxEntries;
        Iterator<String> iterator = map.keySet().iterator();
        while (iterator.hasNext() && toRemove > 0) {
            iterator.next();
            iterator.remove();
            toRemove--;
        }
    }
```

**Why it is a problem:** The comment claims "oldest entries" but `keySet().iterator()` walks
`ConcurrentHashMap` in hash-bucket order, which is a function of the key the attacker
supplies — eviction is effectively arbitrary and attacker-influenceable. Worse, crossing the
threshold in *any one* map triggers eviction in *all three*: an attacker who can grow
`ipAccountBuckets` or `accountBuckets` (keys are `ip|account` and `account`, both derived from
caller-supplied values, see `:89-91`) past `maxEntries` causes entries to be dropped from
`ipBuckets` too, including the attacker's own `count` and `consecutiveFailures` penalty. That
converts the limiter into a brute-force oracle with a self-service reset (CWE-307). The
threshold test is also `>` rather than `>=` and runs *before* insertion, so each map can
settle above `maxEntries`, and `purgeExpiredMap`/`evictIfOverCapacity` perform a full O(n)
scan of three maps inside a request path, which an attacker can trigger repeatedly to burn
CPU. Finally, the three `compute` calls at `:98`, `:127` and `:150` are individually atomic
but not atomic as a group, so a request rejected at step 2 or 3 has already consumed a slot in
the earlier buckets, slightly inflating counts against legitimate traffic.

**Fix:** Evict by a real recency metric rather than iteration order, never let pressure in one
key space discard another key space's state, enforce the bound at insertion time, and move the
sweep off the request path.

```java
    private void ensureCapacity() {
        // Each key space is bounded independently: pressure on one must never
        // discard penalty state belonging to another.
        enforceBound(ipBuckets);
        enforceBound(ipAccountBuckets);
        enforceBound(accountBuckets);
    }

    private void enforceBound(ConcurrentHashMap<String, WindowCounter> map) {
        if (map.size() < maxEntries) {
            return;
        }
        long now = clock.millis();
        purgeExpiredMap(map, now);
        if (map.size() < maxEntries) {
            return;
        }
        // Evict genuinely least-recently-used entries, never hash order.
        map.entrySet().stream()
           .sorted(Comparator.comparingLong(e -> e.getValue().lastAccessMs))
           .limit(Math.max(1, map.size() - maxEntries + 1))
           .map(Map.Entry::getKey)
           .forEach(map::remove);
    }
```
(For a multi-instance or hostile-traffic deployment, back the counters with a shared store —
e.g. Redis keys with a TTL — so the bound is per key with automatic expiry and no global
eviction decision is ever needed.)

### SEC-05: Caller-supplied session-ID regex compiled without restriction

- **Severity:** Low
- **CWE:** CWE-1333: Inefficient Regular Expression Complexity (also CWE-20: Improper Input Validation)
- **Location:** `src/main/java/com/security/session/SessionCookieConfig.java:182-193`

**Vulnerable code:**
```java
// SessionCookieConfig.java:182-193
        public Builder sessionIdConstraints(int minLength, int maxLength, String regexPattern) {
            if (minLength < 16) {
                throw new IllegalArgumentException("Minimum session ID length must be at least 16 characters for security entropy");
            }
            if (maxLength < minLength || maxLength > 512) {
                throw new IllegalArgumentException("Maximum session ID length must be between minLength and 512 characters");
            }
            this.minSessionIdLength = minLength;
            this.maxSessionIdLength = maxLength;
            this.sessionIdPattern = Pattern.compile(regexPattern);
            return this;
        }
```

**Why it is a problem:** The lengths are bounded but the pattern itself is accepted verbatim:
`regexPattern` is not null-checked (a `null` yields `NullPointerException` from
`Pattern.compile`, and a malformed pattern yields an unhandled `PatternSyntaxException`), it
is not required to be anchored or restrictive, and it is the *only* character-class gate on
the value that is written into the `Set-Cookie` header (`PostAuthSessionCookieHandler.java:210`).
A configuration supplying `"(?s).{16,512}"` passes validation for any content, and
`CookieSecurityUtil` only rejects control characters, `;`, `,`, space and tab
(`CookieSecurityUtil.java:85-112`) — so `"`, `\`, `=` and non-ASCII code points would reach
the cookie value, producing an out-of-spec `Set-Cookie` whose parsing differs across
browsers and intermediaries. The same entry point accepts a catastrophically backtracking
pattern (e.g. `"^([A-Za-z0-9]+)+$"`), which against a 512-character attacker-supplied
identifier makes every request a CPU-exhaustion vector. The same unrestricted
`Pattern.compile` applies to `userIdConstraints` at `:195-202`.

**Fix:** Validate the pattern as untrusted configuration: require non-null, bound its length,
require full anchoring, compile it once, and verify against the component's own allow-list
that the resulting pattern cannot admit characters that are illegal in a cookie value.

```java
        private static final Pattern TOKEN_CHARSET_ONLY = Pattern.compile("^\\^?\\[[A-Za-z0-9_.@\\\\\\-]+\\].*$");

        public Builder sessionIdConstraints(int minLength, int maxLength, String regexPattern) {
            if (minLength < 16) {
                throw new IllegalArgumentException("Minimum session ID length must be at least 16 characters for security entropy");
            }
            if (maxLength < minLength || maxLength > 512) {
                throw new IllegalArgumentException("Maximum session ID length must be between minLength and 512 characters");
            }
            if (regexPattern == null || regexPattern.length() > 256) {
                throw new SecurityValidationException("Invalid configuration",
                        "Session ID pattern must be non-null and at most 256 characters");
            }
            if (!regexPattern.startsWith("^") || !regexPattern.endsWith("$")) {
                throw new SecurityValidationException("Invalid configuration",
                        "Session ID pattern must be fully anchored with '^' and '$'");
            }
            if (regexPattern.contains(".") || !TOKEN_CHARSET_ONLY.matcher(regexPattern).matches()) {
                throw new SecurityValidationException("Invalid configuration",
                        "Session ID pattern must be a single bounded character class of cookie-safe characters");
            }
            try {
                this.sessionIdPattern = Pattern.compile(regexPattern);
            } catch (java.util.regex.PatternSyntaxException e) {
                throw new SecurityValidationException("Invalid configuration", "Malformed session ID pattern", e);
            }
            this.minSessionIdLength = minLength;
            this.maxSessionIdLength = maxLength;
            return this;
        }
```

### SEC-06: Internal audit details, including input lengths and configuration values, cross back to the caller

- **Severity:** Low
- **CWE:** CWE-209: Generation of Error Message Containing Sensitive Information
- **Location:** `src/main/java/com/security/session/PostAuthSessionCookieHandler.java:203-207` (detail construction), `:128`, `:163`, `:174` (returned via `PostAuthResult`), `SessionCookieConfig.java:221` / `:232` / `:238` (configuration echoed into exception messages)

**Vulnerable code:**
```java
// PostAuthSessionCookieHandler.java:202-207
        if (sessionId.length() < config.getMinSessionIdLength() || sessionId.length() > config.getMaxSessionIdLength()) {
            return ValidationOutcome.invalid("Session identifier length out of bounds: " + sessionId.length());
        }
        if (userId.length() > config.getMaxUserIdLength()) {
            return ValidationOutcome.invalid("User identifier length out of bounds: " + userId.length());
        }
```

**Why it is a problem:** The HTTP body is correctly generic
(`GENERIC_ERROR_RESPONSE`, `:236`), but the same precise audit strings are placed in
`PostAuthResult.getInternalAuditReason()` and handed back to the caller
(`:128`, `:163`, `:174`), where they carry the exact length of the submitted session
identifier, the distinction between "not found", "revoked", "expired", "user mismatch" and
"already claimed" from `InMemorySessionStateValidator` (`:85-108`), and — via
`SecurityValidationException` — the configured cookie name, path and domain
(`SessionCookieConfig.java:221`, `:232`, `:238`). Nothing in the component stops a caller from
serialising that field into its own response, logging it to a client-visible channel, or
surfacing it in a stack trace (`SecurityValidationException` passes the audit reason to
`super(...)` at `SecurityValidationException.java:12`), at which point the component's own
non-enumeration goal is lost. It is defence-in-depth rather than a direct leak, but it is the
kind of detail that should never leave the server-side audit path.

**Fix:** Keep the stable error *code* in the result object for the caller's control flow, and
confine free-text detail to the logger inside this component. Where detail is unavoidable,
pass it as structured fields that cannot be stringified into a response by accident.

```java
    // Value objects expose a code only; detail stays in the log.
    public static PostAuthResult failure(int statusCode, String errorCode) {
        return new PostAuthResult(false, statusCode, errorCode);
    }

    private PostAuthResult failClosed(HttpResponseContext response, int status, String errorCode, String auditReason)
            throws IOException {
        logger.warn("Request failed closed: code={}, detail={}", errorCode, auditReason); // server-side only
        response.setStatus(status);
        setSecurityHeaders(response);
        response.writeJsonBody(GENERIC_ERROR_RESPONSE);
        return PostAuthResult.failure(status, errorCode);
    }

    // And drop attacker-derived values from the detail strings themselves:
        if (sessionId.length() < config.getMinSessionIdLength() || sessionId.length() > config.getMaxSessionIdLength()) {
            return ValidationOutcome.invalid("Session identifier length out of bounds");
        }
```

### SEC-07: `char[]` entrypoint copies the session token into an immutable `String`, so the wipe is ineffective

- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `src/main/java/com/security/session/PostAuthSessionCookieHandler.java:90-98`

**Vulnerable code:**
```java
// PostAuthSessionCookieHandler.java:90-98
        try {
            String sessionId = (sessionIdChars != null) ? new String(sessionIdChars) : null;
            return handlePostAuthentication(request, response, sessionId, userId);
        } finally {
            if (sessionIdChars != null) {
                Arrays.fill(sessionIdChars, '\0');
            }
        }
```

**Why it is a problem:** This overload exists so a caller can hand over the session token in a
wipeable buffer, but the first thing it does is materialise an immutable `String` from it. That
`String` — along with the `StringBuilder` and header string produced in
`CookieSecurityUtil.buildSetCookieHeader` (`:38-78`) and the `getBytes` copies in
`maskToken` (`CookieSecurityUtil.java:128`) — cannot be zeroed and survives on the heap until
garbage collection, so the session identifier remains recoverable from a heap dump or core file
long after the request. The `Arrays.fill` gives the API the appearance of credential hygiene
without delivering it, which is the worse outcome: a caller may reasonably believe the token
was scrubbed.

**Fix:** Either keep the value in `char[]`/`byte[]` end to end — validating and appending
character by character and wiping every intermediate buffer — or remove the overload and
document plainly that the token lives in an immutable `String` for the request's duration.

```java
    /**
     * Jakarta Servlet entrypoint with a wipeable session token buffer.
     *
     * <p>The token is never copied into an immutable String: validation and
     * Set-Cookie assembly operate on char buffers, and every intermediate
     * buffer is zeroed in a finally block.
     */
    public PostAuthResult handlePostAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            char[] sessionIdChars,
            String userId) throws IOException {
        char[] headerChars = null;
        try {
            return handlePostAuthenticationChars(
                    HttpRequestContext.fromServlet(request, config),
                    HttpResponseContext.fromServlet(response),
                    sessionIdChars, userId);
        } finally {
            if (sessionIdChars != null) {
                Arrays.fill(sessionIdChars, '\0');
            }
            if (headerChars != null) {
                Arrays.fill(headerChars, '\0');
            }
        }
    }
```

### SEC-08: Session is claimed before the cookie header is built; a later failure consumes the session with no rollback

- **Severity:** Low
- **CWE:** CWE-459: Incomplete Cleanup
- **Location:** `src/main/java/com/security/session/PostAuthSessionCookieHandler.java:153-178`

**Vulnerable code:**
```java
// PostAuthSessionCookieHandler.java:166-178
        String setCookieHeader;
        try {
            setCookieHeader = CookieSecurityUtil.buildSetCookieHeader(config, sessionId);
        } catch (SecurityValidationException e) {
            performConstantTimeDummyWork();
            logger.error("Failed to build Set-Cookie header: reason={}, token={}",
                    e.getInternalAuditReason(), CookieSecurityUtil.maskToken(sessionId));
            return failClosed(response, 500, "COOKIE_BUILD_ERROR", e.getInternalAuditReason());
        }

        // 6. Record successful claim in rate limiter
        rateLimiter.recordOutcome(remoteIp, userId, true);
```

**Why it is a problem:** `validateAndClaimSession` (`:153`) flips the session's single-use
claim flag irreversibly (`InMemorySessionStateValidator.java:107`). Everything after that
point can still fail — the header build at `:169`, or the `IOException` that
`response.writeJsonBody` may throw at `:189` after the status and `Set-Cookie` have been
staged — and no path releases the claim or revokes the now-unusable session. The user is left
with a session that server-side state regards as issued but whose cookie never reached the
browser, so the only recovery is a full re-authentication; a client that retries gets
`ALREADY_CLAIMED`. The behaviour is fail-*closed*, which is the right direction, but the
cleanup is missing, and on the `IOException` path the rate limiter has already recorded a
success, clearing the IP's failure penalty for an attempt that did not complete.

**Fix:** Build and validate the header *before* the claim (it depends only on the config and
the already-validated identifier), and wrap the post-claim work so any failure explicitly
revokes or releases the claimed session.

```java
        // 4. Build the Set-Cookie header first: it can fail, and it has no side effects.
        String setCookieHeader;
        try {
            setCookieHeader = CookieSecurityUtil.buildSetCookieHeader(config, sessionId);
        } catch (SecurityValidationException e) {
            performConstantTimeDummyWork();
            logger.error("Failed to build Set-Cookie header: reason={}", e.getInternalAuditReason());
            return failClosed(response, 500, "COOKIE_BUILD_ERROR", e.getInternalAuditReason());
        }

        // 5. Claim the session only once issuance is guaranteed to be constructible.
        SessionValidationResult sessionResult = sessionValidator.validateAndClaimSession(sessionId, userId);
        if (!sessionResult.isSuccess()) {
            performConstantTimeDummyWork();
            rateLimiter.recordOutcome(remoteIp, userId, false);
            logger.warn("Session verification/claim failed: code={}", sessionResult.getErrorCode());
            return failClosed(response, 401, sessionResult.getErrorCode(), sessionResult.getAuditMessage());
        }

        // 6. Any failure after the claim must release it so the user is not stranded.
        boolean issued = false;
        try {
            response.setStatus(200);
            response.addHeader("Set-Cookie", setCookieHeader);
            setSecurityHeaders(response);
            response.writeJsonBody(GENERIC_SUCCESS_RESPONSE);
            issued = true;
        } finally {
            if (!issued) {
                sessionValidator.releaseClaim(sessionId, userId); // new SPI method; revoke if release is unsafe
            } else {
                rateLimiter.recordOutcome(remoteIp, userId, true);
            }
        }
        logger.info("Session cookie successfully established: ip={}, user={}, token={}",
                remoteIp, sanitizeForLog(userId), CookieSecurityUtil.maskToken(sessionId));
        return PostAuthResult.success();
```

### SEC-09: Externally supplied identifier is issued verbatim with no post-authentication rotation

- **Severity:** Low
- **CWE:** CWE-384: Session Fixation
- **Location:** `src/main/java/com/security/session/CookieSecurityUtil.java:39`; identifier accepted at `PostAuthSessionCookieHandler.java:109-113`

**Vulnerable code:**
```java
// CookieSecurityUtil.java:38-39
        StringBuilder sb = new StringBuilder(128);
        sb.append(config.getCookieName()).append('=').append(cookieValue);
```

**Why it is a problem:** The value written to the browser is the caller-supplied `sessionId`
unchanged. The component mitigates this well within its own boundary — the identifier must
exist in server-side state, belong to the claiming user, be unexpired, and be claimable
exactly once (`InMemorySessionStateValidator.java:83-109`) — but it cannot tell whether the
upstream authentication component *rotated* the identifier at the moment of login. If the
upstream reuses a pre-authentication identifier, an attacker who planted that identifier in
the victim's browser beforehand holds a valid authenticated session cookie, and this component
will faithfully re-issue it. The task statement mandates using an externally provided
identifier, so this is a residual design risk to be documented and pushed upstream rather than
a defect in this file; the single-claim check is what keeps it Low rather than High.

**Fix:** Make the rotation requirement explicit and enforceable at the boundary instead of
assumed: have the validator assert that the identifier was minted *after* the authentication
event it is being issued for, and reject identifiers that predate it.

```java
    // SessionStateValidator SPI, with the rotation requirement made explicit:
    /**
     * @param sessionId        identifier minted by the trusted authentication component
     * @param userId           authenticated user claiming the session
     * @param authenticatedAt  instant the authentication event completed
     * @return failure if the identifier predates {@code authenticatedAt}, i.e. it was not
     *         rotated at login and may have been fixated by an attacker
     */
    SessionValidationResult validateAndClaimSession(String sessionId, String userId, Instant authenticatedAt);

    // InMemorySessionStateValidator:
        if (record.getCreatedAt().isBefore(authenticatedAt)) {
            return SessionValidationResult.failure("SESSION_NOT_ROTATED",
                    "Session identifier predates the authentication event; rotation is required");
        }
```

## 6. Verified Controls and Checks With No Finding

- **`HttpOnly` cannot be disabled**: `SessionCookieConfig.java:131` declares
  `private final boolean httpOnly = true` with no setter, and
  `CookieSecurityUtil.java:58-60` always appends `HttpOnly` for that configuration — the
  cookie is never script-readable.
- **Secure defaults for every cookie attribute**: `SessionCookieConfig.java:125-140` defaults
  to `__Host-SESSIONID`, `Path=/`, no `Domain`, `Secure=true`, `SameSite=Strict`,
  `maxAgeSeconds=-1` (browser-session lifetime, so no `Max-Age` is emitted —
  `CookieSecurityUtil.java:48-50`), and `requireSecureTransport=true`. The default build is
  exactly what the cookie-attribute checklist asks for; SEC-03 concerns only what the builder
  *permits*, not what it defaults to.
- **RFC 6265bis cookie-prefix invariants**: `SessionCookieConfig.java:248-258` rejects a
  `__Host-` cookie that is not `Secure`, that carries a `Domain`, or whose `Path` is not `/`;
  `:261-265` rejects a non-`Secure` `__Secure-` cookie; `:268-270` rejects
  `SameSite=None` without `Secure`. `Partitioned` is only emitted together with `Secure`
  (`CookieSecurityUtil.java:74-76`).
- **HTTP response splitting / CRLF injection into `Set-Cookie`**: the cookie value is checked
  for the full control range `c <= 0x1F || c == 0x7F`
  (`CookieSecurityUtil.java:85-96`) and for `;`, `,`, space and tab
  (`:101-112`) before assembly, and `Path` and `Domain` are re-checked at
  `:43` and `:69`. The same checks are applied up front to `sessionId` and `userId` in
  `PostAuthSessionCookieHandler.java:218-224`. With the default identifier pattern
  `^[A-Za-z0-9_-]{16,128}$` (`SessionCookieConfig.java:136`) no header-breaking character can
  reach the response.
- **Bounded, allow-list input validation before any use**: `validateInputs`
  (`PostAuthSessionCookieHandler.java:193-227`) rejects null/blank, enforces
  min/max length against configuration bounds, and applies anchored character allow-lists to
  both `sessionId` and `userId` — type, length, and charset, in that order, before the value
  influences anything.
- **Session identifier is never logged in cleartext**: every log statement that references the
  token routes through `CookieSecurityUtil.maskToken` (`:127`, `:161`, `:173`, `:187`), which
  emits only the first 8 hex characters of a SHA-256 digest
  (`CookieSecurityUtil.java:122-135`). With the enforced ≥16-character identifier this leaves
  no practical path from a log line back to a usable session token.
- **Log injection via the account identifier**: `sanitizeForLog`
  (`PostAuthSessionCookieHandler.java:263-266`) strips CR, LF and tab from `userId` before
  logging, and the `userId` allow-list (`SessionCookieConfig.java:138`) already excludes them.
  The logged IP is constrained to hex digits, `.` and `:` by
  `HttpRequestContext.isValidIp` (`HttpRequestContext.java:85-96`) on the forwarded path and
  comes from the container otherwise.
- **No hardcoded credentials, keys, or secrets**: the only embedded constant is
  `DUMMY_SALT` (`PostAuthSessionCookieHandler.java:50`), used solely as timing padding in
  `performConstantTimeDummyWork` (`:254-261`); it authenticates nothing and grants nothing.
  No file writes, no command-line argument handling, and no secret-bearing output anywhere in
  the component.
- **Generic client-facing failure messages**: all three response bodies
  (`PostAuthSessionCookieHandler.java:43-48`) are fixed strings; `failClosed`
  (`:232-238`) writes `GENERIC_ERROR_RESPONSE` for every failure branch, so the body never
  distinguishes "session not found" from "user mismatch" from "already claimed". Every
  failure path also calls `performConstantTimeDummyWork` before responding. Residual
  observable difference: the HTTP status still separates input-validation and transport
  failures (400) from state failures (401) and throttling (429), which is conventional and
  does not disclose whether an account or session exists.
- **Fail-closed control flow**: null contexts (`:115-118`), failed validation
  (`:124-129`), insecure transport (`:132-137`), throttling (`:141-150`), failed session
  claim (`:154-164`) and header-build errors (`:170-175`) all return a failure result and
  write an error response; there is no branch in which a missing or failed check falls through
  to cookie issuance, and no permissive default is substituted for rejected input.
- **Authorisation decided by server-side state, not by the caller's claim**:
  `InMemorySessionStateValidator.validateAndClaimSession`
  (`InMemorySessionStateValidator.java:78-112`) looks the identifier up in the server-side
  registry and fails closed when it is absent, revoked, or expired, then compares the
  registered owner to the claiming `userId` with `MessageDigest.isEqual`
  (`:100-104`) — a length-safe constant-time comparison, correctly chosen over `String.equals`.
  No client-supplied value short-circuits any of these checks.
- **Atomic check-then-act**: the single-use claim uses
  `claimed.compareAndSet(false, true)` (`InMemorySessionStateValidator.java:107`), so two
  concurrent requests for the same identifier cannot both be issued a cookie; the rate-limiter
  read-modify-write of each bucket happens inside `ConcurrentHashMap.compute`
  (`DualKeyBoundedRateLimiter.java:98`, `:127`, `:150`), which holds the bin lock for the
  duration, so counters cannot be lost to interleaving. All counter mutation is confined to
  those `compute` bodies and to `computeIfPresent` in `recordOutcome` (`:179-189`).
- **Dual-key rate limiting exists and is keyed per source as well as per account**:
  `DualKeyBoundedRateLimiter` maintains separate per-IP, per-IP+account and per-account
  windows (`:31-33`, `:98-169`) with distinct limits (`:15-20`), and the handler returns
  `429` with a `Retry-After` header (`PostAuthSessionCookieHandler.java:145-148`) as the
  throttling checklist requires. The per-account global limit is deliberately higher than the
  per-IP+account limit so one abusive source cannot consume a victim's whole budget. The
  defects in the penalty lifetime and eviction are reported as SEC-01 and SEC-04; the keying
  structure itself is sound.
- **Bounded memory for all stored state**: rate-limiter maps are capped at
  `DEFAULT_MAX_ENTRIES = 10_000` with expiry-based purging
  (`DualKeyBoundedRateLimiter.java:15`, `:192-230`), keys are truncated to 128 characters
  (`:232-241`), and the session registry is capped at `MAX_ACTIVE_SESSIONS = 50_000` with
  expired-entry cleanup before it refuses new registrations
  (`InMemorySessionStateValidator.java:16`, `:67-73`).
- **Cache-control on the authentication response**: `setSecurityHeaders`
  (`PostAuthSessionCookieHandler.java:243-249`) sets
  `Cache-Control: no-store, no-cache, must-revalidate, private`, `Pragma: no-cache`,
  `Expires: 0`, `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY`, and is called
  on every response path including all failures — the `Set-Cookie` cannot be stored by a
  shared cache or proxy.
- **Response content type and charset are set explicitly**:
  `HttpResponseContext.java:57` sets `application/json; charset=UTF-8` before writing,
  avoiding charset-sniffing issues; bodies are fixed constants, so no user data is reflected
  into the response at all (no XSS surface in this component).
- **No injection sinks of the classic kinds**: the component performs no SQL or other database
  access, no OS command execution, no deserialization of untrusted data, no file or path
  handling, no XML/XSLT parsing, no reflection on caller-supplied names, and no outbound
  network calls — so SQL injection, command injection, insecure deserialization, path
  traversal, XXE and SSRF are all structurally absent rather than merely mitigated.
- **Cryptographic use is appropriate and minimal**: only SHA-256 via
  `MessageDigest.getInstance("SHA-256")` for log fingerprinting
  (`CookieSecurityUtil.java:127`) and `MessageDigest.isEqual` for constant-time comparison
  (`:144-147`, `InMemorySessionStateValidator.java:102`). No weak algorithm (MD5/SHA-1/DES),
  no ECB mode, no static IV, no custom cipher, no `java.util.Random` for security purposes,
  and no key material in the component — identifier generation is explicitly out of scope and
  delegated upstream.
- **Dependency hygiene**: `pom.xml:22-24` pins exact versions
  (jakarta.servlet-api 6.0.0, slf4j-api 2.0.9, JUnit 5.10.0) resolved from standard official
  coordinates with no custom, HTTP, or snapshot repositories declared, no plugin fetching
  remote scripts, and no code loaded from shared or world-writable locations. The build also
  compiles with `-Xlint:all -Werror` (`pom.xml:67-70`).
- **Platform mechanisms preferred over hand-rolled ones**: the component builds on the Jakarta
  Servlet API, `java.security.MessageDigest`, `java.util.regex`,
  `java.util.concurrent.ConcurrentHashMap`/`AtomicBoolean`, `java.time.Clock` (injectable, so
  no reliance on wall-clock statics) and SLF4J rather than reimplementing any of them. The one
  deliberate hand-roll — assembling the `Set-Cookie` string instead of using
  `jakarta.servlet.http.Cookie` — is justified, since the servlet `Cookie` API cannot emit
  `SameSite` or `Partitioned` portably; the manual path is paired with the explicit
  control-character and delimiter rejection noted above.
- **Request-method enforcement (reviewed, no finding raised)**:
  `HttpRequestContext.getMethod()` exists but the handler never consults it. This is not a
  vulnerability in itself — the component is invoked server-side by an already-authenticated
  flow rather than routed directly — but callers should restrict the endpoint to `POST` so the
  cookie-issuing action is not reachable by top-level `GET` navigation.
