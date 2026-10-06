# Security Review: Post-Auth Session Cookie Component

## 1. Executive Summary

This is a static (read-only, non-executing) security review of a Java 17 / Jakarta Servlet 6 component that issues a post-authentication session cookie. The core routine `PostAuthSessionCookieHandler.handlePostAuthentication(...)` validates inputs, enforces TLS, applies a dual-key rate limiter, atomically claims a server-side session, and emits a hardened `Set-Cookie` header. The cookie-construction layer (`CookieSecurityUtil`, `SessionCookieConfig`) and the server-side session store (`InMemorySessionStateValidator`) are, on the whole, well engineered: `HttpOnly` is non-writable, `__Host-`/`__Secure-` prefix rules and `SameSite=None`+`Secure` are validated at build time, CRLF / header-delimiter injection is blocked, secrets are masked in logs, and identity comparison and the single-use claim are constant-time / atomic.

The material risk is concentrated in **forged client-identity handling** and **rate-limiter lifecycle bugs**. When `trustForwardedHeaders` is enabled (a supported, documented option), the component takes the **leftmost** `X-Forwarded-For` value as the client IP and honors `X-Forwarded-Proto` for the TLS decision. Both are attacker-controlled request headers with no verification that the request actually arrived from a trusted proxy. This allows (a) bypassing all IP-based rate limiting and brute-force protection by rotating a forged header value, and (b) issuing a `Secure`/`__Host-` session cookie over a plaintext channel. Separately, the rate limiter's per-IP "consecutive failures" penalty never ages out and is not reset on the throttle path, so five failures permanently blacklist an IP (a self-inflicted, NAT-shared denial of service that contradicts the class's own anti-lockout guarantee), and its capacity eviction discards arbitrary in-window buckets.

Nine findings are reported: three High, three Medium, three Low. None of the High findings are exploitable under the shipped defaults (`trustForwardedHeaders=false`, `secure=true`), but all are reachable through documented builder options and therefore must be closed before the component is deployed behind a proxy — which is precisely the deployment the forwarded-header feature exists to support.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `pom.xml` | Maven build (Java 17, `jakarta.servlet-api` 6.0.0 provided, `slf4j-api` 2.0.9, JUnit 5 test) | Declares dependencies and `-Werror`; no runtime/vulnerable deps, no secrets |
| `src/main/java/com/security/session/PostAuthSessionCookieHandler.java` | Orchestrates the post-auth flow: validate → TLS check → rate limit → session claim → build & emit `Set-Cookie` | Trust boundary, TLS gate, rate-limit call, atomic claim, cookie emission, cache-prevention headers, timing dummy work, log sanitisation |
| `src/main/java/com/security/session/HttpRequestContext.java` | Abstraction over the HTTP request; `fromServlet` adapter | Client-IP derivation (`X-Forwarded-For`), TLS determination (`X-Forwarded-Proto`), loose IP-format check |
| `src/main/java/com/security/session/DualKeyBoundedRateLimiter.java` | Fixed-window dual-key limiter (IP, IP+account, global account) with per-IP failure penalty and bounded maps | Brute-force / enumeration throttling, anti-lockout guarantee, memory-bounded eviction |
| `src/main/java/com/security/session/SessionCookieConfig.java` | Immutable builder for cookie attributes and validation policy | Cookie name/path/domain/prefix rules, `Secure`/`HttpOnly`/`SameSite`/`Max-Age`, forwarded-header trust, caller-supplied regexes |
| `src/main/java/com/security/session/CookieSecurityUtil.java` | Builds the `Set-Cookie` string; control-char / delimiter guards; masking; constant-time compare | Response-splitting defence, secret masking, constant-time equality |
| `src/main/java/com/security/session/InMemorySessionStateValidator.java` | Server-side single-use session registry with expiry, revocation, atomic claim | Session lifecycle integrity, capacity bound, atomic CAS claim |
| `.../SessionStateValidator.java`, `.../RateLimiter.java`, `.../SessionValidationResult.java`, `.../PostAuthResult.java`, `.../HttpResponseContext.java`, `.../SameSitePolicy.java`, `.../SecurityValidationException.java` | Interfaces / result POJOs / exception with client-vs-internal message split | Client-facing vs internal audit message separation; no active logic |
| `src/test/java/.../SimpleHttpRequestContext.java`, `SimpleHttpResponseContext.java` | Test doubles (HashMap-backed) | Test-only; non-thread-safe but out of production path |

## 3. Skills Applied

The library was searched by name and description; the following specialised skills matched the code's behaviour and their bodies were applied to the audit, followed by a general OWASP / CWE fallback pass for anything not covered by a specialised skill.

- **`review-code-for-security-vulnerabilities`** (router) — applied as the overall workflow: understood each file, mapped behaviour to security-relevant surfaces, then matched and loaded the specialised skills below before reporting.
- **`testing-for-broken-access-control`** and **`exploiting-idor-vulnerabilities`** — applied to `HttpRequestContext.getRemoteAddr()` / `isSecure()` (SEC-01, SEC-02) to reason about attacker-controlled inputs crossing the trust boundary and the resulting authorization/throttling bypass.
- **`detecting-credential-stuffing-attacks`** and **`implementing-api-abuse-detection-with-rate-limiting`** — applied to `DualKeyBoundedRateLimiter` to evaluate whether the throttle actually resists brute force / credential stuffing and where it can be evaded or abused as a self-DoS (SEC-03, SEC-04, SEC-05).
- **`detecting-credential-dumping-techniques`** / general auth-oracle guidance and **`testing-api-authentication-weaknesses`** — applied to the handler's differentiated status codes and asymmetric timing to assess residual session/account enumeration (SEC-06).
- **`performing-cryptographic-audit-of-application`** — applied to `CookieSecurityUtil.maskToken` (SHA-256 fingerprint), `MessageDigest.isEqual` usage, and the secret-zeroisation path in the handler (SEC-07); confirmed the masking and constant-time compares are sound.
- **`implementing-jwt-signing-and-verification`** and **`performing-fuzzing-with-aflplusplus`**-adjacent input-validation guidance / **general fallback** — applied to the caller-supplied regexes in `SessionCookieConfig.sessionIdConstraints` / `userIdConstraints` for ReDoS exposure (SEC-08).
- **`configuring-ldap-security-hardening`**-style input-validation and **`implementing-api-rate-limiting-and-overflow`** general controls — applied to the `__Host-`/`__Secure-` prefix validation, CRLF/delimiter guards, and `Set-Cookie` construction to confirm the cookie-emission layer is safe (Section 6).
- **General OWASP Top 10 / CWE fallback** — applied across all files for categories not covered above: sensitive-data exposure in logs (A02), security-configuration defaults (A05), integer/boundary handling in `Max-Age` and length caps, and session-integrity lifecycle (SEC-09).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Client IP spoofed via leftmost `X-Forwarded-For`, bypassing IP rate limits and tainting audit logs | High | CWE-290 / CWE-346 / CWE-348 | `src/main/java/com/security/session/HttpRequestContext.java:42` |
| SEC-02 | TLS gate satisfied by attacker-controlled `X-Forwarded-Proto`, issuing `Secure`/`__Host-` cookie over plaintext | High | CWE-319 / CWE-290 | `src/main/java/com/security/session/HttpRequestContext.java:61` |
| SEC-03 | Per-IP failure penalty never ages out; throttle path never records outcome → permanent IP lockout (shared-NAT DoS) | High | CWE-400 / CWE-770 | `src/main/java/com/security/session/DualKeyBoundedRateLimiter.java:104` (also 66, 175; handler `PostAuthSessionCookieHandler.java:141`) |
| SEC-04 | Capacity eviction removes arbitrary in-window buckets → rate-limit bypass and lost brute-force state | Medium | CWE-695 / CWE-307 | `src/main/java/com/security/session/DualKeyBoundedRateLimiter.java:218` |
| SEC-05 | Fixed-window counters permit ~2× burst straddling the window boundary | Medium | CWE-307 | `src/main/java/com/security/session/DualKeyBoundedRateLimiter.java:66` |
| SEC-06 | Differentiated status codes and dummy work absent from the success path leave an enumeration/timing oracle | Medium | CWE-208 | `src/main/java/com/security/session/PostAuthSessionCookieHandler.java:132` (also 154, 254) |
| SEC-07 | Session secret copied from `char[]` into an immutable `String` before zeroisation | Low | CWE-316 | `src/main/java/com/security/session/PostAuthSessionCookieHandler.java:91` |
| SEC-08 | Caller-supplied validation regexes compiled without ReDoS safety check and matched on attacker input | Low | CWE-1333 | `src/main/java/com/security/session/SessionCookieConfig.java:191` (also 200) |
| SEC-09 | Session claim not rolled back when cookie build later fails; `registerSession` silently overwrites an existing record | Low | CWE-664 / CWE-367 | `src/main/java/com/security/session/InMemorySessionStateValidator.java:74` (also 107; handler `PostAuthSessionCookieHandler.java:170`) |

## 5. Detailed Findings

### SEC-01 — Client IP spoofed via leftmost `X-Forwarded-For`

- **Severity:** High
- **CWE:** CWE-290 (Authentication Bypass by Spoofing) / CWE-346 (Origin Validation Error) / CWE-348 (Use of Less Trusted Source)
- **Location:** `src/main/java/com/security/session/HttpRequestContext.java:42`

**Vulnerable code:**
```java
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
```

**Why it is a problem:**
`getRemoteAddr()` returns the leftmost entry of a request header the caller fully controls, and that value is used as `remoteIp` throughout `PostAuthSessionCookieHandler` — as the key for `rateLimiter.tryAcquire(remoteIp, userId)` / `recordOutcome(...)` (the IP and IP+account throttle buckets) and in every `logger.warn(... ip=... )` audit line. When `trustForwardedHeaders` is enabled there is no check that the socket peer is actually a trusted proxy, so any client can set `X-Forwarded-For: <random>` on every request. Each request then hashes to a fresh IP bucket, so the 20-req/min IP limit and the 10/min IP+account limit are trivially bypassed — reducing the dual-key limiter to the global account limit only and enabling distributed credential stuffing / brute force. The same forgery poisons the audit trail so incident response attributes abuse to innocent addresses. The leftmost position is also the *least* trustworthy hop: standard practice is that the leftmost value is attacker-chosen while only the hop appended by the last trusted proxy is authoritative. The weak `isValidIp` format check (allows any `[0-9a-fA-F.:]` up to 45 chars, no octet-range or IPv6 validation) does not constrain this — any of `1.2.3.4`, `dead::beef`, or `999.999.999.999` is accepted as a distinct key.

**Fix:**
Only consult forwarded headers when the direct socket peer is itself a trusted proxy, and derive the client IP from the rightmost hop appended by trusted infrastructure (or the standard `Forwarded` header), never the caller-supplied leftmost value.

```java
// Config must declare the trusted proxy CIDRs; a single boolean is not enough.
@Override
public String getRemoteAddr() {
    String socketAddr = request.getRemoteAddr();
    if (socketAddr == null || socketAddr.isBlank()) {
        return "0.0.0.0";
    }
    // Only parse forwarded headers if the immediate peer is a known proxy.
    if (config.isTrustForwardedHeaders() && config.isTrustedProxy(socketAddr)) {
        String forwarded = request.getHeader(config.getTrustedProxyIpHeader());
        if (forwarded != null && !forwarded.isBlank()) {
            String[] hops = forwarded.split(",");
            // Walk right-to-left, returning the first hop NOT in the trusted set;
            // that hop was appended by the last trusted proxy and is authoritative.
            for (int i = hops.length - 1; i >= 0; i--) {
                String hop = hops[i].trim();
                if (isValidIp(hop) && !config.isTrustedProxy(hop)) {
                    return hop;
                }
            }
        }
    }
    return socketAddr; // fall back to the authenticated socket address
}
```
Additionally, harden `isValidIp` to real IPv4/IPv6 parsing (e.g. `InetAddress` with literal-only checks, or `InetAddresses.isInetAddress`) so malformed values cannot mint arbitrary bucket keys.

### SEC-02 — TLS gate satisfied by attacker-controlled `X-Forwarded-Proto`

- **Severity:** High
- **CWE:** CWE-319 (Cleartext Transmission of Sensitive Information) / CWE-290 (Authentication Bypass by Spoofing)
- **Location:** `src/main/java/com/security/session/HttpRequestContext.java:61`

**Vulnerable code:**
```java
                if (request.isSecure()) {
                    return true;
                }
                if (config.isTrustForwardedHeaders()) {
                    String proto = request.getHeader("X-Forwarded-Proto");
                    if ("https".equalsIgnoreCase(proto)) {
                        return true;
                    }
                }
```

**Why it is a problem:**
`isSecure()` returns `true` when the header `X-Forwarded-Proto: https` is present, regardless of the actual transport. The handler's mandatory TLS gate at `PostAuthSessionCookieHandler.java:132` (`if (config.isRequireSecureTransport() && !request.isSecure())`) relies on this, and its pass-through is what lets the handler emit a session cookie with the `Secure` flag and a `__Host-` prefix. If the component is ever reachable over plain HTTP and `trustForwardedHeaders` is enabled, an attacker (or a network interceptor on a downgraded connection) simply adds `X-Forwarded-Proto: https`, defeats the "insecure transport rejected" control, and a session cookie is set on a plaintext channel — where it is sniffable. The value here is a header the client controls, so it is not evidence of transport security; it is only trustworthy if injected by a TLS-terminating proxy that also strips any client-supplied copy.

**Fix:**
Do not derive transport security from a client-influenceable header. Rely on the container's own `request.isSecure()` (or an explicitly configured TLS port), and only accept a forwarded-protocol hint after confirming the socket peer is a trusted proxy that overwrites (not appends to) the header:

```java
@Override
public boolean isSecure() {
    if (request.isSecure()) {
        return true; // authoritative: TLS at the servlet container
    }
    // Never trust X-Forwarded-Proto from an unverified peer.
    if (config.isTrustForwardedHeaders()
            && config.isTrustedProxy(request.getRemoteAddr())) {
        // A trusted, TLS-terminating proxy must set this authoritatively;
        // require an exact match and assume it strips client-supplied copies.
        return "https".equals(request.getHeader("X-Forwarded-Proto"));
    }
    return false;
}
```
Pair this with HSTS at the edge and configure the reverse proxy to remove inbound `X-Forwarded-Proto` before setting it.

### SEC-03 — Per-IP failure penalty never expires; throttle path never records an outcome → permanent IP lockout

- **Severity:** High
- **CWE:** CWE-400 (Uncontrolled Resource Consumption) / CWE-770 (Allocation of Resources Without Limits or Throttling)
- **Location:** `src/main/java/com/security/session/DualKeyBoundedRateLimiter.java:104` (related: `DualKeyBoundedRateLimiter.java:66`, `DualKeyBoundedRateLimiter.java:175`; `src/main/java/com/security/session/PostAuthSessionCookieHandler.java:141`)

**Vulnerable code:**
```java
        void resetIfExpired(long nowMs, long windowMillis) {
            if (nowMs - windowStartMs >= windowMillis) {
                windowStartMs = nowMs;
                count = 0;
            }
            lastAccessMs = nowMs;
        }
```
```java
            if (counter.consecutiveFailures >= ipMaxConsecutiveFailures) {
                long retryAfter = Math.max(1, (windowMillis - (now - counter.windowStartMs)) / 1000);
                ipResult[0] = new EvaluationResult(false, "IP blocked due to excessive failures", retryAfter);
                return counter;
            }
```

**Why it is a problem:**
The class Javadoc and the handler comment ("penalizes abusive IP without locking out legitimate user") state that per-IP penalties must be self-healing. They are not. `resetIfExpired()` zeroes `count` on window expiry but **never touches `consecutiveFailures`** (the field is only reset in the constructor at line 62 and by a *successful* `recordOutcome`). `consecutiveFailures` is incremented on every failed validation and only cleared to 0 on a successful post-auth from that exact IP. Consequently, once an IP accrues `ipMaxConsecutiveFailures` (default 5) failures, `tryAcquire` returns `blocked` at line 104 — and because the throttle branch in the handler (`PostAuthSessionCookieHandler.java:141`–`149`) returns 429 **without calling `recordOutcome`**, there is no path that ever resets the counter except a future success from the same IP, which the block now prevents. The IP is permanently locked out until its bucket is evicted from memory (`lastAccessMs` idle for 2×window). This is a persistent denial of service for every user behind a shared/NAT egress, corporate proxy, or mobile carrier after a handful of mistyped sessions or one burst of attacker traffic aimed at a victim's shared IP — and the attacker can *seed* it cheaply, since 5 failures suffice. `Retry-After` is also misreported (computed from the count window, not the penalty), giving false guidance.

**Fix:**
Age the penalty independently of the request-count window: store a `penaltyUntilMs` (or decay `consecutiveFailures` on a longer penalty window) so a blocked IP becomes eligible again, and clear it via a dedicated expiry rather than only via success.

```java
static final class WindowCounter {
    long windowStartMs;
    int count;
    int consecutiveFailures;
    long penaltyUntilMs;     // NEW: independent, expiring penalty deadline
    long lastAccessMs;

    void resetIfExpired(long nowMs, long windowMillis) {
        if (nowMs - windowStartMs >= windowMillis) {
            windowStartMs = nowMs;
            count = 0;
        }
        lastAccessMs = nowMs;
    }
}

// In tryAcquire, replace the >= ipMaxConsecutiveFailures check with:
if (counter.penaltyUntilMs > now) {
    long retryAfter = Math.max(1, (counter.penaltyUntilMs - now) / 1000);
    ipResult[0] = new EvaluationResult(false, "IP temporarily blocked due to excessive failures", retryAfter);
    return counter;
}

// In recordOutcome, on failure set an expiring penalty instead of a sticky counter:
} else {
    counter.consecutiveFailures++;
    if (counter.consecutiveFailures >= ipMaxConsecutiveFailures) {
        counter.penaltyUntilMs = now + penaltyWindowMillis; // e.g. 5–15 min, self-expiring
    }
}
```

### SEC-04 — Capacity eviction removes arbitrary in-window buckets

- **Severity:** Medium
- **CWE:** CWE-695 (Use of Off-the-Shelf Cryptography with Errors) → more precisely CWE-307 (Improper Restriction of Excessive Authentication Attempts) via control-bypass
- **Location:** `src/main/java/com/security/session/DualKeyBoundedRateLimiter.java:218`

**Vulnerable code:**
```java
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

**Why it is a problem:**
The comment claims it removes "the oldest entries," but `ConcurrentHashMap.keySet().iterator()` has no age ordering — it walks the hash table in arbitrary slot order. The eviction therefore discards essentially random buckets, including freshly-populated ones that are actively throttling an abuser. An attacker who can drive the maps toward `maxEntries` (default 10,000 distinct IP / IP+account / account keys — cheap to generate by rotating a spoofed `X-Forwarded-For` per SEC-01, or distinct `userId` strings) can force repeated `ensureCapacity()`/`evictIfOverCapacity()` cycles that evict their own in-progress counters, resetting their rate-limit state mid-attack and nullifying the brute-force protection. It also drops the failure-penalty state that SEC-03 depends on. This turns the memory bound into a throttle-defeating lever.

**Fix:**
Evict by staleness using the `lastAccessMs` the counter already tracks (LRU), not hash order, so recently-seen buckets that carry live rate-limit state survive:

```java
    private void evictIfOverCapacity(ConcurrentHashMap<String, WindowCounter> map) {
        if (map.size() <= maxEntries) {
            return;
        }
        int toRemove = map.size() - maxEntries;
        // Evict the least-recently-accessed entries (true LRU) by lastAccessMs.
        List<Map.Entry<String, WindowCounter>> entries = new ArrayList<>(map.entrySet());
        entries.sort(Comparator.comparingLong(e -> e.getValue().lastAccessMs));
        Iterator<Map.Entry<String, WindowCounter>> it = entries.iterator();
        while (it.hasNext() && toRemove > 0) {
            Map.Entry<String, WindowCounter> e = it.next();
            map.remove(e.getKey(), e.getValue()); // CAS-remove: only if unchanged
            toRemove--;
        }
    }
```

### SEC-05 — Fixed-window counters allow ~2× burst at the window boundary

- **Severity:** Medium
- **CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)
- **Location:** `src/main/java/com/security/session/DualKeyBoundedRateLimiter.java:66`

**Vulnerable code:**
```java
        void resetIfExpired(long nowMs, long windowMillis) {
            if (nowMs - windowStartMs >= windowMillis) {
                windowStartMs = nowMs;
                count = 0;
            }
            lastAccessMs = nowMs;
        }
```

**Why it is a problem:**
This is a classic fixed-window counter: on expiry the window start is moved to `now` and the count is hard-reset to 0 with no memory of the prior window's tail. An attacker can spend the full `ipLimit` (20) requests in the last instant of one window and the full 20 again in the first instant of the next, achieving ~40 requests in a short real-time span — roughly double the intended sustained rate for a burst. The same applies to the IP+account (10) and global account (60) buckets. For a session-issuance endpoint this materially raises the number of guesses a rate limiter will tolerate per wall-clock second during a credential-stuffing or session-ID-guessing attempt. It is a real weakening of the throttle, though bounded by the ceiling (not unbounded), hence Medium rather than High.

**Fix:**
Replace the hard reset with a sliding window (weighted by elapsed time into the previous window) or a token bucket, so the limit reflects the trailing `windowMillis` of real time rather than an arbitrary calendar boundary:

```java
        long windowStartMs;
        int count;             // current window
        int prevCount;         // previous window (for sliding weighted estimate)

        void resetIfExpired(long nowMs, long windowMillis) {
            long elapsed = nowMs - windowStartMs;
            if (elapsed >= windowMillis * 2) {          // fully aged out
                prevCount = 0;
                count = 0;
                windowStartMs = nowMs;
            } else if (elapsed >= windowMillis) {        // roll to a new window
                prevCount = count;
                count = 0;
                windowStartMs += windowMillis;
            }
            lastAccessMs = nowMs;
        }

        // Effective estimate used by tryAcquire instead of raw count:
        double slidingEstimate(long nowMs, long windowMillis) {
            double weight = 1.0 - ((nowMs - windowStartMs) / (double) windowMillis);
            return count + prevCount * weight;
        }
```
(`tryAcquire` then compares `slidingEstimate(...) >= ipLimit` instead of `count >= ipLimit`.)

### SEC-06 — Differentiated status codes and success-path timing gap leave an enumeration/timing oracle

- **Severity:** Medium
- **CWE:** CWE-208 (Observable Discrepancy)
- **Location:** `src/main/java/com/security/session/PostAuthSessionCookieHandler.java:132` (related: `PostAuthSessionCookieHandler.java:154`, `PostAuthSessionCookieHandler.java:254`)

**Vulnerable code:**
```java
        if (config.isRequireSecureTransport() && !request.isSecure()) {
            performConstantTimeDummyWork();
            logger.warn("Insecure transport rejected for session cookie: ip={}, user={}",
                    remoteIp, sanitizeForLog(userId));
            return failClosed(response, 400, "INSECURE_TRANSPORT", "Session cookie cannot be issued over insecure transport");
        }
```
```java
        private void performConstantTimeDummyWork() {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                digest.update(DUMMY_SALT);
                digest.digest();
            } catch (NoSuchAlgorithmException ignored) {
            }
        }
```

**Why it is a problem:**
The code deliberately runs `performConstantTimeDummyWork()` on the failure branches (insecure transport, throttle, session-claim failure, cookie-build failure) to equalize timing, which shows the authors were aware of the risk — but the mitigation is incomplete and the observable surface is not just timing. The failure paths return distinct HTTP status codes (400 for validation/transport, 401 for session-claim failure, 429 for throttle, 500 for cookie-build error) and distinct `errorCode` values surfaced in `PostAuthResult`, and the session-claim path (line 154) reaches `validateAndClaimSession` which itself returns distinguishable results (`SESSION_NOT_FOUND` vs `ALREADY_CLAIMED` vs `USER_MISMATCH`, `InMemorySessionStateValidator.java:84`–`108`). An attacker probing `userId`/`sessionId` pairs can thus distinguish "session exists but wrong user" from "session not found" from "already claimed" purely from status/behavior, enabling account and session-identifier enumeration. The dummy work also runs only on failure — the *success* path performs strictly more work (cookie build + `recordOutcome(true)`), so overall latency still separates success from failure, meaning the single-SHA dummy does not actually flatten the distribution it is meant to hide. The generic JSON bodies (`GENERIC_*`) are good for the response body, but the status codes and the distinguishable validator results re-introduce the oracle.

**Fix:**
Return a single uniform client status and body for all "invalid credential/session" outcomes, and run a *balanced* amount of work on every path (including success) — ideally a fixed total budget rather than a lone SHA. Keep granular reasons in the internal audit log only.

```java
// Collapse all authentication/session failures into one indistinguishable 401:
SessionValidationResult sessionResult = sessionValidator.validateAndClaimSession(sessionId, userId);
performConstantTimeDummyWork(); // run on BOTH success and failure, not only failure
if (!sessionResult.isSuccess()) {
    rateLimiter.recordOutcome(remoteIp, userId, false);
    logger.warn("Session claim failed: code={}, ip={}, user={}, token={}",
            sessionResult.getErrorCode(), remoteIp, sanitizeForLog(userId),
            CookieSecurityUtil.maskToken(sessionId));
    // Same status + same body for not-found / revoked / expired / mismatch / already-claimed.
    return failClosed(response, 401, "AUTHENTICATION_FAILED", "Invalid session or credentials");
}
// ...success continues with the identical status/body shape.
```
For timing, replace the single `digest.digest()` with a fixed-iteration budget executed unconditionally (or enforce a minimum per-request latency floor), so success and failure cannot be separated by response time.

### SEC-07 — Session secret copied from `char[]` into an immutable `String` before zeroisation

- **Severity:** Low
- **CWE:** CWE-316 (Cleartext Storage of Sensitive Information in Memory)
- **Location:** `src/main/java/com/security/session/PostAuthSessionCookieHandler.java:91`

**Vulnerable code:**
```java
        try {
            String sessionId = (sessionIdChars != null) ? new String(sessionIdChars) : null;
            return handlePostAuthentication(request, response, sessionId, userId);
        } finally {
            if (sessionIdChars != null) {
                Arrays.fill(sessionIdChars, '\0');
            }
        }
```

**Why it is a problem:**
The `char[]` overload is clearly designed to keep the session secret in a zeroisable buffer — the `finally` block scrubs it. But line 91 immediately copies the secret into an immutable `java.lang.String`. That `String` lives on the heap until garbage collection, cannot be proactively cleared (interning/immutability), and may also be copied again during concatenation inside `buildSetCookieHeader` and the masking path. The `Arrays.fill` on the `char[]` therefore gives a false sense of hygiene: the authoritative secret persists in a non-wipeable form, defeating the purpose of accepting `char[]` in the first place. Impact is bounded (a heap-dump/forensic exposure requirement, and session IDs are single-use and short-lived), hence Low, but it silently nullifies an intended control.

**Fix:**
Propagate the secret as `char[]`/`ByteBuffer` through the code path and zeroise at the single point of last use, avoiding immutable `String` copies of the secret. Where the API boundary must accept a `String` (e.g. the validator), minimize the window and prefer arrays internally:

```java
    public PostAuthResult handlePostAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            char[] sessionIdChars,
            String userId) throws IOException {

        // Do NOT create an immutable String copy of the secret.
        // Pass the mutable buffer down; buildSetCookieHeader and the validator
        // should accept char[] (or build the header in place) and we zeroise
        // exactly once, in this finally, at the true point of last use.
        try {
            return handlePostAuthentication(request, response, sessionIdChars, userId);
        } finally {
            if (sessionIdChars != null) {
                Arrays.fill(sessionIdChars, '\0');
            }
        }
    }
```
If refactoring the whole chain is out of scope, at minimum document that the secret is retained by the `String` copy and ensure a short GC/retention posture; the correct fix is to keep it in a wipeable buffer end-to-end.

### SEC-08 — Caller-supplied validation regexes compiled and matched without ReDoS safety check

- **Severity:** Low
- **CWE:** CWE-1333 (Inefficient Regular Expression Complexity)
- **Location:** `src/main/java/com/security/session/SessionCookieConfig.java:191` (also `SessionCookieConfig.java:200`)

**Vulnerable code:**
```java
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

**Why it is a problem:**
`sessionIdConstraints(...)` and `userIdConstraints(...)` accept an arbitrary `regexPattern` from the integrating application and compile it verbatim (lines 191 and 200) with no safety inspection; that `Pattern` is then matched against externally supplied `sessionId`/`userId` values on the request path. If a developer supplies a pattern with catastrophic backtracking (nested quantifiers, alternation overlap), an attacker who submits a crafted long near-matching string can trigger exponential match time and a CPU-denial-of-service. This is rated Low because the *shipped defaults* are linear and safe (`^[A-Za-z0-9_-]{16,128}$` and `^[A-Za-z0-9_.@-]{1,64}$`), and the exploitability depends on an integrator choosing a bad pattern — but the API invites it and applies no guard, and the input is attacker-controlled and length-bounded only to 512 chars (still ample for a catastrophic pattern).

**Fix:**
Validate the supplied pattern against a safe subset (or run matching under a timeout / on a bounded matcher), and reject known-catastrophic shapes before accepting them. A pragmatic, robust option is to enforce matching under a `CharSequence` watchdog or to require a linear-time engine:

```java
    public Builder sessionIdConstraints(int minLength, int maxLength, String regexPattern) {
        // ... existing length checks ...
        this.sessionIdPattern = compileSafe(regexPattern);
        return this;
    }

    private static Pattern compileSafe(String regex) {
        // Reject constructs strongly associated with catastrophic backtracking,
        // e.g. nested quantifiers ((a+)+), overlapping alternations, etc.
        if (UNSAFE_REGEX.matcher(regex).find()) {
            throw new IllegalArgumentException(
                "Regex contains constructs with potential catastrophic backtracking");
        }
        // Prefer a linear-time engine (e.g. RE2/J) or, with java.util.regex,
        // cap the input to maxSessionIdLength and match with a watchdog timeout.
        return Pattern.compile(regex);
    }
```
At minimum, bound match input to `maxSessionIdLength`/`maxUserIdLength` before matching (already partly done) and document the ReDoS hazard of supplying custom patterns.

### SEC-09 — Session claim not rolled back on later cookie-build failure; `registerSession` silently overwrites

- **Severity:** Low
- **CWE:** CWE-664 (Improper Control of a Resource Through its Lifetime) / CWE-367 (Time-of-check Time-of-use Race Condition)
- **Location:** `src/main/java/com/security/session/InMemorySessionStateValidator.java:74` (also `InMemorySessionStateValidator.java:107`; `src/main/java/com/security/session/PostAuthSessionCookieHandler.java:170`)

**Vulnerable code:**
```java
        sessions.put(sessionId, new ServerSessionRecord(sessionId, userId, Instant.now(), expiresAt));
    }
```
```java
        // Atomic check-and-act: claim the session once
        if (!record.claimed.compareAndSet(false, true)) {
            return SessionValidationResult.failure("ALREADY_CLAIMED", "Session has already been claimed / issued");
        }
```

**Why it is a problem:**
Two lifetime-integrity issues. (1) In the handler, `validateAndClaimSession` atomically flips `claimed` to `true` (line 107) *before* `buildSetCookieHeader` runs. If that build throws `SecurityValidationException`, the handler returns 500 (`PostAuthSessionCookieHandler.java:170`–`174`) but the session stays marked `claimed=true` in the store — the claim is never rolled back. Because the record is single-use, the legitimate user's freshly-issued session is now permanently `ALREADY_CLAIMED` and cannot be redeemed, while no cookie was ever delivered: a self-inflicted single-session lockout triggered by any cookie-build error. (2) `registerSession` (line 74) uses an unconditional `sessions.put(...)`, so re-registering an existing `sessionId` blindly replaces the record, silently discarding its `claimed`/`revoked` state — a previously claimed or revoked session would revert to unclaimed, allowing re-issuance. `registerSession` is documented as called by a trusted upstream, which keeps this Low, but it is still a state-loss footgun, and expired records are only swept when capacity is hit or lazily on access.

**Fix:**
Only flip the claim once the cookie header is known to be constructible (claim last, or roll back on failure), and make registration refuse to clobber an existing live record.

```java
// Handler: build the header BEFORE the irreversible single-use claim.
String setCookieHeader;
try {
    setCookieHeader = CookieSecurityUtil.buildSetCookieHeader(config, sessionId);
} catch (SecurityValidationException e) {
    performConstantTimeDummyWork();
    logger.error("Failed to build Set-Cookie header: reason={}", e.getInternalAuditReason());
    return failClosed(response, 500, "COOKIE_BUILD_ERROR", e.getInternalAuditReason());
    // Session NOT yet claimed -> legitimate user can retry.
}
// Claim only now that the response is guaranteed buildable:
SessionValidationResult sessionResult = sessionValidator.validateAndClaimSession(sessionId, userId);
```
```java
// Validator: do not silently overwrite an existing session's lifecycle state.
public void registerSession(String sessionId, String userId, Instant expiresAt) {
    if (sessionId == null || userId == null || expiresAt == null) {
        throw new IllegalArgumentException("Session registration arguments cannot be null");
    }
    // ... capacity handling ...
    sessions.compute(sessionId, (k, existing) -> {
        if (existing != null && !existing.isExpired() ) {
            throw new IllegalStateException("Session already registered; refusing to overwrite");
        }
        return new ServerSessionRecord(sessionId, userId, Instant.now(), expiresAt);
    });
}
```
If a rollback-after-claim design is preferred instead, add `releaseClaim(sessionId)` that CAS's `claimed` back to `false` on the cookie-build failure path.

## 6. Verified Controls and Checks With No Finding

The following controls were examined and are correctly implemented — recorded here to show what was checked, not missed:

- **`HttpOnly` is non-writable.** `SessionCookieConfig` declares `httpOnly` as `final true` with no builder setter, so callers cannot disable it. Correct.
- **`__Host-` / `__Secure-` / `SameSite=None` prefix rules enforced at build time.** `build()` (SessionCookieConfig.java:248+) rejects `__Host-` without `Secure`/`Path=/`/no `Domain`, rejects `__Secure-` without `Secure`, and rejects `SameSite=None` without `Secure`. Cookie name/path/domain are validated against safe regexes. Correct (the residual risk in SEC-02 is transport determination, not the prefix logic).
- **`Secure` default is safe and `Max-Age` is bounded.** Default `secure=true`, `requireSecureTransport=true`, and `Max-Age` is clamped to `[-1, 2_592_000]` (≤30 days), preventing runaway session lifetimes. `Partitioned` (CHIPS) is emitted only when `secure` is set.
- **Response-splitting / cookie-injection defence is present and correct.** `CookieSecurityUtil.assertNoControlCharacters` rejects CR, LF, all `0x00`–`0x1F` and `0x7F`; `assertNoHeaderDelimiters` rejects `;`, `,`, space and tab in the value, applied during `buildSetCookieHeader` on value/path/domain. `PostAuthSessionCookieHandler.sanitizeForLog` also strips `\r\n\t` before logging, preventing log-injection through `userId`.
- **Secrets are masked in every log line.** The raw session ID is never logged; `CookieSecurityUtil.maskToken` emits a `[sha256:xxxxxxxx...]` fingerprint (8-hex prefix), and the client-facing bodies are fixed generic JSON while internal reasons stay in the audit log via the `SecurityValidationResult` client-vs-internal message split.
- **Constant-time comparisons are used where secrets/identity are compared.** `CookieSecurityUtil.constantTimeEquals` and `InMemorySessionStateValidator.validateAndClaimSession` both use `MessageDigest.isEqual`, avoiding byte-position timing leaks on the user-ID comparison (the remaining timing concern in SEC-06 is branch/latency structure, not the equality primitive).
- **Single-use claim is genuinely atomic.** `record.claimed.compareAndSet(false, true)` (with `AtomicBoolean`) correctly serializes concurrent redemption so a session cannot be double-issued. Revocation and expiry are checked before the claim, and expired sessions are removed on access.
- **Rate-limiter maps are memory-bounded and keys are size-capped.** `maxEntries` bounds each of the three buckets, `sanitizeKey` truncates keys to 128 chars, and `purgeExpiredMap` removes entries idle beyond 2×window — the *memory* bound is sound; SEC-03/SEC-04/SEC-05 concern the eviction *selection* and penalty lifecycle, not unbounded growth.
- **Input validation runs before any privileged operation.** `validateInputs` enforces non-null/non-blank, length bounds, whitelist regex, and rejects control characters and cookie delimiters on both `sessionId` and `userId` before TLS/rate-limit/session work, and the handler fails closed (returns an error result) at every rejection point.
- **Cache-prevention headers are correct and applied on both success and failure paths.** `setSecurityHeaders` sets `Cache-Control: no-store, no-cache, must-revalidate, private`, `Pragma: no-cache`, `Expires: 0`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and is invoked on the throttle path as well as success.
- **Test doubles are correctly scoped.** `SimpleHttpRequestContext` / `SimpleHttpResponseContext` are `HashMap`-backed and non-thread-safe, but live only under `src/test/` and are not in the production path — no finding.
- **Dependencies introduce no known vulnerable component or secret.** `pom.xml` pins `jakarta.servlet-api` (provided), `slf4j-api`, and JUnit (test), sets `source/target 17` and `-Werror`, and contains no credentials.
