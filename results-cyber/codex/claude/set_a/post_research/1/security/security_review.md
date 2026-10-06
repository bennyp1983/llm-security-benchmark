# Security Review: session-cookie-component

## 1. Executive Summary
This Java 17/Jakarta Servlet component takes a server-created session identifier from a request attribute, validates it against authoritative server-side state, and returns it in a hardened cookie. The implementation has strong input allowlists, generic error responses, server-side session lookup, keyed log redaction, and secure defaults. Five vulnerabilities remain: the configuration can deliberately omit `Secure` from the bearer-session cookie (High); the CSRF check accepts requests when browser provenance metadata is absent (Medium); proxy-derived client identity is trusted without verifying that the direct peer is a configured proxy (Medium); each servlet instance keeps independent rate-limit state, allowing aggregate limits to be bypassed across replicas (Medium); and a low-severity concurrency race can exceed the limiter's stated key-space cap.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `pom.xml` | Maven build and dependency declaration | Pins Servlet, SLF4J, JUnit, compiler, and test-plugin versions; uses Maven Central with failed-checksum policy. |
| `README.md` | Deployment and trust-model documentation | Documents cookie, proxy, rate-limit, session-lifecycle, and upstream-authentication assumptions. |
| `src/main/java/com/example/websession/ClientAddressResolver.java` | Chooses a source key for rate limiting | Parses `X-Forwarded-For`, counts trusted hops, bounds header sizes, and performs custom IP-literal validation. |
| `src/main/java/com/example/websession/FixedWindowRateLimiter.java` | In-memory fixed-window limiter | Atomically counts per-key attempts, purges expired entries, and attempts to cap tracked keys. |
| `src/main/java/com/example/websession/GenericResponse.java` | Writes fixed HTTP responses | Uses generic constant bodies, fixed lengths, `no-store`, and `nosniff`; emits `Retry-After` for address throttling. |
| `src/main/java/com/example/websession/IssueOutcome.java` | Models issuance outcomes | Collapses detailed internal failures into coarse externally visible outcomes. |
| `src/main/java/com/example/websession/LogFingerprint.java` | Redacts sensitive log values | Generates an ephemeral 256-bit key and produces truncated HMAC-SHA-256 fingerprints. |
| `src/main/java/com/example/websession/SessionCookieIssuer.java` | Validates sessions and issues/clears cookies | Enforces TLS when configured, looks up server-side state, applies two rate limits, writes cookies, and logs fingerprints. |
| `src/main/java/com/example/websession/SessionCookieServlet.java` | HTTP servlet entry point | Allows POST, checks `Sec-Fetch-Site`, maps outcomes to responses, and fails closed when dependencies are absent. |
| `src/main/java/com/example/websession/SessionCookieSettings.java` | Loads and validates environment configuration | Validates cookie attributes, lifetimes, proxy count, and limiter parameters, but permits explicitly weakened settings. |
| `src/main/java/com/example/websession/SessionIdValidator.java` | Validates session identifier syntax | Enforces a 22-128 character base64url allowlist before header use or session lookup. |
| `src/main/java/com/example/websession/SetCookieHeaderFactory.java` | Constructs deterministic `Set-Cookie` values | Adds path, lifetime, `HttpOnly`, optional `Secure`, and `SameSite`; revalidates the identifier. |
| `src/main/java/com/example/websession/TrustedSession.java` | Carries trusted session facts | Bounds subject-key length and remaining server-side session lifetime. |
| `src/main/java/com/example/websession/TrustedSessionService.java` | Defines the authoritative session lookup seam | Requires active-session validation, revocation awareness, and concurrency-safe implementations. |
| `src/main/java/com/example/websession/package-info.java` | Documents package scope and trust boundaries | Declares authentication/session creation out of scope and all incoming values untrusted. |
| `src/test/java/com/example/websession/ClientAddressResolverTest.java` | Tests address selection | Covers ignored/spoofed forwarding headers, hop selection, malformed input, ports, and IPv6 examples. |
| `src/test/java/com/example/websession/FakeHttp.java` | Supplies servlet test doubles | Models headers, request attributes, TLS state, commitment, response headers, and bodies. |
| `src/test/java/com/example/websession/FixedWindowRateLimiterTest.java` | Tests rate limiting | Covers per-key counter atomicity and sequential capacity, but not concurrent distinct-key admission or multi-instance behavior. |
| `src/test/java/com/example/websession/LogFingerprintTest.java` | Tests log redaction | Checks stable per-instance tags, process separation, fixed length, and closed-state behavior. |
| `src/test/java/com/example/websession/SessionCookieIssuerTest.java` | Tests cookie issuance | Covers cookie flags, client-controlled identifier rejection, lookup failures, response equivalence, TLS, expiry, and throttling. |
| `src/test/java/com/example/websession/SessionCookieSettingsTest.java` | Tests configuration validation | Covers strict defaults, invalid values, unsafe combinations, delimiters, and non-disclosing errors. |
| `src/test/java/com/example/websession/SessionIdValidatorTest.java` | Tests identifier validation | Covers base64url bounds and rejection of header delimiters, Unicode, padding, and oversize values. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: used to inventory every source file, identify security-relevant behavior, route the review to specialized checklists, and require CWE/file-line evidence.
- `performing-security-headers-audit`: applied to `Set-Cookie` attributes, transport protection, cache controls, MIME-sniffing protection, and referrer policy.
- `performing-api-rate-limiting-bypass`: applied to forwarded-address spoofing, per-address/per-subject keying, concurrent bypasses, and enforcement consistency.
- `implementing-api-rate-limiting-and-throttling`: applied to limiter atomicity, fixed-window behavior, bounded storage, response semantics, and distributed deployment behavior.
- `performing-csrf-attack-simulation`: applied to the state-changing POST endpoint, `Sec-Fetch-Site`, absent-header behavior, and cookie `SameSite` policy.
- `testing-api-authentication-weaknesses`: applied to session lookup, token transport, token leakage, failure equivalence, revocation boundaries, and throttling.
- `performing-cryptographic-audit-of-application`: applied to HMAC-SHA-256 selection, random key generation, key lifetime, hardcoded-secret checks, and sensitive logging.
- General OWASP Top 10 / CWE knowledge: applied to custom header construction, configuration validation, servlet lifecycle/error handling, cache behavior, and concurrency where no more specific skill matched.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Configuration can omit `Secure` from the session cookie | High | CWE-614 | `src/main/java/com/example/websession/SetCookieHeaderFactory.java:68-71` |
| SEC-02 | Missing fetch metadata bypasses the CSRF check | Medium | CWE-352 | `src/main/java/com/example/websession/SessionCookieServlet.java:94-97` |
| SEC-03 | Forwarded client address is trusted without authenticating the proxy peer | Medium | CWE-345 | `src/main/java/com/example/websession/ClientAddressResolver.java:35-52` |
| SEC-04 | Per-instance rate-limit state permits cross-replica bypass | Medium | CWE-799 | `src/main/java/com/example/websession/SessionCookieIssuer.java:37-42` |
| SEC-05 | Concurrent new keys can exceed the limiter's memory cap | Low | CWE-362 | `src/main/java/com/example/websession/FixedWindowRateLimiter.java:49-55` |

## 5. Detailed Findings

### SEC-01: Configuration can omit `Secure` from the session cookie
- **Severity:** High
- **CWE:** CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
- **Location:** `src/main/java/com/example/websession/SetCookieHeaderFactory.java:68-71`

**Vulnerable code:**
```java
// src/main/java/com/example/websession/SetCookieHeaderFactory.java:68-71
        sb.append("; HttpOnly");
        if (settings.secure()) {
            sb.append("; Secure");
        }
```

**Why it is a problem:** The cookie contains a bearer session identifier, but `SESSION_COOKIE_SECURE=false` is accepted when the operator also chooses a name without the `__Host-` or `__Secure-` prefix. In that configuration this branch emits the token without `Secure`, and `SessionCookieIssuer` also permits issuance over a plaintext request. A network attacker can then capture the identifier when it is issued or later sent over HTTP. Secure defaults reduce accidental exposure but do not make an explicitly supported unsafe production configuration safe.

**Fix:** Make `Secure` invariant for this session-cookie component and reject any configuration that attempts to disable it. A separate non-production test fixture can model insecure transport without adding an unsafe runtime option.
```java
// SessionCookieSettings.fromLookup
b.secure = requireBoolean(value(lookup, "SESSION_COOKIE_SECURE", "true"),
        "SESSION_COOKIE_SECURE");
if (!b.secure) {
    throw new IllegalArgumentException("SESSION_COOKIE_SECURE must be true");
}

// SetCookieHeaderFactory.build
sb.append("; HttpOnly; Secure");
```

### SEC-02: Missing fetch metadata bypasses the CSRF check
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

**Why it is a problem:** The check fails open: an absent `Sec-Fetch-Site` value returns `false`, so the request is accepted. Older user agents, privacy middleware, and intermediaries may omit fetch metadata. Because this endpoint causes a browser to install an authentication cookie, a cross-site POST that reaches the upstream authenticator can become login/session-establishment CSRF. POST-only routing does not stop an auto-submitted HTML form, and setting `SameSite` on the response cookie is not a reliable substitute for validating the request's origin.

**Fix:** Require positively verified same-origin provenance. Compare `Origin` with a deployment-configured canonical origin rather than deriving trust from the client-controlled `Host` header, and fail closed when required metadata is missing. A synchronizer token bound to the pre-authentication transaction is an appropriate alternative when legitimate clients cannot send fetch metadata.
```java
private static boolean isCrossSite(HttpServletRequest request, String expectedOrigin) {
    String fetchSite = request.getHeader("Sec-Fetch-Site");
    String origin = request.getHeader("Origin");
    if (!"same-origin".equalsIgnoreCase(fetchSite)) {
        return true;
    }
    return origin == null || !origin.equals(expectedOrigin);
}
```

### SEC-03: Forwarded client address is trusted without authenticating the proxy peer
- **Severity:** Medium
- **CWE:** CWE-345: Insufficient Verification of Data Authenticity
- **Location:** `src/main/java/com/example/websession/ClientAddressResolver.java:35-52`

**Vulnerable code:**
```java
// src/main/java/com/example/websession/ClientAddressResolver.java:35-52
    String resolve(HttpServletRequest request) {
        String direct = sanitize(request.getRemoteAddr());
        if (trustedProxyCount == 0) {
            return direct;
        }
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

**Why it is a problem:** A hop count establishes where to read, but not who supplied the header. When `trustedProxyCount` is nonzero, any client that can reach the origin directly can send a chosen `X-Forwarded-For` chain of the expected length and obtain fresh per-address rate-limit buckets. This turns an origin exposure or routing mistake into a reliable limiter bypass. The resolver must first prove that the directly observed peer is one of the configured trusted proxies; multi-proxy deployments should also validate every proxy hop on the trusted side of the chain.

**Fix:** Configure trusted proxy addresses/networks and ignore forwarding headers unless the direct peer matches. Use a real CIDR-aware address type/matcher rather than string suffix or prefix tests.
```java
private final TrustedProxyMatcher trustedProxies;

String resolve(HttpServletRequest request) {
    String direct = sanitize(request.getRemoteAddr());
    if (trustedProxyCount == 0 || UNKNOWN.equals(direct)
            || !trustedProxies.contains(direct)) {
        return direct;
    }
    String header = request.getHeader(FORWARDED_FOR);
    if (header == null || header.length() > MAX_HEADER_LENGTH) {
        return direct;
    }
    return resolveValidatedChain(header, direct, trustedProxyCount, trustedProxies);
}
```

### SEC-04: Per-instance rate-limit state permits cross-replica bypass
- **Severity:** Medium
- **CWE:** CWE-799: Improper Control of Interaction Frequency
- **Location:** `src/main/java/com/example/websession/SessionCookieIssuer.java:37-42`

**Vulnerable code:**
```java
// src/main/java/com/example/websession/SessionCookieIssuer.java:37-42
    private final SessionCookieSettings settings;
    private final TrustedSessionService sessionService;
    private final ClientAddressResolver addressResolver;
    private final FixedWindowRateLimiter perAddressLimiter;
    private final FixedWindowRateLimiter perSubjectLimiter;
    private final LogFingerprint fingerprint;
```

**Why it is a problem:** Both budgets live in the heap of one `SessionCookieIssuer`. In a normal replicated servlet deployment, requests distributed among `N` processes receive `N` independent per-address and per-subject budgets; an attacker can multiply the configured attempt limit by steering or repeatedly sending requests through the load balancer. Restarts also erase all counters. The code and configuration present these values as issuance limits without constraining deployment to a single process, so the protection is not consistently enforced.

**Fix:** Inject limiters backed by a shared store and implement check/increment/expiry as one atomic operation (for example, a Redis Lua script). Namespace keys by endpoint and budget type and define fail-closed behavior for store outages on this sensitive endpoint.
```java
private final RateLimiter perAddressLimiter;
private final RateLimiter perSubjectLimiter;

public SessionCookieIssuer(SessionCookieSettings settings,
                           TrustedSessionService sessionService,
                           RateLimiter perAddressLimiter,
                           RateLimiter perSubjectLimiter,
                           Clock clock) {
    this.settings = Objects.requireNonNull(settings, "settings");
    this.sessionService = Objects.requireNonNull(sessionService, "sessionService");
    this.perAddressLimiter = Objects.requireNonNull(perAddressLimiter, "perAddressLimiter");
    this.perSubjectLimiter = Objects.requireNonNull(perSubjectLimiter, "perSubjectLimiter");
    this.clock = Objects.requireNonNull(clock, "clock");
}
```

### SEC-05: Concurrent new keys can exceed the limiter's memory cap
- **Severity:** Low
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- **Location:** `src/main/java/com/example/websession/FixedWindowRateLimiter.java:49-55`

**Vulnerable code:**
```java
// src/main/java/com/example/websession/FixedWindowRateLimiter.java:49-55
        if (windows.size() >= maxTrackedKeys && !windows.containsKey(key)) {
            purgeExpired(nowMillis);
            if (windows.size() >= maxTrackedKeys && !windows.containsKey(key)) {
                return false;
            }
        }
        Window updated = windows.compute(key, (k, existing) -> {
```

**Why it is a problem:** `ConcurrentHashMap.compute` makes the counter update atomic only for one key. Capacity admission is a separate global check, so many threads using different new keys can all observe available capacity and then all insert. The map can exceed `maxTrackedKeys`, contradicting the claimed hard memory bound. The overshoot is normally limited by request concurrency, which keeps the severity low, but it is attacker-triggerable and can increase memory pressure during a flood. The concurrency test exercises one shared key and therefore does not detect this race.

**Fix:** Make purge, capacity admission, insertion, and the allow/deny decision atomic with respect to all new-key admissions. The simple form below uses one lock; a higher-throughput implementation can use an atomic capacity reservation scheme.
```java
private final Object admissionLock = new Object();

boolean tryAcquire(String key, long nowMillis) {
    if (key == null) {
        return false;
    }
    synchronized (admissionLock) {
        if (!windows.containsKey(key)) {
            purgeExpired(nowMillis);
            if (windows.size() >= maxTrackedKeys) {
                return false;
            }
        }
        Window updated = windows.compute(key, (k, existing) -> {
            if (existing == null || nowMillis - existing.startMillis() >= windowMillis) {
                return new Window(nowMillis, 1);
            }
            int next = existing.count() == Integer.MAX_VALUE
                    ? existing.count() : existing.count() + 1;
            return new Window(existing.startMillis(), next);
        });
        return updated.count() <= permitsPerWindow;
    }
}
```

## 6. Verified Controls and Checks With No Finding
- Server-side session authority: `SessionCookieIssuer.java:102-128` validates identifier shape and requires `TrustedSessionService.lookupActiveSession` to return a live session before issuing a cookie.
- Session fixation boundary: `SessionCookieIssuer.java:102` reads the identifier from a server-side request attribute, while tests confirm headers and cookies are ignored; freshness and privilege-change rotation remain explicitly assigned to the upstream session service.
- Header injection prevention: `SessionIdValidator.java:37-58`, `SessionCookieSettings.java:119-145`, and `SetCookieHeaderFactory.java:30-73` use length-bounded character allowlists and fixed attributes, preventing CR/LF and cookie-attribute injection.
- Cookie hardening under defaults: `SetCookieHeaderFactory.java:52-73` emits host-only scope, `Path=/`, `HttpOnly`, `Secure`, and `SameSite=Strict` for `secureDefaults()`; SEC-01 covers the unsafe configurable exception.
- Session lifetime: `TrustedSession.java:29-36` validates a positive bounded remaining lifetime, and `SessionCookieIssuer.java:165-170` clamps configured persistence to it.
- Sensitive logging and cryptography: `LogFingerprint.java:25-69` uses a random 256-bit HMAC-SHA-256 key, never logs raw inputs, clears temporary byte arrays, and zeroes the key on close; no weak algorithms or hardcoded secrets were found.
- Generic failure behavior: `GenericResponse.java:23-66` returns fixed-size constant bodies without echoing identifiers or provider errors; missing, malformed, and unknown identifiers share the same external result.
- Per-key counter atomicity: `FixedWindowRateLimiter.java:55-63` performs window rollover, increment, and the permit decision atomically for an existing key; SEC-05 is limited to global new-key admission.
- Input and storage bounds: session IDs, subject keys, forwarding headers, addresses, configuration values, cookie lifetime, and rate-limit parameters are bounded before storage or output.
- HTTP method restriction: `SessionCookieServlet.java:99-133` rejects GET, PUT, DELETE, HEAD, and TRACE and returns a fixed `Allow: POST`; OPTIONS discloses only that allowlist.
- Response confidentiality controls: `SessionCookieIssuer.java:172-180` applies `Cache-Control: no-store`, legacy cache prevention, `Vary: Cookie`, `nosniff`, and a restrictive referrer policy to cookie-bearing responses.
- Error handling and startup behavior: `SessionCookieServlet.java:52-68` refuses startup without the trusted session service or valid configuration, and runtime lookup failures emit no cookie or detailed client error.
- Dependency/build review: `pom.xml:18-80` pins direct dependencies and plugins, disables snapshots, and requires failed-checksum handling; no dynamic dependency versions, untrusted repositories, runtime downloads, or build hooks were present.
