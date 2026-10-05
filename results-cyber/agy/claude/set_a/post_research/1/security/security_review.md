# Security Review: Post-Authentication Session Cookie Component

## 1. Executive Summary
This document presents a static application security review of the Post-Authentication Session Cookie Component (`com.example.websession`), implemented in Java 17 using Jakarta Servlet API 6.0. The component is designed to receive a pre-existing server-side session identifier (minted by an upstream trusted authenticator) via a servlet request attribute and issue it to the user agent inside a hardened `Set-Cookie` header via an HTTP POST endpoint (`/session/establish`).

The codebase demonstrates strong baseline security design principles, including the use of modern cookie security attributes (`__Host-` prefix, `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`), input length and character allowlisting against response splitting, zero cleartext logging of identifiers, generic error responses, and atomic check-then-act rate limiter updates. However, the static review identified several security vulnerabilities:
1. **High Severity:** A Denial of Service flaw in `FixedWindowRateLimiter` where the rate-limiting map reaches its maximum tracked key capacity and fails closed, indiscriminately blocking all subsequent legitimate traffic from un-tracked IP addresses.
2. **Medium Severity:** Rate limit bypass in `ClientAddressResolver` caused by reading only the first `X-Forwarded-For` header with `request.getHeader()` instead of aggregating all headers with `request.getHeaders()`, enabling IP spoofing when behind proxies that append distinct header lines.
3. **Medium Severity:** Rate limit key collision and cross-account denial of service in `SessionCookieIssuer` caused by truncating the operational subject rate-limiting key to a 48-bit log fingerprint.
4. **Low Severity:** Incomplete validation of IPv6 literals in `ClientAddressResolver.isIpLiteral()`, which accepts arbitrary non-IP strings containing colons.
5. **Low Severity:** Incomplete CSRF protection in `SessionCookieServlet.isCrossSite()` due to fail-open handling of omitted `Sec-Fetch-Site` headers and failure to block cross-subdomain (`same-site`) requests.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `ClientAddressResolver.java` | Resolves the client IP address from direct socket connection or trusted proxy hops in `X-Forwarded-For`. | Parses untrusted headers, performs IP string sanitization and literal validation, generates rate limiter client keys. |
| `FixedWindowRateLimiter.java` | In-memory fixed-window request rate limiter with thread-safe counters and key capacity limits. | Enforces request quotas, performs atomic counter increments via `ConcurrentHashMap.compute()`, bounds memory consumption to mitigate heap exhaustion. |
| `GenericResponse.java` | Emits standardized HTTP responses (200, 401, 429, 503, 405) with static JSON payloads and security headers. | Prevents error-based information disclosure and oracle attacks; sets `X-Content-Type-Options: nosniff` and `Cache-Control: no-store`. |
| `IssueOutcome.java` | Enum defining the high-level outcome of a session cookie issuance attempt (`ISSUED`, `REJECTED`, `RATE_LIMITED`, `UNAVAILABLE`). | Normalizes failure results into coarse buckets to obscure internal failure reasons from clients. |
| `LogFingerprint.java` | Produces truncated HMAC-SHA256 digests of sensitive values using an ephemeral process key. | Masks session IDs, subject keys, and IP addresses in logs; zeroes key material upon disposal; manages cryptographic key lifecycle. |
| `package-info.java` | Package-level documentation defining component scope and trust model. | Documents component trust boundaries, assumptions regarding upstream authenticators, and data validation requirements. |
| `SessionCookieIssuer.java` | Core orchestration logic: validates request state, checks TLS, queries server-side session store, applies rate limits, and issues cookie headers. | Enforces transport security checks, validates session presence against `TrustedSessionService`, rate-limits by IP and subject, applies response hardening headers, prevents double issuance. |
| `SessionCookieServlet.java` | Jakarta `HttpServlet` handling `POST /session/establish`. | Implements HTTP method enforcement, evaluates `Sec-Fetch-Site` for CSRF mitigation, coordinates fail-closed startup via `UnavailableException`, and delegates issuance to `SessionCookieIssuer`. |
| `SessionCookieSettings.java` | Configuration parser and validator for environment/map settings with strict defaults. | Validates configuration parameters against character allowlists and ranges; enforces cross-field invariants (e.g. `__Host-` requiring `Secure` and `Path=/`). |
| `SessionIdValidator.java` | Syntactic validator for externally supplied session identifiers. | Enforces length bounds (22–128) and base64url character set (`[A-Za-z0-9-_]`), preventing CRLF injection and HTTP response splitting. |
| `SetCookieHeaderFactory.java` | Constructs the raw `Set-Cookie` response header string for issuance and deletion. | Formats cookie attributes (`HttpOnly`, `Secure`, `SameSite`, `Path`, `Max-Age`, `Expires`); omits `Domain` for host-only cookies. |
| `TrustedSession.java` | Immutable record representing server-side session metadata (subject handle, remaining lifetime). | Validates session metadata on construction (lifetime bounds up to 1 year, subject key length bounds up to 256 characters). |
| `TrustedSessionService.java` | Functional interface seam for authoritative server-side session lookups. | Defines the trust boundary interface for session verification. |
| `pom.xml` | Maven build descriptor specifying dependencies and compiler configuration. | Configures pinned dependency versions (`jakarta.servlet-api`, `slf4j-api`, `junit-jupiter`) and strict repository checksum validation. |

## 3. Skills Applied
- `testing-api-authentication-weaknesses`: Applied to assess the session management lifecycle, post-authentication cookie creation, session verification against authoritative backend state, and token validation.
- `performing-security-headers-audit`: Applied to audit cookie flags (`HttpOnly`, `Secure`, `SameSite`, `Path`, `__Host-` prefix) and response hardening headers (`Cache-Control`, `X-Content-Type-Options`, `Vary`, `Referrer-Policy`).
- `testing-for-sensitive-data-exposure`: Applied to verify that session identifiers, subject keys, and client IPs do not leak into logs, responses, error messages, or cache layers.
- `performing-cryptographic-audit-of-application`: Applied to audit HMAC-SHA256 generation, random key generation (`SecureRandom`), and key clearing in `LogFingerprint.java`.
- `performing-api-rate-limiting-bypass`: Applied to evaluate client address resolution, `X-Forwarded-For` header parsing, rate limit key derivation, and multi-header spoofing.
- `performing-csrf-attack-simulation`: Applied to evaluate cross-site request handling, `Sec-Fetch-Site` header checks, and HTTP method enforcement.
- General OWASP Top 10 / CWE Knowledge: Applied to audit for HTTP response splitting / CRLF injection (CWE-113), input validation (CWE-20), concurrency issues (CWE-362), and resource allocation limits / DoS (CWE-400).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Denial of Service via Rate Limiter Map Saturation and Indiscriminate Refusal | High | CWE-400 | `FixedWindowRateLimiter.java:49-54` |
| SEC-02 | IP Rate Limiting Bypass via Multiple `X-Forwarded-For` Headers | Medium | CWE-290 | `ClientAddressResolver.java:40-45` |
| SEC-03 | Rate Limit Key Collision and Cross-User Denial of Service via 48-bit Hash Truncation | Medium | CWE-328 | `SessionCookieIssuer.java:119` |
| SEC-04 | Incomplete IPv6 Address Validation in IP Literal Parser | Low | CWE-20 | `ClientAddressResolver.java:76-94` |
| SEC-05 | Incomplete CSRF Protection via Fail-Open and Same-Site Permissive `Sec-Fetch-Site` Check | Low | CWE-352 | `SessionCookieServlet.java:94-97` |

## 5. Detailed Findings

### SEC-01: Denial of Service via Rate Limiter Map Saturation and Indiscriminate Refusal
- **Severity:** High
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `FixedWindowRateLimiter.java:49-54`

**Vulnerable code:**
```java
// FixedWindowRateLimiter.java:49-54
        if (windows.size() >= maxTrackedKeys && !windows.containsKey(key)) {
            purgeExpired(nowMillis);
            if (windows.size() >= maxTrackedKeys && !windows.containsKey(key)) {
                return false;
            }
        }
```

**Why it is a problem:**
`FixedWindowRateLimiter` enforces a hard limit (`maxTrackedKeys`, default 100,000) on the number of keys tracked in memory. When the number of tracked keys reaches `maxTrackedKeys`, the limiter attempts to purge expired windows. However, if an attacker floods requests using 100,000 distinct source addresses or failed session attempts within the current 60-second window, none of the newly populated entries are expired.

When `windows.size() >= maxTrackedKeys` and no entries can be purged, `tryAcquire()` unconditionally returns `false` for any key not already present in the map. In `SessionCookieIssuer.java:97-100`, this causes the system to classify all requests from un-tracked IP addresses as throttled and return `IssueOutcome.RATE_LIMITED` (HTTP 429). Consequently, an attacker can weaponize the rate limiter into a service-wide denial of service mechanism that blocks all subsequent legitimate users from establishing sessions.

**Fix:**
Instead of failing closed against all new keys when the tracking map reaches capacity, the rate limiter should implement a cache eviction policy (such as Least Recently Used or evicting entries with unexhausted counts) to make room for new traffic. Alternatively, integrate a robust, bounded cache library such as Caffeine configured with an LRU eviction policy.

```java
// FixedWindowRateLimiter.java:49-54
        if (windows.size() >= maxTrackedKeys && !windows.containsKey(key)) {
            purgeExpired(nowMillis);
            if (windows.size() >= maxTrackedKeys && !windows.containsKey(key)) {
                evictLeastRecentlyUsedOrIdleEntry();
            }
        }
```

---

### SEC-02: IP Rate Limiting Bypass via Multiple `X-Forwarded-For` Headers
- **Severity:** Medium
- **CWE:** CWE-290: Authentication Bypass by Spoofing
- **Location:** `ClientAddressResolver.java:40-45`

**Vulnerable code:**
```java
// ClientAddressResolver.java:40-45
        String header = request.getHeader(FORWARDED_FOR);
        if (header == null || header.length() > MAX_HEADER_LENGTH) {
            return direct;
        }
        String[] hops = header.split(",", -1);
        int index = hops.length - trustedProxyCount;
```

**Why it is a problem:**
`ClientAddressResolver.resolve` retrieves the `X-Forwarded-For` header using `request.getHeader(FORWARDED_FOR)`. In the Jakarta Servlet specification, `HttpServletRequest.getHeader()` returns only the *first* header line if a request contains multiple headers with the same name.

When deployed behind reverse proxies, load balancers, or CDNs (e.g., HAProxy, Envoy, Go reverse proxies, or Apache HTTPD) that append a new `X-Forwarded-For` header line rather than merging into a single comma-separated string, the trusted proxy's appended IP appears in a subsequent header line. An attacker can supply their own initial `X-Forwarded-For: <spoofed_ip>` header line. Because `request.getHeader()` inspects only the first header line, `hops.length - trustedProxyCount` indexes into the attacker-controlled header value. The attacker can rotate arbitrary IP addresses on each request to completely bypass per-source rate limiting (`SESSION_ISSUE_MAX_PER_IP_PER_MINUTE`).

**Fix:**
Use `request.getHeaders(FORWARDED_FOR)` to retrieve all `X-Forwarded-For` header lines, combine them into an ordered list of hops, enforce the maximum aggregate header length, and extract the trusted proxy hop from the combined chain.

```java
// ClientAddressResolver.java:40-45
        java.util.Enumeration<String> headers = request.getHeaders(FORWARDED_FOR);
        if (headers == null || !headers.hasMoreElements()) {
            return direct;
        }
        java.util.List<String> hopsList = new java.util.ArrayList<>();
        int totalLength = 0;
        while (headers.hasMoreElements()) {
            String val = headers.nextElement();
            totalLength += val.length();
            if (totalLength > MAX_HEADER_LENGTH) {
                return direct;
            }
            for (String part : val.split(",", -1)) {
                hopsList.add(part.trim());
            }
        }
        int index = hopsList.size() - trustedProxyCount;
        if (index < 0 || index >= hopsList.size()) {
            return direct;
        }
        String candidate = sanitize(hopsList.get(index));
        return candidate.equals(UNKNOWN) ? direct : candidate;
```

---

### SEC-03: Rate Limit Key Collision and Cross-User Denial of Service via 48-bit Hash Truncation
- **Severity:** Medium
- **CWE:** CWE-328: Use of Weak Hash
- **Location:** `SessionCookieIssuer.java:119`

**Vulnerable code:**
```java
// SessionCookieIssuer.java:119
        boolean withinSubjectBudget = perSubjectLimiter.tryAcquire("s|" + fingerprint.of(subjectKey), now);
```

**Why it is a problem:**
In `SessionCookieIssuer.java:119`, the rate-limiting key for authenticated subjects is derived using `fingerprint.of(subjectKey)`. `LogFingerprint.java` generates this tag by truncating an HMAC-SHA256 digest to only 12 hexadecimal characters (`TAG_HEX_CHARS = 12`), which provides only 48 bits of entropy.

While 48 bits of entropy is sufficient for ephemeral log pseudonymization, reusing it as an operational rate-limiting key creates an unacceptable collision rate in enterprise systems. By the birthday paradox, across 2.3 million active subjects there is a ~1% probability of collision, and across 16.7 million subjects there is a ~50% probability of collision. When a collision occurs, requests from one user consume the rate-limiting quota (default 20 requests per minute) of another user, resulting in intermittent `REJECTED` (HTTP 401) errors. Furthermore, if `LogFingerprint` encounters a security exception or has `close()` called, it returns `"-"`, collapsing all subjects in the application into a single key (`"s|-"`) and causing total application lockout after 20 attempts.

**Fix:**
Do not use the truncated log fingerprint as an operational rate-limiting key. Use either the raw `subjectKey` directly (which is already bounded to 256 characters by `TrustedSession`) or compute a full, untruncated cryptographic hash (such as SHA-256 with 256 bits of entropy).

```java
// SessionCookieIssuer.java:119
        // Use the validated subjectKey directly, avoiding truncated hash collisions
        boolean withinSubjectBudget = perSubjectLimiter.tryAcquire("s|" + subjectKey, now);
```

---

### SEC-04: Incomplete IPv6 Address Validation in IP Literal Parser
- **Severity:** Low
- **CWE:** CWE-20: Improper Input Validation
- **Location:** `ClientAddressResolver.java:76-94`

**Vulnerable code:**
```java
// ClientAddressResolver.java:76-94
    private static boolean isIpLiteral(String value) {
        if (value.isEmpty() || value.length() > MAX_ADDRESS_LENGTH) {
            return false;
        }
        boolean sawColon = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == ':') {
                sawColon = true;
                continue;
            }
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex && c != '.') {
                // Rejects '%' zone ids, wildcards, hostnames, and anything else.
                return false;
            }
        }
        return sawColon ? value.length() >= 2 : isDottedQuad(value);
    }
```

**Why it is a problem:**
Line 93 of `ClientAddressResolver.java` evaluates IPv6 literals as `sawColon ? value.length() >= 2 : isDottedQuad(value)`. While IPv4 addresses are strictly validated via `isDottedQuad()`, IPv6 validation checks only that the string contains at least one colon and valid characters of length between 2 and 45.

As a result, non-IP strings such as `":."`, `"a:"`, `"1:2"`, `"::::::::::"`, and `"1.2.3.4:56.78"` are erroneously accepted as valid IP literals. Malformed values in `X-Forwarded-For` hops are therefore passed into rate-limiting maps instead of being normalized to `"unknown"` or falling back to the observed direct socket address.

**Fix:**
Implement strict IPv6 structure validation (checking group counts, 16-bit hex values per group, and proper `::` compression) without triggering DNS resolution.

```java
// ClientAddressResolver.java:76-94
    private static boolean isIpLiteral(String value) {
        if (value.isEmpty() || value.length() > MAX_ADDRESS_LENGTH) {
            return false;
        }
        if (value.indexOf(':') >= 0) {
            return isIpv6Literal(value);
        }
        return isDottedQuad(value);
    }

    private static boolean isIpv6Literal(String value) {
        // Enforce exact 16-bit hex group counts and valid compression without DNS lookup
        String[] parts = value.split("::", -1);
        if (parts.length > 2) {
            return false; // At most one "::" allowed
        }
        int totalGroups = 0;
        for (String part : parts) {
            if (part.isEmpty()) continue;
            String[] groups = part.split(":", -1);
            for (String g : groups) {
                if (g.isEmpty() || g.length() > 4) return false;
                for (int i = 0; i < g.length(); i++) {
                    char c = g.charAt(i);
                    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                        return false;
                    }
                }
                totalGroups++;
            }
        }
        return parts.length == 2 ? totalGroups < 8 : totalGroups == 8;
    }
```

---

### SEC-05: Incomplete CSRF Protection via Fail-Open and Same-Site Permissive `Sec-Fetch-Site` Check
- **Severity:** Low
- **CWE:** CWE-352: Cross-Site Request Forgery (CSRF)
- **Location:** `SessionCookieServlet.java:94-97`

**Vulnerable code:**
```java
// SessionCookieServlet.java:94-97
    private static boolean isCrossSite(HttpServletRequest request) {
        String fetchSite = request.getHeader("Sec-Fetch-Site");
        return "cross-site".equalsIgnoreCase(fetchSite);
    }
```

**Why it is a problem:**
`SessionCookieServlet.isCrossSite()` relies solely on the browser-provided `Sec-Fetch-Site` request header to reject cross-site requests. This implementation exhibits two security weaknesses:
1. Cross-subdomain requests from within the same registrable domain (e.g. `user-content.example.com` to `example.com`) carry `Sec-Fetch-Site: same-site`, which is not rejected by `isCrossSite()`.
2. Fail-open behavior: In user agents that do not implement W3C Fetch Metadata (such as older Safari versions or non-browser clients), `request.getHeader("Sec-Fetch-Site")` returns `null`, causing `isCrossSite()` to return `false`.

If the upstream authentication mechanism relies on ambient credentials (such as HTTP Basic, Digest, Kerberos/SPNEGO, or mTLS), requests triggered from sibling subdomains or older browsers will bypass this check and issue session cookies without anti-CSRF token verification or `Origin`/`Referer` validation.

**Fix:**
Enforce anti-CSRF synchronizer tokens, or implement strict validation of the `Origin` and `Referer` headers as a fallback when `Sec-Fetch-Site` is absent, and reject untrusted `same-site` requests when cross-subdomain isolation is required.

```java
// SessionCookieServlet.java:94-97
    private static boolean isCrossSite(HttpServletRequest request) {
        String fetchSite = request.getHeader("Sec-Fetch-Site");
        if (fetchSite != null) {
            return !"same-origin".equalsIgnoreCase(fetchSite) && !"none".equalsIgnoreCase(fetchSite);
        }
        // Fallback for user agents lacking Fetch Metadata: validate Origin/Referer
        String origin = request.getHeader("Origin");
        if (origin != null) {
            return !isExpectedOrigin(origin, request);
        }
        String referer = request.getHeader("Referer");
        return referer == null || !isExpectedReferer(referer, request);
    }
```

## 6. Verified Controls and Checks With No Finding
- **Cookie Security Attributes (`SetCookieHeaderFactory.java:52-74`, `SessionCookieIssuer.java:128-132`)**: Verified that issued cookies strictly include `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and the `__Host-` prefix (`__Host-SID`), completely mitigating client-side script access, cleartext transmission, cross-site submission, and path-shadowing attacks.
- **HTTP Response Splitting / Header Injection Defense (`SessionIdValidator.java:37-60`)**: Verified that session identifiers are strictly validated to base64url characters (`[A-Za-z0-9-_]`) with length between 22 and 128 characters, preventing CRLF injection (`\r\n`) and cookie attribute breakout.
- **Trust Boundary & Session Verification (`SessionCookieIssuer.java:102-125`)**: Verified that session IDs are accepted exclusively from server-side request attributes (`com.example.websession.SESSION_ID`) and never from client parameters, headers, or cookies. Verified that no cookie is issued without positive validation from `TrustedSessionService.lookupActiveSession()`.
- **Information Disclosure in Responses (`GenericResponse.java:20-66`)**: Verified that all failure outcomes (missing session, invalid format, expired session, subject throttled) return identical HTTP 401 JSON payloads with fixed lengths, preventing username enumeration and timing oracles.
- **Sensitive Data Logging Protection (`LogFingerprint.java:23-70`)**: Verified that raw session identifiers, subject keys, and IP addresses are never written to logs, and are instead replaced by an ephemeral in-memory HMAC-SHA256 digest whose key is zeroed on shutdown.
- **HTTP Cache Hardening (`GenericResponse.java:64`, `SessionCookieIssuer.java:172-181`)**: Verified that responses set `Cache-Control: no-store`, `Pragma: no-cache`, `Expires: 0`, and `Vary: Cookie`, preventing intermediate proxies and shared caches from storing session cookies.
- **HTTP Method Enforcement (`SessionCookieServlet.java:71-135`)**: Verified that all HTTP methods other than `POST` (`GET`, `PUT`, `DELETE`, `HEAD`, `TRACE`) are rejected with HTTP 405 Method Not Allowed and `Allow: POST`, preventing state modification via navigational links or image tags.
- **Request Replay / Double Issuance Guard (`SessionCookieIssuer.java:91-94, 132`)**: Verified that an internal request marker attribute (`com.example.websession.COOKIE_ISSUED`) prevents duplicate cookie issuance within the lifecycle of a single request.
- **Concurrency & Atomic Counter Updates (`FixedWindowRateLimiter.java:55-63`)**: Verified that rate-limiting counter reads, window rollovers, and increments occur atomically within `ConcurrentHashMap.compute()`, preventing check-then-act race conditions.
- **Fail-Closed Configuration Validation (`SessionCookieSettings.java:80-179, 234-255`)**: Verified that invalid, empty, or inconsistent configuration parameters fail immediately at startup with `UnavailableException`, and that exception messages do not echo configuration values.
