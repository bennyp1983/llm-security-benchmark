# Security Review: Authentication Component

## 1. Executive Summary
This security review evaluated the Java 17 authentication component located in `/data/results/codex/set_a/post_research/6/security/`. The component provides username and password authentication, cryptographic password verification, in-memory rate limiting, session token generation and storage, and owner-private rolling file audit logging.

The codebase exhibits strong adherence to defensive programming practices in cryptographic implementation and memory hygiene: password hashing uses PBKDF2-HMAC-SHA-256 with 600,000 iterations, constant-time equality comparisons are enforced, sensitive character and byte arrays are explicitly cleared from memory, session cookies utilize the `__Host-` prefix with strict flags, and audit events are pseudonymized using domain-separated HMAC-SHA-256.

However, the review identified four security vulnerabilities:
1. **Ineffective Rate Limiting / Brute-Force Bypass (High, CWE-307):** The rate limiter classifies requests as throttled, but `AuthenticationService` continues to execute expensive PBKDF2 hash derivations and grants authentication upon encountering correct credentials, bypassing both per-source and per-account rate limits.
2. **Denial of Service via State Table Exhaustion (High, CWE-400):** The in-memory rate limiter throws an unhandled `IllegalStateException` when its tracking table reaches 100,000 entries, causing all subsequent logins for untracked users to fail closed.
3. **Application-Wide Denial of Service via Global Session Exhaustion (Medium, CWE-770):** The in-memory session store enforces a global capacity limit without per-user quotas or eviction, allowing a single account to exhaust session storage and lock out all users.
4. **Collision and Cross-User Throttling via Malformed Username Keying (Low, CWE-20):** All malformed usernames map to the string `"invalid"`, which collides with a valid username and shares a single rate-limiting bucket across all malformed login attempts.

Remediation recommendations and corrected code blocks are provided for each finding.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `pom.xml` | Maven build definition | Compiler configuration (Java 17), UTF-8 encoding, and pinned test dependency (JUnit 5.11.4). |
| `src/main/java/example/security/auth/AuthenticationService.java` | Core authentication coordinator | Validates inputs, coordinates rate limiting, invokes credential verification, issues session tokens, formats cookies, and writes audit events. |
| `src/main/java/example/security/auth/CredentialStore.java` | Credential storage contract | Defines the credential verification interface and validates the `AuthenticatedPrincipal` identifier format. |
| `src/main/java/example/security/auth/PasswordRecord.java` | Stored password container | Holds PBKDF2 salt, hash, and iterations; bounds work factors, defends against array exposure, and redacts string output. |
| `src/main/java/example/security/auth/PasswordVerifier.java` | PBKDF2 password derivation | Implements PBKDF2-HMAC-SHA-256 hashing, input validation, constant-time hash comparison, and `PBEKeySpec` memory wiping. |
| `src/main/java/example/security/auth/InMemoryCredentialStore.java` | In-memory credential repository | Thread-safe credential lookup with dummy PBKDF2 verification for non-existent users to mitigate timing attacks. |
| `src/main/java/example/security/auth/SessionStore.java` | Session storage interface | Defines session lifecycle contracts using SHA-256 token digests. |
| `src/main/java/example/security/auth/InMemorySessionStore.java` | In-memory session repository | Bounded session table with token digest validation, expiration time checks, and passive expiration cleanup. |
| `src/main/java/example/security/auth/LoginRateLimiter.java` | Rate limiter contract | Defines rate limiter decisions (`ALLOW`, `THROTTLED`) and attempt registration. |
| `src/main/java/example/security/auth/InMemoryLoginRateLimiter.java` | Fixed-window in-memory limiter | Tracks attempts per source and per account with fixed-window expiry and a maximum capacity threshold. |
| `src/main/java/example/security/auth/AuditSink.java` | Audit output contract | Defines mandatory durable event append behavior. |
| `src/main/java/example/security/auth/AuthenticationEvent.java` | Structured audit event model | Immutable record validating UUIDs, timestamps, outcome/reason consistency, and 64-character hexadecimal HMAC keys. |
| `src/main/java/example/security/auth/PrivateRollingFileAuditSink.java` | POSIX file audit logger | Enforces `0700` directory and `0600` file permissions, non-symlink verification, file locking, size limits, and log rotation. |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Audited PBKDF2-HMAC-SHA-256 key derivation parameters (600,000 iterations, 128-bit salt, 256-bit hash), `SecureRandom` usage for cryptographic tokens and salts, constant-time verification (`MessageDigest.isEqual`), SHA-256 token hashing, and domain-separated HMAC-SHA-256 correlation keys.
- `testing-api-authentication-weaknesses`: Audited authentication workflow, credential handling, rate-limiting effectiveness, brute-force mitigation, account enumeration defenses, and session token generation/storage.
- `testing-for-sensitive-data-exposure`: Audited memory-zeroing controls (`Arrays.fill` for passwords, tokens, and digests), redaction in `toString()` methods, and pseudonymization of user identities and IP addresses in audit trails.
- `performing-security-headers-audit`: Audited HTTP session cookie attributes (`__Host-` prefix compliance, `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, and omission of `Domain`).
- General OWASP Top 10 / CWE knowledge (no skill matched):
  - Audited POSIX file permission enforcement (`0700` directory, `0600` file), symlink avoidance (`NOFOLLOW_LINKS`), and atomic file operations (`ATOMIC_MOVE`) in `PrivateRollingFileAuditSink.java` against CWE-732 and CWE-59.
  - Audited state table exhaustion, resource bounds, and denial-of-service vulnerabilities in `InMemoryLoginRateLimiter.java` and `InMemorySessionStore.java` against CWE-400 and CWE-770.
  - Audited input validation and username canonicalization in `AuthenticationService.java` against CWE-20.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Ineffective Rate Limiting Bypasses Brute-Force and Credential-Stuffing Protections | High | CWE-307 | `AuthenticationService.java:78-96` |
| SEC-02 | Denial of Service via State Table Exhaustion in In-Memory Rate Limiter | High | CWE-400 | `InMemoryLoginRateLimiter.java:40-43` |
| SEC-03 | Global Session Store Capacity Exhaustion Causes Application-Wide Denial of Service | Medium | CWE-770 | `InMemorySessionStore.java:27-29` |
| SEC-04 | Collision and Cross-User Throttling via Shared Correlation Key for Malformed Usernames | Low | CWE-20 | `AuthenticationService.java:71` |

## 5. Detailed Findings

### SEC-01: Ineffective Rate Limiting Bypasses Brute-Force and Credential-Stuffing Protections
- **Severity:** High
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `AuthenticationService.java:78-96`

**Vulnerable code:**
```java
// AuthenticationService.java:78-96
            try {
                throttled = limiter.registerAttempt(sourceKey, subjectKey, now)
                        == LoginRateLimiter.Decision.THROTTLED;
            } catch (RuntimeException e) {
                return internalFailure(now, subjectKey, sourceKey);
            }

            Optional<CredentialStore.AuthenticatedPrincipal> principal = Optional.empty();
            try {
                if (canonical != null && validPassword) {
                    principal = credentials.verify(canonical, password);
                } else {
                    PasswordVerifier.verify(INVALID_PASSWORD.clone(), dummyRecord);
                }
            } catch (RuntimeException e) {
                return internalFailure(now, subjectKey, sourceKey);
            }

            // Correct credentials bypass a hostile account-induced throttle; failed attempts do not.
            if (principal.isPresent()) {
```

**Why it is a problem:**
When `limiter.registerAttempt()` returns `Decision.THROTTLED`, `AuthenticationService` does not reject or delay the attempt. Instead, it proceeds directly to `credentials.verify(canonical, password)`, computing 600,000 PBKDF2 iterations. If the password matches (`principal.isPresent()`), the code explicitly grants authentication and returns a valid session cookie, completely ignoring the `throttled` status.

This introduces severe security risks:
1. **Unrestricted Password Brute-Force:** An attacker can submit unlimited password guesses against an account. Even if the account limit is exceeded and the limiter signals `THROTTLED`, the attacker is successfully authenticated the moment the correct password is provided.
2. **Per-Source Rate Limit Bypass:** If an attacker conducts a high-volume attack from a single IP address, exceeding `perSource` attempts sets `throttled = true`, but credential verification still executes and authentication still succeeds.
3. **CPU Resource Starvation (Denial of Service):** Because every throttled request still runs the computationally expensive PBKDF2 derivation (600,000 iterations), an attacker can flood the endpoint with requests from a single IP to saturate server CPU capacity.
4. **No Caller/Edge Signal:** The returned `Result` object does not indicate whether an attempt was throttled; all failed attempts return the exact same generic failure object (`Result[authenticated=false, message="Invalid username or password.", setCookieHeader=null]`), preventing upstream proxies or HTTP handlers from applying rate-limiting delays.

**Fix:**
Reject authentication attempts immediately when `limiter.registerAttempt()` returns `Decision.THROTTLED` (especially when the source limit is exceeded), without performing the expensive PBKDF2 derivation. If account-lockout resistance is required, differentiate between source-level throttling (which must always reject) and account-level throttling, or enforce a uniform delay before rejecting.

```java
            LoginRateLimiter.Decision decision;
            try {
                decision = limiter.registerAttempt(sourceKey, subjectKey, now);
            } catch (RuntimeException e) {
                return internalFailure(now, subjectKey, sourceKey);
            }

            if (decision == LoginRateLimiter.Decision.THROTTLED) {
                logFailure(now, subjectKey, sourceKey, AuthenticationEvent.Reason.THROTTLED);
                return Result.failure();
            }

            Optional<CredentialStore.AuthenticatedPrincipal> principal = Optional.empty();
            try {
                if (canonical != null && validPassword) {
                    principal = credentials.verify(canonical, password);
                } else {
                    PasswordVerifier.verify(INVALID_PASSWORD.clone(), dummyRecord);
                }
            } catch (RuntimeException e) {
                return internalFailure(now, subjectKey, sourceKey);
            }

            if (principal.isPresent()) {
```

---

### SEC-02: Denial of Service via State Table Exhaustion in In-Memory Rate Limiter
- **Severity:** High
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `InMemoryLoginRateLimiter.java:40-43`

**Vulnerable code:**
```java
// InMemoryLoginRateLimiter.java:40-43
        // Capacity is checked for both maps before either is mutated.
        if ((!sources.containsKey(sourceKey) && sources.size() >= MAX_KEYS)
                || (!accounts.containsKey(accountKey) && accounts.size() >= MAX_KEYS)) {
            throw new IllegalStateException("Rate-limit capacity exhausted");
        }
```

**Why it is a problem:**
`InMemoryLoginRateLimiter` bounds its internal `sources` and `accounts` maps to `MAX_KEYS = 100_000`. When either map reaches 100,000 entries and a new key is received, `registerAttempt` throws an unhandled `IllegalStateException("Rate-limit capacity exhausted")`.

In `AuthenticationService.java:80-82`, catching `RuntimeException` routes this exception to `internalFailure(now, subjectKey, sourceKey)`, which rejects the attempt.

An unauthenticated remote attacker can submit 100,000 authentication requests specifying distinct randomized usernames (or from diverse IP addresses) within the configured time window (which can be up to 1 hour). Once the `accounts` table reaches capacity, every subsequent login attempt for any legitimate user whose account is not already present in the map triggers `IllegalStateException` and fails. This completely denies login service to legitimate users across the entire application until the time window elapses.

**Fix:**
Rather than throwing an unhandled exception that causes widespread authentication failure, implement an eviction strategy (such as least-recently-used eviction using a bounded `LinkedHashMap`) or fail closed by treating untracked keys as throttled without throwing an exception.

```java
        if (!sources.containsKey(sourceKey) && sources.size() >= MAX_KEYS) {
            return Decision.THROTTLED;
        }
        if (!accounts.containsKey(accountKey) && accounts.size() >= MAX_KEYS) {
            return Decision.THROTTLED;
        }
```

---

### SEC-03: Global Session Store Capacity Exhaustion Causes Application-Wide Denial of Service
- **Severity:** Medium
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `InMemorySessionStore.java:27-29`

**Vulnerable code:**
```java
// InMemorySessionStore.java:27-29
        if (!expiresAt.isAfter(now) || expiresAt.isAfter(now.plusSeconds(86_400)) || sessions.size() >= maximum) {
            return false;
        }
```

**Why it is a problem:**
`InMemorySessionStore` enforces a global maximum session count (`sessions.size() >= maximum`), but lacks any per-account session quota or eviction policy.

A single user account (or an attacker who has compromised one low-privileged account) can authenticate repeatedly in a script until `sessions.size() == maximum`. Once global capacity is reached, `sessions.create()` returns `false` for every subsequent authentication request across the entire system.

In `AuthenticationService.java:103-105`:
```java
if (!sessions.create(tokenDigest, principal.get().accountId(), expires)) {
    return internalFailure(now, subjectKey, sourceKey);
}
```
All subsequent login attempts for all legitimate users fail with `internalFailure`, denying access to the entire application until existing sessions expire (up to 24 hours).

**Fix:**
Track active session counts per `accountId` and enforce a per-account session quota. When an account exceeds its quota, evict the account's oldest session. If the global capacity is approached, evict the oldest expired or least-recently-used session rather than denying session creation globally.

```java
        if (!expiresAt.isAfter(now) || expiresAt.isAfter(now.plusSeconds(86_400))) {
            return false;
        }
        if (sessions.size() >= maximum) {
            var oldest = sessions.entrySet().stream()
                    .min(java.util.Comparator.comparing(e -> e.getValue().expiresAt()));
            oldest.ifPresent(e -> sessions.remove(e.getKey()));
        }
        if (sessions.size() >= maximum) {
            return false;
        }
```

---

### SEC-04: Collision and Cross-User Throttling via Shared Correlation Key for Malformed Usernames
- **Severity:** Low
- **CWE:** CWE-20: Improper Input Validation
- **Location:** `AuthenticationService.java:71`

**Vulnerable code:**
```java
// AuthenticationService.java:71
        String subjectKey = correlate("account", canonical == null ? "invalid" : canonical);
```

**Why it is a problem:**
When a username fails validation (`validUsername(username)` is false due to invalid characters, empty input, or length exceeding 64 characters), `canonical` is set to `null`. Line 71 substitutes the literal string `"invalid"` as the account name for computing the HMAC correlation key.

However, `"invalid"` is also a syntactically valid username under the regex `[a-z0-9][a-z0-9._@-]{0,63}`.
This leads to two issues:
1. **Targeted Denial of Service:** If an account named `"invalid"` exists in the system, all malformed login attempts from any user or automated scanner increment that account's rate-limiting counter, causing the legitimate user `"invalid"` to be throttled.
2. **Aggregated Throttling:** All malformed requests across the system share a single rate-limiting bucket. An automated vulnerability scanner sending invalid input characters will immediately exhaust the shared `"invalid"` bucket, skewing rate-limiting telemetry.

**Fix:**
Use a separate correlation domain or a non-colliding identifier for invalid usernames (such as combining the source address with a dedicated domain tag) so that invalid inputs never collide with valid user accounts.

```java
        String subjectKey = canonical == null
                ? correlate("invalid-input", HexFormat.of().formatHex(sourceBytes))
                : correlate("account", canonical);
```

## 6. Verified Controls and Checks With No Finding
- **Password Hashing Work Factor and Salt Generation:** Verified in `PasswordVerifier.java:17-29` and `PasswordRecord.java:10-25`. Passwords are hashed using PBKDF2-HMAC-SHA-256 with a minimum of 600,000 iterations (and maximum of 2,000,000 iterations) and a 128-bit cryptographically secure salt generated via `SecureRandom`.
- **Constant-Time Password Hash Comparison:** Verified in `PasswordVerifier.java:31-40`. Password verification uses `MessageDigest.isEqual` to compare derived candidate bytes with expected hash bytes, preventing timing side-channel attacks during hash comparison.
- **Timing Attack Resistance on User Enumeration:** Verified in `InMemoryCredentialStore.java:43-51` and `AuthenticationService.java:86-90`. Non-existent usernames and malformed inputs execute a dummy PBKDF2 derivation (`PasswordVerifier.verify(..., dummyRecord)`) with identical iteration counts, ensuring comparable execution time across all failure paths.
- **Session Token Entropy and Storage Security:** Verified in `AuthenticationService.java:99-105` and `SessionStore.java:5-9`. Bearer tokens contain 256 bits of entropy generated via `SecureRandom`. Only the SHA-256 digest of the token is stored in the session store, ensuring that a database compromise does not reveal usable bearer tokens.
- **Cookie Attribute Security:** Verified in `AuthenticationService.java:119-122`. The session cookie uses the `__Host-session` prefix, `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, omits the `Domain` attribute, and specifies an explicit `Max-Age`, adhering to RFC 6265bis.
- **Sensitive Memory Clearing:** Verified in `AuthenticationService.java:128-133`, `PasswordVerifier.java:25-28, 36-39, 59-61`, and `InMemoryCredentialStore.java:38-40`. Plaintext password character arrays, derived hash byte arrays, session token bytes, and IP address buffers are zeroed using `Arrays.fill` within `finally` blocks.
- **Diagnostic Information Redaction:** Verified in `PasswordRecord.java:47` and `AuthenticationService.Result.java:225-228`. Both classes override `toString()` to redact credential material and session cookie values, preventing accidental leakage in application logs or stack traces.
- **Audit Log Pseudonymization:** Verified in `AuthenticationService.java:183-193` and `AuthenticationEvent.java:6-9`. All logged subjects, sources, and sessions are pseudonymized using domain-separated HMAC-SHA-256 with an injected 256-bit key. Raw usernames, passwords, IP addresses, and session tokens never reach audit sinks.
- **Audit Log Injection Prevention:** Verified in `AuthenticationEvent.java:13-30` and `PrivateRollingFileAuditSink.java:93-98`. All audit event fields are strictly validated types (UUID, ISO-8601 Instant, enums, and 64-character lowercase hex strings), preventing CRLF injection or log forgery attacks.
- **Audit Log File System Hardening:** Verified in `PrivateRollingFileAuditSink.java:29-49, 67-76`. The audit sink requires an existing directory with strict POSIX `0700` permissions, creates log files with POSIX `0600` permissions, uses `LinkOption.NOFOLLOW_LINKS` to reject symbolic links, locks files via `FileChannel.lock()`, and enforces bounded log rotation.
- **Fail-Closed Session Creation on Audit Failure:** Verified in `AuthenticationService.java:110-118`. If appending the authentication event to the audit sink fails, the newly generated session is immediately revoked via `safeRevoke(tokenDigest)` and `Result.failure()` is returned.
- **Generic Caller Error Responses:** Verified in `AuthenticationService.java:23, 217-229`. All authentication failures return the identical generic message (`"Invalid username or password."`) and identical null cookie headers, preventing account enumeration by error response content.
