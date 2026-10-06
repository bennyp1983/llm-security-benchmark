# Security Review: Secure User Authentication & Audit Logging Component (`com.security.auth`)

## 1. Executive Summary

The component is a self-contained Java 17 username/password authentication library. `DefaultAuthenticationService` validates client input, applies a sliding-window rate limiter, looks up a `UserRecord` in a repository, verifies the password with PBKDF2-HMAC-SHA512 (210,000 iterations, `SecureRandom` salts, `MessageDigest.isEqual` comparison), issues a 256-bit `SecureRandom` session token, and writes an audit event to a 0600 file via `SecureFileEventLogger`. The cryptographic core is sound: no weak algorithms, no hardcoded usable secrets, no SQL/command/deserialization sinks, constant-time hash comparison, and dummy PBKDF2 work on every failure branch.

The weaknesses are concentrated in the security decisions built on *client-controlled* data and in the audit trail:

- **High:** the rate limiter is keyed on the client-supplied IP string from `AuthenticationRequest`, which is only format-validated. An attacker who controls that value (the usual case when it is taken from `X-Forwarded-For`) rotates it per request and bypasses both source-based brute-force limits (SEC-01).
- **Medium:** when the tracker map reaches its cap the limiter calls `clear()`, wiping *all* attempt counters at once (SEC-02); the global per-account window lets any remote attacker throttle a victim's logins (SEC-03); the per-cause internal error code is exposed on the result object returned to callers (SEC-04); unvalidated usernames are written into a delimiter-structured log line whose sanitiser does not escape delimiters or Unicode line separators (SEC-05); audit writes are silently discarded once the log hits 50 MB, with no rotation (SEC-06); and the dummy PBKDF2 workload always uses the hasher's default iteration count rather than the record's, giving a timing oracle in any deployment with mixed iteration counts (SEC-07).
- **Low:** every audit line is re-emitted through SLF4J to an uncontrolled sink (SEC-08), and the non-POSIX fallback creates the log file with the default umask before restricting it (SEC-09).

No Critical issues were found. Nine findings are reported; verified controls are listed in section 6.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/security/auth/AuthenticationService.java` | Interface for the authenticate operation. | None (contract only). |
| `src/main/java/com/security/auth/DefaultAuthenticationService.java` | Orchestrates validation → rate limit → lookup → status check → password verify → token issue → audit log. | Security decisions on client input, fail-closed error handling, per-branch dummy hashing, credential zeroization in `finally`, audit event construction. |
| `src/main/java/com/security/auth/AuthenticationRequest.java` | Carries username, `char[]` password, client IP across the trust boundary. | Password array copy + zeroization, redacting `toString()`, exposes raw client IP used for rate limiting. |
| `src/main/java/com/security/auth/AuthenticationResult.java` | Result object with a uniform failure message. | Generic user message, but also exposes the internal per-cause error code. |
| `src/main/java/com/security/auth/AuthenticationErrorCode.java` | Enum of internal failure causes. | Documented as "never revealed to clients". |
| `src/main/java/com/security/auth/validation/InputValidator.java` | Allow-list validation of username, password length, IPv4/IPv6 literal. | Regex allow-lists, length bounds, no DNS resolution. |
| `src/main/java/com/security/auth/validation/ValidationException.java` | Checked validation failure. | Messages go to log only. |
| `src/main/java/com/security/auth/crypto/PasswordHasher.java` | Hashing/verification interface. | Declares constant-time verify and dummy verification. |
| `src/main/java/com/security/auth/crypto/Pbkdf2PasswordHasher.java` | PBKDF2WithHmacSHA512 hashing, verification, dummy workload. | KDF parameters, `SecureRandom` salts, `MessageDigest.isEqual`, buffer zeroization, timing equalisation. |
| `src/main/java/com/security/auth/crypto/TokenGenerator.java` | Issues session tokens. | 256-bit `SecureRandom` entropy, URL-safe Base64, 1-hour lifetime. |
| `src/main/java/com/security/auth/model/SessionToken.java` | Session token value object. | Minimum length check, hardened `Set-Cookie` string, SHA-256 audit fingerprint. |
| `src/main/java/com/security/auth/model/UserRecord.java` | Server-side credential record. | Validates username/hash/salt/iteration bounds, defensive array copies. |
| `src/main/java/com/security/auth/model/AccountStatus.java` | ACTIVE/SUSPENDED/LOCKED. | Gate for non-active accounts. |
| `src/main/java/com/security/auth/repository/UserCredentialRepository.java` | Read-only lookup interface. | Server-side state boundary. |
| `src/main/java/com/security/auth/repository/InMemoryUserCredentialRepository.java` | `ConcurrentHashMap` store with capacity cap. | Bounded storage, exact-match username lookup. |
| `src/main/java/com/security/auth/ratelimit/RateLimiter.java` | Rate-limiter interface ("count, then allow"). | Atomicity contract. |
| `src/main/java/com/security/auth/ratelimit/SlidingWindowRateLimiter.java` | Sliding windows per source IP, per (IP, account), per account. | Brute-force/credential-stuffing throttling, bounded tracker cache, `synchronized` atomicity. |
| `src/main/java/com/security/auth/logging/AuthenticationEventLogger.java` | Logger interface. | Event retention contract. |
| `src/main/java/com/security/auth/logging/AuthenticationEvent.java` | Immutable audit event. | CRLF/control-char sanitisation, length bounds, log-line formatting. |
| `src/main/java/com/security/auth/logging/AuthenticationEventType.java` | Event type enum. | Distinguishes failure causes in the log. |
| `src/main/java/com/security/auth/logging/SecureFileEventLogger.java` | Appends events to a private file, retains last 1,000 in memory. | POSIX 0600/0700 permissions, symlink rejection, `NOFOLLOW_LINKS`, size cap, SLF4J mirror. |
| `pom.xml` | Build definition. | Pinned dependency versions (slf4j-api 2.0.16, JUnit 5.10.2); no vulnerable or unpinned artifacts. |
| `src/test/java/...` (4 test classes) | Unit tests for hasher, validator, rate limiter, logger, timing and concurrency. | Reviewed only to confirm intended security behaviour; no test-only credentials that work against production code. |

## 3. Skills Applied

- `performing-cryptographic-audit-of-application`: applied to `Pbkdf2PasswordHasher`, `TokenGenerator`, `SessionToken` — checked KDF choice and iteration count, salt generation and length, key length, hash comparison, RNG source, truncated digest use, and hardcoded key/secret material.
- `testing-api-authentication-weaknesses`: applied to `DefaultAuthenticationService`, `AuthenticationResult`, `TokenGenerator`, `SessionToken` — checked credential-stuffing resistance, response/observable discrepancies between failure causes, token entropy and lifetime, token leakage into logs, and session revocation.
- `performing-api-rate-limiting-bypass`: applied to `SlidingWindowRateLimiter` and the call site in `DefaultAuthenticationService` — checked key derivation from client-controlled identifiers (the `X-Forwarded-For`-style spoofing class), counter reset behaviour, and window/threshold arithmetic. Produced SEC-01 and SEC-02.
- `testing-for-sensitive-data-exposure`: applied to `AuthenticationEvent`, `SecureFileEventLogger`, `AuthenticationRequest.toString()`, `SessionToken` — checked what reaches the log file and secondary sinks, file permissions, and plaintext secret/token retention.
- Behaviour reviewed against general OWASP Top 10 / CWE knowledge because no library skill matched: log injection and audit-trail integrity/availability (CWE-117, CWE-779) in `AuthenticationEvent`/`SecureFileEventLogger`; timing side channels in the dummy-verification path (CWE-208); account-lockout denial of service (CWE-645); file-creation permission race in the non-POSIX fallback (CWE-732/CWE-377); and the concurrency ("check then act") claims of `SlidingWindowRateLimiter` and `SecureFileEventLogger`. There are no SQL, OS-command, path-traversal from user input, XML/deserialization, SSRF, or HTML-rendering sinks anywhere in the component, so the corresponding skills were not applicable.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Rate limiting keyed on client-supplied IP address, enabling brute-force bypass | High | CWE-807 | `src/main/java/com/security/auth/DefaultAuthenticationService.java:63-88` |
| SEC-02 | Tracker cache overflow wipes all rate-limit counters | Medium | CWE-307 | `src/main/java/com/security/auth/ratelimit/SlidingWindowRateLimiter.java:199-201` |
| SEC-03 | Global per-account window lets a remote attacker lock out a victim | Medium | CWE-645 | `src/main/java/com/security/auth/ratelimit/SlidingWindowRateLimiter.java:94-100` |
| SEC-04 | Per-cause internal error code exposed on the result returned to callers | Medium | CWE-204 | `src/main/java/com/security/auth/AuthenticationResult.java:51-53` |
| SEC-05 | Log forging via unvalidated username in a delimiter-structured log line | Medium | CWE-117 | `src/main/java/com/security/auth/logging/AuthenticationEvent.java:71-85` |
| SEC-06 | Audit events silently discarded once the log file reaches its size cap | Medium | CWE-779 | `src/main/java/com/security/auth/logging/SecureFileEventLogger.java:156-162` |
| SEC-07 | Dummy verification uses default iteration count, leaking account existence by timing | Medium | CWE-208 | `src/main/java/com/security/auth/crypto/Pbkdf2PasswordHasher.java:110` |
| SEC-08 | Every audit line mirrored to an SLF4J sink with no permission control | Low | CWE-532 | `src/main/java/com/security/auth/logging/SecureFileEventLogger.java:168-172` |
| SEC-09 | Non-POSIX fallback creates the log file with default umask before restricting it | Low | CWE-732 | `src/main/java/com/security/auth/logging/SecureFileEventLogger.java:106-109` |

## 5. Detailed Findings

### SEC-01: Rate limiting keyed on client-supplied IP address, enabling brute-force bypass
- **Severity:** High
- **CWE:** CWE-807: Reliance on Untrusted Inputs in a Security Decision
- **Location:** `src/main/java/com/security/auth/DefaultAuthenticationService.java:63-88` (with `src/main/java/com/security/auth/validation/InputValidator.java:87-98`)

**Vulnerable code:**
```java
// src/main/java/com/security/auth/DefaultAuthenticationService.java:61-88
            String rawUsername = request.getRawUsername();
            char[] rawPassword = request.getPassword();
            String rawClientIp = request.getClientIp();

            // 1. Trust boundary: Validate all client-supplied inputs (Rule 1)
            String validatedUsername;
            String validatedClientIp;
            try {
                validatedUsername = InputValidator.validateUsername(rawUsername);
                InputValidator.validatePassword(rawPassword);
                validatedClientIp = InputValidator.validateClientIp(rawClientIp);
            } catch (ValidationException ve) {
...
            RateLimitStatus rateLimitStatus = rateLimiter.acquireAttempt(validatedClientIp, validatedUsername);
```

**Why it is a problem:** `validateClientIp` only checks that the string *looks like* an IPv4/IPv6 literal; it does not and cannot establish that the address is the peer's real address. The value arrives inside `AuthenticationRequest`, documented as "client metadata" (`AuthenticationRequest.java:6`), and in every realistic deployment is populated from a request header such as `X-Forwarded-For`, `X-Real-IP` or `True-Client-IP`. Two of the three rate-limit windows (`SRC:` and `SRC_ACC:`) are keyed on it, so an attacker who sends a different well-formed literal on each request gets a fresh counter every time: the 10-attempts-per-IP and 5-attempts-per-(IP, account) limits never fire, and the only remaining brake is the global 25-attempts-per-account window. Credential stuffing across many accounts is then effectively unthrottled, which defeats the component's primary anti-brute-force control. Format-validating an attacker-controlled value does not make it trustworthy — the security decision must be bound to a value the attacker cannot choose.

**Fix:** Require the caller to supply a transport-level peer address and keep the client-asserted value for logging only. Give `AuthenticationRequest` a separate, non-client field (e.g. the socket peer address, or an `X-Forwarded-For` entry trusted only when it was appended by a known reverse proxy) and key the limiter on that; if the deployment cannot provide one, fail closed rather than rate-limit on spoofable data.

```java
// DefaultAuthenticationService.authenticate - key the limiter on the transport peer address
            String rawUsername = request.getRawUsername();
            char[] rawPassword = request.getPassword();
            // Address observed by the server's transport layer; never read from a client header
            String rawPeerIp = request.getTrustedPeerIp();

            String validatedUsername;
            String validatedPeerIp;
            try {
                validatedUsername = InputValidator.validateUsername(rawUsername);
                InputValidator.validatePassword(rawPassword);
                // Fails closed when the caller could not establish a trusted peer address
                validatedPeerIp = InputValidator.validateClientIp(rawPeerIp);
            } catch (ValidationException ve) {
                // ... unchanged dummy-verification / logging / generic failure path ...
                throw ve;
            }

            // Rate-limit decisions use only the non-spoofable peer address
            RateLimitStatus rateLimitStatus = rateLimiter.acquireAttempt(validatedPeerIp, validatedUsername);
```

### SEC-02: Tracker cache overflow wipes all rate-limit counters
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/security/auth/ratelimit/SlidingWindowRateLimiter.java:190-203`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/ratelimit/SlidingWindowRateLimiter.java:190-203
    private void maybePruneExpiredEntries(long now, long windowMillis) {
        if (cleanupCounter.incrementAndGet() % 100 == 0 || trackerMap.size() >= maxCacheEntries) {
            Iterator<Map.Entry<String, WindowTracker>> iterator = trackerMap.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<String, WindowTracker> entry = iterator.next();
                if (entry.getValue().isExpired(now, windowMillis)) {
                    iterator.remove();
                }
            }
            if (trackerMap.size() >= maxCacheEntries) {
                trackerMap.clear();
            }
        }
    }
```

**Why it is a problem:** When pruning cannot bring the map below `maxCacheEntries` (10,000 by default) because the entries are *live*, the limiter deletes every window — including the ones that are currently blocking an in-progress attack. Each attempt creates up to three entries (`SRC:`, `SRC_ACC:`, `ACC:`), so roughly 3,300 distinct (IP, username) pairs inside a 15-minute window are enough to trip it; a distributed credential-stuffing run reaches that trivially, and combined with SEC-01 a single host can do it alone by rotating the asserted IP. The attacker then repeats the flood to reset counters on demand, so no account or source ever reaches its threshold. Choosing availability over enforcement here converts the memory bound into a brute-force bypass primitive.

**Fix:** Never bulk-clear enforcement state. Bound memory by evicting the entries closest to expiry (or the least recently touched), and when the cache is still full, fail closed by throttling the new key instead of forgetting the old ones.

```java
    private void maybePruneExpiredEntries(long now, long windowMillis) {
        if (cleanupCounter.incrementAndGet() % 100 == 0 || trackerMap.size() >= maxCacheEntries) {
            trackerMap.entrySet().removeIf(entry -> entry.getValue().isExpired(now, windowMillis));
        }
    }

    /** Returns true when a new key cannot be tracked, so the caller must fail closed. */
    private boolean cacheExhausted() {
        return trackerMap.size() >= maxCacheEntries;
    }

    @Override
    public synchronized RateLimitStatus acquireAttempt(String clientIp, String username) {
        long now = clock.millis();
        long windowMillis = windowDuration.toMillis();
        maybePruneExpiredEntries(now, windowMillis);

        String sourceKey = (clientIp != null) ? "SRC:" + clientIp : null;
        // Fail closed rather than discarding existing counters (Rule 3/Rule 6)
        if (cacheExhausted() && sourceKey != null && !trackerMap.containsKey(sourceKey)) {
            return RateLimitStatus.SOURCE_RATE_LIMITED;
        }
        // ... existing checks and registration unchanged ...
        return RateLimitStatus.ALLOWED;
    }
```

### SEC-03: Global per-account window lets a remote attacker lock out a victim
- **Severity:** Medium
- **CWE:** CWE-645: Overly Restrictive Account Lockout Mechanism
- **Location:** `src/main/java/com/security/auth/ratelimit/SlidingWindowRateLimiter.java:94-100` (threshold at line 23)

**Vulnerable code:**
```java
// src/main/java/com/security/auth/ratelimit/SlidingWindowRateLimiter.java:94-100
        // 3. Check if global account limit is exceeded
        if (accKey != null) {
            WindowTracker tracker = trackerMap.get(accKey);
            if (tracker != null && tracker.isBlocked(now, windowMillis, maxGlobalAccountAttempts)) {
                return RateLimitStatus.ACCOUNT_RATE_LIMITED;
            }
        }
```

**Why it is a problem:** The `ACC:` window counts *every* attempt against a username regardless of source and regardless of outcome, and `recordSuccess` only removes the single timestamp the successful attempt itself added (`SlidingWindowRateLimiter.java:179-184`). An attacker who knows a victim's username can therefore spend 25 junk attempts in 15 minutes and the victim's own, correct logins are refused from every source — exactly the "use your own limit to lock a legitimate user out" scenario the design set out to avoid. Because the per-(IP, account) and per-source windows already contain targeted abuse, the global window's cost here falls almost entirely on the legitimate user.

**Fix:** Do not let the global account window reject attempts outright. Keep it as a signal (step-up challenge, or counting only *failed* attempts from *unrecognised* sources) and always admit attempts from a source that has recently authenticated successfully for that account, so a remote attacker cannot deny the owner access.

```java
        // 3. Global account window: throttle only sources with no recent successful login for
        //    this account, so an attacker cannot lock the legitimate owner out (Rule 3)
        if (accKey != null && !hasRecentSuccess(clientIp, username, now, windowMillis)) {
            WindowTracker tracker = trackerMap.get(accKey);
            if (tracker != null && tracker.isBlocked(now, windowMillis, maxGlobalAccountAttempts)) {
                return RateLimitStatus.ACCOUNT_RATE_LIMITED;
            }
        }
```

### SEC-04: Per-cause internal error code exposed on the result returned to callers
- **Severity:** Medium
- **CWE:** CWE-204: Observable Response Discrepancy
- **Location:** `src/main/java/com/security/auth/AuthenticationResult.java:51-53` (populated at `src/main/java/com/security/auth/DefaultAuthenticationService.java:127` and `:159`)

**Vulnerable code:**
```java
// src/main/java/com/security/auth/AuthenticationResult.java:51-53
    public AuthenticationErrorCode getInternalErrorCode() {
        return internalErrorCode;
    }
```

**Why it is a problem:** `AuthenticationErrorCode` is documented as "Internal error codes for logging and audit purposes only ... These must NEVER be revealed directly to external clients" (`AuthenticationErrorCode.java:4-6`), yet the only object that crosses back to the caller carries it on a public getter, with a distinct value per cause: `USER_NOT_FOUND` vs `INVALID_CREDENTIALS` vs `ACCOUNT_LOCKED_OR_SUSPENDED` vs `RATE_LIMITED_*`. The uniform `GENERIC_FAILURE_MESSAGE` is therefore only one serialisation choice away from being bypassed: any web layer that maps the code to an HTTP status, an error body, a metric label or a debug header turns it into a username-enumeration and account-state oracle. Audit detail belongs on the event already written to the log, not on the client-facing result.

**Fix:** Keep the cause off the returned object. Pass it to the logger only, and if callers need a coarse signal, expose a deliberately non-discriminating one (e.g. a boolean "retry later" for throttling) that cannot distinguish existing from non-existing accounts.

```java
public final class AuthenticationResult {
    // Cause is recorded in the audit event only; it is not carried across the trust boundary (Rule 6)
    private final boolean success;
    private final String userMessage;
    private final SessionToken sessionToken;

    public static AuthenticationResult failure() {
        return new AuthenticationResult(false, GENERIC_FAILURE_MESSAGE, null);
    }

    public boolean isSuccess() {
        return success;
    }

    public String getUserMessage() {
        return userMessage;
    }
    // no getInternalErrorCode(): every failure is indistinguishable to the caller
}
```

### SEC-05: Log forging via unvalidated username in a delimiter-structured log line
- **Severity:** Medium
- **CWE:** CWE-117: Improper Output Neutralization for Logs
- **Location:** `src/main/java/com/security/auth/logging/AuthenticationEvent.java:71-85` and `:90-99` (raw input reaches it from `src/main/java/com/security/auth/DefaultAuthenticationService.java:76-82`)

**Vulnerable code:**
```java
// src/main/java/com/security/auth/logging/AuthenticationEvent.java:71-85
    private static String sanitizeAndBound(String input, int maxLength, String fallback) {
        if (input == null || input.isBlank()) {
            return fallback;
        }
        // Neutralize carriage returns, newlines, and tabs to prevent log forging
        String sanitized = input.replace('\r', '_')
                .replace('\n', '_')
                .replace('\t', ' ')
                .replaceAll("[\\p{Cntrl}]", "");

        if (sanitized.length() > maxLength) {
            return sanitized.substring(0, maxLength);
        }
        return sanitized;
    }
```

**Why it is a problem:** On the validation-failure path the service logs `rawUsername` and `rawClientIp` — values that failed validation and are fully attacker-chosen (`DefaultAuthenticationService.java:79-80`). `sanitizeAndBound` strips ASCII control characters but leaves the very characters that give `toLogLine()` its structure: `|`, `=`, `"` and spaces. A username of `x | outcome=SUCCESS | event=LOGIN_SUCCESS | user=admin | ip=10.0.0.1 | token_fp=none | details="ok` is written verbatim into the `user=` field, so any SIEM or script that splits on `|`/`=` ingests a fabricated successful-login record for `admin`, with the attacker's own failure hidden inside it. Java's `\p{Cntrl}` is also ASCII-only by default, so U+0085 (NEL), U+2028 and U+2029 survive and are treated as line breaks by a number of log viewers and parsers, re-enabling true line injection. Forgeable audit records undermine the one artefact an incident responder relies on.

**Fix:** Emit structured output rather than hand-formatted text, and neutralise the delimiters as well as all Unicode line/control characters. The snippet below escapes the field separators and quotes and widens the control-character class; pairing it with a JSON encoder for `toLogLine()` removes the ambiguity entirely.

```java
    private static String sanitizeAndBound(String input, int maxLength, String fallback) {
        if (input == null || input.isBlank()) {
            return fallback;
        }
        // Strip all Unicode control/line/paragraph separators, then neutralize field delimiters
        String sanitized = input.replaceAll("[\\p{Cntrl}\\p{Zl}\\p{Zp}\\u0085\\u2028\\u2029]", "")
                .replace('\t', ' ')
                .replace("\\", "\\\\")
                .replace("|", "\\u007C")
                .replace("=", "\\u003D")
                .replace("\"", "\\\"");

        if (sanitized.length() > maxLength) {
            return sanitized.substring(0, maxLength);
        }
        return sanitized;
    }
```

### SEC-06: Audit events silently discarded once the log file reaches its size cap
- **Severity:** Medium
- **CWE:** CWE-779: Logging of Excessive Data (audit-trail loss through unmanaged log growth)
- **Location:** `src/main/java/com/security/auth/logging/SecureFileEventLogger.java:156-162`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/logging/SecureFileEventLogger.java:155-165
        try {
            if (Files.exists(logFilePath) && Files.size(logFilePath) >= maxLogFileSizeBytes) {
                SLF4J_LOGGER.warn("Authentication log file exceeded maximum size of {} bytes. Write omitted to bound storage.", maxLogFileSizeBytes);
            } else {
                writer.write(logLine);
                writer.newLine();
                writer.flush();
            }
        } catch (IOException e) {
            SLF4J_LOGGER.error("Failed to write authentication event to log file", e);
        }
```

**Why it is a problem:** There is no rotation, truncation or archival anywhere in the class, so once the file reaches 50 MB the audit log stops recording *permanently* and the component keeps authenticating. An attacker can reach that state deliberately: each failed attempt writes a line of roughly 200 bytes, and with the source limit defeated (SEC-01) or spread across a botnet, ~250k attempts fill the file — after which the real intrusion leaves no durable record. Even without an attacker, a busy service silently loses its audit trail. Bounding storage is correct; dropping the evidence instead of rolling it over is not.

**Fix:** Rotate the file when it reaches the cap (renaming the current file to a timestamped sibling created with the same 0600 permissions, keeping a bounded number of generations) so writes always succeed, and treat persistent write failure as an alertable condition rather than a warning.

```java
        try {
            if (Files.size(logFilePath) >= maxLogFileSizeBytes) {
                rotateLogFile();   // rename to <log>.<timestamp>, recreate 0600, drop oldest generation
            }
            writer.write(logLine);
            writer.newLine();
            writer.flush();
        } catch (IOException e) {
            SLF4J_LOGGER.error("Failed to write authentication event to log file", e);
        }
```

### SEC-07: Dummy verification uses default iteration count, leaking account existence by timing
- **Severity:** Medium
- **CWE:** CWE-208: Observable Timing Discrepancy
- **Location:** `src/main/java/com/security/auth/crypto/Pbkdf2PasswordHasher.java:110` (compare with `:94`)

**Vulnerable code:**
```java
// src/main/java/com/security/auth/crypto/Pbkdf2PasswordHasher.java:106-112
    public void performDummyVerification(char[] password) {
        char[] pwdToUse = (password != null && password.length > 0) ? password : DUMMY_FALLBACK_PASSWORD;
        byte[] computedHash = null;
        try {
            computedHash = hashPassword(pwdToUse, this.dummySalt, this.defaultIterations);
            // Execute constant-time comparison to match real verification execution profile
            MessageDigest.isEqual(computedHash, this.dummyExpectedHash);
```

**Why it is a problem:** Real verification derives the key with the *record's* iteration count (`computedHash = hashPassword(password, record.getSalt(), record.getIterations())`, line 94), while every failure branch derives it with the hasher's `defaultIterations`. PBKDF2 runtime is linear in the iteration count, and `UserRecord` accepts anything from 1,000 to 2,000,000 (`UserRecord.java:36`), so in any deployment with mixed parameters — a legacy cohort, an in-progress rehash, or a cost increase — "user does not exist" takes measurably different time from "user exists with non-default cost". That is a remotely observable enumeration oracle, the exact attack the dummy workload was added to close. The same mismatch exists for the account-status and validation branches.

**Fix:** Make the dummy workload use the same iteration count as the record would have, by taking the target cost as a parameter and precomputing a dummy expectation for it; where no record is available, use the repository's current cost for the looked-up account class rather than the hasher default.

```java
    @Override
    public void performDummyVerification(char[] password, int iterations) {
        char[] pwdToUse = (password != null && password.length > 0) ? password : DUMMY_FALLBACK_PASSWORD;
        int effectiveIterations = (iterations >= 1000) ? iterations : this.defaultIterations;
        byte[] computedHash = null;
        try {
            // Match the cost of a real verification for this account's stored parameters (Rule 6)
            computedHash = hashPassword(pwdToUse, this.dummySalt, effectiveIterations);
            MessageDigest.isEqual(computedHash, dummyExpectedHashFor(effectiveIterations));
        } finally {
            if (computedHash != null) {
                Arrays.fill(computedHash, (byte) 0);
            }
        }
    }
```

### SEC-08: Every audit line mirrored to an SLF4J sink with no permission control
- **Severity:** Low
- **CWE:** CWE-532: Insertion of Sensitive Information into Log File
- **Location:** `src/main/java/com/security/auth/logging/SecureFileEventLogger.java:168-172`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/logging/SecureFileEventLogger.java:167-172
        // Also emit via standard platform logger for central logging integrations
        if (event.isSuccess()) {
            SLF4J_LOGGER.info("Authentication Event: {}", logLine);
        } else {
            SLF4J_LOGGER.warn("Authentication Event: {}", logLine);
        }
```

**Why it is a problem:** The class takes considerable trouble to create its own log at 0600 inside a 0700 directory, then writes the identical line — usernames, client IPs, account-status and failure causes, and the token fingerprint — to whatever sink the host SLF4J binding points at: typically stderr or a shared application log with default (often 0644) permissions, frequently shipped onward. The private-file control is thereby reduced to the weakest of the two destinations, so local users or log consumers who were never meant to see authentication activity can read it. No password or raw token leaks, which keeps the severity low.

**Fix:** Make the mirror opt-in and non-identifying by default: emit only counters/event types to the platform logger and keep attributable fields in the private file.

```java
        // Mirror only non-attributable metadata; identifying fields stay in the private 0600 log (Rule 5)
        if (mirrorToPlatformLogger) {
            if (event.isSuccess()) {
                SLF4J_LOGGER.info("Authentication Event: event={}", event.getEventType().name());
            } else {
                SLF4J_LOGGER.warn("Authentication Event: event={}", event.getEventType().name());
            }
        }
```

### SEC-09: Non-POSIX fallback creates the log file with default umask before restricting it
- **Severity:** Low
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `src/main/java/com/security/auth/logging/SecureFileEventLogger.java:106-109` and `:128-139`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/logging/SecureFileEventLogger.java:106-109
            } catch (UnsupportedOperationException e) {
                Files.createFile(logFilePath);
                restrictFilePermissionsFallback(logFilePath.toFile(), false);
            }
```

**Why it is a problem:** On a non-POSIX file system the file is created with the process umask and only afterwards narrowed, leaving a window in which another local user can open it and retain a readable handle to all subsequent audit data. `restrictFilePermissionsFallback` also discards the `boolean` results of `setReadable`/`setWritable`/`setExecutable` (lines 129-138), so a failure to apply the restriction is never detected, and the surrounding code proceeds to log as if the file were private. The same pattern applies to the directory fallback at line 96-97.

**Fix:** Create the file atomically with the restrictive ACL (`AclFileAttributeView` on Windows, `PosixFilePermissions` elsewhere), and verify the result — refusing to log rather than logging to a file whose permissions could not be confirmed.

```java
            } catch (UnsupportedOperationException e) {
                Files.createFile(logFilePath);
                if (!restrictFilePermissionsFallback(logFilePath.toFile(), false)) {
                    throw new SecurityException("Unable to restrict log file permissions: " + logFilePath);
                }
            }

    /** Returns false if any restriction could not be applied, so the caller can fail closed. */
    private static boolean restrictFilePermissionsFallback(File file, boolean isDir) {
        boolean ok = file.setReadable(false, false) & file.setReadable(true, true)
                & file.setWritable(false, false) & file.setWritable(true, true);
        ok &= isDir
                ? (file.setExecutable(false, false) & file.setExecutable(true, true))
                : file.setExecutable(false, false);
        return ok;
    }
```

## 6. Verified Controls and Checks With No Finding

- Password hashing algorithm and parameters: `PBKDF2WithHmacSHA512`, 210,000 iterations, 512-bit output, 16-byte minimum salt (`crypto/Pbkdf2PasswordHasher.java:23-26`), with a 1,000-iteration floor enforced in both the constructor (`:40-42`) and `hashPassword` (`:70-72`). Meets current OWASP guidance for PBKDF2-HMAC-SHA512; no MD5/SHA-1, no DES/RC4, no ECB mode, no hand-rolled primitive anywhere in the component.
- Salt generation: per-record salts from `java.security.SecureRandom` with bounds 16–64 bytes (`crypto/Pbkdf2PasswordHasher.java:53-59`); no fixed, time-seeded or derived salts.
- Constant-time secret comparison: hash equality uses `MessageDigest.isEqual` (`crypto/Pbkdf2PasswordHasher.java:96`); no `Arrays.equals`, `==` or early-exit comparison on secret material.
- Session token generation: 32 bytes (256 bits) from `SecureRandom`, URL-safe Base64 without padding, never derived from or accepted from the caller (`crypto/TokenGenerator.java:45-51`); minimum length re-checked in `SessionToken` (`model/SessionToken.java:23-25`); expiry must follow issuance (`:30-32`).
- Token confidentiality in logs: only a truncated SHA-256 fingerprint of the token is logged (`model/SessionToken.java:76-83`), and the raw token never appears in an `AuthenticationEvent`; `AuthenticationRequest.toString()` redacts username, IP and password (`AuthenticationRequest.java:56-61`).
- Cookie hardening: `toSetCookieHeader` emits `Path=/; HttpOnly; Secure; SameSite=Strict` with a bounded `Max-Age`, and validates the cookie name against `^[a-zA-Z0-9_-]+$` so no header injection is possible through it (`model/SessionToken.java:61-68`).
- Hardcoded secrets: no credentials, keys or tokens in source or `pom.xml`. The only literal is `DUMMY_FALLBACK_PASSWORD` (`crypto/Pbkdf2PasswordHasher.java:28`), used solely as filler input to equalise timing; it authenticates nobody and is never compared against stored credentials, so CWE-798 does not apply.
- Credential lifetime in memory: the request copies the caller's array on construction (`AuthenticationRequest.java:19`), `clearCredentials()` zeroes it, the service always invokes it in a `finally` block (`DefaultAuthenticationService.java:190-195`), `PBEKeySpec.clearPassword()` clears the KDF copy (`crypto/Pbkdf2PasswordHasher.java:82`), derived hashes are zeroed (`:100`, `:115`), and the password is never converted to a `String`.
- Injection sinks: the component builds no SQL, LDAP, XPath or OS command, performs no deserialization, no XML/HTML parsing or rendering, no reflection on untrusted names, and no outbound network calls — so SQL injection, command injection, XXE, SSRF and XSS have no applicable sink. The only file path (`logFilePath`) is operator-supplied, not client-supplied, and is normalised to an absolute path (`logging/SecureFileEventLogger.java:57`).
- Input validation at the trust boundary: username restricted to `^[a-zA-Z0-9_.@-]{3,64}$` (`validation/InputValidator.java:13`) — rejecting CR, LF, NUL, quotes, `:`, `;` and path characters, which also guarantees the rate-limiter's `:`-delimited composite keys cannot be made ambiguous; password length bounded 8–128 (`:37-38`, `:74-76`); client IP accepted only as an IPv4/IPv6 literal with no DNS resolution (`:87-98`). Invalid input is rejected, never defaulted to something permissive.
- Fail-closed behaviour: a null request (`DefaultAuthenticationService.java:48-58`) and any unexpected exception (`:179-189`) both log and return a generic failure; the catch-all records only `ex.getClass().getSimpleName()`, so no stack trace or internal detail reaches the caller.
- Uniform failure messaging: all failure paths return `GENERIC_FAILURE_MESSAGE` and no session token (`AuthenticationResult.java:34-37`) — the residual discrepancy is the exposed error code recorded as SEC-04, not the message.
- Equalised work on failure: `performDummyVerification` runs on the validation-failure, rate-limited, user-not-found and non-active-account branches (`DefaultAuthenticationService.java:74, 91, 117, 134`), so all four do a full PBKDF2 derivation; the residual difference is the iteration-count mismatch recorded as SEC-07. The dummy salt and expected hash are precomputed once at construction (`crypto/Pbkdf2PasswordHasher.java:47-49`), avoiding a per-call timing artefact.
- Authentication decided against server-side state only: credentials are checked against a `UserRecord` fetched from the repository (`DefaultAuthenticationService.java:113`), account status must be exactly `ACTIVE` (`:133`) so unknown or future statuses deny access, and no client-supplied value can short-circuit the verification.
- Order of operations: rate limiting is applied before the repository lookup and before any hashing, so an unauthenticated attacker cannot use the login path as an unbounded PBKDF2 amplifier against a known account.
- Concurrency ("check then act") claims: all four `SlidingWindowRateLimiter` public methods are `synchronized` on the instance and `WindowTracker`'s mutators are `synchronized` on the tracker (`ratelimit/SlidingWindowRateLimiter.java:68, 117, 146, 164, 211-231`), so the count-then-allow sequence is atomic and no TOCTOU window exists between `isBlocked` and `addAttempt`. `recordSuccess`'s `removeLatest` was examined specifically: because `acquireAttempt` adds the timestamp and `recordSuccess` removes the newest one under the same monitor, a success is net-neutral and cannot erase another request's recorded failure. `SecureFileEventLogger.logEvent`, `getRecentEvents` and `close` are likewise `synchronized`, so interleaved writes cannot produce torn log lines.
- Bounded storage: tracker map capped at 10,000 entries with periodic pruning (`ratelimit/SlidingWindowRateLimiter.java:25, 190-203` — the overflow *strategy* is SEC-02, but growth itself is bounded), in-memory event retention capped at 1,000 with FIFO eviction (`logging/SecureFileEventLogger.java:148-151`), log file capped at 50 MB (`:156`), user repository capped at 10,000 with an explicit rejection rather than eviction (`repository/InMemoryUserCredentialRepository.java:39-42`), and all logged fields truncated to fixed maxima (`logging/AuthenticationEvent.java:12-14, 81-83`).
- Record integrity: `UserRecord` validates the username through the same validator, enforces hash 32–128 bytes, salt 16–64 bytes, iterations 1,000–2,000,000 and a non-blank algorithm, and returns defensive copies of both byte arrays (`model/UserRecord.java:23-48, 54-60`), so stored state cannot be mutated through a handed-out reference.
- Log file protection: 0600 file and 0700 directory attributes applied at creation, symlink rejection for both file and parent, a world-writable-parent check, existing-file permissions re-applied, and the writer opened with `LinkOption.NOFOLLOW_LINKS` in append mode (`logging/SecureFileEventLogger.java:73-125`) — defeating the symlink-swap class (CWE-59). Only the non-POSIX fallback is weaker, recorded as SEC-09.
- Dependencies: both third-party artifacts are pinned to specific released versions from Maven Central — `slf4j-api` 2.0.16 and `junit-jupiter` 5.10.2 (`pom.xml:19-20, 23-43`) — with `slf4j-simple` confined to test scope; no snapshot versions, version ranges, custom repositories, or code loaded from shared/world-writable locations.
- Scope note (not a defect of this component): the component issues session tokens but, by design, contains no session store, so token validation, revocation on logout/password change, and re-authentication are the host application's responsibility. The 1-hour default lifetime (`crypto/TokenGenerator.java:19`) is the only limit this code can enforce; integrators must add server-side session state to avoid non-revocable sessions.
