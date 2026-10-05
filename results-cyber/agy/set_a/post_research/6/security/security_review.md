# Security Review: User Authentication & Audit Logging Component

## 1. Executive Summary
A comprehensive security code review was performed on the User Authentication and Audit Logging Component, a Java-based implementation designed for secure username/password credential verification, session token issuance, sliding-window rate limiting, and private audit event logging. The component was analyzed across all source files, configuration files, and cryptographic workflows using specialized application security skills from the library alongside general OWASP Top 10 and CWE principles.

While the component incorporates multiple defensive controls—including constant-time password hash comparison, memory zeroization of `char[]` passwords, generic client error messages, and restrictive POSIX file permissions—the review identified seven (7) security vulnerabilities. The most critical issues involve:
1. Complete bypass of rate limiting due to indiscriminate in-memory cache wiping (`trackerMap.clear()`) when cache capacity is reached.
2. Denial of service via heap memory and CPU exhaustion resulting from unvalidated oversized passwords being passed directly into 210,000 PBKDF2 iterations during dummy timing verification.
3. Computational denial of service caused by executing full 210,000 PBKDF2 hashing operations on requests that have already been rejected by the rate limiter.
4. Incomplete audit log sanitization allowing log forging via Unicode line and paragraph separator characters (`\u2028`, `\u2029`).
5. Rate limit bypass on IPv6 addresses due to lack of canonical IP normalization across syntactically distinct representations.

Remediations for each finding have been provided with drop-in code fixes.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/security/auth/AuthenticationService.java` | Core service interface | Defines the contract for credential authentication and audit logging. |
| `src/main/java/com/security/auth/DefaultAuthenticationService.java` | Main authentication orchestrator | Orchestrates input validation, rate limiting, credential lookup, constant-time verification, dummy timing equalization, fail-closed exception handling, and memory zeroization. |
| `src/main/java/com/security/auth/AuthenticationRequest.java` | Authentication request DTO | Manages credentials across trust boundary; stores password as `char[]`, implements `AutoCloseable`, zeroizes memory on close, and masks credentials in `toString()`. |
| `src/main/java/com/security/auth/AuthenticationResult.java` | Authentication response DTO | Enforces uniform generic failure responses to prevent user enumeration; provides session token on success. |
| `src/main/java/com/security/auth/AuthenticationErrorCode.java` | Internal error enumeration | Defines internal error codes for audit logging without exposing details to clients. |
| `src/main/java/com/security/auth/crypto/PasswordHasher.java` | Password hashing interface | Defines contract for PBKDF2 hashing, constant-time verification, dummy timing protection, and salt generation. |
| `src/main/java/com/security/auth/crypto/Pbkdf2PasswordHasher.java` | PBKDF2 cryptographic implementation | Implements `PBKDF2WithHmacSHA512` (210,000 iterations), constant-time verification with `MessageDigest.isEqual`, dummy verification workload, and buffer zeroization. |
| `src/main/java/com/security/auth/crypto/TokenGenerator.java` | Session token generator | Generates 256-bit cryptographically secure session tokens using `SecureRandom` and clears temporary byte buffers. |
| `src/main/java/com/security/auth/model/SessionToken.java` | Session token model | Encapsulates token lifecycle, generates hardened `Set-Cookie` headers, and computes non-reversible SHA-256 fingerprints for logging. |
| `src/main/java/com/security/auth/model/UserRecord.java` | Server-side credential entity | Validates stored credential attributes, enforces bounds, and makes defensive copies of password hash and salt byte arrays. |
| `src/main/java/com/security/auth/model/AccountStatus.java` | Account state enumeration | Represents account status (`ACTIVE`, `SUSPENDED`, `LOCKED`) to enforce access control. |
| `src/main/java/com/security/auth/validation/InputValidator.java` | Untrusted input validator | Enforces username regex whitelist, password length bounds (8–128 characters), and IPv4/IPv6 address syntax validation without DNS resolution. |
| `src/main/java/com/security/auth/validation/ValidationException.java` | Validation exception | Checked exception thrown on trust boundary violation to halt processing. |
| `src/main/java/com/security/auth/ratelimit/RateLimiter.java` | Rate limiter contract | Defines interface for atomic count-then-allow rate limiting across source IP, account, and dual keys. |
| `src/main/java/com/security/auth/ratelimit/SlidingWindowRateLimiter.java` | Sliding window rate limiter | Implements sliding-window throttling with atomic checks, in-memory tracking maps, and cache cleanup. |
| `src/main/java/com/security/auth/repository/UserCredentialRepository.java` | Credential repository contract | Read-only interface for retrieving server-side user credentials by username. |
| `src/main/java/com/security/auth/repository/InMemoryUserCredentialRepository.java` | In-memory repository implementation | Thread-safe bounded credential store enforcing maximum capacity limits. |
| `src/main/java/com/security/auth/logging/AuthenticationEventType.java` | Audit event taxonomy | Enumerates granular authentication audit event classifications. |
| `src/main/java/com/security/auth/logging/AuthenticationEvent.java` | Immutable audit event | Formats audit log lines, bounds string field lengths, and strips standard control characters. |
| `src/main/java/com/security/auth/logging/AuthenticationEventLogger.java` | Event logger interface | Defines contract for logging authentication events and retrieving recent events. |
| `src/main/java/com/security/auth/logging/SecureFileEventLogger.java` | File-based audit logger | Enforces private POSIX permissions (0600 file, 0700 dir), symlink rejection (`NOFOLLOW_LINKS`), parent directory security, bounded file size, and retention buffer. |
| `pom.xml` | Maven build configuration | Manages project dependencies (JUnit 5, SLF4J), Java 17 baseline, and compiler security warning flags (`-Xlint:all`, `-Werror`). |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to PBKDF2WithHmacSHA512 password hashing parameters (210,000 iterations, 16-byte salt, 512-bit key length), SecureRandom salt generation, constant-time verification using `MessageDigest.isEqual`, algorithm compatibility verification, and dummy cryptographic workload execution.
- `testing-api-authentication-weaknesses`: Applied to authentication workflow, credential verification, generic failure responses against user enumeration, session token generation and entropy (256-bit SecureRandom), session expiration, and lockout / brute-force throttling mechanisms.
- `testing-for-sensitive-data-exposure`: Applied to credential handling in memory (char array wiping and key buffer clearing), secret redaction in `toString()`, token masking via SHA-256 fingerprinting in audit logs, and session cookie attributes.
- `exploiting-race-condition-vulnerabilities`: Applied to concurrency handling and atomicity of attempt acquisition (count-then-allow) in sliding-window rate limiting and thread-safe audit log writing.
- `performing-security-headers-audit`: Applied to session cookie security attributes (`HttpOnly; Secure; SameSite=Strict; Path=/`).
- General OWASP Top 10 / CWE knowledge: Applied to input validation bounds and Denial of Service defenses (CWE-20, CWE-400), log sanitization against CRLF injection and Unicode separator forging (CWE-117), and file permissions, symlink rejection, and disk bounds in filesystem logging (CWE-59, CWE-732).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Rate Limiter Cache Wipe on Capacity Enables Complete Rate Limit Bypass | High | CWE-307 | `src/main/java/com/security/auth/ratelimit/SlidingWindowRateLimiter.java:199-201` |
| SEC-02 | Denial of Service via Resource Exhaustion from Oversized Passwords in Dummy Timing Verification | High | CWE-400 | `src/main/java/com/security/auth/DefaultAuthenticationService.java:72-75` |
| SEC-03 | Computational Denial of Service via Cryptographic Execution on Throttled Requests | Medium | CWE-400 | `src/main/java/com/security/auth/DefaultAuthenticationService.java:88-91` |
| SEC-04 | Incomplete Sanitization of Unicode Line and Paragraph Separators in Audit Event Logger | Medium | CWE-117 | `src/main/java/com/security/auth/logging/AuthenticationEvent.java:76-80` |
| SEC-05 | Lack of IPv6 Canonicalization Permits Rate Limiting Bypass via Alternative Syntactic Representations | Medium | CWE-838 | `src/main/java/com/security/auth/validation/InputValidator.java:94-96` |
| SEC-06 | Unvalidated Character Set in SessionToken Value Exposes Set-Cookie to Header Splitting | Low | CWE-113 | `src/main/java/com/security/auth/model/SessionToken.java:23-26` |
| SEC-07 | Missing Algorithm Verification Against Stored UserRecord in Password Verification | Low | CWE-327 | `src/main/java/com/security/auth/crypto/Pbkdf2PasswordHasher.java:88-97` |

## 5. Detailed Findings

### SEC-01: Rate Limiter Cache Wipe on Capacity Enables Complete Rate Limit Bypass
- **Severity:** High
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/security/auth/ratelimit/SlidingWindowRateLimiter.java:199-201`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/ratelimit/SlidingWindowRateLimiter.java:199-201
            if (trackerMap.size() >= maxCacheEntries) {
                trackerMap.clear();
            }
```

**Why it is a problem:** In `SlidingWindowRateLimiter.maybePruneExpiredEntries()`, when the size of `trackerMap` reaches or exceeds `maxCacheEntries` (configured by default to 10,000 entries), the method invokes `trackerMap.clear()`. This unconditionally deletes every active tracking window across all client IP addresses, user accounts, and dual-key combinations.
An attacker attempting a brute-force or credential-stuffing attack against a specific user account can deliberately send 10,000 login requests using random or synthetic usernames/IPs. Once the cache threshold is reached, `trackerMap.clear()` flushes all active rate-limiting state, immediately resetting the attacker's counters to zero. This allows an adversary to bypass the rate limiter at will and continue unauthorized brute-force attempts indefinitely.

**Fix:** Replace the full cache clear with a targeted eviction strategy such as Least Recently Used (LRU) eviction or removing only expired entries. When capacity is reached, evict the oldest entry or reject new untracked keys rather than purging active rate-limiting state:
```java
            if (trackerMap.size() >= maxCacheEntries) {
                // Prune only expired entries first
                trackerMap.entrySet().removeIf(entry -> entry.getValue().isExpired(now, windowMillis));
                // If still at capacity, evict the oldest entry rather than clearing all state
                if (trackerMap.size() >= maxCacheEntries) {
                    Iterator<Map.Entry<String, WindowTracker>> it = trackerMap.entrySet().iterator();
                    if (it.hasNext()) {
                        it.next();
                        it.remove();
                    }
                }
            }
```

---

### SEC-02: Denial of Service via Resource Exhaustion from Oversized Passwords in Dummy Timing Verification
- **Severity:** High
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/security/auth/DefaultAuthenticationService.java:72-75`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/DefaultAuthenticationService.java:72-75
            } catch (ValidationException ve) {
                // Perform dummy cryptographic workload to equalize execution time (Rule 6)
                passwordHasher.performDummyVerification(rawPassword);
```

**Why it is a problem:** `InputValidator.validatePassword()` enforces a maximum length of 128 characters (`MAX_PASSWORD_LENGTH = 128`) specifically to prevent CPU and memory exhaustion attacks against PBKDF2 hashing.
However, when an attacker submits an oversized password (e.g., 10 MB or 100 MB of characters), `InputValidator.validatePassword()` detects the violation and throws a `ValidationException`. In `DefaultAuthenticationService.java`, the catch block intercepts this exception and immediately invokes `passwordHasher.performDummyVerification(rawPassword)`.
Inside `Pbkdf2PasswordHasher.performDummyVerification(char[] password)`, because `password` is non-null and not empty, it passes the raw oversized password into `hashPassword()`. This clones the array into a `PBEKeySpec` and executes 210,000 PBKDF2 HMAC-SHA512 iterations on the massive input.
This completely bypasses the length validation check, allowing remote unauthenticated attackers to cause server-wide Denial of Service via CPU starvation and heap exhaustion (`OutOfMemoryError`).

**Fix:** Ensure `performDummyVerification` validates the candidate password length before processing it, falling back to `DUMMY_FALLBACK_PASSWORD` whenever the password is null, empty, or exceeds `MAX_PASSWORD_LENGTH`:
```java
    @Override
    public void performDummyVerification(char[] password) {
        // Enforce length boundary check to prevent CPU and memory exhaustion
        char[] pwdToUse = (password != null && password.length >= 8 && password.length <= 128)
                ? password
                : DUMMY_FALLBACK_PASSWORD;
        byte[] computedHash = null;
        try {
            computedHash = hashPassword(pwdToUse, this.dummySalt, this.defaultIterations);
            MessageDigest.isEqual(computedHash, this.dummyExpectedHash);
        } finally {
            if (computedHash != null) {
                Arrays.fill(computedHash, (byte) 0);
            }
        }
    }
```

---

### SEC-03: Computational Denial of Service via Cryptographic Execution on Throttled Requests
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/security/auth/DefaultAuthenticationService.java:88-91`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/DefaultAuthenticationService.java:88-91
            RateLimitStatus rateLimitStatus = rateLimiter.acquireAttempt(validatedClientIp, validatedUsername);
            if (rateLimitStatus != RateLimitStatus.ALLOWED) {
                // Perform dummy cryptographic workload to prevent timing enumeration (Rule 6)
                passwordHasher.performDummyVerification(rawPassword);
```

**Why it is a problem:** A primary purpose of an authentication rate limiter is to protect backend computing resources—especially computationally heavy cryptographic algorithms like PBKDF2 with 210,000 iterations—from being exhausted during high-volume attacks.
When `DefaultAuthenticationService` determines that a request is rate-limited (`rateLimitStatus != RateLimitStatus.ALLOWED`), it still invokes `passwordHasher.performDummyVerification(rawPassword)`. This causes the server to execute the full 210,000-iteration PBKDF2 computation (~100–200 ms of CPU time) on every throttled request. An attacker whose IP or account is already rate-limited can flood the endpoint with requests and keep server CPU cores saturated at 100%, causing Denial of Service for legitimate users on other IP addresses.

**Fix:** Remove the invocation of `passwordHasher.performDummyVerification(rawPassword)` from the rate-limiting branch and reject the request immediately:
```java
            RateLimitStatus rateLimitStatus = rateLimiter.acquireAttempt(validatedClientIp, validatedUsername);
            if (rateLimitStatus != RateLimitStatus.ALLOWED) {
                AuthenticationEventType eventType = (rateLimitStatus == RateLimitStatus.SOURCE_RATE_LIMITED)
                        ? AuthenticationEventType.LOGIN_FAILURE_RATE_LIMITED_SOURCE
                        : AuthenticationEventType.LOGIN_FAILURE_RATE_LIMITED_ACCOUNT;

                AuthenticationErrorCode errorCode = (rateLimitStatus == RateLimitStatus.SOURCE_RATE_LIMITED)
                        ? AuthenticationErrorCode.RATE_LIMITED_SOURCE
                        : AuthenticationErrorCode.RATE_LIMITED_ACCOUNT;

                eventLogger.logEvent(new AuthenticationEvent(Instant.now(),
                        eventType,
                        false,
                        validatedUsername,
                        validatedClientIp,
                        "",
                        "Authentication throttled due to rate limiting: " + rateLimitStatus.name()));

                return AuthenticationResult.failure(errorCode);
            }
```

---

### SEC-04: Incomplete Sanitization of Unicode Line and Paragraph Separators in Audit Event Logger
- **Severity:** Medium
- **CWE:** CWE-117: Improper Output Handling for Logs
- **Location:** `src/main/java/com/security/auth/logging/AuthenticationEvent.java:76-80`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/logging/AuthenticationEvent.java:76-80
        // Neutralize carriage returns, newlines, and tabs to prevent log forging
        String sanitized = input.replace('\r', '_')
                .replace('\n', '_')
                .replace('\t', ' ')
                .replaceAll("[\\p{Cntrl}]", "");
```

**Why it is a problem:** When unauthenticated requests fail input validation or cause errors, unvalidated strings (such as `rawUsername` and `rawClientIp`) are logged in `AuthenticationEvent`. The method `sanitizeAndBound()` attempts to strip control characters using `replaceAll("[\\p{Cntrl}]", "")`.
However, Java's `\p{Cntrl}` regex character class matches only ISO control characters (`\p{Cc}`). It does not match Unicode Line Separator `\u2028` (category `\p{Zl}`) or Unicode Paragraph Separator `\u2029` (category `\p{Zp}`). When audit logs are ingested into log aggregators, SIEM web consoles, or terminal monitors, these Unicode characters cause line breaks, enabling an attacker to forge audit log records and inject deceptive log entries.

**Fix:** Explicitly replace Unicode line breaks (`\u2028`, `\u2029`, `\u0085`) and include Unicode separator categories `\p{Zl}` and `\p{Zp}` in the sanitization regex:
```java
        // Neutralize carriage returns, newlines, tabs, and Unicode line/paragraph separators
        String sanitized = input.replace('\r', '_')
                .replace('\n', '_')
                .replace('\t', ' ')
                .replace('\u2028', '_')
                .replace('\u2029', '_')
                .replaceAll("[\\p{Cntrl}\\p{Zl}\\p{Zp}]", "");
```

---

### SEC-05: Lack of IPv6 Canonicalization Permits Rate Limiting Bypass via Alternative Syntactic Representations
- **Severity:** Medium
- **CWE:** CWE-838: Inappropriate Encoding for Output Context
- **Location:** `src/main/java/com/security/auth/validation/InputValidator.java:94-96`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/validation/InputValidator.java:94-96
        if (IPV4_PATTERN.matcher(clientIp).matches() || IPV6_PATTERN.matcher(clientIp).matches()) {
            return clientIp;
        }
```

**Why it is a problem:** `InputValidator.validateClientIp()` validates IPv6 strings against `IPV6_PATTERN` but returns the input string without canonicalization. IPv6 addresses support multiple valid representations (e.g. uppercase vs lowercase hexadecimal, leading zeros like `2001:0db8::` vs `2001:db8::`, and alternative zero-compression placement).
Because `SlidingWindowRateLimiter` builds tracking keys via string concatenation (`"SRC:" + clientIp` and `"SRC_ACC:" + clientIp + ":" + username`), each distinct syntactic variation of the same IPv6 address hashes to a separate entry in `trackerMap`. An attacker connecting from a single IPv6 host can alternate between syntactic variants of their address to bypass per-IP rate limits and account lockout protections.

**Fix:** Canonicalize IPv6 addresses to their standard normalized format without performing DNS lookups:
```java
        if (IPV4_PATTERN.matcher(clientIp).matches()) {
            return clientIp;
        }
        if (IPV6_PATTERN.matcher(clientIp).matches()) {
            try {
                // Canonicalize IPv6 address literal without DNS resolution
                return java.net.InetAddress.getByName(clientIp).getHostAddress().toLowerCase();
            } catch (java.net.UnknownHostException e) {
                throw new ValidationException("Invalid IPv6 address literal.");
            }
        }
```

---

### SEC-06: Unvalidated Character Set in SessionToken Value Exposes Set-Cookie to Header Splitting
- **Severity:** Low
- **CWE:** CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')
- **Location:** `src/main/java/com/security/auth/model/SessionToken.java:23-26`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/model/SessionToken.java:23-26
        if (value == null || value.length() < 32) {
            throw new IllegalArgumentException("Session token value must be non-null and at least 32 characters.");
        }
        this.value = value;
```

**Why it is a problem:** `SessionToken.toSetCookieHeader(String cookieName)` validates the `cookieName` argument with a regex whitelist (`^[a-zA-Z0-9_-]+$`), but the `SessionToken` constructor only validates that `value` is non-null and has a minimum length of 32 characters. It performs no character set validation on `value`.
If an externally provided or caller-supplied token value containing semicolons, control characters, or CRLF sequences (`\r\n`) is passed into `SessionToken`, formatting it into an HTTP cookie header string via `toSetCookieHeader()` could enable HTTP response splitting or unauthorized injection of cookie directives (e.g., overriding `Path`, `Domain`, or `SameSite`).

**Fix:** Enforce strict character set validation on the token value in the `SessionToken` constructor:
```java
        if (value == null || !value.matches("^[a-zA-Z0-9_-]{32,256}$")) {
            throw new IllegalArgumentException("Session token value must match safe character set [a-zA-Z0-9_-] and be between 32 and 256 characters.");
        }
        this.value = value;
```

---

### SEC-07: Missing Algorithm Verification Against Stored UserRecord in Password Verification
- **Severity:** Low
- **CWE:** CWE-327: Use of a Broken or Risky Cryptographic Algorithm
- **Location:** `src/main/java/com/security/auth/crypto/Pbkdf2PasswordHasher.java:88-97`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/crypto/Pbkdf2PasswordHasher.java:88-97
    public boolean verifyPassword(char[] password, UserRecord record) {
        if (password == null || record == null) {
            return false;
        }

        byte[] computedHash = null;
        try {
            computedHash = hashPassword(password, record.getSalt(), record.getIterations());
            // Constant-time byte array equality comparison (Rule 6)
            return MessageDigest.isEqual(computedHash, record.getPasswordHash());
```

**Why it is a problem:** `UserRecord` stores a mandatory `algorithm` identifier (e.g. `"PBKDF2WithHmacSHA512"`). However, `Pbkdf2PasswordHasher.verifyPassword()` does not verify that `record.getAlgorithm()` matches `Pbkdf2PasswordHasher.ALGORITHM`. If user records stored in a database or identity repository use different algorithms (or if algorithm metadata is corrupted), `Pbkdf2PasswordHasher` will blindly attempt to hash the password with `PBKDF2WithHmacSHA512` and compare it against the stored hash bytes. Failing to verify algorithm compatibility can cause unexpected verification failures or potential algorithm confusion if future algorithms are introduced.

**Fix:** Verify that `record.getAlgorithm()` matches `ALGORITHM` before proceeding with hash verification:
```java
    @Override
    public boolean verifyPassword(char[] password, UserRecord record) {
        if (password == null || record == null) {
            return false;
        }
        if (!ALGORITHM.equalsIgnoreCase(record.getAlgorithm())) {
            return false;
        }

        byte[] computedHash = null;
        try {
            computedHash = hashPassword(password, record.getSalt(), record.getIterations());
            // Constant-time byte array equality comparison (Rule 6)
            return MessageDigest.isEqual(computedHash, record.getPasswordHash());
```

## 6. Verified Controls and Checks With No Finding
- Memory Zeroization (CWE-316): Verified that `AuthenticationRequest` stores credentials in mutable `char[]` and zeroizes them via `clearCredentials()` upon `close()` and inside the `finally` block of `DefaultAuthenticationService.authenticate()`. Intermediate PBKDF2 hash buffers in `Pbkdf2PasswordHasher` and random byte buffers in `TokenGenerator` are explicitly cleared with `Arrays.fill`.
- Constant-Time Comparison (CWE-208): Verified that password hash verification in `Pbkdf2PasswordHasher.verifyPassword` and dummy hash comparison in `performDummyVerification` utilize `MessageDigest.isEqual()`, mitigating timing attacks across byte comparisons.
- User Enumeration Prevention (CWE-204): Verified that `AuthenticationResult.failure()` returns an identical generic error message (`"Invalid username or password."`) across all failure scenarios (invalid inputs, non-existent users, locked accounts, wrong passwords, rate-limited requests).
- Session Identifier Entropy and Cookie Hardening (CWE-330, CWE-614): Verified that `TokenGenerator` generates 256 bits of entropy using `java.security.SecureRandom`, and `SessionToken.toSetCookieHeader()` enforces `HttpOnly; Secure; SameSite=Strict; Path=/`.
- Sensitive Data Redaction in Logging (CWE-532): Verified that passwords and raw session tokens are never logged. Passwords are redacted in `AuthenticationRequest.toString()`, and only SHA-256 token fingerprints are written to audit logs.
- Filesystem Access and Symlink Defenses (CWE-59, CWE-732): Verified that `SecureFileEventLogger` restricts file permissions to POSIX `0600` (directory `0700`), rejects symbolic links using `Files.isSymbolicLink()` and `NOFOLLOW_LINKS`, and checks parent directories against `OTHERS_WRITE`.
- Concurrency and Race Condition Defenses (CWE-362): Verified that `SlidingWindowRateLimiter.acquireAttempt` and `SecureFileEventLogger.logEvent` synchronize access to ensure atomic check-and-act operations and thread-safe file writes.
- Fail-Closed Behavior (CWE-276): Verified that `DefaultAuthenticationService` fails closed upon encountering null requests, input validation failures, suspended/locked accounts, non-existent accounts, and unexpected exceptions.
