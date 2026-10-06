# Security Review: Secure User Authentication & Audit Logging Component

## 1. Executive Summary
The component validates username/password login requests, applies in-memory sliding-window throttling, verifies PBKDF2 password hashes, issues random bearer session tokens, and records authentication events in a local audit log. The static review found nine vulnerabilities: one High-severity CPU-exhaustion path because rejected oversized passwords are still passed to PBKDF2; six Medium-severity issues involving fail-open rate-limit eviction, externally observable internal failure codes, inconsistent timing work, weak permitted PBKDF2 parameters, HTTP header injection through publicly constructible tokens, and incomplete log-field neutralization; and two Low-severity issues in non-POSIX permission handling and repository capacity synchronization. The strongest implemented controls are generic user-facing failure text, constant-time hash comparison, secure random salts and tokens, credential zeroization, atomic rate-limit check-and-record behavior, and bounded audit retention.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `pom.xml` | Maven build and dependency configuration | Pins Java 17, SLF4J, JUnit, compiler warnings, and test execution plugins. |
| `src/main/java/com/security/auth/AuthenticationErrorCode.java` | Defines authentication failure reasons | Distinguishes user-not-found, invalid-password, account-state, throttling, and internal failures. |
| `src/main/java/com/security/auth/AuthenticationRequest.java` | Carries untrusted login input | Copies and later zeroizes the password array; exposes username, password, and client IP to the service. |
| `src/main/java/com/security/auth/AuthenticationResult.java` | Returns authentication outcome | Uses generic display text and optional session token, but also exposes the exact internal failure reason. |
| `src/main/java/com/security/auth/AuthenticationService.java` | Authentication service contract | Defines the trust-boundary operation returning an authentication result. |
| `src/main/java/com/security/auth/DefaultAuthenticationService.java` | Orchestrates authentication | Validates input, invokes throttling and password verification, issues tokens, logs outcomes, and clears credentials. |
| `src/main/java/com/security/auth/crypto/PasswordHasher.java` | Password-hashing contract | Defines hashing, verification, dummy timing work, and salt generation. |
| `src/main/java/com/security/auth/crypto/Pbkdf2PasswordHasher.java` | PBKDF2 implementation | Uses PBKDF2-HMAC-SHA512, `SecureRandom`, constant-time comparison, configurable iterations, and buffer clearing. |
| `src/main/java/com/security/auth/crypto/TokenGenerator.java` | Session-token generator | Generates 256-bit random Base64url bearer tokens with one-hour default lifetime. |
| `src/main/java/com/security/auth/logging/AuthenticationEvent.java` | Immutable audit-event model | Bounds fields, strips control characters, and formats delimiter-separated log records. |
| `src/main/java/com/security/auth/logging/AuthenticationEventLogger.java` | Audit-logger contract | Records events and exposes a bounded recent-event view. |
| `src/main/java/com/security/auth/logging/AuthenticationEventType.java` | Audit event taxonomy | Separates success and detailed failure categories. |
| `src/main/java/com/security/auth/logging/SecureFileEventLogger.java` | File and SLF4J audit logger | Creates/reopens log files, assigns permissions, rejects direct symlinks, caps retention/file size, and serializes writes. |
| `src/main/java/com/security/auth/model/AccountStatus.java` | Account-state enumeration | Controls whether a credential record is eligible to authenticate. |
| `src/main/java/com/security/auth/model/SessionToken.java` | Bearer-token value object | Stores the token and lifetime, renders `Set-Cookie`, and derives an audit fingerprint. |
| `src/main/java/com/security/auth/model/UserRecord.java` | Stored credential model | Validates and defensively copies username, hash, salt, iteration count, algorithm label, and account state. |
| `src/main/java/com/security/auth/ratelimit/RateLimiter.java` | Throttling contract | Defines atomic attempt acquisition plus success/failure accounting. |
| `src/main/java/com/security/auth/ratelimit/SlidingWindowRateLimiter.java` | In-memory brute-force limiter | Tracks source, source-account, and global-account windows; synchronizes state; prunes or clears cached trackers. |
| `src/main/java/com/security/auth/repository/InMemoryUserCredentialRepository.java` | In-memory credential repository | Stores credential records in a concurrent map with a nominal capacity limit. |
| `src/main/java/com/security/auth/repository/UserCredentialRepository.java` | Credential lookup contract | Retrieves authoritative server-side user records by validated username. |
| `src/main/java/com/security/auth/validation/InputValidator.java` | Login input validation | Allowlists usernames and IP syntax and bounds username, password, and IP lengths. |
| `src/main/java/com/security/auth/validation/ValidationException.java` | Validation failure type | Carries internal validation details. |
| `src/test/java/com/security/auth/AuthenticationServiceTest.java` | End-to-end authentication tests | Covers success, generic failure text, status handling, input errors, token cookies, logging, and zeroization. |
| `src/test/java/com/security/auth/ConcurrencySecurityTest.java` | Concurrent authentication test | Exercises atomic rate-limit acquisition and synchronized event retention. |
| `src/test/java/com/security/auth/TimingAttackResistanceTest.java` | Timing-work tests | Checks that selected failure paths call dummy hashing, but does not compare work factors or elapsed-time distributions. |
| `src/test/java/com/security/auth/crypto/PasswordHasherTest.java` | Password-hasher tests | Covers matching/nonmatching passwords, salt uniqueness, dummy work, and null handling using a low test work factor. |
| `src/test/java/com/security/auth/logging/SecureFileEventLoggerTest.java` | Audit-logger tests | Covers POSIX permissions, CRLF stripping, retention bounds, final-component symlinks, and approximate file-size bounds. |
| `src/test/java/com/security/auth/ratelimit/RateLimiterTest.java` | Rate-limiter tests | Covers source, source-account, global-account, and success-reset behavior, but not cache saturation. |
| `src/test/java/com/security/auth/validation/InputValidatorTest.java` | Input-validation tests | Covers allowed and rejected usernames, password lengths, and IP formats. |
| `README.md` | Component design and usage documentation | States the intended trust boundaries and security guarantees used to assess implementation gaps. |
| `target/classes/**/*.class`, `target/test-classes/**/*.class` | Generated bytecode copies | Build artifacts corresponding to the reviewed Java sources; not independent source implementations. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Used to inventory every source file, identify security-relevant behavior, route the review to specialized skills, and require CWE/file-line evidence.
- `testing-api-authentication-weaknesses`: Applied to uniform responses, account enumeration, password handling, token entropy, cookie behavior, and session-token exposure.
- `performing-cryptographic-audit-of-application`: Applied to PBKDF2 algorithm/work-factor selection, salts, randomness, hardcoded secrets, constant-time comparison, token generation, and audit fingerprints.
- `implementing-api-rate-limiting-and-throttling`: Applied to source/account keys, sliding-window behavior, atomicity, cache bounds, and fail-safe behavior under capacity pressure.
- `performing-api-rate-limiting-bypass`: Applied statically to identifier rotation, distributed attempts, cache-saturation bypass, and concurrent-attempt behavior; no active bypass testing was performed.
- `exploiting-race-condition-vulnerabilities`: Applied statically to check-then-act operations in throttling, repository capacity enforcement, and log-file handling; no exploit code was executed.
- General OWASP Top 10 / CWE knowledge: Applied where no close skill matched, specifically to oversized-input resource consumption, HTTP response-header injection, structured-log delimiter injection, filesystem permissions, symlink/path handling, secret leakage, and unsafe deserialization/command/query sinks.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Oversized rejected passwords are still processed by PBKDF2 | High | CWE-400 | `src/main/java/com/security/auth/DefaultAuthenticationService.java:68-75` |
| SEC-02 | Rate-limit cache saturation clears all active protections | Medium | CWE-307 | `src/main/java/com/security/auth/ratelimit/SlidingWindowRateLimiter.java:190-201` |
| SEC-03 | Public result API exposes exact authentication failure reasons | Medium | CWE-204 | `src/main/java/com/security/auth/AuthenticationResult.java:34-36` |
| SEC-04 | Dummy and real password checks can use different work factors | Medium | CWE-208 | `src/main/java/com/security/auth/crypto/Pbkdf2PasswordHasher.java:87-112` |
| SEC-05 | Production API permits a 1,000-iteration PBKDF2 work factor | Medium | CWE-916 | `src/main/java/com/security/auth/crypto/Pbkdf2PasswordHasher.java:39-42` |
| SEC-06 | Public session-token constructor enables Set-Cookie header injection | Medium | CWE-113 | `src/main/java/com/security/auth/model/SessionToken.java:22-26` |
| SEC-07 | Audit log fields do not neutralize structural delimiters | Medium | CWE-117 | `src/main/java/com/security/auth/logging/AuthenticationEvent.java:71-84` |
| SEC-08 | Non-POSIX permission failures are silently ignored | Low | CWE-732 | `src/main/java/com/security/auth/logging/SecureFileEventLogger.java:128-138` |
| SEC-09 | Repository capacity check is not atomic with insertion | Low | CWE-362 | `src/main/java/com/security/auth/repository/InMemoryUserCredentialRepository.java:37-42` |

## 5. Detailed Findings

### SEC-01: Oversized rejected passwords are still processed by PBKDF2
- **Severity:** High
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/security/auth/DefaultAuthenticationService.java:68-75`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/DefaultAuthenticationService.java:68-75
            try {
                validatedUsername = InputValidator.validateUsername(rawUsername);
                InputValidator.validatePassword(rawPassword);
                validatedClientIp = InputValidator.validateClientIp(rawClientIp);
            } catch (ValidationException ve) {
                // Perform dummy cryptographic workload to equalize execution time (Rule 6)
                passwordHasher.performDummyVerification(rawPassword);
```

**Why it is a problem:** `validatePassword` correctly rejects arrays longer than 128 characters, but the catch block immediately passes that same unbounded array to the expensive PBKDF2 function. An unauthenticated caller can therefore force costly hashing and password preprocessing with very large inputs despite the advertised input limit. `AuthenticationRequest` also copies the unbounded array before validation, adding avoidable memory pressure. This can exhaust CPU and heap resources with relatively few requests.

**Fix:** Never send a rejected oversized value into a password KDF. Substitute the fixed dummy password for null or oversized input, and enforce the maximum before copying in `AuthenticationRequest` (or at the HTTP/body boundary).
```java
char[] dummyInput = rawPassword;
if (dummyInput == null || dummyInput.length > InputValidator.MAX_PASSWORD_LENGTH) {
    dummyInput = null; // performDummyVerification uses its fixed, bounded fallback
}
passwordHasher.performDummyVerification(dummyInput);
```

### SEC-02: Rate-limit cache saturation clears all active protections
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/security/auth/ratelimit/SlidingWindowRateLimiter.java:190-201`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/ratelimit/SlidingWindowRateLimiter.java:190-201
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

**Why it is a problem:** Once the map reaches its configured bound, all active attempt history is deleted. A distributed attacker can spray unique source/account combinations until the bound is reached, reset every source and account counter, and repeat password guesses that should still be blocked. The memory bound therefore fails open and defeats the primary brute-force control precisely under hostile load.

**Fix:** Prune only expired entries and fail closed for a previously unseen key when capacity remains exhausted. Never clear active counters as an eviction strategy; for multi-instance deployment, use a shared atomic store with TTLs.
```java
int requiredEntries = 0;
if (sourceKey != null && !trackerMap.containsKey(sourceKey)) requiredEntries++;
if (sourceAccKey != null && !trackerMap.containsKey(sourceAccKey)) requiredEntries++;
if (accKey != null && !trackerMap.containsKey(accKey)) requiredEntries++;

if (trackerMap.size() > maxCacheEntries - requiredEntries) {
    return RateLimitStatus.SOURCE_RATE_LIMITED; // fail closed under capacity pressure
}
```

### SEC-03: Public result API exposes exact authentication failure reasons
- **Severity:** Medium
- **CWE:** CWE-204: Observable Response Discrepancy
- **Location:** `src/main/java/com/security/auth/AuthenticationResult.java:34-36,51-53`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/AuthenticationResult.java:34-36,51-53
    public static AuthenticationResult failure(AuthenticationErrorCode internalErrorCode) {
        // Enforce generic message to prevent username harvesting or account enumeration (Rule 6)
        return new AuthenticationResult(false, GENERIC_FAILURE_MESSAGE, null, internalErrorCode);
    }

    public AuthenticationErrorCode getInternalErrorCode() {
        return internalErrorCode;
    }
```

**Why it is a problem:** Although `userMessage` is generic, every caller receives a public discriminator for `USER_NOT_FOUND`, `INVALID_CREDENTIALS`, account status, and rate-limit state. A web/RPC adapter that serializes the result or exposes the getter reveals whether an account exists and why authentication failed. This directly undermines the class's stated uniform-response guarantee; the test suite already consumes the public getter, demonstrating that it is part of the usable API.

**Fix:** Keep detailed failure reasons solely in the protected audit event and remove them from the externally returned result type.
```java
public static AuthenticationResult failure() {
    return new AuthenticationResult(false, GENERIC_FAILURE_MESSAGE, null);
}

// Do not retain or expose AuthenticationErrorCode in the public result.
```

### SEC-04: Dummy and real password checks can use different work factors
- **Severity:** Medium
- **CWE:** CWE-208: Observable Timing Discrepancy
- **Location:** `src/main/java/com/security/auth/crypto/Pbkdf2PasswordHasher.java:87-112`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/crypto/Pbkdf2PasswordHasher.java:87-112
    public boolean verifyPassword(char[] password, UserRecord record) {
        if (password == null || record == null) {
            return false;
        }

        byte[] computedHash = null;
        try {
            computedHash = hashPassword(password, record.getSalt(), record.getIterations());
            // Constant-time byte array equality comparison (Rule 6)
            return MessageDigest.isEqual(computedHash, record.getPasswordHash());
        } finally {
            if (computedHash != null) {
                // Clear derived hash buffer from memory (Rule 5)
                Arrays.fill(computedHash, (byte) 0);
            }
        }
    }

    @Override
    public void performDummyVerification(char[] password) {
        char[] pwdToUse = (password != null && password.length > 0) ? password : DUMMY_FALLBACK_PASSWORD;
        byte[] computedHash = null;
        try {
            computedHash = hashPassword(pwdToUse, this.dummySalt, this.defaultIterations);
            // Execute constant-time comparison to match real verification execution profile
            MessageDigest.isEqual(computedHash, this.dummyExpectedHash);
```

**Why it is a problem:** Real verification uses the per-record iteration count, which `UserRecord` permits anywhere from 1,000 to 2,000,000, while nonexistent, invalid, locked, and throttled cases always use `defaultIterations`. An attacker can repeatedly compare response-time distributions to distinguish failure paths or identify accounts whose records use a materially different work factor. Constant-time byte comparison does not compensate for a different KDF workload.

**Fix:** Enforce one active work factor for all records used by this service, and migrate/rehash legacy records separately so both real and dummy verification perform the same KDF cost.
```java
public boolean verifyPassword(char[] password, UserRecord record) {
    if (password == null || record == null) return false;
    if (record.getIterations() != defaultIterations) {
        throw new IllegalStateException("Credential record requires controlled migration");
    }
    byte[] computedHash = hashPassword(password, record.getSalt(), defaultIterations);
    try {
        return MessageDigest.isEqual(computedHash, record.getPasswordHash());
    } finally {
        Arrays.fill(computedHash, (byte) 0);
    }
}
```

### SEC-05: Production API permits a 1,000-iteration PBKDF2 work factor
- **Severity:** Medium
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `src/main/java/com/security/auth/crypto/Pbkdf2PasswordHasher.java:39-42,70-72`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/crypto/Pbkdf2PasswordHasher.java:39-42,70-72
    public Pbkdf2PasswordHasher(int iterations) {
        if (iterations < 1000) {
            throw new IllegalArgumentException("Iteration count must be at least 1,000.");
        }

        if (iterations < 1000) {
            throw new IllegalArgumentException("Iterations must be at least 1,000.");
        }
```

**Why it is a problem:** Both the public hasher configuration and direct hashing API treat 1,000 PBKDF2-HMAC-SHA512 iterations as acceptable production strength. `UserRecord` accepts the same minimum. An application can therefore create credential records that are inexpensive to brute-force after database theft. The test-only use of 1,000 iterations is understandable, but the production class exposes the same weak range. Current OWASP guidance is substantially higher and should be calibrated upward over time.

**Fix:** Centralize a production minimum (at least the current policy value, benchmarked for the deployment), reject lower values in production constructors and records, and isolate any reduced test cost behind test-only code.
```java
public static final int MIN_ITERATIONS = 220_000;
public static final int DEFAULT_ITERATIONS = MIN_ITERATIONS;

public Pbkdf2PasswordHasher(int iterations) {
    if (iterations < MIN_ITERATIONS) {
        throw new IllegalArgumentException("Iteration count is below the production security policy.");
    }
    this.secureRandom = new SecureRandom();
    this.defaultIterations = iterations;
    // initialize dummy values as before
}
```

### SEC-06: Public session-token constructor enables Set-Cookie header injection
- **Severity:** Medium
- **CWE:** CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting')
- **Location:** `src/main/java/com/security/auth/model/SessionToken.java:22-26,61-67`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/model/SessionToken.java:22-26,61-67
    public SessionToken(String value, String username, Instant issuedAt, Instant expiresAt) {
        if (value == null || value.length() < 32) {
            throw new IllegalArgumentException("Session token value must be non-null and at least 32 characters.");
        }
        this.value = value;

    public String toSetCookieHeader(String cookieName) {
        if (cookieName == null || !cookieName.matches("^[a-zA-Z0-9_-]+$")) {
            throw new IllegalArgumentException("Invalid cookie name format.");
        }
        long maxAgeSeconds = Math.max(0, Duration.between(Instant.now(), expiresAt).getSeconds());
        return String.format("%s=%s; Path=/; Max-Age=%d; HttpOnly; Secure; SameSite=Strict",
                cookieName, value, maxAgeSeconds);
```

**Why it is a problem:** `TokenGenerator` creates a safe Base64url value, but `SessionToken` has a public constructor that accepts any string of at least 32 characters, including CR and LF. `toSetCookieHeader` inserts that value verbatim into an HTTP response header. If any caller constructs a token from upstream or persisted data, an attacker can inject headers or split the response.

**Fix:** Make token construction non-public and reachable only through `TokenGenerator`, or strictly allowlist the exact Base64url representation produced by the generator.
```java
private static final Pattern TOKEN_VALUE = Pattern.compile("^[A-Za-z0-9_-]{43}$");

SessionToken(String value, String username, Instant issuedAt, Instant expiresAt) {
    if (value == null || !TOKEN_VALUE.matcher(value).matches()) {
        throw new IllegalArgumentException("Invalid generated session token format.");
    }
    this.value = value;
    // validate and assign the remaining fields as before
}
```

### SEC-07: Audit log fields do not neutralize structural delimiters
- **Severity:** Medium
- **CWE:** CWE-117: Improper Output Neutralization for Logs
- **Location:** `src/main/java/com/security/auth/logging/AuthenticationEvent.java:71-84`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/logging/AuthenticationEvent.java:71-84
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
```

**Why it is a problem:** Removing control characters prevents extra physical lines, but the log format uses `|`, `=`, and quotes as structure and leaves those characters untouched. Invalid usernames are deliberately logged before validation, and `AuthenticationEvent` is also a public API. An input such as `bad| outcome=SUCCESS | user=admin` can inject apparent fields into the file and SLF4J record, confusing delimiter-based ingestion, alerts, or manual incident review.

**Fix:** Prefer a structured JSON logger that escapes each value. If the delimiter format must remain, encode every character that is structural to that format after removing controls.
```java
String sanitized = input.replace('\r', '_')
        .replace('\n', '_')
        .replace('\t', ' ')
        .replaceAll("[\\p{Cntrl}]", "")
        .replace("%", "%25")
        .replace("|", "%7C")
        .replace("=", "%3D")
        .replace("\"", "%22");
```

### SEC-08: Non-POSIX permission failures are silently ignored
- **Severity:** Low
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `src/main/java/com/security/auth/logging/SecureFileEventLogger.java:128-138`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/logging/SecureFileEventLogger.java:128-138
    private static void restrictFilePermissionsFallback(File file, boolean isDir) {
        file.setReadable(false, false);
        file.setReadable(true, true); // Owner readable only
        file.setWritable(false, false);
        file.setWritable(true, true); // Owner writable only
        if (isDir) {
            file.setExecutable(false, false);
            file.setExecutable(true, true); // Owner executable only
        } else {
            file.setExecutable(false, false);
        }
    }
```

**Why it is a problem:** Every legacy `File.set*` method returns `false` when the permission change cannot be made, but all results are ignored. On a non-POSIX filesystem the component can continue writing sensitive authentication events after its promised owner-only permissions failed, potentially exposing or allowing modification of the audit log.

**Fix:** Treat inability to enforce the security policy as initialization failure, or use the platform ACL API and verify the resulting ACL before opening the file.
```java
private static void restrictFilePermissionsFallback(File file, boolean isDir) {
    boolean secured = file.setReadable(false, false);
    secured &= file.setWritable(false, false);
    secured &= file.setExecutable(false, false);
    secured &= file.setReadable(true, true);
    secured &= file.setWritable(true, true);
    if (isDir) secured &= file.setExecutable(true, true);
    if (!secured) {
        throw new SecurityException("Unable to enforce owner-only permissions: " + file);
    }
}
```

### SEC-09: Repository capacity check is not atomic with insertion
- **Severity:** Low
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- **Location:** `src/main/java/com/security/auth/repository/InMemoryUserCredentialRepository.java:37-42`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/repository/InMemoryUserCredentialRepository.java:37-42
    public void putUser(UserRecord record) {
        Objects.requireNonNull(record, "UserRecord cannot be null.");
        if (store.size() >= maxUsers && !store.containsKey(record.getUsername())) {
            throw new IllegalStateException("User repository capacity reached (" + maxUsers + ").");
        }
        store.put(record.getUsername(), record);
```

**Why it is a problem:** `ConcurrentHashMap` makes individual operations safe, but `size`, `containsKey`, and `put` are three separate operations. Concurrent insertions of distinct usernames can all observe available capacity and then collectively exceed `maxUsers`, weakening the intended memory bound. The current concurrency test only covers the rate limiter and does not exercise this path.

**Fix:** Serialize the compound capacity check and insertion (or maintain an atomic reservation counter with rollback). A synchronized method is sufficient for this in-memory implementation.
```java
public synchronized void putUser(UserRecord record) {
    Objects.requireNonNull(record, "UserRecord cannot be null.");
    if (store.size() >= maxUsers && !store.containsKey(record.getUsername())) {
        throw new IllegalStateException("User repository capacity reached (" + maxUsers + ").");
    }
    store.put(record.getUsername(), record);
}
```

## 6. Verified Controls and Checks With No Finding
- Generic display text: All `AuthenticationResult` failures use the same user-facing string; the separate public internal-code channel is reported as SEC-03.
- Authentication state: Credential checks use a server-side `UserRecord`, and non-active accounts fail closed in `DefaultAuthenticationService.java:112-159`.
- Constant-time comparison: `MessageDigest.isEqual` compares derived hashes in `Pbkdf2PasswordHasher.java:92-101`; differing KDF work factors are separately reported as SEC-04.
- Cryptographic primitives and entropy: Passwords use PBKDF2-HMAC-SHA512 with per-record salts; salts and 256-bit session identifiers use `SecureRandom`; no MD5, SHA-1, DES, RC4, ECB, predictable PRNG, hardcoded production key, or working production credential was found.
- Secret handling: Passwords are stored in mutable arrays, copied on request construction, redacted from `toString`, and cleared in the authentication `finally` block; derived hashes are cleared after comparison. Raw session tokens are not written to audit events.
- Generated-token security: `TokenGenerator` produces Base64url values from 32 random bytes, and generated cookies include `HttpOnly`, `Secure`, `SameSite=Strict`, and `Path=/`; unsafe direct construction is separately reported as SEC-06.
- Token audit value: Only a truncated SHA-256 fingerprint is logged, not the bearer token, in `SessionToken.java:70-83` and `DefaultAuthenticationService.java:168-175`.
- Input validation: Usernames are length-bounded and allowlisted, and IP addresses are matched locally without DNS resolution. The oversized-password failure path is separately reported as SEC-01.
- Rate-limit atomicity: `acquireAttempt` synchronizes check-and-record across source, source-account, and account counters, preventing a same-instance concurrent threshold overrun; saturation eviction is separately reported as SEC-02.
- Audit retention and write serialization: In-memory events and file growth are bounded, and event writes are synchronized. CR/LF/control characters are removed; remaining structural delimiters are separately reported as SEC-07.
- Direct final-component symlinks: `SecureFileEventLogger` rejects a symbolic-link log file and opens with `NOFOLLOW_LINKS`; deployment should still place logs under a trusted directory because full ancestor-path containment is not established by this component.
- Dangerous sinks: No SQL/database query construction, OS command execution, unsafe deserialization, template rendering, XML parsing, outbound network request, dynamic class loading, or native-code loading was present in the reviewed source.
- Test/build handling: All tests and build configuration were reviewed statically. Per instruction, no source code, compiled class, test, Maven build, dependency installation, or generated helper script was executed or imported.
