# Security Review: Secure User Authentication Component

## 1. Executive Summary

This is a static security review of a Java 17 user-authentication component (`secure-auth-component`): PBKDF2 password verification, sliding-window rate limiting, CSPRNG session tokens, and a hardened file audit logger. The overall design is unusually mature — it uses PBKDF2WithHmacSHA512 at 210,000 iterations, constant-time comparison via `MessageDigest.isEqual`, `SecureRandom` 256-bit URL-safe-Base64 tokens, fully flagged cookies (`HttpOnly; Secure; SameSite=Strict; Path=/`), `char[]` zeroization, log-forging sanitization, and fail-closed error handling. No critical exploitable-from-the-network vulnerability such as auth bypass, injection, or secret leakage was found.

Nine findings were identified, two of them High. Both High findings are denial-of-service / brute-force-defense-defeat issues rather than credential-compromise issues:

- **SEC-01 (High):** the timing-equalization "dummy" PBKDF2 runs on the *raw, attacker-controlled password* on the input-validation failure path — a path that executes **before** the rate limiter. An unauthenticated attacker can send unlimited requests with an invalid (e.g. 1-character or megabyte-long) password and force a full 210,000-iteration PBKDF2-SHA512 per request with no throttling: trivial CPU exhaustion.
- **SEC-02 (High):** when the limiter's bounded tracker map overflows, it calls `trackerMap.clear()`, discarding **all** counters. An attacker who sprays valid-format random usernames (the username space is enormous) can keep the map pinned at its 10,000-entry cap and have every IP/account counter wiped roughly every 100 requests, resetting all brute-force limits.

The remaining findings concern brute-force defense weakening (counter crediting on any success, distributed account-lockout DoS via the global account limit), trust placed in repository-supplied KDF parameters (iterations down to 1,000; algorithm string never verified), a TOCTOU symlink race in log-file creation, a hardcoded dummy-password literal, audit-log writes being silently dropped after the size cap, and a small timing oracle between dummy and real verification.

All findings include the exact vulnerable code and a corrected version. Nothing in the reviewed code was executed, built, or installed.

## 2. Scope

All paths are relative to `/data/results/agy/set_a/post_research/6/security/`.

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/security/auth/DefaultAuthenticationService.java` | Core authentication flow / orchestrator | Validates inputs, calls rate limiter, user lookup, status check, password verify, token issue; fail-closed catch-all; dummy workload on every failure path; `finally` credential zeroization |
| `src/main/java/com/security/auth/AuthenticationRequest.java` | Input DTO | Copies caller's `char[]`, throws after `clearCredentials()`, redacting `toString()` |
| `src/main/java/com/security/auth/AuthenticationResult.java` | Result DTO | Uniform generic failure message `Invalid username or password.`; `toString()` omits error code |
| `src/main/java/com/security/auth/AuthenticationService.java` | Service interface | Contract only |
| `src/main/java/com/security/auth/AuthenticationErrorCode.java` | Error codes enum | Internal codes; mapped to generic client message |
| `src/main/java/com/security/auth/crypto/PasswordHasher.java` | Hasher interface | Contract only |
| `src/main/java/com/security/auth/crypto/Pbkdf2PasswordHasher.java` | PBKDF2 hash/verify | PBKDF2WithHmacSHA512, 210k iterations, 512-bit key, 16–64 B `SecureRandom` salts; constant-time verify; dummy verification; hardcoded dummy password literal; trusts `UserRecord` parameters |
| `src/main/java/com/security/auth/crypto/TokenGenerator.java` | Session tokens | `SecureRandom`, 32 bytes, URL-safe Base64 (no padding), default 1 h expiry, buffer zeroization |
| `src/main/java/com/security/auth/model/SessionToken.java` | Token model / cookie | Enforces ≥32-char value; emits `Path=/; HttpOnly; Secure; SameSite=Strict`; SHA-256 audit fingerprint (first 16 hex chars) instead of raw token |
| `src/main/java/com/security/auth/model/UserRecord.java` | Credential record | Validates hash/salt lengths; accepts `iterations` as low as 1,000; stores `algorithm` string without allowlist; defensive copies |
| `src/main/java/com/security/auth/model/AccountStatus.java` | Status enum | ACTIVE / SUSPENDED / LOCKED; non-ACTIVE rejected |
| `src/main/java/com/security/auth/ratelimit/RateLimiter.java` | Limiter interface | `acquireAttempt`, `checkRateLimit`, `recordFailure`, `recordSuccess` |
| `src/main/java/com/security/auth/ratelimit/SlidingWindowRateLimiter.java` | Sliding-window limiter | `synchronized` atomic count-then-allow over SRC / SRC_ACC / ACC keys; bounded cache with `clear()` on overflow; `recordSuccess` pops shared counters; global account hard block |
| `src/main/java/com/security/auth/repository/UserCredentialRepository.java` | Repository interface | Contract only |
| `src/main/java/com/security/auth/repository/InMemoryUserCredentialRepository.java` | In-memory store | Bounded 10,000 users, `ConcurrentHashMap` |
| `src/main/java/com/security/auth/validation/InputValidator.java` | Input validation | Username whitelist `^[a-zA-Z0-9_.@-]{3,64}$`; password 8–128 chars; strict IPv4/IPv6 regex (no DNS resolution) |
| `src/main/java/com/security/auth/validation/ValidationException.java` | Validation exception | Signal only |
| `src/main/java/com/security/auth/logging/AuthenticationEvent.java` | Audit event | Sanitizes CR/LF/TAB/control chars, bounds every field (details 256, username 64, IP 45, fingerprint 32) |
| `src/main/java/com/security/auth/logging/SecureFileEventLogger.java` | File audit logger | Symlink/dir checks, POSIX 0600 file / 0700 dir, `NOFOLLOW_LINKS` append, size cap (drops writes past cap), bounded ring buffer, duplicate emission via SLF4J |
| `src/main/java/com/security/auth/logging/AuthenticationEventLogger.java`, `AuthenticationEventType.java` | Logger interface / event types | Contract / enum only |
| `src/test/java/com/security/auth/*.java` (7 test classes) | Tests | Cover timing equalization, concurrency, rate limiting, validation, logging; reviewed for intent only, not executed |
| `pom.xml` | Build | Java 17; runtime deps only `slf4j-api` 2.0.16; test-only JUnit 5 / slf4j-simple — minimal supply-chain surface |

## 3. Skills Applied

Matched from the skill library by name/description (Step 2 of the router workflow), then applied as knowledge — none of their Python scripts were executed, per the router skill's constraint against running tooling against untrusted Java code:

- **review-code-for-security-vulnerabilities** (router) — the 4-step workflow followed here; it also forbids executing the reviewed code, which was honored.
- **performing-cryptographic-audit-of-application** — drove the KDF audit: algorithm/mode, iteration floor, salt source/length, key length, constant-time comparison, key material zeroization. Source of SEC-05 (low-iteration KDF accepted from the data layer) and SEC-07 (hardcoded secret check), and of the §6 confirmations on PBKDF2 parameters.
- **testing-api-authentication-weaknesses** — checklist for token generation/entropy, session cookie flags, enumeration/timing oracles, uniform failure messaging. Source of SEC-09 (dummy-vs-real timing mismatch) and §6 confirmations on tokens and cookies.
- **implementing-api-rate-limiting-and-throttling** and **performing-api-rate-limiting-bypass** — provided the bypass mindset (key selection, counter state integrity, storage-cap behavior, IP rotation) used to derive SEC-01, SEC-02, SEC-03 and SEC-04.
- **testing-for-sensitive-data-exposure** — checked logs, `toString()`, exception paths and fingerprints for secret leakage; no finding (see §6).
- **testing-for-broken-access-control** — checked status enforcement (SUSPENDED/LOCKED rejected), fail-closed catch paths, and object-level trust boundaries; no separate finding beyond SEC-05's data-layer trust issue.
- **implementing-secret-scanning-with-gitleaks** — motivated the literal-credential scan of all sources; single hit is SEC-07 (a dummy value, not a usable credential).
- **detecting-anomalous-authentication-patterns** — informed the audit-trail quality checks behind SEC-08 (dropped writes break the very telemetry anomaly detection needs).

Covered by general OWASP/CWE knowledge rather than any specialised skill in the library: **CWE-117** log-forging analysis (verified adequate, §6), **CWE-59/CWE-367** symlink-TOCTOU in log-file creation (SEC-06 — no file-handling/TOCTOU skill exists in the library), **CWE-400** resource-exhaustion reasoning on the dummy-workload path (SEC-01), and the **CWE-208** observable-timing reasoning in SEC-09.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Unthrottled full-cost PBKDF2 on unvalidated attacker input (CPU-exhaustion DoS) | High | CWE-400 | `src/main/java/com/security/auth/DefaultAuthenticationService.java:68-74` |
| SEC-02 | Rate-limiter state wiped (`trackerMap.clear()`) on cache overflow resets all brute-force counters | High | CWE-307 | `src/main/java/com/security/auth/ratelimit/SlidingWindowRateLimiter.java:190-202` |
| SEC-03 | Successful login credits attacker's failed attempts on shared source/global counters | Medium | CWE-307 | `src/main/java/com/security/auth/ratelimit/SlidingWindowRateLimiter.java:164-184` |
| SEC-04 | Global per-account limit hard-blocks the legitimate user (distributed account-lockout DoS) | Medium | CWE-307 | `src/main/java/com/security/auth/ratelimit/SlidingWindowRateLimiter.java:94-99` |
| SEC-05 | Repository-supplied KDF parameters trusted: iterations accepted down to 1,000, algorithm never verified | Medium | CWE-326 | `src/main/java/com/security/auth/crypto/Pbkdf2PasswordHasher.java:87-96` |
| SEC-06 | TOCTOU: symlink check then `Files.createFile` without `NOFOLLOW_LINKS` | Medium | CWE-367 | `src/main/java/com/security/auth/logging/SecureFileEventLogger.java:101-105` |
| SEC-07 | Hardcoded dummy-password string literal | Low | CWE-798 | `src/main/java/com/security/auth/crypto/Pbkdf2PasswordHasher.java:28` |
| SEC-08 | Audit events silently dropped after log-size cap (no rotation) | Low | CWE-778 | `src/main/java/com/security/auth/logging/SecureFileEventLogger.java:155-162` |
| SEC-09 | Dummy workload uses configured iterations while real verify uses per-record iterations (timing oracle) | Low | CWE-208 | `src/main/java/com/security/auth/crypto/Pbkdf2PasswordHasher.java:106-113` |

## 5. Detailed Findings

### SEC-01: Unthrottled full-cost PBKDF2 on unvalidated attacker input (CPU-exhaustion DoS)

- **Severity:** High
- **CWE:** CWE-400: Uncontrolled Resource Consumption ('Resource Exhaustion')
- **Location:** `src/main/java/com/security/auth/DefaultAuthenticationService.java:68-74`

**Vulnerable code:**

```java
// src/main/java/com/security/auth/DefaultAuthenticationService.java:68-74
            try {
                validatedUsername = InputValidator.validateUsername(rawUsername);
                InputValidator.validatePassword(rawPassword);
                validatedClientIp = InputValidator.validateClientIp(rawClientIp);
            } catch (ValidationException ve) {
                // Perform dummy cryptographic workload to equalize execution time (Rule 6)
                passwordHasher.performDummyVerification(rawPassword);
```

```java
// src/main/java/com/security/auth/crypto/Pbkdf2PasswordHasher.java:106-113
    public void performDummyVerification(char[] password) {
        char[] pwdToUse = (password != null && password.length > 0) ? password : DUMMY_FALLBACK_PASSWORD;
        byte[] computedHash = null;
        try {
            computedHash = hashPassword(pwdToUse, this.dummySalt, this.defaultIterations);
            // Execute constant-time comparison to match real verification execution profile
            MessageDigest.isEqual(computedHash, this.dummyExpectedHash);
```

**Why it is a problem:** The dummy workload is fed `rawPassword` — input that has just *failed* validation — and `hashPassword` (`Pbkdf2PasswordHasher.java:63-65`) only rejects null/empty, never bounding length. Two amplifiers compound:

1. **No rate limiting.** `rateLimiter.acquireAttempt(...)` is only reached at `DefaultAuthenticationService.java:88`, *after* validation succeeds. Every invalid-input request returns at line 85 without ever touching the limiter, so the attacker is unlimited.
2. **Full cost, unbounded input.** Each such request runs PBKDF2WithHmacSHA512 with `defaultIterations` (210,000 by default) over an attacker-chosen password of arbitrary length (validation is precisely what was skipped). Sending `password="a"` (fails the 8-char minimum) already forces ~210k HMAC-SHA512 iterations per request; a 1 MB password forces far more. A handful of concurrent HTTP clients saturate every CPU core — a complete authentication-service outage with unauthenticated, unthrottled requests. The legitimate paths (lines 91, 117, 134) call the same method but only *after* the limiter and on ≤128-char validated input, so they are bounded; this path is not.

**Fix:** Make the dummy workload a *fixed, internally generated* input (PBKDF2 cost is essentially independent of password length at these sizes, so timing equalization is preserved), and count invalid-input attempts toward the source limit.

```java
// Pbkdf2PasswordHasher.java — dummy workload never touches attacker input
    @Override
    public void performDummyVerification(char[] password) {
        // Fixed-length internal input: constant, bounded cost regardless of attacker bytes.
        // (The parameter is retained for interface compatibility and call-site symmetry.)
        byte[] computedHash = null;
        try {
            computedHash = hashPassword(DUMMY_FIXED_INPUT, this.dummySalt, this.defaultIterations);
            MessageDigest.isEqual(computedHash, this.dummyExpectedHash);
        } finally {
            if (computedHash != null) {
                Arrays.fill(computedHash, (byte) 0);
            }
        }
    }
```

```java
// DefaultAuthenticationService.java — also charge the source for rejected input
            } catch (ValidationException ve) {
                passwordHasher.performDummyVerification(rawPassword);

                // Reject-loop must cost the attacker, not the server: count the attempt
                // even though the inputs did not pass validation.
                rateLimiter.recordFailure(InputValidator.sanitizeForLimiter(rawClientIp),
                                          InputValidator.sanitizeForLimiter(rawUsername));

                eventLogger.logEvent(/* ... unchanged ... */);
                return AuthenticationResult.failure(AuthenticationErrorCode.INVALID_INPUT);
            }
```

(`sanitizeForLimiter` would truncate the raw values to their validator bounds instead of rejecting them, purely for keying the limiter.)

### SEC-02: Rate-limiter state wiped (`trackerMap.clear()`) on cache overflow resets all brute-force counters

- **Severity:** High
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/security/auth/ratelimit/SlidingWindowRateLimiter.java:190-202`

**Vulnerable code:**

```java
// src/main/java/com/security/auth/ratelimit/SlidingWindowRateLimiter.java:190-202
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

**Why it is a problem:** The map is bounded at `DEFAULT_MAX_CACHE_ENTRIES = 10_000`, but the overflow remedy is to discard *everything*. The `ACC:` key space is enormous — `InputValidator` accepts any 3–64-char string matching `^[a-zA-Z0-9_.@-]{3,64}$`, so an attacker can generate effectively unlimited distinct *valid* usernames. A background spray of one attempt per random username (each creating an `ACC:` entry) keeps `trackerMap.size()` at the cap; from then on every 100th request executes `trackerMap.clear()`, erasing all in-window `SRC:`/`SRC_ACC:`/`ACC:` counters across the process. The attacker then brute-forces a real account with ~9 attempts per ~100 filler requests, i.e. a sustained rate of thousands of unthrottled guesses per minute — the entire brute-force defense is reduced to a suggestion. This is the classic failure mode of capping keyed rate-limit stores by nuking them (the rate-limiting skills' storage-capacity checklist) — memory was bounded at the cost of the control's purpose.

**Fix:** Preserve the whole-map invariant by evicting only the least-recently-active entries down to a watermark, never the live counters wholesale:

```java
            if (trackerMap.size() >= maxCacheEntries) {
                // Evict least-recently-active trackers down to 90% capacity instead of
                // destroying every live counter. Expired ones were just removed above.
                int overflow = trackerMap.size() - (maxCacheEntries * 9 / 10);
                if (overflow > 0) {
                    trackerMap.entrySet().stream()
                            .sorted(Comparator.comparingLong(e -> e.getValue().lastActivityMillis()))
                            .limit(overflow)
                            .map(Map.Entry::getKey)
                            .collect(Collectors.toList())
                            .forEach(trackerMap::remove);
                }
            }
```

with a small accessor on `WindowTracker`:

```java
        synchronized long lastActivityMillis() {
            Long last = timestamps.peekLast();
            return last == null ? 0L : last;
        }
```

(F additionally: cap `ACC:` entry creation — e.g. only track an account after its first lookup hit — so random-username spray cannot inflate the key space at all.)

### SEC-03: Successful login credits attacker's failed attempts on shared source/global counters

- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/security/auth/ratelimit/SlidingWindowRateLimiter.java:164-184`

**Vulnerable code:**

```java
// src/main/java/com/security/auth/ratelimit/SlidingWindowRateLimiter.java:164-184
    public synchronized void recordSuccess(String clientIp, String username) {
        long now = clock.millis();
        long windowMillis = windowDuration.toMillis();

        // Clear failures specifically for this source IP + account on success (Rule 3)
        if (clientIp != null && username != null) {
            trackerMap.remove("SRC_ACC:" + clientIp + ":" + username);
        }
        // Remove the successful attempt from source and account counters so successful login doesn't penalize user
        if (clientIp != null) {
            WindowTracker sourceTracker = trackerMap.get("SRC:" + clientIp);
            if (sourceTracker != null) {
                sourceTracker.removeLatest(now, windowMillis);
            }
        }
        if (username != null) {
            WindowTracker accTracker = trackerMap.get("ACC:" + username);
            if (accTracker != null) {
                accTracker.removeLatest(now, windowMillis);
            }
        }
    }
```

**Why it is a problem:** Because `acquireAttempt` counts *every* allowed request into the shared `SRC:<ip>` bucket (10/15 min) and the victim's `ACC:<user>` bucket (25/15 min), `recordSuccess` tries to refund the current success via `removeLatest`. But `WindowTracker.removeLatest` pops the most recent timestamp, which need not — and in an attack will not — belong to the successful login. An attacker with **any valid account of their own** (free to obtain, or via credential stuffing of low-value accounts) can loop: N failed guesses against `victim` (all counted into `SRC:<attacker-ip>`), then one successful login as `attacker` (pops one entry from `SRC:<attacker-ip>`). With a 1:4 success-to-failure ratio the source bucket never reaches 10, and the same trick resets `ACC:<victim>`: the attacker keeps the victim's global counter at (limit − 1) forever while guessing indefinitely. The refund logic turns authenticated success into a rate-limit-credit faucet.

**Fix:** Clearing the per-pair (`SRC_ACC:`) counter on success is fine; the shared buckets must never be credited, since their entries mix attempts against *other* accounts:

```java
    @Override
    public synchronized void recordSuccess(String clientIp, String username) {
        // Reset only the (source, account) pair that actually authenticated.
        // Do NOT removeLatest() on the shared "SRC:"/"ACC:" trackers: those windows
        // also contain attempts against other accounts, and popping one per success
        // lets an attacker refund their own brute-force budget with cheap successes.
        if (clientIp != null && username != null) {
            trackerMap.remove("SRC_ACC:" + clientIp + ":" + username);
        }
    }
```

One legitimate successful attempt costing one slot of the 10/15-min source budget is acceptable; if that is too strict, track successes outside the failed-attempt window entirely.

### SEC-04: Global per-account limit hard-blocks the legitimate user (distributed account-lockout DoS)

- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/security/auth/ratelimit/SlidingWindowRateLimiter.java:94-99`

**Vulnerable code:**

```java
// src/main/java/com/security/auth/ratelimit/SlidingWindowRateLimiter.java:94-99
        // 3. Check if global account limit is exceeded
        if (accKey != null) {
            WindowTracker tracker = trackerMap.get(accKey);
            if (tracker != null && tracker.isBlocked(now, windowMillis, maxGlobalAccountAttempts)) {
                return RateLimitStatus.ACCOUNT_RATE_LIMITED;
            }
        }
```

**Why it is a problem:** `DEFAULT_MAX_GLOBAL_ACCOUNT_ATTEMPTS = 25` per 15 minutes is shared across *all* source IPs, and hitting it returns `ACCOUNT_RATE_LIMITED`, which the service converts into a hard denial for **anyone** — including the real user (`DefaultAuthenticationService.java:88-99`). The class comment claims this "protects accounts against distributed botnet brute force," but the design doc's own anti-lockout rationale (per-IP+account limits chosen precisely so one IP's abuse doesn't lock out others) is silently abandoned here: 26 guesses from a cheap botnet (26 hosts is nothing) lock any named user out of their account for the window, refreshable forever — a textbook distributed account-lockout DoS that also doubles as harassment/lockout-and-phish bait. It even *helps* the attacker who wants to hide activity: block the account, and the real user's own attempts stop adding noise.

**Fix:** On global-limit breach, degrade service for the *suspicious sources* rather than denying the account owner — e.g. require an out-of-band step-up (CAPTCHA / second factor / password-reset flow) instead of refusing authentication outright:

```java
        // 3. Global account limit breached: distributed abuse signal. Do not deny the
        // legitimate user; demand step-up verification for further attempts.
        if (accKey != null) {
            WindowTracker tracker = trackerMap.get(accKey);
            if (tracker != null && tracker.isBlocked(now, windowMillis, maxGlobalAccountAttempts)) {
                return RateLimitStatus.ACCOUNT_REQUIRES_VERIFICATION;
            }
        }
```

with the service mapping `ACCOUNT_REQUIRES_VERIFICATION` to "we noticed unusual activity — complete CAPTCHA / 2FA / reset via verified email" rather than the current generic hard block, and keeping `maxSourceAttempts` enforcement as the primary teeth. (The `RateLimiter.RateLimitStatus` enum gains one value.)

### SEC-05: Repository-supplied KDF parameters trusted: iterations accepted down to 1,000, algorithm never verified

- **Severity:** Medium
- **CWE:** CWE-326: Inadequate Encryption Strength (with CWE-327: Use of a Broken or Risky Cryptographic Algorithm)
- **Location:** `src/main/java/com/security/auth/crypto/Pbkdf2PasswordHasher.java:87-96`

**Vulnerable code:**

```java
// src/main/java/com/security/auth/crypto/Pbkdf2PasswordHasher.java:87-96
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

```java
// src/main/java/com/security/auth/model/UserRecord.java:36-46
        if (iterations < 1_000 || iterations > 2_000_000) {
            throw new IllegalArgumentException("Iterations must be between 1,000 and 2,000,000.");
        }
        if (algorithm == null || algorithm.isBlank()) {
            throw new IllegalArgumentException("Algorithm must not be blank.");
        }

        this.passwordHash = Arrays.copyOf(passwordHash, passwordHash.length);
        this.salt = Arrays.copyOf(salt, salt.length);
        this.iterations = iterations;
        this.algorithm = algorithm;
```

**Why it is a problem:** The component's own Rule 1 ("treat data-store values as attacker-controlled") is not applied here. `verifyPassword` uses `record.getIterations()` verbatim and never compares `record.getAlgorithm()` against `Pbkdf2PasswordHasher.ALGORITHM`. A credential row with `iterations = 1_000` (legal per `UserRecord`) makes that account's effective hashing 210× cheaper than policy — offline-crackable at GPU speed if the store leaks — and a row with `algorithm = "MD5"` (also legal, it only must be non-blank) is silently *not* verified with MD5: the hasher computes PBKDF2 anyway and returns false, so the stored `algorithm` field is a decoration, while low-iteration rows are honored exactly as written. Anyone able to write or import rows (compromised DB, migration bug, LDAP-sync with an external `iterations` attribute — the InMemory repository today, a real one tomorrow) weakens individual accounts invisibly, and the mismatch also feeds SEC-09's timing oracle. `hashPassword`'s own floor of 1,000 iterations (`Pbkdf2PasswordHasher.java:70`) is ~200× below the OWASP PBKDF2-HMAC-SHA512 recommendation the class itself adopts (210,000).

**Fix:** Fail closed on any row that does not meet current policy, at both boundaries:

```java
// UserRecord.java — policy floor and algorithm allowlist at the model boundary
        if (iterations < 210_000 || iterations > 2_000_000) {
            throw new IllegalArgumentException("Iterations must be between 210,000 and 2,000,000.");
        }
        if (!SupportedAlgorithms.isAllowed(algorithm)) { // Set.of("PBKDF2WithHmacSHA512")
            throw new IllegalArgumentException("Unsupported password algorithm: " + algorithm);
        }
```

```java
// Pbkdf2PasswordHasher.java — defence in depth: never run a KDF the row dictates
        if (!ALGORITHM.equals(record.getAlgorithm())) {
            return false; // unknown KDF: refuse rather than silently reinterpret the row
        }
        if (record.getIterations() < defaultIterations) {
            return false; // under-stretched row: force re-enrolment / re-hash flow instead
        }
        computedHash = hashPassword(password, record.getSalt(), record.getIterations());
```

### SEC-06: TOCTOU: symlink check then `Files.createFile` without `NOFOLLOW_LINKS`

- **Severity:** Medium
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition (with CWE-59: Link Following)
- **Location:** `src/main/java/com/security/auth/logging/SecureFileEventLogger.java:101-105`

**Vulnerable code:**

```java
// src/main/java/com/security/auth/logging/SecureFileEventLogger.java:72-74
        // Prevent symlink attacks (CWE-59)
        if (Files.isSymbolicLink(logFilePath)) {
            throw new SecurityException("Log file path cannot be a symbolic link: " + logFilePath);
```

```java
// src/main/java/com/security/auth/logging/SecureFileEventLogger.java:101-105
        if (!Files.exists(logFilePath)) {
            try {
                FileAttribute<Set<PosixFilePermission>> fileAttr = PosixFilePermissions.asFileAttribute(POSIX_FILE_PERMS);
                Files.createFile(logFilePath, fileAttr);
```

**Why it is a problem:** The anti-symlink defense separates check from use: `isSymbolicLink` at line 73, `Files.createFile` at line 105, with parent-directory checks in between — a wide race window. If the log path does not yet exist (fresh deploy, log wiped/rotated away) and lives anywhere a lower-privileged local user can write (e.g. a shared or mis-permissioned directory, `/tmp`-style staging path), the attacker deletes and re-creates the path as a symlink to a target of their choice between the two calls; `Files.createFile` follows it and opens the *target* with the service's privileges, after which every subsequent `Files.exists`/append flows into that file. Ironically the long-lived writer at lines 121-127 *does* pass `LinkOption.NOFOLLOW_LINKS` — the one creation call that matters does not. The result defeats the component's own CWE-59 control: audit data can be redirected/overwritten into an arbitrary file writable by the service account.

**Fix:** Make creation atomic with respect to symlinks — let the open itself refuse a symlink, instead of checking first:

```java
        if (!Files.exists(logFilePath)) {
            try {
                FileAttribute<Set<PosixFilePermission>> fileAttr = PosixFilePermissions.asFileAttribute(POSIX_FILE_PERMS);
                // CREATE_NEW + NOFOLLOW_LINKS: fails (FileAlreadyExistsException /
                // LinkExistsException) if anything — including a swapped-in symlink —
                // appears at the path, closing the check-to-use race.
                Files.newByteChannel(logFilePath,
                        java.util.EnumSet.of(java.nio.file.StandardOpenOption.CREATE_NEW,
                                             java.nio.file.StandardOpenOption.WRITE),
                        fileAttr,
                        java.nio.file.LinkOption.NOFOLLOW_LINKS).close();
            } catch (java.nio.file.FileAlreadyExistsException race) {
                throw new SecurityException("Log file appeared during initialization: " + logFilePath, race);
            } catch (UnsupportedOperationException e) {
                Files.createFile(logFilePath);
                restrictFilePermissionsFallback(logFilePath.toFile(), false);
            }
        }
```

(Fail closed on the race instead of following whatever won it.)

### SEC-07: Hardcoded dummy-password string literal

- **Severity:** Low
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Location:** `src/main/java/com/security/auth/crypto/Pbkdf2PasswordHasher.java:28`

**Vulnerable code:**

```java
// src/main/java/com/security/auth/crypto/Pbkdf2PasswordHasher.java:28
    private static final char[] DUMMY_FALLBACK_PASSWORD = "DummyFallbackPasswordToProtectTiming!".toCharArray();
```

**Why it is a problem:** This is a password-shaped hardcoded secret in source. It is not *usable* as a credential (it only seeds the dummy-hash timing pad, hashed with a random per-startup salt, never compared against a real store), so actual credential risk is nil — but it violates the component's own Rule 2 ("no working secrets in source"), is exactly what secret scanners like gitleaks flag (CWE-798 pattern), and a future refactor that reuses the constant anywhere real (e.g. a test fixture against a shared directory) turns it into an actual credential. The literal also *helps an attacker who can read source*: spotting it, they can pre-observe the dummy branch's timing profile using the known input.

**Fix:** Generate the dummy input programmatically — it only needs to be a fixed-length non-secret, not a password phrase:

```java
    // Fixed-length, programmatically built pad: constant timing profile, nothing for
    // secret scanners to match, no reusable phrase in the binary.
    private static final char[] DUMMY_FIXED_INPUT = new char[32];
    static {
        java.util.Arrays.fill(DUMMY_FIXED_INPUT, 'a');
    }
```

and replace both uses of `DUMMY_FALLBACK_PASSWORD` (lines 49 and 107) with `DUMMY_FIXED_INPUT`.

### SEC-08: Audit events silently dropped after log-size cap (no rotation)

- **Severity:** Low
- **CWE:** CWE-778: Insufficient Logging
- **Location:** `src/main/java/com/security/auth/logging/SecureFileEventLogger.java:155-162`

**Vulnerable code:**

```java
// src/main/java/com/security/auth/logging/SecureFileEventLogger.java:155-162
        try {
            if (Files.exists(logFilePath) && Files.size(logFilePath) >= maxLogFileSizeBytes) {
                SLF4J_LOGGER.warn("Authentication log file exceeded maximum size of {} bytes. Write omitted to bound storage.", maxLogFileSizeBytes);
            } else {
                writer.write(logLine);
                writer.newLine();
                writer.flush();
            }
```

**Why it is a problem:** The size bound is right (unbounded log growth would itself be a DoS), but the remedy is *permanent silence*: once the file reaches the cap, every authentication event — successful logins, brute-force patterns, all of it — is dropped from the forensic record forever, with a single SLF4J warning that carries no evidence. During the busiest moment for an attacker (sustained credential stuffing, which trivially generates ≥50 MB of events at ~300 B/line), the defender's on-disk trail simply stops: incident reconstruction and the anomaly-detection telemetry this component otherwise provides go blind exactly when they are needed, and nothing ever unblinds it short of manual intervention. Bounding storage and keeping the audit trail are not in conflict — rotation achieves both.

**Fix:** Rotate instead of drop:

```java
        try {
            if (Files.size(logFilePath) >= maxLogFileSizeBytes) {
                rotateSecureLogFile(); // close writer; atomically rename to <path>.1
                                       // (recreate with POSIX 0600 + NOFOLLOW, keep N=5 generations,
                                       //  optionally gzip the rotated file), reopen append writer.
            }
            writer.write(logLine);
            writer.newLine();
            writer.flush();
        } catch (IOException e) {
            SLF4J_LOGGER.error("Failed to write authentication event to log file", e);
        }
```

The rotated generations keep total disk use bounded (`maxLogFileSizeBytes × (N+1)`) while `writer` never stops recording.

### SEC-09: Dummy workload uses configured iterations while real verify uses per-record iterations (timing oracle)

- **Severity:** Low
- **CWE:** CWE-208: Observable Timing Discrepancy
- **Location:** `src/main/java/com/security/auth/crypto/Pbkdf2PasswordHasher.java:106-113`

**Vulnerable code:**

```java
// src/main/java/com/security/auth/crypto/Pbkdf2PasswordHasher.java:109-113
        byte[] computedHash = null;
        try {
            computedHash = hashPassword(pwdToUse, this.dummySalt, this.defaultIterations);
            // Execute constant-time comparison to match real verification execution profile
            MessageDigest.isEqual(computedHash, this.dummyExpectedHash);
```

**Why it is a problem:** The whole timing-defense design (dummy runs on not-found, locked, rate-limited paths "to match real verification execution profile") only equalizes timing if the dummy cost equals the *victim record's* cost. But the dummy always uses `this.defaultIterations`, while the real path uses `record.getIterations()` (line 94). Any user whose row was created with a different iteration count — which SEC-05 shows `UserRecord` permits anywhere in 1,000–2,000,000, and which will happen inevitably as the policy floor is raised over time — produces a verify that is seconds-faster (1,000 iters) or ~10× slower (2,000,000 iters) than the dummy fired for "user not found". An unauthenticated attacker measures response time and reliably distinguishes "account exists with legacy parameters" from "account does not exist": username enumeration, defeating Rule 6 for precisely the cohort least protected otherwise. (`TimingAttackResistanceTest` masks this by using a hasher and records built at identical 1,000-iteration parameters.)

**Fix:** Derive the dummy workload from the same parameters the real path would use, or eliminate per-record variance (which SEC-05's fix largely does):

```java
// PasswordHasher interface: dummy cost matched to the policy parameters under attack
    @Override
    public void performDummyVerification(char[] password) {
        byte[] computedHash = null;
        try {
            // Same parameters the real verify path would use for any policy-compliant
            // record, so a legacy-parameter record cannot stand out. With SEC-05's
            // floor enforced, defaultIterations == every record's iterations.
            computedHash = hashPassword(DUMMY_FIXED_INPUT, this.dummySalt,
                    Math.max(this.defaultIterations, POLICY_MIN_ITERATIONS));
            MessageDigest.isEqual(computedHash, this.dummyExpectedHash);
        } finally {
            if (computedHash != null) {
                Arrays.fill(computedHash, (byte) 0);
            }
        }
    }
```

Strictly: reject or re-hash any record where `record.getIterations() != defaultIterations`, so per-record timing variance cannot exist at all.

## 6. Verified Controls and Checks With No Finding

Confirmed present and correctly implemented (all by code reading; nothing was executed):

- **KDF choice and parameters:** PBKDF2WithHmacSHA512, `DEFAULT_ITERATIONS = 210_000` (matches current OWASP guidance for PBKDF2-SHA512), 512-bit derived key, 16–64 B salts from `SecureRandom` (`Pbkdf2PasswordHasher.java:23-26, 52-60`). Caveat: per-record parameter trust is SEC-05.
- **Constant-time comparison:** `MessageDigest.isEqual` for hash equality in both real and dummy paths; no `Arrays.equals`/`==` on secrets.
- **Token generation:** `SecureRandom`, 32 bytes (256-bit), URL-safe Base64 unpadded, default 1 h lifetime; output buffer zeroized (`TokenGenerator.java`); `SessionToken` enforces ≥32-char values.
- **Cookie hardening:** `Path=/; Max-Age=...; HttpOnly; Secure; SameSite=Strict`, cookie name validated against `^[a-zA-Z0-9_-]+$` before emission (`SessionToken.toSetCookieHeader`) — no cookie-injection surface.
- **No raw secrets in logs:** success events log only a 16-hex-char (64-bit) SHA-256 fingerprint of the session token, never the token; `AuthenticationResult.toString()` omits the error code; `AuthenticationRequest.toString()` redacts the password.
- **Secret zeroization:** passwords held in `char[]`, `AuthenticationRequest.clearCredentials()` fills `'\0'` and is invoked in the service's `finally`; `PBEKeySpec.clearPassword()`, computed-hash and salt buffers zeroized in `finally` paths.
- **Fail-closed error handling:** null request rejected up front; generic `INTERNAL_ERROR`/message on unexpected exceptions with only `ex.getClass().getSimpleName()` logged (no stack/detail leakage to clients); all client-visible failures carry the uniform `Invalid username or password.` message.
- **Enumeration defenses (structural):** dummy workload also fired on not-found, inactive/locked, and rate-limited paths; validation errors and authentication errors return the same generic client message (residual caveat = SEC-09).
- **Atomicity of the limiter's check-then-act:** `acquireAttempt` is `synchronized` and registers the attempt across all three trackers inside the same critical section — no TOCTOU between check and count within the limiter itself (the flaws are in eviction/crediting policy, SEC-02/03, not in atomicity).
- **Input validation:** username strict whitelist regex `{3,64}`; client IP matched against strict IPv4/IPv6 regexes only (no hostnames → no DNS lookups, no SSRF-ish rebinding via IP field); password length bounds checked before use.
- **Log forging (CWE-117):** `AuthenticationEvent.sanitizeAndBound` strips `\r`/`\n`/control characters and bounds every interpolated field (details 256, username 64, IP 45, fingerprint 32), so attacker-controlled values cannot inject fake log lines. Note: the README claims U+2028/U+2029 are stripped but `\p{Cntrl}` does not include them — a documentation inaccuracy, harmless for the flat-file format (no JSON/JS context where those chars terminate lines); worth correcting in the README rather than code.
- **Log file permissions:** 0600 file / 0700 directory via `PosixFileAttributeView`, rejection of world-writable parent directory and of symlinked parent, non-POSIX fallback via owner-only `File.set*able` calls; the steady-state append writer opens with `CREATE, APPEND, NOFOLLOW_LINKS` (the unguarded creation race is SEC-06).
- **Bounded memory:** limiter map capped (remedy flawed — SEC-02 — but no unbounded growth), log retention ring buffer bounded (`pollFirst` at cap), repository bounded at 10,000 users, `retainedEvents` deque pre-sized.
- **Account-status enforcement:** only `AccountStatus.ACTIVE` proceeds to password verification; SUSPENDED/LOCKED take the dummy-workload failure path.
- **Duplicate log emission review:** events are emitted both to the 0600 file and via SLF4J (`SecureFileEventLogger.java:167-172`); acceptable — content is sanitized and secret-free, and central logging is the stated purpose — but deployment must ensure the SLF4J destination is at least as access-controlled as the file (no code finding).
- **Attack-surface classes with no present surface:** no SQL/NoSQL, OS command, LDAP, XML, template, or deserialization sinks anywhere; no URL fetching; only compile-time dependency is `slf4j-api` (minimal supply-chain exposure); `InMemoryUserCredentialRepository` uses `ConcurrentHashMap` with defensive copies (`UserRecord` copies hash/salt on construction and on read).
