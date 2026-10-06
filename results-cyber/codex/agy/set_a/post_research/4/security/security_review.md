# Security Review: Secure User Account Registration and Authentication System

## 1. Executive Summary
The component is a Java 17 command-line authentication system backed by an embedded H2 database. It registers users, hashes passwords with PBKDF2-HMAC-SHA512, authenticates credentials, rate-limits failed logins, issues server-side sessions, and records audit events. The implementation has strong baseline controls—including parameterized SQL, random salts and session tokens, generic login failures, hashed token storage, restrictive cookie attributes, and private filesystem permissions—but it is not safe under concurrency as claimed. Session validation can race with logout and accept a revoked token, and login throttling performs its allow-check separately from failure accounting, permitting parallel bursts to bypass the limit. Other material issues allow a successful login to reset an attacker's source counter, leave registration unthrottled, renew sessions indefinitely, reveal account existence during registration, print bearer tokens, and fall back to echoed/immutable password input. Eight findings were identified: two High and six Medium.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `README.md` | Describes the architecture, threat model, controls, and operational usage. | Makes security claims about atomicity, credential output, rate limiting, and session handling that were checked against the implementation. |
| `pom.xml` | Maven build and dependency declaration. | Pins Java 17, H2, SLF4J, JUnit, compiler, test, JAR, and shading plugins. |
| `src/main/java/com/security/auth/Main.java` | Interactive CLI and application lifecycle. | Reads credentials, invokes registration/authentication/session operations, and writes results—including session credentials—to the terminal. |
| `src/main/java/com/security/auth/config/SecurityConfig.java` | Loads environment configuration and secures the data directory. | Handles database credentials, PBKDF2 work factor, path validation, permissions, and identifier masking. |
| `src/main/java/com/security/auth/crypto/CryptoUtils.java` | Cryptographic helper methods. | Wipes arrays, compares values with `MessageDigest.isEqual`, and computes SHA-256 token digests. |
| `src/main/java/com/security/auth/crypto/PasswordHasher.java` | Password hashing and verification. | Uses PBKDF2-HMAC-SHA512, per-password random salts, constant-time comparison, and dummy verification work. |
| `src/main/java/com/security/auth/crypto/TokenGenerator.java` | Session-token generation and validation. | Generates 256-bit random tokens, validates their format, and hashes them before persistence. |
| `src/main/java/com/security/auth/database/DatabaseManager.java` | Schema creation and database access. | Stores users, password hashes, sessions, and audit events; uses prepared statements and enforces database-file permissions. |
| `src/main/java/com/security/auth/model/AuthenticationRequest.java` | Login input model. | Clones and wipes a password array and carries the claimed source IP. |
| `src/main/java/com/security/auth/model/AuthenticationResult.java` | Login result model. | Carries the raw bearer token, cookie, and authenticated user to callers. |
| `src/main/java/com/security/auth/model/RegistrationRequest.java` | Registration input model. | Clones and wipes a password array. |
| `src/main/java/com/security/auth/model/RegistrationResult.java` | Registration result model. | Produces observably different success and failure states. |
| `src/main/java/com/security/auth/model/Session.java` | Persistent session model. | Tracks token hash, user, source IP, creation, activity, and expiry timestamps. |
| `src/main/java/com/security/auth/model/SessionCookie.java` | HTTP cookie representation. | Sets `__Host-`, `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, and `Max-Age`. |
| `src/main/java/com/security/auth/model/User.java` | Persistent user model. | Holds identifiers, password hash, salt, iteration count, and masked string rendering. |
| `src/main/java/com/security/auth/security/RateLimiter.java` | In-memory source/account login throttling. | Tracks failures, blocks sources, delays attacked accounts, clears counters, and bounds map sizes. |
| `src/main/java/com/security/auth/service/AuthenticationService.java` | Core registration, authentication, and session orchestration. | Defines trust-boundary validation, expensive hashing, rate-limit ordering, token issuance, session validation, and logout. |
| `src/main/java/com/security/auth/validation/InputValidator.java` | Input validation and normalization. | Bounds and validates email, username, password, IP, token-related, and UUID values. |
| `src/test/java/com/security/auth/config/SecurityConfigTest.java` | Configuration and permission tests. | Checks directory modes, path rejection, and secret masking. |
| `src/test/java/com/security/auth/crypto/PasswordHasherTest.java` | Password-hashing tests. | Checks unique salts, verification, dummy work, and array wiping. |
| `src/test/java/com/security/auth/crypto/TokenGeneratorTest.java` | Token tests. | Checks format, sample uniqueness, hashing, and malformed-token rejection. |
| `src/test/java/com/security/auth/security/RateLimiterTest.java` | Rate-limiter tests. | Checks sequential source blocking, account delay, and memory bounds, but not concurrent acquisition or reset abuse. |
| `src/test/java/com/security/auth/service/AuthenticationServiceTest.java` | End-to-end service tests. | Checks registration, login failures, session lifecycle, cookie flags, SQLi rejection, and sequential logout, but not unsafe interleavings. |
| `src/test/java/com/security/auth/validation/InputValidatorTest.java` | Validator tests. | Checks accepted/rejected email, username, password, and IP inputs. |

Generated `target/` bytecode, JARs, Maven metadata, and test reports duplicate the reviewed source or record prior builds and were not executed or imported. `data/secure_store/user_auth_db.mv.db` is runtime data, not source code. `prompt.txt`, `prompt_hash.txt`, `result.md`, and `return.txt` are task/provenance artifacts and are not part of the runtime component.

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Used to inventory every source/configuration file, identify security behaviours, route those behaviours to specialized skills, and require CWE and file:line evidence.
- `performing-cryptographic-audit-of-application`: Applied to PBKDF2 parameters, salts, random generation, token hashing, comparisons, secret handling, and dependency declarations.
- `testing-api-authentication-weaknesses`: Applied to login responses, account enumeration, password handling, bearer-token exposure, expiry, revocation, and session lifecycle.
- `implementing-api-rate-limiting-and-throttling`: Applied to per-source/per-account throttling, atomic acquisition, counter reset behaviour, registration abuse, and resource-exhaustion resistance.
- `exploiting-sql-injection-vulnerabilities`: Applied statically to every SQL construction and bind point, including second-order uses of persisted identifiers.
- `implementing-secret-scanning-with-gitleaks`: Applied manually to production and test literals, environment-based credentials, token output, and logging/string-rendering paths; no scanner or repository code was executed.
- General OWASP Top 10 / CWE knowledge: Applied to concurrency/TOCTOU, filesystem permissions and paths, sensitive output, unsafe password-input fallback, configuration validation, and data exposure where no closer library skill matched.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Logout can race with validation and a revoked session can be accepted | High | CWE-367 | `src/main/java/com/security/auth/service/AuthenticationService.java:262` |
| SEC-02 | Rate-limit check and accounting are not atomic | High | CWE-362 | `src/main/java/com/security/auth/service/AuthenticationService.java:155` |
| SEC-03 | Any successful login clears all source failures | Medium | CWE-307 | `src/main/java/com/security/auth/security/RateLimiter.java:124` |
| SEC-04 | Registration performs unthrottled expensive and persistent work | Medium | CWE-770 | `src/main/java/com/security/auth/service/AuthenticationService.java:60` |
| SEC-05 | Activity continually renews sessions with no absolute lifetime | Medium | CWE-613 | `src/main/java/com/security/auth/service/AuthenticationService.java:288` |
| SEC-06 | Registration outcomes disclose whether an account exists | Medium | CWE-203 | `src/main/java/com/security/auth/service/AuthenticationService.java:78` |
| SEC-07 | Raw bearer session credentials are printed to standard output | Medium | CWE-200 | `src/main/java/com/security/auth/Main.java:124` |
| SEC-08 | Password input falls back to an echoed immutable string | Medium | CWE-549 | `src/main/java/com/security/auth/Main.java:177` |

## 5. Detailed Findings

### SEC-01: Logout can race with validation and a revoked session can be accepted
- **Severity:** High
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `src/main/java/com/security/auth/service/AuthenticationService.java:262-301`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/service/AuthenticationService.java:262-301
        String tokenHash = tokenGenerator.hashToken(rawToken);
        Optional<Session> sessionOpt = databaseManager.findSessionByTokenHash(tokenHash);

        if (sessionOpt.isEmpty()) {
            return Optional.empty();
        }

        Session session = sessionOpt.get();
        Instant now = Instant.now();

        // Check expiration
        if (session.isExpired(now)) {
            log.info("Session expired: sessionId={}", session.getId());
            databaseManager.deleteSessionByTokenHash(tokenHash);
            return Optional.empty();
        }

        // Verify source IP binding to prevent token replay from other IPs
        if (!session.getSourceIp().equals(sanitizedSourceIp)) {
            log.warn("Session source IP mismatch detected: sessionIp={}, requestIp={}",
                    session.getSourceIp(), sanitizedSourceIp);
            // Invalidate suspicious session
            databaseManager.deleteSessionByTokenHash(tokenHash);
            return Optional.empty();
        }

        // Check inactivity timeout (e.g. 30 minutes)
        Duration inactiveDuration = Duration.between(session.getLastActiveAt(), now);
        if (inactiveDuration.toMinutes() >= config.getSessionTtlMinutes()) {
            log.info("Session exceeded inactivity timeout: sessionId={}", session.getId());
            databaseManager.deleteSessionByTokenHash(tokenHash);
            return Optional.empty();
        }

        // Slide session expiration and update last active time
        Instant newExpiresAt = now.plus(Duration.ofMinutes(config.getSessionTtlMinutes()));
        databaseManager.updateSessionActivity(session.getId(), now, newExpiresAt);

        // Fetch user from DB
        return databaseManager.findUserById(session.getUserId());
```

**Why it is a problem:** The session is read and checked through one connection, activity is updated through another, and the user is fetched through a third. If `logout()` deletes the row after `findSessionByTokenHash()` but before the final return, `updateSessionActivity()` silently updates zero rows and the already-loaded user is still returned. The request therefore authenticates with a token that has been revoked. The sequential logout test does not exercise this interleaving.

**Fix:** Make validation/touch/user resolution one database transaction and give it a single linearization point. Lock the session row (`SELECT ... FOR UPDATE`) or use an atomic conditional update, require exactly one affected row, fetch the user on the same connection, and commit before returning. A logout ordered before the transaction must make validation fail; one ordered after it takes effect for subsequent requests.
```java
public Optional<User> validateSession(String rawToken, String sourceIp) {
    if (!tokenGenerator.isValidTokenFormat(rawToken)) {
        return Optional.empty();
    }
    String validatedIp = InputValidator.validateSourceIp(sourceIp);
    String tokenHash = tokenGenerator.hashToken(rawToken);
    Instant now = Instant.now();
    return databaseManager.validateAndTouchSessionAtomically(
            tokenHash,
            validatedIp,
            now,
            Duration.ofMinutes(config.getSessionTtlMinutes())
    );
}

// validateAndTouchSessionAtomically must SELECT the session FOR UPDATE,
// validate it, update last_active_at, fetch the user, and commit using one Connection.
```

### SEC-02: Rate-limit check and accounting are not atomic
- **Severity:** High
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- **Location:** `src/main/java/com/security/auth/service/AuthenticationService.java:155-181`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/service/AuthenticationService.java:155-181
            // 2. Dual Rate Limiting Check (Rule 3 & 7)
            RateLimiter.CheckResult checkResult = rateLimiter.checkAllowed(sanitizedSourceIp, normalizedIdentifier);
            if (!checkResult.allowed()) {
                log.warn("Authentication blocked by rate limiter for source={}", sanitizedSourceIp);
                databaseManager.recordAuditLog("AUTH_RATE_LIMITED", SecurityConfig.maskIdentifier(normalizedIdentifier), sanitizedSourceIp, false);
                return AuthenticationResult.rateLimited(checkResult.reason());
            }

            // Apply progressive delay if account is experiencing distributed pressure
            if (checkResult.delayMs() > 0) {
                try {
                    Thread.sleep(checkResult.delayMs());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }

            // 3. Database user lookup
            Optional<User> userOpt = databaseManager.findUserByIdentifier(normalizedIdentifier);

            if (userOpt.isEmpty()) {
                // Rule 6: Constant work timing mitigation!
                // Execute identical dummy PBKDF2 hash computation so response time matches real user verification.
                passwordHasher.verifyDummy(password);

                // Record failure in rate limiter
                rateLimiter.recordFailure(sanitizedSourceIp, normalizedIdentifier);
```

**Why it is a problem:** `checkAllowed()` only reads tracker state. The counter is incremented later, after a database lookup and an expensive PBKDF2 operation. Many concurrent requests from the same source/account can all observe an allowed state before any records a failure, so an attacker can submit an arbitrarily large parallel burst despite the five-failure limit. Each map update inside `recordFailure()` is atomic, but the security decision and reservation are not.

**Fix:** Atomically acquire/reserve an attempt before doing database or password-hash work. For this single-process implementation, a synchronized or correctly locked check-and-increment operation is sufficient; a server deployment should use a shared atomic store. Release only in-flight capacity after completion, while retaining historical attempt/failure counts.
```java
RateLimiter.CheckResult checkResult = rateLimiter.acquireAttempt(
        sanitizedSourceIp,
        normalizedIdentifier
);
if (!checkResult.allowed()) {
    return AuthenticationResult.rateLimited(checkResult.reason());
}

try {
    return verifyCredentialsAndCreateSession(request, normalizedIdentifier, sanitizedSourceIp);
} finally {
    rateLimiter.completeAttempt(sanitizedSourceIp, normalizedIdentifier);
}

// acquireAttempt must atomically check limits and reserve capacity before returning allowed.
```

### SEC-03: Any successful login clears all source failures
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/security/auth/security/RateLimiter.java:124-127`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/security/RateLimiter.java:124-127
    public void recordSuccess(String sourceIp, String accountIdentifier) {
        sourceTrackers.remove(sourceIp);
        accountTrackers.remove(accountIdentifier.toLowerCase());
    }
```

**Why it is a problem:** The source counter aggregates failures against all accounts, but success against any one account removes the entire source record. An attacker with one valid account can make four guesses against a victim, log in to the attacker-controlled account from the same source to reset the counter, and repeat indefinitely. The account delay eventually adds at most five seconds, but the intended 15-minute source block is bypassed.

**Fix:** A success may clear the successfully authenticated account's counter, but it must not erase failures the same source accumulated against other accounts. Let source failures expire naturally or decay them conservatively.
```java
public void recordSuccess(String sourceIp, String accountIdentifier) {
    accountTrackers.remove(accountIdentifier.toLowerCase(Locale.ROOT));
    // Do not clear sourceTrackers here. Source failures span all targeted accounts.
}
```

### SEC-04: Registration performs unthrottled expensive and persistent work
- **Severity:** Medium
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `src/main/java/com/security/auth/service/AuthenticationService.java:60-84`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/service/AuthenticationService.java:60-84
    public RegistrationResult register(RegistrationRequest request, String sourceIp) {
        Objects.requireNonNull(request, "Registration request must not be null");
        String sanitizedSourceIp = InputValidator.validateSourceIp(sourceIp);

        try {
            // 1. Strict Whitelist Input Validation
            String validatedEmail;
            String validatedUsername;
            try {
                validatedEmail = InputValidator.validateAndNormalizeEmail(request.getEmail());
                validatedUsername = InputValidator.validateUsername(request.getUsername());
                InputValidator.validatePassword(request.getPassword());
            } catch (IllegalArgumentException e) {
                log.warn("Registration rejected due to invalid input format: reason={}", e.getMessage());
                // Rule 6: Fail closed with generic message
                return RegistrationResult.failure();
            }

            // 2. Pre-check if user already exists
            boolean alreadyExists = databaseManager.userExists(validatedUsername, validatedEmail);

            // 3. Compute PBKDF2 hash (COMPRABLE WORK)
            // Even if the account already exists, we compute the full PBKDF2 hash
            // to ensure an attacker cannot measure timing differences to enumerate registered users!
            PasswordHasher.HashedPassword hashedPassword = passwordHasher.hash(request.getPassword());
```

**Why it is a problem:** `sourceIp` is validated but never used to limit registration. Every syntactically valid request performs a 210,000-iteration PBKDF2 calculation; unique inputs then add database and audit rows. An unauthenticated client can therefore consume CPU and grow persistent storage without a request, source, or global quota. Password-length bounds do not limit the number of expensive operations.

**Fix:** Apply a separate atomic registration limiter before database access or hashing, with per-source and global quotas. In a networked deployment, derive the source from trusted transport/proxy metadata and use shared rate-limit state.
```java
public RegistrationResult register(RegistrationRequest request, String sourceIp) {
    Objects.requireNonNull(request, "Registration request must not be null");
    String validatedSourceIp = InputValidator.validateSourceIp(sourceIp);
    if (!registrationLimiter.tryAcquire(validatedSourceIp)) {
        request.wipe();
        return RegistrationResult.failure();
    }
    return registerValidatedAndRateLimited(request, validatedSourceIp);
}
```

### SEC-05: Activity continually renews sessions with no absolute lifetime
- **Severity:** Medium
- **CWE:** CWE-613: Insufficient Session Expiration
- **Location:** `src/main/java/com/security/auth/service/AuthenticationService.java:288-301`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/service/AuthenticationService.java:288-301
        // Check inactivity timeout (e.g. 30 minutes)
        Duration inactiveDuration = Duration.between(session.getLastActiveAt(), now);
        if (inactiveDuration.toMinutes() >= config.getSessionTtlMinutes()) {
            log.info("Session exceeded inactivity timeout: sessionId={}", session.getId());
            databaseManager.deleteSessionByTokenHash(tokenHash);
            return Optional.empty();
        }

        // Slide session expiration and update last active time
        Instant newExpiresAt = now.plus(Duration.ofMinutes(config.getSessionTtlMinutes()));
        databaseManager.updateSessionActivity(session.getId(), now, newExpiresAt);

        // Fetch user from DB
        return databaseManager.findUserById(session.getUserId());
```

**Why it is a problem:** Every successful validation moves `expires_at` forward by the full TTL. Because the same TTL is also used as the inactivity timeout, a regularly used or stolen token can remain valid forever. There is no independent absolute maximum lifetime that forces reauthentication.

**Fix:** Keep an immutable absolute expiration (for example, eight hours after issuance) and update only `last_active_at`. Reject a session when either its idle timeout or absolute expiry is reached; do not extend the absolute boundary.
```java
if (!now.isBefore(session.getExpiresAt())) {
    databaseManager.deleteSessionByTokenHash(tokenHash);
    return Optional.empty();
}

Duration idle = Duration.between(session.getLastActiveAt(), now);
if (idle.compareTo(Duration.ofMinutes(config.getSessionTtlMinutes())) >= 0) {
    databaseManager.deleteSessionByTokenHash(tokenHash);
    return Optional.empty();
}

databaseManager.updateSessionActivity(session.getId(), now); // Do not change expires_at.
return databaseManager.findUserById(session.getUserId());
```

### SEC-06: Registration outcomes disclose whether an account exists
- **Severity:** Medium
- **CWE:** CWE-203: Observable Discrepancy
- **Location:** `src/main/java/com/security/auth/service/AuthenticationService.java:78-118`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/service/AuthenticationService.java:78-118
            // 2. Pre-check if user already exists
            boolean alreadyExists = databaseManager.userExists(validatedUsername, validatedEmail);

            // 3. Compute PBKDF2 hash (COMPRABLE WORK)
            // Even if the account already exists, we compute the full PBKDF2 hash
            // to ensure an attacker cannot measure timing differences to enumerate registered users!
            PasswordHasher.HashedPassword hashedPassword = passwordHasher.hash(request.getPassword());

            if (alreadyExists) {
                log.info("Registration aborted: user or email already exists for masked username={}",
                        SecurityConfig.maskIdentifier(validatedUsername));
                databaseManager.recordAuditLog("REGISTRATION_DUPLICATE", SecurityConfig.maskIdentifier(validatedUsername), sanitizedSourceIp, false);
                // Rule 6: Return identical generic message
                return RegistrationResult.failure();
            }

            // 4. Atomic SQL Insertion
            String userId = UUID.randomUUID().toString();
            User newUser = new User(
                    userId,
                    validatedUsername,
                    validatedEmail,
                    hashedPassword.hashBase64(),
                    hashedPassword.saltBase64(),
                    hashedPassword.iterations(),
                    Instant.now()
            );

            boolean inserted = databaseManager.insertUser(newUser);
            if (!inserted) {
                // Caught race condition or DB constraint collision
                log.info("Registration collision during atomic insert for username={}",
                        SecurityConfig.maskIdentifier(validatedUsername));
                databaseManager.recordAuditLog("REGISTRATION_COLLISION", SecurityConfig.maskIdentifier(validatedUsername), sanitizedSourceIp, false);
                return RegistrationResult.failure();
            }

            log.info("New user registered successfully: userId={}, username={}",
                    userId, SecurityConfig.maskIdentifier(validatedUsername));
            databaseManager.recordAuditLog("REGISTRATION_SUCCESS", SecurityConfig.maskIdentifier(validatedUsername), sanitizedSourceIp, true);
            return RegistrationResult.success(userId);
```

**Why it is a problem:** Comparable PBKDF2 work and generic failure text hide differences among failure causes, but they do not hide success versus failure. An unauthenticated attacker can submit a candidate email with a fresh username: an existing email returns failure, while an unused email creates an account and returns success plus a user ID. The same technique works for usernames. This directly enumerates registered identifiers and can pre-register unverified email addresses.

**Fix:** Use a pending-registration/email-verification workflow. Return the same public "request accepted" result whether the identifier exists, conflicts, or was newly queued; do not activate the account or return a user ID until possession of the email address is proven.
```java
public RegistrationResult register(RegistrationRequest request, String sourceIp) {
    String email = InputValidator.validateAndNormalizeEmail(request.getEmail());
    String username = InputValidator.validateUsername(request.getUsername());
    InputValidator.validatePassword(request.getPassword());

    registrationWorkflow.queueVerificationIfEligible(email, username, request.getPassword());
    return RegistrationResult.submitted(
            "If the supplied details can be used, follow-up instructions will be sent."
    );
}
```

### SEC-07: Raw bearer session credentials are printed to standard output
- **Severity:** Medium
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **Location:** `src/main/java/com/security/auth/Main.java:124-127`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/Main.java:124-127
            System.out.println("\n[Response] " + result.getMessage());
            if (result.isSuccess()) {
                System.out.println("[Session Token] " + result.getSessionToken());
                System.out.println("[Set-Cookie]    " + result.getSessionCookie().toHeaderValue());
```

**Why it is a problem:** The token is a bearer credential that grants access to the authenticated account. It is printed twice—once directly and once inside the cookie header. Standard output is commonly captured by terminal scrollback, IDE consoles, process supervisors, CI logs, or redirected files. Anyone who can read that output can replay the token until it expires or is revoked. This also contradicts the README's claim that tokens are never printed.

**Fix:** Do not render bearer credentials to human-readable output. Keep the active session credential inside the client process, or, in an HTTP adapter, send only a `Set-Cookie` response over TLS and ensure response bodies and logs exclude the value.
```java
System.out.println("\n[Response] " + result.getMessage());
if (result.isSuccess()) {
    sessionState.replaceWith(result.getSessionToken());
    System.out.println("[Status] Session established securely.");
    System.out.println("[User Profile] ID=" + result.getUser().getId()
            + ", Username=" + result.getUser().getUsername()
            + ", Email=" + SecurityConfig.maskIdentifier(result.getUser().getEmail()));
}
```

### SEC-08: Password input falls back to an echoed immutable string
- **Severity:** Medium
- **CWE:** CWE-549: Missing Password Field Masking
- **Location:** `src/main/java/com/security/auth/Main.java:177-184`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/Main.java:177-184
    private static char[] readPasswordSecurely(BufferedReader reader, Console console) throws IOException {
        if (console != null) {
            char[] pwd = console.readPassword();
            return (pwd != null) ? pwd : new char[0];
        } else {
            String line = reader.readLine();
            return (line != null) ? line.toCharArray() : new char[0];
        }
    }
```

**Why it is a problem:** When `System.console()` is unavailable—as is common in IDE consoles, redirected execution, and some service wrappers—the code silently reads the password through ordinary standard input. Interactive input may be echoed, and `readLine()` first materializes the secret as an immutable `String` that cannot be wiped, defeating the component's stated memory-clearing guarantee.

**Fix:** Fail closed when a no-echo console is unavailable, or use a platform terminal API that explicitly disables echo and returns a mutable buffer. Do not silently downgrade to `BufferedReader.readLine()`.
```java
private static char[] readPasswordSecurely(Console console) throws IOException {
    if (console == null) {
        throw new IOException("A secure, no-echo console is required for password input");
    }
    char[] password = console.readPassword();
    if (password == null) {
        throw new IOException("Password input was closed");
    }
    return password;
}
```

## 6. Verified Controls and Checks With No Finding
- SQL injection: Every runtime query and mutation in `DatabaseManager.java` uses a fixed SQL string and `PreparedStatement` bind parameters; no external value is concatenated into SQL.
- Password storage: `PasswordHasher.java` uses PBKDF2-HMAC-SHA512 with a 210,000 default iteration count, a fresh 32-byte `SecureRandom` salt, a 512-bit derived value, and constant-time byte comparison.
- Login enumeration: Existing-user bad-password and nonexistent-user paths return the same `AuthenticationResult.failure()` and perform PBKDF2 work; the separate registration discrepancy is reported as SEC-06.
- Session-token generation and storage: `TokenGenerator.java` generates 32 random bytes with `SecureRandom`, enforces a 43-character Base64URL format, and persists only a SHA-256 digest of the high-entropy bearer token.
- Cookie attributes: `SessionCookie.java` uses a `__Host-` name with `Path=/`, `Secure`, `HttpOnly`, `SameSite=Strict`, and a bounded `Max-Age`.
- Logout in non-concurrent execution: `logout()` hashes the presented token and deletes the server-side row; subsequent sequential validation fails. Concurrent validation/revocation is covered by SEC-01.
- Input bounds: Email, username, password, source-IP, and token lengths are bounded before their expensive or persistent uses; username and token character sets are allowlisted.
- Secret literals: No production API key, private key, live password, or fixed session secret was found. The hardcoded dummy PBKDF2 value is not accepted for any account, and test passwords are fixtures.
- Logging and string rendering: Passwords, hashes, salts, and raw tokens are excluded from application logger calls and protected in model `toString()` implementations. Direct terminal disclosure is separately reported as SEC-07.
- Filesystem permissions: `SecurityConfig` creates/restricts the data directory to owner-only access, and `DatabaseManager` attempts owner-only database-file modes. Shared temporary directory prefixes and world-writable final directories are rejected.
- SQL uniqueness and registration races: Database `UNIQUE` constraints on username/email provide the authoritative collision control, and failed inserts are rolled back.
- Dependency advisory spot-check: The declared H2 `2.3.232` is outside the affected range (`1.1.100` through `2.0.204`) of the project's published H2 Console RCE advisory, which lists `2.0.206` as patched. No vulnerable use of that advisory was found. See [GHSA-h376-j262-vhq6](https://github.com/h2database/h2database/security/advisories/GHSA-h376-j262-vhq6).
- Generated artifacts: Compiled classes, JARs, test reports, and the existing database were not executed, built, installed, imported, or modified during this static review.
