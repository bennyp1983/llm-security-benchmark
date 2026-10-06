# Security Review: Secure Java Authentication System

## 1. Executive Summary
The component is a Java 17 command-line authentication system backed by H2. It registers users, hashes passwords with PBKDF2-HMAC-SHA-256, verifies credentials, rate-limits login attempts, issues in-memory sessions, and produces security audit logs. This was a static review only; no source code, compiled classes, JARs, tests, or dependencies were executed or imported.

The review found nine vulnerabilities: one High-severity unbounded rate-limiter cache, seven Medium-severity issues involving session-token disclosure, unbounded session storage, insufficient PBKDF2 work factor, weak password requirements, silent password truncation, potentially echoed fallback password input, and fail-open database permissions, plus one Low-severity unbounded email read. The most urgent correction is to replace the rate limiter's ineffective post-limit cleanup with storage that enforces a hard capacity. Authentication responses, SQL parameterization, session entropy and cookie attributes, constant-time hash comparison, secret zeroization, log-forging defenses, and database transaction handling were otherwise implemented carefully.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `pom.xml` | Maven build and dependency declaration | Pins H2, JUnit, compiler, test, JAR, and shade plugin versions. |
| `dependency-reduced-pom.xml` | Shade plugin's generated reduced build descriptor | Records the post-shading dependency/build configuration. |
| `README.md` | Architecture, usage, and claimed security properties | Documents threat assumptions, credential handling, rate limits, sessions, and file permissions; claims were checked against code. |
| `src/main/java/com/example/auth/AuthenticationResult.java` | Authentication outcome model | Returns generic success, invalid-credential, rate-limit, and internal-error messages and optionally exposes a session. |
| `src/main/java/com/example/auth/AuthenticationService.java` | Registration and login coordinator | Validates inputs, rate-limits attempts, queries users, verifies hashes, issues sessions, manages transactions, logs outcomes, and clears passwords. |
| `src/main/java/com/example/auth/DatabaseManager.java` | H2 connection and schema manager | Accepts JDBC/environment configuration, initializes credential storage, and attempts local database permission hardening. |
| `src/main/java/com/example/auth/HashResult.java` | Password-hash value object | Carries salt, derived hash, work factor, and algorithm. |
| `src/main/java/com/example/auth/InputValidator.java` | Trust-boundary validator | Bounds and canonicalizes email/password/source inputs and validates stored hash parameters. |
| `src/main/java/com/example/auth/Main.java` | Interactive CLI | Reads email/password input, invokes registration/login, and writes authentication/session results to standard output. |
| `src/main/java/com/example/auth/PasswordHasher.java` | Password hashing and verification | Uses PBKDF2-HMAC-SHA-256, random salts, dummy work, constant-time comparison, and array clearing. |
| `src/main/java/com/example/auth/RateLimiter.java` | In-memory login throttling | Tracks source, source/account, and global-account attempts in concurrent maps. |
| `src/main/java/com/example/auth/SecurityLogger.java` | Security/audit logger | Masks email/token values, neutralizes CR/LF, and logs internal authentication reasons and exceptions. |
| `src/main/java/com/example/auth/SessionManager.java` | In-memory session manager | Generates random bearer tokens, builds hardened cookies, validates expiry, revokes tokens, and stores active sessions. |
| `src/main/java/com/example/auth/UserRecord.java` | Database user model | Represents identity, password-hash metadata, and account status. |
| `src/main/java/com/example/auth/UserRepository.java` | Credential repository | Uses prepared statements for user lookup, creation, and counting and validates stored hash metadata. |
| `src/test/java/com/example/auth/AuthenticationServiceTest.java` | Authentication workflow tests | Covers success/failure, generic errors, SQL injection rejection, zeroization, and rate limiting. |
| `src/test/java/com/example/auth/InputValidatorTest.java` | Input validation tests | Covers email syntax/length, control characters, regex timing, password bounds, source IDs, and stored hash parameters. |
| `src/test/java/com/example/auth/PasswordHasherTest.java` | Password hashing tests | Covers derivation, verification, malformed data, dummy work, and salt uniqueness. |
| `src/test/java/com/example/auth/RateLimiterTest.java` | Rate-limiter tests | Covers per-source/account enforcement, concurrency, reset, and lockout behavior, but not hard capacity. |
| `src/test/java/com/example/auth/SecurityAdversarialTest.java` | Adversarial security tests | Covers timing, account enumeration, CR/LF injection, masking, and lockout denial of service. |
| `src/test/java/com/example/auth/SessionManagerTest.java` | Session tests | Covers token length/uniqueness, cookie flags, validation, and invalidation, but not hard capacity. |

Generated `.class`, JAR, Maven-status, and Surefire-report files under `target/` were treated as build artifacts rather than source code. `prompt.txt`, `prompt_hash.txt`, `result.md`, and `return.txt` are task/provenance artifacts and contain no application code.

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Routed the review by first mapping every source file and security-relevant behavior, then selecting and applying the specialized skills below.
- `testing-api-authentication-weaknesses`: Applied to password policy, credential verification, account-enumeration resistance, session lifecycle, token entropy, revocation, and token leakage.
- `performing-cryptographic-audit-of-application`: Applied to PBKDF2 algorithm/work factor, salts, random number generation, constant-time comparison, secret handling, and hardcoded-secret checks.
- `testing-for-sensitive-data-exposure`: Applied to console/log output, error handling, email masking, session-token exposure, credential storage, and database-file protection.
- `exploiting-sql-injection-vulnerabilities`: Applied statically to every JDBC statement, including first- and second-order input paths; no exploitation or execution was performed.
- `implementing-api-rate-limiting-and-throttling`: Applied to attempt keys, atomicity, limits, cleanup, capacity enforcement, and brute-force protections.
- `implementing-api-abuse-detection-with-rate-limiting`: Applied to distributed/rotating-identifier abuse, denial-of-service resistance, cache lifetime, and bounded-state requirements.
- General OWASP Top 10 / CWE knowledge: Applied to CLI input echo/truncation and local database permission failure because no closer specialized skill matched those behaviors.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Rate-limiter caches have no enforceable capacity | High | CWE-770 | `src/main/java/com/example/auth/RateLimiter.java:186-203` |
| SEC-02 | Full session bearer token is written to standard output | Medium | CWE-200 | `src/main/java/com/example/auth/Main.java:83-88` |
| SEC-03 | Active-session limit does not prevent unbounded growth | Medium | CWE-770 | `src/main/java/com/example/auth/SessionManager.java:64-87` |
| SEC-04 | PBKDF2-HMAC-SHA-256 work factor is below current guidance | Medium | CWE-916 | `src/main/java/com/example/auth/PasswordHasher.java:19-22` |
| SEC-05 | Registration accepts weak and commonly compromised passwords | Medium | CWE-521 | `src/main/java/com/example/auth/InputValidator.java:17-20` |
| SEC-06 | Fallback password reader silently truncates credentials | Medium | CWE-187 | `src/main/java/com/example/auth/Main.java:178-194` |
| SEC-07 | Password fallback may expose input through terminal echo | Medium | CWE-522 | `src/main/java/com/example/auth/Main.java:150-160` |
| SEC-08 | Database permission hardening fails open | Medium | CWE-636 | `src/main/java/com/example/auth/DatabaseManager.java:91-125` |
| SEC-09 | Fallback email reader accepts an unbounded line | Low | CWE-400 | `src/main/java/com/example/auth/Main.java:164-175` |

## 5. Detailed Findings

### SEC-01: Rate-limiter caches have no enforceable capacity
- **Severity:** High
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `src/main/java/com/example/auth/RateLimiter.java:186-203`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/RateLimiter.java:186-203
    private AttemptTracker getOrCreateTracker(ConcurrentHashMap<String, AttemptTracker> map,
                                              String key, long windowMs, int maxAttempts, long now) {
        return map.computeIfAbsent(key, k -> {
            entryCount.incrementAndGet();
            return new AttemptTracker(windowMs, maxAttempts, now);
        });
    }

    /**
     * Enforces bounded memory (Rule 5). Purges expired trackers when capacity limit is reached.
     */
    private void evictIfNecessary(long now) {
        if (entryCount.get() > MAX_CACHE_ENTRIES) {
            purgeExpired(sourceTrackers, now);
            purgeExpired(sourceAccountTrackers, now);
            purgeExpired(globalAccountTrackers, now);
            entryCount.set(sourceTrackers.size() + sourceAccountTrackers.size() + globalAccountTrackers.size());
        }
    }
```

**Why it is a problem:** `MAX_CACHE_ENTRIES` is only a threshold for attempting expiry cleanup; it is not a capacity. If the entries are still within their five- or ten-minute windows, none are removed and `computeIfAbsent` keeps allocating entries without limit. An unauthenticated caller can rotate valid source identifiers and email strings to create multiple new trackers per attempt. The implementation therefore permits attacker-driven heap growth despite claiming bounded storage. This risk is amplified because `AuthenticationService.authenticate` creates these keys before it validates the email format.

**Fix:** Use one cache for namespaced tracker keys with a library-enforced hard maximum and time-based expiry, or implement an equally strict atomic admission/eviction policy. Size limits must be enforced during insertion, not merely followed by best-effort cleanup. For a multi-instance deployment, move the counters to a bounded shared store such as Redis.
```java
private final Cache<String, AttemptTracker> trackers = Caffeine.newBuilder()
        .maximumSize(MAX_CACHE_ENTRIES)
        .expireAfterAccess(Duration.ofMillis(GLOBAL_ACCOUNT_WINDOW_MS))
        .build();

private AttemptTracker getOrCreateTracker(String namespace, String key,
                                          long windowMs, int maxAttempts, long now) {
    String cacheKey = namespace + "\0" + key;
    return trackers.get(cacheKey,
            ignored -> new AttemptTracker(windowMs, maxAttempts, now));
}
```

### SEC-02: Full session bearer token is written to standard output
- **Severity:** Medium
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **Location:** `src/main/java/com/example/auth/Main.java:83-88`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/Main.java:83-88
            if (result.isSuccess()) {
                System.out.println("[SUCCESS] " + result.getUserMessage());
                result.getSession().ifPresent(session -> {
                    System.out.println("Session Token: " + SecurityLogger.maskToken(session.sessionId()));
                    System.out.println("Cookie: " + session.cookieHeader());
                });
```

**Why it is a problem:** Although the first line masks the token, `cookieHeader()` contains the complete `__Host-AuthSession` bearer token and the next line prints it verbatim. Standard output is routinely redirected, captured by job runners, retained in terminal scrollback, or collected as logs. Anyone who obtains the output while the in-memory session remains valid can replay the token and impersonate the user.

**Fix:** Do not print bearer credentials. If an integrating HTTP layer needs to set the cookie, pass the cookie value directly to its response API and expose only a non-sensitive confirmation in the CLI.
```java
if (result.isSuccess()) {
    System.out.println("[SUCCESS] " + result.getUserMessage());
    result.getSession().ifPresent(session ->
            System.out.println("Session created; expires at " + session.expiresAt()));
    return 0;
}
```

### SEC-03: Active-session limit does not prevent unbounded growth
- **Severity:** Medium
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `src/main/java/com/example/auth/SessionManager.java:64-87,115-125`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/SessionManager.java:64-87
    public Session createSession(long userId, String email) {
        evictIfNecessary();

        byte[] randomBytes = new byte[TOKEN_BYTE_LENGTH];
        SECURE_RANDOM.nextBytes(randomBytes);
        String token;
        try {
            token = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        } finally {
            Arrays.fill(randomBytes, (byte) 0);
        }

        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(sessionDurationSeconds);

        // Security best practice: __Host- prefix ensures cookie is restricted to host, requires Secure, and Path=/
        String cookieHeader = String.format(
                "__Host-AuthSession=%s; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=%d",
                token, sessionDurationSeconds
        );

        Session session = new Session(token, userId, email, now, expiresAt, cookieHeader);
        activeSessions.put(token, session);
        return session;
```
```java
// src/main/java/com/example/auth/SessionManager.java:115-125
    private void evictIfNecessary() {
        if (activeSessions.size() > MAX_ACTIVE_SESSIONS) {
            Iterator<Map.Entry<String, Session>> it = activeSessions.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<String, Session> entry = it.next();
                if (entry.getValue().isExpired()) {
                    it.remove();
                }
            }
        }
    }
```

**Why it is a problem:** Cleanup occurs before insertion, triggers only when the map is already greater than 10,000 entries, and removes only expired sessions. If all sessions are younger than one hour, the map continues to grow without limit. A user with valid credentials can repeatedly authenticate—successful authentication resets the rate counters—and consume heap with arbitrarily many live sessions.

**Fix:** Enforce the limit atomically before allocating a new session. Also impose a per-user session limit so one account cannot consume the global allowance. A production service should use a bounded session store with expiration; the following minimal in-process correction fails closed when the global capacity is full.
```java
public synchronized Session createSession(long userId, String email) {
    activeSessions.entrySet().removeIf(entry -> entry.getValue().isExpired());
    if (activeSessions.size() >= MAX_ACTIVE_SESSIONS) {
        throw new IllegalStateException("Session capacity reached");
    }

    Session session = generateSession(userId, email);
    activeSessions.put(session.sessionId(), session);
    return session;
}
```

### SEC-04: PBKDF2-HMAC-SHA-256 work factor is below current guidance
- **Severity:** Medium
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `src/main/java/com/example/auth/PasswordHasher.java:19-22`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/PasswordHasher.java:19-22
    public static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    public static final int DEFAULT_ITERATIONS = 210_000;
    public static final int SALT_BYTE_LENGTH = 16; // 128 bits
    public static final int KEY_BIT_LENGTH = 256;  // 256 bits
```

**Why it is a problem:** The algorithm, salt size, and derived-key length are sound, but 210,000 PBKDF2-HMAC-SHA-256 iterations provide substantially less offline-guessing cost than the current OWASP recommendation of 600,000 iterations. If the password database is stolen, an attacker can test guesses roughly three times faster than at the recommended baseline. See the [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

**Fix:** Benchmark the deployment and raise the work factor to at least the current baseline, or migrate to Argon2id with current recommended parameters. Store the work factor per record, accept legacy hashes during verification, and rehash them after successful login.
```java
public static final int DEFAULT_ITERATIONS = 600_000;

public boolean needsRehash(int storedIterations) {
    return storedIterations < DEFAULT_ITERATIONS;
}
```

### SEC-05: Registration accepts weak and commonly compromised passwords
- **Severity:** Medium
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `src/main/java/com/example/auth/InputValidator.java:17-20,105-110`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/InputValidator.java:17-20
    // Minimum password length for new registrations.
    public static final int MIN_PASSWORD_LENGTH = 8;
    // Bounded maximum password length prevents PBKDF2 CPU/memory exhaustion DoS attacks.
    public static final int MAX_PASSWORD_LENGTH = 128;
```
```java
// src/main/java/com/example/auth/InputValidator.java:105-110
    public static boolean isValidPasswordForCreation(char[] password) {
        if (password == null) {
            return false;
        }
        return password.length >= MIN_PASSWORD_LENGTH && password.length <= MAX_PASSWORD_LENGTH;
    }
```

**Why it is a problem:** There is no MFA in this component, yet any eight-character value—including `password`, `12345678`, or a breached credential—is accepted. Length is the only strength control. Current OWASP authentication guidance treats passwords shorter than 15 characters as weak when MFA is not enabled and recommends blocking common and previously compromised passwords. The existing tests explicitly assert that `12345678` is accepted. See the [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).

**Fix:** Require at least 15 characters for password-only authentication, retain support for long passphrases and all character classes, and reject common/breached passwords using a privacy-preserving or local blocklist check. The checker must not log or retain the plaintext password.
```java
public static final int MIN_PASSWORD_LENGTH = 15;

public static boolean isValidPasswordForCreation(char[] password) {
    return password != null
            && password.length >= MIN_PASSWORD_LENGTH
            && password.length <= MAX_PASSWORD_LENGTH
            && !CompromisedPasswordChecker.isCompromised(password);
}
```

### SEC-06: Fallback password reader silently truncates credentials
- **Severity:** Medium
- **CWE:** CWE-187: Partial String Comparison
- **Location:** `src/main/java/com/example/auth/Main.java:178-194`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/Main.java:178-194
    private static char[] readPasswordDirect(InputStream in) throws IOException {
        char[] buffer = new char[InputValidator.MAX_PASSWORD_LENGTH + 2];
        int len = 0;
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') {
                break;
            }
            if (b != '\r') {
                if (len < InputValidator.MAX_PASSWORD_LENGTH) {
                    buffer[len++] = (char) b;
                }
            }
        }
        char[] password = Arrays.copyOf(buffer, len);
        Arrays.fill(buffer, '\0');
        return password;
    }
```

**Why it is a problem:** After 128 characters, additional input is silently discarded. Validation therefore never sees an overlong password and cannot reject it. Two different passwords that share the same first 128 characters become the same credential during both registration and login, contrary to the validator's stated reject-over-limit behavior. Silent truncation can also mislead users and password managers about the secret actually stored.

**Fix:** Detect overflow, drain the remainder of the line, wipe temporary memory, and reject the input. Never turn an invalid credential into a valid prefix.
```java
private static char[] readPasswordDirect(InputStream in) throws IOException {
    char[] buffer = new char[InputValidator.MAX_PASSWORD_LENGTH];
    int len = 0;
    int b;
    while ((b = in.read()) != -1 && b != '\n') {
        if (b == '\r') {
            continue;
        }
        if (len == buffer.length) {
            while ((b = in.read()) != -1 && b != '\n') { /* drain */ }
            Arrays.fill(buffer, '\0');
            throw new IOException("Password exceeds maximum length");
        }
        buffer[len++] = (char) b;
    }
    char[] password = Arrays.copyOf(buffer, len);
    Arrays.fill(buffer, '\0');
    return password;
}
```

### SEC-07: Password fallback may expose input through terminal echo
- **Severity:** Medium
- **CWE:** CWE-522: Insufficiently Protected Credentials
- **Location:** `src/main/java/com/example/auth/Main.java:150-160`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/Main.java:150-160
    private static char[] readPassword(Console console, String prompt) {
        if (console != null) {
            char[] chars = console.readPassword(prompt);
            return chars != null ? chars : new char[0];
        } else {
            System.out.print(prompt);
            try {
                return readPasswordDirect(System.in);
            } catch (IOException e) {
                return new char[0];
            }
        }
```

**Why it is a problem:** `Console.readPassword` suppresses terminal echo, but the fallback reads raw `System.in` without disabling echo. `System.console()` is commonly null under IDEs, wrappers, containers, and redirected execution. If the fallback is connected to an echoing terminal, the password becomes visible on screen and may be retained by terminal capture. Returning an empty password after an I/O failure also conceals the secure-input failure.

**Fix:** Fail closed when no secure console is available, or use a vetted terminal library that explicitly disables and restores echo. Piped secrets should use a separately designed, documented secret-input channel with restrictive handling.
```java
private static char[] readPassword(Console console, String prompt) {
    if (console == null) {
        throw new IllegalStateException("Secure password input is unavailable");
    }
    char[] chars = console.readPassword(prompt);
    if (chars == null) {
        throw new IllegalStateException("Password input was cancelled");
    }
    return chars;
}
```

### SEC-08: Database permission hardening fails open
- **Severity:** Medium
- **CWE:** CWE-636: Not Failing Securely ('Failing Open')
- **Location:** `src/main/java/com/example/auth/DatabaseManager.java:91-125`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/DatabaseManager.java:91-125
    private static void ensureSecureFilePermissionsIfLocal(String jdbcUrl) {
        if (jdbcUrl.startsWith("jdbc:h2:./") || jdbcUrl.startsWith("jdbc:h2:/")) {
            try {
                // Extract file path from H2 JDBC URL
                String rawPath = jdbcUrl.substring("jdbc:h2:".length());
                int semicolonIdx = rawPath.indexOf(';');
                if (semicolonIdx >= 0) {
                    rawPath = rawPath.substring(0, semicolonIdx);
                }
                Path path = Paths.get(rawPath);
                Path parent = path.getParent();
                if (parent != null) {
                    if (!Files.exists(parent)) {
                        if (supportsPosix()) {
                            Set<PosixFilePermission> dirPerms = PosixFilePermissions.fromString("rwx------");
                            Files.createDirectories(parent, PosixFilePermissions.asFileAttribute(dirPerms));
                        } else {
                            Files.createDirectories(parent);
                        }
                    } else if (supportsPosix()) {
                        Files.setPosixFilePermissions(parent, PosixFilePermissions.fromString("rwx------"));
                    }
                }

                // Restrict database file permissions to owner read/write (0600)
                if (supportsPosix()) {
                    Path dbFile = Paths.get(rawPath + ".mv.db");
                    if (Files.exists(dbFile)) {
                        Files.setPosixFilePermissions(dbFile, PosixFilePermissions.fromString("rw-------"));
                    }
                }
            } catch (IOException e) {
                SecurityLogger.logSystemError("Failed to set secure file permissions for database directory/file", e);
            }
        }
    }
```

**Why it is a problem:** The method treats private permissions as a security control, but an `IOException` is only logged and startup continues. On non-POSIX filesystems it creates the directory and performs no equivalent restriction at all. The database contains password hashes, salts, email addresses, and account status; continuing after permission hardening fails can leave that data readable or modifiable by other local users.

**Fix:** Verify the resulting permissions and abort initialization if the configured local database cannot be protected. For non-POSIX systems, apply and verify an equivalent owner-only ACL or require the operator to provide a securely provisioned path.
```java
} catch (IOException e) {
    throw new IllegalStateException(
            "Refusing to use a local database without verified owner-only permissions", e);
}

if (!supportsPosix()) {
    throw new IllegalStateException(
            "Local database requires an explicitly verified owner-only ACL");
}
```

### SEC-09: Fallback email reader accepts an unbounded line
- **Severity:** Low
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/example/auth/Main.java:164-175`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/Main.java:164-175
    private static String readLineFromStream(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') {
                break;
            }
            if (b != '\r') {
                sb.append((char) b);
            }
        }
        return sb.toString();
    }
```

**Why it is a problem:** The email validator has a 254-character limit, but this fallback allocates the entire line before validation. A very large or unterminated input stream can grow the `StringBuilder` until memory is exhausted. This is Low severity in the current local CLI threat model, but becomes remotely exploitable if the method is reused behind a service or fed by an untrusted automation channel.

**Fix:** Enforce the maximum while reading, drain or close the rejected input, and return an error rather than allocating the complete line.
```java
private static String readLineFromStream(InputStream in, int maxLength) throws IOException {
    StringBuilder sb = new StringBuilder(Math.min(maxLength, 64));
    int b;
    while ((b = in.read()) != -1 && b != '\n') {
        if (b == '\r') {
            continue;
        }
        if (sb.length() == maxLength) {
            throw new IOException("Input exceeds maximum length");
        }
        sb.append((char) b);
    }
    return sb.toString();
}
```

## 6. Verified Controls and Checks With No Finding
- SQL injection: All runtime user lookup, insert, and count operations use constant SQL with `PreparedStatement` parameters in `UserRepository.java:20-27,44-47,99-107,114-121`; no user input is concatenated into SQL. The fixed schema DDL in `DatabaseManager.java:63-80` contains no external data.
- Password hashing primitives: `PasswordHasher.java:19-24,69-83,127-139` uses PBKDF2-HMAC-SHA-256, a 128-bit `SecureRandom` salt, a 256-bit output, constant-time `MessageDigest.isEqual`, and clears derived bytes. Only the work factor was deficient.
- Stored hash metadata validation: `InputValidator.java:143-158` allowlists the algorithm, bounds iterations, requires at least a 16-byte salt, and requires a 32-byte hash before expensive verification.
- Password memory hygiene: Caller password arrays are cleared in `AuthenticationService.java:135-140,182-185`; temporary salt/key arrays and `PBEKeySpec` copies are cleared in `PasswordHasher.java:78-83,130-140,161-165,178-180`.
- Session token generation: `SessionManager.java:23-28,67-74` generates 256 bits with `SecureRandom` and URL-safe Base64 without accepting caller-supplied tokens.
- Cookie attributes: `SessionManager.java:79-83` sets the `__Host-` prefix, `Path=/`, `Secure`, `HttpOnly`, `SameSite=Strict`, and a bounded `Max-Age`.
- Session validation and revocation: `SessionManager.java:94-113` rejects null, blank, unknown, and expired tokens and provides explicit invalidation.
- Account-enumeration messages: `AuthenticationResult.java:21-24,43-53` and `AuthenticationService.java:86-125` use generic external failures for malformed credentials, missing/inactive accounts, and password mismatch.
- Timing resistance: `AuthenticationService.java:86-109` and `PasswordHasher.java:143-165` perform dummy PBKDF2 work for malformed input and missing/inactive users; valid hash comparison is constant-time.
- Authentication rate-limit atomicity: `RateLimiter.java:49-93,108-145` synchronizes each check-and-increment operation and applies both source and source/account limits. The finding concerns storage capacity, not per-key atomicity.
- Registration transaction integrity: `AuthenticationService.java:156-180` disables auto-commit and explicitly commits or rolls back; the database unique constraint in `DatabaseManager.java:64-75` resolves concurrent duplicate registration safely.
- Log-forging defense and PII masking: `SecurityLogger.java:45-68,87-110` masks emails and replaces CR/LF in all attacker-influenced audit fields. Passwords and full session tokens are not written by this logger.
- Dependency review: `pom.xml:19-20,23-37` pins H2 2.2.224 and JUnit 5.10.2. The reviewed code does not expose H2 Console, and H2 2.2.224 is newer than the patched version for the H2 Console JNDI advisory; no directly applicable published advisory was identified for the exercised embedded JDBC path.
- Hardcoded secrets: No operational password, API key, private key, or reusable session secret is present. The dummy password in `PasswordHasher.java:26-40` is used only to normalize failure work and is not an authenticator.
- Dynamic execution and unsafe deserialization: No OS command execution, reflection-based loading, object deserialization, template evaluation, or remote-file loading appears in the application source.
- Error handling: User-facing database and cryptographic errors are generic in `AuthenticationService.java:98-101,173-180` and `Main.java:58-68`; detailed errors are limited to internal logs.
