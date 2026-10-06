# Security Review: Secure User Account Registration & Authentication System (`com.security.auth`)

## 1. Executive Summary

The component is a self-contained Java 17 / Maven CLI application that registers users, authenticates them, and issues server-side session tokens backed by an embedded H2 database. Credential handling is unusually careful for generated code: passwords are PBKDF2-HMAC-SHA512 (210,000 iterations, 256-bit per-user salt, 512-bit output), every SQL statement is parameterised, session tokens are 256-bit `SecureRandom` values stored only as SHA-256 hashes, comparisons use `MessageDigest.isEqual`, failure messages are uniform, and a dummy-hash path equalises login timing for unknown accounts.

The real weaknesses are in the *trust model around the anti-abuse controls* rather than in the cryptography:

- The source IP that drives both rate limiting and session binding is supplied by the caller and silently defaults to `127.0.0.1`, so an attacker who can vary it defeats the brute-force protection and the session IP binding entirely (**SEC-01**).
- Registration performs an unauthenticated 210,000-iteration PBKDF2 computation with no rate limiting of any kind, giving a cheap CPU-exhaustion and account-flooding primitive (**SEC-02**).
- The rate limiter's "check" and "record failure" steps are separate, non-atomic map operations despite the class documentation claiming atomicity, so concurrent requests can far exceed the 5-failure limit (**SEC-03**).
- The H2 file holding all password hashes is opened with an empty password by default and is not encrypted at rest; only POSIX `0600` permissions protect it (**SEC-04**).

Eight findings are reported: two High, three Medium, three Low. No SQL injection, weak hash, hardcoded production secret, or insecure deserialization was found.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/security/auth/Main.java` | Interactive CLI driver for register / login / verify / logout | Reads passwords (no-echo via `Console`, echoing fallback), prints session token and cookie header, wipes `char[]`, top-level exception handler |
| `src/main/java/com/security/auth/service/AuthenticationService.java` | Orchestrates registration, authentication, session lifecycle | Input validation calls, rate-limit check, PBKDF2 verify, dummy-hash timing defence, token issue, session validation and revocation, audit logging |
| `src/main/java/com/security/auth/database/DatabaseManager.java` | JDBC persistence for users, sessions, audit logs | JDBC connection with credentials, DDL/DML via `PreparedStatement`, transactions, POSIX `0600` enforcement on DB files, fail-closed `userExists` |
| `src/main/java/com/security/auth/config/SecurityConfig.java` | Runtime configuration from environment | JDBC URL construction from env-controlled path, DB user/password handling, data-directory path validation, `0700` directory creation, identifier masking |
| `src/main/java/com/security/auth/crypto/PasswordHasher.java` | Password hashing / verification | PBKDF2WithHmacSHA512, 210k iterations, 32-byte salt, 512-bit key, constant-time verify, precomputed dummy hash |
| `src/main/java/com/security/auth/crypto/TokenGenerator.java` | Session token generation and hashing | 256-bit `SecureRandom` token, strict 43-char URL-safe format regex, SHA-256 hash for storage |
| `src/main/java/com/security/auth/crypto/CryptoUtils.java` | Memory wiping and constant-time comparison | `Arrays.fill` wipe, `MessageDigest.isEqual`, SHA-256 helpers |
| `src/main/java/com/security/auth/validation/InputValidator.java` | Whitelist validation of all external input | Email/username/password/IP/UUID validation, length bounds, reserved-name blocklist, ReDoS-safe regexes |
| `src/main/java/com/security/auth/security/RateLimiter.java` | Dual-dimension (source + account) brute-force control | `ConcurrentHashMap` trackers, 5-failure source block for 15 min, progressive account delay, stale-entry eviction |
| `src/main/java/com/security/auth/model/*.java` | Request/result/entity DTOs (`User`, `Session`, `SessionCookie`, requests, results) | `char[]` password storage with `wipe()`, masked `toString()`, generic failure messages, `__Host-` cookie with `Secure`/`HttpOnly`/`SameSite=Strict` |
| `pom.xml` | Build definition | Dependency versions (H2 2.3.232, SLF4J 2.0.16), `-Werror` compilation, shade plugin, no dependency-verification or SCA plugin |

Also present but not source under review: `target/` build artefacts, `data/secure_store/user_auth_db.mv.db`, `README.md`, `result.md`, `prompt.txt`, `return.txt`. Nothing in the source folder was executed, built, or imported; the review is purely static.

## 3. Skills Applied

- `review-code-for-security-vulnerabilities`: router skill — drove file-by-file comprehension, keyword extraction (password storage, KDF, session tokens, rate limiting, SQL, secrets, file permissions, race conditions) and selection of the specialised skills below.
- `performing-cryptographic-audit-of-application`: applied to `PasswordHasher`, `CryptoUtils`, `TokenGenerator` and the JDBC/at-rest story — checked KDF parameters, salt generation, RNG, deprecated algorithms, cipher modes, hardcoded keys and secret sourcing (drove SEC-04).
- `testing-api-authentication-weaknesses`: applied to `AuthenticationService.authenticate`/`validateSession`/`logout`, `TokenGenerator` and `SessionCookie` — token entropy, token validation, session fixation/expiry, credential-stuffing resistance, token leakage (drove SEC-01, SEC-06).
- `performing-api-rate-limiting-bypass`: applied to `RateLimiter` and `InputValidator.validateSourceIp` — tested the limiter against header/IP-spoofing bypass and unrestricted-resource-consumption patterns (drove SEC-01, SEC-02, SEC-07).
- `exploiting-race-condition-vulnerabilities`: applied to `RateLimiter.checkAllowed`/`recordFailure` and the register pre-check/insert pair — TOCTOU analysis of check-then-act sequences (drove SEC-03).
- `exploiting-sql-injection-vulnerabilities`: applied to every statement in `DatabaseManager` and to the JDBC URL built in `SecurityConfig.fromEnvironment` — first-order, second-order and connection-string injection (no finding, see section 6).
- `testing-for-sensitive-data-exposure`: applied to all logging and `toString()` paths, `Main` console output and the on-disk database file (drove SEC-04, SEC-05, SEC-06).
- `implementing-aes-encryption-for-data-at-rest`: applied to the H2 datastore holding password hashes — checked for encryption-at-rest and key management (drove SEC-04).
- Reviewed against general OWASP Top 10 / CWE knowledge, with no library skill matching directly: POSIX file-permission handling in `SecurityConfig.ensurePrivateDirectory` / `DatabaseManager.enforceDbFilePermissions` (CWE-276/CWE-732); error-handling and exception-propagation paths including the unwiped-credential path (CWE-248/CWE-212, SEC-08); unbounded in-memory tracker growth (CWE-400, SEC-07); CLI password-entry masking (CWE-549, SEC-05); dependency currency in `pom.xml` (CWE-1104).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Rate limiting and session binding trust a caller-supplied source IP | High | CWE-807 | `src/main/java/com/security/auth/validation/InputValidator.java:166` |
| SEC-02 | Registration performs unauthenticated 210k-iteration PBKDF2 with no rate limit | High | CWE-770 | `src/main/java/com/security/auth/service/AuthenticationService.java:60` |
| SEC-03 | Rate-limiter check and failure record are not atomic (TOCTOU) | Medium | CWE-367 | `src/main/java/com/security/auth/security/RateLimiter.java:57` |
| SEC-04 | Password-hash database opened with empty password and stored unencrypted | Medium | CWE-1188 | `src/main/java/com/security/auth/config/SecurityConfig.java:71` |
| SEC-05 | Password echoed to the terminal when `System.console()` is unavailable | Medium | CWE-549 | `src/main/java/com/security/auth/Main.java:177` |
| SEC-06 | Raw session token written to standard output | Low | CWE-532 | `src/main/java/com/security/auth/Main.java:126` |
| SEC-07 | Blocked-source trackers can be evicted by flooding, clearing active blocks | Low | CWE-400 | `src/main/java/com/security/auth/security/RateLimiter.java:140` |
| SEC-08 | Invalid source IP throws before the wipe guard, leaving the password in memory and killing the process | Low | CWE-248 | `src/main/java/com/security/auth/service/AuthenticationService.java:62` |

## 5. Detailed Findings

### SEC-01: Rate limiting and session binding trust a caller-supplied source IP

- **Severity:** High
- **CWE:** CWE-807: Reliance on Untrusted Inputs in a Security Decision
- **Location:** `src/main/java/com/security/auth/validation/InputValidator.java:166-181`, used at `src/main/java/com/security/auth/service/AuthenticationService.java:140,156,222` and `src/main/java/com/security/auth/service/AuthenticationService.java:280`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/validation/InputValidator.java:166-181
    public static String validateSourceIp(String sourceIp) {
        if (sourceIp == null || sourceIp.isBlank()) {
            return "127.0.0.1"; // Default safe localhost source
        }
        String trimmed = sourceIp.trim();
        if (trimmed.length() > 45) {
            throw new IllegalArgumentException("Source IP exceeds maximum allowable length");
        }
        if ("localhost".equalsIgnoreCase(trimmed) || "127.0.0.1".equals(trimmed) || "::1".equals(trimmed)) {
            return trimmed;
        }
        if (IPV4_PATTERN.matcher(trimmed).matches() || IPV6_PATTERN.matcher(trimmed).matches()) {
            return trimmed;
        }
        throw new IllegalArgumentException("Invalid client source IP format");
    }
```
```java
// src/main/java/com/security/auth/service/AuthenticationService.java:140,156
        String sanitizedSourceIp = InputValidator.validateSourceIp(request.getSourceIp());
        ...
            RateLimiter.CheckResult checkResult = rateLimiter.checkAllowed(sanitizedSourceIp, normalizedIdentifier);
```

**Why it is a problem:** `validateSourceIp` only checks *syntax*; it never establishes *authenticity*. The value originates from `AuthenticationRequest.getSourceIp()`, i.e. from whatever the caller passed in — in any realistic deployment of this service that is an `X-Forwarded-For`-style header or an RPC field, both attacker-controlled. Two security decisions depend on it:

1. `RateLimiter.checkAllowed`/`recordFailure` key the source dimension on this string (`RateLimiter.java:61,91`). An attacker who increments the last octet on every request never accumulates five failures against any single key, so the 5-failures-per-15-minutes block never engages. The account dimension only ever yields a delay capped at 5 s (`RateLimiter.java:45-46`), never a denial, so unlimited password guessing against one account is possible.
2. `validateSession` enforces session binding with `session.getSourceIp().equals(sanitizedSourceIp)` (`AuthenticationService.java:280`). An attacker holding a stolen token simply sends the IP the session was created with — which is also what the audit log records — so the "replay from other IPs" control is cosmetic. Worse, because any syntactically valid value is accepted, an attacker who knows a victim's token *format* can also force deletion of a victim's session by presenting the token with a mismatched IP (`AuthenticationService.java:284` deletes the session on mismatch), turning the control into a session-destruction primitive.

The silent `127.0.0.1` default on blank input compounds this: all callers that omit the field collapse onto one rate-limit bucket, and `Main.java:101,121,145` hardcodes `"127.0.0.1"` for every operation.

**Fix:** Take the peer address from the transport layer, not from the request body, and pass it as a distinct trusted parameter. If a reverse proxy is in front, parse `X-Forwarded-For` only when the immediate peer is an allow-listed proxy, and take the rightmost untrusted hop. Fail closed (reject) rather than defaulting to localhost, and never let a caller-asserted string reach the limiter. Make session binding advisory (log and re-authenticate) rather than destructive, so a forged mismatch cannot delete a victim's session.

```java
// InputValidator.java - require the caller to prove where the value came from
    /**
     * Validates a source IP that was observed at the transport layer.
     * Callers MUST pass the socket peer address (or the hop immediately
     * preceding a trusted proxy), never a client-asserted header value.
     */
    public static String validateSourceIp(String sourceIp) {
        if (sourceIp == null || sourceIp.isBlank()) {
            // Fail closed: an unknown origin must not share a bucket with localhost.
            throw new IllegalArgumentException("Source IP is required");
        }
        String trimmed = sourceIp.trim();
        if (trimmed.length() > 45) {
            throw new IllegalArgumentException("Source IP exceeds maximum allowable length");
        }
        if (IPV4_PATTERN.matcher(trimmed).matches() || IPV6_PATTERN.matcher(trimmed).matches()) {
            return trimmed;
        }
        throw new IllegalArgumentException("Invalid client source IP format");
    }

    /** Resolves the effective client IP, honouring XFF only behind trusted proxies. */
    public static String resolveClientIp(String socketPeerAddress,
                                         String forwardedForHeader,
                                         Set<String> trustedProxies) {
        String peer = validateSourceIp(socketPeerAddress);
        if (!trustedProxies.contains(peer) || forwardedForHeader == null) {
            return peer;
        }
        String[] hops = forwardedForHeader.split(",");
        for (int i = hops.length - 1; i >= 0; i--) {
            String hop = hops[i].trim();
            if (!trustedProxies.contains(hop)) {
                return validateSourceIp(hop);
            }
        }
        return peer;
    }
```
```java
// AuthenticationService.java - trusted peer address supplied by the transport, not the request
    public AuthenticationResult authenticate(AuthenticationRequest request, String trustedPeerIp) {
        Objects.requireNonNull(request, "Authentication request must not be null");
        String sanitizedSourceIp = InputValidator.validateSourceIp(trustedPeerIp);
        ...
    }

    // validateSession: treat an IP change as a signal, not a destruction trigger
        if (!session.getSourceIp().equals(sanitizedSourceIp)) {
            log.warn("Session source IP changed for sessionId={}; requiring re-authentication", session.getId());
            databaseManager.recordAuditLog("SESSION_IP_MISMATCH",
                    SecurityConfig.maskIdentifier(session.getUserId()), sanitizedSourceIp, false);
            return Optional.empty(); // do NOT delete: a forged IP must not revoke a victim's session
        }
```

### SEC-02: Registration performs unauthenticated 210k-iteration PBKDF2 with no rate limit

- **Severity:** High
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `src/main/java/com/security/auth/service/AuthenticationService.java:60-124` (hash at line 84)

**Vulnerable code:**
```java
// src/main/java/com/security/auth/service/AuthenticationService.java:78-92
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
```

**Why it is a problem:** `register()` never consults `rateLimiter` — the field exists (`AuthenticationService.java:38,45`) but is only used by `authenticate()`. Registration is by definition unauthenticated, and the anti-enumeration design deliberately performs the full 210,000-iteration PBKDF2-HMAC-SHA512 computation (`SecurityConfig.java:26` default, `PasswordHasher.java:19`) *even for requests that are going to be rejected as duplicates*. That is roughly 100–300 ms of dedicated CPU per request on commodity hardware, available to any anonymous caller for the cost of one request. A few dozen concurrent registration attempts saturate every core and starve the login path, which needs the same CPU to verify legitimate passwords — a self-inflicted amplification factor of several thousand versus the attacker's cost.

Independently, the absence of any throttle permits unlimited automated account creation (resource/namespace exhaustion, and each successful registration writes a row plus an audit row). Every failed attempt also writes an audit row via `recordAuditLog` (`AuthenticationService.java:89,111`), so the same flood grows the database without bound.

**Fix:** Apply the existing per-source rate limiter to registration before any expensive work, bound concurrent KDF executions with a semaphore sized to the available cores, and short-circuit the hash when the request is already known to be a duplicate *only* behind the rate limit (or, better, keep constant work but let the limiter cap how often that work can be requested).

```java
// AuthenticationService.java
    // Bound total concurrent KDF work so the login path cannot be starved.
    private final Semaphore kdfPermits =
            new Semaphore(Math.max(2, Runtime.getRuntime().availableProcessors()));

    public RegistrationResult register(RegistrationRequest request, String trustedPeerIp) {
        Objects.requireNonNull(request, "Registration request must not be null");
        String sanitizedSourceIp = InputValidator.validateSourceIp(trustedPeerIp);
        try {
            // Throttle BEFORE any PBKDF2 work: registration is unauthenticated.
            RateLimiter.CheckResult gate = rateLimiter.checkAllowed(sanitizedSourceIp, "@register");
            if (!gate.allowed()) {
                databaseManager.recordAuditLog("REGISTRATION_RATE_LIMITED", "[N/A]", sanitizedSourceIp, false);
                return RegistrationResult.failure();
            }

            String validatedEmail;
            String validatedUsername;
            try {
                validatedEmail = InputValidator.validateAndNormalizeEmail(request.getEmail());
                validatedUsername = InputValidator.validateUsername(request.getUsername());
                InputValidator.validatePassword(request.getPassword());
            } catch (IllegalArgumentException e) {
                rateLimiter.recordFailure(sanitizedSourceIp, "@register");
                log.warn("Registration rejected due to invalid input format: reason={}", e.getMessage());
                return RegistrationResult.failure();
            }

            boolean alreadyExists = databaseManager.userExists(validatedUsername, validatedEmail);

            PasswordHasher.HashedPassword hashedPassword;
            if (!kdfPermits.tryAcquire(2, TimeUnit.SECONDS)) {
                log.warn("Registration shed: KDF capacity exhausted");
                return RegistrationResult.failure();
            }
            try {
                hashedPassword = passwordHasher.hash(request.getPassword());
            } finally {
                kdfPermits.release();
            }

            if (alreadyExists) {
                rateLimiter.recordFailure(sanitizedSourceIp, "@register");
                databaseManager.recordAuditLog("REGISTRATION_DUPLICATE",
                        SecurityConfig.maskIdentifier(validatedUsername), sanitizedSourceIp, false);
                return RegistrationResult.failure();
            }
            // ... unchanged insert path ...
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return RegistrationResult.failure();
        } finally {
            request.wipe();
        }
    }
```

### SEC-03: Rate-limiter check and failure record are not atomic (TOCTOU)

- **Severity:** Medium
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `src/main/java/com/security/auth/security/RateLimiter.java:57-80` and `src/main/java/com/security/auth/security/RateLimiter.java:89-116`, invoked from `src/main/java/com/security/auth/service/AuthenticationService.java:156,181,198`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/security/RateLimiter.java:57-66
    public CheckResult checkAllowed(String sourceIp, String accountIdentifier) {
        Instant now = Instant.now();

        // 1. Check Source IP: If source is blocked, reject immediately.
        AttemptTracker sourceTracker = sourceTrackers.get(sourceIp);
        if (sourceTracker != null && sourceTracker.isBlocked(now)) {
            log.warn("Blocked request from source IP due to rate limit: source={}", sourceIp);
            return new CheckResult(false, 0, "Too many failed attempts from this source. Please try again later.");
        }
```

**Why it is a problem:** The class Javadoc claims it "Implements Rule 7: … make the check and the action atomic" (`RateLimiter.java:18-19`), but `checkAllowed` is a plain read (`sourceTrackers.get`) that is separated from the corresponding `recordFailure` write by the entire authentication path — a database lookup plus a ~200 ms PBKDF2 verification (`AuthenticationService.java:173-198`). Any number of requests can pass `checkAllowed` during that window before the first failure is ever recorded. With N concurrent requests the attacker gets N guesses regardless of `MAX_SOURCE_FAILURES = 5`; the single-packet concurrency technique makes N in the hundreds trivial. There is no reservation, no in-flight counter, and no compare-and-set linking the decision to the subsequent state change.

The same pattern applies to the account dimension: the progressive delay is computed from a snapshot (`RateLimiter.java:69-73`) that all concurrent requests read identically, so they all receive the same (often zero) delay.

**Fix:** Make the decision itself a mutating, atomic operation. Increment an in-flight/attempt counter inside a single `ConcurrentHashMap.compute` and reject when the combined committed-failure plus in-flight count exceeds the limit; release the reservation on completion.

```java
// RateLimiter.java
    private record AttemptTracker(int failureCount, int inFlight, Instant windowStart, Instant blockedUntil) {
        boolean isBlocked(Instant now) { return blockedUntil != null && now.isBefore(blockedUntil); }
        boolean isWindowExpired(Instant now, Duration window) {
            return windowStart != null && Duration.between(windowStart, now).compareTo(window) > 0;
        }
        int consumed() { return failureCount + inFlight; }
    }

    /** Atomically reserves an attempt slot; the caller MUST call releaseAttempt() when done. */
    public CheckResult checkAllowed(String sourceIp, String accountIdentifier) {
        Instant now = Instant.now();
        AttemptTracker updated = sourceTrackers.compute(sourceIp, (key, current) -> {
            if (current == null || (!current.isBlocked(now) && current.isWindowExpired(now, SOURCE_WINDOW))) {
                return new AttemptTracker(0, 1, now, null);
            }
            if (current.isBlocked(now) || current.consumed() >= MAX_SOURCE_FAILURES) {
                return current; // no slot granted
            }
            return new AttemptTracker(current.failureCount(), current.inFlight() + 1,
                    current.windowStart(), current.blockedUntil());
        });
        if (updated.isBlocked(now) || updated.inFlight() == 0) {
            log.warn("Blocked request from source IP due to rate limit: source={}", sourceIp);
            return new CheckResult(false, 0, "Too many failed attempts from this source. Please try again later.");
        }
        long delayMs = computeAccountDelay(accountIdentifier, now);
        return new CheckResult(true, delayMs, null);
    }

    /** Must be called in a finally block for every granted attempt. */
    public void releaseAttempt(String sourceIp) {
        sourceTrackers.computeIfPresent(sourceIp, (key, current) ->
                new AttemptTracker(current.failureCount(), Math.max(0, current.inFlight() - 1),
                        current.windowStart(), current.blockedUntil()));
    }
```

### SEC-04: Password-hash database opened with empty password and stored unencrypted

- **Severity:** Medium
- **CWE:** CWE-1188: Initialization of a Resource with an Insecure Default (with CWE-311: Missing Encryption of Sensitive Data)
- **Location:** `src/main/java/com/security/auth/config/SecurityConfig.java:71,75`, `src/main/java/com/security/auth/config/SecurityConfig.java:42`, `src/main/java/com/security/auth/database/DatabaseManager.java:53`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/config/SecurityConfig.java:70-75
        String dbPassEnv = System.getenv("APP_DB_PASSWORD");
        char[] dbPassword = (dbPassEnv != null) ? dbPassEnv.toCharArray() : new char[0];

        // Format embedded H2 database URL pointing inside private directory
        String dbPath = path.resolve("user_auth_db").toString();
        String dbUrl = "jdbc:h2:" + dbPath + ";DB_CLOSE_DELAY=-1;NON_KEYWORDS=USER";
```
```java
// src/main/java/com/security/auth/database/DatabaseManager.java:50-58
    public Connection getConnection() throws SQLException {
        char[] pass = config.getDbPassword();
        try {
            return DriverManager.getConnection(config.getDbUrl(), config.getDbUser(), new String(pass));
        } finally {
            // pass is a cloned copy from config, clear it after connection string creation
            java.util.Arrays.fill(pass, '\0');
        }
    }
```

**Why it is a problem:** If `APP_DB_PASSWORD` is unset — the out-of-the-box state, and the state of the committed `data/secure_store/user_auth_db.mv.db` in this folder — the H2 database is created and opened with user `sa` and an *empty* password, and the URL contains no `CIPHER=AES`. The `.mv.db` file therefore contains every user's email, username, PBKDF2 salt and password hash in a form any copy of the H2 jar can open with two keystrokes. The only protection is the POSIX `0600`/`0700` enforcement in `DatabaseManager.enforceDbFilePermissions` (`DatabaseManager.java:129-154`) and `SecurityConfig.ensurePrivateDirectory` (`SecurityConfig.java:131-170`), which is defeated by anything that moves the file off the host: a backup, a container image layer, a volume snapshot, a misdirected `scp`, or a non-POSIX filesystem where the code falls back to best-effort `File.setReadable` flags. PBKDF2 at 210k iterations slows offline cracking but does not stop it for weak passwords, and the salts are right there.

Secondarily, `new String(pass)` at line 53 defeats the `char[]` discipline the rest of the codebase maintains: the DB password becomes an immutable, un-wipeable `String` on the heap on every single connection, and `getConnection()` is called once per query (no pooling).

**Fix:** Require a database password (fail closed if absent) and enable H2's file encryption, which uses a two-part `"<filePassword> <userPassword>"` credential. Source both from the environment or a secrets manager, and avoid materialising them as `String`s where the driver permits `Properties` with char data.

```java
// SecurityConfig.java
        String dbPassEnv = System.getenv("APP_DB_PASSWORD");
        if (dbPassEnv == null || dbPassEnv.isBlank()) {
            throw new SecurityException("APP_DB_PASSWORD must be set; refusing to open the credential store unprotected");
        }
        String filePassEnv = System.getenv("APP_DB_FILE_PASSWORD");
        if (filePassEnv == null || filePassEnv.isBlank()) {
            throw new SecurityException("APP_DB_FILE_PASSWORD must be set; refusing to store password hashes unencrypted");
        }
        if (filePassEnv.indexOf(' ') >= 0 || dbPassEnv.indexOf(' ') >= 0) {
            throw new SecurityException("Database passwords must not contain spaces (H2 credential separator)");
        }
        // H2 expects "<filePassword> <userPassword>" as the connection password when CIPHER is set.
        char[] dbPassword = (filePassEnv + " " + dbPassEnv).toCharArray();

        String dbPath = path.resolve("user_auth_db").toString();
        String dbUrl = "jdbc:h2:" + dbPath + ";CIPHER=AES;DB_CLOSE_DELAY=-1;NON_KEYWORDS=USER";
```
```java
// DatabaseManager.java - keep the secret out of the String pool and reuse connections
    public Connection getConnection() throws SQLException {
        char[] pass = config.getDbPassword();
        try {
            Properties props = new Properties();
            props.setProperty("user", config.getDbUser());
            props.put("password", pass); // H2 accepts char[] here; not interned as a String
            return DriverManager.getConnection(config.getDbUrl(), props);
        } finally {
            java.util.Arrays.fill(pass, '\0');
        }
    }
```

### SEC-05: Password echoed to the terminal when `System.console()` is unavailable

- **Severity:** Medium
- **CWE:** CWE-549: Missing Password Field Masking
- **Location:** `src/main/java/com/security/auth/Main.java:177-185`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/Main.java:177-185
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

**Why it is a problem:** The method is named `readPasswordSecurely` and the class Javadoc promises "Passwords are read securely without echo" (`Main.java:28`), but `System.console()` returns `null` whenever stdin or stdout is not an interactive TTY — running under an IDE, under `nohup`, inside most CI runners, inside a Docker container started without `-it`, or any time output is piped. In exactly those cases the code silently falls back to `BufferedReader.readLine()`, which does nothing to suppress terminal echo: the password is displayed on screen (shoulder-surfing, screen sharing, screen recording) and, when the session is piped or logged, is captured verbatim in the transcript. The fallback is also where the password additionally becomes an immutable `String` (line 182) that cannot be wiped, so it survives on the heap until GC regardless of the `CryptoUtils.wipe` calls at `Main.java:108,133`.

The failure is silent — the user receives no indication that the "secure" entry path was not used.

**Fix:** Refuse to accept a password when no console is available, unless the operator explicitly opts in to a non-interactive mode (and then read from a file descriptor or environment-provided secret, not from an echoing terminal). Never build a `String`.

```java
// Main.java
    private static char[] readPasswordSecurely(BufferedReader reader, Console console) throws IOException {
        if (console != null) {
            char[] pwd = console.readPassword();
            return (pwd != null) ? pwd : new char[0];
        }
        // No TTY: echo cannot be suppressed. Fail loudly rather than silently exposing the password.
        if (!Boolean.getBoolean("auth.allowInsecurePasswordInput")) {
            throw new IllegalStateException(
                    "No interactive console available; refusing to read a password with terminal echo enabled. "
                  + "Run on a TTY, or set -Dauth.allowInsecurePasswordInput=true to override in a test harness.");
        }
        log.warn("Reading password without echo suppression (explicitly overridden)");
        // Read into a char[] directly so no immutable String is created.
        StringBuilder sink = new StringBuilder();
        int c;
        while ((c = reader.read()) != -1 && c != '\n' && c != '\r') {
            sink.append((char) c);
        }
        char[] pwd = new char[sink.length()];
        sink.getChars(0, sink.length(), pwd, 0);
        sink.setLength(0);
        return pwd;
    }
```

### SEC-06: Raw session token written to standard output

- **Severity:** Low
- **CWE:** CWE-532: Insertion of Sensitive Information into Log File
- **Location:** `src/main/java/com/security/auth/Main.java:126-127`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/Main.java:126-127
                System.out.println("[Session Token] " + result.getSessionToken());
                System.out.println("[Set-Cookie]    " + result.getSessionCookie().toHeaderValue());
```

**Why it is a problem:** The raw 256-bit bearer token — the only thing required to assume the user's session for the next 30 minutes — is printed in clear text to stdout, and `SessionCookie.toHeaderValue()` (`SessionCookie.java:59-68`) prints it a second time inside the full `Set-Cookie` string. Everywhere else in the codebase this value is deliberately protected: it is stored only as a SHA-256 hash (`TokenGenerator.java:45-50`), and both `AuthenticationResult.toString()` (`AuthenticationResult.java:64`) and `SessionCookie.toString()` (`SessionCookie.java:71-74`) render it as `[PROTECTED]`. Printing it to stdout bypasses all of that: the token lands in terminal scrollback, in `script`/`tee` transcripts, in container stdout collected by Docker/Kubernetes log drivers, and in CI job logs that are typically retained and broadly readable. It is a demo CLI, so the exposure is limited — but the same `AuthenticationResult.getSessionToken()` accessor is the one a real front end would use, and the pattern propagates.

**Fix:** Never render the raw token. Show a non-reversible reference (the token hash prefix or the session id) for support purposes, and if the token must be handed to the user, write it only to the TTY via `Console`, not to stdout.

```java
// Main.java
            if (result.isSuccess()) {
                // Do not print the bearer token: stdout is captured by shells, CI and log drivers.
                System.out.println("[Session]       established; token delivered via Set-Cookie only");
                System.out.println("[Session Ref]   " + result.getSessionCookie().toString()); // value masked
                System.out.println("[User Profile]  ID=" + result.getUser().getId() +
                        ", Username=" + result.getUser().getUsername() +
                        ", Email=" + SecurityConfig.maskIdentifier(result.getUser().getEmail()));
            }
```

### SEC-07: Blocked-source trackers can be evicted by flooding, clearing active blocks

- **Severity:** Low
- **CWE:** CWE-400: Uncontrolled Resource Consumption (leading to rate-limit state loss)
- **Location:** `src/main/java/com/security/auth/security/RateLimiter.java:135-158`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/security/RateLimiter.java:136-147
        if (sourceTrackers.size() > 500) {
            sourceTrackers.entrySet().removeIf(entry ->
                    !entry.getValue().isBlocked(now) && entry.getValue().isWindowExpired(now, SOURCE_WINDOW));
        }
        if (sourceTrackers.size() > MAX_TRACKER_ENTRIES) {
            // Evict oldest entries to prevent memory exhaustion
            sourceTrackers.entrySet().stream()
                    .sorted((e1, e2) -> e1.getValue().windowStart().compareTo(e2.getValue().windowStart()))
                    .limit(sourceTrackers.size() - MAX_TRACKER_ENTRIES + 100)
                    .forEach(e -> sourceTrackers.remove(e.getKey()));
        }
```

**Why it is a problem:** The first cleanup pass correctly preserves blocked entries (`!entry.getValue().isBlocked(now)`), but the overflow eviction at line 140 sorts purely by `windowStart` and deletes the oldest entries **including ones with an active `blockedUntil`**. A blocked source is by construction an *old* entry — its window started at least far enough back to accumulate five failures, and the block lasts 15 minutes while the window is only 5. So blocked entries sort to the front of the eviction list. An attacker who first burns five failures to get blocked, then floods the limiter with >10,000 distinct source keys (trivially, given SEC-01 makes the key attacker-chosen), causes their own block to be evicted and resumes guessing immediately. The same holds for `accountTrackers` at lines 152-157.

The eviction is also O(n log n) under a `ConcurrentHashMap` iteration performed inline on the request thread inside `recordFailure` (`RateLimiter.java:116`), so the flood additionally costs the server a full sort per failed login. Finally, all state is in-process only: a restart clears every block.

**Fix:** Evict only entries that are not currently blocked, prefer a bounded LRU/`Caffeine`-style cache with per-entry TTL keyed to the block duration, and move cleanup off the request path. For multi-instance deployments, persist limiter state in a shared store so blocks survive restarts and are not per-node.

```java
// RateLimiter.java
    private void cleanupStaleEntries(Instant now) {
        purge(sourceTrackers, now, SOURCE_WINDOW);
        purge(accountTrackers, now, ACCOUNT_WINDOW);
    }

    private static void purge(ConcurrentHashMap<String, AttemptTracker> trackers,
                              Instant now, Duration window) {
        if (trackers.size() > 500) {
            trackers.entrySet().removeIf(e ->
                    !e.getValue().isBlocked(now) && e.getValue().isWindowExpired(now, window));
        }
        if (trackers.size() > MAX_TRACKER_ENTRIES) {
            // Never evict an active block: that would hand the attacker a reset switch.
            trackers.entrySet().stream()
                    .filter(e -> !e.getValue().isBlocked(now))
                    .sorted(Comparator.comparing(e -> e.getValue().windowStart()))
                    .limit(Math.max(0, trackers.size() - MAX_TRACKER_ENTRIES + 100))
                    .map(Map.Entry::getKey)
                    .forEach(trackers::remove);
        }
    }
```

### SEC-08: Invalid source IP throws before the wipe guard, leaving the password in memory and killing the process

- **Severity:** Low
- **CWE:** CWE-248: Uncaught Exception (with CWE-212: Improper Removal of Sensitive Information Before Storage or Transfer)
- **Location:** `src/main/java/com/security/auth/service/AuthenticationService.java:62` and `src/main/java/com/security/auth/service/AuthenticationService.java:140`; propagates to `src/main/java/com/security/auth/Main.java:71-75`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/service/AuthenticationService.java:60-64
    public RegistrationResult register(RegistrationRequest request, String sourceIp) {
        Objects.requireNonNull(request, "Registration request must not be null");
        String sanitizedSourceIp = InputValidator.validateSourceIp(sourceIp);

        try {
```

**Why it is a problem:** Two defects share this line. First, `validateSourceIp` throws `IllegalArgumentException` for any malformed IP (`InputValidator.java:172,180`) and the call sits *outside* the `try { … } finally { request.wipe(); }` block — so on that path the cloned password `char[]` held by `RegistrationRequest` (`RegistrationRequest.java:20`) is never zeroed and lingers on the heap, defeating the memory-hygiene property the class exists to provide. `authenticate()` has the identical ordering bug at line 140. Second, neither `AuthenticationService` nor the `Main` handlers catch it, so the exception unwinds to the catch-all at `Main.java:71`, which logs and calls `System.exit(1)` — a single malformed source IP terminates the whole process. In a service deployment, a validation failure on untrusted input must produce a 4xx, never a process exit.

**Fix:** Move the validation inside the `try` so the `finally` wipe always runs, and convert the validation failure into the ordinary generic-failure result rather than letting it escape. Remove the process-terminating catch-all from the per-request path.

```java
// AuthenticationService.java
    public RegistrationResult register(RegistrationRequest request, String sourceIp) {
        Objects.requireNonNull(request, "Registration request must not be null");
        try {
            String sanitizedSourceIp;
            try {
                sanitizedSourceIp = InputValidator.validateSourceIp(sourceIp);
            } catch (IllegalArgumentException e) {
                log.warn("Registration rejected: invalid source IP");
                return RegistrationResult.failure();
            }
            // ... remainder unchanged ...
        } finally {
            // Now reached on every path, including invalid-source-IP rejection.
            request.wipe();
        }
    }
```

## 6. Verified Controls and Checks With No Finding

- **SQL injection (CWE-89):** every statement in `DatabaseManager` is a `PreparedStatement` with `setString`/`setInt`/`setTimestamp`/`setBoolean` bind parameters and no string concatenation of user data — `insertUser` (`DatabaseManager.java:164-176`), `userExists` (`:202-206`), `findUserByIdentifier` (`:224-228`), `findUserById` (`:256-259`), `insertSession` (`:284-295`), `findSessionByTokenHash` (`:315-318`), `updateSessionActivity` (`:343-348`), `deleteSessionByTokenHash` (`:359-362`), `recordAuditLog` (`:374-383`). DDL strings are static literals. Checked for second-order injection: values read back from the database are only ever re-bound as parameters, never concatenated.
- **JDBC connection-string injection:** the env-controlled `APP_DATA_DIR` reaches the H2 URL at `SecurityConfig.java:75`, but `validateDirectoryPath` (`SecurityConfig.java:105-126`) rejects `;`, `"`, `'`, NUL, CR and LF before use, blocking injection of extra H2 settings such as `INIT=RUNSCRIPT`. The path is also `toAbsolutePath().normalize()`d (`:62`), and `/tmp`, `/var/tmp` and `/dev/shm` are refused (`:107-109`).
- **Password storage (CWE-916/CWE-759/CWE-760):** PBKDF2WithHmacSHA512 at 210,000 iterations (`PasswordHasher.java:18-19`), meeting the OWASP 2023 guidance of ≥210,000 for SHA-512; a fresh 32-byte `SecureRandom` salt per password (`:92-93`); 512-bit derived key (`:21`); per-user salt and iteration count persisted and used on verify (`AuthenticationService.java:190-195`), so parameters can be upgraded. The constructor refuses fewer than 100,000 iterations (`:35-37`) and `SecurityConfig` clamps the env override to 100,000–5,000,000 (`SecurityConfig.java:82`). No MD5, SHA-1, DES, 3DES, RC4, or ECB-mode usage anywhere in the codebase.
- **Constant-time comparison (CWE-208):** password verification uses `CryptoUtils.constantTimeEquals` → `MessageDigest.isEqual` (`CryptoUtils.java:54`, `PasswordHasher.java:160`), which is the non-short-circuiting JDK implementation.
- **User-enumeration resistance (CWE-204/CWE-203):** login against an unknown account still performs a full PBKDF2 computation via `verifyDummy` (`PasswordHasher.java:179-182`, called at `AuthenticationService.java:178`); registration hashes before branching on existence (`AuthenticationService.java:84`); all authentication failures return the single `GENERIC_FAILURE_MESSAGE` (`AuthenticationResult.java:19,41`) and all registration failures return `RegistrationResult.GENERIC_FAILURE_MESSAGE` (`RegistrationResult.java:11-12`). Residual nuance: `verifyDummy` always uses the *configured* iteration count, so a stored user whose iteration count differs would still be distinguishable by timing — not currently reachable, since all rows are written with the same configured value.
- **Session token entropy and handling (CWE-330/CWE-340/CWE-384):** tokens are 32 bytes from `SecureRandom` (`TokenGenerator.java:14,28-32`), never caller-specified; stored only as a SHA-256 hash (`TokenGenerator.java:45-50`, `DatabaseManager.java:87` `token_hash … UNIQUE`); format is strictly validated before any hashing or lookup (`TokenGenerator.java:58-63`, enforced at `AuthenticationService.java:257,308`). A pre-image attack on the stored hash is infeasible given 256 bits of input entropy, so plain SHA-256 is appropriate here. A fresh token is minted on every successful authentication (`AuthenticationService.java:208`), so there is no session fixation.
- **Session lifecycle:** absolute expiry checked (`AuthenticationService.java:273`), inactivity timeout checked (`:289-294`), sliding renewal written back (`:297-298`), expired sessions deleted server-side (`:275`), logout deletes by token hash (`:307-313`). All checks fail closed, returning `Optional.empty()`.
- **Cookie attributes (CWE-1004/CWE-614/CWE-1275):** `SessionCookie` hardcodes `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/` and the `__Host-` name prefix (`SessionCookie.java:11,22-25,59-68`) with no setters — the attributes cannot be downgraded.
- **Input validation (CWE-20):** whitelist regexes for username (`InputValidator.java:29`) and email (`:24-26`), explicit length bounds on email (5–254), username (3–32) and password (12–128, `:14-21`), control-character and non-ASCII rejection (`:66-71`, `:138-141`), consecutive/leading/trailing-dot rejection (`:73-83`), reserved-username blocklist (`:39-42`), complexity requirements (`:153-157`). Password length is bounded at 128 to cap KDF input cost.
- **ReDoS (CWE-1333):** all five patterns were examined for catastrophic backtracking. `EMAIL_PATTERN`'s nested group `([A-Za-z0-9]+(-[A-Za-z0-9]+)*\.)+` has disjoint character classes at each alternation point (`-` vs alphanumeric vs `.`), so no ambiguous decomposition exists; combined with the 254-character input cap, worst-case matching is linear. `IPV4_PATTERN`, `IPV6_PATTERN`, `USERNAME_PATTERN` and the UUID pattern are anchored and bounded.
- **Credential memory hygiene (CWE-316):** passwords travel as `char[]` and are never converted to `String` on the primary path; `PBEKeySpec.clearPassword()` plus `CryptoUtils.wipe` of salt, raw hash and computed hash in `finally` blocks (`PasswordHasher.java:120-123,163-168`); request objects implement `AutoCloseable` with `wipe()` (`RegistrationRequest.java:38-45`, `AuthenticationRequest.java:90-97`); `Main` wipes in `finally` (`Main.java:108,133`). Exceptions are SEC-05 and SEC-08 above, and the non-cloning `getPassword()` accessors (`RegistrationRequest.java:31`, `AuthenticationRequest.java:82`) which expose the internal array — benign in current usage since every caller treats it read-only.
- **Secrets in source (CWE-798):** no production credentials, API keys or encryption keys are embedded. The DB user and password come from `APP_DB_USER`/`APP_DB_PASSWORD` (`SecurityConfig.java:65-71`). The literal `"DUMMY_INITIALIZATION_SECRET_987#%*"` at `PasswordHasher.java:48` is not a secret: it is hashed once at startup against a random salt purely to produce a timing decoy, and knowing it grants nothing.
- **Sensitive data in logs (CWE-532):** no password, salt, hash or raw token is logged. Identifiers are passed through `SecurityConfig.maskIdentifier` at every log and audit call site (`AuthenticationService.java:88,110,117,159,182,199,234`), and `toString()` on `User`, `Session`, `AuthenticationResult`, `SessionCookie`, `RegistrationRequest`, `AuthenticationRequest` and `SecurityConfig` all redact sensitive fields. Caught `SQLException`s log `e.getMessage()` only, not stack traces or SQL text.
- **File permissions (CWE-276/CWE-732):** the data directory is created with POSIX `0700` as a creation attribute — not chmod-after-create, so there is no race window (`SecurityConfig.java:135-138`) — and existing directories are re-tightened (`:155-157`). Database files are forced to `0600` after schema init, after each user insert, and on close (`DatabaseManager.java:129-154,180,393`). Non-POSIX fallbacks use `File.setReadable/Writable/Executable(…, ownerOnly)`. Note the residual gap recorded under SEC-04: H2 creates the `.mv.db` file itself before `enforceDbFilePermissions` runs, so it exists briefly at the process umask — contained in practice by the `0700` parent directory.
- **Transaction integrity and fail-closed behaviour (CWE-754):** `insertUser` and `insertSession` run with `setAutoCommit(false)` and roll back on error (`DatabaseManager.java:168,182,287,300`); uniqueness is enforced by `UNIQUE` constraints on `users.username`, `users.email` and `sessions.token_hash` rather than by the application pre-check alone, and SQLSTATE `23505` is translated into a generic failure (`:184-188`); `userExists` returns `true` on query error, failing closed (`:210-214`).
- **Insecure deserialization (CWE-502):** none present — no `ObjectInputStream`, no XML/YAML/JSON parsing of untrusted data, no reflection-driven object construction.
- **OS command execution / path traversal (CWE-78/CWE-22):** no `Runtime.exec`, `ProcessBuilder`, or `ScriptEngine` usage. The only filesystem path derives from `APP_DATA_DIR` and is normalised and validated (see above); no user-controlled filename is joined to a path.
- **SSRF / outbound network calls (CWE-918):** the application makes no outbound HTTP or socket connections; the only I/O is stdin/stdout and the embedded file-backed database.
- **Dependencies (CWE-1104/CWE-1395):** H2 2.3.232 and SLF4J 2.0.16 (`pom.xml:20-21`) were current, maintained releases with no known applicable CVEs at the time of review; H2 2.3.x post-dates the CVE-2021-42392 / CVE-2022-23221 console-RCE issues, and the H2 web console is never started by this code. Build uses `-Xlint:all -Werror` (`pom.xml:65-68`). Gap worth noting rather than a vulnerability: there is no dependency-verification (checksum/signature pinning) and no SCA plugin such as `dependency-check` or `cyclonedx` in the build, so future dependency drift is unmonitored.
