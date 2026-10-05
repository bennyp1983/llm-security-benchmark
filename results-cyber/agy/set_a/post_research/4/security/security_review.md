# Security Review: Secure User Account Registration & Authentication System

## 1. Executive Summary
This document provides a comprehensive security review of the Secure User Account Registration & Authentication System, a Java-based application providing user registration, credential persistence using an embedded H2 SQL database, session lifecycle management, and rate limiting. The codebase was engineered with intentional defenses against common web application vulnerabilities, including parameterized SQL queries, PBKDF2-HMAC-SHA512 password hashing with constant-work dummy verification against timing enumeration, memory wiping of sensitive character arrays, cryptographic token generation with SHA-256 storage hashing, and restrictive POSIX file permissions.

Despite these defense-in-depth controls, the security review identified several vulnerabilities that require remediation. Most notably, a flaw in the rate limiting implementation resets the IP-level failure tracker on any successful login, allowing an attacker with a single valid credential to completely bypass IP rate limits during brute-force or credential-stuffing attacks (SEC-01). Additionally, sessions lack an absolute maximum lifetime expiration, allowing active sessions to persist indefinitely (SEC-02). A path traversal flaw in directory path validation permits bypassing world-writable and shared directory restrictions (SEC-03). Password hashes and salts are exposed on the `User` domain model (SEC-04), and database column sizing in the audit logging table causes dropped security audit events when processing valid long identifiers (SEC-05).

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `pom.xml` | Maven build definition and dependency configuration | Declares pinned dependencies (H2 database, SLF4J, JUnit 5), defines compiler security flags (`-Xlint:all -Werror`), and configures executable JAR packaging. |
| `src/main/java/com/security/auth/Main.java` | Interactive command-line interface entry point | Reads user credentials securely without echo via `Console.readPassword()`, manages menu interactions, and executes sensitive memory zeroing in `finally` blocks. |
| `src/main/java/com/security/auth/config/SecurityConfig.java` | Configuration manager and filesystem security enforcer | Reads configuration from environment variables, validates filesystem paths, enforces POSIX 0700 private permissions on data directories, and masks identifiers for logging. |
| `src/main/java/com/security/auth/crypto/CryptoUtils.java` | Cryptographic primitives and memory hygiene utilities | Provides sensitive array wiping (`Arrays.fill`), constant-time byte and string equality comparisons (`MessageDigest.isEqual`), and SHA-256 digest computation. |
| `src/main/java/com/security/auth/crypto/PasswordHasher.java` | Password hashing and verification service | Implements PBKDF2WithHmacSHA512 with 210,000 iterations, 256-bit random salts, 512-bit keys, and constant-work dummy hashing to defeat timing enumeration. |
| `src/main/java/com/security/auth/crypto/TokenGenerator.java` | Cryptographic session token generation and validation | Generates 256-bit entropy tokens via `SecureRandom` (Base64URL), validates 43-character token format, and hashes tokens with SHA-256 for database storage. |
| `src/main/java/com/security/auth/database/DatabaseManager.java` | SQL persistence and transaction manager | Executes parameterized SQL queries via `PreparedStatement`, enforces atomic unique constraints on users and sessions, manages audit logs, and enforces POSIX 0600 file permissions. |
| `src/main/java/com/security/auth/model/AuthenticationRequest.java` | Authentication input data transfer object | Encapsulates login credentials with mutable `char[]` password storage, implements `AutoCloseable` memory wiping, and masks sensitive fields in `toString()`. |
| `src/main/java/com/security/auth/model/AuthenticationResult.java` | Authentication outcome data transfer object | Returns uniform, generic authentication responses, session tokens, secure cookies, and masks credentials in `toString()`. |
| `src/main/java/com/security/auth/model/RegistrationRequest.java` | Registration input data transfer object | Encapsulates registration fields with mutable `char[]` password storage, implements `AutoCloseable` memory wiping, and masks sensitive fields in `toString()`. |
| `src/main/java/com/security/auth/model/RegistrationResult.java` | Registration outcome data transfer object | Returns uniform, non-enumerating generic messages for both registration successes and failures. |
| `src/main/java/com/security/auth/model/Session.java` | Server-side session entity | Tracks session token hash, timestamps (created, expires, last active), source IP binding, and masks token hashes in `toString()`. |
| `src/main/java/com/security/auth/model/SessionCookie.java` | Session cookie encapsulation | Formats HTTP `Set-Cookie` header with RFC 6265bis `__Host-` prefix, `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, and `Max-Age`. |
| `src/main/java/com/security/auth/model/User.java` | User database entity model | Stores user record (id, username, email, password hash, salt, iterations, timestamp), masking sensitive fields in `toString()`. |
| `src/main/java/com/security/auth/security/RateLimiter.java` | In-memory dual-dimensional rate limiter | Implements source IP blocking after consecutive failures, progressive delay backoff for target accounts under attack, and thread-safe atomic tracking with memory bounds. |
| `src/main/java/com/security/auth/service/AuthenticationService.java` | Core authentication and lifecycle orchestrator | Coordinates input validation, constant-work execution on missing/duplicate accounts, session issuance, IP binding verification, and session revocation. |
| `src/main/java/com/security/auth/validation/InputValidator.java` | Strict whitelist input validation | Validates RFC 5321 email bounds and structure, enforces alphanumeric username whitelist with reserved name checks, validates password complexity, and checks IP format. |

## 3. Skills Applied
- `implementing-api-rate-limiting-and-throttling`: Applied to the dual-dimensional rate limiting logic in `RateLimiter.java` and `AuthenticationService.java`, reviewing per-source IP blocking, progressive account delays, window reset conditions, and eviction behavior under load.
- `testing-api-authentication-weaknesses`: Applied to authentication workflows, session token format and entropy in `TokenGenerator.java`, session expiration and revocation in `AuthenticationService.java`, source IP binding validation, and user enumeration resistance.
- `performing-cryptographic-audit-of-application`: Applied to PBKDF2-HMAC-SHA512 parameter selection and dummy verification in `PasswordHasher.java`, PRNG entropy in `TokenGenerator.java`, constant-time comparisons in `CryptoUtils.java`, and SHA-256 digest handling.
- `exploiting-sql-injection-vulnerabilities`: Applied to all database operations in `DatabaseManager.java`, verifying schema creation, query parameterization, transaction isolation, and lack of dynamic SQL string concatenation.
- `testing-for-sensitive-data-exposure`: Applied to password and token lifecycle in memory (`char[]` wiping in `CryptoUtils.java` and DTOs), identifier masking in logs via `SecurityConfig.maskIdentifier`, and POSIX file/directory permission enforcement in `SecurityConfig.java` and `DatabaseManager.java`.
- `performing-security-headers-audit`: Applied to session cookie security attributes in `SessionCookie.java`, auditing `__Host-` prefix compliance, `Secure`, `HttpOnly`, `SameSite=Strict`, `Path`, and expiration directives.
- General OWASP Top 10 / CWE knowledge (A01:2021 Broken Access Control, A03:2021 Injection, A09:2021 Security Logging and Monitoring Failures; CWE-22, CWE-613, CWE-778): Applied to path validation against directory traversal in `SecurityConfig.java`, audit log persistence constraints and error handling in `DatabaseManager.java`, and linear regex safety in `InputValidator.java`.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | IP Rate Limit Bypass via Successful Authentication on Alternate Account | High | CWE-307 | `src/main/java/com/security/auth/security/RateLimiter.java:124-127` |
| SEC-02 | Insufficient Session Expiration via Indefinite Sliding Window Without Absolute Timeout | Medium | CWE-613 | `src/main/java/com/security/auth/service/AuthenticationService.java:288-298` |
| SEC-03 | Path Traversal and World-Writable Check Bypass in Security Directory Validation | Medium | CWE-22 | `src/main/java/com/security/auth/config/SecurityConfig.java:105-109` |
| SEC-04 | Exposure of Password Hash and Salt via User Entity in Authentication Result | Low | CWE-200 | `src/main/java/com/security/auth/model/User.java:44-50` |
| SEC-05 | Audit Log Failure and Dropped Security Events Due to Identifier Column Length Discrepancy | Low | CWE-778 | `src/main/java/com/security/auth/database/DatabaseManager.java:100-107` |

## 5. Detailed Findings

### SEC-01: IP Rate Limit Bypass via Successful Authentication on Alternate Account
- **Severity:** High
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

**Why it is a problem:**
When any authentication attempt succeeds, `AuthenticationService.authenticate` invokes `rateLimiter.recordSuccess(sanitizedSourceIp, normalizedIdentifier)`. Inside `RateLimiter.recordSuccess`, the method unconditionally removes the source IP entry from `sourceTrackers` via `sourceTrackers.remove(sourceIp)`.

This creates a critical rate limiting bypass. An attacker conducting credential stuffing or brute-forcing a targeted user account from an IP address can perform up to 4 invalid login attempts (below `MAX_SOURCE_FAILURES = 5`), and then authenticate using any valid account they control (such as a self-registered test account). Because `sourceTrackers.remove(sourceIp)` purges the IP address's failure count, the source failure counter resets to zero. The attacker can repeat this sequence indefinitely (4 brute-force attempts followed by 1 valid login), completely circumventing the IP-based lockout mechanism and brute-forcing passwords without restriction.

**Fix:**
A successful login for a given user account must reset the failure counter for that specific account only (`accountTrackers`). The source IP's failure history (`sourceTrackers`) must not be cleared by an authentication event on another account; instead, it should decay naturally through the time-based window (`SOURCE_WINDOW`).
```java
    public void recordSuccess(String sourceIp, String accountIdentifier) {
        // Clear only the account-specific failure tracker; do not clear the source IP tracker
        accountTrackers.remove(accountIdentifier.toLowerCase());
    }
```

---

### SEC-02: Insufficient Session Expiration via Indefinite Sliding Window Without Absolute Timeout
- **Severity:** Medium
- **CWE:** CWE-613: Insufficient Session Expiration
- **Location:** `src/main/java/com/security/auth/service/AuthenticationService.java:288-298`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/service/AuthenticationService.java:288-298
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
```

**Why it is a problem:**
In `validateSession`, whenever a session is verified, `newExpiresAt` is computed as `now.plus(Duration.ofMinutes(config.getSessionTtlMinutes()))` and persisted to the database, sliding the expiration forward. While the application checks `session.isExpired(now)` and the idle timeout (`inactiveDuration.toMinutes() >= config.getSessionTtlMinutes()`), it never verifies `session.getCreatedAt()` against an absolute maximum session lifetime.

Per NIST SP 800-63B (Section 7.1) and OWASP Session Management Guidelines, session management mechanisms must enforce both an idle timeout and an absolute timeout. Without an absolute session lifetime ceiling (e.g., 12 or 24 hours), any periodically polled session (such as an automated client, background browser polling, or active user session) will never expire. If a session token is compromised or retained on a shared workstation, it remains valid indefinitely as long as requests occur within the 30-minute idle window.

**Fix:**
Enforce an absolute maximum lifetime (e.g., 24 hours from `session.getCreatedAt()`). If the session's total age exceeds this maximum duration, invalidate the session immediately regardless of recent activity.
```java
        // Check absolute session lifetime (e.g., 24 hours maximum)
        Duration totalLifetime = Duration.between(session.getCreatedAt(), now);
        if (totalLifetime.toHours() >= 24) {
            log.info("Session exceeded absolute maximum lifetime: sessionId={}", session.getId());
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
```

---

### SEC-03: Path Traversal and World-Writable Check Bypass in Security Directory Validation
- **Severity:** Medium
- **CWE:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- **Location:** `src/main/java/com/security/auth/config/SecurityConfig.java:105-109`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/config/SecurityConfig.java:105-109
    private static void validateDirectoryPath(Path path) {
        String pathStr = path.toString();
        if (pathStr.startsWith("/tmp") || pathStr.startsWith("/var/tmp") || pathStr.startsWith("/dev/shm")) {
            throw new SecurityException("Data directory cannot be located in shared or world-writable locations: " + pathStr);
        }
```

**Why it is a problem:**
`validateDirectoryPath` performs prefix validation on `path.toString()` to reject shared or world-writable directory locations (`/tmp`, `/var/tmp`, `/dev/shm`). However, in `SecurityConfig(Builder builder)`:
```java
this.dataDirectory = Objects.requireNonNull(builder.dataDirectory, "dataDirectory must not be null");
validateDirectoryPath(this.dataDirectory);
```
The raw `builder.dataDirectory` is passed to `validateDirectoryPath` without prior normalization or resolution to an absolute path.

If a path with directory traversal segments is supplied (such as `Paths.get("data/../../tmp/auth_store")` or `Paths.get("./var/log/../../tmp/auth_store")`), `path.toString()` does not start with `"/tmp"`, bypassing the security check. Subsequently, `ensurePrivateDirectory` creates and configures the directory inside `/tmp`. In multi-tenant or shared host environments, storing database files in shared or world-writable locations exposes the application to unauthorized local file inspection, symlink attacks, or tampering.

**Fix:**
Ensure that `path` is converted to an absolute path and normalized before inspecting its string prefix or testing file permissions.
```java
    private static void validateDirectoryPath(Path path) {
        Path normalized = path.toAbsolutePath().normalize();
        String pathStr = normalized.toString();
        if (pathStr.startsWith("/tmp") || pathStr.startsWith("/var/tmp") || pathStr.startsWith("/dev/shm")) {
            throw new SecurityException("Data directory cannot be located in shared or world-writable locations: " + pathStr);
        }
```

---

### SEC-04: Exposure of Password Hash and Salt via User Entity in Authentication Result
- **Severity:** Low
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **Location:** `src/main/java/com/security/auth/model/User.java:44-50`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/model/User.java:44-50
    public String getPasswordHash() {
        return passwordHash;
    }

    public String getSalt() {
        return salt;
    }
```

**Why it is a problem:**
The `User` class acts both as an internal database entity and as a user profile model returned directly to API callers via `AuthenticationResult.getUser()`. While `User.toString()` masks the password hash and salt, standard JavaBean getter methods (`getPasswordHash()` and `getSalt()`) remain publicly accessible.

If `AuthenticationResult` or `User` is serialized to JSON or XML by web frameworks (such as Jackson, Gson, or Spring Web MVC) or logged by consuming applications, the password hash and salt are serialized into API responses. This leaks password hashes and salts to clients, enabling offline dictionary and brute-force attacks against user credentials.

**Fix:**
Decouple internal database credentials from client-facing profile objects. Remove `getPasswordHash()` and `getSalt()` from the public `User` model, or return a distinct `UserProfile` DTO that contains only non-sensitive attributes (`id`, `username`, `email`, `createdAt`).
```java
    // Remove getPasswordHash() and getSalt() from public API exposure,
    // or provide an explicit sanitized DTO for external consumers:
    public UserProfile toProfile() {
        return new UserProfile(this.id, this.username, this.email, this.createdAt);
    }
```

---

### SEC-05: Audit Log Failure and Dropped Security Events Due to Identifier Column Length Discrepancy
- **Severity:** Low
- **CWE:** CWE-778: Insufficient Logging
- **Location:** `src/main/java/com/security/auth/database/DatabaseManager.java:100-107`

**Vulnerable code:**
```java
// src/main/java/com/security/auth/database/DatabaseManager.java:100-107
                                "CREATE TABLE IF NOT EXISTS audit_logs (" +
                                "id VARCHAR(36) PRIMARY KEY, " +
                                "event_type VARCHAR(50) NOT NULL, " +
                                "masked_identifier VARCHAR(100) NOT NULL, " +
                                "source_ip VARCHAR(45) NOT NULL, " +
                                "success BOOLEAN NOT NULL, " +
                                "created_at TIMESTAMP NOT NULL" +
                                ")"
```

**Why it is a problem:**
In the `audit_logs` schema, the `masked_identifier` column is constrained to `VARCHAR(100)`. However, `InputValidator.EMAIL_MAX_LENGTH` permits valid RFC 5321 email addresses up to 254 characters. When an email with a long domain part (e.g. `user@subdomain.example...com` exceeding 100 characters) is processed, `SecurityConfig.maskIdentifier` only masks the local part, producing a string that exceeds 100 characters.

When `DatabaseManager.recordAuditLog` attempts to insert this record, the database throws a `JdbcSQLDataException: Value too long for column`. In `DatabaseManager.recordAuditLog` (lines 385–387), the `SQLException` is caught and logged at `WARN` level without saving the audit entry. Consequently, security-relevant events (`AUTH_FAILED_BAD_PASSWORD`, `AUTH_RATE_LIMITED`, `REGISTRATION_DUPLICATE`) involving long identifiers are silently dropped, blinding SOC analysts and audit logs to targeted authentication attacks.

**Fix:**
Expand the `masked_identifier` column to `VARCHAR(256)` to accommodate full RFC 5321 emails plus masking characters, and ensure that identifiers are defensively truncated before insertion into the audit log statement.
```java
                                "CREATE TABLE IF NOT EXISTS audit_logs (" +
                                "id VARCHAR(36) PRIMARY KEY, " +
                                "event_type VARCHAR(50) NOT NULL, " +
                                "masked_identifier VARCHAR(256) NOT NULL, " +
                                "source_ip VARCHAR(45) NOT NULL, " +
                                "success BOOLEAN NOT NULL, " +
                                "created_at TIMESTAMP NOT NULL" +
                                ")"
```

## 6. Verified Controls and Checks With No Finding
- Parameterized SQL Execution: Verified in `DatabaseManager.java` that all SQL statements (user registration, session lookup, activity updates, deletion, and audit logging) utilize `PreparedStatement` with typed parameter binding (`?`). No dynamic SQL string concatenation exists in the persistence layer.
- Password Hashing Algorithm and Work Factor: Verified in `PasswordHasher.java` that passwords are hashed using standard `PBKDF2WithHmacSHA512` with 210,000 iterations, 256-bit cryptographic salt, and 512-bit key length, adhering to OWASP Password Storage Guidelines.
- Side-Channel Timing Attack Mitigation: Verified in `PasswordHasher.java` and `AuthenticationService.java` that when an account does not exist, `PasswordHasher.verifyDummy` executes the identical 210,000-iteration PBKDF2 calculation against precomputed dummy parameters, ensuring response times are indistinguishable between existent and non-existent accounts. Similarly, registration executes password hashing prior to rejecting duplicate accounts.
- Constant-Time Comparison Routines: Verified in `CryptoUtils.java` that byte array and string comparisons utilize `MessageDigest.isEqual`, preventing side-channel timing leaks during cryptographic hash validation.
- In-Memory Credential Hygiene: Verified in `Main.java`, `RegistrationRequest.java`, `AuthenticationRequest.java`, `PasswordHasher.java`, and `CryptoUtils.java` that passwords are read, passed, and hashed exclusively using mutable character arrays (`char[]`), with null-overwriting (`\0`) executed in `finally` blocks immediately upon completion.
- Session Token Randomness and Entropy: Verified in `TokenGenerator.java` that session tokens are generated using `java.security.SecureRandom` with 256 bits (32 bytes) of cryptographic entropy, encoded as URL-safe Base64 without padding (43 characters).
- Database Session Token Hashing: Verified in `TokenGenerator.java` and `DatabaseManager.java` that raw session tokens are hashed using SHA-256 before database persistence, preventing session hijacking in the event of database exfiltration.
- Session Fixation Resistance: Verified in `AuthenticationService.java` that session tokens are minted exclusively by the server upon successful authentication and are never accepted from client input during creation.
- Session Hijacking Mitigation via Source IP Binding: Verified in `AuthenticationService.validateSession` that the client's source IP is verified against the session's recorded IP address, automatically invalidating and revoking the session upon IP mismatch.
- Browser Cookie Security Controls: Verified in `SessionCookie.java` that session cookies implement RFC 6265bis prefixing (`__Host-AUTH_SESSION`), `Path=/`, `Secure`, `HttpOnly`, `SameSite=Strict`, and bounded `Max-Age`.
- Non-Enumerating Generic User Responses: Verified in `RegistrationResult.java` and `AuthenticationResult.java` that error responses return uniform messages (`"Registration request could not be completed. Please verify your details or proceed to login."` and `"Invalid credentials."`), preventing account enumeration via distinct error strings.
- Filesystem Access Controls: Verified in `SecurityConfig.java` and `DatabaseManager.java` that data directories are created with POSIX 0700 (`rwx------`) permissions and database files on disk are enforced to POSIX 0600 (`rw-------`), restricting read/write access exclusively to the process owner.
- Whitelist Input Validation and ReDoS Resistance: Verified in `InputValidator.java` that email validation uses non-backtracking linear regex bounded to 254 octets (RFC 5321), usernames are restricted to `^[a-zA-Z0-9_-]{3,32}$` with reserved name filtering, passwords enforce 12–128 character bounds and complexity rules, and client IP addresses are strictly validated against IPv4/IPv6 patterns.
- Masking of Sensitive Identifiers in Logs: Verified in `SecurityConfig.maskIdentifier` and model `toString()` implementations that usernames and emails are masked in application logs and database hashes/passwords display `[PROTECTED]`.
- Account Lockout Denial of Service Prevention: Verified in `RateLimiter.java` that target accounts experiencing distributed brute-force attacks receive progressive backoff delays (1s to 5s) rather than hard account lockouts, ensuring legitimate users are not denied access by an adversary.
