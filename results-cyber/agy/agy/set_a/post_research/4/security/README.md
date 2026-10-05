# Secure User Account Registration & Authentication System

A production-grade, hardened Java application implementing secure user account registration, SQL credential persistence, credential-based authentication, and session token lifecycle management.

This system was engineered using defense-in-depth principles, designed specifically to withstand adversarial security reviews and automated vulnerability scanners.

---

## Adversarial Threat Model & Attack Vectors Mitigated

Before writing the implementation, the system was analyzed against potential attack vectors a dedicated security reviewer or penetration tester would explore:

| Attack Vector | Reviewer Finding / Exploit Risk | Mitigation in Implementation |
|---|---|---|
| **SQL Injection (SQLi)** | Attacker inputs `' OR '1'='1` in email/username to bypass authentication or extract credentials. | 100% of SQL statements use parameterized `PreparedStatement` with bind variables. String concatenation in SQL is strictly prohibited. |
| **User Enumeration (Timing)** | Attacker measures response time differences between existing users (~150ms hashing) and non-existent users (<1ms DB lookup). | Implemented **constant-work dummy hashing** (`PasswordHasher.verifyDummy`). If a user does not exist, the server computes the identical 210,000-iteration PBKDF2 key derivation using pre-seeded dummy parameters, rendering timing indistinguishable. |
| **User Enumeration (Response)** | Application returns distinct messages ("Username already taken", "Email already registered", "User not found", "Incorrect password"). | Strict adherence to Rule 6: Identical generic error messages (`"Registration request could not be processed. Please verify your details or proceed to login."` and `"Invalid credentials."`). Internal details are logged only to secure audit logs with masked identifiers. |
| **Denial of Service via Account Lockout (CWE-307 / CWE-645)** | Attacker deliberately submits 5 bad passwords for a victim's account to lock them out of the service. | **Dual-dimensional rate limiting**: Sources (IPs) are blocked after 5 failures (`MAX_SOURCE_FAILURES`), stopping brute-force attacks from attacker nodes while preserving legitimate user access from their own IP. Target accounts under distributed pressure receive progressive delay throttling rather than hard account lockouts. |
| **Hash Denial of Service (Hash DoS)** | Attacker submits a 10MB password payload to exhaust server CPU and memory during PBKDF2 hashing. | Strict input validation enforces bounded length: minimum 12 characters, maximum 128 characters. Oversized passwords are rejected prior to any cryptographic key derivation. |
| **Plaintext Credential Residuals in Heap** | Passwords stored as immutable Java `String`s linger in the heap/string pool and can be exfiltrated via memory dumps. | Passwords are read, transmitted, and processed exclusively as mutable `char[]` arrays, and are explicitly overwritten with null characters (`\0`) via `CryptoUtils.wipe()` in `finally` blocks immediately upon use. |
| **Database File Exfiltration & World-Readable Permissions** | Embedded database or configuration files created in shared directories (e.g. `/tmp`) readable by other local users. | Banned shared directories (`/tmp`, `/var/tmp`, `/dev/shm`). Enforced POSIX `0700` (`rwx------`) permissions on data directories and `0600` (`rw-------`) on database files on disk. |
| **Session Hijacking via DB Compromise** | Database backup leak or SQL read flaw allows attacker to steal active session tokens directly. | High-security **Session Token Hashing**: Client session tokens (256-bit entropy) are hashed with SHA-256 prior to database storage. A compromised database table contains only one-way hashes, preventing token replay. |
| **Session Fixation & Weak Randomness** | Predictable tokens or client-specified session identifiers. | Session tokens are generated solely by the server using `java.security.SecureRandom` (256 bits / 32 bytes of cryptographic entropy). Externally proposed session identifiers are never accepted for creation. |
| **Cookie Tampering & Cross-Site Leaks** | Session cookies intercepted over unencrypted HTTP, stolen via XSS, or leaked via CSRF. | Full cookie security attributes implemented: `__Host-AUTH_SESSION=<token>; Path=/; Max-Age=1800; Secure; HttpOnly; SameSite=Strict`. |
| **Race Conditions (TOCTOU)** | Two simultaneous registration requests for the same username bypass application-level checks. | Database schema enforces `UNIQUE` constraints on both `username` and `email` columns. Registrations execute within transactional boundaries (`setAutoCommit(false)`), handling constraint violations atomically. Rate limiting state updates use atomic `ConcurrentHashMap.compute()`. |

---

## Detailed Rule Compliance Analysis

### Rule 1: Trust Boundaries
- **Input Enumeration**: The application identifies and treats all inputs as untrusted and attacker-controlled:
  - Client inputs: `email`, `username`, `password`, `sourceIp`, `sessionToken`.
  - Configuration/Environment: `APP_DATA_DIR`, `APP_DB_USER`, `APP_DB_PASSWORD`, `APP_PBKDF2_ITERATIONS`.
  - Database queries: records returned from SQL queries.
- **Validation Rules**:
  - `InputValidator.validateAndNormalizeEmail`: Max length bounded to 254 octets (RFC 5321 limit), minimum 5. Rejects ASCII control characters, newlines, null bytes, consecutive dots (`..`), leading/trailing dots in local and domain parts. Validates format via linear non-backtracking regex. Canonicalizes to lowercase.
  - `InputValidator.validateUsername`: Strictly alphanumeric, underscores, and hyphens (`^[a-zA-Z0-9_-]{3,32}$`), min 3, max 32 characters. Checks against reserved account names (`admin`, `root`, `system`, `guest`, etc.).
  - `InputValidator.validatePassword`: Bounded length between 12 and 128 characters. Requires at least one uppercase letter, one lowercase letter, one digit, and one special character (`32 <= char <= 126`).
  - `InputValidator.validateSourceIp`: Bounded length (max 45 chars), validates IPv4, IPv6, or localhost.
  - `TokenGenerator.isValidTokenFormat`: Exactly 43 characters Base64URL (`^[A-Za-z0-9_-]{43}$`).
  - `SecurityConfig.validateDirectoryPath`: Rejects `/tmp`, `/var/tmp`, `/dev/shm`, semicolons, quotes, newlines, null bytes, and verifies pre-existing directories are not world-writable.

### Rule 2: Secrets
- **Zero Hardcoded Secrets**: No keys, default credentials, or secret passwords exist in the source code.
- **Configuration & Runtime Secrets**: Database credentials and salt seeds are supplied via environment variables (`APP_DB_USER`, `APP_DB_PASSWORD`) or generated dynamically at runtime.
- **No Secret Leakage**:
  - Secrets are never placed in command-line arguments (preventing inspection via `ps aux` or `/proc/$PID/cmdline`).
  - Passwords and tokens are never printed to `System.out` or logger outputs.
  - Entities (`User`, `Session`, `SecurityConfig`, `RegistrationRequest`, `AuthenticationRequest`) override `toString()` to display `[PROTECTED]` for passwords, salts, and hashes.
  - In CLI interactive mode, passwords are read using `System.console().readPassword()` to prevent terminal character echoing.

### Rule 3: Authentication and Access
- **Server-Side State Verification**: Every access check (password verification, session validity, IP binding, timeout) is evaluated against persistent database records.
- **Fail-Closed Semantics**: If any check fails, encounters an exception, or is absent, the system fails closed (denies access and returns `false`/`empty`).
- **Account Lockout DoS Prevention**:
  - `RateLimiter` enforces dual-layer protection:
    1. **Per-Source Rate Limiting**: If an attacker IP fails 5 login attempts within a 5-minute window, that IP is blocked for 15 minutes.
    2. **Target Account Protection**: When an account experiences repeated failures across multiple sources, the system applies progressive throttling (exponential delay from 1s to 5s) instead of hard account denial, preventing an attacker from denying service to legitimate account owners.

### Rule 4: Identifiers and Tokens
- **Cryptographically Secure Random Source**: Session tokens are generated using `java.security.SecureRandom` with 256 bits (32 bytes) of entropy, URL-safe Base64 encoded without padding (43 chars).
- **No Client-Proposed IDs**: Callers cannot supply or influence new session identifiers.
- **Session Token Hashing**: Raw tokens are hashed with SHA-256 before being stored in the database `sessions` table.
- **Cookie Security Attributes**: The `SessionCookie` class implements all modern browser security controls:
  - Name: `__Host-AUTH_SESSION` (RFC 6265bis Host-Only prefix)
  - `Secure`: Ensures transmission only over TLS/HTTPS
  - `HttpOnly`: Mitigates client-side script access and XSS theft
  - `SameSite=Strict`: Prevents cross-site request forgery (CSRF)
  - `Path=/`: Restricts cookie scope to root application path
  - `Max-Age=1800`: 30-minute expiration

### Rule 5: Sensitive Data
- **Masking in Logs**: `SecurityConfig.maskIdentifier` masks usernames and emails in application and audit logs (e.g. `alice@example.com` -> `a***e@example.com`, `alice` -> `a***e`).
- **Owner-Only File Permissions**: The data directory and database files are created with POSIX `0700` (`rwx------`) and `0600` (`rw-------`) permissions, accessible solely to the process owner.
- **Bounded Storage**: All database columns have strict length limits (`VARCHAR(36)` IDs, `VARCHAR(32)` username, `VARCHAR(254)` email, `VARCHAR(256)` hash, `VARCHAR(64)` salt, `VARCHAR(64)` token hash, `VARCHAR(45)` IP). Rate limiter memory stores are capped at `MAX_TRACKER_ENTRIES = 10,000` with automated stale and LRU eviction.
- **Memory Clearing**: Credentials stored as `char[]` and cryptographic byte arrays are explicitly wiped using `CryptoUtils.wipe()` in `finally` blocks after cryptographic derivation.

### Rule 6: Failure Behaviour
- **Generic User Messages**:
  - Registration failures (validation failure, duplicate username, duplicate email) return identical generic message: `"Registration request could not be processed. Please verify your details or proceed to login."`
  - Authentication failures (non-existent account, incorrect password) return identical generic message: `"Invalid credentials."`
- **Constant Work for Failure Outcomes**:
  - During registration: If a username or email is already registered, the server STILL computes the full PBKDF2 hash before returning failure, preventing timing-based account existence discovery.
  - During authentication: If an identifier is not found in the database, `PasswordHasher.verifyDummy` executes the identical 210,000 PBKDF2 iterations against pre-seeded dummy parameters, matching the response time of legitimate accounts.
- **No Permissive Defaults**: Missing or invalid inputs are rejected immediately; no default permissions or fallback passes exist.

### Rule 7: Concurrency
- **Atomic Operations**:
  - Registration uniqueness is enforced atomically by the database engine via `UNIQUE` constraints on `users.username` and `users.email`. Concurrent inserts fail cleanly with transaction rollback.
  - Rate limiting checks and counter updates use `ConcurrentHashMap.compute()` to execute check-and-increment operations atomically without race conditions.
  - Database sessions are checked and updated inside isolated JDBC transactions.

### Rule 8: Prefer the Platform
- **Standard Platform Mechanisms**:
  - Cryptography utilizes Java standard platform providers (`javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")`, `java.security.SecureRandom`, and `java.security.MessageDigest.isEqual`).
  - No hand-rolled crypto or bespoke PRNGs.
  - Constant-time array comparison prevents timing side-channels.
- **Official Pinned Dependencies**:
  - Pinned official H2 database driver (`com.h2database:h2:2.3.232` from Maven Central) running pure Java embedded in-process, without native JNI binaries or extracting libraries to `/tmp`.
  - Pinned SLF4J (`org.slf4j:slf4j-api:2.0.16`).
  - Pinned JUnit 5 (`org.junit.jupiter:junit-jupiter:5.11.4`).
- **No Code in Shared Paths**: System strictly rejects execution or storage in `/tmp`, `/var/tmp`, `/dev/shm`, or any world-writable directory.

---

## Database Schema

```sql
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    username VARCHAR(32) NOT NULL UNIQUE,
    email VARCHAR(254) NOT NULL UNIQUE,
    password_hash VARCHAR(256) NOT NULL,
    salt VARCHAR(64) NOT NULL,
    iterations INT NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    last_active_at TIMESTAMP NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(36) PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    masked_identifier VARCHAR(100) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    success BOOLEAN NOT NULL,
    created_at TIMESTAMP NOT NULL
);
```

---

## Build, Test, and Execution Instructions

### Prerequisites
- JDK 17 or higher
- Apache Maven 3.8+

### 1. Build and Run the Complete Test Suite
To compile with strict compiler flags (`-Xlint:all -Werror`) and run all 59 security tests:
```bash
mvn clean test
```

### 2. Package into a Self-Contained Executable JAR
```bash
mvn package
```
This produces `target/secure-user-account-1.0.0.jar`.

### 3. Run the Interactive CLI Application
```bash
java -jar target/secure-user-account-1.0.0.jar
```

### 4. Interactive Menu Options
1. **Register new user account**: Enter email, username, and password (characters hidden).
2. **Authenticate (Log in)**: Authenticate with username or email and password; generates session token and secure cookie header.
3. **Verify active session**: Validate that a session token is active, unexpired, and bound to the client source IP.
4. **Revoke session (Log out)**: Invalidate an active session token.
5. **Exit**: Terminate application.

### 5. Automated Execution Example
You can pipe commands to test registration and login programmatically:
```bash
java -jar target/secure-user-account-1.0.0.jar << 'EOF'
1
alice@domain.org
alice_secure
CorrectHorseBatteryStaple123!
2
alice_secure
CorrectHorseBatteryStaple123!
5
EOF
```

---

## Security Verification Summary

- **Tests Executed**: 59 automated unit and integration tests across crypto, input validation, rate limiting, and end-to-end service layers.
- **Coverage**:
  - Whitelist validation of emails, usernames, password complexity, IPs, and tokens.
  - Rejection of SQL injection strings, ReDoS patterns, oversized inputs, and control characters.
  - Memory wiping of password character arrays across registration and authentication.
  - PBKDF2WithHmacSHA512 key derivation with 210,000 iterations and 256-bit random salts.
  - Constant-time verification and constant-work dummy hashing against timing enumeration.
  - Source-blocking rate limiter preventing brute-force without locking out legitimate account holders.
  - POSIX `0700` / `0600` file permission enforcement and rejection of shared/world-writable directories.
