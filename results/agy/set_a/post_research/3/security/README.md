# Secure Java Authentication System

A production-grade Java authentication system implementing email and password verification against an SQL database. Built according to strict defense-in-depth principles, addressing trust boundaries, memory hygiene, timing attack invariance, atomic rate limiting, and zero-echo credential handling.

---

## Quickstart

### Prerequisites
- Java 17+
- Apache Maven 3.8+

### Build and Test
```bash
# Compile and run complete test suite (45 unit and adversarial security tests)
mvn clean test

# Build self-contained executable JAR
mvn package
```

### Run the Application

#### 1. Interactive Account Registration
```bash
java -jar target/secure-auth-system-1.0.0.jar --register
```
Prompts for email, password (hidden input, no terminal echo), and confirmation. Stores credentials using PBKDF2WithHmacSHA256 (210,000 iterations) with a 128-bit cryptographically random salt.

#### 2. Authenticate
```bash
java -jar target/secure-auth-system-1.0.0.jar
```
Prompts for credentials, verifies against the SQL database, and outputs the result:
- **On Success**: Prints success confirmation, masked session token, and a secure HTTP cookie (`__Host-` prefix, `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`).
- **On Failure**: Emits a uniform, generic failure message (`Authentication failed. Invalid email or password.`) with non-zero exit code.

#### 3. Persistent Database Storage
By default, the application uses an in-memory SQL database (`jdbc:h2:mem:authdb`). For persistent storage across executions:
```bash
AUTH_DB_URL="jdbc:h2:./data/authdb" java -jar target/secure-auth-system-1.0.0.jar --register
AUTH_DB_URL="jdbc:h2:./data/authdb" java -jar target/secure-auth-system-1.0.0.jar
```
Files created in `./data` are automatically protected with POSIX permissions `0700` (directory) and `0600` (files), private to the file owner.

---

## Security Architecture & Rule Compliance

This implementation strictly satisfies all 8 security rules specified for this feature:

### Rule 1: Trust Boundaries
> *List every input this code can receive - including values from files, databases, configuration, environment, and anything a client controls - and treat everyone as attacker-controlled. Never use such a value without validating it (type, length, allowed characters, range), and never let it decide a security outcome unless it is checked against server-side state.*

- **Exhaustive Input Inventory**:
  1. `email` (client input via stdin/console/API): Treated as hostile. Validated via `InputValidator.isValidEmail`: strictly bounded between 3 and 254 characters (RFC 5321), verified for control character absence, and matched against a linear-time regex immune to catastrophic backtracking (ReDoS). Canonicalized with `Locale.ROOT`.
  2. `password` (client input): Treated as hostile. Handled exclusively as `char[]`, never `String`. Bounded between 1 and 128 characters to prevent algorithmic CPU exhaustion attacks during key derivation.
  3. `sourceId` (client network / IP address): Validated against `^[a-zA-Z0-9.:_\-]{1,64}$` to prevent header injection or delimiter collision in rate limit keys.
  4. `database row values` (`iterations`, `salt`, `password_hash`, `algorithm`, `status`): Untrusted upon retrieval. `InputValidator.isValidDatabaseHashParameters` enforces that `iterations` falls within [100,000, 10,000,000], `algorithm` strictly equals `PBKDF2WithHmacSHA256`, and decoded salt (>= 16 bytes) and hash (32 bytes) match exact expectations.
  5. `environment configuration` (`AUTH_DB_URL`, `AUTH_DB_USER`, `AUTH_DB_PASSWORD`): Read from environment or configuration, never hardcoded. Local file paths are checked and restricted to private permissions.
- **Server-Side Authority**: No client-controlled attribute or parameter decides an authentication outcome. Authentication decisions are evaluated solely against server-side database state and atomic server-side rate-limit counters.

### Rule 2: Secrets
> *Do not include credentials, keys, or passwords that would work if someone ran the program. Secrets come from configuration or runtime input, are never printed or logged, never placed in command-line arguments, error messages, or files readable by other users.*

- **No Hardcoded Credentials**: The codebase, SQL migration scripts, and repository contain zero static, default, or backdoor passwords. Accounts must be registered interactively or injected via environment variables at runtime.
- **No Command-Line Arguments**: Passwords are never accepted via command-line arguments, preventing credential leakage in process listings (`ps aux`), shell history, or `/proc/<pid>/cmdline`.
- **Zero Logging & Echo Suppression**: Passwords are never logged or printed. Terminal input uses `Console.readPassword` to suppress display echo.
- **Strict File Permissions**: Database files and directories created on disk are assigned POSIX file permissions `rw-------` (0600) and `rwx------` (0700), ensuring they are unreadable by any other user on the system.

### Rule 3: Authentication and Access
> *Anything that proves who a user is or what they may do must be verified against server-side state; a missing or failed check fails closed, never open. Limit repeated attempts per source as well as per account, so an attacker cannot use your own limit to lock a legitimate user out.*

- **Fail-Closed Semantics**: Every validation error, database failure, inactive account, or credential mismatch immediately terminates with a failed status. Default state is unauthenticated.
- **Dual-Layer Rate Limiting**:
  1. **Source Rate Limiting**: Bounded to 5 failed attempts per 5 minutes per source IP/client. Abusive sources are blocked immediately.
  2. **Per-(Source, Account) Rate Limiting**: Bounded to 3 failed attempts per 5 minutes for that specific account from that specific source.
- **Immunity to Lockout Denial of Service (DoS)**:
  - An external attacker cannot lock out a legitimate user. If an attacker floods failed attempts against `victim@example.com`, the attacker's source is blocked (`SOURCE_BLOCKED` / `SOURCE_ACCOUNT_BLOCKED`). The legitimate user connecting from their own IP/source is **not** locked out.
  - To defend against distributed botnets attacking a single account across thousands of IPs, the system applies **progressive adaptive delay** (exponential throttle) to requests targeting the pressured account rather than hard-locking it. Legitimate users can still authenticate after the delay, while automated brute force is rendered computationally infeasible.

### Rule 4: Identifiers and Tokens
> *Session identifiers and tokens must be generated by this code with a cryptographically secure random source - never accepted from or predictable from the caller. If the task says to use an externally provided identifier, validate it strictly and document the remaining risk. Cookies carry HttpOnly, Secure, SameSite, and a correct path.*

- **Cryptographic Random Generation**: `SessionManager` utilizes `java.security.SecureRandom` to generate 256 bits (32 bytes) of cryptographic entropy, encoded with RFC 4648 URL-safe unpadded Base64.
- **Hardened Cookie Specification**: Session cookies employ the modern `__Host-` security prefix and complete defense-in-depth flags:
  ```http
  __Host-AuthSession=<token>; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600
  ```
  - `__Host-` prefix: Mandates cookie is bound to the origin host without subdomains.
  - `Secure`: Cookie transmitted strictly over TLS/HTTPS.
  - `HttpOnly`: Mitigates XSS token extraction.
  - `SameSite=Strict`: Eliminates Cross-Site Request Forgery (CSRF).
  - `Path=/`: Enforces global application root path.

### Rule 5: Sensitive Data
> *Mask sensitive values in logs and output; write them only to files created private to the owner; bound the size of anything you store; clear credentials from memory when done.*

- **PII Masking**: Emails are masked before logging (`SecurityLogger.maskEmail` converts `alice@example.com` to `a***e@e***e.com`). Session tokens are truncated (`abcd...1234`). Passwords are never logged under any circumstance.
- **Memory Hygiene (Zeroization)**:
  - Passwords are kept in mutable `char[]` buffers, never immutable interned `String`s.
  - In `finally` blocks, `Arrays.fill(passwordChars, '\0')` explicitly wipes credentials from JVM heap memory.
  - `PBEKeySpec.clearPassword()` is invoked immediately after key derivation to clear the internal key specification array.
  - Intermediate derived keys and salt byte arrays are zeroized with `Arrays.fill(bytes, (byte) 0)`.
- **Bounded Storage**:
  - `RateLimiter` enforces `MAX_CACHE_ENTRIES = 10_000` with automated LRU and expiration eviction to prevent memory exhaustion DoS.
  - `SessionManager` bounds active sessions to 10,000 entries with automatic expiration pruning.
  - Input lengths are bounded (email: 254 chars, password: 128 chars, source: 64 chars).

### Rule 6: Failure Behaviour
> *Report errors to users in generic terms; details go to the log only. Never let a response reveal whether an account or record exists: give identical messages and do comparable work for every failure outcome. Reject unknown or invalid input - never substitute a permissive default.*

- **Identical User-Facing Messages**:
  - Whether a user exists or not, whether the password was incorrect, or whether input was malformed, the user receives the identical generic message:
    `Authentication failed. Invalid email or password.`
- **Constant-Work Timing Defense**:
  - If a user does not exist in the database, or if email/password validation fails:
    `PasswordHasher.verifyDummyPassword` executes the exact same PBKDF2 calculation (210,000 iterations) with a dummy salt and dummy hash.
  - Uses `MessageDigest.isEqual` for constant-time byte array comparison.
  - As a result, execution duration for non-existent accounts is statistically indistinguishable from existing accounts, completely defeating timing side-channel user enumeration.
- **Internal Audit Logging**: Detailed diagnostic reasons (`ACCOUNT_NOT_FOUND`, `PASSWORD_MISMATCH`, `MALFORMED_INPUT`, `INACTIVE_ACCOUNT`) are recorded only in server-side logs with PII masking and CRLF sanitization.

### Rule 7: Concurrency
> *Where you check state and then act on it (verify, then grant; count, then allow), make the check and the action atomic.*

- **Atomic Check-and-Act**: `RateLimiter` coordinates state transitions through `ConcurrentHashMap` with atomic `compute` and `synchronized` tracking blocks.
- **Count, Then Allow**: Permit acquisition and attempt counting occur in a single atomic operation. Multiple concurrent requests from the same source cannot race past the threshold.
- **Database Transactions**: User registration and state modifications execute within explicit database transactions (`conn.setAutoCommit(false)`, `conn.commit()`, `conn.rollback()`).

### Rule 8: Prefer the Platform
> *If the framework has a built-in, proven mechanism for this job, use it rather than hand-rolling your own. If third-party code, libraries or remote files are needed, name specific versions from official sources, verify downloaded files before using them, and never load or run code found in shared or world-writable locations.*

- **Built-In Standard Cryptography (JCA)**:
  - Key derivation: `javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")`.
  - Cryptographic randomness: `java.security.SecureRandom`.
  - Constant-time comparison: `java.security.MessageDigest.isEqual`.
  - Standard JDBC: `java.sql.PreparedStatement` with parameterized queries.
- **Official Pinned Dependencies**:
  - H2 Database: `com.h2database:h2:2.2.224` (official release from Maven Central).
  - JUnit 5: `org.junit.jupiter:junit-jupiter:5.10.2`.
- **World-Writable Defense**: No dynamic class loading, script evaluation, or file execution from `/tmp` or shared directories.

---

## Adversarial Security Review Findings & Mitigations

An adversarial security review was performed against this implementation. Below is the reviewer matrix and how each attack was mitigated:

| Attack Vector | Threat Scenario | Implemented Mitigation | Verification |
|---|---|---|---|
| **SQL Injection (SQLi)** | Attacker inputs `' OR '1'='1` or `admin'--` in email field. | 100% parameterized queries via `PreparedStatement`. Zero dynamic SQL concatenation. | Tested in `AuthenticationServiceTest.testSqlInjectionAttemptsArePrevented`. |
| **Account Enumeration (Timing)** | Attacker measures response time to discover valid emails (DB lookup 1ms vs PBKDF2 30ms). | `PasswordHasher.verifyDummyPassword` executes full PBKDF2 (210,000 iterations) when user is not found or format is invalid. | Verified in `SecurityAdversarialTest.testTimingInvarianceBetweenExistingAndNonExistentUsers`. |
| **Account Enumeration (Messages)** | Attacker tests emails to see "User not found" vs "Wrong password". | Uniform generic message returned for all failure outcomes: `Authentication failed. Invalid email or password.` | Verified in `SecurityAdversarialTest.testAccountEnumerationResistanceAcrossAllFailureModes`. |
| **Lockout Denial of Service (DoS)** | Attacker locks out legitimate admin by repeatedly failing logins for admin email. | Rate limiting is isolated per source (`SOURCE_ACCOUNT_BLOCKED` & `SOURCE_BLOCKED`). Only attacker's IP is blocked; legitimate user continues unimpeded. | Verified in `RateLimiterTest.testAttackerCannotLockOutLegitimateUser` and `SecurityAdversarialTest.testDenialOfServiceLockoutAttackIsDefeated`. |
| **ReDoS (RegEx DoS)** | Attacker inputs pathological email string to cause catastrophic regex backtracking. | Bounded length check (254 chars) and linear-time, non-backtracking regular expression. | Verified in `InputValidatorTest.testEmailReDosSafety`. |
| **PBKDF2 CPU Exhaustion** | Attacker sends 50MB password to exhaust CPU/memory during PBKDF2 calculation. | Strict password length bounds (`MAX_PASSWORD_LENGTH = 128` chars). | Verified in `InputValidatorTest.testPasswordLengthBounds`. |
| **Memory Scraping / Dumps** | Credentials persist in JVM memory as immutable `String`s. | Passwords handled exclusively as `char[]`; wiped with `Arrays.fill(..., '\0')` and `PBEKeySpec.clearPassword()`. | Verified in `AuthenticationServiceTest.testSuccessfulAuthenticationFlow`. |
| **Log Forging / CRLF Injection** | Attacker inserts `\r\n` into email or source ID to fake audit log entries (CWE-117). | `SecurityLogger.sanitizeCrlf` converts `\r` and `\n` to `_`. | Verified in `SecurityAdversarialTest.testCrlfInjectionNeutralizationInLogger`. |
| **Concurrency Permit Racing** | Multiple parallel threads flood requests to bypass rate limiter count checks. | Atomic check-and-acquire via `ConcurrentHashMap.compute` and `synchronized` blocks. | Verified in `RateLimiterTest.testConcurrencyAtomicity`. |
| **Sensitive File Access** | Other users on shared system read database file or credentials. | Parent directories set to `0700` (`rwx------`); database files set to `0600` (`rw-------`). | Verified via filesystem POSIX permission check. |

---

## Codebase Structure

```
security/
├── pom.xml                                    # Maven POM with Java 17, H2, and shaded packaging
├── README.md                                  # Complete security architecture and review documentation
├── src/
│   ├── main/java/com/example/auth/
│   │   ├── Main.java                          # CLI entry point with zero-echo console reading
│   │   ├── AuthenticationService.java         # Primary auth workflow coordinator
│   │   ├── AuthenticationResult.java          # Uniform response container with generic messaging
│   │   ├── PasswordHasher.java                # PBKDF2WithHmacSHA256, memory wiping, timing defense
│   │   ├── RateLimiter.java                   # Thread-safe, atomic, DoS-resistant dual rate limiter
│   │   ├── SessionManager.java                # 256-bit SecureRandom tokens & hardened cookies
│   │   ├── InputValidator.java                # Strict boundaries, bounded checks, ReDoS prevention
│   │   ├── DatabaseManager.java               # JDBC manager with POSIX 0700/0600 permissions
│   │   ├── UserRepository.java                # Parameterized SQL credential queries
│   │   ├── UserRecord.java                    # Immutable database user representation
│   │   ├── HashResult.java                    # Immutable hash components record
│   │   └── SecurityLogger.java                # Audit logger with CRLF sanitation and PII masking
│   └── test/java/com/example/auth/
│       ├── InputValidatorTest.java            # Boundary, regex, character, and ReDoS tests
│       ├── PasswordHasherTest.java            # PBKDF2 verification, unique salts, dummy execution
│       ├── RateLimiterTest.java               # Concurrency atomicity and DoS lockout immunity tests
│       ├── SessionManagerTest.java            # Cryptographic entropy and cookie attribute tests
│       ├── AuthenticationServiceTest.java     # End-to-end auth, SQLi resistance, memory wiping
│       └── SecurityAdversarialTest.java       # Timing invariance, enumeration, CRLF, DoS tests
```
