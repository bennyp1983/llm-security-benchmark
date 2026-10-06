# Security Review: Secure Authentication CLI (secure-jdbc-auth)

## 1. Executive Summary
The target component is a command-line Java 17 application (`secure-jdbc-auth`) that provides terminal-based authentication against a PostgreSQL database. It accepts an email address and a masked password from `System.console()`, validates and canonicalizes input parameters, reads credential records from an `app_user` database table, verifies password hashes using `PBKDF2WithHmacSHA256` (600,000 iterations), and enforces two-tier rate limiting (source-level and account-level) backed by an `auth_rate_limit` database table.

The codebase incorporates multiple defense-in-depth controls, including parameterized queries, strict input allowlisting, TLS certificate validation (`sslmode=verify-full`), memory clearing for passwords and key material, and generic error reporting without credential or stack trace leakage. However, several significant security weaknesses were identified in the rate limiting, concurrency model, and cryptographic flow:
1. **Unauthenticated Account Lockout Denial of Service (High):** Account-level rate limits are applied unconditionally to any supplied email address, allowing an external attacker to persistently lock out legitimate users by submitting 5 incorrect attempts within a minute.
2. **Global Denial of Service via Static Source Rate Limiting (High):** Source rate limiting relies on a single static constant bucket shared by all CLI executions, allowing any local user to block authentication for all other users across the system by making 10 attempts in a minute.
3. **Database Lock Contention and Serialization Failures (Medium):** The application performs slow, CPU-intensive PBKDF2 derivations while holding exclusive row locks inside a `SERIALIZABLE` database transaction, causing concurrent authentication attempts to abort with PostgreSQL serialization failures (SQLSTATE 40001).
4. **Wasted PBKDF2 Computations on Startup (Medium):** The `PasswordVerifier` constructor redundantly derives a dummy hash using 600,000 PBKDF2 iterations on every application execution, doubling CPU utilization to 1,200,000 iterations per login attempt and increasing denial-of-service risks.
5. **Short-Circuit Evaluation in Hash Comparison (Low):** Java's short-circuit logical operator (`&&`) skips constant-time hash comparison when credential records are null or invalid, undermining the intended timing-invariance mitigation.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `pom.xml` | Maven build and dependency configuration | Declares Java 17 compilation target and pins runtime dependency `org.postgresql:postgresql:42.7.13`. |
| `database/schema.sql` | PostgreSQL database schema definitions | Creates `app_user` and `auth_rate_limit` tables with check constraints; grants least-privilege permissions to `auth_runtime` role. |
| `scripts/verify-pgjdbc.sh` | Build dependency verification script | Validates the SHA-512 checksum of the downloaded pgJDBC JAR before execution to mitigate supply-chain tampering. |
| `src/main/java/example/security/InputValidator.java` | Input validation and normalization utility | Implements regex validation and lowercase canonicalization for emails, character/byte constraints on passwords, and allowlists for database host, port, and SQL identifiers. |
| `src/main/java/example/security/PasswordVerifier.java` | Password hashing and verification service | Implements PBKDF2-HMAC-SHA-256 derivation with 600,000 iterations, dummy hash handling for timing mitigation, and in-memory key wiping. |
| `src/main/java/example/security/CredentialRecord.java` | Immutable data carrier for user credentials | Stores algorithm name, iteration count, salt byte array, password hash byte array, and account enabled flag. |
| `src/main/java/example/security/DatabaseConfig.java` | Database configuration loader | Reads environment variables, validates connection parameters, constructs JDBC URL enforcing `sslmode=verify-full`, and configures timeouts. |
| `src/main/java/example/security/AuthenticationService.java` | Authentication and rate-limiting coordinator | Manages PostgreSQL transactions under `TRANSACTION_SERIALIZABLE`, executes parameterized queries, increments rate limits, and orchestrates credential verification. |
| `src/main/java/example/security/SecureAuthApplication.java` | Command-line application entry point | Enforces terminal-only execution (`System.console()`), reads masked passwords, rejects CLI arguments, handles generic failure logging, and wipes password arrays. |
| `src/test/java/example/security/SecuritySelfTest.java` | Test suite for validator and verifier | Asserts email regex validation, password surrogate/control filtering, and PBKDF2 verification behavior. |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to `PasswordVerifier.java` and `CredentialRecord.java` to review PBKDF2WithHmacSHA256 parameter selection, salt generation, secret clearing, constant-time comparison, and dummy hash derivation.
- `exploiting-sql-injection-vulnerabilities`: Applied to `AuthenticationService.java` and `database/schema.sql` to verify parameterized query usage (`PreparedStatement`), SQL injection resilience, and constraint validation.
- `testing-for-sensitive-data-exposure`: Applied to `SecureAuthApplication.java`, `AuthenticationService.java`, and `DatabaseConfig.java` to review in-memory credential wiping, terminal echo suppression, logger sanitization, and generic failure messaging.
- `implementing-secret-scanning-with-gitleaks`: Applied across all repository files (`pom.xml`, source code, schema, scripts) to verify the absence of embedded passwords, API tokens, or hardcoded database credentials.
- `testing-api-authentication-weaknesses`: Applied to `InputValidator.java` and `AuthenticationService.java` to evaluate authentication workflows, email normalization, surrogate pair validation, and account status checks.
- `performing-api-rate-limiting-bypass`: Applied to `AuthenticationService.java` and `database/schema.sql` to assess rate-limiting algorithms, bucket key generation, and window boundary behaviors.
- General OWASP Top 10 / CWE knowledge: Applied to evaluate database transaction isolation and row lock contention during slow cryptographic operations (CWE-662, CWE-362), overly restrictive account lockout mechanisms enabling unauthenticated DoS (CWE-645), and short-circuit boolean evaluation timing side-channels (CWE-208).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Overly Restrictive Account Lockout Mechanism Enables Unauthenticated Denial of Service | High | CWE-645 | `src/main/java/example/security/AuthenticationService.java:46-60` |
| SEC-02 | Global Denial of Service via Static Console Rate-Limiting Identifier | High | CWE-400 | `src/main/java/example/security/AuthenticationService.java:19` |
| SEC-03 | Database Lock Contention and Serialization Failure Race Condition during Slow PBKDF2 Derivation | Medium | CWE-662 | `src/main/java/example/security/AuthenticationService.java:36-62` |
| SEC-04 | Unnecessary Initialization PBKDF2 Derivation Doubles Cryptographic Workload | Medium | CWE-400 | `src/main/java/example/security/PasswordVerifier.java:19-31` |
| SEC-05 | Short-Circuit Evaluation Bypasses Constant-Time Comparison on Authentication Failure | Low | CWE-208 | `src/main/java/example/security/PasswordVerifier.java:43` |

## 5. Detailed Findings

### SEC-01: Overly Restrictive Account Lockout Mechanism Enables Unauthenticated Denial of Service
- **Severity:** High
- **CWE:** CWE-645: Overly Restrictive Account Lockout Mechanism
- **Location:** `src/main/java/example/security/AuthenticationService.java:46-60`

**Vulnerable code:**
```java
// src/main/java/example/security/AuthenticationService.java:46-60
                String accountBucket = digest(record == null ? INVALID_EMAIL : emailForQuery);
                int accountAttempts = incrementBucket(connection, "account", accountBucket);
                boolean passwordMatches;
                char[] boundedPassword = passwordValid ? password : "invalid-input-placeholder".toCharArray();
                try {
                    passwordMatches = passwordVerifier.verify(boundedPassword, record);
                } finally {
                    if (boundedPassword != password) {
                        Arrays.fill(boundedPassword, '\0');
                    }
                    if (record != null) {
                        clear(record.salt(), record.passwordHash());
                    }
                }
                boolean allowed = !sourceBlocked && accountAttempts <= ACCOUNT_LIMIT_PER_MINUTE;
```

**Why it is a problem:**
The service enforces a strict account-level limit of 5 attempts per minute (`ACCOUNT_LIMIT_PER_MINUTE = 5`). Every authentication request for an existing user updates that account's rate-limit row in `auth_rate_limit`. If `accountAttempts > 5`, line 60 sets `allowed = false`, causing `authenticate()` to return `false` regardless of whether the submitted password is correct.

Because login requests are unauthenticated, an adversary who knows a target user's email address can repeatedly submit 5 failed authentication attempts within a minute. On the 6th attempt, the legitimate user is locked out and cannot log in even with the correct password. An attacker can run a simple automated script sending 5 attempts per minute to keep a victim permanently locked out of their account. In addition, legitimate users who authenticate frequently or whose client tools perform multiple connections will lock themselves out because successful attempts also increment `accountAttempts`.

**Fix:**
Account-level protection should track consecutive failed authentication attempts rather than total attempts, and should not lock out legitimate credentials based solely on unauthenticated third-party submissions. Separate failure tracking should be recorded, and counters should reset upon successful authentication. If account throttling is desired, apply progressive delays rather than a complete authentication lockout:
```java
// src/main/java/example/security/AuthenticationService.java:46-62
                boolean passwordMatches;
                char[] boundedPassword = passwordValid ? password : "invalid-input-placeholder".toCharArray();
                try {
                    passwordMatches = passwordVerifier.verify(boundedPassword, record);
                } finally {
                    if (boundedPassword != password) {
                        Arrays.fill(boundedPassword, '\0');
                    }
                    if (record != null) {
                        clear(record.salt(), record.passwordHash());
                    }
                }
                // Only count failed attempts against account lockout to prevent unauthenticated DoS
                int accountAttempts = 0;
                if (!passwordMatches && record != null) {
                    accountAttempts = incrementBucket(connection, "account_failed", accountBucket);
                }
                boolean allowed = !sourceBlocked && accountAttempts <= ACCOUNT_LIMIT_PER_MINUTE;
                boolean authenticated = inputValid && allowed && passwordMatches;
```

---

### SEC-02: Global Denial of Service via Static Console Rate-Limiting Identifier
- **Severity:** High
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/example/security/AuthenticationService.java:19`

**Vulnerable code:**
```java
// src/main/java/example/security/AuthenticationService.java:19
    private static final String SOURCE_BUCKET = digest("server-defined:local-console:v1");
```

**Why it is a problem:**
The source rate limiter relies on a hardcoded constant string `SOURCE_BUCKET = digest("server-defined:local-console:v1")`. Every invocation of the application against the database shares this single bucket key in the `auth_rate_limit` table.

Line 38 increments this bucket on every login attempt, and line 39 sets `sourceBlocked = true` whenever `sourceAttempts > SOURCE_LIMIT_PER_MINUTE` (10 attempts per minute). Once triggered, line 60 sets `allowed = false`, causing all subsequent authentication attempts across all terminals and users to fail for the remainder of the one-minute window. Any unprivileged local user or malicious process can trigger 10 failed login attempts at the beginning of each minute, causing a total denial of service for all users attempting to authenticate.

**Fix:**
Bind the source rate-limiting bucket to a unique caller or session identifier rather than a shared static constant. For local terminal execution, derive the source identity from the operating system user identity or session ID:
```java
// src/main/java/example/security/AuthenticationService.java:19-21
    private final String sourceBucket;

    AuthenticationService(DatabaseConfig config) throws GeneralSecurityException {
        this.config = config;
        this.passwordVerifier = new PasswordVerifier();
        String callerIdentity = System.getProperty("user.name", "default") + ":"
                + ProcessHandle.current().info().user().orElse("unknown");
        this.sourceBucket = digest("server-defined:source:" + callerIdentity);
    }
```

---

### SEC-03: Database Lock Contention and Serialization Failure Race Condition during Slow PBKDF2 Derivation
- **Severity:** Medium
- **CWE:** CWE-662: Improper Synchronization
- **Location:** `src/main/java/example/security/AuthenticationService.java:36-62`

**Vulnerable code:**
```java
// src/main/java/example/security/AuthenticationService.java:36-62
            connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
            try {
                int sourceAttempts = incrementBucket(connection, "source", SOURCE_BUCKET);
                boolean sourceBlocked = sourceAttempts > SOURCE_LIMIT_PER_MINUTE;
                // Once the source is blocked, collapse attacker-chosen account keys and queries to
                // constants. This bounds database growth while preserving comparable failure work.
                String emailForQuery = sourceBlocked ? INVALID_EMAIL : canonical.orElse(INVALID_EMAIL);
                CredentialRecord record = readCredential(connection, emailForQuery);
                // Unknown accounts share one bucket. Only a server-side credential row can cause
                // a distinct persistent account key to be created.
                String accountBucket = digest(record == null ? INVALID_EMAIL : emailForQuery);
                int accountAttempts = incrementBucket(connection, "account", accountBucket);
                boolean passwordMatches;
                char[] boundedPassword = passwordValid ? password : "invalid-input-placeholder".toCharArray();
                try {
                    passwordMatches = passwordVerifier.verify(boundedPassword, record);
                } finally {
                    if (boundedPassword != password) {
                        Arrays.fill(boundedPassword, '\0');
                    }
                    if (record != null) {
                        clear(record.salt(), record.passwordHash());
                    }
                }
                boolean allowed = !sourceBlocked && accountAttempts <= ACCOUNT_LIMIT_PER_MINUTE;
                boolean authenticated = inputValid && allowed && passwordMatches;
                connection.commit(); // No success is returned unless all checks commit atomically.
                return authenticated;
```

**Why it is a problem:**
The transaction is executed with isolation level `Connection.TRANSACTION_SERIALIZABLE`. Lines 38 and 47 execute `INSERT ... ON CONFLICT DO UPDATE` queries that acquire exclusive row-level write locks on `auth_rate_limit` (specifically on the shared `SOURCE_BUCKET` row). The transaction remains open while line 51 computes PBKDF2 with 600,000 iterations, taking approximately 200–500 milliseconds of CPU time per request.

When concurrent authentication requests occur, the second transaction blocks waiting on the row lock held by the first transaction. In PostgreSQL under `SERIALIZABLE` isolation, modifying a row that was updated and committed by a concurrent transaction aborts the waiting transaction with an unrecoverable serialization failure (`SQLSTATE 40001: could not serialize access due to concurrent update`). Because `AuthenticationService` catches `SQLException` and rolls back (with `SecureAuthApplication` reporting `Authentication unsuccessful.`), any legitimate concurrent authentication attempt will immediately fail simply because another login was in progress.

**Fix:**
Decouple the rate-limiting and credential retrieval transactions from the expensive PBKDF2 hash calculation. Update rate-limiting buckets and fetch credentials in short-lived transactions under `TRANSACTION_READ_COMMITTED`, commit and release all row locks immediately, and then perform the CPU-bound PBKDF2 derivation outside any active database transaction:
```java
// src/main/java/example/security/AuthenticationService.java:34-62
            connection.setReadOnly(false);
            connection.setAutoCommit(true);
            connection.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);

            int sourceAttempts = incrementBucket(connection, "source", sourceBucket);
            boolean sourceBlocked = sourceAttempts > SOURCE_LIMIT_PER_MINUTE;
            String emailForQuery = sourceBlocked ? INVALID_EMAIL : canonical.orElse(INVALID_EMAIL);
            CredentialRecord record = readCredential(connection, emailForQuery);
            String accountBucket = digest(record == null ? INVALID_EMAIL : emailForQuery);
            int accountAttempts = incrementBucket(connection, "account", accountBucket);

            // Compute slow cryptographic derivation outside database transactions to avoid holding locks
            boolean passwordMatches;
            char[] boundedPassword = passwordValid ? password : "invalid-input-placeholder".toCharArray();
            try {
                passwordMatches = passwordVerifier.verify(boundedPassword, record);
            } finally {
                if (boundedPassword != password) {
                    Arrays.fill(boundedPassword, '\0');
                }
                if (record != null) {
                    clear(record.salt(), record.passwordHash());
                }
            }
            boolean allowed = !sourceBlocked && accountAttempts <= ACCOUNT_LIMIT_PER_MINUTE;
            return inputValid && allowed && passwordMatches;
```

---

### SEC-04: Unnecessary Initialization PBKDF2 Derivation Doubles Cryptographic Workload
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/example/security/PasswordVerifier.java:19-31`

**Vulnerable code:**
```java
// src/main/java/example/security/PasswordVerifier.java:19-31
    PasswordVerifier() throws GeneralSecurityException {
        SecureRandom random = new SecureRandom();
        random.nextBytes(dummySalt);
        char[] randomPassword = new char[32];
        for (int i = 0; i < randomPassword.length; i++) {
            randomPassword[i] = (char) ('!' + random.nextInt(94));
        }
        try {
            dummyHash = derive(randomPassword, dummySalt, ITERATIONS);
        } finally {
            Arrays.fill(randomPassword, '\0');
        }
    }
```

**Why it is a problem:**
In `PasswordVerifier`'s constructor, `dummyHash` is computed by executing 600,000 iterations of PBKDF2WithHmacSHA256 (`derive(randomPassword, dummySalt, ITERATIONS)`). Because `SecureAuthApplication.main` constructs a new `AuthenticationService` and `PasswordVerifier` on every run, this 600,000-iteration derivation executes on every single login attempt before the user's password is even evaluated. During `verify()`, a second 600,000-iteration derivation executes for the supplied password.

The purpose of `dummyHash` is solely to provide a non-null 32-byte target for `MessageDigest.isEqual(actual, expected)` when a user record is non-existent or invalid. `MessageDigest.isEqual` performs a simple constant-time 32-byte comparison; it does not check or require that `dummyHash` was generated by PBKDF2. Pre-computing PBKDF2 in the constructor wastes hundreds of milliseconds of CPU time on every CLI run, doubling the computational cost per login (1,200,000 iterations total instead of 600,000) and exacerbating denial-of-service vulnerability under load.

**Fix:**
Populate `dummyHash` with 32 cryptographically secure random bytes using `SecureRandom.nextBytes()`. This takes less than a microsecond, eliminates the redundant 600,000 PBKDF2 iterations, and preserves identical comparison semantics:
```java
// src/main/java/example/security/PasswordVerifier.java:19-24
    PasswordVerifier() {
        SecureRandom random = new SecureRandom();
        random.nextBytes(dummySalt);
        dummyHash = new byte[HASH_BYTES];
        random.nextBytes(dummyHash);
    }
```

---

### SEC-05: Short-Circuit Evaluation Bypasses Constant-Time Comparison on Authentication Failure
- **Severity:** Low
- **CWE:** CWE-208: Observable Timing Discrepancy
- **Location:** `src/main/java/example/security/PasswordVerifier.java:43`

**Vulnerable code:**
```java
// src/main/java/example/security/PasswordVerifier.java:43
            return validRecord && MessageDigest.isEqual(actual, expected);
```

**Why it is a problem:**
`PasswordVerifier` derives `actual` and sets `expected` to `dummyHash` when `validRecord` is false in order to execute a uniform code path and prevent username enumeration through timing analysis. However, on line 43, `return validRecord && MessageDigest.isEqual(actual, expected);` uses Java's short-circuit logical AND (`&&`).

When `validRecord` is `false` (e.g. non-existent user, disabled user, or invalid record parameters), Java short-circuits on `validRecord` and immediately returns `false` without invoking `MessageDigest.isEqual(actual, expected)`. The constant-time array comparison is only executed when `validRecord` is `true`. While the absolute time difference of `MessageDigest.isEqual` is small (nanoseconds) relative to the 600,000 PBKDF2 iterations, skipping the comparison undermines the architectural intent of the dummy hash and introduces an observable branch discrepancy.

**Fix:**
Evaluate `MessageDigest.isEqual(actual, expected)` unconditionally before checking `validRecord`, or use the non-short-circuit bitwise AND operator (`&`) to guarantee constant-time execution:
```java
// src/main/java/example/security/PasswordVerifier.java:42-44
        try {
            boolean matches = MessageDigest.isEqual(actual, expected);
            return validRecord && matches;
        } finally {
```

## 6. Verified Controls and Checks With No Finding
- Parameterized SQL Queries: Verified that queries in `AuthenticationService.java` (lines 89-102 and 111-130) strictly use `PreparedStatement` with positional parameters (`?`) for both rate-limit upserts and credential lookups. No string concatenation or dynamic SQL formatting is present.
- Database Connection URL Injection Prevention: Verified that `DatabaseConfig.java` (lines 8-15) validates all environment parameters against strict allowlists in `InputValidator.java` (`requireHost`, `requirePort`, `requireSqlIdentifier`), preventing connection URL parameter injection or host header manipulation.
- Strict TLS Enforcement: Verified that `DatabaseConfig.java` (line 15) hardcodes `sslmode=verify-full`, ensuring TLS encryption is mandatory and full server certificate hostname validation is enforced.
- Robust Password Hash Algorithm and Cost: Verified that `PasswordVerifier.java` (lines 11-14) uses `PBKDF2WithHmacSHA256` with 600,000 iterations, 16-byte cryptographically secure salts, and 32-byte hash lengths, conforming to modern OWASP and NIST SP 800-63B password storage standards.
- In-Memory Credential Sanitization: Verified that `SecureAuthApplication.java` (lines 48-50) wipes the user's password `char[]` with `Arrays.fill(password, '\0')` in a `finally` block; `PasswordVerifier.java` (lines 54 and 60-62) calls `PBEKeySpec.clearPassword()` and wipes `dummySalt`/`dummyHash`; and `AuthenticationService.java` (lines 54 and 57) zeroes `boundedPassword`, `salt`, and `passwordHash` arrays.
- Sensitive Data Masking and Logging: Verified that `SecureAuthApplication.java` (lines 44-45) logs only the simple class name of caught exceptions (`event type={0}`) and emits generic messages (`Authentication unsuccessful.`) to standard output. Passwords, hashes, salts, SQL statements, and database connection strings are never logged or exposed.
- Console and Terminal Protection: Verified that `SecureAuthApplication.java` (lines 17-26) rejects all command-line arguments to prevent passwords in process tables, and requires `System.console() != null` with `console.readPassword()` to suppress terminal echo and prevent input leakage via redirection or pipes.
- Database Least Privilege: Verified that `database/schema.sql` (lines 24-26) restricts `auth_runtime` permissions to `SELECT` on `app_user` and `SELECT, INSERT, UPDATE` on `auth_rate_limit`, explicitly revoking `DELETE` and `TRUNCATE`.
- Dependency Pinning and Integrity Verification: Verified that `pom.xml` (lines 17-22) pins `org.postgresql:postgresql:42.7.13` and that `scripts/verify-pgjdbc.sh` verifies the driver against a predefined SHA-512 checksum prior to build execution.
