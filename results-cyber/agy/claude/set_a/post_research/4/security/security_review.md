# Security Review: secure-accounts

## 1. Executive Summary
The `secure-accounts` component is a Java 17 service and CLI utility designed to provide user account registration, credential storage, authentication, and session management. It uses an embedded SQLite database, hashes passwords with Argon2id using Bouncy Castle, issues cryptographically secure 256-bit random session tokens stored as SHA-256 digests, and implements per-source and per-account rate limiting.

Overall, the codebase incorporates strong security engineering practices, including parameterized queries (`PreparedStatement`) across all SQL statements, in-memory credential zeroing (`Wipe`), constant-time hash verification (`MessageDigest.isEqual`), strict input allowlisting and NFKC Unicode normalization, and anti-enumeration protections (decoy hashing and unified error responses). However, several security issues were identified during this review:
1. Active sessions are not checked against account disabled status during session resolution, allowing disabled or terminated accounts to maintain authorized access until session expiration.
2. Account throttling is keyed to the user-supplied identifier rather than the resolved canonical account, allowing an attacker to double brute-force attempts and persistently lock out usernames without user remediation.
3. Successful authentications unconditionally increment the source throttle budget without ever being refunded or cleared, causing denial of service for users sharing an IP address or proxy.
4. Registration and authentication share a single source rate-limiting counter, allowing cross-endpoint denial of service.
5. SQLite WAL auxiliary files (`-wal`, `-shm`) created dynamically at runtime bypass startup file permission restrictions when placed outside the protected data directory.
6. The password rehash detection logic omits checking the Argon2 parallelism setting.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `pom.xml` | Maven build definition and dependency declarations | Pins Bouncy Castle, sqlite-jdbc, and slf4j-nop versions with fail checksum policy |
| `src/main/java/com/example/accounts/App.java` | CLI interface for `register`, `login`, `whoami`, `logout` | Masked terminal secret input, session token file I/O with `0600` permissions, input wiping |
| `src/main/java/com/example/accounts/Config.java` | Application runtime configuration loader | Validates environment variables, enforces minimum Argon2 parameters and timeouts, sets `0700` on data directory |
| `src/main/java/com/example/accounts/Database.java` | SQLite connection factory and schema migration | Sets PRAGMAs (`WAL`, `IMMEDIATE`, `foreign_keys`), restricts file permissions, atomic transaction execution |
| `src/main/java/com/example/accounts/AccountRepository.java` | SQL queries for the `account` table | Parameterized `PreparedStatement` queries, handles unique constraint violations |
| `src/main/java/com/example/accounts/AccountService.java` | Orchestration for account registration, authentication, and session validation | Enforces anti-enumeration logic, decoy hash verification, rate limiting, and password rehash triggers |
| `src/main/java/com/example/accounts/PasswordHasher.java` | Argon2id KDF hashing and verification | SecureRandom salt generation, constant-time compare (`MessageDigest.isEqual`), PHC string parsing, pepper mixing |
| `src/main/java/com/example/accounts/InputValidator.java` | Validation and canonicalization of user inputs | Allowlist validation, email RFC restrictions, username NFKC normalization and reserved name checks, password policy checks |
| `src/main/java/com/example/accounts/ThrottleService.java` | Rate limiting and attempt counting | SQLite-backed sliding-window attempt counter per source and per account, SHA-256 key hashing, pruning |
| `src/main/java/com/example/accounts/SessionService.java` | Server-side session management | Generates 32-byte SecureRandom tokens, stores SHA-256 token digests, enforces idle and absolute timeouts, session revocation |
| `src/main/java/com/example/accounts/SessionCookie.java` | HTTP `Set-Cookie` header builder | Builds `__Host-session` cookie with `Path=/`, `HttpOnly`, `Secure`, and `SameSite=Strict` |
| `src/main/java/com/example/accounts/Logging.java` | Logging configuration and formatting | Creates `0600` private log file, sanitizes newlines to prevent log injection |
| `src/main/java/com/example/accounts/Mask.java` | Sensitive identifier masking | Masks email, username, and JDBC URLs for safe logging |
| `src/main/java/com/example/accounts/Wipe.java` | In-memory credential erasure | Overwrites `char[]` and `byte[]` arrays with zero bytes |
| `src/main/java/com/example/accounts/Hex.java` | Hexadecimal byte encoding | Constant-case lowercase hex formatting for digests |
| `src/main/java/com/example/accounts/ValidationException.java` | User input validation failure | Generic exception messaging revealing no server-side state |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Reviewed Argon2id KDF implementation, cost parameters (memory, iterations, parallelism), salt generation entropy via `SecureRandom`, constant-time digest comparison (`MessageDigest.isEqual`), SHA-256 digest storage for session tokens and throttle keys, and secret pepper isolation.
- `testing-api-authentication-weaknesses`: Reviewed authentication flows, session token lifecycle, revocation logic, idle and absolute timeout calculations, and credential handling.
- `implementing-api-rate-limiting-and-throttling`: Reviewed request attempt limiting, sliding window rate limits, per-account and per-source throttling counters, and lockout behaviors.
- `testing-for-sensitive-data-exposure`: Reviewed handling of secrets in memory (zeroing with `Wipe`), filesystem permissions (`0700` and `0600`), masking of identifiers in log statements (`Mask.java`), and suppression of credentials in CLI arguments.
- `exploiting-sql-injection-vulnerabilities`: Reviewed SQL query construction across `AccountRepository`, `Database`, `ThrottleService`, and `SessionService` to ensure parameter binding via `PreparedStatement`.
- General OWASP Top 10 / CWE knowledge: Reviewed input validation and Unicode canonicalization/homoglyph handling (`InputValidator`), account enumeration resistance in registration/login (`AccountService`), SQLite WAL file permission edge cases (`Database`), and transaction isolation/concurrency controls (`Database.inTransaction`).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Active Sessions for Disabled Accounts Are Not Checked During Session Validation | High | CWE-284 | `src/main/java/com/example/accounts/SessionService.java:39-42` |
| SEC-02 | Account Throttling Keyed on User-Supplied Identifier Allows Rate-Limit Bypass and Persistent Denial of Service | Medium | CWE-307 | `src/main/java/com/example/accounts/AccountService.java:157-166` |
| SEC-03 | Successful Logins Unconditionally Consume Source Failure Budget Causing Denial of Service for Shared Networks | Medium | CWE-400 | `src/main/java/com/example/accounts/ThrottleService.java:100-118` |
| SEC-04 | Shared Source Rate-Limiting Counter Enables Cross-Action Denial of Service Between Registration and Authentication | Low | CWE-799 | `src/main/java/com/example/accounts/AccountService.java:114-117` |
| SEC-05 | SQLite WAL and Shared Memory Files Created with Default Umask Outside Data Directory | Low | CWE-732 | `src/main/java/com/example/accounts/Database.java:113-124` |
| SEC-06 | Hash Upgrade Policy in `PasswordHasher.needsRehash` Ignores Argon2 Parallelism Parameter | Low | CWE-916 | `src/main/java/com/example/accounts/PasswordHasher.java:115-118` |

## 5. Detailed Findings

### SEC-01: Active Sessions for Disabled Accounts Are Not Checked During Session Validation
- **Severity:** High
- **CWE:** CWE-284: Improper Access Control
- **Location:** `src/main/java/com/example/accounts/SessionService.java:39-42`

**Vulnerable code:**
```java
// src/main/java/com/example/accounts/SessionService.java:39-42
    private static final String SELECT_SQL = """
            SELECT session_ref, account_id, last_used_at, absolute_expires_at, revoked
            FROM auth_session WHERE token_hash = ?
            """;
```

**Why it is a problem:**
When an account is flagged as disabled (`disabled = 1` in the `account` table), `AccountService.authenticate()` properly refuses new login attempts. However, existing active sessions for that account in `auth_session` are not revoked, and `SessionService.validate()` queries only the `auth_session` table without checking the account's disabled status in the `account` table.

As a result, if an administrative action or security policy disables an account (e.g., following an employee termination or compromise detection), any existing valid session token continues to be accepted by `SessionService.validate()` and `AccountService.resolveSession()` until its absolute timeout expires (which can be up to 7 days by configuration). The disabled user or attacker holding that session token remains fully authorized to act on behalf of the account.

**Fix:**
Join the `account` table in `SELECT_SQL` to ensure the associated account exists and is not disabled (`disabled = 0`):
```java
    private static final String SELECT_SQL = """
            SELECT s.session_ref, s.account_id, s.last_used_at, s.absolute_expires_at, s.revoked
            FROM auth_session s
            JOIN account a ON s.account_id = a.id
            WHERE s.token_hash = ? AND a.disabled = 0
            """;
```

---

### SEC-02: Account Throttling Keyed on User-Supplied Identifier Allows Rate-Limit Bypass and Persistent Denial of Service
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/example/accounts/AccountService.java:157-166`

**Vulnerable code:**
```java
// src/main/java/com/example/accounts/AccountService.java:157-166
        Decisionable gate = database.inTransaction(connection -> {
            ThrottleService.Decision decision =
                    throttle.tryAcquire(connection, source, lookupKey, now);
            if (!decision.allowed()) {
                return new Decisionable(decision, null);
            }
            Optional<AccountRepository.Account> account =
                    lookupKey == null ? Optional.empty() : accounts.findByLogin(connection, lookupKey);
            return new Decisionable(decision, account.orElse(null));
        });
```

**Why it is a problem:**
Accounts in this system can be authenticated using either their canonical email or canonical username (`SELECT ... WHERE email_canonical = ? OR username_canonical = ?`). Because `throttle.tryAcquire` is executed using the raw client-supplied identifier `lookupKey` before account lookup occurs, the system creates two completely independent rate-limiting buckets for the same account: `key("account", username)` and `key("account", email)`.

This leads to two distinct vulnerabilities:
1. **Brute-Force Allowance Doubling:** An attacker targeting a specific user can attempt `ACCOUNTS_MAX_FAILURES_PER_ACCOUNT` guesses against the username, and when that counter triggers `ACCOUNT_THROTTLED`, immediately switch to guessing against the email address for another `ACCOUNTS_MAX_FAILURES_PER_ACCOUNT` attempts.
2. **Persistent Lockout / DoS:** An attacker can intentionally trigger an account lockout on a victim's username by submitting bad passwords. When the legitimate victim signs in using their email address, the login succeeds, but `AccountService` (line 203) calls `throttle.clearAccount(connection, lookupKey, now)` where `lookupKey` is the email address. The victim's username bucket remains locked out until the 15-minute sliding window expires, denying legitimate login by username.

**Fix:**
Lookup the account prior to evaluating the account throttle key, bind the throttle counter to the canonical account ID, and ensure that both username and email identifier counters are cleared upon successful authentication:
```java
        Decisionable gate = database.inTransaction(connection -> {
            Optional<AccountRepository.Account> account =
                    lookupKey == null ? Optional.empty() : accounts.findByLogin(connection, lookupKey);
            String accountThrottleKey = account
                    .map(a -> "acct:" + a.id())
                    .orElse(lookupKey == null ? null : "raw:" + lookupKey);

            ThrottleService.Decision decision =
                    throttle.tryAcquire(connection, source, accountThrottleKey, now);
            if (!decision.allowed()) {
                return new Decisionable(decision, null);
            }
            return new Decisionable(decision, account.orElse(null));
        });
```

---

### SEC-03: Successful Logins Unconditionally Consume Source Failure Budget Causing Denial of Service for Shared Networks
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/example/accounts/ThrottleService.java:100-118`

**Vulnerable code:**
```java
// src/main/java/com/example/accounts/ThrottleService.java:100-118
    public Decision tryAcquire(Connection connection, String sourceId, String accountIdentifier,
                               Instant now) throws SQLException {
        long cutoff = windowCutoff(now);
        String sourceKey = key(SCOPE_SOURCE, sourceId);
        if (failures(connection, SCOPE_SOURCE, sourceKey, cutoff) >= config.maxFailuresPerSource()) {
            return Decision.SOURCE_THROTTLED;
        }
        String accountKey = accountIdentifier == null ? null : key(SCOPE_ACCOUNT, accountIdentifier);
        if (accountKey != null
                && failures(connection, SCOPE_ACCOUNT, accountKey, cutoff)
                        >= config.maxFailuresPerAccount()) {
            return Decision.ACCOUNT_THROTTLED;
        }
        bump(connection, SCOPE_SOURCE, sourceKey, now, cutoff);
        if (accountKey != null) {
            bump(connection, SCOPE_ACCOUNT, accountKey, now, cutoff);
        }
        prune(connection, cutoff);
        return Decision.ALLOW;
    }
```

**Why it is a problem:**
`ThrottleService.tryAcquire` runs before authentication and unconditionally increments the `failures` counter for `SCOPE_SOURCE` on lines 113–115. While a successful authentication clears the `SCOPE_ACCOUNT` counter via `clearAccount`, `ThrottleService` deliberately never resets or decrements `SCOPE_SOURCE` (as noted in lines 125–128).

As a result, successful logins are counted as failures against `ACCOUNTS_MAX_FAILURES_PER_SOURCE` (default 25). In any shared network environment (e.g. corporate NAT, university campus, mobile gateway, or shared multi-user server), 25 legitimate, successful logins within a 15-minute window will consume the entire source budget. When the 26th user attempts to log in with valid credentials, the attempt is rejected with `SOURCE_THROTTLED` ("Too many attempts. Please try again later."), causing an unintentional Denial of Service.

**Fix:**
Only record failures in the source counter when authentication actually fails, or decrement the source counter when authentication succeeds:
```java
    public void recordFailure(Connection connection, String sourceId, String accountIdentifier,
                              Instant now) throws SQLException {
        long cutoff = windowCutoff(now);
        bump(connection, SCOPE_SOURCE, key(SCOPE_SOURCE, sourceId), now, cutoff);
        if (accountIdentifier != null) {
            bump(connection, SCOPE_ACCOUNT, key(SCOPE_ACCOUNT, accountIdentifier), now, cutoff);
        }
        prune(connection, cutoff);
    }
```

---

### SEC-04: Shared Source Rate-Limiting Counter Enables Cross-Action Denial of Service Between Registration and Authentication
- **Severity:** Low
- **CWE:** CWE-799: Improper Control of Interaction Frequency
- **Location:** `src/main/java/com/example/accounts/AccountService.java:114-117`

**Vulnerable code:**
```java
// src/main/java/com/example/accounts/AccountService.java:114-117
            boolean allowed = database.inTransaction(connection ->
                    // Source-only limiting: an attacker must not be able to burn a victim's
                    // *account* counter by repeatedly "registering" their address.
                    throttle.tryAcquire(connection, source, null, now).allowed());
```

**Why it is a problem:**
In `AccountService.register`, registration requests call `throttle.tryAcquire(connection, source, null, now)`. In `AccountService.authenticate`, login attempts call `throttle.tryAcquire(connection, source, lookupKey, now)`. Both methods pass the request source identifier and share the same static scope: `SCOPE_SOURCE = "source"`.

Because both actions update and check the exact same row in `auth_attempt`, rate-limiting events on registration directly interfere with authentication and vice-versa. An attacker performing registration requests from an IP address can exhaust the source limit, blocking legitimate users at that IP from logging in. Conversely, failed login attempts will block registration for users sharing that source.

**Fix:**
Partition source rate-limiting scopes by action, for example `"source_auth"` and `"source_reg"`:
```java
    private static final String SCOPE_ACCOUNT = "account";
    private static final String SCOPE_SOURCE_AUTH = "source_auth";
    private static final String SCOPE_SOURCE_REGISTER = "source_reg";
```

---

### SEC-05: SQLite WAL and Shared Memory Files Created with Default Umask Outside Data Directory
- **Severity:** Low
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `src/main/java/com/example/accounts/Database.java:113-124`

**Vulnerable code:**
```java
// src/main/java/com/example/accounts/Database.java:113-124
        for (String suffix : new String[] {"", "-wal", "-shm", "-journal"}) {
            Path p = suffix.isEmpty() ? base : Paths.get(pathPart + suffix);
            try {
                if (Files.exists(p) && !Files.isSymbolicLink(p)
                        && p.getFileSystem().supportedFileAttributeViews().contains("posix")) {
                    Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-------"));
                }
            } catch (IOException | UnsupportedOperationException e) {
                log.log(Level.WARNING, "could not restrict permissions on database file", e);
            }
        }
```

**Why it is a problem:**
`Database.open()` executes `restrictDatabaseFilePermissions(url)` once during database connection initialization. In SQLite with WAL mode (`journal_mode=WAL`), the `-wal` and `-shm` files are created dynamically during the first write transaction. If these files do not exist when `open()` is called, the loop encounters `Files.exists(p) == false` and does nothing.

When `register` or `login` subsequently executes, the SQLite driver creates `accounts.db-wal` and `accounts.db-shm` under the process umask (typically `0644`). If `ACCOUNTS_JDBC_URL` is configured to point outside `ACCOUNTS_DATA_DIR` (e.g., in a shared directory such as `/var/db/accounts.db`), these files are created with world-readable permissions, exposing uncheckpointed password hashes and session digests to other local users.

**Fix:**
Pre-create the auxiliary WAL and shared memory files with restricted permissions (`rw-------`), or enforce that the database directory is restricted:
```java
        for (String suffix : new String[] {"", "-wal", "-shm", "-journal"}) {
            Path p = suffix.isEmpty() ? base : Paths.get(pathPart + suffix);
            try {
                if (!Files.exists(p)) {
                    if (p.getFileSystem().supportedFileAttributeViews().contains("posix")) {
                        Files.createFile(p, PosixFilePermissions.asFileAttribute(
                                PosixFilePermissions.fromString("rw-------")));
                    }
                } else if (!Files.isSymbolicLink(p)
                        && p.getFileSystem().supportedFileAttributeViews().contains("posix")) {
                    Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-------"));
                }
            } catch (IOException | UnsupportedOperationException e) {
                log.log(Level.WARNING, "could not restrict permissions on database file", e);
            }
        }
```

---

### SEC-06: Hash Upgrade Policy in `PasswordHasher.needsRehash` Ignores Argon2 Parallelism Parameter
- **Severity:** Low
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `src/main/java/com/example/accounts/PasswordHasher.java:115-118`

**Vulnerable code:**
```java
// src/main/java/com/example/accounts/PasswordHasher.java:115-118
                return parsed.memoryKib < settings.memoryKib()
                        || parsed.iterations < settings.iterations()
                        || parsed.hash.length < HASH_LENGTH
                        || parsed.salt.length < SALT_LENGTH;
```

**Why it is a problem:**
`PasswordHasher.needsRehash()` is used during login to detect whether an account's stored password hash was generated with older, weaker Argon2 cost parameters and automatically rehash the password with current settings. It checks `memoryKib`, `iterations`, `hash.length`, and `salt.length`, but omits `parallelism`.

If the system configuration is updated to increase `ACCOUNTS_ARGON2_PARALLELISM` (e.g., from 1 to 4 to utilize multi-core processing or raise hashing resistance), existing accounts will never be flagged for an automatic upgrade on login, remaining at the legacy parallelism factor.

**Fix:**
Include `parsed.parallelism < settings.parallelism()` in the check:
```java
                return parsed.memoryKib < settings.memoryKib()
                        || parsed.iterations < settings.iterations()
                        || parsed.parallelism < settings.parallelism()
                        || parsed.hash.length < HASH_LENGTH
                        || parsed.salt.length < SALT_LENGTH;
```

## 6. Verified Controls and Checks With No Finding
- SQL Injection Defense: Verified all queries in `AccountRepository`, `ThrottleService`, `SessionService`, and `Database` use parameterized `PreparedStatement` with bind parameters; no dynamic SQL string concatenation exists in the codebase.
- Password Hashing Algorithm & Work Factor: Verified Argon2id is implemented via Bouncy Castle with parameters meeting or exceeding OWASP guidelines (`m=64 MiB, t=3, p=1` by default, with strict validation minimums `m >= 19 MiB, t >= 2, p >= 1`).
- Cryptographic Salt Quality: Verified salts are 16 bytes generated per hash using `java.security.SecureRandom`, preventing precomputation and rainbow table attacks.
- Constant-Time Comparison: Verified `MessageDigest.isEqual` is used to compare hash digests in `PasswordHasher.verify()`, eliminating timing side channels.
- In-Memory Secret Sanitization: Verified plaintext passwords and session tokens are manipulated using `char[]` and `byte[]` arrays rather than immutable `String` objects, and cleared via `Wipe.chars()` and `Wipe.bytes()` in `finally` blocks.
- Account Enumeration Resistance: Verified `AccountService` issues identical generic responses for successful vs duplicate registrations, and executes comparable work (using `hasher.newDecoyHash()`) for existent and non-existent accounts on authentication failure.
- Session Token Generation and Storage: Verified session tokens consist of 32 cryptographically secure random bytes from `SecureRandom` (43 unpadded base64url characters), stored exclusively as SHA-256 hashes in the database with separate non-secret 16-byte session references for logging.
- Session Cookie Security: Verified `SessionCookie.setCookieHeader()` enforces the `__Host-session` prefix, `Path=/`, `HttpOnly`, `Secure`, and `SameSite=Strict` attributes, without specifying `Domain`.
- Log Injection (CWE-117) Protection: Verified `Logging.PlainFormatter` strips and escapes carriage returns, newlines, and Unicode line-break characters (`\r`, `\n`, `\u0085`, `\u2028`, `\u2029`) into literal `\n` to prevent log forging.
- Sensitive Data Masking: Verified `Mask.email`, `Mask.username`, and `Mask.jdbcUrl` obfuscate PII and credentials prior to logging, and passwords/tokens are never logged.
- Input Allowlisting and Unicode Normalization: Verified email inputs are restricted to an ASCII subset with length bounds (254 total, 64 local, 63 per domain label), and usernames are normalized using Unicode NFKC normalization prior to case folding and allowlist checking, preventing homoglyph impersonation.
- Session Invalidation on Logout: Verified `SessionService.revoke()` marks the session revoked in the database and `SessionCookie.clearCookieHeader()` issues a `Max-Age=0` clearing header.
