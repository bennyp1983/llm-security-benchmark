# Security Review: Secure CLI Authentication Service

## 1. Executive Summary
The target component is a command-line user authentication and account seeding service implemented in Java using embedded H2 SQL storage. It accepts an email address and password via console prompt or standard input, verifies credentials against stored PBKDF2-HMAC-SHA256 digests, tracks brute-force and credential stuffing attempts across dual rate-limiting budgets (identity and source), issues cryptographically secure 256-bit bearer session tokens, and logs security events to a restricted append-only audit trail. The codebase places strong emphasis on defensive engineering, including input canonicalization, parameterized SQL queries, memory wiping of credentials, constant-time comparisons, and equal-work derivation to mitigate timing side-channels.

Despite these extensive controls, the security review identified several vulnerabilities:
1. **Malformed Email Rate-Limiting Bypass (CPU DoS):** In `AuthService`, email syntax validation occurs before rate-limit reservation. Requests with invalid email formats trigger expensive PBKDF2 derivations (210,000 iterations) without consuming either identity or source budget slots, allowing unauthenticated attackers to exhaust server CPU resources without being throttled.
2. **Missing Source Budget Refund on Successful Authentication (DoS):** While the threat model and documentation state that successful sign-ins should consume no source budget, `AuthService.grant()` only refunds the per-identity budget. Consequently, repeated legitimate logins from a shared network address or deliberate valid authentications by an attacker will permanently deplete the source budget, causing all subsequent authentication attempts from that source to be locked out.
3. **Missing Symlink and Permission Check on Existing Database Files:** `Database.open()` verifies the parent directory but omits `requirePrivateRegularFile()` checks on the database file itself prior to connecting with JDBC, allowing H2 to follow symbolic links if a target file already existed.
4. **Audit Log Size Cap Circumvention Across Invocations:** The 4MB audit log size cap is tracked only in an in-memory counter initialized to 0 on every CLI process execution rather than from disk size, allowing unbounded disk growth across runs.
5. **Unbounded Storage Growth in Session and Throttle Tables:** Neither expired session tokens nor stale throttle records are purged during normal operational execution.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/auth/Main.java` | CLI entry point and process lifecycle (`login`, `seed`, `help`) | Reads credentials via `Console.readPassword` or strict UTF-8 stdin into `char[]`; prevents credentials from entering `argv` or heap `String` objects; enforces uniform failure messages on stdout; halts JVM via `Runtime.halt()` to prevent shutdown hook interference. |
| `src/main/java/com/example/auth/Config.java` | Configuration loading and validation from environment | Loads configuration from environment variables; validates numeric bounds, table names, and paths fail-closed; ensures `sourceMaxAttempts >= identityMaxFailures`; handles DB password as `char[]` and wipes on handoff. |
| `src/main/java/com/example/auth/Database.java` | JDBC connection and schema management | Configures H2 connection URL with security options (`TRACE_LEVEL_FILE=0`, `ACCESS_MODE_DATA=rw-------`); uses parameterized `PreparedStatement` queries; quotes allowlisted table identifiers; validates stored row parameters upon retrieval. |
| `src/main/java/com/example/auth/DbPathGuard.java` | Filesystem permission validation | Verifies paths are owned by the current user, have no group/world permissions (`0700` for directories, `0600` for files), and rejects symbolic links. |
| `src/main/java/com/example/auth/DbFiles.java` | Secure file creation utilities | Creates owner-only files and directories using POSIX attributes and explicit post-creation hardening. |
| `src/main/java/com/example/auth/PosixPermissions.java` | POSIX permission definitions | Defines owner-only constant permission sets `0600` (`rw-------`) and `0700` (`rwx------`). |
| `src/main/java/com/example/auth/CryptoUtils.java` | Cryptographic helper utilities | Provides `SecureRandom` generation, SHA-256 digests, constant-time byte comparisons, hex conversions, and buffer zeroing (`wipe`). |
| `src/main/java/com/example/auth/PasswordHasher.java` | Password hashing and verification | Implements `PBKDF2WithHmacSHA256` key derivation (default 210,000 iterations); uses 16-byte random salts and deterministic blind salts for non-existent users; wipes `PBEKeySpec` in `finally`. |
| `src/main/java/com/example/auth/InputValidator.java` | Input validation and normalization | Enforces strict validation on email addresses (printable ASCII, no punycode, case-folded), passwords (12-1024 chars, no surrogates, no control chars), tokens (64 lowercase hex), and DB paths (no `;` or `=`). |
| `src/main/java/com/example/auth/AuthService.java` | Core authentication and rate-limiting coordinator | Coordinates equal-work derivations, wall-clock timing padding (`minLoginMs`), dual budget reservation, credential checks, and session issuance. |
| `src/main/java/com/example/auth/SessionStore.java` | Server-side session management | Generates 256-bit `SecureRandom` session tokens; stores only SHA-256 token hashes in SQL; performs atomic revocations and verifies validity against expiration timestamps. |
| `src/main/java/com/example/auth/ThrottleStore.java` | Transactional rate-limiting store | Manages dual-budget tracking (identity and source) using transactional `SELECT ... FOR UPDATE` row locks in sorted key order to prevent race conditions and deadlocks; handles clock skew. |
| `src/main/java/com/example/auth/AccountSeeder.java` | Account provisioning logic | Creates accounts with unique salts and PBKDF2 digests; enforces password confirmation; rejects overwriting existing accounts via database unique index. |
| `src/main/java/com/example/auth/LogWriter.java` | Append-only audit logger | Masks email identifiers (`a***@domain.com`); sanitizes lines against an allowlisted character set (blocking CRLF injection); creates log file mode 0600; applies total byte size capping. |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to PBKDF2-HMAC-SHA256 parameters, CSPRNG usage in token/salt generation, constant-time comparisons, and blind salt construction.
- `testing-api-authentication-weaknesses`: Applied to authentication workflows, credential handling, session issuance, token verification, and equal-work timing mitigations.
- `implementing-api-rate-limiting-and-throttling`: Applied to identity and source budget accounting, concurrency row locking, and lockout recovery logic.
- `performing-api-rate-limiting-bypass`: Applied to assessing potential bypasses of rate-limiting controls via input variation or malformed headers/payloads.
- `exploiting-sql-injection-vulnerabilities`: Applied to SQL query construction, dynamic identifier quotation, and JDBC URL parameter handling.
- Review against general OWASP Top 10 / CWE knowledge (CWE-59, CWE-732, CWE-400, CWE-770, CWE-214): Applied to file permissions, symbolic link handling, environment variable handling, and audit log size enforcement.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Malformed Email Input Bypasses Rate Limiting and Triggers Unbounded PBKDF2 Computations (CPU DoS) | High | CWE-400 | `src/main/java/com/example/auth/AuthService.java:126-173` |
| SEC-02 | Successful Logins Fail to Refund Source Budget Counter, Enabling Source Lockout / Denial of Service | High | CWE-400 | `src/main/java/com/example/auth/AuthService.java:272-291` |
| SEC-03 | Missing Symlink and Permission Verification on Existing Database File Prior to Connection | Medium | CWE-59 | `src/main/java/com/example/auth/Database.java:69-76` |
| SEC-04 | Audit Log Size Cap Not Initialized From Existing File Size Across CLI Invocations | Low | CWE-400 | `src/main/java/com/example/auth/LogWriter.java:67-94` |
| SEC-05 | Missing Automated Purge of Expired Sessions and Throttle Records | Low | CWE-770 | `src/main/java/com/example/auth/SessionStore.java:134-145` |

## 5. Detailed Findings

### SEC-01: Malformed Email Input Bypasses Rate Limiting and Triggers Unbounded PBKDF2 Computations (CPU DoS)
- **Severity:** High
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/example/auth/AuthService.java:126-173`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AuthService.java:126-173
            String normalised = InputValidator.requireEmail(email);
            masked = LogWriter.maskEmail(normalised);
            String identityHash = identityHash(normalised);

            List<ThrottleStore.BudgetKey> budgets =
                    ThrottleStore.attemptBudgets(identityHash, config.sourceId(), config);
            boolean slot;
            boolean budgetKnown = true;
            try {
                slot = throttles.reserve(budgets, clock.epochMillis());
            } catch (Database.StorageException e) {
                // Fail closed on the counter itself: if the throttle store cannot be trusted, an
                // attacker who corrupted or filled it would otherwise get unlimited attempts.
                logDbFailure(e);
                slot = false;
                budgetKnown = false;
            }
            if (!budgetKnown) {
                reason = Reason.STORAGE;
                log.log(LogWriter.Event.LOGIN_THROTTLED, masked, reason.code());
                workEqualDerivation(normalised);
            } else if (!slot) {
                reason = Reason.BUDGET_SPENT;
                log.log(LogWriter.Event.LOGIN_THROTTLED, masked, reason.code());
                workEqualDerivation(normalised);
            } else {
                PasswordCheck check = checkCredential(normalised, identityHash, password);
                reason = check.reason;
                if (check.granted) {
                    token = grant(check.identityId, identityHash, masked);
                    if (token != null) {
                        outcome = Outcome.GRANTED;
                        reason = Reason.CREDENTIAL_MATCH;
                        log.log(LogWriter.Event.LOGIN_SUCCESS, masked, reason.code());
                    } else {
                        // Right password, but the session could not be recorded server-side.
                        reason = Reason.STORAGE;
                    }
                } else {
                    log.log(LogWriter.Event.LOGIN_DENIED, masked, reason.code());
                }
            }
        } catch (InputValidator.ValidationException e) {
            reason = e.getMessage() != null && e.getMessage().startsWith("password")
                    ? Reason.INVALID_PASSWORD : Reason.INVALID_EMAIL;
            log.log(LogWriter.Event.LOGIN_INVALID_INPUT, masked, reason.code());
            workEqualDerivation(null);
        }
```

**Why it is a problem:**
In `AuthService.authenticate()`, `InputValidator.requireEmail(email)` is evaluated on line 126 before `throttles.reserve()` is called on line 135. When an invalid or malformed email address is provided (such as an empty string, missing `@`, or unallowed characters), `requireEmail()` throws a `ValidationException`. Execution immediately jumps to the catch block on lines 168-173, bypassing budget reservation entirely. Inside the catch block, `workEqualDerivation(null)` is invoked, executing a full 210,000-iteration PBKDF2 calculation. Because neither the identity counter nor the source budget counter is incremented, an attacker can flood the service with malformed authentication requests that trigger maximum CPU hashing workload while completely bypassing rate-limiting controls.

**Fix:**
Apply source budget rate limiting to all requests before executing `workEqualDerivation(null)`, or reserve a slot in the source-level budget even when input validation fails:
```java
        List<ThrottleStore.BudgetKey> sourceOnlyBudget = List.of(
                ThrottleStore.sourceBudget(config.sourceId(), config.sourceMaxAttempts(), config.sourceWindowSec()));
        try {
            String normalised = InputValidator.requireEmail(email);
            masked = LogWriter.maskEmail(normalised);
            String identityHash = identityHash(normalised);

            List<ThrottleStore.BudgetKey> budgets =
                    ThrottleStore.attemptBudgets(identityHash, config.sourceId(), config);
            boolean slot;
            boolean budgetKnown = true;
            try {
                slot = throttles.reserve(budgets, clock.epochMillis());
            } catch (Database.StorageException e) {
                logDbFailure(e);
                slot = false;
                budgetKnown = false;
            }
            if (!budgetKnown) {
                reason = Reason.STORAGE;
                log.log(LogWriter.Event.LOGIN_THROTTLED, masked, reason.code());
                workEqualDerivation(normalised);
            } else if (!slot) {
                reason = Reason.BUDGET_SPENT;
                log.log(LogWriter.Event.LOGIN_THROTTLED, masked, reason.code());
                workEqualDerivation(normalised);
            } else {
                PasswordCheck check = checkCredential(normalised, identityHash, password);
                reason = check.reason;
                if (check.granted) {
                    token = grant(check.identityId, identityHash, masked);
                    if (token != null) {
                        outcome = Outcome.GRANTED;
                        reason = Reason.CREDENTIAL_MATCH;
                        log.log(LogWriter.Event.LOGIN_SUCCESS, masked, reason.code());
                    } else {
                        reason = Reason.STORAGE;
                    }
                } else {
                    log.log(LogWriter.Event.LOGIN_DENIED, masked, reason.code());
                }
            }
        } catch (InputValidator.ValidationException e) {
            reason = e.getMessage() != null && e.getMessage().startsWith("password")
                    ? Reason.INVALID_PASSWORD : Reason.INVALID_EMAIL;
            log.log(LogWriter.Event.LOGIN_INVALID_INPUT, masked, reason.code());
            boolean sourceSlot = false;
            try {
                sourceSlot = throttles.reserve(sourceOnlyBudget, clock.epochMillis());
            } catch (Database.StorageException se) {
                logDbFailure(se);
            }
            if (sourceSlot) {
                workEqualDerivation(null);
            }
        }
```

---

### SEC-02: Successful Logins Fail to Refund Source Budget Counter, Enabling Source Lockout / Denial of Service
- **Severity:** High
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/example/auth/AuthService.java:272-291`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AuthService.java:272-291
    private String grant(long identityId, String identityHash, String masked) {
        String token;
        try {
            token = sessions.issue(identityId, config.sessionTtlSec(), config.sourceId());
        } catch (Database.StorageException e) {
            logDbFailure(e);
            return null;
        }
        try {
            throttles.refund(ThrottleStore.identityBudget(identityHash,
                    config.identityMaxFailures(), config.identityWindowSec()), clock.epochMillis());
            log.log(LogWriter.Event.COUNTER_REFUNDED, masked, 0);
        } catch (Database.StorageException e) {
            // The refund is a courtesy to the legitimate owner. Failing to refund must not revoke an
            // otherwise valid session, and must not be silent.
            logDbFailure(e);
        }
        log.log(LogWriter.Event.SESSION_ISSUED, masked, 0);
        return token;
    }
```

**Why it is a problem:**
When an authentication attempt begins, `throttles.reserve()` reserves slots on both the `identityBudget` and the `sourceBudget`. In `grant()`, only the `identityBudget` is refunded. The `sourceBudget` remains decremented. The design documentation in `ThrottleStore.java` explicitly states:
*"Deliberate choice: a successful login refunds its own account budget (refund) and consumes no source slot. Otherwise an attacker holding one valid credential could keep spending budget with genuine authentications - or let a legitimate user's correct sign-ins do it for them - until the account or source is locked, turning the limit into a denial-of-service tool. Only failed and refused attempts are charged."*
Because the code fails to refund the source budget, legitimate users sharing a source (such as behind an office NAT, VPN, or CLI source identifier) will permanently consume source slots with every successful login. Once 120 valid logins occur within the 15-minute window, the source budget is exhausted and all subsequent authentication attempts from that source are denied. Additionally, an adversary with one valid account credential can deliberately log in repeatedly to lock out the entire source.

**Fix:**
Refund the source budget in `grant()` alongside the identity budget refund:
```java
    private String grant(long identityId, String identityHash, String masked) {
        String token;
        try {
            token = sessions.issue(identityId, config.sessionTtlSec(), config.sourceId());
        } catch (Database.StorageException e) {
            logDbFailure(e);
            return null;
        }
        try {
            throttles.refund(ThrottleStore.identityBudget(identityHash,
                    config.identityMaxFailures(), config.identityWindowSec()), clock.epochMillis());
            throttles.refund(ThrottleStore.sourceBudget(config.sourceId(),
                    config.sourceMaxAttempts(), config.sourceWindowSec()), clock.epochMillis());
            log.log(LogWriter.Event.COUNTER_REFUNDED, masked, 0);
        } catch (Database.StorageException e) {
            // The refund is a courtesy to the legitimate owner. Failing to refund must not revoke an
            // otherwise valid session, and must not be silent.
            logDbFailure(e);
        }
        log.log(LogWriter.Event.SESSION_ISSUED, masked, 0);
        return token;
    }
```

---

### SEC-03: Missing Symlink and Permission Verification on Existing Database File Prior to Connection
- **Severity:** Medium
- **CWE:** CWE-59: Improper Link Resolution Before File Access ('Link Following')
- **Location:** `src/main/java/com/example/auth/Database.java:69-76`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/Database.java:69-76
    static Database open(Config config, char[] dbPassword) throws StorageException {
        Path dbFile = Path.of(config.dbPath() + ".mv.db");
        try {
            DbPathGuard.verifiedParentDirectory(config.dbPath());
        } catch (IOException e) {
            throw new StorageException("db_location_rejected", e);
        }
        String url = "jdbc:h2:" + config.dbPath()
```

**Why it is a problem:**
`Database.open()` checks `DbPathGuard.verifiedParentDirectory()`, but does not inspect the database file itself (`dbFile`) before invoking `DriverManager.getConnection()`. Unlike `LogWriter.open()`, which checks `Files.isSymbolicLink(file)` and invokes `DbPathGuard.requirePrivateRegularFile(file)` before opening the audit log, `Database.open()` allows H2 to open the database file directly. If `store.mv.db` already exists as a symbolic link pointing to a sensitive file or has insecure permissions, H2 follows the symlink. The post-connection call to `hardenEngineFiles()` explicitly skips symbolic links (`Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)` returns false for symlinks) and ignores exceptions, leaving the target file exposed or corrupted.

**Fix:**
Verify that `dbFile` is not a symbolic link and conforms to private regular file requirements if it already exists before connecting:
```java
    static Database open(Config config, char[] dbPassword) throws StorageException {
        Path dbFile = Path.of(config.dbPath() + ".mv.db");
        try {
            DbPathGuard.verifiedParentDirectory(config.dbPath());
            if (Files.exists(dbFile, LinkOption.NOFOLLOW_LINKS)) {
                DbPathGuard.requirePrivateRegularFile(dbFile);
            }
        } catch (IOException e) {
            throw new StorageException("db_location_rejected", e);
        }
        String url = "jdbc:h2:" + config.dbPath()
```

---

### SEC-04: Audit Log Size Cap Not Initialized From Existing File Size Across CLI Invocations
- **Severity:** Low
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/example/auth/LogWriter.java:67-94`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/LogWriter.java:67-94
    private long written;
    private boolean capNotified;

    private LogWriter(Path file, Writer out) {
        this.file = file;
        this.out = out;
    }

    /**
     * Opens (creating if absent) the audit file. The parent directory must already have been
     * verified private; it is verified again here so this method is safe on its own.
     */
    static LogWriter open(Path file) throws IOException {
        Path parent = file.getParent();
        if (parent == null) {
            throw new IOException("audit_parent_missing");
        }
        DbPathGuard.requirePrivateDirectory(parent);
        if (Files.isSymbolicLink(file)) {
            throw new IOException("audit_file_is_symlink");
        }
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
            DbFiles.newPrivateFile(file).close();
        }
        DbPathGuard.requirePrivateRegularFile(file);
        return new LogWriter(file, Files.newBufferedWriter(file, StandardCharsets.UTF_8,
                StandardOpenOption.WRITE, StandardOpenOption.APPEND));
    }
```

**Why it is a problem:**
`LogWriter` intends to limit audit log file size to 4MB (`MAX_TOTAL_BYTES`) to prevent disk exhaustion. However, the byte counter `written` is initialized to 0 on every call to `LogWriter.open()`. Because each command execution (`login`, `seed`) runs as an independent short-lived process, `written` starts at 0 each time the CLI is invoked and appends new records. The 4MB cap is therefore only enforced within a single process execution rather than against the cumulative on-disk file size, allowing repeated invocations to grow the audit log file indefinitely.

**Fix:**
Initialize `written` with the existing file size (`Files.size(file)`) when opening the audit log:
```java
    private long written;
    private boolean capNotified;

    private LogWriter(Path file, Writer out, long initialBytes) {
        this.file = file;
        this.out = out;
        this.written = initialBytes;
    }

    /**
     * Opens (creating if absent) the audit file. The parent directory must already have been
     * verified private; it is verified again here so this method is safe on its own.
     */
    static LogWriter open(Path file) throws IOException {
        Path parent = file.getParent();
        if (parent == null) {
            throw new IOException("audit_parent_missing");
        }
        DbPathGuard.requirePrivateDirectory(parent);
        if (Files.isSymbolicLink(file)) {
            throw new IOException("audit_file_is_symlink");
        }
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
            DbFiles.newPrivateFile(file).close();
        }
        DbPathGuard.requirePrivateRegularFile(file);
        long currentSize = Files.size(file);
        return new LogWriter(file, Files.newBufferedWriter(file, StandardCharsets.UTF_8,
                StandardOpenOption.WRITE, StandardOpenOption.APPEND), currentSize);
    }
```

---

### SEC-05: Missing Automated Purge of Expired Sessions and Throttle Records
- **Severity:** Low
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `src/main/java/com/example/auth/SessionStore.java:134-145`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/SessionStore.java:134-145
    /** Deletes sessions whose expiry has passed. Bounded work; keeps the table from growing. */
    int purgeExpired() throws Database.StorageException {
        long now = System.currentTimeMillis() / 1000L;
        synchronized (database.jdbcLock()) {
            try (PreparedStatement ps = database.prepare(
                    "DELETE FROM " + table + " WHERE expires_at_epoch_sec <= ?")) {
                ps.setLong(1, now);
                return ps.executeUpdate();
            } catch (SQLException e) {
                throw new Database.StorageException("session_purge_failed", e);
            }
        }
    }
```

**Why it is a problem:**
`SessionStore` implements `purgeExpired()` to prune expired sessions, but this method is never invoked during any runtime operation (e.g. login, session issue, or session verify) and is only exercised in test suites. Similarly, `ThrottleStore` inserts rows into `auth_throttle` for every tested email address hash, but contains no mechanism to purge records whose rate-limiting window has elapsed. Over prolonged operation, both tables will grow continuously, consuming unbounded database storage.

**Fix:**
Trigger `purgeExpired()` during session issuance, and add a pruning query in `ThrottleStore` to delete expired throttle windows:
```java
    String issue(long identityId, int ttlSeconds, String sourceId) throws Database.StorageException {
        if (identityId <= 0) {
            throw new Database.StorageException("session_identity_invalid");
        }
        purgeExpired(); // Opportunistically prune expired session rows
        byte[] raw = CryptoUtils.randomBytes(32);
        String token = CryptoUtils.toHex(raw);
        CryptoUtils.wipe(raw);
        long now = System.currentTimeMillis() / 1000L;
        long expiresAt = now + ttlSeconds;
        if (expiresAt <= now) {
            throw new Database.StorageException("session_ttl_invalid");
        }
        synchronized (database.jdbcLock()) {
            try (PreparedStatement ps = database.prepare(
                    "INSERT INTO " + table
                            + " (token_hash, identity_id, issued_at_epoch_sec, expires_at_epoch_sec,"
                            + " source_id) VALUES (?,?,?,?,?)")) {
                ps.setString(1, CryptoUtils.toHex(CryptoUtils.sha256(token)));
                ps.setLong(2, identityId);
                ps.setLong(3, now);
                ps.setLong(4, expiresAt);
                ps.setString(5, sourceId);
                if (ps.executeUpdate() != 1) {
                    throw new Database.StorageException("session_insert_failed");
                }
            } catch (SQLException e) {
                throw new Database.StorageException("session_insert_failed", e);
            }
        }
        return token;
    }
```

## 6. Verified Controls and Checks With No Finding
- SQL Injection Prevention: Verified in `Database.java`, `SessionStore.java`, `ThrottleStore.java`, and `AccountSeeder.java`. Every query carrying values utilizes `PreparedStatement` with parameterized `?` bind markers. Dynamic table names are verified against an identifier allowlist and SQL reserved words via `InputValidator.requireSqlIdentifier()`, and double-quoted at all interpolation sites.
- JDBC URL Injection Mitigation: Verified in `InputValidator.requireDbPath()`. Database paths reject `;`, `=`, control characters, whitespace, and relative path traversal, preventing H2 connection string parameter smuggling (such as `INIT=RUNSCRIPT FROM ...`).
- Cryptographic Password Hashing: Verified in `PasswordHasher.java`. Utilizes standard JCE `SecretKeyFactory` with `PBKDF2WithHmacSHA256`, 16-byte cryptographically secure random salt, 256 derived bits, and minimum 100,000 iterations (default 210,000). Clears `PBEKeySpec` password buffer in `finally`.
- Credential Exposure in Process Memory and Command Line: Verified in `Main.java` and `InputValidator.java`. Passwords are read via `Console.readPassword` or decoded from stdin directly into `char[]` buffers without creating intermediate `java.lang.String` instances. Buffers are wiped (`Arrays.fill` with 0) in `finally` blocks. Passwords are never accepted via command line arguments (`argv`).
- Account Enumeration and Timing Side-Channel Defenses: Verified in `AuthService.java`. For non-existent accounts, `AuthService` computes an identical PBKDF2 derivation using `WORK_SAMPLE` and a deterministic blind salt (`auth-blind-v1: + email`) to ensure equal computation cost. Response times are floored to a minimum duration (`minLoginMs`, default 1000ms) with spin-waiting. Identical user-facing responses ("Authentication failed.") are returned regardless of whether the account exists or the password was incorrect.
- Session Token Generation and Storage Security: Verified in `SessionStore.java` and `CryptoUtils.java`. Session tokens are 256 bits drawn from `SecureRandom`. The database stores only the SHA-256 digest of the token (`token_hash`), so database disclosure does not reveal usable session credentials.
- Constant-Time Digest Comparisons: Verified in `CryptoUtils.constantTimeEquals()` and `PasswordHasher.matches()`. Compares fixed 32-byte derivations in constant time, preventing timing-based byte leakage.
- Audit Log Injection Protection (CRLF Sanitization): Verified in `LogWriter.java`. Line sanitization strictly checks each log line against an allowlisted character set, dropping or rejecting any line containing `\r`, `\n`, null bytes, or ANSI escape codes. Email addresses in logs are masked (`a***@domain.com`).
- Directory Access Permissions: Verified in `DbPathGuard.java` and `DbFiles.java`. Enforces POSIX 0700 on containing directories and 0600 on created files, verifying ownership matches the current running user and rejecting group/world access bits.
- Transactional Concurrency and Lock Ordering: Verified in `ThrottleStore.java`. Counter reservations use `SELECT ... FOR UPDATE` within an explicit transaction on a dedicated transaction connection, locking rows in sorted key order to avoid deadlocks. Auto-commit is disabled during reservation and restored upon completion.
