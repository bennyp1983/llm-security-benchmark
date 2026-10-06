# Security Review: secure-account-registry

## 1. Executive Summary
The `secure-account-registry` component is a standalone Java 17 command-line application that provides local user account registration and authentication using an embedded SQLite database. Accounts consist of a normalized email address, username, and password. Credential security is implemented using PBKDF2-HMAC-SHA-256 with 600,000 iterations, 16-byte random salts, and constant-time hash comparisons. The application enforces local filesystem boundaries with POSIX permission checks (`0700` directories and `0600` files), symlink traversal rejections, atomic SQLite transactions with `BEGIN IMMEDIATE`, and brute-force rate limiting per source and per account.

The static security audit identified three vulnerabilities:
1. **SEC-01 (Medium)**: In `SecureAccountApplication.java`, calling `System.exit(1)` inside the `try` and `catch` blocks immediately terminates the JVM, preventing the `finally` block from executing and leaving plaintext password characters in heap memory on any failed authentication or rejected registration.
2. **SEC-02 (Medium)**: In `AccountStore.java`, rate-limiting scopes for accounts are derived from the caller's presentation identifier (username or email) rather than a canonical user account identifier, allowing an attacker to double the number of brute-force password attempts against a target account by alternating between username and email.
3. **SEC-03 (Low)**: In `SecurityLog.java`, log rotation truncates the file in place to zero bytes without creating archived backups, permanently destroying historical audit trails and forensic evidence once the 1 MiB limit is reached.

Overall, the codebase demonstrates disciplined defensive programming with strong input validation, strict parameterized SQL queries, constant-time cryptography, and extensive path safety controls.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/example/security/SecureAccountApplication.java` | CLI entry point for `register` and `authenticate` commands | Console input handling, non-echoing password capture, command-line argument validation, credential cleanup in `finally`, process exit codes. |
| `src/main/java/example/security/AccountStore.java` | SQLite account database and rate-limiting manager | Database schema initialization, parameterized query execution, atomic `BEGIN IMMEDIATE` transactions, sliding window rate limiting per source and account, account enumeration defenses. |
| `src/main/java/example/security/PasswordHasher.java` | Password hashing and verification service | PBKDF2-HMAC-SHA-256 derivation with 600,000 iterations, 16-byte cryptographically secure salt generation, constant-time verification with `MessageDigest.isEqual`, dummy derivation for nonexistent accounts. |
| `src/main/java/example/security/InputValidator.java` | Canonicalization and validation utilities | Regex allowlist validation for usernames, RFC-compliant email structure checking, NFC Unicode normalization, password character bounds and surrogate pair validation. |
| `src/main/java/example/security/SecureFiles.java` | Filesystem security and POSIX permission enforcement | Absolute path normalization, symlink rejection across all path segments, POSIX owner-only permission enforcement (`0700`/`0600`), parent directory write permission verification. |
| `src/main/java/example/security/SecurityLog.java` | Structured, bounded audit logger | Bounded security event logging, inter-process file locking via `FileChannel.lock()`, log rotation truncation at 1 MiB, redaction of sensitive exception messages. |
| `src/test/java/example/security/SecuritySelfTest.java` | Test suite for validator, hasher, store, and rate limiter | Assertion-based test cases for input validation, password salting, round-trip auth, duplicate registration non-enumeration, and lockout enforcement. |
| `scripts/verify-dependencies.sh` | Build verification shell script | SHA-256 integrity verification of the downloaded SQLite JDBC driver JAR against maintainer-published checksums. |
| `pom.xml` | Maven build and dependency configuration | Pinned dependencies and plugins, compiler settings (`Java 17`), packaging configuration. |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to password hashing algorithm selection (PBKDF2-HMAC-SHA-256), iteration count (600,000), salt generation randomness, constant-time digest comparison, dummy hash workload for timing equalization, and key buffer clearing.
- `exploiting-sql-injection-vulnerabilities`: Applied to JDBC database operations, prepared statements, dynamic column identifier selection in account lookups, table schema configurations, and SQL constraint enforcement.
- `testing-api-authentication-weaknesses`: Applied to authentication flows, password complexity and surrogate pair validation, account lockout policies, duplicate registration responses, and credential enumeration defenses.
- `implementing-api-rate-limiting-and-throttling`: Applied to sliding window failure tracking, per-source and per-account failure counters, lockout duration calculation, and scope key derivation.
- `performing-directory-traversal-testing`: Applied to `ACCOUNT_DATA_DIRECTORY` path sanitization, symlink detection on parent and target directories, POSIX permission bit verification, and temporary native library redirection.
- General OWASP Top 10 / CWE knowledge: Applied to in-memory credential clearing and lifecycle management (CWE-244 / CWE-316), JVM abrupt termination semantics (`System.exit` vs `finally`), and audit log retention and rotation security (CWE-778).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Sensitive In-Memory Password Buffer Not Cleared on Abrupt Process Exit | Medium | CWE-244 | `src/main/java/example/security/SecureAccountApplication.java:31-56` |
| SEC-02 | Account Lockout Bypass via Split Scope Keys for Username and Email | Medium | CWE-307 | `src/main/java/example/security/AccountStore.java:94-96` |
| SEC-03 | Destructive Audit Log Truncation Destroys Forensic Evidence | Low | CWE-778 | `src/main/java/example/security/SecurityLog.java:36-43` |

## 5. Detailed Findings

### SEC-01: Sensitive In-Memory Password Buffer Not Cleared on Abrupt Process Exit
- **Severity:** Medium
- **CWE:** CWE-244: Improper Clearing of Heap Memory Before Release ('Memory Clearing Neglect')
- **Location:** `src/main/java/example/security/SecureAccountApplication.java:31-56`

**Vulnerable code:**
```java
// src/main/java/example/security/SecureAccountApplication.java:31-56
                AccountStore.RegistrationResult result = store.register(email, username, password);
                if (result == AccountStore.RegistrationResult.ACCEPTED) {
                    console.writer().println("If the account can be created, it is now available.");
                    return;
                }
                console.writer().println("Unable to complete request.");
                System.exit(1);
            } else {
                String login = console.readLine("Username or email: ");
                password = console.readPassword("Password: ");
                if (store.authenticate(login, password)) {
                    console.writer().println("Authentication successful.");
                    return;
                }
                console.writer().println("Authentication failed.");
                System.exit(1);
            }
        } catch (Exception ignored) {
            // Do not reflect exception text, paths, SQL, or configuration to the caller.
            System.err.println("Unable to complete request.");
            System.exit(1);
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
```

**Why it is a problem:**
In Java, invoking `System.exit(status)` halts the Java Virtual Machine immediately. When `System.exit` is called inside a `try` or `catch` block, any associated `finally` block is bypassed and does not execute (per Java Language Specification §14.20.2). Consequently, whenever registration is rejected, authentication fails, or an unexpected runtime exception occurs, line 54 (`Arrays.fill(password, '\0')`) is never executed. The plaintext password remains in heap memory until the process terminates. If core dumps are produced, memory inspection tools run, or JVM shutdown hooks execute prior to OS memory reclamation, plaintext credentials can be exposed.

**Fix:**
Store the intended exit code in a local variable instead of calling `System.exit` directly inside the `try` and `catch` blocks. Allow the `try-finally` block to complete so the `finally` block reliably zeroes the `password` array before calling `System.exit`.
```java
        int exitCode = 0;
        char[] password = null;
        try {
            Path dataDirectory = SecureFiles.initializeDataDirectory(System.getenv("ACCOUNT_DATA_DIRECTORY"));
            SecurityLog log = new SecurityLog(dataDirectory);
            AccountStore store = new AccountStore(dataDirectory, new PasswordHasher(), log);

            if ("register".equals(args[0])) {
                String email = console.readLine("Email: ");
                String username = console.readLine("Username: ");
                password = console.readPassword("Password: ");
                AccountStore.RegistrationResult result = store.register(email, username, password);
                if (result == AccountStore.RegistrationResult.ACCEPTED) {
                    console.writer().println("If the account can be created, it is now available.");
                    return;
                }
                console.writer().println("Unable to complete request.");
                exitCode = 1;
            } else {
                String login = console.readLine("Username or email: ");
                password = console.readPassword("Password: ");
                if (store.authenticate(login, password)) {
                    console.writer().println("Authentication successful.");
                    return;
                }
                console.writer().println("Authentication failed.");
                exitCode = 1;
            }
        } catch (Exception ignored) {
            // Do not reflect exception text, paths, SQL, or configuration to the caller.
            System.err.println("Unable to complete request.");
            exitCode = 1;
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
        if (exitCode != 0) {
            System.exit(exitCode);
        }
```

---

### SEC-02: Account Lockout Bypass via Split Scope Keys for Username and Email
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/example/security/AccountStore.java:94-96`

**Vulnerable code:**
```java
// src/main/java/example/security/AccountStore.java:94-96
        var login = InputValidator.login(loginValue);
        boolean inputValid = login.isPresent() && InputValidator.password(password);
        String accountScope = scopeKey(login.map(InputValidator.Login::canonicalValue).orElse("invalid"));
```

**Why it is a problem:**
The application allows users to authenticate using either their username or their email address. However, `accountScope` is calculated by hashing the raw user-supplied login string (`canonicalValue`) rather than a unified account identifier. In SQLite, the `auth_failures` table stores failure counts keyed on `(scope_type, scope_key)`. As a result, a single user account has two independent rate-limiting buckets: one for `scopeKey(username)` and one for `scopeKey(email)`.

An attacker performing brute-force credential guessing against a known user can make 5 failed attempts targeting the username alias, and then immediately make another 5 failed attempts targeting the email alias (which starts with zero failures), bypassing the 5-attempt account lockout limit and doubling the attack window against that user's credentials before reaching the source limit. Furthermore, locking out the username does not prevent authentication using the email, resulting in an inconsistent lockout state.

**Fix:**
Resolve the account record first to retrieve a canonical identifier (such as the database primary key or canonical username) and derive `accountScope` from that single canonical identifier. This ensures all login attempts against the account update and check the exact same rate-limiting counter regardless of whether the user provided their email or username.
```java
    boolean authenticate(String loginValue, char[] password) {
        var login = InputValidator.login(loginValue);
        boolean inputValid = login.isPresent() && InputValidator.password(password);

        Connection connection = null;
        try {
            connection = connect();
            beginImmediate(connection);
            long now = safeNow();
            RateState source = loadRate(connection, "SOURCE", SOURCE_SCOPE, now);
            AccountRecord account = login.isPresent() ? findAccount(connection, login.get()) : null;
            String accountScope = scopeKey(account != null ? account.canonicalUsername() : "invalid");
            RateState accountRate = account == null
                    ? new RateState(now, 0, 0, now)
                    : loadRate(connection, "ACCOUNT", accountScope, now);
            boolean rateAllowed = source.allowed(SOURCE_FAILURE_LIMIT)
                    && (account == null || accountRate.allowed(ACCOUNT_FAILURE_LIMIT));

            boolean passwordMatches = hasher.verify(password == null ? new char[0] : password,
                    account == null ? null : account.passwordHash());
            boolean authenticated = inputValid && rateAllowed && account != null && passwordMatches;
            if (authenticated) {
                deleteRate(connection, "ACCOUNT", accountScope);
                commit(connection);
                log.event("AUTHENTICATION_SUCCEEDED", null);
                return true;
            }

            recordFailure(connection, "SOURCE", SOURCE_SCOPE, source, SOURCE_FAILURE_LIMIT);
            if (account != null) {
                recordFailure(connection, "ACCOUNT", accountScope, accountRate, ACCOUNT_FAILURE_LIMIT);
            }
            commit(connection);
            log.event("AUTHENTICATION_FAILED", null);
            return false;
        } catch (Exception e) {
            rollbackQuietly(connection);
            log.event("AUTHENTICATION_ERROR", e);
            return false;
        } finally {
            closeQuietly(connection);
        }
    }
```

---

### SEC-03: Destructive Audit Log Truncation Destroys Forensic Evidence
- **Severity:** Low
- **CWE:** CWE-778: Insufficient Logging
- **Location:** `src/main/java/example/security/SecurityLog.java:36-43`

**Vulnerable code:**
```java
// src/main/java/example/security/SecurityLog.java:36-43
                if (size + bytes.length > MAX_BYTES) {
                    channel.truncate(0);
                    channel.position(0);
                    writeFully(channel, ByteBuffer.wrap((Instant.now() + " LOG_ROTATED NONE"
                            + System.lineSeparator()).getBytes(StandardCharsets.US_ASCII)));
                } else {
                    channel.position(size);
                }
```

**Why it is a problem:**
When `size + bytes.length > MAX_BYTES` (1 MiB), `SecurityLog` rotates the log by truncating the file to length 0 in place (`channel.truncate(0)`). It does not create an archived backup copy (e.g. `security.log.1`). This completely deletes all historical security events, including earlier authentication failures, rate-limiting blocks, and database error events. An attacker can intentionally trigger repetitive failed operations (such as invalid registrations or failed authentication attempts) to cause the log to reach 1 MiB, purging all prior audit history and erasing forensic evidence.

**Fix:**
Instead of truncating the log file to zero bytes in place, rotate the existing log by moving or copying it to an archived backup file (e.g., `security.log.1`) before opening and writing to a new active log file, ensuring historical audit records are preserved.
```java
                if (size + bytes.length > MAX_BYTES) {
                    channel.close();
                    Path archive = path.resolveSibling(path.getFileName().toString() + ".1");
                    java.nio.file.Files.move(path, archive, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                    channel = FileChannel.open(path, StandardOpenOption.CREATE,
                            StandardOpenOption.READ, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
                    channel.position(0);
                    writeFully(channel, ByteBuffer.wrap((Instant.now() + " LOG_ROTATED NONE"
                            + System.lineSeparator()).getBytes(StandardCharsets.US_ASCII)));
                } else {
                    channel.position(size);
                }
```

## 6. Verified Controls and Checks With No Finding
- **Password Hashing Algorithm and Iterations**: Verified in `PasswordHasher.java` lines 12-37. Uses PBKDF2 with HMAC-SHA-256 (`PBKDF2WithHmacSHA256`) at 600,000 iterations, adhering to current OWASP password storage recommendations. Salts are 16 bytes generated using `SecureRandom`, and derived keys are 256 bits.
- **Constant-Time Comparison and Timing Attack Resistance**: Verified in `PasswordHasher.java` lines 39-51 and `AccountStore.java` lines 104-111. Credential verification employs `MessageDigest.isEqual` to prevent timing attacks. In addition, when an account does not exist or input is invalid, a full 600,000-iteration PBKDF2 derivation is executed using a process-random `dummySalt` to equalize processing time across all authentication outcomes.
- **SQL Injection Defenses**: Verified in `AccountStore.java` lines 69-76, 138-141, 230-234, 262-276, and 280-284. All database queries involving user input or dynamic values use parameterized `PreparedStatement` instances. In `findHash`, the query column is selected from a static ternary expression between `"email_norm"` and `"username_norm"`, preventing SQL injection.
- **Database Schema and Storage Integrity**: Verified in `AccountStore.java` lines 157-179 and 194-200. SQLite tables are declared with `STRICT` mode and include explicit `CHECK` constraints on field lengths and non-negative integers. Database connection setup enforces `PRAGMA foreign_keys=ON`, `PRAGMA busy_timeout=5000`, and `PRAGMA trusted_schema=OFF`.
- **Atomic Concurrency Control**: Verified in `AccountStore.java` lines 63-77 and 101-124. Account registration and authentication are wrapped in immediate SQLite transactions (`BEGIN IMMEDIATE`), ensuring that state checks (account count limits, rate-limit thresholds) and corresponding state updates are executed atomically without TOCTOU race conditions.
- **Account Enumeration Defenses in Registration**: Verified in `AccountStore.java` lines 64-85 and `SecureAccountApplication.java` lines 31-35. When an email or username is already registered, SQLite raises a constraint violation (error code 19), which is trapped and returned as `RegistrationResult.ACCEPTED`. The password hashing derivation occurs prior to insertion, guaranteeing identical execution time and generic user-facing output (`"If the account can be created, it is now available."`) for both new and duplicate accounts.
- **Filesystem Boundaries and Path Traversal Protection**: Verified in `SecureFiles.java` lines 22-102. `ACCOUNT_DATA_DIRECTORY` is validated against an allowlist pattern, required to be absolute and normalized, checked against symlink components across all parent directories, and rejected if its parent directory is group- or world-writable. Created directories and files are strictly restricted to POSIX owner-only modes (`0700` for directories, `0600` for files) using `NOFOLLOW_LINKS`.
- **Native Library Extraction Hardening**: Verified in `AccountStore.java` lines 33-35. The SQLite driver's native library extraction directory is explicitly redirected away from `/tmp` into a private subfolder (`sqlite-native`) with `0700` permissions via `System.setProperty("org.sqlite.tmpdir", ...)`, preventing shared-directory DLL/so hijacking.
- **Input Validation and Normalization**: Verified in `InputValidator.java` lines 8-80. Usernames are restricted to 3–32 alphanumeric characters and bounded punctuation (`[A-Za-z0-9._-]`), emails are validated for RFC structure, length (max 254), and domain labels, and both are normalized using NFC form and lowercase conversion. Passwords must be 15–128 characters without ISO control characters or uncoupled surrogate pairs.
- **Sensitive Data Exposure Suppression**: Verified in `SecureAccountApplication.java` lines 15-19, 48-51, and `SecurityLog.java` lines 20-28. The CLI mandates an interactive `Console` with masked password input, suppresses internal exception messages and stack traces from stdout/stderr, and logs only fixed alphanumeric event codes without recording passwords, hashes, usernames, or filesystem paths.
