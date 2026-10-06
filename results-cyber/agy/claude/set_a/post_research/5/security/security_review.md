# Security Review: Employee Portal Authentication

## 1. Executive Summary
The target component is a standalone Java 17 authentication subsystem for an internal employee portal. It implements credential enrollment and verification using PBKDF2-HMAC-SHA256, session token generation and lifecycle tracking, HTTP cookie header generation, security event audit logging, and attempt rate-limiting across both in-memory and persistent file-backed stores. The component contains no external dependencies, relying entirely on the Java Standard Library.

The architecture incorporates strong defensive design patterns, such as constant-time verification, decoy PBKDF2 computations to equalize timing side channels between existing and non-existent users, fail-closed authentication logic, strict input character whitelisting, and credential zeroing in memory.

However, a thorough static security audit identified several security vulnerabilities ranging from High to Low severity:
1. **Unchecked File Permissions and Symlink Following during Credential Enrolment (`PortalCli.java`)**: `enroll` and `appendRecord` fail to verify file permissions or ownership on the credential store before writing, allowing unprivileged local attackers to pre-create world-writable files or symlinks to capture hashes or append data to arbitrary files.
2. **Global Session Table Exhaustion Denial of Service (`SessionManager.java`)**: The session manager enforces a hard global cap of 20,000 sessions without per-account throttling or eviction, allowing a single authenticated account to lock out all employees from logging into the portal.
3. **Swallowed Exception on Duplicate Account Records (`FileCredentialStore.java`)**: Duplicate account detection is wrapped inside a per-line `try-catch` block that catches `ValidationException`, causing the store to silently keep the first record based on file order rather than failing closed.
4. **TOCTOU Race Condition in Private File Creation (`PrivateFiles.java`)**: Non-atomic check-then-create calls can cause `FileAlreadyExistsException` under concurrent access, triggering rate limiter unavailability and denying authentication.
5. **Incomplete Parent Directory Ownership and Group-Write Checks (`PrivateFiles.java`)**: Parent directories are not checked for process user ownership or group-write permissions, exposing private files to deletion or replacement by other users sharing the directory.
6. **Concurrency, Encoding, Logging, and Persistence Weaknesses**: Memory visibility races on session idle expiry, raw byte-to-char stdin reading corrupting UTF-8 passwords, unmasked IPv4 addresses in audit logs when ports are included, silent logging failure on I/O error, and non-atomic in-place state file truncation.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/example/portal/auth/Authenticator.java` | Coordinates the authentication workflow | Validates input, reserves rate-limit slots, executes real or decoy PBKDF2 calculations, issues sessions, and fails closed. |
| `src/main/java/com/example/portal/auth/AuthResult.java` | Represents authentication outcome | Emits uniform failure messages, redacts session tokens in `toString()`, and hides internal failure reasons. |
| `src/main/java/com/example/portal/auth/AttemptCounters.java` | Core counting and lockout algorithms | Enforces attempt windows and lockout durations, defends against clock drift, and prunes stale records. |
| `src/main/java/com/example/portal/auth/AttemptLimiter.java` | Interface defining rate-limiting contracts | Defines dual budgets (per-account and per-source) and reservation semantics. |
| `src/main/java/com/example/portal/auth/AuditLog.java` | Security audit event logging | Masks usernames and IP addresses, sanitizes control characters to prevent log injection, and writes to private files. |
| `src/main/java/com/example/portal/auth/CredentialStore.java` | Contract for employee credential lookups | Defines server-side credential lookup operations. |
| `src/main/java/com/example/portal/auth/FileAttemptLimiter.java` | File-backed attempt rate limiter | Uses `FileLock` and in-process `ReentrantLock` for cross-process synchronization and persists counter state to disk. |
| `src/main/java/com/example/portal/auth/FileCredentialStore.java` | File-backed credential repository | Parses `username:hash` files, validates record formats and file bounds, and enforces owner-only permissions on load. |
| `src/main/java/com/example/portal/auth/InMemoryAttemptLimiter.java` | In-memory attempt rate limiter | Provides thread-safe attempt tracking and source-first evaluation using `ReentrantLock`. |
| `src/main/java/com/example/portal/auth/InputPolicy.java` | Input validation and canonicalization | Whitelist-based validation and length bounds for usernames, passwords, and source identifiers. |
| `src/main/java/com/example/portal/auth/PasswordHasher.java` | Password hashing and verification | Computes PBKDF2-HMAC-SHA256 with 600,000 iterations, constant-time equality check, and decoy computations. |
| `src/main/java/com/example/portal/auth/PortalCli.java` | Command-line interface | Handles terminal login and enrollment, blocks CLI password arguments, and manages password memory clearing. |
| `src/main/java/com/example/portal/auth/PrivateFiles.java` | POSIX file permissions utility | Enforces `rw-------` file permissions, checks regular file attributes, and creates owner-only files. |
| `src/main/java/com/example/portal/auth/Session.java` | Server-side session record | Stores session metadata with short digest references; redacts token representations. |
| `src/main/java/com/example/portal/auth/SessionCookie.java` | HTTP Set-Cookie builder | Emits cookies with `__Host-` prefix, `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and `Max-Age`. |
| `src/main/java/com/example/portal/auth/SessionManager.java` | Session token generation and validation | Generates 256-bit CSPRNG tokens, indexes sessions by SHA-256 digest, and enforces idle and absolute timeouts. |
| `src/main/java/com/example/portal/auth/ValidationException.java` | Validation failure exception | Encapsulates internal validation errors without exposing details to untrusted clients. |
| `src/test/java/com/example/portal/auth/SelfTest.java` | Adversarial self-test suite | Executes 20 security regression tests validating timing, lockouts, concurrency, and masking. |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to `PasswordHasher.java` (PBKDF2-HMAC-SHA256, salt generation, constant-time verification, decoy work) and `SessionManager.java` (token generation with `SecureRandom`, token indexing via SHA-256 digests).
- `testing-api-authentication-weaknesses`: Applied to `Authenticator.java`, `SessionManager.java`, and `FileCredentialStore.java` to review credential validation, session issuance, fail-closed handling, and account enumeration defenses.
- `performing-api-rate-limiting-bypass`: Applied to `AttemptLimiter.java`, `AttemptCounters.java`, `InMemoryAttemptLimiter.java`, and `FileAttemptLimiter.java` to evaluate dual-budget rate limiting (per-account and per-source), lockout duration, clock drift handling, and capacity limits.
- `performing-security-headers-audit`: Applied to `SessionCookie.java` for session cookie attributes (`HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, `Max-Age`, `__Host-` prefix).
- `exploiting-race-condition-vulnerabilities`: Applied to `FileAttemptLimiter.java`, `SessionManager.java`, and `PrivateFiles.java` to analyze TOCTOU file creation, cross-process and multi-threaded locking, and atomic state updates.
- General OWASP Top 10 / CWE knowledge (CWE-59, CWE-732, CWE-276, CWE-176, CWE-390, CWE-209): Applied to `PortalCli.java` (file permission enforcement, stdin encoding, command-line arguments), `PrivateFiles.java` (directory permission verification), and `AuditLog.java` (log sanitization and error handling).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Unchecked File Permissions and Symlink Following during Credential Enrolment | High | CWE-59 | `src/main/java/com/example/portal/auth/PortalCli.java:187-188, 214-220` |
| SEC-02 | Unchecked Global Session Table Exhaustion Causes Portal-Wide Denial of Service | High | CWE-770 | `src/main/java/com/example/portal/auth/SessionManager.java:93-98` |
| SEC-03 | Swallowed ValidationException on Duplicate Account Records Permits Load-Order-Dependent Credentials | Medium | CWE-287 | `src/main/java/com/example/portal/auth/FileCredentialStore.java:94-102` |
| SEC-04 | TOCTOU Race Condition in Private File Creation Leading to Denial of Service | Medium | CWE-367 | `src/main/java/com/example/portal/auth/PrivateFiles.java:41-49` |
| SEC-05 | Incomplete Parent Directory Ownership and Group-Write Checks Allows File Hijacking | Medium | CWE-732 | `src/main/java/com/example/portal/auth/PrivateFiles.java:83-89` |
| SEC-06 | Non-Volatile Field in SessionManager Causes Memory Visibility Race and Premature Session Invalidation | Low | CWE-362 | `src/main/java/com/example/portal/auth/SessionManager.java:53, 135, 183` |
| SEC-07 | Stdin Byte-to-Char Casting Corrupts Non-ASCII Passwords and Causes False Lockouts | Low | CWE-176 | `src/main/java/com/example/portal/auth/PortalCli.java:306-315` |
| SEC-08 | Unmasked IPv4 Address in Audit Log when Port is Present | Low | CWE-209 | `src/main/java/com/example/portal/auth/AuditLog.java:133-140` |
| SEC-09 | Silent Failure of Security Audit Logging on Write Errors | Low | CWE-390 | `src/main/java/com/example/portal/auth/AuditLog.java:59-62, 83` |
| SEC-10 | In-Place State File Truncation Creates Window for Rate Limit Reset on System Crash | Low | CWE-391 | `src/main/java/com/example/portal/auth/FileAttemptLimiter.java:244-246` |

## 5. Detailed Findings

### SEC-01: Unchecked File Permissions and Symlink Following during Credential Enrolment
- **Severity:** High
- **CWE:** CWE-59: Improper Link Resolution Before File Access ('Link Following')
- **Location:** `src/main/java/com/example/portal/auth/PortalCli.java:187-188, 214-220`

**Vulnerable code:**
```java
// src/main/java/com/example/portal/auth/PortalCli.java:187-188
            FileCredentialStore.createIfAbsent(storePath);
            appendRecord(storePath, username, record);
```
and
```java
// src/main/java/com/example/portal/auth/PortalCli.java:214-220
        Path resolved = storePath.toAbsolutePath().normalize();
        try (FileChannel channel = FileChannel.open(resolved, StandardOpenOption.READ, StandardOpenOption.WRITE);
             FileLock lock = channel.lock()) {
            if (channel.size() > FileCredentialStore.MAX_FILE_BYTES) {
                throw new ValidationException("credential file exceeds the maximum accepted size");
            }
            for (String line : Files.readAllLines(resolved, StandardCharsets.UTF_8)) {
```

**Why it is a problem:**
When `PortalCli.login` runs, `FileCredentialStore.load` calls `PrivateFiles.requireOwnerOnly(resolved, "credential file")` to ensure that the file exists, is a regular file (not a symlink or device), is owned by the current process user, and has permissions restricted to owner read/write (`rw-------`).

However, during `PortalCli.enroll`, `PrivateFiles.requireOwnerOnly` is never called. If `storePath` already exists, `FileCredentialStore.createIfAbsent(storePath)` returns immediately without verifying ownership or file permissions. `appendRecord` then opens the file using `FileChannel.open` and reads all lines using `Files.readAllLines`.

If another local user pre-creates `storePath` with permissive permissions (such as `0666` or world-writable/readable) or as a symlink pointing to an arbitrary file (e.g., `/etc/shadow`, `/tmp/file`, or another user's file):
1. `appendRecord` follows the symlink and appends the credential record to the target file.
2. If pre-created with permissive permissions, `enroll` appends the newly computed password hash into a file readable by any local account, exposing employee credentials.

**Fix:**
Enforce `PrivateFiles.requireOwnerOnly(resolved, "credential file")` in `appendRecord` before opening the file.

```java
    private static void appendRecord(Path storePath, String username, String record)
            throws IOException, ValidationException {
        Path resolved = storePath.toAbsolutePath().normalize();
        PrivateFiles.requireOwnerOnly(resolved, "credential file");
        try (FileChannel channel = FileChannel.open(resolved, StandardOpenOption.READ, StandardOpenOption.WRITE);
             FileLock lock = channel.lock()) {
            if (channel.size() > FileCredentialStore.MAX_FILE_BYTES) {
                throw new ValidationException("credential file exceeds the maximum accepted size");
            }
            for (String line : Files.readAllLines(resolved, StandardCharsets.UTF_8)) {
                int separator = line.indexOf(':');
                if (separator > 0 && line.substring(0, separator).equalsIgnoreCase(username)) {
                    throw new ValidationException("that account already has a credential on file");
                }
            }
            channel.position(channel.size());
            byte[] bytes = (record + System.lineSeparator()).getBytes(StandardCharsets.UTF_8);
            channel.write(java.nio.ByteBuffer.wrap(bytes));
            channel.force(true);
            Arrays.fill(bytes, (byte) 0);
        }
    }
```

---

### SEC-02: Unchecked Global Session Table Exhaustion Causes Portal-Wide Denial of Service
- **Severity:** High
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `src/main/java/com/example/portal/auth/SessionManager.java:93-98`

**Vulnerable code:**
```java
// src/main/java/com/example/portal/auth/SessionManager.java:93-98
        if (sessions.size() >= MAX_SESSIONS) {
            pruneExpired();
            if (sessions.size() >= MAX_SESSIONS) {
                throw new IllegalStateException("session capacity exhausted");
            }
        }
```

**Why it is a problem:**
`SessionManager` establishes a hard ceiling of `MAX_SESSIONS = 20,000` concurrent live sessions to prevent heap exhaustion. However, there is no restriction on the number of active sessions a single employee account can establish, nor is there an eviction mechanism for active sessions.

When `sessions.size() >= MAX_SESSIONS`, `pruneExpired()` removes only expired sessions. If 20,000 unexpired sessions exist, `sessions.create(username)` throws `IllegalStateException("session capacity exhausted")`.

In `Authenticator.java` (lines 117–130), this `RuntimeException` is caught, access is denied (`AuthResult.denied()`), and the attempt is recorded as a failure. Consequently, an attacker who obtains a single valid employee credential can script repeated authentications to generate 20,000 active sessions. This locks out all users across the entire organization from logging into the portal until the 8-hour absolute session expiration elapses.

**Fix:**
Track active session counts per user, enforce a maximum limit of concurrent sessions per account (e.g., 10), and evict the user's oldest session when the per-user or global limit is reached.

```java
    public static final int MAX_SESSIONS_PER_USER = 10;

    public Issued create(String username) {
        if (sessions.size() >= MAX_SESSIONS) {
            pruneExpired();
        }
        // Evict oldest session for this user if per-user limit is reached
        long userSessions = sessions.values().stream().filter(e -> e.username.equals(username)).count();
        if (userSessions >= MAX_SESSIONS_PER_USER) {
            sessions.entrySet().stream()
                    .filter(e -> e.getValue().username.equals(username))
                    .min(java.util.Comparator.comparing(e -> e.getValue().createdAt))
                    .ifPresent(e -> sessions.remove(e.getKey(), e.getValue()));
        }
        if (sessions.size() >= MAX_SESSIONS) {
            throw new IllegalStateException("session capacity exhausted");
        }
        byte[] raw = new byte[TOKEN_BYTES];
        random.nextBytes(raw);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        java.util.Arrays.fill(raw, (byte) 0);

        String digest = digestOf(token);
        Instant now = Instant.now();
        Entry entry = new Entry(username, now, now.plus(absoluteLifetime), now.plus(idleTimeout));
        if (sessions.putIfAbsent(digest, entry) != null) {
            throw new IllegalStateException("session identifier collision");
        }
        return new Issued(token, new Session(username, referenceOf(digest), now, entry.absoluteExpiry));
    }
```

---

### SEC-03: Swallowed ValidationException on Duplicate Account Records Permits Load-Order-Dependent Credentials
- **Severity:** Medium
- **CWE:** CWE-287: Improper Authentication
- **Location:** `src/main/java/com/example/portal/auth/FileCredentialStore.java:94-102`

**Vulnerable code:**
```java
// src/main/java/com/example/portal/auth/FileCredentialStore.java:94-102
                if (parsed.putIfAbsent(username, hash) != null) {
                    // Two records for one account would make the effective credential depend on
                    // load order. Refuse rather than pick one.
                    throw new ValidationException("duplicate account record");
                }
            } catch (ValidationException e) {
                audit.warn("credential record rejected: " + e.getMessage(), "line=" + lineNumber);
                rejected++;
            }
```

**Why it is a problem:**
`FileCredentialStore.load` intends to fail closed when duplicate accounts appear in the credential file. As documented in the code comment: *"Two records for one account would make the effective credential depend on load order. Refuse rather than pick one."*

However, the `throw new ValidationException("duplicate account record")` is placed inside the per-line `try` block that catches format validation exceptions. When a duplicate record is encountered, the exception is caught on line 99, logged as a warning, and discarded. The loop continues loading subsequent records.

Because `parsed.putIfAbsent` already registered the first occurrence of the account, `parsed` retains the initial record and ignores subsequent records. The credential file is successfully loaded, silently choosing whichever credential appears first in the file rather than refusing the ambiguous store.

**Fix:**
Perform the duplicate account check outside the per-line formatting `try-catch` block (or re-throw the exception) so that encountering duplicate records aborts store loading.

```java
            String username;
            PasswordHasher.StoredHash hash;
            try {
                username = InputPolicy.requireValidUsername(line.substring(0, separator));
                hash = PasswordHasher.parse(line.substring(separator + 1));
            } catch (ValidationException e) {
                audit.warn("credential record rejected: " + e.getMessage(), "line=" + lineNumber);
                rejected++;
                continue;
            }
            if (parsed.putIfAbsent(username, hash) != null) {
                // Two records for one account would make the effective credential depend on
                // load order. Refuse rather than pick one.
                throw new ValidationException("duplicate account record for " + username + " at line " + lineNumber);
            }
```

---

### SEC-04: TOCTOU Race Condition in Private File Creation Leading to Denial of Service
- **Severity:** Medium
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `src/main/java/com/example/portal/auth/PrivateFiles.java:41-49`

**Vulnerable code:**
```java
// src/main/java/com/example/portal/auth/PrivateFiles.java:41-49
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        if (posixSupported()) {
            Files.createFile(path,
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        } else {
            Files.createFile(path);
        }
```

**Why it is a problem:**
`PrivateFiles.createPrivateIfAbsent` uses `Files.exists` followed by `Files.createFile`. This introduces a Time-of-Check to Time-of-Use (TOCTOU) race condition when multiple threads or processes run simultaneously against an uninitialized state file or audit log.

If two processes invoke `createPrivateIfAbsent` before the file exists, both evaluate `Files.exists` as false. The first process creates the file; the second process calls `Files.createFile` and encounters a `java.nio.file.FileAlreadyExistsException` (a subclass of `IOException`).

In `FileAttemptLimiter.tryReserve`, this `IOException` causes the attempt limiter to treat the failure as `Decision.UNAVAILABLE`, denying legitimate user logins and logging tracker unavailability. In `AuditLog.toFile`, it causes process initialization to fail.

**Fix:**
Create the file atomically by calling `Files.createFile` directly and catching `FileAlreadyExistsException`.

```java
    static void createPrivateIfAbsent(Path path) throws IOException {
        try {
            if (posixSupported()) {
                Files.createFile(path,
                        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            } else {
                Files.createFile(path);
            }
        } catch (java.nio.file.FileAlreadyExistsException ignored) {
            // Already created by another concurrent process.
        }
    }
```

---

### SEC-05: Incomplete Parent Directory Ownership and Group-Write Checks Allows File Hijacking
- **Severity:** Medium
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `src/main/java/com/example/portal/auth/PrivateFiles.java:83-89`

**Vulnerable code:**
```java
// src/main/java/com/example/portal/auth/PrivateFiles.java:83-89
        Path parent = path.getParent();
        if (parent != null && posixSupported()
                && Files.getPosixFilePermissions(parent).contains(PosixFilePermission.OTHERS_WRITE)) {
            // A world-writable directory lets another account replace the file wholesale, which
            // defeats every check above.
            throw new ValidationException(kind + " sits in a world-writable directory");
        }
```

**Why it is a problem:**
`PrivateFiles.requireOwnerOnly` validates that sensitive files (`employees.auth`, `attempts.state`, `audit.log`) are regular files owned by the process user with `rw-------` permissions. To guard against replacement attacks, it inspects the parent directory, but only checks for `PosixFilePermission.OTHERS_WRITE`.

In POSIX environments, directory write permissions allow unlinking and renaming files inside that directory regardless of the file's own permissions. If the parent directory is owned by another local user (or has group write permissions `GROUP_WRITE` enabled for a shared group), another user can delete or rename the private file and substitute a malicious version, bypassing the file owner check.

**Fix:**
Verify that the parent directory is owned by the portal process user (or root) and contains neither `OTHERS_WRITE` nor `GROUP_WRITE`.

```java
        Path parent = path.getParent();
        if (parent != null && posixSupported()) {
            Set<PosixFilePermission> parentPerms = Files.getPosixFilePermissions(parent, LinkOption.NOFOLLOW_LINKS);
            if (parentPerms.contains(PosixFilePermission.OTHERS_WRITE)
                    || parentPerms.contains(PosixFilePermission.GROUP_WRITE)) {
                throw new ValidationException(kind + " sits in a group- or world-writable directory");
            }
            String parentOwner = Files.getOwner(parent, LinkOption.NOFOLLOW_LINKS).getName();
            if (!parentOwner.equals(processUser) && !"root".equals(parentOwner)) {
                throw new ValidationException(kind + " directory is not owned by the portal user or root");
            }
        }
```

---

### SEC-06: Non-Volatile Field in SessionManager Causes Memory Visibility Race and Premature Session Invalidation
- **Severity:** Low
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
- **Location:** `src/main/java/com/example/portal/auth/SessionManager.java:53, 135, 183`

**Vulnerable code:**
```java
// src/main/java/com/example/portal/auth/SessionManager.java:49-55
    private static final class Entry {
        private final String username;
        private final Instant createdAt;
        private final Instant absoluteExpiry;
        private Instant idleExpiry;
```

**Why it is a problem:**
`SessionManager.validate()` updates `entry.idleExpiry = now.plus(idleTimeout);` inside a `ConcurrentHashMap.compute` call. However, `idleExpiry` is not declared `volatile`.

When `pruneExpired()` runs on another thread during `create()`, it iterates over `sessions.entrySet()` and inspects `!now.isBefore(entry.idleExpiry)` without locking. Under the Java Memory Model, without a volatile read or memory barrier, the pruning thread can read a stale `idleExpiry` value for an active session. If the stale timestamp appears expired, `pruneExpired()` invokes `sessions.remove(e.getKey(), entry)`, unexpectedly terminating an active user's session.

**Fix:**
Declare `idleExpiry` as `volatile`.

```java
    private static final class Entry {
        private final String username;
        private final Instant createdAt;
        private final Instant absoluteExpiry;
        private volatile Instant idleExpiry;

        Entry(String username, Instant createdAt, Instant absoluteExpiry, Instant idleExpiry) {
            this.username = username;
            this.createdAt = createdAt;
            this.absoluteExpiry = absoluteExpiry;
            this.idleExpiry = idleExpiry;
        }
    }
```

---

### SEC-07: Stdin Byte-to-Char Casting Corrupts Non-ASCII Passwords and Causes False Lockouts
- **Severity:** Low
- **CWE:** CWE-176: Improper Handling of Unicode Encoding
- **Location:** `src/main/java/com/example/portal/auth/PortalCli.java:306-315`

**Vulnerable code:**
```java
// src/main/java/com/example/portal/auth/PortalCli.java:306-315
        while ((c = System.in.read()) >= 0 && c != '\n') {
            if (c == '\r') {
                continue;
            }
            if (length == limit) {
                Arrays.fill(buffer, '\0');
                throw new IOException("input line exceeds the accepted length");
            }
            buffer[length++] = (char) c;
        }
```

**Why it is a problem:**
`PortalCli.readBoundedChars()` reads raw 8-bit bytes from `System.in` and directly casts them to Java 16-bit `char` code units: `buffer[length++] = (char) c;`.

In UTF-8, characters outside US-ASCII consist of multi-byte sequences with byte values between `0x80` and `0xFF`. Direct casting treats each byte as an ISO-8859-1 code point rather than decoding the UTF-8 character. In contrast, interactive password entry via `Console.readPassword()` uses the platform character decoder.

If an employee with non-ASCII characters in their password enrolls via the terminal and attempts to log in via `--password-stdin` (or scripted automation), the resulting character arrays will not match. The authentication attempt fails, and repeated attempts trigger account lockouts.

**Fix:**
Wrap `System.in` with an `InputStreamReader` configured with `StandardCharsets.UTF_8` to read properly decoded characters.

```java
    private static char[] readBoundedChars() throws IOException {
        int limit = InputPolicy.PASSWORD_MAX_LENGTH;
        char[] buffer = new char[limit];
        int length = 0;
        java.io.Reader reader = new java.io.InputStreamReader(System.in, StandardCharsets.UTF_8);
        int c;
        while ((c = reader.read()) >= 0 && c != '\n') {
            if (c == '\r') {
                continue;
            }
            if (length == limit) {
                Arrays.fill(buffer, '\0');
                throw new IOException("input line exceeds the accepted length");
            }
            buffer[length++] = (char) c;
        }
        char[] line = Arrays.copyOf(buffer, length);
        Arrays.fill(buffer, '\0');
        return line;
    }
```

---

### SEC-08: Unmasked IPv4 Address in Audit Log when Port is Present
- **Severity:** Low
- **CWE:** CWE-209: Generation of Error Message Containing Sensitive Information
- **Location:** `src/main/java/com/example/portal/auth/AuditLog.java:133-140`

**Vulnerable code:**
```java
// src/main/java/com/example/portal/auth/AuditLog.java:133-140
        String safe = sanitise(source).toLowerCase(Locale.ROOT);
        if (safe.indexOf(':') >= 0) {
            String[] groups = safe.split(":", -1);
            StringBuilder out = new StringBuilder();
            for (int i = 0; i < Math.min(3, groups.length); i++) {
                out.append(groups[i]).append(':');
            }
            return out.append("*").toString();
        }
```

**Why it is a problem:**
`AuditLog.maskSource` determines IP version by checking whether the input string contains a colon (`:`). It assumes that any string with a colon is an IPv6 address and preserves up to the first three colon-separated groups.

However, `InputPolicy.requireValidSource` permits digits, dots, and colons. If a front end forwards an IPv4 address accompanied by a port (e.g. `192.168.1.50:8080`), `groups` contains `["192.168.1.50", "8080"]`. The loop appends both groups, producing `192.168.1.50:8080:*`, leaving the entire client IPv4 address unmasked in the audit log.

**Fix:**
Strip any trailing port specification before checking for IPv4 or IPv6 structure.

```java
    public static String maskSource(String source) {
        if (source == null || source.isEmpty()) {
            return "<absent>";
        }
        String safe = sanitise(source).toLowerCase(Locale.ROOT);
        // If IPv4 with port, strip port
        int lastColon = safe.lastIndexOf(':');
        int firstColon = safe.indexOf(':');
        if (firstColon >= 0 && firstColon == lastColon && safe.indexOf('.') >= 0) {
            safe = safe.substring(0, firstColon);
        }
        if (safe.indexOf(':') >= 0) {
            String[] groups = safe.split(":", -1);
            StringBuilder out = new StringBuilder();
            for (int i = 0; i < Math.min(3, groups.length); i++) {
                out.append(groups[i]).append(':');
            }
            return out.append("*").toString();
        }
        String[] octets = safe.split("\\.", -1);
        if (octets.length == 4) {
            return octets[0] + "." + octets[1] + "." + octets[2] + ".*";
        }
        return safe.length() <= 4 ? "*" : safe.substring(0, 4) + "*";
    }
```

---

### SEC-09: Silent Failure of Security Audit Logging on Write Errors
- **Severity:** Low
- **CWE:** CWE-390: Detection of Error Condition Without Action
- **Location:** `src/main/java/com/example/portal/auth/AuditLog.java:59-62, 83`

**Vulnerable code:**
```java
// src/main/java/com/example/portal/auth/AuditLog.java:59-62
        PrintStream stream = new PrintStream(
                Files.newOutputStream(resolved, StandardOpenOption.CREATE, StandardOpenOption.APPEND),
                true, StandardCharsets.UTF_8);
        return new AuditLog(stream, true);
```
and
```java
// src/main/java/com/example/portal/auth/AuditLog.java:83
        sink.println(line);
```

**Why it is a problem:**
`AuditLog.toFile` wraps its file output stream in `java.io.PrintStream`. `PrintStream` methods catch and swallow underlying `IOException`s rather than propagating them, setting an internal error state instead.

Because `sink.checkError()` is never called, write failures (such as a full disk or file permission revocation) occur silently. Authentication events, failed attempts, and restrictions will fail to record without alerting administrators.

**Fix:**
Verify `sink.checkError()` after writing, logging to standard error or throwing an alert if writing to the audit sink fails.

```java
    private synchronized void write(String level, String event, String detail) {
        String line = Instant.now() + " " + level + " " + sanitise(event)
                + (detail == null || detail.isEmpty() ? "" : " | " + sanitise(detail));
        sink.println(line);
        if (sink.checkError()) {
            System.err.println("CRITICAL: Audit log failed to write entry: " + event);
        }
    }
```

---

### SEC-10: In-Place State File Truncation Creates Window for Rate Limit Reset on System Crash
- **Severity:** Low
- **CWE:** CWE-391: Unchecked Error Condition
- **Location:** `src/main/java/com/example/portal/auth/FileAttemptLimiter.java:244-246`

**Vulnerable code:**
```java
// src/main/java/com/example/portal/auth/FileAttemptLimiter.java:244-246
            channel.truncate(0);
            channel.position(0);
            channel.write(ByteBuffer.wrap(bytes));
```

**Why it is a problem:**
`FileAttemptLimiter.commit()` truncates the persistent state file to 0 bytes before writing the updated counters. If the host experiences an abrupt shutdown, power outage, or process termination after `channel.truncate(0)` but before `channel.write()` completes, the state file is left empty.

Upon system restart, all accumulated attempt counters and active lockout restrictions are lost, allowing an attacker to reset their brute-force budget by crashing the process or host.

**Fix:**
Over-write the updated counters starting at position 0, then truncate trailing bytes to match the new size, and sync using `channel.force(true)`.

```java
            channel.position(0);
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
            channel.truncate(bytes.length);
            channel.force(true);
```

## 6. Verified Controls and Checks With No Finding
- **PBKDF2 Password Hashing Parameters**: Verified that `PasswordHasher.java` uses `PBKDF2WithHmacSHA256` with 600,000 iterations (conforming to current OWASP guidance), a 16-byte cryptographically secure salt generated via `SecureRandom`, and 256-bit key length.
- **Timing Equalization (Decoy Computations)**: Verified that `Authenticator.java` executes `hasher.performDecoyWork()` whenever an account does not exist, a credential record is malformed, or an account/source is under restriction, ensuring timing parity and preventing account enumeration.
- **Constant-Time Verification**: Verified that `PasswordHasher.verify()` performs constant-time comparison via `MessageDigest.isEqual` to prevent timing attacks against stored digests.
- **Uniform Error Messages**: Verified that `AuthResult` returns identical generic error messages (`AuthResult.GENERIC_FAILURE_MESSAGE`) across all failure scenarios (unknown user, incorrect password, rate-limited account, or internal failure).
- **Session Cookie Security Attributes**: Verified that `SessionCookie.java` enforces `__Host-` prefixing, `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and omits the `Domain` attribute to prevent cross-subdomain leakage and cross-site scripting/request forgery exploitation.
- **Redaction of Sensitive Values**: Verified that `toString()` implementations in `AuthResult`, `Session`, `SessionManager.Issued`, and `PasswordHasher.StoredHash` redact sensitive tokens, passwords, salts, and hashes.
- **Command-Line Password Handling**: Verified that `PortalCli.java` rejects `--password` or `--password=...` arguments to prevent credential exposure in `/proc` process tables and shell history files.
- **In-Memory Credential Zeroing**: Verified that plaintext passwords and derived key byte arrays are wiped using `Arrays.fill(..., '\0')` and `Arrays.fill(..., (byte)0)` in `finally` blocks across `PortalCli`, `PasswordHasher`, and `Authenticator`.
- **Dual-Budget Rate Limiting**: Verified that `AttemptCounters.java` enforces independent per-account (5 attempts/15 min) and per-source (50 attempts/15 min) budgets with temporary restrictions that expire, preventing both brute-force attacks and permanent DoS.
- **Cross-Process Mutual Exclusion**: Verified that `FileAttemptLimiter.java` synchronizes file modifications using `FileLock` alongside in-process `ReentrantLock` instances, preventing concurrent update anomalies.
- **Strict Whitelist Input Validation**: Verified that `InputPolicy.java` enforces strict character whitelists and length bounds for usernames (`[a-zA-Z0-9._-]`, 3–64 chars), source identifiers (1–64 chars), and passwords (1–256 chars).
