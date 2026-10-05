# Security Review: Secure Java Authentication System

## 1. Executive Summary
A comprehensive security review was conducted on the Secure Java Authentication System codebase located in this repository. The application implements an email-and-password authentication service backed by an SQL database (H2), incorporating PBKDF2WithHmacSHA256 password hashing, dual-layer rate limiting, session token management, CRLF-safe audit logging, and input validation.

Overall, the application demonstrates strong architectural security principles: all database queries use parameterized prepared statements preventing SQL injection, password verification enforces constant-time comparison and dummy key derivation to resist account enumeration and timing attacks, sensitive arrays are zeroized in memory, and session tokens use cryptographically secure random entropy. However, several vulnerabilities were identified across resource management, sensitive output handling, thread concurrency, and input stream decoding:
1. **Unbounded Cache Growth (SEC-01, High)**: The rate limiter and session manager caches only evict expired entries; sustained traffic under active time windows causes uncontrolled memory expansion and CPU degradation.
2. **Cleartext Session Cookie Leakage (SEC-02, High)**: Although the CLI masks the session token, it immediately outputs the complete unmasked session cookie header containing the active credential to standard output.
3. **Thread Starvation via Synchronous Sleep (SEC-03, Medium)**: Applying progressive throttling delays via synchronous `Thread.sleep()` on worker threads creates a severe thread exhaustion denial-of-service vector.
4. **Silent Password Truncation and Encoding Corruption (SEC-04, Medium)**: The stream-based password reader silently discards characters beyond 128 without validation error and uses raw byte-to-char casting that corrupts multi-byte UTF-8 characters.
5. **Incomplete Local Database File Permission Hardening (SEC-05, Low)**: The POSIX permission restriction logic does not cover all valid H2 file URLs and risks altering permissions of the working directory.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `pom.xml` | Maven build and project dependency configuration | Declares external dependencies (H2 Database 2.2.224, JUnit Jupiter 5.10.2), compiler security flags (`-Xlint:all`, `-Werror`), and JAR packaging plugins. |
| `src/main/java/com/example/auth/AuthenticationResult.java` | Authentication outcome model | Enforces uniform generic user-facing messages across all failure states to prevent account enumeration; encapsulates optional authenticated session. |
| `src/main/java/com/example/auth/AuthenticationService.java` | Core authentication coordinator | Coordinates rate limiting checks, progressive throttling, input validation, database lookup, dummy PBKDF2 execution, credential verification, and memory zeroization. |
| `src/main/java/com/example/auth/DatabaseManager.java` | Database connection lifecycle and schema manager | Resolves JDBC configuration from environment variables with safe defaults, runs idempotent DDL table creation, and attempts POSIX permission hardening (0700/0600) on local database files. |
| `src/main/java/com/example/auth/HashResult.java` | Immutable PBKDF2 container | Encapsulates Base64 salt, Base64 derived key, iteration count, and algorithm metadata. |
| `src/main/java/com/example/auth/InputValidator.java` | Boundary input validation and canonicalization | Validates email syntax and length (RFC 5321 bounds), enforces password length limits (1-128 for auth, 8-128 for creation), sanitizes client source IDs, and validates database-stored hash parameters. |
| `src/main/java/com/example/auth/Main.java` | CLI application entry point | Handles command-line arguments, user registration, and authentication; reads credentials via `java.io.Console` or raw stream fallback, masks output tokens, and wipes credentials from memory. |
| `src/main/java/com/example/auth/PasswordHasher.java` | Cryptographic password hashing and verification | Implements PBKDF2WithHmacSHA256 (210,000 iterations, 128-bit salt, 256-bit key), constant-time byte comparison (`MessageDigest.isEqual`), dummy key derivation for timing attack defense, and memory zeroization. |
| `src/main/java/com/example/auth/RateLimiter.java` | Multi-tier attempt tracker and rate limiter | Enforces per-source (5 attempts/5 min), per-source-account (3 attempts/5 min), and global account progressive delay throttling; manages cache eviction. |
| `src/main/java/com/example/auth/SecurityLogger.java` | Security audit and diagnostics logger | Implements PII email masking, token truncation, and CRLF neutralization (`\r` and `\n` substitution) to mitigate CWE-117 log forging. |
| `src/main/java/com/example/auth/SessionManager.java` | Session issuance and lifecycle manager | Generates 256-bit cryptographically secure session tokens via `SecureRandom`, constructs hardened HTTP cookies (`__Host-` prefix, Secure, HttpOnly, SameSite=Strict), and tracks session expiration. |
| `src/main/java/com/example/auth/UserRecord.java` | Immutable database user model | Stores retrieved database fields and checks whether account status is active. |
| `src/main/java/com/example/auth/UserRepository.java` | Data access layer for user persistence | Executes parameterized SQL queries (`PreparedStatement`) for user retrieval, account creation, and user counting; verifies database parameters before use. |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to audit cryptographic primitives, key derivation function (PBKDF2WithHmacSHA256), iteration counts, salt generation with SecureRandom, constant-time byte comparisons (`MessageDigest.isEqual`), and in-memory key zeroization in `PasswordHasher.java` and `SessionManager.java`.
- `testing-api-authentication-weaknesses`: Applied to audit session token generation, session lifecycle, token entropy, cookie flag configuration (`__Host-` prefix, Secure, HttpOnly, SameSite=Strict), and authentication flow control in `SessionManager.java` and `AuthenticationService.java`.
- `testing-for-sensitive-data-exposure`: Applied to audit sensitive credential logging, token masking, cleartext output, and credential wiping in `Main.java`, `SecurityLogger.java`, and `AuthenticationService.java`.
- `exploiting-sql-injection-vulnerabilities`: Applied to audit database query construction, SQL parameterization, prepared statements, and DDL schema creation in `UserRepository.java` and `DatabaseManager.java`.
- General OWASP Top 10 / CWE knowledge (including CWE-400 / CWE-770 for resource management and cache exhaustion, CWE-834 for thread blocking, CWE-1188 / CWE-20 for stream input handling, and CWE-732 / CWE-276 for file permissions): Applied to review memory caching in `RateLimiter.java` and `SessionManager.java`, synchronous thread sleeping in `AuthenticationService.java`, stream-based character parsing in `Main.java`, and POSIX file permission logic in `DatabaseManager.java`.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Unbounded Cache Growth Leading to Denial of Service and Resource Exhaustion | High | CWE-400 | `src/main/java/com/example/auth/RateLimiter.java:197-204` |
| SEC-02 | Cleartext Session Credential Exposure in CLI Standard Output | High | CWE-532 | `src/main/java/com/example/auth/Main.java:85-88` |
| SEC-03 | Thread Starvation Denial of Service via Synchronous Sleep Throttling | Medium | CWE-400 | `src/main/java/com/example/auth/AuthenticationService.java:72-80` |
| SEC-04 | Silent Password Truncation and Encoding Corruption in Password Stream Reader | Medium | CWE-1188 | `src/main/java/com/example/auth/Main.java:178-195` |
| SEC-05 | Inadequate File Permission Verification and Insecure Permissions on File-Backed Database | Low | CWE-732 | `src/main/java/com/example/auth/DatabaseManager.java:92-121` |

## 5. Detailed Findings

### SEC-01: Unbounded Cache Growth Leading to Denial of Service and Resource Exhaustion
- **Severity:** High
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/example/auth/RateLimiter.java:197-204`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/RateLimiter.java:197-204
    private void evictIfNecessary(long now) {
        if (entryCount.get() > MAX_CACHE_ENTRIES) {
            purgeExpired(sourceTrackers, now);
            purgeExpired(sourceAccountTrackers, now);
            purgeExpired(globalAccountTrackers, now);
            entryCount.set(sourceTrackers.size() + sourceAccountTrackers.size() + globalAccountTrackers.size());
        }
    }
```

**Why it is a problem:**
The rate limiter enforces an arbitrary entry threshold (`MAX_CACHE_ENTRIES = 10_000`), but `evictIfNecessary` only purges entries that are already expired (`isExpired(now)`). If an attacker distributes authentication requests across varied source identifiers or email addresses within the active 5-to-10 minute window, none of the trackers expire. Consequently, zero entries are removed, and the underlying `ConcurrentHashMap` instances continue to allocate memory without bound, resulting in JVM heap exhaustion (Out-Of-Memory error). Furthermore, once `entryCount` exceeds 10,000, every subsequent request triggers an $O(N)$ linear traversal across all three maps, causing severe CPU spikes and degrading service response times. (A corresponding vulnerability exists in `SessionManager.java:115-125`).

**Fix:**
Enforce an absolute capacity ceiling by implementing LRU (Least Recently Used) eviction or by discarding the oldest/excess active trackers when capacity is reached, ensuring memory usage is strictly bounded.
```java
    private void evictIfNecessary(long now) {
        if (entryCount.get() > MAX_CACHE_ENTRIES) {
            purgeExpired(sourceTrackers, now);
            purgeExpired(sourceAccountTrackers, now);
            purgeExpired(globalAccountTrackers, now);

            // Enforce hard bound if unexpired entries still exceed capacity
            int currentTotal = sourceTrackers.size() + sourceAccountTrackers.size() + globalAccountTrackers.size();
            if (currentTotal > MAX_CACHE_ENTRIES) {
                dropExcessEntries(sourceTrackers, MAX_CACHE_ENTRIES / 3);
                dropExcessEntries(sourceAccountTrackers, MAX_CACHE_ENTRIES / 3);
                dropExcessEntries(globalAccountTrackers, MAX_CACHE_ENTRIES / 3);
                currentTotal = sourceTrackers.size() + sourceAccountTrackers.size() + globalAccountTrackers.size();
            }
            entryCount.set(currentTotal);
        }
    }

    private <K> void dropExcessEntries(ConcurrentHashMap<K, AttemptTracker> map, int targetSize) {
        Iterator<Map.Entry<K, AttemptTracker>> it = map.entrySet().iterator();
        while (it.hasNext() && map.size() > targetSize) {
            it.next();
            it.remove();
        }
    }
```

---

### SEC-02: Cleartext Session Credential Exposure in CLI Standard Output
- **Severity:** High
- **CWE:** CWE-532: Insertion of Sensitive Information into Log File
- **Location:** `src/main/java/com/example/auth/Main.java:85-88`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/Main.java:85-88
                result.getSession().ifPresent(session -> {
                    System.out.println("Session Token: " + SecurityLogger.maskToken(session.sessionId()));
                    System.out.println("Cookie: " + session.cookieHeader());
                });
```

**Why it is a problem:**
On line 86, the program carefully masks the session token using `SecurityLogger.maskToken` (e.g. `abcd...1234`). However, on line 87, the entire HTTP cookie header (`session.cookieHeader()`) is printed directly to standard output. Because `cookieHeader` is constructed as `"__Host-AuthSession=" + token + "..."`, it contains the full, raw, unmasked 256-bit session token. This completely negates the masking on line 86 and exposes the active session credential in cleartext to terminal scrollback buffers, process monitoring utilities, pipeline logs, shell history/redirection files, and local shoulder surfers.

**Fix:**
Mask the session token within the displayed cookie header, or avoid printing the raw session cookie to standard output.
```java
                result.getSession().ifPresent(session -> {
                    System.out.println("Session Token: " + SecurityLogger.maskToken(session.sessionId()));
                    String maskedCookie = String.format(
                            "__Host-AuthSession=%s; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=%d",
                            SecurityLogger.maskToken(session.sessionId()),
                            SessionManager.DEFAULT_SESSION_DURATION_SECONDS
                    );
                    System.out.println("Cookie: " + maskedCookie);
                });
```

---

### SEC-03: Thread Starvation Denial of Service via Synchronous Sleep Throttling
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/example/auth/AuthenticationService.java:72-80`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/AuthenticationService.java:72-80
            if (rateCheck.progressiveDelayMs() > 0) {
                try {
                    Thread.sleep(rateCheck.progressiveDelayMs());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    SecurityLogger.logSystemError("Authentication thread interrupted during throttle delay", e);
                    return AuthenticationResult.internalError();
                }
            }
```

**Why it is a problem:**
When an account receives repeated failed authentication attempts, `RateLimiter` computes a progressive delay between 500ms and 3,000ms. `AuthenticationService` enforces this delay by calling `Thread.sleep()` synchronously on the executing thread. In a multi-threaded application (e.g., a web server or worker thread pool), an attacker targeting an account can open a small number of concurrent requests (e.g., 50-100 connections). Because each request holds and blocks its execution thread for up to 3 seconds, all available threads in the worker pool are rapidly exhausted, causing complete denial of service across all users and system operations (thread starvation).

**Fix:**
Do not block worker threads with synchronous `Thread.sleep()`. Instead, immediately return a rate-limited status indicating that the client should retry after the specified backoff period, or manage delays via non-blocking asynchronous scheduling.
```java
            if (rateCheck.progressiveDelayMs() > 0) {
                SecurityLogger.logRateLimitExceeded(safeEmail, safeSource, "PROGRESSIVE_THROTTLE");
                return AuthenticationResult.rateLimited();
            }
```

---

### SEC-04: Silent Password Truncation and Encoding Corruption in Password Stream Reader
- **Severity:** Medium
- **CWE:** CWE-1188: Insecure Default Initialization of Resource
- **Location:** `src/main/java/com/example/auth/Main.java:178-195`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/Main.java:178-195
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

**Why it is a problem:**
1. **Silent Password Truncation**: When reading credentials from standard input (non-interactive mode), if a password exceeds `MAX_PASSWORD_LENGTH` (128 characters), `readPasswordDirect` ignores any characters beyond 128 and returns the first 128 characters. This silently truncates the password without raising an error or notifying the user. An account registered with a 140-character password will be stored with only the first 128 characters, allowing anyone who enters those 128 characters to authenticate. It also completely bypasses `InputValidator.isValidPasswordForCreation` and `isValidPasswordForAuth`, which are meant to strictly reject out-of-bound passwords. (By contrast, `Console.readPassword()` does not truncate, creating inconsistent validation behavior).
2. **Character Encoding Corruption**: Line 188 performs `buffer[len++] = (char) b`, casting raw individual bytes (0-255) from `InputStream.read()` directly to `char`. For UTF-8 multi-byte characters (such as accented letters, non-Latin scripts, and symbols), each byte of the multi-byte sequence is converted into a distinct `char` rather than decoding the Unicode code point, corrupting the password and causing cross-environment authentication failures.

**Fix:**
Wrap the stream in an explicit `InputStreamReader` configured with UTF-8, and track whether the input exceeded `MAX_PASSWORD_LENGTH`. If overflow occurs, return a buffer larger than the maximum so that `InputValidator` properly rejects the candidate password rather than silently truncating it.
```java
    private static char[] readPasswordDirect(InputStream in) throws IOException {
        InputStreamReader reader = new InputStreamReader(in, StandardCharsets.UTF_8);
        char[] buffer = new char[InputValidator.MAX_PASSWORD_LENGTH + 1];
        int len = 0;
        int c;
        boolean overflow = false;
        while ((c = reader.read()) != -1) {
            if (c == '\n') {
                break;
            }
            if (c != '\r') {
                if (len < InputValidator.MAX_PASSWORD_LENGTH) {
                    buffer[len++] = (char) c;
                } else {
                    overflow = true;
                }
            }
        }
        if (overflow) {
            Arrays.fill(buffer, '\0');
            // Return buffer exceeding MAX_PASSWORD_LENGTH to fail validation cleanly
            return new char[InputValidator.MAX_PASSWORD_LENGTH + 1];
        }
        char[] password = Arrays.copyOf(buffer, len);
        Arrays.fill(buffer, '\0');
        return password;
    }
```

---

### SEC-05: Inadequate File Permission Verification and Insecure Permissions on File-Backed Database
- **Severity:** Low
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `src/main/java/com/example/auth/DatabaseManager.java:92-121`

**Vulnerable code:**
```java
// src/main/java/com/example/auth/DatabaseManager.java:92-121
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
```

**Why it is a problem:**
1. **URL Scheme Bypass**: The check `jdbcUrl.startsWith("jdbc:h2:./") || jdbcUrl.startsWith("jdbc:h2:/")` fails to match valid H2 file URLs using `jdbc:h2:file:`, `jdbc:h2:~/`, or relative paths without leading dots (e.g., `jdbc:h2:data/authdb`). For any such configured URL, permission hardening is entirely skipped, allowing the database file (`.mv.db`) to be created with the system umask default (typically `0644`, world-readable).
2. **Directory Permission Overwrite**: If a relative path such as `jdbc:h2:./authdb` is specified, `path.getParent()` evaluates to `.`. Line 111 then applies `rwx------` (0700) to the current working directory, potentially breaking other applications or group access sharing that directory.
3. **Creation Window of Exposure**: The database file is created by H2 during connection establishment before its file permissions are restricted, leaving a window where unauthorized local users can read password hashes.

**Fix:**
Normalize the JDBC path across all H2 file URI schemes, verify that the parent directory is not the current working directory before restricting permissions, and enforce permission restrictions reliably.
```java
        if (jdbcUrl.startsWith("jdbc:h2:./") || jdbcUrl.startsWith("jdbc:h2:/") || jdbcUrl.startsWith("jdbc:h2:file:")) {
            try {
                String rawPath = jdbcUrl.replaceFirst("^jdbc:h2:(file:)?", "");
                int semicolonIdx = rawPath.indexOf(';');
                if (semicolonIdx >= 0) {
                    rawPath = rawPath.substring(0, semicolonIdx);
                }
                Path path = Paths.get(rawPath).toAbsolutePath().normalize();
                Path parent = path.getParent();
                Path cwd = Paths.get("").toAbsolutePath().normalize();
                if (parent != null && !parent.equals(cwd)) {
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

                if (supportsPosix()) {
                    Path dbFile = Paths.get(path.toString() + ".mv.db");
                    if (Files.exists(dbFile)) {
                        Files.setPosixFilePermissions(dbFile, PosixFilePermissions.fromString("rw-------"));
                    }
                }
            } catch (IOException e) {
                SecurityLogger.logSystemError("Failed to set secure file permissions for database directory/file", e);
            }
        }
```

## 6. Verified Controls and Checks With No Finding
- SQL Injection Prevention (CWE-89): Verified in `UserRepository.java:44-79` and `UserRepository.java:99-108`. All SQL queries (`SELECT_USER_BY_EMAIL`, `INSERT_USER`, `COUNT_USERS`) utilize parameterized `PreparedStatement` with bind variables (`?`). No dynamic SQL concatenation is performed.
- Cryptographic Password Hashing (CWE-916, CWE-328): Verified in `PasswordHasher.java:64-84`. Uses OWASP-compliant `PBKDF2WithHmacSHA256` with 210,000 iterations, a 128-bit cryptographically secure random salt generated via `SecureRandom`, and a 256-bit derived key length.
- Constant-Time Credential Comparison (CWE-208): Verified in `PasswordHasher.java:128`. Credential hashes are compared using `MessageDigest.isEqual()`, mitigating timing attacks on the verification routine.
- User Enumeration & Timing Discrepancy Defense (CWE-204, CWE-208): Verified in `AuthenticationService.java:86-92` and `AuthenticationService.java:104-110`. When an account does not exist or input is malformed, `passwordHasher.verifyDummyPassword()` performs a full PBKDF2 key derivation and constant-time comparison to normalize execution time. User responses are identical (`AuthenticationResult.MSG_INVALID_CREDENTIALS`).
- Memory Hygiene for Credentials (CWE-244, CWE-316): Verified in `AuthenticationService.java:136-140`, `PasswordHasher.java:79-82`, `PasswordHasher.java:131-140`, and `Main.java:95-97`. All sensitive character arrays (`passwordChars`) and intermediate byte arrays (`salt`, `derivedKey`) are zeroized with `Arrays.fill(..., '\0')` in `finally` blocks.
- Session Identifier Entropy & Generation (CWE-330): Verified in `SessionManager.java:64-75`. Session tokens are 256 bits (32 bytes) of entropy generated using `SecureRandom`, encoded using URL-safe Base64 without padding.
- Secure Cookie Attributes (CWE-614, CWE-1004, CWE-1275): Verified in `SessionManager.java:79-84`. Issued session cookies enforce the `__Host-` prefix, `Path=/`, `Secure`, `HttpOnly`, `SameSite=Strict`, and explicit `Max-Age`.
- Log Injection / CRLF Neutralization (CWE-117): Verified in `SecurityLogger.java:87-92`. All logged parameters (emails, source IDs, internal reasons) are sanitized using `sanitizeCrlf()` which replaces `\r` and `\n` characters with underscores.
- PII Masking in Audit Logs (CWE-359): Verified in `SecurityLogger.java:45-69` and `SecurityLogger.java:74-82`. Email addresses and session tokens are masked prior to being logged.
- Concurrency & Check-Then-Act Atomicity in Rate Limiting (CWE-362): Verified in `RateLimiter.java:49-93`. All attempt counter evaluations and increments (`tryAcquire`, `reset`, `getCount`) are synchronized per tracker instance, preventing concurrent race conditions during threshold checks.
