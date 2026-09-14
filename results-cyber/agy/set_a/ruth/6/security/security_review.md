# Security Review: AuthenticationSystem

## 1. Executive Summary
The target codebase is a self-contained Java user authentication and security audit logging system implemented in `AuthenticationSystem.java`. It provides account registration, credential verification using salted PBKDF2-HMAC-SHA256 password hashing, brute-force mitigation through account lockout, and structured key-value audit logging to both console and file destinations.

While the implementation incorporates several sound cryptographic primitives—such as constant-time hash comparisons via `MessageDigest.isEqual`, 100,000 PBKDF2 iterations with unique 16-byte cryptographically secure salts, and dummy hash calculations to mitigate timing side-channels—the security review identified **9 security vulnerabilities**:
- **2 High severity issues**: A race condition in lockout evaluation that permits brute-force credential guessing under concurrent load (CWE-362 / CWE-307), and an unescaped parameter in user registration logging that enables CRLF log injection and entry forging (CWE-117).
- **4 Medium severity issues**: An observable response discrepancy in lockout messages that enables unauthenticated user enumeration (CWE-204), plaintext password exposure in process arguments combined with a hardcoded administrative backdoor (CWE-214 / CWE-798), insecure world-readable default permissions (0644) and lack of file rotation on the audit log (CWE-732 / CWE-770), and lack of password complexity or length validation during registration (CWE-521).
- **3 Low severity issues**: Public exposure of internal mutable byte arrays for password hashes and salts (CWE-375 / CWE-495), retention of plaintext password copies in heap memory via `PBEKeySpec` and String overloads (CWE-316), and locale-sensitive case folding during username indexing (CWE-178).

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `AuthenticationSystem.java` | Core authentication, repository, cryptography, audit logging, and CLI execution harness | Password hashing (PBKDF2), timing attack mitigation, account lockout, credential validation, audit logging, user input sanitization, and CLI argument handling |
| `authentication_audit.log` | Persistent application audit trail | Storage of authentication success/failure events, usernames, client IP addresses, lockout events, and administrative actions |
| `README.md` | System documentation and operational runbook | Architectural claims, security posture descriptions, threat mitigation rationales, and execution commands |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to audit password hashing algorithms (`PBKDF2WithHmacSHA256`), iteration count (100,000), salt generation (`SecureRandom`), constant-time comparison (`MessageDigest.isEqual`), dummy verification side-channel defense, and key derivation parameter management in `PasswordSecurity`.
- `testing-api-authentication-weaknesses`: Applied to evaluate authentication flows, credential verification logic, brute-force protections, account lockout behavior, user existence checks, and user enumeration resistance in `AuthenticationService` and `AuthenticationResult`.
- `testing-for-sensitive-data-exposure`: Applied to evaluate sensitive data handling in memory (`char[]` vs `String`, zeroization routines, `PBEKeySpec` lifecycle), exposure of credentials via CLI arguments, and absence of sensitive credential material in audit logs (`AuditEvent`).
- General OWASP Top 10 / CWE Knowledge:
  - Reviewed against **CWE-117 (Improper Output Handling for Logs)**: Evaluated log injection sanitization, CRLF neutralization (`sanitizeForLog`), and log parameter interpolation across all audit event types.
  - Reviewed against **CWE-732 (Incorrect Permission Assignment)** and **CWE-770 (Allocation of Resources Without Limits or Throttling)**: Evaluated filesystem permissions and unbounded growth in `AuditLogger.initializeLogger` (`FileHandler`).
  - Reviewed against **CWE-362 (Race Condition) / CWE-367 (Time-of-check Time-of-use)**: Evaluated concurrency and shared state synchronization during simultaneous login attempts on `UserAccount`.
  - Reviewed against **CWE-178 (Improper Handling of Case Sensitivity)**: Evaluated case-folding operations in `InMemoryUserRepository` under non-ASCII and international locales.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Race Condition in Account Lockout Enforcement Enables Brute-Force Bypass | High | CWE-362 | `AuthenticationSystem.java:678-713` |
| SEC-02 | Log Injection and Log Forging via Unsanitized `role` Parameter in Registration Audit Log | High | CWE-117 | `AuthenticationSystem.java:520-532` |
| SEC-03 | User Enumeration via Observable Response Discrepancy on Account Lockout | Medium | CWE-204 | `AuthenticationSystem.java:564-567` |
| SEC-04 | Exposure of Plaintext Password via CLI Arguments and Hardcoded Admin Credentials | Medium | CWE-214 | `AuthenticationSystem.java:762-771` |
| SEC-05 | Insecure Default File Permissions and Unbounded Growth on Audit Log File | Medium | CWE-732 | `AuthenticationSystem.java:350-357` |
| SEC-06 | Missing Password Complexity and Minimum Length Enforcement in Registration | Medium | CWE-521 | `AuthenticationSystem.java:613-616` |
| SEC-07 | Exposure of Mutable Internal Byte Arrays for Password Hash and Salt | Low | CWE-375 | `AuthenticationSystem.java:92-93` |
| SEC-08 | Retention of Plaintext Passwords in Heap Memory via String API and Uncleared `PBEKeySpec` | Low | CWE-316 | `AuthenticationSystem.java:194-201` |
| SEC-09 | Locale-Dependent Case Mapping in Username Normalization | Low | CWE-178 | `AuthenticationSystem.java:152` |

## 5. Detailed Findings

### SEC-01: Race Condition in Account Lockout Enforcement Enables Brute-Force Bypass
- **Severity:** High
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- **Location:** `AuthenticationSystem.java:678-713`

**Vulnerable code:**
```java
// AuthenticationSystem.java:678-713
                // 5. Check Lockout Status
                if (user.isLocked()) {
                    if (user.getLockedUntil() != null && Instant.now().isAfter(user.getLockedUntil())) {
                        // Lockout period expired; automatically unlock
                        user.unlockAccount();
                        auditLogger.logAccountUnlocked(correlationId, trimmedUser, "Lockout duration expired");
                    } else {
                        PasswordSecurity.performDummyVerification(password);
                        auditLogger.logAttemptOnLockedAccount(correlationId, trimmedUser, effectiveIp, user.getLockedUntil(), maxFailedAttempts);
                        return AuthenticationResult.locked(correlationId);
                    }
                }

                // 6. Verify Password (Constant-Time)
                boolean passwordValid = PasswordSecurity.verifyPassword(
                    password,
                    user.getSalt(),
                    user.getIterations(),
                    user.getPasswordHash()
                );

                // 7. Handle Result
                if (passwordValid) {
                    user.recordSuccess();
                    auditLogger.logSuccess(correlationId, trimmedUser, effectiveIp, maxFailedAttempts);
                    return AuthenticationResult.success(user.getUsername(), user.getRole(), correlationId);
                } else {
                    int currentFailed = user.incrementFailedAttempts();
                    if (currentFailed >= maxFailedAttempts) {
                        user.lockAccount(lockoutDuration);
                        auditLogger.logAccountLocked(correlationId, trimmedUser, effectiveIp, maxFailedAttempts, lockoutDuration);
                        return AuthenticationResult.locked(correlationId);
                    } else {
                        auditLogger.logBadPassword(correlationId, trimmedUser, effectiveIp, currentFailed, maxFailedAttempts);
                        return AuthenticationResult.failure(correlationId);
                    }
                }
```

**Why it is a problem:**
`AuthenticationService.authenticate()` is not synchronized, and the account lockout check (`user.isLocked()`) occurs prior to the computationally intensive password verification step (`PasswordSecurity.verifyPassword()`, which executes 100,000 PBKDF2 iterations taking ~50-100ms).

An attacker can transmit dozens or hundreds of concurrent login attempts in parallel for a targeted account. Because all parallel threads check `user.isLocked()` before any single request completes its PBKDF2 hash and increments `failedAttempts` at line 704, every concurrent thread passes the lockout check while `failedAttempts < maxFailedAttempts`. All threads proceed to verify their candidate passwords against the stored hash. This time-of-check to time-of-use (TOCTOU) race condition allows attackers to bypass the 5-attempt brute-force restriction (CWE-307) and test large password batches without being locked out.

**Fix:**
Synchronize the lockout verification and attempt recording around the user account, or atomically track in-flight verification requests per user to ensure that no further verification occurs once the failure threshold or concurrency threshold is reached.
```java
                boolean passwordValid;
                int currentFailed = 0;
                boolean shouldLock = false;
                boolean isCurrentlyLocked = false;
                Instant lockedUntil = null;

                synchronized (user) {
                    if (user.isLocked()) {
                        if (user.getLockedUntil() != null && Instant.now().isAfter(user.getLockedUntil())) {
                            user.unlockAccount();
                            auditLogger.logAccountUnlocked(correlationId, trimmedUser, "Lockout duration expired");
                        } else {
                            isCurrentlyLocked = true;
                            lockedUntil = user.getLockedUntil();
                        }
                    }
                }

                if (isCurrentlyLocked) {
                    PasswordSecurity.performDummyVerification(password);
                    auditLogger.logAttemptOnLockedAccount(correlationId, trimmedUser, effectiveIp, lockedUntil, maxFailedAttempts);
                    return AuthenticationResult.failure(correlationId);
                }

                passwordValid = PasswordSecurity.verifyPassword(
                    password,
                    user.getSalt(),
                    user.getIterations(),
                    user.getPasswordHash()
                );

                synchronized (user) {
                    if (passwordValid) {
                        if (user.isLocked()) {
                            auditLogger.logAttemptOnLockedAccount(correlationId, trimmedUser, effectiveIp, user.getLockedUntil(), maxFailedAttempts);
                            return AuthenticationResult.failure(correlationId);
                        }
                        user.recordSuccess();
                    } else {
                        currentFailed = user.incrementFailedAttempts();
                        if (currentFailed >= maxFailedAttempts) {
                            user.lockAccount(lockoutDuration);
                            shouldLock = true;
                        }
                    }
                }

                if (passwordValid) {
                    auditLogger.logSuccess(correlationId, trimmedUser, effectiveIp, maxFailedAttempts);
                    return AuthenticationResult.success(user.getUsername(), user.getRole(), correlationId);
                } else if (shouldLock) {
                    auditLogger.logAccountLocked(correlationId, trimmedUser, effectiveIp, maxFailedAttempts, lockoutDuration);
                    return AuthenticationResult.failure(correlationId);
                } else {
                    auditLogger.logBadPassword(correlationId, trimmedUser, effectiveIp, currentFailed, maxFailedAttempts);
                    return AuthenticationResult.failure(correlationId);
                }
```

---

### SEC-02: Log Injection and Log Forging via Unsanitized `role` Parameter in Registration Audit Log
- **Severity:** High
- **CWE:** CWE-117: Improper Output Handling for Logs
- **Location:** `AuthenticationSystem.java:520-532`

**Vulnerable code:**
```java
// AuthenticationSystem.java:520-532
        public void logUserRegistered(String correlationId, String username, String role, String clientIp) {
            AuditEvent event = new AuditEvent(
                correlationId,
                AuditEventType.USER_REGISTERED,
                sanitizeForLog(username),
                sanitizeForLog(clientIp),
                "SUCCESS",
                "ACCOUNT_PROVISIONED",
                0,
                0,
                "New user registered with role " + role
            );
            logEvent(Level.INFO, event);
        }
```

**Why it is a problem:**
While `username` and `clientIp` are processed through `sanitizeForLog()`, the `role` parameter is concatenated directly into the `details` field (`"New user registered with role " + role`). `registerUser()` (lines 610-627) accepts `role` directly from caller input without validation or character restrictions. Furthermore, `AuditEvent.toStructuredLogString()` embeds `details` directly into `details=\"%s\"` without performing any sanitization.

If a registration request supplies a `role` containing newline characters (`\r\n`), the newline is written directly to `authentication_audit.log` via the `FileHandler` custom formatter (`record.getMessage() + System.lineSeparator()`). This enables an attacker to inject arbitrary counterfeit audit log records (for example, forging fraudulent `AUTH_SUCCESS` events or attributing actions to administrators). Additionally, injecting unescaped quotation marks (`"`) breaks key-value pair parsing in SIEM log parsers.

**Fix:**
Sanitize `role` using `sanitizeForLog()`, validate `role` against an allowlist of valid roles, and sanitize `details` inside `AuditEvent.toStructuredLogString()` as a defensive boundary control.
```java
        public void logUserRegistered(String correlationId, String username, String role, String clientIp) {
            String safeRole = sanitizeForLog(role != null ? role : "USER");
            AuditEvent event = new AuditEvent(
                correlationId,
                AuditEventType.USER_REGISTERED,
                sanitizeForLog(username),
                sanitizeForLog(clientIp),
                "SUCCESS",
                "ACCOUNT_PROVISIONED",
                0,
                0,
                "New user registered with role " + safeRole
            );
            logEvent(Level.INFO, event);
        }
```

---

### SEC-03: User Enumeration via Observable Response Discrepancy on Account Lockout
- **Severity:** Medium
- **CWE:** CWE-204: Observable Response Discrepancy
- **Location:** `AuthenticationSystem.java:564-567`

**Vulnerable code:**
```java
// AuthenticationSystem.java:564-567
        public static AuthenticationResult locked(String correlationId) {
            // Can be generic or slightly informative; generic prevents account enumeration
            return new AuthenticationResult(false, "Invalid username or password or account is locked", null, null, correlationId);
        }
```

**Why it is a problem:**
When an authentication attempt fails on an active account, `AuthenticationResult.failure()` returns the generic message `"Invalid username or password"`. However, when an account is locked (lines 686 and 708), `AuthenticationResult.locked()` returns `"Invalid username or password or account is locked"`.

For a non-existent username, `userOpt.isEmpty()` is always triggered (line 662), consistently returning `AuthenticationResult.failure()` regardless of how many failed attempts are submitted. For an existing username, submitting 5 consecutive invalid passwords triggers `user.lockAccount()`, changing the response message to `"Invalid username or password or account is locked"`. An external unauthenticated attacker can therefore enumerate valid usernames by submitting 5 incorrect passwords for target candidate usernames and observing whether the response message changes.

**Fix:**
Return the identical, uniform error message (`"Invalid username or password"`) across all authentication failure modes, including lockout. Keep the lockout distinction purely in internal audit logs.
```java
        public static AuthenticationResult locked(String correlationId) {
            // Return uniform error message to prevent user enumeration
            return new AuthenticationResult(false, "Invalid username or password", null, null, correlationId);
        }
```

---

### SEC-04: Exposure of Plaintext Password via CLI Arguments and Hardcoded Admin Credentials
- **Severity:** Medium
- **CWE:** CWE-214: Invocation of Process Using Visible Sensitive Information
- **Location:** `AuthenticationSystem.java:762-771`

**Vulnerable code:**
```java
// AuthenticationSystem.java:762-771
            } else if ("--login".equalsIgnoreCase(args[0]) && args.length >= 3) {
                String username = args[1];
                String password = args[2];
                String ip = (args.length >= 4) ? args[3] : "127.0.0.1";
                // Register a default user if database is empty
                authService.registerUser("admin", "AdminSecret123!".toCharArray(), "ADMINISTRATOR", "127.0.0.1");
                AuthenticationResult result = authService.authenticate(username, password.toCharArray(), ip);
                System.out.println("Authentication Outcome: " + result);
                return;
            }
```

**Why it is a problem:**
1. **Plaintext CLI Argument Exposure (CWE-214)**: The `--login` CLI command reads the user password directly from `args[2]`. Command-line arguments are visible in the operating system's process table to all local users via `ps aux`, `top`, or `/proc/<pid>/cmdline`, and are stored in shell history files (`.bash_history`).
2. **Hardcoded Credentials (CWE-798)**: Line 767 silently provisions a default administrative account with the hardcoded username `"admin"` and password `"AdminSecret123!"` whenever `--login` is executed. Hardcoded credentials embedded in source code can be extracted and abused by attackers to gain administrative access.

**Fix:**
Remove hardcoded administrative provisioning from the login handler. Prompt for passwords interactively using `System.console().readPassword()` without echoing characters or exposing them via process arguments.
```java
            } else if ("--login".equalsIgnoreCase(args[0]) && args.length >= 2) {
                String username = args[1];
                String ip = (args.length >= 3) ? args[2] : "127.0.0.1";
                char[] password;
                if (System.console() != null) {
                    password = System.console().readPassword("Enter password for %s: ", username);
                } else {
                    Scanner scanner = new Scanner(System.in);
                    System.out.printf("Enter password for %s: ", username);
                    password = scanner.nextLine().toCharArray();
                }
                AuthenticationResult result = authService.authenticate(username, password, ip);
                System.out.println("Authentication Outcome: " + result);
                return;
            }
```

---

### SEC-05: Insecure Default File Permissions and Unbounded Growth on Audit Log File
- **Severity:** Medium
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `AuthenticationSystem.java:350-357`

**Vulnerable code:**
```java
// AuthenticationSystem.java:350-357
            // File audit trail output
            try {
                FileHandler fileHandler = new FileHandler(logFilePath, true);
                fileHandler.setLevel(Level.ALL);
                fileHandler.setFormatter(customFormatter);
                LOGGER.addHandler(fileHandler);
            } catch (IOException e) {
                System.err.println("Warning: Could not create audit log file: " + e.getMessage());
            }
```

**Why it is a problem:**
1. **Insecure Permissions (CWE-732 / CWE-276)**: `new FileHandler(logFilePath, true)` creates `authentication_audit.log` using the process default umask. On Linux systems, this results in world-readable permissions (`0644` / `rw-r--r--`). Audit logs contain sensitive operational security metadata—including valid usernames, client IP addresses, authentication attempt volumes, and lockout statuses—which are exposed to all local unprivileged users and container co-tenants.
2. **Unbounded Growth / Denial of Service (CWE-770 / CWE-400)**: Calling `FileHandler(logFilePath, true)` configures append mode without setting a maximum file size limit or log rotation count. During high traffic or credential-stuffing attacks, the log file will grow without bound until disk space is exhausted, causing system denial of service.

**Fix:**
Explicitly set restrictive POSIX permissions (`0600` - owner read/write only) upon file creation, and configure `FileHandler` with file size limits and rotation counts.
```java
            // File audit trail output with rotation and restricted permissions
            try {
                File logFile = new File(logFilePath);
                if (!logFile.exists()) {
                    boolean created = logFile.createNewFile();
                    if (created) {
                        logFile.setReadable(false, false);
                        logFile.setReadable(true, true);
                        logFile.setWritable(false, false);
                        logFile.setWritable(true, true);
                        logFile.setExecutable(false, false);
                    }
                }
                // Rotate logs at 10 MB with up to 5 archive files
                int limitBytes = 10 * 1024 * 1024;
                int fileCount = 5;
                FileHandler fileHandler = new FileHandler(logFilePath, limitBytes, fileCount, true);
                fileHandler.setLevel(Level.ALL);
                fileHandler.setFormatter(customFormatter);
                LOGGER.addHandler(fileHandler);
            } catch (IOException e) {
                System.err.println("Warning: Could not create audit log file: " + e.getMessage());
            }
```

---

### SEC-06: Missing Password Complexity and Minimum Length Enforcement in Registration
- **Severity:** Medium
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `AuthenticationSystem.java:613-616`

**Vulnerable code:**
```java
// AuthenticationSystem.java:613-616
                if (username == null || username.trim().isEmpty() || password == null || password.length == 0) {
                    auditLogger.logInvalidInput(correlationId, username, clientIp, "Username or password cannot be empty during registration", maxFailedAttempts);
                    return false;
                }
```

**Why it is a problem:**
`registerUser()` only verifies that `password` is non-null and `password.length > 0`. It does not enforce a minimum length (e.g. at least 12 characters per modern NIST/OWASP guidance), nor does it enforce character complexity or block easily guessable single-character passwords. Users can register passwords as short as 1 character (e.g. `"a"`), making accounts trivial to compromise through online guessing or offline dictionary attacks if hashes are exposed.

**Fix:**
Enforce an adequate minimum password length (e.g. 12 characters) and reasonable upper bound (e.g. 128 characters) during registration.
```java
                if (username == null || username.trim().isEmpty()) {
                    auditLogger.logInvalidInput(correlationId, username, clientIp, "Username cannot be empty during registration", maxFailedAttempts);
                    return false;
                }
                if (password == null || password.length < 12 || password.length > 128) {
                    auditLogger.logInvalidInput(correlationId, username, clientIp, "Password must be between 12 and 128 characters in length", maxFailedAttempts);
                    return false;
                }
```

---

### SEC-07: Exposure of Mutable Internal Byte Arrays for Password Hash and Salt
- **Severity:** Low
- **CWE:** CWE-375: Returning a Mutable Object to an Untrusted Caller
- **Location:** `AuthenticationSystem.java:92-93`

**Vulnerable code:**
```java
// AuthenticationSystem.java:92-93
        public byte[] getPasswordHash() { return passwordHash; }
        public byte[] getSalt() { return salt; }
```

**Why it is a problem:**
In Java, arrays are mutable objects. `UserAccount.getPasswordHash()` and `UserAccount.getSalt()` return direct references to internal `byte[]` fields. Any external component or caller that obtains a `UserAccount` reference can directly modify the contents of the array (for example, zeroing or modifying elements via `user.getPasswordHash()[0] = 0`), corrupting the stored credentials in memory and causing authentication failures.

**Fix:**
Return defensive copies of internal arrays in getters to maintain encapsulation (CWE-495 / CWE-375).
```java
        public byte[] getPasswordHash() { return passwordHash != null ? passwordHash.clone() : null; }
        public byte[] getSalt() { return salt != null ? salt.clone() : null; }
```

---

### SEC-08: Retention of Plaintext Passwords in Heap Memory via String API and Uncleared `PBEKeySpec`
- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `AuthenticationSystem.java:194-201`

**Vulnerable code:**
```java
// AuthenticationSystem.java:194-201
        public static byte[] hashPassword(char[] password, byte[] salt, int iterations) {
            try {
                PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_LENGTH_BITS);
                SecretKeyFactory factory = SecretKeyFactory.getInstance(HASH_ALGORITHM);
                return factory.generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IllegalStateException("Cryptographic key derivation failed for " + HASH_ALGORITHM, e);
            }
        }
```

**Why it is a problem:**
1. `PBEKeySpec` creates an internal copy of the `char[] password` array in its constructor. Without explicitly calling `spec.clearPassword()` in a `finally` block, this copy remains in JVM heap memory until the object is garbage-collected.
2. In addition, `AuthenticationService` provides convenience methods (lines 723-733) that accept passwords as immutable `java.lang.String` objects (`authenticate(String username, String password, String clientIp)`). Strings cannot be zeroed out in memory, persisting in the JVM heap and heap dumps.

**Fix:**
Ensure `spec.clearPassword()` is always called in a `finally` block inside `hashPassword()`, and deprecate or remove the `String`-accepting `authenticate()` overloads in favor of `char[]`.
```java
        public static byte[] hashPassword(char[] password, byte[] salt, int iterations) {
            PBEKeySpec spec = null;
            try {
                spec = new PBEKeySpec(password, salt, iterations, HASH_LENGTH_BITS);
                SecretKeyFactory factory = SecretKeyFactory.getInstance(HASH_ALGORITHM);
                return factory.generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IllegalStateException("Cryptographic key derivation failed for " + HASH_ALGORITHM, e);
            } finally {
                if (spec != null) {
                    spec.clearPassword();
                }
            }
        }
```

---

### SEC-09: Locale-Dependent Case Mapping in Username Normalization
- **Severity:** Low
- **CWE:** CWE-178: Improper Handling of Case Sensitivity
- **Location:** `AuthenticationSystem.java:152`

**Vulnerable code:**
```java
// AuthenticationSystem.java:152
            return Optional.ofNullable(users.get(username.toLowerCase().trim()));
```

**Why it is a problem:**
`InMemoryUserRepository` normalizes usernames using `username.toLowerCase().trim()`. In Java, `String.toLowerCase()` without parameters uses the host system's default locale (`Locale.getDefault()`).

In locales such as Turkish (`tr`) or Azeri (`az`), uppercase `'I'` does not convert to lowercase `'i'`; instead it converts to `'\u0131'` (dotless lowercase i), and lowercase `'i'` converts to `'\u0130'` (dotted uppercase I). If the application executes in such a locale, lookups for usernames containing `'I'` or `'i'` (e.g. `"ADMIN"`, `"alice"`) will fail to match or can result in account collision and authorization bypasses.

**Fix:**
Specify `Locale.ROOT` in all `toLowerCase()` operations to ensure deterministic, locale-invariant ASCII case folding.
```java
            return Optional.ofNullable(users.get(username.toLowerCase(java.util.Locale.ROOT).trim()));
```

## 6. Verified Controls and Checks With No Finding
- **Cryptographic Password Hashing Algorithm**: Verified in `AuthenticationSystem.PasswordSecurity` (lines 172-202) that passwords are hashed using `PBKDF2WithHmacSHA256` with 100,000 iterations and a 16-byte random salt generated via `SecureRandom`. Weak algorithms such as MD5, SHA-1, single-iteration SHA-256, and unsalted hashes were verified to be absent.
- **Constant-Time Hash Comparison**: Verified in `AuthenticationSystem.PasswordSecurity.verifyPassword` (line 211) that hash comparisons use `MessageDigest.isEqual()`, mitigating side-channel timing discrepancy attacks on stored password hashes (CWE-208).
- **Non-Existent User Timing Defense**: Verified in `AuthenticationSystem.AuthenticationService.authenticate` (lines 662-666) and `PasswordSecurity.performDummyVerification` (lines 218-223) that authentication requests for non-existent users trigger a full 100,000-iteration PBKDF2 dummy calculation, ensuring response latency is consistent with existing user verifications (CWE-208).
- **Credential Sanitization in Logs**: Verified in `AuthenticationSystem.AuditEvent` (lines 263-314) that neither plaintext passwords, password hashes, nor salts are stored in `AuditEvent` fields or output by `toStructuredLogString()`, preventing credential leakage in log files (CWE-532).
- **Cryptographic Identifier Generation**: Verified in `AuthenticationSystem.AuthenticationService.authenticate` (line 638) that request correlation IDs are generated using `UUID.randomUUID()`, providing cryptographically secure pseudo-random 128-bit identifiers.
- **Immediate Memory Clearing on Normal Paths**: Verified in `AuthenticationSystem.AuthenticationService.authenticate` (line 716) and `registerUser` (line 629) that the submitted `char[] password` is cleared using `Arrays.fill(password, '\0')` in `finally` blocks upon completion.
- **SQL / Command Injection**: Verified that the codebase does not construct SQL queries, LDAP queries, or operating system commands, eliminating CWE-89, CWE-90, and CWE-78 risks.
