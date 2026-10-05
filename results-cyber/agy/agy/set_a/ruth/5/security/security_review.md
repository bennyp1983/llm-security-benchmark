# Security Review: Java User Authentication and Login System

## 1. Executive Summary
The target system is a standalone Java authentication service implemented in `LoginSystem.java` and documented in `README.md`. It provides credential verification using PBKDF2-HMAC-SHA256 password hashing with per-user cryptographic salts, constant-time hash comparisons, dummy cryptographic verification to resist timing attacks, account lockout policies with sliding failure windows, IP-based sliding-window rate limiting, in-memory account storage, and security audit logging.

While the implementation incorporates several sound cryptographic design choices (such as 210,000 PBKDF2 iterations and `MessageDigest.isEqual`), the review identified multiple significant vulnerabilities. Most notably, the response message and status object disclose whether a username exists via differential `remainingAttempts` values, completely bypassing the dummy hashing defense (CWE-204). Additionally, accepting client-supplied timestamps in `LoginRequest` allows attackers to bypass account lockout and rate limiting windows (CWE-20), and passing null or blank IP addresses completely bypasses IP rate limiting (CWE-307). Secondary findings include unbounded memory growth in the rate limiter (CWE-400), timing discrepancies on locked accounts (CWE-208), hardcoded demo credentials in source and documentation (CWE-798), sensitive credential retention in memory (CWE-316), and command-line / console credential exposure (CWE-214, CWE-522).

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `LoginSystem.java` | Core Java implementation containing authentication service, password hashing, account lockout management, IP rate limiting, user repository, and CLI/interactive runners. | Password hashing (PBKDF2-HMAC-SHA256), constant-time comparison, dummy verification, account lockout state tracking, client IP sliding-window rate limiting, in-memory user storage, audit logging, and CLI credential input handling. |
| `README.md` | System documentation providing design rationale, security claims, compilation instructions, and verification instructions. | Documents security mechanisms, authentication flows, policy configuration, and hardcoded default test account credentials (`alice` and `bob`). |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to PBKDF2-HMAC-SHA256 parameter configuration, key derivation routines, salt generation using `SecureRandom`, constant-time comparison with `MessageDigest.isEqual()`, and hardcoded credential identification.
- `testing-api-authentication-weaknesses`: Applied to user authentication flows, credential verification logic, username enumeration defenses, response message discrepancy analysis, and account lockout handling.
- `performing-api-rate-limiting-bypass`: Applied to `IpRateLimiter` sliding-window logic, client IP validation, IP header omission/blank handling, and resource consumption limits.
- General OWASP Top 10 / CWE Knowledge: Evaluated memory hygiene and sensitive data handling in heap memory (`PBEKeySpec` and `String` immutability under CWE-316), process argument credential exposure (CWE-214), cleartext terminal password echoing (CWE-522), client-side timestamp trust (CWE-20 / CWE-613), and log delimiter injection (CWE-117).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Response Discrepancy Enables Username Enumeration | High | CWE-204 | `LoginSystem.java:438-442` |
| SEC-02 | Client-Controlled Timestamp Bypasses Lockout and Rate Limiting | High | CWE-20 | `LoginSystem.java:386-391` |
| SEC-03 | Rate Limiter Bypass on Missing or Blank Client IP | High | CWE-307 | `LoginSystem.java:350-353` |
| SEC-04 | Unbounded Memory Growth in IP Rate Limiter Causing Denial of Service | Medium | CWE-400 | `LoginSystem.java:348-356` |
| SEC-05 | Timing Side-Channel on Locked User Accounts | Medium | CWE-208 | `LoginSystem.java:583-592` |
| SEC-06 | Hardcoded User Credentials in Source Code and Documentation | Medium | CWE-798 | `LoginSystem.java:654-655` |
| SEC-07 | Sensitive Credentials Retained in Memory via PBEKeySpec and String Constructors | Medium | CWE-316 | `LoginSystem.java:151-159` |
| SEC-08 | Sensitive Credentials Exposed in Process List via Command-Line Arguments | Low | CWE-214 | `LoginSystem.java:662-669` |
| SEC-09 | Plaintext Password Echo During Interactive Console Authentication | Low | CWE-522 | `LoginSystem.java:819-821` |
| SEC-10 | Delimiter Injection in Structured Audit Log Entries | Low | CWE-117 | `LoginSystem.java:481-485` |

## 5. Detailed Findings

### SEC-01: Response Discrepancy Enables Username Enumeration
- **Severity:** High
- **CWE:** CWE-204: Observable Response Discrepancy
- **Location:** `LoginSystem.java:438-442`

**Vulnerable code:**
```java
// LoginSystem.java:438-442
        public static LoginResult invalidCredentials(int remainingAttempts) {
            String msg = remainingAttempts >= 0
                    ? String.format("Invalid username or password. Remaining attempts before lockout: %d.", remainingAttempts)
                    : "Invalid username or password.";
            return new LoginResult(LoginStatus.INVALID_CREDENTIALS, msg, remainingAttempts, Duration.ZERO, null);
        }
```

**Why it is a problem:**
Although `AuthenticationService.authenticate` invokes `passwordSecurity.performDummyVerification` (line 573) to normalize execution time when a user does not exist, line 575 returns `LoginResult.invalidCredentials(-1)`. Conversely, when a valid username is supplied with an incorrect password, line 624 returns `LoginResult.invalidCredentials(remainingAttempts)` where `remainingAttempts >= 0`.
This creates a distinct observable discrepancy:
1. Non-existent accounts yield `"Invalid username or password."` and `result.getRemainingAttempts() == -1`.
2. Existing accounts yield `"Invalid username or password. Remaining attempts before lockout: X."` and `result.getRemainingAttempts() >= 0`.
An attacker can trivially enumerate valid accounts without timing analysis simply by observing the response message or return object.

**Fix:** Return an identical, generic message and uniform status values regardless of whether the account exists. If lockout warnings are required by business policy, they should not disclose whether an account was found versus not found.
```java
        public static LoginResult invalidCredentials() {
            return new LoginResult(LoginStatus.INVALID_CREDENTIALS, "Invalid username or password.", -1, Duration.ZERO, null);
        }
```

---

### SEC-02: Client-Controlled Timestamp Bypasses Lockout and Rate Limiting
- **Severity:** High
- **CWE:** CWE-20: Improper Input Validation
- **Location:** `LoginSystem.java:386-391`

**Vulnerable code:**
```java
// LoginSystem.java:386-391
        public LoginRequest(String username, char[] password, String clientIp, Instant timestamp) {
            this.username = username;
            this.password = password != null ? password.clone() : new char[0];
            this.clientIp = clientIp;
            this.timestamp = timestamp != null ? timestamp : Instant.now();
        }
```

**Why it is a problem:**
`LoginRequest` accepts an arbitrary client-supplied `timestamp`. In `AuthenticationService.authenticate` (line 549), this client timestamp is used as `Instant now = request.getTimestamp();` for all subsequent security calculations, including account lockout expiration checks (`user.isLocked(now)` in line 242) and rate-limiting window sliding (`now.minus(...)` in line 356).
An attacker whose account has been locked can bypass the lockout duration instantly by supplying a future timestamp in the request. Similarly, an attacker can manipulate sliding-window failure resets and rate limits by forging request timestamps.

**Fix:** Always use the authoritative server-side system clock (`Instant.now()`) inside `AuthenticationService.authenticate` rather than trusting client-provided timestamps.
```java
        public LoginResult authenticate(LoginRequest request) {
            Instant now = Instant.now();
            String username = request.getUsername();
            char[] password = request.getPassword();
            String clientIp = request.getClientIp();
```

---

### SEC-03: Rate Limiter Bypass on Missing or Blank Client IP
- **Severity:** High
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `LoginSystem.java:350-353`

**Vulnerable code:**
```java
// LoginSystem.java:350-353
        public synchronized boolean isAllowed(String ipAddress, Instant now, SecurityPolicy policy) {
            if (ipAddress == null || ipAddress.isBlank()) {
                return true; // No IP tracking available
            }
```

**Why it is a problem:**
When `ipAddress` is null, empty, or whitespace, `IpRateLimiter.isAllowed` immediately returns `true`. If an attacker omits the client IP (such as stripping proxy forwarding headers, sending requests without `clientIp`, or targeting an endpoint that fails to resolve client network metadata), the IP rate limiter is completely bypassed. This enables unrestricted credential stuffing and brute-force attacks against any account.

**Fix:** Enforce rate limiting by tracking requests with missing IP addresses under a shared fallback bucket, or reject authentication requests that fail to provide verifiable client network identification.
```java
        public synchronized boolean isAllowed(String ipAddress, Instant now, SecurityPolicy policy) {
            String trackingKey = (ipAddress == null || ipAddress.isBlank()) ? "UNKNOWN_CLIENT_IP" : ipAddress.trim();
            AttemptWindow window = attemptsByIp.computeIfAbsent(trackingKey, k -> new AttemptWindow());
            Instant cutoff = now.minus(policy.getIpRateLimitWindow());
```

---

### SEC-04: Unbounded Memory Growth in IP Rate Limiter Causing Denial of Service
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `LoginSystem.java:348-356`

**Vulnerable code:**
```java
// LoginSystem.java:348-356
        private final Map<String, AttemptWindow> attemptsByIp = new ConcurrentHashMap<>();

        public synchronized boolean isAllowed(String ipAddress, Instant now, SecurityPolicy policy) {
            if (ipAddress == null || ipAddress.isBlank()) {
                return true; // No IP tracking available
            }

            AttemptWindow window = attemptsByIp.computeIfAbsent(ipAddress, k -> new AttemptWindow());
            Instant cutoff = now.minus(policy.getIpRateLimitWindow());
```

**Why it is a problem:**
The `attemptsByIp` map stores an `AttemptWindow` object for every distinct IP address seen. While timestamps within each `AttemptWindow` are evicted when older than `cutoff`, the map entries themselves are never removed when an IP becomes idle or empty. An attacker sending requests with random or spoofed IP addresses will cause `attemptsByIp` to grow indefinitely, consuming heap space until the JVM experiences an `OutOfMemoryError` and crashes.

**Fix:** Prune empty or expired IP entries from the map periodically or remove the entry if `window.timestamps.isEmpty()` after eviction. Alternatively, use a bounded LRU cache (e.g. `LinkedHashMap` with maximum capacity) or an external store with TTL.
```java
            // Evict timestamps outside the window
            while (!window.timestamps.isEmpty() && window.timestamps.peekFirst().isBefore(cutoff)) {
                window.timestamps.pollFirst();
            }

            if (window.timestamps.isEmpty()) {
                attemptsByIp.remove(ipAddress);
            }
```

---

### SEC-05: Timing Side-Channel on Locked User Accounts
- **Severity:** Medium
- **CWE:** CWE-208: Observable Timing Discrepancy
- **Location:** `LoginSystem.java:583-592`

**Vulnerable code:**
```java
// LoginSystem.java:583-592
                if (user.isLocked(now)) {
                    Duration remaining = user.getRemainingLockoutDuration(now);
                    auditLogger.logEvent("LOGIN_ATTEMPT", username, clientIp, "LOCKED", "Account locked. Remaining=" + remaining.toMinutes() + "m");

                    if (policy.isMaskLockoutInResponse()) {
                        // Strict mode: return generic error to completely mask whether account is locked
                        return LoginResult.invalidCredentials(0);
                    } else {
                        return LoginResult.accountLocked(remaining);
                    }
                }
```

**Why it is a problem:**
When an account is in the `LOCKED` state, the method exits immediately at line 589 or 591 without performing password verification. Computing PBKDF2 takes tens of milliseconds (or more depending on CPU and iteration count), whereas returning at line 589 takes less than 1 millisecond. Even if `policy.isMaskLockoutInResponse()` is enabled, an attacker measuring response latency can distinguish between an active account / non-existent account (which runs PBKDF2) and a locked account (which returns immediately), defeating anti-enumeration measures.

**Fix:** Execute dummy cryptographic verification work when an account is locked before returning the rejection result.
```java
                if (user.isLocked(now)) {
                    // Normalize timing by performing dummy cryptographic work
                    passwordSecurity.performDummyVerification(password, policy.getPbkdf2Iterations(), policy.getHashKeyByteLength());
                    Duration remaining = user.getRemainingLockoutDuration(now);
                    auditLogger.logEvent("LOGIN_ATTEMPT", username, clientIp, "LOCKED", "Account locked. Remaining=" + remaining.toMinutes() + "m");

                    if (policy.isMaskLockoutInResponse()) {
                        return LoginResult.invalidCredentials();
                    } else {
                        return LoginResult.accountLocked(remaining);
                    }
                }
```

---

### SEC-06: Hardcoded User Credentials in Source Code and Documentation
- **Severity:** Medium
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Location:** `LoginSystem.java:654-655`

**Vulnerable code:**
```java
// LoginSystem.java:654-655
        authService.registerUser("alice", "AliceSecurePass123!".toCharArray());
        authService.registerUser("bob", "BobSecretP@ssword!".toCharArray());
```

**Why it is a problem:**
Hardcoded demo credentials (`alice` / `AliceSecurePass123!` and `bob` / `BobSecretP@ssword!`) are committed directly in `LoginSystem.java` and exposed in `README.md`. If this code or any derived class is compiled and deployed without stripping `main()`, default accounts with known credentials will be available, leading to unauthorized access.

**Fix:** Remove hardcoded pre-registered user credentials from production application initialization. Load initial credentials dynamically from external configuration, environment variables, or administrative provisioning scripts.
```java
        // Initialize repository from secure external source or leave empty
        // Demo users should only be seeded in isolated test fixtures, not in main()
```

---

### SEC-07: Sensitive Credentials Retained in Memory via PBEKeySpec and String Constructors
- **Severity:** Medium
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `LoginSystem.java:151-159`

**Vulnerable code:**
```java
// LoginSystem.java:151-159
        private byte[] hashRaw(char[] password, byte[] salt, int iterations, int keyLengthBytes) {
            try {
                PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLengthBytes * 8);
                SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
                return factory.generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IllegalStateException("Cryptographic algorithm unavailable: " + ALGORITHM, e);
            }
        }
```

**Why it is a problem:**
`LoginSystem` aims to uphold memory hygiene by wiping `char[] password` arrays after use. However, `PBEKeySpec` creates an internal copy of the password array upon instantiation. The code never calls `spec.clearPassword()`, leaving cleartext password data in the Java heap until garbage collection. Furthermore, `LoginRequest` provides an overloaded constructor accepting `String password` (lines 393-395), creating immutable `String` objects that cannot be cleared from memory. In the event of a heap dump or memory inspection vulnerability, sensitive credentials can be extracted.

**Fix:** Ensure `spec.clearPassword()` is invoked in a `finally` block, and eliminate constructors that accept immutable `String` passwords.
```java
        private byte[] hashRaw(char[] password, byte[] salt, int iterations, int keyLengthBytes) {
            PBEKeySpec spec = null;
            try {
                spec = new PBEKeySpec(password, salt, iterations, keyLengthBytes * 8);
                SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
                return factory.generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IllegalStateException("Cryptographic algorithm unavailable: " + ALGORITHM, e);
            } finally {
                if (spec != null) {
                    spec.clearPassword();
                }
            }
        }
```

---

### SEC-08: Sensitive Credentials Exposed in Process List via Command-Line Arguments
- **Severity:** Low
- **CWE:** CWE-214: Invocation of Process Initializer with Untrusted Host
- **Location:** `LoginSystem.java:662-669`

**Vulnerable code:**
```java
// LoginSystem.java:662-669
        if (args.length >= 2) {
            String user = args[0];
            String pass = args[1];
            System.out.println("=== Authenticating User: " + user + " ===");
            LoginResult cliRes = authService.authenticate(new LoginRequest(user, pass, "127.0.0.1"));
            System.out.println("Status:  " + cliRes.getStatus());
            System.out.println("Message: " + cliRes.getMessage());
            return;
        }
```

**Why it is a problem:**
Accepting passwords as positional command-line arguments (`args[1]`) exposes credentials to all local users on multi-user systems via process table inspection (such as `ps -ef` or `/proc/<pid>/cmdline`). Additionally, command-line invocations are logged to shell history files (such as `.bash_history` or `.zsh_history`).

**Fix:** Remove command-line argument password acceptance. Prompt for passwords interactively using `System.console().readPassword()` or read from standard input.
```java
        if (args.length == 1) {
            String user = args[0];
            char[] passChars;
            if (System.console() != null) {
                passChars = System.console().readPassword("Password for %s: ", user);
            } else {
                System.err.println("Secure console unavailable.");
                return;
            }
            try {
                LoginResult cliRes = authService.authenticate(new LoginRequest(user, passChars, "127.0.0.1"));
                System.out.println("Status:  " + cliRes.getStatus());
                System.out.println("Message: " + cliRes.getMessage());
            } finally {
                Arrays.fill(passChars, '\0');
            }
            return;
        }
```

---

### SEC-09: Plaintext Password Echo During Interactive Console Authentication
- **Severity:** Low
- **CWE:** CWE-522: Insufficiently Protected Credentials
- **Location:** `LoginSystem.java:819-821`

**Vulnerable code:**
```java
// LoginSystem.java:819-821
                System.out.print("Password: ");
                String pass = scanner.nextLine();
                LoginResult result = authService.authenticate(new LoginRequest(user, pass, "127.0.0.1"));
```

**Why it is a problem:**
In `runInteractiveConsole`, user input is read via `java.util.Scanner(System.in).nextLine()`. Standard input through `Scanner` does not mask or disable terminal echoing. The entered password is displayed on-screen in plain view, exposing it to shoulder surfing and persisting it in terminal scrollback buffers. Furthermore, it creates an immutable `String` object for the password.

**Fix:** Use `System.console().readPassword()` to prompt for and read passwords with echo disabled.
```java
                char[] passChars;
                if (System.console() != null) {
                    passChars = System.console().readPassword("Password: ");
                } else {
                    passChars = scanner.nextLine().toCharArray();
                }
                try {
                    LoginResult result = authService.authenticate(new LoginRequest(user, passChars, "127.0.0.1"));
                    System.out.println("\nResult: [" + result.getStatus() + "] " + result.getMessage());
                } finally {
                    Arrays.fill(passChars, '\0');
                }
```

---

### SEC-10: Delimiter Injection in Structured Audit Log Entries
- **Severity:** Low
- **CWE:** CWE-117: Improper Output Neutralization for Logs
- **Location:** `LoginSystem.java:481-485`

**Vulnerable code:**
```java
// LoginSystem.java:481-485
            String sanitizedUser = (username == null || username.isBlank()) ? "<anonymous>" : username.replaceAll("[\\r\\n]", "");
            String sanitizedIp = (ip == null || ip.isBlank()) ? "<unknown-ip>" : ip.replaceAll("[\\r\\n]", "");
            String logEntry = String.format("[AUDIT] Event=%s | User=%s | IP=%s | Outcome=%s | Details=%s",
                    eventType, sanitizedUser, sanitizedIp, outcome, details);
            LOGGER.info(logEntry);
```

**Why it is a problem:**
`AuditLogger` replaces carriage return and newline characters (`\r\n`) to mitigate CRLF log injection. However, the audit log uses pipe (`|`) and equals (`=`) characters as record separators. Untrusted inputs like `username` or `details` are not sanitized for `|` or `=`. An attacker submitting a username such as `alice | Outcome=SUCCESS | Details=Bypassed` can forge log fields, misleading log ingestion parsers or SIEM correlation rules.

**Fix:** Strip or escape delimiter characters (`|`, `=`, newlines) from all log parameters, or format audit entries as structured JSON.
```java
            String sanitizedUser = (username == null || username.isBlank()) 
                    ? "<anonymous>" 
                    : username.replaceAll("[\\r\\n|]", "_");
            String sanitizedIp = (ip == null || ip.isBlank()) 
                    ? "<unknown-ip>" 
                    : ip.replaceAll("[\\r\\n|]", "_");
            String sanitizedDetails = (details == null) 
                    ? "" 
                    : details.replaceAll("[\\r\\n|]", "_");
            String logEntry = String.format("[AUDIT] Event=%s | User=%s | IP=%s | Outcome=%s | Details=%s",
                    eventType, sanitizedUser, sanitizedIp, outcome, sanitizedDetails);
            LOGGER.info(logEntry);
```

## 6. Verified Controls and Checks With No Finding
- Password Hashing Algorithm Selection: Verified that `LoginSystem.java:128` uses `PBKDF2WithHmacSHA256` rather than weak or broken algorithms such as MD5, SHA-1, or unsalted crypt.
- Per-User Cryptographic Salt Generation: Verified that `LoginSystem.java:141-145` generates a distinct 16-byte (128-bit) salt per user using `java.security.SecureRandom`.
- Iteration Count in Default Policy: Verified that `LoginSystem.java:78` defines 210,000 iterations for PBKDF2 in `SecurityPolicy.defaultPolicy()`, complying with current OWASP recommendations for PBKDF2-HMAC-SHA256.
- Constant-Time Digest Verification: Verified that `LoginSystem.java:167` compares password hashes using `MessageDigest.isEqual()`, mitigating byte-by-byte timing side-channel vulnerabilities during hash comparisons.
- Credential Omission from Audit Logs: Verified that `LoginSystem.java:478-487` never records plain passwords, password hashes, or salt values in log statements.
- Memory Zeroing on Request Cleanup: Verified that `LoginSystem.java:627-631` includes a `finally` block in `AuthenticationService.authenticate` that zeroes out the request password buffer via `request.clearPassword()` and `Arrays.fill(password, '\0')`.
- Case-Insensitive Username Normalization: Verified that `LoginSystem.java:326` and `LoginSystem.java:331` normalize usernames using `Locale.ROOT` in `InMemoryUserRepository`, preventing case-variant duplicate accounts.
- Automatic Lockout Expiration: Verified that `LoginSystem.java:242-249` checks time-based lockout expiration dynamically, allowing legitimate users to regain access once the lockout duration elapses without requiring manual administrative intervention.
