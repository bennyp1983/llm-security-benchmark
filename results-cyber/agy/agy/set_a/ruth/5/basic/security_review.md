# Security Review: UserLoginService

## 1. Executive Summary
This security review evaluates the Java user authentication component consisting of `UserLoginService.java` and its alias subclass `LoginService.java`. The component implements credential verification, PBKDF2-HMAC-SHA256 password hashing with per-user salts, constant-time verification, brute-force protection with account lockout, and dual repository backends (in-memory and JDBC SQL storage).

While the cryptographic hashing algorithm and parameter choices are solid (PBKDF2-HMAC-SHA256 with 100,000 iterations and constant-time comparison) and all SQL statements use parameterized queries protecting against SQL injection, the review identified several security vulnerabilities:
1. **Hardcoded Administrative and Demo Credentials (High / CWE-798):** Default constructors and singleton instances automatically seed active accounts with static passwords, including an administrative user (`admin` / `AdminSuperKey987$`).
2. **Account Lockout Race Condition / Brute-Force Bypass (High / CWE-362):** Time-of-check to time-of-use (TOCTOU) concurrency gaps between the lockout check and password evaluation, combined with non-shared `UserAccount` object instantiation in JDBC mode, allow attackers to bypass lockout thresholds through concurrent authentication bursts.
3. **Observable Response & Timing Discrepancies (High / CWE-204, CWE-208):** Incomplete user enumeration mitigations leak user existence through differentiated `remainingAttempts` counters on failed logins and sub-millisecond responses on locked/disabled accounts that skip PBKDF2 hashing.
4. **Non-Thread-Safe JDBC Connection Sharing (Medium / CWE-362):** Sharing a single un-synchronized `Connection` across concurrent login threads introduces database driver race conditions and query failures.
5. **Missing Minimum Password Policy (Medium / CWE-521):** Registration allows single-character and trivial passwords.
6. **Unmanaged Session Token Issuance (Low / CWE-384):** Random tokens are issued without server-side storage, validation, expiration, or revocation mechanisms.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `UserLoginService.java` | Core authentication service, cryptographic utilities, repository implementations (in-memory and JDBC), login policy enforcement, user entity management, and verification harness. | Password hashing (PBKDF2-HMAC-SHA256), salt generation, constant-time verification, dummy hashing against account enumeration, failed login tracking and account lockout, session token generation, character array memory wiping, parameterized SQL execution, thread synchronization, user registration. |
| `LoginService.java` | Subclass and semantic alias extending `UserLoginService` providing constructor chaining and entry point forwarding for API backwards compatibility. | Delegates all authentication, repository handling, and default demo account seeding to `UserLoginService`. |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to PBKDF2WithHmacSHA256 password hashing configuration, iteration counts, SecureRandom salt generation, constant-time hash comparison, token randomness, and embedded secrets in source code.
- `testing-api-authentication-weaknesses`: Applied to authentication workflows, account lockout mechanisms, response/timing user enumeration vectors, credential verification logic, password registration constraints, and session token generation/management.
- `exploiting-race-condition-vulnerabilities`: Applied to concurrency safety, race conditions in account lockout enforcement, check-then-act sequences, and multi-threaded state management in memory and SQL repositories.
- `exploiting-sql-injection-vulnerabilities`: Applied to JDBC database query building, prepared statement parameter binding, and table creation DDL.
- General OWASP Top 10 / CWE Knowledge: Applied to memory sanitization (CWE-244), input validation boundaries (CWE-20), and shared resource synchronization on JDBC connection objects (CWE-662).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Hard-Coded Default Credentials for Administrative and Demo Accounts | High | CWE-798 | `UserLoginService.java:1096-1100` |
| SEC-02 | Concurrency Race Condition in Account Lockout Enforcement Allowing Brute-Force Bypass | High | CWE-362 | `UserLoginService.java:814-864` |
| SEC-03 | Observable Response and Timing Discrepancies Enabling Account Enumeration | High | CWE-204 | `UserLoginService.java:802-827` |
| SEC-04 | Non-Thread-Safe Shared JDBC Connection in Multi-Threaded Service | Medium | CWE-362 | `UserLoginService.java:440-444` |
| SEC-05 | Missing Minimum Password Length and Complexity Validation | Medium | CWE-521 | `UserLoginService.java:969-975` |
| SEC-06 | Session Tokens Issued Without Storage, Expiration, or Validation Controls | Low | CWE-384 | `UserLoginService.java:846-847` |

## 5. Detailed Findings

### SEC-01: Hard-Coded Default Credentials for Administrative and Demo Accounts
- **Severity:** High
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Location:** `UserLoginService.java:1096-1100`

**Vulnerable code:**
```java
// UserLoginService.java:1096-1100
    private void populateDefaultDemoAccounts() {
        registerUser("alice", "AliceSecurePass123!", "alice@example.com", Set.of("USER"));
        registerUser("bob", "BobP@ssword2026!", "bob@example.com", Set.of("USER"));
        registerUser("admin", "AdminSuperKey987$", "admin@example.com", Set.of("ADMIN", "USER"));
    }
```

**Why it is a problem:**
The zero-argument constructor `UserLoginService()` (line 718), its subclass `LoginService()` (line 9), and the static singleton `DEFAULT_INSTANCE` (line 1069) automatically execute `populateDefaultDemoAccounts()`. This creates pre-configured accounts with static, hardcoded plaintext passwords in source code. Critically, this includes an account named `"admin"` with password `"AdminSuperKey987$"` granted administrative privileges (`ADMIN` role). If this service is instantiated in a production environment using default constructors or static convenience methods (`verify`, `processLogin`), an adversary can obtain unauthorized administrative access using these publicly known default credentials.

**Fix:**
Remove hardcoded demo account initialization from production constructors and singleton instances. Demo or seed accounts should only be provisioned explicitly during test executions or loaded from secure external configuration (e.g. environment variables or vault) outside production runtime.
```java
    private void populateDefaultDemoAccounts() {
        // Do not seed default demo or administrative accounts in production code.
        // User accounts should be provisioned dynamically through secure administrative
        // interfaces or populated exclusively within dedicated test harness methods.
    }
```

### SEC-02: Concurrency Race Condition in Account Lockout Enforcement Allowing Brute-Force Bypass
- **Severity:** High
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- **Location:** `UserLoginService.java:814-864`

**Vulnerable code:**
```java
// UserLoginService.java:814-864
        // 3. Check account lockout state
        synchronized (account) {
            if (account.isLocked(now)) {
                Duration remainingLock = Duration.between(now, account.getLockoutUntil());
                long minutes = Math.max(1, remainingLock.toMinutes());
                return LoginResult.failure(LoginStatus.ACCOUNT_LOCKED,
                        "Account is temporarily locked due to multiple failed login attempts. Try again in " + minutes + " minute(s).");
            }
        }

        // 4. Check account enabled state
        if (!account.isEnabled()) {
            return LoginResult.failure(LoginStatus.ACCOUNT_DISABLED, "Account is disabled. Please contact support.");
        }

        // 5. Verify credentials in constant time
        boolean passwordMatches = PasswordSecurity.verify(
                password,
                account.getSalt(),
                account.getPasswordHash(),
                policy.getPbkdf2Iterations(),
                policy.getKeyLengthBits()
        );

        if (passwordMatches) {
            // Login SUCCESS: reset failed attempts, update last login, issue session token
            synchronized (account) {
                account.resetFailedAttempts();
                account.setLastLoginAt(now);
                repository.save(account);
            }

            String sessionToken = policy.isGenerateSessionToken() ? PasswordSecurity.generateSessionToken() : null;
            return LoginResult.success(account, sessionToken);
        } else {
            // Login FAILURE: increment failed attempts and check lockout threshold
            int remainingAttempts;
            boolean newlyLocked = false;

            synchronized (account) {
                int attempts = account.incrementFailedAttempts();
                if (attempts >= policy.getMaxFailedAttempts()) {
                    Instant lockExpiry = now.plus(policy.getLockoutDuration());
                    account.setLockoutUntil(lockExpiry);
                    newlyLocked = true;
                    remainingAttempts = 0;
                } else {
                    remainingAttempts = policy.getMaxFailedAttempts() - attempts;
                }
                repository.save(account);
            }
```

**Why it is a problem:**
The account lockout verification and update mechanism suffers from critical concurrency and time-of-check to time-of-use (TOCTOU) race conditions:
1. In `JdbcAccountRepository.findByUsername()`, a new `UserAccount` object is instantiated for every call (`new UserAccount(...)` at lines 493-496). Consequently, `synchronized (account)` synchronizes on independent object references across different threads, rendering the synchronization completely ineffective when using the JDBC repository.
2. Even in `InMemoryAccountRepository` where object instances are shared, the lock on `account` is released after Step 3 before initiating Step 5 (`PasswordSecurity.verify(...)`). PBKDF2 with 100,000 iterations takes substantial CPU time (~50–100 ms). An attacker can launch multiple parallel authentication attempts simultaneously. All concurrent threads pass the `isLocked()` check before any thread fails, enters Step 6, increments `failedAttempts`, or locks the account. This enables an attacker to submit dozens or hundreds of guesses concurrently without triggering lockout, completely undermining brute-force protection (CWE-307).

**Fix:**
Ensure atomic check-and-increment semantics for authentication attempts. For database-backed repositories, perform the increment and lockout verification within an atomic SQL query or transactional row-level lock (`SELECT ... FOR UPDATE`). For in-memory storage, synchronize the entire verification and state-updating sequence per username using a striped lock or canonical username lock.
```java
        // Synchronize on a canonical lock per username or enforce atomic database transactions
        synchronized (sanitizedUsername.intern()) {
            Optional<UserAccount> currentAccountOpt = repository.findByUsername(sanitizedUsername);
            if (currentAccountOpt.isEmpty()) {
                if (policy.isTimingProtectionEnabled()) {
                    PasswordSecurity.performDummyComputation(password, policy.getPbkdf2Iterations(), policy.getKeyLengthBits());
                }
                return LoginResult.failure(LoginStatus.INVALID_CREDENTIALS, "Invalid username or password.");
            }
            UserAccount account = currentAccountOpt.get();
            if (account.isLocked(now)) {
                if (policy.isTimingProtectionEnabled()) {
                    PasswordSecurity.performDummyComputation(password, policy.getPbkdf2Iterations(), policy.getKeyLengthBits());
                }
                Duration remainingLock = Duration.between(now, account.getLockoutUntil());
                long minutes = Math.max(1, remainingLock.toMinutes());
                return LoginResult.failure(LoginStatus.ACCOUNT_LOCKED,
                        "Account is temporarily locked due to multiple failed login attempts. Try again in " + minutes + " minute(s).");
            }
            if (!account.isEnabled()) {
                if (policy.isTimingProtectionEnabled()) {
                    PasswordSecurity.performDummyComputation(password, policy.getPbkdf2Iterations(), policy.getKeyLengthBits());
                }
                return LoginResult.failure(LoginStatus.ACCOUNT_DISABLED, "Account is disabled. Please contact support.");
            }

            boolean passwordMatches = PasswordSecurity.verify(
                    password,
                    account.getSalt(),
                    account.getPasswordHash(),
                    policy.getPbkdf2Iterations(),
                    policy.getKeyLengthBits()
            );

            if (passwordMatches) {
                account.resetFailedAttempts();
                account.setLastLoginAt(now);
                repository.save(account);
                String sessionToken = policy.isGenerateSessionToken() ? PasswordSecurity.generateSessionToken() : null;
                return LoginResult.success(account, sessionToken);
            } else {
                int attempts = account.incrementFailedAttempts();
                int remainingAttempts = policy.getMaxFailedAttempts() - attempts;
                if (attempts >= policy.getMaxFailedAttempts()) {
                    account.setLockoutUntil(now.plus(policy.getLockoutDuration()));
                    remainingAttempts = 0;
                }
                repository.save(account);
                return LoginResult.failure(LoginStatus.INVALID_CREDENTIALS, "Invalid username or password.");
            }
        }
```

### SEC-03: Observable Response and Timing Discrepancies Enabling Account Enumeration
- **Severity:** High
- **CWE:** CWE-204: Observable Response Discrepancy
- **Location:** `UserLoginService.java:802-827`

**Vulnerable code:**
```java
// UserLoginService.java:802-827
        if (accountOpt.isEmpty()) {
            // Mitigation against account enumeration: execute dummy PBKDF2 hash calculation
            if (policy.isTimingProtectionEnabled()) {
                PasswordSecurity.performDummyComputation(password,
                        policy.getPbkdf2Iterations(),
                        policy.getKeyLengthBits());
            }
            return LoginResult.failure(LoginStatus.INVALID_CREDENTIALS, "Invalid username or password.");
        }

        UserAccount account = accountOpt.get();

        // 3. Check account lockout state
        synchronized (account) {
            if (account.isLocked(now)) {
                Duration remainingLock = Duration.between(now, account.getLockoutUntil());
                long minutes = Math.max(1, remainingLock.toMinutes());
                return LoginResult.failure(LoginStatus.ACCOUNT_LOCKED,
                        "Account is temporarily locked due to multiple failed login attempts. Try again in " + minutes + " minute(s).");
            }
        }

        // 4. Check account enabled state
        if (!account.isEnabled()) {
            return LoginResult.failure(LoginStatus.ACCOUNT_DISABLED, "Account is disabled. Please contact support.");
        }
```

**Why it is a problem:**
Although the application explicitly intends to prevent account enumeration via `PasswordSecurity.performDummyComputation()`, it introduces multiple response discrepancies and timing side channels:
1. **Attempt Counter Discrepancy:** When an account does not exist, line 809 returns `LoginResult.failure(LoginStatus.INVALID_CREDENTIALS, "Invalid username or password.")`, which sets `remainingAttempts` to `-1` (via line 102). When an account exists and the password fails, line 873 returns `LoginResult.failure(..., remainingAttempts)` where `remainingAttempts` is a positive integer (e.g. 4, 3, 2, 1). Any UI or consuming application that inspects `getRemainingAttempts()` (such as `main()` at line 1132 or `runInteractivePrompt()` at line 1191) immediately discloses whether the user account exists.
2. **Timing Side Channel on Locked / Disabled Accounts:** When a user account exists and is locked (`isLocked(now)`) or disabled (`!isEnabled()`), lines 816-827 immediately return `LoginStatus.ACCOUNT_LOCKED` or `LoginStatus.ACCOUNT_DISABLED` without performing any PBKDF2 computation. The response returns in under 1 millisecond, compared to 50–100 milliseconds for missing or valid accounts. An attacker can discern existing locked or disabled accounts by measuring response time (CWE-208) as well as by observing the distinct status codes and messages.

**Fix:**
Return a generic, uniform status code and message across all authentication failure modes. When an account is locked or disabled, execute `PasswordSecurity.performDummyComputation()` before returning to equalize response time, and do not disclose remaining attempts or lockout status unless configured for authenticated internal contexts.
```java
        if (accountOpt.isEmpty()) {
            if (policy.isTimingProtectionEnabled()) {
                PasswordSecurity.performDummyComputation(password,
                        policy.getPbkdf2Iterations(),
                        policy.getKeyLengthBits());
            }
            return LoginResult.failure(LoginStatus.INVALID_CREDENTIALS, "Invalid username or password.");
        }

        UserAccount account = accountOpt.get();

        // 3. Check account lockout state with timing normalization
        synchronized (account) {
            if (account.isLocked(now)) {
                if (policy.isTimingProtectionEnabled()) {
                    PasswordSecurity.performDummyComputation(password,
                            policy.getPbkdf2Iterations(),
                            policy.getKeyLengthBits());
                }
                return LoginResult.failure(LoginStatus.INVALID_CREDENTIALS, "Invalid username or password.");
            }
        }

        // 4. Check account enabled state with timing normalization
        if (!account.isEnabled()) {
            if (policy.isTimingProtectionEnabled()) {
                PasswordSecurity.performDummyComputation(password,
                        policy.getPbkdf2Iterations(),
                        policy.getKeyLengthBits());
            }
            return LoginResult.failure(LoginStatus.INVALID_CREDENTIALS, "Invalid username or password.");
        }
```

### SEC-04: Non-Thread-Safe Shared JDBC Connection in Multi-Threaded Service
- **Severity:** Medium
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- **Location:** `UserLoginService.java:440-444`

**Vulnerable code:**
```java
// UserLoginService.java:440-444
        private final Connection connection;

        public JdbcAccountRepository(Connection connection) {
            this.connection = Objects.requireNonNull(connection, "JDBC Connection cannot be null");
        }
```

**Why it is a problem:**
`JdbcAccountRepository` stores a single `java.sql.Connection` object in an instance field and shares it across all repository operations (`findByUsername`, `save`, `updateLockout`, `updateLastLogin`, and `findAll`). In JDBC, `Connection` objects are not thread-safe. When `UserLoginService` is deployed in a concurrent environment (e.g. a web application handling multiple user logins simultaneously), concurrent calls to `connection.prepareStatement()`, `ps.executeQuery()`, and `ps.executeUpdate()` on the same underlying connection cause race conditions, connection state corruption, interleaving of database network packets, and unhandled `SQLException` failures (CWE-662).

**Fix:**
Refactor `JdbcAccountRepository` to utilize a thread-safe connection pool (`javax.sql.DataSource`) such as HikariCP, acquiring and closing a dedicated connection per transaction using try-with-resources.
```java
        private final javax.sql.DataSource dataSource;

        public JdbcAccountRepository(javax.sql.DataSource dataSource) {
            this.dataSource = Objects.requireNonNull(dataSource, "DataSource cannot be null");
        }

        // Example: Acquire connection per query within try-with-resources
        @Override
        public Optional<UserAccount> findByUsername(String username) {
            if (username == null) return Optional.empty();
            String sql = "SELECT username, salt, password_hash, email, roles, failed_attempts, " +
                    "lockout_until, is_enabled, created_at, last_login_at FROM users WHERE LOWER(username) = LOWER(?)";
            try (Connection conn = dataSource.getConnection();
                 PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, username.trim());
                try (ResultSet rs = ps.executeQuery()) {
                    // process result set...
                }
            } catch (SQLException e) {
                throw new RuntimeException("Database error finding user: " + username, e);
            }
            return Optional.empty();
        }
```

### SEC-05: Missing Minimum Password Length and Complexity Validation
- **Severity:** Medium
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `UserLoginService.java:969-975`

**Vulnerable code:**
```java
// UserLoginService.java:969-975
        if (username == null || username.trim().isEmpty()) {
            return false;
        }
        if (password == null || password.length == 0 || password.length > LoginPolicy.MAX_PASSWORD_LENGTH) {
            return false;
        }
        String cleanUsername = username.trim();
```

**Why it is a problem:**
The `registerUser` methods check that the password is not null, has length > 0, and does not exceed `MAX_PASSWORD_LENGTH` (1024). However, there is no minimum length enforcement and no complexity or entropy requirements. Users can register accounts with single-character passwords (e.g. `"1"` or `"a"`) or trivial whitespace passwords. Such passwords are easily guessed via online attacks before lockout triggers or cracked with minimal computational effort if password hashes are ever leaked.

**Fix:**
Enforce a robust minimum password length policy (at least 8 or 12 characters, in accordance with NIST SP 800-63B guidelines) and validate password complexity or screen against known compromised passwords during registration.
```java
        public static final int MIN_PASSWORD_LENGTH = 12;

        if (username == null || username.trim().isEmpty()) {
            return false;
        }
        if (password == null || password.length < MIN_PASSWORD_LENGTH || password.length > LoginPolicy.MAX_PASSWORD_LENGTH) {
            return false;
        }
        String cleanUsername = username.trim();
```

### SEC-06: Session Tokens Issued Without Storage, Expiration, or Validation Controls
- **Severity:** Low
- **CWE:** CWE-384: Session Fixation
- **Location:** `UserLoginService.java:846-847`

**Vulnerable code:**
```java
// UserLoginService.java:846-847
            String sessionToken = policy.isGenerateSessionToken() ? PasswordSecurity.generateSessionToken() : null;
            return LoginResult.success(account, sessionToken);
```

**Why it is a problem:**
When `policy.isGenerateSessionToken()` is enabled (which is `true` by default in `LoginPolicy.standard()`), `login()` generates a 256-bit random session token via `PasswordSecurity.generateSessionToken()`. However, this token is never stored in the database or memory repository, has no associated expiration timestamp, and provides no validation or revocation API. If a consuming application assumes that `UserLoginService` provides complete session management, the resulting application will lack token validation, timeout mechanisms (CWE-613), and logout invalidation capabilities.

**Fix:**
Either integrate a dedicated session store that tracks token lifetimes, user bindings, and revocation states, or disable automated token generation by default and clearly delineate that session lifecycle management must be provided by a dedicated session manager.
```java
            // If session management is delegated to an external component, omit token generation
            // or register the token in an active session store with an explicit TTL and revocation mechanism.
            String sessionToken = null;
            if (policy.isGenerateSessionToken()) {
                sessionToken = PasswordSecurity.generateSessionToken();
                // Persist session token with expiry and associate with account.getUsername()
                repository.createSession(account.getUsername(), sessionToken, Instant.now().plus(Duration.ofHours(8)));
            }
            return LoginResult.success(account, sessionToken);
```

## 6. Verified Controls and Checks With No Finding
- Strong Cryptographic Hash Algorithm: Verified that `PasswordSecurity` uses `PBKDF2WithHmacSHA256` with 100,000 iterations and 256-bit key length by default (`LoginPolicy.standard()`), avoiding deprecated hashing algorithms like MD5 or SHA-1 (`UserLoginService.java:640`, `279-281`).
- Cryptographically Secure Salt Generation: Verified that salts are generated per user using `java.security.SecureRandom` with a default size of 16 bytes (128 bits), preventing rainbow table attacks (`UserLoginService.java:642`, `657-661`).
- Constant-Time Hash Comparison: Verified that `PasswordSecurity.verify` compares password hashes using `MessageDigest.isEqual(computed, expectedHash)`, protecting against timing side-channel attacks during hash evaluation (`UserLoginService.java:684-687`).
- SQL Injection Prevention: Verified that `JdbcAccountRepository` uses parameterized queries (`PreparedStatement` with `?` placeholders) for all user-supplied input in `findByUsername`, `save`, `updateLockout`, and `updateLastLogin`, preventing SQL injection vulnerabilities (`UserLoginService.java:468-472`, `508-512`, `524-536`, `541-555`, `568-573`, `586-591`).
- Memory Sanitization for Passwords: Verified that `login(String, char[])` and `UserLoginService.main()` clear character arrays (`Arrays.fill(..., '\0')`) to minimize residual plaintext passwords in memory, and `PBEKeySpec.clearPassword()` is invoked in `hashPasswordInternal` (`UserLoginService.java:677-679`, `771`, `941`, `961`, `1197`).
- Protection Against Hash Denial-of-Service (Hash-DoS): Verified that input passwords exceeding `LoginPolicy.MAX_PASSWORD_LENGTH` (1024 characters) are rejected before PBKDF2 processing, mitigating CPU exhaustion attacks via oversized password inputs (`UserLoginService.java:282`, `793-795`, `972-974`).
- Subclass Delegation Integrity: Verified that `LoginService.java` correctly delegates all operations, constructors, and entry points directly to `UserLoginService` without introducing insecure overrides or secondary bypasses (`LoginService.java:7-32`).
