# Security Code Review: Enterprise Administrator Portal

## Executive Summary

A comprehensive security code review was performed on the codebase located in this directory (`AdministratorPortal.java`, `AdminPortal.java`, `Main.java`, and `run-tests.sh`). The application provides an enterprise administrator portal featuring PBKDF2 credential authentication, role-based access control (RBAC), account lockout policies, audit logging, and administrative management services.

The audit identified **15 security vulnerabilities** spanning **Critical**, **High**, **Medium**, and **Low** severities, along with several properly implemented security controls (constant-time hash comparisons, SecureRandom salting, and timing equalization routines).

---

## Skills Applied

In accordance with the code review workflow, the following specialized security review skills from the library were matched and applied:

1. **`performing-cryptographic-audit-of-application`**: Audited password hashing schemes, KDF configuration (PBKDF2 iteration count, key length, salt generation), randomness sources (`SecureRandom`), constant-time equality comparisons, and cryptographic memory hygiene.
2. **`testing-for-sensitive-data-exposure`**: Audited hardcoded secrets, exposure of credentials via command-line arguments and process listings, plaintext session tokens in audit logs, and cleartext credentials lingering in heap memory.
3. **`testing-api-authentication-weaknesses`**: Audited password complexity rules, session lifecycle (expiration, revocation, and idle timeouts), user enumeration via response discrepancies, and credential brute-force protections.
4. **`testing-for-broken-access-control`**: Audited role-based access control (RBAC) enforcement, administrative session validation, and authorization state synchronization upon user deactivation or lockout.
5. **`exploiting-race-condition-vulnerabilities`**: Audited concurrent user repository operations for Time-of-Check to Time-of-Use (TOCTOU) race conditions during account creation.
6. **`implementing-secret-scanning-with-gitleaks`**: Pattern analysis for embedded secrets and static default credentials.

**General Security Review (OWASP Top 10 / CWE Knowledge)**:
For security-relevant behaviors lacking specialized library skills—specifically file permission controls on logging resources (CWE-732/CWE-276), resource exhaustion / denial of service via unbounded log structures (CWE-400/CWE-770), and log sanitization against ANSI escape injection (CWE-117)—review was conducted against general OWASP Top 10 and CWE standards.

---

## Scope & Files Under Review

| File | Primary Function | Security Concerns Evaluated |
|------|------------------|-----------------------------|
| [AdministratorPortal.java](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java) | Core portal logic, authentication, RBAC, crypto, CLI, tests | Hardcoded credentials, session management, PBKDF2 strength, log injection, file permissions, TOCTOU race conditions, resource exhaustion |
| [AdminPortal.java](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdminPortal.java) | Alias entry point delegating to `AdministratorPortal.main` | Exposure of sensitive arguments passed through process invocation |
| [Main.java](file:///data/results-cyber/agy/set_a/pilot/6/basic/Main.java) | Standard entry point delegating to `AdministratorPortal.main` | Exposure of sensitive arguments passed through process invocation |
| [run-tests.sh](file:///data/results-cyber/agy/set_a/pilot/6/basic/run-tests.sh) | Test execution and verification shell script | Hardcoded plain passwords in shell script and process table exposure via CLI invocation |

---

## Findings Summary

| ID | Title | Severity | CWE ID | Primary Location |
|----|-------|----------|--------|------------------|
| SEC-01 | Hard-Coded Default Administrative and User Credentials | **Critical** | CWE-798, CWE-259 | [AdministratorPortal.java:315-326](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L315-L326) |
| SEC-02 | Active Session Token Disclosure in Plaintext Audit Logs | **High** | CWE-532 | [AdministratorPortal.java:568-570](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L568-L570) |
| SEC-03 | Insecure File Permissions for Audit Log File | **High** | CWE-732, CWE-276 | [AdministratorPortal.java:378-380](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L378-L380) |
| SEC-04 | Exposure of Cleartext Passwords in Process Table via CLI Arguments | **High** | CWE-214, CWE-598 | [AdministratorPortal.java:1201-1206](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L1201-L1206) |
| SEC-05 | Absence of Session Expiration, Idle Timeout, and Server-Side Revocation | **Medium** | CWE-613 | [AdministratorPortal.java:455-477](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L455-L477) |
| SEC-06 | Missing Session Re-Validation against Live User State During Authorization Checks | **Medium** | CWE-284, CWE-613 | [AdministratorPortal.java:589-593](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L589-L593) |
| SEC-07 | User Enumeration via Observable Discrepancy in Authentication Responses | **Medium** | CWE-204, CWE-200 | [AdministratorPortal.java:508-530](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L508-L530) |
| SEC-08 | Weak Password Complexity Policy for New Account Creation | **Low** | CWE-521 | [AdministratorPortal.java:847-851](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L847-L851) |
| SEC-09 | Sub-Optimal PBKDF2 Iteration Count for Password Hashing | **Low** | CWE-916 | [AdministratorPortal.java:34-35](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L34-L35) |
| SEC-10 | Time-of-Check to Time-of-Use (TOCTOU) Race Condition in Account Creation | **Low** | CWE-367 | [AdministratorPortal.java:645-648](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L645-L648) |
| SEC-11 | Sensitive Data Residual in Memory via Non-TTY Console Fallback | **Low** | CWE-316, CWE-244 | [AdministratorPortal.java:928-931](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L928-L931) |
| SEC-12 | Uncontrolled Resource Consumption via Unbounded In-Memory Logs and CopyOnWriteArrayList | **Low** | CWE-400, CWE-770 | [AdministratorPortal.java:362-376](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L362-L376) |
| SEC-13 | Incomplete Log Sanitization (ANSI Terminal Escape Injection) | **Low** | CWE-117 | [AdministratorPortal.java:250-253](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L250-L253) |
| SEC-14 | Excessive System Telemetry Information Disclosure in Admin Diagnostics | **Low** | CWE-200, CWE-497 | [AdministratorPortal.java:609-618](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L609-L618) |
| SEC-15 | Lack of IP-Level Rate Limiting on Authentication Interface | **Low** | CWE-307 | [AdministratorPortal.java:492-552](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L492-L552) |

---

## Detailed Findings

### SEC-01: Hard-Coded Default Administrative and User Credentials
- **Severity**: Critical
- **CWE**: [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html), [CWE-259: Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)
- **Evidence**:
  - [AdministratorPortal.java:315-326](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L315-L326):
    ```java
    createUser("admin", "Admin@2026!".toCharArray(), Role.ADMIN);
    createUser("superadmin", "SuperAdmin@2026!".toCharArray(), Role.SUPER_ADMIN);
    createUser("standard_user", "User@2026!".toCharArray(), Role.USER);
    User lockedUser = createUser("locked_admin", "LockedAdmin@2026!".toCharArray(), Role.ADMIN);
    ```
  - [AdministratorPortal.java:753-755](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L753-L755):
    ```java
    System.out.println("  Administrator:  admin       / Admin@2026!");
    System.out.println("  Super Admin:    superadmin  / SuperAdmin@2026!");
    System.out.println("  Standard User:  standard_user / User@2026! (Non-admin denial demo)");
    ```
  - [run-tests.sh:25, 30, 39, 48](file:///data/results-cyber/agy/set_a/pilot/6/basic/run-tests.sh#L25):
    ```bash
    java AdministratorPortal admin Admin@2026! > /dev/null
    java AdministratorPortal standard_user User@2026! > /dev/null 2>&1
    java AdministratorPortal admin WrongPassword123! > /dev/null 2>&1
    java AdministratorPortal locked_admin LockedAdmin@2026! > /dev/null 2>&1
    ```
- **Why It Is a Problem**:
  Static passwords for high-privileged accounts (`admin`, `superadmin`) are embedded directly into source code, printed on the CLI login banner, and written into shell scripts. Anyone who inspects the repository, decompiles the bytecode, or executes the CLI application gains immediate knowledge of administrative credentials, bypassing authentication controls.
- **Remediation**:
  Remove default hard-coded credentials from source code and banner displays. For production installations, prompt for initial administrator credentials upon first startup, generate a strong random temporary password displayed once securely, or ingest initial credentials from a secure external secrets manager or environment variable.

---

### SEC-02: Active Session Token Disclosure in Plaintext Audit Logs
- **Severity**: High
- **CWE**: [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
- **Evidence**:
  - [AdministratorPortal.java:568-570](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L568-L570):
    ```java
    AdminSession session = new AdminSession(user);
    auditLogger.log(AuditEventType.LOGIN_SUCCESS, user.getUsername(),
            "Administrator authenticated successfully. Session: " + session.getSessionId(), clientIp);
    ```
  - Generated log output in [audit.log:1, 6, 10](file:///data/results-cyber/agy/set_a/pilot/6/basic/audit.log#L1):
    ```text
    [2026-09-05T11:01:57.042478253Z] [LOGIN_SUCCESS] User='admin' IP='127.0.0.1' - Administrator authenticated successfully. Session: 20197368-73a8-4355-95b4-ba4bf3bf0fb6
    ```
- **Why It Is a Problem**:
  The `sessionId` acts as a bearer authentication token for administrative operations. Logging the full raw session ID to `audit.log` exposes active administrator sessions to anyone who reads local log files, log shipping pipelines, or centralized log management consoles (e.g. Splunk, ELK). An attacker with log access can hijack active sessions.
- **Remediation**:
  Never log raw session tokens. If session correlation is required in audit records, log a one-way cryptographic hash of the session ID (e.g. `SHA-256(sessionId)`) or a truncated token prefix (e.g. `sessionId.substring(0, 8) + "..."`).

---

### SEC-03: Insecure File Permissions for Audit Log File
- **Severity**: High
- **CWE**: [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html), [CWE-276: Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html)
- **Evidence**:
  - [AdministratorPortal.java:378-380](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L378-L380):
    ```java
    if (logFile != null) {
        try (PrintWriter pw = new PrintWriter(new FileWriter(logFile, true))) {
            pw.println(record.toString());
        } catch (IOException e) {
    ```
- **Why It Is a Problem**:
  The `FileWriter` constructor creates `audit.log` relying on the process's default file creation mask (umask). On standard Linux/UNIX systems, this typically creates files with mode `0644` or `0664` (readable by all users on the operating system). Local unauthorized users on the system can read security events, user activity, client IP addresses, and leaked session IDs. Furthermore, if group/world write permissions are permitted, attackers can tamper with or truncate audit records.
- **Remediation**:
  Create the audit log file using Java NIO with POSIX file permissions restricted strictly to owner read/write (`0600`):
  ```java
  Path logPath = logFile.toPath();
  if (!Files.exists(logPath)) {
      Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
      Files.createFile(logPath, PosixFilePermissions.asFileAttribute(perms));
  }
  ```

---

### SEC-04: Exposure of Cleartext Passwords in Process Table via CLI Arguments
- **Severity**: High
- **CWE**: [CWE-214: Invocation of Process Using Visible Sensitive Information](https://cwe.mitre.org/data/definitions/214.html), [CWE-598: Information Exposure Through Query Strings in GET / CLI Arguments](https://cwe.mitre.org/data/definitions/598.html)
- **Evidence**:
  - [AdministratorPortal.java:1201-1206](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L1201-L1206):
    ```java
    if (args.length >= 2) {
        String username = args[0];
        char[] password = args[1].toCharArray();

        AuthResult result = authService.authenticate(username, password);
        PasswordSecurity.wipe(password);
    ```
  - [AdminPortal.java:6-8](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdminPortal.java#L6-L8) and [Main.java:6-8](file:///data/results-cyber/agy/set_a/pilot/6/basic/Main.java#L6-L8):
    ```java
    public static void main(String[] args) {
        AdministratorPortal.main(args);
    }
    ```
  - [run-tests.sh:25, 30, 39, 48](file:///data/results-cyber/agy/set_a/pilot/6/basic/run-tests.sh#L25):
    ```bash
    java AdministratorPortal admin Admin@2026! > /dev/null
    ```
- **Why It Is a Problem**:
  Operating system command-line arguments are globally visible to all local users via `ps aux`, `top`, or reading `/proc/<pid>/cmdline`. Shell histories (`.bash_history`) also retain the arguments. Furthermore, in Java, `args[1]` enters the JVM as an immutable `java.lang.String`. Converting it to a `char[]` and calling `PasswordSecurity.wipe(password)` only zeroes the temporary array; the underlying `String` in `args[1]` remains retained in the heap memory until garbage collected.
- **Remediation**:
  Do not accept passwords as command-line arguments. Passwords should be read interactively via `System.console().readPassword()` or piped into standard input (`stdin`).

---

### SEC-05: Absence of Session Expiration, Idle Timeout, and Server-Side Revocation
- **Severity**: Medium
- **CWE**: [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)
- **Evidence**:
  - [AdministratorPortal.java:455-477](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L455-L477):
    ```java
    public static class AdminSession {
        private final String sessionId;
        private final User user;
        private final Instant loginTime;

        public AdminSession(User user) {
            this.sessionId = UUID.randomUUID().toString();
            this.user = user;
            this.loginTime = Instant.now();
        }
    ```
  - [AdministratorPortal.java:814-817](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L814-L817):
    ```java
    case "8" -> {
        System.out.println("\nLogging out administrator '" + session.getUser().getUsername() + "'...");
        inSession = false;
    }
    ```
- **Why It Is a Problem**:
  `AdminSession` does not record session expiration duration, maximum lifetime, or idle timeout. When the administrator logs out (`case "8"`), the CLI loop exits (`inSession = false`), but the `AdminSession` object itself is not revoked, marked expired, or removed from any session store. If an `AdminSession` reference is retained, exported, or reused across API/CLI components, it remains valid forever.
- **Remediation**:
  1. Add `Duration maxLifetime` and `Instant lastAccessedTime` to `AdminSession`.
  2. Implement an active session registry in `AdminService` with methods `register(session)`, `validate(session)`, and `revoke(sessionId)`.
  3. Enforce an idle timeout (e.g. 15 minutes) and absolute session timeout (e.g. 8 hours).
  4. Ensure `logout` explicitly revokes the session in the registry.

---

### SEC-06: Missing Session Re-Validation against Live User State During Authorization Checks
- **Severity**: Medium
- **CWE**: [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html), [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)
- **Evidence**:
  - [AdministratorPortal.java:589-593](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L589-L593):
    ```java
    private void assertAdmin(AdminSession session) {
        if (session == null || session.getUser() == null || !session.getUser().getRole().hasAdminPrivilege()) {
            throw new SecurityException("Unauthorized: Valid administrator session required to perform this action.");
        }
    }
    ```
- **Why It Is a Problem**:
  `assertAdmin` inspects only the in-memory `session.getUser().getRole()` reference attached to the session at authentication time. If an administrator deactivates (`toggleAccountStatus(..., false)`), locks (`lockFor(...)`), or deletes the user account, an existing session for that user will continue to execute administrative actions indefinitely without denial because `assertAdmin` never verifies the user's current status in `userRepository`.
- **Remediation**:
  Update `assertAdmin` to query the live `userRepository` by username:
  ```java
  private void assertAdmin(AdminSession session) {
      if (session == null || session.getUser() == null) {
          throw new SecurityException("Unauthorized: Session missing.");
      }
      User liveUser = userRepository.findByUsername(session.getUser().getUsername())
              .orElseThrow(() -> new SecurityException("Unauthorized: User no longer exists."));
      if (!liveUser.isActive() || liveUser.isLocked() || !liveUser.getRole().hasAdminPrivilege()) {
          throw new SecurityException("Unauthorized: Account state invalid or privilege revoked.");
      }
  }
  ```

---

### SEC-07: User Enumeration via Observable Discrepancy in Authentication Responses
- **Severity**: Medium
- **CWE**: [CWE-204: Observable Response Discrepancy](https://cwe.mitre.org/data/definitions/204.html), [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- **Evidence**:
  - [AdministratorPortal.java:508-510](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L508-L510):
    ```java
    return AuthResult.denied(AuthStatusCode.DENIED_INVALID_CREDENTIALS,
            "Access Denied: Invalid username or password.", null);
    ```
  - [AdministratorPortal.java:519-521](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L519-L521):
    ```java
    return AuthResult.denied(AuthStatusCode.DENIED_ACCOUNT_INACTIVE,
            "Access Denied: This account has been deactivated.", user);
    ```
  - [AdministratorPortal.java:528-530](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L528-L530):
    ```java
    return AuthResult.denied(AuthStatusCode.DENIED_ACCOUNT_LOCKED,
            "Access Denied: Account is temporarily locked due to excessive failed attempts.", user);
    ```
- **Why It Is a Problem**:
  Although non-existent users return a generic message ("Invalid username or password"), queries for existing deactivated or locked accounts immediately return explicit error messages ("account has been deactivated" or "Account is temporarily locked"). An unauthenticated attacker can probe usernames to determine which valid accounts exist and whether they are active or locked.
- **Remediation**:
  Return an identical generic response (e.g. `Access Denied: Invalid credentials or account unavailable`) for all authentication rejections, regardless of whether the account does not exist, is deactivated, or is locked.

---

### SEC-08: Weak Password Complexity Policy for New Account Creation
- **Severity**: Low
- **CWE**: [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)
- **Evidence**:
  - [AdministratorPortal.java:847-851](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L847-L851):
    ```java
    char[] newPassword = promptPassword("Enter password for new user: ");
    if (newPassword.length < 6) {
        System.out.println("Error: Password must be at least 6 characters long.");
        PasswordSecurity.wipe(newPassword);
        return;
    }
    ```
- **Why It Is a Problem**:
  The portal permits passwords as short as 6 characters with zero character composition rules (no uppercase, lowercase, numbers, or symbols required) and no dictionary checks. An administrator can create user accounts or other admin accounts with trivially guessable passwords such as `123456` or `admin1`, exposing the system to brute-force or dictionary attacks.
- **Remediation**:
  Enforce a password policy conforming to NIST SP 800-63B:
  - Minimum length of at least 8 to 12 characters.
  - Check against common password blocklists.
  - Require character diversity (uppercase, lowercase, digits, special characters) if complexity rules are utilized.

---

### SEC-09: Sub-Optimal PBKDF2 Iteration Count for Password Hashing
- **Severity**: Low
- **CWE**: [CWE-916: Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
- **Evidence**:
  - [AdministratorPortal.java:34-35](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L34-L35):
    ```java
    public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    public static final int PBKDF2_ITERATIONS = 64_000;
    ```
- **Why It Is a Problem**:
  The iteration count is set to 64,000. Modern industry standards (OWASP Password Storage Cheat Sheet 2023/2024 and NIST SP 800-63B) recommend at least 600,000 iterations for `PBKDF2WithHmacSHA256` (or 210,000 for `PBKDF2WithHmacSHA512`). 64,000 iterations allows modern GPUs to compute millions of candidate hashes per second, making offline cracking feasible if password hashes are exfiltrated.
- **Remediation**:
  Increase `PBKDF2_ITERATIONS` to 600,000 or transition to memory-hard password hashing algorithms such as Argon2id.

---

### SEC-10: Time-of-Check to Time-of-Use (TOCTOU) Race Condition in Account Creation
- **Severity**: Low
- **CWE**: [CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- **Evidence**:
  - [AdministratorPortal.java:645-648](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L645-L648):
    ```java
    public boolean createNewAccount(AdminSession session, String username, char[] password, Role role) {
        assertAdmin(session);
        if (userRepository.exists(username)) {
            return false;
        }
        userRepository.createUser(username, password, role);
    ```
  - [AdministratorPortal.java:335](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L335):
    ```java
    userMap.put(normalizedUsername, user);
    ```
- **Why It Is a Problem**:
  `userRepository.exists(username)` and `userRepository.createUser(...)` are executed as two non-atomic operations against the `userMap` `ConcurrentHashMap`. If two concurrent administrator requests attempt to register an account with the same username simultaneously, both can pass the `exists()` check, causing the second execution to overwrite the first user's record without warning.
- **Remediation**:
  Leverage `ConcurrentHashMap.putIfAbsent`:
  ```java
  public User createUser(String username, char[] password, Role role) {
      String normalized = username.toLowerCase(Locale.ROOT).trim();
      byte[] salt = PasswordSecurity.generateSalt();
      byte[] hash = PasswordSecurity.hashPassword(password, salt);
      User user = new User(normalized, salt, hash, role);
      if (userMap.putIfAbsent(normalized, user) != null) {
          throw new IllegalArgumentException("User already exists: " + normalized);
      }
      return user;
  }
  ```

---

### SEC-11: Sensitive Data Residual in Memory via Non-TTY Console Fallback
- **Severity**: Low
- **CWE**: [CWE-316: Cleartext Storage of Sensitive Information in Memory](https://cwe.mitre.org/data/definitions/316.html), [CWE-244: Improper Clearing of Heap Memory Containing Sensitive Data](https://cwe.mitre.org/data/definitions/244.html)
- **Evidence**:
  - [AdministratorPortal.java:928-931](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L928-L931):
    ```java
    // Fallback for non-TTY environments (pipes, scripts, IDEs)
    System.out.print(prompt);
    try {
        String line = reader.readLine();
        return line != null ? line.toCharArray() : new char[0];
    ```
- **Why It Is a Problem**:
  In non-TTY environments (e.g. piped scripts or automated testing wrappers), `reader.readLine()` reads the password into an immutable `java.lang.String`. Although the caller wipes the returned `char[]` via `PasswordSecurity.wipe(password)`, the immutable `String` cannot be zeroed and remains in JVM heap memory until garbage collected, where it is retrievable via memory inspection or process core dumps.
- **Remediation**:
  In fallback mode, read characters directly into a pre-allocated `char[]` buffer using `reader.read(char[] cbuf, ...)` rather than using `readLine()` which instantiates a `java.lang.String`.

---

### SEC-12: Uncontrolled Resource Consumption via Unbounded In-Memory Logs and CopyOnWriteArrayList
- **Severity**: Low
- **CWE**: [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html), [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)
- **Evidence**:
  - [AdministratorPortal.java:362](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L362):
    ```java
    private final List<AuditRecord> memoryLogs = new CopyOnWriteArrayList<>();
    ```
  - [AdministratorPortal.java:374-376](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L374-L376):
    ```java
    public synchronized void log(AuditEventType type, String username, String details, String clientIp) {
        AuditRecord record = new AuditRecord(type, username, details, clientIp);
        memoryLogs.add(record);
    ```
- **Why It Is a Problem**:
  Every authentication failure and administrative event appends an `AuditRecord` to `memoryLogs` without any size limit. `CopyOnWriteArrayList` allocates a full copy of the underlying array on every single mutation ($O(N)$ allocation per event, leading to $O(N^2)$ cumulative overhead). Under sustained authentication attempts or brute-force scanning, this rapidly exhausts JVM heap space, leading to an `OutOfMemoryError` denial of service. Additionally, `audit.log` grows unbounded on disk without log rotation.
- **Remediation**:
  Replace `memoryLogs` with a bounded circular buffer (e.g. a fixed-capacity ring buffer of 1,000 entries) and implement file-based log rotation with maximum file size limits (e.g. 10 MB per file, max 5 backup files).

---

### SEC-13: Incomplete Log Sanitization (ANSI Terminal Escape Injection)
- **Severity**: Low
- **CWE**: [CWE-117: Improper Output Handling for Logs](https://cwe.mitre.org/data/definitions/117.html)
- **Evidence**:
  - [AdministratorPortal.java:250-253](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L250-L253):
    ```java
    private static String sanitizeForLog(String input) {
        if (input == null) return "N/A";
        return input.replace('\r', '_').replace('\n', '_').replace('\t', ' ');
    }
    ```
- **Why It Is a Problem**:
  While newline and carriage return characters are replaced to protect against multi-line log splitting, ANSI terminal escape sequences (`\u001B[...]`) and non-printable control characters are not stripped. When administrators view audit logs on the terminal via the interactive console ([AdministratorPortal.java:894-903](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L894-L903)) or through terminal commands (`cat audit.log`), malicious input can rewrite terminal output, disguise malicious events, or trigger terminal emulator vulnerabilities.
- **Remediation**:
  Strip ANSI escape codes and unprintable control characters:
  ```java
  private static String sanitizeForLog(String input) {
      if (input == null) return "N/A";
      return input.replaceAll("\u001B\\[[;?0-9]*[a-zA-Z]", "")
                  .replaceAll("[\\p{Cntrl}&&[^\r\n\t]]", "")
                  .replace('\r', '_').replace('\n', '_').replace('\t', ' ');
  }
  ```

---

### SEC-14: Excessive System Telemetry Information Disclosure in Admin Diagnostics
- **Severity**: Low
- **CWE**: [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html), [CWE-497: Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html)
- **Evidence**:
  - [AdministratorPortal.java:609-618](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L609-L618):
    ```java
    diag.put("Java Version", System.getProperty("java.version"));
    diag.put("Java Vendor", System.getProperty("java.vendor"));
    diag.put("OS Name", System.getProperty("os.name"));
    diag.put("OS Architecture", System.getProperty("os.arch"));
    diag.put("Available Processors", Runtime.getRuntime().availableProcessors());
    diag.put("JVM Uptime (seconds)", runtimeBean.getUptime() / 1000);
    diag.put("Portal Uptime (seconds)", uptimeSeconds);
    diag.put("Heap Memory (Used / Max MB)", heapUsed + " MB / " + heapMax + " MB");
    diag.put("Live Thread Count", threadBean.getThreadCount());
    ```
- **Why It Is a Problem**:
  Diagnostics output returns exact JVM minor version strings, vendor information, OS kernel details, and hardware thread topologies. While restricted to administrators, if an attacker gains compromised low-level admin access, this telemetry provides detailed fingerprinting for targeted platform-specific exploit selection.
- **Remediation**:
  Restrict telemetry to high-level health indicators or restrict detailed environment property inspection strictly to `Role.SUPER_ADMIN`.

---

### SEC-15: Lack of IP-Level Rate Limiting on Authentication Interface
- **Severity**: Low
- **CWE**: [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
- **Evidence**:
  - [AdministratorPortal.java:492-552](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L492-L552):
    ```java
    public AuthResult authenticate(String username, char[] password, String clientIp) {
    ...
    ```
- **Why It Is a Problem**:
  Although the application enforces account lockout per username (locking after 5 failed attempts for 15 minutes), there is no IP-level throttling or rate limiting. An attacker can perform horizontal password spraying across multiple user accounts from a single IP address without triggering rate limiting.
- **Remediation**:
  Implement an IP-based rate limiter (such as a token-bucket or sliding-window counter) that throttles requests from any IP address exceeding a threshold of failed attempts.

---

## Verification of Positive Security Controls

The review identified several well-designed security controls that were verified to operate correctly:

1. **Constant-Time Cryptographic Hash Comparison (CWE-208 Resistance)**:
   - Location: [AdministratorPortal.java:281](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L281)
   - `PasswordSecurity.verifyPassword` utilizes `MessageDigest.isEqual(computedHash, storedHash)`, ensuring hash verification is immune to timing side-channel attacks.
2. **Cryptographically Secure Salt Generation**:
   - Location: [AdministratorPortal.java:260-266](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L260-L266)
   - Uses `java.security.SecureRandom` to generate unique 16-byte cryptographic salts for each user account.
3. **Timing Equalization on Authentication Denials (CWE-204 Resistance)**:
   - Location: [AdministratorPortal.java:284-287, 494, 506, 517, 526](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L284-L287)
   - `PasswordSecurity.executeDummyHash()` is invoked for non-existent users, empty credentials, and locked/deactivated accounts to equalize execution time and mitigate timing-based user enumeration.
4. **Memory Zeroing of Sensitive Arrays**:
   - Location: [AdministratorPortal.java:289-293](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L289-L293)
   - `PasswordSecurity.wipe(char[] sensitiveData)` uses `Arrays.fill(sensitiveData, '\0')` to overwrite password arrays in memory.
5. **Account Lockout Enforcement**:
   - Location: [AdministratorPortal.java:538-545](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L538-L545)
   - Automatically locks accounts for 15 minutes after 5 consecutive failed authentication attempts.
6. **Role-Based Access Control (RBAC) Gate**:
   - Location: [AdministratorPortal.java:557-564, 589-593](file:///data/results-cyber/agy/set_a/pilot/6/basic/AdministratorPortal.java#L557-L564)
   - Enforces administrative role verification (`hasAdminPrivilege()`) before granting access to portal sessions or administrative actions.
