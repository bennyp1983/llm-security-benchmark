# Security Vulnerability Review Report: Enterprise Administrator Portal

**Target Folder:** `/data/results-cyber/agy/set_a/pilot/6/security`  
**Review Standard:** Skill `/root/.gemini/config/skills/review-code-for-security-vulnerabilities/SKILL.md`  
**Date:** 2026-09-09  

---

## 1. Executive Summary

A comprehensive source code security audit was performed on the codebase in `/data/results-cyber/agy/set_a/pilot/6/security`. The target application is an Enterprise Administrator Portal implemented in Java, providing authentication, role-based access control (RBAC), account lockout handling, audit logging with persistent disk storage, and an administrative console/CLI interface.

While the application demonstrates several intentional security design choices (constant-time password hash comparison to prevent timing attacks, PBKDF2 salting, dummy hashing for non-existent users, and basic log newline stripping), multiple critical, high, and medium-severity security vulnerabilities were identified. These span hardcoded default credentials, unauthenticated administrative audit log access, insecure CLI credential handling, broken function-level authorization, mutable state/hash exposure in auth results, unbounded memory consumption, missing session tracking/revocation, and cryptographic memory hygiene deficiencies.

---

## 2. File-by-File Scope and Purpose

| File | Primary Function & Security-Relevant Behaviors |
| :--- | :--- |
| [`AdminPortal.java`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdminPortal.java) | Entry-point wrapper alias extending `AdministratorPortal`. Forwards execution directly to `AdministratorPortal.main(args)`. |
| [`Main.java`](file:///data/results-cyber/agy/set_a/pilot/6/security/Main.java) | Entry-point wrapper alias extending `AdministratorPortal`. Forwards execution directly to `AdministratorPortal.main(args)`. |
| [`AdministratorPortal.java`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java) | Core monolithic implementation containing password hashing (`PasswordSecurity`), user data model (`User`), in-memory repository (`UserRepository`), authentication and lockout logic (`AuthenticationService`), session model (`AdminSession`), administrative services (`AdminService`), audit logging and parsing (`AuditLogger`, `AuditRecord`), console interface (`ConsolePortal`), test suite (`TestRunner`), and CLI dispatcher (`main`). |
| [`run-tests.sh`](file:///data/results-cyber/agy/set_a/pilot/6/security/run-tests.sh) | Test orchestration bash script that compiles the Java source files, executes test runners, verifies CLI return codes, and checks audit log persistence. Contains hardcoded passwords passed via command-line arguments. |
| [`audit.log`](file:///data/results-cyber/agy/set_a/pilot/6/security/audit.log) | Disk persistence file containing structured, pipe-delimited audit records created by `AuditLogger`. |

---

## 3. Skills Applied

In accordance with the review workflow defined in `review-code-for-security-vulnerabilities/SKILL.md`, the following specialized skills from the skill library were identified and applied:

1. **`performing-cryptographic-audit-of-application`**:
   - Audited password hashing algorithm (`PBKDF2WithHmacSHA256`), iteration count, salt generation, PRNG (`SecureRandom`), memory clearing, and key specification handling.
2. **`testing-for-broken-access-control`**:
   - Audited Role-Based Access Control (RBAC), function-level access control within `AdminService`, session validation, and separation of duties between admin tiers.
3. **`testing-api-authentication-weaknesses`**:
   - Audited authentication verification paths, session lifecycle, token/session invalidation on logout, account lockout mechanisms, and brute-force mitigation.
4. **`testing-for-sensitive-data-exposure`**:
   - Audited exposure of credentials in process arguments, source code, UI banners, authentication response objects, and log files.
5. **General OWASP Top 10 / CWE Knowledge**:
   - Evaluated behaviors without a direct 1:1 library skill match, including:
     - Unauthenticated access to critical functions via CLI options (CWE-306).
     - Log injection and ANSI terminal escape injection (CWE-117, CWE-150).
     - Denial of service via unbounded memory accumulation in `CopyOnWriteArrayList` (CWE-400, CWE-770).
     - Account lockout denial of service (CWE-400, CWE-307).
     - Insecure file permissions on audit logs (CWE-732).

---

## 4. Summary of Findings

| ID | Finding Title | Severity | CWE ID | Primary Location |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | Hardcoded Administrative and User Credentials in Source Code and UI | **Critical** | CWE-798, CWE-259 | [`AdministratorPortal.java:586-605`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L586-L605) |
| **SEC-02** | Unauthenticated Access to Full Security Audit Logs via Command-Line Interface | **High** | CWE-306, CWE-200 | [`AdministratorPortal.java:1690-1703`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L1690-L1703) |
| **SEC-03** | Plaintext Password Exposure via Process Command-Line Arguments | **High** | CWE-214, CWE-200 | [`AdministratorPortal.java:1707-1709`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L1707-L1709) |
| **SEC-04** | Broken Function-Level Access Control and Lack of Separation of Duties in Admin Services | **High** | CWE-285, CWE-862, CWE-269 | [`AdministratorPortal.java:849-853`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L849-L853) |
| **SEC-05** | Stateless AdminSession with Missing Session Registry, Validation, and Revocation | **High** | CWE-384, CWE-613, CWE-306 | [`AdministratorPortal.java:640-668`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L640-L668) |
| **SEC-06** | Internal User Entity and Password Hash Leakage in Denied Authentication Results | **Medium** | CWE-200, CWE-497 | [`AdministratorPortal.java:690-692`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L690-L692) |
| **SEC-07** | Failure to Clear Plaintext Password Memory in `PBEKeySpec` | **Medium** | CWE-316, CWE-244 | [`AdministratorPortal.java:540-544`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L540-L544) |
| **SEC-08** | Uncontrolled Account Lockout Denial of Service (Account Locking DoS) | **Medium** | CWE-400, CWE-307 | [`AdministratorPortal.java:782-793`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L782-L793) |
| **SEC-09** | Unbounded Heap Allocation and High CPU Overhead in `AuditLogger` (Resource Exhaustion DoS) | **Medium** | CWE-400, CWE-770 | [`AdministratorPortal.java:422`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L422) |
| **SEC-10** | Missing Session Expiration and Inactivity Timeout Enforcement | **Medium** | CWE-613 | [`AdministratorPortal.java:849-853`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L849-L853) |
| **SEC-11** | Insecure Default File Permissions on Persistent Audit Log File | **Medium** | CWE-732, CWE-276 | [`AdministratorPortal.java:454-455`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L454-L455) |
| **SEC-12** | Incomplete Log Sanitization Permitting ANSI Escape and Terminal Injection | **Low** | CWE-117, CWE-150 | [`AdministratorPortal.java:406-410`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L406-L410) |
| **SEC-13** | Sub-optimal PBKDF2 Work Factor / Iteration Count | **Low** | CWE-916 | [`AdministratorPortal.java:40`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L40) |
| **SEC-14** | Absence of Password Complexity and Length Requirements at Service Layer | **Low** | CWE-521 | [`AdministratorPortal.java:906-915`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L906-L915) |
| **SEC-15** | Non-TTY Fallback Uses Immutable String for Password Input | **Low** | CWE-316 | [`AdministratorPortal.java:1320-1321`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L1320-L1321) |
| **SEC-16** | Non-Persistent In-Memory User Repository Reverts Credential Updates on Restart | **Low** | CWE-311, CWE-798 | [`AdministratorPortal.java:578-605`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L578-L605) |

---

## 5. Detailed Vulnerability Findings

### SEC-01: Hardcoded Administrative and User Credentials in Source Code and UI

- **Severity:** Critical
- **CWE ID:** CWE-798 (Use of Hard-coded Credentials), CWE-259 (Use of Hard-coded Password)
- **Evidence:**
  - [`AdministratorPortal.java:586-605`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L586-L605):
    ```java
    586:  // Default administrator account: admin / Admin@2026!
    587:  createUser("admin", "Admin@2026!".toCharArray(), Role.ADMIN);
    588:
    589:  // Default super administrator account: superadmin / SuperAdmin@2026!
    590:  createUser("superadmin", "SuperAdmin@2026!".toCharArray(), Role.SUPER_ADMIN);
    591:
    592:  // Security Officer administrator: secadmin / SecAdmin@2026!
    593:  createUser("secadmin", "SecAdmin@2026!".toCharArray(), Role.SECURITY_OFFICER);
    ...
    ```
  - [`AdministratorPortal.java:1062-1067`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L1062-L1067):
    ```java
    1062: System.out.println("Available accounts for testing and verification:");
    1063: System.out.println("  Administrator:     admin         / Admin@2026!  (Full Admin)");
    1064: System.out.println("  Super Admin:       superadmin    / SuperAdmin@2026! (Super Admin)");
    1065: System.out.println("  Security Officer:  secadmin      / SecAdmin@2026! (Security Admin)");
    ```
  - [`run-tests.sh:30,35,44,62`](file:///data/results-cyber/agy/set_a/pilot/6/security/run-tests.sh#L30)
- **Why It Is a Problem:**
  The application seeds production accounts with static, hardcoded passwords (`Admin@2026!`, `SuperAdmin@2026!`, `SecAdmin@2026!`). Anyone with access to the source code, decompiled bytecode, shell script, or the interactive console banner immediately obtains full administrator privileges without authentication challenge bypass. Because default passwords are baked into the repository initialization routine, every deployment shares the exact same administrative credentials.
- **Remediation:**
  1. Remove all hardcoded credentials and sample test credentials from production code.
  2. Implement a secure first-time setup routine (e.g., prompt for initial superadmin password upon installation, or generate a random one-time bootstrap token written to a restricted file).
  3. Remove plaintext account listings and passwords from the console login banner.

---

### SEC-02: Unauthenticated Access to Full Security Audit Logs via Command-Line Interface

- **Severity:** High
- **CWE ID:** CWE-306 (Missing Authentication for Critical Function), CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
- **Evidence:**
  - [`AdministratorPortal.java:1690-1703`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L1690-L1703):
    ```java
    1690: if (args.length > 0 && (args[0].equals("--logs") || args[0].equals("--audit") || args[0].equals("-l"))) {
    1691:     auditLogger.printAuditSummary(System.out);
    1692:     System.out.println("\n--- All Authentication Audit Records ---");
    1693:     List<AuditRecord> authRecords = auditLogger.getAuthenticationRecords();
    1694:     if (authRecords.isEmpty()) {
    ...
    1698:         for (AuditRecord r : authRecords) {
    1699:             System.out.println(r);
    1700:         }
    1701:     }
    1702:     System.exit(0);
    1703:     return;
    1704: }
    ```
  - [`AdministratorPortal.java:1077-1080`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L1077-L1080) (Console option 2 prints audit summary unauthenticated).
- **Why It Is a Problem:**
  The administrative service properly requires an active admin session when viewing audit logs from inside the portal (`AdminService.viewAuditLogs`), but the CLI interface completely bypasses authentication. Any local user executing `java AdministratorPortal --logs` can view all authentication attempts, targeted usernames, IP addresses, failure reasons, and timestamps. This facilitates user enumeration, reconnaissance, and insider information exposure.
- **Remediation:**
  Require credential authentication and verify administrative privilege before printing audit records in CLI and console modes.

---

### SEC-03: Plaintext Password Exposure via Process Command-Line Arguments

- **Severity:** High
- **CWE ID:** CWE-214 (Invocation of Process Initializer with Untrusted Host/System-Defined Information), CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
- **Evidence:**
  - [`AdministratorPortal.java:1707-1709`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L1707-L1709):
    ```java
    1707: if (args.length >= 2) {
    1708:     String username = args[0];
    1709:     char[] password = args[1].toCharArray();
    ```
  - [`run-tests.sh:30,35,44,53,62`](file:///data/results-cyber/agy/set_a/pilot/6/security/run-tests.sh#L30):
    ```bash
    30: java AdministratorPortal admin Admin@2026! > /dev/null
    ```
- **Why It Is a Problem:**
  Accepting credentials via command-line arguments exposes plaintext passwords to all local system users. In Linux/Unix environments, process arguments are visible to any unprivileged user via `/proc/<PID>/cmdline` and tools like `ps aux`. Command invocations are also stored in cleartext shell history files (`~/.bash_history`). Furthermore, Java receives CLI arguments as immutable `String` objects (`String[] args`), defeating any downstream memory wiping (`PasswordSecurity.wipe(password)`).
- **Remediation:**
  Remove command-line argument password ingestion. Passwords should be accepted exclusively via secure interactive prompts (`System.console().readPassword()`), standard input pipes, or protected configuration files/environment variables with restrictive permissions.

---

### SEC-04: Broken Function-Level Access Control and Lack of Separation of Duties in Admin Services

- **Severity:** High
- **CWE ID:** CWE-285 (Improper Authorization), CWE-862 (Missing Authorization), CWE-269 (Improper Privilege Management)
- **Evidence:**
  - [`AdministratorPortal.java:59-65`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L59-L65):
    ```java
    59:  public enum Role {
    60:      ADMIN(true, "Full Administrator Privileges"),
    61:      SUPER_ADMIN(true, "Super Administrator with Elevated Privileges"),
    62:      SECURITY_OFFICER(true, "Security Officer with Audit & Telemetry Access"),
    ...
    ```
  - [`AdministratorPortal.java:849-853`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L849-L853):
    ```java
    849: private void assertAdmin(AdminSession session) {
    850:     if (session == null || session.getUser() == null || !session.getUser().getRole().hasAdminPrivilege()) {
    851:         throw new SecurityException("Unauthorized: Valid administrator session required to perform this operation.");
    852:     }
    853: }
    ```
  - [`AdministratorPortal.java:906-955`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L906-L955) (`createNewAccount`, `unlockAccount`, `toggleAccountStatus`, `resetPassword`).
- **Why It Is a Problem:**
  Although the application establishes distinct administrative roles (`SUPER_ADMIN`, `ADMIN`, and `SECURITY_OFFICER`), authorization is implemented using a single coarse check: `session.getUser().getRole().hasAdminPrivilege()`. All three administrative roles return `true`.
  As a result:
  1. A user with `SECURITY_OFFICER` role (intended strictly for audit and telemetry review) can reset the password of `SUPER_ADMIN` and `ADMIN` accounts, create new `SUPER_ADMIN` accounts, and deactivate administrators.
  2. A standard `ADMIN` can escalate privileges by resetting the `SUPER_ADMIN`'s credentials or promoting arbitrary accounts to `SUPER_ADMIN`.
  3. There is no separation of duties or least privilege enforcement.
- **Remediation:**
  Implement granular, function-level permission checks (e.g. check for specific permissions such as `MANAGE_USERS`, `RESET_ADMIN_CREDENTIALS`, `VIEW_AUDIT_LOGS`). Ensure that only `SUPER_ADMIN` can modify other administrative accounts, and restrict `SECURITY_OFFICER` strictly to read-only audit and diagnostic endpoints.

---

### SEC-05: Stateless AdminSession with Missing Session Registry, Validation, and Revocation

- **Severity:** High
- **CWE ID:** CWE-384 (Session Fixation), CWE-613 (Insufficient Session Expiration), CWE-306 (Missing Authentication for Critical Function)
- **Evidence:**
  - [`AdministratorPortal.java:640-668`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L640-L668):
    ```java
    640: public static class AdminSession {
    641:     private final String sessionId;
    642:     private final User user;
    ...
    646:     public AdminSession(User user, String clientIp) {
    647:         this.sessionId = UUID.randomUUID().toString();
    ...
    ```
  - [`AdministratorPortal.java:849-853`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L849-L853):
    ```java
    849: private void assertAdmin(AdminSession session) {
    850:     if (session == null || session.getUser() == null || !session.getUser().getRole().hasAdminPrivilege()) {
    851:         throw new SecurityException("Unauthorized: Valid administrator session required to perform this operation.");
    852:     }
    853: }
    ```
  - [`AdministratorPortal.java:1142-1145`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L1142-L1145):
    ```java
    1142: case "10" -> {
    1143:     System.out.println("\nLogging out administrator '" + session.getUser().getUsername() + "'...");
    1144:     inSession = false;
    1145: }
    ```
- **Why It Is a Problem:**
  `AdminService.assertAdmin()` verifies only that the passed `AdminSession` object is non-null and that its wrapped `User` has `hasAdminPrivilege()`. It never checks whether `sessionId` is present in an active session registry or whether the session has been revoked.
  Furthermore, `AdminSession` has a public constructor (`public AdminSession(User user, String clientIp)`), allowing arbitrary code to instantiate a valid session without going through `AuthenticationService`.
  When a user logs out in `ConsolePortal` (line 1144), `inSession = false` merely exits the local console loop; the session is never invalidated on the backend.
- **Remediation:**
  1. Maintain a central, thread-safe session registry (e.g. `Map<String, AdminSession> activeSessions`).
  2. Make the `AdminSession` constructor package-private or accessible only via `AuthenticationService`.
  3. Validate `session.getSessionId()` against the active session registry in `assertAdmin()`.
  4. Implement an explicit `logout(session)` method in `AdminService` / `AuthenticationService` that removes the session ID from the registry.

---

### SEC-06: Internal User Entity and Password Hash Leakage in Denied Authentication Results

- **Severity:** Medium
- **CWE ID:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor), CWE-497 (Exposure of Sensitive System Information to an Unauthorized Control Sphere)
- **Evidence:**
  - [`AdministratorPortal.java:183-203`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L183-L203):
    ```java
    183: public synchronized byte[] getSalt() {
    184:     return salt.clone();
    185: }
    186:
    187: public synchronized byte[] getPasswordHash() {
    188:     return passwordHash.clone();
    189: }
    ...
    200: public synchronized void setRole(Role role) {
    201:     this.role = role;
    202: }
    ```
  - [`AdministratorPortal.java:690-692`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L690-L692):
    ```java
    690: public static AuthResult denied(AuthStatusCode status, String message, User user) {
    691:     return new AuthResult(status, false, message, user, null);
    692: }
    ```
  - [`AdministratorPortal.java:810-812`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L810-L812):
    ```java
    810: return AuthResult.denied(AuthStatusCode.DENIED_NOT_AN_ADMIN,
    811:         "Access Denied: User '" + user.getUsername() + "' has role [" + user.getRole().name() +
    812:                 "]. Administrator privileges are strictly required to enter this portal.", user);
    ```
- **Why It Is a Problem:**
  When authentication is denied due to lack of administrative role (`DENIED_NOT_AN_ADMIN`), account lockout (`DENIED_ACCOUNT_LOCKED`), or inactivity (`DENIED_ACCOUNT_INACTIVE`), `AuthResult.denied()` attaches the live domain `User` entity to the result object.
  Calling `result.getUser()` gives the caller:
  1. Direct access to the account's password hash (`getPasswordHash()`) and salt (`getSalt()`), facilitating offline password cracking.
  2. Direct access to mutable domain methods (`setRole(Role.ADMIN)`, `setActive(true)`, `unlock()`). Any consumer can mutate the shared in-memory user instance to elevate privileges.
- **Remediation:**
  Do not attach domain entities containing credentials or mutable state to `AuthResult`. If caller context is required, return an immutable, unprivileged DTO containing only non-sensitive attributes (e.g. username and lockout timestamp), with no access to salt, hash, or mutators.

---

### SEC-07: Failure to Clear Plaintext Password Memory in `PBEKeySpec`

- **Severity:** Medium
- **CWE ID:** CWE-316 (Cleartext Storage of Sensitive Information in Memory), CWE-244 (Improper Clearing of Heap Memory Before Release)
- **Evidence:**
  - [`AdministratorPortal.java:538-546`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L538-L546):
    ```java
    538: public static byte[] hashPassword(char[] password, byte[] salt) {
    539:     try {
    540:         PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, HASH_KEY_LENGTH);
    541:         SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
    542:         return skf.generateSecret(spec).getEncoded();
    543:     } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
    544:         throw new IllegalStateException("Cryptographic algorithm unavailable: " + e.getMessage(), e);
    545:     }
    546: }
    ```
- **Why It Is a Problem:**
  The Java Cryptography Architecture `PBEKeySpec` class clones the provided `char[]` password upon construction. `PBEKeySpec` provides an explicit `clearPassword()` method specifically intended to zero out this sensitive internal character array once key generation is complete.
  Because `spec.clearPassword()` is omitted, the plaintext password remains allocated in heap memory indefinitely until garbage collection (and even afterwards in un-cleared memory pages), making it susceptible to extraction via heap dumps or memory analysis.
- **Remediation:**
  Call `spec.clearPassword()` inside a `finally` block:
  ```java
  PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, HASH_KEY_LENGTH);
  try {
      SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
      return skf.generateSecret(spec).getEncoded();
  } finally {
      spec.clearPassword();
  }
  ```

---

### SEC-08: Uncontrolled Account Lockout Denial of Service (Account Locking DoS)

- **Severity:** Medium
- **CWE ID:** CWE-400 (Uncontrolled Resource Consumption), CWE-307 (Improper Restriction of Excessive Authentication Attempts)
- **Evidence:**
  - [`AdministratorPortal.java:43-44`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L43-L44):
    ```java
    43: public static final int MAX_FAILED_ATTEMPTS = 5;
    44: public static final Duration LOCKOUT_DURATION = Duration.ofMinutes(15);
    ```
  - [`AdministratorPortal.java:782-793`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L782-L793):
    ```java
    782: if (!passwordValid) {
    783:     user.incrementFailedAttempts();
    784:     if (user.getFailedAttempts() >= MAX_FAILED_ATTEMPTS) {
    785:         user.lockFor(LOCKOUT_DURATION);
    786:         auditLogger.log(AuditEventType.ACCOUNT_LOCKED_AUTO, user.getUsername(),
    ...
    ```
- **Why It Is a Problem:**
  The account lockout policy locks an account for 15 minutes after 5 consecutive failed attempts, keyed purely on the targeted username. There is no IP-based throttling, progressive delay, or CAPTCHA mechanism. An unauthenticated attacker knowing or guessing an administrative username (such as `admin` or `superadmin`) can send 5 failed attempts every 15 minutes to indefinitely lock out legitimate administrators, causing a persistent Denial of Service.
- **Remediation:**
  1. Implement IP-based rate limiting and exponential backoff delays rather than complete account lockouts for administrative accounts.
  2. Implement CAPTCHA or multi-factor authentication (MFA) challenges before triggering account lockout.
  3. Ensure a dedicated emergency administrative bypass / out-of-band console access exists.

---

### SEC-09: Unbounded Heap Allocation and High CPU Overhead in `AuditLogger` (Resource Exhaustion DoS)

- **Severity:** Medium
- **CWE ID:** CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation of Resources Without Limits or Throttling)
- **Evidence:**
  - [`AdministratorPortal.java:422`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L422):
    ```java
    421: public static class AuditLogger {
    422:     private final List<AuditRecord> inMemoryRecords = new CopyOnWriteArrayList<>();
    ...
    448:     AuditRecord record = new AuditRecord(type, username, details, clientIp);
    449:     inMemoryRecords.add(record);
    ```
- **Why It Is a Problem:**
  Every authentication attempt (including failed attempts from automated scanning or brute-force scripts) generates a new `AuditRecord` appended to `inMemoryRecords`.
  `CopyOnWriteArrayList` creates an entire clone of the underlying array on every single `add()` invocation. Under continuous authentication traffic or automated attacks, this causes severe CPU overhead ($O(N)$ allocation per event, resulting in $O(N^2)$ memory copying) and unbounded heap memory consumption, inevitably triggering a `java.lang.OutOfMemoryError` crash.
- **Remediation:**
  1. Replace `CopyOnWriteArrayList` with a bounded FIFO circular buffer or ring buffer for in-memory recent event queries.
  2. Rely primarily on disk-backed append-only streaming logs rather than accumulating all historical audit events in JVM heap memory.

---

### SEC-10: Missing Session Expiration and Inactivity Timeout Enforcement

- **Severity:** Medium
- **CWE ID:** CWE-613 (Insufficient Session Expiration)
- **Evidence:**
  - [`AdministratorPortal.java:649`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L649):
    ```java
    649: this.loginTime = Instant.now();
    ```
  - [`AdministratorPortal.java:849-853`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L849-L853):
    ```java
    849: private void assertAdmin(AdminSession session) {
    850:     if (session == null || session.getUser() == null || !session.getUser().getRole().hasAdminPrivilege()) {
    851:         throw new SecurityException("Unauthorized: Valid administrator session required to perform this operation.");
    852:     }
    853: }
    ```
- **Why It Is a Problem:**
  While `AdminSession` records `loginTime`, `AdminService.assertAdmin()` never evaluates the session's timestamp. There is no idle inactivity timeout and no absolute session lifetime limit. An administrative session remains valid indefinitely as long as the object exists, leaving unattended or intercepted sessions active indefinitely.
- **Remediation:**
  Define a maximum session lifetime (e.g. 4–8 hours) and an idle inactivity timeout (e.g. 15–30 minutes). Track `lastActivityTime` on `AdminSession` and reject requests in `assertAdmin()` when either timeout threshold is exceeded.

---

### SEC-11: Insecure Default File Permissions on Persistent Audit Log File

- **Severity:** Medium
- **CWE ID:** CWE-732 (Incorrect Permission Assignment for Critical Resource), CWE-276 (Incorrect Default Permissions)
- **Evidence:**
  - [`AdministratorPortal.java:454-455`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L454-L455):
    ```java
    454: Files.writeString(logFilePath, logLine, StandardCharsets.UTF_8,
    455:         StandardOpenOption.CREATE, StandardOpenOption.APPEND, StandardOpenOption.WRITE);
    ```
- **Why It Is a Problem:**
  `Files.writeString` with `StandardOpenOption.CREATE` creates `audit.log` using the process's default umask (typically `022` or `002`). This results in file permissions of `0644` or `0664`, allowing any unprivileged local user or process on the host to read the audit log. The audit log contains sensitive operational metadata, targeted usernames, client IP addresses, and authentication event patterns.
- **Remediation:**
  Explicitly create the audit log file with restrictive POSIX permissions (`0600` / read-write only by owner):
  ```java
  if (!Files.exists(logFilePath)) {
      Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
      FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(perms);
      Files.createFile(logFilePath, attr);
  }
  ```

---

### SEC-12: Incomplete Log Sanitization Permitting ANSI Escape and Terminal Injection

- **Severity:** Low
- **CWE ID:** CWE-117 (Improper Output Handling for Logs), CWE-150 (Improper Neutralization of Escape, Meta, or Control Sequences)
- **Evidence:**
  - [`AdministratorPortal.java:406-410`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L406-L410):
    ```java
    406: private static String sanitizeForLog(String input) {
    407:     if (input == null) return "N/A";
    408:     // Prevent log injection attacks (CWE-117)
    409:     return input.replace('\r', '_').replace('\n', '_').replace('\t', ' ').replace('|', '/');
    410: }
    ```
- **Why It Is a Problem:**
  `sanitizeForLog` sanitizes `\r`, `\n`, `\t`, and the delimiter `|`, which prevents basic multi-line log injection and field delimiter corruption. However, it fails to strip ANSI escape codes (e.g. `\u001b[` sequences) or other control characters. When logs are displayed in a terminal emulator (via CLI `--logs` or the console dashboard), an attacker passing ANSI escape sequences in the username field can overwrite terminal display lines, conceal fraudulent events, or exploit terminal emulator vulnerabilities.
- **Remediation:**
  Strip all non-printable ASCII/Unicode control characters and ANSI escape sequences:
  ```java
  private static String sanitizeForLog(String input) {
      if (input == null) return "N/A";
      return input.replaceAll("\\x1B\\[[0-9;]*[a-zA-Z]", "")
                  .replaceAll("[\\p{Cntrl}&&[^\r\n\t]]", "")
                  .replace('\r', '_')
                  .replace('\n', '_')
                  .replace('\t', ' ')
                  .replace('|', '/');
  }
  ```

---

### SEC-13: Sub-optimal PBKDF2 Work Factor / Iteration Count

- **Severity:** Low
- **CWE ID:** CWE-916 (Use of Password Hash With Insufficient Computational Effort)
- **Evidence:**
  - [`AdministratorPortal.java:40`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L40):
    ```java
    40: public static final int PBKDF2_ITERATIONS = 64_000;
    ```
- **Why It Is a Problem:**
  `PBKDF2_ITERATIONS` is set to 64,000. Current OWASP Password Storage Guidelines recommend a minimum of 600,000 iterations when using `PBKDF2WithHmacSHA256` to ensure adequate computational resistance against modern GPU/ASIC offline password cracking clusters.
- **Remediation:**
  Increase the iteration count to at least 600,000 iterations for `PBKDF2WithHmacSHA256`, or migrate to a modern memory-hard password hashing algorithm such as Argon2id or bcrypt.

---

### SEC-14: Absence of Password Complexity and Length Requirements at Service Layer

- **Severity:** Low
- **CWE ID:** CWE-521 (Weak Password Requirements)
- **Evidence:**
  - [`AdministratorPortal.java:906-915`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L906-L915) (`AdminService.createNewAccount`)
  - [`AdministratorPortal.java:942-955`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L942-L955) (`AdminService.resetPassword`)
  - [`AdministratorPortal.java:1175-1178`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L1175-L1178), [`AdministratorPortal.java:1232-1236`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L1232-L1236)
- **Why It Is a Problem:**
  `AdminService.createNewAccount()` and `AdminService.resetPassword()` accept arbitrary password character arrays without verifying length, character set diversity, or entropy. While the console UI checks for `password.length < 6`, this check is absent in the core service layer and is too weak for an enterprise administrator portal.
- **Remediation:**
  Enforce comprehensive password complexity requirements at the service layer (e.g. minimum 12 characters, combination of uppercase, lowercase, numbers, and symbols, and checking against common password lists).

---

### SEC-15: Non-TTY Fallback Uses Immutable String for Password Input

- **Severity:** Low
- **CWE ID:** CWE-316 (Cleartext Storage of Sensitive Information in Memory)
- **Evidence:**
  - [`AdministratorPortal.java:1320-1321`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L1320-L1321):
    ```java
    1320: String line = reader.readLine();
    1321: return line != null ? line.toCharArray() : new char[0];
    ```
- **Why It Is a Problem:**
  In non-TTY environments (e.g., containerized execution or script pipes where `System.console()` is null), `promptPassword` invokes `reader.readLine()`, creating an immutable `java.lang.String`. Although the returned `char[]` is later wiped via `PasswordSecurity.wipe()`, the underlying `String` cannot be wiped and remains in heap memory until cleared by the garbage collector.
- **Remediation:**
  Read characters directly into a `char[]` buffer rather than reading entire lines as immutable `String` instances.

---

### SEC-16: Non-Persistent In-Memory User Repository Reverts Credential Updates on Restart

- **Severity:** Low
- **CWE ID:** CWE-311 (Missing Encryption of Sensitive Data), CWE-798 (Use of Hard-coded Credentials)
- **Evidence:**
  - [`AdministratorPortal.java:578-605`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L578-L605):
    ```java
    578: public static class UserRepository {
    579:     private final Map<String, User> userMap = new ConcurrentHashMap<>();
    580:
    581:     public UserRepository() {
    582:         seedDefaultAccounts();
    583:     }
    ```
- **Why It Is a Problem:**
  User accounts, updated passwords, new account registrations, and unlock states are stored solely in an in-memory `ConcurrentHashMap`. Unlike the audit log, the user store is not persisted. When the application process terminates or restarts, all password resets and new accounts are lost, and the system re-initializes with the default hardcoded credentials. If an admin resets compromised credentials, a restart restores the compromised default password.
- **Remediation:**
  Persist user accounts and password hashes in an encrypted, authenticated database or credential store rather than in-memory volatile structures.

---

## 6. Verification & Positive Security Observations

The codebase was also assessed for common web and system vulnerabilities that were **not** present or were appropriately mitigated:

1. **Timing Attack Mitigation (CWE-208):**  
   Password verification uses `MessageDigest.isEqual(computedHash, storedHash)` ([`AdministratorPortal.java:551`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L551)), ensuring constant-time hash comparison.
2. **User Enumeration Timing Resistance (CWE-204):**  
   When non-existent users or empty credentials are submitted, `PasswordSecurity.executeDummyHash()` ([`AdministratorPortal.java:554-557`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L554-L557)) executes a full PBKDF2 cycle against a dummy salt, equalizing response times.
3. **Audit Event Recording Completeness:**  
   Both successful and unsuccessful authentication attempts across all failure modes (`LOGIN_SUCCESS`, `LOGIN_FAILURE_BAD_CREDENTIALS`, `LOGIN_FAILURE_UNKNOWN_USER`, `LOGIN_FAILURE_EMPTY_CREDENTIALS`, `LOGIN_DENIED_NOT_ADMIN`, `LOGIN_DENIED_LOCKED`, `LOGIN_DENIED_INACTIVE`) are logged ([`AdministratorPortal.java:737-822`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L737-L822)).
4. **Delimited Log Injection Defense (CWE-117):**  
   Newline characters (`\r`, `\n`) and pipe delimiters (`|`) are replaced in `sanitizeForLog` ([`AdministratorPortal.java:406-410`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L406-L410)), preventing traditional multi-line log forging.
5. **Safe Cryptographic Primitives:**  
   The application uses `SecureRandom` for salt generation ([`AdministratorPortal.java:530-536`](file:///data/results-cyber/agy/set_a/pilot/6/security/AdministratorPortal.java#L530-L536)) and avoids weak hashes (such as MD5 or SHA-1) for credential verification.
