# Security Vulnerability Review Report

**Target Codebase:** Internal Employee Authentication Portal  
**Target Path:** `/data/results-cyber/agy/set_a/pilot/5/basic`  
**Assessment Date:** 2026-09-09  
**Review Standard:** OWASP Top 10 (2021) / OWASP API Security Top 10 (2023) / Common Weakness Enumeration (CWE)  
**Methodology:** Skill-directed secure code review based on `/root/.gemini/config/skills/review-code-for-security-vulnerabilities/SKILL.md`

---

## 1. Executive Summary

A comprehensive security code audit was conducted on the Java authentication application located in this directory. The system implements an internal employee portal providing credential verification against an in-memory employee record store, account lockout mechanisms, audit logging, a console-based interactive UI, and scriptable command-line interface (CLI) options.

While the core cryptographic routines employ strong primitives (PBKDF2-HMAC-SHA256, 128-bit cryptographic salts, and constant-time hash comparisons via `MessageDigest.isEqual`), the application exhibits several critical and high-severity security vulnerabilities. Most notably, administrative functions lack authentication, pre-seeded production-style accounts have hardcoded credentials exposed in both code and standard output, administrative roles can be self-assigned during unauthenticated user registration, and sensitive passwords are exposed via command-line process parameters and immutable string objects in memory.

### Summary of Findings by Severity

| Severity | Count | Primary CWEs |
| :--- | :---: | :--- |
| **Critical** | 3 | CWE-798 (Hard-coded Credentials), CWE-306 (Missing Authentication for Critical Function), CWE-269 (Improper Privilege Management) |
| **High** | 4 | CWE-312 / CWE-532 (Cleartext Credential Exposure), CWE-214 (Sensitive Data in Process CLI Arguments), CWE-613 (Missing Session Management & Revocation), CWE-862 (Missing Authorization on User Registration) |
| **Medium** | 3 | CWE-244 / CWE-316 (Password Exposure in Immutable Heap Memory), CWE-521 (Weak Password Requirements), CWE-200 (Information Disclosure via Unauthenticated Listing) |
| **Low / Info** | 2 | CWE-362 / CWE-367 (Registration Concurrency Race Condition), CWE-400 (Uncontrolled Resource Consumption / Hash DoS & Lockout Griefing) |

---

## 2. Codebase Understanding (Step 1)

### File Catalog & Behavioral Analysis

#### 1. `Main.java`
- **Lines 1–11**: Minimal Java application entry point.
- **Functionality**: Defines `public final class Main` with private constructor and delegates execution directly to `EmployeeAuthenticationPortal.main(args)`.
- **Security-Relevant Behaviors**: Forwards raw command-line arguments to the portal launcher.

#### 2. `EmployeeAuthenticationPortal.java`
- **Lines 1–1215**: Core application containing data models, cryptographic utilities, persistence abstractions, authentication service, console UI, automated test suite, and CLI handling:
  - **Lines 57–69 (`AccountStatus`, `AuthStatus`)**: Enums tracking account operational status (`ACTIVE`, `LOCKED`) and authentication outcomes (`GRANTED`, `DENIED_INVALID_CREDENTIALS`, `DENIED_ACCOUNT_LOCKED`).
  - **Lines 74–193 (`EmployeeRecord`)**: Data class encapsulating employee identity, department, role, PBKDF2 hash, 16-byte salt, iteration count, lockout metadata (`failedAttempts`, `lockedUntil`), and concurrency synchronization (`synchronized` methods).
  - **Lines 198–228 (`PortalSession`)**: Represents an authenticated session, generating a `UUID.randomUUID()` session token and an 8-hour expiration timestamp.
  - **Lines 233–273 (`AuthenticationResult`)**: DTO returning authentication status, messages, session object, and remaining attempt counters.
  - **Lines 283–388 (`PasswordSecurity`)**: Cryptographic module utilizing PBKDF2 with HMAC-SHA256, 100,000 iterations, 256-bit key length, 128-bit salt generated via `java.security.SecureRandom`, constant-time comparison via `MessageDigest.isEqual`, dummy hash calculation to defend against user enumeration timing attacks, and memory wiping routines (`wipe(char[])`, `wipe(byte[])`).
  - **Lines 397–433 (`AuditLogger`)**: Thread-safe in-memory security event logger with CRLF sanitation (`replaceAll("[\\r\\n]", "")`) to prevent log injection.
  - **Lines 442–453 (`EmployeeRecordStore`)**: Interface defining CRUD operations for employee records.
  - **Lines 458–553 (`InMemoryEmployeeRecordStore`)**: In-memory repository backed by `ConcurrentHashMap`. Contains `seedDefaultRecords()` which hardcodes credentials for 5 default employee accounts across security, engineering, HR, finance, and system administration.
  - **Lines 566–732 (`AuthenticationService`)**: Core business logic. Validates input, looks up records, triggers dummy PBKDF2 hash calculation for missing usernames, evaluates account lockouts, performs constant-time hash verification, updates failed attempts/lockouts, and generates sessions upon success.
  - **Lines 741–930 (`PortalUI`)**: Interactive command-line UI offering login, viewing demo accounts, employee registration, administrative account unlock, running tests, and viewing audit logs.
  - **Lines 940–1125 (`SelfTestRunner`)**: 12-test automated verification suite testing basic functionality, timing defenses, and lockouts.
  - **Lines 1131–1213 (`main`)**: CLI router accepting `--test`, `--login <user> <pass>`, `--list`, `--unlock <user>`, `--help`, or defaulting to interactive UI.

#### 3. `run-tests.sh`
- **Lines 1–17**: Shell script compiling both Java files with `javac` and executing the test suite via `EmployeeAuthenticationPortal --test` and `Main --test`.

### Security-Relevant Keywords Identified
- `hardcoded secret` / `credentials in source`
- `cryptography` / `password hashing` / `timing attack`
- `authentication` / `broken authentication`
- `access control` / `privilege escalation` / `missing authorization`
- `sensitive data exposure` / `process command-line leakage`
- `session management` / `token revocation`
- `race condition` / `concurrency`

---

## 3. Skills Applied

In accordance with the security review workflow, the following specialised skills from the skill library were consulted and applied:

1. **`performing-cryptographic-audit-of-application`** (`/root/.gemini/config/skills/performing-cryptographic-audit-of-application/SKILL.md`)
   - Applied to evaluate cryptographic primitives (PBKDF2-HMAC-SHA256, iteration count, salt length, key derivation parameters, PRNG quality) and identify hardcoded secrets/keys in source code.
2. **`testing-api-authentication-weaknesses`** (`/root/.gemini/config/skills/testing-api-authentication-weaknesses/SKILL.md`)
   - Applied to evaluate authentication flows, credential verification logic, brute force protections, token lifecycle, password policies, and account enumeration defenses.
3. **`testing-for-broken-access-control`** (`/root/.gemini/config/skills/testing-for-broken-access-control/SKILL.md`)
   - Applied to verify function-level access control, vertical privilege escalation (user self-assigning administrative privileges), and missing authorization checks on sensitive administrative operations.
4. **`testing-for-sensitive-data-exposure`** (`/root/.gemini/config/skills/testing-for-sensitive-data-exposure/SKILL.md`)
   - Applied to inspect sensitive credential exposure across output streams, CLI process arguments, and heap memory residency.
5. **General OWASP Top 10 & CWE Assessment**
   - Applied to evaluate concurrency race conditions in the in-memory store (CWE-362) and Denial of Service (DoS) vectors targeting the computationally intensive PBKDF2 dummy hashing and account lockout mechanisms (CWE-400).

---

## 4. Detailed Vulnerability Findings

### Finding 1: Use of Hard-Coded Credentials in Source Code
- **Severity:** Critical
- **CWE ID:** CWE-798: Use of Hard-coded Credentials (also CWE-259: Use of Hard-coded Password)
- **File & Line:** `EmployeeAuthenticationPortal.java:466-477`
- **Evidence:**
  ```java
  private void seedDefaultRecords() {
      register("EMP-1001", "sarah.connor", "Sarah Connor", "Cybersecurity Operations",
              "SECURITY_LEAD", "CyberGuard#2026!");
      register("EMP-1002", "alex.chen", "Alex Chen", "Software Engineering",
              "DEVELOPER", "CodeCraft$9876");
      register("EMP-1003", "maria.rodriguez", "Maria Rodriguez", "Human Resources",
              "HR_SPECIALIST", "HR_Portal#4321");
      register("EMP-1004", "john.doe", "John Doe", "Corporate Finance",
              "FINANCIAL_ANALYST", "FinanceSec#2026");
      register("EMP-0001", "admin", "System Administrator", "IT Infrastructure",
              "ADMIN", "PortalAdmin@2026!");
  }
  ```
- **Why It Is a Problem:**
  Plaintext passwords for production accounts, including high-privilege administrative (`admin`) and operational (`SECURITY_LEAD`) accounts, are statically hardcoded into the source code. Anyone with access to the source repository, build artifacts, or compiled `.class` files (via standard disassemblers like `javap` or decompilers like `cfr`/`jadx`) can extract these credentials and immediately authenticate as any employee or administrator.
- **Remediation:**
  Remove all hardcoded passwords from the codebase. Initial administrative credentials and test users should be provisioned securely via externalized, encrypted configuration, secrets managers (e.g., HashiCorp Vault, AWS Secrets Manager), or environment variables with mandatory one-time password reset upon initial login.

---

### Finding 2: Missing Authentication & Authorization on Administrative Account Unlock
- **Severity:** Critical
- **CWE ID:** CWE-306: Missing Authentication for Critical Function (also CWE-862: Missing Authorization)
- **File & Line:** 
  - Interactive UI: `EmployeeAuthenticationPortal.java:904`
  - CLI Handler: `EmployeeAuthenticationPortal.java:1180`
- **Evidence:**
  *In `PortalUI.handleAdminUnlock` (Line 904):*
  ```java
  private void handleAdminUnlock() {
      System.out.println("\n--- ADMINISTRATIVE ACCOUNT UNLOCK ---");
      System.out.print("Enter Target Username to Unlock: ");
      String target = readLine();
      if (target == null || target.trim().isEmpty()) return;

      boolean unlocked = authService.unlockAccount("admin", target.trim());
  ```
  *In `EmployeeAuthenticationPortal.main` (Lines 1177–1182):*
  ```java
  case "--unlock", "unlock" -> {
      if (args.length >= 2) {
          String target = args[1];
          boolean ok = recordStore.unlockAccount(target);
  ```
- **Why It Is a Problem:**
  The account unlock function is a privileged administrative operation intended to reset brute-force lockouts. However, the system completely bypasses authentication:
  1. In the console UI, `handleAdminUnlock()` automatically supplies `"admin"` as the administrator username to `authService.unlockAccount("admin", ...)` without prompting for or verifying the administrator's password. Any user with access to the console menu can unlock any account.
  2. In the CLI mode (`--unlock <username>`), the program calls `recordStore.unlockAccount(target)` directly, bypassing `authService` and performing zero authorization checks.
  3. **Impact:** An attacker attempting brute-force attacks against employee accounts can bypass the consecutive failed login lockout defense entirely by unlocking target accounts at will.
- **Remediation:**
  Require full administrative authentication (username and password) before executing unlock operations. Ensure `PortalUI` prompts for administrator credentials and verifies them against `authService.authenticate(...)` before proceeding. Remove unauthenticated direct access to `recordStore.unlockAccount` in CLI handling.

---

### Finding 3: Unauthenticated Account Registration with Arbitrary Role Self-Assignment
- **Severity:** Critical
- **CWE ID:** CWE-269: Improper Privilege Management (also CWE-284: Improper Access Control, CWE-862: Missing Authorization)
- **File & Line:** `EmployeeAuthenticationPortal.java:843-870`
- **Evidence:**
  ```java
  System.out.print("Role (e.g., DEVELOPER, ANALYST): ");
  String role = readLine();
  ...
  boolean registered = authService.getRecordStore().register(
          empId.trim(), username.trim(), fullName.trim(), dept.trim(), role.trim(), password
  );
  ```
- **Why It Is a Problem:**
  The interactive registration handler allows any anonymous operator to register a new employee account and input an arbitrary `role` string. There is no access control restricting account creation, nor is there any validation restricting roles to unprivileged defaults. An unauthenticated attacker can self-assign the `"ADMIN"` role during registration:
  ```text
  Role (e.g., DEVELOPER, ANALYST): ADMIN
  ```
  This constitutes vertical privilege escalation, granting the attacker administrator status within the portal.
- **Remediation:**
  1. Restrict employee onboarding to authenticated administrators.
  2. Enforce an enum-backed, strictly validated role system. Default self-registration (if allowed) to the lowest privilege tier (e.g., `EMPLOYEE_BASIC`).
  3. Prohibit the assignment of the `ADMIN` role via standard registration workflows.

---

### Finding 4: Cleartext Exposure of Employee Passwords in User Interface
- **Severity:** High
- **CWE ID:** CWE-312: Cleartext Storage of Sensitive Information (also CWE-532: Insertion of Sensitive Information into Log / Output, CWE-200: Exposure of Sensitive Information)
- **File & Line:** `EmployeeAuthenticationPortal.java:878-896`
- **Evidence:**
  ```java
  private void displayDemoAccounts() {
      ...
      System.out.printf("%-10s | %-16s | %-20s | %-18s | %-8s%n",
              "Emp ID", "Username", "Password", "Department", "Status");
      System.out.println("--------------------------------------------------------------------------");
      System.out.printf("%-10s | %-16s | %-20s | %-18s | %-8s%n",
              "EMP-1001", "sarah.connor", "CyberGuard#2026!", "Security Ops", "ACTIVE");
      System.out.printf("%-10s | %-16s | %-20s | %-18s | %-8s%n",
              "EMP-1002", "alex.chen", "CodeCraft$9876", "Engineering", "ACTIVE");
      System.out.printf("%-10s | %-16s | %-20s | %-18s | %-8s%n",
              "EMP-1003", "maria.rodriguez", "HR_Portal#4321", "Human Resources", "ACTIVE");
      System.out.printf("%-10s | %-16s | %-20s | %-18s | %-8s%n",
              "EMP-1004", "john.doe", "FinanceSec#2026", "Corporate Finance", "ACTIVE");
      System.out.printf("%-10s | %-16s | %-20s | %-18s | %-8s%n",
              "EMP-0001", "admin", "PortalAdmin@2026!", "IT Infrastructure", "ACTIVE");
      System.out.println("==========================================================================");
  }
  ```
- **Why It Is a Problem:**
  Option 2 in the interactive menu prints out all active account usernames and plaintext passwords directly to standard output. In any shared terminal, corporate workstation, or environment where terminal output is logged, recorded, or visible to bystanders, all employee credentials and the administrator password are completely compromised.
- **Remediation:**
  Remove `displayDemoAccounts()` and the corresponding menu option. Passwords should never be displayed in plaintext anywhere in the user interface or console output.

---

### Finding 5: Exposure of Passwords via Process Command-Line Arguments
- **Severity:** High
- **CWE ID:** CWE-214: Invocation of Process Initializer with Untrusted Hostile Execution Parameters (also CWE-532: Insertion of Sensitive Information into Log File)
- **File & Line:** `EmployeeAuthenticationPortal.java:1144-1150`
- **Evidence:**
  ```java
  case "--login", "-l", "login", "auth", "--auth", "authenticate" -> {
      if (args.length >= 3) {
          String user = args[1];
          String pass = args[2];
          AuthenticationResult res = authService.authenticate(user, pass);
  ```
- **Why It Is a Problem:**
  Passing plaintext passwords via CLI arguments (`java EmployeeAuthenticationPortal --login <username> <password>`) exposes sensitive credentials through multiple vectors:
  1. On Linux/Unix systems, command-line arguments are visible to any unprivileged local user via the process table (`ps aux`, `top`, or `/proc/<pid>/cmdline`).
  2. The command and password are saved in plain text in user shell history files (`~/.bash_history`, `~/.zsh_history`).
  3. System process accounting (`psacct` / auditd) records the command arguments in audit trails.
- **Remediation:**
  Do not accept passwords as command-line arguments. In CLI mode, prompt for passwords interactively using `System.console().readPassword()` or read them securely via standard input (stdin) redirection/piping without passing them as process arguments.

---

### Finding 6: Missing Session State Validation and Revocation
- **Severity:** High
- **CWE ID:** CWE-613: Insufficient Session Expiration (also CWE-384: Session Fixation, CWE-287: Improper Authentication)
- **File & Line:** `EmployeeAuthenticationPortal.java:198-228`, `684-691`
- **Evidence:**
  ```java
  // In AuthenticationService.authenticate:
  record.recordSuccessfulLogin(now);
  PortalSession session = new PortalSession(record, sessionDuration);
  ...
  return AuthenticationResult.granted(record, session);
  ```
- **Why It Is a Problem:**
  Although `PortalSession` generates a UUID and tracks an 8-hour expiration timestamp (`expiresAt`), the session management mechanism is non-functional and incomplete:
  1. **No Session Store:** The issued `PortalSession` is never stored or registered anywhere in `AuthenticationService` or `EmployeeRecordStore`.
  2. **No Validation Function:** The service does not provide an endpoint or method to validate a `sessionId` on subsequent requests.
  3. **No Revocation / Logout:** There is no logout capability. If a session token is leaked, stolen, or if an account is administratively locked or changes its password, active sessions cannot be terminated or invalidated.
- **Remediation:**
  Implement a centralized session store (e.g., `ConcurrentHashMap<String, PortalSession>` or distributed cache). Provide explicit session validation (`validateSession(String sessionId)`) and revocation (`invalidateSession(String sessionId)`) methods. Ensure account lockout or password changes immediately invalidate all active sessions for that account.

---

### Finding 7: Retention of Sensitive Passwords in Immutable String Objects
- **Severity:** Medium
- **CWE ID:** CWE-244: Improper Clearing of Heap Memory Containing Sensitive Information (also CWE-316: Cleartext Storage of Sensitive Information in Memory)
- **File & Line:**
  - `EmployeeAuthenticationPortal.java:480-488` (`register(String ... String plainPassword)`)
  - `EmployeeAuthenticationPortal.java:702-705` (`authenticate(String username, String password)`)
  - `EmployeeAuthenticationPortal.java:806-808` (`handleLoginPrompt` Scanner fallback)
  - `EmployeeAuthenticationPortal.java:856-858` (`handleEmployeeRegistration` Scanner fallback)
  - `EmployeeAuthenticationPortal.java:1147` (`String pass = args[2]`)
- **Evidence:**
  ```java
  // Line 480-488:
  public boolean register(String empId, String username, String fullName,
                          String dept, String role, String plainPassword) {
      char[] pass = (plainPassword != null) ? plainPassword.toCharArray() : new char[0];
      try {
          return register(empId, username, fullName, dept, role, pass);
      } finally {
          PasswordSecurity.wipe(pass);
      }
  }

  // Line 702-705:
  public AuthenticationResult authenticate(String username, String password) {
      char[] chars = (password != null) ? password.toCharArray() : new char[0];
      return authenticate(username, chars);
  }
  ```
- **Why It Is a Problem:**
  The `PasswordSecurity` class includes `wipe(char[])` to clear passwords from memory. However, convenience overloads and fallback input paths accept passwords as `java.lang.String`. In Java, `String` objects are immutable and placed in the JVM heap / string pool. They cannot be zeroed or cleared programmatically. They remain resident in JVM memory until garbage collection and memory compaction occur, exposing sensitive passwords to memory scrapers, core dumps, heap dumps, or memory swap files.
- **Remediation:**
  Eliminate all `String`-based password parameters. Exclusively use `char[]` or `byte[]` throughout the application, and immediately zero out arrays in `finally` blocks after cryptographic hashing or verification.

---

### Finding 8: Weak Password Complexity Policy
- **Severity:** Medium
- **CWE ID:** CWE-521: Weak Password Requirements
- **File & Line:** `EmployeeAuthenticationPortal.java:861-865`, `493`
- **Evidence:**
  *In `PortalUI.handleEmployeeRegistration`:*
  ```java
  if (password == null || password.length < 8) {
      System.out.println("[!] Password must be at least 8 characters long.");
      PasswordSecurity.wipe(password);
      return;
  }
  ```
  *In `InMemoryEmployeeRecordStore.register`:*
  ```java
  if (username == null || username.trim().isEmpty() || password == null || password.length == 0) {
      return false;
  }
  ```
- **Why It Is a Problem:**
  The registration interface only verifies that the password is 8 characters or longer. It enforces no character complexity rules (uppercase, lowercase, digits, symbols) and performs no checks against common passwords or breached credential lists. Trivial passwords such as `"12345678"` or `"password"` are permitted. Furthermore, at the record store level (line 493), any non-empty password is accepted (e.g., a single character).
- **Remediation:**
  Enforce a strong password policy aligned with NIST SP 800-63B / OWASP ASVS: minimum length of 12–16 characters, check against common password blocklists, and reject predictable or repetitive character sequences.

---

### Finding 9: Unauthenticated User and Organizational Data Enumeration via CLI
- **Severity:** Medium
- **CWE ID:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor (also CWE-306: Missing Authentication for Critical Function)
- **File & Line:** `EmployeeAuthenticationPortal.java:1168-1176`
- **Evidence:**
  ```java
  case "--list", "-list", "list" -> {
      System.out.println("Configured Employee Records:");
      for (EmployeeRecord rec : recordStore.getAllEmployees()) {
          System.out.printf(" - %s (%s) | %s | Dept: %s | Role: %s%n",
                  rec.getUsername(), rec.getEmployeeId(), rec.getFullName(),
                  rec.getDepartment(), rec.getRole());
      }
      System.exit(0);
  }
  ```
- **Why It Is a Problem:**
  The `--list` command-line option enumerates and prints all employee records in the system, exposing usernames, employee IDs, full names, departments, and roles without requiring authentication. Attackers can leverage this command to harvest valid usernames for targeted brute force/credential stuffing attacks, identify administrators, and map out internal organizational hierarchy.
- **Remediation:**
  Remove the public `--list` CLI command or require administrator authentication before displaying employee directories.

---

### Finding 10: Race Condition / TOCTOU in InMemoryEmployeeRecordStore Registration
- **Severity:** Low
- **CWE ID:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') (also CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition)
- **File & Line:** `EmployeeAuthenticationPortal.java:497-511`
- **Evidence:**
  ```java
  String normalizedUser = username.trim().toLowerCase();
  if (recordsByUsername.containsKey(normalizedUser)) {
      return false; // User already exists
  }

  byte[] salt = PasswordSecurity.generateSalt();
  String hash = PasswordSecurity.hashPassword(password, salt, PasswordSecurity.DEFAULT_ITERATIONS);

  EmployeeRecord record = new EmployeeRecord(
          empId, normalizedUser, fullName, dept, role, hash, salt,
          PasswordSecurity.DEFAULT_ITERATIONS, AccountStatus.ACTIVE
  );

  recordsByUsername.put(normalizedUser, record);
  recordsById.put(empId, record);
  ```
- **Why It Is a Problem:**
  In `InMemoryEmployeeRecordStore.register`, the existence check (`containsKey`) and insertion (`put`) are separate operations on `ConcurrentHashMap`. Under concurrent access with multiple threads registering the same username, both threads can pass the `containsKey` check, compute heavy PBKDF2 hashes, and the second `put` will overwrite the first. Furthermore, `recordsById` is not checked for collisions at all; a registration with an existing `empId` will silently overwrite an existing employee record in `recordsById`.
- **Remediation:**
  Use atomic operations such as `recordsByUsername.putIfAbsent(normalizedUser, record)` and `recordsById.putIfAbsent(empId, record)`. If either insertion fails, abort and clean up the record.

---

### Finding 11: Denial of Service via Dummy Hashing Resource Exhaustion & Account Griefing
- **Severity:** Low
- **CWE ID:** CWE-400: Uncontrolled Resource Consumption (also CWE-307: Improper Restriction of Excessive Authentication Attempts)
- **File & Line:** `EmployeeAuthenticationPortal.java:618-620`, `149-156`
- **Evidence:**
  *Dummy hash resource exhaustion (Line 618):*
  ```java
  if (optRecord.isEmpty()) {
      PasswordSecurity.performDummyHash(password);
  ```
  *Account lockout trigger (Line 149):*
  ```java
  public synchronized boolean recordFailedAttempt(int maxAttempts, Duration lockoutDuration, Instant now) {
      this.failedAttempts++;
      if (this.failedAttempts >= maxAttempts) {
          this.status = AccountStatus.LOCKED;
  ```
- **Why It Is a Problem:**
  1. **CPU Exhaustion via Dummy Hashing:** To prevent user enumeration timing attacks (CWE-204), the system computes 100,000 iterations of PBKDF2 for non-existent users. However, there is no IP-level or client-level rate limiting. An unauthenticated attacker can flood the portal with non-existent username authentication requests, forcing the server to consume 100% of CPU resources.
  2. **Account Lockout Griefing:** An attacker armed with the list of employee usernames (from `--list`) can submit 5 incorrect passwords for every valid account, causing mass account lockouts across the enterprise and disrupting business operations.
- **Remediation:**
  Implement global and IP-based rate limiting on the authentication endpoint (e.g., token bucket algorithm). Consider progressive delays (exponential backoff) rather than immediate total lockout, or require CAPTCHA/multi-factor authentication after initial failed attempts.

---

## 5. Security Controls Implemented Effectively

During the audit, several notable security defenses were identified that demonstrate sound cryptographic design:

1. **PBKDF2-HMAC-SHA256 Implementation:** Uses 100,000 iterations of PBKDF2 with HMAC-SHA256, aligning with established password storage guidelines.
2. **Cryptographically Secure Salt Generation:** Each user record generates a unique 128-bit salt using `java.security.SecureRandom`.
3. **Constant-Time Hash Comparison:** Verification utilizes `MessageDigest.isEqual` to prevent timing side-channel attacks (CWE-208).
4. **Log Injection Mitigation:** `AuditLogger` sanitizes user input by stripping carriage return (`\r`) and newline (`\n`) characters, preventing log forging/injection attacks.
5. **Memory Scrubbing Utility:** `PasswordSecurity` provides `wipe(char[])` and `wipe(byte[])` routines to overwrite sensitive buffers with null characters/zeros in `finally` blocks.

---

## 6. Recommendations & Remediation Roadmap

1. **Immediate (P0):**
   - Remove hardcoded credentials from `InMemoryEmployeeRecordStore.seedDefaultRecords()`.
   - Remove `displayDemoAccounts()` from `PortalUI`.
   - Enforce authentication on `handleAdminUnlock()` and `--unlock`.
   - Remove the plaintext password command-line parameter (`--login <user> <pass>`).

2. **Short-Term (P1):**
   - Restrict user registration to authenticated administrators.
   - Enforce strong password complexity policies.
   - Remove `--list` CLI enumeration or protect it with administrative authentication.
   - Implement session tracking, validation, and revocation for `PortalSession`.

3. **Medium-Term (P2):**
   - Replace `String` password parameters with `char[]` throughout all public and internal APIs to prevent heap memory residency.
   - Add rate limiting and exponential backoff to mitigate CPU exhaustion attacks and account lockout griefing.
   - Ensure atomic registration checks in `InMemoryEmployeeRecordStore` using `putIfAbsent`.
