# Security Vulnerability Review Report

**Target Directory:** `/data/results-cyber/agy/set_a/pilot/5/security`  
**Date:** September 9, 2026  
**Auditor:** Automated Code Security Review Agent  
**Review Standard:** OWASP Top 10 (2021), OWASP API Security Top 10 (2023), CWE / SANS Top 25  

---

## 1. Executive Summary

A comprehensive source code security assessment was conducted on the software artifacts in this directory. The codebase implements an internal employee authentication system (`EmployeeAuthenticationPortal.java`) designed to authenticate employees, enforce account lockout against brute-force attacks, maintain audit logs, and provide an interactive terminal interface alongside a command-line interface.

While the core cryptographic verification logic correctly incorporates modern practices (PBKDF2-HMAC-SHA256 with 100,000 iterations, 128-bit cryptographically secure salts, and constant-time hash comparisons), significant security vulnerabilities were identified in the surrounding application architecture. Most critically:
- **Administrative authorization can be completely bypassed**, allowing any unauthenticated user to unlock any locked account through both the CLI and interactive menu.
- **Hardcoded credentials for all users (including the system administrator) are stored in plaintext in the source code** and can be viewed on demand via an unauthenticated UI menu option.
- **User enumeration and timing side-channels** exist due to discrepant error messages, exposed retry counters, and short-circuit evaluation when accounts are locked.
- **Denial of Service (DoS)** vectors exist via deliberate account lockouts and unbounded in-memory audit log accumulation.
- **Credentials are exposed via process arguments and immutable Java strings**.

---

## 2. Codebase Overview

Each file in the reviewed directory was analyzed to understand its purpose and security-relevant behaviors:

1. **`EmployeeAuthenticationPortal.java`** (1,087 lines):
   - **Purpose:** Primary application implementing the employee authentication portal, containing domain models (`EmployeeRecord`, `PortalSession`, `AuthenticationResult`), cryptographic utilities (`PasswordSecurity`), data storage (`InMemoryEmployeeRecordStore`), business logic (`AuthenticationService`), interactive console UI (`PortalUI`), and an automated self-test runner (`SelfTestRunner`).
   - **Security-Relevant Behaviors:** Credential hashing and verification, rate limiting / lockout counter tracking, administrative account unlocking, audit logging, interactive menu handling, and CLI argument processing.

2. **`run-tests.sh`** (12 lines):
   - **Purpose:** Shell execution script to compile `EmployeeAuthenticationPortal.java` using `javac` and run its internal test suite using `java EmployeeAuthenticationPortal --test`.
   - **Security-Relevant Behaviors:** Local build and process invocation. Reviewed; no direct vulnerabilities identified in the script itself.

3. **`prompt.txt` / `cyber_prompt.txt` / `result.md` / `return.txt` / `prompt_hash.txt`**:
   - **Purpose:** Metadata, prompts, and run history tracking files from preceding test workflows. Reviewed; contain documentation and test inputs.

---

## 3. Skills Applied

In accordance with the code review workflow, specialized application security skills from the library were matched to the security-relevant behaviors identified in the codebase and systematically applied:

1. **`testing-for-broken-access-control`** (OWASP A01:2021)
   - Evaluated administrative unlock functions, function-level authorization checks, and access restrictions across UI and CLI commands.
2. **`testing-api-authentication-weaknesses`** (OWASP API2:2023 / A07:2021)
   - Evaluated authentication flows, session generation and lifecycle management, token revocation, and user enumeration resistance.
3. **`testing-for-sensitive-data-exposure`** (OWASP A02:2021)
   - Evaluated hardcoded secrets, credential logging, UI data leakage, process memory scrubbing, and command-line argument exposures.
4. **`performing-cryptographic-audit-of-application`**
   - Evaluated key derivation function (KDF) parameters, iteration counts, salt generation randomness, cipher comparisons, and memory wiping routines.
5. **`testing-for-business-logic-vulnerabilities`** (OWASP A04:2021)
   - Evaluated account lockout mechanics, multi-step unlock workflows, rate-limiting bypass paths, and lockout-induced Denial of Service conditions.
6. **General OWASP Top 10 / CWE Knowledge**
   - Applied to evaluate unbounded memory resource consumption (CWE-770 / CWE-400) and mutable object reference leakage (CWE-375 / CWE-495) where no narrow specialized skill exists.

---

## 4. Summary of Findings

| ID | Title | Severity | CWE ID | File:Line |
|---|---|---|---|---|
| **SEC-01** | Hardcoded Credentials & Plaintext Password Exposure in UI | **Critical** | CWE-798, CWE-200 | `EmployeeAuthenticationPortal.java:436-444`, `775-781` |
| **SEC-02** | Missing Authentication & Authorization on Account Unlock | **Critical** | CWE-306, CWE-862 | `EmployeeAuthenticationPortal.java:791`, `1053` |
| **SEC-03** | Credential Exposure via Process Command-Line Arguments | **High** | CWE-214, CWE-532 | `EmployeeAuthenticationPortal.java:1027-1031` |
| **SEC-04** | User Enumeration via Observable Discrepancy & Lockout Timing | **High** | CWE-204, CWE-208 | `EmployeeAuthenticationPortal.java:559-560`, `566-580`, `610-613` |
| **SEC-05** | Denial of Service via Intentional Account Lockout | **Medium** | CWE-645, CWE-400 | `EmployeeAuthenticationPortal.java:592-603` |
| **SEC-06** | Missing Authentication for Security Audit Log Access | **Medium** | CWE-306, CWE-200 | `EmployeeAuthenticationPortal.java:713`, `800-807` |
| **SEC-07** | Broken Session Management & Lack of Revocation/Tracking | **Medium** | CWE-613, CWE-384 | `EmployeeAuthenticationPortal.java:181-210`, `618` |
| **SEC-08** | Unbounded In-Memory Audit Log Allocation (Heap Exhaustion DoS) | **Medium** | CWE-770, CWE-400 | `EmployeeAuthenticationPortal.java:377`, `396` |
| **SEC-09** | Sensitive Credential Retention in Immutable Heap Strings | **Low** | CWE-244, CWE-316 | `EmployeeAuthenticationPortal.java:448`, `634`, `739`, `1030` |
| **SEC-10** | Mutable Internal Record References Leaked via Store Method | **Low** | CWE-375, CWE-495 | `EmployeeAuthenticationPortal.java:484-486` |

---

## 5. Detailed Findings

---

### SEC-01: Hardcoded Credentials & Plaintext Password Exposure in UI
- **Severity:** **Critical**
- **CWE ID:** [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html), [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- **Affected File & Lines:**
  - `EmployeeAuthenticationPortal.java:436-444` (seedDefaultRecords)
  - `EmployeeAuthenticationPortal.java:775-781` (displayTestAccounts)
- **Description:**  
  The system hardcodes valid default production-style accounts in `seedDefaultRecords()`, including employee accounts and an administrator account (`EMP-0001`, username `admin`, password `PortalAdmin@2026!`). Furthermore, in `PortalUI.displayTestAccounts()` (lines 767-784), selecting Option 2 from the main menu prints all employee usernames and their plaintext passwords directly to standard output without requiring any authentication.
- **Security Impact:**  
  Any unauthorized individual running the portal or viewing the source code/binary can immediately compromise all accounts, including full administrative access, leading to complete system compromise.
- **Remediation:**  
  1. Remove hardcoded plaintext passwords from the source code.
  2. Bootstrap initial administrative credentials securely from external environment variables or a secrets manager upon first setup.
  3. Delete the `displayTestAccounts()` method from the production UI, or ensure passwords are never displayed.

---

### SEC-02: Missing Authentication & Authorization on Administrative Account Unlock
- **Severity:** **Critical**
- **CWE ID:** [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html), [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)
- **Affected File & Lines:**
  - `EmployeeAuthenticationPortal.java:791` (handleAdminUnlock)
  - `EmployeeAuthenticationPortal.java:1053` (CLI --unlock handler)
- **Description:**  
  The account unlock capability is designed to be an administrative function (`AuthenticationService.unlockAccount` checks that the caller has role `ADMIN`). However:
  1. In `PortalUI.handleAdminUnlock()` (lines 785-797), Option 3 in the interactive menu allows any unauthenticated user to unlock any account by entering a username. Line 791 hardcodes `"admin"` as the caller (`authService.unlockAccount("admin", target.trim())`), spoofing administrator privileges and completely bypassing the role check.
  2. In `main()` CLI options (lines 1050-1065), running `java EmployeeAuthenticationPortal --unlock <username>` directly calls `recordStore.unlockAccount(target)` without performing any authentication or authorization checks.
- **Security Impact:**  
  Any attacker can unlock any account at will without credentials, completely nullifying the brute-force and lockout protection (CWE-307). Attackers can brute-force an account indefinitely by repeatedly unlocking it after every 5 failed attempts.
- **Remediation:**  
  1. Require an active, authenticated administrator session before granting access to account unlocking functionality.
  2. In `handleAdminUnlock()`, extract the admin username from the authenticated session context rather than hardcoding `"admin"`.
  3. In the CLI entry point, require administrator authentication (e.g., prompting for admin credentials) prior to invoking `unlockAccount`.

---

### SEC-03: Credential Exposure via Process Command-Line Arguments
- **Severity:** **High**
- **CWE ID:** [CWE-214: Invocation of Process Initializer with Untrusted/Sensitive Data](https://cwe.mitre.org/data/definitions/214.html), [CWE-532: Insertion of Sensitive Information into Log File or Process Environment](https://cwe.mitre.org/data/definitions/532.html)
- **Affected File & Lines:**
  - `EmployeeAuthenticationPortal.java:1027-1031` (CLI --login handler)
- **Description:**  
  The application supports command-line authentication via `java EmployeeAuthenticationPortal --login <username> <password>`. Line 1030 captures the password directly from `args[2]`. On multi-user operating systems (such as Linux), process arguments are visible in the global process table (via `/proc/<PID>/cmdline` or tools like `ps aux`, `htop`). Furthermore, arguments executed in interactive shells are written in cleartext to shell history files (`~/.bash_history`, `~/.zsh_history`) and logged by system monitoring daemons (such as `auditd`).
- **Security Impact:**  
  Local unprivileged users or processes running on the same host can harvest plaintext user passwords.
- **Remediation:**  
  Disallow passing passwords directly as command-line arguments. Prompt for the password interactively via `System.console().readPassword()` or accept it via standard input (`stdin`).

---

### SEC-04: User Enumeration via Observable Discrepancy & Lockout Timing
- **Severity:** **High**
- **CWE ID:** [CWE-204: Observable Response Discrepancy](https://cwe.mitre.org/data/definitions/204.html), [CWE-208: Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html)
- **Affected File & Lines:**
  - `EmployeeAuthenticationPortal.java:559-560` (non-existent user response)
  - `EmployeeAuthenticationPortal.java:566-580` (locked account short-circuit)
  - `EmployeeAuthenticationPortal.java:610-613` (existing user incorrect password response)
- **Description:**  
  Although `PasswordSecurity.performDummyHash()` was introduced to prevent timing-based user enumeration, the implementation contains multiple discrepancies that expose whether a username is registered:
  1. **Short-circuit timing on locked accounts:** When an existing user account is locked, line 566 checks `record.isLocked(now)` and immediately returns without computing PBKDF2 (~100ms calculation). An attacker can distinguish a locked account (<1ms response) from a non-existent account (~100ms response).
  2. **Status code discrepancy:** Locked accounts return `AuthStatus.ACCOUNT_LOCKED` (line 579), whereas non-existent accounts return `AuthStatus.INVALID_CREDENTIALS` (line 559).
  3. **Message and counter discrepancy:** For a non-existent user, `remainingAttempts` is `-1` and the message is `"Access denied: Invalid username or password."`. For an existing unlocked user, `remainingAttempts` returns the remaining count (e.g. `4`), and the message reveals: `"Access denied: Invalid username or password. Remaining attempts before lockout: 4"`.
- **Security Impact:**  
  Attackers can reliably enumerate all valid employee usernames in the organization by observing either the response status, message text, remaining attempts count, or latency.
- **Remediation:**  
  1. Return identical, generic error messages (e.g., `"Invalid username or password"`) and identical status codes across all failure scenarios (invalid username, bad password, locked account).
  2. Do not return the remaining attempt counter to unauthenticated clients.
  3. Compute a dummy PBKDF2 hash even when an account is locked before returning the rejection, ensuring uniform response latency.

---

### SEC-05: Denial of Service via Intentional Account Lockout
- **Severity:** **Medium**
- **CWE ID:** [CWE-645: Overly Restrictive Account Lockout](https://cwe.mitre.org/data/definitions/645.html), [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- **Affected File & Lines:**
  - `EmployeeAuthenticationPortal.java:592-603` (recordFailedAttempt and lockout trigger)
- **Description:**  
  The system unconditionally locks an account for 15 minutes after 5 consecutive failed attempts (`DEFAULT_MAX_CONSECUTIVE_ATTEMPTS = 5`), rejecting all subsequent authentication attempts even when the correct password is supplied. Because authentication requires no rate limiting per IP, CAPTCHA, or source verification, an unauthenticated attacker can submit 5 incorrect attempts for known accounts (or all employees in bulk).
- **Security Impact:**  
  An attacker can launch a sustained Denial of Service against all portal users, locking executives, security leads, and administrators out of critical systems.
- **Remediation:**  
  1. Implement IP-based rate limiting or progressive delays (exponential backoff) rather than permanent account lockouts.
  2. Require CAPTCHA challenges after multiple failed attempts.
  3. Implement lockout rules per client IP address rather than locking the global employee account.

---

### SEC-06: Missing Authentication for Security Audit Log Access
- **Severity:** **Medium**
- **CWE ID:** [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html), [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- **Affected File & Lines:**
  - `EmployeeAuthenticationPortal.java:713` (Menu option 5)
  - `EmployeeAuthenticationPortal.java:800-807` (displayAuditLogs)
- **Description:**  
  Option 5 in the interactive console menu ("View Recent Audit Logs") invokes `displayAuditLogs()`, which calls `authService.getAuditLogger().getRecentEntries(10)` without requiring authentication or authorization.
- **Security Impact:**  
  Unauthenticated operators can inspect audit logs revealing usernames, full employee names, departments, roles, timestamps of access, and authentication failure patterns, facilitating targeted social engineering and reconnaissance.
- **Remediation:**  
  Require administrator authentication before permitting any audit log viewing or inspection.

---

### SEC-07: Broken Session Management & Lack of Revocation/Tracking
- **Severity:** **Medium**
- **CWE ID:** [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html), [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
- **Affected File & Lines:**
  - `EmployeeAuthenticationPortal.java:181-210` (PortalSession)
  - `EmployeeAuthenticationPortal.java:618` (PortalSession creation)
- **Description:**  
  When an employee authenticates successfully, line 618 creates a `PortalSession` with a UUID identifier and an 8-hour expiry. However:
  1. The session is never recorded in any server-side session registry.
  2. The application provides no mechanism to validate session tokens on subsequent requests.
  3. There is no logout endpoint or mechanism to revoke active sessions upon password reset, account lockout, or user termination.
- **Security Impact:**  
  Because sessions cannot be validated, tracked, or revoked, the application cannot enforce authenticated access on subsequent requests or invalidate compromised session tokens.
- **Remediation:**  
  Implement a central session store (e.g. a thread-safe map or distributed cache) that associates session IDs with user identities, validates session tokens on every authenticated request, and provides an explicit revocation/logout method.

---

### SEC-08: Unbounded In-Memory Audit Log Allocation (Heap Exhaustion DoS)
- **Severity:** **Medium**
- **CWE ID:** [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html), [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- **Affected File & Lines:**
  - `EmployeeAuthenticationPortal.java:377` (memoryLog declaration)
  - `EmployeeAuthenticationPortal.java:396` (memoryLog.add)
- **Description:**  
  The `AuditLogger` stores every logged event in an unbounded `ArrayList`:
  `private final List<String> memoryLog = Collections.synchronizedList(new ArrayList<>());`
  Every call to `log()` appends an entry to this list without any maximum size limit, eviction policy, or memory bounds.
- **Security Impact:**  
  An attacker executing a flood of authentication requests can continuously grow `memoryLog` until JVM heap space is exhausted, triggering an `OutOfMemoryError` and crashing the application.
- **Remediation:**  
  Replace the unbounded list with a bounded circular buffer (e.g., maintaining the last 1,000 entries) or stream audit records to standard logging frameworks (e.g., Logback/SLF4J) with file-based rotation.

---

### SEC-09: Sensitive Credential Retention in Immutable Heap Strings
- **Severity:** **Low**
- **CWE ID:** [CWE-244: Improper Clearing of Heap Memory Containing Sensitive Data](https://cwe.mitre.org/data/definitions/244.html), [CWE-316: Cleartext Storage of Sensitive Information in Memory](https://cwe.mitre.org/data/definitions/316.html)
- **Affected File & Lines:**
  - `EmployeeAuthenticationPortal.java:448` (register method String argument)
  - `EmployeeAuthenticationPortal.java:634-639` (authenticate String wrapper)
  - `EmployeeAuthenticationPortal.java:739` (readLine fallback in handleLoginPrompt)
  - `EmployeeAuthenticationPortal.java:1030` (args[2] in main)
- **Description:**  
  Although `PasswordSecurity.wipe(char[])` is implemented to scrub credentials from memory, several APIs handle passwords as `java.lang.String` objects:
  - `register(..., String plainPassword)`
  - `authenticate(String username, String password)`
  - `PortalUI.handleLoginPrompt()` fallback: `String p = readLine(); password = p.toCharArray();`
  - `args[2]` in `main()` CLI login
  In Java, `String` instances are immutable and cannot be overwritten; they remain in heap memory until garbage collected, where they can be inspected in core dumps or memory dumps.
- **Security Impact:**  
  Residual cleartext passwords can be recovered from application process memory dumps.
- **Remediation:**  
  Eliminate methods that accept passwords as `String`. In the console UI, read passwords directly into `char[]` using `System.console().readPassword()` or character array streams, and wipe the buffer immediately after use using `Arrays.fill(buffer, '\0')`.

---

### SEC-10: Mutable Internal Record References Leaked via Store Method
- **Severity:** **Low**
- **CWE ID:** [CWE-375: Returning a Mutable Object to an Untrusted Caller](https://cwe.mitre.org/data/definitions/375.html), [CWE-495: Private Data Structure Returned From a Public Method](https://cwe.mitre.org/data/definitions/495.html)
- **Affected File & Lines:**
  - `EmployeeAuthenticationPortal.java:484-486` (getAllEmployees)
- **Description:**  
  `InMemoryEmployeeRecordStore.getAllEmployees()` returns `new ArrayList<>(records.values())`. While the containing list is a new copy, the elements are direct references to the mutable `EmployeeRecord` objects stored in the backing map. Callers can mutate user status or invoke `unlock()` directly on these references.
- **Security Impact:**  
  Internal encapsulation is weakened; any consuming code can bypass `AuthenticationService` checks and directly alter employee security states.
- **Remediation:**  
  Return immutable record representations or Data Transfer Objects (DTOs) from store query methods.

---

## 6. Positive Security Controls Identified

During the audit, several security mechanisms were verified to adhere to industry best practices:
- **Strong Key Derivation:** Implemented using `PBKDF2WithHmacSHA256` with 100,000 iterations and a 256-bit derived key length, complying with NIST SP 800-63B guidelines.
- **Cryptographic Randomness:** Per-user 128-bit salts are generated using `java.security.SecureRandom`.
- **Constant-Time Comparison:** Password hash verification utilizes `MessageDigest.isEqual()` to mitigate byte-by-byte timing attacks (CWE-208).
- **Log Sanitization:** `AuditLogger` sanitizes CRLF characters (`\r`, `\n`) from inputs to mitigate log injection (CWE-117).
