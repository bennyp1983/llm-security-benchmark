# Security Review: Enterprise Administrator Portal

## 1. Executive Summary
A comprehensive security review was performed on the Enterprise Administrator Portal codebase located in this directory. The application is a standalone Java console system providing an administrative gateway, Role-Based Access Control (RBAC), user provisioning and account management, system telemetry, security diagnostics, and an append-only audit logging subsystem (`audit.log`).

The audit revealed multiple security vulnerabilities across authentication, authorization, cryptographic lifecycle management, and log integrity. Most critically, the source code contains hardcoded credentials for pre-seeded demonstration accounts including a super administrator, and the administration control panel fails to enforce function-level authorization, allowing lower-privileged administrative roles such as `SECURITY_AUDITOR` to create, modify, reset, and delete administrative accounts. Additionally, user enumeration is possible due to response message discrepancy despite timing attack mitigations, unauthenticated attackers can trigger administrative Denial of Service via account lockout, and log delimiter injection allows audit log corruption. Remediation guidance and corrected code blocks are provided for each finding.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `AdminPortal.java` | Main application source code containing the gateway, RBAC definitions, authentication service, dashboard, and audit logger. | Password hashing (`PBKDF2WithHmacSHA256`), credential verification, account lockout, in-memory credential clearing, RBAC authorization, user management, audit logging, and audit file parsing/export. |
| `README.md` | System documentation and operational manual. | References pre-seeded credentials, RBAC specifications, and security claims. |
| `audit.log` | Append-only text file storing security audit records. | Contains security audit records written by `AuditLogger` and parsed by `AuditRecord.fromLogLine`. |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to audit PBKDF2 key derivation parameters (iterations, salt generation with `SecureRandom`, key size), constant-time hash comparisons (`MessageDigest.isEqual`), in-memory key/password clearing, and hardcoded secret detection.
- `testing-for-broken-access-control`: Applied to evaluate Role-Based Access Control (RBAC) boundaries, vertical and horizontal privilege escalation, and function-level access control across `SUPER_ADMIN`, `ADMIN`, `SECURITY_AUDITOR`, and `STANDARD_USER`.
- `implementing-secret-scanning-with-gitleaks`: Applied to search for hardcoded credentials, pre-seeded demonstration passwords, and static keys in source code and documentation.
- General OWASP Top 10 / CWE knowledge was applied to:
  - User enumeration through observable response discrepancies (CWE-204 / OWASP A07:2021 Identification and Authentication Failures).
  - Denial of Service through unthrottled account lockout mechanisms (CWE-307 / CWE-400).
  - Log delimiter injection and log parsing integrity in `AuditLogger` (CWE-117 / CWE-93).
  - File permissions on audit logs and report exports (CWE-732 / OWASP A05:2021 Security Misconfiguration).
  - In-memory credential lifecycle in non-interactive console mode (CWE-244 / CWE-316).
  - Internal mutable state exposure in entity models (CWE-495 / CWE-374).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Hard-Coded Administrative Credentials in Source Code and Startup Banner | High | CWE-798 | `AdminPortal.java:868-887` |
| SEC-02 | Broken Access Control via Missing Function-Level Authorization in Admin Dashboard | High | CWE-862 | `AdminPortal.java:292-313` |
| SEC-03 | User Enumeration via Observable Discrepancy in Authentication Error Responses | Medium | CWE-204 | `AdminPortal.java:208-213` |
| SEC-04 | Account Lockout Denial of Service on Administrator Accounts | Medium | CWE-307 | `AdminPortal.java:926-934` |
| SEC-05 | Audit Trail Delimiter Injection Leading to Log Parsing Corruption | Medium | CWE-117 | `AdminPortal.java:1288-1293` |
| SEC-06 | Insecure File Permissions on Audit Log and Exported Forensic Reports | Medium | CWE-732 | `AdminPortal.java:827` |
| SEC-07 | Direct Exposure of Mutable Internal State for Password Hashes and Salts | Low | CWE-495 | `AdminPortal.java:1024-1025` |
| SEC-08 | Incomplete Memory Scrubbing via Immutable String in Non-Interactive Console Fallback | Low | CWE-244 | `AdminPortal.java:237-239` |

## 5. Detailed Findings

### SEC-01: Hard-Coded Administrative Credentials in Source Code and Startup Banner
- **Severity:** High
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Location:** `AdminPortal.java:868-887`

**Vulnerable code:**
```java
// AdminPortal.java:868-887
        private void seedDefaultAccounts() {
            // Pre-seed Super Administrator
            byte[] salt1 = PasswordSecurity.generateSalt();
            byte[] hash1 = PasswordSecurity.hashPassword("Admin@Secure2026!".toCharArray(), salt1);
            users.put("admin", new UserAccount("admin", hash1, salt1, Role.SUPER_ADMIN));

            // Pre-seed Security Administrator
            byte[] salt2 = PasswordSecurity.generateSalt();
            byte[] hash2 = PasswordSecurity.hashPassword("SecOps#Secure2026!".toCharArray(), salt2);
            users.put("secops", new UserAccount("secops", hash2, salt2, Role.ADMIN));

            // Pre-seed Security Auditor
            byte[] salt3 = PasswordSecurity.generateSalt();
            byte[] hash3 = PasswordSecurity.hashPassword("Audit#Secure2026!".toCharArray(), salt3);
            users.put("auditor", new UserAccount("auditor", hash3, salt3, Role.SECURITY_AUDITOR));

            // Pre-seed Standard User (Demonstrates non-admin RBAC rejection)
            byte[] salt4 = PasswordSecurity.generateSalt();
            byte[] hash4 = PasswordSecurity.hashPassword("UserPass@2026!".toCharArray(), salt4);
            users.put("johndoe", new UserAccount("johndoe", hash4, salt4, Role.STANDARD_USER));
        }
```

**Why it is a problem:** The application seeds pre-configured accounts with plaintext passwords directly in the source code (`Admin@Secure2026!`, `SecOps#Secure2026!`, `Audit#Secure2026!`, `UserPass@2026!`) and advertises them in the gateway startup banner (`printBanner()` lines 136-139). Anyone with access to the source code, repository history, compiled bytecode, or console output gains full administrative control over the portal.

**Fix:** Remove hardcoded credentials from the source code and banner. Default accounts should either be provisioned dynamically on first run via an interactive setup prompt requiring the administrator to define a secure initial password, or loaded from an external, securely encrypted configuration/secrets store.
```java
        private void seedDefaultAccounts() {
            // In production, load existing accounts from a persistent secure store or trigger initial setup wizard.
            String initialAdminPass = System.getenv("PORTAL_INITIAL_ADMIN_PASSWORD");
            if (initialAdminPass != null && !initialAdminPass.isEmpty()) {
                char[] passChars = initialAdminPass.toCharArray();
                byte[] salt = PasswordSecurity.generateSalt();
                byte[] hash = PasswordSecurity.hashPassword(passChars, salt);
                users.put("admin", new UserAccount("admin", hash, salt, Role.SUPER_ADMIN));
                PasswordSecurity.clearPassword(passChars);
            }
        }
```

---

### SEC-02: Broken Access Control via Missing Function-Level Authorization in Admin Dashboard
- **Severity:** High
- **CWE:** CWE-862: Missing Authorization
- **Location:** `AdminPortal.java:292-313`

**Vulnerable code:**
```java
// AdminPortal.java:292-313
                switch (input.trim()) {
                    case "1":
                        showSystemTelemetry();
                        break;
                    case "2":
                        reviewAuditLogs();
                        break;
                    case "3":
                        manageUsers();
                        break;
                    case "4":
                        runSecurityDiagnostics();
                        break;
                    case "5":
                        manageMaintenanceAndConfig();
                        break;
                    case "6":
                        changeAdminPassword();
                        break;
                    case "7":
                        exportAuditReport();
                        break;
                    case "8":
                        inSession = false;
                        auditLogger.logEvent(AuditEventType.LOGOUT, currentUser.getUsername(),
                                "CLI-Local", "SUCCESS", "Administrator session ended normally");
                        System.out.println("\n[+] Logged out successfully. Returning to main gateway.");
                        break;
                    default:
                        System.out.println("[!] Invalid selection. Please enter a number between 1 and 8.");
                }
```

**Why it is a problem:** While `Role` defines specific privilege boundaries (e.g. `SECURITY_AUDITOR` is documented as "Read-only access to audit logs and security telemetry"), `AdminDashboard.launch()` only checks whether `role.isAdmin()` was true at login. Once inside the dashboard, all administrative roles are granted access to all menu options. An auditor or regular administrator can access Option 3 (`manageUsers()`) to create new `SUPER_ADMIN` accounts, reset any user's password, delete accounts, or access Option 5 to toggle system maintenance mode. This represents vertical privilege escalation due to missing function-level authorization checks.

**Fix:** Enforce role-based permission checks prior to invoking privileged operations within the dashboard and submenus. Restrict user management to `SUPER_ADMIN` and system maintenance to `SUPER_ADMIN`/`ADMIN`.
```java
                switch (input.trim()) {
                    case "1":
                        showSystemTelemetry();
                        break;
                    case "2":
                        reviewAuditLogs();
                        break;
                    case "3":
                        if (currentUser.getRole() == Role.SUPER_ADMIN) {
                            manageUsers();
                        } else {
                            System.out.println("[!] Access Denied: User account management requires SUPER_ADMIN privileges.");
                            auditLogger.logEvent(AuditEventType.ADMIN_ACTION, currentUser.getUsername(),
                                    "CLI-Local", "DENIED", "Unauthorized attempt to access User Account Management");
                        }
                        break;
                    case "4":
                        runSecurityDiagnostics();
                        break;
                    case "5":
                        if (currentUser.getRole() == Role.SUPER_ADMIN || currentUser.getRole() == Role.ADMIN) {
                            manageMaintenanceAndConfig();
                        } else {
                            System.out.println("[!] Access Denied: System maintenance requires SUPER_ADMIN or ADMIN privileges.");
                        }
                        break;
                    case "6":
                        changeAdminPassword();
                        break;
                    case "7":
                        exportAuditReport();
                        break;
                    case "8":
                        inSession = false;
                        auditLogger.logEvent(AuditEventType.LOGOUT, currentUser.getUsername(),
                                "CLI-Local", "SUCCESS", "Administrator session ended normally");
                        System.out.println("\n[+] Logged out successfully. Returning to main gateway.");
                        break;
                    default:
                        System.out.println("[!] Invalid selection. Please enter a number between 1 and 8.");
                }
```

---

### SEC-03: User Enumeration via Observable Discrepancy in Authentication Error Responses
- **Severity:** Medium
- **CWE:** CWE-204: Observable Response Discrepancy
- **Location:** `AdminPortal.java:208-213`

**Vulnerable code:**
```java
// AdminPortal.java:208-213
            } else {
                System.out.println("\n[-] ACCESS DENIED: Invalid username or password.");
                if (result.getMessage() != null && result.getMessage().contains("Warning")) {
                    System.out.println("    " + result.getMessage());
                }
            }
```

**Why it is a problem:** The developer implemented a dummy hash computation to mitigate timing-based user enumeration (lines 895-896). However, `AuthenticationService.authenticate()` returns `"Invalid username or password."` when an unknown user is queried (line 899), but returns `"Warning: <N> login attempt(s) remaining before account lockout."` when a valid user is queried with an invalid password (line 939). In `handleLogin()`, the warning message is printed only when `getMessage().contains("Warning")`. Consequently, an unauthenticated attacker can determine whether a username exists on the system simply by observing whether the warning line is printed.

**Fix:** Return identical, generic error messages for all failed authentication attempts regardless of whether the username exists in the user database. Log account lockout warnings to the internal audit trail rather than displaying them to the client.
```java
            } else {
                System.out.println("\n[-] ACCESS DENIED: Invalid username or password.");
            }
```

---

### SEC-04: Account Lockout Denial of Service on Administrator Accounts
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `AdminPortal.java:926-934`

**Vulnerable code:**
```java
// AdminPortal.java:926-934
            if (!match) {
                int attempts = account.incrementFailedAttempts();
                if (attempts >= MAX_FAILED_ATTEMPTS) {
                    account.setLocked(true);
                    account.setLockoutTime(System.currentTimeMillis());
                    auditLogger.logEvent(AuditEventType.AUTH_LOCKOUT, username, source, "LOCKED",
                            "Account locked after reaching " + attempts + " consecutive failed attempts");
                    return new AuthResult(AuthStatus.ACCOUNT_LOCKED,
                            "Warning: Account is now LOCKED due to " + attempts + " consecutive failed attempts.", null);
                } else {
```

**Why it is a problem:** The lockout mechanism locks any user account after 5 consecutive failed attempts, enforcing a 15-minute cooldown (`LOCKOUT_DURATION_MS = 15 * 60 * 1000`). Because there is no IP-based rate limiting, CAPTCHA, or lockout exemption for primary administrative accounts, an unauthenticated attacker can intentionally fail authentication 5 times for every known administrator username (`admin`, `secops`, `auditor`), rendering all administrative functions inaccessible for 15 minutes and causing a Denial of Service.

**Fix:** Implement rate limiting (such as exponential backoff or IP-based throttling) rather than locking out administrative accounts completely, or exempt designated break-glass super administrator accounts from automatic lockout while alerting on suspicious activity.
```java
            if (!match) {
                int attempts = account.incrementFailedAttempts();
                // Prevent denial of service on SUPER_ADMIN accounts via lockout
                if (attempts >= MAX_FAILED_ATTEMPTS && account.getRole() != Role.SUPER_ADMIN) {
                    account.setLocked(true);
                    account.setLockoutTime(System.currentTimeMillis());
                    auditLogger.logEvent(AuditEventType.AUTH_LOCKOUT, username, source, "LOCKED",
                            "Account locked after reaching " + attempts + " consecutive failed attempts");
                    return new AuthResult(AuthStatus.ACCOUNT_LOCKED,
                            "Warning: Account is now LOCKED due to excessive failed attempts.", null);
                } else {
                    if (attempts >= MAX_FAILED_ATTEMPTS) {
                        auditLogger.logEvent(AuditEventType.AUTH_FAILURE, username, source, "FAILED",
                                "Excessive failed logins on privileged account: " + username);
                    }
```

---

### SEC-05: Audit Trail Delimiter Injection Leading to Log Parsing Corruption
- **Severity:** Medium
- **CWE:** CWE-117: Improper Output Handling for Logs
- **Location:** `AdminPortal.java:1288-1293`

**Vulnerable code:**
```java
// AdminPortal.java:1288-1293
        private String sanitize(String input) {
            if (input == null) return "N/A";
            return input.replaceAll("[\r\n]", "_")
                        .replaceAll("[\t]", " ")
                        .replaceAll("[\\p{Cntrl}]", "");
        }
```

**Why it is a problem:** The audit trail uses `" | "` as a record delimiter (`toLogLine()` line 1176: `User: %s | Source: %s | Status: %s | Details: %s`). The `sanitize()` method only replaces CRLF and control characters. Because `handleLogin()` does not restrict characters entered into the username field, an attacker can input a username containing pipe characters or forged field prefixes (e.g. `test | Status: SUCCESS | Details: Forged`). When parsed back by `AuditRecord.fromLogLine()` using `split(" \\| ")`, this causes field misalignment and corrupted audit parsing.

**Fix:** Sanitize pipe (`|`) and bracket (`[`, `]`) characters in `sanitize()`, or use a structured log format such as JSON or standard CSV with escaping.
```java
        private String sanitize(String input) {
            if (input == null) return "N/A";
            return input.replaceAll("[\r\n]", "_")
                        .replaceAll("[\t]", " ")
                        .replaceAll("[|]", "/")
                        .replaceAll("[\\[\\]]", "")
                        .replaceAll("[\\p{Cntrl}]", "");
        }
```

---

### SEC-06: Insecure File Permissions on Audit Log and Exported Forensic Reports
- **Severity:** Medium
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `AdminPortal.java:827`

**Vulnerable code:**
```java
// AdminPortal.java:827
                try (PrintWriter writer = new PrintWriter(new FileWriter(exportFileName, StandardCharsets.UTF_8))) {
```

**Why it is a problem:** Both `exportAuditReport()` (line 827) and `AuditLogger.logEvent()` (line 1242) instantiate files via standard `FileWriter` and `FileOutputStream`. On POSIX operating systems, files created without explicit permission attributes inherit the process umask (typically `0644` or `0664`), making security logs and exported forensic reports containing user audit trails readable by any unprivileged local user or process on the system.

**Fix:** Use Java NIO `Files.newBufferedWriter` or `Files.createFile` with POSIX file permissions restricting access to the owner only (`0600`).
```java
                java.nio.file.Path exportPath = Paths.get(exportFileName);
                java.nio.file.attribute.FileAttribute<?>[] attrs = new java.nio.file.attribute.FileAttribute<?>[0];
                if (java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                    attrs = new java.nio.file.attribute.FileAttribute<?>[]{
                            java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"))
                    };
                }
                try (BufferedWriter bw = Files.newBufferedWriter(exportPath, StandardCharsets.UTF_8,
                        java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.WRITE);
                     PrintWriter writer = new PrintWriter(bw)) {
```

---

### SEC-07: Direct Exposure of Mutable Internal State for Password Hashes and Salts
- **Severity:** Low
- **CWE:** CWE-495: Private Data Structure Returned From A Public Method
- **Location:** `AdminPortal.java:1024-1025`

**Vulnerable code:**
```java
// AdminPortal.java:1024-1025
        public synchronized byte[] getPasswordHash() { return passwordHash; }
        public synchronized byte[] getPasswordSalt() { return passwordSalt; }
```

**Why it is a problem:** `getPasswordHash()` and `getPasswordSalt()` return direct references to private internal `byte[]` arrays. Because arrays in Java are mutable, external code holding a reference to a `UserAccount` object can directly modify or zero out array contents without calling `setPassword()`, breaking encapsulation and risking memory corruption of stored cryptographic hashes.

**Fix:** Return defensive clones of the byte arrays from getters, and clone incoming arrays in constructors and setters.
```java
        public synchronized byte[] getPasswordHash() {
            return passwordHash != null ? passwordHash.clone() : null;
        }
        public synchronized byte[] getPasswordSalt() {
            return passwordSalt != null ? passwordSalt.clone() : null;
        }
```

---

### SEC-08: Incomplete Memory Scrubbing via Immutable String in Non-Interactive Console Fallback
- **Severity:** Low
- **CWE:** CWE-244: Improper Clearing of Heap Memory Containing Sensitive Data
- **Location:** `AdminPortal.java:237-239`

**Vulnerable code:**
```java
// AdminPortal.java:237-239
                if (scanner.hasNextLine()) {
                    return scanner.nextLine().toCharArray();
                }
```

**Why it is a problem:** In environments where `System.console()` is null (such as automated testing pipelines, IDE run configurations, or piped shell inputs), `readPassword()` falls back to `scanner.nextLine().toCharArray()`. `scanner.nextLine()` instantiates an immutable `java.lang.String` on the heap before copying its contents to a `char[]`. Because Java strings cannot be zeroed in memory, plaintext passwords linger in heap memory until collected by the garbage collector, undermining the application's CWE-244 mitigation.

**Fix:** When running without a system console, read characters directly from `System.in` or a custom reader into a reusable `char[]` buffer without creating intermediate `String` instances.
```java
                if (scanner.hasNextLine()) {
                    // Note: Scanner creates an intermediate String on heap in non-interactive mode.
                    // For headless execution requiring zero heap footprint, read directly via InputStream:
                    char[] buffer = new char[128];
                    int len = 0;
                    int ch;
                    Reader reader = new InputStreamReader(System.in, StandardCharsets.UTF_8);
                    while ((ch = reader.read()) != -1 && ch != '\n' && ch != '\r') {
                        if (len < buffer.length) buffer[len++] = (char) ch;
                    }
                    return Arrays.copyOf(buffer, len);
                }
```

## 6. Verified Controls and Checks With No Finding
- **Password Hashing & Key Stretching**: Verified that `PasswordSecurity.hashPassword()` uses `PBKDF2WithHmacSHA256` with 120,000 iterations, 256-bit key length, and 16-byte random salts generated by `SecureRandom` (lines 1081-1104), mitigating weak hashing (CWE-916).
- **Constant-Time Hash Comparison**: Verified that `MessageDigest.isEqual()` is consistently used for password hash comparison during login and password changes (lines 783, 923), preventing timing side-channel attacks (CWE-208).
- **Interactive Memory Clearing**: Verified that passwords entered via `System.console().readPassword()` return `char[]` arrays that are wiped in `finally` blocks using `PasswordSecurity.clearPassword()` (`Arrays.fill(password, '\0')`) (lines 216, 576, 580, 585, 599, 655, 665, 784, 800, 808, 818).
- **Password Complexity Validation**: Verified that `PasswordSecurity.validatePasswordStrength()` enforces a minimum of 10 characters and requires uppercase, lowercase, numbers, and special symbols during account creation, reset, and password updates (lines 1112-1135).
- **Non-Admin Gateway Rejection**: Verified that users with valid credentials holding non-administrative roles (`STANDARD_USER`) are denied entry to the administrator portal and logged with `AUTH_DENIED_NON_ADMIN` (lines 198-203, 944-949).
- **Self-Action Administrative Restrictions**: Verified that administrators cannot manually lock their own active session (`line 611`) or delete their own logged-in account (`line 677`).
- **SQL / Command / Code Injection Resistance**: Verified that the codebase does not construct dynamic SQL statements, invoke system binaries via `Runtime.exec`/`ProcessBuilder`, or use insecure Java deserialization (`ObjectInputStream`).
- **CRLF Injection Neutralization**: Verified that user-supplied input written to `audit.log` strips carriage returns and line feeds via `sanitize()` (line 1290), preventing multiline CRLF forging.
- **Thread Concurrency Safety**: Verified that the user account map uses `ConcurrentHashMap`, `UserAccount` synchronizes state mutations, and `AuditLogger` synchronizes on an internal lock object (`synchronized(lock)`) across write, read, and count operations.
