# Security Review: Internal Employee Portal Authentication System

## 1. Executive Summary
A comprehensive source code security review was performed on the Internal Employee Portal Authentication System (`EmployeePortalAuth.java` and associated credential storage `employee_records.txt`). The application provides employee authentication, brute-force mitigation through consecutive failed login throttling and account lockout, password change management, an interactive console dashboard, and scriptable command-line interface (CLI) utilities.

The review identified notable security strengths in the underlying cryptographic architecture, including standard-compliant `PBKDF2WithHmacSHA256` key derivation (65,536 iterations, 256-bit key length), cryptographically secure 128-bit per-user salts, constant-time hash comparisons via `MessageDigest.isEqual()`, memory zeroing of sensitive buffers, and atomic file replacement. 

However, critical and high-severity security weaknesses were identified that undermine the portal's security posture:
1. **Password Hash & Salt Exfiltration on Authentication Failure**: Failed login attempts return an `AuthResult` containing the target employee's entity object, leaking the user's cryptographic salt and password hash to callers without requiring credentials.
2. **Missing Authentication on Critical Administrative Operations**: CLI commands `unlock` and `reset` as well as interactive console main menu option 4 execute sensitive administrative functions (bypassing account lockout and wiping the entire records store) without verifying authentication or administrative authorization.
3. **Hard-Coded Credentials & Startup Banner Leakage**: Pre-configured sample user and administrator credentials are embedded in plaintext in source code and printed to stdout upon launching the portal.
4. **Process Table Password Exposure**: The CLI `login` command accepts passwords as command-line arguments, exposing them in plaintext via process inspection tools (`ps`, `/proc`) and shell history.
5. **User Enumeration**: Differential error messages between non-existent accounts and valid accounts reveal valid usernames and attempt counters.
6. **Insecure Temporary File & Permission Race Condition**: Updated records are written to a fixed temporary file with default umask permissions before setting POSIX 0600 mode, exposing password hashes to local users.

A total of 8 vulnerabilities were identified (3 High, 3 Medium, 2 Low). Immediate remediation is recommended to harden the portal before production deployment.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `EmployeePortalAuth.java` | Core Java application implementing authentication service, credential cryptography, account lockout rate limiting, interactive terminal UI, CLI execution modes, and persistent storage management. | Password hashing with `PBKDF2WithHmacSHA256`, cryptographic salt generation with `SecureRandom`, constant-time hash verification via `MessageDigest.isEqual()`, dummy hash calculation, sensitive memory zeroing, account lockout policy enforcement, administrative authorization, atomic file operations, and record serialization/deserialization. |
| `employee_records.txt` | Pipe-delimited flat-file database storing employee account records, salts, password hashes, and lockout status. | Persistent on-disk storage of Base64-encoded PBKDF2 password hashes, 128-bit cryptographic salts, lockout flags, failure counts, and lockout timestamps subject to filesystem access control. |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to audit cryptographic primitives, key derivation parameters (PBKDF2 iteration count, key length), salt generation entropy, constant-time verification logic, dummy hash computation, memory buffer clearing, and detection of hard-coded credentials.
- `testing-for-sensitive-data-exposure`: Applied to assess exposure of sensitive data, including leakage of internal `Employee` entities and password hashes in `AuthResult`, exposure of plaintext passwords in CLI arguments and process tables, and credential disclosure in console banners.
- `testing-for-broken-access-control`: Applied to evaluate function-level access control, authorization boundaries on administrative actions (account unlocking, database reset), and role derivation logic.
- General OWASP Top 10 / CWE Knowledge: Applied to review observable response discrepancies and user account enumeration (CWE-204), insecure temporary file handling and filesystem permission race conditions (CWE-377 / CWE-732), flat-file CRLF/record injection during delimiter serialization (CWE-93 / CWE-113), and account lockout denial-of-service exposure (CWE-307 / CWE-645).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Exposure of Internal Employee Entity and Password Hashes in Failed Authentication Results | High | CWE-200 | `EmployeePortalAuth.java:531-535` |
| SEC-02 | Missing Authentication and Authorization on Critical Administrative Functions | High | CWE-306 | `EmployeePortalAuth.java:1117-1135` |
| SEC-03 | Hard-Coded Credentials in Application Source Code and Startup Banner Disclosure | High | CWE-798 | `EmployeePortalAuth.java:323-332` |
| SEC-04 | Exposure of Plaintext Passwords via Command-Line Arguments in Process Table | Medium | CWE-214 | `EmployeePortalAuth.java:1042-1048` |
| SEC-05 | User Account Enumeration via Observable Response Discrepancy | Medium | CWE-204 | `EmployeePortalAuth.java:531-534` |
| SEC-06 | Insecure Temporary File Creation and File Permission Exposure Window in Record Storage | Medium | CWE-377 | `EmployeePortalAuth.java:364-372` |
| SEC-07 | Improper Neutralization of CRLF Sequences in Flat-File Database Serialization | Low | CWE-93 | `EmployeePortalAuth.java:170-176` |
| SEC-08 | Insecure Administrative Authorization Derived from Department Attribute | Low | CWE-285 | `EmployeePortalAuth.java:683-685` |

## 5. Detailed Findings

### SEC-01: Exposure of Internal Employee Entity and Password Hashes in Failed Authentication Results
- **Severity:** High
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **Location:** `EmployeePortalAuth.java:531-535`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:531-535
                    return new AuthResult(AuthStatus.ACCESS_DENIED,
                            "Access Denied: Invalid credentials. Security Notice: " + remaining +
                            " consecutive attempt(s) remaining before account lockout.",
                            employee);
```

**Why it is a problem:** When an authentication attempt fails—either because an incorrect password was supplied or because the account is locked (lines 490, 525, and 534)—the `AuthenticationService.authenticate()` method passes the target `Employee` object directly into `AuthResult`. The `Employee` class exposes public getter methods `getSalt()` and `getPasswordHash()` that return the user's cryptographic salt and PBKDF2 password hash. Any caller, API handler, or surrounding integration that executes `authenticate()` receives the entire internal employee entity upon failure. An unauthorized actor or rogue caller can supply an arbitrary username with an invalid password to harvest that user's password hash and salt, enabling offline brute-force and dictionary cracking attacks.

**Fix:** Set the employee reference to `null` in `AuthResult` for all non-successful authentication outcomes (`ACCESS_DENIED` and `ACCOUNT_LOCKED`). Only populate the employee object when authentication succeeds (`SUCCESS`).
```java
                    return new AuthResult(AuthStatus.ACCESS_DENIED,
                            "Access Denied: Invalid credentials. Security Notice: " + remaining +
                            " consecutive attempt(s) remaining before account lockout.",
                            null);
```

---

### SEC-02: Missing Authentication and Authorization on Critical Administrative Functions
- **Severity:** High
- **CWE:** CWE-306: Missing Authentication for Critical Function
- **Location:** `EmployeePortalAuth.java:1117-1135`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:1117-1135
            case "unlock":
                if (args.length < 2) {
                    System.err.println("Usage: java EmployeePortalAuth unlock <username>");
                    System.exit(1);
                }
                String unlockUser = args[1];
                if (authService.unlockAccount(unlockUser)) {
                    System.out.println("SUCCESS: Account '" + unlockUser + "' unlocked and consecutive failure counter reset.");
                } else {
                    System.err.println("ERROR: Account '" + unlockUser + "' not found.");
                    System.exit(1);
                }
                break;

            case "reset":
                recordStore.initializeDefaultRecords();
                recordStore.save();
                System.out.println("SUCCESS: Records store reset to default employee accounts.");
                break;
```

**Why it is a problem:** The application provides command-line functions `unlock <username>` and `reset` that perform high-impact administrative actions without authenticating the invoking user or checking administrative privileges. Any unauthenticated local user or script can execute `java EmployeePortalAuth unlock <username>` to instantly unlock any locked account and reset failed login counters, completely circumventing the portal's brute-force lockout defenses. Furthermore, executing `java EmployeePortalAuth reset` (or selecting Option 4 on the unauthenticated interactive menu at lines 624, 640-642) wipes all modified passwords, user accounts, and audit timestamps, resetting the database to factory defaults without credential verification.

**Fix:** Require verified administrator credentials and role-based authorization before executing account unlocks or database resets. Remove unauthenticated reset capabilities from public menus.
```java
            case "unlock":
                if (args.length < 4) {
                    System.err.println("Usage: java EmployeePortalAuth unlock <admin-user> <admin-pass> <target-user>");
                    System.exit(1);
                }
                String adminUser = args[1];
                char[] adminPass = args[2].toCharArray();
                String unlockUser = args[3];
                try {
                    AuthResult adminAuth = authService.authenticate(adminUser, adminPass);
                    if (!adminAuth.isSuccess() || !"IT Portal Administrator".equalsIgnoreCase(adminAuth.getEmployee().getRole())) {
                        System.err.println("ERROR: Unauthorized. Administrative credentials required.");
                        System.exit(1);
                    }
                    if (authService.unlockAccount(unlockUser)) {
                        System.out.println("SUCCESS: Account '" + unlockUser + "' unlocked.");
                    } else {
                        System.err.println("ERROR: Account '" + unlockUser + "' not found.");
                        System.exit(1);
                    }
                } finally {
                    SecurityUtils.wipe(adminPass);
                }
                break;

            case "reset":
                System.err.println("ERROR: Database reset is restricted to authorized provisioning scripts.");
                System.exit(1);
                break;
```

---

### SEC-03: Hard-Coded Credentials in Application Source Code and Startup Banner Disclosure
- **Severity:** High
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Location:** `EmployeePortalAuth.java:323-332`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:323-332
            addDefaultEmployee("jdoe", "Password123!", "EMP-1001", "John Doe",
                    "Engineering", "Senior Software Engineer");
            addDefaultEmployee("asmith", "SecureHR#2026", "EMP-1002", "Alice Smith",
                    "Human Resources", "HR Operations Lead");
            addDefaultEmployee("admin", "AdminSecure#2026", "EMP-0001", "Marcus Vance",
                    "Information Security", "IT Portal Administrator");
            addDefaultEmployee("bclark", "FinanceKey!99", "EMP-1003", "Bob Clark",
                    "Finance", "Senior Financial Analyst");
```

**Why it is a problem:** Static credentials for standard accounts and the privileged administrator account (`admin:AdminSecure#2026`) are hard-coded into the source code in `initializeDefaultRecords()`. In addition, `PortalUI.printBanner()` (lines 889-894) prints these accounts along with their cleartext passwords directly to standard output upon application launch. Anyone with access to the source code, decompiled bytecode, or console output can obtain valid administrator credentials, granting full control over the portal, employee records, and account lockout configurations.

**Fix:** Remove all hardcoded passwords from the source code and banner. The application should initialize an empty store or prompt for initial administrator credentials during an interactive first-run setup wizard, enforcing mandatory password rotation upon initial login.
```java
        public synchronized void initializeDefaultRecords() {
            employeeMap.clear();
            // Production deployment: Do not embed static credentials in code.
            // Require initial administrator provisioning through secure bootstrap or environment configuration.
            System.out.println("[Notice] Store uninitialized. Run administrative bootstrap to provision accounts.");
        }
```

---

### SEC-04: Exposure of Plaintext Passwords via Command-Line Arguments in Process Table
- **Severity:** Medium
- **CWE:** CWE-214: Invocation of Process Using Visible Sensitive Information
- **Location:** `EmployeePortalAuth.java:1042-1048`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:1042-1048
                if (args.length < 3) {
                    System.err.println("Usage: java EmployeePortalAuth login <username> <password>");
                    System.exit(1);
                }
                String username = args[1];
                char[] password = args[2].toCharArray();
```

**Why it is a problem:** In CLI authentication mode, the password is provided as a command-line argument (`args[2]`). On multi-user operating systems (Linux, macOS, Windows), command-line arguments are visible to all users on the host via process monitoring utilities such as `ps -ef`, `ps aux`, `top`, or the `/proc/<pid>/cmdline` virtual filesystem. Additionally, shell interpreters record command-line arguments in plain text in command history files (`~/.bash_history`, `~/.zsh_history`). Furthermore, passing the password as `args[2]` creates an immutable `java.lang.String` in JVM heap memory before converting to `char[]`, preventing effective memory zeroing via `SecurityUtils.wipe()`.

**Fix:** Prompt for the password interactively using `System.console().readPassword()` or read from standard input (`System.in`) rather than accepting password values as command-line arguments.
```java
                if (args.length < 2) {
                    System.err.println("Usage: java EmployeePortalAuth login <username>");
                    System.exit(1);
                }
                String username = args[1];
                Console console = System.console();
                char[] password;
                if (console != null) {
                    password = console.readPassword("Enter Password: ");
                } else {
                    System.out.print("Enter Password: ");
                    password = new Scanner(System.in).nextLine().toCharArray();
                }
```

---

### SEC-05: User Account Enumeration via Observable Response Discrepancy
- **Severity:** Medium
- **CWE:** CWE-204: Observable Response Discrepancy
- **Location:** `EmployeePortalAuth.java:531-534`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:531-534
                    return new AuthResult(AuthStatus.ACCESS_DENIED,
                            "Access Denied: Invalid credentials. Security Notice: " + remaining +
                            " consecutive attempt(s) remaining before account lockout.",
                            employee);
```

**Why it is a problem:** While the application uses `SecurityUtils.performDummyHash()` to neutralize timing differences between existing and non-existent users, it returns distinct error messages that explicitly disclose account existence. When an unknown username is supplied, line 463 returns `"Access Denied: Invalid credentials."`. When a valid username is supplied with an incorrect password, line 532 returns `"Access Denied: Invalid credentials. Security Notice: <N> consecutive attempt(s) remaining before account lockout."`. If the account is locked, line 488 returns `"Access Denied: Account is LOCKED..."`. An external attacker can enumerate valid corporate usernames by observing which requests trigger the security notice or lockout response.

**Fix:** Return an identical, generic authentication failure message for all failed attempts, regardless of whether the username exists, the password was incorrect, or the account is currently locked.
```java
                    return new AuthResult(AuthStatus.ACCESS_DENIED,
                            "Access Denied: Invalid username or password.",
                            null);
```

---

### SEC-06: Insecure Temporary File Creation and File Permission Exposure Window in Record Storage
- **Severity:** Medium
- **CWE:** CWE-377: Insecure Temporary File
- **Location:** `EmployeePortalAuth.java:364-372`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:364-372
                // Write atomically via temporary file
                Path tempPath = storagePath.resolveSibling(storagePath.getFileName() + ".tmp");
                Files.write(tempPath, lines, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                Files.move(tempPath, storagePath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);

                // Apply POSIX permissions (owner read/write only: 600) where supported
                try {
                    Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
                    Files.setPosixFilePermissions(storagePath, perms);
                } catch (UnsupportedOperationException ignored) {
                    // Non-POSIX filesystem (e.g., standard FAT or Windows)
                }
```

**Why it is a problem:** When `RecordStore.save()` updates employee records, it writes to a predictable temporary file (`employee_records.txt.tmp`) using `Files.write()` without defining POSIX permissions during file creation. The temporary file is created with the process's default umask permissions (often 0644 or 0664, world-readable), creating a window where password hashes and salts can be read by other local processes. Because `Files.move` preserves the source file's permissions, the target file remains world-readable until `Files.setPosixFilePermissions()` executes. Furthermore, because the temporary file name is fixed and predictable, a local adversary could place a symbolic link at `employee_records.txt.tmp` pointing to a sensitive file, causing `Files.write(..., TRUNCATE_EXISTING)` to overwrite arbitrary files owned by the application runner.

**Fix:** Use `Files.createTempFile` with randomized naming and atomically set POSIX 0600 file permissions at creation time via `FileAttribute`.
```java
                Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
                Path parent = storagePath.getParent() != null ? storagePath.getParent() : Paths.get(".");
                Path tempPath = Files.createTempFile(parent, "emp_records_", ".tmp",
                        PosixFilePermissions.asFileAttribute(perms));
                try {
                    Files.write(tempPath, lines, StandardCharsets.UTF_8, StandardOpenOption.TRUNCATE_EXISTING);
                    Files.move(tempPath, storagePath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
                } finally {
                    Files.deleteIfExists(tempPath);
                }
```

---

### SEC-07: Improper Neutralization of CRLF Sequences in Flat-File Database Serialization
- **Severity:** Low
- **CWE:** CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection')
- **Location:** `EmployeePortalAuth.java:170-176`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:170-176
        private static String escape(String s) {
            return s == null ? "" : s.replace("\\", "\\\\").replace("|", "\\p");
        }

        private static String unescape(String s) {
            return s == null ? "" : s.replace("\\p", "|").replace("\\\\", "\\");
        }
```

**Why it is a problem:** `Employee.serialize()` serializes fields into a single pipe-delimited record per employee. While `escape()` substitutes backslashes and pipes, it fails to sanitize or escape carriage return (`\r`) or newline (`\n`) characters. If user-supplied input in fields such as `fullName`, `department`, or `role` contains newline characters (e.g., during programmatic employee registration), writing the record injects raw newline characters into `employee_records.txt`. When `RecordStore.load()` reads the file with `BufferedReader.readLine()`, the injected line is processed as a separate record, leading to record corruption or arbitrary record injection in the flat-file database.

**Fix:** Neutralize carriage return and newline characters during escaping and unescaping, and validate inputs against control characters before storing.
```java
        private static String escape(String s) {
            return s == null ? "" : s.replace("\\", "\\\\")
                                     .replace("|", "\\p")
                                     .replace("\r", "\\r")
                                     .replace("\n", "\\n");
        }

        private static String unescape(String s) {
            return s == null ? "" : s.replace("\\n", "\n")
                                     .replace("\\r", "\r")
                                     .replace("\\p", "|")
                                     .replace("\\\\", "\\");
        }
```

---

### SEC-08: Insecure Administrative Authorization Derived from Department Attribute
- **Severity:** Low
- **CWE:** CWE-285: Improper Authorization
- **Location:** `EmployeePortalAuth.java:683-685`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:683-685
            boolean isAdmin = "Information Security".equalsIgnoreCase(employee.getDepartment()) ||
                              "admin".equalsIgnoreCase(employee.getUsername());
```

**Why it is a problem:** In `launchEmployeeDashboard()`, administrative capabilities (unlocking employee accounts, registering new users, and inspecting credential security audit logs) are granted if the user's username is `"admin"` or if their `department` is `"Information Security"`. The data model already defines a distinct `role` attribute (`employee.getRole()`). Deriving administrative authorization from an organizational department string rather than an explicit administrative role or privilege mapping means that any employee assigned to the Information Security department (such as an intern or junior analyst) is implicitly granted full portal administrative authority.

**Fix:** Enforce role-based access control based on an explicit administrative role check rather than department membership.
```java
            boolean isAdmin = "IT Portal Administrator".equalsIgnoreCase(employee.getRole()) ||
                              "Administrator".equalsIgnoreCase(employee.getRole());
```

## 6. Verified Controls and Checks With No Finding
- Password Hashing Algorithm & Iterations: Verified that passwords are hashed using `PBKDF2WithHmacSHA256` with 65,536 iterations and 256-bit derived key length (`SecurityUtils.java:181-183`), complying with OWASP password storage guidelines.
- Salt Generation & Uniqueness: Verified that 128-bit (16-byte) unique salts are generated per user record using `java.security.SecureRandom` (`SecurityUtils.java:197-201`), mitigating rainbow table and precomputation attacks.
- Constant-Time Hash Comparison: Verified that credential comparison uses `MessageDigest.isEqual(computedHash, storedHash)` (`SecurityUtils.java:224`), eliminating byte-by-byte early-exit timing side channels.
- Dummy Hash Calculation for Non-Existent Users: Verified that `SecurityUtils.performDummyHash` executes during authentication when an unknown username is supplied (`AuthenticationService.java:462`), equalizing processing time to hinder timing-based user enumeration.
- Sensitive Memory Zeroing: Verified that character arrays and hash byte buffers are explicitly overwritten with null/zero bytes via `SecurityUtils.wipe()` in `finally` blocks (`SecurityUtils.java:225-227, 242-255`, `PortalUI.java:677, 776-778`), limiting credential exposure in process memory dumps.
- Consecutive Failed Login Throttling & Account Lockout: Verified that after 3 consecutive wrong password attempts (`MAX_CONSECUTIVE_FAILED_ATTEMPTS = 3`), the account state transitions to locked and rejects all authentication attempts, even with valid credentials (`AuthenticationService.java:467, 514-525`).
- Automatic Cooldown Expiration: Verified that account lockout duration is constrained by a 15-minute expiration timestamp (`lockedUntilEpochMs`) and automatically lifts once the cooldown expires (`AuthenticationService.java:469-474`), preventing permanent account denial of service.
- Login Success Counter Reset: Verified that a successful login immediately resets `failedAttempts` to 0 (`AuthenticationService.java:500`), ensuring that intermittent incorrect passwords do not accumulate into premature lockouts.
- Password Complexity Enforcement: Verified that `SecurityUtils.isPasswordStrong()` validates minimum length (8 characters) and requires uppercase, lowercase, and digit/special characters before allowing registration or password updates (`SecurityUtils.java:258-273`).
- Atomic File Write Operations: Verified that record saving utilizes `Files.move` with `StandardCopyOption.ATOMIC_MOVE` (`RecordStore.java:366`), preventing file corruption and partial writes during sudden process termination.
