# Security Review: Internal Employee Portal Authentication Service (EmployeePortalAuth)

## 1. Executive Summary
The target codebase is an internal Java authentication application (`EmployeePortalAuth.java`) designed to control access to an employee portal, backed by a persistent flat-file record store (`employee_records.txt`). The application implements password hashing using `PBKDF2WithHmacSHA256` with 65,536 iterations, 128-bit cryptographic salts via `SecureRandom`, constant-time hash comparisons via `MessageDigest.isEqual`, account lockout after three consecutive failed attempts, in-memory array wiping, an interactive terminal UI, and CLI operational modes.

While fundamental cryptographic choices for password hashing and comparison are sound, the codebase exhibits critical authorization, credential management, and data handling vulnerabilities. Most critically, administrative operations (such as resetting all accounts to default state and unlocking accounts) are exposed without authentication or access control in both interactive and CLI modes (CWE-306). Hardcoded default credentials are included in the source code and printed to the console banner (CWE-798). Passwords accepted via command-line arguments are exposed to all local users via process listings (CWE-214). Differentiated error messages leak whether usernames exist, subverting timing-attack defenses (CWE-204). File persistence introduces world-readable permission race conditions during temporary file replacement (CWE-732). In addition, sensitive password hashes and salts are exposed on failed authentication results (CWE-200), organizational metadata is accessible unauthenticated (CWE-200), unauthenticated self-tests mutate production accounts and audit records (CWE-284), authorization relies on mutable department strings (CWE-285), and serialization escaping fails to neutralize CRLF injection (CWE-93).

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `EmployeePortalAuth.java` | Main application containing data models, cryptography, storage management, authentication service, interactive menu, and CLI dispatcher. | Password hashing (PBKDF2WithHmacSHA256), cryptographic salt generation, dummy hashing, constant-time verification, in-memory credential wiping, account lockout tracking, file permissions, command-line argument processing, and role authorization. |
| `employee_records.txt` | Flat-file persistent datastore containing delimited employee records, Base64 salts, password hashes, and account states. | Credential storage at rest, schema delimiter formatting, and file permission security. |

## 3. Skills Applied
- `testing-for-broken-access-control`: Applied to assess role-based access control, privilege escalation vectors, administrative function authorization, and unauthenticated execution of store resets, account unlocks, and directory listings.
- `testing-api-authentication-weaknesses`: Applied to evaluate authentication workflows, brute-force lockout mechanisms, error message discrepancies, account enumeration vectors, and credential exposure.
- `performing-cryptographic-audit-of-application`: Applied to audit cryptographic primitives, PBKDF2 iteration counts, key length, salt generation entropy, and constant-time equality comparisons.
- `implementing-secret-scanning-with-gitleaks`: Applied to detect hardcoded default passwords, seeds, and plaintext credentials embedded in source code and startup routines.
- General OWASP Top 10 / CWE knowledge (No library skill matched): Applied to review process command-line argument credential exposure (CWE-214), file system permissions and atomic temporary file creation race conditions (CWE-732 / CWE-378), unauthenticated state mutation and audit log tampering (CWE-284 / CWE-223), and delimiter/CRLF injection in record serialization (CWE-93 / CWE-150).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Missing Authentication on Critical Administrative Functions | Critical | CWE-306 | `EmployeePortalAuth.java:538-556` |
| SEC-02 | Hard-Coded Default Passwords in Source Code and Startup Banner | Critical | CWE-798 | `EmployeePortalAuth.java:286-293` |
| SEC-03 | Plaintext Password Exposure via Command-Line Arguments | High | CWE-214 | `EmployeePortalAuth.java:918-923` |
| SEC-04 | Username Enumeration via Observable Response Discrepancy | High | CWE-204 | `EmployeePortalAuth.java:408-420` |
| SEC-05 | Insecure Temporary File Creation and File Permission Race Condition | High | CWE-732 | `EmployeePortalAuth.java:325-333` |
| SEC-06 | Sensitive Credential Hash and Salt Exposure in AuthResult on Failed Authentication | Medium | CWE-200 | `EmployeePortalAuth.java:440-450` |
| SEC-07 | Sensitive Employee Directory and Account Metadata Disclosed Without Authentication | Medium | CWE-200 | `EmployeePortalAuth.java:750-756` |
| SEC-08 | Unauthenticated Self-Test Execution Mutates Production Data and Audit Timestamps | Medium | CWE-284 | `EmployeePortalAuth.java:848-859` |
| SEC-09 | Flawed Administrative Privilege Assignment Based on Department String | Low | CWE-285 | `EmployeePortalAuth.java:597-598` |
| SEC-10 | Incomplete Sanitization Permitting CRLF Record Injection in Serialized Storage | Low | CWE-93 | `EmployeePortalAuth.java:130-136` |

## 5. Detailed Findings

### SEC-01: Missing Authentication on Critical Administrative Functions
- **Severity:** Critical
- **CWE:** CWE-306: Missing Authentication for Critical Function
- **Location:** `EmployeePortalAuth.java:538-556`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:538-556
                System.out.println("  4. Reset Records Store to Default Accounts");
                System.out.println("  5. Exit Application");
                System.out.print("\nPlease select an option (1-5): ");

                String input = scanner.hasNextLine() ? scanner.nextLine().trim() : "5";
                switch (input) {
                    case "1":
                        handleLogin();
                        break;
                    case "2":
                        handleViewDirectory();
                        break;
                    case "3":
                        handleRunSelfTest();
                        break;
                    case "4":
                        handleResetRecords();
                        break;
                    case "5":
                        System.out.println("\nThank you for using the Internal Employee Portal. Goodbye!");
                        running = false;
                        break;
```

**Why it is a problem:** In interactive mode, menu option 4 ("Reset Records Store to Default Accounts") is directly accessible from the public, unauthenticated main menu. Any user can invoke `handleResetRecords()` and overwrite all production employee passwords and accounts with default credentials without providing administrative authentication. Similarly, in CLI mode (`EmployeePortalAuth.java:967-985`), the `unlock` and `reset` subcommands execute administrative state changes with zero authentication or permission checks, allowing any local user to unlock arbitrary locked accounts or reset the entire user database.

**Fix:** Remove administrative actions from the unauthenticated public menu and CLI root. Enforce that administrative functions (such as store reset and account unlocking) can only be executed within an authenticated administrator session after verifying administrator credentials.
```java
// Corrected code: Remove unauthenticated reset from main menu
                System.out.println("  1. Log In (Employee Portal)");
                System.out.println("  2. Exit Application");
                System.out.print("\nPlease select an option (1-2): ");

                String input = scanner.hasNextLine() ? scanner.nextLine().trim() : "2";
                switch (input) {
                    case "1":
                        handleLogin();
                        break;
                    case "2":
                        System.out.println("\nThank you for using the Internal Employee Portal. Goodbye!");
                        running = false;
                        break;
                    default:
                        System.out.println("[Notice] Invalid selection.");
                }
```

---

### SEC-02: Hard-Coded Default Passwords in Source Code and Startup Banner
- **Severity:** Critical
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Location:** `EmployeePortalAuth.java:286-293`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:286-293
            addDefaultEmployee("jdoe", "Password123!", "EMP-1001", "John Doe",
                    "Engineering", "Senior Software Engineer");
            addDefaultEmployee("asmith", "SecureHR#2026", "EMP-1002", "Alice Smith",
                    "Human Resources", "HR Operations Lead");
            addDefaultEmployee("admin", "AdminSecure#2026", "EMP-0001", "Marcus Vance",
                    "Information Security", "IT Portal Administrator");
            addDefaultEmployee("bclark", "FinanceKey!99", "EMP-1003", "Bob Clark",
                    "Finance", "Senior Financial Analyst");
```

**Why it is a problem:** Default employee accounts are initialized with well-known passwords hardcoded directly into the Java source code (`Password123!`, `SecureHR#2026`, `AdminSecure#2026`, `FinanceKey!99`). Furthermore, `printBanner()` (`EmployeePortalAuth.java:793-798`) outputs these credentials to standard output every time the application starts. The file `employee_records.txt` is seeded with hashes matching these exact credentials. An attacker with access to the source code, repository history, or startup console output gains immediate administrative and user access.

**Fix:** Eliminate hardcoded plaintext credentials from source code and banner displays. For initial system setup, prompt the administrator to set a unique, strong password during initial bootstrapping, or generate a cryptographically random one-time password that must be changed upon first login.
```java
// Corrected code: Require dynamic initial setup without hardcoded passwords
        public synchronized void initializeDefaultRecords() {
            employeeMap.clear();
            Console console = System.console();
            if (console != null) {
                System.out.println("Initial bootstrap: Set administrator credentials.");
                char[] adminPass = console.readPassword("Enter initial admin password: ");
                try {
                    addDefaultEmployee("admin", adminPass, "EMP-0001", "Administrator",
                            "Administration", "ROLE_ADMIN");
                } finally {
                    SecurityUtils.wipe(adminPass);
                }
            } else {
                throw new IllegalStateException("Interactive console required for initial database setup.");
            }
        }
```

---

### SEC-03: Plaintext Password Exposure via Command-Line Arguments
- **Severity:** High
- **CWE:** CWE-214: Invocation of Process Initializer with Sensitive Information to an Insecure Target
- **Location:** `EmployeePortalAuth.java:918-923`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:918-923
                if (args.length < 3) {
                    System.err.println("Usage: java EmployeePortalAuth login <username> <password>");
                    System.exit(1);
                }
                String username = args[1];
                char[] password = args[2].toCharArray();
```

**Why it is a problem:** Accepting passwords as command-line arguments (`args[2]`) exposes plaintext credentials to all local users on the operating system via process table utilities (such as `ps aux`, `top`, or `/proc/<pid>/cmdline`), and records them in shell history files (such as `~/.bash_history`) and system process auditing logs (`auditd`). Furthermore, `args[2]` arrives as an immutable `java.lang.String` in the JVM heap, which cannot be securely cleared by `SecurityUtils.wipe(password)`, nullifying the application's memory hygiene protections.

**Fix:** Remove password arguments from the command-line interface. Read credentials interactively using `System.console().readPassword()`, or accept credentials via standard input (`System.in`) or secure environment variables.
```java
// Corrected code: Prompt securely from console or stdin instead of command-line args
                if (args.length < 2) {
                    System.err.println("Usage: java EmployeePortalAuth login <username>");
                    System.exit(1);
                }
                String username = args[1];
                Console console = System.console();
                char[] password = (console != null) ? console.readPassword("Password: ") : new char[0];
                try {
                    AuthResult result = authService.authenticate(username, password);
```

---

### SEC-04: Username Enumeration via Observable Response Discrepancy
- **Severity:** High
- **CWE:** CWE-204: Observable Response Discrepancy
- **Location:** `EmployeePortalAuth.java:408-420`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:408-420
            // User does not exist in the record store
            if (employee == null) {
                // Perform dummy hash computation to prevent timing attacks
                SecurityUtils.performDummyHash(password);
                return new AuthResult(AuthStatus.ACCESS_DENIED, "Access Denied: Invalid credentials.", null);
            }

            // Check if account is locked
            if (employee.isLocked()) {
                SecurityUtils.performDummyHash(password);
                return new AuthResult(AuthStatus.ACCOUNT_LOCKED,
                        "Access Denied: Account is locked due to too many failed login attempts. Please contact IT Security Support.",
                        employee);
            }
```

**Why it is a problem:** While the application computes a dummy PBKDF2 hash to defend against timing-based username enumeration, it completely negates this defense through its return messages and statuses. When a username does not exist, it returns `"Access Denied: Invalid credentials."` (line 411). When a username exists but the password is wrong, it returns `"Access Denied: Invalid credentials. (" + remaining + " attempt(s) remaining before account lockout)."` (line 449). If the account is locked, it returns status `ACCOUNT_LOCKED` with `"Access Denied: Account is locked..."` (line 418). An attacker can trivially enumerate valid usernames by checking the returned message or status code.

**Fix:** Return an identical, generic error message and status code for all authentication failures regardless of whether the username exists, the password was incorrect, or the account is locked. Handle account lockout notifications out-of-band (such as via email or security logs).
```java
// Corrected code: Uniform response for non-existent, invalid, or locked accounts
            if (employee == null) {
                SecurityUtils.performDummyHash(password);
                return new AuthResult(AuthStatus.ACCESS_DENIED, "Access Denied: Invalid credentials.", null);
            }

            if (employee.isLocked()) {
                SecurityUtils.performDummyHash(password);
                return new AuthResult(AuthStatus.ACCESS_DENIED, "Access Denied: Invalid credentials.", null);
            }
```

---

### SEC-05: Insecure Temporary File Creation and File Permission Race Condition
- **Severity:** High
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `EmployeePortalAuth.java:325-333`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:325-333
                Path tempPath = storagePath.resolveSibling(storagePath.getFileName() + ".tmp");
                Files.write(tempPath, lines, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                Files.move(tempPath, storagePath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);

                // Apply POSIX permissions (owner read/write only: 600) where supported
                try {
                    Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
                    Files.setPosixFilePermissions(storagePath, perms);
                } catch (UnsupportedOperationException ignored) {
```

**Why it is a problem:** When `save()` writes records to `tempPath`, it uses `Files.write(...)` without specifying restrictive file permissions. The temporary file is created with the process's default umask (typically 0644, granting read access to all local users). `Files.move(...)` replaces the target file while preserving the source file's permissions. Only after the file has been moved does the program call `Files.setPosixFilePermissions(...)`. This introduces a Time-of-Check to Time-of-Use (TOCTOU) permission race window during which sensitive password hashes and salts can be read by unauthorized users. Furthermore, on non-POSIX systems (e.g., Windows), the permission call fails silently, leaving the file world-readable indefinitely.

**Fix:** Set restrictive POSIX permissions (`rw-------` / 0600) atomically upon file creation using `FileAttribute<Set<PosixFilePermission>>` with `Files.createFile` or `Files.newByteChannel`.
```java
// Corrected code: Create temporary file with restrictive permissions atomically
                Path tempPath = storagePath.resolveSibling(storagePath.getFileName() + ".tmp");
                Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
                try {
                    Files.deleteIfExists(tempPath);
                    Files.createFile(tempPath, PosixFilePermissions.asFileAttribute(perms));
                } catch (UnsupportedOperationException e) {
                    // Non-POSIX fallback handling
                }
                Files.write(tempPath, lines, StandardCharsets.UTF_8, StandardOpenOption.TRUNCATE_EXISTING);
                Files.move(tempPath, storagePath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
```

---

### SEC-06: Sensitive Credential Hash and Salt Exposure in AuthResult on Failed Authentication
- **Severity:** Medium
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **Location:** `EmployeePortalAuth.java:440-450`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:440-450
                    return new AuthResult(AuthStatus.ACCOUNT_LOCKED,
                            "Access Denied: Incorrect password. Account has been LOCKED after " +
                            MAX_FAILED_ATTEMPTS + " consecutive failed attempts. Contact IT Support.",
                            employee);
                } else {
                    int remaining = MAX_FAILED_ATTEMPTS - employee.getFailedAttempts();
                    recordStore.put(employee);
                    return new AuthResult(AuthStatus.ACCESS_DENIED,
                            "Access Denied: Invalid credentials. (" + remaining + " attempt(s) remaining before account lockout).",
                            employee);
                }
```

**Why it is a problem:** When authentication fails for an existing employee account, `authenticate()` passes the full `Employee` object into `AuthResult` (lines 419, 444, and 450). The `Employee` object provides `getSalt()` and `getPasswordHash()`, exposing raw cryptographic salt and password hash bytes to any calling module, logging listener, or consuming UI component on failed authentication attempts.

**Fix:** Pass `null` for the `Employee` reference in `AuthResult` whenever authentication fails, ensuring that sensitive user data, salts, and password hashes are never exposed outside the authentication domain.
```java
// Corrected code: Do not return the Employee entity upon failed authentication
                    return new AuthResult(AuthStatus.ACCOUNT_LOCKED,
                            "Access Denied: Invalid credentials.",
                            null);
                } else {
                    int remaining = MAX_FAILED_ATTEMPTS - employee.getFailedAttempts();
                    recordStore.put(employee);
                    return new AuthResult(AuthStatus.ACCESS_DENIED,
                            "Access Denied: Invalid credentials.",
                            null);
                }
```

---

### SEC-07: Sensitive Employee Directory and Account Metadata Disclosed Without Authentication
- **Severity:** Medium
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **Location:** `EmployeePortalAuth.java:750-756`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:750-756
            System.out.printf("%-12s %-10s %-20s %-20s %-22s%n", "Username", "Emp ID", "Full Name", "Department", "Role");
            System.out.println("-----------------------------------------------------------------------------------------");
            for (Employee e : recordStore.getAllEmployees()) {
                System.out.printf("%-12s %-10s %-20s %-20s %-22s%n",
                        e.getUsername(), e.getEmployeeId(), e.getFullName(), e.getDepartment(), e.getRole());
            }
        }
```

**Why it is a problem:** The application exposes an unauthenticated "Public Employee Directory" option via interactive menu option 2 and CLI command `list` (`EmployeePortalAuth.java:954-965`). This functionality outputs every employee's username, employee ID, full name, department, role, and account lock status without requiring authentication. Exposing all organizational usernames and employee metadata enables targeted password spraying, credential stuffing, and social engineering attacks.

**Fix:** Restrict employee directory access strictly to authenticated portal sessions. Remove the directory view from unauthenticated menus and CLI subcommands.
```java
// Corrected code: Restrict directory viewing to authenticated sessions
        private void handleViewDirectory(Employee authenticatedUser) {
            if (authenticatedUser == null) {
                System.out.println("[Access Denied] Authentication required to view directory.");
                return;
            }
            System.out.println("\n--- EMPLOYEE DIRECTORY ---");
            for (Employee e : recordStore.getAllEmployees()) {
                System.out.printf("%-12s %-10s %-20s %-20s %-22s%n",
                        e.getUsername(), e.getEmployeeId(), e.getFullName(), e.getDepartment(), e.getRole());
            }
        }
```

---

### SEC-08: Unauthenticated Self-Test Execution Mutates Production Data and Audit Timestamps
- **Severity:** Medium
- **CWE:** CWE-284: Improper Access Control
- **Location:** `EmployeePortalAuth.java:848-859`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:848-859
            // jdoe currently has 1 failed attempt from Test 2. Add 2 more failures to trigger lockout.
            char[] bad1 = "BadAttempt2".toCharArray();
            char[] bad2 = "BadAttempt3".toCharArray();
            authService.authenticate("jdoe", bad1);
            AuthResult rLock = authService.authenticate("jdoe", bad2);
            SecurityUtils.wipe(bad1);
            SecurityUtils.wipe(bad2);

            // Now test that even the CORRECT password is denied once locked
            char[] goodPass = "Password123!".toCharArray();
            AuthResult rPostLock = authService.authenticate("jdoe", goodPass);
            SecurityUtils.wipe(goodPass);
```

**Why it is a problem:** The built-in self-test suite (`SelfTest.runAllTests`) runs against the live production record store. It deliberately fails logins for user `jdoe`, triggers an account lockout, performs an administrative unlock, and then logs in with the hardcoded password `Password123!` (lines 873-876). This mutates `jdoe`'s failed attempt counter and overwrites `lastLogin` with the current timestamp in `employee_records.txt`. Because anyone can trigger `SelfTest` from the unauthenticated menu (option 3) or CLI (`test`), an attacker can tamper with audit timestamps, disrupt live accounts, or cause denial-of-service if `jdoe` has changed their password or if execution is aborted midway through the test.

**Fix:** Run tests against an isolated, in-memory mock record store rather than the production persistent store. Ensure test data never touches persistent storage.
```java
// Corrected code: Execute self-tests in an isolated temporary record store
        public static boolean runAllTests() {
            System.out.println("Starting Diagnostic Suite in Isolated Mock Store...");
            RecordStore mockStore = new RecordStore("mock_test_records.tmp");
            mockStore.initializeDefaultRecords();
            AuthenticationService testAuth = new AuthenticationService(mockStore);
            try {
                // Execute tests against testAuth and mockStore
                return executeTestCases(testAuth, mockStore);
            } finally {
                try { Files.deleteIfExists(Paths.get("mock_test_records.tmp")); } catch (IOException ignored) {}
            }
        }
```

---

### SEC-09: Flawed Administrative Privilege Assignment Based on Department String
- **Severity:** Low
- **CWE:** CWE-285: Improper Authorization
- **Location:** `EmployeePortalAuth.java:597-598`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:597-598
            boolean isAdmin = "Information Security".equalsIgnoreCase(employee.getDepartment()) ||
                              "admin".equalsIgnoreCase(employee.getUsername());
```

**Why it is a problem:** Authorization to administrative portal functions is determined by checking if the user's username is `"admin"` or if their department string equals `"Information Security"`. The actual `role` attribute defined on the `Employee` model is completely ignored. Consequently, any employee assigned to the "Information Security" department (e.g., interns, auditors, HR liaisons) is automatically granted full administrative capabilities, including viewing all employee records, unlocking accounts, and registering new users.

**Fix:** Base authorization checks on an explicit, immutable role or permission authority (e.g., `ROLE_ADMIN`) stored in the employee's role field, rather than loosely checking department names or usernames.
```java
// Corrected code: Authorize based on explicit role attribute
            boolean isAdmin = "ROLE_ADMIN".equalsIgnoreCase(employee.getRole()) ||
                              "ADMINISTRATOR".equalsIgnoreCase(employee.getRole());
```

---

### SEC-10: Incomplete Sanitization Permitting CRLF Record Injection in Serialized Storage
- **Severity:** Low
- **CWE:** CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection')
- **Location:** `EmployeePortalAuth.java:130-136`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:130-136
        private static String escape(String s) {
            return s == null ? "" : s.replace("\\", "\\\\").replace("|", "\\p");
        }

        private static String unescape(String s) {
            return s == null ? "" : s.replace("\\p", "|").replace("\\\\", "\\");
        }
```

**Why it is a problem:** The serialization delimiter escaping mechanism only handles backslashes and pipe characters (`|`). It does not sanitize, escape, or reject carriage return (`\r`) or newline (`\n`) characters. If an employee field (such as `fullName`, `department`, or `role`) contains a newline, serializing the record splits the record across multiple lines, injecting arbitrary lines into `employee_records.txt`. Additionally, the unescaping routine replaces `\\p` with `|` before restoring `\\\\` to `\\`, which corrupts strings containing literal `\p` sequences into `\|`.

**Fix:** Strip or escape newline characters (`\r`, `\n`) in `escape()`, validate fields against strict alphanumeric and safe symbol whitelists during registration, and fix unescaping order.
```java
// Corrected code: Neutralize newlines and properly escape delimiters
        private static String escape(String s) {
            if (s == null) return "";
            return s.replace("\\", "\\\\")
                    .replace("|", "\\p")
                    .replace("\r", "\\r")
                    .replace("\n", "\\n");
        }

        private static String unescape(String s) {
            if (s == null) return "";
            return s.replace("\\n", "\n")
                    .replace("\\r", "\r")
                    .replace("\\p", "|")
                    .replace("\\\\", "\\");
        }
```

## 6. Verified Controls and Checks With No Finding
- Password Hashing Algorithm and Iteration Count: Verified `SecurityUtils.hashPassword` uses `PBKDF2WithHmacSHA256` with 65,536 iterations and a 256-bit derived key length, complying with OWASP and NIST SP 800-63B password storage standards.
- Cryptographic Salt Generation: Verified `SecurityUtils.generateSalt` utilizes `java.security.SecureRandom` to generate unique 128-bit (16-byte) salts per user, preventing rainbow table attacks.
- Constant-Time Hash Comparison: Verified `SecurityUtils.verifyPassword` employs `MessageDigest.isEqual` to compare byte arrays, mitigating side-channel timing attacks against hash comparison.
- Dummy PBKDF2 Computation for Timing Defense: Verified `SecurityUtils.performDummyHash` executes a full PBKDF2 hash cycle on invalid usernames and locked accounts to balance computational latency.
- In-Memory Credential Wiping: Verified `SecurityUtils.wipe` overwrites sensitive `char[]` password arrays and intermediate `byte[]` hash buffers in `handleLogin`, `handleChangePassword`, and `verifyPassword`.
- Password Complexity Enforcement: Verified `SecurityUtils.isPasswordStrong` enforces a minimum length of 8 characters and requires uppercase, lowercase, and digit/special characters.
- Brute-Force Lockout Defense: Verified `AuthenticationService.authenticate` tracks consecutive failed attempts and locks the account when `MAX_FAILED_ATTEMPTS` (3) is reached.
- Thread-Safe Record Store Access: Verified synchronized accessors and mutators (`load`, `save`, `findByUsername`, `put`, `exists`) in `RecordStore` prevent race condition corruption on the internal in-memory map.
