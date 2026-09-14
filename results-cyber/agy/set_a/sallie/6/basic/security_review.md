# Security Review: Enterprise Administrator Portal

## 1. Executive Summary
A comprehensive security review was performed on the Enterprise Administrator Portal implementation (`AdminPortal.java`) and associated documentation (`README.md`). The application is a standalone Java console system providing user authentication, Role-Based Access Control (RBAC), user management, system diagnostics, and audit logging. 

While the application implements several strong defensive security practices—such as PBKDF2-HMAC-SHA256 password hashing with 65,536 iterations, per-user CSPRNG salt generation, constant-time hash comparisons, and interactive console password masking—several security vulnerabilities were identified. The most critical vulnerabilities include hardcoded default administrative credentials, path traversal and arbitrary file overwrite in the audit log export functionality, broken access control allowing standard administrators to reset passwords and compromise super administrator accounts (privilege escalation), user enumeration through observable response discrepancies during login, incomplete clearing of sensitive password material in memory via `PBEKeySpec`, and unbounded in-memory audit log growth leading to denial-of-service risks.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `AdminPortal.java` | Core application source code implementing CLI interface, authentication, authorization, user administration, system diagnostics, configuration, and audit logging. | Password hashing with PBKDF2-HMAC-SHA256, salt generation with `SecureRandom`, constant-time verification with `MessageDigest.isEqual`, in-memory user credential storage, account lockout logic, role-based authorization (`SUPER_ADMIN`, `ADMIN`, `STANDARD_USER`), console and scanner password reading, sensitive memory scrubbing, and audit log file export via `FileWriter`. |
| `README.md` | Plain-English user guide and technical architecture documentation. | Documents default demonstration credentials (`admin`, `superadmin`, `johndoe`), describes RBAC policies, and details system security architecture. |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to the cryptographic password hashing implementation (`PBKDF2WithHmacSHA256`, 65,536 iterations, 256-bit derived key length), salt generation with `SecureRandom`, constant-time digest verification with `MessageDigest.isEqual`, and identification of hardcoded credentials in source code.
- `testing-for-broken-access-control`: Applied to the role-based access control (RBAC) model, evaluating function-level access control, vertical privilege escalation vectors between `ADMIN` and `SUPER_ADMIN` in user management functions, and authorization boundaries.
- `performing-directory-traversal-testing`: Applied to the file export functionality in `exportAuditLogsToFile` to assess path traversal and arbitrary file write/overwrite risks against user-supplied filenames.
- `testing-for-sensitive-data-exposure`: Applied to credential handling in source code, plaintext password retention in memory, character array clearing, and scanner fallback.
- General OWASP Top 10 / CWE knowledge: Applied to user enumeration and observable response discrepancies (CWE-204 / CWE-208 / OWASP A07:2021 Identification and Authentication Failures) during login and lockout handling, as well as uncontrolled resource consumption / memory exhaustion (CWE-770 / CWE-400) from unbounded audit log storage.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Hard-coded Default Administrative and User Credentials | High | CWE-798 | `AdminPortal.java:252-263` |
| SEC-02 | Path Traversal and Arbitrary File Overwrite in Audit Log Export | High | CWE-22 | `AdminPortal.java:771-779` |
| SEC-03 | Broken Access Control Permitting Privilege Escalation to Super Administrator | High | CWE-269 | `AdminPortal.java:626-656` |
| SEC-04 | User Enumeration and Information Exposure via Observable Response Discrepancies | Medium | CWE-204 | `AdminPortal.java:365-398` |
| SEC-05 | Incomplete Sensitive Data Scrubbing in Memory via Uncleared KeySpec and String Fallback | Medium | CWE-316 | `AdminPortal.java:215-223` |
| SEC-06 | Unbounded In-Memory Audit Log Storage Causing Potential Resource Exhaustion | Low | CWE-770 | `AdminPortal.java:37` |

## 5. Detailed Findings

### SEC-01: Hard-coded Default Administrative and User Credentials
- **Severity:** High
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Location:** `AdminPortal.java:252-263`

**Vulnerable code:**
```java
// AdminPortal.java:252-263
    private static void seedInitialAccounts() {
        // Pre-seeded Admin account
        createAccountInternal("admin", "Admin@1234!".toCharArray(), Role.ADMIN);

        // Pre-seeded Super Admin account
        createAccountInternal("superadmin", "SuperSecure2026#".toCharArray(), Role.SUPER_ADMIN);

        // Pre-seeded Standard User account (used to test non-admin access denial)
        createAccountInternal("johndoe", "UserPass@2026".toCharArray(), Role.STANDARD_USER);

        logAudit("SYSTEM", "INITIALIZATION", "SUCCESS", "Pre-seeded default admin and test user accounts.");
    }
```

**Why it is a problem:** The application pre-seeds accounts with hardcoded default usernames and passwords (`admin` / `Admin@1234!`, `superadmin` / `SuperSecure2026#`, and `johndoe` / `UserPass@2026`) directly in the source code. Anyone with access to the source code, repository history, or compiled `.class` bytecode can extract these credentials and immediately authenticate with full administrative privileges. Furthermore, passing string literals like `"Admin@1234!".toCharArray()` stores passwords in the immutable JVM String constant pool, preventing the sensitive plaintext from being cleared from memory.

**Fix:** Remove hardcoded credentials from source code. Require interactive provisioning of the initial administrator account on first launch when the user database is empty, or load administrative credentials from a secure external secrets manager or environment configuration:
```java
    private static void seedInitialAccounts() {
        // Do not embed hardcoded credentials in source code.
        // If userDatabase is empty on startup, enforce an initial administrator setup wizard
        // or load bootstrap credentials from an external protected configuration store.
    }
```

---

### SEC-02: Path Traversal and Arbitrary File Overwrite in Audit Log Export
- **Severity:** High
- **CWE:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- **Location:** `AdminPortal.java:771-779`

**Vulnerable code:**
```java
// AdminPortal.java:771-779
        System.out.print("Enter export filename (default: audit_report.log): ");
        String filename = readLine(scanner);
        if (filename == null) return;
        filename = filename.trim();
        if (filename.isEmpty()) {
            filename = "audit_report.log";
        }

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename))) {
```

**Why it is a problem:** In `exportAuditLogsToFile`, the user-supplied `filename` string is passed directly to `new FileWriter(filename)` without path validation, sanitization, or canonicalization. An administrative user (or an attacker with compromised admin credentials) can enter directory traversal sequences (such as `../../../../etc/cron.d/malicious_task` or `../../../../var/www/html/shell.txt`) or absolute file paths. This allows writing arbitrary audit log contents to any writable location on the host filesystem, potentially overwriting critical system configuration files or achieving code execution.

**Fix:** Validate that the filename matches a strict whitelist pattern (e.g. alphanumeric characters and dashes ending in `.log`), resolve the target path against a dedicated base directory, and ensure the normalized path does not escape the designated export folder:
```java
        System.out.print("Enter export filename (default: audit_report.log): ");
        String rawFilename = readLine(scanner);
        if (rawFilename == null) return;
        rawFilename = rawFilename.trim();
        if (rawFilename.isEmpty()) {
            rawFilename = "audit_report.log";
        }

        if (!rawFilename.matches("^[a-zA-Z0-9_-]+\\.log$")) {
            System.out.println("[!] Error: Filename must contain only alphanumeric characters, underscores, or dashes and end with .log");
            return;
        }

        java.nio.file.Path baseDir = java.nio.file.Paths.get("exports").toAbsolutePath().normalize();
        java.nio.file.Path targetPath = baseDir.resolve(rawFilename).normalize();

        if (!targetPath.startsWith(baseDir)) {
            System.out.println("[!] Security Error: Path traversal attempt detected.");
            return;
        }

        try {
            java.nio.file.Files.createDirectories(baseDir);
        } catch (IOException e) {
            System.out.println("[!] Failed to create export directory: " + e.getMessage());
            return;
        }

        try (BufferedWriter writer = java.nio.file.Files.newBufferedWriter(targetPath, StandardCharsets.UTF_8)) {
```

---

### SEC-03: Broken Access Control Permitting Privilege Escalation to Super Administrator
- **Severity:** High
- **CWE:** CWE-269: Improper Privilege Management
- **Location:** `AdminPortal.java:626-656`

**Vulnerable code:**
```java
// AdminPortal.java:626-656
    private static void resetUserPasswordByAdmin(User currentUser, Scanner scanner, Console console) {
        printSubHeader("ADMINISTRATIVE PASSWORD RESET");
        System.out.print("Enter username to reset password: ");
        String targetUsername = readLine(scanner);
        if (targetUsername == null) return;
        targetUsername = targetUsername.trim();

        User target = userDatabase.get(targetUsername);
        if (target == null) {
            System.out.println("[!] User not found.");
            return;
        }

        char[] newPass = readPassword(scanner, console, "Enter new password for " + targetUsername + " (min 8 chars): ");
        if (newPass == null) return;

        if (newPass.length < 8) {
            System.out.println("[!] Password must be at least 8 characters.");
            SecurityUtils.clearPassword(newPass);
            return;
        }

        byte[] newSalt = SecurityUtils.generateSalt();
        byte[] newHash = SecurityUtils.hashPassword(newPass, newSalt);
        SecurityUtils.clearPassword(newPass);

        target.setPassword(newHash, newSalt);
        target.setLocked(false);
        logAudit(currentUser.getUsername(), "PASSWORD_RESET", "SUCCESS", "Password reset for user '" + targetUsername + "'");
        System.out.println("[+] Password for user '" + targetUsername + "' has been successfully reset.");
    }
```

**Why it is a problem:** The application defines a multi-tier role hierarchy (`SUPER_ADMIN`, `ADMIN`, `STANDARD_USER`) and prevents standard administrators from creating `SUPER_ADMIN` accounts in `registerNewUser` (lines 585-591). However, `resetUserPasswordByAdmin` does not enforce hierarchical authorization checks. A user with the standard `ADMIN` role can specify the username of a `SUPER_ADMIN` account (e.g. `superadmin`), assign a new password, and unlock the account. The standard administrator can then log out and log in as `superadmin`, achieving vertical privilege escalation. A similar absence of hierarchy validation exists in `deleteUserAccount` and `toggleAccountLock`, enabling standard administrators to delete or lock super administrator accounts.

**Fix:** Enforce role hierarchy checks across all user administration functions, ensuring that administrators can only manage accounts of strictly lower privilege levels:
```java
    private static void resetUserPasswordByAdmin(User currentUser, Scanner scanner, Console console) {
        printSubHeader("ADMINISTRATIVE PASSWORD RESET");
        System.out.print("Enter username to reset password: ");
        String targetUsername = readLine(scanner);
        if (targetUsername == null) return;
        targetUsername = targetUsername.trim();

        User target = userDatabase.get(targetUsername);
        if (target == null) {
            System.out.println("[!] User not found.");
            return;
        }

        // Prevent standard administrators from resetting super administrator accounts
        if (currentUser.getRole() != Role.SUPER_ADMIN && target.getRole() == Role.SUPER_ADMIN) {
            System.out.println("[!] Access denied: Only a Super Administrator can reset a Super Administrator account.");
            logAudit(currentUser.getUsername(), "PASSWORD_RESET", "DENIED", "Unauthorized attempt to reset Super Admin account: " + targetUsername);
            return;
        }

        char[] newPass = readPassword(scanner, console, "Enter new password for " + targetUsername + " (min 8 chars): ");
        if (newPass == null) return;

        if (newPass.length < 8) {
            System.out.println("[!] Password must be at least 8 characters.");
            SecurityUtils.clearPassword(newPass);
            return;
        }

        byte[] newSalt = SecurityUtils.generateSalt();
        byte[] newHash = SecurityUtils.hashPassword(newPass, newSalt);
        SecurityUtils.clearPassword(newPass);

        target.setPassword(newHash, newSalt);
        target.setLocked(false);
        logAudit(currentUser.getUsername(), "PASSWORD_RESET", "SUCCESS", "Password reset for user '" + targetUsername + "'");
        System.out.println("[+] Password for user '" + targetUsername + "' has been successfully reset.");
    }
```

---

### SEC-04: User Enumeration and Information Exposure via Observable Response Discrepancies
- **Severity:** Medium
- **CWE:** CWE-204: Observable Response Discrepancy
- **Location:** `AdminPortal.java:365-398`

**Vulnerable code:**
```java
// AdminPortal.java:365-398
        if (user == null) {
            byte[] dummySalt = SecurityUtils.generateSalt();
            SecurityUtils.hashPassword(password, dummySalt);
            logAudit(username, "AUTHENTICATION", "FAILURE", "Unknown username provided.");
            System.out.println("\n[X] ACCESS DENIED: Invalid username or password.");
            return;
        }

        // Check if account is locked
        if (user.isLocked()) {
            logAudit(username, "AUTHENTICATION", "FAILURE", "Login rejected; account is locked.");
            System.out.println("\n[X] ACCESS DENIED: Account is LOCKED due to excessive failed attempts.");
            System.out.println("    Please contact a Super Administrator to unlock this account.");
            return;
        }

        // Verify credentials
        boolean isMatch = SecurityUtils.verifyPassword(password, user.getSalt(), user.getPasswordHash());

        if (!isMatch) {
            user.incrementFailedAttempts();
            int remaining = MAX_FAILED_ATTEMPTS - user.getFailedAttempts();

            if (user.getFailedAttempts() >= MAX_FAILED_ATTEMPTS) {
                user.setLocked(true);
                logAudit(username, "ACCOUNT_LOCKOUT", "WARNING", "Account locked after " + MAX_FAILED_ATTEMPTS + " consecutive failed attempts.");
                System.out.println("\n[X] ACCESS DENIED: Invalid credentials.");
                System.out.println("[!] SECURITY ALERT: Account '" + username + "' has been LOCKED due to " + MAX_FAILED_ATTEMPTS + " consecutive failed attempts.");
            } else {
                logAudit(username, "AUTHENTICATION", "FAILURE", "Incorrect password. Attempt " + user.getFailedAttempts() + "/" + MAX_FAILED_ATTEMPTS);
                System.out.println("\n[X] ACCESS DENIED: Invalid username or password.");
                System.out.println("    Warning: " + remaining + " attempt(s) remaining before account lockout.");
            }
            return;
        }
```

**Why it is a problem:** Although the implementation attempts to mitigate user enumeration timing attacks by running a dummy hash when `user == null`, it exposes observable behavioral differences that completely defeat this mitigation:
1. When an invalid username is submitted, only `[X] ACCESS DENIED: Invalid username or password.` is returned.
2. When a valid username is submitted with an incorrect password, it displays `Warning: X attempt(s) remaining before account lockout.`
3. When an account is locked, it immediately displays `[X] ACCESS DENIED: Account is LOCKED due to excessive failed attempts.`, bypassing password verification entirely (which also creates a significant timing difference).
4. When valid credentials for a standard user are provided, line 405 discloses: `Role 'Standard User' does not have administrative privileges.`
An external attacker can probe usernames and definitively determine valid registered accounts on the system based on these distinct messages.

**Fix:** Standardize all authentication failure messages to a single generic response (`[X] ACCESS DENIED: Invalid username or password.`) regardless of whether the account exists, is locked, or had an incorrect password. Always perform password verification or dummy hashing consistently:
```java
        byte[] saltToUse = (user != null) ? user.getSalt() : SecurityUtils.generateSalt();
        byte[] hashToUse = (user != null) ? user.getPasswordHash() : SecurityUtils.hashPassword(password, saltToUse);

        boolean isMatch = SecurityUtils.verifyPassword(password, saltToUse, hashToUse);

        if (user == null || user.isLocked() || !isMatch) {
            if (user != null && !user.isLocked()) {
                user.incrementFailedAttempts();
                if (user.getFailedAttempts() >= MAX_FAILED_ATTEMPTS) {
                    user.setLocked(true);
                    logAudit(username, "ACCOUNT_LOCKOUT", "WARNING", "Account locked after consecutive failed attempts.");
                } else {
                    logAudit(username, "AUTHENTICATION", "FAILURE", "Incorrect password.");
                }
            } else if (user != null && user.isLocked()) {
                logAudit(username, "AUTHENTICATION", "FAILURE", "Login rejected; account is locked.");
            } else {
                logAudit(username, "AUTHENTICATION", "FAILURE", "Unknown username provided.");
            }
            System.out.println("\n[X] ACCESS DENIED: Invalid username or password.");
            return;
        }
```

---

### SEC-05: Incomplete Sensitive Data Scrubbing in Memory via Uncleared KeySpec and String Fallback
- **Severity:** Medium
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory of a Resource
- **Location:** `AdminPortal.java:215-223`

**Vulnerable code:**
```java
// AdminPortal.java:215-223
        public static byte[] hashPassword(char[] password, byte[] salt) {
            try {
                KeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);
                SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
                return factory.generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new SecurityException("Cryptographic algorithm unavailable for password hashing", e);
            }
        }
```

**Why it is a problem:** `PBEKeySpec` creates an internal copy of the provided `password` character array. Under the Java Cryptography Architecture (JCA), `PBEKeySpec.clearPassword()` must be explicitly called to overwrite this internal buffer with zeros after the key has been generated. Because `spec.clearPassword()` is omitted, the copied password remains in the JVM heap inside the `PBEKeySpec` object until garbage collected. Additionally, in `readPassword` (lines 938-940), when `System.console()` is unavailable, the fallback code invokes `scanner.nextLine().toCharArray()`, creating an immutable `java.lang.String` in heap memory that cannot be erased with `Arrays.fill()`.

**Fix:** Add a `finally` block in `SecurityUtils.hashPassword` to invoke `spec.clearPassword()`:
```java
        public static byte[] hashPassword(char[] password, byte[] salt) {
            PBEKeySpec spec = null;
            try {
                spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);
                SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
                return factory.generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new SecurityException("Cryptographic algorithm unavailable for password hashing", e);
            } finally {
                if (spec != null) {
                    spec.clearPassword();
                }
            }
        }
```

---

### SEC-06: Unbounded In-Memory Audit Log Storage Causing Potential Resource Exhaustion
- **Severity:** Low
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `AdminPortal.java:37`

**Vulnerable code:**
```java
// AdminPortal.java:37
    private static final List<AuditLogEntry> auditLogs = new ArrayList<>();
```

**Why it is a problem:** All events—including failed authentication attempts with nonexistent usernames—are appended to the `auditLogs` list via `logAudit(...)` (lines 272-275). Because this list has no maximum capacity, retention policy, or eviction mechanism, automated authentication attempts or continuous operation can cause unbounded memory growth, potentially leading to `OutOfMemoryError` and application crashes (Denial of Service).

**Fix:** Bound the in-memory audit log list with a maximum entry cap or eviction policy (such as a bounded queue or circular buffer), or stream audit logs directly to a rotated log file:
```java
    private static final int MAX_AUDIT_LOGS = 10000;
    private static final List<AuditLogEntry> auditLogs = Collections.synchronizedList(new ArrayList<AuditLogEntry>() {
        @Override
        public boolean add(AuditLogEntry entry) {
            if (size() >= MAX_AUDIT_LOGS) {
                remove(0);
            }
            return super.add(entry);
        }
    });
```

## 6. Verified Controls and Checks With No Finding
- **Password Hashing Algorithm and Iterations**: Verified in `SecurityUtils.hashPassword` (lines 204-206) that the application uses `PBKDF2WithHmacSHA256` with 65,536 iterations and a 256-bit derived key length, meeting modern standards for password stretching against offline brute-force attacks.
- **Cryptographically Secure Salt Generation**: Verified in `SecurityUtils.generateSalt` (lines 209-213) that a unique 16-byte (128-bit) salt is generated using `java.security.SecureRandom` for each new user and password reset.
- **Timing-Safe Hash Comparison**: Verified in `SecurityUtils.verifyPassword` (lines 229-232) that `MessageDigest.isEqual` is employed to perform constant-time comparisons of password hashes, preventing timing side-channel attacks against digest evaluation.
- **Interactive Password Masking**: Verified in `readPassword` (lines 932-935) that `System.console().readPassword()` is utilized in interactive terminal sessions to prevent shoulder-surfing and terminal history exposure.
- **Caller Memory Scrubbing**: Verified in `handleLoginFlow` (lines 353-355), `registerNewUser` (lines 562, 569-573), and `handleChangeAdminPassword` (lines 847, 860, 867-871, 875) that caller password character arrays are zeroed using `SecurityUtils.clearPassword()` in `finally` blocks and after hashing.
- **Account Lockout Threshold**: Verified in `authenticateAndRoute` (lines 384-399) that accounts are locked after 3 consecutive failed authentication attempts, mitigating online password guessing attacks against targeted accounts.
- **Username Input Validation**: Verified in `registerNewUser` (lines 547-550) that usernames must conform to `^[a-zA-Z0-9_-]{3,20}$`, preventing command injection, format string issues, or directory traversal via usernames.
- **Self-Modification Safeguards**: Verified in `toggleAccountLock` (lines 612-615) and `deleteUserAccount` (lines 665-668) that logged-in administrators cannot lock or delete their own accounts during an active session.
- **Non-Admin Gateway Access Denial**: Verified in `authenticateAndRoute` (lines 401-408) that accounts lacking administrative rights (`STANDARD_USER`) are strictly prevented from accessing the administrative session menu (`runAdminSession`), even after presenting valid credentials.
