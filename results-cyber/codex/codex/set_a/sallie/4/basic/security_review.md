# Security Review: User Account App

## 1. Executive Summary
The component is a Java 17 command-line account manager that registers users, stores salted password hashes in a local properties file, and verifies later login attempts. It uses several sound primitives, including `SecureRandom`, per-account salts, PBKDF2-HMAC-SHA-256, and constant-time hash comparison. Five vulnerabilities were identified: the PBKDF2 work factor is below current guidance; eight-character passwords are accepted without any strength screening; login attempts are unlimited; password input is visibly echoed when no system console is available; and owner-only permissions are not explicitly required for the credential file. The first issue materially reduces resistance to offline password cracking, while the remaining issues weaken online authentication or local credential confidentiality.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `UserAccountApp.java` | Implements registration, persistent account storage, and password authentication. | Accepts usernames and passwords; generates salts; derives PBKDF2 hashes; parses stored hash parameters; compares credentials; reads and atomically replaces a local credential file. |
| `README.md` | Documents requirements, operation, credential storage, and limitations. | Warns that fallback password entry may be visible and that the credential file must be kept private; identifies production controls that are absent. |
| `.gitignore` | Prevents generated artifacts from being committed. | Excludes `credentials.properties` and compiled `.class` files from version control. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Used to inventory the component, identify security-relevant behaviours, route them to specialized skills, and require CWE-tagged file-and-line evidence.
- `performing-cryptographic-audit-of-application`: Applied to the password KDF, iteration count, salt generation, random-number generation, secret handling, and hash comparison.
- General OWASP Top 10 / CWE knowledge: Applied to password policy, excessive authentication attempts, terminal password masking, persisted-input handling, local file permissions, input validation, error handling, and file-update safety because no clearly matching specialized skill covered these non-API CLI behaviours.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | PBKDF2 work factor is below current guidance | High | CWE-916 | `UserAccountApp.java:23` |
| SEC-02 | Weak passwords are accepted | Medium | CWE-521 | `UserAccountApp.java:79-84` |
| SEC-03 | Authentication attempts are unlimited | Medium | CWE-307 | `UserAccountApp.java:49-64` |
| SEC-04 | Passwords are echoed when no secure console is available | Low | CWE-549 | `UserAccountApp.java:189-195` |
| SEC-05 | Credential-file permissions are not explicitly restricted | Low | CWE-732 | `UserAccountApp.java:138-148` |

## 5. Detailed Findings

### SEC-01: PBKDF2 work factor is below current guidance
- **Severity:** High
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `UserAccountApp.java:23`

**Vulnerable code:**
```java
// UserAccountApp.java:23
    private static final int PBKDF2_ITERATIONS = 210_000;
```

**Why it is a problem:** The application stores password hashes where anyone who obtains `credentials.properties` can make guesses offline. Its PBKDF2-HMAC-SHA-256 work factor is 210,000 iterations, substantially below the current [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) recommendation of 600,000 iterations. This makes each offline guess cheaper than the recommended baseline, compounding the risk from weak user-selected passwords. The work factor should also be benchmarked on supported hardware and increased over time.

**Fix:** Raise the PBKDF2-HMAC-SHA-256 work factor to at least the current baseline, benchmark it so interactive verification remains practical, and rehash older records after a successful login when their stored iteration count is lower.
```java
private static final int PBKDF2_ITERATIONS = 600_000;
```

### SEC-02: Weak passwords are accepted
- **Severity:** Medium
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `UserAccountApp.java:79-84`

**Vulnerable code:**
```java
// UserAccountApp.java:79-84
        char[] password = readPassword("Password: ");
        try {
            if (password == null || password.length < 8) {
                System.out.println("The password must contain at least 8 characters.");
                return;
            }
```

**Why it is a problem:** This check accepts easily guessed values such as eight repeated characters and the application has no MFA. Current [OWASP authentication guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) treats passwords shorter than 15 characters as weak when MFA is absent and also recommends blocking common or compromised passwords. Weak passwords increase both online guessing risk and the chance that a disclosed stored hash can be cracked.

**Fix:** Require at least 15 characters in this password-only design, allow long passphrases, impose a generous upper bound for resource safety, and reject known-compromised passwords using a local blocklist or privacy-preserving breach check.
```java
private static final int MIN_PASSWORD_LENGTH = 15;
private static final int MAX_PASSWORD_LENGTH = 128;

char[] password = readPassword("Password: ");
try {
    if (password == null
            || password.length < MIN_PASSWORD_LENGTH
            || password.length > MAX_PASSWORD_LENGTH
            || isKnownCompromised(password)) {
        System.out.println("Choose a 15-128 character password that is not commonly used or compromised.");
        return;
    }
```

### SEC-03: Authentication attempts are unlimited
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `UserAccountApp.java:49-64`

**Vulnerable code:**
```java
// UserAccountApp.java:49-64
        while (true) {
            System.out.println("\n1. Register a new account");
            System.out.println("2. Log in");
            System.out.println("3. Exit");
            String choice = readLine("Choose an option: ");

            if (choice == null || "3".equals(choice.trim())) {
                System.out.println("Goodbye.");
                return;
            }

            switch (choice.trim()) {
                case "1" -> register();
                case "2" -> authenticate();
                default -> System.out.println("Please enter 1, 2, or 3.");
            }
        }
```

**Why it is a problem:** The menu invokes authentication indefinitely and neither `run` nor `authenticate` records failures, delays retries, or enforces a retry budget. An attacker with access to the program can automate password guesses without application-level restriction. PBKDF2 slows each attempt but is not a substitute for controlling excessive authentication attempts.

**Fix:** Make authentication return its result and enforce a durable, per-account retry policy with progressive delay. Avoid a permanent lockout that would let an attacker deny service to a victim; reset the counter after successful authentication and persist or centrally enforce the policy so restarting the process does not bypass it.
```java
private static final int MAX_FAILED_ATTEMPTS = 5;

private void authenticateWithThrottling() throws IOException, GeneralSecurityException {
    String username = readLine("Username: ");
    LoginThrottle throttle = LoginThrottle.load(username);
    if (!throttle.mayAttemptNow()) {
        System.out.println("Invalid username or password.");
        return;
    }

    boolean authenticated = authenticate(username);
    if (authenticated) {
        throttle.clearFailures();
    } else {
        throttle.recordFailure(MAX_FAILED_ATTEMPTS);
    }
    throttle.save();
    System.out.println(authenticated ? "Authentication successful." : "Invalid username or password.");
}
```

### SEC-04: Passwords are echoed when no secure console is available
- **Severity:** Low
- **CWE:** CWE-549: Missing Password Field Masking
- **Location:** `UserAccountApp.java:189-195`

**Vulnerable code:**
```java
// UserAccountApp.java:189-195
    private char[] readPassword(String prompt) throws IOException {
        if (console != null) {
            return console.readPassword("%s", prompt);
        }
        String password = readLine(prompt);
        return password == null ? null : password.toCharArray();
    }
```

**Why it is a problem:** `System.console()` is commonly unavailable under IDEs, redirected input, and some launchers. In that case `readLine` visibly echoes the password, exposing it to shoulder surfing, terminal capture, or logs. The fallback also first stores the secret in an immutable `String`, which cannot be explicitly erased like the returned `char[]`.

**Fix:** Fail closed when masked input is unavailable, or integrate a terminal library that explicitly disables echo without converting the password to `String`.
```java
private char[] readPassword(String prompt) throws IOException {
    if (console == null) {
        throw new IOException("Secure password entry requires an interactive console.");
    }
    return console.readPassword("%s", prompt);
}
```

### SEC-05: Credential-file permissions are not explicitly restricted
- **Severity:** Low
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `UserAccountApp.java:138-148`

**Vulnerable code:**
```java
// UserAccountApp.java:138-148
    private void saveAccounts() throws IOException {
        Path absoluteFile = CREDENTIAL_FILE.toAbsolutePath();
        Path parent = absoluteFile.getParent();
        Files.createDirectories(parent);
        Path temporaryFile = Files.createTempFile(parent, "credentials-", ".tmp");
        try {
            try (var writer = Files.newBufferedWriter(
                    temporaryFile,
                    StandardCharsets.UTF_8,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                accounts.store(writer, "User credentials: PBKDF2 iteration count, salt, and password hash");
```

**Why it is a problem:** The file contains password hashes and therefore requires owner-only access, but creation supplies no explicit file attributes and relies on provider-, platform-, and environment-dependent defaults. On a filesystem whose defaults permit access by other users, they can copy hashes for offline cracking; writable access also permits credential replacement. Documentation telling users to keep the file private does not enforce the control.

**Fix:** Store credentials in a private application-data directory and atomically create the temporary file with owner-read/owner-write permissions. Apply the equivalent owner-only ACL on non-POSIX platforms and fail closed if restrictive permissions cannot be established.
```java
var ownerOnly = PosixFilePermissions.asFileAttribute(
        PosixFilePermissions.fromString("rw-------"));
Path temporaryFile = Files.createTempFile(
        parent,
        "credentials-",
        ".tmp",
        ownerOnly);
```

## 6. Verified Controls and Checks With No Finding
- Password hashing algorithm and salt: `UserAccountApp.java:86-91` uses a fresh 16-byte salt from `SecureRandom` for each registration and stores a one-way PBKDF2 hash rather than plaintext.
- Hash primitive and output size: `UserAccountApp.java:164-170` uses PBKDF2-HMAC-SHA-256 with a 256-bit derived value; no deprecated MD5, SHA-1, DES, RC4, or ECB security primitive is present.
- Password comparison: `UserAccountApp.java:115-116` uses `MessageDigest.isEqual` rather than an ordinary early-exit array comparison.
- In-memory secret cleanup: `UserAccountApp.java:95-98`, `UserAccountApp.java:121-124`, and `UserAccountApp.java:166-172` clear password-bearing mutable buffers/specifications on normal and exceptional paths. The insecure immutable-`String` fallback is reported separately as SEC-04.
- Authentication response: `UserAccountApp.java:127` returns the same failure message for an unknown username and an incorrect password, limiting username enumeration during login.
- Persisted-record parsing: `UserAccountApp.java:110-120` limits splitting to three fields and treats invalid numeric or Base64 data as failed authentication rather than successful authentication.
- Username handling: `UserAccountApp.java:176-181` rejects null, empty, overlong, and whitespace-containing usernames; `Properties.setProperty`/`store` handles metacharacter escaping rather than constructing the file format manually.
- File-update safety: `UserAccountApp.java:142-160` writes to a uniquely created temporary file, attempts an atomic replacement, provides a fallback when atomic moves are unsupported, and cleans up the temporary file. Permission enforcement is reported separately as SEC-05.
- Source-control exposure: `.gitignore:1-2` excludes both compiled classes and the credential database; no hardcoded passwords, keys, tokens, or other secrets were found in the application source.
- Injection and external-interface review: The component constructs no SQL, executes no operating-system commands, deserializes no objects, and makes no network or TLS calls, so SQL injection, command injection, unsafe deserialization, SSRF, and TLS-validation findings do not apply.
