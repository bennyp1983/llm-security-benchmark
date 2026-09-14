# Security Review: Employee Portal Authentication

## 1. Executive Summary
The component is a dependency-free Java command-line employee authentication program. It provisions users into a local credential file, derives password hashes with salted PBKDF2-HMAC-SHA-256, and grants or denies access after checking entered credentials. Four vulnerabilities were identified: the configured PBKDF2 work factor is below current guidance, failed-login throttling can be reset by restarting the process, passwords are visibly echoed when `System.console()` is unavailable, and authentication events are not written to a durable audit trail. The cryptographic construction otherwise uses unique salts, a cryptographically secure random generator, and constant-time hash comparison.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `.gitignore` | Excludes build artifacts and the default credential database from version control. | Reduces accidental disclosure of the password-hash store. |
| `EmployeePortal.java` | Implements employee provisioning, credential persistence, password hashing, and interactive login. | Handles passwords, PBKDF2 parameters, random salts, authentication decisions, login-attempt limits, credential-file parsing/writing, and security event output. |
| `README.md` | Documents compilation, employee provisioning, sign-in, and production limitations. | Warns that the credential file is sensitive and calls out missing production controls. |
| `cyber_prompt.txt` | Records the security-review task and required report format. | Contains no executable behaviour or credentials. |
| `prompt.txt` | Records the original implementation request. | Contains no executable behaviour or credentials. |
| `prompt_hash.txt` | Stores a SHA-256 digest identifying the original prompt. | Contains a non-secret content digest only. |
| `result.md` | Records prior run metadata and an implementation summary. | Contains operational metadata but no application secrets or executable behaviour. |
| `return.txt` | Records the prior tool transcript. | Contains command history and test inputs, including a demonstration password string, but no credential store or active production secret. |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to PBKDF2 algorithm and work-factor selection, salt generation, entropy, password handling, constant-time comparison, and the search for hardcoded secrets or deprecated primitives.
- General OWASP Top 10 / CWE knowledge: Applied to CLI authentication throttling, password-input masking, durable security logging, credential-file parsing and permissions, input validation, resource bounds, path handling, error handling, and concurrency because no specialized library skill matched these non-API Java CLI behaviours.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | PBKDF2 work factor is below current guidance | High | CWE-916 | `EmployeePortal.java:26` |
| SEC-02 | Login-attempt limit resets on every process launch | Medium | CWE-307 | `EmployeePortal.java:63-82` |
| SEC-03 | Passwords are echoed when no system console is available | Low | CWE-549 | `EmployeePortal.java:249-256` |
| SEC-04 | Authentication events lack a durable audit trail | Low | CWE-778 | `EmployeePortal.java:73-81` |

## 5. Detailed Findings

### SEC-01: PBKDF2 work factor is below current guidance
- **Severity:** High
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `EmployeePortal.java:26`

**Vulnerable code:**
```java
// EmployeePortal.java:26
    private static final int PBKDF2_ITERATIONS = 210_000;
```

**Why it is a problem:** New password hashes use PBKDF2-HMAC-SHA-256 with only 210,000 iterations. The current [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) recommends 600,000 or more iterations for PBKDF2-HMAC-SHA-256. If the credential file is disclosed, this setting makes each offline password guess substantially cheaper than the recommended baseline. The risk is amplified because password hashes are portable and can be attacked without invoking the application's three-attempt limit.

**Fix:** Prefer Argon2id with parameters calibrated for the deployment. If PBKDF2 is required, raise the HMAC-SHA-256 work factor to at least 600,000, benchmark it on production hardware, store the selected value per record as the code already does, and rehash older records after successful authentication when their stored work factor is below policy.
```java
private static final int PBKDF2_ITERATIONS = 600_000;
private static final int MIN_PBKDF2_ITERATIONS = 600_000;

// Reject records below policy, or permit them only for a one-time
// successful verification followed immediately by a rehash at the current cost.
if (iterations < MIN_PBKDF2_ITERATIONS) {
    throw new IllegalArgumentException("iteration count is below policy");
}
```

### SEC-02: Login-attempt limit resets on every process launch
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `EmployeePortal.java:63-82`

**Vulnerable code:**
```java
// EmployeePortal.java:63-82
        for (int attempt = 1; attempt <= MAX_LOGIN_ATTEMPTS; attempt++) {
            String username = input.readLine("Username: ").trim();
            char[] password = input.readPassword("Password: ");
            boolean authenticated;
            try {
                authenticated = store.authenticate(username, password);
            } finally {
                java.util.Arrays.fill(password, '\0');
            }

            if (authenticated) {
                System.out.println("Access granted. Welcome, " + username + ".");
                return;
            }

            System.out.println("Access denied. Invalid username or password.");
        }

        System.err.println("Too many failed attempts. Please try again later.");
        System.exit(2);
```

**Why it is a problem:** The counter exists only in the current process. After three failures the program exits, but an attacker can immediately launch it again, run parallel copies, or vary credential-file invocations to obtain unlimited guesses. There is no actual lockout duration, backoff, or account-associated state despite the message asking the user to try later. PBKDF2 increases the cost per guess but does not replace online guess throttling.

**Fix:** Enforce attempt limits in a shared, durable store keyed to the normalized account, with an observation window and temporary lockout or exponential backoff. Updates must be atomic across processes. Clear the failure state after successful authentication, and design the policy so attackers cannot permanently deny service to another employee.
```java
Instant now = Instant.now();
String username = input.readLine("Username: ").trim();
if (attemptStore.isLocked(username, now)) {
    System.out.println("Access denied. Invalid username or password.");
    return;
}

char[] password = input.readPassword("Password: ");
boolean authenticated;
try {
    authenticated = store.authenticate(username, password);
} finally {
    java.util.Arrays.fill(password, '\0');
}

if (authenticated) {
    attemptStore.recordSuccessAtomically(username, now);
    System.out.println("Access granted. Welcome, " + username + ".");
    return;
}
attemptStore.recordFailureAndApplyBackoffAtomically(username, now);
System.out.println("Access denied. Invalid username or password.");
```

### SEC-03: Passwords are echoed when no system console is available
- **Severity:** Low
- **CWE:** CWE-549: Missing Password Field Masking
- **Location:** `EmployeePortal.java:249-256`

**Vulnerable code:**
```java
// EmployeePortal.java:249-256
        char[] readPassword(String prompt) {
            if (console != null) {
                char[] value = console.readPassword("%s", prompt);
                return value == null ? new char[0] : value;
            }
            // Password masking is unavailable when input is redirected or run in some IDEs.
            System.out.print(prompt);
            return scanner.nextLine().toCharArray();
```

**Why it is a problem:** When Java cannot obtain a `Console`—a common case in IDE terminals and some launch environments—the fallback reads the password as an ordinary line. Interactive terminals can echo that line, exposing the password to shoulder surfing, screen capture, terminal recording, or scrollback. The comment acknowledges the loss of masking but the program continues to collect the secret.

**Fix:** Fail closed for interactive password entry when a secure console is unavailable. If automation is required, use a deliberately configured protected secret source rather than silently downgrading to echoed standard input.
```java
char[] readPassword(String prompt) {
    if (console == null) {
        throw new IllegalStateException(
                "Secure password input is unavailable; run from a protected terminal.");
    }
    char[] value = console.readPassword("%s", prompt);
    return value == null ? new char[0] : value;
}
```

### SEC-04: Authentication events lack a durable audit trail
- **Severity:** Low
- **CWE:** CWE-778: Insufficient Logging
- **Location:** `EmployeePortal.java:73-81`

**Vulnerable code:**
```java
// EmployeePortal.java:73-81
            if (authenticated) {
                System.out.println("Access granted. Welcome, " + username + ".");
                return;
            }

            System.out.println("Access denied. Invalid username or password.");
        }

        System.err.println("Too many failed attempts. Please try again later.");
```

**Why it is a problem:** Successes, failures, and exhaustion of the attempt limit are printed only to the current terminal. They are not emitted to a durable, access-controlled audit destination, so repeated guessing and account misuse cannot reliably be detected, correlated, or investigated. This gap is particularly relevant because the in-process attempt limit is bypassable. Passwords must never be included in such events.

**Fix:** Send structured authentication success, failure, and throttling events to an access-controlled audit sink. Include a timestamp, event type, outcome, and a safe account identifier; sanitize control characters and avoid passwords or password hashes. Configure retention, monitoring, and alerting outside the process.
```java
String auditUser = username.replaceAll("[\\r\\n\\t]", "_");
if (authenticated) {
    auditLogger.record("AUTHENTICATION_SUCCESS", auditUser, Instant.now());
    System.out.println("Access granted. Welcome, " + username + ".");
    return;
}

auditLogger.record("AUTHENTICATION_FAILURE", auditUser, Instant.now());
System.out.println("Access denied. Invalid username or password.");
```

## 6. Verified Controls and Checks With No Finding
- Password storage algorithm: `EmployeePortal.java:226-234` uses PBKDF2-HMAC-SHA-256 rather than reversible encryption or a fast general-purpose hash; only the work factor is deficient as reported in SEC-01.
- Salt generation: `EmployeePortal.java:177-182` generates a fresh 16-byte salt for each record using `SecureRandom`.
- Password comparison and username enumeration: `EmployeePortal.java:165-175` performs comparable PBKDF2 work for unknown users, returns a generic failure to callers, and compares derived hashes with `MessageDigest.isEqual`.
- Secret lifetime: `EmployeePortal.java:67-71`, `EmployeePortal.java:107-120`, and `EmployeePortal.java:228-234` clear password arrays and the `PBEKeySpec` in `finally` blocks.
- Hardcoded secrets and weak primitives: No hardcoded production password, encryption key, token, MD5, SHA-1, DES, RC4, or ECB use was found in the application source or supporting files. The demonstration string in `return.txt` is transcript test data and is not referenced by the application.
- Credential record validation: `EmployeePortal.java:135-160` rejects malformed records, invalid usernames, short salts/hashes, low iteration values, and duplicate usernames. The minimum accepted iteration count should nevertheless be raised alongside SEC-01's fix.
- Username and record-delimiter injection: `EmployeePortal.java:24` and `EmployeePortal.java:92-97` restrict provisioned usernames to a bounded allowlist that excludes the colon record separator and control characters.
- Authentication response disclosure: `EmployeePortal.java:78` uses the same user-facing error for an unknown username and an incorrect password.
- Credential-file update integrity: `EmployeePortal.java:203-214` writes through a temporary file and prefers an atomic replacement, reducing partial-file exposure on interruption; the fallback replacement is used only when atomic moves are unsupported.
- Source-control exposure: `.gitignore:1-2` excludes compiled classes and the default `employees.db` credential store, while `README.md:38-40` explicitly directs operators to restrict store access and use secure backups.
- Injection and network attack surface: The component constructs no SQL, invokes no operating-system commands, performs no deserialization of Java objects, renders no HTML, and makes no network or TLS connections; SQL injection, command injection, unsafe deserialization, XSS, SSRF, and TLS configuration therefore did not apply.
