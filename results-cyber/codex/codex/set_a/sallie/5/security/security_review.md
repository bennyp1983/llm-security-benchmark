# Security Review: Employee Portal Authentication

## 1. Executive Summary
The component is a Java console authentication program that loads one employee credential, stores a salted PBKDF2 hash in memory, verifies login attempts, and locks an account for fifteen minutes after five failures. The review found six vulnerabilities: the PBKDF2 work factor is below current guidance, arbitrarily weak passwords are accepted, the bootstrap password is passed through an environment variable, lockout responses disclose account state, a non-console fallback echoes passwords, and locked-account checks have a measurable timing difference. Positive controls include cryptographically random per-record salts, constant-time hash comparison, generic errors for ordinary invalid credentials, password-array clearing, and synchronized lockout updates.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `EmployeePortal.java` | Implements the console login application, in-memory employee store, authentication service, lockout state, and password hasher. | Reads credentials from the environment and terminal, hashes passwords with salted PBKDF2-HMAC-SHA-256, compares hashes, reports authentication state, and synchronizes failed-attempt updates. |
| `README.md` | Documents requirements, startup, credential configuration, input behaviour, and production-store guidance. | Directs operators to supply the initial password through an environment variable, warns that some consoles echo input, and calls for transactional lockout updates in a production store. |
| `cyber_prompt.txt` | Records the security-review request and required report format. | Non-executable; contains no credentials or application behaviour. |
| `prompt.txt` | Records the original implementation requirements. | Non-executable; specifies password authentication and protection against unlimited consecutive guesses. |
| `prompt_hash.txt` | Stores a hash identifying the original prompt. | Non-executable; contains a digest but no authentication or cryptographic application logic. |
| `result.md` | Summarizes the earlier implementation run and claimed checks. | Non-executable; describes password hashing, lockout, environment-based credentials, and test outcomes without containing a real secret. |
| `return.txt` | Stores the earlier agent transcript and command metadata. | Non-executable; includes example credentials and shell commands, but the values are demonstrative rather than live secrets. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: used to inventory every file, understand the application, identify security-relevant behaviours, route the review to matching specialized guidance, and require CWE and line-level evidence.
- `performing-cryptographic-audit-of-application`: applied to PBKDF2 algorithm and work-factor selection, salt entropy, secret sourcing, password handling, and constant-time comparison.
- General OWASP Top 10 / CWE knowledge: applied to password requirements, environment-variable exposure, authentication-response uniformity, password masking, timing discrepancies, account lockout, and concurrency because no closer source-review skill matched those behaviours.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | PBKDF2 work factor is below current guidance | Medium | CWE-916 | `EmployeePortal.java:249` |
| SEC-02 | Arbitrarily weak passwords are accepted | Medium | CWE-521 | `EmployeePortal.java:213-216` |
| SEC-03 | Bootstrap password is stored in an environment variable | Medium | CWE-526 | `EmployeePortal.java:31-40` |
| SEC-04 | Distinct lockout response enables account enumeration | Low | CWE-203 | `EmployeePortal.java:91-100` |
| SEC-05 | Fallback input echoes the password | Low | CWE-549 | `EmployeePortal.java:74-84` |
| SEC-06 | Locked accounts have a distinguishable authentication time | Low | CWE-208 | `EmployeePortal.java:168-177` |

## 5. Detailed Findings

### SEC-01: PBKDF2 work factor is below current guidance
- **Severity:** Medium
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `EmployeePortal.java:249`

**Vulnerable code:**
```java
// EmployeePortal.java:249
        private static final int ITERATIONS = 210_000;
```

**Why it is a problem:** The application uses PBKDF2-HMAC-SHA-256 with 210,000 iterations. Current OWASP Password Storage Cheat Sheet guidance recommends 600,000 iterations for PBKDF2-HMAC-SHA-256. If the in-memory design is replaced with the documented persistent store and password hashes are later exposed, the lower cost makes each offline password guess materially cheaper. The algorithm, 256-bit derived-key length, unique salt, and secure random generator are otherwise appropriate.

**Fix:** Benchmark the deployment platform and raise the PBKDF2-HMAC-SHA-256 work factor to at least the current recommended baseline while keeping verification latency acceptable. Store the work factor with each persistent hash so it can be upgraded over time.
```java
        private static final int ITERATIONS = 600_000;
```

### SEC-02: Arbitrarily weak passwords are accepted
- **Severity:** Medium
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `EmployeePortal.java:213-216`

**Vulnerable code:**
```java
// EmployeePortal.java:213-216
        void add(String username, char[] password) {
            if (isBlank(username) || password.length == 0) {
                throw new IllegalArgumentException("Username and password are required");
            }
```

**Why it is a problem:** The only password requirement is that at least one character be present. An operator can therefore configure a trivially guessed employee password. The online lockout slows repeated guesses through this program, but it does not make a weak password safe and does not protect a copied password hash from offline guessing.

**Fix:** Enforce an organization-approved minimum length and reject excessively long input to bound resource use. For a password-only login, a minimum of 15 characters is a suitable baseline; also screen new passwords against known-compromised values where the deployment supports it.
```java
        void add(String username, char[] password) {
            if (isBlank(username) || password == null
                    || password.length < 15 || password.length > 128) {
                throw new IllegalArgumentException(
                        "A username and a password of 15 to 128 characters are required");
            }
```

### SEC-03: Bootstrap password is stored in an environment variable
- **Severity:** Medium
- **CWE:** CWE-526: Cleartext Storage of Sensitive Information in an Environment Variable
- **Location:** `EmployeePortal.java:31-40`

**Vulnerable code:**
```java
// EmployeePortal.java:31-40
        String initialUsername = System.getenv("EMPLOYEE_USERNAME");
        String initialPassword = System.getenv("EMPLOYEE_PASSWORD");
        if (isBlank(initialUsername) || isBlank(initialPassword)) {
            System.err.println(
                    "Set EMPLOYEE_USERNAME and EMPLOYEE_PASSWORD before starting the portal.");
            System.exit(1);
            return;
        }

        char[] initialPasswordChars = initialPassword.toCharArray();
```

**Why it is a problem:** The cleartext password is inherited through the process environment, where same-context processes, child processes, crash diagnostics, support tooling, or accidental environment logging may expose it. Java also materializes it as an immutable `String`, so clearing `initialPasswordChars` does not erase the original password object. The README's `export` workflow can additionally cause real values to be retained in shell history depending on how an operator enters the command.

**Fix:** Obtain the bootstrap password from a protected secret provider or masked console input directly into a mutable `char[]`. Do not place it in an environment variable or immutable `String`, and clear the array after hashing.
```java
        Console bootstrapConsole = System.console();
        if (bootstrapConsole == null) {
            throw new IllegalStateException("A secure console is required for initialization");
        }
        String initialUsername = bootstrapConsole.readLine("Initial employee username: ");
        char[] initialPasswordChars = bootstrapConsole.readPassword(
                "Initial employee password: ");
        if (isBlank(initialUsername) || initialPasswordChars == null) {
            throw new IllegalArgumentException("Username and password are required");
        }
        try {
            store.add(initialUsername.trim(), initialPasswordChars);
        } finally {
            Arrays.fill(initialPasswordChars, '\0');
        }
```

### SEC-04: Distinct lockout response enables account enumeration
- **Severity:** Low
- **CWE:** CWE-203: Observable Discrepancy
- **Location:** `EmployeePortal.java:91-100`

**Vulnerable code:**
```java
// EmployeePortal.java:91-100
                    if (result.status == AuthenticationStatus.AUTHENTICATED) {
                        System.out.println("Access granted.");
                        return;
                    }
                    if (result.status == AuthenticationStatus.LOCKED) {
                        System.out.println("Access denied. This account is temporarily locked."
                                + " Try again in " + result.retryAfterSeconds + " seconds.");
                    } else {
                        System.out.println("Access denied. Invalid username or password.");
                    }
```

**Why it is a problem:** Unknown usernames always receive the invalid-credentials text, while a valid username produces a lockout-specific message and countdown after five failures. A user who can operate the prompt can test candidate usernames and distinguish registered employees, improving the targeting of password guessing or social engineering. The exact remaining lockout duration also exposes internal authentication state.

**Fix:** Return the same public message for every failed authentication state. If lockout details are operationally necessary, send them through a separate trusted notification channel or protected audit log rather than the unauthenticated prompt.
```java
                    if (result.status == AuthenticationStatus.AUTHENTICATED) {
                        System.out.println("Access granted.");
                        return;
                    }
                    System.out.println("Access denied. Invalid username or password.");
```

### SEC-05: Fallback input echoes the password
- **Severity:** Low
- **CWE:** CWE-549: Missing Password Field Masking
- **Location:** `EmployeePortal.java:74-84`

**Vulnerable code:**
```java
// EmployeePortal.java:74-84
                } else {
                    System.out.print("Username: ");
                    if (!scanner.hasNextLine()) {
                        return;
                    }
                    username = scanner.nextLine();
                    System.out.print("Password: ");
                    if (!scanner.hasNextLine()) {
                        return;
                    }
                    password = scanner.nextLine().toCharArray();
```

**Why it is a problem:** When `System.console()` is unavailable, `Scanner.nextLine()` reads a visibly echoed password from standard input. The password can be observed over the user's shoulder, captured in a terminal transcript, or retained by an IDE/development console. Documentation acknowledges the behaviour, but warning users does not protect the credential.

**Fix:** Fail closed when masked terminal input is unavailable, or use a reviewed terminal library that disables echo. Never silently downgrade password entry to an echoed input path.
```java
        Console console = System.console();
        if (console == null) {
            System.err.println("A secure, password-masking console is required.");
            return;
        }

        while (true) {
            String username = console.readLine("Username: ");
            if (username == null) {
                return;
            }
            char[] password = console.readPassword("Password: ");
            if (password == null) {
                return;
            }
```

### SEC-06: Locked accounts have a distinguishable authentication time
- **Severity:** Low
- **CWE:** CWE-208: Observable Timing Discrepancy
- **Location:** `EmployeePortal.java:168-177`

**Vulnerable code:**
```java
// EmployeePortal.java:168-177
            // Do real password-hashing work even when the username does not exist.
            if (record == null) {
                PasswordHasher.matches(password, dummySalt, dummyHash);
                return AuthenticationResult.invalid();
            }

            if (record.lockedUntil != null && now.isBefore(record.lockedUntil)) {
                long remaining = Math.max(1,
                        Duration.between(now, record.lockedUntil).getSeconds());
                return AuthenticationResult.locked(remaining);
```

**Why it is a problem:** Unknown users perform a full PBKDF2 calculation, but known locked users return without one. Even after SEC-04's visible messages are unified, this large processing-time difference lets an observer distinguish locked valid accounts from unknown usernames. Raising the PBKDF2 work factor as recommended in SEC-01 makes the difference more pronounced.

**Fix:** Perform one password-hash verification on every authentication path, including active lockouts, while continuing to reject the request regardless of whether the supplied password was correct.
```java
            if (record == null) {
                PasswordHasher.matches(password, dummySalt, dummyHash);
                return AuthenticationResult.invalid();
            }

            if (record.lockedUntil != null && now.isBefore(record.lockedUntil)) {
                PasswordHasher.matches(password, record.salt, record.passwordHash);
                long remaining = Math.max(1,
                        Duration.between(now, record.lockedUntil).getSeconds());
                return AuthenticationResult.locked(remaining);
            }
```

## 6. Verified Controls and Checks With No Finding
- Unique salt and entropy: each employee receives a 16-byte salt generated by `SecureRandom` at `EmployeePortal.java:217-219` and `EmployeePortal.java:251-260`.
- Password-hash algorithm and size: `PBKDF2WithHmacSHA256` derives 256 bits at `EmployeePortal.java:248-250`; no deprecated digest, cipher, or insecure mode is used.
- Constant-time comparison: derived hashes are compared with `MessageDigest.isEqual` at `EmployeePortal.java:276-281`.
- Mutable-secret cleanup: password input, the bootstrap `char[]`, the `PBEKeySpec` copy, and computed comparison hashes are cleared at `EmployeePortal.java:43-45`, `EmployeePortal.java:101-103`, `EmployeePortal.java:271-273`, and `EmployeePortal.java:278-282`; SEC-03 separately covers the immutable environment `String`.
- Ordinary invalid-login uniformity: nonexistent users perform dummy PBKDF2 work at `EmployeePortal.java:168-171`, and non-locked unknown and known users receive the same message at `EmployeePortal.java:98-100`; SEC-04 and SEC-06 cover the lockout exceptions.
- Guess restriction: five consecutive failures produce a fifteen-minute per-account lockout, successful authentication resets failures, and guesses during lockout are rejected at `EmployeePortal.java:22-23` and `EmployeePortal.java:174-200`.
- Concurrent in-process updates: the complete read/check/update operation is synchronized at `EmployeePortal.java:163-201`, preventing concurrent calls through this service instance from bypassing the attempt threshold.
- Record encapsulation: salts and hashes are cloned on record construction at `EmployeePortal.java:240-244`, preventing the caller's original arrays from mutating stored values.
- Hardcoded secrets: no live password, key, token, or credential is embedded in the source or ancillary files; literals in examples and the dummy-hash input are non-secret.
- Injection and unsafe I/O surfaces: the reviewed code performs no SQL queries, OS command execution, path access, deserialization, outbound network calls, TLS configuration, HTML rendering, or dynamic code loading.
