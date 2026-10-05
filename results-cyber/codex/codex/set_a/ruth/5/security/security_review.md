# Security Review: Java Console Login Application

## 1. Executive Summary

The component is a dependency-free Java console application that authenticates one in-memory demo account, hashes its password with salted PBKDF2-HMAC-SHA-256, and temporarily locks the account after five failures. Three vulnerabilities were identified: the distinct lockout response enables username enumeration, the working demo credential is hard-coded and disclosed, and the fallback input path does not mask passwords. The password hashing, comparison, credential-failure message, mutable password cleanup, and synchronized lockout-state updates were otherwise implemented defensively.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `LoginApplication.java` | Implements console input, account storage, password hashing, authentication, and temporary lockout. | Accepts credentials; embeds a demo credential; uses PBKDF2, random salts, and constant-time comparison; tracks failures; reveals lockout state; falls back to visible password input. |
| `README.md` | Documents the application, demo credential, build/run procedure, and production caveats. | Publicly repeats the working credential and describes security controls and operational limitations. |
| `cyber_prompt.txt` | Records the instructions for this security review. | Contains no executable behavior or application secrets. |
| `prompt.txt` | Records the original implementation request. | Defines authentication and repeated-failure requirements but contains no executable behavior. |
| `prompt_hash.txt` | Stores a hash identifying the original prompt. | Contains no executable behavior or credential material. |
| `result.md` | Records prior run metadata and an implementation summary. | Describes claimed security controls but contains no executable behavior or secrets. |
| `return.txt` | Stores a transcript of the prior implementation and validation run. | Contains build/test commands and output, including the demo credential as part of a test command. |

## 3. Skills Applied

- `performing-cryptographic-audit-of-application`: Applied to the password KDF algorithm and parameters, salt generation, secret handling, hard-coded password, and hash comparison.
- `testing-for-sensitive-data-exposure`: Applied to credential disclosure in source/documentation/output and masking of password input.
- General OWASP Top 10 / CWE knowledge: Applied to authentication response consistency, username enumeration, account lockout state handling, denial-of-service exposure, input handling, and concurrency because no specialized application-code skill closely matched those behaviors.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Lockout response enables username enumeration | Medium | CWE-204 | `LoginApplication.java:69` |
| SEC-02 | Working account credential is hard-coded | Medium | CWE-798 | `LoginApplication.java:33` |
| SEC-03 | Fallback password input is not masked | Low | CWE-549 | `LoginApplication.java:90` |

## 5. Detailed Findings

### SEC-01: Lockout response enables username enumeration

- **Severity:** Medium
- **CWE:** CWE-204: Observable Response Discrepancy
- **Location:** `LoginApplication.java:69-73`

**Vulnerable code:**
```java
// LoginApplication.java:69-73
                case INVALID_CREDENTIALS -> System.out.println(
                        "Access denied: invalid username or password.");
                case LOCKED -> System.out.println(
                        "Access denied: account temporarily locked. Try again in "
                                + result.retryAfterSeconds() + " second(s).");
```

**Why it is a problem:** Unknown usernames always produce `INVALID_CREDENTIALS`, while a real username produces the distinguishable `LOCKED` response after five bad attempts. An attacker can therefore test candidate usernames, make five guesses for each, and identify registered accounts from the response. The same behavior also tells an attacker exactly when to resume attempts and facilitates targeted account-lockout denial of service.

**Fix:** Enforce lockout internally but return the same externally observable response for invalid credentials and locked accounts. If retry timing must be shown, do so only after a separate trusted recovery or authenticated flow.
```java
                case INVALID_CREDENTIALS, LOCKED -> System.out.println(
                        "Access denied: invalid username or password.");
```

### SEC-02: Working account credential is hard-coded

- **Severity:** Medium
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Location:** `LoginApplication.java:33`

**Vulnerable code:**
```java
// LoginApplication.java:33
        accounts.addAccount("demo", "ChangeMe123!".toCharArray());
```

**Why it is a problem:** The only account is initialized with a password available to anyone who can read the source, packaged bytecode, startup output at line 38, README, or prior run transcript. Because this is a working credential rather than a placeholder, knowledge of the repository is sufficient to authenticate whenever the application is run unchanged. Renaming the variable or merely removing the startup message would not remove the credential from the artifact.

**Fix:** Provision the initial password at deployment or prompt for it through a masked channel; never ship or display a default password. The following console-only example obtains the value at startup and erases the caller's buffer after account creation.
```java
        Console console = System.console();
        if (console == null) {
            throw new IllegalStateException("A secure console is required for account setup");
        }

        InMemoryAccountStore accounts = new InMemoryAccountStore();
        char[] initialPassword = console.readPassword("Create password for demo account: ");
        if (initialPassword == null || initialPassword.length == 0) {
            throw new IllegalArgumentException("password must not be empty");
        }
        try {
            accounts.addAccount("demo", initialPassword);
        } finally {
            Arrays.fill(initialPassword, '\0');
        }
```

### SEC-03: Fallback password input is not masked

- **Severity:** Low
- **CWE:** CWE-549: Missing Password Field Masking
- **Location:** `LoginApplication.java:90-92`

**Vulnerable code:**
```java
// LoginApplication.java:90-92
        // IDEs and redirected input do not expose a Console, so input cannot be hidden.
        System.out.print("Password: ");
        return scanner.hasNextLine() ? scanner.nextLine().toCharArray() : null;
```

**Why it is a problem:** When `System.console()` is unavailable, typed passwords may be echoed in cleartext by an IDE or terminal and exposed to shoulder surfing, screen recording, or captured console logs. `Scanner.nextLine()` also first creates an immutable `String`, so converting it to a character array does not make every in-memory copy erasable.

**Fix:** Fail closed when a masked console is unavailable, or integrate a trusted terminal library that can disable echo without creating an intermediate `String`. For this dependency-free application, require `Console.readPassword`.
```java
    private static char[] readPassword(Console console, Scanner scanner) {
        if (console == null) {
            throw new IllegalStateException("Masked password input requires an interactive console");
        }
        return console.readPassword("Password: ");
    }
```

## 6. Verified Controls and Checks With No Finding

- Password storage: `LoginApplication.java:189-192` stores only a per-account salt and derived hash, not the submitted plaintext password.
- KDF strength: `LoginApplication.java:213-216` uses PBKDF2-HMAC-SHA-256 with 210,000 iterations and a 256-bit derived key; no deprecated hash or encryption primitive is used.
- Salt and randomness: `LoginApplication.java:217` and `LoginApplication.java:229-232` use `SecureRandom` to generate a fresh 16-byte salt for each account.
- Timing-resistant verification: `LoginApplication.java:248-254` derives the submitted hash and compares it with `MessageDigest.isEqual`; `LoginApplication.java:142-151` also performs expensive verification for unknown and locked accounts.
- Generic ordinary failure message: `LoginApplication.java:69-70` does not distinguish an unknown username from a wrong password before lockout; the separate lockout response is reported in SEC-01.
- Password cleanup: `LoginApplication.java:57-62`, `LoginApplication.java:191`, and `LoginApplication.java:235-245` clear mutable password buffers and the `PBEKeySpec` copy after use. The immutable fallback copy is reported in SEC-03.
- Lockout threshold and expiry: `LoginApplication.java:166-170` enforces five consecutive failures and a 30-second lockout, while `LoginApplication.java:156-159` resets expired state.
- Concurrency safety: `LoginApplication.java:148-173` synchronizes updates per account, and `LoginApplication.java:181-197` synchronizes map access, preventing lost failure-count updates within this process.
- Authentication state reset: `LoginApplication.java:161-163` resets the failure counter after successful authentication.
- Injection and dangerous execution: No SQL/database query construction, deserialization, file/path access, shell command execution, dynamic code loading, network request, TLS configuration, or HTML rendering exists in the application source.
- Error disclosure and logging: Authentication failures return controlled messages and the application does not log submitted passwords, hashes, salts, stack traces, or internal paths.
