# Security Review: Internal Employee Portal Authentication

## 1. Executive Summary
The component is a dependency-free Java 17 console authenticator. It provisions salted PBKDF2 password verifiers into a fixed, private credential store, checks proposed passwords against a server-managed compromised-password blocklist, and applies process-local source blocking and per-account backoff during login. Two vulnerabilities were identified. Most importantly, an unauthenticated console user can send end-of-file at the username prompt and terminate the verifier, discarding all in-memory rate-limit state; if the service is restarted, this permits repeated reset-and-retry cycles. Terminal values are also length-checked only after `Console` has buffered a complete line, leaving a local memory-exhaustion path on terminal implementations that do not impose a sufficiently small line limit. No critical or high-severity findings were identified.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `build.sh` | Compiles production and test classes and runs the security test entry point. | Sets a restrictive umask, treats compiler warnings as errors, and executes locally built bytecode without downloading dependencies. |
| `src/main/java/com/acme/portal/Main.java` | Parses the command mode and implements interactive login and credential provisioning. | Reads attacker-controlled terminal input, selects privileged operations, clears password buffers, uses generic failures, and coordinates store locking and updates. |
| `src/main/java/com/acme/portal/Authenticator.java` | Canonicalizes usernames and makes each authentication decision. | Validates usernames and password length, performs dummy password hashing, combines throttling with credential verification, and serializes decisions. |
| `src/main/java/com/acme/portal/CredentialStore.java` | Parses, validates, locks, and atomically replaces the credential store. | Enforces fixed record bounds and syntax, checks file and directory protections, rejects symlinks, clones verifier material, and uses an inter-process update lock. |
| `src/main/java/com/acme/portal/LoginGuard.java` | Tracks failed attempts and computes source blocks and account delays. | Holds process-local rate-limit state, uses monotonic time, bounds retained account keys, and hashes usernames with a random per-process salt. |
| `src/main/java/com/acme/portal/PasswordBlocklist.java` | Loads a fixed list of SHA-256 hashes for common or compromised passwords. | Validates the file type, mode, size, entry count, encoding, uniqueness, and syntax before checking a candidate password. |
| `src/main/java/com/acme/portal/PasswordHasher.java` | Generates salts and derives and compares password verifiers. | Uses `SecureRandom`, PBKDF2-HMAC-SHA-256, fixed salt/hash sizes, constant-time comparison, and temporary-buffer clearing. |
| `src/test/java/com/acme/portal/SecurityTests.java` | Exercises successful and failed authentication and credential-store safety checks. | Creates private temporary stores and tests normalization, unknown/invalid users, oversized passwords, source restriction, file modes, and malformed stores. |
| `build/classes/com/acme/portal/*.class` | Generated production bytecode, including nested record, lock, decision, key, and hash-value classes. | Build artifacts corresponding to the reviewed production source; timestamps show they were generated after the source files. |
| `build/test-classes/com/acme/portal/*.class` | Generated test bytecode and its nested functional interface. | Build artifacts corresponding to the reviewed security test source. |
| `README.md` | Documents deployment, trust assumptions, data formats, and claimed controls. | Defines the single-instance/service-manager threat model, fixed paths, required file protections, and process-local throttling limitation. |
| `prompt.txt`, `cyber_prompt.txt`, `prompt_hash.txt`, `result.md`, `return.txt` | Non-executable task and prior-run metadata. | No runtime security behavior; reviewed for embedded usable secrets and executable content, with none found. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Used as the required router workflow to inventory every source file, identify security-relevant behavior, select specialist skills, and require CWE and file-line evidence.
- `performing-cryptographic-audit-of-application`: Applied to password derivation, salt and random generation, digest use, constant-time comparison, hardcoded-secret checks, and temporary secret handling.
- General OWASP Top 10 / CWE knowledge: Applied to console input bounds, authentication throttling and reset behavior, authorization assumptions, credential-file parsing and permissions, symlink/TOCTOU exposure, error handling, concurrency, command execution, and denial-of-service risks because no non-API specialist skill clearly matched these console and filesystem behaviors.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Console EOF resets authentication throttling | Medium | CWE-307 | `src/main/java/com/acme/portal/Main.java:60-65` |
| SEC-02 | Terminal input is bounded only after allocation | Low | CWE-770 | `src/main/java/com/acme/portal/Main.java:61-65,89-91` |

## 5. Detailed Findings

### SEC-01: Console EOF resets authentication throttling
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/acme/portal/Main.java:60-65`

**Vulnerable code:**
```java
// src/main/java/com/acme/portal/Main.java:60-65
        while (true) {
            String username = console.readLine("Username: ");
            if (username == null) {
                return 1;
            }
            char[] password = console.readPassword("Password: ");
```

**Why it is a problem:** `Console.readLine` returns `null` when the user sends end-of-file (for example, Control-D on Unix). The code treats that attacker-controlled event as a reason to end the supposedly long-running verifier. All failure counters, source-block deadlines, and account delays live only in the current `LoginGuard` object, so termination discards them. An employee can make several guesses, send EOF, and—when the supervisor restarts the service—continue with fresh counters. Without automatic restart, the same behavior is an unauthenticated denial of service. This directly contradicts the design goal that restarting the command must not be a normal retry path. The weakness is especially concrete because the Java console contract explicitly makes EOF user-generatable, while the deployment model gives the employee access to that console.

**Fix:** Do not use terminal EOF as the verifier's shutdown control. Keep the same authenticator alive, apply a bounded delay on EOF, and reserve shutdown for a trusted service-manager signal. For defense against crashes, signals, or mandatory restarts, move the source and account counters into a protected transactional store or an organizational identity provider so a process restart cannot erase them.
```java
        while (true) {
            String username = console.readLine("Username: ");
            if (username == null) {
                // Preserve this process and its LoginGuard state. A trusted
                // service-manager signal, not claimant input, controls shutdown.
                Thread.sleep(1_000L);
                continue;
            }
            char[] password = console.readPassword("Password: ");
```

### SEC-02: Terminal input is bounded only after allocation
- **Severity:** Low
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `src/main/java/com/acme/portal/Main.java:61-65,89-91`

**Vulnerable code:**
```java
// src/main/java/com/acme/portal/Main.java:61-65
            String username = console.readLine("Username: ");
            if (username == null) {
                return 1;
            }
            char[] password = console.readPassword("Password: ");

// src/main/java/com/acme/portal/Main.java:89-91
        String username = Authenticator.canonicalUsername(console.readLine("Employee username: "));
        char[] password = console.readPassword("New password: ");
        char[] confirmation = console.readPassword("Confirm password: ");
```

**Why it is a problem:** `readLine` and `readPassword` return the complete line as a newly allocated `String` or `char[]`; neither API accepts an application maximum. The checks in `Authenticator.canonicalUsername` and `provision` therefore occur only after the terminal provider has consumed and allocated storage for all supplied characters. On a pseudo-terminal or terminal configuration without a suitably small kernel line limit, a local claimant can submit an extremely large username, password, or confirmation and exhaust heap before the 64/128-character rejection runs. The impact is limited to availability and requires access to the attached terminal, which is why the severity is low.

**Fix:** Use an audited terminal-input abstraction that disables echo for secrets and enforces the maximum while characters are being consumed, discarding excess input without growing its buffer. A limit applied to the returned value is too late. The following call-site pattern assumes `BoundedTerminal` documents and enforces that contract during ingestion.
```java
        String username = terminal.readLine("Employee username: ", 64);
        char[] password = terminal.readPassword(
                "New password: ", Authenticator.MAX_PASSWORD_CHARS);
        char[] confirmation = terminal.readPassword(
                "Confirm password: ", Authenticator.MAX_PASSWORD_CHARS);
```

## 6. Verified Controls and Checks With No Finding
- Password storage cryptography: `PasswordHasher.java:11-30` uses 600,000-iteration PBKDF2-HMAC-SHA-256, 128-bit salts from `SecureRandom`, and 256-bit derived values; the current OWASP password-storage recommendation for PBKDF2-HMAC-SHA-256 is 600,000 iterations.
- Password comparison and account enumeration: `PasswordHasher.java:34-41` uses `MessageDigest.isEqual`, while `Authenticator.java:38-43` performs the same PBKDF2 operation with a dummy record for invalid or unknown usernames before returning the same denial result.
- Authentication decision integrity: `Authenticator.java:24-49` serializes the complete throttle-check, verifier-check, decision, and counter-update sequence and fails closed unless every condition succeeds.
- Source and account controls within one uninterrupted process: `LoginGuard.java:30-59` applies a rolling source limit, a timed source block, per-account increasing delay, bounded state, and monotonic time without creating a permanent account lockout.
- Username and credential-record validation: `Authenticator.java:52-58` allowlists canonical usernames; `CredentialStore.java:109-155` bounds file size, users, line length, field count, Base64 output lengths, duplicate names, and empty stores and rejects the complete store on malformed content.
- Filesystem protections: `CredentialStore.java:61-83,158-219` rejects symlinked or broadly writable paths, uses mode `0600`, creates private temporary files, locks updates, and atomically replaces the store. Under the documented service-account ownership and protected-directory preconditions, no exploitable cross-privilege path race was found.
- Compromised-password control: `PasswordBlocklist.java:33-57` fails closed on an absent, non-regular, symlinked, incorrectly permissioned, empty, oversized, undersized, duplicate, or syntactically invalid list.
- Secret exposure: `Main.java:77-79,120-125`, `PasswordHasher.java:29-30,39-40`, and `PasswordBlocklist.java:68-70` clear mutable password and derived buffers. User-visible and logged failures at `Main.java:27-49` do not include usernames, passwords, paths, or exception details.
- Provisioning policy: `Main.java:97-116` enforces the minimum and maximum password lengths, confirmation, blocklist check, username inequality, random salt generation, update locking, and private atomic storage. Its administrator-only authorization is delegated to the documented OS service-account boundary rather than claimant input.
- Command and dependency surface: `Main.java:27-40` accepts exactly one of two literal modes, and neither production Java code nor `build.sh` invokes an OS command with user-controlled runtime data, downloads remote code, loads plugins, or uses third-party dependencies.
- Sessions, tokens, SQL, and network transport: No session identifier, cookie, JWT, database query, socket, URL fetch, or TLS endpoint exists in the reviewed component, so no corresponding injection, token-validation, cookie, SSRF, or transport-security issue applies.
- Test credentials and cleanup: The password literal in `SecurityTests.java:20,35,45` is used only with a randomly salted store in a private temporary directory and cannot authenticate against the fixed production store; test cleanup does not expose a production secret.
