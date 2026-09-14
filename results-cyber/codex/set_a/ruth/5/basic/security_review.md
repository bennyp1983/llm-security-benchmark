# Security Review: Java Login Example

## 1. Executive Summary
The component is a dependency-free Java 17 command-line login demonstration backed by an in-memory account map. It reads one username/password pair, derives a PBKDF2-HMAC-SHA-256 hash, and performs a constant-time comparison. The most serious issue is that the only valid password is hardcoded and also disclosed in documentation and an execution transcript, so anyone with the distributed files knows the credential. The review also found an undersized PBKDF2 work factor, an unmasked password-input fallback, no restriction on repeated authentication attempts, incomplete clearing of password material on exceptional paths, and unbounded input buffering.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `LoginApplication.java` | Implements credential input, an in-memory account store, PBKDF2 password hashing, and authentication. | Embeds the demo password; reads secrets from a console or standard input; creates salts with `SecureRandom`; hashes with PBKDF2-HMAC-SHA-256; compares hashes with `MessageDigest.isEqual`; and has no persistent attempt limiter. |
| `README.md` | Documents the application, compilation, execution, demo credentials, and production caveats. | Publishes the valid credential and recommends a shell command containing it; acknowledges visible fallback input and absent production rate limiting. |
| `cyber_prompt.txt` | Records the instructions for this security review. | Contains no executable behaviour or secrets, but dictates report structure and review requirements. |
| `prompt.txt` | Records the original implementation request. | Defines the authentication requirement but contains no credential or executable behaviour. |
| `prompt_hash.txt` | Stores a SHA-256-sized identifier for the original prompt. | Contains no authentication secret and is not used by the application. |
| `result.md` | Records run metadata and a summary of the generated application. | Makes security claims about password hashing and input but contains no executable code or credential value. |
| `return.txt` | Stores the prior tool/command transcript. | Retains the valid password inside a recorded shell command, creating another plaintext copy of the credential. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Used as the routing workflow to inventory every file, identify security-relevant behaviours, select specialized skills, and require CWE/file-line evidence.
- `implementing-secret-scanning-with-gitleaks`: Applied to plaintext credentials embedded in source, documentation, and command transcripts, including remediation considerations for all retained copies.
- `performing-cryptographic-audit-of-application`: Applied to PBKDF2 algorithm and work-factor selection, salt generation, output size, secret handling, and constant-time verification.
- General OWASP Top 10 / CWE knowledge: Applied to CLI password masking, authentication-attempt restriction, exceptional-path secret cleanup, and input-size/resource limits because no CLI-oriented library skill clearly matched those behaviours.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Valid account credential is hardcoded and publicly disclosed | High | CWE-798 | `LoginApplication.java:22` |
| SEC-02 | PBKDF2-HMAC-SHA-256 uses an insufficient work factor | Medium | CWE-916 | `LoginApplication.java:82` |
| SEC-03 | Fallback password entry is not masked | Medium | CWE-549 | `LoginApplication.java:52-57` |
| SEC-04 | Authentication attempts are not restricted | Medium | CWE-307 | `LoginApplication.java:101-116` |
| SEC-05 | Password buffer is not cleared if authentication throws | Low | CWE-316 | `LoginApplication.java:24-29` |
| SEC-06 | Input lines are buffered without a size limit | Low | CWE-400 | `LoginApplication.java:60-68` |

## 5. Detailed Findings

### SEC-01: Valid account credential is hardcoded and publicly disclosed
- **Severity:** High
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Location:** `LoginApplication.java:22` (also disclosed at `README.md:33-38` and `return.txt:9-10`)

**Vulnerable code:**
```java
        accounts.addAccount("demo", "correct-horse-battery-staple".toCharArray());
```

**Why it is a problem:** The sole account's valid password is part of the compiled program and is available to anyone who can read or decompile it. The same value is explicitly published in the README and retained in the command transcript, so hashing it at startup does not provide secrecy. If this demonstration is deployed, reused, or adapted without removing the credential, an attacker can authenticate immediately. Changing the Java line alone is insufficient while plaintext copies remain in documentation, logs, or repository history.

**Fix:** Do not create an account from a source-code literal. Load an already salted password hash and its parameters from a protected account store, or require one-time secure enrollment. Remove the credential from the README and transcripts; if it has ever protected anything real, rotate it and clean retained history as appropriate.
```java
        AccountStore accounts = AccountStore.loadFromProtectedStore();
```

### SEC-02: PBKDF2-HMAC-SHA-256 uses an insufficient work factor
- **Severity:** Medium
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `LoginApplication.java:80-82` and `LoginApplication.java:118-122`

**Vulnerable code:**
```java
        private static final int SALT_BYTES = 16;
        private static final int HASH_BITS = 256;
        private static final int ITERATIONS = 210_000;
```
```java
        private static byte[] hashPassword(char[] password, byte[] salt) {
            PBEKeySpec specification = new PBEKeySpec(password, salt, ITERATIONS, HASH_BITS);
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                return factory.generateSecret(specification).getEncoded();
```

**Why it is a problem:** The 210,000-iteration value is substantially below the current OWASP recommendation of 600,000 iterations for PBKDF2-HMAC-SHA-256. If password hashes are obtained, the lower work factor makes offline guessing materially cheaper. Because the work factor is a global constant rather than stored with each account, existing hashes also cannot be upgraded gradually. See the [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

**Fix:** Prefer a calibrated, memory-hard password hash such as Argon2id where dependencies permit it. If PBKDF2-HMAC-SHA-256 is required, use at least 600,000 iterations, benchmark it so verification remains safely below one second in the deployment environment, store the work factor with each hash, and rehash older records after successful login.
```java
        private static final int SALT_BYTES = 16;
        private static final int HASH_BITS = 256;
        private static final int ITERATIONS = 600_000;
```

### SEC-03: Fallback password entry is not masked
- **Severity:** Medium
- **CWE:** CWE-549: Missing Password Field Masking
- **Location:** `LoginApplication.java:52-57`

**Vulnerable code:**
```java
        // System.console() is commonly unavailable in IDEs and when input is piped.
        System.out.print("Username: ");
        String username = readLine();
        System.out.print("Password: ");
        String password = readLine();
        return new Credentials(username, password.toCharArray());
```

**Why it is a problem:** When `System.console()` is unavailable, the application reads the password through ordinary standard input. In interactive IDE terminals this input can be echoed on screen, exposed to shoulder surfing, captured in terminal recordings, or retained by the IDE. The fallback also creates the password as an immutable `String`, which cannot be explicitly erased.

**Fix:** Fail closed when a masking-capable console is unavailable, or use a well-reviewed terminal library that disables echo. Automated tests should inject a credential provider rather than placing a password in a shell command.
```java
        Console console = System.console();
        if (console == null) {
            throw new IOException("A secure, password-masking console is required.");
        }
        String username = console.readLine("Username: ");
        char[] password = console.readPassword("Password: ");
        return new Credentials(username, password == null ? new char[0] : password);
```

### SEC-04: Authentication attempts are not restricted
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `LoginApplication.java:101-116`

**Vulnerable code:**
```java
        boolean authenticate(String username, char[] submittedPassword) {
            Account account = accounts.get(username);
            if (account == null || submittedPassword == null) {
                // Perform password hashing even for an unknown user to reduce timing differences.
                byte[] unusedSalt = new byte[SALT_BYTES];
                hashPassword(submittedPassword == null ? new char[0] : submittedPassword, unusedSalt);
                return false;
            }

            byte[] submittedHash = hashPassword(submittedPassword, account.salt());
            try {
                return MessageDigest.isEqual(account.passwordHash(), submittedHash);
            } finally {
                Arrays.fill(submittedHash, (byte) 0);
            }
        }
```

**Why it is a problem:** `authenticate` performs every submitted guess without delay, backoff, lockout, or a shared attempt counter. Although the current CLI accepts only one guess per process, it can be restarted without limit, and the reusable `AccountStore` method has no protection if incorporated into a long-running application. This enables automated password guessing and also multiplies the CPU cost of PBKDF2.

**Fix:** Enforce attempt limits in a persistent layer that survives process restarts. Track both account and source dimensions, apply bounded exponential backoff or temporary lockout, log abuse without logging credentials, and avoid permanent account-lockout denial of service. A shared limiter should wrap every authentication call.
```java
        boolean authenticate(String username, char[] submittedPassword) {
            if (!attemptLimiter.tryAcquire(username)) {
                return false;
            }
            boolean authenticated = verifyPassword(username, submittedPassword);
            attemptLimiter.recordResult(username, authenticated);
            return authenticated;
        }
```

### SEC-05: Password buffer is not cleared if authentication throws
- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `LoginApplication.java:24-29`

**Vulnerable code:**
```java
        Credentials credentials = readCredentials(args);
        boolean authenticated = accounts.authenticate(
                credentials.username(), credentials.password());

        // Remove the caller-owned password copy as soon as it is no longer needed.
        Arrays.fill(credentials.password(), '\0');
```

**Why it is a problem:** The password array is cleared only after `authenticate` returns normally. If PBKDF2 initialization or derivation throws, execution skips the wipe and leaves the cleartext password in memory until garbage collection. Memory dumps, diagnostics, or a same-process compromise can then recover it. The non-console fallback compounds this by first storing the password in an immutable `String`.

**Fix:** Put the authentication call inside `try`/`finally` so the caller-owned array is cleared on every path, and remove the immutable-`String` fallback as described in SEC-03.
```java
        Credentials credentials = readCredentials(args);
        boolean authenticated;
        try {
            authenticated = accounts.authenticate(
                    credentials.username(), credentials.password());
        } finally {
            Arrays.fill(credentials.password(), '\0');
        }
```

### SEC-06: Input lines are buffered without a size limit
- **Severity:** Low
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `LoginApplication.java:60-68`

**Vulnerable code:**
```java
    private static String readLine() throws IOException {
        StringBuilder value = new StringBuilder();
        int character;
        while ((character = System.in.read()) != -1 && character != '\n') {
            if (character != '\r') {
                value.append((char) character);
            }
        }
        return value.toString();
```

**Why it is a problem:** The loop appends until a newline or end-of-file with no maximum length. A large or non-terminating input stream can make the process continually allocate memory and eventually exhaust the heap. The impact is limited to this CLI process today, but the helper becomes more dangerous if reused around remotely influenced input.

**Fix:** Prefer removing this fallback as in SEC-03. If line-based input remains necessary, set an explicit limit appropriate to usernames/passwords and reject overlong input instead of truncating it silently.
```java
    private static String readLine(int maximumCharacters) throws IOException {
        StringBuilder value = new StringBuilder();
        int character;
        while ((character = System.in.read()) != -1 && character != '\n') {
            if (character != '\r') {
                if (value.length() >= maximumCharacters) {
                    throw new IOException("Input exceeds the permitted length.");
                }
                value.append((char) character);
            }
        }
        return value.toString();
    }
```

## 6. Verified Controls and Checks With No Finding
- Password hashing algorithm: `LoginApplication.java:118-129` uses PBKDF2-HMAC-SHA-256 rather than a fast general-purpose hash, and clears the `PBEKeySpec` password in a `finally` block; the work-factor weakness is reported separately as SEC-02.
- Salt generation: `LoginApplication.java:80` and `LoginApplication.java:95-98` generate a fresh 16-byte salt for each added account with `SecureRandom`.
- Hash comparison: `LoginApplication.java:110-115` uses `MessageDigest.isEqual` and clears the submitted derived hash in a `finally` block.
- User-enumeration resistance: `LoginApplication.java:103-107` performs PBKDF2 even for an unknown username, while `LoginApplication.java:31-35` returns the same generic message for an unknown user and an incorrect password.
- Command-line leakage prevention: `LoginApplication.java:39-43` rejects credentials supplied as Java command-line arguments; the README/transcript shell-command disclosure and standard-input fallback are covered by SEC-01 and SEC-03.
- Mutable account data encapsulation: `LoginApplication.java:134-148` defensively copies salt and password-hash arrays on construction and access.
- Injection and unsafe execution: No SQL/database access, deserialization, file/path operation, template/HTML output, network request, dynamic class loading, or OS command execution exists in `LoginApplication.java`.
- Authentication result handling: `LoginApplication.java:31-36` grants success only after a matching hash and exits nonzero on failure.
- Non-source artifacts: `cyber_prompt.txt`, `prompt.txt`, `prompt_hash.txt`, and `result.md` contain no executable code or additional secret values; `return.txt` was checked separately and its retained credential is included in SEC-01.
