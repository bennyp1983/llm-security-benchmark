# Security Review: JDBC User Account Service

## 1. Executive Summary
`UserAccountService` registers and authenticates users through an existing JDBC connection. It stores salted PBKDF2-HMAC-SHA-256 password hashes in a versioned format and uses parameterized SQL for every user-controlled database value. Three medium-severity authentication weaknesses were identified: authentication attempts are not throttled, registration accepts passwords as short as one character, and nonexistent usernames bypass the expensive password derivation step, creating a username-enumeration timing signal. No SQL injection, plaintext-password storage, weak random-number generation, non-constant-time hash comparison, hardcoded secret, or fail-open credential-parsing issue was found.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `UserAccountService.java` | Implements JDBC-backed account registration and password authentication. | Validates credentials, executes SQL, generates salts, derives and compares password hashes, parses stored credentials, and clears mutable secret buffers. |
| `README.md` | Documents the schema, compilation, API usage, password handling, transaction ownership, TLS, and database least privilege. | Advises callers to obtain and clear passwords safely, suppress database error details, use TLS, and restrict database permissions. |
| `prompt.txt` | Records the original implementation request. | Non-executable task text; requests secure password handling. |
| `cyber_prompt.txt` | Records the security-review request and required report structure. | Non-executable review instructions; contains no application behavior. |
| `prompt_hash.txt` | Stores a hash identifying the prompt. | Static metadata with no executable or secret-handling behavior. |
| `result.md` | Records run metadata and a prior implementation summary. | Non-executable metadata; describes claimed security controls but does not enforce them. |
| `return.txt` | Stores a transcript of the prior implementation run. | Non-executable log metadata; contains command history but no credentials or application secrets. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Used as the routing workflow to inventory every file, identify security-relevant behavior, select specialized skills, and require CWE and file:line evidence.
- `testing-api-authentication-weaknesses`: Applied to password-policy enforcement, excessive authentication attempts, credential-stuffing resistance, account enumeration, and authentication failure behavior.
- `performing-cryptographic-audit-of-application`: Applied to PBKDF2 algorithm and work-factor selection, salt generation, derived-key size, comparison behavior, secret lifetime, and hardcoded-secret checks.
- `exploiting-sql-injection-vulnerabilities`: Applied to both JDBC data paths, including registration, authentication, parameter binding, and second-order use of stored usernames.
- General OWASP Top 10 / CWE knowledge: Applied to input bounds, resource-exhaustion limits, credential-format parsing, exception behavior, database transport and least privilege, transaction ownership, and sensitive-data handling where no closer specialized skill matched.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Authentication attempts are not throttled | Medium | CWE-307 | `UserAccountService.java:79` |
| SEC-02 | Registration accepts trivially weak passwords | Medium | CWE-521 | `UserAccountService.java:181-185` |
| SEC-03 | Username existence leaks through authentication timing | Medium | CWE-208 | `UserAccountService.java:97-103` |

## 5. Detailed Findings

### SEC-01: Authentication attempts are not throttled
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `UserAccountService.java:79-88`

**Vulnerable code:**
```java
// UserAccountService.java:79-88
    public boolean authenticate(String username, char[] password) throws SQLException {
        if (!isValidUsername(username)
                || password == null
                || password.length == 0
                || password.length > MAX_PASSWORD_LENGTH) {
            return false;
        }

        String storedCredential = null;
        try (PreparedStatement statement = connection.prepareStatement(SELECT_CREDENTIAL)) {
```

**Why it is a problem:** Every syntactically valid request is allowed to proceed without an attempt counter, delay, lockout policy, or rate-limit decision. An attacker can therefore make unlimited online password guesses or reuse breached username/password pairs. PBKDF2 makes each individual guess costly, but it does not bound distributed or sustained online attempts; it can also amplify resource consumption on the application host. Because this class has no client or request context, the primary control should normally be enforced by the calling authentication endpoint, with this service participating in account-level failure tracking if appropriate.

**Fix:** Require the authentication boundary to acquire a rate-limit permit before calling the service, using account-, client-, and global-level limits with progressive backoff. Record success and failure without creating a permanent account-lockout denial of service. For example:
```java
public boolean authenticateRequest(
        String clientKey, String username, char[] password) throws SQLException {
    String accountKey = username == null ? "<invalid>" : username;
    if (!authenticationLimiter.tryAcquire(clientKey, accountKey)) {
        return false;
    }

    boolean authenticated = accountService.authenticate(username, password);
    authenticationLimiter.recordResult(clientKey, accountKey, authenticated);
    return authenticated;
}
```

### SEC-02: Registration accepts trivially weak passwords
- **Severity:** Medium
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `UserAccountService.java:181-185`

**Vulnerable code:**
```java
// UserAccountService.java:181-185
    private static void validatePassword(char[] password) {
        if (password == null || password.length == 0 || password.length > MAX_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be 1-" + MAX_PASSWORD_LENGTH + " characters");
        }
    }
```

**Why it is a problem:** The only minimum-strength requirement is that the password contain one character. Users can register credentials such as `a`, which are immediately guessable regardless of the strength of PBKDF2. This increases account-takeover risk from password guessing and credential attacks.

**Fix:** Enforce an appropriate minimum length, continue allowing long passphrases, and reject passwords found in a breached-password blocklist at the registration boundary. Avoid brittle composition rules. The exact minimum should follow the application's authentication and MFA policy; the following establishes a reasonable code-level baseline:
```java
private static final int MIN_PASSWORD_LENGTH = 12;
private static final int MAX_PASSWORD_LENGTH = 1024;

private static void validatePassword(char[] password) {
    if (password == null
            || password.length < MIN_PASSWORD_LENGTH
            || password.length > MAX_PASSWORD_LENGTH) {
        throw new IllegalArgumentException(
                "Password must be " + MIN_PASSWORD_LENGTH + "-"
                        + MAX_PASSWORD_LENGTH + " characters");
    }
}
```

### SEC-03: Username existence leaks through authentication timing
- **Severity:** Medium
- **CWE:** CWE-208: Observable Timing Discrepancy
- **Location:** `UserAccountService.java:97-103`

**Vulnerable code:**
```java
// UserAccountService.java:97-103
        if (storedCredential == null) {
            return false;
        }

        char[] workingPassword = password.clone();
        try {
            return verifyStoredCredential(workingPassword, storedCredential);
```

**Why it is a problem:** An unknown username returns immediately, while a known username triggers a 600,000-iteration PBKDF2 operation. That large and repeatable difference can let a remote attacker enumerate registered usernames even if the surrounding endpoint uses the same status code and message for every failed login. Enumerated accounts make password spraying and credential stuffing more effective.

**Fix:** Run the same credential-verification path for missing accounts by substituting a syntactically valid dummy credential, then force the result to false when no account existed. Keep external failure messages and status codes uniform as well.
```java
private static final String DUMMY_CREDENTIAL =
        "pbkdf2-sha256$600000$AAAAAAAAAAAAAAAAAAAAAA==$"
                + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

char[] workingPassword = password.clone();
try {
    boolean accountExists = storedCredential != null;
    String credential = accountExists ? storedCredential : DUMMY_CREDENTIAL;
    boolean passwordMatches = verifyStoredCredential(workingPassword, credential);
    return accountExists && passwordMatches;
} finally {
    Arrays.fill(workingPassword, '\0');
}
```

## 6. Verified Controls and Checks With No Finding
- SQL injection resistance: Both SQL statements are fixed constants (`UserAccountService.java:32-35`), and `username` plus the derived credential are bound with `PreparedStatement.setString` (`UserAccountService.java:63-65`, `UserAccountService.java:88-92`). No dynamic or second-order SQL construction exists.
- Password storage: Registration stores only a versioned salted PBKDF2 credential rather than the plaintext password (`UserAccountService.java:109-119`).
- KDF and work factor for newly created credentials: PBKDF2-HMAC-SHA-256 uses 600,000 iterations and a 256-bit derived key (`UserAccountService.java:24-28`, `UserAccountService.java:112`). No deprecated cryptographic primitive is used.
- Salt generation: Each registration obtains a fresh 16-byte salt from `SecureRandom` (`UserAccountService.java:38-42`, `UserAccountService.java:109-112`).
- Password-hash comparison: `MessageDigest.isEqual` is used instead of an early-exit array comparison (`UserAccountService.java:144-145`).
- Stored-credential validation: The parser checks the format identifier, field count, iteration range, decoded salt length, and derived-key length, and malformed encodings fail closed (`UserAccountService.java:127-147`). The encoded database column also bounds the input size to 512 characters as documented in `README.md:18-22`.
- Secret-memory hygiene: Public methods clone caller-owned password arrays, internal password copies and derived byte arrays are cleared in `finally` blocks, and `PBEKeySpec.clearPassword()` is always called (`UserAccountService.java:60-72`, `UserAccountService.java:101-106`, `UserAccountService.java:117-119`, `UserAccountService.java:148-162`). The README tells callers to clear their own arrays (`README.md:49-83`).
- Hardcoded secrets and leakage: No database password, cryptographic key, token, plaintext account password, or credential logging was found in source, documentation, or metadata files.
- Input and resource bounds: Username and password lengths are capped before database or KDF processing (`UserAccountService.java:29-30`, `UserAccountService.java:174-185`), and parsed KDF iterations and hash length are bounded (`UserAccountService.java:132-145`).
- JDBC resource management: Statements and result sets use try-with-resources (`UserAccountService.java:63-69`, `UserAccountService.java:88-95`).
- Database operational controls: The README explicitly assigns transaction completion to the caller, recommends generic handling of unique-key errors, requires TLS for networked connections, and recommends least-privilege database access (`README.md:85-92`). These deployment controls cannot be verified from this standalone class.
