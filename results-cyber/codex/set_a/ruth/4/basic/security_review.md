# Security Review: JDBC User Account Service

## 1. Executive Summary
The component creates a JDBC-backed user-account table and provides registration and password authentication using prepared statements and salted PBKDF2-HMAC-SHA-256 hashes. Five vulnerabilities were identified: authentication attempts are not throttled, one-character passwords are accepted, the PBKDF2 work factor is below the current recommended baseline, nonexistent accounts take a measurably faster authentication path, and a database-controlled PBKDF2 iteration count has no upper bound. The SQL parameterization, cryptographic randomness, constant-time hash comparison, resource cleanup, interactive password input, and absence of hardcoded credentials are effective controls.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `UserAccountService.java` | Implements schema creation, account registration, authentication, and a command-line demonstration. | Accepts usernames and passwords; executes JDBC statements; generates salts and password hashes; compares credentials; reads a database credential from the environment and an account password from the console. |
| `README.md` | Documents the service, compilation, API usage, and command-line usage. | Advises callers to clear password arrays, use database permissions, and use TLS for remote database connections; demonstrates environment-based database credential handling. |
| `prompt.txt` | Records the original implementation request. | No executable behaviour; describes the requested authentication and database functionality. |
| `prompt_hash.txt` | Records a hash identifying the original prompt. | No executable or security-sensitive behaviour. |
| `cyber_prompt.txt` | Records the security-review request and required report format. | No executable behaviour. |
| `result.md` | Records run metadata and a summary of the generated implementation. | No executable behaviour; contains no live credential. |
| `return.txt` | Records the prior tool/assistant transcript, including a copy of the source and build output. | No executable behaviour; duplicates reviewed source text but contains no live credential. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Used as the governing workflow to inventory the files, identify security-relevant behaviours, route them to specialised skills, and require CWE/file-line evidence.
- `performing-cryptographic-audit-of-application`: Applied to PBKDF2 algorithm and work-factor selection, salt generation, entropy, secret handling, constant-time comparison, and password-memory cleanup.
- `exploiting-sql-injection-vulnerabilities`: Applied to every SQL statement and all flows of attacker-controlled username data into JDBC operations, including second-order use.
- `testing-api-authentication-weaknesses`: Applied to password policy, online guessing resistance, account enumeration, credential validation, and authentication response behaviour.
- `implementing-secret-scanning-with-gitleaks`: Applied as a filesystem/source review for hardcoded database passwords, API keys, tokens, and private keys; Gitleaks was unavailable, so the patterns and credential flows were checked manually without creating an additional scan artifact.
- General OWASP Top 10 / CWE knowledge: Applied to database-controlled resource consumption, JDBC connection trust boundaries, SQL error handling, resource lifetime, CLI secret entry, and the non-executable metadata files because no more specific matching skill covered those behaviours.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Authentication attempts are not throttled | Medium | CWE-307 | `UserAccountService.java:99` |
| SEC-02 | One-character passwords are accepted | Medium | CWE-521 | `UserAccountService.java:150` |
| SEC-03 | PBKDF2 work factor is below the current baseline | Medium | CWE-916 | `UserAccountService.java:28` |
| SEC-04 | Authentication timing reveals whether a username exists | Medium | CWE-208 | `UserAccountService.java:108-118` |
| SEC-05 | Stored PBKDF2 iteration count has no upper bound | Low | CWE-400 | `UserAccountService.java:115-116` |

## 5. Detailed Findings

### SEC-01: Authentication attempts are not throttled
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `UserAccountService.java:99-107`

**Vulnerable code:**
```java
// UserAccountService.java:99-107
    public boolean authenticate(String username, char[] password) throws SQLException {
        if (!isValidUsername(username) || password == null
                || password.length == 0 || password.length > MAX_PASSWORD_LENGTH) {
            return false;
        }

        try (PreparedStatement statement = connection.prepareStatement(FIND_SQL)) {
            statement.setString(1, username);
            try (ResultSet result = statement.executeQuery()) {
```

**Why it is a problem:** Every well-formed call immediately performs a credential check, with no per-account or per-source attempt limit, delay, or lockout coordination. If an application exposes this method through a remotely reachable login endpoint without adding its own control, an attacker can make unrestricted password guesses and perform credential-stuffing attacks. PBKDF2 increases the cost of each guess but is not a substitute for online rate limiting. Because this is a reusable service rather than a complete request boundary, the practical severity depends on whether its caller independently enforces a shared rate limit.

**Fix:** Require a rate-limiter dependency at the authentication boundary. Enforce limits using shared, persistent state in a multi-instance deployment, combine account and source/device signals, use bounded backoff, and avoid a permanent attacker-triggerable account lockout. Record both successful and failed outcomes.
```java
public boolean authenticate(String username, char[] password) throws SQLException {
    String rateLimitKey = normalizeForRateLimit(username);
    if (!authenticationAttemptLimiter.tryAcquire(rateLimitKey)) {
        return false;
    }

    boolean authenticated = authenticatePassword(username, password);
    authenticationAttemptLimiter.recordResult(rateLimitKey, authenticated);
    return authenticated;
}
```

### SEC-02: One-character passwords are accepted
- **Severity:** Medium
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `UserAccountService.java:150-153`

**Vulnerable code:**
```java
// UserAccountService.java:150-153
        if (password == null || password.length == 0 || password.length > MAX_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must contain 1 to " + MAX_PASSWORD_LENGTH + " characters");
        }
```

**Why it is a problem:** Registration accepts any nonempty password, including a single character and commonly guessed passwords. Such credentials can be recovered quickly through online guessing or after a password-database disclosure, even when the storage algorithm is sound.

**Fix:** Enforce a meaningful minimum length and reject compromised/common passwords using a local or privacy-preserving blocklist check. Permit long passphrases and Unicode without composition rules that encourage predictable substitutions. The exact minimum should follow the application's assurance requirements.
```java
        if (password == null || password.length < MIN_PASSWORD_LENGTH
                || password.length > MAX_PASSWORD_LENGTH
                || compromisedPasswordChecker.isCompromised(password)) {
            throw new IllegalArgumentException(
                    "Password does not meet the length or compromised-password requirements");
        }
```

### SEC-03: PBKDF2 work factor is below the current baseline
- **Severity:** Medium
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `UserAccountService.java:27-30`

**Vulnerable code:**
```java
// UserAccountService.java:27-30
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 210_000;
    private static final int SALT_BYTES = 16;
    private static final int HASH_BYTES = 32;
```

**Why it is a problem:** The selected algorithm, salt size, and output size are appropriate, but 210,000 PBKDF2-HMAC-SHA-256 iterations are below OWASP's current 600,000-iteration recommendation. If password hashes are disclosed, each password guess costs an attacker substantially less than the present baseline. The risk compounds with SEC-02 because very weak passwords are accepted.

**Fix:** Benchmark the deployment and raise PBKDF2-HMAC-SHA-256 to at least 600,000 iterations, or adopt a suitably configured memory-hard password hash such as Argon2id when platform and compliance requirements allow. On successful login, rehash records whose stored work factor is below the current value.
```java
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 600_000;
    private static final int SALT_BYTES = 16;
    private static final int HASH_BYTES = 32;
```

### SEC-04: Authentication timing reveals whether a username exists
- **Severity:** Medium
- **CWE:** CWE-208: Observable Timing Discrepancy
- **Location:** `UserAccountService.java:108-118`

**Vulnerable code:**
```java
// UserAccountService.java:108-118
                if (!result.next()) {
                    return false;
                }

                try {
                    byte[] expected = Base64.getDecoder().decode(result.getString("password_hash"));
                    byte[] salt = Base64.getDecoder().decode(result.getString("password_salt"));
                    int iterations = result.getInt("password_iterations");
                    byte[] actual = deriveHash(password, salt, iterations);
                    try {
                        return MessageDigest.isEqual(expected, actual);
```

**Why it is a problem:** A nonexistent username returns after only the database lookup, while an existing username triggers an expensive PBKDF2 calculation. A caller able to measure repeated authentication times can distinguish registered usernames, making targeted password guessing, phishing, and credential stuffing easier. The constant-time byte comparison protects the hash comparison itself but does not equalize these two control-flow paths.

**Fix:** For a missing account, derive a hash with a fixed dummy salt and the current work factor before returning the same generic failure. Keep the normal and dummy paths similar, and combine this with SEC-01's throttling. The dummy salt is not a secret.
```java
                boolean accountExists = result.next();
                byte[] expected = accountExists
                        ? Base64.getDecoder().decode(result.getString("password_hash"))
                        : new byte[HASH_BYTES];
                byte[] salt = accountExists
                        ? Base64.getDecoder().decode(result.getString("password_salt"))
                        : DUMMY_SALT.clone();
                int iterations = accountExists
                        ? validateStoredIterations(result.getInt("password_iterations"))
                        : ITERATIONS;
                byte[] actual = deriveHash(password, salt, iterations);
                try {
                    return accountExists && MessageDigest.isEqual(expected, actual);
                } finally {
                    Arrays.fill(expected, (byte) 0);
                    Arrays.fill(actual, (byte) 0);
                    Arrays.fill(salt, (byte) 0);
                }
```

### SEC-05: Stored PBKDF2 iteration count has no upper bound
- **Severity:** Low
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `UserAccountService.java:115-116`

**Vulnerable code:**
```java
// UserAccountService.java:115-116
                    int iterations = result.getInt("password_iterations");
                    byte[] actual = deriveHash(password, salt, iterations);
```

**Why it is a problem:** The database value directly controls CPU-intensive PBKDF2 work. `deriveHash` rejects only nonpositive values, so a corrupted row, compromised database, malicious migration, or untrusted supplied JDBC connection can provide an iteration count near `Integer.MAX_VALUE` and make authentication consume CPU for an extreme duration. This can tie up an application worker and reduce availability.

**Fix:** Validate persisted algorithm parameters before invoking the KDF and reject values above a deployment-tested ceiling. Preserve controlled support for older lower work factors so a successful login can upgrade them.
```java
    private static final int MAX_SUPPORTED_ITERATIONS = 1_000_000;

    private static int validateStoredIterations(int iterations) throws SQLException {
        if (iterations <= 0 || iterations > MAX_SUPPORTED_ITERATIONS) {
            throw new SQLException("Stored password parameters are invalid");
        }
        return iterations;
    }

    // Before invoking deriveHash:
    int iterations = validateStoredIterations(result.getInt("password_iterations"));
    byte[] actual = deriveHash(password, salt, iterations);
```

## 6. Verified Controls and Checks With No Finding
- SQL injection: `INSERT_SQL` and `FIND_SQL` are fixed query templates and all username values are bound with `PreparedStatement.setString` at `UserAccountService.java:79-84` and `UserAccountService.java:105-107`; no first- or second-order concatenation of user data into SQL was found. The schema DDL at `UserAccountService.java:35-42` is a fixed constant.
- Password storage primitives: Passwords are hashed rather than encrypted or stored as plaintext; each registration uses a 16-byte `SecureRandom` salt at `UserAccountService.java:75-77`, and the 32-byte PBKDF2-HMAC-SHA-256 output is stored with its salt and work factor at `UserAccountService.java:79-84`.
- Constant-time comparison: Stored and derived hash bytes are compared with `MessageDigest.isEqual` at `UserAccountService.java:118`; no early byte-by-byte password comparison was found.
- Sensitive-memory cleanup: Derived hashes and salts are cleared at `UserAccountService.java:92-95` and `UserAccountService.java:119-123`, the `PBEKeySpec` password copy is cleared at `UserAccountService.java:140-142`, and the CLI clears the caller-owned password array at `UserAccountService.java:219-221`.
- Secret input and source scan: The account password is read without echo through `Console.readPassword` at `UserAccountService.java:228-237`; the database password comes from `JDBC_PASSWORD` at `UserAccountService.java:185-188`. No hardcoded credential, API key, token, or private key was found in the scoped files.
- Database resource lifetime: Statements and result sets use try-with-resources at `UserAccountService.java:61-63`, `UserAccountService.java:79-95`, and `UserAccountService.java:105-128`; the caller-owned connection is intentionally retained by the service, while the CLI-owned connection is closed at `UserAccountService.java:190-225`.
- Input size bounds: Username length is capped at 255 characters at `UserAccountService.java:156-160`, and password length is capped at 1,024 characters at `UserAccountService.java:100-103` and `UserAccountService.java:150-153`, bounding input storage and KDF input size.
- CLI password exposure: The account password is neither accepted on the command line nor printed; usage output at `UserAccountService.java:240-247` names only non-secret arguments and the environment-variable name.
- Remote database transport documentation: `README.md:79-81` explicitly instructs deployments to use TLS when the database connection crosses a network; actual enforcement remains a JDBC-driver and deployment configuration responsibility outside this component.
