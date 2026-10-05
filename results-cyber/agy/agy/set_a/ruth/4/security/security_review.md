# Security Review: UserAccountService

## 1. Executive Summary
This security review assesses the `UserAccountService` Java component, designed to handle user account registration, password updates, and credential authentication against an SQL database via JDBC. The component implements defense-in-depth principles, notably employing `PBKDF2WithHmacSHA512` with 210,000 iterations, unique 128-bit salts via `SecureRandom`, constant-time hash comparison via `MessageDigest.isEqual`, and parameterized SQL statements.

Despite these robust controls, the audit identified several vulnerabilities. Most notably, `authenticateUser` omits the maximum password length bound that is enforced during registration, exposing the service to Algorithmic Complexity Denial of Service (DoS) via oversized PBKDF2 payloads. In addition, the authentication workflow blindly trusts algorithm and iteration metadata retrieved from the database without validation against an allowlist or security thresholds, permitting potential cryptographic downgrade attacks. Minor issues include password memory cleanse violations when validation fails before `try-finally` blocks, missing old-password authentication in `updatePassword`, and persistence of plaintext credentials in JVM heap memory when using `String` overloads.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `UserAccountService.java` | Core service class providing schema creation, registration, authentication, metadata query, and password update. | Key derivation via PBKDF2-HMAC-SHA512, SecureRandom salting, parameterized JDBC queries, constant-time verification, memory wiping, and timing mitigation. |
| `pom.xml` | Maven project build definition. | Manages dependencies (H2 Database 2.2.224) and Java 17 compiler configurations. |
| `run_demo.sh` | Shell script for compiling and executing the security verification suite. | Runs `javac` and launches `java` classpath with local H2 driver and CLI arguments. |
| `README.md` | Component documentation and architecture specifications. | Documents cryptographic choices, memory handling guidelines, schema definition, and integration steps. |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to the evaluation of PBKDF2 KDF parameters, iteration counts, SecureRandom salt generation, key length derivations, algorithm agility mechanisms, and constant-time comparisons.
- `testing-for-sensitive-data-exposure`: Applied to credential lifecycle handling in memory, heap retention risks of `String` vs mutable `char[]`, zeroization guarantees, and buffer cleanup across normal and exceptional execution paths.
- `testing-api-authentication-weaknesses`: Applied to authentication verification flows, user enumeration defenses, timing side-channels, and password reset/update authorization.
- `exploiting-sql-injection-vulnerabilities`: Applied to JDBC database query construction, verifying prepared statement parameterization across all DDL and DML operations.
- General OWASP Top 10 / CWE knowledge (CWE-400 / CWE-390): Applied to algorithmic complexity resource consumption attacks on password hashing and silent error conditions.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Algorithmic Complexity Denial of Service via Unbounded Password Length in Authentication | High | CWE-400 | `UserAccountService.java:344-347` |
| SEC-02 | Cryptographic Algorithm Downgrade and Unbounded Iterations from Stored Records | High | CWE-757 | `UserAccountService.java:377-387` |
| SEC-03 | Sensitive Password Array Retained in Memory on Input Validation Failure | Medium | CWE-244 | `UserAccountService.java:228-238` |
| SEC-04 | Missing Current Password Verification and Silent Failure in Password Update | Medium | CWE-306 | `UserAccountService.java:516-539` |
| SEC-05 | Inadequate Key Length and Algorithm Validation in Custom Service Constructor | Low | CWE-326 | `UserAccountService.java:144-164` |
| SEC-06 | Plaintext Password Exposure in JVM Heap via String Overload Methods | Low | CWE-316 | `UserAccountService.java:297-308` |
| SEC-07 | Observable Timing Discrepancy in Dummy Authentication When Stored Iterations Differ | Low | CWE-208 | `UserAccountService.java:354-372` |

## 5. Detailed Findings

### SEC-01: Algorithmic Complexity Denial of Service via Unbounded Password Length in Authentication
- **Severity:** High
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `UserAccountService.java:344-347`

**Vulnerable code:**
```java
// UserAccountService.java:344-347
        validateUsername(username);
        if (password == null) {
            throw new ValidationException("Password cannot be null.");
        }
```

**Why it is a problem:**
The service defines `DEFAULT_MAX_PASSWORD_LENGTH = 128` specifically to defend against algorithmic complexity and CPU exhaustion attacks on PBKDF2 (as documented in class comments at lines 38-39 and 88-89). While `registerUser` and `updatePassword` enforce this limit via `validatePassword(password)`, `authenticateUser` only verifies `password == null`. An unauthenticated attacker can submit excessively large passwords (e.g., 10 MB - 100 MB) during authentication. Executing 210,000 iterations of PBKDF2-HMAC-SHA512 over megabyte-scale buffers ties up JVM worker threads and causes severe CPU starvation, leading to application-wide Denial of Service.

**Fix:**
Enforce maximum password length validation in `authenticateUser`. If the supplied password exceeds `maxPasswordLength`, zero out the array and immediately reject the attempt before triggering expensive cryptographic operations:
```java
        validateUsername(username);
        if (password == null) {
            throw new ValidationException("Password cannot be null.");
        }
        if (password.length > this.maxPasswordLength) {
            if (wipePassword) {
                Arrays.fill(password, '\0');
            }
            return false;
        }
```

---

### SEC-02: Cryptographic Algorithm Downgrade and Unbounded Iterations from Stored Records
- **Severity:** High
- **CWE:** CWE-757: Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade')
- **Location:** `UserAccountService.java:377-387`

**Vulnerable code:**
```java
// UserAccountService.java:377-387
                int userIterations = rs.getInt("iterations");
                String userAlgorithm = rs.getString("algorithm");

                byte[] salt = Base64.getDecoder().decode(saltBase64);
                byte[] expectedHash = Base64.getDecoder().decode(storedHashBase64);
                byte[] computedHash = null;

                try {
                    // Derive hash using the user's stored parameters
                    computedHash = hashPassword(password, salt, userIterations,
                                                expectedHash.length * 8, userAlgorithm);
```

**Why it is a problem:**
During authentication, `userAlgorithm` and `userIterations` are loaded directly from the database and passed into `hashPassword` without verification against an allowlist of approved algorithms or acceptable work-factor bounds. If a database record is modified (via SQL injection elsewhere, backup tampering, or insider threat), an adversary can force the server to use obsolete, insecure algorithms supported by the JVM provider (such as `PBEWithMD5AndDES` or `PBKDF2WithHmacSHA1`) or set `userIterations` to 1, bypassing intended cryptographic protection. Conversely, setting `userIterations` to an extreme value (e.g., 2,000,000,000) causes thread hanging and CPU exhaustion whenever authentication is attempted for that user.

**Fix:**
Validate `userAlgorithm` against an allowlist of permitted secure algorithms, ensure `userIterations` falls within safe operating boundaries (`10_000 <= userIterations <= 2_000_000`), and ensure `expectedHash` meets the minimum expected key length:
```java
                int userIterations = rs.getInt("iterations");
                String userAlgorithm = rs.getString("algorithm");

                if (!"PBKDF2WithHmacSHA512".equalsIgnoreCase(userAlgorithm) &&
                    !"PBKDF2WithHmacSHA256".equalsIgnoreCase(userAlgorithm)) {
                    throw new SecurityConfigurationException("Unsupported or insecure algorithm in user record: " + userAlgorithm, null);
                }
                if (userIterations < 10_000 || userIterations > 2_000_000) {
                    throw new SecurityConfigurationException("Invalid iteration count in user record: " + userIterations, null);
                }

                byte[] salt = Base64.getDecoder().decode(saltBase64);
                byte[] expectedHash = Base64.getDecoder().decode(storedHashBase64);
                if (expectedHash.length < 16) {
                    throw new SecurityConfigurationException("Stored hash length is insufficiently secure.", null);
                }
                byte[] computedHash = null;

                try {
                    computedHash = hashPassword(password, salt, userIterations,
                                                expectedHash.length * 8, userAlgorithm);
```

---

### SEC-03: Sensitive Password Array Retained in Memory on Input Validation Failure
- **Severity:** Medium
- **CWE:** CWE-244: Improper Clearing of Heap Memory Before Release ('Memory Cleanse Violation')
- **Location:** `UserAccountService.java:228-238`

**Vulnerable code:**
```java
// UserAccountService.java:228-238
        Objects.requireNonNull(conn, "Database connection must not be null.");
        validateUsername(username);
        validatePassword(password);

        // Pre-check existence before expensive hashing computation
        if (isUserExists(conn, username)) {
            if (wipePassword && password != null) {
                Arrays.fill(password, '\0');
            }
            throw new UserAlreadyExistsException("User '" + username + "' is already registered.");
        }
```

**Why it is a problem:**
`validateUsername` and `validatePassword` are executed before entering the `try-finally` block responsible for zeroing out the password array. If input validation fails (e.g., username has invalid characters, or password does not meet the minimum length), a `ValidationException` is thrown immediately. Because execution halts before line 234 or line 273, the `password` array is never cleared despite `wipePassword = true`. Plaintext credentials remain resident in JVM memory indefinitely, defeating the memory hygiene guarantees promised by the service. Identical omissions occur in `authenticateUser` (line 344) and `updatePassword` (lines 519-520).

**Fix:**
Enclose all validation and processing inside a `try-finally` block so that `password` zeroization is guaranteed regardless of whether validation passes or throws an exception:
```java
        Objects.requireNonNull(conn, "Database connection must not be null.");
        try {
            validateUsername(username);
            validatePassword(password);

            if (isUserExists(conn, username)) {
                throw new UserAlreadyExistsException("User '" + username + "' is already registered.");
            }
            // Proceed with hashing and storage...
        } finally {
            if (wipePassword && password != null) {
                Arrays.fill(password, '\0');
            }
        }
```

---

### SEC-04: Missing Current Password Verification and Silent Failure in Password Update
- **Severity:** Medium
- **CWE:** CWE-306: Missing Authentication for Critical Function
- **Location:** `UserAccountService.java:516-539`

**Vulnerable code:**
```java
// UserAccountService.java:516-539
    public void updatePassword(Connection conn, String username, char[] newPassword)
            throws SQLException, ValidationException {
        Objects.requireNonNull(conn, "Database connection must not be null.");
        validateUsername(username);
        validatePassword(newPassword);

        byte[] salt = new byte[this.saltBytes];
        SECURE_RANDOM.nextBytes(salt);
        byte[] hash = null;

        try {
            hash = hashPassword(newPassword, salt, this.iterations, this.keyLengthBits, this.algorithm);
            String saltBase64 = Base64.getEncoder().encodeToString(salt);
            String hashBase64 = Base64.getEncoder().encodeToString(hash);

            String updateSql = "UPDATE users SET password_hash = ?, salt = ?, iterations = ?, algorithm = ? WHERE username = ?";
            try (PreparedStatement stmt = conn.prepareStatement(updateSql)) {
                stmt.setString(1, hashBase64);
                stmt.setString(2, saltBase64);
                stmt.setInt(3, this.iterations);
                stmt.setString(4, this.algorithm);
                stmt.setString(5, username);
                stmt.executeUpdate();
            }
```

**Why it is a problem:**
`updatePassword` modifies credentials without validating the existing user password or verifying caller authorization. Any application component with access to the service could update arbitrary user accounts without proving identity. Furthermore, `stmt.executeUpdate()` return value is never checked. If the target `username` does not exist in the database, 0 rows are modified, but the method returns successfully without notifying the caller, resulting in an undetected silent failure (CWE-390).

**Fix:**
Require the user's current password for verification, authenticate the user before updating credentials, and check that `executeUpdate()` affected exactly one row:
```java
    public void updatePassword(Connection conn, String username, char[] currentPassword, char[] newPassword)
            throws SQLException, ValidationException, AuthenticationException {
        Objects.requireNonNull(conn, "Database connection must not be null.");
        if (!authenticateUser(conn, username, currentPassword, true)) {
            throw new AuthenticationException("Current password authentication failed for user: " + username);
        }
        validateUsername(username);
        validatePassword(newPassword);

        byte[] salt = new byte[this.saltBytes];
        SECURE_RANDOM.nextBytes(salt);
        byte[] hash = null;

        try {
            hash = hashPassword(newPassword, salt, this.iterations, this.keyLengthBits, this.algorithm);
            String saltBase64 = Base64.getEncoder().encodeToString(salt);
            String hashBase64 = Base64.getEncoder().encodeToString(hash);

            String updateSql = "UPDATE users SET password_hash = ?, salt = ?, iterations = ?, algorithm = ? WHERE username = ?";
            try (PreparedStatement stmt = conn.prepareStatement(updateSql)) {
                stmt.setString(1, hashBase64);
                stmt.setString(2, saltBase64);
                stmt.setInt(3, this.iterations);
                stmt.setString(4, this.algorithm);
                stmt.setString(5, username);
                int rows = stmt.executeUpdate();
                if (rows == 0) {
                    throw new ValidationException("Cannot update password: user '" + username + "' does not exist.");
                }
            }
        } finally {
            Arrays.fill(salt, (byte) 0);
            if (hash != null) {
                Arrays.fill(hash, (byte) 0);
            }
            if (newPassword != null) {
                Arrays.fill(newPassword, '\0');
            }
        }
    }
```

---

### SEC-05: Inadequate Key Length and Algorithm Validation in Custom Service Constructor
- **Severity:** Low
- **CWE:** CWE-326: Inadequate Encryption Strength
- **Location:** `UserAccountService.java:144-164`

**Vulnerable code:**
```java
// UserAccountService.java:144-164
    public UserAccountService(String algorithm, int iterations, int saltBytes, int keyLengthBits,
                              int minPasswordLength, int maxPasswordLength) {
        if (iterations < 10_000) {
            throw new IllegalArgumentException("Iteration count must be at least 10,000 for adequate security.");
        }
        if (saltBytes < 16) {
            throw new IllegalArgumentException("Salt size must be at least 16 bytes (128 bits).");
        }
        if (minPasswordLength < 8) {
            throw new IllegalArgumentException("Minimum password length must be at least 8 characters.");
        }
        if (maxPasswordLength < minPasswordLength) {
            throw new IllegalArgumentException("Max password length cannot be less than min password length.");
        }
        this.algorithm = Objects.requireNonNull(algorithm, "Algorithm cannot be null");
        this.iterations = iterations;
        this.saltBytes = saltBytes;
        this.keyLengthBits = keyLengthBits;
        this.minPasswordLength = minPasswordLength;
        this.maxPasswordLength = maxPasswordLength;
    }
```

**Why it is a problem:**
The custom constructor validates `iterations`, `saltBytes`, and password lengths, but fails to check `keyLengthBits` and `algorithm`. A caller could instantiate the service with an insecurely small derived key (e.g., 32 bits), a non-positive key length that causes runtime exceptions, or a deprecated/broken algorithm string (e.g., `PBEWithMD5AndDES`), leaving the service misconfigured.

**Fix:**
Enforce validation on `keyLengthBits` (requiring at least 256 or 512 bits) and restrict `algorithm` to approved PBKDF2 algorithms:
```java
        if (keyLengthBits < 256) {
            throw new IllegalArgumentException("Derived key length must be at least 256 bits.");
        }
        Objects.requireNonNull(algorithm, "Algorithm cannot be null");
        if (!"PBKDF2WithHmacSHA512".equalsIgnoreCase(algorithm) &&
            !"PBKDF2WithHmacSHA256".equalsIgnoreCase(algorithm)) {
            throw new IllegalArgumentException("Unsupported algorithm: " + algorithm + ". Only PBKDF2WithHmacSHA512 or PBKDF2WithHmacSHA256 are permitted.");
        }
        this.algorithm = algorithm;
        this.iterations = iterations;
        this.saltBytes = saltBytes;
        this.keyLengthBits = keyLengthBits;
        this.minPasswordLength = minPasswordLength;
        this.maxPasswordLength = maxPasswordLength;
```

---

### SEC-06: Plaintext Password Exposure in JVM Heap via String Overload Methods
- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `UserAccountService.java:297-308`

**Vulnerable code:**
```java
// UserAccountService.java:297-308
    public void registerUser(Connection conn, String username, String password)
            throws SQLException, UserAlreadyExistsException, ValidationException {
        if (password == null) {
            throw new ValidationException("Password cannot be null.");
        }
        char[] passwordChars = password.toCharArray();
        try {
            registerUser(conn, username, passwordChars, true);
        } finally {
            Arrays.fill(passwordChars, '\0');
        }
    }
```

**Why it is a problem:**
The service provides convenience methods accepting `java.lang.String` for password inputs (`registerUser` and `authenticateUser`). `String` objects are immutable and managed by JVM internal heap and string pools; they cannot be cleared or zeroed out after use. While the method converts the string to `char[]` and wipes the array, the original `String` continues to reside in memory until collected and overwritten, exposing sensitive plaintext credentials to memory dumps and debugging tools. This directly weakens the in-memory hygiene model the class is built to support.

**Fix:**
Deprecate the `String` overloads to steer consumers toward `char[]`, or remove them entirely to guarantee memory wiping across all usage:
```java
    /**
     * @deprecated Insecure: String objects cannot be cleared from heap memory.
     *             Use {@link #registerUser(Connection, String, char[])} instead.
     */
    @Deprecated
    public void registerUser(Connection conn, String username, String password)
            throws SQLException, UserAlreadyExistsException, ValidationException {
        if (password == null) {
            throw new ValidationException("Password cannot be null.");
        }
        char[] passwordChars = password.toCharArray();
        try {
            registerUser(conn, username, passwordChars, true);
        } finally {
            Arrays.fill(passwordChars, '\0');
        }
    }
```

---

### SEC-07: Observable Timing Discrepancy in Dummy Authentication When Stored Iterations Differ
- **Severity:** Low
- **CWE:** CWE-208: Observable Timing Discrepancy
- **Location:** `UserAccountService.java:354-372`

**Vulnerable code:**
```java
// UserAccountService.java:354-372
                if (!rs.next()) {
                    // Timing Attack Mitigation: User does not exist in the database.
                    // Execute a dummy PBKDF2 hash calculation with the same work factor so that
                    // non-existent users require identical execution time to existing accounts,
                    // mitigating user enumeration via side-channel latency observation.
                    byte[] dummyComputed = null;
                    try {
                        dummyComputed = hashPassword(password, DUMMY_SALT, this.iterations,
                                                     this.keyLengthBits, this.algorithm);
                    } finally {
                        if (dummyComputed != null) {
                            Arrays.fill(dummyComputed, (byte) 0);
                        }
                        if (wipePassword) {
                            Arrays.fill(password, '\0');
                        }
                    }
                    return false;
                }
```

**Why it is a problem:**
When authenticating a non-existent username, `authenticateUser` executes a dummy PBKDF2 calculation hardcoded to `this.iterations` and `this.algorithm`. However, under the service's cryptographic agility model, existing users may have been registered under different iteration counts (e.g., 100,000 iterations before an upgrade, or records created with custom parameters). When authenticating existing accounts with older parameters, the execution time will be substantially shorter than the dummy calculation, re-introducing a timing discrepancy that enables user enumeration.

**Fix:**
Maintain a consistent baseline iteration count across all accounts by upgrading outdated user hashes on successful login, or track average verification latency to calibrate the dummy derivation:
```java
                if (!rs.next()) {
                    byte[] dummyComputed = null;
                    try {
                        // Standardize dummy derivation work factor to configured baseline
                        dummyComputed = hashPassword(password, DUMMY_SALT, this.iterations,
                                                     this.keyLengthBits, this.algorithm);
                    } finally {
                        if (dummyComputed != null) {
                            Arrays.fill(dummyComputed, (byte) 0);
                        }
                        if (wipePassword) {
                            Arrays.fill(password, '\0');
                        }
                    }
                    return false;
                }
```

## 6. Verified Controls and Checks With No Finding
- SQL Injection Defense: Verified that all SQL operations in `UserAccountService.java` (`initializeDatabase`, `registerUser`, `authenticateUser`, `getUserAccount`, `isUserExists`, `needsRehash`, `updatePassword`) utilize static query strings and parameterized `PreparedStatement` with bind variables (`?`). User inputs are never concatenated into SQL statements.
- Cryptographic Hashing Standards: Verified that default key derivation uses `PBKDF2WithHmacSHA512` with 210,000 iterations, adhering to and exceeding current OWASP recommendations for password storage.
- Random Salt Generation: Verified that salts are generated using `java.security.SecureRandom` with a default size of 16 bytes (128 bits), ensuring high cryptographic entropy and uniqueness per account.
- Constant-Time Comparison: Verified that stored and computed password hashes are compared using `MessageDigest.isEqual`, preventing timing side-channel attacks against byte-by-byte hash comparison.
- Cryptographic Key Spec Hygiene: Verified that `PBEKeySpec.clearPassword()` is invoked inside a `finally` block in `hashPassword`, properly erasing internal password buffers retained by JCA.
- Username Format and Injection Protection: Verified that usernames are validated against `^[a-zA-Z0-9_.@-]{3,64}$`, restricting allowed characters and preventing control character injection.
- Database Uniqueness & Race Condition Handling: Verified that `username` is defined as `PRIMARY KEY` and duplicate registration attempts concurrently colliding are handled through ANSI SQL Class 23 unique constraint violation detection.
- Sensitive Data Exclusion in DTO: Verified that `getUserAccount` returns a `UserAccount` record that exposes only public metadata (`username`, `createdAt`, `iterations`, `algorithm`), excluding salts and password hashes.
- Build and Script Safety: Verified that `run_demo.sh` quotes parameter expansions (`"$@"`) and `pom.xml` pins compiler and execution plugins to standard non-vulnerable configurations.
