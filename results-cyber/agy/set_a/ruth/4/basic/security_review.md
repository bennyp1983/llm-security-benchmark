# Security Review: UserAccountService

## 1. Executive Summary
The codebase implements `UserAccountService`, a Java component responsible for user registration, credential persistence, and user authentication against an SQL database using standard JDBC. It includes programmatic schema initialization, salted password hashing using PBKDF2 with HMAC-SHA512, timing-attack countermeasures, and unit tests using an in-memory H2 database.

Overall, the core architecture demonstrates strong baseline security practices: SQL queries consistently use parameterized `PreparedStatement` instances to eliminate SQL injection, password hashing follows current OWASP recommendations (PBKDF2-HMAC-SHA512 with 210,000 iterations and 16-byte random salts), and credential comparisons employ constant-time evaluation alongside dummy hash calculations for non-existent users. However, five security vulnerabilities across Medium and Low severity were identified: a weak password policy allowing single-character passwords (SEC-01), missing input length constraints on authentication endpoints exposing the service to Denial of Service via oversized inputs (SEC-02), sensitive credentials and derived keys lingering in heap memory due to incomplete array clearing (SEC-03), lack of username sanitization permitting control characters and deceptive formatting (SEC-04), and overly broad SQL exception matching that misclassifies database syntax errors and non-uniqueness constraint violations as duplicate user registrations (SEC-05).

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `UserAccountService.java` | Core service class providing user registration, credential storage, and authentication APIs. | Executes DDL table creation; executes parameterized SQL INSERT and SELECT queries; generates cryptographic salts with `SecureRandom`; computes PBKDF2-HMAC-SHA512 hashes; performs dummy hashing and constant-time comparisons; validates input constraints; handles SQL exceptions for duplicate keys. |
| `src/test/java/UserAccountServiceTest.java` | Automated JUnit 5 unit test suite for the service. | Validates account registration, password hashing and salting, distinct salts across users, duplicate username rejection, credential authentication, input validation error handling, and parameterized query resilience against SQL injection payloads. |
| `pom.xml` | Apache Maven project configuration and dependency manifest. | Declares external dependencies (`com.h2database:h2:2.2.224`, `org.junit.jupiter:junit-jupiter:5.10.2`), specifies Java compiler target version (Java 17), and configures test execution plugins. |
| `README.md` | System documentation and integration guide. | Documents security features, cryptographic parameters, ANSI SQL schema definitions, API usage examples, memory handling claims, and instructions for compiling and running the service. |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to assess cryptographic algorithm selection (`PBKDF2WithHmacSHA512`), iteration count adequacy (210,000 iterations), salt generation entropy (`SecureRandom` with 16 bytes), derived key bit length (256 bits), constant-time comparison correctness (`MessageDigest.isEqual`), dummy hashing mechanics, and in-memory credential clearing lifecycle.
- `exploiting-sql-injection-vulnerabilities`: Applied to inspect SQL query construction across `createUsersTable`, `registerUser`, `authenticateUser`, and `userExists`, checking for string concatenation, dynamic statement manipulation, and improper parameter binding.
- `testing-api-authentication-weaknesses`: Applied to examine credential validation logic, password policy enforcement, authentication timing differentials, username enumeration risks, and denial-of-service attack vectors on authentication handlers.
- General OWASP Top 10 and CWE knowledge: Applied to evaluate input validation and boundary enforcement (CWE-20), uncontrolled resource consumption in authentication (CWE-400), memory clearing neglect (CWE-316, CWE-244), and exception handling precision in database error recovery (CWE-390, CWE-754).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Weak Password Policy Permits Single-Character and Trivial Passwords | Medium | CWE-521 | `UserAccountService.java:330-332` |
| SEC-02 | Lack of Input Length Limits in Authentication Enables Denial of Service | Medium | CWE-400 | `UserAccountService.java:224-226` |
| SEC-03 | Cleartext Retention of Sensitive Credentials and Derived Keys in Memory | Low | CWE-316 | `UserAccountService.java:304-314` |
| SEC-04 | Unsanitized Username Input Permits Control Characters and Deceptive Formatting | Low | CWE-20 | `UserAccountService.java:324-329` |
| SEC-05 | Overly Broad SQLState Matching in Duplicate Key Detection Masks Syntax and System Errors | Low | CWE-390 | `UserAccountService.java:338-343` |

## 5. Detailed Findings

### SEC-01: Weak Password Policy Permits Single-Character and Trivial Passwords
- **Severity:** Medium
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `UserAccountService.java:330-332`

**Vulnerable code:**
```java
// UserAccountService.java:330-332
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password cannot be null or empty.");
        }
```

**Why it is a problem:**
The input validation method `validateInput` only ensures that the password is non-null and not 0 characters in length. As a result, passwords as short as a single character (e.g., `"a"` or `"1"`) or passwords consisting entirely of whitespace are accepted during user registration. NIST SP 800-63B (Section 5.1.1.2) and OWASP Password Storage guidelines require a minimum password length of at least 8 characters. Allowing short and trivial passwords leaves registered accounts highly vulnerable to credential stuffing, dictionary attacks, and online brute-force guessing.

**Fix:**
Enforce a minimum password length of at least 8 characters (or 12 characters for elevated security) and reject whitespace-only passwords during registration validation.
```java
        if (password == null || password.length < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters long.");
        }
```

### SEC-02: Lack of Input Length Limits in Authentication Enables Denial of Service
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `UserAccountService.java:224-226`

**Vulnerable code:**
```java
// UserAccountService.java:224-226
        if (username == null || username.trim().isEmpty() || password == null || password.length == 0) {
            return false;
        }
```

**Why it is a problem:**
While `registerUser` calls `validateInput` to enforce an upper bound of 1024 characters on passwords and 255 characters on usernames, `authenticateUser` does not invoke `validateInput` or apply any upper length restrictions. An unauthenticated attacker can submit arbitrarily large password strings or character arrays (e.g., tens or hundreds of megabytes) to `authenticateUser`. The authentication logic then clones the character array inside `PBEKeySpec` and executes the CPU-intensive PBKDF2 algorithm with 210,000 iterations (either using the stored salt or through `dummyHash`). Submitting excessively long passwords triggers heavy memory allocations and CPU consumption, leading to server thread starvation, excessive garbage collection pauses, and potential `OutOfMemoryError` conditions.

**Fix:**
Apply upper length bounds on both `username` and `password` inside `authenticateUser` before initiating database queries or executing cryptographic hashing.
```java
        if (username == null || username.trim().isEmpty() || username.length() > 255 ||
            password == null || password.length == 0 || password.length > 1024) {
            return false;
        }
```

### SEC-03: Cleartext Retention of Sensitive Credentials and Derived Keys in Memory
- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `UserAccountService.java:304-314`

**Vulnerable code:**
```java
// UserAccountService.java:304-314
    private static byte[] hashPassword(char[] password, byte[] salt) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH_BITS);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(HASH_ALGORITHM);
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Cryptographic algorithm unavailable: " + HASH_ALGORITHM, e);
        } finally {
            spec.clearPassword();
        }
    }
```

**Why it is a problem:**
The service claims to enforce in-memory security by clearing password specifications via `spec.clearPassword()`. However, `PBEKeySpec.clearPassword()` only zeroes out the internal defensive clone made inside `PBEKeySpec`; it does not clear the `password` array passed into `hashPassword`. Furthermore, in `registerUser(String, String)` and `authenticateUser(String, String)` (lines 86 and 183), calling `password.toCharArray()` creates a temporary character array that is never zeroed out. Additionally, the raw derived key bytes returned by `skf.generateSecret(spec).getEncoded()` in `registerUser` (line 139) and `authenticateUser` (line 251) remain in heap memory until cleared by the garbage collector. This leaves plaintext passwords and cryptographic keys exposed to inspection via memory dumps, process core dumps, and heap analysis (CWE-316, CWE-244).

**Fix:**
Explicitly zero out temporary `char[]` password arrays and derived key `byte[]` arrays using `java.util.Arrays.fill()` as soon as cryptographic encoding and verification are complete.
```java
    private static byte[] hashPassword(char[] password, byte[] salt) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH_BITS);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(HASH_ALGORITHM);
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Cryptographic algorithm unavailable: " + HASH_ALGORITHM, e);
        } finally {
            spec.clearPassword();
        }
    }

    public static boolean registerUser(Connection connection, String username, char[] password) throws SQLException {
        if (connection == null) {
            throw new IllegalArgumentException("Database connection cannot be null.");
        }
        validateInput(username, password);

        if (userExists(connection, username)) {
            return false;
        }

        byte[] salt = generateSalt();
        byte[] hash = hashPassword(password, salt);
        String saltBase64 = Base64.getEncoder().encodeToString(salt);
        String hashBase64 = Base64.getEncoder().encodeToString(hash);
        java.util.Arrays.fill(hash, (byte) 0);

        String insertSql = "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)";
        try (PreparedStatement stmt = connection.prepareStatement(insertSql)) {
            stmt.setString(1, username);
            stmt.setString(2, hashBase64);
            stmt.setString(3, saltBase64);
            int rowsAffected = stmt.executeUpdate();
            return rowsAffected > 0;
        } catch (SQLException ex) {
            if (isDuplicateKeyViolation(ex)) {
                return false;
            }
            throw ex;
        }
    }
```

### SEC-04: Unsanitized Username Input Permits Control Characters and Deceptive Formatting
- **Severity:** Low
- **CWE:** CWE-20: Improper Input Validation
- **Location:** `UserAccountService.java:324-329`

**Vulnerable code:**
```java
// UserAccountService.java:324-329
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be null or blank.");
        }
        if (username.length() > 255) {
            throw new IllegalArgumentException("Username cannot exceed 255 characters.");
        }
```

**Why it is a problem:**
`validateInput` checks whether `username.trim().isEmpty()` is true, but does not actually trim the username or restrict allowable characters before storing it in the database (`stmt.setString(1, username)`). Consequently, usernames containing leading or trailing whitespace (e.g., `"admin "` or `" admin"`), non-printable ASCII control characters, or newlines (`\r\n`) are permitted. In database engines that differentiate trailing whitespace (such as PostgreSQL and SQLite), an attacker can register `"admin "` to spoof the legitimate `"admin"` account. In engines with `PAD SPACE` collations (such as MySQL), collisions behave inconsistently across leading vs. trailing whitespace. Furthermore, embedded newlines and control characters can lead to Log Injection (CWE-117) when usernames are recorded in audit logs.

**Fix:**
Trim the username, enforce a strict character whitelist (such as alphanumeric characters, periods, underscores, and hyphens), and define minimum and maximum length boundaries.
```java
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be null or blank.");
        }
        String trimmed = username.trim();
        if (trimmed.length() < 3 || trimmed.length() > 64 || !trimmed.matches("^[a-zA-Z0-9_.-]+$")) {
            throw new IllegalArgumentException("Username must be between 3 and 64 characters and contain only alphanumeric characters, underscores, dots, or hyphens.");
        }
```

### SEC-05: Overly Broad SQLState Matching in Duplicate Key Detection Masks Syntax and System Errors
- **Severity:** Low
- **CWE:** CWE-390: Detection of Error Condition Without Action
- **Location:** `UserAccountService.java:338-343`

**Vulnerable code:**
```java
// UserAccountService.java:338-343
    private static boolean isDuplicateKeyViolation(SQLException ex) {
        String sqlState = ex.getSQLState();
        if (sqlState != null && (sqlState.startsWith("23") || sqlState.equals("42601"))) {
            return true;
        }
        int errorCode = ex.getErrorCode();
```

**Why it is a problem:**
`isDuplicateKeyViolation` uses `sqlState.startsWith("23") || sqlState.equals("42601")` to determine whether an `INSERT` failure was caused by a duplicate primary key collision. In PostgreSQL and ANSI SQL, SQLState `42601` is `syntax_error`, not a constraint violation. Furthermore, SQLState class `23` covers all integrity constraint violations, including `23502` (not null violation), `23503` (foreign key violation), and `23514` (check constraint violation), whereas only `23505` represents a unique key violation. If a database query fails due to a syntax error or an unrelated schema constraint failure, the service misinterprets the exception as a duplicate username collision and silently returns `false` instead of allowing the application to observe and log the underlying database error.

**Fix:**
Refine SQLState checks to match specific unique constraint violation codes (`23505` for PostgreSQL/ANSI, or `23000` when accompanied by vendor-specific error codes or messages), and remove `42601`.
```java
    private static boolean isDuplicateKeyViolation(SQLException ex) {
        String sqlState = ex.getSQLState();
        if ("23505".equals(sqlState)) {
            return true;
        }
        int errorCode = ex.getErrorCode();
        // SQLite = 19 (SQLITE_CONSTRAINT), MySQL = 1062 (ER_DUP_ENTRY), Oracle = 1 (ORA-00001)
        if (errorCode == 19 || errorCode == 1062 || errorCode == 1) {
            return true;
        }
        String msg = ex.getMessage();
        return msg != null && (msg.contains("unique") || msg.contains("UNIQUE") || msg.contains("Duplicate") || msg.contains("duplicate"));
    }
```

## 6. Verified Controls and Checks With No Finding
- SQL Injection Prevention (CWE-89): Verified that all SQL queries in `UserAccountService.java` use parameterized `PreparedStatement` placeholders (`?`) for user input, including registration insertion (`line 144`), credential selection (`line 228`), and user existence queries (`line 287`). The schema creation DDL in `createUsersTable` (`line 56`) uses a static, immutable query string. No dynamic string concatenation exists in database calls.
- Cryptographic Algorithm Selection and Work Factor (CWE-327, CWE-916): Verified that password hashing uses `PBKDF2WithHmacSHA512` with 210,000 iterations and a 256-bit derived key length (`lines 23-26`), which fully complies with OWASP Password Storage recommendations for PBKDF2-HMAC-SHA512.
- Cryptographic Salt Generation (CWE-338): Verified that per-user salts are generated using `java.security.SecureRandom` (`lines 28, 298-302`) with a length of 16 bytes (128 bits), ensuring cryptographically strong randomness and uniqueness across accounts.
- Constant-Time Credential Comparison (CWE-208): Verified that password hash verification utilizes `MessageDigest.isEqual(storedHash, computedHash)` (`line 254`), which executes in constant time and prevents timing side-channel attacks on hash byte equality.
- Timing-Based User Enumeration Defense: Verified that when an authentication attempt targets a non-existent username, `authenticateUser` executes `dummyHash(password)` (`lines 244-246, 316-321`) using a static dummy salt. This ensures the computationally expensive PBKDF2 operation executes regardless of whether the account exists, equalizing response times.
- Concurrency and Race Condition Handling (CWE-362): Verified that `registerUser` handles concurrent registration attempts for the same username by wrapping the database `INSERT` in exception handling that checks for unique key collisions (`lines 144-158`), mitigating check-then-act race conditions between the existence pre-check and row insertion.
- Production Secret and Credential Hardcoding (CWE-798): Verified that no hardcoded credentials, production secrets, or private keys exist within core service logic. Credentials present in `main` (`lines 383-391`) are isolated demonstration defaults for local in-memory H2 database testing.
- Dependency Vulnerabilities: Verified that project dependencies declared in `pom.xml` (`com.h2database:h2:2.2.224` and `org.junit.jupiter:junit-jupiter:5.10.2`) are current stable versions with no open critical vulnerabilities applicable to this service.
