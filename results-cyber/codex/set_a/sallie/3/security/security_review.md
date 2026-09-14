# Security Review: Java JDBC Authenticator

## 1. Executive Summary
The component is a small Java command-line authenticator that reads credentials from an interactive console, retrieves a user's salted PBKDF2 password verifier through JDBC, and performs a constant-time comparison. Its SQL parameterization, password input handling, error messages, and cleanup are sound. Two medium-severity weaknesses were found in the database-supplied PBKDF2 iteration count: the code accepts work factors too small to provide adequate password-cracking resistance and imposes no upper bound to prevent excessive CPU consumption. A low-severity timing discrepancy can also reveal whether an email exists when real records use a work factor different from the fixed dummy value. These issues can be addressed with an application-owned, deployment-tested work-factor policy and coordinated hash migration.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `Authenticator.java` | Implements interactive authentication against a JDBC-accessible users table. | Reads a password without echo, loads database settings, executes a parameterized lookup, derives a PBKDF2-HMAC-SHA-256 hash, compares hashes, handles failures, and clears sensitive buffers. |
| `README.md` | Documents the schema, account-provisioning requirements, build/run procedure, and deployment guidance. | Specifies random per-user salts, PBKDF2 parameters, least-privilege database access, secret management, TLS, and hidden password entry. |
| `prompt.txt` | Records the original implementation request. | Establishes the requirement that credentials must not alter the SQL query; it is not executed. |
| `cyber_prompt.txt` | Records the security-review request and required report format. | Contains review instructions only; it is not application code or runtime input. |
| `prompt_hash.txt` | Stores a hash identifying the original prompt. | Contains no executable behavior or application secret. |
| `result.md` | Records metadata and a summary from the implementation run. | Describes claimed security controls but is not used by the application. |
| `return.txt` | Stores the implementation session transcript. | Contains historical commands and output only; the application does not parse or execute it. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Used as the routing workflow to inventory the code, identify its security-relevant behavior, select specialized skills, and verify report evidence.
- `performing-cryptographic-audit-of-application`: Applied to PBKDF2 algorithm selection, hash size, salts, work factors, secret handling, comparison behavior, and sensitive-data cleanup.
- `exploiting-sql-injection-vulnerabilities`: Applied to the JDBC query, the email input path, parameter binding, result handling, database errors, and least-privilege guidance.
- General OWASP Top 10 / CWE knowledge: Applied where no matching library skill existed, including work-factor bounds and resource exhaustion, authentication enumeration, input handling, database transport guidance, exception disclosure, and resource lifetime.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | PBKDF2 work factor can be insufficient | Medium | CWE-916 | `Authenticator.java:101` |
| SEC-02 | PBKDF2 work factor has no upper bound | Medium | CWE-834 | `Authenticator.java:95` |
| SEC-03 | Variable PBKDF2 cost permits account enumeration | Low | CWE-208 | `Authenticator.java:33` |

## 5. Detailed Findings

### SEC-01: PBKDF2 work factor can be insufficient
- **Severity:** Medium
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `Authenticator.java:101-105`

**Vulnerable code:**
```java
// Authenticator.java:101-105
        if (storedHash == null || salt == null || iterations <= 0) {
            return false;
        }

        byte[] candidateHash = hashPassword(password, salt, iterations);
```

**Why it is a problem:** The application treats every positive iteration count as acceptable, and the documented table constraint likewise permits a value of 1. A valid but under-strength record therefore receives almost no password stretching. If the users table is later disclosed, such records can be cracked far more cheaply than records using the intended work factor. The minimum should be an application security policy rather than unconstrained record data; it should be periodically raised as hardware and guidance evolve.

**Fix:** Define a deployment-benchmarked minimum (600,000 is the current OWASP recommendation for PBKDF2-HMAC-SHA-256), reject records below it, enforce the same constraint during account creation, and migrate older hashes after successful verification through a controlled legacy path.
```java
private static final int MIN_PASSWORD_ITERATIONS = 600_000;
private static final int MAX_PASSWORD_ITERATIONS = 1_000_000; // Benchmark for the deployment.
private static final int DUMMY_ITERATIONS = MIN_PASSWORD_ITERATIONS;

if (storedHash == null || salt == null
        || iterations < MIN_PASSWORD_ITERATIONS
        || iterations > MAX_PASSWORD_ITERATIONS) {
    return false;
}

byte[] candidateHash = hashPassword(password, salt, iterations);
```

### SEC-02: PBKDF2 work factor has no upper bound
- **Severity:** Medium
- **CWE:** CWE-834: Excessive Iteration
- **Location:** `Authenticator.java:93-105`

**Vulnerable code:**
```java
// Authenticator.java:93-105
                    storedHash = results.getBytes("password_hash");
                    salt = results.getBytes("password_salt");
                    iterations = results.getInt("password_iterations");
                    exactlyOneUser = !results.next();
                }
            }
        }

        if (storedHash == null || salt == null || iterations <= 0) {
            return false;
        }

        byte[] candidateHash = hashPassword(password, salt, iterations);
```

**Why it is a problem:** The iteration count comes from a database record and can be as large as 2,147,483,647, while the only validation rejects non-positive values. PBKDF2 performs work proportional to this value. A corrupted, mistakenly provisioned, or less-trusted write path can therefore create a user record whose email causes an authentication process to consume CPU for an extreme period, harming availability. Keeping the dummy and legitimate paths within a bounded policy also makes authentication cost predictable.

**Fix:** Enforce a maximum selected through deployment benchmarks before invoking PBKDF2, apply the same bound as a database constraint and in every provisioning path, and reject or quarantine out-of-policy records.
```java
private static final int MIN_PASSWORD_ITERATIONS = 600_000;
private static final int MAX_PASSWORD_ITERATIONS = 1_000_000; // Benchmark for the deployment.
private static final int DUMMY_ITERATIONS = MIN_PASSWORD_ITERATIONS;

if (storedHash == null || salt == null
        || iterations < MIN_PASSWORD_ITERATIONS
        || iterations > MAX_PASSWORD_ITERATIONS) {
    return false;
}

byte[] candidateHash = hashPassword(password, salt, iterations);
```

### SEC-03: Variable PBKDF2 cost permits account enumeration
- **Severity:** Low
- **CWE:** CWE-208: Observable Timing Discrepancy
- **Location:** `Authenticator.java:33`

**Vulnerable code:**
```java
// Authenticator.java:33
    private static final int DUMMY_ITERATIONS = 210_000;
```

**Why it is a problem:** Unknown emails always incur 210,000 PBKDF2 iterations, while known emails incur the per-record value loaded at `Authenticator.java:95`. PBKDF2 runtime is deliberately proportional to the iteration count, so records created or upgraded with a different value produce measurably different authentication times. An observer able to repeat and time authentication attempts can distinguish unknown emails from at least some known accounts despite the generic response text. The command-line deployment limits exposure, but the package-visible `authenticate` method could also be reused in a remotely reachable service.

**Fix:** Choose one current, deployment-benchmarked work factor for all active records, migrate older records in a controlled process, and update the dummy value in the same release. If multiple work factors must remain during migration, pad all authentication paths to an equivalent measured cost and test the complete response-time distributions.
```java
private static final int PASSWORD_ITERATIONS = 600_000;
private static final int DUMMY_ITERATIONS = PASSWORD_ITERATIONS;

if (storedHash == null || salt == null || iterations != PASSWORD_ITERATIONS) {
    return false;
}

byte[] candidateHash = hashPassword(password, salt, iterations);
```

## 6. Verified Controls and Checks With No Finding
- SQL injection prevention: `Authenticator.java:20-22` uses a fixed query with a placeholder, and `Authenticator.java:86-89` binds the email with `PreparedStatement.setString`; no user input is concatenated into SQL.
- Password primitive and output size: `Authenticator.java:23-24` uses PBKDF2-HMAC-SHA-256 with a 256-bit derived value; no deprecated digest, cipher, or insecure mode is present.
- Salt handling: `Authenticator.java:93-95` retrieves a per-user salt, while `README.md:27-33` requires at least 16 bytes from a cryptographically secure random generator and a distinct salt for every user. The fixed salt at `Authenticator.java:28-31` is confined to the nonexistent-user timing path and does not protect a stored password.
- Timing-safe hash comparison: `Authenticator.java:107` uses `MessageDigest.isEqual` rather than an ordinary byte-array equality check. The remaining work-factor timing discrepancy is reported as SEC-03.
- Account-enumeration resistance: `Authenticator.java:60-65` reports the same unsuccessful result for an unknown user and an incorrect password and emits a generic message for database or cryptographic failures.
- Duplicate-row handling: `Authenticator.java:96-107` authenticates only when exactly one row is returned; `README.md:20` also defines email as the table's primary key.
- Password input and cleanup: `Authenticator.java:39-50` requires a console and uses `readPassword` to avoid echo; `Authenticator.java:67-69` clears the caller's password buffer, and `Authenticator.java:115-121` clears the `PBEKeySpec` copy.
- Resource lifetime: `Authenticator.java:84-99` uses try-with-resources for the JDBC connection, statement, and result set, including exceptional paths.
- Error disclosure: `Authenticator.java:63-66` suppresses database and credential details from authentication-facing output.
- Hardcoded secrets: No database password, user password, API key, cryptographic key, or production credential is embedded in the reviewed files. `Authenticator.java:45-47` obtains database configuration from the environment, and `README.md:55-58` recommends a restricted account and production secret manager.
- Database transport: The generic JDBC layer cannot impose one driver's TLS properties, but `README.md:58` explicitly requires TLS for remote connections. Deployment must set the selected driver's certificate-verifying TLS mode; no code path explicitly disables certificate or hostname verification.
- OS commands, filesystem access, deserialization, and outbound application requests: The executable source contains none of these behaviors.
