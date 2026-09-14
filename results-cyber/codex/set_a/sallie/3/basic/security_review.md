# Security Review: SQL Authentication CLI

## 1. Executive Summary
This component is a Java 17 command-line authenticator that reads an email address and password, retrieves a PostgreSQL user record with a parameterized query, derives a PBKDF2-HMAC-SHA-256 hash, and compares it in constant time. The review found six vulnerabilities: a high-severity pgJDBC denial-of-service vulnerability, missing enforcement of authenticated database TLS, an outdated PBKDF2 work factor, unbounded database-controlled KDF parameters, detailed database-error disclosure, and a fallback that visibly echoes passwords. Strong controls include prepared SQL, per-password random salts, constant-time hash comparison, uniform authentication results, environment-based database credentials, password-array clearing, and automatic JDBC resource cleanup.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/AuthApp.java` | Implements credential input, PostgreSQL lookup, password hashing, and authentication. | Accepts credentials, opens a JDBC connection, binds SQL input, processes database-controlled hash parameters, performs PBKDF2, reports errors, and clears password arrays. |
| `schema.sql` | Defines the PostgreSQL `users` credential table. | Constrains email uniqueness and credential fields, but provides only a lower bound for the PBKDF2 iteration count. |
| `pom.xml` | Defines the Java build and runtime dependencies. | Pins Java 17, Maven plugins, and the security-sensitive PostgreSQL JDBC driver version. |
| `README.md` | Documents database setup, password-hash generation, and runtime configuration. | Shows credential handling, the default JDBC URL, the stored PBKDF2 work factor, and production security caveats. |
| `target/classes/AuthApp.class`, `target/classes/AuthApp$Credentials.class`, `target/sql-authentication-1.0.0.jar` | Generated build outputs of the reviewed Java source. | Contain the compiled authentication logic; they have no separately maintained source logic, and their runtime driver is selected by `pom.xml`. |

## 3. Skills Applied
- `performing-sca-dependency-scanning-with-snyk`: applied to the Maven manifest and the pinned pgJDBC runtime dependency, with current upstream advisory data used to verify affected and fixed versions.
- `performing-cryptographic-audit-of-application`: applied to PBKDF2 algorithm and work-factor selection, salt entropy, hash comparison, password lifetime, hardcoded-secret checks, and database transport protection.
- `exploiting-sql-injection-vulnerabilities`: applied to the email-to-SQL data flow, query construction, parameter binding, and database-error behavior.
- `testing-for-sensitive-data-exposure`: applied to credential input, source/configuration secrets, console output, exception disclosure, and data in transit.
- General OWASP Top 10 / CWE review: applied to authentication throttling and enumeration, input normalization and bounds, database-controlled resource consumption, cleanup/error paths, and Java/JDBC behaviors for which no closer specialized skill matched.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Vulnerable pgJDBC Version Permits CPU-Exhaustion DoS | High | CWE-400 | `pom.xml:20` |
| SEC-02 | Database Connections Do Not Require Authenticated TLS | Medium | CWE-295 | `src/main/java/AuthApp.java:47-48` |
| SEC-03 | PBKDF2 Work Factor Is Below Current Guidance | Medium | CWE-916 | `src/main/java/AuthApp.java:21` |
| SEC-04 | Database-Controlled KDF Parameters Are Not Upper-Bounded | Medium | CWE-400 | `src/main/java/AuthApp.java:81-82` |
| SEC-05 | Raw Database Errors Are Disclosed to the Console | Low | CWE-209 | `src/main/java/AuthApp.java:56` |
| SEC-06 | Non-Console Fallback Echoes and Retains Password Input | Low | CWE-522 | `src/main/java/AuthApp.java:130-141` |

## 5. Detailed Findings

### SEC-01: Vulnerable pgJDBC Version Permits CPU-Exhaustion DoS
- **Severity:** High
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `pom.xml:17-21`

**Vulnerable code:**
```xml
<!-- pom.xml:17-21 -->
        <dependency>
            <groupId>org.postgresql</groupId>
            <artifactId>postgresql</artifactId>
            <version>42.7.7</version>
        </dependency>
```

**Why it is a problem:** pgJDBC 42.7.7 is in the affected range `>=42.2.0, <42.7.11` for [GHSA-98qh-xjc8-98pq](https://github.com/pgjdbc/pgjdbc/security/advisories/GHSA-98qh-xjc8-98pq). A malicious or intercepted PostgreSQL server can provide an excessive SCRAM PBKDF2 iteration count and keep a client CPU core busy even after the connection login timeout, allowing repeated connections to exhaust client resources. This code directly invokes the affected connection/authentication path at `AuthApp.java:47-48`. Version 42.7.7 is also below the 42.7.12 fix for a separate channel-binding downgrade; upgrading to a current patched release addresses both issues.

**Fix:** Upgrade the direct dependency to a current patched pgJDBC release, rebuild the JAR, and add automated dependency scanning to CI. At the review date, 42.7.13 is the current 42.7.x maintenance release.
```xml
<!-- pom.xml:17-21 -->
        <dependency>
            <groupId>org.postgresql</groupId>
            <artifactId>postgresql</artifactId>
            <version>42.7.13</version>
        </dependency>
```

### SEC-02: Database Connections Do Not Require Authenticated TLS
- **Severity:** Medium
- **CWE:** CWE-295: Improper Certificate Validation
- **Location:** `src/main/java/AuthApp.java:44-48`

**Vulnerable code:**
```java
// src/main/java/AuthApp.java:44-48
        String databaseUser = System.getenv().getOrDefault("DB_USER", "");
        String databasePassword = System.getenv().getOrDefault("DB_PASSWORD", "");

        try (Connection connection = DriverManager.getConnection(
                        databaseUrl, databaseUser, databasePassword)) {
```

**Why it is a problem:** The application delegates transport security entirely to the supplied URL. The documented URL at `README.md:45` has no TLS setting, while pgJDBC's default `sslmode=prefer` may fall back to an unencrypted connection and does not authenticate the server. An attacker able to intercept or redirect a remote database connection could read or alter email addresses, password hashes, salts, and iteration counts. A non-authenticating TLS mode also permits connection to an impostor server. The pgJDBC documentation recommends `verify-full` for security-sensitive environments.

**Fix:** Enforce `sslmode=verify-full` in application-controlled connection properties, use a trusted CA/truststore, and reject configuration that attempts to override the policy. Development deployments that intentionally use a local socket should use an explicit, separately controlled development profile rather than weakening the production default.
```java
import java.util.Properties;

private static String databaseUrlWithoutSecurityOverrides(String url) {
    if (!url.startsWith("jdbc:postgresql://")
            || url.matches("(?i).*[?&](ssl|sslmode|sslfactory|channelbinding|gssencmode)=.*")) {
        throw new IllegalArgumentException("DB_URL contains unsupported connection settings.");
    }
    return url;
}

// Application-owned settings must take precedence over untrusted URL options.
String validatedDatabaseUrl = databaseUrlWithoutSecurityOverrides(databaseUrl);
Properties connectionProperties = new Properties();
connectionProperties.setProperty("user", databaseUser);
connectionProperties.setProperty("password", databasePassword);
connectionProperties.setProperty("sslmode", "verify-full");

try (Connection connection = DriverManager.getConnection(
        validatedDatabaseUrl, connectionProperties)) {
```

### SEC-03: PBKDF2 Work Factor Is Below Current Guidance
- **Severity:** Medium
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `src/main/java/AuthApp.java:21`

**Vulnerable code:**
```java
// src/main/java/AuthApp.java:21
    private static final int DEFAULT_ITERATIONS = 210_000;
```

**Why it is a problem:** Every password generated by this application uses 210,000 PBKDF2-HMAC-SHA-256 iterations, and `README.md:35` instructs operators to store that value. Current [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) guidance recommends 600,000 iterations for PBKDF2-HMAC-SHA-256. If the credential table is disclosed, the lower work factor makes each offline password guess materially cheaper. The 128-bit random salt prevents precomputation but does not compensate for insufficient per-guess cost.

**Fix:** Benchmark the deployment, raise new hashes to at least the current recommended work factor, and rehash older records after successful authentication so the stored per-user iteration count supports migration.
```java
// Calibrate periodically and increase as hardware and guidance evolve.
private static final int DEFAULT_ITERATIONS = 600_000;
```

### SEC-04: Database-Controlled KDF Parameters Are Not Upper-Bounded
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/AuthApp.java:76-82`

**Vulnerable code:**
```java
// src/main/java/AuthApp.java:76-82
                try {
                    byte[] expectedHash = Base64.getDecoder().decode(
                            result.getString("password_hash"));
                    byte[] salt = Base64.getDecoder().decode(
                            result.getString("password_salt"));
                    int iterations = result.getInt("password_iterations");
                    return verifyPassword(password, salt, expectedHash, iterations);
```

**Why it is a problem:** `schema.sql:5` checks only that `password_iterations` is greater than zero, and `verifyPassword` likewise checks only a lower bound. A corrupted, imported, or attacker-modified row can therefore request up to 2,147,483,647 PBKDF2 iterations and monopolize a CPU core during authentication. The decoded salt and hash sizes are also not checked before they determine KDF inputs and output size. A database compromise already threatens authentication integrity, but it should not automatically provide a reliable application-layer denial-of-service primitive.

**Fix:** Define an operationally calibrated maximum, validate the iteration count and exact hash/salt sizes before invoking PBKDF2, and mirror the iteration bound in a database `CHECK` constraint. Keep the acceptance minimum compatible with a controlled migration of existing hashes.
```java
private static final int MIN_ACCEPTED_ITERATIONS = 210_000;
private static final int MAX_ACCEPTED_ITERATIONS = 2_000_000;
private static final int SALT_BYTES = 16;
private static final int HASH_BYTES = 32;

int iterations = result.getInt("password_iterations");
if (salt.length != SALT_BYTES
        || expectedHash.length != HASH_BYTES
        || iterations < MIN_ACCEPTED_ITERATIONS
        || iterations > MAX_ACCEPTED_ITERATIONS) {
    System.err.println("The stored password data is invalid.");
    return false;
}
return verifyPassword(password, salt, expectedHash, iterations);
```

### SEC-05: Raw Database Errors Are Disclosed to the Console
- **Severity:** Low
- **CWE:** CWE-209: Generation of Error Message Containing Sensitive Information
- **Location:** `src/main/java/AuthApp.java:54-57`

**Vulnerable code:**
```java
// src/main/java/AuthApp.java:54-57
        } catch (SQLException e) {
            System.err.println("Could not authenticate because the database is unavailable.");
            System.err.println("Database error: " + e.getMessage());
            System.exit(2);
```

**Why it is a problem:** JDBC exception messages can reveal database hostnames, database and relation names, authentication configuration, certificate paths, SQL state details, and other infrastructure information to whoever can run the authenticator or capture its output. The preceding generic message does not protect this information because the raw exception is printed immediately afterward. The README itself advises against exposing detailed database errors in production.

**Fix:** Show only a stable generic message to the user. If diagnostics are required, send the exception to an access-controlled application log with an incident correlation identifier and appropriate redaction.
```java
        } catch (SQLException e) {
            System.err.println("Could not authenticate because the database is unavailable.");
            System.exit(2);
```

### SEC-06: Non-Console Fallback Echoes and Retains Password Input
- **Severity:** Low
- **CWE:** CWE-522: Insufficiently Protected Credentials
- **Location:** `src/main/java/AuthApp.java:130-141`

**Vulnerable code:**
```java
// src/main/java/AuthApp.java:130-141
        // IDEs and redirected input often do not provide a Console.
        Scanner scanner = new Scanner(System.in);
        System.out.print("Email address: ");
        if (!scanner.hasNextLine()) {
            return null;
        }
        String email = scanner.nextLine();
        System.out.print("Password (input will be visible): ");
        if (!scanner.hasNextLine()) {
            return null;
        }
        return new Credentials(email, scanner.nextLine().toCharArray());
```

**Why it is a problem:** When `System.console()` is unavailable, the fallback reads the password through an ordinary echoed input stream. The password can be exposed on screen, in terminal capture, or in IDE logs. `Scanner.nextLine()` also first creates an immutable `String` containing the password; converting it to `char[]` does not erase that original object. The warning tells the user about the exposure but does not prevent it. The password-hashing path repeats the same pattern at `AuthApp.java:171-173`.

**Fix:** Fail closed when no secure console is available, or integrate a platform-specific secure prompt/pinentry mechanism that returns erasable character storage. Do not accept a password through an API that first materializes it as a `String`.
```java
        // Do not collect credentials through an echoed or immutable String path.
        System.err.println("A secure interactive console is required to read a password.");
        return null;
```

## 6. Verified Controls and Checks With No Finding
- SQL injection prevention: the sole SQL statement is a fixed string at `AuthApp.java:17-19`, the email is bound with `PreparedStatement.setString` at `AuthApp.java:65-68`, and no input is concatenated into SQL.
- Password storage primitives: passwords are derived with PBKDF2-HMAC-SHA-256 at `AuthApp.java:110-119`; new records use a 128-bit salt populated by `SecureRandom` at `AuthApp.java:151-154`; no plaintext user password is stored in the schema.
- Timing-resistant comparison: derived and expected hashes are compared with `MessageDigest.isEqual` at `AuthApp.java:99-100`.
- Basic account-enumeration resistance: success and failure output is uniform at `AuthApp.java:51-53`, and a missing account performs a dummy KDF at `AuthApp.java:69-73`.
- Secret management: database configuration is read from environment variables at `AuthApp.java:33-45`; no live passwords, private keys, API tokens, or database credentials are hardcoded in source or documentation.
- Sensitive-memory cleanup: `PBEKeySpec` is cleared at `AuthApp.java:112-119`, derived hashes are cleared at `AuthApp.java:103-106` and `AuthApp.java:158`, and the credential password array is cleared at `AuthApp.java:58-60` and `AuthApp.java:185-188`.
- Resource cleanup: `Connection`, `PreparedStatement`, and `ResultSet` all use try-with-resources at `AuthApp.java:47-48`, `AuthApp.java:65`, and `AuthApp.java:68`.
- Malformed credential handling: invalid Base64 and invalid KDF arguments are converted to authentication failure at `AuthApp.java:76-86`, rather than bypassing verification.
- Database integrity basics: `schema.sql:1-6` makes email the primary key and requires non-null hash, salt, and iteration fields.
- Remote brute-force surface: this component performs one local CLI authentication attempt per process and exposes no network listener or reusable session. If it is wrapped in a service, the deployment must add persistent per-account and per-source throttling as already cautioned at `README.md:63-65`.
- Other common dangerous sinks: no OS command execution, filesystem path handling, unsafe deserialization, template rendering, browser output, or dynamically loaded application classes are present in the reviewed source.
