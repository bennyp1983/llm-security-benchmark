# Security Review: User Authentication System

## 1. Executive Summary
This document presents the security review of the SQL User Authentication System located in this directory. The component is a Java-based authentication application that verifies user email addresses and passwords against credentials stored in an SQL database (defaulting to embedded H2 with fallback to an in-memory driver). The system incorporates several defense-in-depth controls, including parameterized `PreparedStatement` queries to prevent SQL injection, PBKDF2-HMAC-SHA256 password hashing with 100,000 iterations and 16-byte random salts, constant-time hash comparisons via `MessageDigest.isEqual()`, and dummy hash calculations to mitigate timing discrepancies for non-existent users.

Despite these positive cryptographic and query controls, several security vulnerabilities were identified. The most critical issue is the presence of hardcoded default credentials that are automatically seeded into the database on startup, establishing a permanent backdoor administrative account (`bob@example.com` / `AdminSecure456#`). In addition, the authentication service prematurely branches on disabled user accounts before credential verification, returning a differential error message that permits account enumeration. Other findings include sensitive credential leakage in domain entities, insecure command-line password arguments visible in process listings, exposure of technical database details in error messages, uncontrolled search paths for dynamic JDBC driver loading, and a lack of rate limiting or account lockout controls.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `UserAuthentication.java` | Main application source file containing CLI entrypoint, authentication service, password security logic, SQL repositories, and dynamic database connection management. | Handles password hashing (PBKDF2), constant-time comparison, database schema creation, credential queries, default account seeding, command-line argument processing, dynamic driver class loading, and error handling. |
| `pom.xml` | Maven project build configuration and dependency specification. | Defines compiler configuration (Java 17) and specifies third-party database dependency `com.h2database:h2` version `2.2.224`. |
| `lib/h2.jar` | Third-party binary library archive containing H2 Database Engine v2.2.224. | Provides embedded and in-memory SQL database functionality. |
| `lib/sqlite-jdbc.jar` | Third-party binary library archive containing SQLite JDBC Driver v3.45.1.0. | Provides SQLite JDBC driver implementations dynamically loaded if H2 is absent. |
| `lib/slf4j-api.jar` | Third-party binary library archive containing SLF4J API v1.7.36. | Logging facade dependency used by database drivers. |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to audit cryptographic primitives, key derivation functions (PBKDF2-HMAC-SHA256), iteration counts, salt generation entropy (`SecureRandom`), constant-time byte comparisons (`MessageDigest.isEqual()`), and detection of hardcoded secrets.
- `testing-api-authentication-weaknesses`: Applied to audit the authentication workflow, account enumeration vectors via differential response messages, credential verification order, and authentication brute-force resilience.
- `testing-for-sensitive-data-exposure`: Applied to audit domain models for excessive credential data exposure (password hashes and salts), process listing exposure (`args`), stack trace leakage, and raw SQL exception messages.
- `exploiting-sql-injection-vulnerabilities`: Applied to audit database query construction, verifying that parameterized queries (`PreparedStatement`) are consistently applied across query and insertion operations.
- `implementing-secret-scanning-with-gitleaks`: Applied to detect hardcoded accounts, passwords, and default configuration credentials in source code and usage outputs.
- General OWASP Top 10 / CWE Review:
  - CWE-427 (Uncontrolled Search Path Element / OWASP A08:2021): Applied to evaluate dynamic JAR loading from relative working directory paths via `URLClassLoader` and reflection.
  - CWE-307 (Improper Restriction of Excessive Authentication Attempts / OWASP A07:2021): Applied to evaluate the absence of login attempt throttling, rate limiting, and account lockout.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Hardcoded Credentials and Insecure Default Account Seeding | Critical | CWE-798 | `UserAuthentication.java:454-466` |
| SEC-02 | User Enumeration via Observable Response Discrepancy on Inactive Accounts | High | CWE-204 | `UserAuthentication.java:335-340` |
| SEC-03 | Excessive Sensitive Data Exposure in User Data Model | High | CWE-200 | `UserAuthentication.java:143-165` |
| SEC-04 | Credential Exposure in Process Listing via Command-Line Arguments | Medium | CWE-214 | `UserAuthentication.java:766-769` |
| SEC-05 | Information Disclosure via Raw Database Exception Messages and Stack Traces | Medium | CWE-209 | `UserAuthentication.java:357-360` |
| SEC-06 | Uncontrolled Search Path for Dynamic JDBC Driver Class Loading | Medium | CWE-427 | `UserAuthentication.java:483-499` |
| SEC-07 | Absence of Rate Limiting and Account Lockout Mechanism | Low | CWE-307 | `UserAuthentication.java:309-322` |

## 5. Detailed Findings

### SEC-01: Hardcoded Credentials and Insecure Default Account Seeding
- **Severity:** Critical
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Location:** `UserAuthentication.java:454-466`

**Vulnerable code:**
```java
// UserAuthentication.java:454-466
            // Seed 3 test accounts:
            // 1. Alice Johnson (Standard active user)
            repo.createUser(conn, "alice@example.com", "Password123!".toCharArray(),
                    "Alice Johnson", "USER", true);

            // 2. Bob Smith (Administrator)
            repo.createUser(conn, "bob@example.com", "AdminSecure456#".toCharArray(),
                    "Bob Smith", "ADMIN", true);

            // 3. Carol White (Disabled account)
            repo.createUser(conn, "carol@example.com", "CarolPass789$".toCharArray(),
                    "Carol White", "USER", false);
```

**Why it is a problem:** In `DatabaseManager.seedDefaultAccountsIfEmpty`, the application automatically seeds test accounts and an administrative account into the database whenever the `users` table lacks `alice@example.com`. Default accounts are created with hardcoded plaintext passwords, including an administrator account (`bob@example.com` / `AdminSecure456#`). Furthermore, identical credentials are hardcoded into `InMemorySqlDriver.seedMemoryUser` (lines 571-575) and printed in `printUsage` (lines 879-883). Because `initializeDatabase()` is executed during every authentication invocation (line 821), connecting the application to any external or production SQL database will automatically inject known administrative accounts, creating a backdoor for attackers with knowledge of the source code.

**Fix:** Remove hardcoded credentials and automatic seeding from production startup logic. Initial administrative accounts should only be provisioned through secure configuration mechanisms (such as environment variables or secrets management systems) or via a dedicated setup utility that requires the administrator to define a unique, strong password.
```java
            // Production database initialization must never insert hardcoded credentials.
            // Retrieve initial administrative credentials securely from external environment variables.
            String initialAdminEmail = System.getenv("INITIAL_ADMIN_EMAIL");
            String initialAdminPassword = System.getenv("INITIAL_ADMIN_PASSWORD");

            if (initialAdminEmail != null && initialAdminPassword != null &&
                !initialAdminEmail.isBlank() && !initialAdminPassword.isBlank()) {
                Optional<User> existing = repo.findByEmail(conn, initialAdminEmail);
                if (existing.isEmpty()) {
                    repo.createUser(conn, initialAdminEmail.trim(), initialAdminPassword.toCharArray(),
                            "System Administrator", "ADMIN", true);
                }
            }
```

### SEC-02: User Enumeration via Observable Response Discrepancy on Inactive Accounts
- **Severity:** High
- **CWE:** CWE-204: Observable Response Discrepancy
- **Location:** `UserAuthentication.java:335-340`

**Vulnerable code:**
```java
// UserAuthentication.java:335-340
                // Check if the user account is active
                if (!user.isActive()) {
                    PasswordSecurity.dummyVerification(password);
                    return AuthResult.failure("Authentication failed: Account is disabled. Contact system administrator.", System.nanoTime() - startTime);
                }
```

**Why it is a problem:** In `AuthenticationService.authenticate`, the account status check `if (!user.isActive())` is executed before the password is verified. If the account is marked inactive (`active = false`), the service immediately returns `"Authentication failed: Account is disabled. Contact system administrator."` (line 338). For non-existent accounts or incorrect passwords on active accounts, the service returns `"Authentication failed: Invalid email address or password."` (lines 330, 354). Because the disabled check occurs prior to password validation and regardless of what password was supplied, an unauthenticated attacker can submit arbitrary passwords against any email address to determine whether the account exists and is disabled, directly enabling user enumeration.

**Fix:** Verify credentials before checking account status, and return a uniform generic failure message for both non-existent accounts and invalid credentials.
```java
                // Verify password first before evaluating account status
                boolean passwordValid = PasswordSecurity.verify(
                        password,
                        user.getPasswordHash(),
                        user.getSalt(),
                        user.getIterations()
                );

                long duration = System.nanoTime() - startTime;

                if (!passwordValid || !user.isActive()) {
                    // Return uniform generic error message to prevent account enumeration
                    return AuthResult.failure("Authentication failed: Invalid email address or password.", duration);
                }

                return AuthResult.success("Authentication successful! Welcome, " + user.getFullName() + ".", user, duration);
```

### SEC-03: Excessive Sensitive Data Exposure in User Data Model
- **Severity:** High
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **Location:** `UserAuthentication.java:143-165`

**Vulnerable code:**
```java
// UserAuthentication.java:143-165
    public static class User {
        private final long id;
        private final String email;
        private final String passwordHash;
        private final String salt;
        private final int iterations;
        private final String fullName;
        private final String role;
        private final boolean active;
        private final String createdAt;

        public User(long id, String email, String passwordHash, String salt, int iterations,
                    String fullName, String role, boolean active, String createdAt) {
            this.id = id;
            this.email = email;
            this.passwordHash = passwordHash;
            this.salt = salt;
            this.iterations = iterations;
            this.fullName = fullName;
            this.role = role;
            this.active = active;
            this.createdAt = createdAt;
        }
```

**Why it is a problem:** The `User` domain entity stores the user's password hash (`passwordHash`), cryptographic salt (`salt`), and iteration count (`iterations`), and exposes them via public getters (`getPasswordHash()`, `getSalt()`, `getIterations()`). When `authenticate()` succeeds, this entire `User` object is packaged into the `AuthResult` object returned to the caller (lines 203-205, 352). If `AuthResult` or `User` is passed to higher application tiers, serialized into an API response (e.g. JSON REST response), or stored in a session store, the password hashes and salts are exposed, enabling offline dictionary and cracking attacks.

**Fix:** Remove sensitive credential data (`passwordHash`, `salt`, `iterations`) from the domain `User` entity, and handle credentials strictly within internal database authentication queries.
```java
    public static class User {
        private final long id;
        private final String email;
        private final String fullName;
        private final String role;
        private final boolean active;
        private final String createdAt;

        public User(long id, String email, String fullName, String role, boolean active, String createdAt) {
            this.id = id;
            this.email = email;
            this.fullName = fullName;
            this.role = role;
            this.active = active;
            this.createdAt = createdAt;
        }

        public long getId() { return id; }
        public String getEmail() { return email; }
        public String getFullName() { return fullName; }
        public String getRole() { return role; }
        public boolean isActive() { return active; }
        public String getCreatedAt() { return createdAt; }
    }
```

### SEC-04: Credential Exposure in Process Listing via Command-Line Arguments
- **Severity:** Medium
- **CWE:** CWE-214: Invocation of Process Using Visible Sensitive Information
- **Location:** `UserAuthentication.java:766-769`

**Vulnerable code:**
```java
// UserAuthentication.java:766-769
            if (args.length >= 2) {
                email = args[0];
                password = args[1].toCharArray();
            }
```

**Why it is a problem:** In `main`, the application accepts plain text passwords directly from command-line arguments (`args[1]`). On Unix and Linux environments, command-line arguments are visible in the process table to all local users via tools like `ps aux`, `top`, and `/proc/<pid>/cmdline`. Furthermore, arguments entered on the command line are saved in plaintext within shell history files (`~/.bash_history`). Additionally, passing the password via `args[1]` loads an immutable `java.lang.String` into the JVM memory space, bypassing the security intent of using `char[]` and preventing prompt memory erasure.

**Fix:** Eliminate passing passwords through command-line arguments. Require passwords to be entered interactively using `System.console().readPassword()` or streamed through secure standard input/environment variables.
```java
            if (args.length >= 1) {
                email = args[0];
                Console console = System.console();
                if (console != null) {
                    password = console.readPassword("Enter password for %s: ", email);
                } else {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
                    String passLine = reader.readLine();
                    password = (passLine != null) ? passLine.toCharArray() : new char[0];
                }
            }
```

### SEC-05: Information Disclosure via Raw Database Exception Messages and Stack Traces
- **Severity:** Medium
- **CWE:** CWE-209: Generation of Error Message Containing Sensitive Information
- **Location:** `UserAuthentication.java:357-360`

**Vulnerable code:**
```java
// UserAuthentication.java:357-360
            } catch (SQLException e) {
                long duration = System.nanoTime() - startTime;
                return AuthResult.failure("Database error during authentication: " + e.getMessage(), duration);
            }
```

**Why it is a problem:** When an SQL exception occurs during authentication, `AuthenticationService.authenticate` appends `e.getMessage()` directly to the failure result, which is subsequently printed to the console via `printResultBanner` (line 855). Raw `SQLException` messages reveal database structure, SQL syntax errors, table and column names, connection strings, hostnames, and database engine versions. Furthermore, uncaught exceptions in `main` (lines 807-808) invoke `e.printStackTrace()`, printing internal class hierarchies and source line numbers to standard error.

**Fix:** Log detailed exception information securely to internal server logs and return sanitized, generic error messages to callers and end users.
```java
            } catch (SQLException e) {
                long duration = System.nanoTime() - startTime;
                // Log detailed error to internal logging system
                System.err.println("[LOG] Database failure encountered during authentication: " + e.getClass().getName());
                // Return generic, non-informative failure message to the client
                return AuthResult.failure("Authentication failed due to an internal service error.", duration);
            }
```

### SEC-06: Uncontrolled Search Path for Dynamic JDBC Driver Class Loading
- **Severity:** Medium
- **CWE:** CWE-427: Uncontrolled Search Path Element
- **Location:** `UserAuthentication.java:483-499`

**Vulnerable code:**
```java
// UserAuthentication.java:483-499
            String[] searchPaths = {
                    "lib/h2.jar",
                    "h2.jar",
                    "lib/h2-2.2.224.jar",
                    "lib/sqlite-jdbc.jar",
                    System.getProperty("user.home") + "/.m2/repository/com/h2database/h2/2.2.224/h2-2.2.224.jar",
                    System.getProperty("user.home") + "/.m2/repository/org/xerial/sqlite-jdbc/3.45.1.0/sqlite-jdbc-3.45.1.0.jar"
            };

            for (String path : searchPaths) {
                File jar = new File(path);
                if (jar.exists() && jar.isFile()) {
                    if (tryLoadDriverJar(jar)) {
                        return;
                    }
                }
            }
```

**Why it is a problem:** `DatabaseManager.bootstrapDriverIfNeeded()` searches for JDBC driver JAR files using relative paths in the current working directory (`"lib/h2.jar"`, `"h2.jar"`, etc.). When a file is found, `tryLoadDriverJar` loads and executes the driver class via `URLClassLoader` and reflection (`newInstance()`). If the application is launched from a directory where unprivileged users have write access (such as a shared server directory or `/tmp`), an attacker can plant a trojanized `h2.jar` or `sqlite-jdbc.jar` containing malicious code in its driver class constructor or static initializer, resulting in arbitrary code execution with the permissions of the application process.

**Fix:** Rely on the standard Java classpath (`-cp`) configured at runtime rather than probing relative paths in the working directory. If dynamic loading from an external path is required, validate paths against an explicit absolute allowlist and verify the JAR's cryptographic signature or hash before loading.
```java
            // Verify if driver is present on the trusted runtime classpath
            if (isClassAvailable("org.h2.Driver") || isClassAvailable("org.sqlite.JDBC")) {
                return;
            }

            // Fall back to the built-in pure Java driver without probing the working directory
            registerInMemoryFallbackDriver();
```

### SEC-07: Absence of Rate Limiting and Account Lockout Mechanism
- **Severity:** Low
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `UserAuthentication.java:309-322`

**Vulnerable code:**
```java
// UserAuthentication.java:309-322
        public AuthResult authenticate(Connection connection, String email, char[] password) {
            long startTime = System.nanoTime();

            // 1. Validate inputs
            if (email == null || email.trim().isEmpty()) {
                return AuthResult.failure("Authentication failed: Email address cannot be blank.", System.nanoTime() - startTime);
            }
            if (!EMAIL_PATTERN.matcher(email.trim()).matches()) {
                return AuthResult.failure("Authentication failed: Invalid email address format.", System.nanoTime() - startTime);
            }
            if (password == null || password.length == 0) {
                return AuthResult.failure("Authentication failed: Password cannot be blank.", System.nanoTime() - startTime);
            }
```

**Why it is a problem:** `AuthenticationService.authenticate` does not track failed authentication attempts, apply exponential backoff, or enforce account lockout after repeated failures. Although PBKDF2 with 100,000 iterations slows down hash computation, attackers can perform unconstrained automated online brute-force and credential-stuffing attacks without triggering defensive locks or alerting thresholds.

**Fix:** Implement a rate-limiting and account lockout tracking mechanism that monitors consecutive failed authentication attempts per account and IP address, locking the account or imposing a delay after a defined threshold (e.g. 5 consecutive failed attempts).
```java
        private static final Map<String, Integer> ATTEMPTS_CACHE = new java.util.concurrent.ConcurrentHashMap<>();
        private static final Map<String, Long> LOCKOUT_CACHE = new java.util.concurrent.ConcurrentHashMap<>();
        private static final int MAX_FAILED_ATTEMPTS = 5;
        private static final long LOCKOUT_DURATION_MS = 15 * 60 * 1000L; // 15 minutes

        public AuthResult authenticate(Connection connection, String email, char[] password) {
            long startTime = System.nanoTime();

            String normalizedEmail = (email != null) ? email.trim().toLowerCase() : "";
            long now = System.currentTimeMillis();

            if (LOCKOUT_CACHE.getOrDefault(normalizedEmail, 0L) > now) {
                PasswordSecurity.dummyVerification(password);
                return AuthResult.failure("Authentication failed: Account temporarily locked due to excessive failed attempts.", System.nanoTime() - startTime);
            }

            // 1. Validate inputs
            if (email == null || email.trim().isEmpty()) {
                return AuthResult.failure("Authentication failed: Email address cannot be blank.", System.nanoTime() - startTime);
            }
            if (!EMAIL_PATTERN.matcher(email.trim()).matches()) {
                return AuthResult.failure("Authentication failed: Invalid email address format.", System.nanoTime() - startTime);
            }
            if (password == null || password.length == 0) {
                return AuthResult.failure("Authentication failed: Password cannot be blank.", System.nanoTime() - startTime);
            }
```

## 6. Verified Controls and Checks With No Finding
- SQL Injection Defense: Verified in `UserRepository.findByEmail` (lines 234-237) and `UserRepository.createUser` (lines 273-281) that all SQL interactions use parameterized `PreparedStatement` queries with parameter binding (`?`), preventing SQL injection vulnerabilities.
- Cryptographic Password Hashing: Verified in `PasswordSecurity.hash` (lines 85-95) that password hashing implements PBKDF2 with HMAC-SHA256 (`PBKDF2WithHmacSHA256`) using 100,000 iterations and a 256-bit derived key length, adhering to NIST SP 800-63B guidelines.
- Cryptographic Salt Generation: Verified in `PasswordSecurity.generateSalt` (lines 76-80) that each user record receives a unique 16-byte (128-bit) salt generated via `java.security.SecureRandom`, neutralizing precomputed rainbow table attacks.
- Constant-Time Hash Comparison: Verified in `PasswordSecurity.verify` (lines 116-119) that password verification uses `MessageDigest.isEqual()`, mitigating side-channel timing attacks on hash verification.
- Dummy PBKDF2 Timing Equalization for Non-Existent Accounts: Verified in `PasswordSecurity.dummyVerification` (lines 129-136) and `AuthenticationService.authenticate` (line 329) that non-existent accounts trigger a dummy PBKDF2 derivation with a fixed dummy salt to equalize latency and mitigate timing attacks.
- Input Email Format Validation: Verified in `AuthenticationService.authenticate` (lines 316-318) that input email addresses are validated against regex pattern `^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$`, and checked for null/blank values before query execution.
- In-Memory Password Clearing for Console Input: Verified in `PasswordSecurity.hash` (line 93) that `spec.clearPassword()` is invoked in a `finally` block, and in `main` (line 801) that `Arrays.fill(password, '\0')` is called to clear the password array in memory after interactive console input.
- Third-Party Dependency Vulnerability Check: Verified in `pom.xml` (lines 23-26) that `com.h2database:h2` is pinned to version `2.2.224`, which contains security fixes for known historical H2 vulnerabilities (such as CVE-2021-42392, CVE-2022-23221, and CVE-2022-45868).
