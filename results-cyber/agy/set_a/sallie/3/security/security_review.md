# Security Review: User Authentication System

## 1. Executive Summary
The target system is a standalone Java application implementing a SQL-backed user authentication service and command-line interface (`UserAuthentication.java`, entrypoint alias `UserAuthenticator.java`, database schema `schema.sql`, and build descriptor `pom.xml`). It authenticates users against stored credentials in a SQL database (defaulting to local SQLite `users.db` or external JDBC databases) and provides account management operations.

The codebase implements several strong baseline security controls, notably strict query parameterization with `PreparedStatement` to prevent SQL injection, robust PBKDF2-HMAC-SHA256 password hashing with 210,000 iterations, 128-bit `SecureRandom` per-user salts, constant-time hash comparisons via `MessageDigest.isEqual()`, and dummy hash calculations to equalize timing differences between existing and non-existing accounts.

However, the audit identified multiple security vulnerabilities across authentication, credential storage, access control, and environment security:
- **High Severity:** Default accounts with hardcoded passwords (including an administrative account `bob@example.com` / `AdminSecure456#`) are automatically seeded into newly initialized databases and in-memory fallback storage (CWE-798).
- **High Severity:** The `add-user` CLI command permits unauthenticated, arbitrary password resets against existing accounts, including administrative accounts (CWE-306).
- **High Severity:** The CLI interface accepts plaintext passwords as command-line arguments, exposing sensitive credentials through OS process tables, shell history logs, and immutable `String` objects in JVM heap memory (CWE-214).
- **Medium Severity:** Disabled accounts trigger an explicit error message before password verification, allowing unauthenticated attackers to enumerate valid and inactive email addresses (CWE-204).
- **Medium Severity:** The default SQLite database `users.db` is created with default OS permissions (0644), making user password hashes and salts readable by any local user on the host (CWE-276).
- **Medium Severity:** Dynamic driver bootstrapping searches an untrusted relative directory (`lib/`) for executable JAR files, creating an untrusted search path vulnerability (CWE-426).
- **Low Severity:** The non-console input fallback reads passwords as immutable `java.lang.String` objects, preventing prompt memory scrubbing (CWE-316).

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `UserAuthentication.java` | Core application providing CLI entrypoint, authentication service, password hashing, user repository, database management, driver bootstrapping, and in-memory mock SQL fallback. | PreparedStatement SQL query parameterization, PBKDF2-HMAC-SHA256 password derivation, SecureRandom salt generation, constant-time verification, timing attack mitigation, CLI argument parsing, console password masking with stdin fallback, relative path JAR loading via URLClassLoader, database file creation, and default account seeding. |
| `UserAuthenticator.java` | Direct entrypoint alias extending `UserAuthentication` and delegating to its `main` method. | Inherits and executes the CLI interface and authentication workflow of `UserAuthentication`. |
| `schema.sql` | SQL DDL script defining the relational schema for the `users` table across SQLite, PostgreSQL, MySQL, and H2. | Database schema definition, storage layout for password hashes, Base64 salts, iteration counts, account status flags, role definitions, and unique email indexes. |
| `pom.xml` | Maven build descriptor and dependency configuration. | Specifies dependency libraries (`sqlite-jdbc` 3.45.1.0, `h2` 2.2.224, `slf4j` 1.7.36/1.7.32) and compiler compliance targets (Java 17). |

## 3. Skills Applied
- `performing-cryptographic-audit-of-application`: Applied to audit password hashing algorithm selection (`PBKDF2WithHmacSHA256`), iteration count (210,000), salt generation using `SecureRandom`, constant-time byte comparison using `MessageDigest.isEqual()`, timing side-channel defenses, and hardcoded credentials in source code.
- `exploiting-sql-injection-vulnerabilities`: Applied to inspect SQL query construction, parameter binding across repository methods (`findByEmail`, `createUser`, `updatePassword`), DDL execution during database initialization, and fallback mock driver query parsing.
- `testing-for-sensitive-data-exposure`: Applied to assess credential handling across CLI arguments, memory retention (`char[]` vs `String`), error messaging, database file permissions on disk (`users.db`), and console input masking.
- General OWASP Top 10 / CWE knowledge: Applied to review missing authentication and authorization on the `add-user` command (OWASP A01:2021 - Broken Access Control / CWE-306), dynamic class loading from untrusted relative directories (CWE-426: Untrusted Search Path), and account enumeration via observable response discrepancies (OWASP A07:2021 - Identification and Authentication Failures / CWE-204).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Hardcoded Default Credentials Seeded in Database and In-Memory Storage | High | CWE-798 | `UserAuthentication.java:561-568` |
| SEC-02 | Unauthenticated Account Password Overwrite via `add-user` Command | High | CWE-306 | `UserAuthentication.java:349-359` |
| SEC-03 | Sensitive Credential Exposure in Command-Line Arguments | High | CWE-214 | `UserAuthentication.java:1006-1010` |
| SEC-04 | Account Enumeration via Inactive Account State Response Discrepancy | Medium | CWE-204 | `UserAuthentication.java:416-420` |
| SEC-05 | Insecure Default File Permissions on SQLite Database File | Medium | CWE-276 | `UserAuthentication.java:81` |
| SEC-06 | Dynamic Class Loading of Unverified JARs from Relative Directory | Medium | CWE-426 | `UserAuthentication.java:586-596` |
| SEC-07 | Cleartext Password Retention as Immutable String on Non-Console Input Fallback | Low | CWE-316 | `UserAuthentication.java:913-916` |

## 5. Detailed Findings

### SEC-01: Hardcoded Default Credentials Seeded in Database and In-Memory Storage
- **Severity:** High
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Location:** `UserAuthentication.java:561-568`

**Vulnerable code:**
```java
// UserAuthentication.java:561-568
            // Seed demonstration test accounts
            repo.createUser(conn, "alice@example.com", "Password123!".toCharArray(),
                    "Alice Johnson", "USER", true);
            repo.createUser(conn, "bob@example.com", "AdminSecure456#".toCharArray(),
                    "Bob Smith", "ADMIN", true);
            repo.createUser(conn, "carol@example.com", "CarolPass789$".toCharArray(),
                    "Carol White", "USER", false);
```

**Why it is a problem:** `DatabaseManager.initializeDatabase()` automatically executes `seedDefaultAccountsIfEmpty()` whenever the `users` table is newly created or empty. This inserts default accounts with hardcoded, well-known credentials into the database, including an administrative account (`bob@example.com` with password `AdminSecure456#` and role `ADMIN`), as well as `alice@example.com` (`Password123!`) and `carol@example.com` (`CarolPass789$`). Identical credentials are also hardcoded in `InMemorySqlDriver` (lines 678-682) and printed in `printUsage()` (lines 1097-1101). Anyone deploying the application who does not immediately purge or reconfigure these accounts leaves a well-known administrative backdoor, allowing immediate compromise of the system.

**Fix:** Remove automatic default user seeding from the production initialization path. If demonstration accounts are required, gate seeding behind an explicit test/demo flag or profile, or prompt the administrator to configure an initial password securely during setup.
```java
        private static void seedDefaultAccountsIfEmpty(Connection conn) throws SQLException {
            // Do not seed default accounts with hardcoded passwords in production.
            // In a production environment, initial administrator setup should require
            // interactive input or secure out-of-band credential provisioning.
        }
```

### SEC-02: Unauthenticated Account Password Overwrite via `add-user` Command
- **Severity:** High
- **CWE:** CWE-306: Missing Authentication for Critical Function
- **Location:** `UserAuthentication.java:349-359`

**Vulnerable code:**
```java
// UserAuthentication.java:349-359
        public boolean saveOrUpdateUser(Connection connection, String email, char[] password,
                                        String fullName, String role, boolean active) throws SQLException {
            Optional<User> existing = findByEmail(connection, email);
            if (existing.isPresent()) {
                updatePassword(connection, email, password);
                return false; // updated
            } else {
                createUser(connection, email, password, fullName, role, active);
                return true;  // created
            }
        }
```

**Why it is a problem:** The `saveOrUpdateUser` method called by the CLI `add-user` command (lines 960-996) checks if an account matching the target email address already exists. If found, it immediately invokes `updatePassword(connection, email, password)` to overwrite the existing password without requiring the old password, any existing session authentication, or administrative authorization. Any user with CLI access can execute `UserAuthentication add-user <target-email> <new-password>` to overwrite the password of any user, including administrator accounts (`bob@example.com`), resulting in complete account takeover.

**Fix:** Separate user creation from password updates. Prevent `add-user` from overwriting passwords of existing accounts. If an account already exists, reject the operation. Password modification must require verifying the user's current password or an authenticated, authorized administrator session.
```java
        public boolean saveOrUpdateUser(Connection connection, String email, char[] password,
                                        String fullName, String role, boolean active) throws SQLException {
            Optional<User> existing = findByEmail(connection, email);
            if (existing.isPresent()) {
                throw new SQLException("Cannot overwrite existing user account: " + email);
            }
            return createUser(connection, email, password, fullName, role, active);
        }
```

### SEC-03: Sensitive Credential Exposure in Command-Line Arguments
- **Severity:** High
- **CWE:** CWE-214: Invocation of Process Initializer with Untrusted/Sensitive Information
- **Location:** `UserAuthentication.java:1006-1010`

**Vulnerable code:**
```java
// UserAuthentication.java:1006-1010
            if (args.length > argOffset + 1) {
                password = args[argOffset + 1].toCharArray();
            } else {
                password = reader.readPassword("Password: ");
            }
```

**Why it is a problem:** The application allows passwords to be passed directly as command-line arguments (both in the login workflow at lines 1006-1010 and the `add-user` workflow at lines 969-973, documented in `printUsage()` lines 1084-1089). On multi-user operating systems, command-line arguments are visible in cleartext to all local users via process listing utilities (`ps aux`, `top`, `/proc/<pid>/cmdline`), are recorded in plain text in user shell history files (`~/.bash_history`, `~/.zsh_history`), and may be captured by system audit frameworks. Furthermore, accepting passwords via `String[] args` creates immutable `java.lang.String` objects on the JVM heap, bypassing the memory-clearing protection provided by `Arrays.fill(password, '\0')`.

**Fix:** Do not accept passwords as command-line arguments. Passwords should always be acquired interactively via masked console input (`Console.readPassword()`) or piped securely via standard input.
```java
            // Never read passwords from command-line arguments; always prompt securely
            password = reader.readPassword("Password: ");
```

### SEC-04: Account Enumeration via Inactive Account State Response Discrepancy
- **Severity:** Medium
- **CWE:** CWE-204: Observable Response Discrepancy
- **Location:** `UserAuthentication.java:416-420`

**Vulnerable code:**
```java
// UserAuthentication.java:416-420
                // 3. Verify account state
                if (!user.isActive()) {
                    PasswordSecurity.dummyVerification(password);
                    return AuthResult.failure("Authentication failed: Account is disabled. Contact system administrator.", System.nanoTime() - startTime);
                }
```

**Why it is a problem:** In `AuthenticationService.authenticate`, the account active state check (`!user.isActive()`) occurs before password verification. When an attacker targets a disabled account (such as `carol@example.com`) with an arbitrary or incorrect password, the service returns `"Authentication failed: Account is disabled. Contact system administrator."` In contrast, attempting to authenticate against a non-existent email returns `"Authentication failed: Invalid email address or password."` This observable discrepancy allows unauthenticated attackers to enumerate valid email addresses and identify disabled accounts without needing to know or guess valid passwords.

**Fix:** Verify the password before checking the active status, and return the standard generic message `"Authentication failed: Invalid email address or password."` on authentication failures. Only reveal that an account is disabled if the user has successfully provided the correct credentials.
```java
                // 3. Constant-time password verification before revealing account status
                boolean validPassword = PasswordSecurity.verify(
                        password,
                        user.getPasswordHash(),
                        user.getSalt(),
                        user.getIterations()
                );

                long duration = System.nanoTime() - startTime;

                if (!validPassword) {
                    return AuthResult.failure("Authentication failed: Invalid email address or password.", duration);
                }

                if (!user.isActive()) {
                    return AuthResult.failure("Authentication failed: Account is disabled. Contact system administrator.", duration);
                }

                return AuthResult.success("Authentication successful! Welcome, " + user.getFullName() + ".", user, duration);
```

### SEC-05: Insecure Default File Permissions on SQLite Database File
- **Severity:** Medium
- **CWE:** CWE-276: Incorrect Default Permissions
- **Location:** `UserAuthentication.java:81`

**Vulnerable code:**
```java
// UserAuthentication.java:81
    private static final String DEFAULT_SQLITE_URL = "jdbc:sqlite:users.db";
```

**Why it is a problem:** By default, the application connects to a local SQLite database file named `users.db` created in the current working directory. The application does not enforce restrictive file system access permissions when creating the database file. Consequently, the file is created with default OS file permissions governed by the process umask (typically `0644` / `-rw-r--r--`, as verified on disk). This allows any unprivileged local user or process on the system to read `users.db`, exposing all user email addresses, PBKDF2 password hashes, per-user salts, iteration counts, and role assignments for offline cracking.

**Fix:** Ensure that local database files are created in a protected directory or that explicit restrictive POSIX file permissions (`0600`, owner read/write only) are applied to the database file immediately upon creation.
```java
    private static final String DEFAULT_SQLITE_URL = "jdbc:sqlite:users.db";

    public static Connection getConnection() throws SQLException {
        // Enforce restrictive file permissions (0600) on local SQLite database file
        File dbFile = new File("users.db");
        if (dbFile.exists()) {
            dbFile.setReadable(false, false);
            dbFile.setReadable(true, true);
            dbFile.setWritable(false, false);
            dbFile.setWritable(true, true);
            dbFile.setExecutable(false, false);
        }
        // Proceed with connection initialization...
```

### SEC-06: Dynamic Class Loading of Unverified JARs from Relative Directory
- **Severity:** Medium
- **CWE:** CWE-426: Untrusted Search Path
- **Location:** `UserAuthentication.java:586-596`

**Vulnerable code:**
```java
// UserAuthentication.java:586-596
            File libDir = new File("lib");
            if (libDir.isDirectory()) {
                File[] files = libDir.listFiles((dir, name) -> name.toLowerCase(Locale.ROOT).endsWith(".jar"));
                if (files != null) {
                    for (File f : files) {
                        try {
                            jarUrls.add(f.toURI().toURL());
                        } catch (Exception ignored) {}
                    }
                }
            }
```

**Why it is a problem:** `DatabaseManager.bootstrapDriverIfNeeded()` searches for JDBC driver JAR files in a relative directory path `lib` located in the current working directory, dynamically loading any discovered `.jar` file into a `URLClassLoader` and loading classes with initialization enabled (`Class.forName(driverClass, true, loader)`). If the application is executed from a shared or untrusted directory (such as `/tmp` or a shared workspace), an attacker can supply a malicious JAR containing an altered or malicious driver class. The application will load and instantiate it, executing arbitrary code with the application's privileges.

**Fix:** Do not load executable code from relative paths in the current working directory. Rely on the standard JVM classpath configured during deployment, or require an absolute, administrator-configured path with signature or cryptographic hash verification.
```java
            // Do not dynamically load arbitrary JARs from untrusted relative working directories.
            // Require JDBC drivers to be supplied on the JVM classpath or from a trusted system directory.
            String trustedLibPath = System.getProperty("app.trusted.lib.dir");
            if (trustedLibPath != null) {
                File libDir = new File(trustedLibPath);
                if (libDir.isAbsolute() && libDir.isDirectory()) {
                    File[] files = libDir.listFiles((dir, name) -> name.toLowerCase(Locale.ROOT).endsWith(".jar"));
                    if (files != null) {
                        for (File f : files) {
                            try {
                                jarUrls.add(f.toURI().toURL());
                            } catch (Exception ignored) {}
                        }
                    }
                }
            }
```

### SEC-07: Cleartext Password Retention as Immutable String on Non-Console Input Fallback
- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `UserAuthentication.java:913-916`

**Vulnerable code:**
```java
// UserAuthentication.java:913-916
            // Fallback for piped standard input or non-interactive terminals
            String line = readLine(prompt);
            return line.toCharArray();
```

**Why it is a problem:** When `System.console()` is null (such as when run inside containers, IDEs, background processes, or non-interactive shells), `readPassword` falls back to `readLine()`, which reads the password into an immutable `java.lang.String`. Although converted to a `char[]`, the `String` object persists on the JVM heap. Because `java.lang.String` cannot be zeroed or cleared with `Arrays.fill()`, the cleartext password remains in memory until garbage collection and memory compaction occur, exposing credentials during core dumps or memory forensics.

**Fix:** In the fallback branch, read characters directly from the reader into a `char[]` buffer without instantiating an intermediate `String`.
```java
            // Fallback for piped standard input or non-interactive terminals without String allocation
            System.out.print(prompt);
            System.out.flush();
            char[] buffer = new char[256];
            int count = 0;
            int ch;
            BufferedReader in = getStdin();
            while ((ch = in.read()) != -1 && ch != '\r' && ch != '\n') {
                if (count >= buffer.length) {
                    buffer = Arrays.copyOf(buffer, buffer.length * 2);
                }
                buffer[count++] = (char) ch;
            }
            if (count == 0 && ch == -1) {
                throw new IOException("End of input stream reached.");
            }
            return Arrays.copyOf(buffer, count);
```

## 6. Verified Controls and Checks With No Finding
- Parameterized SQL Queries (SQL Injection Prevention): Verified that all database queries in `UserRepository` (`SELECT_USER_BY_EMAIL_SQL`, `INSERT_USER_SQL`, `UPDATE_USER_PASSWORD_SQL` at lines 253-263, 277-280, 318-326, 337-343) strictly use `PreparedStatement` with `?` parameter placeholders. User input is bound out-of-band and cannot alter the SQL query structure or syntax. Verified that automated test cases (lines 1161-1187) confirm resilience against tautology, comment injection, stacked queries, and password-field injection.
- Cryptographic Password Hashing Algorithm: Verified that `PasswordSecurity` (lines 93-96, 118-127) uses `PBKDF2WithHmacSHA256` with a work factor of 210,000 iterations (meeting OWASP password storage recommendations) and 256-bit derived key length. Weak or obsolete hashing algorithms (MD5, SHA-1, plain SHA-256) are not used.
- Cryptographic Salt Generation: Verified that `PasswordSecurity.generateSalt()` (lines 98, 108-112) generates 16 bytes (128 bits) of cryptographic entropy using `java.security.SecureRandom`, producing unique per-user salts. Predictable or static salts are not used for user accounts.
- Constant-Time Hash Comparison: Verified that `PasswordSecurity.verify()` (lines 151-153) evaluates the derived hash against the expected stored hash using `MessageDigest.isEqual()`, mitigating side-channel timing attacks on byte-by-byte comparison mismatches.
- Non-Existent Account Latency Equalisation: Verified that `AuthenticationService.authenticate()` (lines 408-412) executes `PasswordSecurity.dummyVerification(password)` with `DEFAULT_ITERATIONS` when an email address is not found in the database, equalizing response times between existing and non-existing accounts to prevent timing-based user enumeration.
- Sensitive Memory Sanitization in Authenticate & Main: Verified that `PBEKeySpec.clearPassword()` is invoked in a `finally` block in `PasswordSecurity.hash()` (line 125) and `Arrays.fill(password, '\0')` is executed in `main` (lines 1029-1031) to scrub candidate password buffers after authentication.
- Input Syntax Validation and Boundary Limits: Verified that email addresses are checked against an RFC-compliant regex pattern (`EMAIL_PATTERN` at line 84) and length-capped at 255 characters (line 1068), preventing buffer exhaustion and malformed input before database querying.
- Dependency Vulnerability Review: Verified that dependencies declared in `pom.xml` (`sqlite-jdbc:3.45.1.0`, `h2:2.2.224`, `slf4j-api:1.7.36`, `slf4j-nop:1.7.32`) use patched versions free from known high/critical CVEs (such as historical H2 RCE CVEs in versions <= 2.1.210).
- Schema Design and Data Integrity: Verified that `schema.sql` (lines 9-22) enforces `NOT NULL` constraints, unique email constraints (`UNIQUE`), and indexes (`idx_users_email`), storing password hashes and salts separately without plain text credential exposure in the database schema.
