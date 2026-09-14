# Security Review: UserAccountRepository

## 1. Executive Summary
`UserAccountRepository` is a JDBC-based Java component that implements user account retrieval by username from an SQL database. The component exhibits robust security engineering across its primary data access flows: it strictly utilizes parameterized queries (`PreparedStatement`) with placeholder binding to prevent SQL injection (CWE-89), excludes sensitive authentication credentials such as password hashes from queries and domain models (CWE-200), enforces input validation and query execution limits to prevent Denial of Service (CWE-400 / CWE-1284), and reliably cleans up database statements and result sets using try-with-resources while preserving caller connection ownership (CWE-404).

However, an uncontrolled search path vulnerability (CWE-427, Medium severity) was identified in the demonstration/CLI helper method `obtainDemoConnection()`. Specifically, the driver loader attempts to search and dynamically load a JAR file from the world-writable directory `/tmp/h2.jar`. On multi-user systems, an unprivileged local attacker could place a malicious JAR at `/tmp/h2.jar` to achieve arbitrary code execution in the application's JVM process context. Additionally, a minor resource leak (CWE-772, Low severity) exists where `URLClassLoader` instances are not closed if driver instantiation fails.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `UserAccountRepository.java` | Core repository class providing user account retrieval, result mapping, domain modeling, and a standalone demonstration CLI test suite. | Parameterized SQL query execution via `PreparedStatement`, dynamic column extraction and mapping from `ResultSetMetaData`, sensitive credential omission in domain record `UserAccount`, defensive input validation and bounds checking, resource lifecycle management, and dynamic driver JAR loading via `URLClassLoader` in `obtainDemoConnection()`. |
| `lib/h2.jar` | Third-party relational database engine (H2 Database Engine v2.2.224). | Embedded in-memory SQL database library used for local demonstration, integration testing, and verification suite execution. |

## 3. Skills Applied
- `exploiting-sql-injection-vulnerabilities`: Applied to SQL query construction (`DEFAULT_SELECT_QUERY`), `PreparedStatement` preparation, bind parameter setting, and `ResultSet` execution across `findByUsername` and `requireByUsername` methods to verify resilience against SQL injection.
- `performing-second-order-sql-injection`: Applied to input processing, data flow from parameters to query results, and domain object population to ensure retrieved input cannot result in second-order SQL injection.
- `testing-for-sensitive-data-exposure`: Applied to domain record fields (`UserAccount`), SQL query projections, and database schema definition (`users` table) to verify that password hashes, salts, and authentication secrets are not exposed to callers or serialized models.
- General OWASP Top 10 / CWE knowledge (A08:2021 – Software and Data Integrity Failures / CWE-427 / CWE-426): Applied to dynamic class loading and filesystem paths in `obtainDemoConnection()` where candidate JARs are located and loaded via `URLClassLoader`.
- General OWASP Top 10 / CWE knowledge (A04:2021 – Insecure Design / CWE-400 / CWE-1284 / CWE-404 / CWE-772): Applied to input boundary constraints (`MAX_USERNAME_LENGTH`), query timeout configurations (`QUERY_TIMEOUT_SECONDS`), result limits (`setMaxRows(1)`), try-with-resources resource cleanup, connection lifecycle preservation, and classloader closure.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Uncontrolled Search Path for Dynamic Library Loading via Shared Temporary Directory | Medium | CWE-427 | `UserAccountRepository.java:715-719` |
| SEC-02 | Missing Resource Release on Failed Dynamic URLClassLoader Resolution | Low | CWE-772 | `UserAccountRepository.java:723-736` |

## 5. Detailed Findings

### SEC-01: Uncontrolled Search Path for Dynamic Library Loading via Shared Temporary Directory
- **Severity:** Medium
- **CWE:** CWE-427: Uncontrolled Search Path Element
- **Location:** `UserAccountRepository.java:715-719`

**Vulnerable code:**
```java
// UserAccountRepository.java:715-719
        File[] candidateJars = {
            new File("lib/h2.jar"),
            new File("h2.jar"),
            new File("/tmp/h2.jar")
        };
```

**Why it is a problem:** In `obtainDemoConnection()`, the application iterates over candidate file paths to locate the H2 database driver JAR, instantiating a `URLClassLoader` and invoking `Class.forName("org.h2.Driver", true, loader).getDeclaredConstructor().newInstance()`. The list of candidate locations includes `new File("/tmp/h2.jar")`. In Unix/Linux environments, `/tmp` is a world-writable directory (`01777`). Any unprivileged local user or malicious process on the host can place a crafted `h2.jar` file containing arbitrary Java bytecode under the class name `org.h2.Driver`. If the application is executed from a working directory where `lib/h2.jar` or `./h2.jar` does not exist, the application will load `/tmp/h2.jar` and execute the attacker's static initializers and constructor in the security context of the user executing the JVM, leading to local privilege escalation or arbitrary code execution. Furthermore, using relative paths `lib/h2.jar` and `h2.jar` allows current-working-directory library planting if the command is executed from an untrusted working directory.

**Fix:** Remove `/tmp/h2.jar` and unvalidated relative paths from the search list. Rely on the standard JVM classpath or restrict library resolution strictly to an application-managed, non-writable installation directory with absolute paths.
```java
        // Restrict candidate JARs to secure, application-controlled paths; omit world-writable /tmp
        File appLibJar = new File("lib/h2.jar").getAbsoluteFile();
        File[] candidateJars = appLibJar.exists() ? new File[]{ appLibJar } : new File[0];
```

### SEC-02: Missing Resource Release on Failed Dynamic URLClassLoader Resolution
- **Severity:** Low
- **CWE:** CWE-772: Missing Release of Resource after Effective Lifetime
- **Location:** `UserAccountRepository.java:723-736`

**Vulnerable code:**
```java
// UserAccountRepository.java:723-736
                try {
                    URLClassLoader loader = new URLClassLoader(
                        new URL[]{jar.toURI().toURL()},
                        UserAccountRepository.class.getClassLoader()
                    );
                    Driver driver = (Driver) Class.forName("org.h2.Driver", true, loader)
                        .getDeclaredConstructor().newInstance();
                    Properties props = new Properties();
                    props.setProperty("user", "sa");
                    props.setProperty("password", "");
                    return driver.connect(h2Url, props);
                } catch (Throwable ignored) {
                }
```

**Why it is a problem:** `URLClassLoader` implements `AutoCloseable` and retains open file descriptors and native OS resources for loaded JAR archives. If an exception occurs during reflection (`Class.forName`, `newInstance`) or database connection (`driver.connect`), the exception is suppressed (`catch (Throwable ignored)`) and the loop continues without closing `loader`. This results in leaked file handles and locks on the candidate JAR files until JVM termination.

**Fix:** Ensure the `URLClassLoader` is closed if driver loading or connection establishment fails before returning, or close candidate loaders when abandoned.
```java
                URLClassLoader loader = null;
                try {
                    loader = new URLClassLoader(
                        new URL[]{jar.toURI().toURL()},
                        UserAccountRepository.class.getClassLoader()
                    );
                    Driver driver = (Driver) Class.forName("org.h2.Driver", true, loader)
                        .getDeclaredConstructor().newInstance();
                    Properties props = new Properties();
                    props.setProperty("user", "sa");
                    props.setProperty("password", "");
                    return driver.connect(h2Url, props);
                } catch (Throwable ignored) {
                    if (loader != null) {
                        try {
                            loader.close();
                        } catch (Exception closeIgnored) {
                        }
                    }
                }
```

## 6. Verified Controls and Checks With No Finding
- Parameterized SQL Query Execution (CWE-89): Verified in `UserAccountRepository.java:55-58` and `UserAccountRepository.java:392-402`. The query `SELECT id, username, email, full_name, role, is_active, created_at, last_login_at FROM users WHERE username = ?` uses the standard parameter placeholder `?`, and `pstmt.setString(1, trimmed)` securely passes the user-supplied username as a typed literal parameter. No user input is concatenated, formatted, or interpolated into SQL command strings.
- Second-Order SQL Injection Defense (CWE-89): Verified in `UserAccountRepository.java:401-411`. Retrieved account fields from `ResultSet` are mapped into strongly-typed domain model properties and are not reused in downstream raw SQL statements.
- Credential Protection and Sensitive Data Omission (CWE-200 / CWE-359 / CWE-522): Verified in `UserAccountRepository.java:55-58` and `UserAccountRepository.java:123-149`. Although the underlying `users` database table contains a `password_hash` column, the query projection strictly omits authentication credentials and password hashes. The `UserAccount` domain record contains only non-sensitive account metadata, mitigating credential exposure via memory dumps, logging, or serialization.
- Resource Lifecycle Management (CWE-404 / CWE-772): Verified in `UserAccountRepository.java:392-411`. `PreparedStatement` and `ResultSet` are created within nested try-with-resources blocks, ensuring deterministic closure of database statement and cursor handles even when database errors or runtime exceptions occur.
- Caller Connection Integrity and Ownership: Verified in `UserAccountRepository.java:377-412`. The borrowed `Connection` passed by the caller is neither closed, committed, nor rolled back by the repository, correctly preserving caller transaction semantics and connection pool lifecycles.
- Defensive Input Validation and DoS Prevention (CWE-20 / CWE-400 / CWE-1284): Verified in `UserAccountRepository.java:382-389` and `UserAccountRepository.java:393-400`. Null, blank, and empty strings are rejected early without executing database round-trips; input lengths are capped at `MAX_USERNAME_LENGTH` (255 characters); `pstmt.setMaxRows(1)` ensures only a single row is returned; and `pstmt.setQueryTimeout(10)` guards against hanging or long-running database queries.
