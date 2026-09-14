# Security Review: Secure JDBC User Account Retrieval (UserAccountRepository)

## 1. Executive Summary
A comprehensive security review was conducted on the codebase in this folder, which implements a Java-based repository for retrieving user accounts from an SQL database using an active JDBC connection (`UserAccountRepository.java`), along with build configuration (`pom.xml`) and documentation (`README.md`).

The core repository retrieval logic demonstrates high security maturity regarding primary database threats: SQL injection is thoroughly prevented via strict parameterized queries (`PreparedStatement` with `?` markers), query projection excludes sensitive credentials like password hashes, caller connection ownership is preserved, and statements and result sets are deterministically closed using try-with-resources.

However, five security findings were identified. The most significant finding (High severity) is an uncontrolled search path element in the demo database initialization routine: the code probes the world-writable `/tmp` directory for `h2.jar` and dynamically loads classes using `URLClassLoader`, which allows local attackers to execute arbitrary Java code. Additional findings include locale-dependent case conversions in column metadata matching that break record hydration in locales such as Turkish (Medium), silent suppression of `SQLException` during metadata extraction causing hollow records to be returned (Medium), an unclosed `URLClassLoader` resource leak (Low), and unescaped command-line arguments printed to standard output allowing log/terminal injection (Low).

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `UserAccountRepository.java` | Core data access repository, domain records, exceptions, dynamic mock driver, and self-verification test runner. | SQL query construction and binding, JDBC resource lifecycle management, input normalization, dynamic class loading via `URLClassLoader`, reflective mocking, and console logging. |
| `pom.xml` | Maven build definition and execution profile. | Compiler configuration and system-scoped dependency resolution on local `lib/h2.jar`. |
| `README.md` | Component architecture, security rationale, API usage, and build instructions. | Documents expected security controls (CWE-89, CWE-404, CWE-200, CWE-20, CWE-117) and run configurations. |

## 3. Skills Applied
- `exploiting-sql-injection-vulnerabilities`: Applied to evaluate SQL query construction, placeholder binding via `PreparedStatement`, quote handling, and injection payload resistance in `UserAccountRepository.java`.
- `testing-for-sensitive-data-exposure`: Applied to audit database projection columns, domain model fields, and test data in `UserAccountRepository.java` for unintended exposure of password hashes, salts, and secret credentials.
- Reviewed against general OWASP Top 10 / CWE knowledge because no library skill matched:
  - Untrusted search path and dynamic class loading evaluated against CWE-427 (Uncontrolled Search Path Element) and CWE-426 (Untrusted Search Path).
  - JDBC and classloader resource management evaluated against CWE-404 (Improper Resource Shutdown or Release), CWE-772 (Missing Release of Resource after Effective Lifetime), and CWE-775 (Missing Release of File Descriptor or Handle after Effective Lifetime).
  - Case mapping and locale sensitivity evaluated against CWE-178 (Improper Handling of Case Sensitivity).
  - Error condition handling and exception suppression evaluated against CWE-391 (Unchecked Error Condition) and CWE-390 (Detection of Error Condition Without Action).
  - Output handling and log forging evaluated against CWE-117 (Improper Output Handling for Logs) and CWE-150 (Improper Neutralization of Escape, Meta, or Control Sequences).
  - Input validation and bounds checking evaluated against CWE-20 (Improper Input Validation) and CWE-400 (Uncontrolled Resource Consumption).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Untrusted Search Path and Dynamic Class Loading from Shared Directory (`/tmp/h2.jar`) | High | CWE-427 | `UserAccountRepository.java:765-787` |
| SEC-02 | Locale-Sensitive Case Conversion in Column Name Resolution (`toLowerCase()`) | Medium | CWE-178 | `UserAccountRepository.java:548-552` |
| SEC-03 | Silent Suppression of Database Metadata Exceptions Returning Hollow Records | Medium | CWE-391 | `UserAccountRepository.java:542-556` |
| SEC-04 | Missing Release of File Descriptor on `URLClassLoader` Instance | Low | CWE-775 | `UserAccountRepository.java:774-784` |
| SEC-05 | Potential Log Injection and Terminal Control Sequence Injection in CLI Output | Low | CWE-117 | `UserAccountRepository.java:592-599` |

## 5. Detailed Findings

### SEC-01: Untrusted Search Path and Dynamic Class Loading from Shared Directory (`/tmp/h2.jar`)
- **Severity:** High
- **CWE:** CWE-427: Uncontrolled Search Path Element
- **Location:** `UserAccountRepository.java:765-787`

**Vulnerable code:**
```java
// UserAccountRepository.java:765-787
        File[] candidateJars = {
            new File("lib/h2.jar"),
            new File("h2.jar"),
            new File("/tmp/h2.jar")
        };

        for (File jar : candidateJars) {
            if (jar.exists()) {
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
            }
        }
```

**Why it is a problem:** `obtainDemoConnection()` attempts to find an H2 driver JAR across several locations, explicitly listing `/tmp/h2.jar` in `candidateJars`. In Linux/Unix systems, `/tmp` is a world-writable directory with sticky permissions (`1777`). Any local unprivileged user or malicious process sharing the host can write an arbitrary JAR file to `/tmp/h2.jar`. If the application is executed from a directory lacking `lib/h2.jar` and `h2.jar`, `obtainDemoConnection()` discovers `/tmp/h2.jar`, instantiates a `URLClassLoader` targeting it, and calls `Class.forName("org.h2.Driver", true, loader).getDeclaredConstructor().newInstance()`. Loading an untrusted class with `initialize = true` executes the static initializer block (`static { ... }`) and constructor of `org.h2.Driver` within the attacker-supplied JAR under the permissions and security context of the user executing `UserAccountRepository`. This provides a local privilege escalation and arbitrary code execution path. Furthermore, resolving relative paths like `lib/h2.jar` against the working directory inherits risks if run from untrusted directories.

**Fix:** Remove `/tmp/h2.jar` and any untrusted shared paths from `candidateJars`. Restrict candidate search locations to trusted application directories, or rely standardly on the system classpath / Java Service Provider Interface (`ServiceLoader`), falling back directly to `createMockConnection()` if unavailable.
```java
        // Search only trusted, application-controlled candidate paths
        File[] candidateJars = {
            new File("lib/h2.jar")
        };

        for (File jar : candidateJars) {
            if (jar.exists()) {
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
            }
        }
```

### SEC-02: Locale-Sensitive Case Conversion in Column Name Resolution (`toLowerCase()`)
- **Severity:** Medium
- **CWE:** CWE-178: Improper Handling of Case Sensitivity
- **Location:** `UserAccountRepository.java:548-552`

**Vulnerable code:**
```java
// UserAccountRepository.java:548-552
                String label = meta.getColumnLabel(i);
                if (label != null) cols.add(label.toLowerCase());
                String name = meta.getColumnName(i);
                if (name != null) cols.add(name.toLowerCase());
```

**Why it is a problem:** In `extractColumnNames()`, column labels and names are converted to lowercase using `label.toLowerCase()` and `name.toLowerCase()` without specifying `Locale.ROOT`. In Java, parameterless `toLowerCase()` uses `Locale.getDefault()`. In certain locales such as Turkish (`tr`) and Azerbaijani (`az`), the lowercase mapping for the ASCII character `'I'` (U+0049) is the dotless small letter `'ı'` (U+0131), while the lowercase of `'i'` is `'i'` and uppercase of `'i'` is `'\u0130'`. On a system configured with a Turkish locale, standard column identifiers such as `"ID"`, `"EMAIL"`, and `"IS_ACTIVE"` become `"ıd"`, `"emaıl"`, and `"ıs_actıve"`. When `mapRowToUserAccount()` checks `cols.contains("id")`, `cols.contains("email")`, and `cols.contains("is_active")`, every lookup returns `false`. Consequently, valid user records retrieved from the database have their IDs, emails, active status flags, and timestamps silently dropped or set to default fallback values, resulting in data corruption and application errors.

**Fix:** Use `toLowerCase(Locale.ROOT)` to enforce locale-independent ASCII lowercase conversion for all database metadata identifiers.
```java
                String label = meta.getColumnLabel(i);
                if (label != null) cols.add(label.toLowerCase(Locale.ROOT));
                String name = meta.getColumnName(i);
                if (name != null) cols.add(name.toLowerCase(Locale.ROOT));
```

### SEC-03: Silent Suppression of Database Metadata Exceptions Returning Hollow Records
- **Severity:** Medium
- **CWE:** CWE-391: Unchecked Error Condition
- **Location:** `UserAccountRepository.java:542-556`

**Vulnerable code:**
```java
// UserAccountRepository.java:542-556
    private static Set<String> extractColumnNames(ResultSet rs) {
        Set<String> cols = new HashSet<>();
        try {
            ResultSetMetaData meta = rs.getMetaData();
            int count = meta.getColumnCount();
            for (int i = 1; i <= count; i++) {
                String label = meta.getColumnLabel(i);
                if (label != null) cols.add(label.toLowerCase());
                String name = meta.getColumnName(i);
                if (name != null) cols.add(name.toLowerCase());
            }
        } catch (SQLException ignored) {
        }
        return Collections.unmodifiableSet(cols);
    }
```

**Why it is a problem:** `extractColumnNames()` catches any `SQLException` thrown during metadata retrieval and silently swallows it without logging or rethrowing (`catch (SQLException ignored) {}`). If metadata retrieval fails (for example due to a transient network interruption, driver error, or invalid cursor state), `cols` remains an empty set. Rather than failing fast and letting the caller handle the failure, `mapRowToUserAccount()` executes against this empty set and constructs a `UserAccount` object with all `null` values and fallback defaults (`id = null, username = null, email = null, role = "USER", isActive = true, createdAt = null, lastLoginAt = null`). This synthetic object is then wrapped in `Optional.of(...)` and returned to the caller as if a valid user record had been retrieved, concealing the underlying database failure and corrupting application state.

**Fix:** Allow `extractColumnNames()` to throw `SQLException` so that metadata inspection failures propagate out of `mapRowToUserAccount(ResultSet rs)` (which already declares `throws SQLException`).
```java
    private static Set<String> extractColumnNames(ResultSet rs) throws SQLException {
        Set<String> cols = new HashSet<>();
        ResultSetMetaData meta = rs.getMetaData();
        int count = meta.getColumnCount();
        for (int i = 1; i <= count; i++) {
            String label = meta.getColumnLabel(i);
            if (label != null) cols.add(label.toLowerCase(Locale.ROOT));
            String name = meta.getColumnName(i);
            if (name != null) cols.add(name.toLowerCase(Locale.ROOT));
        }
        return Collections.unmodifiableSet(cols);
    }
```

### SEC-04: Missing Release of File Descriptor on `URLClassLoader` Instance
- **Severity:** Low
- **CWE:** CWE-775: Missing Release of File Descriptor or Handle after Effective Lifetime
- **Location:** `UserAccountRepository.java:774-784`

**Vulnerable code:**
```java
// UserAccountRepository.java:774-784
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
```

**Why it is a problem:** When loading the H2 driver dynamically from candidate JAR paths, `obtainDemoConnection()` instantiates a `URLClassLoader`. `URLClassLoader` implements `java.io.Closeable` / `AutoCloseable` and opens file descriptors on the underlying JAR archive. The instantiated `loader` is never closed, nor is it managed if driver instantiation or connection establishment fails in the loop. Failing to close the `URLClassLoader` causes open file handle leaks on POSIX systems and file-locking issues on Windows operating systems, preventing JAR cleanup, deletion, or replacement.

**Fix:** Track the `URLClassLoader` instance and ensure it is properly closed in the event of an error or when class loading has completed.
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
                        } catch (Exception closeEx) {
                            // Suppress close exception
                        }
                    }
                }
```

### SEC-05: Potential Log Injection and Terminal Control Sequence Injection in CLI Output
- **Severity:** Low
- **CWE:** CWE-117: Improper Output Handling for Logs
- **Location:** `UserAccountRepository.java:592-599`

**Vulnerable code:**
```java
// UserAccountRepository.java:592-599
                String target = args[0];
                System.out.println("Looking up user: '" + target + "'");
                Optional<UserAccount> accountOpt = repository.findByUsername(target);
                if (accountOpt.isPresent()) {
                    printAccountDetails(accountOpt.get());
                } else {
                    System.out.println("Result: No account found matching '" + target + "'.");
                }
```

**Why it is a problem:** In CLI mode within `main()`, the user-supplied argument `args[0]` (`target`) is printed directly to `System.out` without sanitizing newline characters (`\r`, `\n`) or terminal control sequences. When standard output is piped to system logs (e.g. via systemd, cron, or logging collectors like Fluentd/syslog) or monitored via an interactive terminal, an attacker passing crafted command-line arguments containing CRLF characters or ANSI escape sequences can forge log entries, spoof authentication success messages, or manipulate terminal emulator displays. The codebase correctly recognized this risk in `UserAccountNotFoundException.sanitizeForLog()`, but omitted it in `main()`.

**Fix:** Sanitize `target` using `UserAccountNotFoundException.sanitizeForLog()` (or strip control characters) before printing to standard output.
```java
                String target = args[0];
                String sanitizedTarget = UserAccountNotFoundException.sanitizeForLog(target);
                System.out.println("Looking up user: '" + sanitizedTarget + "'");
                Optional<UserAccount> accountOpt = repository.findByUsername(target);
                if (accountOpt.isPresent()) {
                    printAccountDetails(accountOpt.get());
                } else {
                    System.out.println("Result: No account found matching '" + sanitizedTarget + "'.");
                }
```

## 6. Verified Controls and Checks With No Finding
- SQL Injection Defense (CWE-89): Verified that `DEFAULT_SELECT_QUERY` (`UserAccountRepository.java:59-63`) uses positional bind placeholders (`?`) and `findByUsername` (`UserAccountRepository.java:439-454`) uses `PreparedStatement` with `pstmt.setString(1, trimmed)`. User input is strictly bound as a data literal, preventing SQL injection vectors including tautologies, comments, stacked queries, and UNION-based exfiltration.
- Caller Connection Ownership: Verified that `UserAccountRepository.java` borrows the active `Connection` without invoking `close()`, `commit()`, or `rollback()`, properly preserving caller transaction boundaries and external connection pool lifecycles.
- Deterministic Resource Management (CWE-404 / CWE-772): Verified that `PreparedStatement` and `ResultSet` are allocated within nested Java try-with-resources blocks (`UserAccountRepository.java:439-461`), guaranteeing automatic resource disposal even when SQL exceptions occur.
- Principle of Least Privilege and Credential Protection (CWE-200 / CWE-312): Verified that query projections explicitly request only non-sensitive columns (`id, username, email, full_name, role, is_active, created_at, last_login_at`) and that the immutable `UserAccount` record (`UserAccountRepository.java:133-159`) excludes password hashes, salts, and secret credentials.
- Defensive Input Validation and DoS Bounds (CWE-20 / CWE-400): Verified that `findByUsername` safely handles `null`, empty, and blank whitespace inputs by returning `Optional.empty()` without issuing database queries (`UserAccountRepository.java:429-436`), enforces a maximum username length bound of 255 characters (`MAX_USERNAME_LENGTH`), limits row buffering via `pstmt.setMaxRows(1)`, and enforces statement timeouts via `pstmt.setQueryTimeout(10)`.
- Log Injection Defense in Exception Types (CWE-117): Verified that `UserAccountNotFoundException` (`UserAccountRepository.java:164-185`) sanitizes user input via `sanitizeForLog()`, stripping `\r` and `\n` characters before embedding into exception messages.
- Maven Build Configuration: Verified that `pom.xml` configures source/target release versions consistently to Java 17 and contains no insecure repository URLs or malicious build plugins.
