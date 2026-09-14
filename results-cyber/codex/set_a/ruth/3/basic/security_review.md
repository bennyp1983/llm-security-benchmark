# Security Review: JDBC User Account Lookup

## 1. Executive Summary
`UserAccountLookup` is a small Java/JDBC component that retrieves one user record by an exact username, returns it as an immutable value object, and includes a command-line demonstration. The database query is correctly parameterized and JDBC resources are closed deterministically. One medium-severity issue was identified: the command-line path obtains the database password from an environment variable, where the credential may be exposed through process inspection, diagnostic output, crash collection, container configuration, or inherited environments.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/UserAccountLookup.java` | Implements the JDBC lookup, account model, and command-line entry point. | Accepts user-controlled input, executes SQL, reads database connection configuration and a password, returns PII, handles database errors, and manages JDBC resources. |
| `README.md` | Documents the schema, API use, compilation, and command-line configuration. | Shows a parameterized lookup and instructs operators to place the database password in `JDBC_PASSWORD`. |
| `prompt.txt` | Records the original implementation request. | Contains no executable behaviour or secrets. |
| `cyber_prompt.txt` | Records the security-review request and required report format. | Contains no executable behaviour or secrets. |
| `prompt_hash.txt` | Stores a hash identifying the original prompt. | Contains no executable behaviour or credential material. |
| `result.md` | Stores prior run metadata and an implementation summary. | Contains local path and build metadata but no credentials or executable application logic. |
| `return.txt` | Stores the prior tool transcript. | Contains commands, local paths, and token counts but no credentials or executable application logic. |

## 3. Skills Applied
- `exploiting-sql-injection-vulnerabilities`: applied to the username input, SQL statement construction, parameter binding, and query execution path.
- `testing-for-sensitive-data-exposure`: applied to database credential handling, secret scanning, account-data output, database error output, and transport configuration.
- General OWASP Top 10 / CWE knowledge: applied to input validation, authorization boundaries, JDBC resource management, denial-of-service considerations, and exception handling because no closer specialised skill matched those behaviours.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Database password sourced from an environment variable | Medium | CWE-526 | `src/UserAccountLookup.java:77` |

## 5. Detailed Findings

### SEC-01: Database password sourced from an environment variable
- **Severity:** Medium
- **CWE:** CWE-526: Exposure of Sensitive Information Through Environmental Variables
- **Location:** `src/UserAccountLookup.java:75-77`

**Vulnerable code:**
```java
// src/UserAccountLookup.java:75-77
        String jdbcUrl = System.getenv("JDBC_URL");
        String jdbcUser = System.getenv("JDBC_USER");
        String jdbcPassword = System.getenv("JDBC_PASSWORD");
```

**Why it is a problem:** The database password is placed in the process environment; `README.md:55-57` explicitly instructs operators to configure it this way. Environment variables can be copied into child processes and may be captured by process-inspection tooling, support bundles, crash reports, container-orchestration metadata, or accidental environment dumps. Disclosure would give an attacker the permissions of the application's database account. Actual exploitability depends on operating-system and deployment controls, but the source creates this exposure by making an environment variable the credential channel.

**Fix:** Obtain production credentials from a secrets manager or workload identity and pass them to the application through a protected, non-environment channel. For an interactive command-line demonstration, read the password without echoing it and clear the mutable buffer promptly. The following replacement removes `JDBC_PASSWORD` from the process environment; a production integration should replace the prompt with its secret-provider client.
```java
        String jdbcUrl = System.getenv("JDBC_URL");
        String jdbcUser = System.getenv("JDBC_USER");
        Console passwordConsole = System.console();
        if (passwordConsole == null) {
            throw new IllegalStateException(
                    "A console or configured secret provider is required for the database password");
        }

        char[] jdbcPassword = passwordConsole.readPassword("Database password: ");
        if (jdbcPassword == null) {
            throw new IllegalStateException("Database password was not provided");
        }
        String username = args.length > 0 ? args[0] : readUsername();
        try {
            try (Connection connection = DriverManager.getConnection(
                    jdbcUrl, jdbcUser == null ? "" : jdbcUser,
                    new String(jdbcPassword))) {
                Optional<UserAccount> account = findByUsername(connection, username);
                // Handle the result without logging credentials.
            }
        } finally {
            java.util.Arrays.fill(jdbcPassword, '\0');
        }
```

## 6. Verified Controls and Checks With No Finding
- SQL injection prevention: `src/UserAccountLookup.java:21-23` uses a fixed SQL string with a placeholder, and `src/UserAccountLookup.java:43-46` binds the username with `PreparedStatement.setString`; no user input is concatenated into SQL.
- Input validation: `src/UserAccountLookup.java:63-68` rejects null and blank usernames before database use. No security decision relies on sanitization; injection safety comes from parameter binding.
- JDBC resource lifecycle: nested try-with-resources blocks at `src/UserAccountLookup.java:43-60` close the statement and result set, while `src/UserAccountLookup.java:86-95` closes the connection owned by the CLI. The reusable method correctly leaves its caller-owned connection open.
- Hardcoded-secret scan: all scoped files were checked for credential and private-key patterns. No live secret was found; `README.md:57` contains only the explicit placeholder `change-me`.
- Credential disclosure through application output: the program never prints `jdbcPassword`, and it does not include the password in application-constructed error messages.
- Excessive account fields: `src/UserAccountLookup.java:21-23` selects only the five fields represented by the documented `UserAccount` result and does not select password hashes, tokens, or other authentication material.
- Error handling: `src/UserAccountLookup.java:96-102` catches expected input and SQL exceptions and does not print stack traces. The code does not interpolate credentials into errors.
- Resource-exhaustion review: the lookup executes one equality predicate and consumes at most the first result row at `src/UserAccountLookup.java:46-58`; the documented schema makes `username` unique.
- Authorization boundary: `findByUsername` is a data-access helper that requires an already-active `Connection` at `src/UserAccountLookup.java:38-40`; authentication and row-level authorization are necessarily owned by its caller or the database and are not bypassed in this component.
- Transport review: no code disables TLS or certificate verification. Transport protection is controlled by the externally supplied JDBC URL and driver, so deployments must require the appropriate driver-specific TLS verification settings.
