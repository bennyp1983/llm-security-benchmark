# Security Review: JDBC User Account Lookup

## 1. Executive Summary
`AccountLookup` is a small JDBC data-access component that retrieves one user account by exact username and includes an optional command-line demonstration. Its SQL construction is resistant to SQL injection because it uses a constant query with a bound `PreparedStatement` parameter, and database credentials are obtained from environment variables rather than embedded in source. Two disclosure issues were identified: the account's `toString()` exposes email and display-name PII and is printed by the CLI, and raw JDBC exception messages are written to standard error. No Critical or High severity issue was found.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `AccountLookup.java` | Looks up a user account by username and provides a CLI demonstration. | Accepts a caller-controlled username, executes a parameterized SQL query, reads database connection values from the environment, materializes PII, prints account data, and emits database errors. |

## 3. Skills Applied
- `exploiting-sql-injection-vulnerabilities`: Applied to the JDBC query, parameter binding, and user-controlled username flow.
- `testing-for-sensitive-data-exposure`: Applied to credentials, returned PII, string representations, console output, and error-message disclosure.
- General OWASP Top 10 / CWE knowledge: Applied to input validation and resource-exhaustion bounds, authorization boundaries, error handling, connection lifecycle, and deployment-controlled JDBC transport settings where no closer skill matched.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | User PII exposed through string representation and console output | Medium | CWE-532 | `AccountLookup.java:99-107` |
| SEC-02 | Raw database error details exposed to the console | Low | CWE-209 | `AccountLookup.java:134-136` |

## 5. Detailed Findings

### SEC-01: User PII exposed through string representation and console output
- **Severity:** Medium
- **CWE:** CWE-532: Insertion of Sensitive Information into Log File
- **Location:** `AccountLookup.java:99-107` (the value is emitted at `AccountLookup.java:129-130`)

**Vulnerable code:**
```java
// AccountLookup.java:99-107
        @Override
        public String toString() {
            return "UserAccount{" +
                    "id=" + id +
                    ", username='" + username + '\'' +
                    ", email='" + email + '\'' +
                    ", displayName='" + displayName + '\'' +
                    ", active=" + active +
                    '}';
```

**Why it is a problem:** `toString()` serializes the account's internal ID, username, email address, and display name. The command-line path passes this object directly to `System.out.println` at line 130, and the same representation could easily enter application logs during debugging or error handling. Console output is commonly captured by shell history tooling, CI systems, containers, and centralized log collectors, broadening access to PII beyond the database and increasing retention. An attacker or lower-privileged operator with access to those outputs could collect account information.

**Fix:** Do not place PII in a general-purpose string representation. Return a redacted representation and have the demonstration print only the minimum result state; expose individual fields only to explicitly authorized application code that needs them.
```java
        @Override
        public String toString() {
            return "UserAccount{fields=[REDACTED]}";
        }

        // In main, do not print the account object.
        if (account.isPresent()) {
            System.out.println("Account found.");
        } else {
            System.out.println("No account found for that username.");
        }
```

### SEC-02: Raw database error details exposed to the console
- **Severity:** Low
- **CWE:** CWE-209: Generation of Error Message Containing Sensitive Information
- **Location:** `AccountLookup.java:134-136`

**Vulnerable code:**
```java
// AccountLookup.java:134-136
        } catch (SQLException exception) {
            System.err.println("Database lookup failed: " + exception.getMessage());
            System.exit(1);
```

**Why it is a problem:** JDBC exception messages can contain database product and driver details, host or schema names, SQL fragments, object names, and operational state. Printing the raw message exposes those internals to anyone who can see command output or collected standard-error logs and gives an attacker useful reconnaissance. The impact is limited because this is a local demonstration path and no stack trace is printed.

**Fix:** Emit a stable, generic user-facing message. If diagnostics are required, record the exception only in a separately protected internal telemetry channel with access controls and redaction rather than standard error.
```java
        } catch (SQLException exception) {
            System.err.println("Database lookup failed.");
            System.exit(1);
        }
```

## 6. Verified Controls and Checks With No Finding
- SQL injection prevention: The SQL text is a constant with a single placeholder at `AccountLookup.java:16-18`, and the untrusted username is bound with `PreparedStatement.setString` at `AccountLookup.java:43-46`; it is never concatenated into SQL.
- Hardcoded secrets: No credentials or connection strings are embedded in the Java source; `JDBC_URL`, `DB_USER`, and `DB_PASSWORD` are loaded from environment variables at `AccountLookup.java:121-126`.
- Basic input validation: Null and blank usernames are rejected before database use at `AccountLookup.java:38-41`. No practical resource-exhaustion finding was established for this small lookup method, although callers should still enforce application-specific username length limits.
- Resource management: Statements and result sets are closed using nested try-with-resources at `AccountLookup.java:43-59`, and the CLI connection is closed by try-with-resources at `AccountLookup.java:125-137`.
- Connection state validation: The constructor rejects null and already-closed connections at `AccountLookup.java:26-30`.
- Data minimization in the query: The query selects named columns rather than using `SELECT *` at `AccountLookup.java:16-18`, and no password or authentication-secret column is retrieved.
- Authorization boundary: The file is a data-access helper with no request, session, or principal context. Authorization cannot be implemented or disproved within this component and must be enforced by its caller before invoking `findByUsername`; no evidence of an authorization bypass exists in the in-scope code.
- JDBC transport configuration: The URL is supplied by trusted deployment configuration rather than user input at `AccountLookup.java:121-126`. TLS enforcement depends on the selected JDBC driver and deployed URL, so no source-level transport vulnerability was established.
