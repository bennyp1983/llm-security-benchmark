# Security Review: UserAccountLookup (JDBC user account lookup)

## 1. Executive Summary
`UserAccountLookup` is a small Java 17 class. It looks up a user account in an SQL database by a username the user supplies, using an existing JDBC `Connection`. It returns a record with non-sensitive fields: `id`, `username`, `email`, `full_name`, `active` and `created_at`. A command-line `main` method demonstrates the lookup. It reads connection settings from environment variables and prints the account it finds to the terminal.

The main risk for this code is SQL injection, and it is handled correctly. The SQL text is a compile-time constant with a single `?` placeholder. The username is bound with `PreparedStatement.setString`, and an allow-list check (length and `[A-Za-z0-9._-]`) runs first as an extra layer. The query does not select password hashes. JDBC resources are closed with try-with-resources. The statement has a query timeout and a row limit. Error output does not echo input or print driver messages.

The review found **one Low-severity issue** (SEC-01). The command-line demo prints values from the database (`email`, `full_name`, `username`) to the terminal without removing control characters. Anyone who can write those columns, for example through self-registration or a profile update, can store ANSI/OSC escape sequences or bidi override characters. These run in the terminal of the operator who runs the lookup. The review found no Critical, High or Medium issues.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `UserAccountLookup.java` | Library class and CLI demo that look up a user account by username through JDBC. | Builds the SQL query (parameterised `PreparedStatement`), validates untrusted input (`validateUsername`), limits which columns are selected (no credentials), manages resources (try-with-resources, query timeout, `setMaxRows`), reads DB credentials from environment variables, handles errors and exit codes, and prints database data to the terminal. |
| `README.md` | Documentation: behaviour, expected schema, how to compile, run and set environment variables. | Describes the input-handling design, the expected `users` schema (includes `password_hash`, which is never selected), and the example JDBC URL and how credentials are supplied (`read -rs DB_PASSWORD`). No code runs. |
| `prompt.txt`, `cyber_prompt.txt`, `result.md`, `return.txt`, `prompt_hash.txt` | Task prompts and run metadata/logs for how the code was generated. | None. These are not source code. They were checked for embedded secrets and none were found. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: The router workflow. Used to list files and behaviours, choose skills and structure this report.
- `exploiting-sql-injection-vulnerabilities`: Applied to how the query is built and executed (`UserAccountLookup.java:37-40`, `73-79`). Checked for string concatenation, dynamic identifiers and stacked or UNION injection paths, and confirmed the parameterised-query remediation pattern is already in use.
- `performing-second-order-sql-injection`: Applied to data read back from the database (`mapRow`, `UserAccountLookup.java:117-126`). Checked whether stored values are later used in SQL. They are not. That review of stored data led to SEC-01: the values reach a different output sink, the terminal.
- `testing-for-sensitive-data-exposure`: Applied to the selected columns and returned record (`UserAccountLookup.java:38-52`), the error output (`172-182`) and how credentials are handled (`147-154`, `README.md:98-107`).
- `testing-for-broken-access-control`: Applied to `findByUsername` to check whether the class enforces or skips authorisation, and to user-enumeration behaviour (exit codes `0` or `1`).
- `implementing-secret-scanning-with-gitleaks`: Its secret-detection patterns were applied by hand to every file in the folder to look for hardcoded passwords, tokens and connection strings with credentials. The Gitleaks tool was not run.
- General OWASP Top 10 / CWE knowledge (no specific library skill matched): terminal escape and control-character output (CWE-150), log and output injection from error messages (CWE-117), resource exhaustion and timeouts (CWE-400/CWE-770), regular-expression denial of service (CWE-1333), trust in the JDBC URL from the environment (CWE-15), and cleartext DB transport (CWE-319).

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Database values printed to terminal without neutralising control/escape sequences | Low | CWE-150 | `UserAccountLookup.java:162` |

## 5. Detailed Findings

### SEC-01: Database values printed to terminal without neutralising control/escape sequences
- **Severity:** Low
- **CWE:** CWE-150: Improper Neutralization of Escape, Meta, or Control Sequences
- **Location:** `UserAccountLookup.java:162-167`

**Vulnerable code:**
```java
// UserAccountLookup.java:162-167
                System.out.println("  id:         " + a.id());
                System.out.println("  username:   " + a.username());
                System.out.println("  email:      " + a.email());
                System.out.println("  full name:  " + a.fullName());
                System.out.println("  active:     " + a.active());
                System.out.println("  created at: " + a.createdAt());
```

**Why it is a problem:** The input username is strictly validated. The values printed here are not: they come from the `users` table (`mapRow`, `UserAccountLookup.java:117-126`). Other application flows usually let end users write columns such as `full_name` and `email`, for example registration or profile editing. The demo prints them straight to the operator's terminal. Stored data that contains ESC-based sequences (`[...`, OSC `]...`), carriage returns or Unicode bidi overrides (`U+202E`) is interpreted by the terminal. That lets an attacker:
- rewrite or hide earlier output, for example making an `active: false` line appear as `true` or forging a "No account found" message;
- change the window title or inject clickable OSC 8 hyperlinks;
- on vulnerable terminal emulators, trigger sequences that report data back into the input buffer, which has led to command execution in known terminal CVEs.

This is a stored (second-order) output-injection path. The input-side validation does not cover it. Severity is Low because only the CLI demo is affected, and it needs both write access to those columns and an operator who runs the tool.

**Fix:** Before printing values that come from the database, escape ISO control characters and Unicode format characters (which include bidi overrides). Apply this to every string field, including `username`, because database collation can return a stored value that differs from the validated input.
```java
                System.out.println("  id:         " + a.id());
                System.out.println("  username:   " + safeForTerminal(a.username()));
                System.out.println("  email:      " + safeForTerminal(a.email()));
                System.out.println("  full name:  " + safeForTerminal(a.fullName()));
                System.out.println("  active:     " + a.active());
                System.out.println("  created at: " + a.createdAt());

    /** Escapes control and format characters so stored data cannot drive the terminal. */
    private static String safeForTerminal(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); ) {
            int cp = value.codePointAt(i);
            if (Character.isISOControl(cp) || Character.getType(cp) == Character.FORMAT) {
                sb.append(String.format("\\u%04X", cp));
            } else {
                sb.appendCodePoint(cp);
            }
            i += Character.charCount(cp);
        }
        return sb.toString();
    }
```

## 6. Verified Controls and Checks With No Finding
- **SQL injection (CWE-89):** The SQL text is a `private static final` constant with a single `?` placeholder (`UserAccountLookup.java:38-40`). The username is bound with `stmt.setString(1, validated)` (`UserAccountLookup.java:77`). No SQL is built by string concatenation anywhere, and no table or column names are dynamic.
- **Second-order SQL injection:** Values read in `mapRow` (`UserAccountLookup.java:117-126`) are returned or printed only. They are never put back into a SQL statement.
- **Input validation (CWE-20):** `validateUsername` (`UserAccountLookup.java:97-115`) rejects null, empty and over-length (>64) input and anything outside `^[A-Za-z0-9._-]{1,64}$`. It uses `matches()`, so the whole string must match. The check is defence in depth and does not replace binding.
- **ReDoS (CWE-1333):** `USERNAME_PATTERN` (`UserAccountLookup.java:34-35`) is a single bounded character class with no nested quantifiers, and length is checked before the regex runs (`UserAccountLookup.java:105`).
- **Sensitive data exposure (CWE-200/CWE-359):** The query selects only `id, username, email, full_name, active, created_at` (`UserAccountLookup.java:39`). `password_hash` (`README.md:52`) is never read, and the `UserAccount` record has no credential fields (`UserAccountLookup.java:45-52`). Note: the auto-generated `toString()` of the record includes `email` and `fullName`. Callers should avoid logging the whole record (CWE-532), but this code does not log it.
- **Error message information leakage (CWE-209):** `SQLException` is reported as SQLState only (`UserAccountLookup.java:175-178`). Validation errors use fixed messages that do not echo input (`UserAccountLookup.java:110-112`, `172-174`). The duplicate-row message is a static string (`UserAccountLookup.java:85-86`, `179-181`).
- **Log/output injection from input (CWE-117):** Raw user input is never included in an exception message or printed (`UserAccountLookup.java:110-112`).
- **Hardcoded credentials (CWE-798/CWE-259):** No passwords, tokens or credential-bearing URLs appear in any file. `main` reads `DB_URL`, `DB_USER` and `DB_PASSWORD` from the environment (`UserAccountLookup.java:147`, `153-154`). The README tells users to enter the password with `read -rs` so it stays out of shell history (`README.md:104`). The files `result.md`, `return.txt` and the prompt files were also checked and contain no secrets.
- **Resource management / DoS (CWE-400, CWE-404, CWE-770):** `PreparedStatement`, `ResultSet` and the demo `Connection` are closed with try-with-resources (`UserAccountLookup.java:73`, `79`, `153`). The query has a 5-second timeout (`UserAccountLookup.java:42`, `74`) and returns at most two rows (`UserAccountLookup.java:76`). An injected caller connection is not closed, which is the documented design (`README.md:70`).
- **Data integrity / ambiguous identity:** If more than one row matches, the code throws `IllegalStateException` instead of silently returning an arbitrary account (`UserAccountLookup.java:84-87`).
- **Null handling:** A null `connection` is rejected in the constructor (`UserAccountLookup.java:57`), and a null `created_at` is handled (`UserAccountLookup.java:118`, `125`).
- **Access control / user enumeration (CWE-639, CWE-204):** `findByUsername` does no authorisation, and the demo's exit code `0` or `1` shows whether an account exists (`UserAccountLookup.java:159-171`). This is not a vulnerability in this component. The CLI caller must already hold database credentials that can read `users` directly, so no privilege boundary is crossed. Any application that exposes `findByUsername` to remote users must add its own authorisation and uniform "not found" responses.
- **Externally controlled JDBC URL (CWE-15):** `DB_URL` is taken from the environment unchanged (`UserAccountLookup.java:147-154`). Driver-specific URL options (for example H2 `INIT=RUNSCRIPT` or MySQL `autoDeserialize`) can be dangerous, but the environment is set by the same operator who runs the process. No trust boundary is crossed, so this is not a finding. The URL should never come from untrusted input.
- **Cleartext database transport (CWE-319):** The code neither enforces nor disables TLS. That is left to the JDBC URL. The README example points to `localhost` (`README.md:102`). For remote databases, operators should add driver TLS options (for example `sslmode=verify-full` for PostgreSQL). Nothing in the code weakens certificate validation.
- **Deserialization, command execution, file/path access, cryptography, XSS:** None of these appear anywhere in the folder, so none apply.
