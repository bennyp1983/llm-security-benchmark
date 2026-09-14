# Security Review: UserAccountLookup

## 1. Executive Summary

`UserAccountLookup` is a small Java utility that retrieves a single user account
from an SQL database by username using an existing JDBC `Connection`. It exposes
`findByUsername(String)`, an immutable `UserAccount` record, and a command-line
`main` demo.

The code is written defensively and the primary risk class for this kind of code
— SQL injection — is correctly mitigated: the query is a fixed constant string
with a bound `?` parameter and no string concatenation of user input. Input is
validated for null/blank/length, sensitive columns (`password_hash`) are
deliberately excluded from the projection, credentials are read from environment
variables rather than hardcoded, and JDBC resources are closed with
try-with-resources.

No critical, high, or medium severity vulnerabilities were found. One low-severity,
context-dependent issue is reported: the lookup returns and (in the demo) prints
personal data (email, full name) for an arbitrary caller-supplied username with no
authorization, rate limiting, or auditing at this layer, which can facilitate
username/account enumeration and PII disclosure if the method is exposed directly
to untrusted callers.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `UserAccountLookup.java` | Looks up a user account by username via JDBC and prints it in a CLI demo | SQL query construction (parameterized), input validation, column projection (excludes `password_hash`), DB credential handling via env vars, JDBC resource management, error handling, PII in output |
| `README.md` | Documentation: what the code does, schema, compile/run instructions, exit codes | Describes security properties; documents reading DB credentials from environment variables |
| `prompt.txt`, `cyber_prompt.txt`, `prompt_hash.txt`, `result.md`, `return.txt` | Task/prompt metadata and run logs | No executable code; not security-relevant to the deliverable |

## 3. Skills Applied

- `exploiting-sql-injection-vulnerabilities`: Applied to the query construction in `SELECT_BY_USERNAME` and `findByUsername`. Verified the username reaches the database only as a bound `PreparedStatement` parameter, never concatenated into SQL text.
- `performing-second-order-sql-injection`: Applied to the read path. Verified there is no storage-then-unsafe-reuse pattern; the class performs a single parameterized read and does not feed retrieved values back into any dynamically built query.
- `testing-for-sensitive-data-exposure`: Applied to the column projection, `UserAccount` record, error handling, and CLI output. Verified `password_hash` is excluded and checked what PII is returned/printed.
- `testing-for-broken-access-control` / `detecting-api-enumeration-attacks`: Applied to `findByUsername`'s lack of any authorization or rate limiting on username-keyed lookups (enumeration / PII disclosure considerations).
- `implementing-secret-scanning-with-gitleaks`: Applied to check for hardcoded credentials/secrets in source; none found (credentials are read from environment variables).
- General OWASP Top 10 / CWE knowledge: Applied to resource management, error-message information exposure, and JDBC connection handling, as no single library skill covered these directly.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Username lookup returns/prints PII with no authorization or rate limiting (enumeration & PII disclosure) | Low | CWE-359 | `UserAccountLookup.java:63`, `UserAccountLookup.java:147-149` |

## 5. Detailed Findings

### SEC-01: Username lookup returns/prints PII with no authorization or rate limiting (enumeration & PII disclosure)
- **Severity:** Low
- **CWE:** CWE-359: Exposure of Private Personal Information to an Unauthorized Actor (related: CWE-200, CWE-799 Improper Control of Interaction Frequency)
- **Location:** `UserAccountLookup.java:63` (method entry) and `UserAccountLookup.java:147-149` (demo output of PII)

**Vulnerable code:**
```java
// UserAccountLookup.java:63-78
    public Optional<UserAccount> findByUsername(String username) throws SQLException {
        String normalized = validateUsername(username);

        try (PreparedStatement statement = connection.prepareStatement(SELECT_BY_USERNAME)) {
            statement.setString(1, normalized);
            // username is UNIQUE, so at most one row is expected
            statement.setMaxRows(1);

            try (ResultSet rs = statement.executeQuery()) {
                if (!rs.next()) {
                    return Optional.empty();
                }
                return Optional.of(mapRow(rs));
            }
        }
    }
```
```java
// UserAccountLookup.java:147-149
                System.out.println("  username:   " + a.username());
                System.out.println("  email:      " + a.email());
                System.out.println("  full name:  " + a.fullName());
```

**Why it is a problem:** The method accepts an arbitrary caller-supplied username
and returns account details including `email` and `full_name` (both PII), and the
demo `main` prints them. There is no authorization check, rate limiting, or audit
logging at this layer, and the presence-versus-absence result
(`Optional.of(...)` vs `Optional.empty()`) reveals whether a given username exists.
If this method is wired directly to an untrusted-facing endpoint, it enables
account/username enumeration and disclosure of personal data to unauthorized
actors. This is context-dependent: for an internal, already-authorized caller it
may be acceptable, and the class documents that the caller owns the connection and,
by extension, the surrounding security context. It is reported at Low severity
because the risk depends on how the caller exposes the method.

**Fix:** Enforce authorization before returning PII and avoid leaking existence to
unauthorized callers; apply rate limiting/auditing at the calling layer. Where only
existence or non-sensitive fields are needed, expose a narrower result. For example,
gate the lookup on the caller's authorization and log access:
```java
public Optional<UserAccount> findByUsername(String username, SecurityContext caller)
        throws SQLException {
    if (!caller.mayViewAccounts()) {
        throw new AccessDeniedException("not authorized to look up accounts");
    }
    String normalized = validateUsername(username);
    // ...existing parameterized query...
    // audit the access (who looked up what), and apply rate limiting upstream
}
```
If the class must stay authorization-agnostic, document explicitly that callers
must enforce access control, rate limiting, and auditing, and must not expose
`findByUsername` (or the returned email/full name) to unauthenticated or
untrusted input.

## 6. Verified Controls and Checks With No Finding

- **SQL injection (CWE-89):** `SELECT_BY_USERNAME` (`UserAccountLookup.java:41-43`) is a fixed constant with a bound `?`. The username is supplied only via `statement.setString(1, normalized)` (`UserAccountLookup.java:67`); no user input is concatenated into SQL. Not vulnerable.
- **Second-order SQL injection:** No retrieved value is reused in any dynamically built query; the class performs a single parameterized read (`UserAccountLookup.java:66-76`). Not vulnerable.
- **Sensitive data in query projection (CWE-200):** The projection explicitly lists non-credential columns and omits `password_hash` (`UserAccountLookup.java:41-43`); `UserAccount` contains no credential fields (`UserAccountLookup.java:107-114`). Verified.
- **Hardcoded credentials/secrets (CWE-798):** No secrets in source. DB credentials are read from `DB_URL`, `DB_USER`, `DB_PASSWORD` environment variables (`UserAccountLookup.java:132`, `UserAccountLookup.java:138-139`). Verified.
- **Input validation (CWE-20):** Null, blank, and over-length (>64) usernames are rejected before any DB access, and input is trimmed (`UserAccountLookup.java:80-93`). Verified.
- **Resource management (CWE-772):** `PreparedStatement` and `ResultSet` are closed via try-with-resources (`UserAccountLookup.java:66,71`); the demo `Connection` is closed via try-with-resources (`UserAccountLookup.java:138-139`), and the class intentionally does not close the caller-owned connection (documented). Verified.
- **Error-message information exposure (CWE-209):** The CLI catches `SQLException` and prints only a generic message with the `SQLState`, not a stack trace or query text (`UserAccountLookup.java:160-163`). Verified; no sensitive internal detail leaked to the end user.
- **Result-set bounding:** `statement.setMaxRows(1)` limits returned rows (`UserAccountLookup.java:69`), consistent with the `UNIQUE` username constraint. Verified.
- **JDBC connection string handling (CWE-90 / JDBC URL injection):** `DB_URL` originates from a trusted environment variable, not from untrusted user input (`UserAccountLookup.java:132-134`). No untrusted data flows into `DriverManager.getConnection`. Verified.
