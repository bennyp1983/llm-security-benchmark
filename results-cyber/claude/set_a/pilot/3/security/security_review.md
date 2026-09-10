# Security Code Review — `com.example.users` JDBC user-lookup code

**Scope reviewed:** `src/com/example/users/UserAccount.java`, `src/com/example/users/UserAccountDao.java`, `src/com/example/users/UserLookupExample.java` (3 files, ~180 LoC).
**Method:** the `review-code-for-security-vulnerabilities` router skill — understand the code, select matching specialised skills from the library, apply their checklists against the code, report with CWE ids and `file:line` evidence.
**Date:** 2026-09-09

---

## 1. What the code does (Step 1)

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `UserAccount.java` | Immutable DTO for a row of the `users` table (id, username, email, enabled, created_at). | Holds PII (username, e-mail). Defensive copies of the mutable `Timestamp` on construction (`UserAccount.java:19`) and on read (`UserAccount.java:39`). `toString()` deliberately omits e-mail (`UserAccount.java:44-45`). |
| `UserAccountDao.java` | Reads user accounts from a caller-supplied JDBC `Connection`: exact lookup by username and a prefix (`LIKE`) search. | SQL statement construction; user-supplied `username`/`prefix` reaching the database; `LIKE` wildcard escaping (`UserAccountDao.java:99-109`); result-set size cap via `setMaxRows` (`UserAccountDao.java:80`); exception message construction (`UserAccountDao.java:57`); no authentication/authorisation logic; no credential or crypto handling. |
| `UserLookupExample.java` | Demo caller: looks up a username and prints the outcome. | Untrusted username flows into `System.out.println` (`UserLookupExample.java:18`); uniform "not found" message to avoid enumeration (`UserLookupExample.java:20-22`). |

**Keywords derived:** SQL injection, second-order SQL injection, LIKE-wildcard injection, sensitive data / PII exposure, error-message information leakage, log injection, access control, resource limits, input validation. No cryptography, no secrets, no deserialization, no file/path or OS-command handling, no network/TLS code exists in scope.

---

## 2. Skills applied (Step 2/3)

Selected from the library by name grep + description skim, in priority order:

1. **`exploiting-sql-injection-vulnerabilities`** — applied in full to both queries (injection-point discovery, string-concatenation review, stacked-query and `ORDER BY`/identifier-injection review, remediation criteria "parameterized query" definition).
2. **`performing-second-order-sql-injection`** — applied: mapped storage points vs. trigger points in this code.
3. **`testing-for-sensitive-data-exposure`** — applied: PII in objects/output, error-response information leakage, excessive data returned by list endpoints.
4. **`testing-for-broken-access-control`** — applied: is any authorisation performed before returning another user's record (horizontal access / IDOR-by-username)?
5. **`testing-for-business-logic-vulnerabilities`** — skimmed and applied lightly (limit handling, uniqueness assumption); no e-commerce/workflow logic present.

Behaviours with **no** matching library skill (log injection into stdout, unbounded `limit` / resource consumption, input-length validation, JDBC `ESCAPE` portability) were reviewed against general **OWASP Top 10 (A01, A03, A04, A05, A09) and CWE** knowledge, as noted in the findings below.

---

## 3. Headline result

**No SQL injection vulnerability was found.** Both statements are compile-time constants with `?` placeholders bound via `PreparedStatement.setString` — `UserAccountDao.java:22-27`, `:48-49`, `:78-79`. There is no string concatenation of user input into SQL text anywhere, no dynamic table/column/`ORDER BY` identifier taken from input, no stacked queries, and no `Statement.execute`/`executeQuery(String)` usage. The `LIKE` search additionally escapes `%`, `_` and `\` (`UserAccountDao.java:99-109`) and declares `ESCAPE '\'` (`UserAccountDao.java:27`), so a caller cannot turn a prefix search into a full-table wildcard scan. This is the correct pattern; the primary objective of the code is met.

The issues below are real but secondary — information leakage, missing authorisation, output handling and resource limits.

---

## 4. Findings

### F-1 — Untrusted username echoed into an exception message (information leakage / log forging)
- **Severity:** Low
- **CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information); secondary CWE-117 (Improper Output Neutralization for Logs)
- **Evidence:** `src/com/example/users/UserAccountDao.java:57`
  ```java
  throw new SQLException("More than one user matched username: " + username);
  ```
- **Why it is a problem:** `username` is explicitly documented as attacker-controlled and "may be any string" (`UserAccountDao.java:41`). The raw value is embedded in an exception message that will typically reach an application log or, in many stacks, an error page. An attacker can inject CR/LF and fake log records, inject ANSI/terminal control sequences, or plant payloads that fire in a downstream log viewer. The message also confirms internal database state (a broken `UNIQUE` constraint on `users.username`) to whoever sees it.
- **Fix:** Do not interpolate the input. Log a sanitised/length-capped value at most, and keep the caller-visible message generic:
  ```java
  throw new SQLException("More than one user matched the supplied username");
  ```
  If the value is needed for diagnostics, log it separately through a logger with newline/control-character stripping, or log only a hash/length.

### F-2 — DAO performs no authorisation; any caller can read any user's record by name
- **Severity:** Low (design/contract issue — Medium if the DAO is reachable from a request handler without a check)
- **CWE:** CWE-862 (Missing Authorization); related CWE-639 (Authorization Bypass Through User-Controlled Key)
- **Evidence:** `src/com/example/users/UserAccountDao.java:45-62` and `:71-88`; caller `src/com/example/users/UserLookupExample.java:13-18`
- **Why it is a problem:** Applying the `testing-for-broken-access-control` checklist: the lookup key is a fully user-controlled string, and neither the DAO nor the sample caller establishes *who* is asking or whether they may see that account. `findByUsernamePrefix("", 1000)` (an empty prefix matches everything after escaping) enumerates the whole user table together with e-mail addresses — a horizontal access-control / mass-disclosure primitive if this ever sits behind an unauthenticated or under-authorised endpoint. The class Javadoc does not state that authorisation is the caller's responsibility, so the contract is easy to get wrong.
- **Fix:** Enforce authorisation in the service layer above the DAO before calling either method (own-account only, or an explicit `user:read` privilege for directory search), and document that the DAO is authorisation-agnostic. Consider rejecting a blank/very short prefix in `findByUsernamePrefix`.

### F-3 — PII (e-mail address) returned by default from the search path
- **Severity:** Low
- **CWE:** CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor) / CWE-213 (Exposure of Sensitive Information Due to Incompatible Policies)
- **Evidence:** `src/com/example/users/UserAccountDao.java:26` and `:90-97` (`email` is always selected and mapped), consumed at `src/com/example/users/UserLookupExample.java:18`
- **Why it is a problem:** The `testing-for-sensitive-data-exposure` "excessive data in list endpoints" check fires: the prefix/autocomplete-style search returns full records including e-mail for every match, rather than the minimum needed for a name search. If the result is serialised to an API response, the whole result set leaks user e-mail addresses. (`UserAccount.toString()` at `:44-45` correctly omits e-mail, which limits accidental *log* exposure — that part is good — but the getter at `:30-32` and any JSON serialiser still expose it.)
- **Fix:** Give the search path a narrower projection (`SELECT id, username` plus a dedicated lightweight DTO), and only return e-mail from the single-record path when the caller is authorised for it.

### F-4 — Untrusted data written to stdout without neutralisation
- **Severity:** Low
- **CWE:** CWE-117 (Improper Output Neutralization for Logs)
- **Evidence:** `src/com/example/users/UserLookupExample.java:18`
  ```java
  System.out.println("Found: " + account.get());
  ```
- **Why it is a problem:** `account.get().toString()` embeds the stored `username` (`UserAccount.java:45`), which originated from user input at registration time. Newlines or terminal escape sequences in that value forge or corrupt log lines when stdout is captured by a log collector. Reviewed against general OWASP A09 (Security Logging and Monitoring Failures) knowledge — no library skill covers this directly.
- **Fix:** Use a logging framework with parameterised messages and strip `\r`/`\n`/control characters from user-derived fields before emitting them (e.g. `username.replaceAll("[\\p{Cntrl}]", "")`).

### F-5 — Caller-supplied `limit` is unbounded (resource consumption / bulk extraction)
- **Severity:** Low
- **CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling); related CWE-1284 (Improper Validation of Specified Quantity in Input)
- **Evidence:** `src/com/example/users/UserAccountDao.java:71-80`
  ```java
  if (limit <= 0) { throw new IllegalArgumentException("limit must be positive"); }
  ...
  statement.setMaxRows(limit);
  ```
- **Why it is a problem:** Only the lower bound is validated. `limit = Integer.MAX_VALUE` is accepted, and every returned row is accumulated into an in-memory `ArrayList` (`:77`, `:83`), so a single request against a large `users` table can exhaust heap and dump the directory. `setMaxRows` also caps rows *after* the server has executed the query, so it does not bound database-side work.
- **Fix:** Clamp to a server-side maximum, e.g. `int effective = Math.min(limit, MAX_PAGE_SIZE);`, and prefer a SQL-level `FETCH FIRST ? ROWS ONLY` / `LIMIT ?` bound parameter over `setMaxRows` so the database also stops early.

### F-6 — No length/character validation on `username` and `prefix`
- **Severity:** Informational
- **CWE:** CWE-20 (Improper Input Validation)
- **Evidence:** `src/com/example/users/UserAccountDao.java:46` and `:72` — only `Objects.requireNonNull`, no bounds check
- **Why it is a problem:** Not exploitable as injection (binding neutralises that), but a multi-megabyte `prefix` is expanded character-by-character by `escapeLikeWildcards` (`:99-109`) into a new `StringBuilder` and then shipped to the database as a `LIKE` pattern — wasted memory and a costly non-indexable scan. Defence-in-depth allowlisting is the standard OWASP A03 companion control to parameterisation.
- **Fix:** Reject usernames/prefixes exceeding the column length (and, if the schema allows, validate against the permitted username character set) before querying.

### F-7 — `ESCAPE '\'` literal is not portable and can break on MySQL (robustness, not a vulnerability)
- **Severity:** Informational
- **CWE:** CWE-1078 / general robustness (no direct security impact)
- **Evidence:** `src/com/example/users/UserAccountDao.java:26-27`
  ```java
  "WHERE username LIKE ? ESCAPE '\\' ORDER BY username"   // SQL text is: ESCAPE '\'
  ```
- **Why it is worth noting:** On MySQL/MariaDB without `NO_BACKSLASH_ESCAPES`, a backslash inside a string literal is itself an escape character, so the SQL text `ESCAPE '\'` is a syntax error (the literal is not terminated). The failure mode is a thrown `SQLException`, **not** injection or a wildcard bypass — the escaping in `escapeLikeWildcards` is itself correct and complete (`\`, `%`, `_` all handled, backslash handled first). Flagged so the LIKE-escaping defence is not silently lost during a database migration.
- **Fix:** Use a non-backslash escape character that needs no quoting, e.g. `ESCAPE '!'` with `escapeLikeWildcards` prefixing `!`, or set the escape character per-dialect.

---

## 5. Checks performed that did **not** fire

Applying the selected skills' checklists in full; each of these was verified against the code and found clean:

- **First-order SQL injection** (`exploiting-sql-injection-vulnerabilities`, Steps 1/3/5): no concatenation, no `String.format`, no `Statement`/`executeQuery(String)`; both SQL strings are `private static final` constants — `UserAccountDao.java:22-27`. Payloads such as `' OR '1'='1`, `admin'--`, `'; DROP TABLE users--` are bound as literals at `:49` and `:79`. No error-based, UNION-based, boolean-blind, time-based or stacked-query vector exists.
- **Identifier / `ORDER BY` injection:** the sort column is hard-coded (`UserAccountDao.java:27`); no dynamic table, column or direction from input.
- **LIKE-wildcard injection:** escaping is applied before the wildcard is appended, and the `%` is added to the *value*, not the SQL — `UserAccountDao.java:79`, `:99-109`.
- **Second-order SQL injection** (`performing-second-order-sql-injection`, Step 1): the code has **no storage points** — no `INSERT`/`UPDATE`, no stored procedure calls, and no path where a value read from the DB is re-used to build SQL. `mapRow` (`:90-97`) only materialises a DTO.
- **Secrets in source** (`testing-for-sensitive-data-exposure`, Step 1): no hard-coded credentials, connection strings, API keys or tokens; the `Connection` is injected by the caller (`UserAccountDao.java:34-36`).
- **Cryptography / password storage:** none present — no password column is selected (`:22-27`), no hashing, no encryption, no RNG. Nothing to weaken.
- **Username enumeration:** the sample caller deliberately returns an identical message for both branches — `UserLookupExample.java:19-23`. Correct.
- **Resource leaks:** both `PreparedStatement` and `ResultSet` use try-with-resources (`:48-61`, `:78-86`); the DAO correctly does not close a `Connection` it does not own (`:32`).
- **Mutable-state / DTO issues:** `UserAccount` is `final` with `final` fields and defensive `Timestamp` copies in and out (`UserAccount.java:19`, `:39`) — no CWE-374/375 exposure.
- **Deserialization, path traversal, OS command injection, SSRF, XXE, XSS, TLS configuration:** no corresponding code exists in scope (no serialization, file, process, HTTP, XML or view-rendering APIs are used). Reviewed against general OWASP Top 10 / CWE knowledge and confirmed not applicable.

---

## 6. Summary

| ID | Severity | CWE | Location |
|---|---|---|---|
| F-1 | Low | CWE-209 / CWE-117 | `UserAccountDao.java:57` |
| F-2 | Low | CWE-862 / CWE-639 | `UserAccountDao.java:45`, `:71` |
| F-3 | Low | CWE-359 | `UserAccountDao.java:26`, `:90-97` |
| F-4 | Low | CWE-117 | `UserLookupExample.java:18` |
| F-5 | Low | CWE-770 / CWE-1284 | `UserAccountDao.java:73-80` |
| F-6 | Info | CWE-20 | `UserAccountDao.java:46`, `:72` |
| F-7 | Info | robustness | `UserAccountDao.java:26-27` |

No Critical, High or Medium findings. The injection-resistance objective stated in the class Javadoc (`UserAccountDao.java:15-18`) is genuinely met by the implementation; the residual risk is concentrated in error-message handling, output neutralisation, authorisation being left entirely to the caller, and an unbounded result limit.
