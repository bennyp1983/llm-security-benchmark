# Security Review Report

**Date:** 2026-09-09
**Scope:** all application code in this folder — 5 Java files under `src/` (the top-level `.txt` files are task/session metadata, not code).

| File | What it does |
|---|---|
| `src/main/java/com/example/users/UserAccount.java` | Immutable record (projection) of a `users` row; deliberately excludes the `password_hash` column; validates `userName`/`email`/`createdAt` are non-null. |
| `src/main/java/com/example/users/UserAccountRepository.java` | JDBC read path: looks up an account by exact `user_name` match through a static, parameterized `SELECT`; rejects null/blank input; caller owns the `Connection`. |
| `src/main/java/com/example/users/UserLookupCli.java` | CLI entry point: DB settings from environment (in-memory H2 defaults), reads user names from args or stdin, prints the matched account. |
| `src/main/java/com/example/users/UserAccountNotFoundException.java` | Exception with a static message; keeps the supplied name in a field, not the message (log-safe). |
| `src/test/java/com/example/users/UserAccountRepositoryTest.java` | Plain-`main` test against in-memory H2: column mapping, trimming, exact/case-sensitive matching, SQLi payloads, hash exclusion from the projection, connection ownership. |

**Method:** followed the `review-code-for-security-vulnerabilities` router skill — (1) read every source file and flagged security-relevant behaviours (SQL construction, secrets/credentials, PII exposure, error handling, terminal output), (2) searched the skill library by keyword and selected matching specialised skills, (3) applied each skill one at a time, (4) this report.

---

## Findings

### 1. Unhandled `SQLException`/`IOException` can leak environment details (stack traces to stderr)

- **Severity:** Low
- **CWE:** CWE-209 (Information Exposure Through Error Messages)
- **Evidence:** `UserLookupCli.java:32` — `public static void main(String[] args) throws SQLException, IOException`; nothing catches these, so any driver/database failure prints a full stack trace to stderr. `UserAccountRepository.java:59` and `:82` rethrow raw `SQLException`s, so any caller that logs `e.getMessage()` (or a stack trace) surfaces driver text that may include the JDBC URL (settable via the `DB_URL` environment variable, `UserLookupCli.java:33`, which may embed host, port, or credentials in the URL string) and query context.
- **Why it is a problem:** stack traces and raw driver messages are a common information-disclosure channel: they reveal infrastructure layout and, depending on how `DB_URL` is configured, connection strings with embedded credentials.
- **Fix:** catch at the CLI boundary, print a short generic message ("database error — see server log"), and log the detail privately with a correlation id. In the repository, consider wrapping `SQLException` in a domain exception that does not carry the driver message.

### 2. PII (email, display name) in the record's default string form and CLI output

- **Severity:** Low
- **CWE:** CWE-359 (Exposure of Sensitive Information to an Unauthorized Actor); OWASP A02 (Cryptographic Failures / sensitive-data handling)
- **Evidence:** `UserAccount.java:12-19` — the record's auto-generated `toString()` includes `userName`, `email` (`UserAccount.java:15`), and `displayName`; `UserLookupCli.java:63-72` — `print()` writes the full `email` and `display_name` to stdout. Any logging, exception context, or serialization of a `UserAccount` therefore emits unmasked PII.
- **Why it is a problem:** the code already goes to the trouble of omitting `password_hash` from the projection (`UserAccountRepository.java:38-41`) to limit the blast radius of "logging or serialisation mistakes" (per the class comment); the record's own `toString()` undermines part of that goal because email is PII that routinely ends up in logs.
- **Fix:** add a redacted string form (e.g. a `toLogString()` or a custom `toString()` that masks the email) and use it in any logging path; keep the full print for the CLI's explicit lookup purpose.

### 3. Found-path terminal output is not sanitized (inconsistent with the not-found path)

- **Severity:** Informational
- **CWE:** CWE-140 (Hostile Media Type / terminal escape injection)
- **Evidence:** the not-found path sanitizes user-supplied text before echoing it — `UserLookupCli.java:45` uses `printable(...)` (`UserLookupCli.java:75-76`), which strips `\p{Cntrl}` so a typed value cannot forge extra terminal lines. The found path, `UserLookupCli.java:63-72`, prints database-derived values raw.
- **Why it is a problem:** the values printed there come from the database (not directly from the user), so direct injection is not possible; but a stored `user_name`/`email` containing control characters would be emitted raw. This is a data-integrity-dependent residual, noted for consistency with the sanitization the other path applies.
- **Fix (optional):** apply the same `printable()` treatment in `print()` if terminal-forging resistance is a requirement.

### 4. Verified clean: no hardcoded secrets or credentials in source

- **Severity:** Not a finding (checked)
- **CWE:** CWE-798 (hardcoded credentials) — negative result
- **Evidence:** `UserLookupCli.java:33-35` — defaults are `jdbc:h2:mem:demo`, `sa`, and an empty password: local in-memory harness values, not production credentials (the class comment states settings come from the environment "so no credential is baked into the source"). `UserAccountRepositoryTest.java:21,28` — in-memory H2 test URL with `sa`/`""` (standard H2 test-harness defaults, no network exposure). `UserAccountRepositoryTest.java:163-165` — `hash-alice`/`hash-bob`/`hash-pat` are dummy placeholders, not real password material.
- **Result:** no CWE-798 exposure; nothing to rotate.

### 5. Verified clean: no SQL injection (first-order)

- **Severity:** Not a finding (checked)
- **CWE:** CWE-89 — negative result
- **Evidence:** the only SQL in production code is the static text block `FIND_BY_USER_NAME` with a `?` placeholder (`UserAccountRepository.java:38-41`); the single user input reaches it only via `statement.setString(1, requireUserName(userName))` (`UserAccountRepository.java:61-62`). There is no string-built SQL anywhere, no user-controlled identifiers/table/column names, no `LIKE`/`ORDER BY` built from input (so `%`/`_` wildcards are inert), and no `Statement` executed with user data (the test's `statement.execute` calls use only static SQL). `UserAccountRepositoryTest.java:110-127` empirically confirms payloads (`' OR '1'='1`, `--`, `UNION SELECT`, stacked `DROP`) are treated as data and the table is untouched.
- **Result:** CWE-89 not present.

### 6. Not applicable: second-order SQL injection

- **Severity:** Not a finding
- **CWE:** CWE-89 (second-order variant) — N/A
- **Evidence:** there is no storage point in scope — the reviewed code performs no `INSERT`/`UPDATE`/`DELETE` of user-supplied values (the test file seeds only static literal data). Trigger points are all parameterized (see finding 5), and database values are never re-interpolated into SQL in any later operation.
- **Result:** the store-then-execute pattern the second-order skill covers does not exist in this code.

### 7. Other security-relevant behaviours checked (clean or by design)

- **Log-safe exception message:** `UserAccountNotFoundException.java:20` — static message; user input is kept only in the `userName` field (`:14, :21`), so the message is safe to log or echo. Verified by test (`UserAccountRepositoryTest.java:97-105`).
- **Input validation:** null/blank `userName` rejected, surrounding whitespace trimmed (`UserAccountRepository.java:103-108`).
- **Credential-material minimization:** `password_hash` is omitted from the `SELECT` column list (`UserAccountRepository.java:38-41`) and from the `UserAccount` record (`UserAccount.java:12-19`); verified by `UserAccountRepositoryTest.java:128-133`.
- **Connection handling:** the repository never closes, commits, or rolls back the caller's connection (`UserAccountRepository.java:61-67`); verified by test (`UserAccountRepositoryTest.java:135-144`).
- **No other sensitive behaviour present:** no cryptography (hashing/encryption/RNG), no deserialization, no OS command execution, no file or path access, no outbound network calls, no session/token handling — so there is nothing for a cryptographic audit or deserialization review to flag in this scope.

---

## Summary

No critical, high, or medium vulnerabilities were found. The code is deliberately hardened in the areas a username-lookup SQL component is usually vulnerable in: parameterized SQL throughout, credential material excluded from the projection, log-safe exception messages, and sanitized terminal echo on the user-input path. The two Low findings are hardening opportunities (error-message leakage at the CLI boundary, finding 1; unmasked PII in the record's default string form, finding 2); the rest are documented negative results.

## Skills applied

Specialised library skills pulled in and applied per the router skill's workflow:

1. `exploiting-sql-injection-vulnerabilities` — manual SQLi techniques used to verify parameterization and absence of injectable vectors (findings 5).
2. `performing-second-order-sql-injection` — storage/trigger-point mapping to rule out stored-input injection (finding 6).
3. `testing-for-sensitive-data-exposure` — PII in responses/output, secrets leakage, and information leakage in error messages (findings 1, 2).
4. `implementing-secret-scanning-with-gitleaks` — hardcoded-secret/credential detection across the source (finding 4).

Security-relevant behaviours with no directly matching library skill were reviewed against general OWASP Top 10 / CWE knowledge, as the router skill requires: terminal escape injection (CWE-140, finding 3), information exposure through error messages (CWE-209, finding 1), and sensitive information in non-log resources (CWE-359, finding 2).
