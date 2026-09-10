# Security Code Review — `com.example.account`

**Scope:** `src/com/example/account/UserAccount.java`, `UserAccountDao.java`, `UserLookupExample.java` (3 files, Java, JDBC).
**Method:** Skill `review-code-for-security-vulnerabilities` (router) — code understood first, then matching specialised skills selected from the library and applied against the code.

---

## Step 1 — What the code does

| File | Purpose | Security-relevant behaviour |
|------|---------|-----------------------------|
| `UserAccount.java` | Immutable DTO for a row of the `users` table (id, username, email, password_hash, enabled, created_at). | Holds **credential material** (`passwordHash`) with a public getter; `toString()` renders PII (username, email); defensive copies of the mutable `Timestamp`. |
| `UserAccountDao.java` | Read-only DAO: `findByUsername()` over a caller-supplied `Connection`. | **SQL query construction** (static SQL + `PreparedStatement` bind), input validation (null/blank), result-set mapping that pulls `password_hash` into memory, `setMaxRows(1)`. No authorization check. |
| `UserLookupExample.java` | Example caller wiring untrusted `usernameFromUser` into the DAO. | **Untrusted input handling**, **output of account data to stdout**, **error handling** (`printStackTrace`), differentiated found/not-found messaging. |

Keywords derived: *sql injection, second-order sqli, sensitive data exposure, password/credential storage, PII in logs, error handling / stack trace leakage, access control, user enumeration*.

## Step 2 — Skills selected

Grepped the library root for `sql|inject|crypto|secret|password|auth|sensitive|log|enumerat|access-control|deserial`, then skimmed the `description` frontmatter of the closest matches. Selected, in priority order:

1. `exploiting-sql-injection-vulnerabilities` — the DAO builds and runs SQL over untrusted input.
2. `performing-second-order-sql-injection` — values read back out of the DB could be re-used in later queries.
3. `testing-for-sensitive-data-exposure` — password hash + PII flow through the DTO and to stdout.
4. `testing-for-broken-access-control` — an account-lookup entry point with no caller authorization.

Not selected (no matching behaviour in the code): cryptography/`performing-cryptographic-audit-of-application` (no hashing, encryption, RNG or key handling is performed here), `exploiting-insecure-deserialization`, JWT/OAuth/token skills, XSS/XXE/SSRF, secrets-scanning skills (no credentials, connection strings or keys are embedded in these files — verified by inspection).

---

## Step 3/4 — Findings

Severity is rated for the code as written, assuming `UserLookupExample.lookup()` models a real caller path fed by end-user input.

### 1. Password hash is loaded and exposed by a public getter (Medium) — CWE-522 / CWE-200
- **Evidence:** `UserAccountDao.java:26` selects `password_hash`; `UserAccountDao.java:69` maps it into the DTO; `UserAccount.java:47-49` exposes `getPasswordHash()`; `UserAccount.java:17` stores it as a `String`.
- **Why it matters:** `findByUsername()` is a general-purpose read used by any caller (the doc comment on `UserAccountDao.java:39` explicitly anticipates untrusted input reaching it), yet every caller receives the stored credential verifier whether or not it is authenticating. That widens the blast radius of any serialization, caching, debugger dump, heap dump or accidental field-echo (e.g. a JSON mapper serializing all getters) into offline password-cracking material. Because the hash is an immutable `String`, it also cannot be zeroed and lingers in the heap and potentially in the string pool until GC — the concern `testing-for-sensitive-data-exposure` Step 6 raises about password hashes appearing in responses.
- **Fix:** Do not select `password_hash` in the general lookup. Provide a separate, narrowly-scoped method (e.g. `Optional<char[]> findPasswordHashForAuthentication(String username)`) used only by the authentication component, return `char[]`/`byte[]` that the caller wipes after verification, and drop `getPasswordHash()` from the shared DTO.

### 2. Username enumeration via distinguishable output (Medium) — CWE-204
- **Evidence:** `UserLookupExample.java:18` prints `"Found: " + account` when the account exists versus `UserLookupExample.java:22` printing `"No matching account."` when it does not; `UserLookupExample.java:24-25` returns a third, distinct message (`"Invalid username supplied."`) for the validation failure at `UserAccountDao.java:45-47`.
- **Why it matters:** The comment at `UserLookupExample.java:20-21` asserts the message "cannot be used to enumerate which usernames exist", but the two branches are trivially distinguishable — one echoes the account, the other does not. An attacker who can reach this path can confirm valid usernames one at a time, which is exactly the observable-response discrepancy `testing-for-sensitive-data-exposure` Step 6 flags for registration/lookup endpoints. There is also no rate limiting or throttling anywhere on this path, so enumeration is unbounded.
- **Fix:** If this path is reachable by unauthenticated or low-privilege callers, return a single generic response regardless of outcome and log the real result server-side only; otherwise gate the endpoint behind authorization (see finding 4) and add rate limiting on repeated lookups per caller.

### 3. Account PII written to standard output (Medium) — CWE-532 / CWE-359
- **Evidence:** `UserLookupExample.java:18` — `System.out.println("Found: " + account)` invokes `UserAccount.toString()` at `UserAccount.java:59-67`, which emits `id`, `username`, `email` and `createdAt`.
- **Why it matters:** `toString()` correctly omits the hash (`UserAccount.java:8-10`), but username + email are still personal data, and stdout is routinely captured into container logs, journald, and log-aggregation pipelines with far weaker access controls and far longer retention than the database. Under GDPR-style regimes this is an unintended processing/retention of PII, and for an attacker with log read access it is a ready-made user list.
- **Fix:** Do not print account contents. Emit a non-identifying correlation value (the surrogate `id`, or a hashed/truncated username) through a real logging framework at debug level, and keep email out of log output entirely.

### 4. No authorization check on the account-lookup path (Medium) — CWE-862
- **Evidence:** `UserAccountDao.java:44` `findByUsername()` and `UserLookupExample.java:13` `lookup(Connection, String)` accept any username and return the full record; neither takes a caller/principal argument nor consults one.
- **Why it matters:** Applying `testing-for-broken-access-control` Step 3/4: there is no vertical check (is this caller allowed to read arbitrary accounts?) and no horizontal check (is this caller the owner of the requested account?). Any code path that can pass a string can read any user's record, including the credential hash from finding 1. A DAO is a legitimate place to leave authorization to the layer above, but `UserLookupExample` is presented as the caller and enforces nothing, so as shipped the composed path is unauthorized-read-by-design.
- **Fix:** Enforce authorization in the calling layer before invoking the DAO — require an authenticated principal and allow either `principal.username.equals(username)` or an explicit `USER_READ`/admin privilege. Document on `findByUsername()` that it performs no authorization and must not be exposed directly.

### 5. Raw stack trace dumped on SQL failure (Low) — CWE-209 / CWE-1295
- **Evidence:** `UserLookupExample.java:28` — `e.printStackTrace()` inside the `SQLException` handler.
- **Why it matters:** `printStackTrace()` writes to `System.err`, bypassing whatever logging configuration, redaction and access controls the application has. JDBC `SQLException` messages frequently embed the failing SQL text, schema/table names, driver and database version, and sometimes connection details — precisely the fingerprinting material `exploiting-sql-injection-vulnerabilities` Step 2 relies on. It also produces unstructured output that is easy to lose in incident response. The user-facing message at line 29 is correctly generic; the defect is the sink, not the message.
- **Fix:** Replace with a logger call (`logger.error("user lookup failed", e)`) via SLF4J/`java.util.logging`, ensure the log destination is access-controlled, and consider logging `e.getSQLState()`/error code plus a correlation id rather than the full message.

### 6. Silent single-row truncation masks a data-integrity anomaly (Informational) — CWE-390
- **Evidence:** `UserAccountDao.java:51-53` — `setMaxRows(1)` with a comment noting a second row "would indicate corrupt data"; `UserAccountDao.java:56-59` returns the first row without ever checking for a second.
- **Why it matters:** The code recognises that duplicate usernames indicate corruption (or a uniqueness-constraint bypass, e.g. Unicode/case-collision registration) but then guarantees the condition can never be observed. If a duplicate ever exists, the lookup silently returns whichever row the engine yields first — a non-deterministic identity resolution that could hand back the wrong account. This is a detection gap rather than a directly exploitable flaw.
- **Fix:** Fetch up to two rows and treat a second row as an error (throw / alert), and enforce a unique index with a normalised (e.g. case-folded) username column at the database level.

### 7. `enabled` is read but never enforced (Informational) — CWE-285
- **Evidence:** `UserAccountDao.java:70` reads the `enabled` column and `UserAccount.java:51-53` exposes it, but no caller in scope — including `UserLookupExample.java:16-23` — consults `isEnabled()` before treating the account as usable.
- **Why it matters:** Disabled/deactivated accounts are returned indistinguishably from active ones. Whether this is a vulnerability depends on out-of-scope callers, but any authentication or authorization path built on this DAO that forgets the check will happily authenticate a suspended user.
- **Fix:** Have the authentication/authorization layer reject `!account.isEnabled()` explicitly, or expose a `findEnabledByUsername()` variant that filters in SQL.

---

## Checks that passed (no finding)

- **SQL injection (CWE-89) — clean.** `UserAccountDao.java:25-28` is a compile-time constant with no concatenation of caller data; the username is bound with `statement.setString(1, username)` at `UserAccountDao.java:50`. There is no dynamic table/column/`ORDER BY` fragment, no string-built `WHERE`, no `Statement.executeQuery(String)`, and no stored-procedure call with concatenated arguments — so none of the error-based, UNION, boolean-blind or time-based vectors in `exploiting-sql-injection-vulnerabilities` Steps 1–3 apply. The doc comment at `UserAccountDao.java:18-24` is accurate.
- **Second-order SQL injection (CWE-89) — clean.** Applying `performing-second-order-sql-injection` Step 1: this code has no storage point (it is read-only) and no trigger point — values read at `UserAccountDao.java:65-71` are placed in a DTO and never re-embedded in SQL. Note that safety here depends on downstream callers continuing to parameterise any query built from `getUsername()`/`getEmail()`.
- **Hardcoded secrets / credentials (CWE-798) — none.** No connection strings, passwords, API keys or key material appear in any of the three files; the `Connection` is injected by the caller (`UserAccountDao.java:32-34`).
- **Cryptography (CWE-327/328/330) — not applicable.** These files perform no hashing, encryption, signing, key derivation or random-number generation; they only transport an already-computed hash. The strength of the password hashing scheme itself must be reviewed wherever `password_hash` is produced — that code is out of scope here.
- **Mutable-state exposure (CWE-374) — handled correctly.** `Timestamp` is defensively copied on both ingress (`UserAccount.java:32`) and egress (`UserAccount.java:56`), and the class is `final` with `final` fields.
- **Null/blank input handling.** `UserAccountDao.java:45-47` rejects null/blank usernames before touching the database, and `UserAccountDao.java:33` rejects a null connection.
- **Resource handling (CWE-772).** Both `PreparedStatement` (`UserAccountDao.java:49`) and `ResultSet` (`UserAccountDao.java:55`) use try-with-resources; the borrowed `Connection` is deliberately left to the caller, which is documented at `UserAccountDao.java:13-14`.

### Behaviours reviewed against general OWASP/CWE knowledge (no library skill matched)

- **Untrusted-input length/charset limits.** `findByUsername()` accepts a username of any length; no library skill covered generic input-size limits, so it was assessed against CWE-1284 — the risk is bounded here because the value is bound as a parameter and capped at one row, so it is noted rather than reported as a finding. Consider a maximum-length check consistent with the column definition.
- **Trim inconsistency.** `UserAccountDao.java:45` validates `username.trim()` but binds the *untrimmed* value at line 50, so `" alice "` passes validation and then matches nothing. Not a security flaw on its own (assessed against CWE-20), but normalising once, up front, avoids validation/use mismatches becoming one later.
- **No rate limiting or lockout** on repeated lookups (CWE-307-adjacent) — reinforces finding 2; no library skill covered it directly.

---

## Skills applied

1. `exploiting-sql-injection-vulnerabilities` — injection-point discovery and parameterised-query verification against `UserAccountDao`. Result: no injection.
2. `performing-second-order-sql-injection` — storage-point/trigger-point mapping. Result: no storage or trigger point in scope.
3. `testing-for-sensitive-data-exposure` — data over-exposure, password-hash exposure, PII in logs, error-message leakage (Steps 2, 5, 6). Result: findings 1, 2, 3, 5.
4. `testing-for-broken-access-control` — vertical/horizontal authorization checks on the lookup path (Steps 1, 3, 4). Result: finding 4.

## Summary

| # | Severity | CWE | Location |
|---|----------|-----|----------|
| 1 | Medium | CWE-522 / CWE-200 | `UserAccount.java:47`, `UserAccountDao.java:26,69` |
| 2 | Medium | CWE-204 | `UserLookupExample.java:18,22` |
| 3 | Medium | CWE-532 / CWE-359 | `UserLookupExample.java:18`, `UserAccount.java:61-66` |
| 4 | Medium | CWE-862 | `UserAccountDao.java:44`, `UserLookupExample.java:13` |
| 5 | Low | CWE-209 / CWE-1295 | `UserLookupExample.java:28` |
| 6 | Informational | CWE-390 | `UserAccountDao.java:51-53` |
| 7 | Informational | CWE-285 | `UserAccountDao.java:70`, `UserLookupExample.java:16-23` |

No SQL injection, hardcoded secrets, or cryptographic weaknesses were found in these three files. The most consequential issues are the credential hash travelling in a general-purpose DTO and the absence of any authorization or rate limiting on the lookup path.
