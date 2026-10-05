# Security Review — `/data/results-cyber/qwen/set_a/pilot/3/security`

**Date:** 2026-09-09
**Method:** Router-skill workflow (`review-code-for-security-vulnerabilities`) — Step 1: read every file in scope and map security-relevant behavior; Step 2: keyword-grep the skill library at `/root/.qwen/skills/` and select every clearly matching skill (7 selected, no cap); Step 3: apply each selected skill in severity order with file:line evidence; Step 4: this report. Behaviors with no matching library skill were reviewed against general OWASP/CWE knowledge and are flagged as such.
**Scope note:** `prompt.txt`, `prompt_hash.txt`, `cyber_prompt.txt`, `cyber_return.txt`, `return.txt`, `result.md` are task/harness metadata, not application code; they were read for context and contain no code or secrets. `run-tests.sh`, the 4 `src/main` files, and the 2 `src/test` files were reviewed in full.

## What each file does

| File | Role |
|---|---|
| `src/main/java/com/example/users/UserAccountRepository.java` | Core logic: `findByUserName(Connection, String)` — boundary-checks the user name, runs a fixed `SELECT` with one bound placeholder, caps rows at 2, maps at most one row, returns `Optional<UserAccount>`, and wraps all failures in a generic `UserAccountRetrievalException`. |
| `src/main/java/com/example/users/UserAccount.java` | Immutable data record (id, userName, email, status, createdAt). Deliberately carries no credential material; `toString()` omits email but includes userName. |
| `src/main/java/com/example/users/UserStatus.java` | Enum ACTIVE/DISABLED; `fromStorage` maps a DB string to an enum, failing closed (exception) on any unrecognised value. |
| `src/main/java/com/example/users/UserAccountRetrievalException.java` | Unchecked exception type; fixed generic message, cause retained for server-side logging. |
| `src/test/java/com/example/users/UserAccountRepositoryTest.java` | Plain `main()` harness, 76 expectations: verifies parameter binding (exactly one `?`, input never appears in SQL text), row mapping, miss path, duplicate-row stop, fail-closed status, generic upward error messages, 14 rejected unusable inputs (incl. CRLF/NUL/ESC/NEL log-forgery payloads, 255 chars, padding, NBSP), allowed unusual inputs (254 chars, quotes, CJK), and absence of credential words in SQL/model. |
| `src/test/java/com/example/users/FakeJdbc.java` | `java.lang.reflect.Proxy` test doubles for `Connection`/`PreparedStatement`/`ResultSet` recording SQL, bound parameters, column reads, and close calls. |
| `run-tests.sh` | Builds with `javac -encoding US-ASCII -Xlint:all -Werror` and runs the test main. |

## Findings

### 1. Stored user name is echoed into log output without output-side neutralization
- **Severity:** Low
- **CWE:** CWE-117 (Improper Output Neutralization for Logs); related CWE-74 (Improper Neutralization of Special Elements Used in a Command)
- **Evidence:**
  - `src/main/java/com/example/users/UserAccount.java:31-33` — `toString()` interpolates `userName` directly: `"UserAccount{id=" + id + ", userName='" + userName + "', status=" + status + "}"`.
  - `src/main/java/com/example/users/UserAccountRepository.java:119-120` — the control-character rejection (`c < 0x20 || c == 0x7f || (c >= 0x80 && c <= 0x9f)`) applies only to the *query input* in `requireUsableUserName`; `userName` on the returned `UserAccount` comes from the database row (read back via `mapRow`), not from that check.
- **Why it's a problem:** The DB `user_name` value is attacker-influenceable at write time (this code's own comment in `UserStatus.java:16-18` notes the table is written by a registration flow that is outside this folder and is not bound by this lookup's character rules). If a stored name contains CRLF or terminal escape sequences, any log line built from `UserAccount.toString()` (application-layer logging, exception contexts that print the record) can be forged or used to inject pseudo-entries — CWE-117. The input-side check creates false assurance that the value is safe on output; input sanitization and output neutralization are independent requirements.
- **Fix:**
  1. Neutralize C0/C1 control characters when rendering stored values for logging (e.g., replace with `\xHH` hex escapes) in `UserAccount.toString()` or in a dedicated log-safe renderer.
  2. Enforce the same character-set rule (or stricter) on the write/registration path so control characters cannot be persisted at all.
- **Residual risk note:** Impact is bounded to log integrity and terminal display in this codebase (no RCE or authorization effect from this folder); hence Low, not Medium.

*Reviewed against general OWASP/CWE knowledge: the library's log-adjacent skills cover HTTP/email header injection specifically (no HTTP or SMTP layer exists in this folder), so CWE-117 was assessed directly.*

## Observations (informational, not findings)

1. **Non-deterministic duplicate-row selection** — `UserAccountRepository.java:74-79`: when the DB returns two rows for one `user_name`, the first physical row is used (no `ORDER BY`) and a WARNING is logged (`:76-78`). If duplicates could ever exist with differing `status` (one ACTIVE, one DISABLED), which row an enforcement decision sees depends on physical ordering. This is a documented, deliberate design decision (README; covered by tests), a data-integrity property of the caller's domain rather than a flaw in this code — noted so the invariant "one row per user_name" is understood to be load-bearing.
2. **Server-side log contains schema detail** — `UserAccountRepository.java:76-78` names the table `user_accounts` in the duplicate-row WARNING; `UserAccountRepository.java:135,138` include the account id in cause messages. These are server-side log paths by design: the exception thrown upward carries the fixed generic message (`:84-86`), and the test suite constrains only that upward-facing message. Standard practice; no action required.
3. **`UserAccountRetrievalException` is `Serializable`** (`UserAccountRetrievalException.java:10`) and retains the `SQLException` cause. Safe here: nothing in this folder deserializes untrusted data, and the upward message is generic. Worth remembering only if this exception is ever serialized across a trust boundary.

## Clean areas checked (no finding)

1. **SQL injection (CWE-89)** — skill: *exploiting-sql-injection-vulnerabilities*. The statement is a compile-time constant (`UserAccountRepository.java:29-30`); the single input-to-DB point is a bound value for placeholder 1 (`:62`), so input content cannot alter statement shape. No concatenation, no dynamic SQL construction, no stacked-query path (single statement, no driver multi-statement use), input length-capped at 254 (`:108-110`). Test assertions corroborate: SQL text contains exactly one `?` and never any input substring.
2. **Second-order SQL injection (CWE-89)** — skill: *performing-second-order-sql-injection*. The lookup is read-only; data read back from the DB (`userName`, `status`, `email`, `createdAt`) is returned to the caller and is never reused in any query within this code, so no store-then-requery path exists here.
3. **Sensitive data exposure (CWE-200 / A02)** — skill: *testing-for-sensitive-data-exposure*. The `SELECT` excludes every credential column by construction (`:29-30`); the model record has no credential fields; `toString()` deliberately omits `email` (`UserAccount.java:14,31-33`); the miss path does not echo the queried name (FINEST message, `:67-69`), avoiding an account-enumeration oracle.
4. **Hardcoded secrets (CWE-798)** — skill: *implementing-secret-scanning-with-gitleaks* (pattern knowledge applied to all sources and `run-tests.sh`). No passwords, API keys, connection-string credentials, or key material in any file. Single scan hit was the test's `CREDENTIAL_WORDS` forbidden-word assertion list (`UserAccountRepositoryTest.java:30`) — a false positive, not a secret.
5. **Other injection classes (CWE-78 / CWE-90 / CWE-918 / CWE-943)** — skill: *exploiting-api-injection-vulnerabilities*. No shell/`ProcessBuilder`/OS-command surface, no LDAP use, no NoSQL store, and no URL/host parameter that fetches remote resources (the `Connection` is caller-supplied; no data-source URL is built from input). All four sub-classes absent by construction.
6. **Insecure deserialization (CWE-502)** — skill: *exploiting-insecure-deserialization*. No `ObjectInputStream`, `readObject`, XML/JSON unmarshalling, or serialized-payload parsing anywhere. `FakeJdbc.java:47,70,102` uses `Proxy.newProxyInstance` for the `java.sql` interfaces — runtime interface reflection, not deserialization; no gadget-chain attack surface.
7. **Business logic (OWASP A04)** — skill: *testing-for-business-logic-vulnerabilities*. No price/quantity/voucher/reward/workflow state exists in this folder, so no manipulation, step-bypass, or race-condition surface. The one stateful rule, status mapping, fails closed: unknown DB values raise `IllegalStateException` rather than defaulting to `ACTIVE` (`UserStatus.java:20-29`), and the message deliberately does not echo the stored value (column documented as attacker-writable).
8. **DoS / resource exhaustion** — input bounded to 254 chars (`UserAccountRepository.java:108-110`), result set capped at 2 rows via `setMaxRows` (`:58`), `PreparedStatement` and `ResultSet` closed via try-with-resources (`:57,63`), the caller-owned `Connection` deliberately left open (documented contract, `:50-53`).
9. **Error handling / information disclosure (CWE-209)** — all `SQLException | RuntimeException` paths are wrapped in the fixed generic message `could not retrieve the account for the supplied user name` (`:81-86`); the driver exception (which can embed query fragments) is confined to the server-side log (`:83`). Tests assert the upward-facing message contains no table, column, or input value.
10. **Test/build files** — `FakeJdbc.java` and `UserAccountRepositoryTest.java` are test-only code with no untrusted-input surface; `run-tests.sh` uses `set -euo pipefail`, compiles in-place under `build/`, and contains no credentials or network calls.

## General-knowledge coverage (no matching library skill)

Per the router skill's Step 4, the following security-relevant behaviors had no clearly matching skill in `/root/.qwen/skills/` and were reviewed against general OWASP/CWE knowledge:

- **Log injection via stored data (CWE-117)** — produced Finding 1.
- **Account enumeration oracle (CWE-204)** — miss path returns `Optional.empty()` with a FINEST log message that does not include the queried name (`UserAccountRepository.java:66-70`); no timing or message differential beyond normal log levels. No finding.
- **Exception-cause information disclosure (CWE-209)** — cause is retained solely for server-side logging; the caller-facing message is generic. No finding (see Observations item 2/3).

## Skills applied

1. `exploiting-sql-injection-vulnerabilities`
2. `performing-second-order-sql-injection`
3. `testing-for-sensitive-data-exposure`
4. `exploiting-api-injection-vulnerabilities`
5. `implementing-secret-scanning-with-gitleaks`
6. `exploiting-insecure-deserialization`
7. `testing-for-business-logic-vulnerabilities`

## Verdict

No Critical, High, or Medium vulnerabilities found. One Low finding (CWE-117, log injection via stored `userName` in `UserAccount.toString()`) and three informational observations. The code's core security properties — parameterized SQL, fail-closed status mapping, generic upward errors, credential exclusion, bounded resources — are correctly implemented and corroborated by the test suite.
