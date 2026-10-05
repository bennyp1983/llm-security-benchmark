## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** 88441061-38a4-49b0-86e1-6eb5fad52905
- **Input tokens:** 6526859
- **Output tokens:** 60114
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 6586973
- **Duration:** 34m 45.064s
- **Turns:** 43

---

Confirmed: only security_review.md was written; every other file retains its original 02:04 timestamp.

Task complete. Report concisely.
</think>

Review complete. Report written to `/data/results-cyber/qwen/set_a/ruth/5/security/security_review.md` (751 lines). `LoginService.java`, `LoginServiceTest.java` and every other file are untouched (original `02:04` timestamps intact).

## What the code is

`LoginService.java` (764 lines) is a self-contained authentication component: `login()` flow, `PasswordHasher` (PBKDF2-HMAC-SHA256 record encode/verify), `LoginAttemptTracker` (rolling-window lockout), an account store, and an audit hook. `LoginServiceTest.java` is a 1010-line dependency-free suite; `README.md` is a design/threat-model doc.

## Findings — 12 total (2 High, 4 Medium, 6 Low)

| ID | Title | Severity | CWE | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | Lockout keyed on username only ⇒ spraying never trips it | High | CWE-307 | `:420` |
| SEC-02 | 210k-iteration PBKDF2, below OWASP's 600k and not memory-hard | High | CWE-916 | `:238-239` |
| SEC-03 | Cost floor of 1,000 accepted; no rehash-on-login upgrade | Medium | CWE-916 | `:235-236`, `:363-365` |
| SEC-04 | Unbounded, attacker-influenceable KDF CPU per request | Medium | CWE-400 | `:237` |
| SEC-05 | Lockout state exists only in one JVM | Medium | CWE-307 | `:420` |
| SEC-06 | `changePassword` authenticates nobody, emits no audit event | Medium | CWE-306 | `:652-665` |
| SEC-07 | `ACCOUNT_LOCKED` + `retryInSeconds` confirms account exists | Low | CWE-204 | `:49`, `:162-166` |
| SEC-08 | Hard-coded demo credentials | Low | CWE-798 | `:686-688` |
| SEC-09 | Password record and audit lines printed to stdout | Low | CWE-532 | `:694`, `:115-116` |
| SEC-10 | `spec.clearPassword()` skipped on the error path | Low | CWE-316 | `:337-347` |
| SEC-11 | No strength or breached-password policy at enrolment | Low | CWE-521 | `:642-651` |
| SEC-12 | Malformed-name attempts logged as `username=null` | Low | CWE-778 | `:157-160` |

The two Highs are the load-bearing ones: the file's headline control (lockout) is bypassed by the attack class it exists to stop, because there is no source/IP dimension to the throttle at all — one password across many usernames records one failure per key, forever. And every new password enrols at ~⅓ of the current published cost baseline for an algorithm that does not scale with memory.

## Controls that held up (section 6, 16 entries)

The genuinely hard parts are correct: constant-time `MessageDigest.isEqual` (`:326`); timing parity on all five refusal shapes via a runtime-derived `burnWork()` (`:157-159`, `:162-166`, `:169-172`, `:175-181`, `:321-323`); fail-closed `parse` that never throws (`:349-378`); refusal of the `PBEKeySpec` NUL/surrogate collision class (`:279-300`); and the exact-match username allowlist (`:57`), which means no CR/LF or `<` can ever reach a key or an audit line — so no injection and no log forging. A suspected CWE-362 race in the idle-sweep was investigated and **retracted**: `entrySet().removeIf` takes the same bucket lock as `compute`, and `lastPurgeMillis` is `volatile` and written only under `purgeLock`.

## Process notes

Skills applied (section 3): the entry skill plus `performing-cryptographic-audit-of-application`, `testing-api-authentication-weaknesses`, `implementing-api-abuse-detection-with-rate-limiting`, `hunting-credential-stuffing-attacks`, `detecting-anomalous-authentication-patterns`, `testing-for-broken-access-control`, `testing-for-sensitive-data-exposure`, `implementing-secret-scanning-with-gitleaks` — with an explicit line for the four behaviours (tracker thread-safety, `PBEKeySpec` zeroisation semantics, KDF availability cost, lockout-state durability) that had no matching library skill and were checked against general OWASP/CWE knowledge.

`README.md` self-declares several gaps as out of scope; I credited the documentation as accurate but still reported each gap, since the shipped file is the graded artefact. Two format defects in my own first draft were caught and fixed on verification: findings SEC-02–SEC-12 were emitted as `##` instead of the required `###`, and one inline code span was left unbalanced — the final file has exactly one `#`, sections 1–6, twelve level-3 findings, and 25 language-tagged `java` fence pairs (every finding carries both the verbatim source excerpt and a corrected block).
