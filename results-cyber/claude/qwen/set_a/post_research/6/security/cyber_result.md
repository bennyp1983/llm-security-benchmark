## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 3dc824e6-a0c2-4f6d-9e39-08bb4d62a73a
- **Input tokens:** 50
- **Output tokens:** 33609
- **Thinking tokens:** 9881
- **Cached read tokens:** 2619113
- **Cache creation tokens:** 170106
- **Total tokens:** 33659
- **Duration:** 7m 42.265s
- **Turns:** 27

---

Review complete. `security_review.md` is written in `/data/results-cyber/claude/qwen/set_a/post_research/6/security/` — the source tree was only read, never modified, and nothing in it was compiled, run, or imported.

**What the code is:** a dependency-free Java 17 username/password authentication component (25 production classes) — peppered PBKDF2-HMAC-SHA256 credential verification, per-account lockout plus per-source rate limiting, opaque server-side session ids, and a fail-closed append-only audit log.

**Workflow followed:** read all 25 main + 11 test sources, derived keywords (password hashing/KDF, pepper & keystore, session tokens, rate limiting, audit logging, file permissions, concurrency, timing side channels), grepped the skill library by name, skimmed candidate descriptions, then applied 7 specialised skills — `performing-cryptographic-audit-of-application`, `testing-api-authentication-weaknesses`, `implementing-api-rate-limiting-and-throttling`, `performing-api-rate-limiting-bypass`, `hunting-credential-stuffing-attacks`, `exploiting-race-condition-vulnerabilities`, `testing-for-sensitive-data-exposure`. Audit-log file handling, the credential/config parsers and the fail-closed availability trade-offs had no matching skill and were reviewed against general OWASP/CWE knowledge, as noted in §3.

**9 findings, all with CWE ids and `file:line` evidence:**

| ID | Severity | Issue |
|---|---|---|
| SEC-01 | High | Every *already-throttled* attempt still writes an audit line; the 64 MiB log ceiling then makes the fail-closed logger deny all authentication — ~335k requests from one unauthenticated address is a global outage (CWE-779) |
| SEC-02 | Medium | `evictIdleSources` ignores `blockedUntilMillis`, so a live per-source block is deleted and the budget reset once the 20k-key table is full (CWE-307) |
| SEC-03 | Medium | `evictIdle*` runs `removeIf` on the same map from inside `ConcurrentHashMap.compute()` — forbidden by the JDK contract, two attempts on different bins can deadlock the throttle (CWE-833) |
| SEC-04 | Medium | `padUntil` sleeps while holding one of only 4 global derivation permits, capping logins at ~20/s and making blanket `WORK_UNAVAILABLE` denials cheap (CWE-400) |
| SEC-05–09 | Low | 120k PBKDF2 floor vs OWASP's 600k; indefinitely sliding session with no absolute lifetime; unsalted SHA-256 `account_id` in logs; session-table saturation logs other users out; latency-floor clamp reopens a timing oracle at high work factors |

The cryptography itself held up — no SQL/command injection, deserialization, hardcoded secrets, log injection, or path-traversal issues; §6 lists ~18 controls verified with specific line references, including the constant-time compare, equal-work decoy derivation, uniform denial text, `CREATE_NEW`+0600 log creation with per-write inode re-checks, and the no-free-text audit record format.
