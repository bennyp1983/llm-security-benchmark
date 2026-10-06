## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 8e53e096-33de-47ff-bcb7-1f0a2de6dede
- **Input tokens:** 28
- **Output tokens:** 26922
- **Thinking tokens:** 7331
- **Cached read tokens:** 759855
- **Cache creation tokens:** 81574
- **Total tokens:** 26950
- **Duration:** 6m 5.442s
- **Turns:** 14

---

Report written to `security_review.md` in the working folder (`/data/results-cyber/claude/codex/set_a/post_research/6/security`). Nothing in the source tree was modified or executed.

**What the code is:** a self-contained Java 17 auth component — PBKDF2-HMAC-SHA-256 verification, CSPRNG session tokens stored only as SHA-256 digests, a `__Host-` cookie, an HMAC-pseudonymised 0600 rolling audit log, plus in-memory credential/session/rate-limiter adapters.

**Skills applied** (per the skill's grep-names-then-skim-descriptions workflow): `performing-cryptographic-audit-of-application`, `testing-api-authentication-weaknesses`, `implementing-api-rate-limiting-and-throttling`, `performing-api-rate-limiting-bypass`, `exploiting-race-condition-vulnerabilities`, `testing-for-sensitive-data-exposure`, `performing-security-headers-audit`; clock-failure handling, audit-loss semantics, unbounded state and log attribution were reviewed against general OWASP/CWE knowledge since no skill matched.

**Findings (6):**

| ID | Severity | Issue |
|---|---|---|
| SEC-01 | High | CWE-307 — the `THROTTLED` decision is computed at `AuthenticationService.java:78`, logged, then discarded. Verification still runs and a correct password still mints a session; a wrong one returns the same generic failure as attempt #1. `Result` (`:217-229`) exposes no throttle flag, so the README's "delay at the HTTP edge" mitigation is not implementable. Each unrestricted attempt also buys a 600k-iteration PBKDF2. |
| SEC-02 | Medium | CWE-770 — `InMemoryLoginRateLimiter.java:40-43` *throws* when the 100k-key account map is full; keys come from attacker-chosen usernames, so flooding distinct names makes every login for an untracked account fail closed. |
| SEC-03 | Medium | CWE-778 — `logFailure` (`:154-160`) swallows all audit exceptions with no counter or signal, violating `AuditSink`'s own "never silently discard" contract. |
| SEC-04 | Low | CWE-208 — unknown-account dummy KDF is pinned to 600k iterations while real records may use up to 2,000,000 (`PasswordRecord.java:10-11`), giving a latency enumeration oracle. |
| SEC-05 | Low | CWE-754 — `safeNow()` substitutes `Instant.EPOCH` on clock failure, stamping 1970 into the audit log and freezing limiter window expiry. |
| SEC-06 | Low | CWE-117 — the `"invalid"` sentinel shares the `"account"` HMAC domain, colliding with a real account named `invalid`. |

The cryptography itself is sound — no finding there. Section 6 records the verified controls in detail (constant-time compare, digest-only session storage, `__Host-` cookie correctness, zeroisation on every path, atomic limiter/session/audit operations, 0700/0600 + `NOFOLLOW_LINKS` audit file handling, no injection sink of any kind, no hardcoded secret, pinned dependencies).
