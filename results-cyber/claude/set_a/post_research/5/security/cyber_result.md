## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** ce3b2c9c-0138-4e4d-9e21-0bb34b8ec529
- **Input tokens:** 50
- **Output tokens:** 35601
- **Thinking tokens:** 11526
- **Cached read tokens:** 1896817
- **Cache creation tokens:** 120743
- **Total tokens:** 35651
- **Duration:** 14m 2.163s
- **Turns:** 25

---

Done. `security_review.md` is written; no other file was created or modified.

**Workflow followed:** read all 18 source files + `build.sh` → derived keywords (password hashing/KDF, session tokens, rate limiting, file permissions, logging/secrets, input validation) → grepped the skill library by name and skimmed descriptions → applied the matching skills' checklists against the code, citing `file:line`.

**Skills applied:** `performing-cryptographic-audit-of-application`, `testing-api-authentication-weaknesses`, `implementing-api-rate-limiting-and-throttling`, `performing-api-rate-limiting-bypass`, `testing-for-sensitive-data-exposure`. Local-filesystem trust-boundary behaviour (symlinks, permission bits, TOCTOU), credential-input encoding, and audit-log reliability had no matching library skill and were reviewed against general OWASP/CWE knowledge — stated as such in section 3.

**Findings (8):**

| ID | Title | Sev | CWE |
|---|---|---|---|
| SEC-01 | `PortalCli.appendRecord` opens the credential file with no file-type/ownership/permission check — symlink-following credential write, and appends to an already world-readable file | High | CWE-59 |
| SEC-02 | Per-source attempt budget keyed on an unauthenticated caller-supplied source id → spray protection bypass | Medium | CWE-807 |
| SEC-03 | `requireOwnerOnly` only rejects a *world*-writable parent dir; group-writable (and loose ancestors) pass | Medium | CWE-732 |
| SEC-04 | Check-then-open race between privacy verification and the subsequent path re-resolution | Low | CWE-367 |
| SEC-05 | Enrolment password policy is length-only, no common/breached check | Low | CWE-521 |
| SEC-06 | Piped passwords read byte-wise and cast to `char`; stdin and terminal paths disagree for non-ASCII | Low | CWE-176 |
| SEC-07 | `PrintStream` swallows audit-log write failures silently | Low | CWE-778 |
| SEC-08 | Attempt-state file rewritten truncate-then-write; an interrupted commit clears all restrictions | Low | CWE-754 |

The headline is SEC-01: every other file access in the project gates on `PrivateFiles.requireOwnerOnly` (`FileCredentialStore.java:60`, `FileAttemptLimiter.java:157`, `AuditLog.java:57`) — the enrolment path is the one that skips it, and `createPrivateIfAbsent` returns early for an existing symlink, so `FileChannel.open` resolves it.

All 13 "vulnerable code" excerpts were programmatically diffed against the source files to confirm they are byte-exact at the cited line ranges. Section 6 lists ~30 controls verified with no finding — the component's crypto parameters, uniform-denial/uniform-timing design, atomic fail-closed rate limiting, and log hygiene all hold up, and there is no SQL, deserialization, command-execution, XSS or SSRF surface.
