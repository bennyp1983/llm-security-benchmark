## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** 05ae0e06-053d-4e45-86e8-cc60c97c6ae0
- **Input tokens:** 6290528
- **Output tokens:** 58247
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 6348775
- **Duration:** 22m 54.218s
- **Turns:** 42

---



Review complete. Deliverable: `/data/results-cyber/qwen/claude/set_a/post_research/6/security/security_review.md` (54.7 KB, 929 lines) — the only file created; the source folder is a read-only mount and is untouched (`touch` there returns "Read-only file system", all mtimes still Oct 1).

**Findings — 6 total (1 High, 3 Medium, 2 Low)**

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Throttle checks the budget but never consumes it | High | CWE-362 | `LoginThrottle.java:87` |
| SEC-02 | Throttle key is a client-supplied string, not a provened peer address | Medium | CWE-307 | `InputPolicy.java:108` |
| SEC-03 | Capacity cap turns table growth into denial of all logins | Medium | CWE-770 | `LoginThrottle.java:142` |
| SEC-04 | Decoy verify diverges from real verify in length and iteration count | Medium | CWE-208 | `PasswordHasher.java:38` |
| SEC-05 | Records accepted below the documented iteration floor | Low | CWE-916 | `CredentialRecord.java:25` |
| SEC-06 | Success wipes the account's whole failure history | Low | CWE-307 | `LoginThrottle.java:119` |

The strongest is SEC-01: `admit()` only *reads* counters (`isBlocked` returns `existing` unchanged from its `compute`), and the sole increment happens in `recordFailure()` — called at `AuthenticationService.java:132`, *after* a 210 000-iteration PBKDF2 verify. A parallel burst therefore overruns the 10-failure/15-minute budget and voids the CPU-cost bound. Corroborated independently by the project's own test, which asserts `admitted.get() <= budget + threads` (budget 3, 16 threads) — i.e. the codebase tolerates a full 16-request overrun.

Two candidates were deliberately pushed to §6 rather than padded into findings, with reasoning: the log `openForAppend` permission-check TOCTOU (`0700` owner-only parent dir makes it unexploitable) and the 7-day cookie `Max-Age` vs 8-hour absolute timeout (fails closed; recorded as config drift only).

**Verification run against the finished report**
- All 10 `// <file>:<line>` vulnerable-code excerpts diff byte-for-byte against the read-only source: `10 cited excerpt block(s), 0 mismatch(es)`.
- 17 fences, all `java`-tagged, balanced; exactly 1 level-1 heading; 6 level-2 sections in the mandated order.
- Summary-table IDs and `### SEC-0N:` headings identical and in severity order; each finding has all three of Severity / CWE / Location plus Vulnerable code / Why it is a problem / Fix.

Per the instruction not to execute the untrusted code, nothing was built, installed, or imported — analysis was read-only, and the temporary diff script was kept outside both folders and deleted.
