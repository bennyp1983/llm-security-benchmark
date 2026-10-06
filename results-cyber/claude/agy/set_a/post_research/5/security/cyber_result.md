## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 813105b2-8b7b-45c2-9d5d-b5f6f511fdc8
- **Input tokens:** 36
- **Output tokens:** 34004
- **Thinking tokens:** 6194
- **Cached read tokens:** 1377533
- **Cache creation tokens:** 117775
- **Total tokens:** 34040
- **Duration:** 7m 25.036s
- **Turns:** 19

---

Report written to `/data/results-cyber/claude/agy/set_a/post_research/5/security/security_review.md`. The source tree was read only — nothing in it was modified or executed.

**Workflow followed:** read all 19 main-source files (plus pom/README/tests) → extracted keywords (password storage, session tokens, rate limiting, cookies, file permissions, audit logging, HTTP input handling) → grepped sibling skill names and skimmed descriptions → applied 7 specialised skills one at a time (crypto audit, API auth weaknesses, rate-limit bypass, sensitive-data exposure, security headers, CSRF, broken access control), plus general OWASP/CWE review for concurrency, file hardening, in-memory credential lifetime and build hygiene.

**13 findings**, all with CWE ids, exact excerpts and fixes:

| ID | Finding | Sev |
|---|---|---|
| SEC-01 | Lockout state lives only in a 10k-entry access-ordered LRU; flooding distinct usernames **evicts the victim's lockout record**, resetting brute-force protection (CWE-307) | High |
| SEC-02 | CLI **prompts the caller for the source IP** used in rate limiting and session binding, so the per-source axis is attacker-rotatable (CWE-807) | High |
| SEC-03 | Server is always `HttpServer` (no TLS) with `requireSecureCookies=false` at all three call sites → passwords/tokens in cleartext, no `Secure`, no HSTS (CWE-319) | High |
| SEC-04 | CLI prints the **full session token** and raw cookie header (CWE-532) | Medium |
| SEC-05 | Session IP binding **fails open** when either IP is null; the CLI advertises "leave empty to skip IP check" (CWE-636) | Medium |
| SEC-06 | Rate-limit gate reads the counter before a ~200 ms PBKDF2 and writes after → 8-thread concurrent burst overshoots the limit (CWE-367) | Medium |
| SEC-07 | Cookie reader accepts the unprefixed `portal_session` even in secure mode, defeating the `__Host-` guarantee (CWE-565) | Medium |
| SEC-08 | 0600 applied only on the *create* path; pre-existing `employees.db`/`audit.log` used without checking mode, owner or symlink status (CWE-732) | Medium |
| SEC-09 – SEC-13 | Passwords transit immutable `String`s; log recreated at umask; no CSRF/Content-Type check; sessions survive suspension; length-only password policy | Low |

The cryptographic core and most hardening claims hold up — section 6 lists 24 verified controls, including correct rejection of `X-Forwarded-For`, genuinely absent hardcoded credentials, sound PBKDF2 parameters, consistent timing-neutral failure paths, and structurally inapplicable injection classes.
