## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 2d126ee7-26be-42ec-b508-da2cdaa22180
- **Input tokens:** 66
- **Output tokens:** 39218
- **Thinking tokens:** 13399
- **Cached read tokens:** 4030841
- **Cache creation tokens:** 194867
- **Total tokens:** 39284
- **Duration:** 9m 43.58s
- **Turns:** 33

---

The review is complete. `security_review.md` is written in the current working folder (`/data/results-cyber/claude/qwen/set_a/post_research/5/security/`); nothing in the source folder was touched.

**What the code is:** a dependency-free Java 21 authentication service for an internal employee portal — JDK `HttpsServer` front end (`GET/POST /login`, `POST /logout`), a CLI for enrolment/reset/disable, PBKDF2 password records in a file roster, per-account and per-source attempt limiting with a durable ledger, and server-side sessions/CSRF state.

**Findings (7):**

| ID | Severity | Issue |
|---|---|---|
| SEC-01 | High | `GET /login` is unmetered and each hit inserts into a global 50,000-entry CSRF map that evicts oldest-first. A flood flushes every legitimate pending token, so logins fail service-wide — and each CSRF failure is charged to the *victim's* source budget, blocking honest addresses for 8 hours (CWE-770) |
| SEC-02 | Medium | The per-source budget is incremented by *successful* logins and never cleared by success, so 30 normal sign-ins in 5 minutes from one NAT/proxy address lock out everyone behind it; the 8-hour ceiling assumes the blocked party is the attacker (CWE-645) |
| SEC-03 | Medium | PBKDF2-HMAC-SHA256 at 150,000 iterations (100,000 floor) vs. OWASP's 600,000 (CWE-916) |
| SEC-04 | Low | Record `alg`/`hashAlg` labels are parsed but never validated; the strict roster loader checks everything except them (CWE-20) |
| SEC-05 | Low | Every attempt rewrites + fsyncs the whole throttle ledger under one monitor, and a full subject map throws, turning authentication into a 500 (CWE-400) |
| SEC-06 | Low | `public` test hooks ship in production: `AuditClock.useForTesting` (rewinding the clock disables all lockouts and expiry) and `ThrottleManager.clearAccountForTesting` (CWE-489) |
| SEC-07 | Low | `issueCsrfToken` reads `pendingCsrf.size()` outside the monitor guarding that map (CWE-567) |

Worth stating plainly: the usual high-severity categories are genuinely absent here, and I verified rather than assumed them — no injection sinks of any kind, no hardcoded secrets, no client-supplied session identifier, correct cookie attributes, one byte-identical denial response with equalised KDF work and latency padding on every path, `0600`/`0700` files with symlink and ownership refusals, and strict fail-closed configuration. Section 6 lists each verified control with its `file:line`. The remaining findings are availability and KDF-strength issues, which is why SEC-01 rather than a credential bug tops the list.
