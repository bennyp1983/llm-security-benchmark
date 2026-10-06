## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** da8f4027-8d80-4f1f-8b02-160072633dcf
- **Input tokens:** 46
- **Output tokens:** 31115
- **Thinking tokens:** 10205
- **Cached read tokens:** 1940526
- **Cache creation tokens:** 139709
- **Total tokens:** 31161
- **Duration:** 7m 17.785s
- **Turns:** 24

---

Report written to `security_review.md` in the working folder. Nothing in the source tree was touched, and no code was executed or built.

**What the code is:** a Java 17 CLI that registers accounts, authenticates them, and manages bearer sessions against embedded H2. It is genuinely hardened — Argon2id with per-record salts and enforced work factors, fully parameterised SQL, 256-bit session tokens stored only as SHA-256, uniform failure messages with equal-cost dummy derivations, atomic SQL rate limiting, and audit writes that gate security decisions.

**Findings (6):**

| ID | Severity | Issue |
|---|---|---|
| SEC-01 | High | `Config.java:148` builds the H2 JDBC URL by concatenating the unvalidated `APP_DATA_DIR`/`--data-dir` value. H2 parses `;` as a setting separator, so a directory named `…;INIT=RUNSCRIPT FROM 'http://…'\;--` executes attacker SQL at connect time (also reachable: `AUTO_SERVER=TRUE`, `TRACE_LEVEL_FILE=3`, which undoes the hardening set 70 lines earlier). CWE-74 → CWE-94. |
| SEC-02 | Medium | `AuditLog.java:151` *deletes* the trail when the 64 MiB budget is reached rather than rotating it; refused registrations write records without charging the source budget (`Main.java:211`), so flooding erases earlier `LOGIN_SUCCESS`/`ACCOUNT_LOCKED` history. CWE-778. |
| SEC-03 | Low | `Config.java:128` copies the DB password into an unerasable `String`, defeating `Secrets`. It is avoidable — H2 accepts a `char[]` via `Properties.put`. CWE-316. |
| SEC-04 | Low | `Throttle.isUniqueViolation` matches all SQLState `23xxx`, so a CHECK-constraint rejection is reported as a duplicate and the user sees the "registration is complete" message with exit 0. CWE-754. |
| SEC-05 | Low | Latent: account lookups concatenate a predicate fragment into the SQL text. All four call sites pass literals today; the helper has no guard. CWE-89. |
| SEC-06 | Low | Permission/symlink checks on the password file and data dir are TOCTOU — `AuditLog.append` uses `NOFOLLOW_LINKS` on the open and explains why, but `Config` does not follow its own rule. CWE-367. |

Each finding has the exact excerpt plus a corrected code block. Section 6 lists ~20 controls I verified with no finding, with file:line evidence.
