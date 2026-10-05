## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 0fa5e3ad-33a8-4312-bc8b-60b0bd2c7298
- **Input tokens:** 38
- **Output tokens:** 31847
- **Thinking tokens:** 8627
- **Cached read tokens:** 1378685
- **Cache creation tokens:** 102461
- **Total tokens:** 31885
- **Duration:** 7m 4.522s
- **Turns:** 19

---

Report written to `security_review.md` (only file created; nothing else modified).

**Workflow followed:** read all 16 Java sources + `schema.sql`, `pom.xml`, `scripts/smoke-test.sh` and the doc files (Step 1) → grepped the skill library by name and skimmed descriptions (Step 2) → applied the matching skills one at a time against the code (Step 3) → wrote the report in the required structure (Step 4).

**Skills applied:** `performing-cryptographic-audit-of-application`, `testing-api-authentication-weaknesses`, `exploiting-sql-injection-vulnerabilities`, `performing-second-order-sql-injection`, `testing-for-sensitive-data-exposure`, `testing-for-broken-access-control`, `implementing-secrets-management-with-vault`, `testing-for-business-logic-vulnerabilities`; JDBC driver-URL parameter abuse, file TOCTOU/symlink handling, DDL splitting, cookie construction and supply-chain posture were reviewed against general OWASP/CWE knowledge as no library skill matched.

**Result: 10 findings — no Critical or High.** The code is genuinely well hardened (all SQL parameterised, PBKDF2-HMAC-SHA512 210k with per-user salt, `MessageDigest.isEqual`, `SecureRandom` tokens stored only as SHA-256, uniform failure message with decoy-hash timing equalisation, no hardcoded secrets). The findings are design/defence-in-depth gaps:

| ID | Finding | Sev | CWE |
|---|---|---|---|
| SEC-01 | Password change doesn't revoke existing sessions (`CredentialRepository.java:60`) | Medium | 613 |
| SEC-02 | DB transport never requires TLS; cleartext JDBC URLs accepted (`AuthConfig.java:28`) | Medium | 319 |
| SEC-03 | Dangerous JDBC options contained by an incomplete denylist (`AuthConfig.java:36`) | Medium | 184 |
| SEC-04 | Process-wide source id + never-cleared source counter → deployment-wide lockout (`AuthService.java:165`) | Medium | 645 |
| SEC-05 | `set-password` silently re-activates a deactivated account (`CredentialRepository.java:19`) | Low | 284 |
| SEC-06 | Unsalted SHA-256 pseudonymising emails in throttle table + logs (`LoginThrottle.java:63`) | Low | 328 |
| SEC-07 | DB password copied into a `String`; `System.exit` inside try-with-resources skips wiping (`Database.java:28`) | Low | 316 |
| SEC-08 | Non-TTY fallback echoes password into an unwipeable `String` (`ConsoleIo.java:43`) | Low | 549 |
| SEC-09 | Silent empty-DB-password fallback for remote URLs (`AuthConfig.java:151`) | Low | 258 |
| SEC-10 | Password-file permission check and read race (`AuthConfig.java:123`) | Low | 367 |

Each finding carries an exact code excerpt (I verified all ten excerpts byte-match the source lines) and a corrected code block; section 6 lists ~25 verified controls with `file:line` evidence.
