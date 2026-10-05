## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 8147a6b3-c2c7-450c-83d4-12529499eb7b
- **Input tokens:** 60
- **Output tokens:** 40392
- **Thinking tokens:** 19318
- **Cached read tokens:** 2809695
- **Cache creation tokens:** 134957
- **Total tokens:** 40452
- **Duration:** 9m 27.731s
- **Turns:** 31

---

Report written to `security_review.md`. No other files were created or modified.

**What the code is:** a Java 17 Maven CLI (`register`/`login`/`whoami`/`logout`) doing account registration, Argon2id password auth, and server-side session management over SQLite.

**Workflow followed:** inventoried all 15 production sources plus `pom.xml` (step 1), grepped the skill library by name and skimmed descriptions (step 2), then applied the matched skills one at a time (step 3) — cryptographic audit, API authentication weaknesses, sensitive data exposure, SQL injection, rate-limiting implementation/bypass, race conditions — and covered the rest (Unicode canonicalisation, log injection, symlink/TOCTOU, terminal secret input, deserialization, dependency provenance) against general OWASP/CWE knowledge.

**Result: no critical or high findings.** The hard parts are genuinely right: all SQL is parameterised, Argon2id with per-hash `SecureRandom` salt and `MessageDigest.isEqual`, 256-bit CSPRNG session tokens stored only as SHA-256 and validated against server state, no hardcoded secrets, and enumeration resistance enforced by operation *ordering* (decoy-hash work equalisation) rather than just wording.

Eight findings, each with an exact excerpt, CWE and fix:

| ID | Severity | Issue |
|---|---|---|
| SEC-01 | Medium | `accounts.db` created under the umask; chmod `0600` only *after* migration (`Database.java:53`) — inconsistent with how `Logging` and `App` pre-create their files |
| SEC-02 | Low | `System.console() != null` used as a terminal test; on JDK 22+ this bypasses the `ACCOUNTS_PASSWORD_STDIN` opt-in and echo suppression (`App.java:306`) |
| SEC-03 | Low | Throttle keys are unsalted SHA-256 over emails/IPs with an *optional* pepper, so by default the identifiers are recoverable — contradicting the class's own claim (`ThrottleService.java:190`) |
| SEC-04 | Low | Counter is a fixed, not sliding, window → ~2× the limit across a boundary (`ThrottleService.java:57`) |
| SEC-05 | Low | CLI source id from the writable `user.name` property — `-Duser.name=…` yields a fresh rate-limit bucket (`App.java:239`) |
| SEC-06 | Low | Stored-hash parser accepts `m=8 KiB, t=1`, far below the policy floor it enforces on write (`PasswordHasher.java:41`) |
| SEC-07 | Low | New login neither rotates nor revokes prior sessions; `revokeAllForAccount` is never called anywhere (`AccountService.java:202`) |
| SEC-08 | Low | Breached-password blocklist is a 20-entry exact-match stub (`InputValidator.java:40`) |

SEC-01's severity hinges on `ACCOUNTS_JDBC_URL` pointing outside the `0700` data directory — which `Config` permits, since it only prefix-checks the URL; I stated that dependency explicitly rather than rating it on the default path alone. Section 6 lists ~20 verified controls with evidence.
