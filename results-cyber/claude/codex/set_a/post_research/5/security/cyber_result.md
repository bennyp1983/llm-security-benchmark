## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 127a0b40-9cb5-4606-b96b-139b1a2dc928
- **Input tokens:** 42
- **Output tokens:** 33860
- **Thinking tokens:** 11190
- **Cached read tokens:** 1320444
- **Cache creation tokens:** 88956
- **Total tokens:** 33902
- **Duration:** 7m 41.994s
- **Turns:** 21

---

Review complete. Report written to `security_review.md` in the working folder; nothing in the source folder was touched, and no other file was created or modified.

**What the code is:** `com.acme.portal` — a dependency-free Java 17 console authenticator (6 main classes + a self-test) that provisions and verifies employee credentials against a fixed-path, 0600 credential file.

**Verdict:** the crypto/storage core is solid — PBKDF2-HMAC-SHA-256 at 600k iterations with per-record `SecureRandom` salts, `MessageDigest.isEqual` everywhere, `char[]` zeroing, allowlist/size-bounded store parsing, symlink + permission checks, atomic private writes, equal PBKDF2 work for unknown users, no hardcoded usable secrets, and no injection/deserialization surface at all. No authentication bypass was found. The defects cluster in the brute-force control the task specifically required.

8 findings:

| ID | Severity | Issue |
|---|---|---|
| SEC-01 | High | CWE-307 — all throttle state is process-local, and `Main.java:62-64` exits the "long-lived verifier" on console EOF (Ctrl-D), an action available pre-authentication; a supervised restart clears the 15-min block and all counters |
| SEC-02 | Medium | CWE-645 — the single global source counter makes 5 bad guesses a 15-minute denial for the legitimate console user even with a correct password |
| SEC-03 | Medium | CWE-778 — zero authentication logging; the two log calls also drop the exception, so store tampering and crypto failures are indistinguishable |
| SEC-04 | Low | CWE-367 — file metadata validated by path, then re-opened by path in `CredentialStore.load` |
| SEC-05 | Low | CWE-789 — no per-line bound on the 66 MB blocklist; the resulting `OutOfMemoryError` is an `Error` and escapes the `RuntimeException` handler |
| SEC-06 | Low | CWE-754 — `sourceBlockedUntil = 0` as "unset" denies every login on a JVM whose `nanoTime()` origin is negative |
| SEC-07 | Low | CWE-180 — length checked before `toLowerCase`, so e.g. U+212A folds into the ASCII allowlist |
| SEC-08 | Low | CWE-667 — the exclusive inter-process lock is held across PBKDF2 and the up-to-2s throttle sleep, letting a guessing loop starve `provision` |

Skills applied: `performing-cryptographic-audit-of-application`, `testing-api-authentication-weaknesses`, `performing-api-rate-limiting-bypass`, `testing-for-sensitive-data-exposure`, `exploiting-race-condition-vulnerabilities`; logging, resource bounds, time-source and locking behaviour were reviewed against general OWASP/CWE knowledge, as noted in section 3.
