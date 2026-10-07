## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** afc281d9-f05b-4bd6-a2f5-4127379a9214
- **Input tokens:** 6311192
- **Output tokens:** 80641
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 6391833
- **Duration:** 32m 5.512s
- **Turns:** 43

---



Done. `security_review.md` is written to the current working folder only (`/data/results-cyber/qwen/agy/set_a/post_research/5/security/security_review.md`, 87 KB). Source folder untouched — newest mtime anywhere under it is 2026-10-01 04:44:31, predating this session, and the mount refused a write test with "Read-only file system". No other file created.

**Result: 14 findings — 1 Critical, 2 High, 4 Medium, 7 Low**

| ID | Sev | CWE | Location |
|---|---|---|---|
| SEC-01 | Critical | 319 | `cli/EmployeePortalApp.java:49` |
| SEC-02 | High | 565 | `web/PortalHttpHandler.java:173` |
| SEC-03 | High | 862 | `service/AuthenticationService.java:193` |
| SEC-04 | Medium | 770 | `ratelimit/RateLimiter.java:81` |
| SEC-05 | Medium | 290 | `cli/EmployeePortalApp.java:117` |
| SEC-06 | Medium | 390 | `repository/FileEmployeeRepository.java:128` |
| SEC-07 | Medium | 73 | `config/SecurityConfig.java:184` |
| SEC-08…14 | Low | 117, 116, 400, 400, 522, 521, 352 | see report |

**Headline:** the crypto core is genuinely sound (PBKDF2-HMAC-SHA512 @210k, 32B salts, `MessageDigest.isEqual`, dummy-hash timing parity on every early return, wiped `char[]`). The defects are in wiring and trust boundaries. SEC-01 is the load-bearing one: `requireSecureCookies = false` is hardcoded at three call sites (`:49`, `:246`, `:270`) while `PortalServer.java:21` serves plaintext HTTP on the wildcard address — so the hardened `__Host-`/`Secure` cookie branch is unreachable dead code, and passwords plus 256-bit session tokens cross the wire in the clear with no `Secure` flag.

**Two things worth your attention beyond the findings:**
1. `README.md`'s "zero findings" and its Rule 3/Rule 4 claims (including `__Host-`-prefixed, `Secure`-flagged cookies) are contradicted by SEC-01 and SEC-02. There is no config knob to enable the secure path — it's a literal, so an operator cannot opt in without recompiling.
2. The 913-line / 39-test suite is real (no `@Disabled`, no tautological asserts) but never exercises the CLI default wiring where SEC-01 lives, which is why the claim survived CI.

§6 records the controls that are correct so they don't get regressed — notably that `extractClientIp` uses the socket and deliberately ignores `X-Forwarded-For` (the opposite of the CLI path in SEC-05), and that `HttpOnly`/`SameSite=Strict` are appended unconditionally.

Report structure self-checked: one H1, all six mandated headings at their levels, 53 code fences all tagged `java`, and §4 IDs/severities identical to and in the same order as §5. Every finding carries CWE id + name, `file:line`, a byte-exact excerpt under a `// <file>:<range>` header, and a corrected code block. Reviewed statically throughout — nothing was executed, built, or imported.
