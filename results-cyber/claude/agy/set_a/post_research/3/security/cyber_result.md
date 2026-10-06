## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 389fce59-fc79-40fe-9f23-dbcb7cbb7f2a
- **Input tokens:** 58
- **Output tokens:** 38627
- **Thinking tokens:** 9541
- **Cached read tokens:** 2288706
- **Cache creation tokens:** 116645
- **Total tokens:** 38685
- **Duration:** 8m 21.309s
- **Turns:** 29

---

Report written to `security_review.md` in the working folder; the source folder was read-only and is unmodified (no files there have changed).

**What the code is:** a Java 17 CLI auth system (`com.example.auth`) — PBKDF2-HMAC-SHA256 password storage over an embedded H2 database, `SecureRandom` session tokens, in-memory rate limiting, masked audit logging.

**Skills applied** (per the router workflow): `performing-cryptographic-audit-of-application`, `testing-api-authentication-weaknesses`, `hunting-credential-stuffing-attacks` + `implementing-api-rate-limiting-and-throttling`, `testing-for-sensitive-data-exposure`, `exploiting-sql-injection-vulnerabilities`, `implementing-secrets-management-with-vault`; ReDoS, stdin decoding, session eviction and the registration race were reviewed against general OWASP/CWE knowledge.

**10 findings, each with exact excerpt, CWE and fix:**

| ID | Finding | Sev | CWE |
|---|---|---|---|
| SEC-01 | Both hard rate limits keyed on caller-supplied `sourceId`; global per-account limiter uses `Integer.MAX_VALUE` and only sleeps ≤3 s, and success resets all counters → unlimited password guessing | High | 307 |
| SEC-02 | `evictIfNecessary` only purges *expired* trackers, so `MAX_CACHE_ENTRIES` is never enforced — and keys are built from `canonicalizeEmail` output *before* validation, so they are unbounded attacker strings | Medium | 770 |
| SEC-03 | `AUTH_DB_URL` passed verbatim to `DriverManager` despite the "validates database configuration" comment → H2 `;INIT=RUNSCRIPT` SQL/code execution | Medium | 15 |
| SEC-04 | `Main.java:87` prints the full cookie header one line after deliberately masking the token | Medium | 532 |
| SEC-05 | Defaults to `sa` with an empty password; creates persistent H2 databases with no auth | Medium | 1188 |
| SEC-06 | `MAX_ACTIVE_SESSIONS` likewise never enforced (sweep only removes expired sessions) | Low | 770 |
| SEC-07 | Length-only 8-char password policy accepts `"password"`, `"12345678"` | Low | 521 |
| SEC-08 | 210 000 iterations is the SHA-**512** OWASP figure; SHA-256 wants 600 000 | Low | 916 |
| SEC-09 | Dummy derivation fixed at `DEFAULT_ITERATIONS` vs per-row `storedIterations` → enumeration oracle once any row's work factor differs | Low | 208 |
| SEC-10 | stdin reader silently truncates at 128 chars and casts bytes to `char` (Latin-1 decode of UTF-8) | Low | 20 |

Section 6 records the controls that held up with file:line evidence: parameterised SQL throughout, re-validation of database-sourced hash parameters, `MessageDigest.isEqual`, `SecureRandom` everywhere, correct `__Host-`/`Secure`/`HttpOnly`/`SameSite=Strict` cookie attributes, `finally`-block zeroisation on every password path, uniform failure messages, CRLF log neutralisation, no hardcoded secrets, non-catastrophic regexes, fail-closed error handling, `synchronized` check-and-increment, 0700/0600 database file permissions, and no deserialization/command-execution/outbound-TLS surface.
