## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** af0d8034-f4bb-4769-acae-f5d988816e23
- **Input tokens:** 22
- **Output tokens:** 27599
- **Thinking tokens:** 8743
- **Cached read tokens:** 582240
- **Cache creation tokens:** 80100
- **Total tokens:** 27621
- **Duration:** 14m 23.468s
- **Turns:** 16

---

Review complete. Report written to `/data/results-cyber/claude/codex/set_a/post_research/3/security/security_review.md` (nothing in the source folder was touched).

**What the code is:** a Java 17 CLI that reads email + masked password from a TTY, verifies against a PostgreSQL `app_user` row with PBKDF2-HMAC-SHA-256, and prints one of two fixed messages. 7 source files plus schema, pom, and an integrity script.

**Skill workflow:** Step 1 inventoried each file's security behaviour; Step 2 grepped the library by name and skimmed descriptions; Step 3 applied, one at a time — `exploiting-sql-injection-vulnerabilities`, `performing-cryptographic-audit-of-application`, `testing-api-authentication-weaknesses`, `implementing-api-rate-limiting-and-throttling`, `performing-api-rate-limiting-bypass`, `exploiting-race-condition-vulnerabilities`, `testing-for-sensitive-data-exposure`, `detecting-dependency-confusion`. Environment trust, Java exception hygiene, and schema/grants had no matching skill and were reviewed against general OWASP/CWE knowledge.

**Findings (7 — no Critical/High):**

| ID | Issue | Sev | CWE |
|---|---|---|---|
| SEC-01 | `SOURCE_BUCKET` is a compile-time constant — the "per-source" limit is one global 10/min bucket, so anyone can deny service to all users; that single row also makes concurrent logins abort each other under `SERIALIZABLE` | Medium | 645 |
| SEC-02 | DB host/port/name/user come from env with no `sslrootcert` pin or host allowlist — whoever sets the env chooses the server that decides authentication | Medium | 15 |
| SEC-03 | Fixed window discards the count each minute: 2x boundary burst, no backoff, 7,200 guesses/account/day indefinitely | Medium | 307 |
| SEC-04 | Unkeyed SHA-256 of the email persisted as `bucket_key`; distinct key created only when the account exists → existence oracle + dictionary-recoverable | Low | 916 |
| SEC-05 | `catch` lists only 3 types while `authenticate` rethrows `RuntimeException` → stack trace to stderr and no generic message | Low | 248 |
| SEC-06 | SHA-512 pin is a manual step after `dependency:go-offline`; build succeeds without it, and the path comes from `$MAVEN_REPOSITORY` | Low | 494 |
| SEC-07 | Minimum password length is 1; the 15-char policy exists only in the README | Low | 521 |

**No finding** on the parts that matter most: all SQL is parameterized, KDF parameters are pinned in code so a hostile row can't weaken or amplify work, comparison is `MessageDigest.isEqual`, dummy hashing equalizes failure work, failure text is uniform, credential buffers are zeroized, no secrets anywhere, and the grants are least-privilege. Section 6 lists 20 verified controls with line evidence.

One caveat stated in the report: offline, I could not confirm that pgJDBC 42.7.13 exists or that the pinned SHA-512 is correct — that pin should be re-checked against the official release page.
